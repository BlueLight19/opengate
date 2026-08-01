# OGTP/1 Bounded UDP Runtime Core

Status: **draft 0.3 portable runtime contract; no socket adapter yet**.

This document defines the fixed-capacity boundary between OGTP protocol state
and a UDP socket implementation. The Rust implementation is in
`src/runtime.rs`. It performs no system calls, owns no socket, starts no task,
and allocates no heap memory internally.

The intended deployment model gives each connection shard to one event-loop
owner. Platform adapters borrow buffers from this module and return explicit
ownership tokens. Protocol input cannot grow a buffer pool, timer table, or
completion queue.

## Resource model

Receive and transmit storage use separate arenas:

- `ReceiveQueue<RX_SLOTS, BUFFER_SIZE>` contains exactly `RX_SLOTS` buffers;
- `TransmitQueue<TX_SLOTS, BUFFER_SIZE>` contains exactly `TX_SLOTS` buffers;
- each arena has independent fixed free and ready rings;
- `RuntimeTimerQueue<TIMERS>` contains exactly `TIMERS` timer entries and one
  fixed binary min-heap;
- all capacities are compile-time constants and may be zero.

Separating RX and TX prevents an inbound flood from consuming buffers already
reserved for acknowledgements, path validation, or connection shutdown. Pool
exhaustion is explicit backpressure. It never allocates, blocks, or evicts an
unrelated live slot.

The payload contribution to the userspace footprint is exactly:

```text
(RX_SLOTS + TX_SLOTS) * BUFFER_SIZE
```

Slot metadata, ownership generations, and the two index rings add fixed
compile-time overhead. Deployments should measure the complete types with
`core::mem::size_of` for their selected constants and include socket buffers,
kernel-pinned memory, and alignment separately.

Queue constructors are `const`, allowing static or caller-selected startup
placement without a runtime initialization loop. Large arenas should be placed
in startup-owned storage rather than on a small thread stack. No buffer is
sized from a peer-controlled length.

## Ownership state machines

Receive slots follow this state machine:

```text
Free -> Reserved -> Ready -> Delivered -> Free
          |                              
          +-------------------------> Free (cancel or invalid commit)
```

Transmit slots follow this state machine:

```text
Free -> Reserved -> Ready -> Submitting -> Free (synchronous completion)
          |                 |       |
          |                 |       +-> KernelOwned -> Free (exact completion)
          |                 +----------> Ready (transient backpressure)
          +---------------------------> Free (cancel or invalid commit)
```

Reservations and delivered/submitting datagrams are non-`Copy`, non-`Clone`
tokens. Operations that release, requeue, or transfer a slot consume the
token. A generation check rejects stale, duplicate, foreign, and wrong-state
use. Borrowed views expose exact payload slices without copying and cannot be
constructed outside the module.

Cancellation and invalid commits clear the entire reserved buffer because a
socket adapter may have written beyond its reported length. Normal completion
clears the used payload range. Metadata is removed before the slot returns to
the free ring. Dropping either arena applies compiler-resistant zeroization to
every complete buffer. Debug output reports only bounded counters or byte
lengths and redacts endpoints, payloads, deadlines, and ownership identifiers.

## Datagram shape and UDP offload

`commit` rejects empty datagrams, lengths beyond `BUFFER_SIZE`, and GRO/GSO
segment sizes larger than the committed length. These failures release and
clear the reservation transactionally.

Receive metadata retains source and destination endpoints, socket and
interface identifiers, ECN, a monotonic receive timestamp, and an optional UDP
GRO segment size. `ReceivedDatagramView::segments` returns the original
datagrams in order without allocating or copying; the final segment may be
shorter.

Transmit metadata retains the corresponding routing fields, ECN, an absolute
send-not-before timestamp, and an optional UDP GSO segment size. The socket
adapter remains responsible for checking platform offload limits and falling
back to individual datagrams without changing protocol semantics.

## Backpressure and kernel completion

A portable synchronous adapter calls `TransmitQueue::complete` only after the
kernel has copied the submitted bytes. A transient `EAGAIN` or equivalent
returns the consumed submission with `requeue`, placing it at the bounded ready
ring's tail without allocating a separate retry item. This avoids one blocked
path preventing attempts already queued for other paths.

An asynchronous or zero-copy adapter calls `defer_completion` after successful
submission. This moves the slot to `KernelOwned`; syscall success alone does
not release it. Only the matching `TransmitCompletionTag` may call
`complete_deferred`. Until that event, pool statistics expose the retained
slot and no reservation may reuse its memory.

Adapters must map partial batch submission individually: completed datagrams
are released or deferred, while unsubmitted datagrams are requeued. They must
not treat one batch result as ownership completion for every element.

## Timer semantics

`RuntimeTimerQueue` is a stable fixed-capacity min-heap over absolute monotonic
microsecond deadlines. Equal deadlines fire in insertion order. Every timer is
bound to an opaque `TimerOwner` and a typed `RuntimeTimerKind`.

Cancellation tokens include persistent per-slot generations. A token for an
expired or cancelled timer cannot cancel a later timer that reuses the same
slot. Capacity, generation, and insertion-counter exhaustion fail closed.
Polling with a timestamp older than the preceding poll is rejected without
removing an event.

The queue deliberately has no wall-clock conversion and no background worker.
The event-loop owner supplies monotonic time, drains every expired event, and
maps its owner back to bounded connection, path, handshake, or object state.

## Event-loop integration order

A socket-backed shard should:

1. complete kernel-owned TX buffers whose exact completion events arrived;
2. reserve RX buffers and submit or perform bounded receive operations;
3. commit successful receives with all ancillary metadata;
4. pop ready RX buffers, split GRO aggregates, and perform header, replay, and
   AEAD validation before changing connection state;
5. release each RX token after all borrowed views are no longer used;
6. drain expired timers using one monotonic timestamp;
7. let recovery, pacing, and transfer state create bounded TX reservations;
8. submit ready TX buffers subject to `send_not_before_micros`, completing,
   deferring, or requeuing every consumed token exactly once.

RX exhaustion should stop or reduce receive submission until slots return. TX
exhaustion should propagate bounded backpressure into pacing and application
scheduling. Neither condition authorizes unbounded spill queues.

## Implemented guarantees and remaining work

Deterministic tests cover fixed pool exhaustion, FIFO delivery, GRO splitting,
invalid shape rollback, zeroing on reuse, synchronous completion, transient TX
requeue, deferred kernel ownership, duplicate completion rejection, stable
timer ordering, monotonic polling, capacity exhaustion, cancellation, and
stale-token rejection after slot reuse.

The next runtime slices are:

1. a portable nonblocking UDP adapter with ancillary address, interface, ECN,
   and timestamp extraction plus batched `recvmmsg`/`sendmmsg` where available;
2. fixed connection/DCID ownership and bounded cross-thread completion rings;
3. a Linux `io_uring` backend with registered buffers and capability-gated
   multishot receive, UDP GRO/GSO, and zero-copy completion handling;
4. syscall, allocation, copy, cache, RSS, pinned-memory, and goodput
   measurements from `BENCHMARKS.md`;
5. stateful fuzzing of adapter errors, partial batches, completion reordering,
   and resource exhaustion.

This core does not make the runtime production-ready. Platform adapters,
kernel capability detection, cancellation races, descriptor lifecycle,
cross-platform conformance, and independent security review remain release
blockers.
