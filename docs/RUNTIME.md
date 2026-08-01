# OGTP/1 Bounded UDP Runtime Core

Status: **draft 0.3 portable runtime and standard UDP adapter contract**.

This document defines the fixed-capacity boundary between OGTP protocol state
and a UDP socket implementation. The fixed-resource implementation is in
`src/runtime.rs`; the safe standard-library adapter is in
`src/runtime/portable.rs`. The core performs no system calls, owns no socket,
starts no task, and allocates no heap memory internally.

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

Receive metadata retains the source endpoint, socket identifier, monotonic
receive timestamp, and an optional UDP GRO segment size. Exact destination,
interface, and ECN observations use `Option`; an adapter must return `None`
rather than inventing ancillary data it could not observe.
`ReceivedDatagramView::segments` returns the original datagrams in order
without allocating or copying; the final segment may be shorter.

Transmit metadata retains the corresponding routing fields, ECN, an absolute
send-not-before timestamp, and an optional UDP GSO segment size. The socket
adapter remains responsible for checking platform offload limits and falling
back to individual datagrams without changing protocol semantics.

## Fixed batch ownership

Platform syscalls must borrow multiple pool slots without constructing an
aliasing mutable slice or a heap-backed staging list. The core provides exact
compile-time batches for that boundary.

`ReceiveQueue::reserve_batch<N>` reserves all `N` slots or returns every slot
acquired by that call. Resource counts are unchanged after failure. The
returned `ReceiveBatchReservation<N>` exposes all payload areas at once through
`batch_buffers_mut`; Rust's disjoint-index validation proves that no two slices
alias. After the syscall, `into_reservations` restores the individual ownership
tokens so each successful element can be committed and every unused or failed
element can be cancelled independently.

`TransmitQueue::pop_batch<N>` removes exactly `N` ready datagrams in FIFO order.
If fewer are available, it returns `None` without popping any. A backend borrows
each immutable view to build its syscall descriptors, then calls
`into_datagrams` after the result. For a partial batch, accepted elements are
completed or deferred, transiently blocked elements are requeued, and permanent
local failures are discarded. A smaller compile-time batch or the ordinary
single-datagram path handles the tail.

Batch tokens are non-`Copy`, non-`Clone`, redacted in `Debug`, and marked
`must_use`. The batch layer allocates no memory, performs no payload copy, and
contains no unsafe code. It is shared by future `recvmmsg`/`sendmmsg` and
`io_uring` adapters rather than duplicating ownership logic per platform.

## Safe standard-library adapter

`PortableUdpSocket` owns one `std::net::UdpSocket`, assigns it a stable runtime
socket ID, and forces nonblocking mode. It is a compatibility and integration
backend, not the final high-throughput Linux path. It is `Send` but deliberately
not `Sync`: ownership may move to an event-loop thread, while the fast path
cannot share the adapter concurrently or acquire an implicit internal lock.

Receive operations reserve a queue slot before calling `recv_from` and write
directly into that slot. The configured OGTP maximum requires one additional
buffer byte. This probe byte distinguishes an exact maximum-size datagram from
an oversized datagram truncated to the supplied slice; the oversized prefix is
cleared and never committed. The portable profile rejects maxima above 65,527
bytes and excludes IPv6 jumbograms.

The adapter records `None` for destination, interface, and ECN values that the
standard library cannot observe. A concrete non-wildcard bind supplies the
exact local destination; a wildcard bind does not. Callers query a compact
capability set before enabling ECN or any offload-dependent behavior.

Transmit operations enforce the socket ID and caller-supplied monotonic pacing
deadline. The adapter accepts normal route selection, or a source equal to its
concrete bound endpoint. It rejects per-datagram source/interface selection,
ECN marking, and GSO when they require unavailable ancillary APIs. A pacing
delay or `WouldBlock` requeues the token. Successful standard sends complete
synchronously. Unsupported metadata and permanent socket errors discard the
encoded bytes while leaving protocol recovery state responsible for reliable
rescheduling.

The standard backend performs one syscall per attempt and reports batching,
GRO/GSO, kernel timestamps, ECN, and deferred completion as unsupported. Those
features belong to capability-gated platform backends; they must retain the
same ownership outcomes.

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
stale-token rejection after slot reuse. Local loopback tests additionally
cover direct nonblocking receive, explicit unavailable metadata, oversize
probing, buffer-capacity rejection, pacing, synchronous transmit, IPv6 scope
preservation, and unsupported-offload cleanup. Fixed-batch tests cover
all-or-nothing RX rollback, simultaneous disjoint buffer writes, FIFO TX
extraction, incomplete-batch immutability, and mixed synchronous, requeued,
discarded, and deferred completion outcomes.

The next runtime slices are:

1. a platform socket adapter with destination/interface/ECN/timestamp ancillary
   extraction plus batched `recvmmsg`/`sendmmsg` where available;
2. fixed connection/DCID ownership and bounded cross-thread completion rings;
3. a Linux `io_uring` backend with registered buffers and capability-gated
   multishot receive, UDP GRO/GSO, and zero-copy completion handling;
4. syscall, allocation, copy, cache, RSS, pinned-memory, and goodput
   measurements from `BENCHMARKS.md`;
5. stateful fuzzing of adapter errors, partial batches, completion reordering,
   and resource exhaustion.

This runtime does not make OGTP production-ready. Full ancillary-data support,
batched platform adapters, kernel capability detection, cancellation races,
descriptor lifecycle, cross-platform conformance, and independent security
review remain release blockers.
