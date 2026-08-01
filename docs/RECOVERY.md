# OGTP/1 Bounded Loss Recovery

Status: **draft 0.2 implementation contract**.

This document describes the sender-side recovery state implemented in
`src/recovery.rs`. It covers bounded packet metadata, RTT estimation,
ACK-driven loss detection, PTO state, persistent-congestion detection, and
selection of a path for reinjection. The congestion window and pacer are
described in [`CONGESTION.md`](CONGESTION.md).

## Fixed-capacity packet state

Every path owns a `SentPacketTable`. Construction allocates the configured
fixed boxed slot slice and a same-size free-index stack. Recording pops one
free index, so it is O(1) and performs no allocation. Packet-number gaps caused
by untracked ACK-only packets cannot collide with occupied slots.

A slot retains only:

- the 62-bit packet number;
- its monotonic send timestamp;
- encoded bytes charged to bytes-in-flight;
- an optional stable recovery token.

The token identifies DATA metadata or an idempotent control operation. It does
not contain plaintext or ciphertext. DATA can therefore be reread from its
source descriptor after loss. If every slot is occupied, sending is stopped
with explicit backpressure; the table never grows to accommodate the new
packet.

Pure ACK packets that are not ACK-eliciting are not entered in this table.
Packet numbers strictly increase and send timestamps never decrease per path.
Counters and byte accounting reject overflow instead of wrapping.

## ACK processing

ACK range membership is evaluated directly from the borrowed wire frame and
walks no more than 33 ranges. Processing scans the fixed slot table twice:

1. release packets selected by packet or time loss thresholds;
2. release newly acknowledged packets and update bytes-in-flight.

Loss events are emitted before acknowledgement events from the same ACK. This
allows the congestion controller to reduce its window before considering any
eligible ACK-driven growth.

Events are delivered synchronously to a caller-provided callback. No vector or
queue is created by the recovery layer. An ACK covering a packet number never
sent on its path is rejected before state mutation.

Only a newly acknowledged `Largest Acked` packet contributes an RTT sample.
Peer-reported ACK delay is capped at 25 ms and cannot reduce the adjusted
sample below the minimum observed RTT. Smoothing uses integer arithmetic with
the coefficients specified in `SPEC.md`.

## Loss and timers

The packet threshold is three newer packet numbers. The time threshold is 9/8
of the larger of latest and smoothed RTT, with a 1 ms timer granularity. A time
threshold applies only below the largest packet number acknowledged on that
path, which prevents declaring the current tail lost solely because no ACK has
arrived.

The estimator also exposes the base probe timeout:

```text
PTO = smoothed_rtt + max(4 * rtt_variance, 1 ms) + max_ack_delay
```

Before an RTT sample, the formula uses the 333 ms initial RTT. A time-threshold
loss deadline takes precedence over PTO. Otherwise, the last ACK-eliciting send
arms PTO while such a packet remains in flight.

PTO expiration requests two probe datagrams and increases a saturating binary
backoff. It does not declare any outstanding packet lost and does not reduce
the congestion window. PTO probes may temporarily exceed the congestion window
but remain charged to bytes-in-flight. A newly acknowledging ACK resets the
backoff. The idle timeout is expected to terminate a dead path before the
representable timer duration saturates.

Persistent congestion requires at least two consecutive lost ACK-eliciting
packets, a prior RTT sample when they were sent, no acknowledged or unresolved
packet between them, and a send-time span of at least:

```text
3 * (smoothed_rtt + max(4 * rtt_variance, 1 ms) + max_ack_delay)
```

The allocation-free tracker accepts packet outcomes in non-decreasing send-time
order and rejects ordering regressions. Confirmed persistent congestion
collapses the associated CUBIC window to two maximum-sized datagrams.

## Multipath reinjection

A lost packet may emit a stable recovery token. The selector considers only
validated, sendable paths with a non-zero delivery-rate estimate and minimizes
the estimated delivery delay defined in `SPEC.md`. The selection is
deterministic and allocation-free.

The selected path assigns a fresh path-local packet number and seals the
recovered plaintext again. A token is never permission to reuse old ciphertext.
Caller-owned fragment completion state suppresses redundant work if the
original packet arrives after a successful reinjection.

## Deterministic coverage

The test suite covers:

- fixed-slot exhaustion, packet-number gaps, and reuse without capacity growth;
- ACK ranges that simultaneously acknowledge and declare packets lost;
- packet-threshold and time-threshold loss;
- bounded ACK-delay RTT adjustment, PTO arming/backoff/reset, and timer
  precedence;
- consecutive-loss persistent-congestion detection;
- ETA selection that excludes failed paths;
- failover reinjection followed by late delivery of the original packet.
