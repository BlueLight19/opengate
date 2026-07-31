# OGTP/1 Bounded Loss Recovery

Status: **draft 0.2 implementation contract**.

This document describes the sender-side recovery state implemented in
`src/recovery.rs`. It covers bounded packet metadata, RTT estimation,
ACK-driven loss detection, and selection of a path for reinjection. It does not
yet implement the congestion window, pacer, PTO state machine, or persistent
congestion response.

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

1. release newly acknowledged packets and update bytes-in-flight;
2. release packets selected by packet or time loss thresholds.

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

Before an RTT sample, the formula uses the 333 ms initial RTT. PTO backoff,
probe transmission, and persistent-congestion state remain release blockers.

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

- circular-slot exhaustion and reuse without capacity growth;
- ACK ranges that simultaneously acknowledge and declare packets lost;
- packet-threshold and time-threshold loss;
- bounded ACK-delay RTT adjustment and PTO calculation;
- ETA selection that excludes failed paths;
- failover reinjection followed by late delivery of the original packet.
