# OGTP/1 Coupled Multipath Congestion Control

Status: **draft 0.2 experimental implementation contract**.

OGTP runs one congestion controller, pacer, RTT estimator, ECN validator, and
recovery space per path. Independent controllers are unsafe when paths cross
the same bottleneck because one connection can then behave like several
competing flows. OGTP therefore couples congestion-avoidance increases across
concurrently active paths.

The coupling equations are based on the Experimental Linked Increases
Algorithm (LIA) in [RFC 6356](https://www.rfc-editor.org/rfc/rfc6356.html).
They are adapted as a growth cap around byte-counted CUBIC rather than used as
the additive increase of a Reno controller. This is not a Standards Track
algorithm and is not a claim that OGTP is already fair to TCP or QUIC. As
noted by [RFC 9743](https://www.rfc-editor.org/rfc/rfc9743.html), concurrent
multipath congestion control still has no Standards Track RFC.

## Objectives

The controller is designed to pursue the three RFC 6356 goals:

1. perform at least as well as a single flow on the best available path;
2. take no more capacity at a shared bottleneck than a comparable single flow;
3. move traffic away from more congested paths without unstable flapping.

The implementation enforces a conservative per-ACK increase bound. Only
physical shared-bottleneck measurements can establish the second objective for
the combined CUBIC/LIA profile.

## Fixed-capacity state

`LiaCoupler` supports at most 16 path snapshots and performs no heap
allocation. The caller supplies a borrowed `CoupledPathState` slice containing:

- the stable path identifier and active state;
- congestion window, slow-start threshold, and bytes in flight;
- smoothed RTT and maximum datagram size;
- recovery and application-limited state.

Only Q32 fractional growth credit is retained per path. A retired path must
call `retire_path`; this clears its credit slot and prevents a recycled path
identifier from inheriting growth.

All multiplications use checked `u128` arithmetic. Duplicate identifiers,
invalid RTT or datagram size, unavailable acknowledged paths, capacity
exhaustion, and arithmetic overflow fail closed instead of silently changing
the fairness calculation.

## Effective windows

For each active path `i`, the coupling calculation uses:

```text
effective_i = cwnd_i
effective_i = min(effective_i, ssthresh_i)  when in recovery
effective_i = min(effective_i, flight_i)    when application limited
```

A zero effective window does not participate. This prevents an inflated
recovery window or an idle path from increasing the connection's aggregate
aggressiveness. The acknowledged path must have a non-zero effective window.

## Integer LIA calculation

The reference path `max` maximizes `effective_i / rtt_i²`. Ties retain the
first path in the caller's stable ordering. With `alpha_scale = 512`:

```text
aggregate = sum(effective_i)
normalized_sum = sum((rtt_max * effective_i) / rtt_i)

alpha_scaled = 512 * aggregate * effective_max
               / normalized_sum²
```

For newly acknowledged bytes on path `i`, OGTP computes two Q32 budgets:

```text
linked_q32 = alpha_scaled * bytes_acked * MDS_i * 2^32
             / (512 * aggregate)

reno_q32 = bytes_acked * MDS_i * 2^32 / effective_i

path_credit_q32 += min(linked_q32, reno_q32)
growth_limit = floor(path_credit_q32 / 2^32)
```

The fractional remainder stays in `path_credit_q32`. Unlike forcing a
one-byte increase for every sub-byte result, this preserves the long-term
integer rate without creating a per-ACK minimum burst. For two identical paths
with 12,000-byte windows, 100 ms RTTs, 1,200-byte datagrams, and a 1,200-byte
ACK, `alpha_scaled` is 256 and the immediate growth limit is 30 bytes. A single
path produces the Reno limit of 120 bytes.

## Interaction with CUBIC

HyStart++ and Conservative Slow Start remain per-path and are not capped by
LIA. During congestion avoidance, the ACK path applies:

```text
actual_growth = min(CUBIC_proposal, LIA_growth_limit)
```

The cap also applies to CUBIC's Reno-friendly region. Unused whole-byte LIA or
CUBIC budget is discarded, so the implementation can be less aggressive than
either standalone increase function. Loss, validated ECN-CE, recovery epochs,
and persistent congestion retain the per-path CUBIC behavior in
[`CONGESTION.md`](CONGESTION.md), including `beta = 0.7`.

RFC 6356 couples Reno increases while retaining Reno decreases. OGTP instead
combines a LIA-derived increase cap with CUBIC decreases. The code therefore
must be described as an experimental CUBIC/LIA profile, not as conforming LIA,
and its shared-bottleneck behavior must be measured before deployment.

## Scheduling and failure

Coupling limits aggregate window growth; it does not choose a path. The chunk
scheduler still minimizes estimated arrival time using pacer delay, RTT,
queued bytes, estimated rate, and loss penalty. Reinjection may select a
different validated path, but the retransmitted bytes are charged to that
path's own congestion window.

Path failure removes the path from new coupling snapshots immediately. Packets
already in flight retain their recovery state, and their data may be
reinjected elsewhere. Re-enabling or replacing a path requires fresh path
validation and a valid RTT sample before it can participate.

## Validation required

Before the profile can be enabled by default, tests must cover:

- one OGTP multipath connection against one CUBIC and one QUIC connection at a
  shared physical or emulated bottleneck;
- truly disjoint bottlenecks, unequal RTTs, unequal datagram sizes, random
  loss, ECN, and application-limited traffic;
- path addition, retirement, failure, recovery, and rapidly changing RTT;
- aggregate goodput, Jain fairness index, queue delay, loss, CE rate, and
  per-path window trajectories;
- comparison with a high-precision model and with uncoupled CUBIC;
- cycles per ACK for 1, 2, 4, 8, and 16 active paths.

The present implementation recalculates alpha in bounded `O(paths)` work on
each ACK. A future measured optimization may cache the aggregate and alpha for
one RTT, as suggested by RFC 6356, but it must preserve deterministic
invalidation and checked arithmetic.
