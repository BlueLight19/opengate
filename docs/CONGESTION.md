# OGTP/1 Congestion Control and Pacing

Status: **draft 0.2 implementation contract**.

OGTP uses a per-path, byte-counted CUBIC controller and a scalar nanosecond
pacer. These mechanisms are implemented directly for OGTP datagrams; OGTP is
not encapsulated in QUIC. The control laws follow
[RFC 9438](https://www.rfc-editor.org/rfc/rfc9438.html), while the recovery
timer and persistent-congestion rules follow
[RFC 9002](https://www.rfc-editor.org/rfc/rfc9002.html). Initial slow-start
exit follows [RFC 9406](https://www.rfc-editor.org/rfc/rfc9406.html).
ECN codepoints follow [RFC 3168](https://www.rfc-editor.org/rfc/rfc3168.html),
with a validation strategy adapted from
[RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html#section-13.4.2).

## Congestion window

For maximum datagram size `MDS`, the initial and minimum windows are:

```text
initial_cwnd = min(10 * MDS, max(2 * MDS, 14,720 bytes))
minimum_cwnd = 2 * MDS
```

Every ACK-eliciting datagram is charged by its full encoded size. A normal send
is rejected when it would exceed the window. A PTO probe may temporarily
exceed the window, but its bytes remain in flight until acknowledged or
declared lost.

Slow start adds newly acknowledged bytes to the window. ACKs for packets sent
before the current recovery epoch release their accounting but do not grow the
window.

## HyStart++

HyStart++ is enabled by default for the initial slow start and may be disabled
in `CubicConfig`. Its state is scalar: two optional round minima, one inclusive
packet-number boundary, an RTT sample counter, a CSS baseline, and a CSS round
counter.

Recovery supplies at most one raw RTT sample per authenticated ACK. The
controller groups samples into packet-number rounds and uses the RFC 9406
constants:

```text
minimum delay threshold = 4 ms
maximum delay threshold = 16 ms
RTT threshold divisor   = 8
samples per decision     = 8
CSS growth divisor       = 4
maximum CSS rounds       = 5
```

A round whose minimum RTT exceeds the previous round minimum by the clamped
delay threshold enters Conservative Slow Start. CSS grows by one quarter of
newly acknowledged bytes. A sufficiently sampled CSS round below the trigger
baseline resumes standard slow start; persistent inflation across five rounds
sets `ssthresh = cwnd` and enters CUBIC. Because OGTP always paces controlled
traffic, it applies no additional per-ACK byte cap. A loss permanently ends
HyStart++ for that connection, as subsequent slow starts have a discovered
threshold.

## ECN congestion events

An ACK-preview event exposes authenticated peer counters and newly acknowledged
packet markings before any loss or acknowledgement callback. The per-path ECN
validator either disables marking or returns the validated CE-counter increase.
A non-zero increase calls `on_ecn_ce` while all pre-ACK bytes remain in flight.

CE uses the same CUBIC reduction and recovery-epoch suppression as loss, but it
does not remove a packet or recovery token. ACK callbacks that follow cannot
grow the window for packets sent before that recovery epoch. If the ACK also
declares loss, the later loss event releases bytes without applying a second
ordinary reduction.

## CUBIC profile

The controller uses:

- multiplicative decrease `beta = 7/10`;
- cubic constant `C = 2/5`;
- Reno-friendly `alpha = 9/17` below the previous window, then `alpha = 1`;
- fast convergence enabled by default.

On the first loss in a recovery epoch, the controller validates the flight
size against the current window, sets the slow-start threshold to 0.7 of that
value, and enforces the two-datagram minimum. Other packets sent before the
same recovery epoch cannot cause another ordinary reduction. Fast convergence
sets the remembered maximum to 0.85 of the current window when the current
window is below the preceding maximum.

Congestion avoidance evaluates the cubic function using Q32 fixed-point
credits and saturating `u128` intermediates. Fractional byte growth carries
across ACKs. The one-RTT target is clamped to no more than 1.5 times the current
window. Reno-friendly growth remains available below the cubic estimate.
Application-limited time is removed from the cubic epoch instead of being
mistaken for network delay.

Confirmed persistent congestion collapses the window to two maximum-sized
datagrams. The detector is deliberately separate from loss declaration: its
caller must feed every ACK-eliciting packet outcome in non-decreasing send-time
order so an acknowledged or unresolved packet can break a candidate loss run.

## Pacing

The pacer retains a single next-departure timestamp and performs no allocation.
For `bytes` scheduled against a congestion window and smoothed RTT:

```text
spacing_ns = ceil(bytes * smoothed_rtt_us * 1,000
                  / (congestion_window * pacing_gain))
```

The pacing gain is 5/4 during slow start and 1 during congestion avoidance.
The caller may schedule a single datagram or the total bytes of a UDP GSO
batch. A production runtime maps the returned absolute timestamp to its kernel
transmit mechanism; the protocol library itself neither sleeps nor owns a
timer wheel.

## Recovery event ordering

For one authenticated ACK, packet-threshold and time-threshold loss events are
delivered before acknowledgement events. This lets the controller reduce the
window before applying any eligible ACK growth. PTO backoff resets only when
the ACK newly acknowledges a tracked packet. PTO expiration requests probes;
it never calls the loss or congestion-reduction path.

## Remaining validation

The implementation still needs:

- production event-loop wiring for all persistent-congestion outcomes;
- production wiring that forwards each recovery RTT sample to HyStart++ once;
- kernel ancillary-data wiring and physical-path ECN bleaching tests;
- comparisons of fixed-point CUBIC trajectories with a high-precision model;
- kernel pacing, UDP GSO, CPU, allocation, and fairness measurements;
- a coupled controller for paths that share a bottleneck.

Until those items and the security blockers in `SPEC.md` are resolved, these
algorithms are an experimental implementation profile, not a production claim.
