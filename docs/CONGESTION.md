# OGTP/1 Congestion Control and Pacing

Status: **draft 0.2 implementation contract**.

OGTP uses a per-path, byte-counted CUBIC controller and a scalar nanosecond
pacer. These mechanisms are implemented directly for OGTP datagrams; OGTP is
not encapsulated in QUIC. The control laws follow
[RFC 9438](https://www.rfc-editor.org/rfc/rfc9438.html), while the recovery
timer and persistent-congestion rules follow
[RFC 9002](https://www.rfc-editor.org/rfc/rfc9002.html).

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

- HyStart++ or an equivalently measured slow-start exit;
- ECN negotiation, validation, and congestion response;
- production event-loop wiring for all persistent-congestion outcomes;
- comparisons of fixed-point CUBIC trajectories with a high-precision model;
- kernel pacing, UDP GSO, CPU, allocation, and fairness measurements;
- a coupled controller for paths that share a bottleneck.

Until those items and the security blockers in `SPEC.md` are resolved, these
algorithms are an experimental implementation profile, not a production claim.
