# OGTP/1 Explicit Congestion Notification

Status: **draft 0.2 implementation contract**.

OGTP negotiates ECN feedback with handshake capability bit 3. The base profile
uses the IP codepoints from
[RFC 3168](https://www.rfc-editor.org/rfc/rfc3168.html), marks outgoing traffic
with ECT(0), and validates each path independently. The validation rules adapt
the deployment safeguards in
[RFC 9000 Section 13.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-13.4)
without encapsulating OGTP in QUIC.

## Authenticated ACK extension

Bit 7 of the ACK `Count and Flags` byte appends three network-order `u64`
counters in ECT(0), ECT(1), CE order. Bit 6 is reserved and zero; bits 5..0
retain the bounded additional-range count. The 24-byte trailer is inside packet
protection, so an off-path party cannot forge congestion feedback.

The receiver increments exactly one counter for each newly authenticated,
non-duplicate UDP datagram whose IP header carries ECT(0), ECT(1), or CE.
Not-ECT does not increment a counter. Counter overflow is an explicit local
error and never wraps.

## Per-path validation

A newly created negotiated path starts in `Testing` and marks at most ten
successfully submitted datagrams ECT(0). Valid feedback moves the path to
`Capable`. If ten probes have been sent without validation, marking pauses in
`Unknown` until feedback or loss resolves the probes.

For every authenticated ACK that advances the largest acknowledged packet
number, the sender verifies:

- ECN counters are present when an ECT-marked packet is newly acknowledged;
- all three cumulative counters are monotonic;
- reported ECT(0), ECT(1), and total counts do not exceed sent marked packets;
- counter increases cover the original markings of newly acknowledged packets;
- ECT(1) is zero in the base profile because OGTP sends only ECT(0).

Reordered or duplicate ACKs do not alter validation state. Missing feedback,
counter regression, impossible totals, apparent rewriting, or loss of all ten
validation probes moves the path to `Failed`. Failed and non-negotiated paths
send Not-ECT. A later revalidation policy is not part of the initial profile.

## Congestion response

A validated CE-counter increase is treated as a loss-equivalent CUBIC
congestion event. The ACK preview is delivered before loss and acknowledgement
callbacks, ensuring that ACK-driven growth cannot precede the reduction. CE
does not remove bytes from flight. Loss and CE signals from one recovery epoch
cause only one ordinary multiplicative decrease.

An authenticated peer can exaggerate CE only to reduce received throughput,
which it can already do using flow-control credits or by withholding ACKs. An
on-path attacker can set CE, drop packets, erase ECT, or add delay; transport
cryptography cannot prevent those network actions. Validation detects several
forms of suppression and rewriting and safely falls back to Not-ECT.

## Kernel contract

The protocol library does not manipulate IP headers. A production runtime must:

- set ECT(0) per outgoing datagram or GSO batch through the platform socket API;
- retain the codepoint actually submitted in `SentPacket` metadata;
- request received IPv4 and IPv6 traffic-class ancillary data;
- call the receive counter only after authentication and duplicate rejection;
- preserve path separation when batching or steering datagrams.

The opt-in Linux adapter uses per-batch `IP_TOS`/`IPV6_TCLASS` control messages
for transmission and `IP_RECVTOS`/`IPV6_RECVTCLASS` control messages for
reception. Exact behavior across kernel versions, GSO/GRO, tunnels, and
hardware offloads remains a measurement and interoperability requirement, not
a production-readiness claim.
