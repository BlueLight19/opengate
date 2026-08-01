# OGTP — OpenGate Transfer Protocol

OGTP is an experimental peer-to-peer transport built directly on UDP for
reliable transfer of large objects. It targets an unordered, multipath,
end-to-end encrypted data path with strictly bounded memory use.

OGTP is not layered on QUIC. The project still reuses standardized
cryptographic primitives and proven networking principles. It does not define
new cryptographic algorithms.

## Project status

The current `0.2` version is an early design and codec milestone:

- a working OGTP/1 specification;
- a threat model;
- reproducible performance targets;
- allocation-free Rust codecs for short-header DATA, ACK, CONTROL, and PROBE
  packets, plus fragmented long-header handshake packets;
- sender-side CREDIT accounting that enforces absolute byte and fragment
  ceilings without charging retransmissions twice;
- canonical handshake, transcript, and HKDF serializers;
- provider-neutral in-place packet-protection orchestration with enforced AEAD
  usage limits;
- reproducible AES-256-GCM and ChaCha20-Poly1305 packet vectors;
- fixed-capacity sent-packet recovery with integer RTT estimation, ACK-driven
  loss detection, and deterministic multipath reinjection selection;
- bounded PTO and persistent-congestion state, byte-counted CUBIC, and a
  nanosecond integer pacer for each path;
- allocation-free HyStart++ with Conservative Slow Start and packet-number
  round tracking;
- negotiated per-path ECN probing, authenticated cumulative feedback, strict
  validation, and loss-equivalent CUBIC response;
- an opt-in deterministic multipath fault simulator.

This code is not production-ready and must not yet protect sensitive data.

## Documents

- [`SPEC.md`](docs/SPEC.md) — wire format and state machine;
- [`CRYPTO.md`](docs/CRYPTO.md) — transcript, hybrid key schedule, and labels;
- [`THREAT_MODEL.md`](docs/THREAT_MODEL.md) — guarantees, adversaries, and limits;
- [`BENCHMARKS.md`](docs/BENCHMARKS.md) — RAM/CPU budgets and measurement plan;
- [`CONGESTION.md`](docs/CONGESTION.md) — CUBIC, PTO, and pacing profile;
- [`ECN.md`](docs/ECN.md) — ECN wire feedback and per-path validation;
- [`RECOVERY.md`](docs/RECOVERY.md) — bounded loss-recovery invariants;
- [`SIMULATION.md`](docs/SIMULATION.md) — deterministic fault-model semantics.

## Development

The default library has no external dependencies. Development-only RustCrypto
packages reproduce the public cryptographic vectors:

```sh
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
```

The next milestones are coupled multipath control, an audited cryptographic
provider adapter, and a batched UDP runtime with ECN ancillary data plus
measured allocation/copy budgets.
