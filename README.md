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
  packets, plus fragmented long-header handshake packets.
- sender-side CREDIT accounting that enforces absolute byte and fragment
  ceilings without charging retransmissions twice.

This code is not production-ready and must not yet protect sensitive data.

## Documents

- [`SPEC.md`](docs/SPEC.md) — wire format and state machine;
- [`CRYPTO.md`](docs/CRYPTO.md) — transcript, hybrid key schedule, and labels;
- [`THREAT_MODEL.md`](docs/THREAT_MODEL.md) — guarantees, adversaries, and limits;
- [`BENCHMARKS.md`](docs/BENCHMARKS.md) — RAM/CPU budgets and measurement plan.

## Development

The initial codec has no external dependencies:

```sh
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

The next milestones are a deterministic loss/reordering simulator, an audited
cryptographic-provider interface, and packet protection test vectors.
