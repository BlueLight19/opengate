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
- canonical, allocation-free CREDIT, COMMIT, and windowed RESUME values with
  public bit-exact CONTROL vectors;
- bounded canonical object manifests with domain-separated SHA-384 Merkle
  inputs, dual-signature envelopes, and allocation-free fragment codecs;
- fixed-pool manifest reassembly plus transactional, idempotent COMMIT and
  atomic windowed RESUME state with caller-selected range capacities;
- provider-neutral Merkle hashing with a 32-level, 1,536-byte subtree stack
  whose RAM use is independent of object size;
- fail-closed hybrid peer and manifest authentication orchestration with
  trust-anchor binding, Finished HMAC, Ed25519, and ML-DSA-65 gates;
- stateless `HELLO`/`RETRY` parsing, pre-allocation `INIT` cookie admission,
  fixed-pool handshake reassembly, and transactional transcript snapshots;
- fixed 226-byte authenticated `RETRY` cookies with complete endpoint/context
  binding, two-generation key rotation, and bounded post-cookie quotas;
- provider-neutral X25519/ML-KEM-768 exchange, complete HKDF-SHA-384 schedule,
  one-shot handshake AEAD, and authenticated application-secret type gates;
- an opt-in concrete `RustCrypto` handshake and identity provider with
  operating-system entropy, compiler-resistant secret zeroization, real
  X25519 + ML-KEM-768 exchange, strict Ed25519 + randomized ML-DSA-65
  authentication, dual-signed manifests, both negotiated AEAD suites, and a
  complete mutually authenticated encrypted `RESPONSE`/`FINISH` path;
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
- fixed-capacity linked-increases coupling for up to 16 concurrent paths, with
  integer alpha calculation and a conservative CUBIC growth cap;
- an opt-in deterministic multipath fault simulator.

This code is not production-ready and must not yet protect sensitive data.

## Documents

- [`SPEC.md`](docs/SPEC.md) — wire format and state machine;
- [`CRYPTO.md`](docs/CRYPTO.md) — transcript, hybrid key schedule, and labels;
- [`AUTHENTICATION.md`](docs/AUTHENTICATION.md) — atomic dual-signature identity
  and manifest verification contract;
- [`HANDSHAKE_STATE.md`](docs/HANDSHAKE_STATE.md) — stateless admission,
  fixed-memory reassembly, and transactional transcript state;
- [`RETRY_ADMISSION.md`](docs/RETRY_ADMISSION.md) — authenticated stateless
  cookies, rotation, expiration, and fixed post-cookie admission;
- [`HANDSHAKE_CRYPTO.md`](docs/HANDSHAKE_CRYPTO.md) — hybrid exchange, key
  schedule, Finished values, and RESPONSE/FINISH AEAD;
- [`RUSTCRYPTO_PROVIDER.md`](docs/RUSTCRYPTO_PROVIDER.md) — concrete provider
  dependencies, entropy, memory behavior, tests, and audit limitations;
- [`RUSTCRYPTO_AUTHENTICATION.md`](docs/RUSTCRYPTO_AUTHENTICATION.md) — concrete
  identity keys, signing, verification, fixed memory, and release blockers;
- [`THREAT_MODEL.md`](docs/THREAT_MODEL.md) — guarantees, adversaries, and limits;
- [`BENCHMARKS.md`](docs/BENCHMARKS.md) — RAM/CPU budgets and measurement plan;
- [`CONGESTION.md`](docs/CONGESTION.md) — CUBIC, PTO, and pacing profile;
- [`ECN.md`](docs/ECN.md) — ECN wire feedback and per-path validation;
- [`MANIFEST.md`](docs/MANIFEST.md) — signed object geometry and Merkle format;
- [`MERKLE_REDUCTION.md`](docs/MERKLE_REDUCTION.md) — fixed-memory streaming
  verification of complete object roots;
- [`TRANSFER_STATE.md`](docs/TRANSFER_STATE.md) — bounded MANIFEST, COMMIT, and
  RESUME runtime invariants;
- [`MULTIPATH.md`](docs/MULTIPATH.md) — experimental coupled path control;
- [`RECOVERY.md`](docs/RECOVERY.md) — bounded loss-recovery invariants;
- [`SIMULATION.md`](docs/SIMULATION.md) — deterministic fault-model semantics.

## Development

The default library depends only on `zeroize` so protocol-owned handshake
secrets receive compiler-resistant erasure. The concrete software provider is
opt-in:

```sh
cargo test --features rustcrypto-provider --test rustcrypto_handshake_provider
cargo test --features rustcrypto-provider --test rustcrypto_authentication_provider
cargo test --features rustcrypto-provider --test rustcrypto_authenticated_handshake
```

All feature combinations and public cryptographic vectors are checked with:

```sh
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
```

The next milestones are independent review or replacement of the concrete
post-quantum provider, official ML-DSA/ML-KEM differential vectors, complete
frozen encrypted-handshake vectors for cross-implementation testing, physical
shared-bottleneck validation, and a batched UDP runtime with ECN ancillary data
plus measured allocation/copy budgets.
