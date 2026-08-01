# OGTP/1 RustCrypto Handshake Provider

Status: **concrete interoperability implementation; not production-approved**.

This document specifies `src/rustcrypto_provider.rs`, enabled by the
`rustcrypto-provider` Cargo feature. The module implements the complete
`HandshakeCryptoProvider` and `ForkableSha384Provider` boundaries without
changing the OGTP wire format or key schedule.

## Scope

The adapter supplies:

- X25519 ephemeral key generation and agreement through `x25519-dalek`;
- ML-KEM-768 key generation, encapsulation, decapsulation, canonical public-key
  validation, and implicit rejection through `ml-kem`;
- SHA-384, HMAC-SHA-384, and HKDF-SHA-384;
- AES-256-GCM and ChaCha20-Poly1305 in-place handshake protection;
- forkable SHA-384 contexts for transactional transcripts;
- operating-system entropy through fallible `getrandom` calls.

It does not supply Ed25519, ML-DSA-65, packet-key installation, persistent key
storage, hardware-backed keys, or the UDP event loop.

Enable it explicitly:

```sh
cargo test --features rustcrypto-provider --test rustcrypto_handshake_provider
```

The default build keeps the protocol orchestration provider-neutral and does
not compile the KEM, curve, KDF, HMAC, or AEAD implementations.

## Entropy and deterministic ML-KEM entry point

Every X25519 private scalar, ML-KEM 64-byte seed, and ML-KEM encapsulation
random value comes from a separate fallible operating-system entropy request.
An entropy error clears the temporary buffer and terminates the handshake; no
public value or installable secret is returned.

The adapter enables the `ml-kem` `hazmat` feature only to call its deterministic
encapsulation primitive after filling all 32 input bytes directly from the
operating system. This avoids the dependency's convenience API, which wraps a
fallible system RNG in a panic-on-error adapter. The deterministic primitive is
private to this module and is never exposed through the OGTP public API.

This design performs a small fixed number of entropy syscalls per handshake.
They are outside the bulk packet path. A future per-thread DRBG may reduce
handshake latency, but it requires reseeding, fork-safety, state-erasure, and
failure-policy review before adoption.

## Memory and erasure

ML-KEM is compiled without its `alloc` feature. X25519, ML-KEM inputs and
outputs, hybrid secrets, HKDF stages, Finished values, AEAD keys, IVs, tags,
and candidate plaintexts all have compile-time sizes. No allocation depends on
a packet field or peer-controlled length.

Protocol-owned secret arrays use `zeroize`, which prevents the compiler from
removing the overwrite. The selected X25519 and ML-KEM private-key types enable
their zeroize-on-drop support. Caller-owned temporary entropy, ML-KEM
shared-secret, HKDF PRK output, and HMAC output buffers are explicitly zeroized
after use.

These measures do not prove that every backend temporary, register, kernel RNG
buffer, swap page, crash dump, hypervisor snapshot, or copied process page has
been erased. Production deployment requires platform policy and independent
review of generated code and secret lifetimes.

## Failure behavior

The provider exposes only five diagnostic classes:

- operating-system entropy unavailable;
- non-canonical ML-KEM-768 encapsulation key;
- HKDF failure;
- HMAC failure;
- AEAD backend failure.

Diagnostics never contain keys, random seeds, ciphertexts, shared secrets,
plaintext, tags, transcript hashes, or derived material. Exact-length ML-KEM
ciphertexts never produce a validity error: decapsulation returns either the
real secret or the FIPS 203 implicit-rejection secret. The subsequent handshake
AEAD is the only peer-visible validity gate.

Invalid AEAD tags map to `HandshakeAeadOpenResult::Invalid`, not a backend
failure. The provider-neutral caller owns a fixed candidate buffer and destroys
it on every invalid result, so unauthenticated plaintext is never returned.

## Validation

`tests/rustcrypto_handshake_provider.rs` checks:

- fresh initiator and responder X25519/ML-KEM-768 agreement;
- equal directional Finished values at both peers;
- complete responder and initiator authentication protection;
- AES-256-GCM and ChaCha20-Poly1305;
- byte-exact AEAD output against the published packet-protection vectors;
- ciphertext tamper rejection;
- published HKDF extract and expand stages;
- rejection of a non-canonical ML-KEM encapsulation key without output changes;
- successful implicit-rejection processing of a malformed ML-KEM ciphertext.

The provider-neutral unit tests continue to inject entropy, KEM, KDF, length,
and AEAD failures that are difficult to trigger through a real backend.

## Audit status and release blockers

This adapter is concrete, but it is not described as audited. In particular,
the selected `ml-kem` crate currently warns that it has not received an
independent audit. The adapter therefore enables interoperability testing and
measurement but does not remove the repository's production warning.

Before sensitive deployment, OGTP still requires:

- independent review of the protocol composition and this adapter;
- an independent audit of the selected ML-KEM implementation or replacement
  with an equivalently tested audited/formally verified backend;
- official known-answer tests and differential tests against an independent
  FIPS 203 implementation;
- generated-code timing and side-channel evaluation on supported targets;
- platform tests for entropy failure, fork/VM snapshot behavior, secret
  erasure, swap, crash dumps, and process termination;
- complete encrypted `RESPONSE` and `FINISH` interoperability vectors.
