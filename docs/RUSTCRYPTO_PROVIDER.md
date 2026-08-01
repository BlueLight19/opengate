# OGTP/1 RustCrypto Cryptographic Provider

Status: **concrete interoperability implementation; not production-approved**.

This document specifies `src/rustcrypto_provider.rs`, enabled by the
`rustcrypto-provider` Cargo feature. The module implements the complete
`HandshakeCryptoProvider`, `ForkableSha384Provider`, and
`HybridAuthenticationProvider` boundaries without changing the OGTP wire
format or key schedule.

## Scope

The adapter supplies:

- X25519 ephemeral key generation and agreement through `x25519-dalek`;
- ML-KEM-768 key generation, encapsulation, decapsulation, canonical public-key
  validation, and implicit rejection through `ml-kem`;
- SHA-384, HMAC-SHA-384, and HKDF-SHA-384;
- AES-256-GCM and ChaCha20-Poly1305 in-place handshake protection;
- forkable SHA-384 contexts for transactional transcripts;
- strict ordinary Ed25519 signing and verification;
- randomized ordinary ML-DSA-65 signing and verification;
- non-cloneable hybrid identity keys and canonical handshake/manifest signing;
- operating-system entropy through fallible `getrandom` calls.

It does not supply packet-key installation, persistent key storage,
hardware-backed keys, or the UDP event loop. The identity implementation is
specified in
[`RUSTCRYPTO_AUTHENTICATION.md`](RUSTCRYPTO_AUTHENTICATION.md).

Enable it explicitly:

```sh
cargo test --features rustcrypto-provider --test rustcrypto_handshake_provider
cargo test --features rustcrypto-provider --test rustcrypto_authentication_provider
```

The default build keeps the protocol orchestration provider-neutral and does
not compile the KEM, curve, signature, KDF, HMAC, or AEAD implementations.

## Entropy and deterministic ML-KEM entry point

Every X25519 private scalar, ML-KEM 64-byte seed, and ML-KEM encapsulation
random value comes from a separate fallible operating-system entropy request.
An entropy error clears the temporary buffer and terminates the handshake; no
public value or installable secret is returned.

Hybrid identity generation likewise uses independent Ed25519 and ML-DSA-65
seeds. Each randomized ML-DSA-65 signature makes a fresh fallible entropy
request; an error returns no hybrid signature.

The adapter enables the `ml-kem` `hazmat` feature only to call its deterministic
encapsulation primitive after filling all 32 input bytes directly from the
operating system. This avoids the dependency's convenience API, which wraps a
fallible system RNG in a panic-on-error adapter. The deterministic primitive is
private to this module and is never exposed through the OGTP public API.

This design performs a small fixed number of entropy syscalls per identity
generation and handshake. They are outside the bulk packet path. A future
per-thread DRBG may reduce handshake latency, but it requires reseeding,
fork-safety, state-erasure, and failure-policy review before adoption.

## Memory and erasure

ML-KEM and ML-DSA are compiled without their `alloc` features. X25519, ML-KEM
inputs and outputs, identity keys and signatures, hybrid secrets, HKDF stages,
Finished values, AEAD keys, IVs, tags, and candidate plaintexts all have
compile-time sizes. No allocation depends on a packet field or peer-controlled
length.

Protocol-owned secret arrays use `zeroize`, which prevents the compiler from
removing the overwrite. The selected X25519, Ed25519, ML-KEM, and ML-DSA
private-key types enable their zeroize-on-drop support. Caller-owned temporary
entropy, ML-KEM shared-secret, HKDF PRK output, and HMAC output buffers are
explicitly zeroized after use.

These measures do not prove that every backend temporary, register, kernel RNG
buffer, swap page, crash dump, hypervisor snapshot, or copied process page has
been erased. Production deployment requires platform policy and independent
review of generated code and secret lifetimes.

## Failure behavior

The provider exposes only eight diagnostic classes:

- operating-system entropy unavailable;
- non-canonical ML-KEM-768 encapsulation key;
- HKDF failure;
- HMAC failure;
- contextualized signature input overflow;
- Ed25519 signing failure;
- randomized ML-DSA-65 signing or entropy failure;
- AEAD backend failure.

Diagnostics never contain keys, random seeds, ciphertexts, shared secrets,
plaintext, tags, transcript hashes, or derived material. Exact-length ML-KEM
ciphertexts never produce a validity error: decapsulation returns either the
real secret or the FIPS 203 implicit-rejection secret. The subsequent handshake
AEAD is the only peer-visible KEM validity gate. Malformed or invalid Finished,
Ed25519, and ML-DSA-65 values similarly map to `Invalid`, not backend failure.

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
`tests/rustcrypto_authentication_provider.rs` additionally checks real hybrid
identity authentication, randomized signing, strict Ed25519 validation,
malformed ML-DSA rejection, dual-signed manifests, an RFC 8032 vector, and
fixed identity-memory bounds. See
[`RUSTCRYPTO_AUTHENTICATION.md`](RUSTCRYPTO_AUTHENTICATION.md) for the exact
authentication validation and remaining blockers.

## Audit status and release blockers

This adapter is concrete, but it is not described as audited. In particular,
the selected `ml-kem` and `ml-dsa` crates currently warn that they have not
received an independent audit. The adapter therefore enables interoperability
testing and measurement but does not remove the repository's production
warning.

Before sensitive deployment, OGTP still requires:

- independent review of the protocol composition and this adapter;
- an independent audit of the selected ML-KEM and ML-DSA implementations or
  replacement with equivalently tested audited/formally verified backends;
- official known-answer tests and differential tests against independent
  FIPS 203 and FIPS 204 implementations;
- generated-code timing and side-channel evaluation on supported targets;
- platform tests for entropy failure, fork/VM snapshot behavior, secret
  erasure, swap, crash dumps, and process termination;
- complete encrypted `RESPONSE` and `FINISH` interoperability vectors.
