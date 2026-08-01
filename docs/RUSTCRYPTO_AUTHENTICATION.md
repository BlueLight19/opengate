# OGTP/1 RustCrypto Hybrid Authentication

Status: **concrete interoperability implementation; not production-approved**.

This document specifies the identity-key and authentication portion of
`src/rustcrypto_provider.rs`, enabled by the `rustcrypto-provider` Cargo
feature. It implements the provider-neutral contract in
[`AUTHENTICATION.md`](AUTHENTICATION.md) with Ed25519, ML-DSA-65, SHA-384, and
HMAC-SHA-384.

The implementation is an interoperability and review target. In particular,
the selected RustCrypto `ml-dsa` implementation currently states that it has
not received an independent audit. Enabling this feature does not qualify OGTP
for sensitive or production deployment.

## Algorithms and dependency profile

The concrete profile uses:

- `ed25519-dalek` 3.0 with precomputed verification tables and private-key
  zeroization;
- `ml-dsa` 0.1.1 with the FIPS 204 ML-DSA-65 parameter set, randomized
  signing, private-key zeroization, and no `alloc` feature;
- RustCrypto SHA-384 and HMAC-SHA-384;
- fallible operating-system entropy through `getrandom`.

Ed25519 uses its ordinary RFC 8032 mode, not Ed25519ph. Verification calls
`verify_strict`, which rejects weak public keys and signature malleability
accepted by more permissive verification modes.

ML-DSA-65 also uses its ordinary mode with an empty FIPS 204 context because
OGTP performs protocol domain separation in the exact signed message. Signing
uses the randomized FIPS 204 variant. Every signature requests fresh 32-byte
randomness from the operating system, and failure is returned to the caller.
Verification decodes the complete fixed-size signature before running the
verification equation. A malformed key or signature is `Invalid`, not a
provider malfunction.

Finished verification uses the HMAC implementation's constant-time tag
verification operation. Invalid Finished, Ed25519, and ML-DSA-65 values remain
separate from provider errors so the orchestration cannot accept an
authenticator after an internal failure.

## Sender identity API

`RustCryptoIdentityKeyPair` owns one Ed25519 signing key and one expanded
ML-DSA-65 signing key. It is deliberately non-cloneable and its `Debug`
implementation reveals no key material.

Two construction paths exist:

- `generate` obtains two independent 32-byte seeds from the operating system;
- `from_seed_bytes` reconstructs both algorithms from caller-supplied seeds
  for persistent-key loading and reproducible tests.

The second path never takes ownership of the source buffers. The caller must
protect and erase them. The OGTP wrapper intentionally provides no private-seed
export operation.

Only public identity material is exposed:

- the 32-byte Ed25519 public key;
- the 1,952-byte ML-DSA-65 public key;
- the canonical 48-byte hybrid identity fingerprint.

The wrapper provides two high-level signing operations:

- `sign_handshake(role, transcript_hash)` signs the role-specific canonical
  handshake authentication message;
- `sign_manifest(unsigned_manifest)` hashes and signs the exact canonical
  unsigned manifest.

There is no public raw-message signing operation. This reduces the chance that
an application omits the OGTP context, signs a transcript at the wrong
milestone, or signs a manifest serialization different from the one verified
by the receiver. Both operations return one fixed-size
`RustCryptoHybridSignature` containing the 64-byte Ed25519 and 3,309-byte
ML-DSA-65 values.

Two still higher-level sender operations remove the remaining transcript/AEAD
assembly hazard:

- `seal_responder_authenticated_identity` constructs and seals the responder
  block and advances the sender transcript to initiator authentication;
- `seal_initiator_authenticated_identity` constructs and seals the initiator
  block and advances the sender transcript to complete.

Both obtain the role and signature milestone from `HandshakeTranscript`, sign
the canonical contextualized hash, append only the signed content to a
candidate transcript, compute Finished over the resulting snapshot, seal the
complete fixed plaintext with the same role-correct AAD, and commit the exact
Finished bytes. The application does not provide raw signature or Finished
hashes to these operations.

## Memory and secret lifetime

The selected Ed25519 and ML-DSA configurations do not require heap allocation.
The ML-DSA expanded private key remains resident in the identity object to
avoid expensive expansion for every handshake and manifest. This trades a
larger, constant control-plane identity object for lower repeated CPU cost.

The integration test enforces a 96 KiB compile-time upper bound on
`RustCryptoIdentityKeyPair` and an exact 3,373-byte hybrid-signature size. These
are control-plane values independent of object size, datagram length, path
count, or attacker-controlled fields. Temporary signing stack usage still
requires target-specific measurement before production deployment.

Both dependency private-key types enable zeroize-on-drop support. Generation
seeds use `Zeroizing` buffers. These measures do not prove erasure of compiler,
backend, register, kernel RNG, crash-dump, swap, VM snapshot, or copied process
state. Platform hardening and generated-code review remain required.

## Failure behavior

Canonical signing can return only:

- operating-system entropy unavailable during identity generation;
- contextualized signature input overflow;
- Ed25519 signing failure;
- randomized ML-DSA-65 signing or entropy failure.

The authenticated sender wrappers can additionally return transcript-stage,
transcript-provider, Finished, output-length, or AEAD failures. They preflight
the complete output length and clear the fixed ciphertext region on all later
errors. Transcript preparation is rollback-safe until commit. If sealing has
already succeeded and the final transcript snapshot fails, that handshake is
terminal because retrying would reuse a reserved AEAD nonce.

Verification maps peer-controlled malformed values to
`VerificationResult::Invalid`. Provider errors never contain key material,
signatures, MACs, transcript hashes, manifest hashes, or entropy bytes.

No `AuthenticatedIdentity` or `VerifiedManifest` capability is created until
the provider-neutral orchestration has accepted every required fingerprint,
Finished, and signature check.

## Validation

`tests/rustcrypto_authentication_provider.rs` checks:

- real Ed25519 + randomized ML-DSA-65 handshake authentication;
- atomic installation of the authenticated hybrid identity;
- independent rejection of tampered Finished, Ed25519, and ML-DSA-65 values;
- trust-anchor rejection before signature verification;
- strict rejection of a weak Ed25519 public key;
- malformed ML-DSA-65 signature rejection without a provider failure;
- real dual-signature manifest creation and verification;
- independent rejection of each tampered manifest signature;
- the RFC 8032 Ed25519 empty-message known-answer vector;
- entropy-backed identity generation and fixed-size memory bounds.

`tests/rustcrypto_authenticated_handshake.rs` additionally performs a complete
mutual wire exchange for AES-256-GCM and ChaCha20-Poly1305. It uses real
X25519/ML-KEM-768, real Ed25519/randomized ML-DSA-65 identities, independent
transcript states, encrypted `RESPONSE` and `FINISH`, both trust checks, both
Finished checks, and equal application-secret derivation.

Run the concrete authentication suite with:

```sh
cargo test --features rustcrypto-provider \
  --test rustcrypto_authentication_provider
cargo test --features rustcrypto-provider \
  --test rustcrypto_authenticated_handshake
```

## Release blockers

Before sensitive deployment, this adapter still requires:

- independent cryptographic and implementation review;
- an independent audit of the selected ML-DSA implementation or replacement
  with an equivalently tested audited or formally verified backend;
- official FIPS 204 ML-DSA-65 known-answer vectors and differential tests
  against an independent implementation;
- frozen encrypted `RESPONSE` and `FINISH` vectors for independent
  cross-implementation consumption (the live randomized end-to-end path is
  already tested);
- target-specific signing and verification latency, peak-stack, timing, and
  side-channel measurements;
- fault-injection tests for entropy failure, process fork, VM snapshot and
  restore, abnormal termination, and secret erasure;
- integration with audited persistent-key storage or hardware-backed identity
  keys where the deployment requires them.
