# OGTP/1 Hybrid Authentication Orchestration

Status: **draft 0.2 implementation contract; external provider required**.

This document specifies the fail-closed orchestration in
`src/authentication.rs`. The library fixes inputs, validation order, trust
binding, and atomic installation. It does not implement or claim to audit
SHA-384, HMAC-SHA-384, Ed25519, or ML-DSA-65.

Reproducible identity-fingerprint, contextualized-signature-input, and
Finished-HMAC vectors are published in
[`authentication-v1.txt`](../test-vectors/authentication-v1.txt).

## Provider interfaces

`Sha384Provider` is shared by authentication, transcript, and Merkle code. It
creates a streaming context implementing `TranscriptSink` and finalizes exactly
48 digest bytes. `HybridAuthenticationProvider` adds:

- constant-time HMAC-SHA-384 Finished verification;
- ordinary Ed25519 verification, not Ed25519ph;
- ordinary ML-DSA-65 verification;
- a distinct `Valid` or `Invalid` result separate from internal provider
  failure.

Public-key and signature sizes are present in the Rust method types. A provider
must still reject non-canonical encodings, invalid points or keys, algorithm
misuse, and backend failures according to the applicable standards. It must
not accept a signature after an internal error.

The default library has no concrete provider or cryptographic dependency. A
production adapter requires independent review, constant-time analysis, known-
answer tests, and version pinning.

## Required preconditions

`authenticate_peer_identity` receives a decrypted, canonically decoded
`IdentityAuth` and a `PeerAuthenticationContext`. Before the call, the
handshake state machine must have:

1. validated the RETRY cookie and amplification limit where applicable;
2. reassembled the logical handshake message in a fixed buffer;
3. authenticated and decrypted its AEAD ciphertext;
4. constructed the exact named transcript snapshots from `CRYPTO.md`;
5. derived the direction- and role-correct Finished key;
6. loaded an out-of-band trust-anchor fingerprint.

The orchestration cannot prove that caller-supplied transcript hashes or keys
came from the correct state-machine epoch. They are grouped in one borrowed
`PeerAuthenticationContext` to reduce accidental role or snapshot mixing.
Its `Debug` representation redacts both hashes, the Finished key, and
fingerprints.

## Fail-closed verification order

The function performs these checks in a fixed order:

1. compute `SHA-384("OGTP/1 identity\x00" || Ed25519PK || ML-DSA-65PK)`;
2. compare it with the fingerprint announced earlier on the wire;
3. compare it with the out-of-band trust anchor;
4. verify the Finished HMAC over the correct transcript snapshot;
5. verify Ed25519 over the contextualized signature input;
6. verify ML-DSA-65 over the identical input;
7. copy the two public keys into fixed-size authenticated identity state.

Fingerprint comparisons inspect all 48 bytes. Fingerprints are public identity
claims; the provider remains responsible for constant-time Finished comparison.

This order rejects accidental or malicious key substitution before signature
work. Finished HMAC proves possession of the handshake secret before either
public-key verification, and the cheaper Ed25519 check precedes ML-DSA-65. It
therefore reduces post-cookie cryptographic CPU exposure without weakening the
requirement that all authenticators succeed.

An invalid authenticator and a provider malfunction are separate errors. No
`AuthenticatedIdentity` value exists on either path. The returned identity owns
one fixed 32-byte Ed25519 key, one fixed 1,952-byte ML-DSA-65 key, and the
48-byte trust-bound fingerprint; it has no heap-backed key collection.

## Manifest authentication

`verify_manifest` requires an `AuthenticatedIdentity` capability and a
canonical decoded manifest. It:

1. compares the signed manifest fingerprint with the authenticated peer;
2. streams the canonical unsigned manifest through SHA-384;
3. constructs `64 * 0x20 || "OGTP/1 object manifest" || 0x00 || hash` in a
   fixed 192-byte stack buffer;
4. verifies Ed25519, then ML-DSA-65, over the same bytes;
5. returns `VerifiedManifest` only after both succeed.

`VerifiedManifest` is the capability used to install object geometry,
transfer-control state, and a Merkle reducer. Its debug output exposes geometry
but redacts object identity, signer identity, and root. A signer mismatch is
rejected before hashing or signature verification, and an invalid Ed25519
signature prevents the more expensive ML-DSA operation.

Canonical manifest decoding alone never creates this token. A failed manifest
also invalidates every RESUME claim associated with its proposed object slot.

## Fixed memory and logging

Contextualized signature messages are at most 192 bytes and are assembled in a
fixed stack buffer because ordinary Ed25519 and ML-DSA provider APIs generally
consume a contiguous message. Public keys are copied only once after complete
handshake authentication. There is no per-verification heap allocation in the
orchestration layer.

`Debug` output for authentication contexts, installed identities, and verified
manifests is explicitly redacted. Provider errors are still provider-owned;
adapters must ensure their error values never include keys, MACs, plaintext,
complete transcript hashes, or global object hashes.

## Tests and remaining production work

Deterministic tests cover independent fingerprint reproduction, exact
contextual separation, successful atomic installation, every invalid-result
short circuit, provider failures distinct from invalid authenticators,
manifest signer binding, dual manifest signatures, and debug redaction.

Production work still includes a concrete audited provider, real Ed25519 and
ML-DSA-65 known-answer and negative vectors, full encrypted-handshake vectors,
transcript-snapshot state integration, key erasure, stateful fuzzing, and
cryptographic CPU benchmarking under invalid authenticated traffic.
