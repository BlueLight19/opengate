# OGTP/1 Hybrid Authentication Orchestration

Status: **draft 0.2 implementation contract; optional concrete provider
available for interoperability**.

This document specifies the fail-closed orchestration in
`src/authentication.rs`. The library fixes inputs, validation order, trust
binding, and atomic installation. The orchestration does not implement or
claim to audit SHA-384, HMAC-SHA-384, Ed25519, or ML-DSA-65. The optional
`rustcrypto-provider` feature implements this boundary as an interoperability
and review target; it is specified in
[`RUSTCRYPTO_AUTHENTICATION.md`](RUSTCRYPTO_AUTHENTICATION.md).

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

The default library has no concrete authentication provider. The optional
RustCrypto adapter has explicit dependency versions, real end-to-end tests,
strict Ed25519 verification, randomized ML-DSA-65 signing, and fixed-size key
state. It remains non-production because its ML-DSA dependency is not
independently audited and complete FIPS 204 differential coverage is pending.

## Required preconditions

`authenticate_peer_identity` receives a decrypted, canonically decoded
`IdentityAuth` and a `PeerAuthenticationContext`. Before the call, the
handshake state machine must have:

1. validated the RETRY cookie and amplification limit where applicable;
2. reassembled the logical handshake message in a fixed buffer;
3. authenticated and decrypted its AEAD ciphertext through the role-specific
   fixed-candidate contract in
   [`HANDSHAKE_CRYPTO.md`](HANDSHAKE_CRYPTO.md);
4. obtained the exact named transcript snapshots from the transactional state
   in [`HANDSHAKE_STATE.md`](HANDSHAKE_STATE.md);
5. derived the direction- and role-correct Finished key;
6. loaded an out-of-band trust-anchor fingerprint.

The handshake state now constructs snapshots in canonical order and rolls back
provider failures, but the authentication function still cannot prove that the
caller paired them with the correct role-specific Finished key. The values are
grouped in one borrowed `PeerAuthenticationContext` to reduce accidental role
or epoch mixing. Its `Debug` representation redacts both hashes, the Finished
key, and fingerprints.

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
manifests is explicitly redacted. The borrowed `RETRY`, `INIT`, `RESPONSE`,
`FINISH`, and `IdentityAuth` codec values also use redacted `Debug`
implementations. Provider errors are still provider-owned; adapters must ensure
their error values never include keys, MACs, plaintext, complete transcript
hashes, or global object hashes.

Application traffic secrets cannot be derived through the public API from
AEAD success alone. The crypto schedule additionally requires the resulting
`AuthenticatedIdentity` and the completed transcript milestone.

## Tests and remaining production work

Provider-neutral deterministic tests cover independent fingerprint
reproduction, exact contextual separation, successful atomic installation,
every invalid-result short circuit, provider failures distinct from invalid
authenticators, manifest signer binding, dual manifest signatures, and debug
redaction.

The feature-gated concrete tests additionally cover real hybrid handshake and
manifest signatures, independent Finished/Ed25519/ML-DSA tampering, weak
Ed25519 keys, malformed ML-DSA signatures, the RFC 8032 empty-message vector,
entropy-backed key generation, fixed identity-memory bounds, and a complete
mutually authenticated encrypted `RESPONSE`/`FINISH` exchange with independent
peer transcripts and equal application secrets for both cipher suites.
The frozen encrypted-handshake vector adds reproducible deterministic ML-DSA
signatures, exact signature/plaintext/ciphertext digests, and every Finished
input/output needed by an independent consumer. Production signing remains
randomized.

Production work still includes an audited ML-DSA provider or audited
replacement, official FIPS 204 known-answer and differential vectors, full
independent consumption of the published encrypted-handshake vector, UDP event-
loop integration around the implemented transcript and sender state, platform
key-erasure tests, stateful fuzzing, and cryptographic CPU/stack benchmarking
under invalid authenticated traffic.
