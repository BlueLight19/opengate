# OGTP/1 Stateless RETRY Cookies and Admission

Status: **draft 0.2 implementation contract; external AEAD provider required**.

This document specifies the server-local authenticated-cookie and bounded
post-cookie admission code in `src/retry.rs`. Peers continue to treat the
cookie as opaque. The format is therefore not an interoperability requirement,
but every deployment using this implementation must preserve the same format,
policy, and opening keys across the intended validation cluster.

## Security boundary

The cookie prevents spoofed-source traffic from allocating handshake
reassembly state or triggering X25519, ML-KEM, Ed25519, or ML-DSA work. It is
not peer authentication and is replayable until expiration. A valid cookie
therefore passes only the first admission gate; fixed global/source quotas and
the handshake deadline remain mandatory.

`RetryCookieProvider` supplies:

- SHA-384 for hashing the canonical `HELLO`;
- an audited AEAD with a 256-bit or stronger key, 96-bit nonce, and 128-bit tag;
- a distinct invalid-tag result separate from provider failure.

AES-256-GCM and ChaCha20-Poly1305 satisfy the size profile. The provider owns
key storage and constant-time authentication. The orchestration contains no
custom encryption algorithm and the default library contains no concrete key.

All token-validation errors must produce the same silent network behavior.
Detailed error variants exist for local metrics and tests only; they must not
be reflected to the sender as distinguishable responses.

## Fixed cookie format

The implementation emits exactly 226 bytes, within the protocol's opaque
16..256-byte cookie envelope:

```text
Format u8=1 | Key ID u32 | Nonce[12]
            | Encrypted Plaintext[193] | AEAD Tag[16]
```

AEAD additional data is:

```text
"OGTP/1 retry cookie\x00" || Format || Key ID || Nonce
```

The canonical 193-byte plaintext is:

```text
Issued At u64 | Expires At u64 | Address Family u8
Address[16] | Source Port u16 | OGTP Version u32
Initiator CID Length u8 | Initiator CID[20]
Responder CID Length u8 | Responder CID[20]
Client Random[32] | Server Random[32] | HELLO Hash[48]
```

Timestamps are unsigned Unix seconds in network byte order. Address family is
4 or 6. IPv4 occupies the first four address bytes and the remaining twelve
bytes must be zero. Connection IDs use zero-padded 20-byte fields; non-zero
padding or a length above 20 is rejected. Source port zero is rejected.

`HELLO Hash` is SHA-384 over the exact canonical 90-byte `HELLO`. The separate
client random is intentionally redundant: it makes the mandatory random
binding explicit while the hash binds cipher offers, capabilities, transport
limits, identity fingerprint, and reserved-byte canonicalization.

The complete outer header is authenticated. Changing the format, key ID, or
nonce therefore invalidates the tag. Validation copies the bounded ciphertext
to candidate storage, opens it there, validates every canonical field and
binding, and returns `ValidatedRetryCookie` only after all checks succeed.
Candidate plaintext is overwritten before return.

The size is also an amplification invariant. The smallest valid long-header
`HELLO` UDP payload is 107 bytes. Even a `RETRY` using two maximum 20-byte CIDs
is 317 bytes, below `3 * 107 = 321`. The runtime must still count traffic and
must never emit multiple pre-validation responses for one received `HELLO`.

## Time policy

`RetryCookiePolicy` fixes one non-zero lifetime and a maximum future-clock skew.
The skew cannot exceed the lifetime. Issuance computes:

```text
Expires At = Issued At + Lifetime
```

Overflow is rejected. Validation requires the identical lifetime, rejects an
issue time later than `now + skew`, and rejects the cookie exactly when
`now >= Expires At`. Expiration never receives a grace period.

The validated capability also records its local validation time. The admission
table rejects it if the supplied clock moves backward before admission, as well
as when it reaches expiry. Deployments still need an explicit wall-clock versus
monotonic-clock policy for rotation, validation, and handshake deadlines.

Changing the lifetime immediately invalidates outstanding cookies. Clustered
responders must therefore deploy policy changes only after the previous cookie
generation has drained, or coordinate the change with a wire-format/key
generation transition.

## Nonce and key rotation

Each `RetryCookieKey` contains an opaque provider key, public key ID, unique
eight-byte nonce scope, monotonic 32-bit counter, and three timestamps:

```text
Activate At < Seal Until <= Accept Until
```

The nonce is `Scope[8] || Counter u32`. The counter is reserved before the
provider call and is never rolled back after failure, preventing ambiguous
nonce reuse. Counter exhaustion stops issuance and therefore requires rotation
before 2^32 attempts. The scope need not be secret, but it must be globally
unique among all sealing processes and boots sharing a key. The caller must not
clone key-ring state and must install a new scope or key after restoring a
process snapshot. A cluster may share opening keys only if nonce scopes are
coordinated without collision.

The fixed key ring retains an active sealing key and at most one previous
opening key. Rotation is permitted only when:

- the active key has reached `Seal Until`;
- the next key is currently inside its sealing interval;
- the key ID is distinct;
- any older previous key has reached `Accept Until`.

An issued cookie must expire no later than its key's `Accept Until`. Validation
also proves that its embedded issue/expiry timestamps fall within the selected
key schedule. These rules prevent a retired key from minting apparently fresh
cookies after its sealing interval.

Dropping a key invokes its Rust destructor but does not by itself guarantee
physical erasure. Provider key types require audited zeroization or opaque
hardware-handle destruction.

## Fixed post-cookie admission

`HandshakeAdmissionTable<SLOTS>` contains exactly `SLOTS` preallocated metadata
entries. It performs a bounded linear scan; no address, CID, or token controls
an allocation. Configuration fixes a non-zero global capacity, per-source
limit, and handshake timeout.

The source quota uses an exact IPv4 address or an IPv6 `/64` prefix. This makes
trivial IPv6 interface-identifier rotation consume the same quota. Distributed
addresses and prefixes remain a residual DDoS risk and require upstream
rate-limiting. The socket adapter must normalize IPv4-mapped IPv6 addresses to
the IPv4 representation before cookie issuance and validation so one source
cannot occupy both quota namespaces.

An admission identity binds endpoint, version, both CIDs, server random, and
canonical `HELLO` hash. Replaying the same context returns the existing lease
without increasing counts. A changed handshake context is a new admission even
when its CIDs are reused.

The table sweeps expired deadlines before every admission. A new entry returns
an opaque generation-tagged `HandshakeAdmissionLease`; this lease is required
by `ReassemblyAdmission::CookieValidated` before `INIT` can reserve its fixed
16 KiB reassembly slot. Duplicate or stale release calls cannot clear a reused
slot.

The table and the reassembly arena must share the same ownership boundary. A
runtime must not retain or use a copied lease after releasing it or after its
deadline expires. The lease is an unforgeable external API capability, not a
revocable reference.

## Event-loop order

The responder processes a new `INIT` in this order:

1. parse fragment zero with `decode_init_admission_prefix`;
2. rebuild `RetryCookieBinding` from the observed source, packet CIDs, decoded
   `HELLO`, and server random;
3. authenticate and validate the cookie;
4. admit the returned capability under fixed global and normalized-source
   quotas;
5. allocate or find the connection-local reassembly owner represented by the
   admission lease;
6. ingest `INIT` fragments using that lease;
7. release admission and reassembly state on completion, failure, or deadline.

Cookie validation must remain before X25519/ML-KEM work. It performs one AEAD
open and, only after a valid tag, one SHA-384 hash of the 90-byte `HELLO`.

## Validation and remaining work

Deterministic tests cover complete binding, ciphertext/header tampering, future
issue times, strict expiration, policy mismatch, provider failures, provider
length violations, nonce consumption after failure, two-generation rotation,
idempotent admission, global and per-source exhaustion, IPv6 `/64` grouping,
stale release, deadlines, configuration errors, and diagnostic redaction.

Production work still includes:

- audited AES-256-GCM or ChaCha20-Poly1305 and SHA-384 provider adapters;
- secure key provisioning, zeroization, rotation scheduling, and snapshot
  recovery;
- a monotonic/wall-clock policy suitable for the deployment topology;
- event-loop wiring that couples each lease to exactly one preallocated
  reassembly owner;
- 3x amplification accounting before address validation;
- distributed rate limits and CPU benchmarks under valid-cookie floods;
- stateful fuzzing of token parsing, time boundaries, rotation, and lease
  lifecycle.
