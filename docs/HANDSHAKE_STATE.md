# OGTP/1 Bounded Handshake Receive State

Status: **draft 0.2 implementation contract; runtime integration required**.

This document specifies the bounded receive and transcript state implemented in
`src/handshake_state.rs`. It covers stateless admission, fixed-capacity
fragment reassembly, canonical transcript transitions, and failure semantics.
Cookie authentication and the fixed post-cookie quota table are implemented by
[`RETRY_ADMISSION.md`](RETRY_ADMISSION.md). This layer does not perform hybrid
key exchange, handshake AEAD opening, peer authentication, retransmission, or
timeout scheduling.

## Resource model

`HELLO`, `RETRY`, and `VERSION_NEGOTIATION` are decoded directly from one
complete datagram. They never reserve a reassembly slot. A fragmented or empty
stateless message is rejected.

`HandshakeReassembler<SLOTS>` owns exactly `SLOTS` compile-time slots. Each
slot contains:

- one 16,384-byte logical-message buffer;
- one 2,048-byte receipt bitmap, with one bit per possible message byte;
- fixed metadata for version, Connection IDs, message type, message ID, length,
  and received-byte accounting.

One slot is therefore less than 20 KiB, including metadata. Pool memory is
independent of attacker-declared lengths and never grows at runtime. The owner
chooses `SLOTS` from an explicit post-cookie connection and global memory
budget. A reassembler is connection-local or admission-owner-local; it must not
be shared as a global namespace among unrelated Connection ID pairs because
the public completion key is only `(packet type, message ID)`.

The structure may be embedded in preallocated connection storage or another
fixed arena. Implementations must account for its complete size before
admitting a connection and must avoid accidentally copying the structure.

## Stateless INIT admission

The responder first receives fragment zero of `INIT` and calls
`decode_init_admission_prefix`. The fragment must contain:

```text
Canonical HELLO[90] | Server Random[32] | Cookie Length u16
                    | Complete Cookie[16..256]
```

The decoder validates the long-packet bounds, canonical `HELLO`, cookie bounds,
and the exact declared logical length of `1,340 + Cookie Length`. It returns a
borrowed cookie view without allocating a slot. The runtime authenticates the
cookie, checks expiry and address/CID bindings, and applies fixed global/source
quotas. The quota table returns an opaque `HandshakeAdmissionLease`; only
`CookieValidated(lease)` may admit `INIT` to reassembly.

External callers cannot construct the lease fields. The runtime must still
couple each live lease to exactly one preallocated reassembly owner and stop
using it after release or deadline expiration.

`RESPONSE` and `FINISH` require `ExistingHandshake`, meaning that the receiving
connection already owns the corresponding expected state. The pool accepts
only these exact logical lengths:

| Message | Accepted logical length |
|---|---:|
| `INIT` | 1,356..1,596 bytes |
| `RESPONSE` | 6,601 bytes |
| `FINISH` | 5,423 bytes |

## Reassembly rules

Every admitted fragment is checked before slot lookup or mutation:

1. both Connection IDs are at most 20 bytes;
2. the declared message is at most 16 KiB and has the exact type-specific
   length;
3. the fragment is non-empty;
4. `Fragment Offset + Fragment Length` is checked and does not exceed the
   logical length;
5. the admission marker matches the message type.

Fragments may arrive out of order. An identical overlap is idempotent and does
not increase received-byte accounting. Any overlap containing a different byte
clears the affected slot and returns `ConflictingOverlap`. A version, logical
length, or Connection ID change for an existing local `(type, message ID)` also
clears the slot. This fail-closed behavior prevents a message assembled from
two metadata contexts.

The receiver may borrow a completed message only after every receipt bit in the
declared range has been set. It must decode the exact logical message before
use, then call `release` promptly. Release overwrites the Rust-owned arrays and
returns the slot to the pool. Production secret-erasure guarantees still
require compiler- and platform-appropriate audited handling; the reassembly
buffers currently contain public handshake material or ciphertext, not opened
identity plaintext.

`Debug` output for the pool and completed-message view redacts buffer contents
and Connection IDs. Admission views redact the cookie and server random. Raw
handshake codec values must likewise never be logged by the runtime.

Pool exhaustion rejects the new logical message and preserves existing slots.
The library does not choose eviction victims. The runtime owns absolute
deadlines, per-source quotas, global admission limits, and cleanup on connection
failure. Incomplete slots must never survive their handshake deadline.

## Transactional transcript

`HandshakeTranscript` enforces this canonical order:

```text
SessionContext -> HELLO -> RETRY -> INIT -> RESPONSE prefix
               -> responder auth content -> responder Finished
               -> initiator auth content -> initiator Finished
```

It validates exact logical encodings before hashing. `INIT` must repeat the
stored `HELLO`, `RETRY` server random, and cookie. `RESPONSE` must select an
offered cipher, negotiate only known offered capabilities, and never increase
the offered UDP payload or path limits. Cookie state is overwritten after a
valid `INIT`, and the retained `HELLO` is dropped after a valid `RESPONSE`.

The transcript uses `ForkableSha384Provider`. Each transition forks the running
SHA-384 context, updates the candidate, obtains every required snapshot, and
only then replaces the live context. Decode, consistency, framing, fork, and
snapshot failures leave the stage and live hash unchanged.

The state returns the exact named hashes required by `CRYPTO.md`:

- `record_response`: `TH_pre_auth` / responder signature hash;
- `record_responder_auth`: responder Finished hash and initiator signature
  hash;
- `record_initiator_auth`: initiator Finished hash and `TH_full`.

Hash-bearing result values and transcript `Debug` output are redacted.

Authentication plaintext must be supplied only after successful AEAD opening.
The transcript layer validates its fixed canonical shape but does not verify
Finished, Ed25519, ML-DSA-65, or trust anchors. The runtime passes the returned
snapshots to the authentication orchestration in `AUTHENTICATION.md`. If peer
authentication fails after a transcript transition, it must discard the whole
handshake and must not process the next transition.

## Error and event-loop contract

The event loop processes a received handshake fragment in this order:

1. decode the long header and enforce datagram bounds;
2. handle stateless messages directly, or parse and authenticate the `INIT`
   admission prefix;
3. reserve/use an admitted fixed reassembly slot;
4. after completion, decode the exact logical message;
5. perform hybrid key exchange or AEAD opening as required;
6. advance a candidate transcript and obtain the required snapshots;
7. perform Finished and dual-signature authentication;
8. install authenticated connection state only after every gate succeeds;
9. release the reassembly slot on both success and terminal failure.

No error authorizes partially decoded fields, plaintext, transcript state, or
identity state to become active. Provider failures are terminal for the current
handshake even though the low-level transcript object remains transactionally
unchanged for deterministic testing.

## Validation and remaining work

Deterministic tests cover stateless decoding, pre-allocation cookie extraction,
out-of-order completion, duplicate fragments, conflicting overlaps, metadata
changes, admission errors, invalid manually constructed packet bounds,
Connection ID limits, pool exhaustion, independent transcript reproduction,
negotiation failures, and provider failures during both updates and snapshots.

Production work still includes:

- concrete hybrid KEM, AEAD, and authentication integration;
- lease/reassembly ownership and deadline wiring in the UDP runtime;
- stateful fuzzing of fragmentation, rollback, and slot lifecycle;
- encrypted-handshake interoperability vectors;
- audited secret erasure and cryptographic provider adapters;
- CPU and memory benchmarks under distributed valid-cookie traffic.
