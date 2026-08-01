# OGTP/1 Bounded Transfer-Control State

Status: **draft 0.2 implementation contract**.

This document defines the allocation-free state that connects authenticated
MANIFEST, COMMIT, and RESUME CONTROL values to a future OGTP event loop. The
Rust implementation is in `src/transfer.rs`. It deliberately owns no socket,
cryptographic provider, filesystem handle, or heap-backed collection.

These state machines accept only values from packets that have already passed
header validation, replay filtering, and AEAD authentication. They do not make
unauthenticated input safe by themselves.

## Compile-time capacities

All attacker-influenced collections have caller-selected constant capacities:

- `ManifestReassembler<SLOTS>` owns exactly `SLOTS` logical-manifest buffers;
- every manifest slot contains 3,775 bytes and a 472-byte receipt bitmap;
- `CommitTracker<RANGES>` owns at most `RANGES` normalized committed runs;
- `ResumeTracker<RANGES>` owns separate installed and pending range sets, each
  bounded by `RANGES`.

No wire length changes these allocations. Exhaustion returns
`ManifestPoolExhausted` or `RangeCapacityExceeded`; it never grows memory,
silently evicts authenticated state, or partially applies the input. The event
loop applies stricter per-peer and global admission quotas before reserving a
manifest slot.

Capacity is a deployment choice. A larger `RANGES` value tolerates more sparse
objects but increases fixed per-object state. A runtime may ask the peer to
coalesce state, retry with a new snapshot, or close an abusive object when the
configured bound is reached.

## Manifest reassembly

`ManifestReassembler` indexes incomplete logical manifests by connection-local
object slot. Fragments may arrive out of order. For every byte:

- a first arrival sets its receipt bit and copies the byte once;
- an identical overlap is an idempotent replay;
- a different overlapping byte erases and releases the entire slot;
- changing the declared logical length also erases and releases the slot.

Receipt accounting is computed before mutation. Once every byte is present,
the reassembler performs exact canonical `Manifest::decode` validation. A
decode failure erases the slot. A successful decode leaves the bytes borrowed
from the fixed slot until the caller explicitly releases it.

Canonical decoding is not trust installation. The runtime must then:

1. match the signer fingerprint to the authenticated peer and trust policy;
2. hash the canonical unsigned manifest;
3. verify both Ed25519 and ML-DSA-65 signatures;
4. reserve bounded storage and per-object transfer state;
5. atomically install the object slot, then erase the reassembly slot.

Any failure follows the same erase path. Object-slot uniqueness and non-reuse
for the connection are enforced by the surrounding connection state.

## Idempotent COMMIT state

One `CommitTracker` belongs to one installed object slot and its signed chunk
count. `apply` first builds a fixed-capacity candidate state. It rejects:

- a different object slot;
- any range outside the signed object geometry;
- normalized state that exceeds `RANGES`;
- `OBJECT_COMPLETE` without full chunk coverage;
- a newer value that attempts to regress completed state.

A sequence less than or equal to the newest applied sequence is ignored. On a
successful newer value, overlapping and adjacent ranges are merged. The
infallible callback receives only subranges that were not already committed,
so duplicated or overlapping COMMIT values cannot release sender byte or
fragment credit twice. Delta emission is streamed and has no hidden segment
array or heap allocation.

All fallible validation and candidate updates finish before callback emission
or state replacement. An error preserves the sequence, normalized ranges, and
completion bit exactly. The callback should release the runtime's per-chunk
storage, retransmission, and CREDIT accounting; it must not perform a fallible
operation.

For an empty object, an `OBJECT_COMPLETE` COMMIT with zero ranges is valid and
covers the complete zero-chunk domain.

## Atomic RESUME snapshots

A `ResumeTracker` keeps two independent fixed-capacity range sets:

- `installed` is the newest complete snapshot visible to scheduling;
- `pending` is an incomplete candidate and is never exposed as verified state.

The first window of a sequence starts at zero. Later windows with that sequence
must start exactly at the previous exclusive end. `FINAL_WINDOW` is true if
and only if the window ends at the signed chunk count. Relative ranges are
checked by the wire codec and translated to absolute ranges with checked
arithmetic before insertion.

A forward gap, invalid final flag, out-of-object window, or capacity failure
returns an error without changing either installed or pending state. A replay
behind the pending boundary is ignored. A higher sequence may replace an
incomplete candidate only from window zero. The installed snapshot changes in
one swap only after a gap-free final window reaches the object boundary.

Applications may call `abort_pending` after a timeout or policy error. This
never changes the last installed snapshot. DATA scheduling may skip chunks
only after `ResumeStatus::Installed`; pending ranges are not evidence of local
possession.

An empty object has no legal non-empty RESUME window and needs no RESUME
exchange. Its completion is represented by the installed manifest geometry
and a zero-range final COMMIT.

## Event-loop ordering

A single-owner connection loop should use the state in this order:

1. receive into a preallocated datagram buffer;
2. validate the header, packet-number window, and AEAD tag;
3. decode canonical CONTROL values without allocation;
4. apply authenticated MANIFEST fragments under admission quotas;
5. verify both manifest signatures before creating object state;
6. write DATA directly at its object offset and verify chunk hashes;
7. emit COMMIT only for locally verified chunks;
8. apply peer COMMIT deltas to release sender resources exactly once;
9. install a RESUME snapshot before using it to suppress DATA scheduling.

The trackers contain no internal locks. OGTP's intended fast path gives one
connection to one event-loop owner. Cross-thread storage completion is returned
as bounded messages and applied by that owner.

## Failure and timeout policy

The library reports structural failures but does not choose connection policy.
The runtime distinguishes ordinary backpressure from authenticated abuse:

- pool exhaustion may defer a new object without disturbing active objects;
- a conflicting manifest overlap should reject that object and may close a
  repeatedly abusive peer;
- a RESUME discontinuity may abort only the pending snapshot and request a new
  sequence;
- repeated range-capacity failures should disable sparse resume for that object
  or close it according to negotiated policy;
- incomplete manifest and RESUME state must have bounded owner-driven timers.

Timeout tables themselves must also be fixed-capacity and keyed by existing
object slots; a network value must never create an unbounded timer or task.

## Verified properties and remaining integration

Deterministic unit tests cover out-of-order manifest completion, identical and
conflicting overlaps, length changes, pool exhaustion, invalid completed
manifests, COMMIT replay and completion regression, delta fragmentation beyond
64 runs, range-capacity rollback, RESUME discontinuity, interrupted snapshots,
and atomic replacement.

Production work still includes continuous stateful fuzzing, audited signature
and SHA-384 provider integration, bounded reorder/storage wiring around the
implemented Merkle reducer, storage durability policy, timeout wiring, and
measurement inside the batched UDP runtime.
