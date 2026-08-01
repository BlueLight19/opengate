# OGTP/1 Bounded Merkle Reduction

Status: **draft 0.2 implementation contract**.

This document specifies the fixed-memory reducer implemented in
`src/merkle.rs`. It computes the exact tree defined by
[`MANIFEST.md`](MANIFEST.md) while retaining at most one perfect-subtree root
per binary level. It does not implement SHA-384; an audited provider supplies
that standardized primitive.

A reproducible seven-chunk vector is published in
[`merkle-reducer-v1.txt`](../test-vectors/merkle-reducer-v1.txt).

## Memory bound

The signed chunk count is a `u32`, so every representable object needs at most
32 live subtree slots. Each slot is one 48-byte SHA-384 digest:

```text
32 * 48 bytes = 1,536 bytes
```

The reducer also stores the manifest header, a 32-bit occupancy mask, and a
32-bit received-chunk counter. Its memory is constant for a 1 MiB object, a
100 GiB object, or a multi-TiB object. No DATA length, chunk count, or tree
shape causes a heap allocation inside the reducer.

The external SHA-384 provider owns its contexts and must document any memory
or hardware-queue use. Production profiles should use fixed-size contexts and
must not allocate once per internal node.

## Provider boundary

`Sha384Provider` starts an independent streaming context and finalizes it to
exactly 48 bytes. Canonical leaf, node, and empty-root bytes enter that context
through `TranscriptSink`. This keeps tree logic independent of a particular
cryptographic library while preventing the reducer from concatenating large
chunk inputs in memory.

Provider errors are explicit. A failed leaf hash does not create a
`HashedChunk`; a failed internal-node hash does not advance the reducer. The
same chunk may be retried with the same or a replacement provider.

Default debug output omits object IDs, leaf digests, subtree digests, and root
values. `RootMismatch` carries no hash bytes, reducing the risk that generic
error logging violates the protocol's possession-privacy policy.

## Split hashing and ordered reduction

Multipath delivery is naturally out of order, while a binary streaming reducer
is simplest and smallest in order. OGTP separates the operations:

1. `hash_chunk` validates the signed index and exact expected length, then
   computes the domain-separated leaf without changing reducer state.
2. The opaque `HashedChunk` binds object ID, chunk index, chunk length, and the
   resulting digest.
3. `push_hashed_chunk` accepts only the next sequential index and rejects a
   leaf from another object.

This permits receive workers to hash a chunk as soon as its bytes are complete.
The single-owner event loop then drains hashed chunks in index order from one
of these bounded strategies:

- a small fixed-capacity reorder table sized by receive CREDIT;
- a sequential storage reader when chunks are already written by offset;
- a bounded in-memory table plus an on-disk 48-byte-per-chunk sidecar for very
  wide reordering.

The reducer never creates that queue itself. Queue exhaustion applies receive
backpressure; it must not grow RAM or discard a hash that has already caused
the peer to receive COMMIT credit.

## Online carry algorithm

The occupancy mask is the binary representation of the number of inserted
leaves. Inserting one leaf behaves like incrementing that counter:

1. if level zero is empty, store the leaf there;
2. otherwise hash `Node_1(existing, incoming)` and carry to level one;
3. repeat while the destination level is occupied;
4. clear consumed lower slots and install the resulting perfect subtree.

All required node hashes are calculated before the occupancy mask, subtree
array, or received count changes. A provider failure during a long carry is
therefore transactional.

Insertion performs at most 31 internal hashes for the representable `u32`
chunk-count domain. Across a complete object, ordinary carry work remains
linear in the number of leaves.

## Finalizing an irregular tree

For a power-of-two leaf count, one occupied slot is already the root. For any
other count, finalization scans occupied slots from low to high while holding
one rightmost accumulator:

1. duplicate the right accumulator with itself until it reaches the next
   occupied level;
2. combine the occupied left subtree with that right accumulator;
3. continue until no occupied level remains.

This exactly reproduces duplication of an odd final node at every non-root
level. Missing leaves and full intermediate levels are never materialized.
Finalization is read-only and may be retried after a provider failure.

For zero chunks, the result is the separately domain-separated empty-object
root. A one-chunk root is the leaf directly and has no internal-node wrapper.

## Root installation and COMMIT

`computed_root` is available only after the exact signed chunk count has been
inserted. `verify_manifest_root` compares it with the root from the already
authenticated manifest and returns `RootMismatch` on any difference.

A leaf digest alone is not a Merkle membership proof. It confirms canonical
hashing of the received bytes but becomes collectively authenticated by the
signed root only after final reduction. A receiver may emit ordinary COMMIT
for bytes it has authenticated, stored, and hashed according to its durability
policy. It emits `OBJECT_COMPLETE` only after `verify_manifest_root` succeeds.

On root mismatch, the runtime rejects the object, retains no trusted partial
result, and follows its storage rollback policy. It must not attempt to guess
which individual chunk was wrong from the final root alone.

## Tests and production work

Deterministic tests compare the bounded reducer with a reference implementation
that materializes complete levels for 0, 1, 2, 3, 5, 6, 7, 8, and 9 chunks.
They also cover out-of-order leaf hashing, wrong lengths and indices,
cross-object leaf substitution, incomplete finalization, root mismatch, and an
injected provider failure during the deepest representable 31-level carry.

Production integration still requires an audited SHA-384 adapter, a bounded
reorder/storage strategy, stateful fuzzing, and CPU/copy measurements using
the target event loop and storage backend.
