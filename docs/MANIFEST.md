# OGTP/1 Canonical Object Manifest

Status: **draft 0.2 implementation contract**.

Every transferred object is described by one bounded logical manifest. The
manifest binds object geometry, a random identifier, a domain-separated
SHA-384 Merkle root, an informational display name, and the authenticated
sender identity. Ed25519 and ML-DSA-65 sign the same contextualized content
hash; both signatures are mandatory.

Canonical vectors are published in
[`manifest-v1.txt`](../test-vectors/manifest-v1.txt). The signature bytes in
that file are synthetic patterns, not valid signatures.

## Logical encoding

The unsigned content is:

```text
Format Version u8 = 1
Flags u8 = 0
Object ID[32]
Object Size u64
Chunk Size u32
Chunk Count u32
Merkle Root[48]
Signer Identity Fingerprint[48]
Display Name Length u8
Display Name[Display Name Length]
```

The fixed unsigned prefix is 147 bytes. The complete logical manifest appends:

```text
Ed25519 Signature[64]
ML-DSA-65 Signature[3309]
```

The display name occupies 0 through 255 UTF-8 bytes, making the complete
logical manifest 3,520 through 3,775 bytes. It must not contain a Unicode
control character, `/`, or `\`. It is an informational label only. A receiver
never treats it as a path, never creates parent directories from it, and may
replace it when choosing a local filename.

`Object ID` is a uniformly random, non-zero value. It is not a content hash and
must not be reused for different bytes. The signer fingerprint is the SHA-384
identity fingerprint defined by the handshake and must match both the current
authenticated peer and the applicable trust anchor. The Merkle root and signer
fingerprint must not be all zero.

`Chunk Size` is a power of two between 64 KiB and 16 MiB inclusive. The encoded
chunk count is exact:

```text
Chunk Count = 0                                      when Object Size = 0
Chunk Count = floor((Object Size - 1) / Chunk Size) + 1 otherwise
```

Geometry whose calculated count does not fit `u32` is not representable.

## Signature input

Let `UnsignedHash = SHA-384(Unsigned Manifest)`. Both signature schemes sign
the same byte string:

```text
64 * 0x20
|| "OGTP/1 object manifest"
|| 0x00
|| UnsignedHash
```

Ed25519 uses its ordinary signing mode over this byte string; ML-DSA-65 uses
its ordinary signing mode over the same bytes. This is not Ed25519ph. A
receiver verifies the geometry, signer fingerprint, Ed25519 signature, and
ML-DSA-65 signature before accepting the object slot or any RESUME claim.

The two signatures are intentionally outside the hashed unsigned content.
Their fixed order and sizes make the logical representation unambiguous.

## Merkle construction

All integer fields below use network byte order. Chunk `i` has exact final
length `ChunkLength_i`, including a shorter last chunk:

```text
Leaf_i = SHA-384(
    "OGTP/1 chunk\x00"
    || Object ID
    || Chunk Index u32
    || Chunk Length u32
    || Chunk Bytes
)
```

Leaves are level zero. Parents at level `L`, starting with `L = 1`, are:

```text
Node_L = SHA-384(
    "OGTP/1 node\x00"
    || Level u32
    || Left Child[48]
    || Right Child[48]
)
```

When a non-root level has an odd final child, that child is duplicated as both
left and right input. A one-chunk object's root is its leaf directly. Reduction
continues until one hash remains. The empty-object root is:

```text
SHA-384("OGTP/1 empty\x00" || Object ID)
```

Including object identity, chunk index, exact length, node level, and distinct
domain separators prevents structural ambiguity and cross-object leaf reuse.
The constant-memory reduction algorithm and provider boundary are specified in
[`MERKLE_REDUCTION.md`](MERKLE_REDUCTION.md).

## CONTROL fragmentation

The ML-DSA signature makes every logical manifest larger than the baseline
UDP payload. Each CONTROL `MANIFEST` TLV therefore carries one non-empty
fragment value:

```text
Object Slot u32 | Manifest Length u16 | Fragment Offset u16 | Fragment[N]
```

`Manifest Length` is between 3,520 and 3,775. `Fragment Offset + N` does not
exceed it. At the 1,200-byte baseline UDP payload, `N` is at most 1,160 bytes:

```text
1200 - 13 short header - 16 AEAD tag - 3 TLV header - 8 fragment header
```

Every fragment is independently protected, acknowledged, and retransmitted.
For each admitted in-progress manifest, the receiver assigns one fixed
3,775-byte reassembly slot plus a fixed receipt bitmap from a bounded pool.
Identical overlaps are ignored; different overlapping bytes abort the object.
The object slot is never reused within a connection. After complete reassembly,
the logical length derived from the display-name byte must exactly match
`Manifest Length` and all signature checks must succeed.

Wire lengths never allocate memory. A receiver reserves a manifest slot only
within its authenticated per-connection and global object quotas.

## Completion and resume

AEAD validation and manifest bounds permit a fragment to be written at its
final object offset. A chunk becomes locally verified after all its bytes are
present and its leaf hash has been computed. `OBJECT_COMPLETE` is emitted only
after reducing every leaf to the signed root.

For an empty object, COMMIT may set `OBJECT_COMPLETE` with zero ranges. For a
non-empty object, duplicate COMMIT ranges remain idempotent and never release
sender credit twice. A RESUME snapshot is accepted only after this manifest
and both signatures have been authenticated under the same trusted identity.

The implemented fixed-pool reassembler and transactional COMMIT/RESUME state
are specified in [`TRANSFER_STATE.md`](TRANSFER_STATE.md). Canonical manifest
decoding is intentionally separate from identity matching and signature
verification; a runtime must complete both checks before installing the slot.

## Remaining production work

The codec and hashing inputs are provider-neutral. Production still requires:

- an audited Ed25519 and ML-DSA-65 provider adapter;
- event-loop admission, timeout, and signature-verification wiring around the
  implemented fixed-buffer reassembler;
- event-loop integration of the implemented reducer with a bounded
  out-of-order leaf or storage strategy;
- fuzzing, independent vectors, and cross-implementation verification;
- explicit policy for local filenames, overwrite behavior, and filesystem
  atomicity.
