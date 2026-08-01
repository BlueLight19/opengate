# OGTP/1 Cryptographic Schedule

Status: **draft 0.2, review required before production**.

This document fixes domain separation, transcript records, hybrid-secret order,
HKDF labels, authentication inputs, and traffic-secret derivation. It does not
claim that the construction has received an independent cryptographic audit.

## 1. Primitive profile

OGTP/1 uses:

- ML-KEM-768 from FIPS 203;
- X25519 with the all-zero shared-secret check;
- ML-DSA-65 from FIPS 204;
- Ed25519;
- SHA-384 and HMAC-SHA-384;
- HKDF-SHA-384 following RFC 5869;
- AES-256-GCM or ChaCha20-Poly1305 with a 16-byte tag.

The current hybrid order follows the IETF X25519MLKEM768 construction:

```text
hybrid_shared_secret = ml_kem_shared_secret[32]
                    || x25519_shared_secret[32]
```

Both components MUST be exactly 32 bytes. X25519 all-zero output, a provider
backend failure, or an incorrect public-key/ciphertext length aborts the
handshake without using a partial secret. An exact-length malformed ML-KEM
ciphertext follows FIPS 203 implicit rejection and is detected only when the
derived handshake AEAD fails authentication.

The implemented provider boundary, consumed initiator state, atomic responder
result, all-zero check, fixed secret storage, and hybrid ordering are specified
in [`HANDSHAKE_CRYPTO.md`](HANDSHAKE_CRYPTO.md). ML-KEM providers preserve
implicit rejection; authentication failure is observed at the handshake AEAD.
The feature-gated concrete handshake and identity adapter and its explicit
audit limitations are specified in
[`RUSTCRYPTO_PROVIDER.md`](RUSTCRYPTO_PROVIDER.md) and
[`RUSTCRYPTO_AUTHENTICATION.md`](RUSTCRYPTO_AUTHENTICATION.md).

## 2. Canonical transcript

Long-header fragmentation metadata is not hashed directly. Once reassembled,
every logical value is added as a canonical record:

```text
Record Type u8 | Value Length u32 | Value[Value Length]
```

The transcript begins with a session-context record:

```text
Type 0xff:
Version u32 | Initiator CID Length u8 | Initiator CID
            | Responder CID Length u8 | Responder CID
```

The remaining record types are:

| Type | Value |
|---:|---|
| `0x00` | Canonical HELLO |
| `0x01` | Canonical RETRY |
| `0x02` | Canonical INIT |
| `0x03` | RESPONSE prefix through Encrypted Auth Length |
| `0x04` | Responder Identity Auth excluding Finished MAC |
| `0x05` | Responder Finished MAC |
| `0x06` | Initiator Identity Auth excluding Finished MAC |
| `0x07` | Initiator Finished MAC |

All transcript integers use network byte order. Implementations SHOULD update a
running SHA-384 state and MUST NOT retain full messages after they are no longer
needed.

The implemented fixed-state transition and rollback contract is specified in
[`HANDSHAKE_STATE.md`](HANDSHAKE_STATE.md). It forks the running hash for each
candidate transition and commits only after all required snapshots succeed.

Named transcript hashes are:

```text
TH_pre_auth     = SHA-384(records 0xff, 0x00, 0x01, 0x02, 0x03)
TH_r_signature  = TH_pre_auth
TH_r_finished   = SHA-384(records through 0x04)
TH_i_signature  = SHA-384(records through 0x05)
TH_i_finished   = SHA-384(records through 0x06)
TH_full         = SHA-384(records through 0x07)
```

## 3. Signature inputs

Both signature algorithms sign the same contextualized byte string. The 64
leading space bytes follow the defensive context pattern used by TLS 1.3.

```text
responder_signature_input = 64 * 0x20
                          || "OGTP/1 responder authentication"
                          || 0x00 || TH_r_signature

initiator_signature_input = 64 * 0x20
                          || "OGTP/1 initiator authentication"
                          || 0x00 || TH_i_signature
```

The Ed25519 and ML-DSA-65 signatures MUST both verify. Before signature
verification, the receiver checks:

```text
identity_fingerprint =
    SHA-384("OGTP/1 identity\x00" || ed25519_public_key || ml_dsa_public_key)
```

against the fingerprint carried earlier and against the out-of-band trust
anchor. Failure of either comparison or signature aborts the handshake.

The implemented provider boundary, fail-closed verification order, Finished
gate, and authenticated-identity capability are specified in
[`AUTHENTICATION.md`](AUTHENTICATION.md).

### Object manifest signatures

Object manifests reuse the authenticated identity keys but have an independent
context. Let `ManifestHash` be SHA-384 over the canonical unsigned content
specified in [`MANIFEST.md`](MANIFEST.md). Both algorithms sign:

```text
64 * 0x20 || "OGTP/1 object manifest" || 0x00 || ManifestHash
```

The signer fingerprint inside the hashed content must match the current
authenticated peer and the trust anchor. Ed25519 uses its ordinary signing
mode, not Ed25519ph. ML-DSA-65 signs the same contextualized bytes. Failure of
either signature rejects the manifest and every associated resume claim.

## 4. OGTP-Expand-Label

OGTP reuses the TLS 1.3 structured-label pattern with an independent prefix:

```text
OGTP-Expand-Label(Secret, Label, Context, Length) =
    HKDF-Expand(Secret, HkdfLabel, Length)

HkdfLabel = Length u16
          || Full Label Length u8
          || "ogtp1 " || Label
          || Context Length u8
          || Context
```

Labels are non-empty ASCII. Context and prefixed label are each at most 255
bytes. Labels contain no terminating NUL.

```text
Derive-Secret(Secret, Label, TranscriptHash) =
    OGTP-Expand-Label(Secret, Label, TranscriptHash, 48)
```

The assigned labels are:

| Label | Purpose |
|---|---|
| `derived` | Extract-stage separation |
| `i hs` / `r hs` | Initiator/responder handshake traffic |
| `i ap` / `r ap` | Initiator/responder application traffic |
| `finished` | Finished HMAC key |
| `path` | Per-DCID path secret |
| `key` | 32-byte AEAD key |
| `iv` | 12-byte AEAD IV |
| `hp` | 32-byte header-protection key |
| `traffic upd` | Next application traffic secret |

## 5. Key schedule

`Zero` is 48 zero bytes and `EmptyHash = SHA-384("")`. No PSK or 0-RTT
branch exists in OGTP/1.

```text
early_secret       = HKDF-Extract(salt=Zero, IKM=Zero)
derived_early      = Derive-Secret(early_secret, "derived", EmptyHash)
handshake_secret   = HKDF-Extract(derived_early, hybrid_shared_secret)

i_hs               = Derive-Secret(handshake_secret, "i hs", TH_pre_auth)
r_hs               = Derive-Secret(handshake_secret, "r hs", TH_pre_auth)

i_finished_key     = OGTP-Expand-Label(i_hs, "finished", "", 48)
r_finished_key     = OGTP-Expand-Label(r_hs, "finished", "", 48)

derived_handshake  = Derive-Secret(handshake_secret, "derived", EmptyHash)
master_secret      = HKDF-Extract(derived_handshake, Zero)

i_ap_0             = Derive-Secret(master_secret, "i ap", TH_full)
r_ap_0             = Derive-Secret(master_secret, "r ap", TH_full)
```

Finished values are:

```text
r_finished = HMAC-SHA-384(r_finished_key, TH_r_finished)
i_finished = HMAC-SHA-384(i_finished_key, TH_i_finished)
```

The responder Identity Auth is encrypted with keys expanded from `r_hs`; the
initiator Identity Auth uses `i_hs`:

```text
handshake_key = OGTP-Expand-Label(sender_hs, "key", "", 32)
handshake_iv  = OGTP-Expand-Label(sender_hs, "iv",  "", 12)
nonce         = handshake_iv XOR left_pad_96(message_id)
```

RESPONSE uses `TH_pre_auth` as AEAD AAD. FINISH uses `TH_i_signature` as AAD.
The logical ciphertext is sealed once and then fragmented by the long-header
layer.

The implemented role-specific seal/open functions reserve encryption exactly
once before calling the provider, contain opened plaintext in fixed candidate
storage, and require completed-transcript plus authenticated-identity
capabilities before application-secret derivation. See
[`HANDSHAKE_CRYPTO.md`](HANDSHAKE_CRYPTO.md).

## 6. Per-path traffic keys

Every direction and DCID receives independent material:

```text
path_secret = OGTP-Expand-Label(sender_application_secret,
                                "path", dcid[8], 48)
path_key    = OGTP-Expand-Label(path_secret, "key", "", 32)
path_iv     = OGTP-Expand-Label(path_secret, "iv",  "", 12)
path_hp     = OGTP-Expand-Label(path_secret, "hp",  "", 32)
```

The short-packet AEAD nonce is:

```text
nonce = path_iv XOR left_pad_96(packet_number_62)
```

A traffic update derives the next directional application secret and then
re-derives the AEAD key and IV for every active path from its DCID:

```text
application_secret_N+1 =
    OGTP-Expand-Label(application_secret_N, "traffic upd", "", 48)
```

`path_hp` is derived from `path_secret_0` and remains stable for the lifetime of
the DCID. It MUST NOT change during a symmetric key update because the receiver
needs it to reveal the protected key-phase bit. A full hybrid rekey allocates
new DCIDs and therefore new header-protection keys.

Old AEAD traffic secrets, keys, and IVs are erased after the receive grace
period. Packet numbers remain monotonic across a symmetric key update.

## 7. Short-header protection

Short packets use a fixed four-byte packet number, so the 16-byte
header-protection sample starts at byte 13, immediately after the short header.
Header protection is applied after AEAD sealing.

For AES-256-GCM, the five-byte mask is the first five bytes of:

```text
AES-256-ECB(path_hp, sample[16])
```

For ChaCha20-Poly1305, `sample[0..4]` is a little-endian block counter,
`sample[4..16]` is the 96-bit nonce, and the mask is the first five bytes of the
ChaCha20 keystream.

Application and removal are the same XOR operation:

```text
flags_low_7_bits ^= mask[0] & 0x7f
packet_number[0..4] ^= mask[1..5]
```

The header-form bit remains public. The DCID remains public so the receiver can
select the connection and stable header-protection key. After unmasking, the
complete 13-byte header is AEAD Additional Authenticated Data.

Following the conservative limits established for these AEADs by RFC 9001:

| Suite | Encrypted packets per key | Failed authentication attempts per connection |
|---|---:|---:|
| AES-256-GCM | `2^23` | `2^52` |
| ChaCha20-Poly1305 | bounded by OGTP `2^62` PN space | `2^36` |

An endpoint initiates a key update before an encryption limit and closes the
session before an authentication-failure limit. Counters never wrap.

## 8. Test vectors

Machine-readable draft vectors are stored in:

- [`authentication-v1.txt`](../test-vectors/authentication-v1.txt), covering
  identity fingerprinting, handshake signature input, and Finished HMAC;
- [`kdf-sha384-v1.txt`](../test-vectors/kdf-sha384-v1.txt), covering the key
  schedule and per-path derivation;
- [`packet-protection-v1.txt`](../test-vectors/packet-protection-v1.txt),
  covering nonce formation, AEAD output, header-protection samples and masks,
  and complete protected packets for both cipher suites.

They use:

- hybrid shared secret `00..3f`;
- `TH_pre_auth = a0..cf`;
- `TH_full = d0..ff`;
- path DCID `0001020304050607`.

The KDF vectors were cross-checked using Python's standard HMAC/SHA-384
implementation and `cryptography`'s independent HKDFExpand implementation. The
packet vectors are continuously reproduced with independent RustCrypto AEAD,
AES block-cipher, and ChaCha20 implementations in `tests/packet_vectors.rs`.

## 9. Release requirements

Before production use, this schedule requires:

- independent cryptographic review;
- complete encrypted-handshake vectors carrying real hybrid identity values;
- independent audit or replacement of the feature-gated concrete provider,
  plus official X25519/ML-KEM-768 and ML-DSA-65 known-answer and differential
  coverage; real Ed25519/ML-DSA negative tests already run in the feature-gated
  suite;
- authenticated-cookie and batched-runtime integration of the bounded
  handshake state;
- enforcement of algorithm-specific AEAD usage limits;
- constant-time key handling and comparison;
- erasure tests for ephemeral, handshake, and previous-epoch secrets;
- formal verification of authentication, downgrade resistance, and key
  separation.
