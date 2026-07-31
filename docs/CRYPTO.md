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

Both components MUST be exactly 32 bytes. X25519 all-zero output, ML-KEM
decapsulation failure, or an incorrect public-key/ciphertext length aborts the
handshake without using a partial secret.

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
re-derives every active path from its DCID:

```text
application_secret_N+1 =
    OGTP-Expand-Label(application_secret_N, "traffic upd", "", 48)
```

Old traffic secrets and derived keys are erased after the receive grace period.
Packet numbers remain monotonic across a symmetric key update.

## 7. Test vectors

Machine-readable draft vectors are stored in
[`test-vectors/kdf-sha384-v1.txt`](../test-vectors/kdf-sha384-v1.txt). They use:

- hybrid shared secret `00..3f`;
- `TH_pre_auth = a0..cf`;
- `TH_full = d0..ff`;
- path DCID `0001020304050607`.

The vectors were cross-checked using Python's standard HMAC/SHA-384
implementation and `cryptography`'s independent HKDFExpand implementation.

## 8. Release requirements

Before production use, this schedule requires:

- independent cryptographic review;
- vectors covering Finished MACs, transcript records, AEAD, and header
  protection;
- enforcement of algorithm-specific AEAD usage limits;
- constant-time key handling and comparison;
- erasure tests for ephemeral, handshake, and previous-epoch secrets;
- formal verification of authentication, downgrade resistance, and key
  separation.

