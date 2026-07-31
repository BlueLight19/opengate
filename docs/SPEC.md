# OGTP/1 Working Specification

Status: **draft 0.2, not suitable for production**.

OGTP is a reliable peer-to-peer transport over UDP. It is specialized for
large-object transfer, multipath operation, and bounded memory use. The key
words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are normative requirements.

## 1. Goals

OGTP/1 has the following goals:

1. transfer multi-terabyte objects without memory proportional to object size;
2. accept fragments out of order and write them directly at their final offset;
3. use several network paths simultaneously;
4. provide confidentiality, integrity, mutual authentication, forward secrecy,
   and hybrid post-quantum protection;
5. support UDP GSO/GRO, `io_uring`, and an optional AF_XDP profile without
   changing the wire format;
6. remain fair to competing traffic through mandatory congestion control.

OGTP/1 is not a generic byte-stream transport, does not attempt to hide traffic
volume, and cannot survive compromise of an endpoint.

## 2. Architecture

A session contains one or more objects and one or more paths. Every path has
its own Destination Connection ID (DCID), keys, packet-number space, anti-replay
window, congestion controller, and pacer. Objects are divided into chunks;
chunks are divided into fragments sized for the active path MTU.

The data path imposes no global ordering. Object completion is determined from
its signed manifest after all chunks and the Merkle root have been verified.

## 3. UDP and MTU

- The initial UDP payload MUST NOT exceed 1,200 bytes.
- OGTP MUST NOT depend on IP fragmentation.
- A larger payload requires validated path-MTU discovery using padded PROBE
  packets and acknowledgements.
- A path change resets its payload limit to 1,200 bytes until it is validated
  again.
- Equal-sized datagrams MAY be grouped with UDP GSO. Every resulting segment
  remains independently encrypted and authenticated.

## 4. Connection IDs and packet numbers

A short-header DCID is eight bytes. It is random, non-zero, and unique for at
least as long as any corresponding key may remain in memory. Every new path
receives a new DCID.

Each path maintains an unsigned 62-bit internal packet number. The low 32 bits
are transmitted; the receiver reconstructs the value nearest to its next
expected number. A sender MUST NOT reuse a packet number with the same path key
and MUST update or retire the path before exhausting the number space.

## 5. Short header

Before cryptographic header protection:

```text
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |0| Class |K| Reserved |          Destination CID ...          |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |        ... Destination CID   |    Packet Number (32 bits)    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |    Packet Number (continued) |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The size is 13 bytes:

- bit 7: `0`, short form;
- bits 6..5: `DATA=0`, `CONTROL=1`, `ACK=2`, `PROBE=3`;
- bit 4: key phase;
- bits 3..0: reserved and zero before protection;
- bytes 1..8: public DCID;
- bytes 9..12: truncated packet number in network byte order.

The class, key phase, reserved bits, and packet number MUST be masked by header
protection. The seven low flag bits are XORed with the low seven bits of mask
byte zero; the four packet-number bytes are XORed with mask bytes one through
four. The DCID remains visible so a receiver can select the connection and
stable header-protection key.

## 6. Packet protection

OGTP/1 cipher suites are:

- `OGTP_AES_256_GCM_SHA384`;
- `OGTP_CHACHA20_POLY1305_SHA384`.

The AEAD tag is 16 bytes. The unmasked short header is Additional Authenticated
Data. The 96-bit nonce is:

```text
nonce = path_iv XOR left_pad_96(packet_number_62)
```

`path_key`, `path_iv`, and the header-protection key are derived with
HKDF-SHA-384 from the traffic secret, direction, and DCID. A path key is
therefore never shared across packet-number spaces.

Send processing is strictly: encode plaintext, seal plaintext in place, append
the tag, then protect the header. Receive processing performs the inverse. An
implementation MUST NOT expose plaintext before tag validation.

The HKDF labels, key schedule, and header-protection construction are fixed in
[`CRYPTO.md`](CRYPTO.md). Complete packet-protection vectors for both cipher
suites are published in
[`packet-protection-v1.txt`](../test-vectors/packet-protection-v1.txt).

## 7. DATA fast path

The plaintext of a DATA packet begins with:

```text
+-------------+-------------+-----------------+--------+----------+
| Object Slot | Chunk Index | Fragment Offset | Length | Fragment |
| 32 bits     | 32 bits     | 32 bits         | 16 bit | N bytes  |
+-------------+-------------+-----------------+--------+----------+
```

All integers use network byte order. `Length` MUST exactly equal the remaining
plaintext size. At the baseline MTU, the maximum fragment is 1,157 bytes:

```text
1200 - 13 short header - 16 tag - 14 DATA metadata = 1157
```

After authentication and manifest-bound checks, a receiver writes a fragment
directly to:

```text
object_base + chunk_index * chunk_size + fragment_offset
```

Overlapping ranges with different contents close the object. Identical
duplicates are ignored.

## 8. ACK packets

ACK plaintext is encoded as:

```text
Largest Acked u64 | ACK Delay usec u32 | First Range Length u16 | Count u8
                  | Count * (Gap u16 | Range Length u16)
```

`First Range Length` is the number of contiguous acknowledged packets ending at
`Largest Acked` and MUST be non-zero. `Count` is the number of additional ranges
and MUST NOT exceed 32. For every additional range:

- `Gap` is the non-zero number of unacknowledged packet numbers below the
  preceding range;
- `Range Length` is the non-zero number of acknowledged packet numbers in the
  next lower range.

For example, `Largest=100`, `First Length=3`, `Gap=2`, and `Range Length=4`
acknowledges `[98,100]` and `[92,95]`. Underflow or a non-canonical zero value is
a protocol error.

ACKs are path-local. They confirm network receipt and authentication, not
durable storage. Old ranges MAY be discarded to respect the advertised memory
budget.

An ACK-eliciting packet is acknowledged no later than 25 ms after receipt. A
receiver SHOULD acknowledge at least every second ACK-eliciting packet and
SHOULD acknowledge immediately when a newly received packet creates or fills a
gap. `ACK Delay usec` is measured from packet receipt until ACK transmission.
The sender caps the reported delay at 25,000 microseconds before RTT
adjustment. An authenticated ACK whose `Largest Acked` exceeds the largest
packet sent on that path is a protocol violation.

Each path maintains independent integer RTT state. Before the first sample,
the initial RTT is 333 ms. For a newly acknowledged `Largest Acked` packet:

```text
raw_rtt = acknowledgement_time - send_time
min_rtt = min(min_rtt, raw_rtt)
adjusted_rtt = raw_rtt - min(reported_ack_delay, 25 ms)
```

The delay is subtracted only when the result would not fall below `min_rtt`.
The first adjusted sample initializes `smoothed_rtt` and
`rtt_variance = adjusted_rtt / 2`. Later samples use integer updates:

```text
rtt_variance = (3 * rtt_variance + abs(smoothed_rtt - adjusted_rtt)) / 4
smoothed_rtt = (7 * smoothed_rtt + adjusted_rtt) / 8
```

After an authenticated ACK, an older outstanding packet is lost when either:

1. `Largest Acked - Packet Number >= 3`; or
2. it was sent at least `9/8 * max(latest_rtt, smoothed_rtt)` ago and a newer
   packet has been acknowledged.

The time threshold has a minimum granularity of 1 ms. Loss processing removes
packet metadata immediately and emits only stable DATA/control recovery tokens;
it does not retain payload bytes. Every retransmission is a new packet on the
selected path, uses that path's next packet number and keys, and is sealed
again. Ciphertext, nonce, and packet number MUST NOT be reused.

## 9. CONTROL packets

CONTROL plaintext is a sequence of canonical TLVs:

```text
Type u8 | Length u16 | Value[Length]
```

The initial registry is:

| Type | Name | Purpose |
|---:|---|---|
| `0x01` | PING | Requests acknowledgement |
| `0x02` | CREDIT | Advertises available receive capacity |
| `0x03` | MANIFEST | Describes and signs an object |
| `0x04` | COMMIT | Confirms written and verified chunks |
| `0x05` | RESUME | Reports chunks already present |
| `0x06` | PATH_OFFER | Reserves a CID for a new path |
| `0x07` | PATH_ACCEPT | Accepts a CID and derives path keys |
| `0x08` | PATH_RETIRE | Gracefully retires a path |
| `0x09` | KEY_UPDATE | Confirms a new symmetric key phase |
| `0x0a` | CLOSE | Authenticated connection closure |
| `0x0b` | ERROR | Bounded protocol error |

Unknown types with a clear high bit are ignored. Unknown types with a set high
bit cause `UNSUPPORTED_CRITICAL_FRAME`. A packet containing a truncated TLV is
invalid in its entirety.

## 10. PROBE packets

PROBE plaintext is:

```text
Kind u8 | Token[16] | Zero Padding[N]
```

The initial kinds are:

| Kind | Name | Behavior |
|---:|---|---|
| `0x00` | PATH_CHALLENGE | Requests an echo on the candidate path |
| `0x01` | PATH_RESPONSE | Echoes a PATH_CHALLENGE token |
| `0x02` | MTU_PROBE | Tests a padded datagram size |
| `0x03` | MTU_ACK | Confirms an MTU_PROBE token |

The token is unpredictable. Padding MUST consist entirely of zero bytes before
encryption. A response does not need to repeat the probe padding.

## 11. Credits and bounded memory

CREDIT has an exact 20-byte value:

```text
Sequence u64 | Max Uncommitted Bytes u64 | Max Inflight Fragments u32
```

The limits are absolute ceilings for unique object bytes and fragments sent but
not yet covered by COMMIT. A retransmission of the same fragment consumes no
additional credit. `Sequence` increases monotonically; stale or duplicate
updates are ignored. A newer update may lower a limit below the amount already
in flight, in which case the sender stops new unique DATA until accounting
falls below both limits. It does not revoke existing data. The sender MUST NOT
exceed either limit.

An implementation MUST support fixed-size pools for:

- receive buffers;
- transmit buffers waiting for kernel release;
- in-flight packet metadata;
- an optional small cache of recent ciphertexts.

Network-acknowledged data need not remain in RAM. For retransmission, a sender
MAY reread `(descriptor, offset, length)` from the source. Any retransmission
cache is optional and strictly bounded.

COMMIT is emitted after a chunk has been written and verified. Final success
requires the expected manifest root and every required COMMIT.

## 12. Manifest and resume

A manifest contains a random object identity, object size, chunk size, chunk
count, SHA-384 Merkle root, minimal metadata, and dual Ed25519 + ML-DSA-65
signatures.

Wire-visible identifiers are never global content hashes. A resume exchange
sends a compressed bitmap of verified chunks inside an encrypted packet. The
sender retransmits only missing ranges.

## 13. Hybrid handshake

The handshake uses a versioned long header and fragmentable messages limited to
16 KiB. Its state flow is:

```text
Initiator                            Responder
    | HELLO(version, nonce, CID)        |
    |---------------------------------->| 
    | RETRY(stateless cookie)           |
    |<----------------------------------|
    | INIT(cookie, X25519_i, ML-KEM pk) |
    |---------------------------------->| 
    | RESPONSE(X25519_r, ML-KEM ct,     |
    |          encrypted auth_r)        |
    |<----------------------------------|
    | FINISH(encrypted auth_i, MAC)     |
    |---------------------------------->| 
```

The 64-byte hybrid shared input is `ML-KEM-768 shared secret || X25519 shared
secret`, matching the current X25519MLKEM768 IETF construction. It is injected
into an HKDF-SHA-384 key schedule bound to the SHA-384 transcript hash.
`auth_r` and `auth_i` contain Ed25519 and ML-DSA-65 signatures over the
transcript and negotiated parameters.

The RETRY cookie binds at least the source address, source port, CID, nonce,
version, and expiry. Before cookie validation, a responder:

- keeps no per-client state;
- performs no ML-KEM or ML-DSA operation;
- does not exceed a 3x amplification factor.

Identity keys are pre-authenticated through an invitation, fingerprint, QR
code, or verifiable directory. Trust on first use is a separate and explicitly
weaker profile.

### 13.1 Long-header wire format

Every handshake datagram carries one bounded fragment:

```text
Flags u8 | Version u32 | DCID Length u8 | DCID[0..20]
         | SCID Length u8 | SCID[0..20] | Message ID u32
         | Fragment Offset u16 | Fragment Length u16
         | Message Length u16 | Fragment[Fragment Length]
```

All integers use network byte order. The fixed portion is 17 bytes, excluding
both Connection IDs and the fragment. In `Flags`:

- bit 7 is one;
- bits 6..4 encode `HELLO=0`, `RETRY=1`, `INIT=2`, `RESPONSE=3`, `FINISH=4`,
  or `VERSION_NEGOTIATION=5`;
- bits 3..0 are zero.

`Message ID` identifies fragments belonging to the same logical handshake
message. `Fragment Offset + Fragment Length` MUST NOT exceed `Message Length`.
The UDP datagram MUST end immediately after the declared fragment. A logical
message MUST NOT exceed 16 KiB, and an implementation MUST reject overlaps with
different bytes.

HELLO and RETRY require no fragment reassembly. A responder MUST validate the
RETRY cookie before allocating an INIT reassembly slot. Reassembly uses a fixed
16 KiB slot plus a bounded receipt bitmap; unauthenticated wire lengths never
control an allocation.

### 13.2 Logical message encodings

The following constants are normative:

| Component | Size |
|---|---:|
| Random value | 32 bytes |
| SHA-384 identity fingerprint | 48 bytes |
| X25519 public key | 32 bytes |
| ML-KEM-768 encapsulation key | 1,184 bytes |
| ML-KEM-768 ciphertext | 1,088 bytes |
| Ed25519 public key | 32 bytes |
| Ed25519 signature | 64 bytes |
| ML-DSA-65 public key | 1,952 bytes |
| ML-DSA-65 signature | 3,309 bytes |
| HMAC-SHA-384 Finished value | 48 bytes |

The identity fingerprint is:

```text
SHA-384("OGTP/1 identity\x00" || Ed25519 public key || ML-DSA-65 public key)
```

#### HELLO

```text
Client Random[32] | Identity Fingerprint[48] | Cipher Bitmap u16
                  | Capabilities u32 | Max UDP Payload u16
                  | Max Paths u8 | Reserved u8=0
```

HELLO is exactly 90 bytes. Cipher Bitmap bit 0 offers AES-256-GCM-SHA384 and
bit 1 offers ChaCha20-Poly1305-SHA384. At least one known bit is required.
Capability bit 0 requests multipath, bit 1 resume, and bit 2 periodic hybrid PQ
rekey. Unknown capability bits are ignored. `Max UDP Payload` is at least 1,200
and `Max Paths` is between 1 and 16.

#### RETRY

```text
Server Random[32] | Cookie Length u16 | Opaque Cookie[16..256]
```

The cookie is an authenticated, encrypted server token. Its plaintext binds the
source address and port, both random values, the offered version, both
Connection IDs, an expiry, and a hash of canonical HELLO. Its internal encoding
is server-local and is never parsed by the initiator.

#### INIT

```text
Canonical HELLO[90] | Server Random[32] | Cookie Length u16
                    | Opaque Cookie[16..256] | X25519 Public Key[32]
                    | ML-KEM-768 Encapsulation Key[1184]
```

HELLO is repeated so a stateless responder can reconstruct the transcript after
validating its cookie. INIT is 1,340 bytes plus the cookie and therefore uses
long-header fragmentation at the baseline MTU.

#### RESPONSE

```text
Selected Cipher u16 | Negotiated Capabilities u32 | Max UDP Payload u16
                    | Max Paths u8 | Reserved u8=0
                    | Responder Identity Fingerprint[48]
                    | X25519 Public Key[32] | ML-KEM-768 Ciphertext[1088]
                    | Encrypted Auth Length u16=5421
                    | Encrypted Responder Identity Auth[5421]
```

Selected Cipher is `0x0001` for AES-256-GCM-SHA384 or `0x0002` for
ChaCha20-Poly1305-SHA384. Negotiated capabilities MUST be a subset of HELLO.
RESPONSE is exactly 6,601 bytes.

#### FINISH

```text
Encrypted Auth Length u16=5421 | Encrypted Initiator Identity Auth[5421]
```

FINISH is exactly 5,423 bytes.

#### Identity Auth plaintext

Before AEAD sealing, both authentication blocks are exactly 5,405 bytes:

```text
Ed25519 Public Key[32] | ML-DSA-65 Public Key[1952]
                       | Ed25519 Signature[64]
                       | ML-DSA-65 Signature[3309]
                       | Finished HMAC-SHA-384[48]
```

The AEAD adds a 16-byte tag, producing the 5,421-byte encrypted value carried
by RESPONSE and FINISH. A receiver verifies that the two public keys hash to
the identity fingerprint before verifying either signature.

## 14. Multipath

A new path is first announced over an authenticated path with
PATH_OFFER/PATH_ACCEPT. The receiver installs the new DCID and can select the
session when the first packet arrives on the new four-tuple. A PROBE
challenge/response validates reachability before DATA is sent.

Each path has independent congestion control, pacing, and ACK state. The chunk
scheduler estimates:

```text
ETA = pacer_delay + RTT/2 + queued_bytes/estimated_rate + loss_penalty
```

A retransmission MAY use a different path. The implementation MUST avoid
treating paths that share a bottleneck as fully independent capacity. CUBIC
with pacing is the initial profile; a coupled multipath controller will be
specified after measurements.

For a recovery token, the initial path selector minimizes the saturating
integer estimate:

```text
delivery_delay = pacer_delay + smoothed_rtt/2
               + ceil(queued_bytes * 1_000_000 / estimated_rate_bytes_per_sec)
               + loss_penalty
```

Only validated, sendable paths with a non-zero rate estimate are eligible.
The original path remains eligible if healthy; equal estimates are resolved by
the lowest path identifier. Completion state is keyed by the stable recovery
token so a late original packet or ACK cannot complete or retransmit the same
fragment twice.

Address discovery, rendezvous, hole punching, and relay operation are separate
services. A relay carries opaque OGTP datagrams and owns no session key.

## 15. FEC

Forward error correction is not part of the initial OGTP/1 core. A future
extension may negotiate systematic blocks and repair fragments. It must create
a repair only when its expected arrival precedes a retransmission and must
remain under congestion control.

## 16. Linux implementation path

The recommended profile is a userspace engine:

1. fixed buffers registered with `io_uring`;
2. multishot and zero-copy receive where available;
3. in-place encryption and decryption;
4. UDP GRO/GSO for batched packet processing;
5. offset-based file writes without global reassembly;
6. single-core connection ownership with no fast-path lock;
7. optional AF_XDP on controlled NICs and networks.

XDP never receives keys or plaintext. It may only route by DCID, rate-limit,
and reject structurally invalid packet forms.

## 17. Release blockers

- Independent cryptographic audit and cross-implementation validation.
- Canonical manifest and dual-signature encoding.
- Bit-exact CREDIT, COMMIT, and RESUME values.
- PTO, persistent-congestion, CUBIC, and pacing integration.
- Coupled multipath congestion controller.
- Relay negotiation and behavior.
