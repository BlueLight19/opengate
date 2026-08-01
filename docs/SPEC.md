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
Largest Acked u64 | ACK Delay usec u32 | First Range Length u16
                  | Count and Flags u8
                  | Count * (Gap u16 | Range Length u16)
                  | Optional ECN Counters[24]
```

`First Range Length` is the number of contiguous acknowledged packets ending at
`Largest Acked` and MUST be non-zero. In `Count and Flags`, bit 7 indicates ECN
counters, bit 6 is zero, and bits 5..0 contain the number of additional ranges.
The range count MUST NOT exceed 32. For every additional range:

- `Gap` is the non-zero number of unacknowledged packet numbers below the
  preceding range;
- `Range Length` is the non-zero number of acknowledged packet numbers in the
  next lower range.

For example, `Largest=100`, `First Length=3`, `Gap=2`, and `Range Length=4`
acknowledges `[98,100]` and `[92,95]`. Underflow or a non-canonical zero value is
a protocol error.

When ECN capability bit 3 was negotiated and bit 7 is set, the ACK ends with:

```text
ECT(0) Count u64 | ECT(1) Count u64 | CE Count u64
```

These are cumulative, path-local counts of newly authenticated, non-duplicate
UDP datagrams by their received IP ECN codepoint. The counters are inside the
AEAD-protected ACK plaintext. An endpoint MUST NOT send this trailer without
negotiation, and bit 6 or trailing bytes are a protocol error.

The base sender marks ECT(0), never ECT(1). A new path sends at most ten ECT(0)
validation probes. Valid feedback must be monotonic, must cover every newly
acknowledged ECT-marked packet, and cannot report more packets than the sender
marked. An ACK that does not advance `Largest Acked` is ignored for validation
so reordering cannot disable ECN. Missing, decreasing, rewritten, excessive,
or entirely lost validation feedback disables ECN on that path and subsequent
datagrams use Not-ECT.

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

If a time-threshold loss deadline exists, it is the active recovery timer.
Otherwise, an outstanding ACK-eliciting packet arms the probe timeout:

```text
PTO = smoothed_rtt + max(4 * rtt_variance, 1 ms) + max_ack_delay
```

The initial RTT of 333 ms is used before the first sample. Consecutive PTO
expirations double the timeout with saturating arithmetic. An ACK that newly
acknowledges a packet resets this backoff. Each expiration authorizes exactly
two ACK-eliciting probe datagrams. It MUST NOT itself declare packets lost or
reduce the congestion window. Probe bytes remain charged to bytes-in-flight,
although the two probes MAY temporarily exceed the congestion window.

Persistent congestion requires at least two consecutive lost ACK-eliciting
packets that were sent after the first RTT sample. No acknowledged or still
unresolved ACK-eliciting packet may occur between them in send-time order. The
span from the first to the last lost packet MUST be at least three times the
base, non-backed-off PTO. Once confirmed, the path congestion window collapses
to its minimum of two maximum-sized datagrams.

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
| `0x03` | MANIFEST | Carries a fragment of a signed object manifest |
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

Canonical values and complete TLVs for CREDIT, COMMIT, and RESUME are published
in [`control-values-v1.txt`](../test-vectors/control-values-v1.txt).

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
requires the expected manifest root and every required COMMIT. Its value is:

```text
Sequence u64 | Object Slot u32 | Flags u8 | Range Count u8
             | Range Count * (Chunk Start u32 | Chunk Count u32)
```

`Sequence` is monotonically increasing within one object slot. Stale or
duplicate COMMIT values are ignored. In `Flags`, bit 0 is `OBJECT_COMPLETE` and
bits 7 through 1 are zero. `OBJECT_COMPLETE` MUST be set only after every
manifest chunk and the final Merkle root have been verified.

`Range Count` is between 1 and 32 inclusive, except that an
`OBJECT_COMPLETE` COMMIT MAY carry zero new ranges. COMMIT ranges use absolute
chunk indices. Every `Chunk Count` is non-zero and
`Chunk Start + Chunk Count` MUST NOT exceed `2^32`. Ranges are strictly
increasing, non-overlapping, and non-adjacent; adjacent runs MUST be merged to
produce one canonical encoding. The sender validates every range against the
manifest and releases byte and fragment credit from its local per-chunk
accounting. A duplicate committed chunk never releases credit twice, and no
wire-supplied byte count is trusted.

## 12. Manifest and resume

A logical manifest has this exact encoding:

```text
Format Version u8=1 | Flags u8=0 | Object ID[32] | Object Size u64
Chunk Size u32 | Chunk Count u32 | SHA-384 Merkle Root[48]
Signer Identity Fingerprint[48] | Display Name Length u8
Display Name[0..255] | Ed25519 Signature[64] | ML-DSA-65 Signature[3309]
```

The complete value is 3,520 through 3,775 bytes. `Object ID` is random,
non-zero, and never a content hash. `Chunk Size` is a power of two from 64 KiB
through 16 MiB. `Chunk Count` is zero for an empty object and otherwise equals
`floor((Object Size - 1) / Chunk Size) + 1`. The display name is valid UTF-8
without control characters, `/`, or `\`; it is informational and MUST NOT be
interpreted as a filesystem path.

The signatures cover the contextualized SHA-384 hash of every field through
the display name. Both signatures and the signer fingerprint MUST verify. The
Merkle leaf binds the object ID, chunk index, exact chunk length, and bytes.
Internal nodes bind their level and ordered child hashes with a distinct domain
separator. Odd nodes are duplicated; a one-leaf root is the leaf itself. The
empty root has a separate domain. Exact inputs are specified in
[`MANIFEST.md`](MANIFEST.md), and the fixed-memory reduction algorithm is
specified in [`MERKLE_REDUCTION.md`](MERKLE_REDUCTION.md).

Because a logical manifest exceeds the baseline datagram, each MANIFEST TLV is
a fragment:

```text
Object Slot u32 | Manifest Length u16 | Fragment Offset u16 | Fragment[N]
```

Fragments are non-empty and remain inside the declared logical length. For
each admitted manifest, the receiver takes one fixed 3,775-byte slot and a
receipt bitmap from a bounded pool. Identical overlaps are ignored;
conflicting overlaps abort the object. The object is not installed until
complete reassembly, exact logical decoding, signer identity matching, and
both signature verifications succeed.

Wire-visible identifiers are never global content hashes. A resume exchange
sends a range-compressed bitmap of verified chunks inside encrypted CONTROL
packets. Each RESUME value describes one window:

```text
Sequence u64 | Object Slot u32 | Window Start u32
             | Window Chunk Count u32 | Flags u8 | Range Count u8
             | Range Count * (Relative Start u32 | Chunk Count u32)
```

`Window Chunk Count` is non-zero and the exclusive end of the window MUST NOT
exceed `2^32` or the manifest chunk count. In `Flags`, bit 0 is `FINAL_WINDOW`
and bits 7 through 1 are zero. `Range Count` is between 0 and 32 inclusive; an
empty list means that no chunk in the window is already verified. Range starts
are relative to `Window Start`. Counts are non-zero, ranges stay inside the
window, and the same sorted, non-overlapping, non-adjacent canonical rule as
COMMIT applies.

All windows in one snapshot carry the same sequence and object slot. The first
window starts at zero; each following window starts at the exclusive end of the
previous one. `FINAL_WINDOW` is set exactly on the window ending at the
manifest chunk count. A sender does not skip DATA until it has authenticated a
complete gap-free snapshot. Newer snapshot sequences replace older ones;
stale, duplicate, overlapping, or discontinuous windows are ignored or abort
that snapshot without changing committed state. The sender then transmits only
chunks absent from the verified ranges.

The fixed-capacity implementation contract, atomic update rules, exhaustion
behavior, and required event-loop ordering are defined in
[`TRANSFER_STATE.md`](TRANSFER_STATE.md).

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

The implemented receive contract is defined in
[`HANDSHAKE_STATE.md`](HANDSHAKE_STATE.md). A slot adds a fixed 2,048-byte
receipt bitmap and metadata. `INIT` admission parses fragment zero and exposes
the complete cookie before any slot is reserved. Identical overlaps are
idempotent; conflicting overlaps or changed message metadata clear the local
slot. The runtime supplies fixed pool capacity, post-cookie quotas, deadlines,
and terminal cleanup.

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
Capability bit 0 requests multipath, bit 1 resume, bit 2 periodic hybrid PQ
rekey, and bit 3 ECN feedback. Unknown capability bits are ignored. `Max UDP
Payload` is at least 1,200 and `Max Paths` is between 1 and 16.

#### RETRY

```text
Server Random[32] | Cookie Length u16 | Opaque Cookie[16..256]
```

The cookie is an authenticated, encrypted server token. Its plaintext binds the
source address and port, both random values, the offered version, both
Connection IDs, an expiry, and a hash of canonical HELLO. Its internal encoding
is server-local and is never parsed by the initiator.

The implemented server-local profile emits a fixed 226-byte cookie with format
version, key ID, 96-bit nonce, 193-byte encrypted binding, and 128-bit AEAD tag.
It uses a per-key nonce prefix plus monotonic counter, strict expiration, two
opening generations, exact IPv4 or IPv6 address binding, and fixed post-cookie
global/source quotas. The complete contract is specified in
[`RETRY_ADMISSION.md`](RETRY_ADMISSION.md).

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
The fail-closed provider and installation contract is defined in
[`AUTHENTICATION.md`](AUTHENTICATION.md).

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
treating paths that share a bottleneck as fully independent capacity. When
more than one validated path is concurrently eligible for DATA, the sender
MUST apply the coupled congestion-avoidance profile below. No more than 16
paths may participate in one coupling group.

For a maximum datagram size `MDS`, each path begins with:

```text
initial_cwnd = min(10 * MDS, max(2 * MDS, 14,720 bytes))
minimum_cwnd = 2 * MDS
```

The CUBIC constants are `beta=0.7`, `C=0.4`, and Reno-friendly `alpha=9/17`
before the previous congestion window is recovered, then `alpha=1`. Slow
start increases the congestion window by newly acknowledged bytes. On a new
congestion event, the slow-start threshold becomes 0.7 times the smaller of
the congestion window and the flight size immediately before the loss, never
below `minimum_cwnd`. Further losses from packets sent before that recovery
epoch do not reduce the window again. Fast convergence is enabled.

HyStart++ is enabled only for the initial slow start. It consumes at most one
raw RTT sample per authenticated ACK. The first sampled round ends at the
largest packet number already sent. A later sample for a packet beyond the
current boundary begins a new round, moves the current round's minimum RTT to
the previous-round minimum, and sets a new boundary at the largest packet
number sent.

After at least eight samples in a round, the sender computes:

```text
delay_threshold = max(4 ms, min(previous_round_min_rtt / 8, 16 ms))
```

If the current round minimum is at least the previous minimum plus this
threshold, the sender enters Conservative Slow Start (CSS). CSS increases the
window by one quarter of newly acknowledged bytes. Its baseline is the minimum
RTT that triggered CSS. If a CSS round obtains at least eight samples and its
minimum falls below the baseline, standard slow start resumes. Otherwise, CSS
lasts at most five rounds, including a partial transition round, and then sets
the slow-start threshold to the current window to enter CUBIC congestion
avoidance. A loss during either slow-start mode disables HyStart++ for the
remainder of the connection.

A successfully validated increase in the authenticated CE counter is a CUBIC
congestion event equivalent to loss. ECN feedback is processed before loss and
acknowledgement events from the same ACK. It does not release bytes-in-flight,
and loss plus CE can reduce the congestion window at most once in one recovery
epoch. Persistent congestion may still collapse the window to its minimum.

Congestion avoidance evaluates the RFC 9438 cubic window with fixed-point
integer arithmetic and accumulates sub-byte growth credit. The target used for
one RTT is bounded between the current window and 1.5 times that window.
Application-limited time is excluded from the CUBIC epoch.

Concurrent paths couple their increases using an integer profile derived from
the Experimental Linked Increases Algorithm in
[RFC 6356](https://www.rfc-editor.org/rfc/rfc6356.html). For active path `i`,
the effective window is `cwnd_i`, limited to `ssthresh_i` during recovery and
to `flight_i` while application limited. Paths with zero effective window do
not participate. The acknowledged path MUST have a non-zero effective window.

The reference path `max` maximizes `effective_i / rtt_i²`. With
`alpha_scale = 512`, the sender computes using checked integer arithmetic:

```text
aggregate = sum(effective_i)
normalized_sum = sum((rtt_max * effective_i) / rtt_i)
alpha_scaled = 512 * aggregate * effective_max / normalized_sum²

linked_growth = alpha_scaled * bytes_acked * MDS_i / (512 * aggregate)
reno_growth = bytes_acked * MDS_i / effective_i
```

The two growth values are accumulated as path-local Q32 credits before taking
whole bytes. For a congestion-avoidance ACK, actual window growth MUST NOT
exceed either the ordinary CUBIC proposal or
`min(linked_growth, reno_growth)`. The coupling cap does not apply during Slow
Start or Conservative Slow Start. Invalid snapshots, duplicate path
identifiers, exhausted fixed state, or arithmetic overflow MUST NOT increase a
window. Retiring a path clears its fractional coupling credit.

This is an experimental CUBIC/LIA profile, not LIA conformance: loss and ECN
decreases retain CUBIC `beta = 0.7` rather than the Reno behavior assumed by
RFC 6356. Shared-bottleneck fairness remains a release blocker. The complete
implementation contract and required measurements are in
[`MULTIPATH.md`](MULTIPATH.md).

The per-path pacer stores one next-departure timestamp. For a datagram or UDP
GSO batch of `bytes`, it computes the ceiling of:

```text
spacing_ns = bytes * smoothed_rtt_us * 1,000 / (cwnd * pacing_gain)
```

The pacing gain is 5/4 in slow start and 1 in congestion avoidance. A GSO
batch is paced by its total encoded byte count; segmentation does not make
bytes disappear from congestion accounting.

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
- Persistent-congestion and ECN ancillary-data integration with the production
  event loop.
- Physical shared-bottleneck fairness validation of the experimental
  CUBIC/LIA controller.
- Relay negotiation and behavior.
- Audited concrete authentication provider, bounded storage/Merkle integration,
  and transfer-control timeout wiring in the batched UDP runtime.
- Audited stateless-cookie AEAD adapter plus lease/reassembly ownership,
  amplification accounting, deadline, handshake AEAD, and state-lifecycle
  wiring in that runtime.
