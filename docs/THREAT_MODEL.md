# OGTP/1 Threat Model

Status: draft 0.1. This document describes the intended guarantees, not
guarantees already established by the current implementation.

## Protected assets

- Contents and encrypted metadata of transferred objects.
- Authenticity of both peers.
- Integrity, logical ordering, and completeness of an object.
- Past and current session keys.
- Reasonable availability of RAM, CPU, and connection tables.
- Inability of a relay to read or silently modify transferred data.

## Adversaries in scope

OGTP assumes that an attacker can:

- observe, drop, duplicate, delay, reorder, and inject datagrams;
- control a NAT, router, Wi-Fi network, rendezvous server, or relay;
- record traffic now and attempt to decrypt it later with a quantum computer;
- spoof UDP source addresses and launch amplification attacks;
- open many handshakes, send pathological fragments, and target parser worst
  cases;
- compromise a long-term identity key long after a session has ended.

## Trust assumptions

- At least one out-of-band method validates peer identity public keys.
- The operating system, random number generator, and endpoint are not
  compromised during the session.
- Selected cryptographic implementations are correct, constant-time where
  required, and resistant to known side channels.
- X25519 and ML-KEM-768 are not both broken during the handshake.
- Ed25519 and ML-DSA-65 are not both forgeable during authentication.

## Intended guarantees

After successful mutual authentication, OGTP aims to provide:

- confidentiality and integrity for every short-header packet;
- transcript binding for the version, cipher suites, identities, and negotiated
  parameters;
- forward secrecy after ephemeral secrets are erased;
- hybrid resistance to harvest-now-decrypt-later attacks;
- per-path replay protection;
- detection of object modification through AEAD tags, the manifest, and its
  Merkle root;
- content confidentiality against rendezvous services and relays.

## Non-goals

OGTP does not protect against:

- a compromised endpoint, kernel, firmware, or user account;
- analysis of timing, volume, addresses, or session duration;
- radio jamming, loss of every path, or volumetric DDoS;
- an authenticated peer intentionally sending a dangerous file;
- loss or exfiltration of a key before it is erased;
- incorrect initial identity validation.

Optional padding can reduce some leakage, but OGTP/1 does not claim traffic
analysis resistance.

## Attacks and mitigations

| Threat | Planned mitigation | Residual risk |
|---|---|---|
| Man-in-the-middle | Dual transcript signatures and pre-authenticated keys | Human pairing error |
| Future quantum decryption | Ephemeral X25519 + ML-KEM-768 | Implementation flaw or break of both families |
| Nonce reuse | Separate key per DCID, monotonic packet number, close before limit | State bug or snapshot restore |
| Replay | Per-path packet-number window, sequenced CONTROL values, and idempotent COMMIT accounting | CPU spent before rejection |
| ECN suppression or rewriting | Authenticated cumulative counters, sender-mark validation, per-path fallback to Not-ECT | An on-path attacker can still add CE or drop/delay traffic |
| UDP amplification | Stateless RETRY and 3x amplification limit | Botnet using valid source addresses |
| Handshake RAM exhaustion | Cookie before state, message limit, global and per-source quotas | Distributed source addresses |
| DATA RAM exhaustion | Credits, fixed pools, manifest bounds | Lower throughput under pressure |
| Cryptographic CPU exhaustion | Cookie before PQ operations, batching, quotas | Authenticated malicious peer |
| Path injection | Authenticated PATH_OFFER followed by challenge/response | Denial of service on the physical path |
| Traffic shifting | Per-path validation plus coupled congestion-avoidance growth | An on-path attacker can still degrade one path and redirect encrypted traffic |
| Downgrade | Version and suites signed into the transcript | Negotiation flaws still require audit |
| Chunk substitution | AEAD plus signed, domain-separated object/chunk/length Merkle inputs | Hash collision considered infeasible |
| Filename traversal | Signed name is informational UTF-8 and never a receiver path | Unsafe application policy can still choose a bad local path |
| Malicious relay | End-to-end encryption and replay protection | Timing metadata remains visible |

## Implementation rules

1. The network parser performs no allocation based on an unauthenticated
   length.
2. Every length is checked before arithmetic or slicing.
3. No plaintext is written or exposed before AEAD validation.
4. Secret and MAC comparisons use constant-time operations.
5. Keys remain isolated from XDP/eBPF code and are erased when they expire.
6. The fast path uses no Rust `unsafe` without an isolated module, explicit
   justification, Miri tests, and dedicated review.
7. Logs never contain keys, complete RETRY tokens, plaintext, or global hashes
   that enable possession-confirmation attacks.
8. Application 0-RTT is forbidden in OGTP/1.

## Validation required before production

- Published test vectors for every derivation and packet type.
- Continuous fuzzing of the fixed-capacity manifest and transfer-state code;
  deterministic conflicting-overlap and rollback tests already exist.
- Stateful fuzzing of bounded Merkle carries and irregular-tree finalization;
  deterministic reference-tree and provider-failure tests already exist.
- Continuous fuzzing of codecs, the state machine, and handshake fragmentation.
- Differential tests between two independent implementations.
- A formal handshake and key-update model, for example in Tamarin or ProVerif.
- Analysis and enforcement of AEAD usage limits.
- Shared-bottleneck fairness and traffic-shifting evaluation for coupled paths.
- Independent cryptographic and systems audits.
- A vulnerability reporting program and wire-version rotation strategy.
