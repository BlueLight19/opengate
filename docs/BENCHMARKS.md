# OGTP/1 Benchmark Plan

The terms "ultra-fast" and "low overhead" are translated here into
reproducible measurements. No number should be published without its full
configuration, confidence interval, and baseline comparison.

## Primary metrics

- Useful goodput in Gbit/s, excluding headers and retransmissions.
- Percentage of raw UDP throughput on the same path.
- CPU cycles per useful byte, separated into send and receive costs.
- System calls per million datagrams.
- Full memory copies per useful byte.
- Peak userspace and kernel memory per connection.
- p50, p95, and p99 completion time.
- Energy per GiB on platforms exposing reliable counters.
- Recovery time after complete path loss.

## Acceptance invariants

The final engine must provide:

1. no heap allocation per DATA packet in steady state;
2. memory bounded by the configured budget within 10%, independent of object
   size;
3. no growth in metadata for packets that have already been acknowledged;
4. at most one send system call per 32-datagram batch when GSO is active;
5. no IP fragmentation;
6. clean backpressure or termination instead of exceeding credits or memory;
7. no multipath gain obtained by disabling congestion fairness.

## Memory profiles

| Profile | RX | Kernel-pinned TX | Metadata | Retransmission cache | Target total |
|---|---:|---:|---:|---:|---:|
| Compact | 16 MiB | 16 MiB | 8 MiB | 0 | ≤48 MiB |
| Standard | 32 MiB | 32 MiB | 16 MiB | 32 MiB | ≤128 MiB |
| High throughput | 128 MiB | 128 MiB | 64 MiB | 192 MiB | ≤512 MiB |

These figures include control-structure headroom but exclude the global system
page cache. Measurements must therefore publish RSS, PSS, socket buffers, and
attributable page cache separately.

## Network matrix

| Scenario | RTT | Loss | Reordering | Paths |
|---|---:|---:|---:|---|
| LAN | <1 ms | 0% | 0% | Ethernet |
| Nearby Internet | 20 ms | 0.1% | 0.1% | Fiber |
| Long distance | 100 ms | 0.5% | 1% | Fiber |
| Mobile | 50–150 ms | 1–3% | 2% | Wi-Fi + 5G |
| Degraded | 200 ms | 5% | 5% | Two asymmetric paths |
| Failover | Variable | Complete outage | Variable | Ethernet to 5G |

`tc netem` is suitable for reproducible tests. Final experiments must also use
two physical hosts so loopback, veth, and deferred copies do not distort
zero-copy results.

Before wall-clock experiments, every loss-recovery and multipath change is run
through the logical-clock simulator described in [`SIMULATION.md`](SIMULATION.md).
The deterministic suite covers periodic loss, duplication, reordering, path
disablement, and preservation of already in-flight packets. It is a protocol
correctness gate, not a substitute for `netem` or physical-host measurements.

## Object sizes

- 1 KiB to measure handshake cost.
- 1 MiB for small transfers.
- 1 GiB for steady-state behavior.
- 100 GiB to detect leaks and drift.
- A multi-TiB logical sparse file to validate memory independence.

Content sets include incompressible bytes, zeros, repeated fragments, and
unaligned boundaries. OGTP does not implicitly compress data.

## Baselines

Each OGTP result must be compared on identical hardware with:

- raw UDP using the same datagram size;
- UDP plus the same AEAD without reliability;
- TCP or a reliable transfer reference;
- `sendmmsg`/`recvmmsg` without GSO/GRO;
- `io_uring` with and without zero-copy;
- AES-256-GCM and ChaCha20-Poly1305.

This decomposition separates protocol, cryptographic, and kernel-interface
costs.

## Multipath

Across truly independent bottlenecks, target goodput is at least 85% of the sum
of the single-path goodputs, subject to CPU and storage limits. Across paths
sharing a bottleneck, OGTP must not obtain a gain by consuming more capacity
than an equivalent single-path connection.

Required measurements:

- utilization and loss per path;
- chunks delivered out of order;
- retransmissions reinjected on another path;
- detection and recovery time after failure;
- duplicated bytes;
- accuracy of the estimated-arrival-time scheduler.

## Security and robustness workload

Performance alone is insufficient. The harness includes:

- packets truncated at every possible byte;
- maximum lengths and arithmetic overflow attempts;
- massive duplication and replay;
- ACK packets containing 0 through 32 additional ranges;
- millions of unknown DCIDs;
- incomplete handshake fragments;
- invalid authentication tags;
- key-phase changes at boundary conditions;
- memory pressure and artificially slow storage.

The required result is rejection with bounded time and memory, never a panic,
deadlock, or attacker-controlled allocation.
