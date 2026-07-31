# OGTP/1 Deterministic Network Simulator

Status: **draft 0.2 test infrastructure**.

The simulator gives protocol state machines a reproducible logical-clock
network. It exists to make loss recovery, ACK generation, retransmission,
multipath scheduling, and failover tests independent of operating-system timing
and pseudorandom seeds.

It is not part of the production data path. The module is available to unit
tests and can be exposed to external test harnesses with the `simulator` Cargo
feature:

```sh
cargo test --all-features
```

## Model

Each path has an independent profile:

- base one-way delay in logical ticks;
- optional loss of every Nth enabled transmission;
- optional duplication of every Nth enabled transmission;
- optional extra delay on every Nth enabled transmission, producing
  reordering when later packets arrive first;
- a deterministic delay for the duplicated copy.

Fault rules use the one-based transmission count of their path. Loss is applied
before duplication and reordering. A lost packet therefore produces no queued
copy. Packets sent to a disabled path consume a connection-wide simulation
sequence number but do not advance that path's enabled-transmission counter.

Disabling a path only blocks new transmissions. Packets already in flight stay
queued and may arrive after failover, which exercises duplicate suppression and
late-ACK handling. Deliveries at the same logical tick preserve injection order.

## Reproducibility contract

Given the same ordered calls, path profiles, and payloads, the simulator MUST
produce the same sequence numbers, outcomes, delivery ticks, duplicate flags,
and payload order on every run. It reads neither wall-clock time nor entropy.
All logical counters reject overflow instead of wrapping.

The initial unit scenarios prove:

1. the exact interaction of loss, duplication, and induced reordering;
2. failover to a lower-latency path while preserving packets already in flight
   on the disabled path;
3. packet-threshold loss detection, reinjection on an alternate path, target
   acknowledgement, and subsequent late arrival of the original packet.

## Deliberate limitations

The current model does not simulate serialization bandwidth, queue capacity,
ECN, correlated burst loss, NAT rebinding, MTU changes, or congestion-control
feedback. Those behaviors will be added as scripted events when the associated
protocol state machines exist. Performance conclusions MUST come from the
benchmark matrix and real kernel/network measurements, never from logical
ticks.
