//! Wire primitives for the experimental `OpenGate` Transfer Protocol.
//!
//! The default build contains allocation-free wire codecs, bounded flow
//! accounting, handshake serialization, and provider-neutral packet-protection
//! orchestration. The optional deterministic simulator is excluded from
//! production builds unless the `simulator` feature is enabled.

#![forbid(unsafe_code)]

pub mod flow;
pub mod handshake;
pub mod kdf;
pub mod protection;
#[cfg(any(test, feature = "simulator"))]
pub mod simulator;
pub mod transcript;
pub mod wire;
