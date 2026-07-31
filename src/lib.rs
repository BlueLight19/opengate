//! Wire primitives for the experimental `OpenGate` Transfer Protocol.
//!
//! This crate currently implements only the allocation-free codec for the
//! unprotected short header and DATA plaintext. Cryptography, UDP I/O and
//! congestion control intentionally remain outside this crate.

#![forbid(unsafe_code)]

pub mod flow;
pub mod wire;
