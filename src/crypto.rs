//! Provider-neutral interfaces for standardized OGTP cryptographic primitives.

use crate::transcript::TranscriptSink;

/// SHA-384 digest size.
pub const SHA384_OUTPUT_LEN: usize = 48;
/// One SHA-384 digest.
pub type Sha384Digest = [u8; SHA384_OUTPUT_LEN];

/// Streaming SHA-384 operations shared by transcript, identity, and Merkle code.
///
/// A context receives canonical bytes through [`TranscriptSink`]. Providers
/// may wrap software hashes, hardware engines, or opaque cryptographic handles.
pub trait Sha384Provider {
    type Context: TranscriptSink;
    type Error;

    /// Starts one independent SHA-384 operation.
    ///
    /// # Errors
    ///
    /// Returns a provider-specific error when a context cannot be created.
    fn start_sha384(&self) -> Result<Self::Context, Self::Error>;

    /// Finalizes one SHA-384 operation and returns exactly 48 bytes.
    ///
    /// # Errors
    ///
    /// Returns a provider-specific error when hashing cannot be completed.
    fn finish_sha384(&self, context: Self::Context) -> Result<Sha384Digest, Self::Error>;
}

/// SHA-384 provider whose running contexts can be forked transactionally.
///
/// Handshake transcript state uses a fork as a candidate update and commits it
/// only after every required snapshot succeeds.
pub trait ForkableSha384Provider: Sha384Provider {
    /// Creates an independent context with exactly the same running hash state.
    ///
    /// # Errors
    ///
    /// Returns a provider-specific error when the context cannot be cloned or
    /// exported safely.
    fn fork_sha384(&self, context: &Self::Context) -> Result<Self::Context, Self::Error>;

    /// Returns the current digest without consuming or modifying `context`.
    ///
    /// # Errors
    ///
    /// Returns a provider-specific fork or finalization error.
    fn snapshot_sha384(&self, context: &Self::Context) -> Result<Sha384Digest, Self::Error> {
        let snapshot = self.fork_sha384(context)?;
        self.finish_sha384(snapshot)
    }
}
