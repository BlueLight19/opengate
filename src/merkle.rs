//! Provider-neutral, bounded-memory streaming Merkle reduction.

use core::fmt;

use crate::crypto::Sha384Digest;
pub use crate::crypto::Sha384Provider;
use crate::manifest::{
    MERKLE_ROOT_LEN, ManifestError, ManifestHeader, OBJECT_ID_LEN, feed_chunk_leaf_input,
    feed_empty_root_input, feed_merkle_node_input,
};

/// SHA-384 digest size used throughout the object tree.
pub type MerkleHash = Sha384Digest;

/// Number of perfect-subtree slots needed for every representable `u32` chunk count.
pub const MAX_MERKLE_LEVELS: usize = u32::BITS as usize;

/// Opaque result of hashing one geometrically valid object chunk.
///
/// A hashed chunk may be held in a bounded reorder queue and later inserted
/// into its object's reducer. Its digest is not proof of membership until the
/// complete tree matches the signed manifest root.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct HashedChunk {
    object_id: [u8; OBJECT_ID_LEN],
    chunk_index: u32,
    chunk_length: u32,
    digest: MerkleHash,
}

impl fmt::Debug for HashedChunk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HashedChunk")
            .field("chunk_index", &self.chunk_index)
            .field("chunk_length", &self.chunk_length)
            .finish_non_exhaustive()
    }
}

impl HashedChunk {
    /// Returns the object-local chunk index bound into the digest.
    #[must_use]
    pub const fn chunk_index(&self) -> u32 {
        self.chunk_index
    }

    /// Returns the exact byte length bound into the digest.
    #[must_use]
    pub const fn chunk_length(&self) -> u32 {
        self.chunk_length
    }

    /// Returns the domain-separated SHA-384 leaf digest.
    #[must_use]
    pub const fn digest(&self) -> &MerkleHash {
        &self.digest
    }
}

/// Result of inserting one sequential leaf into the reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MerklePushStatus {
    pub chunk_index: u32,
    pub received_chunks: u32,
    pub expected_chunks: u32,
}

/// Fixed-memory reducer for one installed manifest.
///
/// The reducer stores at most one 48-byte perfect-subtree root at each of 32
/// levels, independent of object size. Leaves must be inserted in chunk-index
/// order, but their hashing may happen earlier and out of order.
#[derive(Clone)]
pub struct MerkleReducer {
    header: ManifestHeader,
    received_chunks: u32,
    occupied_levels: u32,
    subtrees: [MerkleHash; MAX_MERKLE_LEVELS],
}

impl fmt::Debug for MerkleReducer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MerkleReducer")
            .field("received_chunks", &self.received_chunks)
            .field("expected_chunks", &self.header.chunk_count)
            .field("occupied_levels", &self.occupied_levels.count_ones())
            .finish_non_exhaustive()
    }
}

impl MerkleReducer {
    /// Creates an empty reducer after revalidating signed object geometry.
    ///
    /// # Errors
    ///
    /// Returns the manifest validation error for invalid geometry or identity
    /// fields.
    pub fn new(header: ManifestHeader) -> Result<Self, ManifestError> {
        header.validate()?;
        Ok(Self {
            header,
            received_chunks: 0,
            occupied_levels: 0,
            subtrees: [[0; MERKLE_ROOT_LEN]; MAX_MERKLE_LEVELS],
        })
    }

    /// Hashes any chunk of this object without changing reduction state.
    ///
    /// This permits multipath workers to hash completed chunks immediately.
    /// The resulting [`HashedChunk`] still has to enter `push_hashed_chunk` in
    /// strict index order.
    ///
    /// # Errors
    ///
    /// Returns an error for an index outside the signed geometry, an incorrect
    /// chunk length, arithmetic failure, or a SHA-384 provider failure.
    pub fn hash_chunk<P: Sha384Provider>(
        &self,
        provider: &P,
        chunk_index: u32,
        chunk: &[u8],
    ) -> Result<HashedChunk, MerkleError<P::Error>> {
        let expected_length = self.expected_chunk_length(chunk_index)?;
        if chunk.len() != usize::try_from(expected_length).map_err(|_| MerkleError::Overflow)? {
            return Err(MerkleError::ChunkLengthMismatch {
                chunk_index,
                expected: expected_length,
                actual: chunk.len(),
            });
        }

        let mut context = provider.start_sha384().map_err(MerkleError::Provider)?;
        feed_chunk_leaf_input(&mut context, &self.header.object_id, chunk_index, chunk)
            .map_err(MerkleError::Manifest)?;
        let digest = provider
            .finish_sha384(context)
            .map_err(MerkleError::Provider)?;
        Ok(HashedChunk {
            object_id: self.header.object_id,
            chunk_index,
            chunk_length: expected_length,
            digest,
        })
    }

    /// Hashes and inserts the next sequential object chunk atomically.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-sequential index, invalid length, exhausted
    /// geometry, arithmetic failure, or a SHA-384 provider failure. Reduction
    /// state remains unchanged on every error.
    pub fn push_chunk<P: Sha384Provider>(
        &mut self,
        provider: &P,
        chunk_index: u32,
        chunk: &[u8],
    ) -> Result<MerklePushStatus, MerkleError<P::Error>> {
        self.validate_next_index(chunk_index)?;
        let hashed = self.hash_chunk(provider, chunk_index, chunk)?;
        self.push_hashed_chunk(provider, hashed)
    }

    /// Inserts one previously hashed chunk in strict index order.
    ///
    /// Internal-node hashes are completed before any subtree slot changes, so
    /// a provider failure cannot partially advance the tree.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong object, a non-sequential index, invalid
    /// geometry, capacity/invariant failure, or a SHA-384 provider failure.
    pub fn push_hashed_chunk<P: Sha384Provider>(
        &mut self,
        provider: &P,
        hashed: HashedChunk,
    ) -> Result<MerklePushStatus, MerkleError<P::Error>> {
        if hashed.object_id != self.header.object_id {
            return Err(MerkleError::HashedChunkObjectMismatch);
        }
        self.validate_next_index(hashed.chunk_index)?;
        let expected_length = self.expected_chunk_length(hashed.chunk_index)?;
        if hashed.chunk_length != expected_length {
            return Err(MerkleError::ChunkLengthMismatch {
                chunk_index: hashed.chunk_index,
                expected: expected_length,
                actual: usize::try_from(hashed.chunk_length).map_err(|_| MerkleError::Overflow)?,
            });
        }

        let mut current = hashed.digest;
        let mut level = 0_usize;
        while level < MAX_MERKLE_LEVELS && self.level_occupied(level) {
            current = hash_node(
                provider,
                u32::try_from(level + 1).map_err(|_| MerkleError::Overflow)?,
                &self.subtrees[level],
                &current,
            )?;
            level += 1;
        }
        if level == MAX_MERKLE_LEVELS {
            return Err(MerkleError::TreeCapacityExceeded);
        }
        let received_chunks = self
            .received_chunks
            .checked_add(1)
            .ok_or(MerkleError::Overflow)?;

        for subtree in &mut self.subtrees[..level] {
            subtree.fill(0);
        }
        let lower_levels = if level == 0 { 0 } else { (1_u32 << level) - 1 };
        self.occupied_levels &= !lower_levels;
        self.subtrees[level] = current;
        self.occupied_levels |= 1_u32 << level;
        self.received_chunks = received_chunks;

        Ok(MerklePushStatus {
            chunk_index: hashed.chunk_index,
            received_chunks,
            expected_chunks: self.header.chunk_count,
        })
    }

    /// Computes the canonical root after every signed chunk has been inserted.
    ///
    /// Odd rightmost subtrees are duplicated at each required level without
    /// materializing missing leaves or a full level of hashes.
    ///
    /// # Errors
    ///
    /// Returns an error when chunks are missing, an internal invariant fails,
    /// arithmetic overflows, or the SHA-384 provider fails. This operation
    /// does not change reducer state and may be retried.
    pub fn computed_root<P: Sha384Provider>(
        &self,
        provider: &P,
    ) -> Result<MerkleHash, MerkleError<P::Error>> {
        if self.received_chunks != self.header.chunk_count {
            return Err(MerkleError::Incomplete {
                expected: self.header.chunk_count,
                received: self.received_chunks,
            });
        }
        if self.occupied_levels != self.received_chunks {
            return Err(MerkleError::TreeInvariantViolation);
        }
        if self.header.chunk_count == 0 {
            let mut context = provider.start_sha384().map_err(MerkleError::Provider)?;
            feed_empty_root_input(&mut context, &self.header.object_id);
            return provider
                .finish_sha384(context)
                .map_err(MerkleError::Provider);
        }

        let mut right: Option<(usize, MerkleHash)> = None;
        for level in 0..MAX_MERKLE_LEVELS {
            if !self.level_occupied(level) {
                continue;
            }
            right = Some(match right {
                None => (level, self.subtrees[level]),
                Some((mut right_level, mut right_hash)) => {
                    if right_level > level {
                        return Err(MerkleError::TreeInvariantViolation);
                    }
                    while right_level < level {
                        right_hash = hash_node(
                            provider,
                            u32::try_from(right_level + 1).map_err(|_| MerkleError::Overflow)?,
                            &right_hash,
                            &right_hash,
                        )?;
                        right_level += 1;
                    }
                    let combined = hash_node(
                        provider,
                        u32::try_from(level + 1).map_err(|_| MerkleError::Overflow)?,
                        &self.subtrees[level],
                        &right_hash,
                    )?;
                    (level + 1, combined)
                }
            });
        }
        right
            .map(|(_, hash)| hash)
            .ok_or(MerkleError::TreeInvariantViolation)
    }

    /// Computes and compares the complete root with the signed manifest root.
    ///
    /// # Errors
    ///
    /// Returns [`MerkleError::RootMismatch`] in addition to the failures from
    /// [`Self::computed_root`].
    pub fn verify_manifest_root<P: Sha384Provider>(
        &self,
        provider: &P,
    ) -> Result<(), MerkleError<P::Error>> {
        let actual = self.computed_root(provider)?;
        if actual != self.header.merkle_root {
            return Err(MerkleError::RootMismatch);
        }
        Ok(())
    }

    /// Returns the number of sequential leaves already reduced.
    #[must_use]
    pub const fn received_chunks(&self) -> u32 {
        self.received_chunks
    }

    /// Returns the exact signed number of chunks expected.
    #[must_use]
    pub const fn expected_chunks(&self) -> u32 {
        self.header.chunk_count
    }

    /// Returns whether every signed chunk has entered the reducer.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.received_chunks == self.header.chunk_count
    }

    fn validate_next_index<E>(&self, chunk_index: u32) -> Result<(), MerkleError<E>> {
        if chunk_index != self.received_chunks {
            return Err(MerkleError::ChunkIndexMismatch {
                expected: self.received_chunks,
                actual: chunk_index,
            });
        }
        if chunk_index >= self.header.chunk_count {
            return Err(MerkleError::ChunkIndexOutsideObject {
                index: chunk_index,
                chunk_count: self.header.chunk_count,
            });
        }
        Ok(())
    }

    fn expected_chunk_length<E>(&self, chunk_index: u32) -> Result<u32, MerkleError<E>> {
        if chunk_index >= self.header.chunk_count {
            return Err(MerkleError::ChunkIndexOutsideObject {
                index: chunk_index,
                chunk_count: self.header.chunk_count,
            });
        }
        let offset = u64::from(chunk_index)
            .checked_mul(u64::from(self.header.chunk_size))
            .ok_or(MerkleError::Overflow)?;
        let remaining = self
            .header
            .object_size
            .checked_sub(offset)
            .ok_or(MerkleError::Overflow)?;
        u32::try_from(remaining.min(u64::from(self.header.chunk_size)))
            .map_err(|_| MerkleError::Overflow)
    }

    fn level_occupied(&self, level: usize) -> bool {
        self.occupied_levels & (1_u32 << level) != 0
    }
}

fn hash_node<P: Sha384Provider>(
    provider: &P,
    level: u32,
    left: &MerkleHash,
    right: &MerkleHash,
) -> Result<MerkleHash, MerkleError<P::Error>> {
    let mut context = provider.start_sha384().map_err(MerkleError::Provider)?;
    feed_merkle_node_input(&mut context, level, left, right);
    provider
        .finish_sha384(context)
        .map_err(MerkleError::Provider)
}

/// Bounded Merkle hashing or reduction failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MerkleError<E> {
    Manifest(ManifestError),
    Provider(E),
    ChunkIndexOutsideObject {
        index: u32,
        chunk_count: u32,
    },
    ChunkIndexMismatch {
        expected: u32,
        actual: u32,
    },
    ChunkLengthMismatch {
        chunk_index: u32,
        expected: u32,
        actual: usize,
    },
    HashedChunkObjectMismatch,
    Incomplete {
        expected: u32,
        received: u32,
    },
    RootMismatch,
    TreeCapacityExceeded,
    TreeInvariantViolation,
    Overflow,
}

impl<E: fmt::Display> fmt::Display for MerkleError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(error) => error.fmt(formatter),
            Self::Provider(error) => write!(formatter, "SHA-384 provider failure: {error}"),
            Self::ChunkIndexOutsideObject { index, chunk_count } => write!(
                formatter,
                "chunk index {index} is outside object chunk count {chunk_count}"
            ),
            Self::ChunkIndexMismatch { expected, actual } => write!(
                formatter,
                "non-sequential chunk index: expected {expected}, got {actual}"
            ),
            Self::ChunkLengthMismatch {
                chunk_index,
                expected,
                actual,
            } => write!(
                formatter,
                "chunk {chunk_index} length mismatch: expected {expected}, got {actual}"
            ),
            Self::HashedChunkObjectMismatch => {
                formatter.write_str("hashed chunk belongs to a different object")
            }
            Self::Incomplete { expected, received } => write!(
                formatter,
                "Merkle tree incomplete: expected {expected} chunks, received {received}"
            ),
            Self::RootMismatch => {
                formatter.write_str("computed Merkle root does not match signed manifest")
            }
            Self::TreeCapacityExceeded => formatter.write_str("Merkle subtree capacity exceeded"),
            Self::TreeInvariantViolation => {
                formatter.write_str("Merkle reducer invariant violation")
            }
            Self::Overflow => formatter.write_str("Merkle accounting overflow"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for MerkleError<E> {}

#[cfg(test)]
mod tests {
    use core::cell::Cell;
    use core::convert::Infallible;

    use sha2::{Digest, Sha384};

    use super::*;
    use crate::handshake::IDENTITY_FINGERPRINT_LEN;
    use crate::manifest::{MERKLE_ROOT_LEN, MIN_CHUNK_SIZE};
    use crate::transcript::TranscriptSink;

    struct Sha384Context(Sha384);

    impl TranscriptSink for Sha384Context {
        fn update(&mut self, bytes: &[u8]) {
            self.0.update(bytes);
        }
    }

    struct RustCryptoSha384;

    impl Sha384Provider for RustCryptoSha384 {
        type Context = Sha384Context;
        type Error = Infallible;

        fn start_sha384(&self) -> Result<Self::Context, Self::Error> {
            Ok(Sha384Context(Sha384::new()))
        }

        fn finish_sha384(&self, context: Self::Context) -> Result<MerkleHash, Self::Error> {
            Ok(context.0.finalize().into())
        }
    }

    struct FailingSha384 {
        remaining_finishes: Cell<usize>,
    }

    impl Sha384Provider for FailingSha384 {
        type Context = Sha384Context;
        type Error = &'static str;

        fn start_sha384(&self) -> Result<Self::Context, Self::Error> {
            Ok(Sha384Context(Sha384::new()))
        }

        fn finish_sha384(&self, context: Self::Context) -> Result<MerkleHash, Self::Error> {
            let remaining = self.remaining_finishes.get();
            if remaining == 0 {
                return Err("injected failure");
            }
            self.remaining_finishes.set(remaining - 1);
            Ok(context.0.finalize().into())
        }
    }

    fn header(object_id_byte: u8, object_size: u64, root: MerkleHash) -> ManifestHeader {
        let chunk_count = if object_size == 0 {
            0
        } else {
            u32::try_from((object_size - 1) / u64::from(MIN_CHUNK_SIZE) + 1)
                .expect("small test object")
        };
        ManifestHeader {
            object_id: [object_id_byte; OBJECT_ID_LEN],
            object_size,
            chunk_size: MIN_CHUNK_SIZE,
            chunk_count,
            merkle_root: root,
            signer_identity_fingerprint: [0x33; IDENTITY_FINGERPRINT_LEN],
        }
    }

    fn object_chunks(chunk_count: usize) -> Vec<Vec<u8>> {
        (0..chunk_count)
            .map(|chunk_index| {
                let length = if chunk_index + 1 == chunk_count {
                    123
                } else {
                    usize::try_from(MIN_CHUNK_SIZE).expect("chunk size fits")
                };
                (0..length)
                    .map(|offset| {
                        u8::try_from((chunk_index * 17 + offset * 31 + 7) & 0xff)
                            .expect("masked byte fits")
                    })
                    .collect()
            })
            .collect()
    }

    fn object_size(chunks: &[Vec<u8>]) -> u64 {
        chunks
            .iter()
            .map(|chunk| u64::try_from(chunk.len()).expect("test chunk fits"))
            .sum()
    }

    fn reference_root(object_id: &[u8; OBJECT_ID_LEN], chunks: &[Vec<u8>]) -> MerkleHash {
        let provider = RustCryptoSha384;
        if chunks.is_empty() {
            let mut context = provider.start_sha384().expect("infallible provider");
            feed_empty_root_input(&mut context, object_id);
            return provider
                .finish_sha384(context)
                .expect("infallible provider");
        }

        let mut nodes = chunks
            .iter()
            .enumerate()
            .map(|(index, chunk)| {
                let mut context = provider.start_sha384().expect("infallible provider");
                feed_chunk_leaf_input(
                    &mut context,
                    object_id,
                    u32::try_from(index).expect("test index fits"),
                    chunk,
                )
                .expect("test chunk length fits");
                provider
                    .finish_sha384(context)
                    .expect("infallible provider")
            })
            .collect::<Vec<_>>();
        let mut level = 1_u32;
        while nodes.len() > 1 {
            if nodes.len() % 2 != 0 {
                nodes.push(*nodes.last().expect("non-empty level"));
            }
            nodes = nodes
                .chunks_exact(2)
                .map(|pair| {
                    let mut context = provider.start_sha384().expect("infallible provider");
                    feed_merkle_node_input(&mut context, level, &pair[0], &pair[1]);
                    provider
                        .finish_sha384(context)
                        .expect("infallible provider")
                })
                .collect();
            level += 1;
        }
        nodes[0]
    }

    #[test]
    fn streaming_roots_match_level_materialization_for_irregular_trees() {
        let provider = RustCryptoSha384;
        for chunk_count in [0, 1, 2, 3, 5, 6, 7, 8, 9] {
            let chunks = object_chunks(chunk_count);
            let mut manifest = header(0x11, object_size(&chunks), [0x55; MERKLE_ROOT_LEN]);
            manifest.merkle_root = reference_root(&manifest.object_id, &chunks);
            let mut reducer = MerkleReducer::new(manifest).expect("geometry is valid");
            for (index, chunk) in chunks.iter().enumerate() {
                let status = reducer
                    .push_chunk(
                        &provider,
                        u32::try_from(index).expect("test index fits"),
                        chunk,
                    )
                    .expect("chunk reduces");
                assert_eq!(
                    status.received_chunks,
                    u32::try_from(index + 1).expect("test count fits")
                );
            }
            assert!(reducer.is_complete());
            assert_eq!(
                reducer
                    .computed_root(&provider)
                    .expect("complete root computes"),
                manifest.merkle_root
            );
            reducer
                .verify_manifest_root(&provider)
                .expect("signed root matches");
        }
    }

    #[test]
    fn chunks_may_hash_out_of_order_but_reduce_only_in_order() {
        let provider = RustCryptoSha384;
        let chunks = object_chunks(7);
        let mut manifest = header(0x22, object_size(&chunks), [0x55; MERKLE_ROOT_LEN]);
        manifest.merkle_root = reference_root(&manifest.object_id, &chunks);
        let mut reducer = MerkleReducer::new(manifest).expect("geometry is valid");

        let mut hashed = chunks
            .iter()
            .enumerate()
            .rev()
            .map(|(index, chunk)| {
                reducer
                    .hash_chunk(
                        &provider,
                        u32::try_from(index).expect("test index fits"),
                        chunk,
                    )
                    .expect("out-of-order hashing is valid")
            })
            .collect::<Vec<_>>();
        assert_eq!(reducer.received_chunks(), 0);
        assert_eq!(hashed[0].chunk_index(), 6);
        hashed.reverse();
        for leaf in hashed {
            reducer
                .push_hashed_chunk(&provider, leaf)
                .expect("ordered leaf reduces");
        }
        reducer
            .verify_manifest_root(&provider)
            .expect("root matches");
    }

    #[test]
    fn geometry_order_completion_and_root_mismatch_fail_closed() {
        let provider = RustCryptoSha384;
        let chunks = object_chunks(2);
        let root = reference_root(&[0x44; OBJECT_ID_LEN], &chunks);
        let manifest = header(0x44, object_size(&chunks), root);
        let mut reducer = MerkleReducer::new(manifest).expect("geometry is valid");

        assert_eq!(
            reducer.computed_root(&provider),
            Err(MerkleError::Incomplete {
                expected: 2,
                received: 0,
            })
        );
        assert_eq!(
            reducer.push_chunk(&provider, 1, &chunks[1]),
            Err(MerkleError::ChunkIndexMismatch {
                expected: 0,
                actual: 1,
            })
        );
        assert_eq!(reducer.received_chunks(), 0);
        assert_eq!(
            reducer.push_chunk(&provider, 0, &chunks[0][..chunks[0].len() - 1]),
            Err(MerkleError::ChunkLengthMismatch {
                chunk_index: 0,
                expected: MIN_CHUNK_SIZE,
                actual: chunks[0].len() - 1,
            })
        );
        assert_eq!(reducer.received_chunks(), 0);
        for (index, chunk) in chunks.iter().enumerate() {
            reducer
                .push_chunk(
                    &provider,
                    u32::try_from(index).expect("test index fits"),
                    chunk,
                )
                .expect("valid chunk reduces");
        }

        let mut wrong_manifest = manifest;
        wrong_manifest.merkle_root = [0xaa; MERKLE_ROOT_LEN];
        let mut wrong = MerkleReducer::new(wrong_manifest).expect("geometry is valid");
        for (index, chunk) in chunks.iter().enumerate() {
            wrong
                .push_chunk(
                    &provider,
                    u32::try_from(index).expect("test index fits"),
                    chunk,
                )
                .expect("valid chunk reduces");
        }
        assert!(matches!(
            wrong.verify_manifest_root(&provider),
            Err(MerkleError::RootMismatch)
        ));
    }

    #[test]
    fn provider_failure_during_carry_does_not_advance_state() {
        let chunks = object_chunks(2);
        let manifest = header(0x66, object_size(&chunks), [0x55; MERKLE_ROOT_LEN]);
        let mut reducer = MerkleReducer::new(manifest).expect("geometry is valid");
        let failing = FailingSha384 {
            remaining_finishes: Cell::new(2),
        };

        reducer
            .push_chunk(&failing, 0, &chunks[0])
            .expect("first leaf consumes one hash");
        assert_eq!(
            reducer.push_chunk(&failing, 1, &chunks[1]),
            Err(MerkleError::Provider("injected failure"))
        );
        assert_eq!(reducer.received_chunks(), 1);

        reducer
            .push_chunk(&RustCryptoSha384, 1, &chunks[1])
            .expect("retry from unchanged state succeeds");
        assert_eq!(reducer.received_chunks(), 2);
    }

    #[test]
    fn hashed_chunk_is_bound_to_its_object() {
        let provider = RustCryptoSha384;
        let chunks = object_chunks(1);
        let first = MerkleReducer::new(header(0x77, object_size(&chunks), [0x55; MERKLE_ROOT_LEN]))
            .expect("geometry is valid");
        let leaf = first
            .hash_chunk(&provider, 0, &chunks[0])
            .expect("leaf hashes");
        let mut second =
            MerkleReducer::new(header(0x88, object_size(&chunks), [0x55; MERKLE_ROOT_LEN]))
                .expect("geometry is valid");
        assert_eq!(
            second.push_hashed_chunk(&provider, leaf),
            Err(MerkleError::HashedChunkObjectMismatch)
        );
        assert_eq!(second.received_chunks(), 0);
    }

    #[test]
    fn deepest_representable_carry_is_bounded_and_transactional() {
        let manifest = ManifestHeader {
            object_id: [0x99; OBJECT_ID_LEN],
            object_size: u64::from(u32::MAX) * u64::from(MIN_CHUNK_SIZE),
            chunk_size: MIN_CHUNK_SIZE,
            chunk_count: u32::MAX,
            merkle_root: [0x55; MERKLE_ROOT_LEN],
            signer_identity_fingerprint: [0x33; IDENTITY_FINGERPRINT_LEN],
        };
        let mut reducer = MerkleReducer::new(manifest).expect("maximum geometry is valid");
        reducer.received_chunks = (1_u32 << 31) - 1;
        reducer.occupied_levels = reducer.received_chunks;
        for (level, subtree) in reducer.subtrees.iter_mut().enumerate().take(31) {
            subtree.fill(u8::try_from(level + 1).expect("level fits"));
        }
        let before_subtrees = reducer.subtrees;
        let leaf = HashedChunk {
            object_id: manifest.object_id,
            chunk_index: reducer.received_chunks,
            chunk_length: MIN_CHUNK_SIZE,
            digest: [0xaa; MERKLE_ROOT_LEN],
        };
        let failing = FailingSha384 {
            remaining_finishes: Cell::new(30),
        };

        assert_eq!(
            reducer.push_hashed_chunk(&failing, leaf),
            Err(MerkleError::Provider("injected failure"))
        );
        assert_eq!(reducer.received_chunks, (1_u32 << 31) - 1);
        assert_eq!(reducer.occupied_levels, (1_u32 << 31) - 1);
        assert_eq!(reducer.subtrees, before_subtrees);

        reducer
            .push_hashed_chunk(&RustCryptoSha384, leaf)
            .expect("31-level carry succeeds");
        assert_eq!(reducer.received_chunks, 1_u32 << 31);
        assert_eq!(reducer.occupied_levels, 1_u32 << 31);
    }
}
