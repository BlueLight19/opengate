//! Canonical signed object manifests and bounded MANIFEST fragmentation.

use core::fmt;

use crate::handshake::{ED25519_SIGNATURE_LEN, IDENTITY_FINGERPRINT_LEN, ML_DSA_65_SIGNATURE_LEN};
use crate::transcript::{SIGNATURE_CONTEXT_PREFIX_LEN, TranscriptSink};
use crate::wire::{WireError, read_u16, read_u32, read_u64};

/// OGTP/1 manifest format identifier.
pub const MANIFEST_FORMAT_VERSION: u8 = 1;
/// Random object identifier size.
pub const OBJECT_ID_LEN: usize = 32;
/// SHA-384 Merkle root size.
pub const MERKLE_ROOT_LEN: usize = 48;
/// Minimum supported chunk size: 64 KiB.
pub const MIN_CHUNK_SIZE: u32 = 64 * 1_024;
/// Maximum supported chunk size: 16 MiB.
pub const MAX_CHUNK_SIZE: u32 = 16 * 1_024 * 1_024;
/// Maximum UTF-8 byte length of the informational display name.
pub const MAX_DISPLAY_NAME_LEN: usize = 255;
/// Fixed unsigned bytes preceding the display name.
pub const MANIFEST_UNSIGNED_FIXED_LEN: usize = 147;
/// Smallest complete signed manifest.
pub const MIN_SIGNED_MANIFEST_LEN: usize =
    MANIFEST_UNSIGNED_FIXED_LEN + ED25519_SIGNATURE_LEN + ML_DSA_65_SIGNATURE_LEN;
/// Largest complete signed manifest.
pub const MAX_SIGNED_MANIFEST_LEN: usize = MIN_SIGNED_MANIFEST_LEN + MAX_DISPLAY_NAME_LEN;
/// Fixed bytes preceding a logical-manifest fragment.
pub const MANIFEST_FRAGMENT_FIXED_LEN: usize = 8;
/// Context used to sign the SHA-384 hash of the unsigned manifest.
pub const MANIFEST_SIGNATURE_CONTEXT: &[u8] = b"OGTP/1 object manifest";
/// Domain separator for a Merkle leaf input.
pub const MERKLE_LEAF_CONTEXT: &[u8] = b"OGTP/1 chunk\x00";
/// Domain separator for a Merkle internal-node input.
pub const MERKLE_NODE_CONTEXT: &[u8] = b"OGTP/1 node\x00";
/// Domain separator for an empty-object Merkle root input.
pub const MERKLE_EMPTY_CONTEXT: &[u8] = b"OGTP/1 empty\x00";

const FLAGS_OFFSET: usize = 1;
const OBJECT_ID_OFFSET: usize = 2;
const OBJECT_SIZE_OFFSET: usize = 34;
const CHUNK_SIZE_OFFSET: usize = 42;
const CHUNK_COUNT_OFFSET: usize = 46;
const MERKLE_ROOT_OFFSET: usize = 50;
const SIGNER_FINGERPRINT_OFFSET: usize = 98;
const DISPLAY_NAME_LENGTH_OFFSET: usize = 146;

/// Fixed fields covered by both object signatures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestHeader {
    /// Random, non-zero object identity that is not a content hash.
    pub object_id: [u8; OBJECT_ID_LEN],
    /// Exact object length in bytes.
    pub object_size: u64,
    /// Power-of-two chunk size in bytes.
    pub chunk_size: u32,
    /// Exact ceiling of `object_size / chunk_size`.
    pub chunk_count: u32,
    /// SHA-384 root of the domain-separated chunk tree.
    pub merkle_root: [u8; MERKLE_ROOT_LEN],
    /// SHA-384 fingerprint of the identity whose keys sign this manifest.
    pub signer_identity_fingerprint: [u8; IDENTITY_FINGERPRINT_LEN],
}

impl ManifestHeader {
    /// Validates geometry and non-zero identity fields.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid object identity, fingerprint, root,
    /// chunk size, or chunk count.
    pub fn validate(self) -> Result<(), ManifestError> {
        if self.object_id.iter().all(|byte| *byte == 0) {
            return Err(ManifestError::ZeroObjectId);
        }
        if self
            .signer_identity_fingerprint
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(ManifestError::ZeroSignerFingerprint);
        }
        if self.merkle_root.iter().all(|byte| *byte == 0) {
            return Err(ManifestError::ZeroMerkleRoot);
        }
        if !self.chunk_size.is_power_of_two()
            || !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&self.chunk_size)
        {
            return Err(ManifestError::InvalidChunkSize(self.chunk_size));
        }
        let expected = expected_chunk_count(self.object_size, self.chunk_size);
        if expected != u64::from(self.chunk_count) {
            return Err(ManifestError::InvalidChunkCount {
                expected,
                actual: self.chunk_count,
            });
        }
        Ok(())
    }

    /// Encodes the canonical unsigned content consumed by SHA-384.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid fields or display name, arithmetic
    /// overflow, or an undersized output.
    pub fn encode_unsigned(
        self,
        display_name: &str,
        output: &mut [u8],
    ) -> Result<usize, ManifestError> {
        self.validate()?;
        validate_display_name(display_name)?;
        let needed = unsigned_length(display_name.len())?;
        require_output(output, needed)?;
        let prefix = self.encoded_prefix(display_name.len())?;
        output[..MANIFEST_UNSIGNED_FIXED_LEN].copy_from_slice(&prefix);
        output[MANIFEST_UNSIGNED_FIXED_LEN..needed].copy_from_slice(display_name.as_bytes());
        Ok(needed)
    }

    /// Streams canonical unsigned content directly into a caller-owned hash.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid fields or an invalid display name.
    pub fn feed_unsigned(
        self,
        display_name: &str,
        sink: &mut impl TranscriptSink,
    ) -> Result<(), ManifestError> {
        self.validate()?;
        validate_display_name(display_name)?;
        let prefix = self.encoded_prefix(display_name.len())?;
        sink.update(&prefix);
        sink.update(display_name.as_bytes());
        Ok(())
    }

    /// Encodes unsigned content followed by fixed Ed25519 and ML-DSA-65 signatures.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid manifest fields, signature sizes, or an
    /// undersized output.
    pub fn encode_signed(
        self,
        display_name: &str,
        ed25519_signature: &[u8],
        ml_dsa_65_signature: &[u8],
        output: &mut [u8],
    ) -> Result<usize, ManifestError> {
        validate_signature_length(
            "Ed25519 signature",
            ed25519_signature.len(),
            ED25519_SIGNATURE_LEN,
        )?;
        validate_signature_length(
            "ML-DSA-65 signature",
            ml_dsa_65_signature.len(),
            ML_DSA_65_SIGNATURE_LEN,
        )?;
        self.validate()?;
        validate_display_name(display_name)?;
        let unsigned_len = unsigned_length(display_name.len())?;
        let needed = unsigned_len
            .checked_add(ED25519_SIGNATURE_LEN)
            .and_then(|value| value.checked_add(ML_DSA_65_SIGNATURE_LEN))
            .ok_or(WireError::LengthOverflow)?;
        require_output(output, needed)?;

        self.encode_unsigned(display_name, &mut output[..unsigned_len])?;
        let ed25519_end = unsigned_len + ED25519_SIGNATURE_LEN;
        output[unsigned_len..ed25519_end].copy_from_slice(ed25519_signature);
        output[ed25519_end..needed].copy_from_slice(ml_dsa_65_signature);
        Ok(needed)
    }

    fn encoded_prefix(
        self,
        display_name_length: usize,
    ) -> Result<[u8; MANIFEST_UNSIGNED_FIXED_LEN], ManifestError> {
        let mut prefix = [0_u8; MANIFEST_UNSIGNED_FIXED_LEN];
        prefix[0] = MANIFEST_FORMAT_VERSION;
        prefix[FLAGS_OFFSET] = 0;
        prefix[OBJECT_ID_OFFSET..OBJECT_SIZE_OFFSET].copy_from_slice(&self.object_id);
        prefix[OBJECT_SIZE_OFFSET..CHUNK_SIZE_OFFSET]
            .copy_from_slice(&self.object_size.to_be_bytes());
        prefix[CHUNK_SIZE_OFFSET..CHUNK_COUNT_OFFSET]
            .copy_from_slice(&self.chunk_size.to_be_bytes());
        prefix[CHUNK_COUNT_OFFSET..MERKLE_ROOT_OFFSET]
            .copy_from_slice(&self.chunk_count.to_be_bytes());
        prefix[MERKLE_ROOT_OFFSET..SIGNER_FINGERPRINT_OFFSET].copy_from_slice(&self.merkle_root);
        prefix[SIGNER_FINGERPRINT_OFFSET..DISPLAY_NAME_LENGTH_OFFSET]
            .copy_from_slice(&self.signer_identity_fingerprint);
        prefix[DISPLAY_NAME_LENGTH_OFFSET] =
            u8::try_from(display_name_length).map_err(|_| ManifestError::InvalidDisplayName)?;
        Ok(prefix)
    }
}

/// Borrowed canonical signed manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Manifest<'a> {
    /// Validated fixed signed fields.
    pub header: ManifestHeader,
    /// Informational UTF-8 name; never a filesystem path.
    pub display_name: &'a str,
    unsigned_content: &'a [u8],
    ed25519_signature: &'a [u8],
    ml_dsa_65_signature: &'a [u8],
}

impl<'a> Manifest<'a> {
    /// Decodes and validates one exact logical signed manifest.
    ///
    /// This validates representation and geometry, not either signature or the
    /// Merkle root.
    ///
    /// # Errors
    ///
    /// Returns an error for truncation, trailing bytes, unsupported fields,
    /// invalid UTF-8 metadata, or inconsistent chunk geometry.
    pub fn decode(input: &'a [u8]) -> Result<Self, ManifestError> {
        if input.len() < MIN_SIGNED_MANIFEST_LEN {
            return Err(WireError::PacketTooShort {
                minimum: MIN_SIGNED_MANIFEST_LEN,
                actual: input.len(),
            }
            .into());
        }
        if input[0] != MANIFEST_FORMAT_VERSION {
            return Err(ManifestError::UnsupportedVersion(input[0]));
        }
        if input[FLAGS_OFFSET] != 0 {
            return Err(ManifestError::InvalidFlags(input[FLAGS_OFFSET]));
        }
        let display_name_length = usize::from(input[DISPLAY_NAME_LENGTH_OFFSET]);
        let unsigned_len = unsigned_length(display_name_length)?;
        let expected = unsigned_len
            .checked_add(ED25519_SIGNATURE_LEN)
            .and_then(|value| value.checked_add(ML_DSA_65_SIGNATURE_LEN))
            .ok_or(WireError::LengthOverflow)?;
        require_exact(input, expected)?;

        let display_name_bytes = &input[MANIFEST_UNSIGNED_FIXED_LEN..unsigned_len];
        let display_name = core::str::from_utf8(display_name_bytes)
            .map_err(|_| ManifestError::InvalidDisplayName)?;
        validate_display_name(display_name)?;
        let header = ManifestHeader {
            object_id: copy_array(input, OBJECT_ID_OFFSET)?,
            object_size: read_u64(input, OBJECT_SIZE_OFFSET)?,
            chunk_size: read_u32(input, CHUNK_SIZE_OFFSET)?,
            chunk_count: read_u32(input, CHUNK_COUNT_OFFSET)?,
            merkle_root: copy_array(input, MERKLE_ROOT_OFFSET)?,
            signer_identity_fingerprint: copy_array(input, SIGNER_FINGERPRINT_OFFSET)?,
        };
        header.validate()?;
        let ed25519_end = unsigned_len + ED25519_SIGNATURE_LEN;
        Ok(Self {
            header,
            display_name,
            unsigned_content: &input[..unsigned_len],
            ed25519_signature: &input[unsigned_len..ed25519_end],
            ml_dsa_65_signature: &input[ed25519_end..expected],
        })
    }

    /// Returns the exact content whose SHA-384 hash is signed.
    #[must_use]
    pub const fn unsigned_content(&self) -> &'a [u8] {
        self.unsigned_content
    }

    /// Returns the fixed 64-byte Ed25519 signature.
    #[must_use]
    pub const fn ed25519_signature(&self) -> &'a [u8] {
        self.ed25519_signature
    }

    /// Returns the fixed 3,309-byte ML-DSA-65 signature.
    #[must_use]
    pub const fn ml_dsa_65_signature(&self) -> &'a [u8] {
        self.ml_dsa_65_signature
    }
}

/// Borrowed MANIFEST CONTROL value carrying part of a logical manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestFragment<'a> {
    /// Connection-local object slot being installed.
    pub object_slot: u32,
    /// Total logical signed-manifest length.
    pub manifest_length: u16,
    /// Byte offset of this fragment in the logical manifest.
    pub fragment_offset: u16,
    /// Borrowed logical-manifest bytes.
    pub fragment: &'a [u8],
}

impl<'a> ManifestFragment<'a> {
    /// Encodes one exact MANIFEST CONTROL value.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid logical length, empty or out-of-bounds
    /// fragment, or an undersized output.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, ManifestError> {
        validate_manifest_length(usize::from(self.manifest_length))?;
        validate_fragment(
            usize::from(self.manifest_length),
            usize::from(self.fragment_offset),
            self.fragment.len(),
        )?;
        let needed = MANIFEST_FRAGMENT_FIXED_LEN
            .checked_add(self.fragment.len())
            .ok_or(WireError::LengthOverflow)?;
        require_output(output, needed)?;
        output[0..4].copy_from_slice(&self.object_slot.to_be_bytes());
        output[4..6].copy_from_slice(&self.manifest_length.to_be_bytes());
        output[6..8].copy_from_slice(&self.fragment_offset.to_be_bytes());
        output[8..needed].copy_from_slice(self.fragment);
        Ok(needed)
    }

    /// Decodes one exact MANIFEST CONTROL value without copying its fragment.
    ///
    /// # Errors
    ///
    /// Returns an error for truncation or invalid logical fragment bounds.
    pub fn decode(input: &'a [u8]) -> Result<Self, ManifestError> {
        let minimum = MANIFEST_FRAGMENT_FIXED_LEN + 1;
        if input.len() < minimum {
            return Err(WireError::PacketTooShort {
                minimum,
                actual: input.len(),
            }
            .into());
        }
        let manifest_length = read_u16(input, 4)?;
        let fragment_offset = read_u16(input, 6)?;
        let fragment = &input[MANIFEST_FRAGMENT_FIXED_LEN..];
        validate_manifest_length(usize::from(manifest_length))?;
        validate_fragment(
            usize::from(manifest_length),
            usize::from(fragment_offset),
            fragment.len(),
        )?;
        Ok(Self {
            object_slot: read_u32(input, 0)?,
            manifest_length,
            fragment_offset,
            fragment,
        })
    }
}

/// Streams the contextualized input signed by both manifest signature schemes.
pub fn feed_manifest_signature_input(
    sink: &mut impl TranscriptSink,
    unsigned_content_hash: &[u8; MERKLE_ROOT_LEN],
) {
    sink.update(&[0x20; SIGNATURE_CONTEXT_PREFIX_LEN]);
    sink.update(MANIFEST_SIGNATURE_CONTEXT);
    sink.update(&[0]);
    sink.update(unsigned_content_hash);
}

/// Streams the exact SHA-384 input for one chunk leaf.
///
/// # Errors
///
/// Returns an error when the chunk length does not fit the signed 32-bit field.
pub fn feed_chunk_leaf_input(
    sink: &mut impl TranscriptSink,
    object_id: &[u8; OBJECT_ID_LEN],
    chunk_index: u32,
    chunk: &[u8],
) -> Result<(), ManifestError> {
    let chunk_length = u32::try_from(chunk.len()).map_err(|_| ManifestError::ChunkTooLarge {
        length: chunk.len(),
    })?;
    sink.update(MERKLE_LEAF_CONTEXT);
    sink.update(object_id);
    sink.update(&chunk_index.to_be_bytes());
    sink.update(&chunk_length.to_be_bytes());
    sink.update(chunk);
    Ok(())
}

/// Streams the exact SHA-384 input for one internal Merkle node.
pub fn feed_merkle_node_input(
    sink: &mut impl TranscriptSink,
    level: u32,
    left: &[u8; MERKLE_ROOT_LEN],
    right: &[u8; MERKLE_ROOT_LEN],
) {
    sink.update(MERKLE_NODE_CONTEXT);
    sink.update(&level.to_be_bytes());
    sink.update(left);
    sink.update(right);
}

/// Streams the exact SHA-384 input defining the root of an empty object.
pub fn feed_empty_root_input(sink: &mut impl TranscriptSink, object_id: &[u8; OBJECT_ID_LEN]) {
    sink.update(MERKLE_EMPTY_CONTEXT);
    sink.update(object_id);
}

fn expected_chunk_count(object_size: u64, chunk_size: u32) -> u64 {
    if object_size == 0 {
        0
    } else {
        (object_size - 1) / u64::from(chunk_size) + 1
    }
}

fn validate_display_name(display_name: &str) -> Result<(), ManifestError> {
    if display_name.len() > MAX_DISPLAY_NAME_LEN
        || display_name
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\'))
    {
        return Err(ManifestError::InvalidDisplayName);
    }
    Ok(())
}

fn validate_signature_length(
    component: &'static str,
    actual: usize,
    expected: usize,
) -> Result<(), ManifestError> {
    if actual != expected {
        return Err(ManifestError::InvalidSignatureLength {
            component,
            expected,
            actual,
        });
    }
    Ok(())
}

fn validate_manifest_length(length: usize) -> Result<(), ManifestError> {
    if !(MIN_SIGNED_MANIFEST_LEN..=MAX_SIGNED_MANIFEST_LEN).contains(&length) {
        return Err(ManifestError::InvalidLogicalLength {
            length,
            minimum: MIN_SIGNED_MANIFEST_LEN,
            maximum: MAX_SIGNED_MANIFEST_LEN,
        });
    }
    Ok(())
}

fn validate_fragment(total: usize, offset: usize, length: usize) -> Result<(), ManifestError> {
    if length == 0 || offset.checked_add(length).is_none_or(|end| end > total) {
        return Err(WireError::InvalidFragmentBounds.into());
    }
    Ok(())
}

fn unsigned_length(display_name_length: usize) -> Result<usize, ManifestError> {
    if display_name_length > MAX_DISPLAY_NAME_LEN {
        return Err(ManifestError::InvalidDisplayName);
    }
    MANIFEST_UNSIGNED_FIXED_LEN
        .checked_add(display_name_length)
        .ok_or_else(|| WireError::LengthOverflow.into())
}

fn require_output(output: &[u8], needed: usize) -> Result<(), ManifestError> {
    if output.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            available: output.len(),
        }
        .into());
    }
    Ok(())
}

fn require_exact(input: &[u8], expected: usize) -> Result<(), ManifestError> {
    if input.len() < expected {
        return Err(WireError::PacketTooShort {
            minimum: expected,
            actual: input.len(),
        }
        .into());
    }
    if input.len() != expected {
        return Err(WireError::LengthMismatch {
            expected,
            actual: input.len(),
        }
        .into());
    }
    Ok(())
}

fn copy_array<const N: usize>(input: &[u8], offset: usize) -> Result<[u8; N], ManifestError> {
    let end = offset.checked_add(N).ok_or(WireError::LengthOverflow)?;
    input
        .get(offset..end)
        .ok_or(WireError::PacketTooShort {
            minimum: end,
            actual: input.len(),
        })?
        .try_into()
        .map_err(|_| WireError::LengthOverflow.into())
}

/// Canonical manifest validation or framing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestError {
    Wire(WireError),
    UnsupportedVersion(u8),
    InvalidFlags(u8),
    ZeroObjectId,
    ZeroSignerFingerprint,
    ZeroMerkleRoot,
    InvalidChunkSize(u32),
    InvalidChunkCount {
        expected: u64,
        actual: u32,
    },
    InvalidDisplayName,
    InvalidSignatureLength {
        component: &'static str,
        expected: usize,
        actual: usize,
    },
    InvalidLogicalLength {
        length: usize,
        minimum: usize,
        maximum: usize,
    },
    ChunkTooLarge {
        length: usize,
    },
}

impl From<WireError> for ManifestError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => error.fmt(formatter),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported manifest version {version}")
            }
            Self::InvalidFlags(flags) => write!(formatter, "invalid manifest flags {flags:#x}"),
            Self::ZeroObjectId => formatter.write_str("manifest object ID is all zero"),
            Self::ZeroSignerFingerprint => {
                formatter.write_str("manifest signer fingerprint is all zero")
            }
            Self::ZeroMerkleRoot => formatter.write_str("manifest Merkle root is all zero"),
            Self::InvalidChunkSize(size) => write!(formatter, "invalid manifest chunk size {size}"),
            Self::InvalidChunkCount { expected, actual } => write!(
                formatter,
                "invalid manifest chunk count {actual}, expected {expected}"
            ),
            Self::InvalidDisplayName => formatter.write_str("invalid manifest display name"),
            Self::InvalidSignatureLength {
                component,
                expected,
                actual,
            } => write!(
                formatter,
                "invalid {component} length: expected {expected}, got {actual}"
            ),
            Self::InvalidLogicalLength {
                length,
                minimum,
                maximum,
            } => write!(
                formatter,
                "invalid logical manifest length {length}, expected {minimum}..={maximum}"
            ),
            Self::ChunkTooLarge { length } => {
                write!(formatter, "chunk length {length} exceeds 32-bit encoding")
            }
        }
    }
}

impl std::error::Error for ManifestError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder(Vec<u8>);

    impl TranscriptSink for Recorder {
        fn update(&mut self, bytes: &[u8]) {
            self.0.extend_from_slice(bytes);
        }
    }

    fn header() -> ManifestHeader {
        let mut object_id = [0_u8; OBJECT_ID_LEN];
        for (index, byte) in object_id.iter_mut().enumerate() {
            *byte = u8::try_from(index).expect("object ID index fits");
        }
        ManifestHeader {
            object_id,
            object_size: u64::from(MIN_CHUNK_SIZE) * 4 + 123,
            chunk_size: MIN_CHUNK_SIZE,
            chunk_count: 5,
            merkle_root: [0xa5; MERKLE_ROOT_LEN],
            signer_identity_fingerprint: [0x5a; IDENTITY_FINGERPRINT_LEN],
        }
    }

    #[test]
    fn signed_manifest_round_trip_borrows_large_signatures() {
        let header = header();
        let name = "archive.bin";
        let ed25519 = [0xed; ED25519_SIGNATURE_LEN];
        let ml_dsa = [0xda; ML_DSA_65_SIGNATURE_LEN];
        let mut encoded = [0_u8; MAX_SIGNED_MANIFEST_LEN];
        let written = header
            .encode_signed(name, &ed25519, &ml_dsa, &mut encoded)
            .expect("valid manifest encodes");

        assert_eq!(written, MIN_SIGNED_MANIFEST_LEN + name.len());
        assert_eq!(encoded[0], MANIFEST_FORMAT_VERSION);
        assert_eq!(encoded[FLAGS_OFFSET], 0);
        assert_eq!(encoded[DISPLAY_NAME_LENGTH_OFFSET], 11);
        let decoded = Manifest::decode(&encoded[..written]).expect("manifest decodes");
        assert_eq!(decoded.header, header);
        assert_eq!(decoded.display_name, name);
        assert_eq!(decoded.unsigned_content().len(), 158);
        assert_eq!(decoded.ed25519_signature(), ed25519);
        assert_eq!(decoded.ml_dsa_65_signature(), ml_dsa);
    }

    #[test]
    fn streaming_unsigned_content_matches_encoding() {
        let mut encoded = [0_u8; MANIFEST_UNSIGNED_FIXED_LEN + MAX_DISPLAY_NAME_LEN];
        let written = header()
            .encode_unsigned("résumé.bin", &mut encoded)
            .expect("UTF-8 display name encodes");
        let mut recorder = Recorder::default();
        header()
            .feed_unsigned("résumé.bin", &mut recorder)
            .expect("unsigned content streams");
        assert_eq!(recorder.0, encoded[..written]);
    }

    #[test]
    fn empty_object_geometry_is_valid() {
        let empty = ManifestHeader {
            object_size: 0,
            chunk_count: 0,
            ..header()
        };
        assert_eq!(empty.validate(), Ok(()));
    }

    #[test]
    fn invalid_geometry_and_identity_fields_fail_closed() {
        assert_eq!(
            ManifestHeader {
                object_id: [0; OBJECT_ID_LEN],
                ..header()
            }
            .validate(),
            Err(ManifestError::ZeroObjectId)
        );
        assert_eq!(
            ManifestHeader {
                signer_identity_fingerprint: [0; IDENTITY_FINGERPRINT_LEN],
                ..header()
            }
            .validate(),
            Err(ManifestError::ZeroSignerFingerprint)
        );
        assert_eq!(
            ManifestHeader {
                merkle_root: [0; MERKLE_ROOT_LEN],
                ..header()
            }
            .validate(),
            Err(ManifestError::ZeroMerkleRoot)
        );
        for invalid_size in [MIN_CHUNK_SIZE - 1, MIN_CHUNK_SIZE + 1, MAX_CHUNK_SIZE + 1] {
            assert_eq!(
                ManifestHeader {
                    chunk_size: invalid_size,
                    ..header()
                }
                .validate(),
                Err(ManifestError::InvalidChunkSize(invalid_size))
            );
        }
        assert_eq!(
            ManifestHeader {
                chunk_count: 4,
                ..header()
            }
            .validate(),
            Err(ManifestError::InvalidChunkCount {
                expected: 5,
                actual: 4,
            })
        );
    }

    #[test]
    fn display_name_and_signature_lengths_are_strict() {
        let mut output = [0_u8; MAX_SIGNED_MANIFEST_LEN];
        let ed25519 = [0xed; ED25519_SIGNATURE_LEN];
        let ml_dsa = [0xda; ML_DSA_65_SIGNATURE_LEN];
        for invalid_name in ["../secret", "path\\file", "line\nbreak"] {
            assert_eq!(
                header().encode_signed(invalid_name, &ed25519, &ml_dsa, &mut output),
                Err(ManifestError::InvalidDisplayName)
            );
        }
        let oversized_name = "a".repeat(MAX_DISPLAY_NAME_LEN + 1);
        assert_eq!(
            header().encode_signed(&oversized_name, &ed25519, &ml_dsa, &mut output),
            Err(ManifestError::InvalidDisplayName)
        );
        assert_eq!(
            header().encode_signed("file", &ed25519[..63], &ml_dsa, &mut output),
            Err(ManifestError::InvalidSignatureLength {
                component: "Ed25519 signature",
                expected: ED25519_SIGNATURE_LEN,
                actual: 63,
            })
        );
        assert_eq!(
            header().encode_signed("file", &ed25519, &ml_dsa[..3_308], &mut output),
            Err(ManifestError::InvalidSignatureLength {
                component: "ML-DSA-65 signature",
                expected: ML_DSA_65_SIGNATURE_LEN,
                actual: 3_308,
            })
        );
    }

    #[test]
    fn decode_rejects_version_flags_utf8_trailing_and_truncation() {
        let ed25519 = [0xed; ED25519_SIGNATURE_LEN];
        let ml_dsa = [0xda; ML_DSA_65_SIGNATURE_LEN];
        let mut encoded = [0_u8; MAX_SIGNED_MANIFEST_LEN + 1];
        let written = header()
            .encode_signed("x", &ed25519, &ml_dsa, &mut encoded)
            .expect("manifest encodes");

        encoded[0] = 2;
        assert_eq!(
            Manifest::decode(&encoded[..written]),
            Err(ManifestError::UnsupportedVersion(2))
        );
        encoded[0] = MANIFEST_FORMAT_VERSION;
        encoded[FLAGS_OFFSET] = 1;
        assert_eq!(
            Manifest::decode(&encoded[..written]),
            Err(ManifestError::InvalidFlags(1))
        );
        encoded[FLAGS_OFFSET] = 0;
        encoded[MANIFEST_UNSIGNED_FIXED_LEN] = 0xff;
        assert_eq!(
            Manifest::decode(&encoded[..written]),
            Err(ManifestError::InvalidDisplayName)
        );
        encoded[MANIFEST_UNSIGNED_FIXED_LEN] = b'x';
        assert_eq!(
            Manifest::decode(&encoded[..=written]),
            Err(ManifestError::Wire(WireError::LengthMismatch {
                expected: written,
                actual: written + 1,
            }))
        );
        assert_eq!(
            Manifest::decode(&encoded[..MIN_SIGNED_MANIFEST_LEN - 1]),
            Err(ManifestError::Wire(WireError::PacketTooShort {
                minimum: MIN_SIGNED_MANIFEST_LEN,
                actual: MIN_SIGNED_MANIFEST_LEN - 1,
            }))
        );
    }

    #[test]
    fn manifest_fragment_round_trip_is_borrowed_and_bounded() {
        let fragment_bytes = [0x42; 1_000];
        let fragment = ManifestFragment {
            object_slot: 7,
            manifest_length: u16::try_from(MIN_SIGNED_MANIFEST_LEN).expect("length fits"),
            fragment_offset: 1_000,
            fragment: &fragment_bytes,
        };
        let mut encoded = [0_u8; 1_024];
        let written = fragment.encode(&mut encoded).expect("fragment encodes");
        let decoded = ManifestFragment::decode(&encoded[..written]).expect("fragment decodes");
        assert_eq!(decoded, fragment);

        assert_eq!(
            ManifestFragment {
                fragment: &[],
                ..fragment
            }
            .encode(&mut encoded),
            Err(ManifestError::Wire(WireError::InvalidFragmentBounds))
        );
        assert_eq!(
            ManifestFragment {
                fragment_offset: u16::try_from(MIN_SIGNED_MANIFEST_LEN - 10).expect("offset fits"),
                fragment: &[0; 11],
                ..fragment
            }
            .encode(&mut encoded),
            Err(ManifestError::Wire(WireError::InvalidFragmentBounds))
        );
        assert_eq!(
            ManifestFragment::decode(&[0_u8; MANIFEST_FRAGMENT_FIXED_LEN]),
            Err(ManifestError::Wire(WireError::PacketTooShort {
                minimum: MANIFEST_FRAGMENT_FIXED_LEN + 1,
                actual: MANIFEST_FRAGMENT_FIXED_LEN,
            }))
        );
        for invalid_length in [MIN_SIGNED_MANIFEST_LEN - 1, MAX_SIGNED_MANIFEST_LEN + 1] {
            let invalid = ManifestFragment {
                manifest_length: u16::try_from(invalid_length).expect("test length fits"),
                fragment_offset: 0,
                fragment: &[1],
                ..fragment
            };
            assert_eq!(
                invalid.encode(&mut encoded),
                Err(ManifestError::InvalidLogicalLength {
                    length: invalid_length,
                    minimum: MIN_SIGNED_MANIFEST_LEN,
                    maximum: MAX_SIGNED_MANIFEST_LEN,
                })
            );
        }
        assert_eq!(
            fragment.encode(&mut [0_u8; MANIFEST_FRAGMENT_FIXED_LEN]),
            Err(ManifestError::Wire(WireError::BufferTooSmall {
                needed: MANIFEST_FRAGMENT_FIXED_LEN + fragment_bytes.len(),
                available: MANIFEST_FRAGMENT_FIXED_LEN,
            }))
        );
    }

    #[test]
    fn signature_and_merkle_inputs_are_domain_separated() {
        let content_hash = [0x11; MERKLE_ROOT_LEN];
        let mut signature = Recorder::default();
        feed_manifest_signature_input(&mut signature, &content_hash);
        assert_eq!(
            &signature.0[..SIGNATURE_CONTEXT_PREFIX_LEN],
            &[0x20; SIGNATURE_CONTEXT_PREFIX_LEN]
        );
        assert_eq!(
            &signature.0[SIGNATURE_CONTEXT_PREFIX_LEN
                ..SIGNATURE_CONTEXT_PREFIX_LEN + MANIFEST_SIGNATURE_CONTEXT.len()],
            MANIFEST_SIGNATURE_CONTEXT
        );
        assert_eq!(signature.0.last(), Some(&0x11));

        let mut leaf = Recorder::default();
        feed_chunk_leaf_input(&mut leaf, &header().object_id, 3, b"chunk")
            .expect("small chunk fits");
        assert!(leaf.0.starts_with(MERKLE_LEAF_CONTEXT));
        assert!(leaf.0.ends_with(b"chunk"));

        let mut node = Recorder::default();
        feed_merkle_node_input(
            &mut node,
            1,
            &[0x22; MERKLE_ROOT_LEN],
            &[0x33; MERKLE_ROOT_LEN],
        );
        assert!(node.0.starts_with(MERKLE_NODE_CONTEXT));

        let mut empty = Recorder::default();
        feed_empty_root_input(&mut empty, &header().object_id);
        assert!(empty.0.starts_with(MERKLE_EMPTY_CONTEXT));
        assert_ne!(leaf.0, node.0);
        assert_ne!(leaf.0, empty.0);
    }
}
