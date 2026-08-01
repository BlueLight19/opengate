//! Allocation-free OGTP/1 fast-path wire codec.
//!
//! Header protection and AEAD are deliberately not implemented here. A sender
//! encodes a header and DATA plaintext, seals the plaintext in place with an
//! audited crypto provider, appends the tag, then applies header protection.

use core::fmt;

pub mod ack;
pub mod control;
pub mod long;
pub mod probe;

/// Size of a short header before header protection.
pub const SHORT_HEADER_LEN: usize = 13;
/// Size of the authentication tag required by OGTP/1 cipher suites.
pub const AEAD_TAG_LEN: usize = 16;
/// Size of the fixed metadata preceding a DATA fragment.
pub const DATA_METADATA_LEN: usize = 14;
/// Conservative UDP payload used until path MTU discovery succeeds.
pub const BASELINE_UDP_PAYLOAD: usize = 1_200;
/// Maximum DATA bytes in a baseline packet.
pub const BASELINE_FRAGMENT_PAYLOAD: usize =
    BASELINE_UDP_PAYLOAD - SHORT_HEADER_LEN - AEAD_TAG_LEN - DATA_METADATA_LEN;

const LONG_HEADER_BIT: u8 = 0x80;
const CLASS_MASK: u8 = 0x60;
const CLASS_SHIFT: u8 = 5;
const KEY_PHASE_BIT: u8 = 0x10;
const RESERVED_MASK: u8 = 0x0f;

/// Classes carried by an OGTP short-header packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PacketClass {
    Data = 0,
    Control = 1,
    Ack = 2,
    Probe = 3,
}

impl PacketClass {
    const fn from_flags(flags: u8) -> Self {
        match (flags & CLASS_MASK) >> CLASS_SHIFT {
            0 => Self::Data,
            1 => Self::Control,
            2 => Self::Ack,
            3 => Self::Probe,
            _ => unreachable!(),
        }
    }
}

/// Unprotected representation of an OGTP short header.
///
/// On the wire, the class, key phase and packet number are masked. The DCID
/// remains visible so the receiver can select the connection and header key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShortHeader {
    pub class: PacketClass,
    pub key_phase: bool,
    pub destination_connection_id: [u8; 8],
    pub truncated_packet_number: u32,
}

impl ShortHeader {
    /// Encodes the header before cryptographic header protection.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::BufferTooSmall`] when `output` cannot hold a
    /// complete short header.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, WireError> {
        if output.len() < SHORT_HEADER_LEN {
            return Err(WireError::BufferTooSmall {
                needed: SHORT_HEADER_LEN,
                available: output.len(),
            });
        }

        let mut flags = (self.class as u8) << CLASS_SHIFT;
        if self.key_phase {
            flags |= KEY_PHASE_BIT;
        }

        output[0] = flags;
        output[1..9].copy_from_slice(&self.destination_connection_id);
        output[9..13].copy_from_slice(&self.truncated_packet_number.to_be_bytes());
        Ok(SHORT_HEADER_LEN)
    }

    /// Decodes a header after cryptographic header protection was removed.
    ///
    /// # Errors
    ///
    /// Returns an error when the input is truncated, is a long header or has
    /// non-zero reserved bits after header protection was removed.
    pub fn decode_unprotected(input: &[u8]) -> Result<Self, WireError> {
        if input.len() < SHORT_HEADER_LEN {
            return Err(WireError::PacketTooShort {
                minimum: SHORT_HEADER_LEN,
                actual: input.len(),
            });
        }

        let flags = input[0];
        if flags & LONG_HEADER_BIT != 0 {
            return Err(WireError::UnexpectedLongHeader);
        }
        if flags & RESERVED_MASK != 0 {
            return Err(WireError::ReservedBitsSet(flags & RESERVED_MASK));
        }

        let mut dcid = [0_u8; 8];
        dcid.copy_from_slice(&input[1..9]);
        let packet_number = read_u32(input, 9)?;

        Ok(Self {
            class: PacketClass::from_flags(flags),
            key_phase: flags & KEY_PHASE_BIT != 0,
            destination_connection_id: dcid,
            truncated_packet_number: packet_number,
        })
    }
}

/// Fixed metadata decrypted at the beginning of a DATA packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataMetadata {
    /// Connection-local identifier assigned to a manifest object.
    pub object_slot: u32,
    /// Zero-based chunk number within the object.
    pub chunk_index: u32,
    /// Byte offset of this fragment within the chunk.
    pub fragment_offset: u32,
    /// Number of DATA bytes following this metadata.
    pub fragment_length: u16,
}

/// Borrowed DATA frame returned by the decoder without allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataFrame<'a> {
    pub metadata: DataMetadata,
    pub fragment: &'a [u8],
}

impl DataMetadata {
    /// Writes metadata followed by `fragment` into an AEAD plaintext buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if the declared and actual fragment lengths differ,
    /// if their sum overflows or if `output` is too small.
    pub fn encode_with_fragment(
        self,
        fragment: &[u8],
        output: &mut [u8],
    ) -> Result<usize, WireError> {
        if usize::from(self.fragment_length) != fragment.len() {
            return Err(WireError::FragmentLengthMismatch {
                declared: usize::from(self.fragment_length),
                actual: fragment.len(),
            });
        }

        let needed = DATA_METADATA_LEN
            .checked_add(fragment.len())
            .ok_or(WireError::LengthOverflow)?;
        if output.len() < needed {
            return Err(WireError::BufferTooSmall {
                needed,
                available: output.len(),
            });
        }

        output[0..4].copy_from_slice(&self.object_slot.to_be_bytes());
        output[4..8].copy_from_slice(&self.chunk_index.to_be_bytes());
        output[8..12].copy_from_slice(&self.fragment_offset.to_be_bytes());
        output[12..14].copy_from_slice(&self.fragment_length.to_be_bytes());
        output[14..needed].copy_from_slice(fragment);
        Ok(needed)
    }
}

impl<'a> DataFrame<'a> {
    /// Decodes an authenticated DATA plaintext without copying its fragment.
    ///
    /// # Errors
    ///
    /// Returns an error when the plaintext is truncated or when its declared
    /// fragment length does not equal the remaining number of bytes.
    pub fn decode_plaintext(input: &'a [u8]) -> Result<Self, WireError> {
        if input.len() < DATA_METADATA_LEN {
            return Err(WireError::PacketTooShort {
                minimum: DATA_METADATA_LEN,
                actual: input.len(),
            });
        }

        let object_slot = read_u32(input, 0)?;
        let chunk_index = read_u32(input, 4)?;
        let fragment_offset = read_u32(input, 8)?;
        let fragment_length = read_u16(input, 12)?;
        let actual = input.len() - DATA_METADATA_LEN;
        if usize::from(fragment_length) != actual {
            return Err(WireError::FragmentLengthMismatch {
                declared: usize::from(fragment_length),
                actual,
            });
        }

        Ok(Self {
            metadata: DataMetadata {
                object_slot,
                chunk_index,
                fragment_offset,
                fragment_length,
            },
            fragment: &input[DATA_METADATA_LEN..],
        })
    }
}

pub(super) fn read_u16(input: &[u8], offset: usize) -> Result<u16, WireError> {
    let end = offset.checked_add(2).ok_or(WireError::LengthOverflow)?;
    let bytes = input.get(offset..end).ok_or(WireError::PacketTooShort {
        minimum: end,
        actual: input.len(),
    })?;
    let array = <[u8; 2]>::try_from(bytes).map_err(|_| WireError::LengthOverflow)?;
    Ok(u16::from_be_bytes(array))
}

pub(super) fn read_u32(input: &[u8], offset: usize) -> Result<u32, WireError> {
    let end = offset.checked_add(4).ok_or(WireError::LengthOverflow)?;
    let bytes = input.get(offset..end).ok_or(WireError::PacketTooShort {
        minimum: end,
        actual: input.len(),
    })?;
    let array = <[u8; 4]>::try_from(bytes).map_err(|_| WireError::LengthOverflow)?;
    Ok(u32::from_be_bytes(array))
}

pub(super) fn read_u64(input: &[u8], offset: usize) -> Result<u64, WireError> {
    let end = offset.checked_add(8).ok_or(WireError::LengthOverflow)?;
    let bytes = input.get(offset..end).ok_or(WireError::PacketTooShort {
        minimum: end,
        actual: input.len(),
    })?;
    let array = <[u8; 8]>::try_from(bytes).map_err(|_| WireError::LengthOverflow)?;
    Ok(u64::from_be_bytes(array))
}

/// Reconstructs a full packet number from the 32-bit value carried on wire.
///
/// `expected` is one greater than the largest successfully authenticated
/// packet number on this path. The result is capped to OGTP's 62-bit space.
#[must_use]
pub const fn reconstruct_packet_number(truncated: u32, expected: u64) -> u64 {
    const WINDOW: u64 = 1_u64 << 32;
    const HALF_WINDOW: u64 = WINDOW / 2;
    const MASK: u64 = WINDOW - 1;
    const MAX_PACKET_NUMBER: u64 = (1_u64 << 62) - 1;

    let candidate = (expected & !MASK) | truncated as u64;
    if candidate.saturating_add(HALF_WINDOW) <= expected && candidate <= MAX_PACKET_NUMBER - WINDOW
    {
        candidate + WINDOW
    } else if candidate > expected.saturating_add(HALF_WINDOW) && candidate >= WINDOW {
        candidate - WINDOW
    } else {
        candidate
    }
}

/// Errors produced by the allocation-free wire codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    BufferTooSmall { needed: usize, available: usize },
    PacketTooShort { minimum: usize, actual: usize },
    FragmentLengthMismatch { declared: usize, actual: usize },
    ReservedBitsSet(u8),
    UnexpectedLongHeader,
    UnexpectedShortHeader,
    LengthOverflow,
    LengthMismatch { expected: usize, actual: usize },
    TooManyAckRanges { count: usize, maximum: usize },
    InvalidAckRanges,
    InvalidAckFlags(u8),
    FrameValueTooLarge { length: usize, maximum: usize },
    UnknownProbeKind(u8),
    NonZeroProbePadding,
    UnknownLongPacketType(u8),
    ConnectionIdTooLong { length: usize, maximum: usize },
    HandshakeMessageTooLarge { length: usize, maximum: usize },
    InvalidFragmentBounds,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall { needed, available } => {
                write!(
                    formatter,
                    "buffer too small: need {needed}, have {available}"
                )
            }
            Self::PacketTooShort { minimum, actual } => {
                write!(formatter, "packet too short: need {minimum}, have {actual}")
            }
            Self::FragmentLengthMismatch { declared, actual } => write!(
                formatter,
                "fragment length mismatch: declared {declared}, actual {actual}"
            ),
            Self::ReservedBitsSet(bits) => write!(formatter, "reserved bits set: {bits:#x}"),
            Self::UnexpectedLongHeader => formatter.write_str("unexpected long header"),
            Self::UnexpectedShortHeader => formatter.write_str("unexpected short header"),
            Self::LengthOverflow => formatter.write_str("encoded length overflow"),
            Self::LengthMismatch { expected, actual } => {
                write!(
                    formatter,
                    "length mismatch: expected {expected}, actual {actual}"
                )
            }
            Self::TooManyAckRanges { count, maximum } => {
                write!(formatter, "too many ACK ranges: {count}, maximum {maximum}")
            }
            Self::InvalidAckRanges => formatter.write_str("invalid ACK ranges"),
            Self::InvalidAckFlags(flags) => write!(formatter, "invalid ACK flags: {flags:#x}"),
            Self::FrameValueTooLarge { length, maximum } => {
                write!(
                    formatter,
                    "frame value too large: {length}, maximum {maximum}"
                )
            }
            Self::UnknownProbeKind(kind) => write!(formatter, "unknown probe kind: {kind:#x}"),
            Self::NonZeroProbePadding => formatter.write_str("non-zero probe padding"),
            Self::UnknownLongPacketType(kind) => {
                write!(formatter, "unknown long-header packet type: {kind:#x}")
            }
            Self::ConnectionIdTooLong { length, maximum } => {
                write!(
                    formatter,
                    "connection ID too long: {length}, maximum {maximum}"
                )
            }
            Self::HandshakeMessageTooLarge { length, maximum } => write!(
                formatter,
                "handshake message too large: {length}, maximum {maximum}"
            ),
            Self::InvalidFragmentBounds => formatter.write_str("invalid handshake fragment bounds"),
        }
    }
}

impl std::error::Error for WireError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_header_round_trip() {
        let original = ShortHeader {
            class: PacketClass::Data,
            key_phase: true,
            destination_connection_id: *b"path-001",
            truncated_packet_number: 0xa1b2_c3d4,
        };
        let mut bytes = [0_u8; SHORT_HEADER_LEN];

        assert_eq!(original.encode(&mut bytes), Ok(SHORT_HEADER_LEN));
        assert_eq!(ShortHeader::decode_unprotected(&bytes), Ok(original));
    }

    #[test]
    fn all_short_header_classes_round_trip() {
        for class in [
            PacketClass::Data,
            PacketClass::Control,
            PacketClass::Ack,
            PacketClass::Probe,
        ] {
            let original = ShortHeader {
                class,
                key_phase: false,
                destination_connection_id: [0x5a; 8],
                truncated_packet_number: 9,
            };
            let mut bytes = [0_u8; SHORT_HEADER_LEN];
            original.encode(&mut bytes).expect("test buffer fits");
            assert_eq!(ShortHeader::decode_unprotected(&bytes), Ok(original));
        }
    }

    #[test]
    fn every_truncated_short_header_is_rejected() {
        let bytes = [0_u8; SHORT_HEADER_LEN];
        for length in 0..SHORT_HEADER_LEN {
            assert_eq!(
                ShortHeader::decode_unprotected(&bytes[..length]),
                Err(WireError::PacketTooShort {
                    minimum: SHORT_HEADER_LEN,
                    actual: length,
                })
            );
        }
    }

    #[test]
    fn data_frame_round_trip_borrows_fragment() {
        let fragment = b"authenticated fragment";
        let metadata = DataMetadata {
            object_slot: 7,
            chunk_index: 42,
            fragment_offset: 1_024,
            fragment_length: u16::try_from(fragment.len()).expect("test fragment fits"),
        };
        let mut plaintext = [0_u8; 128];

        let written = metadata
            .encode_with_fragment(fragment, &mut plaintext)
            .expect("encode succeeds");
        let decoded = DataFrame::decode_plaintext(&plaintext[..written]).expect("decode succeeds");

        assert_eq!(decoded.metadata, metadata);
        assert_eq!(decoded.fragment, fragment);
    }

    #[test]
    fn data_length_mismatch_is_rejected() {
        let metadata = DataMetadata {
            object_slot: 1,
            chunk_index: 2,
            fragment_offset: 3,
            fragment_length: 2,
        };
        let mut output = [0_u8; 32];

        assert_eq!(
            metadata.encode_with_fragment(b"abc", &mut output),
            Err(WireError::FragmentLengthMismatch {
                declared: 2,
                actual: 3,
            })
        );
    }

    #[test]
    fn every_truncated_data_metadata_is_rejected() {
        let bytes = [0_u8; DATA_METADATA_LEN];
        for length in 0..DATA_METADATA_LEN {
            assert_eq!(
                DataFrame::decode_plaintext(&bytes[..length]),
                Err(WireError::PacketTooShort {
                    minimum: DATA_METADATA_LEN,
                    actual: length,
                })
            );
        }
    }

    #[test]
    fn declared_length_mismatch_is_rejected_on_decode() {
        let mut plaintext = [0_u8; DATA_METADATA_LEN + 1];
        plaintext[12..14].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            DataFrame::decode_plaintext(&plaintext),
            Err(WireError::FragmentLengthMismatch {
                declared: 2,
                actual: 1,
            })
        );
    }

    #[test]
    fn baseline_payload_math_is_stable() {
        assert_eq!(BASELINE_FRAGMENT_PAYLOAD, 1_157);
        assert_eq!(
            SHORT_HEADER_LEN + DATA_METADATA_LEN + BASELINE_FRAGMENT_PAYLOAD + AEAD_TAG_LEN,
            BASELINE_UDP_PAYLOAD
        );
    }

    #[test]
    fn packet_number_reconstruction_handles_wrap() {
        assert_eq!(reconstruct_packet_number(3, 0x1_0000_0002), 0x1_0000_0003);
        assert_eq!(
            reconstruct_packet_number(0xffff_fffe, 0x1_0000_0002),
            0xffff_fffe
        );
    }

    #[test]
    fn reserved_bits_are_rejected_after_unmasking() {
        let mut bytes = [0_u8; SHORT_HEADER_LEN];
        bytes[0] = 0x01;
        assert_eq!(
            ShortHeader::decode_unprotected(&bytes),
            Err(WireError::ReservedBitsSet(1))
        );
    }
}
