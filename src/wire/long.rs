//! Allocation-free long-header codec for fragmented handshake messages.

use super::{WireError, read_u16, read_u32};

/// Maximum Connection ID length in a long header.
pub const MAX_LONG_CONNECTION_ID_LEN: usize = 20;
/// Maximum reassembled handshake message size.
pub const MAX_HANDSHAKE_MESSAGE_LEN: usize = 16 * 1_024;
/// Long-header bytes excluding the two variable-length Connection IDs.
pub const LONG_HEADER_FIXED_LEN: usize = 17;

const LONG_HEADER_BIT: u8 = 0x80;
const TYPE_MASK: u8 = 0x70;
const TYPE_SHIFT: u8 = 4;
const RESERVED_MASK: u8 = 0x0f;

/// Packet types used during version negotiation and the hybrid handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LongPacketType {
    Hello = 0,
    Retry = 1,
    Init = 2,
    Response = 3,
    Finish = 4,
    VersionNegotiation = 5,
}

impl LongPacketType {
    const fn from_wire(value: u8) -> Result<Self, WireError> {
        match value {
            0 => Ok(Self::Hello),
            1 => Ok(Self::Retry),
            2 => Ok(Self::Init),
            3 => Ok(Self::Response),
            4 => Ok(Self::Finish),
            5 => Ok(Self::VersionNegotiation),
            _ => Err(WireError::UnknownLongPacketType(value)),
        }
    }
}

/// Borrowed long-header packet containing one handshake-message fragment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LongPacket<'a> {
    pub packet_type: LongPacketType,
    pub version: u32,
    pub destination_connection_id: &'a [u8],
    pub source_connection_id: &'a [u8],
    pub message_id: u32,
    pub fragment_offset: u16,
    pub message_length: u16,
    pub fragment: &'a [u8],
}

impl<'a> LongPacket<'a> {
    /// Encodes one fragment of a long-header handshake message.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized Connection ID or message, invalid
    /// fragment bounds, arithmetic overflow, or an undersized output buffer.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, WireError> {
        validate_connection_id(self.destination_connection_id)?;
        validate_connection_id(self.source_connection_id)?;
        validate_fragment(
            self.fragment_offset,
            self.message_length,
            self.fragment.len(),
        )?;

        let needed = LONG_HEADER_FIXED_LEN
            .checked_add(self.destination_connection_id.len())
            .and_then(|value| value.checked_add(self.source_connection_id.len()))
            .and_then(|value| value.checked_add(self.fragment.len()))
            .ok_or(WireError::LengthOverflow)?;
        if output.len() < needed {
            return Err(WireError::BufferTooSmall {
                needed,
                available: output.len(),
            });
        }

        let destination_length =
            u8::try_from(self.destination_connection_id.len()).map_err(|_| {
                WireError::ConnectionIdTooLong {
                    length: self.destination_connection_id.len(),
                    maximum: MAX_LONG_CONNECTION_ID_LEN,
                }
            })?;
        let source_length = u8::try_from(self.source_connection_id.len()).map_err(|_| {
            WireError::ConnectionIdTooLong {
                length: self.source_connection_id.len(),
                maximum: MAX_LONG_CONNECTION_ID_LEN,
            }
        })?;
        let fragment_length =
            u16::try_from(self.fragment.len()).map_err(|_| WireError::InvalidFragmentBounds)?;

        output[0] = LONG_HEADER_BIT | ((self.packet_type as u8) << TYPE_SHIFT);
        output[1..5].copy_from_slice(&self.version.to_be_bytes());
        output[5] = destination_length;
        let mut cursor = 6;
        output[cursor..cursor + self.destination_connection_id.len()]
            .copy_from_slice(self.destination_connection_id);
        cursor += self.destination_connection_id.len();
        output[cursor] = source_length;
        cursor += 1;
        output[cursor..cursor + self.source_connection_id.len()]
            .copy_from_slice(self.source_connection_id);
        cursor += self.source_connection_id.len();
        output[cursor..cursor + 4].copy_from_slice(&self.message_id.to_be_bytes());
        cursor += 4;
        output[cursor..cursor + 2].copy_from_slice(&self.fragment_offset.to_be_bytes());
        cursor += 2;
        output[cursor..cursor + 2].copy_from_slice(&fragment_length.to_be_bytes());
        cursor += 2;
        output[cursor..cursor + 2].copy_from_slice(&self.message_length.to_be_bytes());
        cursor += 2;
        output[cursor..needed].copy_from_slice(self.fragment);
        Ok(needed)
    }

    /// Decodes one complete long-header datagram without allocating.
    ///
    /// # Errors
    ///
    /// Returns an error for a short-form header, reserved or unknown type bits,
    /// truncated fields, oversized identifiers/messages, trailing bytes, or
    /// invalid fragment bounds.
    pub fn decode(input: &'a [u8]) -> Result<Self, WireError> {
        if input.len() < LONG_HEADER_FIXED_LEN {
            return Err(WireError::PacketTooShort {
                minimum: LONG_HEADER_FIXED_LEN,
                actual: input.len(),
            });
        }
        let flags = input[0];
        if flags & LONG_HEADER_BIT == 0 {
            return Err(WireError::UnexpectedShortHeader);
        }
        if flags & RESERVED_MASK != 0 {
            return Err(WireError::ReservedBitsSet(flags & RESERVED_MASK));
        }
        let packet_type = LongPacketType::from_wire((flags & TYPE_MASK) >> TYPE_SHIFT)?;
        let version = read_u32(input, 1)?;

        let destination_length = usize::from(input[5]);
        if destination_length > MAX_LONG_CONNECTION_ID_LEN {
            return Err(WireError::ConnectionIdTooLong {
                length: destination_length,
                maximum: MAX_LONG_CONNECTION_ID_LEN,
            });
        }
        let mut cursor = 6;
        let destination_connection_id = take(input, &mut cursor, destination_length)?;

        let source_length_bytes = take(input, &mut cursor, 1)?;
        let source_length = usize::from(
            source_length_bytes
                .first()
                .copied()
                .ok_or(WireError::LengthOverflow)?,
        );
        if source_length > MAX_LONG_CONNECTION_ID_LEN {
            return Err(WireError::ConnectionIdTooLong {
                length: source_length,
                maximum: MAX_LONG_CONNECTION_ID_LEN,
            });
        }
        let source_connection_id = take(input, &mut cursor, source_length)?;

        let message_id = read_u32(input, cursor)?;
        cursor += 4;
        let fragment_offset = read_u16(input, cursor)?;
        cursor += 2;
        let fragment_length = usize::from(read_u16(input, cursor)?);
        cursor += 2;
        let message_length = read_u16(input, cursor)?;
        cursor += 2;

        let expected = cursor
            .checked_add(fragment_length)
            .ok_or(WireError::LengthOverflow)?;
        if input.len() < expected {
            return Err(WireError::PacketTooShort {
                minimum: expected,
                actual: input.len(),
            });
        }
        if input.len() != expected {
            return Err(WireError::LengthMismatch {
                expected,
                actual: input.len(),
            });
        }
        validate_fragment(fragment_offset, message_length, fragment_length)?;

        Ok(Self {
            packet_type,
            version,
            destination_connection_id,
            source_connection_id,
            message_id,
            fragment_offset,
            message_length,
            fragment: &input[cursor..expected],
        })
    }
}

fn validate_connection_id(connection_id: &[u8]) -> Result<(), WireError> {
    if connection_id.len() > MAX_LONG_CONNECTION_ID_LEN {
        return Err(WireError::ConnectionIdTooLong {
            length: connection_id.len(),
            maximum: MAX_LONG_CONNECTION_ID_LEN,
        });
    }
    Ok(())
}

fn validate_fragment(
    fragment_offset: u16,
    message_length: u16,
    fragment_length: usize,
) -> Result<(), WireError> {
    let message_length = usize::from(message_length);
    if message_length > MAX_HANDSHAKE_MESSAGE_LEN {
        return Err(WireError::HandshakeMessageTooLarge {
            length: message_length,
            maximum: MAX_HANDSHAKE_MESSAGE_LEN,
        });
    }
    let fragment_end = usize::from(fragment_offset)
        .checked_add(fragment_length)
        .ok_or(WireError::LengthOverflow)?;
    if fragment_end > message_length {
        return Err(WireError::InvalidFragmentBounds);
    }
    Ok(())
}

fn take<'a>(input: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8], WireError> {
    let end = cursor
        .checked_add(length)
        .ok_or(WireError::LengthOverflow)?;
    let value = input.get(*cursor..end).ok_or(WireError::PacketTooShort {
        minimum: end,
        actual: input.len(),
    })?;
    *cursor = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_packet_round_trip_borrows_all_fields() {
        let mut output = [0_u8; 256];
        let written = LongPacket {
            packet_type: LongPacketType::Init,
            version: 1,
            destination_connection_id: b"dest-cid",
            source_connection_id: b"source-cid",
            message_id: 17,
            fragment_offset: 100,
            message_length: 200,
            fragment: b"fragment",
        }
        .encode(&mut output)
        .expect("valid long packet");
        let packet = LongPacket::decode(&output[..written]).expect("packet decodes");

        assert_eq!(packet.packet_type, LongPacketType::Init);
        assert_eq!(packet.version, 1);
        assert_eq!(packet.destination_connection_id, b"dest-cid");
        assert_eq!(packet.source_connection_id, b"source-cid");
        assert_eq!(packet.message_id, 17);
        assert_eq!(packet.fragment_offset, 100);
        assert_eq!(packet.message_length, 200);
        assert_eq!(packet.fragment, b"fragment");
    }

    #[test]
    fn every_long_packet_type_round_trips() {
        for packet_type in [
            LongPacketType::Hello,
            LongPacketType::Retry,
            LongPacketType::Init,
            LongPacketType::Response,
            LongPacketType::Finish,
            LongPacketType::VersionNegotiation,
        ] {
            let mut output = [0_u8; 64];
            let written = LongPacket {
                packet_type,
                version: 1,
                destination_connection_id: &[],
                source_connection_id: b"source",
                message_id: 0,
                fragment_offset: 0,
                message_length: 1,
                fragment: &[0],
            }
            .encode(&mut output)
            .expect("valid packet");
            assert_eq!(
                LongPacket::decode(&output[..written])
                    .expect("decodes")
                    .packet_type,
                packet_type
            );
        }
    }

    #[test]
    fn invalid_fragment_bounds_are_rejected() {
        let mut output = [0_u8; 64];
        assert_eq!(
            LongPacket {
                packet_type: LongPacketType::Init,
                version: 1,
                destination_connection_id: &[],
                source_connection_id: &[],
                message_id: 0,
                fragment_offset: 9,
                message_length: 10,
                fragment: &[1, 2],
            }
            .encode(&mut output),
            Err(WireError::InvalidFragmentBounds)
        );
    }

    #[test]
    fn oversized_connection_id_is_rejected() {
        let connection_id = [0_u8; MAX_LONG_CONNECTION_ID_LEN + 1];
        let mut output = [0_u8; 128];
        assert_eq!(
            LongPacket {
                packet_type: LongPacketType::Hello,
                version: 1,
                destination_connection_id: &connection_id,
                source_connection_id: &[],
                message_id: 0,
                fragment_offset: 0,
                message_length: 0,
                fragment: &[],
            }
            .encode(&mut output),
            Err(WireError::ConnectionIdTooLong {
                length: MAX_LONG_CONNECTION_ID_LEN + 1,
                maximum: MAX_LONG_CONNECTION_ID_LEN,
            })
        );
    }
}
