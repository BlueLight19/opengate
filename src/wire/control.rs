//! Allocation-free codec and iterator for CONTROL packet TLVs.

use super::{WireError, read_u16};

/// Size of a CONTROL TLV header.
pub const CONTROL_FRAME_HEADER_LEN: usize = 3;

/// CONTROL frame types assigned by OGTP/1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ControlType {
    Ping = 0x01,
    Credit = 0x02,
    Manifest = 0x03,
    Commit = 0x04,
    Resume = 0x05,
    PathOffer = 0x06,
    PathAccept = 0x07,
    PathRetire = 0x08,
    KeyUpdate = 0x09,
    Close = 0x0a,
    Error = 0x0b,
}

impl ControlType {
    /// Maps an assigned wire value to its semantic type.
    #[must_use]
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Ping),
            0x02 => Some(Self::Credit),
            0x03 => Some(Self::Manifest),
            0x04 => Some(Self::Commit),
            0x05 => Some(Self::Resume),
            0x06 => Some(Self::PathOffer),
            0x07 => Some(Self::PathAccept),
            0x08 => Some(Self::PathRetire),
            0x09 => Some(Self::KeyUpdate),
            0x0a => Some(Self::Close),
            0x0b => Some(Self::Error),
            _ => None,
        }
    }
}

/// Returns whether an unknown CONTROL type is critical.
#[must_use]
pub const fn is_critical_type(frame_type: u8) -> bool {
    frame_type & 0x80 != 0
}

/// A borrowed CONTROL TLV.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlFrame<'a> {
    pub frame_type: u8,
    pub value: &'a [u8],
}

impl ControlFrame<'_> {
    /// Returns the assigned semantic type, if known.
    #[must_use]
    pub const fn known_type(self) -> Option<ControlType> {
        ControlType::from_wire(self.frame_type)
    }
}

/// Encodes one CONTROL TLV.
///
/// # Errors
///
/// Returns an error when the value exceeds 65,535 bytes, arithmetic overflows,
/// or the output buffer is too small.
pub fn encode_control_frame(
    frame_type: u8,
    value: &[u8],
    output: &mut [u8],
) -> Result<usize, WireError> {
    let value_length = u16::try_from(value.len()).map_err(|_| WireError::FrameValueTooLarge {
        length: value.len(),
        maximum: usize::from(u16::MAX),
    })?;
    let needed = CONTROL_FRAME_HEADER_LEN
        .checked_add(value.len())
        .ok_or(WireError::LengthOverflow)?;
    if output.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            available: output.len(),
        });
    }

    output[0] = frame_type;
    output[1..3].copy_from_slice(&value_length.to_be_bytes());
    output[3..needed].copy_from_slice(value);
    Ok(needed)
}

/// Iterator over CONTROL TLVs that stops after the first malformed frame.
#[derive(Clone, Debug)]
pub struct ControlFrameIter<'a> {
    remaining: &'a [u8],
    failed: bool,
}

impl<'a> ControlFrameIter<'a> {
    /// Creates an iterator over one authenticated CONTROL plaintext.
    #[must_use]
    pub const fn new(payload: &'a [u8]) -> Self {
        Self {
            remaining: payload,
            failed: false,
        }
    }
}

impl<'a> Iterator for ControlFrameIter<'a> {
    type Item = Result<ControlFrame<'a>, WireError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.remaining.is_empty() {
            return None;
        }
        if self.remaining.len() < CONTROL_FRAME_HEADER_LEN {
            self.failed = true;
            return Some(Err(WireError::PacketTooShort {
                minimum: CONTROL_FRAME_HEADER_LEN,
                actual: self.remaining.len(),
            }));
        }

        let value_length = match read_u16(self.remaining, 1) {
            Ok(value) => usize::from(value),
            Err(error) => {
                self.failed = true;
                return Some(Err(error));
            }
        };
        let Some(needed) = CONTROL_FRAME_HEADER_LEN.checked_add(value_length) else {
            self.failed = true;
            return Some(Err(WireError::LengthOverflow));
        };
        if self.remaining.len() < needed {
            self.failed = true;
            return Some(Err(WireError::PacketTooShort {
                minimum: needed,
                actual: self.remaining.len(),
            }));
        }

        let frame = ControlFrame {
            frame_type: self.remaining[0],
            value: &self.remaining[CONTROL_FRAME_HEADER_LEN..needed],
        };
        self.remaining = &self.remaining[needed..];
        Some(Ok(frame))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_sequence_round_trip() {
        let mut payload = [0_u8; 64];
        let first =
            encode_control_frame(ControlType::Ping as u8, &[], &mut payload).expect("PING fits");
        let second =
            encode_control_frame(ControlType::Credit as u8, b"credit", &mut payload[first..])
                .expect("CREDIT fits");
        let frames = ControlFrameIter::new(&payload[..first + second])
            .collect::<Result<Vec<_>, _>>()
            .expect("valid sequence");

        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].known_type(), Some(ControlType::Ping));
        assert_eq!(frames[0].value, b"");
        assert_eq!(frames[1].known_type(), Some(ControlType::Credit));
        assert_eq!(frames[1].value, b"credit");
    }

    #[test]
    fn iterator_reports_truncation_once() {
        let bytes = [ControlType::Credit as u8, 0, 4, 1, 2];
        let mut frames = ControlFrameIter::new(&bytes);
        assert_eq!(
            frames.next(),
            Some(Err(WireError::PacketTooShort {
                minimum: 7,
                actual: 5,
            }))
        );
        assert_eq!(frames.next(), None);
    }

    #[test]
    fn unknown_type_criticality_uses_high_bit() {
        assert_eq!(ControlType::from_wire(0x40), None);
        assert!(!is_critical_type(0x40));
        assert!(is_critical_type(0xc0));
    }
}
