//! Allocation-free codec for ACK packet plaintext.

use super::{WireError, read_u16, read_u32, read_u64};

/// Bytes before the first additional ACK range.
pub const ACK_BASE_LEN: usize = 15;
/// Encoded size of every additional ACK range.
pub const ACK_RANGE_LEN: usize = 4;
/// Maximum number of additional ranges in one ACK packet.
pub const MAX_ADDITIONAL_ACK_RANGES: usize = 32;

/// One acknowledged range below the preceding range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AckRange {
    /// Number of unacknowledged packets between this and the preceding range.
    pub gap: u16,
    /// Number of acknowledged packets in this range.
    pub length: u16,
}

/// Borrowed ACK frame decoded without allocating a range collection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AckFrame<'a> {
    pub largest_acked: u64,
    pub ack_delay_micros: u32,
    pub first_range_length: u16,
    encoded_ranges: &'a [u8],
}

impl<'a> AckFrame<'a> {
    /// Encodes a canonical ACK plaintext.
    ///
    /// # Errors
    ///
    /// Returns an error for too many ranges, zero or underflowing range values,
    /// arithmetic overflow, or an output buffer that is too small.
    pub fn encode(
        largest_acked: u64,
        ack_delay_micros: u32,
        first_range_length: u16,
        additional_ranges: &[AckRange],
        output: &mut [u8],
    ) -> Result<usize, WireError> {
        if additional_ranges.len() > MAX_ADDITIONAL_ACK_RANGES {
            return Err(WireError::TooManyAckRanges {
                count: additional_ranges.len(),
                maximum: MAX_ADDITIONAL_ACK_RANGES,
            });
        }
        validate_ranges(
            largest_acked,
            first_range_length,
            additional_ranges.iter().copied(),
        )?;

        let ranges_len = additional_ranges
            .len()
            .checked_mul(ACK_RANGE_LEN)
            .ok_or(WireError::LengthOverflow)?;
        let needed = ACK_BASE_LEN
            .checked_add(ranges_len)
            .ok_or(WireError::LengthOverflow)?;
        if output.len() < needed {
            return Err(WireError::BufferTooSmall {
                needed,
                available: output.len(),
            });
        }

        output[0..8].copy_from_slice(&largest_acked.to_be_bytes());
        output[8..12].copy_from_slice(&ack_delay_micros.to_be_bytes());
        output[12..14].copy_from_slice(&first_range_length.to_be_bytes());
        output[14] =
            u8::try_from(additional_ranges.len()).map_err(|_| WireError::TooManyAckRanges {
                count: additional_ranges.len(),
                maximum: MAX_ADDITIONAL_ACK_RANGES,
            })?;

        let mut offset = ACK_BASE_LEN;
        for range in additional_ranges {
            output[offset..offset + 2].copy_from_slice(&range.gap.to_be_bytes());
            output[offset + 2..offset + 4].copy_from_slice(&range.length.to_be_bytes());
            offset += ACK_RANGE_LEN;
        }
        Ok(needed)
    }

    /// Decodes and validates an entire ACK plaintext.
    ///
    /// # Errors
    ///
    /// Returns an error when the input is truncated, has trailing bytes,
    /// contains too many ranges, or describes zero/underflowing ranges.
    pub fn decode(input: &'a [u8]) -> Result<Self, WireError> {
        if input.len() < ACK_BASE_LEN {
            return Err(WireError::PacketTooShort {
                minimum: ACK_BASE_LEN,
                actual: input.len(),
            });
        }

        let range_count = usize::from(input[14]);
        if range_count > MAX_ADDITIONAL_ACK_RANGES {
            return Err(WireError::TooManyAckRanges {
                count: range_count,
                maximum: MAX_ADDITIONAL_ACK_RANGES,
            });
        }
        let expected = ACK_BASE_LEN
            .checked_add(
                range_count
                    .checked_mul(ACK_RANGE_LEN)
                    .ok_or(WireError::LengthOverflow)?,
            )
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

        let frame = Self {
            largest_acked: read_u64(input, 0)?,
            ack_delay_micros: read_u32(input, 8)?,
            first_range_length: read_u16(input, 12)?,
            encoded_ranges: &input[ACK_BASE_LEN..],
        };
        validate_ranges(
            frame.largest_acked,
            frame.first_range_length,
            frame.additional_ranges(),
        )?;
        Ok(frame)
    }

    /// Returns the number of additional ranges after the first range.
    #[must_use]
    pub const fn additional_range_count(self) -> usize {
        self.encoded_ranges.len() / ACK_RANGE_LEN
    }

    /// Iterates over additional ranges without allocating.
    #[must_use]
    pub const fn additional_ranges(self) -> AckRangeIter<'a> {
        AckRangeIter {
            remaining: self.encoded_ranges,
        }
    }
}

/// Iterator over borrowed ACK range bytes.
#[derive(Clone, Debug)]
pub struct AckRangeIter<'a> {
    remaining: &'a [u8],
}

impl Iterator for AckRangeIter<'_> {
    type Item = AckRange;

    fn next(&mut self) -> Option<Self::Item> {
        let bytes = self.remaining.get(..ACK_RANGE_LEN)?;
        self.remaining = self.remaining.get(ACK_RANGE_LEN..)?;
        Some(AckRange {
            gap: read_u16(bytes, 0).ok()?,
            length: read_u16(bytes, 2).ok()?,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let count = self.remaining.len() / ACK_RANGE_LEN;
        (count, Some(count))
    }
}

impl ExactSizeIterator for AckRangeIter<'_> {}

fn validate_ranges(
    largest_acked: u64,
    first_range_length: u16,
    additional_ranges: impl Iterator<Item = AckRange>,
) -> Result<(), WireError> {
    if first_range_length == 0 {
        return Err(WireError::InvalidAckRanges);
    }
    let mut current_start = largest_acked
        .checked_sub(u64::from(first_range_length) - 1)
        .ok_or(WireError::InvalidAckRanges)?;

    for range in additional_ranges {
        if range.gap == 0 || range.length == 0 {
            return Err(WireError::InvalidAckRanges);
        }
        let next_end = current_start
            .checked_sub(u64::from(range.gap) + 1)
            .ok_or(WireError::InvalidAckRanges)?;
        current_start = next_end
            .checked_sub(u64::from(range.length) - 1)
            .ok_or(WireError::InvalidAckRanges)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_round_trip_preserves_ranges() {
        let ranges = [
            AckRange { gap: 2, length: 4 },
            AckRange { gap: 1, length: 2 },
        ];
        let mut output = [0_u8; 64];
        let written = AckFrame::encode(100, 250, 3, &ranges, &mut output).expect("valid ACK");
        let decoded = AckFrame::decode(&output[..written]).expect("decodes");

        assert_eq!(decoded.largest_acked, 100);
        assert_eq!(decoded.ack_delay_micros, 250);
        assert_eq!(decoded.first_range_length, 3);
        assert_eq!(decoded.additional_range_count(), 2);
        assert_eq!(decoded.additional_ranges().collect::<Vec<_>>(), ranges);
    }

    #[test]
    fn zero_and_underflowing_ranges_are_rejected() {
        let mut output = [0_u8; 64];
        assert_eq!(
            AckFrame::encode(10, 0, 0, &[], &mut output),
            Err(WireError::InvalidAckRanges)
        );
        assert_eq!(
            AckFrame::encode(1, 0, 2, &[AckRange { gap: 1, length: 1 }], &mut output),
            Err(WireError::InvalidAckRanges)
        );
    }

    #[test]
    fn trailing_ack_bytes_are_rejected() {
        let mut output = [0_u8; ACK_BASE_LEN + 1];
        let written = AckFrame::encode(5, 0, 1, &[], &mut output).expect("valid ACK");
        output[written] = 0;
        assert_eq!(
            AckFrame::decode(&output),
            Err(WireError::LengthMismatch {
                expected: ACK_BASE_LEN,
                actual: ACK_BASE_LEN + 1,
            })
        );
    }
}
