//! Allocation-free codec and iterator for CONTROL packet TLVs.

use super::{WireError, read_u16, read_u32, read_u64};

/// Size of a CONTROL TLV header.
pub const CONTROL_FRAME_HEADER_LEN: usize = 3;

/// Encoded size of one canonical chunk range.
pub const CHUNK_RANGE_LEN: usize = 8;
/// Maximum number of ranges accepted in one COMMIT or RESUME value.
pub const MAX_CHUNK_RANGES: usize = 32;
/// Fixed bytes preceding the ranges in a COMMIT value.
pub const COMMIT_FIXED_LEN: usize = 14;
/// Fixed bytes preceding the ranges in a RESUME value.
pub const RESUME_FIXED_LEN: usize = 22;

const COMMIT_OBJECT_COMPLETE_FLAG: u8 = 0x01;
const RESUME_FINAL_WINDOW_FLAG: u8 = 0x01;
const CHUNK_INDEX_SPACE: u64 = 1_u64 << 32;

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

/// One non-empty contiguous run of chunk indices.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkRange {
    /// Absolute chunk index for COMMIT, or window-relative offset for RESUME.
    pub start: u32,
    /// Number of chunks in the run.
    pub count: u32,
}

impl ChunkRange {
    /// Returns the exclusive end in a widened integer domain.
    #[must_use]
    pub fn end_exclusive(self) -> u64 {
        u64::from(self.start) + u64::from(self.count)
    }
}

/// Allocation-free iterator over a validated encoded range sequence.
#[derive(Clone, Debug)]
pub struct ChunkRangeIter<'a> {
    remaining: &'a [u8],
    remaining_count: usize,
}

impl<'a> ChunkRangeIter<'a> {
    const fn new(encoded_ranges: &'a [u8], range_count: usize) -> Self {
        Self {
            remaining: encoded_ranges,
            remaining_count: range_count,
        }
    }
}

impl Iterator for ChunkRangeIter<'_> {
    type Item = ChunkRange;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining_count == 0 {
            return None;
        }
        let Ok(start) = read_u32(self.remaining, 0) else {
            self.remaining_count = 0;
            return None;
        };
        let Ok(count) = read_u32(self.remaining, 4) else {
            self.remaining_count = 0;
            return None;
        };
        self.remaining = &self.remaining[CHUNK_RANGE_LEN..];
        self.remaining_count -= 1;
        Some(ChunkRange { start, count })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining_count, Some(self.remaining_count))
    }
}

impl ExactSizeIterator for ChunkRangeIter<'_> {}

/// Sender-owned fields for one COMMIT value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitHeader {
    /// Monotonically increasing sequence within the object slot.
    pub sequence: u64,
    /// Connection-local manifest object slot.
    pub object_slot: u32,
    /// Whether the receiver verified the complete object and manifest root.
    pub object_complete: bool,
}

impl CommitHeader {
    /// Encodes a canonical COMMIT value followed by absolute chunk ranges.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, oversized, overlapping, adjacent, or
    /// out-of-domain range sequence, or when `output` is too small.
    pub fn encode(self, ranges: &[ChunkRange], output: &mut [u8]) -> Result<usize, WireError> {
        validate_range_count(ranges.len(), self.object_complete)?;
        validate_ranges(ranges.iter().copied(), CHUNK_INDEX_SPACE)?;
        let needed = control_value_len(COMMIT_FIXED_LEN, ranges.len())?;
        ensure_output(needed, output.len())?;

        output[0..8].copy_from_slice(&self.sequence.to_be_bytes());
        output[8..12].copy_from_slice(&self.object_slot.to_be_bytes());
        output[12] = if self.object_complete {
            COMMIT_OBJECT_COMPLETE_FLAG
        } else {
            0
        };
        output[13] = u8::try_from(ranges.len()).map_err(|_| WireError::LengthOverflow)?;
        encode_ranges(ranges, &mut output[COMMIT_FIXED_LEN..needed]);
        Ok(needed)
    }
}

/// Borrowed, validated COMMIT value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Commit<'a> {
    pub header: CommitHeader,
    encoded_ranges: &'a [u8],
    range_count: usize,
}

impl<'a> Commit<'a> {
    /// Decodes and semantically validates one exact COMMIT value.
    ///
    /// # Errors
    ///
    /// Returns an error for a length mismatch, unsupported flag, or a
    /// non-canonical range sequence.
    pub fn decode(input: &'a [u8]) -> Result<Self, WireError> {
        ensure_fixed_input(input, COMMIT_FIXED_LEN)?;
        let flags = input[12];
        if flags & !COMMIT_OBJECT_COMPLETE_FLAG != 0 {
            return Err(WireError::InvalidControlFlags {
                frame_type: ControlType::Commit as u8,
                flags,
            });
        }
        let range_count = usize::from(input[13]);
        validate_range_count(range_count, flags & COMMIT_OBJECT_COMPLETE_FLAG != 0)?;
        let needed = control_value_len(COMMIT_FIXED_LEN, range_count)?;
        ensure_exact_input(input, needed)?;
        let encoded_ranges = &input[COMMIT_FIXED_LEN..needed];
        validate_ranges(
            ChunkRangeIter::new(encoded_ranges, range_count),
            CHUNK_INDEX_SPACE,
        )?;
        Ok(Self {
            header: CommitHeader {
                sequence: read_u64(input, 0)?,
                object_slot: read_u32(input, 8)?,
                object_complete: flags & COMMIT_OBJECT_COMPLETE_FLAG != 0,
            },
            encoded_ranges,
            range_count,
        })
    }

    /// Returns the number of committed ranges.
    #[must_use]
    pub const fn range_count(&self) -> usize {
        self.range_count
    }

    /// Iterates over the validated ranges without allocation.
    #[must_use]
    pub fn ranges(&self) -> ChunkRangeIter<'a> {
        ChunkRangeIter::new(self.encoded_ranges, self.range_count)
    }
}

/// Sender-owned fields for one window of a RESUME snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResumeHeader {
    /// Monotonically increasing snapshot sequence within the object slot.
    pub sequence: u64,
    /// Connection-local manifest object slot.
    pub object_slot: u32,
    /// First chunk index described by this window.
    pub window_start: u32,
    /// Number of chunk indices described by this window.
    pub window_chunk_count: u32,
    /// Whether this is the last window in the snapshot.
    pub final_window: bool,
}

impl ResumeHeader {
    /// Encodes a canonical RESUME value with window-relative present ranges.
    ///
    /// An empty range list is valid and reports that no chunk in the window is
    /// already verified.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid window, too many ranges, a
    /// non-canonical range sequence, or an undersized output.
    pub fn encode(self, ranges: &[ChunkRange], output: &mut [u8]) -> Result<usize, WireError> {
        validate_resume_window(self.window_start, self.window_chunk_count)?;
        validate_range_count(ranges.len(), true)?;
        validate_ranges(ranges.iter().copied(), u64::from(self.window_chunk_count))?;
        let needed = control_value_len(RESUME_FIXED_LEN, ranges.len())?;
        ensure_output(needed, output.len())?;

        output[0..8].copy_from_slice(&self.sequence.to_be_bytes());
        output[8..12].copy_from_slice(&self.object_slot.to_be_bytes());
        output[12..16].copy_from_slice(&self.window_start.to_be_bytes());
        output[16..20].copy_from_slice(&self.window_chunk_count.to_be_bytes());
        output[20] = if self.final_window {
            RESUME_FINAL_WINDOW_FLAG
        } else {
            0
        };
        output[21] = u8::try_from(ranges.len()).map_err(|_| WireError::LengthOverflow)?;
        encode_ranges(ranges, &mut output[RESUME_FIXED_LEN..needed]);
        Ok(needed)
    }
}

/// Borrowed, validated RESUME window value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Resume<'a> {
    pub header: ResumeHeader,
    encoded_ranges: &'a [u8],
    range_count: usize,
}

impl<'a> Resume<'a> {
    /// Decodes and semantically validates one exact RESUME window value.
    ///
    /// # Errors
    ///
    /// Returns an error for a length mismatch, invalid window, unsupported
    /// flag, or a range outside the window.
    pub fn decode(input: &'a [u8]) -> Result<Self, WireError> {
        ensure_fixed_input(input, RESUME_FIXED_LEN)?;
        let flags = input[20];
        if flags & !RESUME_FINAL_WINDOW_FLAG != 0 {
            return Err(WireError::InvalidControlFlags {
                frame_type: ControlType::Resume as u8,
                flags,
            });
        }
        let window_start = read_u32(input, 12)?;
        let window_chunk_count = read_u32(input, 16)?;
        validate_resume_window(window_start, window_chunk_count)?;
        let range_count = usize::from(input[21]);
        validate_range_count(range_count, true)?;
        let needed = control_value_len(RESUME_FIXED_LEN, range_count)?;
        ensure_exact_input(input, needed)?;
        let encoded_ranges = &input[RESUME_FIXED_LEN..needed];
        validate_ranges(
            ChunkRangeIter::new(encoded_ranges, range_count),
            u64::from(window_chunk_count),
        )?;
        Ok(Self {
            header: ResumeHeader {
                sequence: read_u64(input, 0)?,
                object_slot: read_u32(input, 8)?,
                window_start,
                window_chunk_count,
                final_window: flags & RESUME_FINAL_WINDOW_FLAG != 0,
            },
            encoded_ranges,
            range_count,
        })
    }

    /// Returns the number of verified ranges in the window.
    #[must_use]
    pub const fn range_count(&self) -> usize {
        self.range_count
    }

    /// Iterates over window-relative verified ranges without allocation.
    #[must_use]
    pub fn ranges(&self) -> ChunkRangeIter<'a> {
        ChunkRangeIter::new(self.encoded_ranges, self.range_count)
    }
}

fn validate_resume_window(window_start: u32, window_count: u32) -> Result<(), WireError> {
    let end = u64::from(window_start) + u64::from(window_count);
    if window_count == 0 || end > CHUNK_INDEX_SPACE {
        return Err(WireError::InvalidResumeWindow);
    }
    Ok(())
}

fn validate_range_count(count: usize, allow_empty: bool) -> Result<(), WireError> {
    if count > MAX_CHUNK_RANGES {
        return Err(WireError::TooManyChunkRanges {
            count,
            maximum: MAX_CHUNK_RANGES,
        });
    }
    if !allow_empty && count == 0 {
        return Err(WireError::InvalidChunkRanges);
    }
    Ok(())
}

fn validate_ranges(
    ranges: impl Iterator<Item = ChunkRange>,
    upper_bound: u64,
) -> Result<(), WireError> {
    let mut previous_end = None;
    for range in ranges {
        let start = u64::from(range.start);
        let end = range.end_exclusive();
        if range.count == 0
            || end > upper_bound
            || previous_end.is_some_and(|previous| start <= previous)
        {
            return Err(WireError::InvalidChunkRanges);
        }
        previous_end = Some(end);
    }
    Ok(())
}

fn control_value_len(fixed: usize, range_count: usize) -> Result<usize, WireError> {
    fixed
        .checked_add(
            range_count
                .checked_mul(CHUNK_RANGE_LEN)
                .ok_or(WireError::LengthOverflow)?,
        )
        .ok_or(WireError::LengthOverflow)
}

fn ensure_output(needed: usize, available: usize) -> Result<(), WireError> {
    if available < needed {
        return Err(WireError::BufferTooSmall { needed, available });
    }
    Ok(())
}

fn ensure_fixed_input(input: &[u8], fixed: usize) -> Result<(), WireError> {
    if input.len() < fixed {
        return Err(WireError::PacketTooShort {
            minimum: fixed,
            actual: input.len(),
        });
    }
    Ok(())
}

fn ensure_exact_input(input: &[u8], needed: usize) -> Result<(), WireError> {
    if input.len() < needed {
        return Err(WireError::PacketTooShort {
            minimum: needed,
            actual: input.len(),
        });
    }
    if input.len() != needed {
        return Err(WireError::LengthMismatch {
            expected: needed,
            actual: input.len(),
        });
    }
    Ok(())
}

fn encode_ranges(ranges: &[ChunkRange], output: &mut [u8]) {
    for (index, range) in ranges.iter().copied().enumerate() {
        let offset = index * CHUNK_RANGE_LEN;
        output[offset..offset + 4].copy_from_slice(&range.start.to_be_bytes());
        output[offset + 4..offset + CHUNK_RANGE_LEN].copy_from_slice(&range.count.to_be_bytes());
    }
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

    const COMMIT_RANGES: [ChunkRange; 2] = [
        ChunkRange { start: 0, count: 3 },
        ChunkRange { start: 5, count: 2 },
    ];

    const RESUME_RANGES: [ChunkRange; 2] = [
        ChunkRange {
            start: 0,
            count: 10,
        },
        ChunkRange {
            start: 20,
            count: 5,
        },
    ];

    const fn commit_header() -> CommitHeader {
        CommitHeader {
            sequence: 0x1112_1314_1516_1718,
            object_slot: 0x0102_0304,
            object_complete: true,
        }
    }

    const fn resume_header() -> ResumeHeader {
        ResumeHeader {
            sequence: 0x2122_2324_2526_2728,
            object_slot: 0x0102_0304,
            window_start: 0x1000,
            window_chunk_count: 0x100,
            final_window: true,
        }
    }

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

    #[test]
    fn commit_value_is_bit_exact_and_borrowed() {
        let expected = [
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00,
            0x00, 0x02,
        ];
        let mut output = [0_u8; 64];
        let written = commit_header()
            .encode(&COMMIT_RANGES, &mut output)
            .expect("canonical COMMIT encodes");
        assert_eq!(written, expected.len());
        assert_eq!(&output[..written], expected);

        let decoded = Commit::decode(&output[..written]).expect("COMMIT decodes");
        assert_eq!(decoded.header, commit_header());
        assert_eq!(decoded.range_count(), 2);
        assert_eq!(decoded.ranges().len(), 2);
        assert_eq!(decoded.ranges().collect::<Vec<_>>(), COMMIT_RANGES);
    }

    #[test]
    fn resume_value_is_bit_exact_and_borrowed() {
        let expected = [
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00,
            0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x0a, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x05,
        ];
        let mut output = [0_u8; 64];
        let written = resume_header()
            .encode(&RESUME_RANGES, &mut output)
            .expect("canonical RESUME encodes");
        assert_eq!(written, expected.len());
        assert_eq!(&output[..written], expected);

        let decoded = Resume::decode(&output[..written]).expect("RESUME decodes");
        assert_eq!(decoded.header, resume_header());
        assert_eq!(decoded.range_count(), 2);
        assert_eq!(decoded.ranges().collect::<Vec<_>>(), RESUME_RANGES);
    }

    #[test]
    fn commit_rejects_non_canonical_ranges() {
        let mut output = [0_u8; 512];
        let incomplete = CommitHeader {
            object_complete: false,
            ..commit_header()
        };
        assert_eq!(
            incomplete.encode(&[], &mut output),
            Err(WireError::InvalidChunkRanges)
        );
        for ranges in [
            [
                ChunkRange { start: 0, count: 0 },
                ChunkRange { start: 5, count: 1 },
            ],
            [
                ChunkRange { start: 0, count: 3 },
                ChunkRange { start: 3, count: 1 },
            ],
            [
                ChunkRange { start: 5, count: 2 },
                ChunkRange { start: 4, count: 1 },
            ],
            [
                ChunkRange {
                    start: u32::MAX,
                    count: 2,
                },
                ChunkRange { start: 0, count: 1 },
            ],
        ] {
            assert_eq!(
                commit_header().encode(&ranges, &mut output),
                Err(WireError::InvalidChunkRanges)
            );
        }
        let too_many = [ChunkRange { start: 0, count: 1 }; MAX_CHUNK_RANGES + 1];
        assert_eq!(
            commit_header().encode(&too_many, &mut output),
            Err(WireError::TooManyChunkRanges {
                count: MAX_CHUNK_RANGES + 1,
                maximum: MAX_CHUNK_RANGES,
            })
        );
    }

    #[test]
    fn complete_commit_may_carry_no_new_ranges() {
        let mut output = [0_u8; COMMIT_FIXED_LEN];
        assert_eq!(
            commit_header().encode(&[], &mut output),
            Ok(COMMIT_FIXED_LEN)
        );
        let decoded = Commit::decode(&output).expect("complete empty COMMIT decodes");
        assert!(decoded.header.object_complete);
        assert_eq!(decoded.range_count(), 0);
    }

    #[test]
    fn resume_validates_window_and_allows_an_empty_bitmap() {
        let mut output = [0_u8; 64];
        let empty_written = resume_header()
            .encode(&[], &mut output)
            .expect("empty present set is canonical");
        assert_eq!(empty_written, RESUME_FIXED_LEN);
        assert_eq!(
            Resume::decode(&output[..empty_written])
                .expect("empty RESUME decodes")
                .range_count(),
            0
        );

        let zero_window = ResumeHeader {
            window_chunk_count: 0,
            ..resume_header()
        };
        assert_eq!(
            zero_window.encode(&[], &mut output),
            Err(WireError::InvalidResumeWindow)
        );
        let overflowing_window = ResumeHeader {
            window_start: u32::MAX,
            window_chunk_count: 2,
            ..resume_header()
        };
        assert_eq!(
            overflowing_window.encode(&[], &mut output),
            Err(WireError::InvalidResumeWindow)
        );
        assert_eq!(
            resume_header().encode(
                &[ChunkRange {
                    start: 250,
                    count: 7,
                }],
                &mut output,
            ),
            Err(WireError::InvalidChunkRanges)
        );
    }

    #[test]
    fn typed_control_values_reject_flags_lengths_and_truncation() {
        let mut commit = [0_u8; 64];
        let commit_len = commit_header()
            .encode(&COMMIT_RANGES, &mut commit)
            .expect("COMMIT encodes");
        commit[12] = 0x02;
        assert_eq!(
            Commit::decode(&commit[..commit_len]),
            Err(WireError::InvalidControlFlags {
                frame_type: ControlType::Commit as u8,
                flags: 0x02,
            })
        );
        commit[12] = 0x01;
        commit[13] = 3;
        assert_eq!(
            Commit::decode(&commit[..commit_len]),
            Err(WireError::PacketTooShort {
                minimum: COMMIT_FIXED_LEN + 3 * CHUNK_RANGE_LEN,
                actual: commit_len,
            })
        );

        let mut resume = [0_u8; 64];
        let resume_len = resume_header()
            .encode(&RESUME_RANGES, &mut resume)
            .expect("RESUME encodes");
        resume[20] = 0x80;
        assert_eq!(
            Resume::decode(&resume[..resume_len]),
            Err(WireError::InvalidControlFlags {
                frame_type: ControlType::Resume as u8,
                flags: 0x80,
            })
        );

        for length in 0..COMMIT_FIXED_LEN {
            assert_eq!(
                Commit::decode(&[0_u8; COMMIT_FIXED_LEN][..length]),
                Err(WireError::PacketTooShort {
                    minimum: COMMIT_FIXED_LEN,
                    actual: length,
                })
            );
        }
        for length in 0..RESUME_FIXED_LEN {
            assert_eq!(
                Resume::decode(&[0_u8; RESUME_FIXED_LEN][..length]),
                Err(WireError::PacketTooShort {
                    minimum: RESUME_FIXED_LEN,
                    actual: length,
                })
            );
        }
    }
}
