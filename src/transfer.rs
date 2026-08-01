//! Bounded transfer-control state for manifests, COMMIT, and RESUME.

use core::fmt;

use crate::manifest::{
    MAX_SIGNED_MANIFEST_LEN, MIN_SIGNED_MANIFEST_LEN, Manifest, ManifestError, ManifestFragment,
};
use crate::wire::WireError;
use crate::wire::control::{ChunkRange, Commit, Resume};

const RECEIPT_BITMAP_LEN: usize = MAX_SIGNED_MANIFEST_LEN.div_ceil(8);
const EMPTY_RANGE: ChunkRange = ChunkRange { start: 0, count: 0 };

/// Result of accepting one authenticated MANIFEST fragment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestAssemblyStatus {
    Incomplete {
        object_slot: u32,
        received_bytes: usize,
        manifest_length: usize,
    },
    Complete {
        object_slot: u32,
        manifest_length: usize,
    },
}

#[derive(Debug)]
struct ManifestSlot {
    occupied: bool,
    object_slot: u32,
    manifest_length: usize,
    received_bytes: usize,
    bytes: [u8; MAX_SIGNED_MANIFEST_LEN],
    receipt: [u8; RECEIPT_BITMAP_LEN],
}

impl ManifestSlot {
    const fn new() -> Self {
        Self {
            occupied: false,
            object_slot: 0,
            manifest_length: 0,
            received_bytes: 0,
            bytes: [0; MAX_SIGNED_MANIFEST_LEN],
            receipt: [0; RECEIPT_BITMAP_LEN],
        }
    }

    fn begin(&mut self, object_slot: u32, manifest_length: usize) {
        self.occupied = true;
        self.object_slot = object_slot;
        self.manifest_length = manifest_length;
        self.received_bytes = 0;
        self.receipt.fill(0);
    }

    fn contains_byte(&self, offset: usize) -> bool {
        self.receipt[offset / 8] & (1 << (offset % 8)) != 0
    }

    fn mark_byte(&mut self, offset: usize) {
        self.receipt[offset / 8] |= 1 << (offset % 8);
    }

    fn clear(&mut self) {
        self.bytes.fill(0);
        self.receipt.fill(0);
        self.occupied = false;
        self.object_slot = 0;
        self.manifest_length = 0;
        self.received_bytes = 0;
    }
}

/// Fixed pool of logical-manifest reassembly slots.
#[derive(Debug)]
pub struct ManifestReassembler<const SLOTS: usize> {
    slots: [ManifestSlot; SLOTS],
}

impl<const SLOTS: usize> ManifestReassembler<SLOTS> {
    /// Creates an empty pool without heap allocation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| ManifestSlot::new()),
        }
    }

    /// Atomically accepts one authenticated fragment.
    ///
    /// Identical overlaps are idempotent. A conflicting overlap or changed
    /// logical length clears that object's incomplete slot. Completion also
    /// performs canonical manifest decoding, but not signature verification.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bounds, pool exhaustion, conflicting
    /// bytes, a changed logical length, or an invalid completed manifest.
    pub fn ingest(
        &mut self,
        fragment: ManifestFragment<'_>,
    ) -> Result<ManifestAssemblyStatus, TransferError> {
        validate_manifest_fragment(fragment)?;
        let total = usize::from(fragment.manifest_length);
        let offset = usize::from(fragment.fragment_offset);
        let index = if let Some(index) = self.slot_index(fragment.object_slot) {
            if self.slots[index].manifest_length != total {
                self.slots[index].clear();
                return Err(TransferError::ManifestLengthChanged(fragment.object_slot));
            }
            index
        } else {
            let index = self
                .slots
                .iter()
                .position(|slot| !slot.occupied)
                .ok_or(TransferError::ManifestPoolExhausted)?;
            self.slots[index].begin(fragment.object_slot, total);
            index
        };

        if let Some(conflict) = conflicting_offset(&self.slots[index], offset, fragment.fragment) {
            self.slots[index].clear();
            return Err(TransferError::ConflictingManifestOverlap {
                object_slot: fragment.object_slot,
                offset: conflict,
            });
        }
        let newly_received =
            count_new_fragment_bytes(&self.slots[index], offset, fragment.fragment);
        let updated_received_bytes = self.slots[index]
            .received_bytes
            .checked_add(newly_received)
            .ok_or(TransferError::AccountingOverflow)?;
        write_new_fragment_bytes(&mut self.slots[index], offset, fragment.fragment);
        self.slots[index].received_bytes = updated_received_bytes;

        if self.slots[index].received_bytes == total {
            if let Err(error) = Manifest::decode(&self.slots[index].bytes[..total]) {
                self.slots[index].clear();
                return Err(error.into());
            }
            Ok(ManifestAssemblyStatus::Complete {
                object_slot: fragment.object_slot,
                manifest_length: total,
            })
        } else {
            Ok(ManifestAssemblyStatus::Incomplete {
                object_slot: fragment.object_slot,
                received_bytes: self.slots[index].received_bytes,
                manifest_length: total,
            })
        }
    }

    /// Borrows a canonically decoded complete manifest.
    ///
    /// Signature verification is still required before installation.
    ///
    /// # Errors
    ///
    /// Returns an error when the slot is unknown, incomplete, or unexpectedly
    /// fails canonical decoding.
    pub fn completed_manifest(&self, object_slot: u32) -> Result<Manifest<'_>, TransferError> {
        let index = self
            .slot_index(object_slot)
            .ok_or(TransferError::UnknownManifestSlot(object_slot))?;
        let slot = &self.slots[index];
        if slot.received_bytes != slot.manifest_length {
            return Err(TransferError::ManifestIncomplete(object_slot));
        }
        Manifest::decode(&slot.bytes[..slot.manifest_length]).map_err(Into::into)
    }

    /// Erases and releases one manifest slot after installation or rejection.
    pub fn release(&mut self, object_slot: u32) -> bool {
        if let Some(index) = self.slot_index(object_slot) {
            self.slots[index].clear();
            true
        } else {
            false
        }
    }

    /// Returns the number of occupied reassembly slots.
    #[must_use]
    pub fn active_slots(&self) -> usize {
        self.slots.iter().filter(|slot| slot.occupied).count()
    }

    fn slot_index(&self, object_slot: u32) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.occupied && slot.object_slot == object_slot)
    }
}

impl<const SLOTS: usize> Default for ManifestReassembler<SLOTS> {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_manifest_fragment(fragment: ManifestFragment<'_>) -> Result<(), TransferError> {
    let total = usize::from(fragment.manifest_length);
    let offset = usize::from(fragment.fragment_offset);
    if !(MIN_SIGNED_MANIFEST_LEN..=MAX_SIGNED_MANIFEST_LEN).contains(&total) {
        return Err(ManifestError::InvalidLogicalLength {
            length: total,
            minimum: MIN_SIGNED_MANIFEST_LEN,
            maximum: MAX_SIGNED_MANIFEST_LEN,
        }
        .into());
    }
    if fragment.fragment.is_empty()
        || offset
            .checked_add(fragment.fragment.len())
            .is_none_or(|end| end > total)
    {
        return Err(ManifestError::Wire(WireError::InvalidFragmentBounds).into());
    }
    Ok(())
}

fn conflicting_offset(slot: &ManifestSlot, offset: usize, bytes: &[u8]) -> Option<usize> {
    bytes.iter().copied().enumerate().find_map(|(index, byte)| {
        let absolute = offset + index;
        (slot.contains_byte(absolute) && slot.bytes[absolute] != byte).then_some(absolute)
    })
}

fn count_new_fragment_bytes(slot: &ManifestSlot, offset: usize, bytes: &[u8]) -> usize {
    bytes
        .iter()
        .enumerate()
        .filter(|(index, _)| !slot.contains_byte(offset + index))
        .count()
}

fn write_new_fragment_bytes(slot: &mut ManifestSlot, offset: usize, bytes: &[u8]) {
    for (index, byte) in bytes.iter().copied().enumerate() {
        let absolute = offset + index;
        if !slot.contains_byte(absolute) {
            slot.bytes[absolute] = byte;
            slot.mark_byte(absolute);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RangeSet<const RANGES: usize> {
    ranges: [ChunkRange; RANGES],
    len: usize,
}

impl<const RANGES: usize> RangeSet<RANGES> {
    const fn new() -> Self {
        Self {
            ranges: [EMPTY_RANGE; RANGES],
            len: 0,
        }
    }

    fn as_slice(&self) -> &[ChunkRange] {
        &self.ranges[..self.len]
    }

    fn insert(&mut self, incoming: ChunkRange) -> Result<(), TransferError> {
        let mut rebuilt = Self::new();
        let mut merged = incoming;
        let mut inserted = false;
        for current in self.as_slice().iter().copied() {
            if current.end_exclusive() < u64::from(merged.start) {
                rebuilt.push(current)?;
            } else if merged.end_exclusive() < u64::from(current.start) {
                if !inserted {
                    rebuilt.push(merged)?;
                    inserted = true;
                }
                rebuilt.push(current)?;
            } else {
                merged = merge_ranges(merged, current)?;
            }
        }
        if !inserted {
            rebuilt.push(merged)?;
        }
        *self = rebuilt;
        Ok(())
    }

    fn push(&mut self, range: ChunkRange) -> Result<(), TransferError> {
        if self.len == RANGES {
            return Err(TransferError::RangeCapacityExceeded { maximum: RANGES });
        }
        self.ranges[self.len] = range;
        self.len += 1;
        Ok(())
    }

    fn covers_all(&self, chunk_count: u32) -> bool {
        if chunk_count == 0 {
            self.len == 0
        } else {
            self.len == 1 && self.ranges[0].start == 0 && self.ranges[0].count == chunk_count
        }
    }

    fn chunk_count(&self) -> u64 {
        self.as_slice()
            .iter()
            .map(|range| u64::from(range.count))
            .sum()
    }
}

fn merge_ranges(left: ChunkRange, right: ChunkRange) -> Result<ChunkRange, TransferError> {
    let start = left.start.min(right.start);
    let end = left.end_exclusive().max(right.end_exclusive());
    let count =
        u32::try_from(end - u64::from(start)).map_err(|_| TransferError::AccountingOverflow)?;
    Ok(ChunkRange { start, count })
}

/// Result of applying one sequenced COMMIT value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitStatus {
    IgnoredStale,
    Applied {
        sequence: u64,
        newly_committed_chunks: u64,
        object_complete: bool,
    },
}

/// Bounded idempotent committed-chunk state for one object slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitTracker<const RANGES: usize> {
    object_slot: u32,
    chunk_count: u32,
    newest_sequence: Option<u64>,
    committed: RangeSet<RANGES>,
    object_complete: bool,
}

impl<const RANGES: usize> CommitTracker<RANGES> {
    /// Creates empty committed state for an installed manifest.
    #[must_use]
    pub const fn new(object_slot: u32, chunk_count: u32) -> Self {
        Self {
            object_slot,
            chunk_count,
            newest_sequence: None,
            committed: RangeSet::new(),
            object_complete: false,
        }
    }

    /// Applies a COMMIT atomically and emits only newly committed ranges.
    ///
    /// The callback cannot fail and is invoked only after all validation and
    /// fixed-capacity updates succeed. The caller uses these ranges to release
    /// its own byte and fragment accounting.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong object, out-of-bounds ranges, capacity
    /// exhaustion, completion regression, or premature completion.
    pub fn apply(
        &mut self,
        commit: &Commit<'_>,
        mut on_new_range: impl FnMut(ChunkRange),
    ) -> Result<CommitStatus, TransferError> {
        if commit.header.object_slot != self.object_slot {
            return Err(TransferError::ObjectSlotMismatch {
                expected: self.object_slot,
                actual: commit.header.object_slot,
            });
        }
        if self
            .newest_sequence
            .is_some_and(|sequence| commit.header.sequence <= sequence)
        {
            return Ok(CommitStatus::IgnoredStale);
        }
        if self.object_complete && !commit.header.object_complete {
            return Err(TransferError::CompletionRegression);
        }

        let previous = self.committed;
        let mut candidate = previous;
        for range in commit.ranges() {
            validate_object_range(range, self.chunk_count)?;
            candidate.insert(range)?;
        }
        if commit.header.object_complete && !candidate.covers_all(self.chunk_count) {
            return Err(TransferError::PrematureObjectCompletion);
        }
        let newly_committed_chunks = difference_count(&previous, commit.ranges())?;
        emit_differences(&previous, commit.ranges(), &mut on_new_range)?;

        self.committed = candidate;
        self.newest_sequence = Some(commit.header.sequence);
        self.object_complete |= commit.header.object_complete;
        Ok(CommitStatus::Applied {
            sequence: commit.header.sequence,
            newly_committed_chunks,
            object_complete: self.object_complete,
        })
    }

    /// Returns the normalized committed ranges.
    #[must_use]
    pub fn committed_ranges(&self) -> &[ChunkRange] {
        self.committed.as_slice()
    }

    /// Returns the greatest applied COMMIT sequence.
    #[must_use]
    pub const fn newest_sequence(&self) -> Option<u64> {
        self.newest_sequence
    }

    /// Returns whether a validated final COMMIT covered the entire object.
    #[must_use]
    pub const fn object_complete(&self) -> bool {
        self.object_complete
    }
}

fn validate_object_range(range: ChunkRange, chunk_count: u32) -> Result<(), TransferError> {
    if range.count == 0 || range.end_exclusive() > u64::from(chunk_count) {
        return Err(TransferError::ChunkRangeOutsideObject);
    }
    Ok(())
}

fn difference_count<const RANGES: usize>(
    previous: &RangeSet<RANGES>,
    incoming: impl Iterator<Item = ChunkRange>,
) -> Result<u64, TransferError> {
    let mut total = 0_u64;
    for range in incoming {
        total = total
            .checked_add(visit_range_differences(previous.as_slice(), range, |_| {})?)
            .ok_or(TransferError::AccountingOverflow)?;
    }
    Ok(total)
}

fn emit_differences<const RANGES: usize>(
    previous: &RangeSet<RANGES>,
    incoming: impl Iterator<Item = ChunkRange>,
    callback: &mut impl FnMut(ChunkRange),
) -> Result<(), TransferError> {
    for range in incoming {
        visit_range_differences(previous.as_slice(), range, &mut *callback)?;
    }
    Ok(())
}

fn visit_range_differences(
    previous: &[ChunkRange],
    incoming: ChunkRange,
    mut callback: impl FnMut(ChunkRange),
) -> Result<u64, TransferError> {
    let mut total = 0_u64;
    let mut cursor = u64::from(incoming.start);
    let incoming_end = incoming.end_exclusive();
    for existing in previous {
        let existing_start = u64::from(existing.start);
        let existing_end = existing.end_exclusive();
        if existing_end <= cursor {
            continue;
        }
        if existing_start >= incoming_end {
            break;
        }
        if existing_start > cursor {
            visit_difference(
                cursor,
                existing_start.min(incoming_end),
                &mut total,
                &mut callback,
            )?;
        }
        cursor = cursor.max(existing_end);
        if cursor >= incoming_end {
            break;
        }
    }
    if cursor < incoming_end {
        visit_difference(cursor, incoming_end, &mut total, &mut callback)?;
    }
    Ok(total)
}

fn visit_difference(
    start: u64,
    end: u64,
    total: &mut u64,
    callback: &mut impl FnMut(ChunkRange),
) -> Result<(), TransferError> {
    let range = ChunkRange {
        start: u32::try_from(start).map_err(|_| TransferError::AccountingOverflow)?,
        count: u32::try_from(end - start).map_err(|_| TransferError::AccountingOverflow)?,
    };
    *total = total
        .checked_add(u64::from(range.count))
        .ok_or(TransferError::AccountingOverflow)?;
    callback(range);
    Ok(())
}

/// Result of accepting one RESUME window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResumeStatus {
    IgnoredStale,
    Pending {
        sequence: u64,
        next_window_start: u32,
    },
    Installed {
        sequence: u64,
        present_chunks: u64,
    },
}

/// Atomic, fixed-capacity RESUME snapshot assembler for one object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResumeTracker<const RANGES: usize> {
    object_slot: u32,
    chunk_count: u32,
    installed_sequence: Option<u64>,
    installed: RangeSet<RANGES>,
    pending_sequence: Option<u64>,
    pending_next_window: u32,
    pending: RangeSet<RANGES>,
}

impl<const RANGES: usize> ResumeTracker<RANGES> {
    /// Creates empty snapshot state for an installed manifest.
    #[must_use]
    pub const fn new(object_slot: u32, chunk_count: u32) -> Self {
        Self {
            object_slot,
            chunk_count,
            installed_sequence: None,
            installed: RangeSet::new(),
            pending_sequence: None,
            pending_next_window: 0,
            pending: RangeSet::new(),
        }
    }

    /// Atomically accepts one authenticated RESUME window.
    ///
    /// A pending snapshot is never exposed. Only a gap-free final window swaps
    /// the complete candidate into installed state.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong object, discontinuous windows, incorrect
    /// final flags, object-bound violations, or range-capacity exhaustion.
    pub fn apply(&mut self, resume: &Resume<'_>) -> Result<ResumeStatus, TransferError> {
        if resume.header.object_slot != self.object_slot {
            return Err(TransferError::ObjectSlotMismatch {
                expected: self.object_slot,
                actual: resume.header.object_slot,
            });
        }
        if self.is_stale(resume) {
            return Ok(ResumeStatus::IgnoredStale);
        }

        let sequence = resume.header.sequence;
        let window_start = resume.header.window_start;
        let window_end = u64::from(window_start) + u64::from(resume.header.window_chunk_count);
        if window_end > u64::from(self.chunk_count) {
            return Err(TransferError::ResumeWindowOutsideObject);
        }
        let expected_final = window_end == u64::from(self.chunk_count);
        if resume.header.final_window != expected_final {
            return Err(TransferError::InvalidResumeFinalFlag);
        }

        let continuing = self.pending_sequence == Some(sequence);
        if continuing && window_start != self.pending_next_window {
            if window_start < self.pending_next_window {
                return Ok(ResumeStatus::IgnoredStale);
            }
            return Err(TransferError::ResumeDiscontinuity {
                expected: self.pending_next_window,
                actual: window_start,
            });
        }
        if !continuing && window_start != 0 {
            return Err(TransferError::ResumeDiscontinuity {
                expected: 0,
                actual: window_start,
            });
        }

        let mut candidate = if continuing {
            self.pending
        } else {
            RangeSet::new()
        };
        for relative in resume.ranges() {
            let absolute_start = window_start
                .checked_add(relative.start)
                .ok_or(TransferError::AccountingOverflow)?;
            let absolute = ChunkRange {
                start: absolute_start,
                count: relative.count,
            };
            validate_object_range(absolute, self.chunk_count)?;
            candidate.insert(absolute)?;
        }

        if resume.header.final_window {
            self.installed = candidate;
            self.installed_sequence = Some(sequence);
            self.pending = RangeSet::new();
            self.pending_sequence = None;
            self.pending_next_window = 0;
            Ok(ResumeStatus::Installed {
                sequence,
                present_chunks: self.installed.chunk_count(),
            })
        } else {
            self.pending = candidate;
            self.pending_sequence = Some(sequence);
            self.pending_next_window =
                u32::try_from(window_end).map_err(|_| TransferError::AccountingOverflow)?;
            Ok(ResumeStatus::Pending {
                sequence,
                next_window_start: self.pending_next_window,
            })
        }
    }

    /// Returns the newest completely installed snapshot sequence.
    #[must_use]
    pub const fn installed_sequence(&self) -> Option<u64> {
        self.installed_sequence
    }

    /// Returns verified ranges from the newest complete snapshot.
    #[must_use]
    pub fn verified_ranges(&self) -> &[ChunkRange] {
        self.installed.as_slice()
    }

    /// Returns the sequence of an incomplete snapshot, if any.
    #[must_use]
    pub const fn pending_sequence(&self) -> Option<u64> {
        self.pending_sequence
    }

    /// Returns the required start of the next pending snapshot window.
    #[must_use]
    pub const fn pending_next_window(&self) -> Option<u32> {
        if self.pending_sequence.is_some() {
            Some(self.pending_next_window)
        } else {
            None
        }
    }

    /// Aborts an incomplete snapshot without changing installed state.
    pub fn abort_pending(&mut self) -> bool {
        let had_pending = self.pending_sequence.is_some();
        self.pending = RangeSet::new();
        self.pending_sequence = None;
        self.pending_next_window = 0;
        had_pending
    }

    fn is_stale(&self, resume: &Resume<'_>) -> bool {
        self.installed_sequence
            .is_some_and(|sequence| resume.header.sequence <= sequence)
            || self
                .pending_sequence
                .is_some_and(|sequence| resume.header.sequence < sequence)
    }
}

/// Bounded transfer-state failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferError {
    Manifest(ManifestError),
    ManifestPoolExhausted,
    ManifestLengthChanged(u32),
    ConflictingManifestOverlap { object_slot: u32, offset: usize },
    UnknownManifestSlot(u32),
    ManifestIncomplete(u32),
    ObjectSlotMismatch { expected: u32, actual: u32 },
    ChunkRangeOutsideObject,
    RangeCapacityExceeded { maximum: usize },
    PrematureObjectCompletion,
    CompletionRegression,
    ResumeWindowOutsideObject,
    InvalidResumeFinalFlag,
    ResumeDiscontinuity { expected: u32, actual: u32 },
    AccountingOverflow,
}

impl From<ManifestError> for TransferError {
    fn from(error: ManifestError) -> Self {
        Self::Manifest(error)
    }
}

impl fmt::Display for TransferError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(error) => error.fmt(formatter),
            Self::ManifestPoolExhausted => {
                formatter.write_str("manifest reassembly pool exhausted")
            }
            Self::ManifestLengthChanged(slot) => {
                write!(formatter, "manifest length changed for object slot {slot}")
            }
            Self::ConflictingManifestOverlap {
                object_slot,
                offset,
            } => write!(
                formatter,
                "conflicting manifest overlap for object slot {object_slot} at byte {offset}"
            ),
            Self::UnknownManifestSlot(slot) => {
                write!(formatter, "unknown manifest object slot {slot}")
            }
            Self::ManifestIncomplete(slot) => {
                write!(formatter, "manifest object slot {slot} is incomplete")
            }
            Self::ObjectSlotMismatch { expected, actual } => write!(
                formatter,
                "object slot mismatch: expected {expected}, got {actual}"
            ),
            Self::ChunkRangeOutsideObject => {
                formatter.write_str("chunk range exceeds manifest object bounds")
            }
            Self::RangeCapacityExceeded { maximum } => {
                write!(formatter, "chunk range capacity {maximum} exceeded")
            }
            Self::PrematureObjectCompletion => {
                formatter.write_str("OBJECT_COMPLETE does not cover every chunk")
            }
            Self::CompletionRegression => {
                formatter.write_str("newer COMMIT regresses completed object state")
            }
            Self::ResumeWindowOutsideObject => {
                formatter.write_str("RESUME window exceeds manifest chunk count")
            }
            Self::InvalidResumeFinalFlag => {
                formatter.write_str("RESUME FINAL_WINDOW does not match object boundary")
            }
            Self::ResumeDiscontinuity { expected, actual } => write!(
                formatter,
                "RESUME window discontinuity: expected {expected}, got {actual}"
            ),
            Self::AccountingOverflow => formatter.write_str("transfer accounting overflow"),
        }
    }
}

impl std::error::Error for TransferError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{
        ED25519_SIGNATURE_LEN, IDENTITY_FINGERPRINT_LEN, ML_DSA_65_SIGNATURE_LEN,
    };
    use crate::manifest::{
        MAX_SIGNED_MANIFEST_LEN, MERKLE_ROOT_LEN, MIN_CHUNK_SIZE, ManifestHeader,
    };
    use crate::wire::control::{CommitHeader, ResumeHeader};

    const OBJECT_SLOT: u32 = 7;

    fn encode_manifest(output: &mut [u8; MAX_SIGNED_MANIFEST_LEN]) -> usize {
        let header = ManifestHeader {
            object_id: [0x11; 32],
            object_size: u64::from(MIN_CHUNK_SIZE) * 3,
            chunk_size: MIN_CHUNK_SIZE,
            chunk_count: 3,
            merkle_root: [0x22; MERKLE_ROOT_LEN],
            signer_identity_fingerprint: [0x33; IDENTITY_FINGERPRINT_LEN],
        };
        header
            .encode_signed(
                "object.bin",
                &[0x44; ED25519_SIGNATURE_LEN],
                &[0x55; ML_DSA_65_SIGNATURE_LEN],
                output,
            )
            .expect("test manifest encodes")
    }

    fn fragment(slot: u32, complete: &[u8], offset: usize) -> ManifestFragment<'_> {
        ManifestFragment {
            object_slot: slot,
            manifest_length: u16::try_from(complete.len()).expect("manifest length fits"),
            fragment_offset: u16::try_from(offset).expect("fragment offset fits"),
            fragment: &complete[offset..],
        }
    }

    fn decode_commit<'a>(
        header: CommitHeader,
        ranges: &[ChunkRange],
        output: &'a mut [u8; 512],
    ) -> Commit<'a> {
        let written = header.encode(ranges, output).expect("test COMMIT encodes");
        Commit::decode(&output[..written]).expect("test COMMIT decodes")
    }

    fn decode_resume<'a>(
        header: ResumeHeader,
        ranges: &[ChunkRange],
        output: &'a mut [u8; 512],
    ) -> Resume<'a> {
        let written = header.encode(ranges, output).expect("test RESUME encodes");
        Resume::decode(&output[..written]).expect("test RESUME decodes")
    }

    #[test]
    fn manifest_reassembly_is_out_of_order_and_idempotent() {
        let mut encoded = [0_u8; MAX_SIGNED_MANIFEST_LEN];
        let length = encode_manifest(&mut encoded);
        let complete = &encoded[..length];
        let split = 1_700;
        let mut reassembler = ManifestReassembler::<2>::new();

        assert_eq!(
            reassembler
                .ingest(fragment(OBJECT_SLOT, complete, split))
                .expect("tail fragment is accepted"),
            ManifestAssemblyStatus::Incomplete {
                object_slot: OBJECT_SLOT,
                received_bytes: length - split,
                manifest_length: length,
            }
        );
        assert_eq!(
            reassembler
                .ingest(fragment(OBJECT_SLOT, complete, split))
                .expect("identical replay is accepted"),
            ManifestAssemblyStatus::Incomplete {
                object_slot: OBJECT_SLOT,
                received_bytes: length - split,
                manifest_length: length,
            }
        );
        let prefix = ManifestFragment {
            fragment: &complete[..split],
            ..fragment(OBJECT_SLOT, complete, 0)
        };
        assert_eq!(
            reassembler
                .ingest(prefix)
                .expect("prefix completes manifest"),
            ManifestAssemblyStatus::Complete {
                object_slot: OBJECT_SLOT,
                manifest_length: length,
            }
        );
        let decoded = reassembler
            .completed_manifest(OBJECT_SLOT)
            .expect("completed manifest remains borrowed from the pool");
        assert_eq!(decoded.display_name, "object.bin");
        assert_eq!(decoded.header.chunk_count, 3);
        assert!(reassembler.release(OBJECT_SLOT));
        assert_eq!(reassembler.active_slots(), 0);
    }

    #[test]
    fn conflicting_manifest_overlap_and_length_change_erase_partial_state() {
        let mut encoded = [0_u8; MAX_SIGNED_MANIFEST_LEN];
        let length = encode_manifest(&mut encoded);
        let complete = &encoded[..length];
        let mut reassembler = ManifestReassembler::<1>::new();
        let prefix = ManifestFragment {
            fragment: &complete[..1_000],
            ..fragment(OBJECT_SLOT, complete, 0)
        };
        reassembler.ingest(prefix).expect("prefix is accepted");

        let mut conflicting = complete[900..1_100].to_vec();
        conflicting[17] ^= 1;
        assert_eq!(
            reassembler.ingest(ManifestFragment {
                object_slot: OBJECT_SLOT,
                manifest_length: u16::try_from(length).expect("length fits"),
                fragment_offset: 900,
                fragment: &conflicting,
            }),
            Err(TransferError::ConflictingManifestOverlap {
                object_slot: OBJECT_SLOT,
                offset: 917,
            })
        );
        assert_eq!(reassembler.active_slots(), 0);

        reassembler.ingest(prefix).expect("slot can be reused");
        assert_eq!(
            reassembler.ingest(ManifestFragment {
                object_slot: OBJECT_SLOT,
                manifest_length: u16::try_from(length + 1).expect("length fits"),
                fragment_offset: 0,
                fragment: &complete[..1],
            }),
            Err(TransferError::ManifestLengthChanged(OBJECT_SLOT))
        );
        assert_eq!(reassembler.active_slots(), 0);
    }

    #[test]
    fn manifest_pool_exhaustion_and_invalid_completion_fail_closed() {
        let mut encoded = [0_u8; MAX_SIGNED_MANIFEST_LEN];
        let length = encode_manifest(&mut encoded);
        let complete = &encoded[..length];
        let first_byte = |slot| ManifestFragment {
            object_slot: slot,
            manifest_length: u16::try_from(length).expect("length fits"),
            fragment_offset: 0,
            fragment: &complete[..1],
        };
        let mut reassembler = ManifestReassembler::<2>::new();
        reassembler.ingest(first_byte(1)).expect("first slot fits");
        reassembler.ingest(first_byte(2)).expect("second slot fits");
        assert_eq!(
            reassembler.ingest(first_byte(3)),
            Err(TransferError::ManifestPoolExhausted)
        );
        assert_eq!(reassembler.active_slots(), 2);

        let invalid = [0_u8; MIN_SIGNED_MANIFEST_LEN];
        let mut invalid_reassembler = ManifestReassembler::<1>::new();
        assert!(matches!(
            invalid_reassembler.ingest(fragment(9, &invalid, 0)),
            Err(TransferError::Manifest(_))
        ));
        assert_eq!(invalid_reassembler.active_slots(), 0);
        assert_eq!(
            invalid_reassembler.completed_manifest(9),
            Err(TransferError::UnknownManifestSlot(9))
        );
    }

    #[test]
    fn commit_application_is_idempotent_and_emits_only_deltas() {
        let mut tracker = CommitTracker::<4>::new(OBJECT_SLOT, 10);
        let mut encoded = [0_u8; 512];
        let first_ranges = [
            ChunkRange { start: 0, count: 4 },
            ChunkRange { start: 8, count: 2 },
        ];
        let first = decode_commit(
            CommitHeader {
                sequence: 1,
                object_slot: OBJECT_SLOT,
                object_complete: false,
            },
            &first_ranges,
            &mut encoded,
        );
        let mut emitted = Vec::new();
        assert_eq!(
            tracker.apply(&first, |range| emitted.push(range)),
            Ok(CommitStatus::Applied {
                sequence: 1,
                newly_committed_chunks: 6,
                object_complete: false,
            })
        );
        assert_eq!(emitted, first_ranges);
        emitted.clear();
        assert_eq!(
            tracker.apply(&first, |range| emitted.push(range)),
            Ok(CommitStatus::IgnoredStale)
        );
        assert!(emitted.is_empty());

        let mut second_encoded = [0_u8; 512];
        let second = decode_commit(
            CommitHeader {
                sequence: 2,
                object_slot: OBJECT_SLOT,
                object_complete: false,
            },
            &[ChunkRange { start: 2, count: 7 }],
            &mut second_encoded,
        );
        assert_eq!(
            tracker.apply(&second, |range| emitted.push(range)),
            Ok(CommitStatus::Applied {
                sequence: 2,
                newly_committed_chunks: 4,
                object_complete: false,
            })
        );
        assert_eq!(emitted, [ChunkRange { start: 4, count: 4 }]);
        assert_eq!(
            tracker.committed_ranges(),
            &[ChunkRange {
                start: 0,
                count: 10,
            }]
        );

        let mut final_encoded = [0_u8; 512];
        let final_commit = decode_commit(
            CommitHeader {
                sequence: 3,
                object_slot: OBJECT_SLOT,
                object_complete: true,
            },
            &[],
            &mut final_encoded,
        );
        assert_eq!(
            tracker.apply(&final_commit, |_| {}),
            Ok(CommitStatus::Applied {
                sequence: 3,
                newly_committed_chunks: 0,
                object_complete: true,
            })
        );
        assert!(tracker.object_complete());
        assert_eq!(tracker.newest_sequence(), Some(3));
    }

    #[test]
    fn rejected_commit_does_not_mutate_sequence_or_ranges() {
        let mut tracker = CommitTracker::<2>::new(OBJECT_SLOT, 10);
        let mut encoded = [0_u8; 512];
        let premature = decode_commit(
            CommitHeader {
                sequence: 10,
                object_slot: OBJECT_SLOT,
                object_complete: true,
            },
            &[],
            &mut encoded,
        );
        assert_eq!(
            tracker.apply(&premature, |_| {}),
            Err(TransferError::PrematureObjectCompletion)
        );
        assert_eq!(tracker.newest_sequence(), None);

        let mut valid_encoded = [0_u8; 512];
        let valid = decode_commit(
            CommitHeader {
                sequence: 9,
                object_slot: OBJECT_SLOT,
                object_complete: false,
            },
            &[
                ChunkRange { start: 0, count: 1 },
                ChunkRange { start: 2, count: 1 },
            ],
            &mut valid_encoded,
        );
        tracker.apply(&valid, |_| {}).expect("valid state applies");
        let before = tracker.committed_ranges().to_vec();

        let mut overflow_encoded = [0_u8; 512];
        let capacity_overflow = decode_commit(
            CommitHeader {
                sequence: 11,
                object_slot: OBJECT_SLOT,
                object_complete: false,
            },
            &[ChunkRange { start: 4, count: 1 }],
            &mut overflow_encoded,
        );
        assert_eq!(
            tracker.apply(&capacity_overflow, |_| {}),
            Err(TransferError::RangeCapacityExceeded { maximum: 2 })
        );
        assert_eq!(tracker.newest_sequence(), Some(9));
        assert_eq!(tracker.committed_ranges(), before);

        let mut outside_encoded = [0_u8; 512];
        let outside = decode_commit(
            CommitHeader {
                sequence: 12,
                object_slot: OBJECT_SLOT,
                object_complete: false,
            },
            &[ChunkRange { start: 9, count: 2 }],
            &mut outside_encoded,
        );
        assert_eq!(
            tracker.apply(&outside, |_| {}),
            Err(TransferError::ChunkRangeOutsideObject)
        );
        assert_eq!(tracker.newest_sequence(), Some(9));
        assert_eq!(tracker.committed_ranges(), before);
    }

    #[test]
    fn commit_delta_streaming_has_no_hidden_segment_limit() {
        let mut tracker = CommitTracker::<65>::new(OBJECT_SLOT, 129);
        let first_ranges = (0..32)
            .map(|index| ChunkRange {
                start: index * 2 + 1,
                count: 1,
            })
            .collect::<Vec<_>>();
        let second_ranges = (0..32)
            .map(|index| ChunkRange {
                start: index * 2 + 65,
                count: 1,
            })
            .collect::<Vec<_>>();
        for (sequence, ranges) in [(1, &first_ranges), (2, &second_ranges)] {
            let mut encoded = [0_u8; 512];
            let commit = decode_commit(
                CommitHeader {
                    sequence,
                    object_slot: OBJECT_SLOT,
                    object_complete: false,
                },
                ranges,
                &mut encoded,
            );
            tracker.apply(&commit, |_| {}).expect("sparse ranges fit");
        }

        let mut encoded = [0_u8; 512];
        let covering = decode_commit(
            CommitHeader {
                sequence: 3,
                object_slot: OBJECT_SLOT,
                object_complete: true,
            },
            &[ChunkRange {
                start: 0,
                count: 129,
            }],
            &mut encoded,
        );
        let mut emitted = Vec::new();
        assert_eq!(
            tracker.apply(&covering, |range| emitted.push(range)),
            Ok(CommitStatus::Applied {
                sequence: 3,
                newly_committed_chunks: 65,
                object_complete: true,
            })
        );
        assert_eq!(emitted.len(), 65);
        assert!(emitted.iter().all(|range| range.count == 1));
    }

    #[test]
    fn completed_commit_state_cannot_regress() {
        let mut tracker = CommitTracker::<1>::new(OBJECT_SLOT, 4);
        let mut encoded = [0_u8; 512];
        let complete = decode_commit(
            CommitHeader {
                sequence: 1,
                object_slot: OBJECT_SLOT,
                object_complete: true,
            },
            &[ChunkRange { start: 0, count: 4 }],
            &mut encoded,
        );
        tracker
            .apply(&complete, |_| {})
            .expect("completion applies");

        let mut regression_encoded = [0_u8; 512];
        let regression = decode_commit(
            CommitHeader {
                sequence: 2,
                object_slot: OBJECT_SLOT,
                object_complete: false,
            },
            &[ChunkRange { start: 0, count: 1 }],
            &mut regression_encoded,
        );
        assert_eq!(
            tracker.apply(&regression, |_| {}),
            Err(TransferError::CompletionRegression)
        );
        assert_eq!(tracker.newest_sequence(), Some(1));
        assert!(tracker.object_complete());
    }

    #[test]
    fn resume_windows_install_only_a_complete_contiguous_snapshot() {
        let mut tracker = ResumeTracker::<4>::new(OBJECT_SLOT, 10);
        let mut first_encoded = [0_u8; 512];
        let first = decode_resume(
            ResumeHeader {
                sequence: 1,
                object_slot: OBJECT_SLOT,
                window_start: 0,
                window_chunk_count: 4,
                final_window: false,
            },
            &[ChunkRange { start: 0, count: 2 }],
            &mut first_encoded,
        );
        assert_eq!(
            tracker.apply(&first),
            Ok(ResumeStatus::Pending {
                sequence: 1,
                next_window_start: 4,
            })
        );
        assert_eq!(tracker.installed_sequence(), None);
        assert_eq!(tracker.pending_sequence(), Some(1));
        assert_eq!(tracker.pending_next_window(), Some(4));
        assert_eq!(tracker.apply(&first), Ok(ResumeStatus::IgnoredStale));

        let mut gap_encoded = [0_u8; 512];
        let gap = decode_resume(
            ResumeHeader {
                sequence: 1,
                object_slot: OBJECT_SLOT,
                window_start: 5,
                window_chunk_count: 5,
                final_window: true,
            },
            &[],
            &mut gap_encoded,
        );
        assert_eq!(
            tracker.apply(&gap),
            Err(TransferError::ResumeDiscontinuity {
                expected: 4,
                actual: 5,
            })
        );
        assert_eq!(tracker.pending_next_window(), Some(4));

        let mut final_encoded = [0_u8; 512];
        let final_window = decode_resume(
            ResumeHeader {
                sequence: 1,
                object_slot: OBJECT_SLOT,
                window_start: 4,
                window_chunk_count: 6,
                final_window: true,
            },
            &[ChunkRange { start: 1, count: 2 }],
            &mut final_encoded,
        );
        assert_eq!(
            tracker.apply(&final_window),
            Ok(ResumeStatus::Installed {
                sequence: 1,
                present_chunks: 4,
            })
        );
        assert_eq!(tracker.installed_sequence(), Some(1));
        assert_eq!(tracker.pending_sequence(), None);
        assert_eq!(
            tracker.verified_ranges(),
            &[
                ChunkRange { start: 0, count: 2 },
                ChunkRange { start: 5, count: 2 },
            ]
        );
        assert_eq!(tracker.apply(&first), Ok(ResumeStatus::IgnoredStale));
    }

    #[test]
    fn incomplete_new_resume_never_replaces_installed_state() {
        let mut tracker = ResumeTracker::<2>::new(OBJECT_SLOT, 4);
        let mut installed_encoded = [0_u8; 512];
        let installed = decode_resume(
            ResumeHeader {
                sequence: 1,
                object_slot: OBJECT_SLOT,
                window_start: 0,
                window_chunk_count: 4,
                final_window: true,
            },
            &[ChunkRange { start: 0, count: 2 }],
            &mut installed_encoded,
        );
        tracker.apply(&installed).expect("snapshot installs");
        let before = tracker.verified_ranges().to_vec();

        let mut pending_encoded = [0_u8; 512];
        let pending = decode_resume(
            ResumeHeader {
                sequence: 2,
                object_slot: OBJECT_SLOT,
                window_start: 0,
                window_chunk_count: 2,
                final_window: false,
            },
            &[ChunkRange { start: 1, count: 1 }],
            &mut pending_encoded,
        );
        tracker.apply(&pending).expect("new snapshot is pending");
        assert_eq!(tracker.installed_sequence(), Some(1));
        assert_eq!(tracker.verified_ranges(), before);
        assert!(tracker.abort_pending());
        assert!(!tracker.abort_pending());
        assert_eq!(tracker.installed_sequence(), Some(1));
        assert_eq!(tracker.verified_ranges(), before);
    }

    #[test]
    fn rejected_resume_window_preserves_pending_candidate() {
        let mut tracker = ResumeTracker::<1>::new(OBJECT_SLOT, 4);
        let mut first_encoded = [0_u8; 512];
        let first = decode_resume(
            ResumeHeader {
                sequence: 1,
                object_slot: OBJECT_SLOT,
                window_start: 0,
                window_chunk_count: 2,
                final_window: false,
            },
            &[ChunkRange { start: 0, count: 1 }],
            &mut first_encoded,
        );
        tracker.apply(&first).expect("first window is pending");

        let mut overflow_encoded = [0_u8; 512];
        let capacity_overflow = decode_resume(
            ResumeHeader {
                sequence: 1,
                object_slot: OBJECT_SLOT,
                window_start: 2,
                window_chunk_count: 2,
                final_window: true,
            },
            &[ChunkRange { start: 1, count: 1 }],
            &mut overflow_encoded,
        );
        assert_eq!(
            tracker.apply(&capacity_overflow),
            Err(TransferError::RangeCapacityExceeded { maximum: 1 })
        );
        assert_eq!(tracker.pending_sequence(), Some(1));
        assert_eq!(tracker.pending_next_window(), Some(2));
        assert_eq!(tracker.installed_sequence(), None);

        let mut replacement_encoded = [0_u8; 512];
        let replacement = decode_resume(
            ResumeHeader {
                sequence: 2,
                object_slot: OBJECT_SLOT,
                window_start: 0,
                window_chunk_count: 4,
                final_window: true,
            },
            &[ChunkRange { start: 0, count: 4 }],
            &mut replacement_encoded,
        );
        tracker
            .apply(&replacement)
            .expect("new complete snapshot replaces pending state");
        assert_eq!(tracker.installed_sequence(), Some(2));
        assert_eq!(
            tracker.verified_ranges(),
            &[ChunkRange { start: 0, count: 4 }]
        );
    }

    #[test]
    fn resume_bounds_and_final_flag_are_enforced_before_mutation() {
        let mut tracker = ResumeTracker::<2>::new(OBJECT_SLOT, 10);
        let mut flag_encoded = [0_u8; 512];
        let invalid_flag = decode_resume(
            ResumeHeader {
                sequence: 1,
                object_slot: OBJECT_SLOT,
                window_start: 0,
                window_chunk_count: 5,
                final_window: true,
            },
            &[],
            &mut flag_encoded,
        );
        assert_eq!(
            tracker.apply(&invalid_flag),
            Err(TransferError::InvalidResumeFinalFlag)
        );
        assert_eq!(tracker.pending_sequence(), None);

        let mut outside_encoded = [0_u8; 512];
        let outside = decode_resume(
            ResumeHeader {
                sequence: 2,
                object_slot: OBJECT_SLOT,
                window_start: 8,
                window_chunk_count: 3,
                final_window: true,
            },
            &[],
            &mut outside_encoded,
        );
        assert_eq!(
            tracker.apply(&outside),
            Err(TransferError::ResumeWindowOutsideObject)
        );
        assert_eq!(tracker.pending_sequence(), None);
        assert_eq!(tracker.installed_sequence(), None);
    }
}
