//! Sender-side flow-credit accounting for bounded-memory transfers.
//!
//! A reservation represents unique object bytes accepted for transmission.
//! Retransmitting the same fragment must not reserve credit a second time.

use core::fmt;

use crate::wire::{WireError, read_u32, read_u64};

/// Exact size of a CREDIT control-frame value.
pub const CREDIT_VALUE_LEN: usize = 20;

/// Absolute receive limits advertised by a peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Credit {
    /// Monotonically increasing update sequence.
    pub sequence: u64,
    /// Maximum unique bytes sent but not yet committed by the receiver.
    pub max_uncommitted_bytes: u64,
    /// Maximum unique fragments sent but not yet committed by the receiver.
    pub max_inflight_fragments: u32,
}

impl Credit {
    /// Encodes the exact CREDIT control-frame value.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::BufferTooSmall`] if `output` is shorter than
    /// [`CREDIT_VALUE_LEN`].
    pub fn encode(self, output: &mut [u8]) -> Result<usize, WireError> {
        if output.len() < CREDIT_VALUE_LEN {
            return Err(WireError::BufferTooSmall {
                needed: CREDIT_VALUE_LEN,
                available: output.len(),
            });
        }
        output[0..8].copy_from_slice(&self.sequence.to_be_bytes());
        output[8..16].copy_from_slice(&self.max_uncommitted_bytes.to_be_bytes());
        output[16..20].copy_from_slice(&self.max_inflight_fragments.to_be_bytes());
        Ok(CREDIT_VALUE_LEN)
    }

    /// Decodes an exact CREDIT control-frame value.
    ///
    /// # Errors
    ///
    /// Returns an error unless `input` is exactly [`CREDIT_VALUE_LEN`] bytes.
    pub fn decode(input: &[u8]) -> Result<Self, WireError> {
        if input.len() < CREDIT_VALUE_LEN {
            return Err(WireError::PacketTooShort {
                minimum: CREDIT_VALUE_LEN,
                actual: input.len(),
            });
        }
        if input.len() != CREDIT_VALUE_LEN {
            return Err(WireError::LengthMismatch {
                expected: CREDIT_VALUE_LEN,
                actual: input.len(),
            });
        }
        Ok(Self {
            sequence: read_u64(input, 0)?,
            max_uncommitted_bytes: read_u64(input, 8)?,
            max_inflight_fragments: read_u32(input, 16)?,
        })
    }
}

/// Sender-side accounting for the newest peer credit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreditWindow {
    credit: Credit,
    outstanding_bytes: u64,
    outstanding_fragments: u32,
}

impl CreditWindow {
    /// Starts accounting from an authenticated initial CREDIT.
    #[must_use]
    pub const fn new(credit: Credit) -> Self {
        Self {
            credit,
            outstanding_bytes: 0,
            outstanding_fragments: 0,
        }
    }

    /// Applies a strictly newer absolute credit update.
    ///
    /// Returns `true` when the update was applied. Stale and duplicate updates
    /// are ignored. A lower new limit stops future reservations but never
    /// invalidates bytes already in flight.
    pub fn apply_update(&mut self, credit: Credit) -> bool {
        if credit.sequence <= self.credit.sequence {
            return false;
        }
        self.credit = credit;
        true
    }

    /// Reserves credit for one new unique DATA fragment.
    ///
    /// Retransmissions of already reserved bytes MUST bypass this method.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty fragment, arithmetic overflow, or when
    /// either advertised limit would be exceeded.
    pub fn try_reserve(&mut self, fragment_bytes: u64) -> Result<(), FlowError> {
        if fragment_bytes == 0 {
            return Err(FlowError::EmptyFragment);
        }
        let next_bytes = self
            .outstanding_bytes
            .checked_add(fragment_bytes)
            .ok_or(FlowError::AccountingOverflow)?;
        let next_fragments = self
            .outstanding_fragments
            .checked_add(1)
            .ok_or(FlowError::AccountingOverflow)?;
        if next_bytes > self.credit.max_uncommitted_bytes
            || next_fragments > self.credit.max_inflight_fragments
        {
            return Err(FlowError::CreditExceeded);
        }
        self.outstanding_bytes = next_bytes;
        self.outstanding_fragments = next_fragments;
        Ok(())
    }

    /// Releases committed unique bytes and fragments.
    ///
    /// # Errors
    ///
    /// Returns an error if the release exceeds current outstanding accounting.
    pub fn release(
        &mut self,
        committed_bytes: u64,
        committed_fragments: u32,
    ) -> Result<(), FlowError> {
        let remaining_bytes = self
            .outstanding_bytes
            .checked_sub(committed_bytes)
            .ok_or(FlowError::ReleaseExceedsOutstanding)?;
        let remaining_fragments = self
            .outstanding_fragments
            .checked_sub(committed_fragments)
            .ok_or(FlowError::ReleaseExceedsOutstanding)?;
        self.outstanding_bytes = remaining_bytes;
        self.outstanding_fragments = remaining_fragments;
        Ok(())
    }

    /// Returns the newest authenticated peer credit.
    #[must_use]
    pub const fn credit(self) -> Credit {
        self.credit
    }

    /// Returns unique bytes sent but not committed.
    #[must_use]
    pub const fn outstanding_bytes(self) -> u64 {
        self.outstanding_bytes
    }

    /// Returns unique fragments sent but not committed.
    #[must_use]
    pub const fn outstanding_fragments(self) -> u32 {
        self.outstanding_fragments
    }
}

/// Errors from sender credit accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowError {
    EmptyFragment,
    AccountingOverflow,
    CreditExceeded,
    ReleaseExceedsOutstanding,
}

impl fmt::Display for FlowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyFragment => formatter.write_str("cannot reserve an empty fragment"),
            Self::AccountingOverflow => formatter.write_str("flow accounting overflow"),
            Self::CreditExceeded => formatter.write_str("peer credit exceeded"),
            Self::ReleaseExceedsOutstanding => {
                formatter.write_str("release exceeds outstanding flow accounting")
            }
        }
    }
}

impl std::error::Error for FlowError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn initial_credit() -> Credit {
        Credit {
            sequence: 1,
            max_uncommitted_bytes: 2_000,
            max_inflight_fragments: 2,
        }
    }

    #[test]
    fn credit_value_round_trip() {
        let credit = initial_credit();
        let mut output = [0_u8; CREDIT_VALUE_LEN];
        assert_eq!(credit.encode(&mut output), Ok(CREDIT_VALUE_LEN));
        assert_eq!(Credit::decode(&output), Ok(credit));
    }

    #[test]
    fn reservations_obey_both_limits() {
        let mut window = CreditWindow::new(initial_credit());
        assert_eq!(window.try_reserve(1_000), Ok(()));
        assert_eq!(window.try_reserve(1_000), Ok(()));
        assert_eq!(window.try_reserve(1), Err(FlowError::CreditExceeded));
        assert_eq!(window.outstanding_bytes(), 2_000);
        assert_eq!(window.outstanding_fragments(), 2);

        assert_eq!(window.release(1_000, 1), Ok(()));
        assert_eq!(window.try_reserve(500), Ok(()));
    }

    #[test]
    fn stale_updates_are_ignored_and_lower_limits_stop_new_work() {
        let mut window = CreditWindow::new(initial_credit());
        window.try_reserve(1_000).expect("initial credit allows it");
        assert!(!window.apply_update(Credit {
            sequence: 1,
            max_uncommitted_bytes: 10_000,
            max_inflight_fragments: 10,
        }));
        assert!(window.apply_update(Credit {
            sequence: 2,
            max_uncommitted_bytes: 500,
            max_inflight_fragments: 1,
        }));
        assert_eq!(window.try_reserve(1), Err(FlowError::CreditExceeded));
        assert_eq!(window.release(1_000, 1), Ok(()));
        assert_eq!(window.try_reserve(500), Ok(()));
    }

    #[test]
    fn invalid_release_does_not_mutate_accounting() {
        let mut window = CreditWindow::new(initial_credit());
        window.try_reserve(100).expect("credit allows it");
        assert_eq!(
            window.release(101, 1),
            Err(FlowError::ReleaseExceedsOutstanding)
        );
        assert_eq!(window.outstanding_bytes(), 100);
        assert_eq!(window.outstanding_fragments(), 1);
    }
}
