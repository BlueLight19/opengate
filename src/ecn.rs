//! Allocation-free Explicit Congestion Notification state for one path.
//!
//! OGTP uses ECT(0) for its base profile, authenticates cumulative receiver
//! counters inside ACK plaintext, and disables marking on validation failure.

use core::fmt;

/// Maximum ECT(0)-marked packets used to validate a new path.
pub const ECN_VALIDATION_PROBES: u8 = 10;

/// The two-bit ECN field carried by an IPv4 or IPv6 header.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum EcnCodepoint {
    #[default]
    NotEct = 0b00,
    Ect1 = 0b01,
    Ect0 = 0b10,
    Ce = 0b11,
}

/// Cumulative counts reported in an authenticated ACK.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EcnCounts {
    pub ect0: u64,
    pub ect1: u64,
    pub ce: u64,
}

impl EcnCounts {
    fn checked_delta(self, previous: Self) -> Option<Self> {
        Some(Self {
            ect0: self.ect0.checked_sub(previous.ect0)?,
            ect1: self.ect1.checked_sub(previous.ect1)?,
            ce: self.ce.checked_sub(previous.ce)?,
        })
    }

    fn checked_total(self) -> Option<u64> {
        self.ect0.checked_add(self.ect1)?.checked_add(self.ce)
    }
}

/// Receiver-side cumulative counter state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EcnReceiver {
    counts: EcnCounts,
}

impl EcnReceiver {
    /// Accounts for one newly authenticated, non-duplicate UDP datagram.
    ///
    /// # Errors
    ///
    /// Returns [`EcnError::CounterOverflow`] rather than wrapping a wire
    /// counter. Not-ECT datagrams do not affect the counters.
    pub fn on_datagram(&mut self, codepoint: EcnCodepoint) -> Result<(), EcnError> {
        let counter = match codepoint {
            EcnCodepoint::NotEct => return Ok(()),
            EcnCodepoint::Ect0 => &mut self.counts.ect0,
            EcnCodepoint::Ect1 => &mut self.counts.ect1,
            EcnCodepoint::Ce => &mut self.counts.ce,
        };
        *counter = counter.checked_add(1).ok_or(EcnError::CounterOverflow)?;
        Ok(())
    }

    /// Returns the counters to include in the next authenticated ACK.
    #[must_use]
    pub const fn counts(self) -> EcnCounts {
        self.counts
    }
}

/// Current sender-side ECN capability for one path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcnState {
    Disabled,
    Testing,
    Unknown,
    Capable,
    Failed,
}

/// Reason a path permanently stopped using ECN.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcnFailure {
    MissingCounts,
    CountersDecreased,
    CountsExceedSentPackets,
    MarkingWasRewritten,
    AllValidationProbesLost,
}

/// Result of processing authenticated ECN feedback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcnValidationResult {
    Ignored,
    Validated { ce_increase: u64 },
    Failed(EcnFailure),
}

/// Sender-side path validator and marking policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EcnValidator {
    state: EcnState,
    failure: Option<EcnFailure>,
    sent_ect0: u64,
    sent_ect1: u64,
    validation_probes_sent: u8,
    validation_probes_lost: u64,
    largest_acknowledged_processed: Option<u64>,
    peer_counts: EcnCounts,
}

impl EcnValidator {
    /// Creates per-path ECN state after capability negotiation.
    #[must_use]
    pub const fn new(negotiated: bool) -> Self {
        Self {
            state: if negotiated {
                EcnState::Testing
            } else {
                EcnState::Disabled
            },
            failure: None,
            sent_ect0: 0,
            sent_ect1: 0,
            validation_probes_sent: 0,
            validation_probes_lost: 0,
            largest_acknowledged_processed: None,
            peer_counts: EcnCounts {
                ect0: 0,
                ect1: 0,
                ce: 0,
            },
        }
    }

    /// Returns the IP codepoint to apply to the next outgoing datagram.
    #[must_use]
    pub const fn outgoing_codepoint(self) -> EcnCodepoint {
        match self.state {
            EcnState::Testing | EcnState::Capable => EcnCodepoint::Ect0,
            EcnState::Disabled | EcnState::Unknown | EcnState::Failed => EcnCodepoint::NotEct,
        }
    }

    /// Records the codepoint actually applied after a successful kernel send.
    ///
    /// # Errors
    ///
    /// Returns an error when the codepoint violates the current base-profile
    /// policy or a counter would overflow.
    pub fn on_packet_sent(&mut self, codepoint: EcnCodepoint) -> Result<(), EcnError> {
        match codepoint {
            EcnCodepoint::NotEct => return Ok(()),
            EcnCodepoint::Ect1 | EcnCodepoint::Ce => {
                return Err(EcnError::UnsupportedOutgoingCodepoint);
            }
            EcnCodepoint::Ect0 => {}
        }
        if !matches!(self.state, EcnState::Testing | EcnState::Capable) {
            return Err(EcnError::MarkingNotPermitted);
        }
        self.sent_ect0 = self
            .sent_ect0
            .checked_add(1)
            .ok_or(EcnError::CounterOverflow)?;
        if self.state == EcnState::Testing {
            self.validation_probes_sent = self
                .validation_probes_sent
                .checked_add(1)
                .ok_or(EcnError::CounterOverflow)?;
            if self.validation_probes_sent >= ECN_VALIDATION_PROBES {
                self.state = EcnState::Unknown;
            }
        }
        Ok(())
    }

    /// Records validation probes that recovery declared lost.
    pub fn on_validation_probes_lost(&mut self, count: u64) -> EcnValidationResult {
        if matches!(self.state, EcnState::Disabled | EcnState::Capable) {
            return EcnValidationResult::Ignored;
        }
        if self.state == EcnState::Failed {
            return EcnValidationResult::Failed(
                self.failure.unwrap_or(EcnFailure::AllValidationProbesLost),
            );
        }
        self.validation_probes_lost = self.validation_probes_lost.saturating_add(count);
        if self.validation_probes_sent >= ECN_VALIDATION_PROBES
            && self.validation_probes_lost >= u64::from(self.validation_probes_sent)
        {
            return self.fail(EcnFailure::AllValidationProbesLost);
        }
        EcnValidationResult::Ignored
    }

    /// Validates cumulative counts from one authenticated, non-reordered ACK.
    ///
    /// `newly_acked_ect0` and `newly_acked_ect1` count newly acknowledged
    /// packets by their original sender marking. ACKs that do not advance the
    /// largest acknowledged packet number are ignored to tolerate reordering.
    pub fn validate_ack(
        &mut self,
        largest_acknowledged: u64,
        newly_acked_ect0: u64,
        newly_acked_ect1: u64,
        counts: Option<EcnCounts>,
    ) -> EcnValidationResult {
        if self.state == EcnState::Disabled {
            return EcnValidationResult::Ignored;
        }
        if self.state == EcnState::Failed {
            return EcnValidationResult::Failed(
                self.failure.unwrap_or(EcnFailure::CountsExceedSentPackets),
            );
        }
        if self
            .largest_acknowledged_processed
            .is_some_and(|largest| largest_acknowledged <= largest)
        {
            return EcnValidationResult::Ignored;
        }
        let Some(newly_acked_marked) = newly_acked_ect0.checked_add(newly_acked_ect1) else {
            return self.fail(EcnFailure::CountsExceedSentPackets);
        };
        let Some(counts) = counts else {
            if newly_acked_marked != 0 {
                return self.fail(EcnFailure::MissingCounts);
            }
            self.largest_acknowledged_processed = Some(largest_acknowledged);
            return EcnValidationResult::Ignored;
        };
        let Some(delta) = counts.checked_delta(self.peer_counts) else {
            return self.fail(EcnFailure::CountersDecreased);
        };
        let Some(sent_total) = self.sent_ect0.checked_add(self.sent_ect1) else {
            return self.fail(EcnFailure::CountsExceedSentPackets);
        };
        let Some(reported_total) = counts.checked_total() else {
            return self.fail(EcnFailure::CountsExceedSentPackets);
        };
        if counts.ect0 > self.sent_ect0
            || counts.ect1 > self.sent_ect1
            || reported_total > sent_total
        {
            return self.fail(EcnFailure::CountsExceedSentPackets);
        }
        let ect0_coverage = delta.ect0.checked_add(delta.ce);
        let ect1_coverage = delta.ect1.checked_add(delta.ce);
        let delta_total = delta.checked_total();
        if ect0_coverage.is_none_or(|value| value < newly_acked_ect0)
            || ect1_coverage.is_none_or(|value| value < newly_acked_ect1)
            || delta_total.is_none_or(|value| value < newly_acked_marked)
        {
            return self.fail(EcnFailure::MarkingWasRewritten);
        }

        self.peer_counts = counts;
        self.largest_acknowledged_processed = Some(largest_acknowledged);
        if newly_acked_marked != 0 || reported_total != 0 {
            self.state = EcnState::Capable;
        }
        EcnValidationResult::Validated {
            ce_increase: delta.ce,
        }
    }

    /// Returns the current path capability state.
    #[must_use]
    pub const fn state(self) -> EcnState {
        self.state
    }

    /// Returns the last successfully validated peer counters.
    #[must_use]
    pub const fn peer_counts(self) -> EcnCounts {
        self.peer_counts
    }

    fn fail(&mut self, reason: EcnFailure) -> EcnValidationResult {
        self.state = EcnState::Failed;
        self.failure = Some(reason);
        EcnValidationResult::Failed(reason)
    }
}

/// Invalid local ECN accounting or marking operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcnError {
    CounterOverflow,
    UnsupportedOutgoingCodepoint,
    MarkingNotPermitted,
}

impl fmt::Display for EcnError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CounterOverflow => formatter.write_str("ECN counter overflow"),
            Self::UnsupportedOutgoingCodepoint => {
                formatter.write_str("outgoing ECN codepoint is not supported by this profile")
            }
            Self::MarkingNotPermitted => {
                formatter.write_str("ECN marking is not permitted in the current path state")
            }
        }
    }
}

impl std::error::Error for EcnError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn send_probe(validator: &mut EcnValidator) {
        let codepoint = validator.outgoing_codepoint();
        assert_eq!(codepoint, EcnCodepoint::Ect0);
        validator
            .on_packet_sent(codepoint)
            .expect("validation marking is permitted");
    }

    #[test]
    fn receiver_counts_only_new_ecn_datagrams() {
        let mut receiver = EcnReceiver::default();
        receiver
            .on_datagram(EcnCodepoint::NotEct)
            .expect("Not-ECT is ignored");
        receiver
            .on_datagram(EcnCodepoint::Ect0)
            .expect("ECT(0) increments");
        receiver
            .on_datagram(EcnCodepoint::Ect1)
            .expect("ECT(1) increments");
        receiver
            .on_datagram(EcnCodepoint::Ce)
            .expect("CE increments");
        assert_eq!(
            receiver.counts(),
            EcnCounts {
                ect0: 1,
                ect1: 1,
                ce: 1,
            }
        );
    }

    #[test]
    fn valid_probe_feedback_enables_ecn_and_reports_ce_delta() {
        let mut validator = EcnValidator::new(true);
        send_probe(&mut validator);
        send_probe(&mut validator);
        assert_eq!(
            validator.validate_ack(
                1,
                2,
                0,
                Some(EcnCounts {
                    ect0: 1,
                    ect1: 0,
                    ce: 1,
                }),
            ),
            EcnValidationResult::Validated { ce_increase: 1 }
        );
        assert_eq!(validator.state(), EcnState::Capable);
        assert_eq!(validator.outgoing_codepoint(), EcnCodepoint::Ect0);
    }

    #[test]
    fn missing_or_rewritten_feedback_disables_path_marking() {
        let mut missing = EcnValidator::new(true);
        send_probe(&mut missing);
        assert_eq!(
            missing.validate_ack(0, 1, 0, None),
            EcnValidationResult::Failed(EcnFailure::MissingCounts)
        );
        assert_eq!(missing.outgoing_codepoint(), EcnCodepoint::NotEct);

        let mut rewritten = EcnValidator::new(true);
        send_probe(&mut rewritten);
        assert_eq!(
            rewritten.validate_ack(0, 1, 0, Some(EcnCounts::default())),
            EcnValidationResult::Failed(EcnFailure::MarkingWasRewritten)
        );
    }

    #[test]
    fn reordered_ack_does_not_fail_validation() {
        let mut validator = EcnValidator::new(true);
        send_probe(&mut validator);
        assert_eq!(
            validator.validate_ack(
                5,
                1,
                0,
                Some(EcnCounts {
                    ect0: 1,
                    ect1: 0,
                    ce: 0,
                }),
            ),
            EcnValidationResult::Validated { ce_increase: 0 }
        );
        assert_eq!(
            validator.validate_ack(4, 0, 0, Some(EcnCounts::default())),
            EcnValidationResult::Ignored
        );
        assert_eq!(validator.state(), EcnState::Capable);
    }

    #[test]
    fn all_ten_validation_probes_lost_disables_ecn() {
        let mut validator = EcnValidator::new(true);
        for _ in 0..ECN_VALIDATION_PROBES {
            send_probe(&mut validator);
        }
        assert_eq!(validator.state(), EcnState::Unknown);
        assert_eq!(validator.outgoing_codepoint(), EcnCodepoint::NotEct);
        assert_eq!(
            validator.on_validation_probes_lost(u64::from(ECN_VALIDATION_PROBES)),
            EcnValidationResult::Failed(EcnFailure::AllValidationProbesLost)
        );
    }

    #[test]
    fn impossible_cumulative_counts_are_rejected() {
        let mut validator = EcnValidator::new(true);
        send_probe(&mut validator);
        assert_eq!(
            validator.validate_ack(
                0,
                1,
                0,
                Some(EcnCounts {
                    ect0: 2,
                    ect1: 0,
                    ce: 0,
                }),
            ),
            EcnValidationResult::Failed(EcnFailure::CountsExceedSentPackets)
        );
    }
}
