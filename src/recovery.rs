//! Bounded sender-side loss recovery and multipath reinjection selection.
//!
//! A [`SentPacketTable`] allocates all fixed storage at construction. Recording,
//! acknowledging, and declaring packets lost never grows those allocations.

use core::fmt;

use crate::protection::MAX_PACKET_NUMBER;
use crate::wire::DataMetadata;
use crate::wire::ack::AckFrame;

/// Packet-number distance that declares an older packet lost.
pub const PACKET_LOSS_THRESHOLD: u64 = 3;
/// Numerator of the RTT-relative loss-time threshold.
pub const TIME_LOSS_THRESHOLD_NUMERATOR: u64 = 9;
/// Denominator of the RTT-relative loss-time threshold.
pub const TIME_LOSS_THRESHOLD_DENOMINATOR: u64 = 8;
/// Timer granularity used by loss and probe timeout calculations.
pub const TIMER_GRANULARITY_MICROS: u64 = 1_000;
/// Initial RTT used before the first valid sample.
pub const DEFAULT_INITIAL_RTT_MICROS: u64 = 333_000;
/// Maximum peer-reported ACK delay accepted by the base profile.
pub const DEFAULT_MAX_ACK_DELAY_MICROS: u64 = 25_000;
/// Number of probe datagrams requested by one PTO expiration.
pub const PTO_PROBE_DATAGRAMS: u8 = 2;
/// Largest exponential backoff retained in the PTO state.
pub const MAX_PTO_BACKOFF_EXPONENT: u32 = 63;
/// Base-PTO multiplier used to establish persistent congestion.
pub const PERSISTENT_CONGESTION_THRESHOLD: u64 = 3;

/// Recovery timing parameters fixed for one negotiated session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryConfig {
    initial_rtt_micros: u64,
    max_ack_delay_micros: u64,
}

impl RecoveryConfig {
    /// Creates timing parameters with a non-zero initial RTT.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::InvalidConfiguration`] when the initial RTT is
    /// zero.
    pub const fn new(
        initial_rtt_micros: u64,
        max_ack_delay_micros: u64,
    ) -> Result<Self, RecoveryError> {
        if initial_rtt_micros == 0 {
            return Err(RecoveryError::InvalidConfiguration);
        }
        Ok(Self {
            initial_rtt_micros,
            max_ack_delay_micros,
        })
    }

    /// Returns the initial RTT assumption.
    #[must_use]
    pub const fn initial_rtt_micros(self) -> u64 {
        self.initial_rtt_micros
    }

    /// Returns the largest ACK delay accepted during RTT adjustment.
    #[must_use]
    pub const fn max_ack_delay_micros(self) -> u64 {
        self.max_ack_delay_micros
    }
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            initial_rtt_micros: DEFAULT_INITIAL_RTT_MICROS,
            max_ack_delay_micros: DEFAULT_MAX_ACK_DELAY_MICROS,
        }
    }
}

/// Integer-only RTT estimator for one network path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RttEstimator {
    config: RecoveryConfig,
    latest_rtt_micros: Option<u64>,
    minimum_rtt_micros: Option<u64>,
    smoothed_rtt_micros: Option<u64>,
    rtt_variance_micros: Option<u64>,
}

impl RttEstimator {
    /// Creates an estimator with no measured sample.
    #[must_use]
    pub const fn new(config: RecoveryConfig) -> Self {
        Self {
            config,
            latest_rtt_micros: None,
            minimum_rtt_micros: None,
            smoothed_rtt_micros: None,
            rtt_variance_micros: None,
        }
    }

    /// Records one raw RTT sample and its untrusted peer-reported ACK delay.
    ///
    /// The ACK delay is capped by the session configuration and is subtracted
    /// only when doing so cannot reduce the sample below the observed minimum.
    pub fn record_sample(&mut self, raw_rtt_micros: u64, reported_ack_delay_micros: u64) {
        self.latest_rtt_micros = Some(raw_rtt_micros);
        let minimum = self
            .minimum_rtt_micros
            .map_or(raw_rtt_micros, |current| current.min(raw_rtt_micros));
        self.minimum_rtt_micros = Some(minimum);
        let ack_delay = reported_ack_delay_micros.min(self.config.max_ack_delay_micros);
        let adjusted = if raw_rtt_micros >= minimum.saturating_add(ack_delay) {
            raw_rtt_micros - ack_delay
        } else {
            raw_rtt_micros
        };

        if let (Some(smoothed), Some(variance)) =
            (self.smoothed_rtt_micros, self.rtt_variance_micros)
        {
            let deviation = smoothed.abs_diff(adjusted);
            self.rtt_variance_micros = Some(weighted_average(variance, deviation, 3, 4));
            self.smoothed_rtt_micros = Some(weighted_average(smoothed, adjusted, 7, 8));
        } else {
            self.smoothed_rtt_micros = Some(adjusted);
            self.rtt_variance_micros = Some(adjusted / 2);
        }
    }

    /// Returns the most recent raw RTT sample.
    #[must_use]
    pub const fn latest_rtt_micros(self) -> Option<u64> {
        self.latest_rtt_micros
    }

    /// Returns the smallest raw RTT sample.
    #[must_use]
    pub const fn minimum_rtt_micros(self) -> Option<u64> {
        self.minimum_rtt_micros
    }

    /// Returns the smoothed, ACK-delay-adjusted RTT.
    #[must_use]
    pub const fn smoothed_rtt_micros(self) -> Option<u64> {
        self.smoothed_rtt_micros
    }

    /// Returns smoothed RTT, falling back to the configured initial RTT.
    #[must_use]
    pub const fn effective_smoothed_rtt_micros(self) -> u64 {
        match self.smoothed_rtt_micros {
            Some(value) => value,
            None => self.config.initial_rtt_micros,
        }
    }

    /// Returns the smoothed absolute RTT deviation.
    #[must_use]
    pub const fn rtt_variance_micros(self) -> Option<u64> {
        self.rtt_variance_micros
    }

    /// Returns whether at least one valid RTT sample has been recorded.
    #[must_use]
    pub const fn has_sample(self) -> bool {
        self.latest_rtt_micros.is_some()
    }

    /// Returns the current time threshold for declaring an older packet lost.
    #[must_use]
    pub fn loss_delay_micros(self) -> u64 {
        let latest = self
            .latest_rtt_micros
            .unwrap_or(self.config.initial_rtt_micros);
        let smoothed = self
            .smoothed_rtt_micros
            .unwrap_or(self.config.initial_rtt_micros);
        scale_ceil(
            latest.max(smoothed),
            TIME_LOSS_THRESHOLD_NUMERATOR,
            TIME_LOSS_THRESHOLD_DENOMINATOR,
        )
        .max(TIMER_GRANULARITY_MICROS)
    }

    /// Returns the base probe timeout before exponential backoff.
    #[must_use]
    pub fn probe_timeout_micros(self) -> u64 {
        let smoothed = self
            .smoothed_rtt_micros
            .unwrap_or(self.config.initial_rtt_micros);
        let variance = self
            .rtt_variance_micros
            .unwrap_or(self.config.initial_rtt_micros / 2);
        smoothed
            .saturating_add(variance.saturating_mul(4).max(TIMER_GRANULARITY_MICROS))
            .saturating_add(self.config.max_ack_delay_micros)
    }

    /// Returns the minimum lost-packet span for persistent congestion.
    #[must_use]
    pub fn persistent_congestion_duration_micros(self) -> u64 {
        self.probe_timeout_micros()
            .saturating_mul(PERSISTENT_CONGESTION_THRESHOLD)
    }
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new(RecoveryConfig::default())
    }
}

/// Currently armed recovery timer for one path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryTimer {
    /// Time-threshold loss detection takes precedence over PTO.
    LossDetection { deadline_micros: u64 },
    /// Probe timeout for tail loss or lost acknowledgements.
    ProbeTimeout { deadline_micros: u64 },
}

/// Action returned when a valid PTO deadline expires.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeAction {
    pub probe_datagrams: u8,
    pub backoff_exponent: u32,
}

/// Per-path PTO arming and bounded exponential-backoff state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProbeTimeoutState {
    last_ack_eliciting_sent_at_micros: Option<u64>,
    backoff_exponent: u32,
}

impl ProbeTimeoutState {
    /// Records the monotonic send time of an ACK-eliciting packet.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::ClockWentBackwards`] if the timestamp is older
    /// than the preceding ACK-eliciting send.
    pub fn on_ack_eliciting_sent(&mut self, sent_at_micros: u64) -> Result<(), RecoveryError> {
        if self
            .last_ack_eliciting_sent_at_micros
            .is_some_and(|last| sent_at_micros < last)
        {
            return Err(RecoveryError::ClockWentBackwards);
        }
        self.last_ack_eliciting_sent_at_micros = Some(sent_at_micros);
        Ok(())
    }

    /// Resets PTO backoff after an ACK newly acknowledges a packet.
    pub fn on_ack(&mut self, newly_acknowledged: bool) {
        if newly_acknowledged {
            self.backoff_exponent = 0;
        }
    }

    /// Selects a time-threshold loss timer or, otherwise, a PTO timer.
    ///
    /// Returns `None` when no ACK-eliciting packet is in flight.
    #[must_use]
    pub fn timer(
        self,
        rtt: RttEstimator,
        loss_deadline_micros: Option<u64>,
        has_ack_eliciting_in_flight: bool,
    ) -> Option<RecoveryTimer> {
        if let Some(deadline_micros) = loss_deadline_micros {
            return Some(RecoveryTimer::LossDetection { deadline_micros });
        }
        if !has_ack_eliciting_in_flight {
            return None;
        }
        let sent_at = self.last_ack_eliciting_sent_at_micros?;
        Some(RecoveryTimer::ProbeTimeout {
            deadline_micros: sent_at.saturating_add(self.duration_micros(rtt)),
        })
    }

    /// Processes one PTO expiration without declaring any packet lost.
    ///
    /// # Errors
    ///
    /// Returns an error when no PTO is armed or `now_micros` precedes its
    /// deadline.
    pub fn on_expiration(
        &mut self,
        now_micros: u64,
        rtt: RttEstimator,
        has_ack_eliciting_in_flight: bool,
    ) -> Result<ProbeAction, RecoveryError> {
        let Some(RecoveryTimer::ProbeTimeout { deadline_micros }) =
            self.timer(rtt, None, has_ack_eliciting_in_flight)
        else {
            return Err(RecoveryError::ProbeTimeoutNotArmed);
        };
        if now_micros < deadline_micros {
            return Err(RecoveryError::TimerNotExpired {
                deadline_micros,
                now_micros,
            });
        }
        self.backoff_exponent = self
            .backoff_exponent
            .saturating_add(1)
            .min(MAX_PTO_BACKOFF_EXPONENT);
        Ok(ProbeAction {
            probe_datagrams: PTO_PROBE_DATAGRAMS,
            backoff_exponent: self.backoff_exponent,
        })
    }

    /// Returns the current exponentially backed-off PTO duration.
    #[must_use]
    pub fn duration_micros(self, rtt: RttEstimator) -> u64 {
        let multiplier = 1_u64 << self.backoff_exponent.min(MAX_PTO_BACKOFF_EXPONENT);
        rtt.probe_timeout_micros().saturating_mul(multiplier)
    }

    /// Returns the current bounded backoff exponent.
    #[must_use]
    pub const fn backoff_exponent(self) -> u32 {
        self.backoff_exponent
    }
}

/// Outcome of one ACK-eliciting packet in send-time order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CongestionOutcome {
    Acknowledged,
    Lost,
    Outstanding,
}

/// Allocation-free detector for a consecutive lost-packet time span.
///
/// The integration layer feeds every ACK-eliciting packet in non-decreasing
/// send-time order. An acknowledgement or unresolved packet breaks the run.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PersistentCongestionTracker {
    last_observed_sent_at_micros: Option<u64>,
    run_start_micros: Option<u64>,
    run_end_micros: Option<u64>,
    lost_packets_in_run: u64,
}

impl PersistentCongestionTracker {
    /// Observes one chronologically ordered packet outcome.
    ///
    /// Returns `true` when at least two consecutive packets with prior RTT
    /// knowledge are lost across the configured persistent-congestion duration.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::OutcomeTimeWentBackwards`] for out-of-order
    /// input.
    pub fn observe(
        &mut self,
        sent_at_micros: u64,
        outcome: CongestionOutcome,
        rtt_sample_existed_when_sent: bool,
        persistent_duration_micros: u64,
    ) -> Result<bool, RecoveryError> {
        if self
            .last_observed_sent_at_micros
            .is_some_and(|last| sent_at_micros < last)
        {
            return Err(RecoveryError::OutcomeTimeWentBackwards);
        }
        self.last_observed_sent_at_micros = Some(sent_at_micros);
        if outcome != CongestionOutcome::Lost || !rtt_sample_existed_when_sent {
            self.reset_run();
            return Ok(false);
        }
        if self.run_start_micros.is_none() {
            self.run_start_micros = Some(sent_at_micros);
        }
        self.run_end_micros = Some(sent_at_micros);
        self.lost_packets_in_run = self.lost_packets_in_run.saturating_add(1);
        let span = sent_at_micros.saturating_sub(self.run_start_micros.unwrap_or(sent_at_micros));
        Ok(self.lost_packets_in_run >= 2 && span >= persistent_duration_micros)
    }

    /// Clears both chronological and current-run state.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    fn reset_run(&mut self) {
        self.run_start_micros = None;
        self.run_end_micros = None;
        self.lost_packets_in_run = 0;
    }
}

/// Stable retransmission identity retained instead of payload bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryToken {
    /// One DATA fragment that can be reread from its object source.
    Data(DataMetadata),
    /// One idempotent control operation in a caller-owned bounded table.
    Control(u64),
}

/// Metadata retained for one acknowledgement-eliciting packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SentPacket {
    pub packet_number: u64,
    pub sent_at_micros: u64,
    pub encoded_bytes: u32,
    pub recovery_token: Option<RecoveryToken>,
}

/// Reason an outstanding packet was declared lost.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LossReason {
    PacketThreshold,
    TimeThreshold,
}

/// Allocation-free callback event produced while processing an ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryEvent {
    Acknowledged(SentPacket),
    Lost {
        packet: SentPacket,
        reason: LossReason,
    },
}

/// Aggregate result of processing one authenticated ACK frame.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AckSummary {
    pub acknowledged_packets: usize,
    pub acknowledged_bytes: u64,
    pub lost_packets: usize,
    pub lost_bytes: u64,
    pub largest_newly_acknowledged: Option<u64>,
    pub raw_rtt_sample_micros: Option<u64>,
}

/// Fixed-capacity per-path sent-packet ledger.
///
/// A preallocated free-index stack makes insertion O(1), including when
/// untracked ACK-only packets create gaps in the packet-number sequence. An
/// empty free stack is backpressure until ACK or loss processing releases a
/// slot.
#[derive(Debug)]
pub struct SentPacketTable {
    slots: Box<[Option<SentPacket>]>,
    free_slots: Vec<usize>,
    outstanding_packets: usize,
    outstanding_bytes: u64,
    largest_sent: Option<u64>,
    largest_acknowledged: Option<u64>,
    last_sent_at_micros: Option<u64>,
}

impl SentPacketTable {
    /// Allocates the complete, fixed slot table once.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::InvalidCapacity`] for a zero capacity.
    pub fn with_capacity(capacity: usize) -> Result<Self, RecoveryError> {
        if capacity == 0 {
            return Err(RecoveryError::InvalidCapacity);
        }
        let mut free_slots = Vec::with_capacity(capacity);
        for index in (0..capacity).rev() {
            free_slots.push(index);
        }
        Ok(Self {
            slots: vec![None; capacity].into_boxed_slice(),
            free_slots,
            outstanding_packets: 0,
            outstanding_bytes: 0,
            largest_sent: None,
            largest_acknowledged: None,
            last_sent_at_micros: None,
        })
    }

    /// Records one newly sent acknowledgement-eliciting packet.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero packet size, non-monotonic packet number or
    /// clock, a packet number outside the 62-bit space, accounting overflow, or
    /// exhaustion of the configured fixed slot table.
    pub fn record(&mut self, packet: SentPacket) -> Result<(), RecoveryError> {
        if packet.encoded_bytes == 0 {
            return Err(RecoveryError::ZeroPacketSize);
        }
        if packet.packet_number > MAX_PACKET_NUMBER {
            return Err(RecoveryError::PacketNumberOutOfRange(packet.packet_number));
        }
        if self
            .largest_sent
            .is_some_and(|largest| packet.packet_number <= largest)
        {
            return Err(RecoveryError::NonMonotonicPacketNumber);
        }
        if self
            .last_sent_at_micros
            .is_some_and(|last| packet.sent_at_micros < last)
        {
            return Err(RecoveryError::ClockWentBackwards);
        }
        let Some(&index) = self.free_slots.last() else {
            let oldest_packet_number = self
                .slots
                .iter()
                .flatten()
                .map(|tracked| tracked.packet_number)
                .min()
                .unwrap_or(packet.packet_number);
            return Err(RecoveryError::CapacityExhausted {
                oldest_packet_number,
            });
        };
        let next_packets = self
            .outstanding_packets
            .checked_add(1)
            .ok_or(RecoveryError::AccountingOverflow)?;
        let next_bytes = self
            .outstanding_bytes
            .checked_add(u64::from(packet.encoded_bytes))
            .ok_or(RecoveryError::AccountingOverflow)?;

        self.free_slots.pop();
        self.slots[index] = Some(packet);
        self.outstanding_packets = next_packets;
        self.outstanding_bytes = next_bytes;
        self.largest_sent = Some(packet.packet_number);
        self.last_sent_at_micros = Some(packet.sent_at_micros);
        Ok(())
    }

    /// Applies one authenticated path-local ACK and emits ACK/loss events.
    ///
    /// `visitor` is called synchronously and no event collection is allocated.
    /// The RTT sample is taken only when `ack.largest_acked` is newly
    /// acknowledged and still present in the table.
    ///
    /// # Errors
    ///
    /// Returns an error when the ACK acknowledges a packet number never sent on
    /// this path or when `now_micros` precedes the most recent send timestamp.
    pub fn on_ack(
        &mut self,
        ack: AckFrame<'_>,
        now_micros: u64,
        rtt: &mut RttEstimator,
        mut visitor: impl FnMut(RecoveryEvent),
    ) -> Result<AckSummary, RecoveryError> {
        let largest_sent = self.largest_sent.ok_or(RecoveryError::AckForUnsentPacket {
            largest_acked: ack.largest_acked,
        })?;
        if ack.largest_acked > largest_sent {
            return Err(RecoveryError::AckForUnsentPacket {
                largest_acked: ack.largest_acked,
            });
        }
        if self
            .last_sent_at_micros
            .is_some_and(|sent_at| now_micros < sent_at)
        {
            return Err(RecoveryError::ClockWentBackwards);
        }

        let mut summary = AckSummary::default();
        if let Some(packet) = self.find(ack.largest_acked) {
            let raw_sample = now_micros - packet.sent_at_micros;
            rtt.record_sample(raw_sample, u64::from(ack.ack_delay_micros));
            summary.raw_rtt_sample_micros = Some(raw_sample);
        }
        self.largest_acknowledged = Some(
            self.largest_acknowledged
                .map_or(ack.largest_acked, |current| current.max(ack.largest_acked)),
        );

        let largest_acknowledged = self.largest_acknowledged.unwrap_or(ack.largest_acked);
        let loss_delay = rtt.loss_delay_micros();
        for index in 0..self.slots.len() {
            let Some(packet) = self.slots[index] else {
                continue;
            };
            if ack.acknowledges(packet.packet_number)
                || packet.packet_number >= largest_acknowledged
            {
                continue;
            }
            let packet_threshold =
                largest_acknowledged - packet.packet_number >= PACKET_LOSS_THRESHOLD;
            let time_threshold = packet.sent_at_micros.saturating_add(loss_delay) <= now_micros;
            let reason = if packet_threshold {
                Some(LossReason::PacketThreshold)
            } else if time_threshold {
                Some(LossReason::TimeThreshold)
            } else {
                None
            };
            if let Some(reason) = reason {
                self.slots[index] = None;
                self.free_slots.push(index);
                self.release_accounting(packet);
                summary.lost_packets += 1;
                summary.lost_bytes = summary
                    .lost_bytes
                    .saturating_add(u64::from(packet.encoded_bytes));
                visitor(RecoveryEvent::Lost { packet, reason });
            }
        }

        for index in 0..self.slots.len() {
            let Some(packet) = self.slots[index] else {
                continue;
            };
            if ack.acknowledges(packet.packet_number) {
                self.slots[index] = None;
                self.free_slots.push(index);
                self.release_accounting(packet);
                summary.acknowledged_packets += 1;
                summary.acknowledged_bytes = summary
                    .acknowledged_bytes
                    .saturating_add(u64::from(packet.encoded_bytes));
                summary.largest_newly_acknowledged = Some(
                    summary
                        .largest_newly_acknowledged
                        .map_or(packet.packet_number, |current| {
                            current.max(packet.packet_number)
                        }),
                );
                visitor(RecoveryEvent::Acknowledged(packet));
            }
        }
        Ok(summary)
    }

    /// Returns the configured maximum number of outstanding packets.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// Returns the number of packets currently awaiting ACK or loss.
    #[must_use]
    pub const fn outstanding_packets(&self) -> usize {
        self.outstanding_packets
    }

    /// Returns encoded bytes currently awaiting ACK or loss.
    #[must_use]
    pub const fn outstanding_bytes(&self) -> u64 {
        self.outstanding_bytes
    }

    /// Returns the largest packet number ever recorded on this path.
    #[must_use]
    pub const fn largest_sent(&self) -> Option<u64> {
        self.largest_sent
    }

    /// Returns the largest authenticated packet number ever acknowledged.
    #[must_use]
    pub const fn largest_acknowledged(&self) -> Option<u64> {
        self.largest_acknowledged
    }

    fn find(&self, packet_number: u64) -> Option<SentPacket> {
        self.slots
            .iter()
            .flatten()
            .find(|packet| packet.packet_number == packet_number)
            .copied()
    }

    fn release_accounting(&mut self, packet: SentPacket) {
        self.outstanding_packets = self.outstanding_packets.saturating_sub(1);
        self.outstanding_bytes = self
            .outstanding_bytes
            .saturating_sub(u64::from(packet.encoded_bytes));
    }
}

/// Current scheduling inputs for one validated path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathCandidate {
    pub path_id: u8,
    pub validated: bool,
    pub sendable: bool,
    pub smoothed_rtt_micros: u64,
    pub pacer_delay_micros: u64,
    pub queued_bytes: u64,
    pub estimated_rate_bytes_per_second: u64,
    pub loss_penalty_micros: u64,
}

impl PathCandidate {
    /// Estimates delay until delivery, or returns `None` for an unusable path.
    #[must_use]
    pub fn estimated_delivery_delay_micros(self) -> Option<u64> {
        if !self.validated || !self.sendable || self.estimated_rate_bytes_per_second == 0 {
            return None;
        }
        let queue_delay = u128::from(self.queued_bytes)
            .saturating_mul(1_000_000)
            .div_ceil(u128::from(self.estimated_rate_bytes_per_second));
        let estimate = u128::from(self.pacer_delay_micros)
            .saturating_add(u128::from(self.smoothed_rtt_micros / 2))
            .saturating_add(queue_delay)
            .saturating_add(u128::from(self.loss_penalty_micros));
        Some(u64::try_from(estimate).unwrap_or(u64::MAX))
    }
}

/// Chosen target for retransmitting one stable recovery token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReinjectionDecision {
    pub token: RecoveryToken,
    pub source_path_id: u8,
    pub target_path_id: u8,
    pub estimated_delivery_delay_micros: u64,
}

/// Selects the usable path with the lowest estimated delivery delay.
///
/// The original path remains eligible when it is still usable. Ties are broken
/// by path identifier, making the decision deterministic.
#[must_use]
pub fn select_reinjection_path(
    token: RecoveryToken,
    source_path_id: u8,
    candidates: &[PathCandidate],
) -> Option<ReinjectionDecision> {
    candidates
        .iter()
        .filter_map(|candidate| {
            candidate
                .estimated_delivery_delay_micros()
                .map(|estimate| (*candidate, estimate))
        })
        .min_by_key(|(candidate, estimate)| (*estimate, candidate.path_id))
        .map(|(candidate, estimate)| ReinjectionDecision {
            token,
            source_path_id,
            target_path_id: candidate.path_id,
            estimated_delivery_delay_micros: estimate,
        })
}

/// Invalid recovery input or exhausted bounded state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryError {
    InvalidConfiguration,
    InvalidCapacity,
    ZeroPacketSize,
    PacketNumberOutOfRange(u64),
    NonMonotonicPacketNumber,
    ClockWentBackwards,
    CapacityExhausted {
        oldest_packet_number: u64,
    },
    AccountingOverflow,
    AckForUnsentPacket {
        largest_acked: u64,
    },
    ProbeTimeoutNotArmed,
    TimerNotExpired {
        deadline_micros: u64,
        now_micros: u64,
    },
    OutcomeTimeWentBackwards,
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => formatter.write_str("invalid recovery configuration"),
            Self::InvalidCapacity => formatter.write_str("invalid sent-packet table capacity"),
            Self::ZeroPacketSize => formatter.write_str("cannot track a zero-byte packet"),
            Self::PacketNumberOutOfRange(number) => {
                write!(formatter, "packet number exceeds 62 bits: {number}")
            }
            Self::NonMonotonicPacketNumber => {
                formatter.write_str("packet numbers must increase monotonically")
            }
            Self::ClockWentBackwards => formatter.write_str("recovery clock moved backwards"),
            Self::CapacityExhausted {
                oldest_packet_number,
            } => write!(
                formatter,
                "sent-packet table is full; oldest packet is {oldest_packet_number}"
            ),
            Self::AccountingOverflow => formatter.write_str("recovery accounting overflow"),
            Self::AckForUnsentPacket { largest_acked } => {
                write!(formatter, "ACK covers unsent packet {largest_acked}")
            }
            Self::ProbeTimeoutNotArmed => formatter.write_str("probe timeout is not armed"),
            Self::TimerNotExpired {
                deadline_micros,
                now_micros,
            } => write!(
                formatter,
                "recovery timer deadline {deadline_micros} is after current time {now_micros}"
            ),
            Self::OutcomeTimeWentBackwards => {
                formatter.write_str("congestion outcomes are not in send-time order")
            }
        }
    }
}

impl std::error::Error for RecoveryError {}

fn weighted_average(previous: u64, sample: u64, previous_weight: u64, divisor: u64) -> u64 {
    let weighted = u128::from(previous)
        .saturating_mul(u128::from(previous_weight))
        .saturating_add(u128::from(sample));
    u64::try_from(weighted / u128::from(divisor)).unwrap_or(u64::MAX)
}

fn scale_ceil(value: u64, numerator: u64, denominator: u64) -> u64 {
    let scaled = u128::from(value)
        .saturating_mul(u128::from(numerator))
        .div_ceil(u128::from(denominator));
    u64::try_from(scaled).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simulator::{DeterministicNetwork, PathProfile};
    use crate::wire::ack::AckRange;
    use core::num::NonZeroU64;

    fn sent(packet_number: u64, sent_at_micros: u64) -> SentPacket {
        SentPacket {
            packet_number,
            sent_at_micros,
            encoded_bytes: 1_200,
            recovery_token: Some(RecoveryToken::Control(packet_number)),
        }
    }

    fn track_and_send(
        network: &mut DeterministicNetwork<RecoveryToken>,
        table: &mut SentPacketTable,
        path_id: u8,
        packet_number: u64,
    ) {
        let packet = sent(packet_number, network.now());
        table.record(packet).expect("packet fits");
        network
            .send(path_id, packet.recovery_token.expect("test token exists"))
            .expect("network send succeeds");
    }

    fn apply_ack(
        table: &mut SentPacketTable,
        rtt: &mut RttEstimator,
        largest_acked: u64,
        ranges: &[AckRange],
        now_micros: u64,
        visitor: impl FnMut(RecoveryEvent),
    ) -> AckSummary {
        let mut encoded = [0_u8; 160];
        let length =
            AckFrame::encode(largest_acked, 0, 1, ranges, &mut encoded).expect("ACK encodes");
        let ack = AckFrame::decode(&encoded[..length]).expect("ACK decodes");
        table
            .on_ack(ack, now_micros, rtt, visitor)
            .expect("ACK applies")
    }

    fn failover_candidates() -> [PathCandidate; 2] {
        [
            PathCandidate {
                path_id: 0,
                validated: true,
                sendable: false,
                smoothed_rtt_micros: 10,
                pacer_delay_micros: 0,
                queued_bytes: 0,
                estimated_rate_bytes_per_second: 1_000_000,
                loss_penalty_micros: 0,
            },
            PathCandidate {
                path_id: 1,
                validated: true,
                sendable: true,
                smoothed_rtt_micros: 4,
                pacer_delay_micros: 0,
                queued_bytes: 0,
                estimated_rate_bytes_per_second: 1_000_000,
                loss_penalty_micros: 0,
            },
        ]
    }

    fn failover_network() -> DeterministicNetwork<RecoveryToken> {
        let mut network = DeterministicNetwork::new();
        network
            .add_path(
                0,
                PathProfile {
                    base_delay_ticks: 5,
                    reorder_every: NonZeroU64::new(2),
                    reorder_delay_ticks: 20,
                    ..PathProfile::default()
                },
            )
            .expect("source path is unique");
        network
            .add_path(
                1,
                PathProfile {
                    base_delay_ticks: 2,
                    ..PathProfile::default()
                },
            )
            .expect("target path is unique");
        network
    }

    #[test]
    fn fixed_table_applies_backpressure_without_growing() {
        let mut table = SentPacketTable::with_capacity(2).expect("valid capacity");
        let free_stack_capacity = table.free_slots.capacity();
        table.record(sent(0, 0)).expect("first slot");
        table.record(sent(1, 0)).expect("second slot");
        assert_eq!(
            table.record(sent(2, 0)),
            Err(RecoveryError::CapacityExhausted {
                oldest_packet_number: 0
            })
        );
        assert_eq!(table.capacity(), 2);
        assert_eq!(table.outstanding_packets(), 2);
        assert_eq!(table.outstanding_bytes(), 2_400);

        let mut encoded = [0_u8; 32];
        let length = AckFrame::encode(0, 0, 1, &[], &mut encoded).expect("ACK encodes");
        let ack = AckFrame::decode(&encoded[..length]).expect("ACK decodes");
        table
            .on_ack(ack, 1, &mut RttEstimator::default(), |_| {})
            .expect("ACK applies");
        table.record(sent(2, 1)).expect("released slot is reused");
        assert_eq!(table.capacity(), 2);
        assert_eq!(table.free_slots.capacity(), free_stack_capacity);
    }

    #[test]
    fn skipped_untracked_packet_numbers_do_not_collide() {
        let mut table = SentPacketTable::with_capacity(2).expect("valid capacity");
        table.record(sent(0, 0)).expect("first packet fits");
        table
            .record(sent(1_000_000, 1))
            .expect("packet-number gaps do not consume slots");
        assert_eq!(table.outstanding_packets(), 2);
    }

    #[test]
    fn rtt_adjustment_is_bounded_by_minimum_and_configured_ack_delay() {
        let config = RecoveryConfig::new(333_000, 25_000).expect("valid timing");
        let mut rtt = RttEstimator::new(config);
        rtt.record_sample(100_000, 50_000);
        assert_eq!(rtt.minimum_rtt_micros(), Some(100_000));
        assert_eq!(rtt.smoothed_rtt_micros(), Some(100_000));

        rtt.record_sample(125_000, 50_000);
        assert_eq!(rtt.latest_rtt_micros(), Some(125_000));
        assert_eq!(rtt.minimum_rtt_micros(), Some(100_000));
        assert_eq!(rtt.smoothed_rtt_micros(), Some(100_000));
        assert_eq!(rtt.rtt_variance_micros(), Some(37_500));
        assert_eq!(rtt.loss_delay_micros(), 140_625);
        assert_eq!(rtt.probe_timeout_micros(), 275_000);
    }

    #[test]
    fn pto_arms_backs_off_and_resets_without_declaring_loss() {
        let mut rtt = RttEstimator::new(
            RecoveryConfig::new(333_000, 25_000).expect("valid recovery configuration"),
        );
        rtt.record_sample(100_000, 0);
        let mut pto = ProbeTimeoutState::default();
        pto.on_ack_eliciting_sent(1_000).expect("clock advances");
        let base_duration = rtt.probe_timeout_micros();
        assert_eq!(
            pto.timer(rtt, None, true),
            Some(RecoveryTimer::ProbeTimeout {
                deadline_micros: 1_000 + base_duration
            })
        );
        assert!(matches!(
            pto.on_expiration(1_000, rtt, true),
            Err(RecoveryError::TimerNotExpired { .. })
        ));
        assert_eq!(
            pto.on_expiration(1_000 + base_duration, rtt, true),
            Ok(ProbeAction {
                probe_datagrams: 2,
                backoff_exponent: 1,
            })
        );
        assert_eq!(pto.duration_micros(rtt), base_duration * 2);
        pto.backoff_exponent = MAX_PTO_BACKOFF_EXPONENT;
        assert_eq!(pto.duration_micros(rtt), u64::MAX);
        pto.on_ack(true);
        assert_eq!(pto.backoff_exponent(), 0);
        assert_eq!(pto.timer(rtt, None, false), None);
        assert_eq!(
            pto.timer(rtt, Some(42), true),
            Some(RecoveryTimer::LossDetection {
                deadline_micros: 42
            })
        );
    }

    #[test]
    fn persistent_congestion_requires_a_consecutive_timed_loss_run() {
        let mut tracker = PersistentCongestionTracker::default();
        assert_eq!(
            tracker.observe(0, CongestionOutcome::Lost, true, 300),
            Ok(false)
        );
        assert_eq!(
            tracker.observe(300, CongestionOutcome::Lost, true, 300),
            Ok(true)
        );

        tracker.reset();
        assert_eq!(
            tracker.observe(0, CongestionOutcome::Lost, true, 300),
            Ok(false)
        );
        assert_eq!(
            tracker.observe(100, CongestionOutcome::Acknowledged, true, 300),
            Ok(false)
        );
        assert_eq!(
            tracker.observe(400, CongestionOutcome::Lost, true, 300),
            Ok(false)
        );
        assert_eq!(
            tracker.observe(399, CongestionOutcome::Lost, true, 300),
            Err(RecoveryError::OutcomeTimeWentBackwards)
        );
    }

    #[test]
    fn ack_ranges_release_packets_and_packet_threshold_declares_loss() {
        let mut table = SentPacketTable::with_capacity(8).expect("valid capacity");
        for packet_number in 0..6 {
            table
                .record(sent(packet_number, packet_number * 100))
                .expect("packet fits");
        }
        let mut encoded = [0_u8; 32];
        let length = AckFrame::encode(5, 0, 1, &[AckRange { gap: 2, length: 1 }], &mut encoded)
            .expect("ACK encodes");
        let ack = AckFrame::decode(&encoded[..length]).expect("ACK decodes");
        let mut events = Vec::new();
        let summary = table
            .on_ack(ack, 1_000, &mut RttEstimator::default(), |event| {
                events.push(event);
            })
            .expect("ACK applies");

        assert_eq!(summary.acknowledged_packets, 2);
        assert_eq!(summary.acknowledged_bytes, 2_400);
        assert_eq!(summary.lost_packets, 2);
        assert_eq!(summary.lost_bytes, 2_400);
        assert_eq!(summary.largest_newly_acknowledged, Some(5));
        assert_eq!(summary.raw_rtt_sample_micros, Some(500));
        assert_eq!(table.outstanding_packets(), 2);
        assert!(events.contains(&RecoveryEvent::Acknowledged(sent(2, 200))));
        assert!(events.contains(&RecoveryEvent::Acknowledged(sent(5, 500))));
        assert!(events.contains(&RecoveryEvent::Lost {
            packet: sent(0, 0),
            reason: LossReason::PacketThreshold,
        }));
        assert!(events.contains(&RecoveryEvent::Lost {
            packet: sent(1, 100),
            reason: LossReason::PacketThreshold,
        }));
    }

    #[test]
    fn time_threshold_detects_loss_without_three_newer_packets() {
        let mut table = SentPacketTable::with_capacity(4).expect("valid capacity");
        table.record(sent(0, 0)).expect("packet fits");
        table.record(sent(1, 0)).expect("packet fits");
        let mut rtt = RttEstimator::new(
            RecoveryConfig::new(10_000, 0).expect("valid recovery configuration"),
        );
        let mut encoded = [0_u8; 32];
        let first_length = AckFrame::encode(1, 0, 1, &[], &mut encoded).expect("ACK encodes");
        let first_ack = AckFrame::decode(&encoded[..first_length]).expect("ACK decodes");
        let first = table
            .on_ack(first_ack, 2_000, &mut rtt, |_| {})
            .expect("ACK applies");
        assert_eq!(first.lost_packets, 0);

        table.record(sent(2, 2_000)).expect("packet fits");
        let second_length = AckFrame::encode(2, 0, 1, &[], &mut encoded).expect("ACK encodes");
        let second_ack = AckFrame::decode(&encoded[..second_length]).expect("ACK decodes");
        let mut loss = None;
        let second = table
            .on_ack(second_ack, 5_000, &mut rtt, |event| {
                if let RecoveryEvent::Lost { packet, reason } = event {
                    loss = Some((packet.packet_number, reason));
                }
            })
            .expect("ACK applies");

        assert_eq!(second.lost_packets, 1);
        assert_eq!(loss, Some((0, LossReason::TimeThreshold)));
        assert_eq!(table.outstanding_packets(), 0);
    }

    #[test]
    fn delayed_packet_is_reinjected_on_failover_and_can_arrive_late() {
        let mut network = failover_network();

        let mut source = SentPacketTable::with_capacity(8).expect("valid source table");
        for packet_number in 0..3 {
            track_and_send(&mut network, &mut source, 0, packet_number);
        }
        assert_eq!(
            network.deliver_next().expect("packet zero arrives").payload,
            RecoveryToken::Control(0)
        );
        assert_eq!(
            network.deliver_next().expect("packet two arrives").payload,
            RecoveryToken::Control(2)
        );

        let mut source_rtt = RttEstimator::default();
        let first = apply_ack(
            &mut source,
            &mut source_rtt,
            2,
            &[AckRange { gap: 1, length: 1 }],
            network.now(),
            |_| {},
        );
        assert_eq!(first.acknowledged_packets, 2);
        assert_eq!(first.lost_packets, 0);

        for packet_number in 3..5 {
            track_and_send(&mut network, &mut source, 0, packet_number);
        }
        assert_eq!(
            network.deliver_next().expect("packet four arrives").payload,
            RecoveryToken::Control(4)
        );

        let mut lost_token = None;
        let second = apply_ack(
            &mut source,
            &mut source_rtt,
            4,
            &[
                AckRange { gap: 1, length: 1 },
                AckRange { gap: 1, length: 1 },
            ],
            network.now(),
            |event| {
                if let RecoveryEvent::Lost { packet, .. } = event {
                    lost_token = packet.recovery_token;
                }
            },
        );
        assert_eq!(second.lost_packets, 1);
        let token = lost_token.expect("delayed packet is declared lost");
        assert_eq!(token, RecoveryToken::Control(1));

        network
            .set_path_enabled(0, false)
            .expect("source path exists");
        let candidates = failover_candidates();
        let decision = select_reinjection_path(token, 0, &candidates)
            .expect("validated alternate path is available");
        assert_eq!(decision.target_path_id, 1);

        let mut target = SentPacketTable::with_capacity(4).expect("valid target table");
        target
            .record(SentPacket {
                packet_number: 0,
                sent_at_micros: network.now(),
                encoded_bytes: 1_200,
                recovery_token: Some(token),
            })
            .expect("target packet fits");
        network.send(1, token).expect("reinjection send succeeds");
        assert_eq!(
            network.deliver_next().expect("reinjection arrives").payload,
            token
        );

        let target_summary = apply_ack(
            &mut target,
            &mut RttEstimator::default(),
            0,
            &[],
            network.now(),
            |_| {},
        );
        assert_eq!(target_summary.acknowledged_packets, 1);
        assert_eq!(target.outstanding_packets(), 0);

        let late_original = network.deliver_next().expect("original arrives late");
        assert_eq!(late_original.path_id, 0);
        assert_eq!(late_original.payload, token);
        assert_eq!(late_original.delivery_tick, 25);
    }

    #[test]
    fn reinjection_prefers_arrival_time_and_skips_failed_paths() {
        let token = RecoveryToken::Control(9);
        let candidates = [
            PathCandidate {
                path_id: 0,
                validated: true,
                sendable: false,
                smoothed_rtt_micros: 10_000,
                pacer_delay_micros: 0,
                queued_bytes: 0,
                estimated_rate_bytes_per_second: 1_000_000,
                loss_penalty_micros: 0,
            },
            PathCandidate {
                path_id: 1,
                validated: true,
                sendable: true,
                smoothed_rtt_micros: 50_000,
                pacer_delay_micros: 1_000,
                queued_bytes: 1_000,
                estimated_rate_bytes_per_second: 1_000_000,
                loss_penalty_micros: 2_000,
            },
            PathCandidate {
                path_id: 2,
                validated: true,
                sendable: true,
                smoothed_rtt_micros: 20_000,
                pacer_delay_micros: 0,
                queued_bytes: 100_000,
                estimated_rate_bytes_per_second: 1_000_000,
                loss_penalty_micros: 0,
            },
        ];

        assert_eq!(
            select_reinjection_path(token, 0, &candidates),
            Some(ReinjectionDecision {
                token,
                source_path_id: 0,
                target_path_id: 1,
                estimated_delivery_delay_micros: 29_000,
            })
        );
    }
}
