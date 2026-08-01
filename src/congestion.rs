//! Per-path CUBIC congestion window and integer nanosecond pacer.
//!
//! All state is scalar and all calculations use saturating integer arithmetic.
//! No congestion or pacing operation allocates.

use core::fmt;

use crate::recovery::RttEstimator;

pub const MIN_MAX_DATAGRAM_SIZE: u32 = 1_200;
pub const CUBIC_BETA_NUMERATOR: u64 = 7;
pub const CUBIC_BETA_DENOMINATOR: u64 = 10;
pub const CUBIC_C_NUMERATOR: u64 = 2;
pub const CUBIC_C_DENOMINATOR: u64 = 5;
pub const CUBIC_ALPHA_NUMERATOR: u64 = 9;
pub const CUBIC_ALPHA_DENOMINATOR: u64 = 17;

const FIXED_POINT_SHIFT: u32 = 32;
const FIXED_POINT_ONE: u128 = 1_u128 << FIXED_POINT_SHIFT;
const MICROS_PER_SECOND_CUBED: u128 = 1_000_000_000_000_000_000;

/// Immutable configuration for one path's congestion controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CubicConfig {
    max_datagram_size: u32,
    fast_convergence: bool,
}

impl CubicConfig {
    /// Creates a CUBIC configuration for a validated datagram size.
    ///
    /// # Errors
    ///
    /// Returns [`CongestionError::InvalidMaxDatagramSize`] below the OGTP
    /// baseline of 1,200 bytes.
    pub const fn new(
        max_datagram_size: u32,
        fast_convergence: bool,
    ) -> Result<Self, CongestionError> {
        if max_datagram_size < MIN_MAX_DATAGRAM_SIZE {
            return Err(CongestionError::InvalidMaxDatagramSize);
        }
        Ok(Self {
            max_datagram_size,
            fast_convergence,
        })
    }

    /// Returns the path's current maximum UDP payload size.
    #[must_use]
    pub const fn max_datagram_size(self) -> u32 {
        self.max_datagram_size
    }

    /// Returns whether RFC 9438 fast convergence is enabled.
    #[must_use]
    pub const fn fast_convergence(self) -> bool {
        self.fast_convergence
    }
}

impl Default for CubicConfig {
    fn default() -> Self {
        Self {
            max_datagram_size: MIN_MAX_DATAGRAM_SIZE,
            fast_convergence: true,
        }
    }
}

/// Current congestion-control phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CongestionPhase {
    SlowStart,
    CongestionAvoidance,
}

/// Result of processing one loss signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CongestionEventResult {
    pub window_reduced: bool,
    pub persistent_congestion: bool,
    pub congestion_window: u64,
}

/// Byte-counted CUBIC state for one independently controlled path.
#[derive(Debug)]
pub struct CubicController {
    config: CubicConfig,
    congestion_window: u64,
    slow_start_threshold: u64,
    bytes_in_flight: u64,
    congestion_window_prior: u64,
    maximum_window: u64,
    epoch_started_at_micros: Option<u64>,
    epoch_window: u64,
    estimated_reno_window_fixed: u128,
    cubic_credit_fixed: u128,
    recovery_started_at_micros: Option<u64>,
    application_limited_since_micros: Option<u64>,
    last_event_at_micros: Option<u64>,
}

impl CubicController {
    /// Creates a path controller in slow start.
    #[must_use]
    pub fn new(config: CubicConfig) -> Self {
        let maximum_datagram = u64::from(config.max_datagram_size);
        let initial_window = maximum_datagram
            .saturating_mul(10)
            .min(maximum_datagram.saturating_mul(2).max(14_720));
        Self {
            config,
            congestion_window: initial_window,
            slow_start_threshold: u64::MAX,
            bytes_in_flight: 0,
            congestion_window_prior: initial_window,
            maximum_window: 0,
            epoch_started_at_micros: None,
            epoch_window: initial_window,
            estimated_reno_window_fixed: u128::from(initial_window) << FIXED_POINT_SHIFT,
            cubic_credit_fixed: 0,
            recovery_started_at_micros: None,
            application_limited_since_micros: None,
            last_event_at_micros: None,
        }
    }

    /// Returns whether a normal congestion-controlled packet can be sent.
    #[must_use]
    pub fn can_send(&self, encoded_bytes: u32) -> bool {
        self.bytes_in_flight
            .checked_add(u64::from(encoded_bytes))
            .is_some_and(|next| next <= self.congestion_window)
    }

    /// Charges one sent packet to bytes in flight.
    ///
    /// PTO probes may temporarily exceed the congestion window but remain
    /// charged because they add network load.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero-size packet, accounting overflow, or a
    /// normal send that would exceed the congestion window.
    pub fn on_packet_sent(
        &mut self,
        encoded_bytes: u32,
        is_pto_probe: bool,
    ) -> Result<(), CongestionError> {
        if encoded_bytes == 0 {
            return Err(CongestionError::ZeroPacketSize);
        }
        let next = self
            .bytes_in_flight
            .checked_add(u64::from(encoded_bytes))
            .ok_or(CongestionError::AccountingOverflow)?;
        if !is_pto_probe && next > self.congestion_window {
            return Err(CongestionError::CongestionWindowExceeded);
        }
        self.bytes_in_flight = next;
        Ok(())
    }

    /// Releases acknowledged bytes and grows the window when eligible.
    ///
    /// Packets sent before the current recovery epoch release accounting but do
    /// not grow the window. Application-limited periods also suppress growth.
    ///
    /// # Errors
    ///
    /// Returns an error for clock regression, an impossible acknowledgement,
    /// or an acknowledgement timestamp preceding the packet send time.
    pub fn on_packet_acknowledged(
        &mut self,
        acknowledged_bytes: u32,
        packet_sent_at_micros: u64,
        now_micros: u64,
        rtt: RttEstimator,
    ) -> Result<(), CongestionError> {
        self.validate_event_time(packet_sent_at_micros, now_micros)?;
        let acknowledged = u64::from(acknowledged_bytes);
        if acknowledged == 0 || acknowledged > self.bytes_in_flight {
            return Err(CongestionError::AcknowledgementExceedsFlight);
        }
        self.bytes_in_flight -= acknowledged;
        self.last_event_at_micros = Some(now_micros);
        if self
            .recovery_started_at_micros
            .is_some_and(|recovery| packet_sent_at_micros <= recovery)
            || self.application_limited_since_micros.is_some()
        {
            return Ok(());
        }
        if self.phase() == CongestionPhase::SlowStart {
            self.congestion_window = self.congestion_window.saturating_add(acknowledged);
        } else {
            self.grow_cubic(acknowledged, now_micros, rtt);
        }
        Ok(())
    }

    /// Releases lost bytes and applies at most one reduction per recovery epoch.
    ///
    /// Persistent congestion always collapses the window to two datagrams.
    ///
    /// # Errors
    ///
    /// Returns an error for clock regression or loss accounting larger than
    /// bytes in flight.
    pub fn on_packet_lost(
        &mut self,
        lost_bytes: u32,
        packet_sent_at_micros: u64,
        now_micros: u64,
        persistent_congestion: bool,
    ) -> Result<CongestionEventResult, CongestionError> {
        self.validate_event_time(packet_sent_at_micros, now_micros)?;
        let lost = u64::from(lost_bytes);
        if lost == 0 || lost > self.bytes_in_flight {
            return Err(CongestionError::LossExceedsFlight);
        }
        let flight_before_loss = self.bytes_in_flight;
        self.bytes_in_flight -= lost;
        self.last_event_at_micros = Some(now_micros);
        let in_current_recovery = self
            .recovery_started_at_micros
            .is_some_and(|recovery| packet_sent_at_micros <= recovery);
        if in_current_recovery && !persistent_congestion {
            return Ok(self.event_result(false, false));
        }

        self.congestion_window_prior = self.congestion_window;
        self.maximum_window = if self.config.fast_convergence
            && self.maximum_window != 0
            && self.congestion_window < self.maximum_window
        {
            mul_ratio(self.congestion_window, 17, 20)
        } else {
            self.congestion_window
        };
        let validated_flight = flight_before_loss.min(self.congestion_window);
        self.slow_start_threshold = mul_ratio(
            validated_flight,
            CUBIC_BETA_NUMERATOR,
            CUBIC_BETA_DENOMINATOR,
        )
        .max(self.minimum_window());
        self.congestion_window = if persistent_congestion {
            self.minimum_window()
        } else {
            self.slow_start_threshold
        };
        self.recovery_started_at_micros = Some(now_micros);
        self.reset_epoch();
        Ok(self.event_result(true, persistent_congestion))
    }

    /// Starts or ends an application-limited period.
    ///
    /// Paused time is excluded from the CUBIC epoch as required by RFC 9438.
    ///
    /// # Errors
    ///
    /// Returns [`CongestionError::ClockWentBackwards`] when time regresses.
    pub fn set_application_limited(
        &mut self,
        now_micros: u64,
        limited: bool,
    ) -> Result<(), CongestionError> {
        if self
            .last_event_at_micros
            .is_some_and(|last| now_micros < last)
        {
            return Err(CongestionError::ClockWentBackwards);
        }
        match (limited, self.application_limited_since_micros) {
            (true, None) => self.application_limited_since_micros = Some(now_micros),
            (false, Some(started)) => {
                if now_micros < started {
                    return Err(CongestionError::ClockWentBackwards);
                }
                if let Some(epoch) = self.epoch_started_at_micros.as_mut() {
                    *epoch = epoch.saturating_add(now_micros - started);
                }
                self.application_limited_since_micros = None;
            }
            _ => {}
        }
        self.last_event_at_micros = Some(now_micros);
        Ok(())
    }

    /// Returns the current controller phase.
    #[must_use]
    pub const fn phase(&self) -> CongestionPhase {
        if self.congestion_window < self.slow_start_threshold {
            CongestionPhase::SlowStart
        } else {
            CongestionPhase::CongestionAvoidance
        }
    }

    /// Returns the current congestion window in bytes.
    #[must_use]
    pub const fn congestion_window(&self) -> u64 {
        self.congestion_window
    }

    /// Returns the slow-start threshold in bytes.
    #[must_use]
    pub const fn slow_start_threshold(&self) -> u64 {
        self.slow_start_threshold
    }

    /// Returns current congestion-controlled bytes in flight.
    #[must_use]
    pub const fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    /// Returns currently available normal-send capacity.
    #[must_use]
    pub const fn available_window(&self) -> u64 {
        self.congestion_window.saturating_sub(self.bytes_in_flight)
    }

    /// Returns the minimum two-datagram congestion window.
    #[must_use]
    pub fn minimum_window(&self) -> u64 {
        u64::from(self.config.max_datagram_size) * 2
    }

    fn grow_cubic(&mut self, acknowledged: u64, now_micros: u64, rtt: RttEstimator) {
        if self.epoch_started_at_micros.is_none() {
            self.epoch_started_at_micros = Some(now_micros);
            self.epoch_window = self.congestion_window;
            self.estimated_reno_window_fixed =
                u128::from(self.congestion_window) << FIXED_POINT_SHIFT;
            self.cubic_credit_fixed = 0;
        }
        self.update_reno_estimate(acknowledged);
        let epoch = self.epoch_started_at_micros.unwrap_or(now_micros);
        let elapsed = now_micros.saturating_sub(epoch);
        let smoothed_rtt = rtt.effective_smoothed_rtt_micros();
        let cubic_now = self.cubic_window_at(elapsed);
        let cubic_after_rtt = self.cubic_window_at(elapsed.saturating_add(smoothed_rtt));
        let reno_window = fixed_to_u64(self.estimated_reno_window_fixed);
        if cubic_now < reno_window {
            self.congestion_window = self.congestion_window.max(reno_window);
            return;
        }
        let upper = self
            .congestion_window
            .saturating_add(self.congestion_window / 2);
        let target = cubic_after_rtt.clamp(self.congestion_window, upper);
        let difference = target.saturating_sub(self.congestion_window);
        let increment_fixed = u128::from(self.config.max_datagram_size)
            .saturating_mul(u128::from(difference))
            .saturating_mul(FIXED_POINT_ONE)
            / u128::from(self.congestion_window.max(1));
        self.cubic_credit_fixed = self.cubic_credit_fixed.saturating_add(increment_fixed);
        let increment = fixed_to_u64(self.cubic_credit_fixed);
        self.cubic_credit_fixed &= FIXED_POINT_ONE - 1;
        self.congestion_window = self.congestion_window.saturating_add(increment);
    }

    fn update_reno_estimate(&mut self, acknowledged: u64) {
        let current_estimate = fixed_to_u64(self.estimated_reno_window_fixed);
        let (alpha_numerator, alpha_denominator) =
            if current_estimate >= self.congestion_window_prior {
                (1, 1)
            } else {
                (CUBIC_ALPHA_NUMERATOR, CUBIC_ALPHA_DENOMINATOR)
            };
        let increment = u128::from(alpha_numerator)
            .saturating_mul(u128::from(acknowledged))
            .saturating_mul(u128::from(self.config.max_datagram_size))
            .saturating_mul(FIXED_POINT_ONE)
            / u128::from(alpha_denominator)
                .saturating_mul(u128::from(self.congestion_window.max(1)));
        self.estimated_reno_window_fixed =
            self.estimated_reno_window_fixed.saturating_add(increment);
    }

    fn cubic_window_at(&self, elapsed_micros: u64) -> u64 {
        if self.maximum_window == 0 {
            return self.congestion_window;
        }
        let k = cubic_k_micros(
            self.maximum_window,
            self.epoch_window,
            self.config.max_datagram_size,
        );
        let distance = elapsed_micros.abs_diff(k);
        let cubic_term = u128::from(self.config.max_datagram_size)
            .saturating_mul(u128::from(CUBIC_C_NUMERATOR))
            .saturating_mul(u128::from(distance).saturating_pow(3))
            / u128::from(CUBIC_C_DENOMINATOR).saturating_mul(MICROS_PER_SECOND_CUBED);
        let term = u64::try_from(cubic_term).unwrap_or(u64::MAX);
        if elapsed_micros < k {
            self.maximum_window.saturating_sub(term)
        } else {
            self.maximum_window.saturating_add(term)
        }
    }

    fn validate_event_time(
        &self,
        packet_sent_at_micros: u64,
        now_micros: u64,
    ) -> Result<(), CongestionError> {
        if packet_sent_at_micros > now_micros
            || self
                .last_event_at_micros
                .is_some_and(|last| now_micros < last)
        {
            return Err(CongestionError::ClockWentBackwards);
        }
        Ok(())
    }

    fn reset_epoch(&mut self) {
        self.epoch_started_at_micros = None;
        self.epoch_window = self.congestion_window;
        self.estimated_reno_window_fixed = u128::from(self.congestion_window) << FIXED_POINT_SHIFT;
        self.cubic_credit_fixed = 0;
    }

    const fn event_result(
        &self,
        window_reduced: bool,
        persistent_congestion: bool,
    ) -> CongestionEventResult {
        CongestionEventResult {
            window_reduced,
            persistent_congestion,
            congestion_window: self.congestion_window,
        }
    }
}

/// One deterministic pacing decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacingDecision {
    pub send_at_nanos: u64,
    pub queue_delay_nanos: u64,
    pub next_send_at_nanos: u64,
}

/// Scalar nanosecond pacer for individual datagrams or GSO batches.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Pacer {
    next_send_at_nanos: u64,
}

impl Pacer {
    /// Schedules bytes according to the current congestion window and RTT.
    ///
    /// Slow start uses a 5/4 pacing gain; congestion avoidance uses unity.
    ///
    /// # Errors
    ///
    /// Returns an error for zero bytes, zero window, or zero RTT.
    pub fn schedule(
        &mut self,
        now_nanos: u64,
        scheduled_bytes: u32,
        congestion_window: u64,
        smoothed_rtt_micros: u64,
        phase: CongestionPhase,
    ) -> Result<PacingDecision, CongestionError> {
        if scheduled_bytes == 0 || congestion_window == 0 || smoothed_rtt_micros == 0 {
            return Err(CongestionError::InvalidPacingInput);
        }
        let (gain_numerator, gain_denominator) = match phase {
            CongestionPhase::SlowStart => (5_u128, 4_u128),
            CongestionPhase::CongestionAvoidance => (1_u128, 1_u128),
        };
        let numerator = u128::from(scheduled_bytes)
            .saturating_mul(u128::from(smoothed_rtt_micros))
            .saturating_mul(1_000)
            .saturating_mul(gain_denominator);
        let denominator = u128::from(congestion_window).saturating_mul(gain_numerator);
        let spacing = numerator.div_ceil(denominator).max(1);
        let spacing = u64::try_from(spacing).unwrap_or(u64::MAX);
        let send_at_nanos = now_nanos.max(self.next_send_at_nanos);
        self.next_send_at_nanos = send_at_nanos.saturating_add(spacing);
        Ok(PacingDecision {
            send_at_nanos,
            queue_delay_nanos: send_at_nanos - now_nanos,
            next_send_at_nanos: self.next_send_at_nanos,
        })
    }

    /// Clears queued pacing delay after path reset or retirement.
    pub fn reset(&mut self, now_nanos: u64) {
        self.next_send_at_nanos = now_nanos;
    }

    /// Returns the next scheduled departure time.
    #[must_use]
    pub const fn next_send_at_nanos(self) -> u64 {
        self.next_send_at_nanos
    }
}

/// Congestion-control or pacing input failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CongestionError {
    InvalidMaxDatagramSize,
    ZeroPacketSize,
    CongestionWindowExceeded,
    AccountingOverflow,
    AcknowledgementExceedsFlight,
    LossExceedsFlight,
    ClockWentBackwards,
    InvalidPacingInput,
}

impl fmt::Display for CongestionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMaxDatagramSize => {
                formatter.write_str("maximum datagram size is below 1,200 bytes")
            }
            Self::ZeroPacketSize => formatter.write_str("cannot send a zero-byte packet"),
            Self::CongestionWindowExceeded => formatter.write_str("congestion window exceeded"),
            Self::AccountingOverflow => formatter.write_str("congestion accounting overflow"),
            Self::AcknowledgementExceedsFlight => {
                formatter.write_str("acknowledgement exceeds bytes in flight")
            }
            Self::LossExceedsFlight => formatter.write_str("loss exceeds bytes in flight"),
            Self::ClockWentBackwards => formatter.write_str("congestion clock moved backwards"),
            Self::InvalidPacingInput => formatter.write_str("invalid pacing input"),
        }
    }
}

impl std::error::Error for CongestionError {}

fn mul_ratio(value: u64, numerator: u64, denominator: u64) -> u64 {
    let result = u128::from(value).saturating_mul(u128::from(numerator)) / u128::from(denominator);
    u64::try_from(result).unwrap_or(u64::MAX)
}

fn fixed_to_u64(value: u128) -> u64 {
    u64::try_from(value >> FIXED_POINT_SHIFT).unwrap_or(u64::MAX)
}

fn cubic_k_micros(maximum_window: u64, epoch_window: u64, maximum_datagram: u32) -> u64 {
    let difference = maximum_window.saturating_sub(epoch_window);
    if difference == 0 {
        return 0;
    }
    let radicand = u128::from(difference)
        .saturating_mul(u128::from(CUBIC_C_DENOMINATOR))
        .saturating_mul(MICROS_PER_SECOND_CUBED)
        / u128::from(maximum_datagram).saturating_mul(u128::from(CUBIC_C_NUMERATOR));
    integer_cube_root(radicand)
}

fn integer_cube_root(value: u128) -> u64 {
    let mut low = 0_u64;
    let mut high = (1_u64 << 43).min(u64::try_from(value).unwrap_or(u64::MAX));
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        let middle_u128 = u128::from(middle);
        let fits = middle == 0
            || middle_u128 <= value / middle_u128
                && middle_u128 <= value / middle_u128 / middle_u128;
        if fits {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    low
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::{
        ProbeTimeoutState, RecoveryConfig, RecoveryEvent, SentPacket, SentPacketTable,
    };
    use crate::wire::ack::AckFrame;

    fn sampled_rtt(micros: u64) -> RttEstimator {
        let mut rtt = RttEstimator::new(
            RecoveryConfig::new(micros, 0).expect("valid recovery configuration"),
        );
        rtt.record_sample(micros, 0);
        rtt
    }

    #[test]
    fn initial_window_slow_start_and_normal_send_limit_are_bounded() {
        let mut controller = CubicController::new(CubicConfig::default());
        assert_eq!(controller.congestion_window(), 12_000);
        assert_eq!(controller.minimum_window(), 2_400);
        assert_eq!(controller.phase(), CongestionPhase::SlowStart);
        for _ in 0..10 {
            controller
                .on_packet_sent(1_200, false)
                .expect("window permits");
        }
        assert_eq!(
            controller.on_packet_sent(1_200, false),
            Err(CongestionError::CongestionWindowExceeded)
        );
        controller
            .on_packet_sent(1_200, true)
            .expect("PTO probe may exceed cwnd");
        assert_eq!(controller.bytes_in_flight(), 13_200);
    }

    #[test]
    fn slow_start_grows_by_acknowledged_bytes() {
        let mut controller = CubicController::new(CubicConfig::default());
        controller
            .on_packet_sent(1_200, false)
            .expect("packet sends");
        controller
            .on_packet_acknowledged(1_200, 0, 100, sampled_rtt(100))
            .expect("ACK applies");
        assert_eq!(controller.congestion_window(), 13_200);
        assert_eq!(controller.bytes_in_flight(), 0);
    }

    #[test]
    fn one_loss_epoch_reduces_once_and_persistent_loss_collapses_window() {
        let mut controller = CubicController::new(CubicConfig::default());
        for _ in 0..10 {
            controller
                .on_packet_sent(1_200, false)
                .expect("window permits");
        }
        let first = controller
            .on_packet_lost(1_200, 0, 10, false)
            .expect("loss applies");
        assert!(first.window_reduced);
        assert_eq!(controller.congestion_window(), 8_400);
        let second = controller
            .on_packet_lost(1_200, 5, 10, false)
            .expect("same epoch accounting applies");
        assert!(!second.window_reduced);
        assert_eq!(controller.congestion_window(), 8_400);
        let persistent = controller
            .on_packet_lost(1_200, 5, 10, true)
            .expect("persistent congestion applies");
        assert!(persistent.persistent_congestion);
        assert_eq!(controller.congestion_window(), 2_400);
    }

    #[test]
    fn congestion_avoidance_growth_is_ack_clocked_and_bounded() {
        let mut controller = CubicController::new(CubicConfig::default());
        for _ in 0..10 {
            controller
                .on_packet_sent(1_200, false)
                .expect("window permits");
        }
        controller
            .on_packet_lost(1_200, 0, 10, false)
            .expect("loss applies");
        assert_eq!(controller.congestion_window(), 8_400);
        assert_eq!(controller.phase(), CongestionPhase::CongestionAvoidance);
        controller
            .on_packet_acknowledged(1_200, 11, 20, sampled_rtt(10_000))
            .expect("CUBIC ACK applies at the threshold");
        assert!(controller.congestion_window() >= 8_400);
        assert!(controller.congestion_window() < 9_600);
        controller
            .on_packet_acknowledged(1_200, 12, 30, sampled_rtt(10_000))
            .expect("CUBIC ACK applies");
        assert!(controller.congestion_window() >= 8_400);
        assert!(controller.congestion_window() <= 12_600);
        assert_eq!(controller.phase(), CongestionPhase::CongestionAvoidance);
    }

    #[test]
    fn pacer_uses_nanosecond_spacing_and_slow_start_gain() {
        let mut pacer = Pacer::default();
        let first = pacer
            .schedule(0, 1_200, 12_000, 100_000, CongestionPhase::SlowStart)
            .expect("valid pacing input");
        assert_eq!(first.send_at_nanos, 0);
        assert_eq!(first.next_send_at_nanos, 8_000_000);
        let second = pacer
            .schedule(0, 1_200, 12_000, 100_000, CongestionPhase::SlowStart)
            .expect("valid pacing input");
        assert_eq!(second.send_at_nanos, 8_000_000);
        assert_eq!(second.queue_delay_nanos, 8_000_000);
    }

    #[test]
    fn integer_cube_root_is_exact_at_boundaries() {
        assert_eq!(integer_cube_root(0), 0);
        assert_eq!(integer_cube_root(1), 1);
        assert_eq!(integer_cube_root(26), 2);
        assert_eq!(integer_cube_root(27), 3);
        assert_eq!(
            integer_cube_root(u128::from(1_000_000_u64).pow(3)),
            1_000_000
        );
    }

    #[test]
    fn recovery_events_reduce_before_ack_growth_and_reset_pto() {
        let mut controller = CubicController::new(CubicConfig::default());
        let mut recovery = SentPacketTable::with_capacity(8).expect("valid recovery capacity");
        let mut pto = ProbeTimeoutState::default();
        for packet_number in 0..5 {
            let sent_at_micros = packet_number;
            controller
                .on_packet_sent(1_200, false)
                .expect("initial window permits packet");
            recovery
                .record(SentPacket {
                    packet_number,
                    sent_at_micros,
                    encoded_bytes: 1_200,
                    recovery_token: None,
                })
                .expect("recovery slot is available");
            pto.on_ack_eliciting_sent(sent_at_micros)
                .expect("clock advances");
        }

        let mut ack_bytes = [0_u8; 32];
        let ack_length = AckFrame::encode(4, 0, 1, &[], &mut ack_bytes).expect("ACK encodes");
        let ack = AckFrame::decode(&ack_bytes[..ack_length]).expect("ACK decodes");
        let mut rtt = RttEstimator::default();
        let event_rtt = rtt;
        let mut event_kinds = Vec::new();
        let summary = recovery
            .on_ack(ack, 10_000, &mut rtt, |event| match event {
                RecoveryEvent::Lost { packet, .. } => {
                    event_kinds.push("lost");
                    controller
                        .on_packet_lost(packet.encoded_bytes, packet.sent_at_micros, 10_000, false)
                        .expect("loss accounting matches");
                }
                RecoveryEvent::Acknowledged(packet) => {
                    event_kinds.push("acked");
                    controller
                        .on_packet_acknowledged(
                            packet.encoded_bytes,
                            packet.sent_at_micros,
                            10_000,
                            event_rtt,
                        )
                        .expect("ACK accounting matches");
                }
            })
            .expect("recovery ACK applies");
        pto.on_ack(summary.acknowledged_packets != 0);

        assert_eq!(event_kinds, vec!["lost", "lost", "acked"]);
        assert_eq!(controller.congestion_window(), 4_200);
        assert_eq!(controller.bytes_in_flight(), 2_400);
        assert_eq!(pto.backoff_exponent(), 0);
    }
}
