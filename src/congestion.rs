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
pub const HYSTART_MIN_RTT_THRESHOLD_MICROS: u64 = 4_000;
pub const HYSTART_MAX_RTT_THRESHOLD_MICROS: u64 = 16_000;
pub const HYSTART_RTT_THRESHOLD_DIVISOR: u64 = 8;
pub const HYSTART_MIN_RTT_SAMPLES: u8 = 8;
pub const HYSTART_CSS_GROWTH_DIVISOR: u64 = 4;
pub const HYSTART_CSS_ROUNDS: u8 = 5;

const FIXED_POINT_SHIFT: u32 = 32;
const FIXED_POINT_ONE: u128 = 1_u128 << FIXED_POINT_SHIFT;
const MICROS_PER_SECOND_CUBED: u128 = 1_000_000_000_000_000_000;

/// Immutable configuration for one path's congestion controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CubicConfig {
    max_datagram_size: u32,
    fast_convergence: bool,
    hystart_enabled: bool,
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
            hystart_enabled: true,
        })
    }

    /// Enables or disables `HyStart++` for the initial slow start.
    #[must_use]
    pub const fn with_hystart(mut self, enabled: bool) -> Self {
        self.hystart_enabled = enabled;
        self
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

    /// Returns whether RFC 9406 `HyStart++` is enabled.
    #[must_use]
    pub const fn hystart_enabled(self) -> bool {
        self.hystart_enabled
    }
}

impl Default for CubicConfig {
    fn default() -> Self {
        Self {
            max_datagram_size: MIN_MAX_DATAGRAM_SIZE,
            fast_convergence: true,
            hystart_enabled: true,
        }
    }
}

/// Current congestion-control phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CongestionPhase {
    SlowStart,
    ConservativeSlowStart,
    CongestionAvoidance,
}

/// Observable `HyStart++` transition caused by one RTT sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HyStartEvent {
    None,
    EnteredConservativeSlowStart,
    ResumedSlowStart,
    ExitedToCongestionAvoidance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HyStartMode {
    Disabled,
    Standard,
    Conservative,
    Complete,
}

/// Allocation-free RFC 9406 round and delay detector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HyStartState {
    mode: HyStartMode,
    round_end_packet_number: Option<u64>,
    last_round_min_rtt_micros: Option<u64>,
    current_round_min_rtt_micros: Option<u64>,
    rtt_sample_count: u8,
    css_baseline_min_rtt_micros: Option<u64>,
    css_rounds: u8,
}

impl HyStartState {
    const fn new(enabled: bool) -> Self {
        Self {
            mode: if enabled {
                HyStartMode::Standard
            } else {
                HyStartMode::Disabled
            },
            round_end_packet_number: None,
            last_round_min_rtt_micros: None,
            current_round_min_rtt_micros: None,
            rtt_sample_count: 0,
            css_baseline_min_rtt_micros: None,
            css_rounds: 0,
        }
    }

    fn observe_rtt(
        &mut self,
        acknowledged_packet_number: u64,
        largest_sent_packet_number: u64,
        raw_rtt_micros: u64,
    ) -> Result<HyStartEvent, CongestionError> {
        if raw_rtt_micros == 0 {
            return Err(CongestionError::InvalidRttSample);
        }
        if acknowledged_packet_number > largest_sent_packet_number {
            return Err(CongestionError::AcknowledgementExceedsLargestSent);
        }
        if matches!(self.mode, HyStartMode::Disabled | HyStartMode::Complete) {
            return Ok(HyStartEvent::None);
        }

        if let Some(round_end) = self.round_end_packet_number {
            if acknowledged_packet_number > round_end {
                if self.mode == HyStartMode::Conservative {
                    if self.css_rounds >= HYSTART_CSS_ROUNDS {
                        self.mode = HyStartMode::Complete;
                        return Ok(HyStartEvent::ExitedToCongestionAvoidance);
                    }
                    self.css_rounds = self.css_rounds.saturating_add(1);
                }
                self.last_round_min_rtt_micros = self.current_round_min_rtt_micros;
                self.current_round_min_rtt_micros = None;
                self.rtt_sample_count = 0;
                self.round_end_packet_number = Some(largest_sent_packet_number);
            }
        } else {
            self.round_end_packet_number = Some(largest_sent_packet_number);
        }

        self.current_round_min_rtt_micros = Some(
            self.current_round_min_rtt_micros
                .map_or(raw_rtt_micros, |minimum| minimum.min(raw_rtt_micros)),
        );
        self.rtt_sample_count = self.rtt_sample_count.saturating_add(1);
        if self.rtt_sample_count < HYSTART_MIN_RTT_SAMPLES {
            return Ok(HyStartEvent::None);
        }

        match self.mode {
            HyStartMode::Standard => {
                let (Some(last_minimum), Some(current_minimum)) = (
                    self.last_round_min_rtt_micros,
                    self.current_round_min_rtt_micros,
                ) else {
                    return Ok(HyStartEvent::None);
                };
                let threshold = (last_minimum / HYSTART_RTT_THRESHOLD_DIVISOR).clamp(
                    HYSTART_MIN_RTT_THRESHOLD_MICROS,
                    HYSTART_MAX_RTT_THRESHOLD_MICROS,
                );
                if current_minimum >= last_minimum.saturating_add(threshold) {
                    self.mode = HyStartMode::Conservative;
                    self.css_baseline_min_rtt_micros = Some(current_minimum);
                    self.css_rounds = 1;
                    return Ok(HyStartEvent::EnteredConservativeSlowStart);
                }
            }
            HyStartMode::Conservative => {
                if let (Some(current_minimum), Some(baseline)) = (
                    self.current_round_min_rtt_micros,
                    self.css_baseline_min_rtt_micros,
                ) && current_minimum < baseline
                {
                    self.mode = HyStartMode::Standard;
                    self.css_baseline_min_rtt_micros = None;
                    self.css_rounds = 0;
                    return Ok(HyStartEvent::ResumedSlowStart);
                }
            }
            HyStartMode::Disabled | HyStartMode::Complete => {}
        }
        Ok(HyStartEvent::None)
    }

    fn on_congestion_signal(&mut self) {
        if matches!(self.mode, HyStartMode::Standard | HyStartMode::Conservative) {
            self.mode = HyStartMode::Complete;
        }
    }
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
    hystart: HyStartState,
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
            hystart: HyStartState::new(config.hystart_enabled),
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
        match self.phase() {
            CongestionPhase::SlowStart => {
                self.congestion_window = self.congestion_window.saturating_add(acknowledged);
            }
            CongestionPhase::ConservativeSlowStart => {
                self.congestion_window = self
                    .congestion_window
                    .saturating_add(acknowledged / HYSTART_CSS_GROWTH_DIVISOR);
            }
            CongestionPhase::CongestionAvoidance => {
                self.grow_cubic(acknowledged, now_micros, rtt);
            }
        }
        Ok(())
    }

    /// Feeds one newly measured raw RTT sample to `HyStart++`.
    ///
    /// Recovery supplies at most one sample per authenticated ACK. Packet
    /// numbers delimit rounds without retaining a packet history. On the CSS
    /// completion event, this method sets the slow-start threshold to the
    /// current congestion window and begins CUBIC congestion avoidance.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero RTT sample or an acknowledged packet number
    /// above the largest packet sent on this path.
    pub fn on_rtt_sample(
        &mut self,
        acknowledged_packet_number: u64,
        largest_sent_packet_number: u64,
        raw_rtt_micros: u64,
    ) -> Result<HyStartEvent, CongestionError> {
        let event = self.hystart.observe_rtt(
            acknowledged_packet_number,
            largest_sent_packet_number,
            raw_rtt_micros,
        )?;
        if event == HyStartEvent::ExitedToCongestionAvoidance {
            self.slow_start_threshold = self.congestion_window;
            self.reset_epoch();
        }
        Ok(event)
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
        Ok(self.apply_congestion_event(
            packet_sent_at_micros,
            now_micros,
            persistent_congestion,
            flight_before_loss,
        ))
    }

    /// Applies one validated increase in the peer's cumulative CE counter.
    ///
    /// This method is called from the recovery ACK-preview event, before lost
    /// and acknowledged bytes are released. CE is equivalent to an ordinary
    /// congestion event and can reduce the window at most once per recovery
    /// epoch; it does not remove bytes from flight.
    ///
    /// # Errors
    ///
    /// Returns an error for clock regression or when no bytes are in flight.
    pub fn on_ecn_ce(
        &mut self,
        triggering_packet_sent_at_micros: u64,
        now_micros: u64,
    ) -> Result<CongestionEventResult, CongestionError> {
        self.validate_event_time(triggering_packet_sent_at_micros, now_micros)?;
        if self.bytes_in_flight == 0 {
            return Err(CongestionError::EcnWithoutFlight);
        }
        let flight_before_ack = self.bytes_in_flight;
        self.last_event_at_micros = Some(now_micros);
        Ok(self.apply_congestion_event(
            triggering_packet_sent_at_micros,
            now_micros,
            false,
            flight_before_ack,
        ))
    }

    fn apply_congestion_event(
        &mut self,
        triggering_packet_sent_at_micros: u64,
        now_micros: u64,
        persistent_congestion: bool,
        flight_before_event: u64,
    ) -> CongestionEventResult {
        self.hystart.on_congestion_signal();
        let in_current_recovery = self
            .recovery_started_at_micros
            .is_some_and(|recovery| triggering_packet_sent_at_micros <= recovery);
        if in_current_recovery && !persistent_congestion {
            return self.event_result(false, false);
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
        let validated_flight = flight_before_event.min(self.congestion_window);
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
        self.event_result(true, persistent_congestion)
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
            match self.hystart.mode {
                HyStartMode::Conservative => CongestionPhase::ConservativeSlowStart,
                HyStartMode::Disabled | HyStartMode::Standard | HyStartMode::Complete => {
                    CongestionPhase::SlowStart
                }
            }
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
            CongestionPhase::SlowStart | CongestionPhase::ConservativeSlowStart => (5_u128, 4_u128),
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
    InvalidRttSample,
    AcknowledgementExceedsLargestSent,
    EcnWithoutFlight,
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
            Self::InvalidRttSample => formatter.write_str("RTT sample must be non-zero"),
            Self::AcknowledgementExceedsLargestSent => {
                formatter.write_str("acknowledged packet exceeds largest packet sent")
            }
            Self::EcnWithoutFlight => {
                formatter.write_str("ECN congestion event has no bytes in flight")
            }
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
    use crate::ecn::{EcnCodepoint, EcnCounts, EcnState, EcnValidationResult, EcnValidator};
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

    fn feed_hystart_round(
        controller: &mut CubicController,
        first_packet: u64,
        last_packet: u64,
        raw_rtt_micros: u64,
    ) -> HyStartEvent {
        let mut event = HyStartEvent::None;
        for packet_number in first_packet..=last_packet {
            event = controller
                .on_rtt_sample(packet_number, last_packet, raw_rtt_micros)
                .expect("valid HyStart++ sample");
        }
        event
    }

    #[test]
    fn initial_window_slow_start_and_normal_send_limit_are_bounded() {
        let mut controller = CubicController::new(CubicConfig::default());
        assert_eq!(controller.congestion_window(), 12_000);
        assert_eq!(controller.minimum_window(), 2_400);
        assert_eq!(controller.phase(), CongestionPhase::SlowStart);
        assert!(CubicConfig::default().hystart_enabled());
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
    fn validated_ecn_ce_reduces_once_without_releasing_flight() {
        let mut controller = CubicController::new(CubicConfig::default());
        for _ in 0..10 {
            controller
                .on_packet_sent(1_200, false)
                .expect("initial window permits packet");
        }
        let first = controller
            .on_ecn_ce(0, 10)
            .expect("validated CE signal applies");
        assert!(first.window_reduced);
        assert_eq!(controller.congestion_window(), 8_400);
        assert_eq!(controller.bytes_in_flight(), 12_000);

        let repeated = controller
            .on_ecn_ce(5, 10)
            .expect("same recovery epoch is ignored");
        assert!(!repeated.window_reduced);
        assert_eq!(controller.congestion_window(), 8_400);
        assert_eq!(controller.bytes_in_flight(), 12_000);
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
    fn hystart_enters_css_after_a_sustained_delay_increase() {
        let mut controller = CubicController::new(CubicConfig::default());
        assert_eq!(
            feed_hystart_round(&mut controller, 0, 7, 10_000),
            HyStartEvent::None
        );
        assert_eq!(
            feed_hystart_round(&mut controller, 8, 15, 15_000),
            HyStartEvent::EnteredConservativeSlowStart
        );
        assert_eq!(controller.phase(), CongestionPhase::ConservativeSlowStart);

        controller
            .on_packet_sent(1_200, false)
            .expect("initial window permits packet");
        controller
            .on_packet_acknowledged(1_200, 0, 1, sampled_rtt(10_000))
            .expect("CSS acknowledgement applies");
        assert_eq!(controller.congestion_window(), 12_300);
    }

    #[test]
    fn hystart_resumes_standard_slow_start_when_delay_spike_clears() {
        let mut controller = CubicController::new(CubicConfig::default());
        feed_hystart_round(&mut controller, 0, 7, 10_000);
        feed_hystart_round(&mut controller, 8, 15, 15_000);
        assert_eq!(
            feed_hystart_round(&mut controller, 16, 23, 9_000),
            HyStartEvent::ResumedSlowStart
        );
        assert_eq!(controller.phase(), CongestionPhase::SlowStart);
    }

    #[test]
    fn hystart_exits_to_cubic_after_five_css_rounds() {
        let mut controller = CubicController::new(CubicConfig::default());
        feed_hystart_round(&mut controller, 0, 7, 10_000);
        feed_hystart_round(&mut controller, 8, 15, 15_000);

        assert_eq!(
            controller.on_rtt_sample(16, 23, 15_000),
            Ok(HyStartEvent::None)
        );
        assert_eq!(
            controller.on_rtt_sample(24, 31, 15_000),
            Ok(HyStartEvent::None)
        );
        assert_eq!(
            controller.on_rtt_sample(32, 39, 15_000),
            Ok(HyStartEvent::None)
        );
        assert_eq!(
            controller.on_rtt_sample(40, 47, 15_000),
            Ok(HyStartEvent::None)
        );
        assert_eq!(
            controller.on_rtt_sample(48, 55, 15_000),
            Ok(HyStartEvent::ExitedToCongestionAvoidance)
        );
        assert_eq!(
            controller.slow_start_threshold(),
            controller.congestion_window()
        );
        assert_eq!(controller.phase(), CongestionPhase::CongestionAvoidance);
    }

    #[test]
    fn hystart_can_be_disabled_and_rejects_invalid_samples() {
        let config = CubicConfig::default().with_hystart(false);
        assert!(!config.hystart_enabled());
        let mut controller = CubicController::new(config);
        assert_eq!(
            feed_hystart_round(&mut controller, 0, 7, 10_000),
            HyStartEvent::None
        );
        assert_eq!(controller.phase(), CongestionPhase::SlowStart);
        assert_eq!(
            controller.on_rtt_sample(0, 0, 0),
            Err(CongestionError::InvalidRttSample)
        );
        assert_eq!(
            controller.on_rtt_sample(1, 0, 10_000),
            Err(CongestionError::AcknowledgementExceedsLargestSent)
        );
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
                    ecn_codepoint: crate::ecn::EcnCodepoint::NotEct,
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
                RecoveryEvent::AckPreview(_) => {}
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
        controller
            .on_rtt_sample(
                summary
                    .largest_newly_acknowledged
                    .expect("ACK releases a packet"),
                recovery.largest_sent().expect("packets were sent"),
                summary.raw_rtt_sample_micros.expect("ACK samples RTT"),
            )
            .expect("HyStart++ observes the ACK sample");
        pto.on_ack(summary.acknowledged_packets != 0);

        assert_eq!(event_kinds, vec!["lost", "lost", "acked"]);
        assert_eq!(controller.congestion_window(), 4_200);
        assert_eq!(controller.bytes_in_flight(), 2_400);
        assert_eq!(pto.backoff_exponent(), 0);
    }

    #[test]
    fn authenticated_ecn_preview_reduces_before_ack_events() {
        let mut controller = CubicController::new(CubicConfig::default());
        let mut recovery = SentPacketTable::with_capacity(8).expect("valid recovery capacity");
        let mut ecn = EcnValidator::new(true);
        for packet_number in 0..5 {
            let codepoint = ecn.outgoing_codepoint();
            assert_eq!(codepoint, EcnCodepoint::Ect0);
            ecn.on_packet_sent(codepoint)
                .expect("ECT(0) probe is permitted");
            controller
                .on_packet_sent(1_200, false)
                .expect("initial window permits packet");
            recovery
                .record(SentPacket {
                    packet_number,
                    sent_at_micros: packet_number,
                    encoded_bytes: 1_200,
                    ecn_codepoint: codepoint,
                    recovery_token: None,
                })
                .expect("recovery slot is available");
        }

        let counts = EcnCounts {
            ect0: 4,
            ect1: 0,
            ce: 1,
        };
        let mut ack_bytes = [0_u8; 64];
        let ack_length = AckFrame::encode_with_ecn(4, 0, 5, &[], Some(counts), &mut ack_bytes)
            .expect("ECN ACK encodes");
        let ack = AckFrame::decode(&ack_bytes[..ack_length]).expect("ECN ACK decodes");
        let mut rtt = RttEstimator::default();
        let event_rtt = rtt;
        let mut event_kinds = Vec::new();
        let summary = recovery
            .on_ack(ack, 10_000, &mut rtt, |event| match event {
                RecoveryEvent::AckPreview(preview) => {
                    event_kinds.push("preview");
                    let result = ecn.validate_ack(
                        preview
                            .largest_newly_acknowledged
                            .expect("ACK releases marked packets"),
                        preview.acknowledged_ect0_packets,
                        preview.acknowledged_ect1_packets,
                        preview.peer_ecn_counts,
                    );
                    assert_eq!(result, EcnValidationResult::Validated { ce_increase: 1 });
                    controller
                        .on_ecn_ce(
                            preview
                                .largest_newly_acknowledged_sent_at_micros
                                .expect("preview retains trigger send time"),
                            10_000,
                        )
                        .expect("validated CE enters recovery");
                }
                RecoveryEvent::Lost { .. } => event_kinds.push("lost"),
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
            .expect("ECN ACK applies");

        assert_eq!(
            event_kinds,
            vec!["preview", "acked", "acked", "acked", "acked", "acked"]
        );
        assert_eq!(summary.acknowledged_ect0_packets, 5);
        assert_eq!(ecn.state(), EcnState::Capable);
        assert_eq!(controller.congestion_window(), 4_200);
        assert_eq!(controller.bytes_in_flight(), 0);
    }
}
