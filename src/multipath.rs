//! Allocation-free linked-increases coupling for concurrent paths.
//!
//! The integer equations are based on the Experimental LIA algorithm in
//! RFC 6356. OGTP applies the result as an upper bound on CUBIC growth, so
//! this module is an experimental conservative adaptation rather than an
//! implementation of the RFC's Reno controller.

use core::fmt;

use crate::congestion::MIN_MAX_DATAGRAM_SIZE;

/// Maximum number of paths that may participate in one coupled calculation.
pub const MAX_COUPLED_PATHS: usize = 16;

/// Integer precision recommended by RFC 6356 for the LIA alpha calculation.
pub const LIA_ALPHA_SCALE: u128 = 512;

const CREDIT_SHIFT: u32 = 32;
const CREDIT_ONE: u128 = 1_u128 << CREDIT_SHIFT;
const CREDIT_MASK: u128 = CREDIT_ONE - 1;

/// Borrowed per-path inputs to one linked-increases calculation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoupledPathState {
    /// Stable identifier within the connection.
    pub path_id: u8,
    /// Whether the path is eligible to participate.
    pub active: bool,
    /// Current congestion window in bytes.
    pub congestion_window: u64,
    /// Current congestion-controlled flight in bytes.
    pub bytes_in_flight: u64,
    /// Current slow-start threshold in bytes.
    pub slow_start_threshold: u64,
    /// Smoothed round-trip time in microseconds.
    pub smoothed_rtt_micros: u64,
    /// Maximum UDP payload currently usable on this path.
    pub max_datagram_size: u32,
    /// Whether recovery requires substituting the slow-start threshold.
    pub in_recovery: bool,
    /// Whether flight, rather than the window, limits the sender.
    pub application_limited: bool,
}

impl CoupledPathState {
    /// Returns the window that participates in LIA's aggregate calculations.
    ///
    /// Recovery substitutes `ssthresh` for an inflated congestion window.
    /// Application-limited paths contribute no more than their actual flight.
    #[must_use]
    pub const fn effective_window(self) -> u64 {
        let recovery_window = if self.in_recovery {
            if self.congestion_window < self.slow_start_threshold {
                self.congestion_window
            } else {
                self.slow_start_threshold
            }
        } else {
            self.congestion_window
        };
        if self.application_limited && self.bytes_in_flight < recovery_window {
            self.bytes_in_flight
        } else {
            recovery_window
        }
    }
}

/// Observable result of one linked-increases calculation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiaDecision {
    /// Whole bytes by which the acknowledged path may grow on this ACK.
    pub growth_limit_bytes: u64,
    /// RFC 6356 alpha multiplied by [`LIA_ALPHA_SCALE`].
    pub alpha_scaled: u128,
    /// Sum of all participating effective congestion windows.
    pub aggregate_window: u64,
    /// Effective window of the acknowledged path.
    pub acknowledged_path_window: u64,
    /// Path selected by the `cwnd / RTT^2` maximum in the alpha numerator.
    pub reference_path_id: u8,
    /// Number of paths with non-zero effective windows.
    pub participating_paths: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LiaCredit {
    path_id: u8,
    occupied: bool,
    fractional_q32: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LiaInputs {
    alpha_scaled: u128,
    aggregate_window: u64,
    acknowledged_window: u64,
    acknowledged_mds: u32,
    reference_path_id: u8,
    participating_paths: u8,
}

impl LiaCredit {
    const EMPTY: Self = Self {
        path_id: 0,
        occupied: false,
        fractional_q32: 0,
    };
}

/// Fixed-capacity per-connection LIA state.
///
/// The caller owns path controllers and supplies a borrowed snapshot on each
/// ACK. This object retains only sub-byte Q32 growth credits and never
/// allocates.
#[derive(Debug)]
pub struct LiaCoupler {
    credits: [LiaCredit; MAX_COUPLED_PATHS],
}

impl LiaCoupler {
    /// Creates an empty linked-increases coupler.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            credits: [LiaCredit::EMPTY; MAX_COUPLED_PATHS],
        }
    }

    /// Calculates and accounts the growth limit for one newly acknowledged ACK.
    ///
    /// Active paths with a zero effective window are omitted. Every other
    /// active path must have a valid RTT, congestion window, and datagram size.
    /// Fractional growth carries between ACKs independently for each path.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or oversized path set, duplicate active
    /// identifiers, an unavailable acknowledged path, invalid state, or any
    /// integer overflow. A path identifier must be retired before more than 16
    /// distinct identifiers consume credit slots.
    pub fn ack_growth_limit(
        &mut self,
        acknowledged_path_id: u8,
        acknowledged_bytes: u32,
        paths: &[CoupledPathState],
    ) -> Result<LiaDecision, MultipathError> {
        if acknowledged_bytes == 0 {
            return Err(MultipathError::ZeroAcknowledgedBytes);
        }
        let inputs = calculate_lia_inputs(acknowledged_path_id, paths)?;

        let acked = u128::from(acknowledged_bytes);
        let mds = u128::from(inputs.acknowledged_mds);
        let linked_numerator = checked_mul(
            checked_mul(checked_mul(inputs.alpha_scaled, acked)?, mds)?,
            CREDIT_ONE,
        )?;
        let linked_denominator = checked_mul(LIA_ALPHA_SCALE, u128::from(inputs.aggregate_window))?;
        let linked_growth_q32 = linked_numerator / linked_denominator;

        let reno_numerator = checked_mul(checked_mul(acked, mds)?, CREDIT_ONE)?;
        let reno_growth_q32 = reno_numerator / u128::from(inputs.acknowledged_window);
        let permitted_q32 = linked_growth_q32.min(reno_growth_q32);

        let credit = self.credit_for_path(acknowledged_path_id)?;
        let accumulated_q32 = permitted_q32
            .checked_add(u128::from(credit.fractional_q32))
            .ok_or(MultipathError::ArithmeticOverflow)?;
        let growth_limit_bytes = u64::try_from(accumulated_q32 >> CREDIT_SHIFT)
            .map_err(|_| MultipathError::ArithmeticOverflow)?;
        credit.fractional_q32 = u64::try_from(accumulated_q32 & CREDIT_MASK)
            .map_err(|_| MultipathError::ArithmeticOverflow)?;

        Ok(LiaDecision {
            growth_limit_bytes,
            alpha_scaled: inputs.alpha_scaled,
            aggregate_window: inputs.aggregate_window,
            acknowledged_path_window: inputs.acknowledged_window,
            reference_path_id: inputs.reference_path_id,
            participating_paths: inputs.participating_paths,
        })
    }

    /// Removes any fractional credit retained for a retired path identifier.
    ///
    /// Returns `true` when a slot was cleared.
    pub fn retire_path(&mut self, path_id: u8) -> bool {
        if let Some(credit) = self
            .credits
            .iter_mut()
            .find(|credit| credit.occupied && credit.path_id == path_id)
        {
            *credit = LiaCredit::EMPTY;
            true
        } else {
            false
        }
    }

    fn credit_for_path(&mut self, path_id: u8) -> Result<&mut LiaCredit, MultipathError> {
        if let Some(index) = self
            .credits
            .iter()
            .position(|credit| credit.occupied && credit.path_id == path_id)
        {
            return Ok(&mut self.credits[index]);
        }
        let credit = self
            .credits
            .iter_mut()
            .find(|credit| !credit.occupied)
            .ok_or(MultipathError::CreditSlotsExhausted)?;
        credit.path_id = path_id;
        credit.occupied = true;
        credit.fractional_q32 = 0;
        Ok(credit)
    }
}

fn calculate_lia_inputs(
    acknowledged_path_id: u8,
    paths: &[CoupledPathState],
) -> Result<LiaInputs, MultipathError> {
    if paths.is_empty() {
        return Err(MultipathError::EmptyPathSet);
    }
    if paths.len() > MAX_COUPLED_PATHS {
        return Err(MultipathError::TooManyPaths);
    }

    let mut aggregate_window = 0_u64;
    let mut participating_paths = 0_u8;
    let mut reference: Option<(u8, u64, u64)> = None;
    let mut acknowledged: Option<(u64, u32)> = None;
    for (index, path) in paths.iter().copied().enumerate() {
        if !path.active {
            continue;
        }
        validate_unique_path(path, &paths[..index])?;
        let window = path.effective_window();
        if window == 0 {
            continue;
        }
        aggregate_window = aggregate_window
            .checked_add(window)
            .ok_or(MultipathError::ArithmeticOverflow)?;
        participating_paths = participating_paths
            .checked_add(1)
            .ok_or(MultipathError::ArithmeticOverflow)?;
        if path.path_id == acknowledged_path_id {
            acknowledged = Some((window, path.max_datagram_size));
        }
        match reference {
            None => reference = Some((path.path_id, window, path.smoothed_rtt_micros)),
            Some((_, best_window, best_rtt))
                if path_ratio_is_greater(
                    window,
                    path.smoothed_rtt_micros,
                    best_window,
                    best_rtt,
                )? =>
            {
                reference = Some((path.path_id, window, path.smoothed_rtt_micros));
            }
            Some(_) => {}
        }
    }

    let (acknowledged_window, acknowledged_mds) =
        acknowledged.ok_or(MultipathError::AckPathUnavailable)?;
    let (reference_path_id, reference_window, reference_rtt) =
        reference.ok_or(MultipathError::AckPathUnavailable)?;
    let mut normalized_sum = 0_u128;
    for path in paths.iter().copied().filter(|path| path.active) {
        let window = path.effective_window();
        if window != 0 {
            let normalized = checked_mul(u128::from(reference_rtt), u128::from(window))?
                / u128::from(path.smoothed_rtt_micros);
            normalized_sum = normalized_sum
                .checked_add(normalized)
                .ok_or(MultipathError::ArithmeticOverflow)?;
        }
    }
    let normalized_square = checked_mul(normalized_sum, normalized_sum)?;
    if normalized_square == 0 {
        return Err(MultipathError::ArithmeticOverflow);
    }
    let alpha_numerator = checked_mul(
        checked_mul(LIA_ALPHA_SCALE, u128::from(aggregate_window))?,
        u128::from(reference_window),
    )?;
    Ok(LiaInputs {
        alpha_scaled: alpha_numerator / normalized_square,
        aggregate_window,
        acknowledged_window,
        acknowledged_mds,
        reference_path_id,
        participating_paths,
    })
}

fn validate_unique_path(
    path: CoupledPathState,
    preceding_paths: &[CoupledPathState],
) -> Result<(), MultipathError> {
    if preceding_paths
        .iter()
        .any(|candidate| candidate.active && candidate.path_id == path.path_id)
    {
        return Err(MultipathError::DuplicatePathId(path.path_id));
    }
    if path.congestion_window == 0
        || path.smoothed_rtt_micros == 0
        || path.max_datagram_size < MIN_MAX_DATAGRAM_SIZE
    {
        return Err(MultipathError::InvalidPathState(path.path_id));
    }
    Ok(())
}

impl Default for LiaCoupler {
    fn default() -> Self {
        Self::new()
    }
}

fn path_ratio_is_greater(
    candidate_window: u64,
    candidate_rtt: u64,
    current_window: u64,
    current_rtt: u64,
) -> Result<bool, MultipathError> {
    let candidate_side = checked_mul(
        u128::from(candidate_window),
        checked_mul(u128::from(current_rtt), u128::from(current_rtt))?,
    )?;
    let current_side = checked_mul(
        u128::from(current_window),
        checked_mul(u128::from(candidate_rtt), u128::from(candidate_rtt))?,
    )?;
    Ok(candidate_side > current_side)
}

fn checked_mul(left: u128, right: u128) -> Result<u128, MultipathError> {
    left.checked_mul(right)
        .ok_or(MultipathError::ArithmeticOverflow)
}

/// Invalid multipath coupling input or bounded-state exhaustion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MultipathError {
    EmptyPathSet,
    TooManyPaths,
    DuplicatePathId(u8),
    AckPathUnavailable,
    InvalidPathState(u8),
    ZeroAcknowledgedBytes,
    ArithmeticOverflow,
    CreditSlotsExhausted,
}

impl fmt::Display for MultipathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPathSet => formatter.write_str("coupled path set is empty"),
            Self::TooManyPaths => formatter.write_str("coupled path set exceeds 16 paths"),
            Self::DuplicatePathId(path_id) => {
                write!(formatter, "duplicate active path identifier {path_id}")
            }
            Self::AckPathUnavailable => {
                formatter.write_str("acknowledged path has no effective window")
            }
            Self::InvalidPathState(path_id) => {
                write!(formatter, "invalid congestion state for path {path_id}")
            }
            Self::ZeroAcknowledgedBytes => {
                formatter.write_str("newly acknowledged byte count is zero")
            }
            Self::ArithmeticOverflow => {
                formatter.write_str("multipath coupling arithmetic overflow")
            }
            Self::CreditSlotsExhausted => {
                formatter.write_str("all multipath credit slots are occupied")
            }
        }
    }
}

impl std::error::Error for MultipathError {}

#[cfg(test)]
mod tests {
    use super::*;

    const fn path(path_id: u8) -> CoupledPathState {
        CoupledPathState {
            path_id,
            active: true,
            congestion_window: 12_000,
            bytes_in_flight: 12_000,
            slow_start_threshold: 12_000,
            smoothed_rtt_micros: 100_000,
            max_datagram_size: 1_200,
            in_recovery: false,
            application_limited: false,
        }
    }

    #[test]
    fn equal_paths_have_half_scaled_alpha_and_thirty_byte_growth() {
        let mut coupler = LiaCoupler::new();
        let decision = coupler
            .ack_growth_limit(0, 1_200, &[path(0), path(1)])
            .expect("equal path snapshot is valid");

        assert_eq!(decision.alpha_scaled, 256);
        assert_eq!(decision.aggregate_window, 24_000);
        assert_eq!(decision.acknowledged_path_window, 12_000);
        assert_eq!(decision.growth_limit_bytes, 30);
        assert_eq!(decision.reference_path_id, 0);
        assert_eq!(decision.participating_paths, 2);
    }

    #[test]
    fn one_path_reduces_to_reno_growth() {
        let mut coupler = LiaCoupler::new();
        let decision = coupler
            .ack_growth_limit(7, 1_200, &[path(7)])
            .expect("single path snapshot is valid");

        assert_eq!(decision.alpha_scaled, LIA_ALPHA_SCALE);
        assert_eq!(decision.growth_limit_bytes, 120);
        assert_eq!(decision.participating_paths, 1);
    }

    #[test]
    fn lower_rtt_path_is_the_deterministic_alpha_reference() {
        let slower = path(0);
        let mut faster = path(1);
        faster.smoothed_rtt_micros = 50_000;

        let decision = LiaCoupler::new()
            .ack_growth_limit(1, 1_200, &[slower, faster])
            .expect("unequal RTT snapshot is valid");

        assert_eq!(decision.reference_path_id, 1);
        assert_eq!(decision.alpha_scaled, 455);
        assert_eq!(decision.growth_limit_bytes, 53);
    }

    #[test]
    fn application_limited_and_recovery_windows_are_effective() {
        let mut limited = path(0);
        limited.application_limited = true;
        limited.bytes_in_flight = 6_000;
        let mut recovering = path(1);
        recovering.congestion_window = 14_000;
        recovering.slow_start_threshold = 8_000;
        recovering.in_recovery = true;

        let decision = LiaCoupler::new()
            .ack_growth_limit(0, 1_200, &[limited, recovering])
            .expect("effective windows are valid");

        assert_eq!(limited.effective_window(), 6_000);
        assert_eq!(recovering.effective_window(), 8_000);
        assert_eq!(decision.aggregate_window, 14_000);
        assert_eq!(decision.acknowledged_path_window, 6_000);
    }

    #[test]
    fn invalid_snapshots_fail_closed() {
        let mut coupler = LiaCoupler::new();
        assert_eq!(
            coupler.ack_growth_limit(0, 1_200, &[]),
            Err(MultipathError::EmptyPathSet)
        );
        assert_eq!(
            coupler.ack_growth_limit(0, 1_200, &[path(0), path(0)]),
            Err(MultipathError::DuplicatePathId(0))
        );
        let mut invalid_rtt = path(0);
        invalid_rtt.smoothed_rtt_micros = 0;
        assert_eq!(
            coupler.ack_growth_limit(0, 1_200, &[invalid_rtt]),
            Err(MultipathError::InvalidPathState(0))
        );
        let too_many = [path(0); MAX_COUPLED_PATHS + 1];
        assert_eq!(
            coupler.ack_growth_limit(0, 1_200, &too_many),
            Err(MultipathError::TooManyPaths)
        );
    }

    #[test]
    fn fractional_credit_is_path_local_and_retirable() {
        let mut coupler = LiaCoupler::new();
        let first = coupler
            .ack_growth_limit(0, 3, &[path(0)])
            .expect("fractional growth is valid");
        let second = coupler
            .ack_growth_limit(0, 3, &[path(0)])
            .expect("fractional growth accumulates");
        assert_eq!(first.growth_limit_bytes, 0);
        assert_eq!(second.growth_limit_bytes, 0);
        assert!(coupler.retire_path(0));
        assert!(!coupler.retire_path(0));
        assert_eq!(
            coupler
                .ack_growth_limit(0, 3, &[path(0)])
                .expect("retired path can be reused")
                .growth_limit_bytes,
            0
        );
    }

    #[test]
    fn credit_capacity_requires_explicit_path_retirement() {
        let mut coupler = LiaCoupler::new();
        for path_id in 0_u8..u8::try_from(MAX_COUPLED_PATHS).expect("capacity fits") {
            coupler
                .ack_growth_limit(path_id, 1_200, &[path(path_id)])
                .expect("credit slot is available");
        }
        let replacement_id = u8::try_from(MAX_COUPLED_PATHS).expect("capacity fits");
        assert_eq!(
            coupler.ack_growth_limit(replacement_id, 1_200, &[path(replacement_id)]),
            Err(MultipathError::CreditSlotsExhausted)
        );
        assert!(coupler.retire_path(0));
        assert!(
            coupler
                .ack_growth_limit(replacement_id, 1_200, &[path(replacement_id)])
                .is_ok()
        );
    }
}
