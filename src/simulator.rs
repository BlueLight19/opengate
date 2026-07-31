//! Deterministic packet-network simulator for protocol testing.
//!
//! This module is intentionally outside the production data path. It is built
//! for unit tests or when the `simulator` feature is explicitly enabled.

use core::fmt;
use core::num::NonZeroU64;

/// Deterministic latency and periodic fault pattern for one path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PathProfile {
    /// Normal one-way delivery latency in logical ticks.
    pub base_delay_ticks: u64,
    /// Drop every Nth enabled transmission.
    pub drop_every: Option<NonZeroU64>,
    /// Duplicate every Nth enabled transmission.
    pub duplicate_every: Option<NonZeroU64>,
    /// Delay every Nth enabled transmission to cause deterministic reordering.
    pub reorder_every: Option<NonZeroU64>,
    /// Extra latency added to a selected reordered transmission.
    pub reorder_delay_ticks: u64,
    /// Extra latency for the second copy of a duplicated transmission.
    pub duplicate_delay_ticks: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PathState {
    id: u8,
    profile: PathProfile,
    enabled: bool,
    transmissions: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Scheduled<T> {
    delivery_tick: u64,
    insertion_order: u64,
    path_id: u8,
    sequence: u64,
    duplicate: bool,
    payload: T,
}

/// Result of injecting one logical packet into a simulated path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendOutcome {
    /// One or two deliveries were queued.
    Scheduled { sequence: u64, copies: u8 },
    /// The path was administratively disabled.
    Disabled { sequence: u64 },
    /// The path's periodic loss rule selected this transmission.
    Dropped { sequence: u64 },
}

/// One packet copy delivered by the simulated network.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Delivery<T> {
    pub delivery_tick: u64,
    pub path_id: u8,
    pub sequence: u64,
    pub duplicate: bool,
    pub payload: T,
}

/// A deterministic, logical-clock network with independent path faults.
///
/// The queue deliberately uses ordinary allocations and a linear minimum scan:
/// simulator behavior is transparent and reproducible, while no simulator code
/// is present in a default production build.
#[derive(Clone, Debug, Default)]
pub struct DeterministicNetwork<T> {
    now: u64,
    next_sequence: u64,
    next_insertion_order: u64,
    paths: Vec<PathState>,
    queue: Vec<Scheduled<T>>,
}

impl<T> DeterministicNetwork<T> {
    /// Creates an empty simulator at logical tick zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            now: 0,
            next_sequence: 0,
            next_insertion_order: 0,
            paths: Vec::new(),
            queue: Vec::new(),
        }
    }

    /// Adds an enabled path with a stable identifier.
    ///
    /// # Errors
    ///
    /// Returns [`SimulatorError::PathAlreadyExists`] if the identifier is
    /// already registered.
    pub fn add_path(&mut self, path_id: u8, profile: PathProfile) -> Result<(), SimulatorError> {
        if self.paths.iter().any(|path| path.id == path_id) {
            return Err(SimulatorError::PathAlreadyExists(path_id));
        }
        self.paths.push(PathState {
            id: path_id,
            profile,
            enabled: true,
            transmissions: 0,
        });
        Ok(())
    }

    /// Enables or disables new transmissions on one path.
    ///
    /// Already queued deliveries are unaffected, matching packets already in
    /// flight when an interface fails.
    ///
    /// # Errors
    ///
    /// Returns [`SimulatorError::UnknownPath`] for an unregistered identifier.
    pub fn set_path_enabled(&mut self, path_id: u8, enabled: bool) -> Result<(), SimulatorError> {
        let path = self.path_mut(path_id)?;
        path.enabled = enabled;
        Ok(())
    }

    /// Returns the current logical tick.
    #[must_use]
    pub const fn now(&self) -> u64 {
        self.now
    }

    /// Returns the number of packet copies awaiting delivery.
    #[must_use]
    pub const fn queued_deliveries(&self) -> usize {
        self.queue.len()
    }

    /// Injects one packet into a path and applies its deterministic fault rule.
    ///
    /// A logical sequence number is consumed even when the packet is disabled
    /// or dropped. Duplication clones `payload` exactly once.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown path or an exhausted logical counter.
    pub fn send(&mut self, path_id: u8, payload: T) -> Result<SendOutcome, SimulatorError>
    where
        T: Clone,
    {
        let sequence = self.next_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(SimulatorError::CounterOverflow)?;
        let path_index = self
            .paths
            .iter()
            .position(|path| path.id == path_id)
            .ok_or(SimulatorError::UnknownPath(path_id))?;
        if !self.paths[path_index].enabled {
            self.next_sequence = next_sequence;
            return Ok(SendOutcome::Disabled { sequence });
        }

        let transmission = self.paths[path_index]
            .transmissions
            .checked_add(1)
            .ok_or(SimulatorError::CounterOverflow)?;
        let profile = self.paths[path_index].profile;
        if matches_period(transmission, profile.drop_every) {
            self.paths[path_index].transmissions = transmission;
            self.next_sequence = next_sequence;
            return Ok(SendOutcome::Dropped { sequence });
        }

        let mut delivery_tick = self
            .now
            .checked_add(profile.base_delay_ticks)
            .ok_or(SimulatorError::CounterOverflow)?;
        if matches_period(transmission, profile.reorder_every) {
            delivery_tick = delivery_tick
                .checked_add(profile.reorder_delay_ticks)
                .ok_or(SimulatorError::CounterOverflow)?;
        }
        let duplicate = matches_period(transmission, profile.duplicate_every);
        let copies = u8::from(duplicate) + 1;
        let next_order = self
            .next_insertion_order
            .checked_add(u64::from(copies))
            .ok_or(SimulatorError::CounterOverflow)?;
        let second_delivery_tick = if duplicate {
            Some(
                delivery_tick
                    .checked_add(profile.duplicate_delay_ticks)
                    .ok_or(SimulatorError::CounterOverflow)?,
            )
        } else {
            None
        };

        self.paths[path_index].transmissions = transmission;
        self.next_sequence = next_sequence;
        if let Some(duplicate_delivery_tick) = second_delivery_tick {
            self.queue.push(Scheduled {
                delivery_tick,
                insertion_order: self.next_insertion_order,
                path_id,
                sequence,
                duplicate: false,
                payload: payload.clone(),
            });
            self.queue.push(Scheduled {
                delivery_tick: duplicate_delivery_tick,
                insertion_order: self.next_insertion_order + 1,
                path_id,
                sequence,
                duplicate: true,
                payload,
            });
        } else {
            self.queue.push(Scheduled {
                delivery_tick,
                insertion_order: self.next_insertion_order,
                path_id,
                sequence,
                duplicate: false,
                payload,
            });
        }
        self.next_insertion_order = next_order;
        Ok(SendOutcome::Scheduled { sequence, copies })
    }

    /// Delivers the next queued packet copy and advances the logical clock.
    ///
    /// Equal-tick deliveries retain their injection order. Returns `None` when
    /// the simulated network has no packet in flight.
    pub fn deliver_next(&mut self) -> Option<Delivery<T>> {
        let index = self
            .queue
            .iter()
            .enumerate()
            .min_by_key(|(_, packet)| (packet.delivery_tick, packet.insertion_order))
            .map(|(index, _)| index)?;
        let scheduled = self.queue.swap_remove(index);
        self.now = scheduled.delivery_tick;
        Some(Delivery {
            delivery_tick: scheduled.delivery_tick,
            path_id: scheduled.path_id,
            sequence: scheduled.sequence,
            duplicate: scheduled.duplicate,
            payload: scheduled.payload,
        })
    }

    fn path_mut(&mut self, path_id: u8) -> Result<&mut PathState, SimulatorError> {
        self.paths
            .iter_mut()
            .find(|path| path.id == path_id)
            .ok_or(SimulatorError::UnknownPath(path_id))
    }
}

fn matches_period(transmission: u64, period: Option<NonZeroU64>) -> bool {
    period.is_some_and(|value| transmission.is_multiple_of(value.get()))
}

/// Deterministic simulator configuration or counter failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimulatorError {
    PathAlreadyExists(u8),
    UnknownPath(u8),
    CounterOverflow,
}

impl fmt::Display for SimulatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PathAlreadyExists(path) => write!(formatter, "path {path} already exists"),
            Self::UnknownPath(path) => write!(formatter, "unknown path {path}"),
            Self::CounterOverflow => formatter.write_str("simulator logical counter overflow"),
        }
    }
}

impl std::error::Error for SimulatorError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn every(value: u64) -> Option<NonZeroU64> {
        NonZeroU64::new(value)
    }

    #[test]
    fn loss_duplication_and_reordering_follow_the_script() {
        let mut network = DeterministicNetwork::new();
        network
            .add_path(
                4,
                PathProfile {
                    base_delay_ticks: 5,
                    drop_every: every(3),
                    duplicate_every: every(2),
                    reorder_every: every(4),
                    reorder_delay_ticks: 10,
                    duplicate_delay_ticks: 1,
                },
            )
            .expect("path is unique");
        for payload in 0_u8..5 {
            network.send(4, payload).expect("send succeeds");
        }
        assert_eq!(network.queued_deliveries(), 6);

        let mut deliveries = Vec::new();
        while let Some(delivery) = network.deliver_next() {
            deliveries.push((
                delivery.delivery_tick,
                delivery.sequence,
                delivery.duplicate,
                delivery.payload,
            ));
        }
        assert_eq!(
            deliveries,
            vec![
                (5, 0, false, 0),
                (5, 1, false, 1),
                (5, 4, false, 4),
                (6, 1, true, 1),
                (15, 3, false, 3),
                (16, 3, true, 3),
            ]
        );
        assert_eq!(network.now(), 16);
    }

    #[test]
    fn disabled_path_preserves_in_flight_packets_and_allows_failover() {
        let mut network = DeterministicNetwork::new();
        network
            .add_path(
                0,
                PathProfile {
                    base_delay_ticks: 20,
                    ..PathProfile::default()
                },
            )
            .expect("first path is unique");
        network
            .add_path(
                1,
                PathProfile {
                    base_delay_ticks: 3,
                    ..PathProfile::default()
                },
            )
            .expect("second path is unique");

        assert_eq!(
            network.send(0, "already-in-flight").expect("send works"),
            SendOutcome::Scheduled {
                sequence: 0,
                copies: 1
            }
        );
        network.set_path_enabled(0, false).expect("path exists");
        assert_eq!(
            network.send(0, "blocked").expect("disabled is an outcome"),
            SendOutcome::Disabled { sequence: 1 }
        );
        network.send(1, "failover").expect("alternate path works");

        assert_eq!(
            network.deliver_next().expect("fast path arrives").payload,
            "failover"
        );
        assert_eq!(
            network
                .deliver_next()
                .expect("in-flight packet survives")
                .payload,
            "already-in-flight"
        );
        assert!(network.deliver_next().is_none());
    }

    #[test]
    fn scheduling_overflow_does_not_partially_consume_counters() {
        let mut network = DeterministicNetwork::new();
        network
            .add_path(
                7,
                PathProfile {
                    base_delay_ticks: 1,
                    ..PathProfile::default()
                },
            )
            .expect("path is unique");
        network.now = u64::MAX;

        assert_eq!(network.send(7, 42_u8), Err(SimulatorError::CounterOverflow));
        assert_eq!(network.next_sequence, 0);
        assert_eq!(network.paths[0].transmissions, 0);
        assert_eq!(network.queued_deliveries(), 0);
    }
}
