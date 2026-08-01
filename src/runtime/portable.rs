//! Safe nonblocking UDP adapter built on `std::net::UdpSocket`.
//!
//! This backend deliberately exposes its missing capabilities. The standard
//! library does not provide destination/interface/ECN ancillary data, UDP
//! GRO/GSO, batched syscalls, or asynchronous completion. Platform backends
//! can add those features while preserving the queue ownership contract.

use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};

use super::{
    IpAddress, ReceiveMetadata, ReceiveQueue, RuntimeQueueError, TransmitMetadata, TransmitQueue,
    UdpEndpoint,
};
use crate::ecn::EcnCodepoint;

/// Largest ordinary UDP payload accepted by this portable adapter.
///
/// The extra byte used to detect a datagram above the configured OGTP limit is
/// not included. IPv6 jumbograms are outside the OGTP/1 portable profile.
pub const MAX_PORTABLE_DATAGRAM_SIZE: usize = 65_527;

/// One socket-adapter feature that callers must negotiate explicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum PortableUdpCapability {
    ExactReceiveDestination,
    ReceiveInterface,
    ReceiveEcn,
    KernelReceiveTimestamp,
    UdpGro,
    SourceSelection,
    TransmitInterface,
    TransmitEcn,
    UdpGso,
    BatchedSyscalls,
    DeferredCompletion,
}

/// Compact set of features observable through one adapter instance.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PortableUdpCapabilities(u16);

impl PortableUdpCapabilities {
    const fn empty() -> Self {
        Self(0)
    }

    const fn with(mut self, capability: PortableUdpCapability) -> Self {
        self.0 |= 1 << capability as u16;
        self
    }

    /// Returns whether this adapter supports `capability`.
    #[must_use]
    pub const fn contains(self, capability: PortableUdpCapability) -> bool {
        self.0 & (1 << capability as u16) != 0
    }
}

impl fmt::Debug for PortableUdpCapabilities {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut set = formatter.debug_set();
        for capability in [
            PortableUdpCapability::ExactReceiveDestination,
            PortableUdpCapability::ReceiveInterface,
            PortableUdpCapability::ReceiveEcn,
            PortableUdpCapability::KernelReceiveTimestamp,
            PortableUdpCapability::UdpGro,
            PortableUdpCapability::SourceSelection,
            PortableUdpCapability::TransmitInterface,
            PortableUdpCapability::TransmitEcn,
            PortableUdpCapability::UdpGso,
            PortableUdpCapability::BatchedSyscalls,
            PortableUdpCapability::DeferredCompletion,
        ] {
            if self.contains(capability) {
                set.entry(&capability);
            }
        }
        set.finish()
    }
}

/// One nonblocking receive attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum PortableReceiveOutcome {
    Received {
        bytes: usize,
    },
    WouldBlock,
    PoolExhausted,
    DroppedEmpty,
    DroppedOversized {
        configured_limit: usize,
        observed_at_least: usize,
    },
}

/// One nonblocking transmit attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum PortableTransmitOutcome {
    Idle,
    Sent { bytes: usize },
    WouldBlock,
    NotReady { send_not_before_micros: u64 },
}

/// Unsupported routing or offload request rejected before transmission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortableTransmitRejection {
    WrongSocket { expected: u16, actual: u16 },
    SourceSelectionUnavailable,
    InterfaceSelectionUnavailable,
    EcnUnavailable,
    GsoUnavailable,
    InvalidIpv4Scope,
}

/// Safe portable-adapter failure.
#[derive(Debug)]
pub enum PortableUdpError {
    Io(io::Error),
    Queue(RuntimeQueueError),
    InvalidMaximumDatagramSize { size: usize },
    ReceiveBufferTooSmall { capacity: usize, required: usize },
    UnsupportedTransmit(PortableTransmitRejection),
}

impl fmt::Display for PortableUdpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "UDP socket failure: {error}"),
            Self::Queue(error) => write!(formatter, "UDP queue failure: {error}"),
            Self::InvalidMaximumDatagramSize { size } => write!(
                formatter,
                "portable UDP maximum datagram size {size} is outside 1..={MAX_PORTABLE_DATAGRAM_SIZE}"
            ),
            Self::ReceiveBufferTooSmall { capacity, required } => write!(
                formatter,
                "receive buffer capacity {capacity} is smaller than required probe size {required}"
            ),
            Self::UnsupportedTransmit(reason) => {
                write!(
                    formatter,
                    "portable UDP transmit metadata is unsupported: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for PortableUdpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Queue(error) => Some(error),
            Self::InvalidMaximumDatagramSize { .. }
            | Self::ReceiveBufferTooSmall { .. }
            | Self::UnsupportedTransmit(_) => None,
        }
    }
}

impl fmt::Display for PortableTransmitRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongSocket { expected, actual } => {
                write!(
                    formatter,
                    "socket ID {actual} does not match adapter {expected}"
                )
            }
            Self::SourceSelectionUnavailable => {
                formatter.write_str("per-datagram source selection is unavailable")
            }
            Self::InterfaceSelectionUnavailable => {
                formatter.write_str("per-datagram interface selection is unavailable")
            }
            Self::EcnUnavailable => formatter.write_str("per-datagram ECN is unavailable"),
            Self::GsoUnavailable => formatter.write_str("UDP GSO is unavailable"),
            Self::InvalidIpv4Scope => formatter.write_str("IPv4 endpoint has a non-zero scope ID"),
        }
    }
}

/// Nonblocking standard-library socket bound to one fixed runtime socket ID.
pub struct PortableUdpSocket {
    socket: UdpSocket,
    socket_id: u16,
    local_endpoint: UdpEndpoint,
    exact_local_endpoint: bool,
    maximum_datagram_size: usize,
    single_owner: PhantomData<Cell<()>>,
}

impl PortableUdpSocket {
    /// Binds and configures a nonblocking UDP socket.
    ///
    /// # Errors
    ///
    /// Returns a socket or configuration error. The maximum must leave one
    /// receive-buffer byte available for oversize detection.
    pub fn bind(
        address: SocketAddr,
        socket_id: u16,
        maximum_datagram_size: usize,
    ) -> Result<Self, PortableUdpError> {
        let socket = UdpSocket::bind(address).map_err(PortableUdpError::Io)?;
        Self::from_socket(socket, socket_id, maximum_datagram_size)
    }

    /// Takes ownership of a bound socket and enables nonblocking mode.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid maximum, nonblocking setup failure, or
    /// unavailable local socket address.
    pub fn from_socket(
        socket: UdpSocket,
        socket_id: u16,
        maximum_datagram_size: usize,
    ) -> Result<Self, PortableUdpError> {
        if !(1..=MAX_PORTABLE_DATAGRAM_SIZE).contains(&maximum_datagram_size) {
            return Err(PortableUdpError::InvalidMaximumDatagramSize {
                size: maximum_datagram_size,
            });
        }
        socket.set_nonblocking(true).map_err(PortableUdpError::Io)?;
        let local_address = socket.local_addr().map_err(PortableUdpError::Io)?;
        let exact_local_endpoint = !local_address.ip().is_unspecified();
        Ok(Self {
            socket,
            socket_id,
            local_endpoint: local_address.into(),
            exact_local_endpoint,
            maximum_datagram_size,
            single_owner: PhantomData,
        })
    }

    /// Returns the fixed runtime identifier assigned to this socket.
    #[must_use]
    pub const fn socket_id(&self) -> u16 {
        self.socket_id
    }

    /// Returns the address reported by `local_addr` after binding.
    #[must_use]
    pub const fn local_endpoint(&self) -> UdpEndpoint {
        self.local_endpoint
    }

    /// Returns the configured OGTP datagram limit, excluding the probe byte.
    #[must_use]
    pub const fn maximum_datagram_size(&self) -> usize {
        self.maximum_datagram_size
    }

    /// Reports which metadata and acceleration features this backend exposes.
    #[must_use]
    pub const fn capabilities(&self) -> PortableUdpCapabilities {
        let capabilities = PortableUdpCapabilities::empty();
        if self.exact_local_endpoint {
            capabilities.with(PortableUdpCapability::ExactReceiveDestination)
        } else {
            capabilities
        }
    }

    /// Borrows the socket for readiness registration and socket options.
    ///
    /// The caller must preserve nonblocking mode.
    #[must_use]
    pub const fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Returns the owned socket.
    #[must_use]
    pub fn into_inner(self) -> UdpSocket {
        self.socket
    }

    /// Attempts one receive directly into a fixed queue reservation.
    ///
    /// `now_micros` must come from the event loop's monotonic clock. An extra
    /// byte is always offered to the kernel so a datagram above the configured
    /// protocol limit cannot be accepted as a valid truncated prefix.
    ///
    /// # Errors
    ///
    /// Returns socket, queue, or buffer-configuration errors. On every return,
    /// the reservation is either committed or returned exactly once.
    pub fn try_receive<const SLOTS: usize, const BUFFER_SIZE: usize>(
        &self,
        queue: &mut ReceiveQueue<SLOTS, BUFFER_SIZE>,
        now_micros: u64,
    ) -> Result<PortableReceiveOutcome, PortableUdpError> {
        let required = self.maximum_datagram_size + 1;
        if BUFFER_SIZE < required {
            return Err(PortableUdpError::ReceiveBufferTooSmall {
                capacity: BUFFER_SIZE,
                required,
            });
        }
        let reservation = match queue.reserve() {
            Ok(reservation) => reservation,
            Err(RuntimeQueueError::PoolExhausted) => {
                return Ok(PortableReceiveOutcome::PoolExhausted);
            }
            Err(error) => return Err(PortableUdpError::Queue(error)),
        };

        let result = loop {
            let receive_result = {
                let buffer = queue
                    .buffer_mut(&reservation)
                    .map_err(PortableUdpError::Queue)?;
                self.socket.recv_from(&mut buffer[..required])
            };
            if !matches!(
                &receive_result,
                Err(error) if error.kind() == io::ErrorKind::Interrupted
            ) {
                break receive_result;
            }
        };

        let (length, source) = match result {
            Ok(received) => received,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                queue
                    .release_unwritten_receive_reservation(reservation)
                    .map_err(PortableUdpError::Queue)?;
                return Ok(PortableReceiveOutcome::WouldBlock);
            }
            Err(error) => {
                // Some platforms can copy a truncated datagram before
                // reporting an error such as EMSGSIZE. Clear the full slot.
                queue.cancel(reservation).map_err(PortableUdpError::Queue)?;
                return Err(PortableUdpError::Io(error));
            }
        };

        if length == 0 {
            queue.cancel(reservation).map_err(PortableUdpError::Queue)?;
            return Ok(PortableReceiveOutcome::DroppedEmpty);
        }
        if length > self.maximum_datagram_size {
            queue.cancel(reservation).map_err(PortableUdpError::Queue)?;
            return Ok(PortableReceiveOutcome::DroppedOversized {
                configured_limit: self.maximum_datagram_size,
                observed_at_least: length,
            });
        }

        queue
            .commit(
                reservation,
                length,
                ReceiveMetadata {
                    source: source.into(),
                    destination: self.exact_local_endpoint.then_some(self.local_endpoint),
                    socket_id: self.socket_id,
                    interface_index: None,
                    ecn: None,
                    received_at_micros: now_micros,
                    gro_segment_size: None,
                },
            )
            .map_err(PortableUdpError::Queue)?;
        Ok(PortableReceiveOutcome::Received { bytes: length })
    }

    /// Attempts one ready transmit without blocking.
    ///
    /// A pacing deadline or `WouldBlock` requeues the datagram. Unsupported
    /// metadata and permanent socket errors discard the encoded datagram; the
    /// protocol recovery record remains responsible for reliable rescheduling.
    ///
    /// # Errors
    ///
    /// Returns a metadata, socket, or queue error after resolving buffer
    /// ownership exactly once.
    pub fn try_transmit<const SLOTS: usize, const BUFFER_SIZE: usize>(
        &self,
        queue: &mut TransmitQueue<SLOTS, BUFFER_SIZE>,
        now_micros: u64,
    ) -> Result<PortableTransmitOutcome, PortableUdpError> {
        let Some(datagram) = queue.pop() else {
            return Ok(PortableTransmitOutcome::Idle);
        };
        let metadata = queue
            .view(&datagram)
            .map_err(PortableUdpError::Queue)?
            .metadata();

        if metadata.send_not_before_micros > now_micros {
            queue.requeue(datagram).map_err(PortableUdpError::Queue)?;
            return Ok(PortableTransmitOutcome::NotReady {
                send_not_before_micros: metadata.send_not_before_micros,
            });
        }
        if let Err(rejection) = self.validate_transmit_metadata(metadata) {
            queue.discard(datagram).map_err(PortableUdpError::Queue)?;
            return Err(PortableUdpError::UnsupportedTransmit(rejection));
        }
        let destination = match SocketAddr::try_from(metadata.destination) {
            Ok(destination) => destination,
            Err(rejection) => {
                queue.discard(datagram).map_err(PortableUdpError::Queue)?;
                return Err(PortableUdpError::UnsupportedTransmit(rejection));
            }
        };

        let result = loop {
            let send_result = {
                let view = queue.view(&datagram).map_err(PortableUdpError::Queue)?;
                self.socket.send_to(view.payload(), destination)
            };
            if !matches!(
                &send_result,
                Err(error) if error.kind() == io::ErrorKind::Interrupted
            ) {
                break send_result;
            }
        };

        match result {
            Ok(length) => {
                let expected = queue
                    .view(&datagram)
                    .map_err(PortableUdpError::Queue)?
                    .payload()
                    .len();
                if length != expected {
                    queue.discard(datagram).map_err(PortableUdpError::Queue)?;
                    return Err(PortableUdpError::Io(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "UDP send accepted only part of one datagram",
                    )));
                }
                queue.complete(datagram).map_err(PortableUdpError::Queue)?;
                Ok(PortableTransmitOutcome::Sent { bytes: length })
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                queue.requeue(datagram).map_err(PortableUdpError::Queue)?;
                Ok(PortableTransmitOutcome::WouldBlock)
            }
            Err(error) => {
                queue.discard(datagram).map_err(PortableUdpError::Queue)?;
                Err(PortableUdpError::Io(error))
            }
        }
    }

    fn validate_transmit_metadata(
        &self,
        metadata: TransmitMetadata,
    ) -> Result<(), PortableTransmitRejection> {
        if metadata.socket_id != self.socket_id {
            return Err(PortableTransmitRejection::WrongSocket {
                expected: self.socket_id,
                actual: metadata.socket_id,
            });
        }
        if let Some(source) = metadata.source
            && (!self.exact_local_endpoint || source != self.local_endpoint)
        {
            return Err(PortableTransmitRejection::SourceSelectionUnavailable);
        }
        if metadata.interface_index.is_some() {
            return Err(PortableTransmitRejection::InterfaceSelectionUnavailable);
        }
        if metadata.ecn != EcnCodepoint::NotEct {
            return Err(PortableTransmitRejection::EcnUnavailable);
        }
        if metadata.gso_segment_size.is_some() {
            return Err(PortableTransmitRejection::GsoUnavailable);
        }
        Ok(())
    }
}

impl fmt::Debug for PortableUdpSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PortableUdpSocket")
            .field("socket_id", &self.socket_id)
            .field("local_endpoint", &"<redacted>")
            .field("maximum_datagram_size", &self.maximum_datagram_size)
            .field("capabilities", &self.capabilities())
            .finish_non_exhaustive()
    }
}

impl From<SocketAddr> for UdpEndpoint {
    fn from(address: SocketAddr) -> Self {
        match address {
            SocketAddr::V4(address) => Self {
                address: IpAddress::V4(address.ip().octets()),
                port: address.port(),
                scope_id: 0,
            },
            SocketAddr::V6(address) => Self {
                address: IpAddress::V6(address.ip().octets()),
                port: address.port(),
                scope_id: address.scope_id(),
            },
        }
    }
}

impl TryFrom<UdpEndpoint> for SocketAddr {
    type Error = PortableTransmitRejection;

    fn try_from(endpoint: UdpEndpoint) -> Result<Self, Self::Error> {
        match endpoint.address {
            IpAddress::V4(octets) => {
                if endpoint.scope_id != 0 {
                    return Err(PortableTransmitRejection::InvalidIpv4Scope);
                }
                Ok(Self::V4(SocketAddrV4::new(
                    Ipv4Addr::from(octets),
                    endpoint.port,
                )))
            }
            IpAddress::V6(octets) => Ok(Self::V6(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                endpoint.port,
                0,
                endpoint.scope_id,
            ))),
        }
    }
}

impl From<IpAddr> for IpAddress {
    fn from(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(address) => Self::V4(address.octets()),
            IpAddr::V6(address) => Self::V6(address.octets()),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU16;
    use std::time::Duration;

    use super::*;

    fn localhost() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 0))
    }

    fn transmit_metadata(
        adapter: &PortableUdpSocket,
        destination: SocketAddr,
        send_not_before_micros: u64,
    ) -> TransmitMetadata {
        TransmitMetadata {
            source: None,
            destination: destination.into(),
            socket_id: adapter.socket_id(),
            interface_index: None,
            ecn: EcnCodepoint::NotEct,
            send_not_before_micros,
            gso_segment_size: None,
        }
    }

    fn receive_after_send<const SLOTS: usize, const BUFFER_SIZE: usize>(
        adapter: &PortableUdpSocket,
        queue: &mut ReceiveQueue<SLOTS, BUFFER_SIZE>,
        now_micros: u64,
    ) -> PortableReceiveOutcome {
        for _ in 0..100 {
            let outcome = adapter.try_receive(queue, now_micros).expect("receive");
            if outcome != PortableReceiveOutcome::WouldBlock {
                return outcome;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("loopback datagram did not arrive before the test deadline");
    }

    #[test]
    fn receive_is_nonblocking_direct_bounded_and_metadata_explicit() {
        let receiver = PortableUdpSocket::bind(localhost(), 7, 1_200).expect("receiver");
        let capabilities = receiver.capabilities();
        assert!(capabilities.contains(PortableUdpCapability::ExactReceiveDestination));
        assert!(!capabilities.contains(PortableUdpCapability::ReceiveEcn));
        assert!(!capabilities.contains(PortableUdpCapability::BatchedSyscalls));
        let sender = UdpSocket::bind(localhost()).expect("sender");
        sender
            .send_to(
                b"hello",
                SocketAddr::try_from(receiver.local_endpoint()).unwrap(),
            )
            .expect("send");

        let mut queue = ReceiveQueue::<1, 1_201>::new();
        assert_eq!(
            receive_after_send(&receiver, &mut queue, 42),
            PortableReceiveOutcome::Received { bytes: 5 }
        );
        let datagram = queue.pop().expect("received token");
        let view = queue.view(&datagram).expect("received view");
        assert_eq!(view.payload(), b"hello");
        let metadata = view.metadata();
        assert_eq!(metadata.socket_id, 7);
        assert_eq!(metadata.received_at_micros, 42);
        assert_eq!(metadata.destination, Some(receiver.local_endpoint()));
        assert_eq!(metadata.interface_index, None);
        assert_eq!(metadata.ecn, None);
        assert_eq!(metadata.gro_segment_size, None);
        queue.release(datagram).expect("release");

        assert_eq!(
            receiver.try_receive(&mut queue, 43).expect("empty poll"),
            PortableReceiveOutcome::WouldBlock
        );
        assert_eq!(queue.stats().free, 1);

        sender
            .send_to(
                &[],
                SocketAddr::try_from(receiver.local_endpoint()).unwrap(),
            )
            .expect("send empty datagram");
        assert_eq!(
            receive_after_send(&receiver, &mut queue, 44),
            PortableReceiveOutcome::DroppedEmpty
        );
        assert_eq!(queue.stats().free, 1);
    }

    #[test]
    fn receive_probe_rejects_oversized_and_small_pool_buffers() {
        let receiver = PortableUdpSocket::bind(localhost(), 8, 4).expect("receiver");
        let sender = UdpSocket::bind(localhost()).expect("sender");
        sender
            .send_to(
                b"sixsix",
                SocketAddr::try_from(receiver.local_endpoint()).unwrap(),
            )
            .expect("send oversized");

        let mut queue = ReceiveQueue::<1, 5>::new();
        assert_eq!(
            receive_after_send(&receiver, &mut queue, 1),
            PortableReceiveOutcome::DroppedOversized {
                configured_limit: 4,
                observed_at_least: 5,
            }
        );
        assert_eq!(queue.stats().free, 1);

        let mut too_small = ReceiveQueue::<1, 4>::new();
        assert!(matches!(
            receiver.try_receive(&mut too_small, 2),
            Err(PortableUdpError::ReceiveBufferTooSmall {
                capacity: 4,
                required: 5,
            })
        ));
    }

    #[test]
    fn transmit_honors_pacing_and_completes_synchronously() {
        let sender = PortableUdpSocket::bind(localhost(), 9, 1_200).expect("sender");
        let receiver = UdpSocket::bind(localhost()).expect("receiver");
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout");
        let destination = receiver.local_addr().expect("receiver address");

        let mut queue = TransmitQueue::<1, 32>::new();
        let reservation = queue.reserve().expect("reservation");
        queue.buffer_mut(&reservation).expect("buffer")[..4].copy_from_slice(b"data");
        queue
            .commit(reservation, 4, transmit_metadata(&sender, destination, 10))
            .expect("commit");
        assert_eq!(
            sender.try_transmit(&mut queue, 9).expect("pacing"),
            PortableTransmitOutcome::NotReady {
                send_not_before_micros: 10,
            }
        );
        assert_eq!(queue.stats().ready, 1);
        assert_eq!(
            sender.try_transmit(&mut queue, 10).expect("transmit"),
            PortableTransmitOutcome::Sent { bytes: 4 }
        );
        assert_eq!(queue.stats().free, 1);

        let mut payload = [0_u8; 4];
        let (length, _) = receiver.recv_from(&mut payload).expect("receive sent data");
        assert_eq!(length, 4);
        assert_eq!(&payload, b"data");
    }

    #[test]
    fn unsupported_offload_is_explicit_and_releases_the_buffer() {
        let sender = PortableUdpSocket::bind(localhost(), 10, 1_200).expect("sender");
        let receiver = UdpSocket::bind(localhost()).expect("receiver");
        let destination = receiver.local_addr().expect("receiver address");
        let mut queue = TransmitQueue::<1, 32>::new();
        let reservation = queue.reserve().expect("reservation");
        queue.buffer_mut(&reservation).expect("buffer")[..4].copy_from_slice(b"data");
        let mut metadata = transmit_metadata(&sender, destination, 0);
        metadata.gso_segment_size = NonZeroU16::new(2);
        queue
            .commit(reservation, 4, metadata)
            .expect("queue accepts platform-neutral GSO metadata");

        assert!(matches!(
            sender.try_transmit(&mut queue, 0),
            Err(PortableUdpError::UnsupportedTransmit(
                PortableTransmitRejection::GsoUnavailable
            ))
        ));
        assert_eq!(queue.stats().free, 1);
    }

    #[test]
    fn endpoint_conversion_preserves_ipv6_scope_and_rejects_ipv4_scope() {
        let address = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 44_000, 0, 12));
        let endpoint: UdpEndpoint = address.into();
        assert_eq!(endpoint.scope_id, 12);
        assert_eq!(SocketAddr::try_from(endpoint), Ok(address));

        let invalid = UdpEndpoint {
            address: IpAddress::V4([127, 0, 0, 1]),
            port: 44_000,
            scope_id: 1,
        };
        assert_eq!(
            SocketAddr::try_from(invalid),
            Err(PortableTransmitRejection::InvalidIpv4Scope)
        );
    }
}
