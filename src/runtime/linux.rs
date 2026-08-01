//! Linux batched UDP adapter with ancillary metadata.
//!
//! The adapter owns one nonblocking socket and preallocates every `mmsghdr`,
//! address slot, and control-message buffer during construction. Its receive
//! fast path calls `recvmmsg` directly into fixed runtime queue buffers. It
//! performs no payload copy and creates no heap-backed batch list.

use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use core::num::NonZeroU16;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::os::fd::AsRawFd;

use nix::errno::Errno;
use nix::libc;
use nix::sys::socket::{
    ControlMessageOwned, MsgFlags, MultiHeaders, RecvMsg, SockaddrStorage, getsockopt, recvmmsg,
    setsockopt, sockopt,
};
use nix::sys::time::TimeSpec;
use ogtp_linux_sys::{IpVersion, LinuxSendBatch, SendBatchResult, SendControl};

use super::{
    IpAddress, ReceiveMetadata, ReceiveQueue, RuntimeQueueError, TransmitBatch, TransmitDatagram,
    TransmitMetadata, TransmitQueue, UdpCapabilities, UdpCapability, UdpEndpoint,
};
use crate::ecn::EcnCodepoint;

/// Largest non-jumbogram UDP payload supported by the Linux OGTP profile.
pub const MAX_LINUX_DATAGRAM_SIZE: usize = 65_527;

/// Conservative Linux UDP GSO segment-count ceiling per aggregate.
pub const MAX_LINUX_GSO_SEGMENTS: usize = 64;

/// Linux socket features enabled before the adapter enters its event loop.
///
/// Requested options are strict: construction fails if the running kernel or
/// socket family rejects one. This prevents a deployment from silently losing
/// metadata that its congestion control or multipath policy expects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LinuxUdpFeature {
    PacketInfo,
    Ecn,
    ReceiveKernelTimestamp,
    ReceiveDropCounter,
    UdpGro,
    UdpGso,
}

/// Compact set of Linux socket features selected at construction.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct LinuxUdpConfig(u8);

impl LinuxUdpConfig {
    /// Creates a configuration with no optional socket feature.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Returns a configuration with `feature` enabled.
    #[must_use]
    pub const fn with(mut self, feature: LinuxUdpFeature) -> Self {
        self.0 |= 1 << feature as u8;
        self
    }

    /// Returns whether `feature` is enabled.
    #[must_use]
    pub const fn contains(self, feature: LinuxUdpFeature) -> bool {
        self.0 & (1 << feature as u8) != 0
    }
}

impl Default for LinuxUdpConfig {
    fn default() -> Self {
        Self::empty()
            .with(LinuxUdpFeature::PacketInfo)
            .with(LinuxUdpFeature::Ecn)
            .with(LinuxUdpFeature::ReceiveKernelTimestamp)
            .with(LinuxUdpFeature::ReceiveDropCounter)
            .with(LinuxUdpFeature::UdpGro)
            .with(LinuxUdpFeature::UdpGso)
    }
}

impl fmt::Debug for LinuxUdpConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut set = formatter.debug_set();
        for feature in [
            LinuxUdpFeature::PacketInfo,
            LinuxUdpFeature::Ecn,
            LinuxUdpFeature::ReceiveKernelTimestamp,
            LinuxUdpFeature::ReceiveDropCounter,
            LinuxUdpFeature::UdpGro,
            LinuxUdpFeature::UdpGso,
        ] {
            if self.contains(feature) {
                set.entry(&feature);
            }
        }
        set.finish()
    }
}

/// Result of one nonblocking batched receive attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum LinuxReceiveBatchOutcome {
    /// A compile-time zero-size batch performed no work.
    Idle,
    /// The kernel returned one or more datagrams.
    Received {
        committed_datagrams: usize,
        committed_bytes: usize,
        dropped_datagrams: usize,
    },
    /// The socket had no datagram ready.
    WouldBlock,
    /// The fixed receive pool could not supply the entire requested batch.
    PoolExhausted,
}

/// Result of one nonblocking fixed-size transmit attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum LinuxTransmitBatchOutcome {
    /// No datagram was ready, or a zero-size batch performed no work.
    Idle,
    /// Some datagrams are ready, but fewer than the compile-time batch size.
    IncompleteBatch { ready_datagrams: usize },
    /// A kernel-accepted prefix completed synchronously; the suffix was
    /// requeued in its original order.
    Sent {
        sent_datagrams: usize,
        sent_bytes: usize,
        requeued_datagrams: usize,
    },
    /// The socket returned `EAGAIN` and the whole batch was requeued.
    WouldBlock,
    /// At least one pacing deadline is in the future; the whole batch was
    /// requeued without entering the kernel.
    NotReady { send_not_before_micros: u64 },
}

/// Invalid or unsupported Linux transmit metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxTransmitRejection {
    WrongSocket { expected: u16, actual: u16 },
    InvalidIpv4Scope,
    ZeroDestinationPort,
    SourcePortMismatch { expected: u16, actual: u16 },
    AddressFamilyMismatch,
    HeterogeneousBatch,
    InterfaceScopeConflict,
    SourceSelectionUnavailable,
    InterfaceSelectionUnavailable,
    EcnUnavailable,
    GsoUnavailable,
    DatagramTooLarge { length: usize, maximum: usize },
    InvalidGsoSegment { size: usize, length: usize },
    TooManyGsoSegments { segments: usize, maximum: usize },
}

/// Safe Linux adapter failure.
#[derive(Debug)]
pub enum LinuxUdpError {
    Io(io::Error),
    Queue(RuntimeQueueError),
    InvalidMaximumDatagramSize { size: usize },
    ReceiveBufferTooSmall { capacity: usize, required: usize },
    UnsupportedTransmit(LinuxTransmitRejection),
}

impl fmt::Display for LinuxUdpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "Linux UDP socket failure: {error}"),
            Self::Queue(error) => write!(formatter, "Linux UDP queue failure: {error}"),
            Self::InvalidMaximumDatagramSize { size } => write!(
                formatter,
                "Linux UDP maximum datagram size {size} is outside 1..={MAX_LINUX_DATAGRAM_SIZE}"
            ),
            Self::ReceiveBufferTooSmall { capacity, required } => write!(
                formatter,
                "receive buffer capacity {capacity} is smaller than configured datagram size {required}"
            ),
            Self::UnsupportedTransmit(reason) => {
                write!(
                    formatter,
                    "Linux UDP transmit metadata is unsupported: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for LinuxUdpError {
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

impl fmt::Display for LinuxTransmitRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongSocket { expected, actual } => {
                write!(
                    formatter,
                    "socket ID {actual} does not match adapter {expected}"
                )
            }
            Self::InvalidIpv4Scope => formatter.write_str("IPv4 endpoint has a non-zero scope ID"),
            Self::ZeroDestinationPort => formatter.write_str("destination port is zero"),
            Self::SourcePortMismatch { expected, actual } => {
                write!(
                    formatter,
                    "source port {actual} does not match bound port {expected}"
                )
            }
            Self::AddressFamilyMismatch => {
                formatter.write_str("source, destination, and socket address families differ")
            }
            Self::HeterogeneousBatch => formatter
                .write_str("batch source, interface, ECN, or GSO metadata is not homogeneous"),
            Self::InterfaceScopeConflict => {
                formatter.write_str("IPv6 scope and requested interface conflict")
            }
            Self::SourceSelectionUnavailable => {
                formatter.write_str("per-datagram source selection is unavailable")
            }
            Self::InterfaceSelectionUnavailable => {
                formatter.write_str("per-datagram interface selection is unavailable")
            }
            Self::EcnUnavailable => formatter.write_str("per-datagram ECN is unavailable"),
            Self::GsoUnavailable => formatter.write_str("UDP GSO is unavailable"),
            Self::DatagramTooLarge { length, maximum } => {
                write!(
                    formatter,
                    "datagram length {length} exceeds maximum {maximum}"
                )
            }
            Self::InvalidGsoSegment { size, length } => write!(
                formatter,
                "UDP GSO segment size {size} is invalid for payload length {length}"
            ),
            Self::TooManyGsoSegments { segments, maximum } => write!(
                formatter,
                "UDP GSO aggregate has {segments} segments, above maximum {maximum}"
            ),
        }
    }
}

/// Single-owner Linux socket with fixed startup-allocated batch descriptors.
///
/// `BATCH` is the maximum number of datagrams accepted by one `recvmmsg`
/// call. A smaller tail can use another adapter instantiation or the portable
/// single-datagram path. The type can move to an event-loop thread but cannot
/// be shared concurrently.
pub struct LinuxUdpSocket<const BATCH: usize> {
    socket: UdpSocket,
    socket_id: u16,
    local_endpoint: UdpEndpoint,
    exact_local_endpoint: bool,
    maximum_datagram_size: usize,
    capabilities: UdpCapabilities,
    rx_headers: MultiHeaders<SockaddrStorage>,
    tx_batch: LinuxSendBatch<BATCH>,
    single_owner: PhantomData<Cell<()>>,
}

impl<const BATCH: usize> LinuxUdpSocket<BATCH> {
    /// Binds and configures a nonblocking Linux UDP socket.
    ///
    /// # Errors
    ///
    /// Returns an address, socket-option, allocation-independent validation,
    /// or local-address error.
    pub fn bind(
        address: SocketAddr,
        socket_id: u16,
        maximum_datagram_size: usize,
        config: LinuxUdpConfig,
    ) -> Result<Self, LinuxUdpError> {
        let socket = UdpSocket::bind(address).map_err(LinuxUdpError::Io)?;
        Self::from_socket(socket, socket_id, maximum_datagram_size, config)
    }

    /// Takes ownership of a bound socket and enables requested Linux options.
    ///
    /// Control-message and syscall header storage is allocated exactly once
    /// here. The socket is switched to nonblocking mode before it is exposed.
    ///
    /// # Errors
    ///
    /// Returns an error when the maximum is invalid, local-address discovery
    /// fails, nonblocking mode fails, or a requested capability is rejected.
    pub fn from_socket(
        socket: UdpSocket,
        socket_id: u16,
        maximum_datagram_size: usize,
        config: LinuxUdpConfig,
    ) -> Result<Self, LinuxUdpError> {
        if !(1..=MAX_LINUX_DATAGRAM_SIZE).contains(&maximum_datagram_size) {
            return Err(LinuxUdpError::InvalidMaximumDatagramSize {
                size: maximum_datagram_size,
            });
        }

        socket.set_nonblocking(true).map_err(LinuxUdpError::Io)?;
        let local_address = socket.local_addr().map_err(LinuxUdpError::Io)?;
        let exact_local_endpoint = !local_address.ip().is_unspecified();

        if config.contains(LinuxUdpFeature::PacketInfo) {
            match local_address {
                SocketAddr::V4(_) => set_option(&socket, sockopt::Ipv4PacketInfo, &true)?,
                SocketAddr::V6(_) => set_option(&socket, sockopt::Ipv6RecvPacketInfo, &true)?,
            }
        }
        if config.contains(LinuxUdpFeature::Ecn) {
            match local_address {
                SocketAddr::V4(_) => set_option(&socket, sockopt::IpRecvTos, &true)?,
                SocketAddr::V6(_) => set_option(&socket, sockopt::Ipv6RecvTClass, &true)?,
            }
        }
        if config.contains(LinuxUdpFeature::ReceiveKernelTimestamp) {
            set_option(&socket, sockopt::ReceiveTimestampns, &true)?;
        }
        if config.contains(LinuxUdpFeature::ReceiveDropCounter) {
            set_option(&socket, sockopt::RxqOvfl, &1)?;
        }
        if config.contains(LinuxUdpFeature::UdpGro) {
            set_option(&socket, sockopt::UdpGroSegment, &true)?;
        }
        if config.contains(LinuxUdpFeature::UdpGso) {
            let _current_segment_size = get_option(&socket, sockopt::UdpGsoSegment)?;
        }

        let mut capabilities = UdpCapabilities::empty().with(UdpCapability::BatchedSyscalls);
        if config.contains(LinuxUdpFeature::PacketInfo) {
            capabilities = capabilities
                .with(UdpCapability::ExactReceiveDestination)
                .with(UdpCapability::ReceiveInterface)
                .with(UdpCapability::SourceSelection)
                .with(UdpCapability::TransmitInterface);
        } else if exact_local_endpoint {
            capabilities = capabilities.with(UdpCapability::ExactReceiveDestination);
        }
        if config.contains(LinuxUdpFeature::Ecn) {
            capabilities = capabilities
                .with(UdpCapability::ReceiveEcn)
                .with(UdpCapability::TransmitEcn);
        }
        if config.contains(LinuxUdpFeature::ReceiveKernelTimestamp) {
            capabilities = capabilities.with(UdpCapability::KernelReceiveTimestamp);
        }
        if config.contains(LinuxUdpFeature::ReceiveDropCounter) {
            capabilities = capabilities.with(UdpCapability::ReceiveDropCounter);
        }
        if config.contains(LinuxUdpFeature::UdpGro) {
            capabilities = capabilities.with(UdpCapability::UdpGro);
        }
        if config.contains(LinuxUdpFeature::UdpGso) {
            capabilities = capabilities.with(UdpCapability::UdpGso);
        }

        let control_space = nix::cmsg_space!(
            libc::in_pktinfo,
            libc::in6_pktinfo,
            u8,
            i32,
            i32,
            TimeSpec,
            u32
        );

        Ok(Self {
            socket,
            socket_id,
            local_endpoint: local_address.into(),
            exact_local_endpoint,
            maximum_datagram_size,
            capabilities,
            rx_headers: MultiHeaders::preallocate(BATCH, Some(control_space)),
            tx_batch: LinuxSendBatch::new().map_err(LinuxUdpError::Io)?,
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

    /// Returns the per-datagram size limit used after GRO segmentation.
    #[must_use]
    pub const fn maximum_datagram_size(&self) -> usize {
        self.maximum_datagram_size
    }

    /// Reports enabled metadata and Linux acceleration features.
    #[must_use]
    pub const fn capabilities(&self) -> UdpCapabilities {
        self.capabilities
    }

    /// Borrows the socket for readiness registration.
    ///
    /// The caller must preserve nonblocking mode and all enabled receive
    /// socket options.
    #[must_use]
    pub const fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Returns the owned socket.
    #[must_use]
    pub fn into_inner(self) -> UdpSocket {
        self.socket
    }

    /// Receives up to `BATCH` datagrams directly into fixed queue buffers.
    ///
    /// `now_micros` must come from the event loop's monotonic clock. Kernel
    /// timestamps use realtime and are exposed separately. The call uses
    /// `MSG_DONTWAIT | MSG_TRUNC` with no timeout; full kernel datagram lengths
    /// are therefore available without triggering the Linux timeout defect in
    /// `recvmmsg`.
    ///
    /// # Errors
    ///
    /// Returns socket, queue, or buffer-configuration errors. Every reserved
    /// slot is committed, cancelled and cleared, or returned unwritten before
    /// this method returns.
    pub fn try_receive_batch<const SLOTS: usize, const BUFFER_SIZE: usize>(
        &mut self,
        queue: &mut ReceiveQueue<SLOTS, BUFFER_SIZE>,
        now_micros: u64,
    ) -> Result<LinuxReceiveBatchOutcome, LinuxUdpError> {
        if BATCH == 0 {
            return Ok(LinuxReceiveBatchOutcome::Idle);
        }
        if BUFFER_SIZE < self.maximum_datagram_size {
            return Err(LinuxUdpError::ReceiveBufferTooSmall {
                capacity: BUFFER_SIZE,
                required: self.maximum_datagram_size,
            });
        }

        let batch = match queue.reserve_batch::<BATCH>() {
            Ok(batch) => batch,
            Err(RuntimeQueueError::PoolExhausted) => {
                return Ok(LinuxReceiveBatchOutcome::PoolExhausted);
            }
            Err(error) => return Err(LinuxUdpError::Queue(error)),
        };

        let context = ReceiveContext {
            socket_id: self.socket_id,
            local_endpoint: self.local_endpoint,
            exact_local_endpoint: self.exact_local_endpoint,
            maximum_datagram_size: self.maximum_datagram_size,
            buffer_size: BUFFER_SIZE,
            now_micros,
        };
        let mut records = [ReceiveRecord::Unused; BATCH];

        let syscall_result = {
            let buffers = queue
                .batch_buffers_mut(&batch)
                .map_err(LinuxUdpError::Queue)?;
            let mut io_vectors = buffers.map(|buffer| [IoSliceMut::new(buffer)]);
            recvmmsg(
                self.socket.as_raw_fd(),
                &mut self.rx_headers,
                io_vectors.iter_mut(),
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_TRUNC,
                None,
            )
            .map(|results| {
                let mut received = 0;
                for (position, message) in results.enumerate() {
                    records[position] = parse_receive_message(&message, context);
                    received += 1;
                }
                received
            })
        };

        let reservations = batch.into_reservations();
        match syscall_result {
            Ok(received) => resolve_received_batch(queue, reservations, records, received),
            Err(error) => resolve_failed_receive(queue, reservations, error),
        }
    }

    /// Submits exactly `BATCH` ready datagrams with one nonblocking
    /// `sendmmsg` call.
    ///
    /// Linux applies one ancillary set to the complete multi-message call, so
    /// source, interface, ECN, GSO size, and address family must be homogeneous
    /// across the batch. Destinations and payload lengths may differ. Callers
    /// should group the ready queue by this profile before using the method.
    ///
    /// A partial kernel result completes only its accepted prefix and requeues
    /// the suffix. `EAGAIN`, pacing, metadata rejection, and local view errors
    /// never lose ownership. A permanent socket error discards the encoded
    /// batch so protocol recovery can reschedule it without a local spin loop.
    ///
    /// # Errors
    ///
    /// Returns a queue, metadata, or socket error after every popped datagram
    /// has been completed, requeued, or discarded exactly once.
    pub fn try_transmit_batch<const SLOTS: usize, const BUFFER_SIZE: usize>(
        &mut self,
        queue: &mut TransmitQueue<SLOTS, BUFFER_SIZE>,
        now_micros: u64,
    ) -> Result<LinuxTransmitBatchOutcome, LinuxUdpError> {
        if BATCH == 0 {
            return Ok(LinuxTransmitBatchOutcome::Idle);
        }
        let ready_datagrams = queue.stats().ready;
        if ready_datagrams < BATCH {
            return if ready_datagrams == 0 {
                Ok(LinuxTransmitBatchOutcome::Idle)
            } else {
                Ok(LinuxTransmitBatchOutcome::IncompleteBatch { ready_datagrams })
            };
        }
        let batch = queue
            .pop_batch::<BATCH>()
            .ok_or(LinuxUdpError::Queue(RuntimeQueueError::InvariantViolation))?;

        let preparation = match prepare_transmit_batch(self, queue, &batch, now_micros) {
            Ok(preparation) => preparation,
            Err(error) => {
                requeue_transmit_datagrams(queue, batch.into_datagrams())?;
                return Err(match error {
                    TransmitPreparationError::Queue(error) => LinuxUdpError::Queue(error),
                    TransmitPreparationError::Rejected(error) => {
                        LinuxUdpError::UnsupportedTransmit(error)
                    }
                });
            }
        };
        let prepared = match preparation {
            PreparedTransmit::Ready(prepared) => prepared,
            PreparedTransmit::NotReady {
                send_not_before_micros,
            } => {
                requeue_transmit_datagrams(queue, batch.into_datagrams())?;
                return Ok(LinuxTransmitBatchOutcome::NotReady {
                    send_not_before_micros,
                });
            }
        };

        let send_result = self.submit_prepared_batch(queue, &batch, &prepared);
        let datagrams = batch.into_datagrams();
        match send_result {
            Ok(result) if result.sent() != 0 => {
                resolve_sent_batch(queue, datagrams, result, prepared.expected_lengths)
            }
            Ok(_) => {
                requeue_transmit_datagrams(queue, datagrams)?;
                Err(LinuxUdpError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "sendmmsg accepted an empty prefix",
                )))
            }
            Err(TransmitSubmissionError::Queue(error)) => {
                requeue_transmit_datagrams(queue, datagrams)?;
                Err(LinuxUdpError::Queue(error))
            }
            Err(TransmitSubmissionError::Io(error))
                if error.kind() == io::ErrorKind::WouldBlock =>
            {
                requeue_transmit_datagrams(queue, datagrams)?;
                Ok(LinuxTransmitBatchOutcome::WouldBlock)
            }
            Err(TransmitSubmissionError::Io(error)) => {
                discard_transmit_datagrams(queue, datagrams)?;
                Err(LinuxUdpError::Io(error))
            }
        }
    }

    fn submit_prepared_batch<const SLOTS: usize, const BUFFER_SIZE: usize>(
        &mut self,
        queue: &TransmitQueue<SLOTS, BUFFER_SIZE>,
        batch: &TransmitBatch<BATCH>,
        prepared: &PreparedTransmitBatch<BATCH>,
    ) -> Result<SendBatchResult<BATCH>, TransmitSubmissionError> {
        let mut payloads: [&[u8]; BATCH] = [&[]; BATCH];
        for (position, datagram) in batch.datagrams().iter().enumerate() {
            payloads[position] = queue
                .view(datagram)
                .map_err(TransmitSubmissionError::Queue)?
                .payload();
        }
        loop {
            let result = self.tx_batch.send(
                &self.socket,
                &payloads,
                &prepared.destinations,
                prepared.control,
            );
            if !matches!(&result, Err(error) if error.kind() == io::ErrorKind::Interrupted) {
                return result.map_err(TransmitSubmissionError::Io);
            }
        }
    }
}

impl<const BATCH: usize> fmt::Debug for LinuxUdpSocket<BATCH> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxUdpSocket")
            .field("socket_id", &self.socket_id)
            .field("local_endpoint", &"<redacted>")
            .field("maximum_datagram_size", &self.maximum_datagram_size)
            .field("batch_size", &BATCH)
            .field("capabilities", &self.capabilities)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
struct ReceiveContext {
    socket_id: u16,
    local_endpoint: UdpEndpoint,
    exact_local_endpoint: bool,
    maximum_datagram_size: usize,
    buffer_size: usize,
    now_micros: u64,
}

#[derive(Clone, Copy)]
enum ReceiveRecord {
    Unused,
    Dropped,
    Accepted {
        length: usize,
        metadata: ReceiveMetadata,
    },
}

enum PreparedTransmit<const BATCH: usize> {
    Ready(PreparedTransmitBatch<BATCH>),
    NotReady { send_not_before_micros: u64 },
}

struct PreparedTransmitBatch<const BATCH: usize> {
    destinations: [SocketAddr; BATCH],
    expected_lengths: [usize; BATCH],
    control: SendControl,
}

enum TransmitPreparationError {
    Queue(RuntimeQueueError),
    Rejected(LinuxTransmitRejection),
}

enum TransmitSubmissionError {
    Queue(RuntimeQueueError),
    Io(io::Error),
}

fn prepare_transmit_batch<const SLOTS: usize, const BUFFER_SIZE: usize, const BATCH: usize>(
    adapter: &LinuxUdpSocket<BATCH>,
    queue: &TransmitQueue<SLOTS, BUFFER_SIZE>,
    batch: &TransmitBatch<BATCH>,
    now_micros: u64,
) -> Result<PreparedTransmit<BATCH>, TransmitPreparationError> {
    let first_datagram = batch
        .datagrams()
        .first()
        .ok_or(TransmitPreparationError::Queue(
            RuntimeQueueError::InvariantViolation,
        ))?;
    let first_metadata = queue
        .view(first_datagram)
        .map_err(TransmitPreparationError::Queue)?
        .metadata();
    let first_destination = endpoint_to_socket_address(first_metadata.destination)
        .map_err(TransmitPreparationError::Rejected)?;
    let family = socket_address_family(first_destination);
    if family != endpoint_family(adapter.local_endpoint) {
        return Err(TransmitPreparationError::Rejected(
            LinuxTransmitRejection::AddressFamilyMismatch,
        ));
    }

    let (control_source, interface_index) = prepare_source_control(adapter, first_metadata, family)
        .map_err(TransmitPreparationError::Rejected)?;
    let ecn = if adapter.capabilities.contains(UdpCapability::TransmitEcn) {
        Some(ecn_to_bits(first_metadata.ecn))
    } else if first_metadata.ecn == EcnCodepoint::NotEct {
        None
    } else {
        return Err(TransmitPreparationError::Rejected(
            LinuxTransmitRejection::EcnUnavailable,
        ));
    };
    if first_metadata.gso_segment_size.is_some()
        && !adapter.capabilities.contains(UdpCapability::UdpGso)
    {
        return Err(TransmitPreparationError::Rejected(
            LinuxTransmitRejection::GsoUnavailable,
        ));
    }

    let mut destinations = core::array::from_fn(|_| first_destination);
    let mut expected_lengths = [0; BATCH];
    let mut future_deadline = None;
    for (position, datagram) in batch.datagrams().iter().enumerate() {
        let view = queue
            .view(datagram)
            .map_err(TransmitPreparationError::Queue)?;
        let metadata = view.metadata();
        validate_homogeneous_metadata(metadata, first_metadata, adapter.socket_id)
            .map_err(TransmitPreparationError::Rejected)?;
        let destination = endpoint_to_socket_address(metadata.destination)
            .map_err(TransmitPreparationError::Rejected)?;
        if socket_address_family(destination) != family {
            return Err(TransmitPreparationError::Rejected(
                LinuxTransmitRejection::AddressFamilyMismatch,
            ));
        }
        validate_destination_scope(destination, interface_index)
            .map_err(TransmitPreparationError::Rejected)?;
        validate_transmit_shape(
            view.payload().len(),
            metadata.gso_segment_size,
            adapter.maximum_datagram_size,
        )
        .map_err(TransmitPreparationError::Rejected)?;
        if metadata.send_not_before_micros > now_micros {
            future_deadline = Some(
                future_deadline.map_or(metadata.send_not_before_micros, |deadline: u64| {
                    deadline.min(metadata.send_not_before_micros)
                }),
            );
        }
        destinations[position] = destination;
        expected_lengths[position] = view.payload().len();
    }

    if let Some(send_not_before_micros) = future_deadline {
        return Ok(PreparedTransmit::NotReady {
            send_not_before_micros,
        });
    }
    Ok(PreparedTransmit::Ready(PreparedTransmitBatch {
        destinations,
        expected_lengths,
        control: SendControl {
            family,
            source: control_source,
            interface_index,
            ecn,
            gso_segment_size: first_metadata.gso_segment_size.map(NonZeroU16::get),
        },
    }))
}

fn prepare_source_control<const BATCH: usize>(
    adapter: &LinuxUdpSocket<BATCH>,
    metadata: TransmitMetadata,
    family: IpVersion,
) -> Result<(Option<IpAddr>, Option<u32>), LinuxTransmitRejection> {
    let mut interface_index = metadata.interface_index;
    let mut control_source = None;
    if let Some(source) = metadata.source {
        if source.port != adapter.local_endpoint.port {
            return Err(LinuxTransmitRejection::SourcePortMismatch {
                expected: adapter.local_endpoint.port,
                actual: source.port,
            });
        }
        let source_address = endpoint_to_socket_address(source)?;
        if socket_address_family(source_address) != family {
            return Err(LinuxTransmitRejection::AddressFamilyMismatch);
        }
        if let SocketAddr::V6(source) = source_address
            && source.scope_id() != 0
        {
            if interface_index.is_some_and(|index| index != source.scope_id()) {
                return Err(LinuxTransmitRejection::InterfaceScopeConflict);
            }
            interface_index = Some(source.scope_id());
        }
        if source != adapter.local_endpoint {
            if !adapter
                .capabilities
                .contains(UdpCapability::SourceSelection)
            {
                return Err(LinuxTransmitRejection::SourceSelectionUnavailable);
            }
            control_source = Some(source_address.ip());
        }
    }
    if interface_index.is_some()
        && !adapter
            .capabilities
            .contains(UdpCapability::TransmitInterface)
    {
        return Err(LinuxTransmitRejection::InterfaceSelectionUnavailable);
    }
    Ok((control_source, interface_index))
}

fn validate_homogeneous_metadata(
    metadata: TransmitMetadata,
    first: TransmitMetadata,
    socket_id: u16,
) -> Result<(), LinuxTransmitRejection> {
    if metadata.socket_id != socket_id {
        return Err(LinuxTransmitRejection::WrongSocket {
            expected: socket_id,
            actual: metadata.socket_id,
        });
    }
    if metadata.source != first.source
        || metadata.interface_index != first.interface_index
        || metadata.ecn != first.ecn
        || metadata.gso_segment_size != first.gso_segment_size
    {
        return Err(LinuxTransmitRejection::HeterogeneousBatch);
    }
    Ok(())
}

fn validate_transmit_shape(
    length: usize,
    segment_size: Option<NonZeroU16>,
    maximum_datagram_size: usize,
) -> Result<(), LinuxTransmitRejection> {
    let Some(segment_size) = segment_size else {
        return if length <= maximum_datagram_size {
            Ok(())
        } else {
            Err(LinuxTransmitRejection::DatagramTooLarge {
                length,
                maximum: maximum_datagram_size,
            })
        };
    };
    let segment_size = usize::from(segment_size.get());
    if segment_size > maximum_datagram_size || segment_size > length {
        return Err(LinuxTransmitRejection::InvalidGsoSegment {
            size: segment_size,
            length,
        });
    }
    let segments = length.div_ceil(segment_size);
    if segments > MAX_LINUX_GSO_SEGMENTS {
        return Err(LinuxTransmitRejection::TooManyGsoSegments {
            segments,
            maximum: MAX_LINUX_GSO_SEGMENTS,
        });
    }
    Ok(())
}

fn validate_destination_scope(
    destination: SocketAddr,
    interface_index: Option<u32>,
) -> Result<(), LinuxTransmitRejection> {
    if let SocketAddr::V6(destination) = destination
        && destination.scope_id() != 0
        && interface_index.is_some_and(|index| index != destination.scope_id())
    {
        return Err(LinuxTransmitRejection::InterfaceScopeConflict);
    }
    Ok(())
}

fn endpoint_to_socket_address(endpoint: UdpEndpoint) -> Result<SocketAddr, LinuxTransmitRejection> {
    if endpoint.port == 0 {
        return Err(LinuxTransmitRejection::ZeroDestinationPort);
    }
    match endpoint.address {
        IpAddress::V4(octets) => {
            if endpoint.scope_id != 0 {
                return Err(LinuxTransmitRejection::InvalidIpv4Scope);
            }
            Ok(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(octets),
                endpoint.port,
            )))
        }
        IpAddress::V6(octets) => Ok(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(octets),
            endpoint.port,
            0,
            endpoint.scope_id,
        ))),
    }
}

const fn endpoint_family(endpoint: UdpEndpoint) -> IpVersion {
    match endpoint.address {
        IpAddress::V4(_) => IpVersion::V4,
        IpAddress::V6(_) => IpVersion::V6,
    }
}

const fn socket_address_family(address: SocketAddr) -> IpVersion {
    match address {
        SocketAddr::V4(_) => IpVersion::V4,
        SocketAddr::V6(_) => IpVersion::V6,
    }
}

const fn ecn_to_bits(ecn: EcnCodepoint) -> u8 {
    match ecn {
        EcnCodepoint::NotEct => 0b00,
        EcnCodepoint::Ect1 => 0b01,
        EcnCodepoint::Ect0 => 0b10,
        EcnCodepoint::Ce => 0b11,
    }
}

fn requeue_transmit_datagrams<const SLOTS: usize, const BUFFER_SIZE: usize, const BATCH: usize>(
    queue: &mut TransmitQueue<SLOTS, BUFFER_SIZE>,
    datagrams: [TransmitDatagram; BATCH],
) -> Result<(), LinuxUdpError> {
    resolve_transmit_datagrams(queue, datagrams, false)
}

fn discard_transmit_datagrams<const SLOTS: usize, const BUFFER_SIZE: usize, const BATCH: usize>(
    queue: &mut TransmitQueue<SLOTS, BUFFER_SIZE>,
    datagrams: [TransmitDatagram; BATCH],
) -> Result<(), LinuxUdpError> {
    resolve_transmit_datagrams(queue, datagrams, true)
}

fn resolve_transmit_datagrams<const SLOTS: usize, const BUFFER_SIZE: usize, const BATCH: usize>(
    queue: &mut TransmitQueue<SLOTS, BUFFER_SIZE>,
    datagrams: [TransmitDatagram; BATCH],
    discard: bool,
) -> Result<(), LinuxUdpError> {
    let mut first_error = None;
    for datagram in datagrams {
        let result = if discard {
            queue.discard(datagram)
        } else {
            queue.requeue(datagram)
        };
        if first_error.is_none() {
            first_error = result.err();
        }
    }
    first_error.map_or(Ok(()), |error| Err(LinuxUdpError::Queue(error)))
}

fn resolve_sent_batch<const SLOTS: usize, const BUFFER_SIZE: usize, const BATCH: usize>(
    queue: &mut TransmitQueue<SLOTS, BUFFER_SIZE>,
    datagrams: [TransmitDatagram; BATCH],
    result: SendBatchResult<BATCH>,
    expected_lengths: [usize; BATCH],
) -> Result<LinuxTransmitBatchOutcome, LinuxUdpError> {
    let mut first_queue_error = None;
    let mut length_mismatch = false;
    let mut sent_bytes = Some(0usize);
    for (position, datagram) in datagrams.into_iter().enumerate() {
        let resolution = if position < result.sent() {
            length_mismatch |= result.lengths()[position] != expected_lengths[position];
            sent_bytes = sent_bytes.and_then(|total| total.checked_add(result.lengths()[position]));
            queue.complete(datagram)
        } else {
            queue.requeue(datagram)
        };
        if first_queue_error.is_none() {
            first_queue_error = resolution.err();
        }
    }
    if let Some(error) = first_queue_error {
        return Err(LinuxUdpError::Queue(error));
    }
    let Some(sent_bytes) = sent_bytes else {
        return Err(LinuxUdpError::Queue(RuntimeQueueError::InvariantViolation));
    };
    if length_mismatch {
        return Err(LinuxUdpError::Io(io::Error::new(
            io::ErrorKind::WriteZero,
            "sendmmsg reported a partial UDP datagram",
        )));
    }
    Ok(LinuxTransmitBatchOutcome::Sent {
        sent_datagrams: result.sent(),
        sent_bytes,
        requeued_datagrams: BATCH - result.sent(),
    })
}

#[derive(Default)]
struct AncillaryData {
    destination: Option<UdpEndpoint>,
    interface_index: Option<u32>,
    ecn: Option<EcnCodepoint>,
    kernel_timestamp_unix_nanos: Option<u64>,
    socket_drop_count: Option<u32>,
    gro_segment_size: Option<NonZeroU16>,
    conflict: bool,
}

fn parse_receive_message(
    message: &RecvMsg<'_, '_, SockaddrStorage>,
    context: ReceiveContext,
) -> ReceiveRecord {
    if message.bytes == 0
        || message.bytes > context.buffer_size
        || message
            .flags
            .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
    {
        return ReceiveRecord::Dropped;
    }
    let Some(source) = message.address.as_ref().and_then(endpoint_from_storage) else {
        return ReceiveRecord::Dropped;
    };

    let Ok(control_messages) = message.cmsgs() else {
        return ReceiveRecord::Dropped;
    };
    let mut ancillary = AncillaryData::default();
    for control in control_messages {
        apply_control_message(&mut ancillary, &control, context.local_endpoint.port);
    }

    let segment_size = ancillary
        .gro_segment_size
        .map_or(message.bytes, |size| usize::from(size.get()));
    if ancillary.conflict
        || segment_size > context.maximum_datagram_size
        || segment_size > message.bytes
        || (ancillary.gro_segment_size.is_none() && message.bytes > context.maximum_datagram_size)
    {
        return ReceiveRecord::Dropped;
    }

    ReceiveRecord::Accepted {
        length: message.bytes,
        metadata: ReceiveMetadata {
            source,
            destination: ancillary.destination.or_else(|| {
                context
                    .exact_local_endpoint
                    .then_some(context.local_endpoint)
            }),
            socket_id: context.socket_id,
            interface_index: ancillary.interface_index,
            ecn: ancillary.ecn,
            received_at_micros: context.now_micros,
            kernel_timestamp_unix_nanos: ancillary.kernel_timestamp_unix_nanos,
            socket_drop_count: ancillary.socket_drop_count,
            gro_segment_size: ancillary.gro_segment_size,
        },
    }
}

fn apply_control_message(
    ancillary: &mut AncillaryData,
    control: &ControlMessageOwned,
    local_port: u16,
) {
    match control {
        ControlMessageOwned::Ipv4PacketInfo(info) => {
            let destination = UdpEndpoint {
                address: IpAddress::V4(info.ipi_addr.s_addr.to_ne_bytes()),
                port: local_port,
                scope_id: 0,
            };
            merge_ancillary(
                &mut ancillary.destination,
                destination,
                &mut ancillary.conflict,
            );
            if info.ipi_ifindex > 0 {
                merge_ancillary(
                    &mut ancillary.interface_index,
                    info.ipi_ifindex.cast_unsigned(),
                    &mut ancillary.conflict,
                );
            }
        }
        ControlMessageOwned::Ipv6PacketInfo(info) => {
            let destination = UdpEndpoint {
                address: IpAddress::V6(info.ipi6_addr.s6_addr),
                port: local_port,
                scope_id: info.ipi6_ifindex,
            };
            merge_ancillary(
                &mut ancillary.destination,
                destination,
                &mut ancillary.conflict,
            );
            if info.ipi6_ifindex != 0 {
                merge_ancillary(
                    &mut ancillary.interface_index,
                    info.ipi6_ifindex,
                    &mut ancillary.conflict,
                );
            }
        }
        ControlMessageOwned::Ipv4Tos(value) => merge_ancillary(
            &mut ancillary.ecn,
            ecn_from_bits(*value),
            &mut ancillary.conflict,
        ),
        ControlMessageOwned::Ipv6TClass(value) => {
            let Ok(value) = u8::try_from(value & 0xff) else {
                ancillary.conflict = true;
                return;
            };
            merge_ancillary(
                &mut ancillary.ecn,
                ecn_from_bits(value),
                &mut ancillary.conflict,
            );
        }
        ControlMessageOwned::ScmTimestampns(timestamp) => {
            let Some(timestamp) = timestamp_to_unix_nanos(*timestamp) else {
                ancillary.conflict = true;
                return;
            };
            merge_ancillary(
                &mut ancillary.kernel_timestamp_unix_nanos,
                timestamp,
                &mut ancillary.conflict,
            );
        }
        ControlMessageOwned::RxqOvfl(count) => merge_ancillary(
            &mut ancillary.socket_drop_count,
            *count,
            &mut ancillary.conflict,
        ),
        ControlMessageOwned::UdpGroSegments(size) => {
            let Ok(size) = u16::try_from(*size) else {
                ancillary.conflict = true;
                return;
            };
            let Some(size) = NonZeroU16::new(size) else {
                ancillary.conflict = true;
                return;
            };
            merge_ancillary(
                &mut ancillary.gro_segment_size,
                size,
                &mut ancillary.conflict,
            );
        }
        _ => {}
    }
}

fn resolve_received_batch<const SLOTS: usize, const BUFFER_SIZE: usize, const BATCH: usize>(
    queue: &mut ReceiveQueue<SLOTS, BUFFER_SIZE>,
    reservations: [super::ReceiveReservation; BATCH],
    records: [ReceiveRecord; BATCH],
    received: usize,
) -> Result<LinuxReceiveBatchOutcome, LinuxUdpError> {
    let mut committed_datagrams = 0;
    let mut committed_bytes = 0;
    let mut dropped_datagrams = 0;
    let mut first_error = None;

    for (position, reservation) in reservations.into_iter().enumerate() {
        let result = match records[position] {
            ReceiveRecord::Accepted { length, metadata } => {
                committed_datagrams += 1;
                committed_bytes += length;
                queue.commit(reservation, length, metadata)
            }
            ReceiveRecord::Dropped => {
                dropped_datagrams += 1;
                queue.cancel(reservation)
            }
            ReceiveRecord::Unused => {
                debug_assert!(position >= received);
                queue.release_unwritten_receive_reservation(reservation)
            }
        };
        if first_error.is_none() {
            first_error = result.err();
        }
    }

    if let Some(error) = first_error {
        return Err(LinuxUdpError::Queue(error));
    }
    Ok(LinuxReceiveBatchOutcome::Received {
        committed_datagrams,
        committed_bytes,
        dropped_datagrams,
    })
}

fn resolve_failed_receive<const SLOTS: usize, const BUFFER_SIZE: usize, const BATCH: usize>(
    queue: &mut ReceiveQueue<SLOTS, BUFFER_SIZE>,
    reservations: [super::ReceiveReservation; BATCH],
    error: Errno,
) -> Result<LinuxReceiveBatchOutcome, LinuxUdpError> {
    let would_block = error == Errno::EAGAIN;
    let mut first_error = None;
    for reservation in reservations {
        let result = if would_block {
            queue.release_unwritten_receive_reservation(reservation)
        } else {
            queue.cancel(reservation)
        };
        if first_error.is_none() {
            first_error = result.err();
        }
    }
    if let Some(queue_error) = first_error {
        return Err(LinuxUdpError::Queue(queue_error));
    }
    if would_block {
        Ok(LinuxReceiveBatchOutcome::WouldBlock)
    } else {
        Err(LinuxUdpError::Io(errno_to_io(error)))
    }
}

fn endpoint_from_storage(storage: &SockaddrStorage) -> Option<UdpEndpoint> {
    if let Some(address) = storage.as_sockaddr_in() {
        let address = SocketAddr::V4((*address).into());
        return Some(address.into());
    }
    storage.as_sockaddr_in6().map(|address| {
        let address = SocketAddr::V6((*address).into());
        address.into()
    })
}

fn merge_ancillary<T: Copy + Eq>(slot: &mut Option<T>, value: T, conflict: &mut bool) {
    if slot.is_some_and(|existing| existing != value) {
        *conflict = true;
    } else {
        *slot = Some(value);
    }
}

const fn ecn_from_bits(value: u8) -> EcnCodepoint {
    match value & 0b11 {
        0b00 => EcnCodepoint::NotEct,
        0b01 => EcnCodepoint::Ect1,
        0b10 => EcnCodepoint::Ect0,
        _ => EcnCodepoint::Ce,
    }
}

fn timestamp_to_unix_nanos(timestamp: TimeSpec) -> Option<u64> {
    let seconds = u64::try_from(timestamp.tv_sec()).ok()?;
    let nanoseconds = u64::try_from(timestamp.tv_nsec()).ok()?;
    if nanoseconds >= 1_000_000_000 {
        return None;
    }
    seconds.checked_mul(1_000_000_000)?.checked_add(nanoseconds)
}

fn set_option<O: nix::sys::socket::SetSockOpt>(
    socket: &UdpSocket,
    option: O,
    value: &O::Val,
) -> Result<(), LinuxUdpError> {
    setsockopt(socket, option, value).map_err(|error| LinuxUdpError::Io(errno_to_io(error)))
}

fn get_option<O: nix::sys::socket::GetSockOpt>(
    socket: &UdpSocket,
    option: O,
) -> Result<O::Val, LinuxUdpError> {
    getsockopt(socket, option).map_err(|error| LinuxUdpError::Io(errno_to_io(error)))
}

fn errno_to_io(error: Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn localhost() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 0))
    }

    fn enqueue<const SLOTS: usize, const BUFFER_SIZE: usize>(
        queue: &mut TransmitQueue<SLOTS, BUFFER_SIZE>,
        payload: &[u8],
        metadata: TransmitMetadata,
    ) {
        let reservation = queue.reserve().expect("reserve");
        queue.buffer_mut(&reservation).expect("buffer")[..payload.len()].copy_from_slice(payload);
        queue
            .commit(reservation, payload.len(), metadata)
            .expect("commit");
    }

    fn transmit_metadata(
        adapter: &LinuxUdpSocket<2>,
        destination: SocketAddr,
        deadline: u64,
        ecn: EcnCodepoint,
    ) -> TransmitMetadata {
        TransmitMetadata {
            source: None,
            destination: destination.into(),
            socket_id: adapter.socket_id(),
            interface_index: None,
            ecn,
            send_not_before_micros: deadline,
            gso_segment_size: None,
        }
    }

    #[test]
    fn feature_set_is_explicit_and_compact() {
        let config = LinuxUdpConfig::empty()
            .with(LinuxUdpFeature::PacketInfo)
            .with(LinuxUdpFeature::UdpGro);
        assert!(config.contains(LinuxUdpFeature::PacketInfo));
        assert!(config.contains(LinuxUdpFeature::UdpGro));
        assert!(!config.contains(LinuxUdpFeature::Ecn));
    }

    #[test]
    fn ecn_and_timestamp_conversion_are_fail_closed() {
        assert_eq!(ecn_from_bits(0xfc), EcnCodepoint::NotEct);
        assert_eq!(ecn_from_bits(0xfd), EcnCodepoint::Ect1);
        assert_eq!(ecn_from_bits(0xfe), EcnCodepoint::Ect0);
        assert_eq!(ecn_from_bits(0xff), EcnCodepoint::Ce);
        assert_eq!(
            timestamp_to_unix_nanos(TimeSpec::new(7, 23)),
            Some(7_000_000_023)
        );
        assert_eq!(timestamp_to_unix_nanos(TimeSpec::new(-1, 0)), None);
        assert_eq!(
            timestamp_to_unix_nanos(TimeSpec::new(0, 1_000_000_000)),
            None
        );
    }

    #[test]
    fn empty_socket_receive_is_nonblocking_and_restores_batch() {
        let mut adapter = LinuxUdpSocket::<2>::bind(localhost(), 9, 1_200, LinuxUdpConfig::empty())
            .expect("adapter");
        let mut queue = ReceiveQueue::<2, 1_200>::new();

        assert_eq!(
            adapter.try_receive_batch(&mut queue, 42).expect("receive"),
            LinuxReceiveBatchOutcome::WouldBlock
        );
        assert_eq!(queue.stats().free, 2);
        assert_eq!(queue.stats().ready, 0);
    }

    #[test]
    fn batch_receive_commits_payloads_in_kernel_order() {
        let mut adapter =
            LinuxUdpSocket::<2>::bind(localhost(), 11, 1_200, LinuxUdpConfig::empty())
                .expect("adapter");
        let sender = UdpSocket::bind(localhost()).expect("sender");
        sender
            .send_to(b"first", adapter.socket().local_addr().expect("local"))
            .expect("first send");
        sender
            .send_to(b"second", adapter.socket().local_addr().expect("local"))
            .expect("second send");

        let mut queue = ReceiveQueue::<2, 1_200>::new();
        assert_eq!(
            adapter.try_receive_batch(&mut queue, 73).expect("receive"),
            LinuxReceiveBatchOutcome::Received {
                committed_datagrams: 2,
                committed_bytes: 11,
                dropped_datagrams: 0,
            }
        );

        let first = queue.pop().expect("first datagram");
        assert_eq!(queue.view(&first).expect("first view").payload(), b"first");
        queue.release(first).expect("release first");
        let second = queue.pop().expect("second datagram");
        assert_eq!(
            queue.view(&second).expect("second view").payload(),
            b"second"
        );
        queue.release(second).expect("release second");
    }

    #[test]
    fn oversized_datagram_is_dropped_and_cleared() {
        let mut adapter = LinuxUdpSocket::<1>::bind(localhost(), 13, 8, LinuxUdpConfig::empty())
            .expect("adapter");
        let sender = UdpSocket::bind(localhost()).expect("sender");
        sender
            .send_to(b"ninebytes", adapter.socket().local_addr().expect("local"))
            .expect("send");

        let mut queue = ReceiveQueue::<1, 16>::new();
        assert_eq!(
            adapter.try_receive_batch(&mut queue, 91).expect("receive"),
            LinuxReceiveBatchOutcome::Received {
                committed_datagrams: 0,
                committed_bytes: 0,
                dropped_datagrams: 1,
            }
        );
        assert_eq!(queue.stats().free, 1);
        assert!(queue.pop().is_none());
    }

    #[test]
    fn batch_transmit_completes_payloads_in_order() {
        let receiver = UdpSocket::bind(localhost()).expect("receiver");
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("timeout");
        let destination = receiver.local_addr().expect("destination");
        let mut adapter =
            LinuxUdpSocket::<2>::bind(localhost(), 17, 1_200, LinuxUdpConfig::empty())
                .expect("adapter");
        let metadata = transmit_metadata(&adapter, destination, 0, EcnCodepoint::NotEct);
        let mut queue = TransmitQueue::<2, 1_200>::new();
        enqueue(&mut queue, b"one", metadata);
        enqueue(&mut queue, b"three", metadata);

        assert_eq!(
            adapter.try_transmit_batch(&mut queue, 5).expect("send"),
            LinuxTransmitBatchOutcome::Sent {
                sent_datagrams: 2,
                sent_bytes: 8,
                requeued_datagrams: 0,
            }
        );
        assert_eq!(queue.stats().free, 2);

        let mut payload = [0; 16];
        let (length, _) = receiver.recv_from(&mut payload).expect("first receive");
        assert_eq!(&payload[..length], b"one");
        let (length, _) = receiver.recv_from(&mut payload).expect("second receive");
        assert_eq!(&payload[..length], b"three");
    }

    #[test]
    fn pacing_and_heterogeneous_metadata_requeue_the_complete_batch() {
        let receiver = UdpSocket::bind(localhost()).expect("receiver");
        let destination = receiver.local_addr().expect("destination");
        let mut adapter =
            LinuxUdpSocket::<2>::bind(localhost(), 19, 1_200, LinuxUdpConfig::empty())
                .expect("adapter");
        let mut queue = TransmitQueue::<2, 1_200>::new();
        enqueue(
            &mut queue,
            b"a",
            transmit_metadata(&adapter, destination, 50, EcnCodepoint::NotEct),
        );
        enqueue(
            &mut queue,
            b"b",
            transmit_metadata(&adapter, destination, 70, EcnCodepoint::NotEct),
        );
        assert_eq!(
            adapter.try_transmit_batch(&mut queue, 49).expect("pacing"),
            LinuxTransmitBatchOutcome::NotReady {
                send_not_before_micros: 50,
            }
        );
        assert_eq!(queue.stats().ready, 2);

        let first = queue.pop().expect("first");
        queue.discard(first).expect("discard first");
        let second = queue.pop().expect("second");
        queue.discard(second).expect("discard second");
        enqueue(
            &mut queue,
            b"a",
            transmit_metadata(&adapter, destination, 0, EcnCodepoint::NotEct),
        );
        enqueue(
            &mut queue,
            b"b",
            transmit_metadata(&adapter, destination, 0, EcnCodepoint::Ect0),
        );
        assert!(matches!(
            adapter.try_transmit_batch(&mut queue, 1),
            Err(LinuxUdpError::UnsupportedTransmit(
                LinuxTransmitRejection::HeterogeneousBatch
            ))
        ));
        assert_eq!(queue.stats().ready, 2);
    }

    #[test]
    fn gso_validation_enforces_datagram_and_aggregate_limits() {
        assert_eq!(
            validate_transmit_shape(1_201, None, 1_200),
            Err(LinuxTransmitRejection::DatagramTooLarge {
                length: 1_201,
                maximum: 1_200,
            })
        );
        assert_eq!(
            validate_transmit_shape(1_000, NonZeroU16::new(1_001), 1_200),
            Err(LinuxTransmitRejection::InvalidGsoSegment {
                size: 1_001,
                length: 1_000,
            })
        );
        assert_eq!(
            validate_transmit_shape(65, NonZeroU16::new(1), 1_200),
            Err(LinuxTransmitRejection::TooManyGsoSegments {
                segments: 65,
                maximum: MAX_LINUX_GSO_SEGMENTS,
            })
        );
    }
}
