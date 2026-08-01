//! Fixed-capacity building blocks for a single-owner UDP event loop.
//!
//! This module owns no socket and performs no system call. It provides the
//! bounded buffer queues, kernel-completion ownership, endpoint metadata, and
//! monotonic timer queue needed by portable and platform-specific adapters.

use core::fmt;
use core::num::NonZeroU16;
use zeroize::Zeroize;

use crate::ecn::EcnCodepoint;

/// IPv4 or IPv6 address stored without allocation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IpAddress {
    V4([u8; 4]),
    V6([u8; 16]),
}

/// UDP endpoint stored without allocation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UdpEndpoint {
    pub address: IpAddress,
    pub port: u16,
}

/// Ancillary metadata attached to one received UDP buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveMetadata {
    pub source: UdpEndpoint,
    pub destination: UdpEndpoint,
    pub socket_id: u16,
    pub interface_index: u32,
    pub ecn: EcnCodepoint,
    pub received_at_micros: u64,
    /// UDP GRO segment size. `None` means the buffer contains one datagram.
    pub gro_segment_size: Option<NonZeroU16>,
}

/// Routing and ancillary metadata for one outgoing UDP buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransmitMetadata {
    pub source: UdpEndpoint,
    pub destination: UdpEndpoint,
    pub socket_id: u16,
    pub interface_index: u32,
    pub ecn: EcnCodepoint,
    pub send_not_before_micros: u64,
    /// UDP GSO segment size. `None` submits one datagram.
    pub gso_segment_size: Option<NonZeroU16>,
}

/// Fixed queue resource counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferQueueStats {
    pub capacity: usize,
    pub free: usize,
    pub ready: usize,
    pub reserved_or_delivered: usize,
    pub kernel_owned: usize,
}

/// Receive-buffer reservation owned by a socket adapter.
#[must_use = "a receive reservation must be committed or cancelled"]
pub struct ReceiveReservation {
    index: usize,
    generation: u32,
}

impl fmt::Debug for ReceiveReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReceiveReservation(<redacted>)")
    }
}

/// Completed receive-buffer ownership returned to the event loop.
#[must_use = "a received datagram must be released"]
pub struct ReceivedDatagram {
    index: usize,
    generation: u32,
}

impl fmt::Debug for ReceivedDatagram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReceivedDatagram(<redacted>)")
    }
}

/// Borrowed untrusted datagram and kernel-supplied metadata.
pub struct ReceivedDatagramView<'a> {
    payload: &'a [u8],
    metadata: ReceiveMetadata,
}

impl fmt::Debug for ReceivedDatagramView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceivedDatagramView")
            .field(
                "payload",
                &format_args!("<redacted, {} bytes>", self.payload.len()),
            )
            .field("metadata", &"<redacted>")
            .finish()
    }
}

impl<'a> ReceivedDatagramView<'a> {
    /// Returns the exact bytes received from the socket adapter.
    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Returns the ancillary metadata captured with the buffer.
    #[must_use]
    pub const fn metadata(&self) -> ReceiveMetadata {
        self.metadata
    }

    /// Iterates one datagram or the individual datagrams coalesced by UDP GRO.
    #[must_use]
    pub fn segments(&self) -> DatagramSegments<'a> {
        DatagramSegments {
            payload: self.payload,
            segment_size: self
                .metadata
                .gro_segment_size
                .map_or(self.payload.len(), |size| usize::from(size.get())),
            offset: 0,
        }
    }
}

/// Iterator over one ordinary datagram or one UDP GRO buffer.
pub struct DatagramSegments<'a> {
    payload: &'a [u8],
    segment_size: usize,
    offset: usize,
}

impl<'a> Iterator for DatagramSegments<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.payload.len() {
            return None;
        }
        let end = self
            .offset
            .saturating_add(self.segment_size)
            .min(self.payload.len());
        let segment = &self.payload[self.offset..end];
        self.offset = end;
        Some(segment)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.payload.len().saturating_sub(self.offset);
        let count = remaining.div_ceil(self.segment_size);
        (count, Some(count))
    }
}

impl ExactSizeIterator for DatagramSegments<'_> {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiveState {
    Free,
    Reserved,
    Ready,
    Delivered,
}

struct ReceiveSlot<const BUFFER_SIZE: usize> {
    bytes: [u8; BUFFER_SIZE],
    length: usize,
    metadata: Option<ReceiveMetadata>,
    generation: u32,
    state: ReceiveState,
}

impl<const BUFFER_SIZE: usize> ReceiveSlot<BUFFER_SIZE> {
    const fn new() -> Self {
        Self {
            bytes: [0; BUFFER_SIZE],
            length: 0,
            metadata: None,
            generation: 0,
            state: ReceiveState::Free,
        }
    }
}

/// Separate fixed receive arena and completion-order queue.
///
/// Construction allocates no heap storage. A caller may place the whole arena
/// in a preallocated box or connection-owner region during startup.
pub struct ReceiveQueue<const SLOTS: usize, const BUFFER_SIZE: usize> {
    slots: [ReceiveSlot<BUFFER_SIZE>; SLOTS],
    free: IndexQueue<SLOTS>,
    ready: IndexQueue<SLOTS>,
}

impl<const SLOTS: usize, const BUFFER_SIZE: usize> ReceiveQueue<SLOTS, BUFFER_SIZE> {
    /// Creates a queue with every slot free and zeroed.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [const { ReceiveSlot::new() }; SLOTS],
            free: IndexQueue::with_all_indices(),
            ready: IndexQueue::new(),
        }
    }

    /// Reserves one stable receive buffer for a socket operation.
    ///
    /// # Errors
    ///
    /// Returns pool exhaustion or generation exhaustion without modifying any
    /// occupied slot.
    pub fn reserve(&mut self) -> Result<ReceiveReservation, RuntimeQueueError> {
        for _ in 0..SLOTS {
            let index = self.free.pop().ok_or(RuntimeQueueError::PoolExhausted)?;
            let Some(generation) = self.slots[index].generation.checked_add(1) else {
                let restored = self.free.push(index);
                debug_assert!(restored);
                continue;
            };
            let slot = &mut self.slots[index];
            debug_assert_eq!(slot.state, ReceiveState::Free);
            slot.generation = generation;
            slot.state = ReceiveState::Reserved;
            return Ok(ReceiveReservation { index, generation });
        }
        Err(RuntimeQueueError::GenerationExhausted)
    }

    /// Returns the complete stable buffer for one outstanding receive.
    ///
    /// # Errors
    ///
    /// Returns `InvalidOwnership` for a stale, released, or wrong-state token.
    pub fn buffer_mut(
        &mut self,
        reservation: &ReceiveReservation,
    ) -> Result<&mut [u8], RuntimeQueueError> {
        let slot = self.receive_slot_mut(
            reservation.index,
            reservation.generation,
            ReceiveState::Reserved,
        )?;
        Ok(&mut slot.bytes)
    }

    /// Commits the bytes and ancillary metadata produced by one receive.
    ///
    /// Invalid length or GRO metadata releases and clears the reservation.
    ///
    /// # Errors
    ///
    /// Returns an ownership, empty-datagram, length, segment, or internal
    /// invariant error.
    pub fn commit(
        &mut self,
        reservation: ReceiveReservation,
        length: usize,
        metadata: ReceiveMetadata,
    ) -> Result<(), RuntimeQueueError> {
        if let Err(error) =
            validate_datagram_shape::<BUFFER_SIZE>(length, metadata.gro_segment_size)
        {
            self.release_receive_reservation(reservation)?;
            return Err(error);
        }
        let slot = self.receive_slot_mut(
            reservation.index,
            reservation.generation,
            ReceiveState::Reserved,
        )?;
        slot.length = length;
        slot.metadata = Some(metadata);
        slot.state = ReceiveState::Ready;
        if !self.ready.push(reservation.index) {
            self.clear_receive_slot(reservation.index, true);
            return Err(RuntimeQueueError::InvariantViolation);
        }
        Ok(())
    }

    /// Cancels and clears an outstanding receive reservation.
    ///
    /// # Errors
    ///
    /// Returns `InvalidOwnership` for a stale or wrong-state reservation.
    pub fn cancel(&mut self, reservation: ReceiveReservation) -> Result<(), RuntimeQueueError> {
        self.release_receive_reservation(reservation)
    }

    /// Pops the next completed buffer in receive-completion order.
    #[must_use]
    pub fn pop(&mut self) -> Option<ReceivedDatagram> {
        let index = self.ready.pop()?;
        let slot = &mut self.slots[index];
        debug_assert_eq!(slot.state, ReceiveState::Ready);
        slot.state = ReceiveState::Delivered;
        Some(ReceivedDatagram {
            index,
            generation: slot.generation,
        })
    }

    /// Borrows the exact received bytes and metadata.
    ///
    /// # Errors
    ///
    /// Returns `InvalidOwnership` for a stale, released, or wrong-state token.
    pub fn view(
        &self,
        datagram: &ReceivedDatagram,
    ) -> Result<ReceivedDatagramView<'_>, RuntimeQueueError> {
        let slot =
            self.receive_slot(datagram.index, datagram.generation, ReceiveState::Delivered)?;
        let metadata = slot.metadata.ok_or(RuntimeQueueError::InvariantViolation)?;
        Ok(ReceivedDatagramView {
            payload: &slot.bytes[..slot.length],
            metadata,
        })
    }

    /// Releases a delivered datagram and clears its used bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidOwnership` for a stale or wrong-state token.
    #[allow(clippy::needless_pass_by_value)] // Consuming the token enforces single ownership.
    pub fn release(&mut self, datagram: ReceivedDatagram) -> Result<(), RuntimeQueueError> {
        self.receive_slot(datagram.index, datagram.generation, ReceiveState::Delivered)?;
        self.clear_receive_slot(datagram.index, false);
        Ok(())
    }

    /// Returns current fixed-resource counters.
    #[must_use]
    pub fn stats(&self) -> BufferQueueStats {
        let delivered = self
            .slots
            .iter()
            .filter(|slot| matches!(slot.state, ReceiveState::Reserved | ReceiveState::Delivered))
            .count();
        BufferQueueStats {
            capacity: SLOTS,
            free: self.free.len(),
            ready: self.ready.len(),
            reserved_or_delivered: delivered,
            kernel_owned: 0,
        }
    }

    #[allow(clippy::needless_pass_by_value)] // Consuming the token prevents duplicate release.
    fn release_receive_reservation(
        &mut self,
        reservation: ReceiveReservation,
    ) -> Result<(), RuntimeQueueError> {
        self.receive_slot(
            reservation.index,
            reservation.generation,
            ReceiveState::Reserved,
        )?;
        self.clear_receive_slot(reservation.index, true);
        Ok(())
    }

    fn receive_slot(
        &self,
        index: usize,
        generation: u32,
        state: ReceiveState,
    ) -> Result<&ReceiveSlot<BUFFER_SIZE>, RuntimeQueueError> {
        let slot = self
            .slots
            .get(index)
            .ok_or(RuntimeQueueError::InvalidOwnership)?;
        if slot.generation != generation || slot.state != state {
            return Err(RuntimeQueueError::InvalidOwnership);
        }
        Ok(slot)
    }

    fn receive_slot_mut(
        &mut self,
        index: usize,
        generation: u32,
        state: ReceiveState,
    ) -> Result<&mut ReceiveSlot<BUFFER_SIZE>, RuntimeQueueError> {
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(RuntimeQueueError::InvalidOwnership)?;
        if slot.generation != generation || slot.state != state {
            return Err(RuntimeQueueError::InvalidOwnership);
        }
        Ok(slot)
    }

    fn clear_receive_slot(&mut self, index: usize, clear_complete_buffer: bool) {
        let slot = &mut self.slots[index];
        let clear_length = if clear_complete_buffer {
            BUFFER_SIZE
        } else {
            slot.length
        };
        slot.bytes[..clear_length].fill(0);
        slot.length = 0;
        slot.metadata = None;
        slot.state = ReceiveState::Free;
        let restored = self.free.push(index);
        debug_assert!(restored);
    }
}

impl<const SLOTS: usize, const BUFFER_SIZE: usize> Default for ReceiveQueue<SLOTS, BUFFER_SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const SLOTS: usize, const BUFFER_SIZE: usize> Drop for ReceiveQueue<SLOTS, BUFFER_SIZE> {
    fn drop(&mut self) {
        for slot in &mut self.slots {
            slot.bytes.zeroize();
            slot.length = 0;
            slot.metadata = None;
            slot.state = ReceiveState::Free;
        }
    }
}

impl<const SLOTS: usize, const BUFFER_SIZE: usize> fmt::Debug for ReceiveQueue<SLOTS, BUFFER_SIZE> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceiveQueue")
            .field("stats", &self.stats())
            .field("buffers", &"<redacted>")
            .finish()
    }
}

/// Transmit-buffer reservation owned by the protocol event loop.
#[must_use = "a transmit reservation must be committed or cancelled"]
pub struct TransmitReservation {
    index: usize,
    generation: u32,
}

impl fmt::Debug for TransmitReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TransmitReservation(<redacted>)")
    }
}

/// Ready transmit-buffer ownership returned to a socket adapter.
#[must_use = "a submitted datagram must be completed, deferred, or requeued"]
pub struct TransmitDatagram {
    index: usize,
    generation: u32,
}

impl fmt::Debug for TransmitDatagram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TransmitDatagram(<redacted>)")
    }
}

/// Stable tag retained until the kernel releases a zero-copy transmit buffer.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
#[must_use = "a kernel-owned transmit tag must be completed"]
pub struct TransmitCompletionTag {
    index: usize,
    generation: u32,
}

impl fmt::Debug for TransmitCompletionTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TransmitCompletionTag(<redacted>)")
    }
}

/// Borrowed outgoing bytes and routing metadata.
pub struct TransmitDatagramView<'a> {
    payload: &'a [u8],
    metadata: TransmitMetadata,
}

impl fmt::Debug for TransmitDatagramView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransmitDatagramView")
            .field(
                "payload",
                &format_args!("<redacted, {} bytes>", self.payload.len()),
            )
            .field("metadata", &"<redacted>")
            .finish()
    }
}

impl<'a> TransmitDatagramView<'a> {
    /// Returns the exact bytes to submit to the socket adapter.
    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Returns the routing and ancillary metadata for this submission.
    #[must_use]
    pub const fn metadata(&self) -> TransmitMetadata {
        self.metadata
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransmitState {
    Free,
    Reserved,
    Ready,
    Submitting,
    KernelOwned,
}

struct TransmitSlot<const BUFFER_SIZE: usize> {
    bytes: [u8; BUFFER_SIZE],
    length: usize,
    metadata: Option<TransmitMetadata>,
    generation: u32,
    state: TransmitState,
}

impl<const BUFFER_SIZE: usize> TransmitSlot<BUFFER_SIZE> {
    const fn new() -> Self {
        Self {
            bytes: [0; BUFFER_SIZE],
            length: 0,
            metadata: None,
            generation: 0,
            state: TransmitState::Free,
        }
    }
}

/// Separate fixed transmit arena with retry and kernel-completion ownership.
pub struct TransmitQueue<const SLOTS: usize, const BUFFER_SIZE: usize> {
    slots: [TransmitSlot<BUFFER_SIZE>; SLOTS],
    free: IndexQueue<SLOTS>,
    ready: IndexQueue<SLOTS>,
}

impl<const SLOTS: usize, const BUFFER_SIZE: usize> TransmitQueue<SLOTS, BUFFER_SIZE> {
    /// Creates a queue with every slot free and zeroed.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [const { TransmitSlot::new() }; SLOTS],
            free: IndexQueue::with_all_indices(),
            ready: IndexQueue::new(),
        }
    }

    /// Reserves one stable outgoing buffer.
    ///
    /// # Errors
    ///
    /// Returns pool exhaustion or generation exhaustion.
    pub fn reserve(&mut self) -> Result<TransmitReservation, RuntimeQueueError> {
        for _ in 0..SLOTS {
            let index = self.free.pop().ok_or(RuntimeQueueError::PoolExhausted)?;
            let Some(generation) = self.slots[index].generation.checked_add(1) else {
                let restored = self.free.push(index);
                debug_assert!(restored);
                continue;
            };
            let slot = &mut self.slots[index];
            debug_assert_eq!(slot.state, TransmitState::Free);
            slot.generation = generation;
            slot.state = TransmitState::Reserved;
            return Ok(TransmitReservation { index, generation });
        }
        Err(RuntimeQueueError::GenerationExhausted)
    }

    /// Returns the complete stable buffer for packet encoding and protection.
    ///
    /// # Errors
    ///
    /// Returns `InvalidOwnership` for a stale or wrong-state reservation.
    pub fn buffer_mut(
        &mut self,
        reservation: &TransmitReservation,
    ) -> Result<&mut [u8], RuntimeQueueError> {
        let slot = self.transmit_slot_mut(
            reservation.index,
            reservation.generation,
            TransmitState::Reserved,
        )?;
        Ok(&mut slot.bytes)
    }

    /// Commits an encoded datagram or GSO batch to the transmit queue.
    ///
    /// Invalid length or GSO metadata releases and clears the reservation.
    ///
    /// # Errors
    ///
    /// Returns an ownership, empty-datagram, length, segment, or internal
    /// invariant error.
    pub fn commit(
        &mut self,
        reservation: TransmitReservation,
        length: usize,
        metadata: TransmitMetadata,
    ) -> Result<(), RuntimeQueueError> {
        if let Err(error) =
            validate_datagram_shape::<BUFFER_SIZE>(length, metadata.gso_segment_size)
        {
            self.release_transmit_reservation(reservation)?;
            return Err(error);
        }
        let slot = self.transmit_slot_mut(
            reservation.index,
            reservation.generation,
            TransmitState::Reserved,
        )?;
        slot.length = length;
        slot.metadata = Some(metadata);
        slot.state = TransmitState::Ready;
        if !self.ready.push(reservation.index) {
            self.clear_transmit_slot(reservation.index, true);
            return Err(RuntimeQueueError::InvariantViolation);
        }
        Ok(())
    }

    /// Cancels and clears an outstanding transmit reservation.
    ///
    /// # Errors
    ///
    /// Returns `InvalidOwnership` for a stale or wrong-state reservation.
    pub fn cancel(&mut self, reservation: TransmitReservation) -> Result<(), RuntimeQueueError> {
        self.release_transmit_reservation(reservation)
    }

    /// Pops the next buffer ready for a send operation.
    #[must_use]
    pub fn pop(&mut self) -> Option<TransmitDatagram> {
        let index = self.ready.pop()?;
        let slot = &mut self.slots[index];
        debug_assert_eq!(slot.state, TransmitState::Ready);
        slot.state = TransmitState::Submitting;
        Some(TransmitDatagram {
            index,
            generation: slot.generation,
        })
    }

    /// Borrows the exact outgoing bytes and routing metadata.
    ///
    /// # Errors
    ///
    /// Returns `InvalidOwnership` for a stale or wrong-state token.
    pub fn view(
        &self,
        datagram: &TransmitDatagram,
    ) -> Result<TransmitDatagramView<'_>, RuntimeQueueError> {
        let slot = self.transmit_slot(
            datagram.index,
            datagram.generation,
            TransmitState::Submitting,
        )?;
        let metadata = slot.metadata.ok_or(RuntimeQueueError::InvariantViolation)?;
        Ok(TransmitDatagramView {
            payload: &slot.bytes[..slot.length],
            metadata,
        })
    }

    /// Releases a synchronously submitted datagram and clears its used bytes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidOwnership` for a stale or wrong-state token.
    #[allow(clippy::needless_pass_by_value)] // Consuming the token enforces single ownership.
    pub fn complete(&mut self, datagram: TransmitDatagram) -> Result<(), RuntimeQueueError> {
        self.transmit_slot(
            datagram.index,
            datagram.generation,
            TransmitState::Submitting,
        )?;
        self.clear_transmit_slot(datagram.index, false);
        Ok(())
    }

    /// Requeues a datagram after transient socket backpressure.
    ///
    /// # Errors
    ///
    /// Returns `InvalidOwnership` or an internal queue invariant failure.
    #[allow(clippy::needless_pass_by_value)] // Consuming the token enforces single ownership.
    pub fn requeue(&mut self, datagram: TransmitDatagram) -> Result<(), RuntimeQueueError> {
        self.transmit_slot(
            datagram.index,
            datagram.generation,
            TransmitState::Submitting,
        )?;
        if !self.ready.push(datagram.index) {
            return Err(RuntimeQueueError::InvariantViolation);
        }
        self.slots[datagram.index].state = TransmitState::Ready;
        Ok(())
    }

    /// Transfers ownership to a kernel zero-copy operation.
    ///
    /// The returned tag, not successful syscall submission, releases the
    /// buffer when its matching kernel completion arrives.
    ///
    /// # Errors
    ///
    /// Returns `InvalidOwnership` for a stale or wrong-state token.
    #[allow(clippy::needless_pass_by_value)] // Consuming the token transfers ownership.
    pub fn defer_completion(
        &mut self,
        datagram: TransmitDatagram,
    ) -> Result<TransmitCompletionTag, RuntimeQueueError> {
        let slot = self.transmit_slot_mut(
            datagram.index,
            datagram.generation,
            TransmitState::Submitting,
        )?;
        slot.state = TransmitState::KernelOwned;
        Ok(TransmitCompletionTag {
            index: datagram.index,
            generation: datagram.generation,
        })
    }

    /// Releases a buffer after its exact kernel completion tag arrives.
    ///
    /// # Errors
    ///
    /// Returns `InvalidOwnership` for a duplicate, stale, or foreign tag.
    pub fn complete_deferred(
        &mut self,
        tag: TransmitCompletionTag,
    ) -> Result<(), RuntimeQueueError> {
        self.transmit_slot(tag.index, tag.generation, TransmitState::KernelOwned)?;
        self.clear_transmit_slot(tag.index, false);
        Ok(())
    }

    /// Returns current fixed-resource counters.
    #[must_use]
    pub fn stats(&self) -> BufferQueueStats {
        let reserved_or_submitting = self
            .slots
            .iter()
            .filter(|slot| {
                matches!(
                    slot.state,
                    TransmitState::Reserved | TransmitState::Submitting
                )
            })
            .count();
        let kernel_owned = self
            .slots
            .iter()
            .filter(|slot| slot.state == TransmitState::KernelOwned)
            .count();
        BufferQueueStats {
            capacity: SLOTS,
            free: self.free.len(),
            ready: self.ready.len(),
            reserved_or_delivered: reserved_or_submitting,
            kernel_owned,
        }
    }

    #[allow(clippy::needless_pass_by_value)] // Consuming the token prevents duplicate release.
    fn release_transmit_reservation(
        &mut self,
        reservation: TransmitReservation,
    ) -> Result<(), RuntimeQueueError> {
        self.transmit_slot(
            reservation.index,
            reservation.generation,
            TransmitState::Reserved,
        )?;
        self.clear_transmit_slot(reservation.index, true);
        Ok(())
    }

    fn transmit_slot(
        &self,
        index: usize,
        generation: u32,
        state: TransmitState,
    ) -> Result<&TransmitSlot<BUFFER_SIZE>, RuntimeQueueError> {
        let slot = self
            .slots
            .get(index)
            .ok_or(RuntimeQueueError::InvalidOwnership)?;
        if slot.generation != generation || slot.state != state {
            return Err(RuntimeQueueError::InvalidOwnership);
        }
        Ok(slot)
    }

    fn transmit_slot_mut(
        &mut self,
        index: usize,
        generation: u32,
        state: TransmitState,
    ) -> Result<&mut TransmitSlot<BUFFER_SIZE>, RuntimeQueueError> {
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(RuntimeQueueError::InvalidOwnership)?;
        if slot.generation != generation || slot.state != state {
            return Err(RuntimeQueueError::InvalidOwnership);
        }
        Ok(slot)
    }

    fn clear_transmit_slot(&mut self, index: usize, clear_complete_buffer: bool) {
        let slot = &mut self.slots[index];
        let clear_length = if clear_complete_buffer {
            BUFFER_SIZE
        } else {
            slot.length
        };
        slot.bytes[..clear_length].fill(0);
        slot.length = 0;
        slot.metadata = None;
        slot.state = TransmitState::Free;
        let restored = self.free.push(index);
        debug_assert!(restored);
    }
}

impl<const SLOTS: usize, const BUFFER_SIZE: usize> Default for TransmitQueue<SLOTS, BUFFER_SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const SLOTS: usize, const BUFFER_SIZE: usize> Drop for TransmitQueue<SLOTS, BUFFER_SIZE> {
    fn drop(&mut self) {
        for slot in &mut self.slots {
            slot.bytes.zeroize();
            slot.length = 0;
            slot.metadata = None;
            slot.state = TransmitState::Free;
        }
    }
}

impl<const SLOTS: usize, const BUFFER_SIZE: usize> fmt::Debug
    for TransmitQueue<SLOTS, BUFFER_SIZE>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransmitQueue")
            .field("stats", &self.stats())
            .field("buffers", &"<redacted>")
            .finish()
    }
}

/// Opaque event-loop owner used to bind timers to connection/path state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TimerOwner(pub u64);

/// Runtime deadlines sharing one bounded monotonic timer queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeTimerKind {
    HandshakeDeadline,
    IdleTimeout,
    Ack,
    LossDetection,
    Pacing,
    PathValidation,
    TransferControl,
    Application(u16),
}

/// Cancellation capability for one armed timer.
#[derive(Clone, Copy, Eq, PartialEq)]
#[must_use = "retain the token if the timer may need cancellation"]
pub struct RuntimeTimerToken {
    index: usize,
    generation: u32,
}

impl fmt::Debug for RuntimeTimerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuntimeTimerToken(<redacted>)")
    }
}

/// One timer removed from the queue after its monotonic deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeTimerEvent {
    pub owner: TimerOwner,
    pub kind: RuntimeTimerKind,
    pub deadline_micros: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TimerEntry {
    owner: TimerOwner,
    kind: RuntimeTimerKind,
    deadline_micros: u64,
    insertion_order: u64,
    generation: u32,
}

/// Fixed-capacity stable min-heap for all event-loop deadlines.
pub struct RuntimeTimerQueue<const TIMERS: usize> {
    entries: [Option<TimerEntry>; TIMERS],
    generations: [u32; TIMERS],
    heap: [usize; TIMERS],
    heap_len: usize,
    free: IndexQueue<TIMERS>,
    next_insertion_order: u64,
    last_poll_micros: u64,
}

impl<const TIMERS: usize> RuntimeTimerQueue<TIMERS> {
    /// Creates an empty timer queue at monotonic time zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [None; TIMERS],
            generations: [0; TIMERS],
            heap: [0; TIMERS],
            heap_len: 0,
            free: IndexQueue::with_all_indices(),
            next_insertion_order: 0,
            last_poll_micros: 0,
        }
    }

    /// Arms one deadline and returns its cancellation capability.
    ///
    /// Equal deadlines fire in insertion order.
    ///
    /// # Errors
    ///
    /// Returns capacity, counter, generation, or invariant failure without
    /// overwriting an existing timer.
    pub fn arm(
        &mut self,
        owner: TimerOwner,
        kind: RuntimeTimerKind,
        deadline_micros: u64,
    ) -> Result<RuntimeTimerToken, RuntimeTimerError> {
        let next_order = self
            .next_insertion_order
            .checked_add(1)
            .ok_or(RuntimeTimerError::CounterExhausted)?;
        for _ in 0..TIMERS {
            let index = self
                .free
                .pop()
                .ok_or(RuntimeTimerError::CapacityExhausted)?;
            let Some(generation) = self.generations[index].checked_add(1) else {
                let restored = self.free.push(index);
                debug_assert!(restored);
                continue;
            };
            self.entries[index] = Some(TimerEntry {
                owner,
                kind,
                deadline_micros,
                insertion_order: self.next_insertion_order,
                generation,
            });
            self.generations[index] = generation;
            self.next_insertion_order = next_order;
            self.heap_push(index)?;
            return Ok(RuntimeTimerToken { index, generation });
        }
        Err(RuntimeTimerError::GenerationExhausted)
    }

    /// Cancels exactly the timer named by `token`.
    ///
    /// Returns `false` for an expired, already cancelled, or foreign token.
    pub fn cancel(&mut self, token: RuntimeTimerToken) -> bool {
        let Some(entry) = self.entries.get(token.index).copied().flatten() else {
            return false;
        };
        if entry.generation != token.generation {
            return false;
        }
        let Some(position) = self.heap[..self.heap_len]
            .iter()
            .position(|index| *index == token.index)
        else {
            return false;
        };
        self.heap_remove(position);
        self.entries[token.index] = None;
        let restored = self.free.push(token.index);
        debug_assert!(restored);
        true
    }

    /// Removes the earliest timer if it has expired at `now_micros`.
    ///
    /// # Errors
    ///
    /// Returns `ClockWentBackwards` without modifying the queue when the event
    /// loop supplies a decreasing monotonic timestamp.
    pub fn pop_expired(
        &mut self,
        now_micros: u64,
    ) -> Result<Option<RuntimeTimerEvent>, RuntimeTimerError> {
        if now_micros < self.last_poll_micros {
            return Err(RuntimeTimerError::ClockWentBackwards {
                previous: self.last_poll_micros,
                current: now_micros,
            });
        }
        self.last_poll_micros = now_micros;
        let Some(&index) = self.heap.first().filter(|_| self.heap_len != 0) else {
            return Ok(None);
        };
        let entry = self.entries[index].ok_or(RuntimeTimerError::InvariantViolation)?;
        if entry.deadline_micros > now_micros {
            return Ok(None);
        }
        self.heap_remove(0);
        self.entries[index] = None;
        let restored = self.free.push(index);
        debug_assert!(restored);
        Ok(Some(RuntimeTimerEvent {
            owner: entry.owner,
            kind: entry.kind,
            deadline_micros: entry.deadline_micros,
        }))
    }

    /// Returns the earliest armed deadline.
    #[must_use]
    pub fn next_deadline_micros(&self) -> Option<u64> {
        let index = *self.heap.first().filter(|_| self.heap_len != 0)?;
        self.entries[index].map(|entry| entry.deadline_micros)
    }

    /// Returns the number of armed timers.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.heap_len
    }

    /// Returns whether no timer is armed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.heap_len == 0
    }

    fn heap_push(&mut self, index: usize) -> Result<(), RuntimeTimerError> {
        if self.heap_len >= TIMERS {
            return Err(RuntimeTimerError::InvariantViolation);
        }
        let mut position = self.heap_len;
        self.heap[position] = index;
        self.heap_len += 1;
        while position != 0 {
            let parent = (position - 1) / 2;
            if !self.timer_precedes(self.heap[position], self.heap[parent])? {
                break;
            }
            self.heap.swap(position, parent);
            position = parent;
        }
        Ok(())
    }

    fn heap_remove(&mut self, position: usize) {
        debug_assert!(position < self.heap_len);
        self.heap_len -= 1;
        if position == self.heap_len {
            return;
        }
        self.heap[position] = self.heap[self.heap_len];
        if position != 0 {
            let parent = (position - 1) / 2;
            if self
                .timer_precedes(self.heap[position], self.heap[parent])
                .unwrap_or(false)
            {
                self.heap.swap(position, parent);
                let mut current = parent;
                while current != 0 {
                    let next_parent = (current - 1) / 2;
                    if !self
                        .timer_precedes(self.heap[current], self.heap[next_parent])
                        .unwrap_or(false)
                    {
                        break;
                    }
                    self.heap.swap(current, next_parent);
                    current = next_parent;
                }
                return;
            }
        }
        let mut current = position;
        loop {
            let left = current.saturating_mul(2).saturating_add(1);
            if left >= self.heap_len {
                break;
            }
            let right = left + 1;
            let smallest = if right < self.heap_len
                && self
                    .timer_precedes(self.heap[right], self.heap[left])
                    .unwrap_or(false)
            {
                right
            } else {
                left
            };
            if !self
                .timer_precedes(self.heap[smallest], self.heap[current])
                .unwrap_or(false)
            {
                break;
            }
            self.heap.swap(current, smallest);
            current = smallest;
        }
    }

    fn timer_precedes(&self, left: usize, right: usize) -> Result<bool, RuntimeTimerError> {
        let left = self.entries[left].ok_or(RuntimeTimerError::InvariantViolation)?;
        let right = self.entries[right].ok_or(RuntimeTimerError::InvariantViolation)?;
        Ok((left.deadline_micros, left.insertion_order)
            < (right.deadline_micros, right.insertion_order))
    }
}

impl<const TIMERS: usize> Default for RuntimeTimerQueue<TIMERS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const TIMERS: usize> fmt::Debug for RuntimeTimerQueue<TIMERS> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeTimerQueue")
            .field("armed", &self.heap_len)
            .field("capacity", &TIMERS)
            .field("deadlines", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Bounded datagram-queue failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeQueueError {
    PoolExhausted,
    GenerationExhausted,
    InvalidOwnership,
    EmptyDatagram,
    DatagramTooLarge { length: usize, capacity: usize },
    InvalidSegmentSize { segment_size: usize, length: usize },
    InvariantViolation,
}

impl fmt::Display for RuntimeQueueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PoolExhausted => formatter.write_str("fixed datagram pool exhausted"),
            Self::GenerationExhausted => formatter.write_str("datagram generation exhausted"),
            Self::InvalidOwnership => formatter.write_str("invalid datagram buffer ownership"),
            Self::EmptyDatagram => formatter.write_str("empty OGTP datagram"),
            Self::DatagramTooLarge { length, capacity } => write!(
                formatter,
                "datagram length {length} exceeds buffer capacity {capacity}"
            ),
            Self::InvalidSegmentSize {
                segment_size,
                length,
            } => write!(
                formatter,
                "UDP segment size {segment_size} is invalid for buffer length {length}"
            ),
            Self::InvariantViolation => formatter.write_str("datagram queue invariant violation"),
        }
    }
}

impl std::error::Error for RuntimeQueueError {}

/// Bounded timer-queue failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeTimerError {
    CapacityExhausted,
    CounterExhausted,
    GenerationExhausted,
    ClockWentBackwards { previous: u64, current: u64 },
    InvariantViolation,
}

impl fmt::Display for RuntimeTimerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityExhausted => formatter.write_str("fixed timer capacity exhausted"),
            Self::CounterExhausted => formatter.write_str("timer insertion counter exhausted"),
            Self::GenerationExhausted => formatter.write_str("timer generation exhausted"),
            Self::ClockWentBackwards { previous, current } => write!(
                formatter,
                "monotonic clock moved backwards from {previous} to {current} microseconds"
            ),
            Self::InvariantViolation => formatter.write_str("timer queue invariant violation"),
        }
    }
}

impl std::error::Error for RuntimeTimerError {}

#[derive(Clone)]
struct IndexQueue<const CAPACITY: usize> {
    entries: [usize; CAPACITY],
    head: usize,
    length: usize,
}

impl<const CAPACITY: usize> IndexQueue<CAPACITY> {
    const fn new() -> Self {
        Self {
            entries: [0; CAPACITY],
            head: 0,
            length: 0,
        }
    }

    const fn with_all_indices() -> Self {
        let mut queue = Self::new();
        let mut index = 0;
        while index < CAPACITY {
            queue.entries[index] = index;
            index += 1;
        }
        queue.length = CAPACITY;
        queue
    }

    fn push(&mut self, value: usize) -> bool {
        if self.length == CAPACITY || CAPACITY == 0 {
            return false;
        }
        let tail = (self.head + self.length) % CAPACITY;
        self.entries[tail] = value;
        self.length += 1;
        true
    }

    fn pop(&mut self) -> Option<usize> {
        if self.length == 0 || CAPACITY == 0 {
            return None;
        }
        let value = self.entries[self.head];
        self.head = (self.head + 1) % CAPACITY;
        self.length -= 1;
        Some(value)
    }

    const fn len(&self) -> usize {
        self.length
    }
}

fn validate_datagram_shape<const BUFFER_SIZE: usize>(
    length: usize,
    segment_size: Option<NonZeroU16>,
) -> Result<(), RuntimeQueueError> {
    if length == 0 {
        return Err(RuntimeQueueError::EmptyDatagram);
    }
    if length > BUFFER_SIZE {
        return Err(RuntimeQueueError::DatagramTooLarge {
            length,
            capacity: BUFFER_SIZE,
        });
    }
    if let Some(segment_size) = segment_size {
        let segment_size = usize::from(segment_size.get());
        if segment_size > length {
            return Err(RuntimeQueueError::InvalidSegmentSize {
                segment_size,
                length,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(last: u8, port: u16) -> UdpEndpoint {
        UdpEndpoint {
            address: IpAddress::V4([192, 0, 2, last]),
            port,
        }
    }

    fn receive_metadata(segment_size: Option<u16>) -> ReceiveMetadata {
        ReceiveMetadata {
            source: endpoint(1, 44_000),
            destination: endpoint(2, 44_001),
            socket_id: 3,
            interface_index: 4,
            ecn: EcnCodepoint::Ect0,
            received_at_micros: 5,
            gro_segment_size: segment_size.and_then(NonZeroU16::new),
        }
    }

    fn transmit_metadata(segment_size: Option<u16>) -> TransmitMetadata {
        TransmitMetadata {
            source: endpoint(2, 44_001),
            destination: endpoint(1, 44_000),
            socket_id: 3,
            interface_index: 4,
            ecn: EcnCodepoint::Ect0,
            send_not_before_micros: 6,
            gso_segment_size: segment_size.and_then(NonZeroU16::new),
        }
    }

    #[test]
    fn receive_pool_is_bounded_ordered_segmented_and_cleared() {
        let mut queue = ReceiveQueue::<2, 16>::new();
        let first = queue.reserve().expect("first reservation");
        let second = queue.reserve().expect("second reservation");
        assert!(matches!(
            queue.reserve(),
            Err(RuntimeQueueError::PoolExhausted)
        ));
        queue.buffer_mut(&first).expect("first buffer")[..10].copy_from_slice(b"abcdefghij");
        queue.buffer_mut(&second).expect("second buffer")[..4].copy_from_slice(b"WXYZ");
        queue
            .commit(first, 10, receive_metadata(Some(4)))
            .expect("first commit");
        queue
            .commit(second, 4, receive_metadata(None))
            .expect("second commit");

        let first = queue.pop().expect("first completion");
        let view = queue.view(&first).expect("first view");
        assert_eq!(
            view.segments().collect::<Vec<_>>(),
            vec![&b"abcd"[..], &b"efgh"[..], &b"ij"[..]]
        );
        queue.release(first).expect("first release");

        let reused = queue.reserve().expect("released slot is reusable");
        assert!(
            queue
                .buffer_mut(&reused)
                .expect("reused buffer")
                .iter()
                .all(|byte| *byte == 0)
        );
        queue.cancel(reused).expect("cancel reused buffer");

        let second = queue.pop().expect("second completion");
        assert_eq!(queue.view(&second).expect("second view").payload(), b"WXYZ");
        queue.release(second).expect("second release");
        assert_eq!(queue.stats().free, 2);
    }

    #[test]
    fn invalid_receive_shape_releases_the_reservation() {
        let mut queue = ReceiveQueue::<1, 8>::new();
        let empty = queue.reserve().expect("reservation");
        assert_eq!(
            queue.commit(empty, 0, receive_metadata(None)),
            Err(RuntimeQueueError::EmptyDatagram)
        );
        let invalid_gro = queue.reserve().expect("slot released after error");
        assert_eq!(
            queue.commit(invalid_gro, 4, receive_metadata(Some(5))),
            Err(RuntimeQueueError::InvalidSegmentSize {
                segment_size: 5,
                length: 4,
            })
        );
        assert_eq!(queue.stats().free, 1);
    }

    #[test]
    fn transmit_backpressure_and_kernel_completion_preserve_ownership() {
        let mut queue = TransmitQueue::<1, 16>::new();
        let reservation = queue.reserve().expect("reservation");
        queue.buffer_mut(&reservation).expect("buffer")[..8].copy_from_slice(b"payload!");
        queue
            .commit(reservation, 8, transmit_metadata(Some(4)))
            .expect("commit");
        let submission = queue.pop().expect("submission");
        assert_eq!(
            queue.view(&submission).expect("view").payload(),
            b"payload!"
        );
        queue.requeue(submission).expect("EAGAIN requeue");
        let submission = queue.pop().expect("retried submission");
        let tag = queue
            .defer_completion(submission)
            .expect("kernel takes ownership");
        assert_eq!(queue.stats().kernel_owned, 1);
        assert!(matches!(
            queue.reserve(),
            Err(RuntimeQueueError::PoolExhausted)
        ));
        queue
            .complete_deferred(tag)
            .expect("matching kernel completion");
        assert_eq!(
            queue.complete_deferred(tag),
            Err(RuntimeQueueError::InvalidOwnership)
        );
        let reused = queue.reserve().expect("completion releases slot");
        assert!(
            queue
                .buffer_mut(&reused)
                .expect("cleared buffer")
                .iter()
                .all(|byte| *byte == 0)
        );
        queue.cancel(reused).expect("cancel");
    }

    #[test]
    fn transmit_validation_and_synchronous_completion_release_the_slot() {
        let mut queue = TransmitQueue::<1, 8>::new();
        let invalid = queue.reserve().expect("invalid reservation");
        queue.buffer_mut(&invalid).expect("invalid buffer")[..4].copy_from_slice(b"test");
        assert_eq!(
            queue.commit(invalid, 4, transmit_metadata(Some(5))),
            Err(RuntimeQueueError::InvalidSegmentSize {
                segment_size: 5,
                length: 4,
            })
        );

        let valid = queue.reserve().expect("slot released after error");
        queue.buffer_mut(&valid).expect("valid buffer")[..4].copy_from_slice(b"safe");
        queue
            .commit(valid, 4, transmit_metadata(None))
            .expect("valid commit");
        let submission = queue.pop().expect("submission");
        assert_eq!(queue.view(&submission).expect("view").payload(), b"safe");
        queue.complete(submission).expect("synchronous completion");

        let reused = queue.reserve().expect("completed slot is reusable");
        assert!(
            queue
                .buffer_mut(&reused)
                .expect("cleared buffer")
                .iter()
                .all(|byte| *byte == 0)
        );
        queue.cancel(reused).expect("cancel");
    }

    #[test]
    fn timer_queue_is_stable_cancellable_bounded_and_monotonic() {
        let mut timers = RuntimeTimerQueue::<3>::new();
        let late = timers
            .arm(TimerOwner(1), RuntimeTimerKind::IdleTimeout, 30)
            .expect("late timer");
        let first_equal = timers
            .arm(TimerOwner(2), RuntimeTimerKind::Ack, 20)
            .expect("first equal timer");
        let _second_equal = timers
            .arm(TimerOwner(3), RuntimeTimerKind::Pacing, 20)
            .expect("second equal timer");
        assert_eq!(
            timers.arm(TimerOwner(4), RuntimeTimerKind::TransferControl, 40),
            Err(RuntimeTimerError::CapacityExhausted)
        );
        assert!(timers.cancel(late));
        assert!(!timers.cancel(late));
        assert_eq!(timers.next_deadline_micros(), Some(20));
        assert_eq!(timers.pop_expired(19).expect("monotonic poll"), None);
        assert_eq!(
            timers.pop_expired(20).expect("first expiry"),
            Some(RuntimeTimerEvent {
                owner: TimerOwner(2),
                kind: RuntimeTimerKind::Ack,
                deadline_micros: 20,
            })
        );
        assert!(!timers.cancel(first_equal));
        assert_eq!(
            timers.pop_expired(20).expect("stable equal expiry"),
            Some(RuntimeTimerEvent {
                owner: TimerOwner(3),
                kind: RuntimeTimerKind::Pacing,
                deadline_micros: 20,
            })
        );
        assert_eq!(
            timers.pop_expired(19),
            Err(RuntimeTimerError::ClockWentBackwards {
                previous: 20,
                current: 19,
            })
        );
        assert!(timers.is_empty());
    }

    #[test]
    fn stale_timer_token_cannot_cancel_a_reused_slot() {
        let mut timers = RuntimeTimerQueue::<1>::new();
        let stale = timers
            .arm(TimerOwner(1), RuntimeTimerKind::Ack, 10)
            .expect("first timer");
        assert!(timers.cancel(stale));

        let current = timers
            .arm(TimerOwner(2), RuntimeTimerKind::Pacing, 20)
            .expect("replacement timer");
        assert!(!timers.cancel(stale));
        assert!(timers.cancel(current));
        assert!(timers.is_empty());
    }

    #[test]
    fn queue_and_token_debug_output_redacts_network_data() {
        let mut receive = ReceiveQueue::<1, 32>::new();
        let reservation = receive.reserve().expect("reservation");
        receive.buffer_mut(&reservation).expect("buffer")[..6].copy_from_slice(b"secret");
        assert!(!format!("{receive:?}").contains("secret"));
        assert!(!format!("{reservation:?}").contains("192"));
        receive.cancel(reservation).expect("cancel");

        let timers = RuntimeTimerQueue::<1>::new();
        assert!(format!("{timers:?}").contains("<redacted>"));
    }
}
