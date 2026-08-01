//! Bounded handshake reassembly and transactional transcript state.

use core::fmt;

use crate::crypto::{ForkableSha384Provider, SHA384_OUTPUT_LEN, Sha384Digest};
use crate::handshake::{
    CIPHER_SUITE_AES_256_GCM_SHA384_BIT, CIPHER_SUITE_CHACHA20_POLY1305_SHA384_BIT, FINISH_LEN,
    FINISHED_MAC_LEN, HELLO_LEN, Hello, IDENTITY_AUTH_LEN, INIT_FIXED_LEN, IdentityAuth, Init,
    KNOWN_CAPABILITY_BITS, MAX_RETRY_COOKIE_LEN, MIN_RETRY_COOKIE_LEN, RANDOM_LEN,
    RESPONSE_FIXED_LEN, RESPONSE_LEN, Response, Retry,
};
use crate::retry::HandshakeAdmissionLease;
use crate::transcript::{SessionContext, TranscriptError, TranscriptRecordType, feed_record};
use crate::wire::WireError;
use crate::wire::long::{
    LongPacket, LongPacketType, MAX_HANDSHAKE_MESSAGE_LEN, MAX_LONG_CONNECTION_ID_LEN,
};

const HANDSHAKE_RECEIPT_BITMAP_LEN: usize = MAX_HANDSHAKE_MESSAGE_LEN.div_ceil(8);
const MAX_SESSION_CONTEXT_LEN: usize = 6 + 2 * MAX_LONG_CONNECTION_ID_LEN;
const IDENTITY_AUTH_CONTENT_LEN: usize = IDENTITY_AUTH_LEN - FINISHED_MAC_LEN;

/// Admission proof required before a fragmented logical message may reserve a
/// reassembly slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReassemblyAdmission {
    /// The responder has validated the stateless RETRY cookie from the INIT prefix.
    CookieValidated(HandshakeAdmissionLease),
    /// The connection already owns state that expects RESPONSE or FINISH.
    ExistingHandshake,
}

/// Statelessly parsed INIT prefix needed to validate a RETRY cookie before
/// allocating a full reassembly slot.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct InitAdmissionView<'a> {
    pub hello: Hello,
    pub server_random: [u8; RANDOM_LEN],
    pub cookie: &'a [u8],
}

impl fmt::Debug for InitAdmissionView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InitAdmissionView")
            .field("hello", &self.hello)
            .field("server_random", &"<redacted>")
            .field("cookie", &"<redacted>")
            .finish()
    }
}

/// Extracts the bounded cookie-bearing INIT prefix from fragment zero.
///
/// The caller validates `cookie`, admits the resulting capability through the
/// fixed quota table, and passes the returned lease through
/// [`ReassemblyAdmission::CookieValidated`] to the pool.
///
/// # Errors
///
/// Returns an error for the wrong packet type, a non-zero offset, a short
/// prefix, invalid HELLO/cookie length, or inconsistent logical message length.
pub fn decode_init_admission_prefix<'a>(
    packet: &LongPacket<'a>,
) -> Result<InitAdmissionView<'a>, HandshakeReassemblyError> {
    validate_long_packet_shape(packet)?;
    if packet.packet_type != LongPacketType::Init {
        return Err(HandshakeReassemblyError::UnexpectedPacketType(
            packet.packet_type,
        ));
    }
    if packet.fragment_offset != 0 {
        return Err(HandshakeReassemblyError::InitPrefixMustStartAtZero);
    }
    let cookie_length_offset = HELLO_LEN + RANDOM_LEN;
    let prefix_fixed = cookie_length_offset + 2;
    if packet.fragment.len() < prefix_fixed {
        return Err(HandshakeReassemblyError::InitPrefixTooShort {
            needed: prefix_fixed,
            actual: packet.fragment.len(),
        });
    }
    let hello = Hello::decode(&packet.fragment[..HELLO_LEN])?;
    let server_random = packet.fragment[HELLO_LEN..cookie_length_offset]
        .try_into()
        .map_err(|_| HandshakeReassemblyError::InvariantViolation)?;
    let cookie_length = usize::from(u16::from_be_bytes(
        packet.fragment[cookie_length_offset..prefix_fixed]
            .try_into()
            .map_err(|_| HandshakeReassemblyError::InvariantViolation)?,
    ));
    if !(MIN_RETRY_COOKIE_LEN..=MAX_RETRY_COOKIE_LEN).contains(&cookie_length) {
        return Err(HandshakeReassemblyError::InvalidCookieLength(cookie_length));
    }
    let cookie_end = prefix_fixed
        .checked_add(cookie_length)
        .ok_or(HandshakeReassemblyError::AccountingOverflow)?;
    if packet.fragment.len() < cookie_end {
        return Err(HandshakeReassemblyError::InitPrefixTooShort {
            needed: cookie_end,
            actual: packet.fragment.len(),
        });
    }
    let expected_message_length = INIT_FIXED_LEN
        .checked_add(cookie_length)
        .ok_or(HandshakeReassemblyError::AccountingOverflow)?;
    if usize::from(packet.message_length) != expected_message_length {
        return Err(HandshakeReassemblyError::InvalidDeclaredMessageLength {
            packet_type: LongPacketType::Init,
            length: usize::from(packet.message_length),
        });
    }
    Ok(InitAdmissionView {
        hello,
        server_random,
        cookie: &packet.fragment[prefix_fixed..cookie_end],
    })
}

/// Borrowed stateless HELLO, RETRY, or version-negotiation message.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum StatelessHandshakeMessage<'a> {
    Hello(Hello),
    Retry(Retry<'a>),
    VersionNegotiation(&'a [u8]),
}

impl fmt::Debug for StatelessHandshakeMessage<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hello(hello) => formatter.debug_tuple("Hello").field(hello).finish(),
            Self::Retry(_) => formatter
                .debug_tuple("Retry")
                .field(&"<cookie redacted>")
                .finish(),
            Self::VersionNegotiation(value) => formatter
                .debug_struct("VersionNegotiation")
                .field("length", &value.len())
                .finish(),
        }
    }
}

/// Decodes a complete stateless long-header logical message without a pool.
///
/// # Errors
///
/// Returns an error unless the message is `HELLO`, `RETRY`, or `VERSION_NEGOTIATION`
/// and the entire non-empty logical value is in fragment zero.
pub fn decode_stateless_message<'a>(
    packet: &LongPacket<'a>,
) -> Result<StatelessHandshakeMessage<'a>, HandshakeReassemblyError> {
    validate_long_packet_shape(packet)?;
    if packet.fragment_offset != 0
        || packet.fragment.is_empty()
        || packet.fragment.len() != usize::from(packet.message_length)
    {
        return Err(HandshakeReassemblyError::StatelessMessageFragmented);
    }
    match packet.packet_type {
        LongPacketType::Hello => Ok(StatelessHandshakeMessage::Hello(Hello::decode(
            packet.fragment,
        )?)),
        LongPacketType::Retry => Ok(StatelessHandshakeMessage::Retry(Retry::decode(
            packet.fragment,
        )?)),
        LongPacketType::VersionNegotiation => Ok(StatelessHandshakeMessage::VersionNegotiation(
            packet.fragment,
        )),
        packet_type => Err(HandshakeReassemblyError::UnexpectedPacketType(packet_type)),
    }
}

struct ReassemblySlot {
    occupied: bool,
    packet_type: LongPacketType,
    version: u32,
    destination_connection_id: [u8; MAX_LONG_CONNECTION_ID_LEN],
    destination_length: usize,
    source_connection_id: [u8; MAX_LONG_CONNECTION_ID_LEN],
    source_length: usize,
    message_id: u32,
    message_length: usize,
    received_bytes: usize,
    bytes: [u8; MAX_HANDSHAKE_MESSAGE_LEN],
    receipt: [u8; HANDSHAKE_RECEIPT_BITMAP_LEN],
}

impl ReassemblySlot {
    const fn new() -> Self {
        Self {
            occupied: false,
            packet_type: LongPacketType::Hello,
            version: 0,
            destination_connection_id: [0; MAX_LONG_CONNECTION_ID_LEN],
            destination_length: 0,
            source_connection_id: [0; MAX_LONG_CONNECTION_ID_LEN],
            source_length: 0,
            message_id: 0,
            message_length: 0,
            received_bytes: 0,
            bytes: [0; MAX_HANDSHAKE_MESSAGE_LEN],
            receipt: [0; HANDSHAKE_RECEIPT_BITMAP_LEN],
        }
    }

    fn begin(&mut self, packet: &LongPacket<'_>) {
        self.occupied = true;
        self.packet_type = packet.packet_type;
        self.version = packet.version;
        self.destination_length = packet.destination_connection_id.len();
        self.destination_connection_id[..self.destination_length]
            .copy_from_slice(packet.destination_connection_id);
        self.source_length = packet.source_connection_id.len();
        self.source_connection_id[..self.source_length]
            .copy_from_slice(packet.source_connection_id);
        self.message_id = packet.message_id;
        self.message_length = usize::from(packet.message_length);
        self.received_bytes = 0;
        self.receipt.fill(0);
    }

    fn metadata_matches(&self, packet: &LongPacket<'_>) -> bool {
        self.version == packet.version
            && self.message_length == usize::from(packet.message_length)
            && &self.destination_connection_id[..self.destination_length]
                == packet.destination_connection_id
            && &self.source_connection_id[..self.source_length] == packet.source_connection_id
    }

    fn contains_byte(&self, offset: usize) -> bool {
        self.receipt[offset / 8] & (1 << (offset % 8)) != 0
    }

    fn mark_byte(&mut self, offset: usize) {
        self.receipt[offset / 8] |= 1 << (offset % 8);
    }

    fn clear(&mut self) {
        self.destination_connection_id.fill(0);
        self.source_connection_id.fill(0);
        self.bytes.fill(0);
        self.receipt.fill(0);
        *self = Self::new();
    }
}

/// Result of accepting one admitted long-header fragment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeAssemblyStatus {
    Incomplete {
        packet_type: LongPacketType,
        message_id: u32,
        received_bytes: usize,
        message_length: usize,
    },
    Complete {
        packet_type: LongPacketType,
        message_id: u32,
        message_length: usize,
    },
}

/// Complete logical handshake message borrowed from one fixed pool slot.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ReassembledHandshakeMessage<'a> {
    pub packet_type: LongPacketType,
    pub version: u32,
    pub destination_connection_id: &'a [u8],
    pub source_connection_id: &'a [u8],
    pub message_id: u32,
    pub value: &'a [u8],
}

impl fmt::Debug for ReassembledHandshakeMessage<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReassembledHandshakeMessage")
            .field("packet_type", &self.packet_type)
            .field("version", &self.version)
            .field(
                "destination_connection_id",
                &format_args!("<redacted, {} bytes>", self.destination_connection_id.len()),
            )
            .field(
                "source_connection_id",
                &format_args!("<redacted, {} bytes>", self.source_connection_id.len()),
            )
            .field("message_id", &self.message_id)
            .field(
                "value",
                &format_args!("<redacted, {} bytes>", self.value.len()),
            )
            .finish()
    }
}

/// Fixed pool for admitted INIT, RESPONSE, and FINISH logical messages.
pub struct HandshakeReassembler<const SLOTS: usize> {
    slots: [ReassemblySlot; SLOTS],
}

impl<const SLOTS: usize> fmt::Debug for HandshakeReassembler<SLOTS> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandshakeReassembler")
            .field("slots", &"<redacted>")
            .field("capacity", &SLOTS)
            .field("active_slots", &self.active_slots())
            .finish()
    }
}

impl<const SLOTS: usize> HandshakeReassembler<SLOTS> {
    /// Creates an empty fixed-capacity pool.
    #[must_use]
    pub fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| ReassemblySlot::new()),
        }
    }

    /// Accepts one admitted fragment atomically.
    ///
    /// `HELLO`, `RETRY`, and `VERSION_NEGOTIATION` are rejected because they must use
    /// [`decode_stateless_message`] without allocating a slot.
    ///
    /// # Errors
    ///
    /// Returns an error for missing admission, invalid declared length, pool
    /// exhaustion, changed metadata, conflicting overlap, or accounting failure.
    pub fn ingest(
        &mut self,
        packet: &LongPacket<'_>,
        admission: ReassemblyAdmission,
    ) -> Result<HandshakeAssemblyStatus, HandshakeReassemblyError> {
        validate_reassembly_admission(packet.packet_type, admission)?;
        validate_fragmented_message(packet)?;
        let offset = usize::from(packet.fragment_offset);
        let total = usize::from(packet.message_length);
        let index = if let Some(index) = self.slot_index(packet.packet_type, packet.message_id) {
            if !self.slots[index].metadata_matches(packet) {
                self.slots[index].clear();
                return Err(HandshakeReassemblyError::MessageMetadataChanged {
                    packet_type: packet.packet_type,
                    message_id: packet.message_id,
                });
            }
            index
        } else {
            let index = self
                .slots
                .iter()
                .position(|slot| !slot.occupied)
                .ok_or(HandshakeReassemblyError::PoolExhausted)?;
            self.slots[index].begin(packet);
            index
        };

        if let Some(conflict) = conflicting_offset(&self.slots[index], offset, packet.fragment) {
            self.slots[index].clear();
            return Err(HandshakeReassemblyError::ConflictingOverlap {
                packet_type: packet.packet_type,
                message_id: packet.message_id,
                offset: conflict,
            });
        }
        let newly_received = count_new_bytes(&self.slots[index], offset, packet.fragment);
        let received_bytes = self.slots[index]
            .received_bytes
            .checked_add(newly_received)
            .ok_or(HandshakeReassemblyError::AccountingOverflow)?;
        write_new_bytes(&mut self.slots[index], offset, packet.fragment);
        self.slots[index].received_bytes = received_bytes;

        if received_bytes == total {
            Ok(HandshakeAssemblyStatus::Complete {
                packet_type: packet.packet_type,
                message_id: packet.message_id,
                message_length: total,
            })
        } else {
            Ok(HandshakeAssemblyStatus::Incomplete {
                packet_type: packet.packet_type,
                message_id: packet.message_id,
                received_bytes,
                message_length: total,
            })
        }
    }

    /// Borrows one complete logical message from the pool.
    ///
    /// # Errors
    ///
    /// Returns an error when the slot is unknown or incomplete.
    pub fn completed_message(
        &self,
        packet_type: LongPacketType,
        message_id: u32,
    ) -> Result<ReassembledHandshakeMessage<'_>, HandshakeReassemblyError> {
        let index = self.slot_index(packet_type, message_id).ok_or(
            HandshakeReassemblyError::UnknownMessage {
                packet_type,
                message_id,
            },
        )?;
        let slot = &self.slots[index];
        if slot.received_bytes != slot.message_length {
            return Err(HandshakeReassemblyError::MessageIncomplete {
                packet_type,
                message_id,
            });
        }
        Ok(ReassembledHandshakeMessage {
            packet_type,
            version: slot.version,
            destination_connection_id: &slot.destination_connection_id[..slot.destination_length],
            source_connection_id: &slot.source_connection_id[..slot.source_length],
            message_id,
            value: &slot.bytes[..slot.message_length],
        })
    }

    /// Erases and releases one logical-message slot.
    pub fn release(&mut self, packet_type: LongPacketType, message_id: u32) -> bool {
        if let Some(index) = self.slot_index(packet_type, message_id) {
            self.slots[index].clear();
            true
        } else {
            false
        }
    }

    /// Returns the number of occupied slots.
    #[must_use]
    pub fn active_slots(&self) -> usize {
        self.slots.iter().filter(|slot| slot.occupied).count()
    }

    fn slot_index(&self, packet_type: LongPacketType, message_id: u32) -> Option<usize> {
        self.slots.iter().position(|slot| {
            slot.occupied && slot.packet_type == packet_type && slot.message_id == message_id
        })
    }
}

impl<const SLOTS: usize> Default for HandshakeReassembler<SLOTS> {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_reassembly_admission(
    packet_type: LongPacketType,
    admission: ReassemblyAdmission,
) -> Result<(), HandshakeReassemblyError> {
    match (packet_type, admission) {
        (LongPacketType::Init, ReassemblyAdmission::CookieValidated(_))
        | (
            LongPacketType::Response | LongPacketType::Finish,
            ReassemblyAdmission::ExistingHandshake,
        ) => Ok(()),
        (LongPacketType::Hello | LongPacketType::Retry | LongPacketType::VersionNegotiation, _) => {
            Err(HandshakeReassemblyError::StatelessMessageDoesNotUsePool)
        }
        _ => Err(HandshakeReassemblyError::AdmissionRequired(packet_type)),
    }
}

fn validate_fragmented_message(packet: &LongPacket<'_>) -> Result<(), HandshakeReassemblyError> {
    validate_long_packet_shape(packet)?;
    if packet.fragment.is_empty() {
        return Err(HandshakeReassemblyError::EmptyFragment);
    }
    let length = usize::from(packet.message_length);
    let valid = match packet.packet_type {
        LongPacketType::Init => (INIT_FIXED_LEN + MIN_RETRY_COOKIE_LEN
            ..=INIT_FIXED_LEN + MAX_RETRY_COOKIE_LEN)
            .contains(&length),
        LongPacketType::Response => length == RESPONSE_LEN,
        LongPacketType::Finish => length == FINISH_LEN,
        _ => false,
    };
    if !valid {
        return Err(HandshakeReassemblyError::InvalidDeclaredMessageLength {
            packet_type: packet.packet_type,
            length,
        });
    }
    Ok(())
}

fn validate_long_packet_shape(packet: &LongPacket<'_>) -> Result<(), HandshakeReassemblyError> {
    for connection_id in [
        packet.destination_connection_id,
        packet.source_connection_id,
    ] {
        if connection_id.len() > MAX_LONG_CONNECTION_ID_LEN {
            return Err(WireError::ConnectionIdTooLong {
                length: connection_id.len(),
                maximum: MAX_LONG_CONNECTION_ID_LEN,
            }
            .into());
        }
    }
    let message_length = usize::from(packet.message_length);
    if message_length > MAX_HANDSHAKE_MESSAGE_LEN {
        return Err(WireError::HandshakeMessageTooLarge {
            length: message_length,
            maximum: MAX_HANDSHAKE_MESSAGE_LEN,
        }
        .into());
    }
    let fragment_end = usize::from(packet.fragment_offset)
        .checked_add(packet.fragment.len())
        .ok_or(WireError::LengthOverflow)?;
    if fragment_end > message_length {
        return Err(WireError::InvalidFragmentBounds.into());
    }
    Ok(())
}

fn conflicting_offset(slot: &ReassemblySlot, offset: usize, bytes: &[u8]) -> Option<usize> {
    bytes.iter().copied().enumerate().find_map(|(index, byte)| {
        let absolute = offset + index;
        (slot.contains_byte(absolute) && slot.bytes[absolute] != byte).then_some(absolute)
    })
}

fn count_new_bytes(slot: &ReassemblySlot, offset: usize, bytes: &[u8]) -> usize {
    bytes
        .iter()
        .enumerate()
        .filter(|(index, _)| !slot.contains_byte(offset + index))
        .count()
}

fn write_new_bytes(slot: &mut ReassemblySlot, offset: usize, bytes: &[u8]) {
    for (index, byte) in bytes.iter().copied().enumerate() {
        let absolute = offset + index;
        if !slot.contains_byte(absolute) {
            slot.bytes[absolute] = byte;
            slot.mark_byte(absolute);
        }
    }
}

/// Current canonical transcript transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeTranscriptStage {
    ExpectHello,
    ExpectRetry,
    ExpectInit,
    ExpectResponse,
    ExpectResponderAuth,
    ExpectInitiatorAuth,
    Complete,
}

/// Signature and Finished transcript snapshots for one peer.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AuthenticationTranscriptHashes {
    signature: Sha384Digest,
    finished: Sha384Digest,
}

impl AuthenticationTranscriptHashes {
    #[must_use]
    pub const fn signature(&self) -> &Sha384Digest {
        &self.signature
    }

    #[must_use]
    pub const fn finished(&self) -> &Sha384Digest {
        &self.finished
    }
}

impl fmt::Debug for AuthenticationTranscriptHashes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticationTranscriptHashes(<redacted>)")
    }
}

/// Transcript state after processing decrypted responder authentication.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ResponderTranscriptMilestone {
    pub authentication: AuthenticationTranscriptHashes,
    initiator_signature: Sha384Digest,
}

impl ResponderTranscriptMilestone {
    #[must_use]
    pub const fn initiator_signature(&self) -> &Sha384Digest {
        &self.initiator_signature
    }
}

impl fmt::Debug for ResponderTranscriptMilestone {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResponderTranscriptMilestone(<redacted>)")
    }
}

/// Final transcript state after processing decrypted initiator authentication.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct InitiatorTranscriptMilestone {
    pub authentication: AuthenticationTranscriptHashes,
    full: Sha384Digest,
}

impl InitiatorTranscriptMilestone {
    #[must_use]
    pub const fn full(&self) -> &Sha384Digest {
        &self.full
    }

    #[cfg(test)]
    pub(crate) const fn for_test(full: Sha384Digest) -> Self {
        Self {
            authentication: AuthenticationTranscriptHashes {
                signature: [0; SHA384_OUTPUT_LEN],
                finished: [0; SHA384_OUTPUT_LEN],
            },
            full,
        }
    }
}

impl fmt::Debug for InitiatorTranscriptMilestone {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InitiatorTranscriptMilestone(<redacted>)")
    }
}

/// Transactional canonical handshake transcript.
pub struct HandshakeTranscript<P: ForkableSha384Provider> {
    context: P::Context,
    stage: HandshakeTranscriptStage,
    hello: Option<Hello>,
    retry_server_random: [u8; RANDOM_LEN],
    retry_cookie: [u8; MAX_RETRY_COOKIE_LEN],
    retry_cookie_length: usize,
    pre_auth: Sha384Digest,
    initiator_signature: Sha384Digest,
}

impl<P: ForkableSha384Provider> fmt::Debug for HandshakeTranscript<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandshakeTranscript")
            .field("stage", &self.stage)
            .field("context", &"<redacted>")
            .field("hello", &"<redacted>")
            .field("retry_server_random", &"<redacted>")
            .field("retry_cookie", &"<redacted>")
            .field("retry_cookie_length", &"<redacted>")
            .field("pre_auth", &"<redacted>")
            .field("initiator_signature", &"<redacted>")
            .finish()
    }
}

impl<P: ForkableSha384Provider> HandshakeTranscript<P> {
    /// Starts a transcript with the canonical session-context record.
    ///
    /// # Errors
    ///
    /// Returns a session-context encoding, transcript-framing, or provider error.
    pub fn new(
        provider: &P,
        session: SessionContext<'_>,
    ) -> Result<Self, HandshakeTranscriptError<P::Error>> {
        let mut value = [0_u8; MAX_SESSION_CONTEXT_LEN];
        let length = session.encode(&mut value)?;
        let mut context = provider
            .start_sha384()
            .map_err(HandshakeTranscriptError::Provider)?;
        feed_record(
            &mut context,
            TranscriptRecordType::SessionContext,
            &value[..length],
        )?;
        Ok(Self {
            context,
            stage: HandshakeTranscriptStage::ExpectHello,
            hello: None,
            retry_server_random: [0; RANDOM_LEN],
            retry_cookie: [0; MAX_RETRY_COOKIE_LEN],
            retry_cookie_length: 0,
            pre_auth: [0; SHA384_OUTPUT_LEN],
            initiator_signature: [0; SHA384_OUTPUT_LEN],
        })
    }

    /// Adds a canonical HELLO record.
    ///
    /// # Errors
    ///
    /// Returns an error for an unexpected stage, invalid `HELLO`, transcript
    /// framing failure, or provider failure. State is unchanged on error.
    pub fn record_hello(
        &mut self,
        provider: &P,
        value: &[u8],
    ) -> Result<(), HandshakeTranscriptError<P::Error>> {
        self.require_stage(HandshakeTranscriptStage::ExpectHello)?;
        let hello = Hello::decode(value)?;
        let candidate = append_record(provider, &self.context, TranscriptRecordType::Hello, value)?;
        self.context = candidate;
        self.hello = Some(hello);
        self.stage = HandshakeTranscriptStage::ExpectRetry;
        Ok(())
    }

    /// Adds a canonical RETRY record and retains its bounded consistency fields.
    ///
    /// # Errors
    ///
    /// Returns an error for an unexpected stage, invalid `RETRY`, transcript
    /// framing failure, or provider failure. State is unchanged on error.
    pub fn record_retry(
        &mut self,
        provider: &P,
        value: &[u8],
    ) -> Result<(), HandshakeTranscriptError<P::Error>> {
        self.require_stage(HandshakeTranscriptStage::ExpectRetry)?;
        let retry = Retry::decode(value)?;
        let candidate = append_record(provider, &self.context, TranscriptRecordType::Retry, value)?;
        self.context = candidate;
        self.retry_server_random = retry.server_random;
        self.retry_cookie[..retry.cookie.len()].copy_from_slice(retry.cookie);
        self.retry_cookie_length = retry.cookie.len();
        self.stage = HandshakeTranscriptStage::ExpectInit;
        Ok(())
    }

    /// Adds canonical INIT after checking its repeated HELLO, random, and cookie.
    ///
    /// # Errors
    ///
    /// Returns an error for an unexpected stage, invalid or inconsistent
    /// `INIT`, transcript framing failure, or provider failure. State is
    /// unchanged on error.
    pub fn record_init(
        &mut self,
        provider: &P,
        value: &[u8],
    ) -> Result<(), HandshakeTranscriptError<P::Error>> {
        self.require_stage(HandshakeTranscriptStage::ExpectInit)?;
        let init = Init::decode(value)?;
        if self.hello != Some(init.hello)
            || self.retry_server_random != init.server_random
            || &self.retry_cookie[..self.retry_cookie_length] != init.cookie
        {
            return Err(HandshakeTranscriptError::InitDoesNotMatchRetry);
        }
        let candidate = append_record(provider, &self.context, TranscriptRecordType::Init, value)?;
        self.context = candidate;
        self.retry_server_random.fill(0);
        self.retry_cookie.fill(0);
        self.retry_cookie_length = 0;
        self.stage = HandshakeTranscriptStage::ExpectResponse;
        Ok(())
    }

    /// Adds the canonical RESPONSE prefix and returns `TH_pre_auth`.
    ///
    /// # Errors
    ///
    /// Returns an error for an unexpected stage, invalid or excessive
    /// negotiation, transcript framing failure, or provider failure. State is
    /// unchanged on error.
    pub fn record_response(
        &mut self,
        provider: &P,
        value: &[u8],
    ) -> Result<Sha384Digest, HandshakeTranscriptError<P::Error>> {
        self.require_stage(HandshakeTranscriptStage::ExpectResponse)?;
        let response = Response::decode(value)?;
        let hello = self
            .hello
            .ok_or(HandshakeTranscriptError::InvariantViolation)?;
        let selected_bit = match response.selected_cipher_suite {
            crate::handshake::CipherSuite::Aes256GcmSha384 => CIPHER_SUITE_AES_256_GCM_SHA384_BIT,
            crate::handshake::CipherSuite::ChaCha20Poly1305Sha384 => {
                CIPHER_SUITE_CHACHA20_POLY1305_SHA384_BIT
            }
        };
        if hello.cipher_suite_bitmap & selected_bit == 0
            || response.negotiated_capabilities & !hello.capabilities != 0
            || response.negotiated_capabilities & !KNOWN_CAPABILITY_BITS != 0
            || response.max_udp_payload > hello.max_udp_payload
            || response.max_paths > hello.max_paths
        {
            return Err(HandshakeTranscriptError::NegotiationMismatch);
        }
        let candidate = append_record(
            provider,
            &self.context,
            TranscriptRecordType::ResponsePrefix,
            &value[..RESPONSE_FIXED_LEN],
        )?;
        let pre_auth = provider
            .snapshot_sha384(&candidate)
            .map_err(HandshakeTranscriptError::Provider)?;
        self.context = candidate;
        self.pre_auth = pre_auth;
        self.hello = None;
        self.stage = HandshakeTranscriptStage::ExpectResponderAuth;
        Ok(pre_auth)
    }

    /// Adds decrypted responder auth content and Finished records atomically.
    ///
    /// # Errors
    ///
    /// Returns an error for an unexpected stage, invalid plaintext, transcript
    /// framing failure, or provider failure. State is unchanged on error.
    pub fn record_responder_auth(
        &mut self,
        provider: &P,
        plaintext: &[u8],
    ) -> Result<ResponderTranscriptMilestone, HandshakeTranscriptError<P::Error>> {
        self.require_stage(HandshakeTranscriptStage::ExpectResponderAuth)?;
        IdentityAuth::decode(plaintext)?;
        let mut candidate = provider
            .fork_sha384(&self.context)
            .map_err(HandshakeTranscriptError::Provider)?;
        feed_record(
            &mut candidate,
            TranscriptRecordType::ResponderAuthContent,
            &plaintext[..IDENTITY_AUTH_CONTENT_LEN],
        )?;
        let responder_finished = provider
            .snapshot_sha384(&candidate)
            .map_err(HandshakeTranscriptError::Provider)?;
        feed_record(
            &mut candidate,
            TranscriptRecordType::ResponderFinished,
            &plaintext[IDENTITY_AUTH_CONTENT_LEN..],
        )?;
        let initiator_signature = provider
            .snapshot_sha384(&candidate)
            .map_err(HandshakeTranscriptError::Provider)?;

        self.context = candidate;
        self.initiator_signature = initiator_signature;
        self.stage = HandshakeTranscriptStage::ExpectInitiatorAuth;
        Ok(ResponderTranscriptMilestone {
            authentication: AuthenticationTranscriptHashes {
                signature: self.pre_auth,
                finished: responder_finished,
            },
            initiator_signature,
        })
    }

    /// Adds decrypted initiator auth content and Finished records atomically.
    ///
    /// # Errors
    ///
    /// Returns an error for an unexpected stage, invalid plaintext, transcript
    /// framing failure, or provider failure. State is unchanged on error.
    pub fn record_initiator_auth(
        &mut self,
        provider: &P,
        plaintext: &[u8],
    ) -> Result<InitiatorTranscriptMilestone, HandshakeTranscriptError<P::Error>> {
        self.require_stage(HandshakeTranscriptStage::ExpectInitiatorAuth)?;
        IdentityAuth::decode(plaintext)?;
        let mut candidate = provider
            .fork_sha384(&self.context)
            .map_err(HandshakeTranscriptError::Provider)?;
        feed_record(
            &mut candidate,
            TranscriptRecordType::InitiatorAuthContent,
            &plaintext[..IDENTITY_AUTH_CONTENT_LEN],
        )?;
        let initiator_finished = provider
            .snapshot_sha384(&candidate)
            .map_err(HandshakeTranscriptError::Provider)?;
        feed_record(
            &mut candidate,
            TranscriptRecordType::InitiatorFinished,
            &plaintext[IDENTITY_AUTH_CONTENT_LEN..],
        )?;
        let full = provider
            .snapshot_sha384(&candidate)
            .map_err(HandshakeTranscriptError::Provider)?;

        self.context = candidate;
        self.stage = HandshakeTranscriptStage::Complete;
        Ok(InitiatorTranscriptMilestone {
            authentication: AuthenticationTranscriptHashes {
                signature: self.initiator_signature,
                finished: initiator_finished,
            },
            full,
        })
    }

    #[must_use]
    pub const fn stage(&self) -> HandshakeTranscriptStage {
        self.stage
    }

    fn require_stage(
        &self,
        expected: HandshakeTranscriptStage,
    ) -> Result<(), HandshakeTranscriptError<P::Error>> {
        if self.stage != expected {
            return Err(HandshakeTranscriptError::UnexpectedStage {
                expected,
                actual: self.stage,
            });
        }
        Ok(())
    }
}

fn append_record<P: ForkableSha384Provider>(
    provider: &P,
    current: &P::Context,
    record_type: TranscriptRecordType,
    value: &[u8],
) -> Result<P::Context, HandshakeTranscriptError<P::Error>> {
    let mut candidate = provider
        .fork_sha384(current)
        .map_err(HandshakeTranscriptError::Provider)?;
    feed_record(&mut candidate, record_type, value)?;
    Ok(candidate)
}

/// Handshake reassembly or admission failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeReassemblyError {
    Wire(WireError),
    Handshake(crate::handshake::HandshakeError),
    UnexpectedPacketType(LongPacketType),
    StatelessMessageFragmented,
    StatelessMessageDoesNotUsePool,
    InitPrefixMustStartAtZero,
    InitPrefixTooShort {
        needed: usize,
        actual: usize,
    },
    InvalidCookieLength(usize),
    InvalidDeclaredMessageLength {
        packet_type: LongPacketType,
        length: usize,
    },
    AdmissionRequired(LongPacketType),
    EmptyFragment,
    PoolExhausted,
    MessageMetadataChanged {
        packet_type: LongPacketType,
        message_id: u32,
    },
    ConflictingOverlap {
        packet_type: LongPacketType,
        message_id: u32,
        offset: usize,
    },
    UnknownMessage {
        packet_type: LongPacketType,
        message_id: u32,
    },
    MessageIncomplete {
        packet_type: LongPacketType,
        message_id: u32,
    },
    AccountingOverflow,
    InvariantViolation,
}

impl From<WireError> for HandshakeReassemblyError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl From<crate::handshake::HandshakeError> for HandshakeReassemblyError {
    fn from(error: crate::handshake::HandshakeError) -> Self {
        Self::Handshake(error)
    }
}

impl fmt::Display for HandshakeReassemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => error.fmt(formatter),
            Self::Handshake(error) => error.fmt(formatter),
            Self::UnexpectedPacketType(packet_type) => {
                write!(formatter, "unexpected long packet type {packet_type:?}")
            }
            Self::StatelessMessageFragmented => {
                formatter.write_str("stateless handshake message is fragmented or empty")
            }
            Self::StatelessMessageDoesNotUsePool => {
                formatter.write_str("stateless handshake message must not reserve a pool slot")
            }
            Self::InitPrefixMustStartAtZero => {
                formatter.write_str("INIT admission prefix must start at offset zero")
            }
            Self::InitPrefixTooShort { needed, actual } => write!(
                formatter,
                "INIT admission prefix too short: need {needed}, got {actual}"
            ),
            Self::InvalidCookieLength(length) => {
                write!(formatter, "invalid INIT cookie length {length}")
            }
            Self::InvalidDeclaredMessageLength {
                packet_type,
                length,
            } => write!(
                formatter,
                "invalid declared {packet_type:?} message length {length}"
            ),
            Self::AdmissionRequired(packet_type) => {
                write!(
                    formatter,
                    "missing reassembly admission for {packet_type:?}"
                )
            }
            Self::EmptyFragment => formatter.write_str("empty admitted handshake fragment"),
            Self::PoolExhausted => formatter.write_str("handshake reassembly pool exhausted"),
            Self::MessageMetadataChanged {
                packet_type,
                message_id,
            } => write!(
                formatter,
                "metadata changed for {packet_type:?} message {message_id}"
            ),
            Self::ConflictingOverlap {
                packet_type,
                message_id,
                offset,
            } => write!(
                formatter,
                "conflicting overlap in {packet_type:?} message {message_id} at byte {offset}"
            ),
            Self::UnknownMessage {
                packet_type,
                message_id,
            } => write!(formatter, "unknown {packet_type:?} message {message_id}"),
            Self::MessageIncomplete {
                packet_type,
                message_id,
            } => write!(formatter, "incomplete {packet_type:?} message {message_id}"),
            Self::AccountingOverflow => formatter.write_str("handshake accounting overflow"),
            Self::InvariantViolation => {
                formatter.write_str("handshake reassembly invariant violation")
            }
        }
    }
}

impl std::error::Error for HandshakeReassemblyError {}

/// Transactional canonical-transcript failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandshakeTranscriptError<E> {
    Handshake(crate::handshake::HandshakeError),
    Transcript(TranscriptError),
    Provider(E),
    UnexpectedStage {
        expected: HandshakeTranscriptStage,
        actual: HandshakeTranscriptStage,
    },
    InitDoesNotMatchRetry,
    NegotiationMismatch,
    InvariantViolation,
}

impl<E> From<crate::handshake::HandshakeError> for HandshakeTranscriptError<E> {
    fn from(error: crate::handshake::HandshakeError) -> Self {
        Self::Handshake(error)
    }
}

impl<E> From<TranscriptError> for HandshakeTranscriptError<E> {
    fn from(error: TranscriptError) -> Self {
        Self::Transcript(error)
    }
}

impl<E: fmt::Display> fmt::Display for HandshakeTranscriptError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Handshake(error) => error.fmt(formatter),
            Self::Transcript(error) => error.fmt(formatter),
            Self::Provider(error) => write!(formatter, "transcript provider failure: {error}"),
            Self::UnexpectedStage { expected, actual } => write!(
                formatter,
                "unexpected handshake transcript stage {actual:?}, expected {expected:?}"
            ),
            Self::InitDoesNotMatchRetry => {
                formatter.write_str("INIT does not repeat HELLO, RETRY random, and cookie")
            }
            Self::NegotiationMismatch => {
                formatter.write_str("RESPONSE negotiation exceeds HELLO offer")
            }
            Self::InvariantViolation => {
                formatter.write_str("handshake transcript invariant violation")
            }
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for HandshakeTranscriptError<E> {}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use sha2::{Digest, Sha384};

    use super::*;
    use crate::crypto::Sha384Provider;
    use crate::handshake::{
        CAPABILITY_MULTIPATH_BIT, CAPABILITY_PERIODIC_HYBRID_REKEY_BIT, CAPABILITY_RESUME_BIT,
        CipherSuite, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN, ENCRYPTED_IDENTITY_AUTH_LEN,
        IDENTITY_FINGERPRINT_LEN, ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN,
        ML_KEM_768_CIPHERTEXT_LEN, ML_KEM_768_ENCAPSULATION_KEY_LEN, X25519_PUBLIC_KEY_LEN,
    };
    use crate::transcript::{TranscriptSink, feed_record};

    #[derive(Clone)]
    struct Sha384Context(Sha384);

    impl TranscriptSink for Sha384Context {
        fn update(&mut self, bytes: &[u8]) {
            self.0.update(bytes);
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ProviderError;

    #[derive(Default)]
    struct TestProvider {
        fail_next_fork: Cell<bool>,
        successful_forks_before_failure: Cell<Option<usize>>,
    }

    impl Sha384Provider for TestProvider {
        type Context = Sha384Context;
        type Error = ProviderError;

        fn start_sha384(&self) -> Result<Self::Context, Self::Error> {
            Ok(Sha384Context(Sha384::new()))
        }

        fn finish_sha384(&self, context: Self::Context) -> Result<Sha384Digest, Self::Error> {
            Ok(context.0.finalize().into())
        }
    }

    impl ForkableSha384Provider for TestProvider {
        fn fork_sha384(&self, context: &Self::Context) -> Result<Self::Context, Self::Error> {
            if self.fail_next_fork.replace(false) {
                return Err(ProviderError);
            }
            if let Some(remaining) = self.successful_forks_before_failure.get() {
                if remaining == 0 {
                    self.successful_forks_before_failure.set(None);
                    return Err(ProviderError);
                }
                self.successful_forks_before_failure
                    .set(Some(remaining - 1));
            }
            Ok(context.clone())
        }
    }

    #[derive(Default)]
    struct Recorder(Vec<u8>);

    impl TranscriptSink for Recorder {
        fn update(&mut self, bytes: &[u8]) {
            self.0.extend_from_slice(bytes);
        }
    }

    fn digest(recorder: &Recorder) -> Sha384Digest {
        Sha384::digest(&recorder.0).into()
    }

    fn canonical_hello() -> Hello {
        Hello {
            client_random: [0x11; RANDOM_LEN],
            identity_fingerprint: [0x22; IDENTITY_FINGERPRINT_LEN],
            cipher_suite_bitmap: CIPHER_SUITE_AES_256_GCM_SHA384_BIT
                | CIPHER_SUITE_CHACHA20_POLY1305_SHA384_BIT,
            capabilities: CAPABILITY_MULTIPATH_BIT | CAPABILITY_RESUME_BIT,
            max_udp_payload: 1_400,
            max_paths: 4,
        }
    }

    fn encode_hello() -> [u8; HELLO_LEN] {
        let mut value = [0_u8; HELLO_LEN];
        canonical_hello().encode(&mut value).expect("valid HELLO");
        value
    }

    fn encode_retry(cookie: &[u8]) -> Vec<u8> {
        let mut value = vec![0_u8; crate::handshake::RETRY_FIXED_LEN + cookie.len()];
        Retry {
            server_random: [0x33; RANDOM_LEN],
            cookie,
        }
        .encode(&mut value)
        .expect("valid RETRY");
        value
    }

    fn encode_init(cookie: &[u8]) -> Vec<u8> {
        let mut value = vec![0_u8; INIT_FIXED_LEN + cookie.len()];
        Init {
            hello: canonical_hello(),
            server_random: [0x33; RANDOM_LEN],
            cookie,
            x25519_public_key: [0x44; X25519_PUBLIC_KEY_LEN],
            ml_kem_encapsulation_key: &[0x55; ML_KEM_768_ENCAPSULATION_KEY_LEN],
        }
        .encode(&mut value)
        .expect("valid INIT");
        value
    }

    fn encode_response() -> [u8; RESPONSE_LEN] {
        let mut value = [0_u8; RESPONSE_LEN];
        Response {
            selected_cipher_suite: CipherSuite::Aes256GcmSha384,
            negotiated_capabilities: CAPABILITY_MULTIPATH_BIT,
            max_udp_payload: 1_400,
            max_paths: 2,
            identity_fingerprint: [0x66; IDENTITY_FINGERPRINT_LEN],
            x25519_public_key: [0x77; X25519_PUBLIC_KEY_LEN],
            ml_kem_ciphertext: &[0x88; ML_KEM_768_CIPHERTEXT_LEN],
            encrypted_identity_auth: &[0x99; ENCRYPTED_IDENTITY_AUTH_LEN],
        }
        .encode(&mut value)
        .expect("valid RESPONSE");
        value
    }

    fn encode_identity_auth(seed: u8) -> [u8; IDENTITY_AUTH_LEN] {
        let mut value = [0_u8; IDENTITY_AUTH_LEN];
        IdentityAuth {
            ed25519_public_key: [seed; ED25519_PUBLIC_KEY_LEN],
            ml_dsa_public_key: &[seed.wrapping_add(1); ML_DSA_65_PUBLIC_KEY_LEN],
            ed25519_signature: [seed.wrapping_add(2); ED25519_SIGNATURE_LEN],
            ml_dsa_signature: &[seed.wrapping_add(3); ML_DSA_65_SIGNATURE_LEN],
            finished_mac: [seed.wrapping_add(4); FINISHED_MAC_LEN],
        }
        .encode(&mut value)
        .expect("valid identity authentication");
        value
    }

    fn packet(
        packet_type: LongPacketType,
        message_id: u32,
        message_length: usize,
        fragment_offset: usize,
        fragment: &[u8],
    ) -> LongPacket<'_> {
        LongPacket {
            packet_type,
            version: 1,
            destination_connection_id: b"responder",
            source_connection_id: b"initiator",
            message_id,
            fragment_offset: u16::try_from(fragment_offset).expect("test offset fits"),
            message_length: u16::try_from(message_length).expect("test length fits"),
            fragment,
        }
    }

    #[test]
    fn hello_and_retry_are_decoded_without_a_pool_slot() {
        let hello = encode_hello();
        assert_eq!(
            decode_stateless_message(&packet(LongPacketType::Hello, 1, HELLO_LEN, 0, &hello)),
            Ok(StatelessHandshakeMessage::Hello(canonical_hello()))
        );

        let cookie = [0xa5; MIN_RETRY_COOKIE_LEN];
        let retry = encode_retry(&cookie);
        match decode_stateless_message(&packet(LongPacketType::Retry, 2, retry.len(), 0, &retry))
            .expect("complete RETRY")
        {
            StatelessHandshakeMessage::Retry(decoded) => assert_eq!(decoded.cookie, cookie),
            other => panic!("unexpected stateless message: {other:?}"),
        }

        let mut pool = HandshakeReassembler::<1>::new();
        assert_eq!(
            pool.ingest(
                &packet(LongPacketType::Hello, 1, HELLO_LEN, 0, &hello),
                ReassemblyAdmission::ExistingHandshake,
            ),
            Err(HandshakeReassemblyError::StatelessMessageDoesNotUsePool)
        );
        assert_eq!(pool.active_slots(), 0);
    }

    #[test]
    fn init_cookie_is_available_before_slot_allocation_and_debug_is_redacted() {
        let cookie = [0xa5; 32];
        let init = encode_init(&cookie);
        let first_fragment = &init[..400];
        let view = decode_init_admission_prefix(&packet(
            LongPacketType::Init,
            3,
            init.len(),
            0,
            first_fragment,
        ))
        .expect("INIT prefix");
        assert_eq!(view.hello, canonical_hello());
        assert_eq!(view.server_random, [0x33; RANDOM_LEN]);
        assert_eq!(view.cookie, cookie);
        let debug = format!("{view:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("165"));
    }

    #[test]
    fn reassembly_is_out_of_order_idempotent_and_bounded() {
        let response = encode_response();
        let split = 3_000;
        let mut pool = HandshakeReassembler::<1>::new();
        let tail = packet(
            LongPacketType::Response,
            7,
            RESPONSE_LEN,
            split,
            &response[split..],
        );
        assert_eq!(
            pool.ingest(&tail, ReassemblyAdmission::ExistingHandshake),
            Ok(HandshakeAssemblyStatus::Incomplete {
                packet_type: LongPacketType::Response,
                message_id: 7,
                received_bytes: RESPONSE_LEN - split,
                message_length: RESPONSE_LEN,
            })
        );
        assert_eq!(
            pool.ingest(&tail, ReassemblyAdmission::ExistingHandshake),
            Ok(HandshakeAssemblyStatus::Incomplete {
                packet_type: LongPacketType::Response,
                message_id: 7,
                received_bytes: RESPONSE_LEN - split,
                message_length: RESPONSE_LEN,
            })
        );
        assert_eq!(
            pool.ingest(
                &packet(
                    LongPacketType::Response,
                    7,
                    RESPONSE_LEN,
                    0,
                    &response[..split],
                ),
                ReassemblyAdmission::ExistingHandshake,
            ),
            Ok(HandshakeAssemblyStatus::Complete {
                packet_type: LongPacketType::Response,
                message_id: 7,
                message_length: RESPONSE_LEN,
            })
        );
        let complete = pool
            .completed_message(LongPacketType::Response, 7)
            .expect("complete message");
        assert_eq!(complete.value, response);
        assert_eq!(complete.destination_connection_id, b"responder");
        let message_debug = format!("{complete:?}");
        assert!(message_debug.contains("<redacted, 6601 bytes>"));
        assert!(!message_debug.contains("153, 153"));
        let pool_debug = format!("{pool:?}");
        assert!(pool_debug.contains("slots: \"<redacted>\""));
        assert!(pool.release(LongPacketType::Response, 7));
        assert_eq!(pool.active_slots(), 0);
        assert!(core::mem::size_of::<HandshakeReassembler<1>>() < 20 * 1_024);
    }

    #[test]
    fn overlap_and_metadata_changes_fail_closed() {
        let response = encode_response();
        let mut pool = HandshakeReassembler::<1>::new();
        pool.ingest(
            &packet(
                LongPacketType::Response,
                8,
                RESPONSE_LEN,
                0,
                &response[..100],
            ),
            ReassemblyAdmission::ExistingHandshake,
        )
        .expect("first fragment");
        let mut conflicting = response[50..100].to_vec();
        conflicting[10] ^= 1;
        assert_eq!(
            pool.ingest(
                &packet(LongPacketType::Response, 8, RESPONSE_LEN, 50, &conflicting,),
                ReassemblyAdmission::ExistingHandshake,
            ),
            Err(HandshakeReassemblyError::ConflictingOverlap {
                packet_type: LongPacketType::Response,
                message_id: 8,
                offset: 60,
            })
        );
        assert_eq!(pool.active_slots(), 0);

        let first = packet(
            LongPacketType::Response,
            9,
            RESPONSE_LEN,
            0,
            &response[..100],
        );
        pool.ingest(&first, ReassemblyAdmission::ExistingHandshake)
            .expect("first fragment");
        let mut changed = first;
        changed.version = 2;
        assert_eq!(
            pool.ingest(&changed, ReassemblyAdmission::ExistingHandshake),
            Err(HandshakeReassemblyError::MessageMetadataChanged {
                packet_type: LongPacketType::Response,
                message_id: 9,
            })
        );
        assert_eq!(pool.active_slots(), 0);
    }

    #[test]
    fn invalid_or_unadmitted_fragments_do_not_consume_slots() {
        let response = encode_response();
        let mut pool = HandshakeReassembler::<1>::new();
        assert_eq!(
            pool.ingest(
                &packet(
                    LongPacketType::Response,
                    10,
                    RESPONSE_LEN,
                    0,
                    &response[..100],
                ),
                ReassemblyAdmission::CookieValidated(HandshakeAdmissionLease::for_test()),
            ),
            Err(HandshakeReassemblyError::AdmissionRequired(
                LongPacketType::Response
            ))
        );

        let invalid_bounds = packet(
            LongPacketType::Response,
            10,
            RESPONSE_LEN,
            RESPONSE_LEN - 10,
            &response[..100],
        );
        assert_eq!(
            pool.ingest(&invalid_bounds, ReassemblyAdmission::ExistingHandshake),
            Err(HandshakeReassemblyError::Wire(
                WireError::InvalidFragmentBounds
            ))
        );

        let oversized_connection_id = [0_u8; MAX_LONG_CONNECTION_ID_LEN + 1];
        let mut invalid_connection_id = packet(
            LongPacketType::Response,
            10,
            RESPONSE_LEN,
            0,
            &response[..100],
        );
        invalid_connection_id.destination_connection_id = &oversized_connection_id;
        assert_eq!(
            pool.ingest(
                &invalid_connection_id,
                ReassemblyAdmission::ExistingHandshake,
            ),
            Err(HandshakeReassemblyError::Wire(
                WireError::ConnectionIdTooLong {
                    length: MAX_LONG_CONNECTION_ID_LEN + 1,
                    maximum: MAX_LONG_CONNECTION_ID_LEN,
                }
            ))
        );
        assert_eq!(pool.active_slots(), 0);

        pool.ingest(
            &packet(
                LongPacketType::Response,
                11,
                RESPONSE_LEN,
                0,
                &response[..100],
            ),
            ReassemblyAdmission::ExistingHandshake,
        )
        .expect("occupies only slot");
        assert_eq!(
            pool.ingest(
                &packet(
                    LongPacketType::Response,
                    12,
                    RESPONSE_LEN,
                    0,
                    &response[..100],
                ),
                ReassemblyAdmission::ExistingHandshake,
            ),
            Err(HandshakeReassemblyError::PoolExhausted)
        );
        assert_eq!(pool.active_slots(), 1);
    }

    #[test]
    fn transcript_snapshots_match_independent_canonical_hashing() {
        let provider = TestProvider::default();
        let session = SessionContext {
            version: 1,
            initiator_connection_id: b"initiator",
            responder_connection_id: b"responder",
        };
        let hello = encode_hello();
        let cookie = [0xa5; 32];
        let retry = encode_retry(&cookie);
        let init = encode_init(&cookie);
        let response = encode_response();
        let responder_auth = encode_identity_auth(0xb0);
        let initiator_auth = encode_identity_auth(0xc0);

        let mut expected = Recorder::default();
        let mut session_value = [0_u8; MAX_SESSION_CONTEXT_LEN];
        let session_length = session.encode(&mut session_value).expect("session context");
        feed_record(
            &mut expected,
            TranscriptRecordType::SessionContext,
            &session_value[..session_length],
        )
        .expect("record");
        feed_record(&mut expected, TranscriptRecordType::Hello, &hello).expect("record");
        feed_record(&mut expected, TranscriptRecordType::Retry, &retry).expect("record");
        feed_record(&mut expected, TranscriptRecordType::Init, &init).expect("record");
        feed_record(
            &mut expected,
            TranscriptRecordType::ResponsePrefix,
            &response[..RESPONSE_FIXED_LEN],
        )
        .expect("record");
        let expected_pre_auth = digest(&expected);
        feed_record(
            &mut expected,
            TranscriptRecordType::ResponderAuthContent,
            &responder_auth[..IDENTITY_AUTH_CONTENT_LEN],
        )
        .expect("record");
        let expected_responder_finished = digest(&expected);
        feed_record(
            &mut expected,
            TranscriptRecordType::ResponderFinished,
            &responder_auth[IDENTITY_AUTH_CONTENT_LEN..],
        )
        .expect("record");
        let expected_initiator_signature = digest(&expected);
        feed_record(
            &mut expected,
            TranscriptRecordType::InitiatorAuthContent,
            &initiator_auth[..IDENTITY_AUTH_CONTENT_LEN],
        )
        .expect("record");
        let expected_initiator_finished = digest(&expected);
        feed_record(
            &mut expected,
            TranscriptRecordType::InitiatorFinished,
            &initiator_auth[IDENTITY_AUTH_CONTENT_LEN..],
        )
        .expect("record");
        let expected_full = digest(&expected);

        let mut transcript = HandshakeTranscript::new(&provider, session).expect("starts");
        transcript.record_hello(&provider, &hello).expect("HELLO");
        transcript.record_retry(&provider, &retry).expect("RETRY");
        transcript.record_init(&provider, &init).expect("INIT");
        assert_eq!(
            transcript
                .record_response(&provider, &response)
                .expect("RESPONSE"),
            expected_pre_auth
        );
        let responder = transcript
            .record_responder_auth(&provider, &responder_auth)
            .expect("responder authentication");
        assert_eq!(responder.authentication.signature(), &expected_pre_auth);
        assert_eq!(
            responder.authentication.finished(),
            &expected_responder_finished
        );
        assert_eq!(
            responder.initiator_signature(),
            &expected_initiator_signature
        );
        let initiator = transcript
            .record_initiator_auth(&provider, &initiator_auth)
            .expect("initiator authentication");
        assert_eq!(
            initiator.authentication.signature(),
            &expected_initiator_signature
        );
        assert_eq!(
            initiator.authentication.finished(),
            &expected_initiator_finished
        );
        assert_eq!(initiator.full(), &expected_full);
        assert_eq!(transcript.stage(), HandshakeTranscriptStage::Complete);
    }

    #[test]
    fn transcript_validation_failures_preserve_the_expected_stage() {
        let provider = TestProvider::default();
        let session = SessionContext {
            version: 1,
            initiator_connection_id: b"initiator",
            responder_connection_id: b"responder",
        };
        let hello = encode_hello();
        let cookie = [0xa5; 32];
        let retry = encode_retry(&cookie);
        let init = encode_init(&cookie);
        let response = encode_response();
        let mut transcript = HandshakeTranscript::new(&provider, session).expect("starts");
        transcript.record_hello(&provider, &hello).expect("HELLO");
        transcript.record_retry(&provider, &retry).expect("RETRY");

        let mut mismatched_init = init.clone();
        mismatched_init[HELLO_LEN] ^= 1;
        assert_eq!(
            transcript.record_init(&provider, &mismatched_init),
            Err(HandshakeTranscriptError::InitDoesNotMatchRetry)
        );
        assert_eq!(transcript.stage(), HandshakeTranscriptStage::ExpectInit);
        transcript
            .record_init(&provider, &init)
            .expect("correct INIT");

        let mut excessive_response = response;
        excessive_response[2..6]
            .copy_from_slice(&CAPABILITY_PERIODIC_HYBRID_REKEY_BIT.to_be_bytes());
        assert_eq!(
            transcript.record_response(&provider, &excessive_response),
            Err(HandshakeTranscriptError::NegotiationMismatch)
        );
        assert_eq!(transcript.stage(), HandshakeTranscriptStage::ExpectResponse);
        transcript
            .record_response(&provider, &response)
            .expect("correct RESPONSE");
    }

    #[test]
    fn provider_failure_does_not_commit_a_transcript_transition() {
        let provider = TestProvider::default();
        let session = SessionContext {
            version: 1,
            initiator_connection_id: b"initiator",
            responder_connection_id: b"responder",
        };
        let hello = encode_hello();
        let mut transcript = HandshakeTranscript::new(&provider, session).expect("starts");
        provider.fail_next_fork.set(true);
        assert_eq!(
            transcript.record_hello(&provider, &hello),
            Err(HandshakeTranscriptError::Provider(ProviderError))
        );
        assert_eq!(transcript.stage(), HandshakeTranscriptStage::ExpectHello);
        transcript
            .record_hello(&provider, &hello)
            .expect("retry succeeds");
        assert_eq!(transcript.stage(), HandshakeTranscriptStage::ExpectRetry);
    }

    #[test]
    fn snapshot_failure_does_not_commit_partial_records() {
        let provider = TestProvider::default();
        let session = SessionContext {
            version: 1,
            initiator_connection_id: b"initiator",
            responder_connection_id: b"responder",
        };
        let hello = encode_hello();
        let cookie = [0xa5; 32];
        let retry = encode_retry(&cookie);
        let init = encode_init(&cookie);
        let response = encode_response();
        let responder_auth = encode_identity_auth(0xb0);
        let mut transcript = HandshakeTranscript::new(&provider, session).expect("starts");
        transcript.record_hello(&provider, &hello).expect("HELLO");
        transcript.record_retry(&provider, &retry).expect("RETRY");
        transcript.record_init(&provider, &init).expect("INIT");

        provider.successful_forks_before_failure.set(Some(1));
        assert_eq!(
            transcript.record_response(&provider, &response),
            Err(HandshakeTranscriptError::Provider(ProviderError))
        );
        assert_eq!(transcript.stage(), HandshakeTranscriptStage::ExpectResponse);
        transcript
            .record_response(&provider, &response)
            .expect("RESPONSE retry");

        provider.successful_forks_before_failure.set(Some(1));
        assert_eq!(
            transcript.record_responder_auth(&provider, &responder_auth),
            Err(HandshakeTranscriptError::Provider(ProviderError))
        );
        assert_eq!(
            transcript.stage(),
            HandshakeTranscriptStage::ExpectResponderAuth
        );
        transcript
            .record_responder_auth(&provider, &responder_auth)
            .expect("authentication retry");
        assert_eq!(
            transcript.stage(),
            HandshakeTranscriptStage::ExpectInitiatorAuth
        );
    }
}
