//! Provider-neutral short-packet protection orchestration.
//!
//! This module defines operation ordering, nonces, header masking, and usage
//! limits. Cryptographic primitives are supplied by an external provider.

use core::fmt;

use crate::handshake::CipherSuite;
use crate::wire::{
    AEAD_TAG_LEN, SHORT_HEADER_LEN, ShortHeader, WireError, reconstruct_packet_number,
};

pub const HEADER_PROTECTION_SAMPLE_LEN: usize = 16;
pub const HEADER_PROTECTION_MASK_LEN: usize = 5;
pub const HEADER_PROTECTION_SAMPLE_OFFSET: usize = SHORT_HEADER_LEN;
pub const MIN_PROTECTED_SHORT_PACKET_LEN: usize =
    HEADER_PROTECTION_SAMPLE_OFFSET + HEADER_PROTECTION_SAMPLE_LEN;
pub const MAX_PACKET_NUMBER: u64 = (1_u64 << 62) - 1;

pub const AES_GCM_ENCRYPTION_LIMIT: u64 = 1_u64 << 23;
pub const CHACHA20_ENCRYPTION_LIMIT: u64 = 1_u64 << 62;
pub const AES_GCM_AUTH_FAILURE_LIMIT: u64 = 1_u64 << 52;
pub const CHACHA20_AUTH_FAILURE_LIMIT: u64 = 1_u64 << 36;

/// Cryptographic operations required by the packet layer.
///
/// Implementations own key storage and may use software, hardware, or opaque
/// handles. A successful seal/open returns the resulting payload length.
pub trait PacketCryptoProvider {
    type AeadKey;
    type HeaderProtectionKey;

    /// Encrypts `plaintext_length` bytes in place and appends a 16-byte tag.
    ///
    /// # Errors
    ///
    /// Returns an error when the key is invalid or the provider cannot seal
    /// the payload.
    fn seal_in_place(
        &self,
        suite: CipherSuite,
        key: &Self::AeadKey,
        nonce: &[u8; 12],
        additional_data: &[u8],
        payload_and_tag: &mut [u8],
        plaintext_length: usize,
    ) -> Result<usize, ProviderError>;

    /// Authenticates and decrypts a ciphertext plus its 16-byte tag in place.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::AuthenticationFailed`] for an invalid tag, or
    /// another error when the key or provider is unavailable.
    fn open_in_place(
        &self,
        suite: CipherSuite,
        key: &Self::AeadKey,
        nonce: &[u8; 12],
        additional_data: &[u8],
        ciphertext_and_tag: &mut [u8],
    ) -> Result<usize, ProviderError>;

    /// Produces the five-byte AES-ECB or `ChaCha20` header-protection mask.
    ///
    /// # Errors
    ///
    /// Returns an error when the key is invalid or the provider cannot produce
    /// the mask.
    fn header_protection_mask(
        &self,
        suite: CipherSuite,
        key: &Self::HeaderProtectionKey,
        sample: &[u8; HEADER_PROTECTION_SAMPLE_LEN],
    ) -> Result<[u8; HEADER_PROTECTION_MASK_LEN], ProviderError>;
}

/// Borrowed packet-protection material for one direction and path.
///
/// Keeping these values together prevents callers from accidentally combining
/// an AEAD key, IV, and header-protection key from different paths. The header-
/// protection key remains stable while the destination connection ID is in use.
pub struct PathProtection<'a, P: PacketCryptoProvider> {
    pub suite: CipherSuite,
    pub aead_key: &'a P::AeadKey,
    pub header_protection_key: &'a P::HeaderProtectionKey,
    pub iv: &'a [u8; 12],
}

/// Protects one short packet whose plaintext is already placed after the
/// 13-byte header area.
///
/// # Errors
///
/// Returns an error for invalid lengths or packet number, exhausted AEAD usage,
/// a header/packet-number mismatch, or a provider failure. A reserved usage
/// count is not rolled back after a provider failure because nonce reuse would
/// then become ambiguous.
pub fn protect_short_packet<P: PacketCryptoProvider>(
    provider: &P,
    protection: &PathProtection<'_, P>,
    header: ShortHeader,
    packet_number: u64,
    plaintext_length: usize,
    packet: &mut [u8],
    usage: &mut EncryptionUsage,
) -> Result<usize, ProtectionError> {
    validate_packet_number(packet_number)?;
    if u64::from(header.truncated_packet_number) != packet_number & u64::from(u32::MAX) {
        return Err(ProtectionError::PacketNumberMismatch);
    }
    let protected_payload_length = plaintext_length
        .checked_add(AEAD_TAG_LEN)
        .ok_or(WireError::LengthOverflow)?;
    let packet_length = SHORT_HEADER_LEN
        .checked_add(protected_payload_length)
        .ok_or(WireError::LengthOverflow)?;
    if packet.len() < packet_length {
        return Err(WireError::BufferTooSmall {
            needed: packet_length,
            available: packet.len(),
        }
        .into());
    }
    if packet_length < MIN_PROTECTED_SHORT_PACKET_LEN {
        return Err(WireError::PacketTooShort {
            minimum: MIN_PROTECTED_SHORT_PACKET_LEN,
            actual: packet_length,
        }
        .into());
    }

    usage.reserve(protection.suite)?;
    let mut additional_data = [0_u8; SHORT_HEADER_LEN];
    header.encode(&mut additional_data)?;
    packet[..SHORT_HEADER_LEN].copy_from_slice(&additional_data);
    let nonce = packet_nonce(protection.iv, packet_number)?;
    let sealed_length = provider.seal_in_place(
        protection.suite,
        protection.aead_key,
        &nonce,
        &additional_data,
        &mut packet[SHORT_HEADER_LEN..packet_length],
        plaintext_length,
    )?;
    if sealed_length != protected_payload_length {
        return Err(ProtectionError::ProviderLengthMismatch {
            expected: protected_payload_length,
            actual: sealed_length,
        });
    }

    let mask = mask_for_packet(
        provider,
        protection.suite,
        protection.header_protection_key,
        packet,
    )?;
    apply_short_header_mask(packet, &mask)?;
    Ok(packet_length)
}

/// Removes short-header protection using the stable per-DCID HP key.
///
/// The returned header exposes the key phase, allowing the caller to select the
/// current or next AEAD key before opening the payload.
///
/// # Errors
///
/// Returns an error for a short packet, invalid unmasked header, or provider
/// failure.
pub fn remove_short_header_protection<P: PacketCryptoProvider>(
    provider: &P,
    protection: &PathProtection<'_, P>,
    packet: &mut [u8],
) -> Result<ShortHeader, ProtectionError> {
    let mask = mask_for_packet(
        provider,
        protection.suite,
        protection.header_protection_key,
        packet,
    )?;
    apply_short_header_mask(packet, &mask)?;
    Ok(ShortHeader::decode_unprotected(packet)?)
}

/// Authenticates and opens a packet after header protection was removed.
///
/// # Errors
///
/// Returns an error for invalid lengths/packet number, a provider failure, or
/// an exhausted authentication-failure limit. Authentication failures are
/// counted across the connection.
pub fn open_short_payload<P: PacketCryptoProvider>(
    provider: &P,
    protection: &PathProtection<'_, P>,
    header: ShortHeader,
    expected_packet_number: u64,
    packet: &mut [u8],
    failures: &mut AuthenticationFailureUsage,
) -> Result<OpenedPacket, ProtectionError> {
    if packet.len() < SHORT_HEADER_LEN + AEAD_TAG_LEN {
        return Err(WireError::PacketTooShort {
            minimum: SHORT_HEADER_LEN + AEAD_TAG_LEN,
            actual: packet.len(),
        }
        .into());
    }
    let packet_number =
        reconstruct_packet_number(header.truncated_packet_number, expected_packet_number);
    validate_packet_number(packet_number)?;
    let nonce = packet_nonce(protection.iv, packet_number)?;
    let mut additional_data = [0_u8; SHORT_HEADER_LEN];
    additional_data.copy_from_slice(&packet[..SHORT_HEADER_LEN]);
    let ciphertext_length = packet.len() - SHORT_HEADER_LEN;
    let opened = provider.open_in_place(
        protection.suite,
        protection.aead_key,
        &nonce,
        &additional_data,
        &mut packet[SHORT_HEADER_LEN..],
    );
    let plaintext_length = match opened {
        Ok(length) => length,
        Err(ProviderError::AuthenticationFailed) => {
            failures.record_failure(protection.suite)?;
            return Err(ProviderError::AuthenticationFailed.into());
        }
        Err(error) => return Err(error.into()),
    };
    let expected_plaintext_length = ciphertext_length - AEAD_TAG_LEN;
    if plaintext_length != expected_plaintext_length {
        return Err(ProtectionError::ProviderLengthMismatch {
            expected: expected_plaintext_length,
            actual: plaintext_length,
        });
    }
    Ok(OpenedPacket {
        header,
        packet_number,
        plaintext_length,
    })
}

/// Result metadata after successful packet opening.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenedPacket {
    pub header: ShortHeader,
    pub packet_number: u64,
    pub plaintext_length: usize,
}

/// Applies or removes the fixed OGTP short-header mask.
///
/// # Errors
///
/// Returns an error if `packet` does not contain the complete short header.
pub fn apply_short_header_mask(
    packet: &mut [u8],
    mask: &[u8; HEADER_PROTECTION_MASK_LEN],
) -> Result<(), ProtectionError> {
    if packet.len() < SHORT_HEADER_LEN {
        return Err(WireError::PacketTooShort {
            minimum: SHORT_HEADER_LEN,
            actual: packet.len(),
        }
        .into());
    }
    packet[0] ^= mask[0] & 0x7f;
    for (packet_byte, mask_byte) in packet[9..13].iter_mut().zip(&mask[1..5]) {
        *packet_byte ^= *mask_byte;
    }
    Ok(())
}

/// Derives a 96-bit AEAD nonce from the path IV and full packet number.
///
/// # Errors
///
/// Returns an error if `packet_number` exceeds the 62-bit OGTP space.
pub fn packet_nonce(iv: &[u8; 12], packet_number: u64) -> Result<[u8; 12], ProtectionError> {
    validate_packet_number(packet_number)?;
    let mut nonce = *iv;
    let encoded = packet_number.to_be_bytes();
    for (nonce_byte, packet_byte) in nonce[4..].iter_mut().zip(encoded) {
        *nonce_byte ^= packet_byte;
    }
    Ok(nonce)
}

fn mask_for_packet<P: PacketCryptoProvider>(
    provider: &P,
    suite: CipherSuite,
    key: &P::HeaderProtectionKey,
    packet: &[u8],
) -> Result<[u8; HEADER_PROTECTION_MASK_LEN], ProtectionError> {
    if packet.len() < MIN_PROTECTED_SHORT_PACKET_LEN {
        return Err(WireError::PacketTooShort {
            minimum: MIN_PROTECTED_SHORT_PACKET_LEN,
            actual: packet.len(),
        }
        .into());
    }
    let sample = <&[u8; HEADER_PROTECTION_SAMPLE_LEN]>::try_from(
        &packet[HEADER_PROTECTION_SAMPLE_OFFSET
            ..HEADER_PROTECTION_SAMPLE_OFFSET + HEADER_PROTECTION_SAMPLE_LEN],
    )
    .map_err(|_| WireError::LengthOverflow)?;
    Ok(provider.header_protection_mask(suite, key, sample)?)
}

fn validate_packet_number(packet_number: u64) -> Result<(), ProtectionError> {
    if packet_number > MAX_PACKET_NUMBER {
        return Err(ProtectionError::PacketNumberOutOfRange(packet_number));
    }
    Ok(())
}

const fn encryption_limit(suite: CipherSuite) -> u64 {
    match suite {
        CipherSuite::Aes256GcmSha384 => AES_GCM_ENCRYPTION_LIMIT,
        CipherSuite::ChaCha20Poly1305Sha384 => CHACHA20_ENCRYPTION_LIMIT,
    }
}

const fn authentication_failure_limit(suite: CipherSuite) -> u64 {
    match suite {
        CipherSuite::Aes256GcmSha384 => AES_GCM_AUTH_FAILURE_LIMIT,
        CipherSuite::ChaCha20Poly1305Sha384 => CHACHA20_AUTH_FAILURE_LIMIT,
    }
}

/// Per-key count of encrypted packets.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EncryptionUsage {
    encrypted_packets: u64,
}

impl EncryptionUsage {
    /// Reserves one encryption invocation before calling the provider.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectionError::EncryptionLimitReached`] at the suite limit.
    pub fn reserve(&mut self, suite: CipherSuite) -> Result<(), ProtectionError> {
        let limit = encryption_limit(suite);
        if self.encrypted_packets >= limit {
            return Err(ProtectionError::EncryptionLimitReached);
        }
        self.encrypted_packets = self
            .encrypted_packets
            .checked_add(1)
            .ok_or(ProtectionError::EncryptionLimitReached)?;
        Ok(())
    }

    /// Returns encrypted packets consumed under this key.
    #[must_use]
    pub const fn encrypted_packets(self) -> u64 {
        self.encrypted_packets
    }

    /// Returns whether the current invocation was the final permitted one.
    #[must_use]
    pub const fn update_required(self, suite: CipherSuite) -> bool {
        self.encrypted_packets >= encryption_limit(suite)
    }
}

/// Connection-wide count of failed packet authentications.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuthenticationFailureUsage {
    failed_authentications: u64,
}

impl AuthenticationFailureUsage {
    /// Records one failed authentication attempt.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectionError::AuthenticationFailureLimitReached`] when the
    /// new count reaches the conservative suite limit.
    pub fn record_failure(&mut self, suite: CipherSuite) -> Result<(), ProtectionError> {
        let limit = authentication_failure_limit(suite);
        if self.failed_authentications >= limit.saturating_sub(1) {
            self.failed_authentications = limit;
            return Err(ProtectionError::AuthenticationFailureLimitReached);
        }
        self.failed_authentications = self
            .failed_authentications
            .checked_add(1)
            .ok_or(ProtectionError::AuthenticationFailureLimitReached)?;
        Ok(())
    }

    /// Returns the connection-wide failure count.
    #[must_use]
    pub const fn failed_authentications(self) -> u64 {
        self.failed_authentications
    }
}

/// Failures reported by a cryptographic provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderError {
    AuthenticationFailed,
    InvalidKey,
    Internal,
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticationFailed => formatter.write_str("packet authentication failed"),
            Self::InvalidKey => formatter.write_str("invalid cryptographic key"),
            Self::Internal => formatter.write_str("cryptographic provider failure"),
        }
    }
}

impl std::error::Error for ProviderError {}

/// Packet-protection orchestration failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectionError {
    Wire(WireError),
    Provider(ProviderError),
    PacketNumberMismatch,
    PacketNumberOutOfRange(u64),
    ProviderLengthMismatch { expected: usize, actual: usize },
    EncryptionLimitReached,
    AuthenticationFailureLimitReached,
}

impl From<WireError> for ProtectionError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl From<ProviderError> for ProtectionError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

impl fmt::Display for ProtectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => error.fmt(formatter),
            Self::Provider(error) => error.fmt(formatter),
            Self::PacketNumberMismatch => {
                formatter.write_str("truncated and full packet numbers differ")
            }
            Self::PacketNumberOutOfRange(number) => {
                write!(formatter, "packet number exceeds 62 bits: {number}")
            }
            Self::ProviderLengthMismatch { expected, actual } => write!(
                formatter,
                "cryptographic provider length mismatch: expected {expected}, actual {actual}"
            ),
            Self::EncryptionLimitReached => formatter.write_str("AEAD encryption limit reached"),
            Self::AuthenticationFailureLimitReached => {
                formatter.write_str("AEAD authentication-failure limit reached")
            }
        }
    }
}

impl std::error::Error for ProtectionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{DataFrame, DataMetadata, PacketClass};

    struct FakeProvider;

    impl PacketCryptoProvider for FakeProvider {
        type AeadKey = ();
        type HeaderProtectionKey = ();

        fn seal_in_place(
            &self,
            _suite: CipherSuite,
            _key: &Self::AeadKey,
            _nonce: &[u8; 12],
            _additional_data: &[u8],
            payload_and_tag: &mut [u8],
            plaintext_length: usize,
        ) -> Result<usize, ProviderError> {
            for byte in &mut payload_and_tag[..plaintext_length] {
                *byte ^= 0xaa;
            }
            payload_and_tag[plaintext_length..plaintext_length + AEAD_TAG_LEN].fill(0x55);
            Ok(plaintext_length + AEAD_TAG_LEN)
        }

        fn open_in_place(
            &self,
            _suite: CipherSuite,
            _key: &Self::AeadKey,
            _nonce: &[u8; 12],
            _additional_data: &[u8],
            ciphertext_and_tag: &mut [u8],
        ) -> Result<usize, ProviderError> {
            let plaintext_length = ciphertext_and_tag
                .len()
                .checked_sub(AEAD_TAG_LEN)
                .ok_or(ProviderError::AuthenticationFailed)?;
            if ciphertext_and_tag[plaintext_length..]
                .iter()
                .any(|byte| *byte != 0x55)
            {
                return Err(ProviderError::AuthenticationFailed);
            }
            for byte in &mut ciphertext_and_tag[..plaintext_length] {
                *byte ^= 0xaa;
            }
            Ok(plaintext_length)
        }

        fn header_protection_mask(
            &self,
            _suite: CipherSuite,
            _key: &Self::HeaderProtectionKey,
            sample: &[u8; HEADER_PROTECTION_SAMPLE_LEN],
        ) -> Result<[u8; HEADER_PROTECTION_MASK_LEN], ProviderError> {
            let mut mask = [0_u8; HEADER_PROTECTION_MASK_LEN];
            mask.copy_from_slice(&sample[..HEADER_PROTECTION_MASK_LEN]);
            Ok(mask)
        }
    }

    #[test]
    fn short_packet_round_trip_preserves_plaintext() {
        let provider = FakeProvider;
        let packet_number = 7;
        let header = ShortHeader {
            class: PacketClass::Data,
            key_phase: false,
            destination_connection_id: *b"path-001",
            truncated_packet_number: packet_number,
        };
        let fragment = b"hello";
        let metadata = DataMetadata {
            object_slot: 1,
            chunk_index: 2,
            fragment_offset: 0,
            fragment_length: u16::try_from(fragment.len()).expect("test fragment fits"),
        };
        let mut packet = [0_u8; 128];
        let plaintext_length = metadata
            .encode_with_fragment(fragment, &mut packet[SHORT_HEADER_LEN..])
            .expect("DATA encodes");
        let mut encryption_usage = EncryptionUsage::default();
        let protection = PathProtection {
            suite: CipherSuite::Aes256GcmSha384,
            aead_key: &(),
            header_protection_key: &(),
            iv: &[0; 12],
        };
        let packet_length = protect_short_packet(
            &provider,
            &protection,
            header,
            u64::from(packet_number),
            plaintext_length,
            &mut packet,
            &mut encryption_usage,
        )
        .expect("packet protects");
        assert_ne!(&packet[..SHORT_HEADER_LEN], &[0; SHORT_HEADER_LEN]);

        let decoded_header =
            remove_short_header_protection(&provider, &protection, &mut packet[..packet_length])
                .expect("header opens");
        assert_eq!(decoded_header, header);
        let mut failures = AuthenticationFailureUsage::default();
        let opened = open_short_payload(
            &provider,
            &protection,
            decoded_header,
            u64::from(packet_number),
            &mut packet[..packet_length],
            &mut failures,
        )
        .expect("payload opens");
        let data = DataFrame::decode_plaintext(
            &packet[SHORT_HEADER_LEN..SHORT_HEADER_LEN + opened.plaintext_length],
        )
        .expect("DATA decodes");
        assert_eq!(data.fragment, fragment);
        assert_eq!(encryption_usage.encrypted_packets(), 1);
        assert_eq!(failures.failed_authentications(), 0);
    }

    #[test]
    fn header_mask_is_reversible_and_preserves_form_bit() {
        let mut packet = [0_u8; SHORT_HEADER_LEN];
        packet[0] = 0x60;
        packet[9..13].copy_from_slice(&[1, 2, 3, 4]);
        let original = packet;
        let mask = [0xff, 0x10, 0x20, 0x30, 0x40];
        apply_short_header_mask(&mut packet, &mask).expect("mask applies");
        assert_eq!(packet[0] & 0x80, original[0] & 0x80);
        assert_ne!(packet, original);
        apply_short_header_mask(&mut packet, &mask).expect("mask removes");
        assert_eq!(packet, original);
    }

    #[test]
    fn nonce_xors_packet_number_into_low_64_bits() {
        let iv = [0xa5; 12];
        let nonce = packet_nonce(&iv, 0x0102_0304_0506_0708).expect("packet number fits");
        assert_eq!(&nonce[..4], &[0xa5; 4]);
        assert_eq!(
            &nonce[4..],
            &[0xa4, 0xa7, 0xa6, 0xa1, 0xa0, 0xa3, 0xa2, 0xad]
        );
    }

    #[test]
    fn authentication_failure_is_counted() {
        let provider = FakeProvider;
        let header = ShortHeader {
            class: PacketClass::Control,
            key_phase: false,
            destination_connection_id: [1; 8],
            truncated_packet_number: 0,
        };
        let mut packet = [0_u8; SHORT_HEADER_LEN + AEAD_TAG_LEN];
        header.encode(&mut packet).expect("header fits");
        let mut failures = AuthenticationFailureUsage::default();
        let protection = PathProtection {
            suite: CipherSuite::ChaCha20Poly1305Sha384,
            aead_key: &(),
            header_protection_key: &(),
            iv: &[0; 12],
        };
        assert_eq!(
            open_short_payload(
                &provider,
                &protection,
                header,
                0,
                &mut packet,
                &mut failures,
            ),
            Err(ProtectionError::Provider(
                ProviderError::AuthenticationFailed
            ))
        );
        assert_eq!(failures.failed_authentications(), 1);
    }

    #[test]
    fn encryption_limits_never_wrap() {
        for (suite, limit) in [
            (CipherSuite::Aes256GcmSha384, AES_GCM_ENCRYPTION_LIMIT),
            (
                CipherSuite::ChaCha20Poly1305Sha384,
                CHACHA20_ENCRYPTION_LIMIT,
            ),
        ] {
            let mut usage = EncryptionUsage {
                encrypted_packets: limit - 1,
            };
            usage.reserve(suite).expect("final invocation is permitted");
            assert!(usage.update_required(suite));
            assert_eq!(
                usage.reserve(suite),
                Err(ProtectionError::EncryptionLimitReached)
            );
            assert_eq!(usage.encrypted_packets(), limit);
        }
    }

    #[test]
    fn authentication_failure_limits_close_on_the_boundary() {
        for (suite, limit) in [
            (CipherSuite::Aes256GcmSha384, AES_GCM_AUTH_FAILURE_LIMIT),
            (
                CipherSuite::ChaCha20Poly1305Sha384,
                CHACHA20_AUTH_FAILURE_LIMIT,
            ),
        ] {
            let mut usage = AuthenticationFailureUsage {
                failed_authentications: limit - 1,
            };
            assert_eq!(
                usage.record_failure(suite),
                Err(ProtectionError::AuthenticationFailureLimitReached)
            );
            assert_eq!(usage.failed_authentications(), limit);
            assert_eq!(
                usage.record_failure(suite),
                Err(ProtectionError::AuthenticationFailureLimitReached)
            );
            assert_eq!(usage.failed_authentications(), limit);
        }
    }
}
