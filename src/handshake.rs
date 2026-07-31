//! Allocation-free codecs for canonical OGTP/1 handshake messages.
//!
//! These types encode logical handshake messages. The long-header wire layer
//! fragments the resulting bytes independently.

use core::fmt;

use crate::wire::{AEAD_TAG_LEN, WireError, read_u16, read_u32};

pub const RANDOM_LEN: usize = 32;
pub const IDENTITY_FINGERPRINT_LEN: usize = 48;
pub const X25519_PUBLIC_KEY_LEN: usize = 32;
pub const ML_KEM_768_ENCAPSULATION_KEY_LEN: usize = 1_184;
pub const ML_KEM_768_CIPHERTEXT_LEN: usize = 1_088;
pub const ML_KEM_SHARED_SECRET_LEN: usize = 32;
pub const X25519_SHARED_SECRET_LEN: usize = 32;
pub const HYBRID_SHARED_SECRET_LEN: usize = ML_KEM_SHARED_SECRET_LEN + X25519_SHARED_SECRET_LEN;
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
pub const ED25519_SIGNATURE_LEN: usize = 64;
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1_952;
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3_309;
pub const FINISHED_MAC_LEN: usize = 48;
pub const MIN_RETRY_COOKIE_LEN: usize = 16;
pub const MAX_RETRY_COOKIE_LEN: usize = 256;
pub const MIN_MAX_UDP_PAYLOAD: u16 = 1_200;
pub const MAX_NEGOTIATED_PATHS: u8 = 16;

pub const HELLO_LEN: usize = 90;
pub const RETRY_FIXED_LEN: usize = RANDOM_LEN + 2;
pub const INIT_FIXED_LEN: usize =
    HELLO_LEN + RANDOM_LEN + 2 + X25519_PUBLIC_KEY_LEN + ML_KEM_768_ENCAPSULATION_KEY_LEN;
pub const IDENTITY_AUTH_LEN: usize = ED25519_PUBLIC_KEY_LEN
    + ML_DSA_65_PUBLIC_KEY_LEN
    + ED25519_SIGNATURE_LEN
    + ML_DSA_65_SIGNATURE_LEN
    + FINISHED_MAC_LEN;
pub const ENCRYPTED_IDENTITY_AUTH_LEN: usize = IDENTITY_AUTH_LEN + AEAD_TAG_LEN;
pub const RESPONSE_FIXED_LEN: usize = 2
    + 4
    + 2
    + 1
    + 1
    + IDENTITY_FINGERPRINT_LEN
    + X25519_PUBLIC_KEY_LEN
    + ML_KEM_768_CIPHERTEXT_LEN
    + 2;
pub const RESPONSE_LEN: usize = RESPONSE_FIXED_LEN + ENCRYPTED_IDENTITY_AUTH_LEN;
pub const FINISH_LEN: usize = 2 + ENCRYPTED_IDENTITY_AUTH_LEN;

pub const CIPHER_SUITE_AES_256_GCM_SHA384_BIT: u16 = 1 << 0;
pub const CIPHER_SUITE_CHACHA20_POLY1305_SHA384_BIT: u16 = 1 << 1;
pub const KNOWN_CIPHER_SUITE_BITS: u16 =
    CIPHER_SUITE_AES_256_GCM_SHA384_BIT | CIPHER_SUITE_CHACHA20_POLY1305_SHA384_BIT;

/// A cipher suite selected by the responder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum CipherSuite {
    Aes256GcmSha384 = 0x0001,
    ChaCha20Poly1305Sha384 = 0x0002,
}

impl CipherSuite {
    const fn from_wire(value: u16) -> Result<Self, HandshakeError> {
        match value {
            0x0001 => Ok(Self::Aes256GcmSha384),
            0x0002 => Ok(Self::ChaCha20Poly1305Sha384),
            _ => Err(HandshakeError::UnknownCipherSuite(value)),
        }
    }
}

/// Canonical HELLO message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hello {
    pub client_random: [u8; RANDOM_LEN],
    pub identity_fingerprint: [u8; IDENTITY_FINGERPRINT_LEN],
    pub cipher_suite_bitmap: u16,
    pub capabilities: u32,
    pub max_udp_payload: u16,
    pub max_paths: u8,
}

impl Hello {
    /// Encodes a canonical HELLO message.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid negotiation fields or a short output.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, HandshakeError> {
        self.validate()?;
        require_output(output, HELLO_LEN)?;
        output[0..32].copy_from_slice(&self.client_random);
        output[32..80].copy_from_slice(&self.identity_fingerprint);
        output[80..82].copy_from_slice(&self.cipher_suite_bitmap.to_be_bytes());
        output[82..86].copy_from_slice(&self.capabilities.to_be_bytes());
        output[86..88].copy_from_slice(&self.max_udp_payload.to_be_bytes());
        output[88] = self.max_paths;
        output[89] = 0;
        Ok(HELLO_LEN)
    }

    /// Decodes an exact canonical HELLO message.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-exact length, non-zero reserved byte, or
    /// invalid negotiation fields.
    pub fn decode(input: &[u8]) -> Result<Self, HandshakeError> {
        require_exact(input, HELLO_LEN)?;
        if input[89] != 0 {
            return Err(HandshakeError::NonZeroReserved(input[89]));
        }
        let hello = Self {
            client_random: copy_array(input, 0)?,
            identity_fingerprint: copy_array(input, 32)?,
            cipher_suite_bitmap: read_u16(input, 80)?,
            capabilities: read_u32(input, 82)?,
            max_udp_payload: read_u16(input, 86)?,
            max_paths: input[88],
        };
        hello.validate()?;
        Ok(hello)
    }

    fn validate(self) -> Result<(), HandshakeError> {
        if self.cipher_suite_bitmap & KNOWN_CIPHER_SUITE_BITS == 0 {
            return Err(HandshakeError::NoKnownCipherSuite);
        }
        validate_transport_limits(self.max_udp_payload, self.max_paths)
    }
}

/// Borrowed RETRY message carrying a stateless cookie.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Retry<'a> {
    pub server_random: [u8; RANDOM_LEN],
    pub cookie: &'a [u8],
}

impl<'a> Retry<'a> {
    /// Encodes a canonical RETRY message.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid cookie length or a short output.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, HandshakeError> {
        validate_cookie(self.cookie)?;
        let needed = RETRY_FIXED_LEN
            .checked_add(self.cookie.len())
            .ok_or(WireError::LengthOverflow)?;
        require_output(output, needed)?;
        output[0..32].copy_from_slice(&self.server_random);
        output[32..34].copy_from_slice(&u16_len(self.cookie.len())?.to_be_bytes());
        output[34..needed].copy_from_slice(self.cookie);
        Ok(needed)
    }

    /// Decodes a canonical RETRY message.
    ///
    /// # Errors
    ///
    /// Returns an error for truncation, trailing bytes, or an invalid cookie.
    pub fn decode(input: &'a [u8]) -> Result<Self, HandshakeError> {
        if input.len() < RETRY_FIXED_LEN {
            return Err(WireError::PacketTooShort {
                minimum: RETRY_FIXED_LEN,
                actual: input.len(),
            }
            .into());
        }
        let cookie_length = usize::from(read_u16(input, 32)?);
        let expected = RETRY_FIXED_LEN
            .checked_add(cookie_length)
            .ok_or(WireError::LengthOverflow)?;
        require_exact(input, expected)?;
        let cookie = &input[RETRY_FIXED_LEN..];
        validate_cookie(cookie)?;
        Ok(Self {
            server_random: copy_array(input, 0)?,
            cookie,
        })
    }
}

/// Borrowed INIT message containing the initiator hybrid key share.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Init<'a> {
    pub hello: Hello,
    pub server_random: [u8; RANDOM_LEN],
    pub cookie: &'a [u8],
    pub x25519_public_key: [u8; X25519_PUBLIC_KEY_LEN],
    pub ml_kem_encapsulation_key: &'a [u8],
}

impl<'a> Init<'a> {
    /// Encodes a canonical INIT message.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid fields, incorrect ML-KEM key size, or a
    /// short output.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, HandshakeError> {
        validate_cookie(self.cookie)?;
        require_component_length(
            "ML-KEM-768 encapsulation key",
            self.ml_kem_encapsulation_key.len(),
            ML_KEM_768_ENCAPSULATION_KEY_LEN,
        )?;
        let needed = INIT_FIXED_LEN
            .checked_add(self.cookie.len())
            .ok_or(WireError::LengthOverflow)?;
        require_output(output, needed)?;

        self.hello.encode(&mut output[..HELLO_LEN])?;
        let mut cursor = HELLO_LEN;
        output[cursor..cursor + RANDOM_LEN].copy_from_slice(&self.server_random);
        cursor += RANDOM_LEN;
        output[cursor..cursor + 2].copy_from_slice(&u16_len(self.cookie.len())?.to_be_bytes());
        cursor += 2;
        output[cursor..cursor + self.cookie.len()].copy_from_slice(self.cookie);
        cursor += self.cookie.len();
        output[cursor..cursor + X25519_PUBLIC_KEY_LEN].copy_from_slice(&self.x25519_public_key);
        cursor += X25519_PUBLIC_KEY_LEN;
        output[cursor..needed].copy_from_slice(self.ml_kem_encapsulation_key);
        Ok(needed)
    }

    /// Decodes a canonical INIT message without copying the ML-KEM key.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid HELLO fields, cookie bounds, truncation,
    /// trailing bytes, or an incorrect ML-KEM key size.
    pub fn decode(input: &'a [u8]) -> Result<Self, HandshakeError> {
        if input.len() < INIT_FIXED_LEN {
            return Err(WireError::PacketTooShort {
                minimum: INIT_FIXED_LEN,
                actual: input.len(),
            }
            .into());
        }
        let hello = Hello::decode(&input[..HELLO_LEN])?;
        let server_random = copy_array(input, HELLO_LEN)?;
        let cookie_length_offset = HELLO_LEN + RANDOM_LEN;
        let cookie_length = usize::from(read_u16(input, cookie_length_offset)?);
        let expected = INIT_FIXED_LEN
            .checked_add(cookie_length)
            .ok_or(WireError::LengthOverflow)?;
        require_exact(input, expected)?;

        let cookie_start = cookie_length_offset + 2;
        let cookie_end = cookie_start + cookie_length;
        let cookie = &input[cookie_start..cookie_end];
        validate_cookie(cookie)?;
        let x25519_public_key = copy_array(input, cookie_end)?;
        let ml_kem_start = cookie_end + X25519_PUBLIC_KEY_LEN;
        let ml_kem_encapsulation_key = &input[ml_kem_start..];
        require_component_length(
            "ML-KEM-768 encapsulation key",
            ml_kem_encapsulation_key.len(),
            ML_KEM_768_ENCAPSULATION_KEY_LEN,
        )?;
        Ok(Self {
            hello,
            server_random,
            cookie,
            x25519_public_key,
            ml_kem_encapsulation_key,
        })
    }
}

/// Borrowed RESPONSE containing the responder key share and encrypted identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Response<'a> {
    pub selected_cipher_suite: CipherSuite,
    pub negotiated_capabilities: u32,
    pub max_udp_payload: u16,
    pub max_paths: u8,
    pub identity_fingerprint: [u8; IDENTITY_FINGERPRINT_LEN],
    pub x25519_public_key: [u8; X25519_PUBLIC_KEY_LEN],
    pub ml_kem_ciphertext: &'a [u8],
    pub encrypted_identity_auth: &'a [u8],
}

impl<'a> Response<'a> {
    /// Encodes a fixed-size canonical RESPONSE message.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid negotiated limits, component sizes, or a
    /// short output.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, HandshakeError> {
        validate_transport_limits(self.max_udp_payload, self.max_paths)?;
        require_component_length(
            "ML-KEM-768 ciphertext",
            self.ml_kem_ciphertext.len(),
            ML_KEM_768_CIPHERTEXT_LEN,
        )?;
        require_component_length(
            "encrypted identity authentication",
            self.encrypted_identity_auth.len(),
            ENCRYPTED_IDENTITY_AUTH_LEN,
        )?;
        require_output(output, RESPONSE_LEN)?;

        output[0..2].copy_from_slice(&(self.selected_cipher_suite as u16).to_be_bytes());
        output[2..6].copy_from_slice(&self.negotiated_capabilities.to_be_bytes());
        output[6..8].copy_from_slice(&self.max_udp_payload.to_be_bytes());
        output[8] = self.max_paths;
        output[9] = 0;
        output[10..58].copy_from_slice(&self.identity_fingerprint);
        output[58..90].copy_from_slice(&self.x25519_public_key);
        output[90..1_178].copy_from_slice(self.ml_kem_ciphertext);
        output[1_178..1_180]
            .copy_from_slice(&u16_len(self.encrypted_identity_auth.len())?.to_be_bytes());
        output[1_180..RESPONSE_LEN].copy_from_slice(self.encrypted_identity_auth);
        Ok(RESPONSE_LEN)
    }

    /// Decodes a fixed-size canonical RESPONSE message without large copies.
    ///
    /// # Errors
    ///
    /// Returns an error for any non-exact size, unknown suite, non-zero
    /// reserved byte, invalid limit, or incorrect component length.
    pub fn decode(input: &'a [u8]) -> Result<Self, HandshakeError> {
        require_exact(input, RESPONSE_LEN)?;
        if input[9] != 0 {
            return Err(HandshakeError::NonZeroReserved(input[9]));
        }
        let selected_cipher_suite = CipherSuite::from_wire(read_u16(input, 0)?)?;
        let max_udp_payload = read_u16(input, 6)?;
        let max_paths = input[8];
        validate_transport_limits(max_udp_payload, max_paths)?;
        let encrypted_length = usize::from(read_u16(input, 1_178)?);
        require_component_length(
            "encrypted identity authentication",
            encrypted_length,
            ENCRYPTED_IDENTITY_AUTH_LEN,
        )?;
        Ok(Self {
            selected_cipher_suite,
            negotiated_capabilities: read_u32(input, 2)?,
            max_udp_payload,
            max_paths,
            identity_fingerprint: copy_array(input, 10)?,
            x25519_public_key: copy_array(input, 58)?,
            ml_kem_ciphertext: &input[90..1_178],
            encrypted_identity_auth: &input[1_180..],
        })
    }
}

/// Borrowed FINISH message carrying initiator authentication ciphertext.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Finish<'a> {
    pub encrypted_identity_auth: &'a [u8],
}

impl<'a> Finish<'a> {
    /// Encodes a canonical FINISH message.
    ///
    /// # Errors
    ///
    /// Returns an error for an incorrect ciphertext size or a short output.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, HandshakeError> {
        require_component_length(
            "encrypted identity authentication",
            self.encrypted_identity_auth.len(),
            ENCRYPTED_IDENTITY_AUTH_LEN,
        )?;
        require_output(output, FINISH_LEN)?;
        output[0..2].copy_from_slice(&u16_len(self.encrypted_identity_auth.len())?.to_be_bytes());
        output[2..FINISH_LEN].copy_from_slice(self.encrypted_identity_auth);
        Ok(FINISH_LEN)
    }

    /// Decodes a fixed-size canonical FINISH message.
    ///
    /// # Errors
    ///
    /// Returns an error for any non-exact or inconsistent length.
    pub fn decode(input: &'a [u8]) -> Result<Self, HandshakeError> {
        require_exact(input, FINISH_LEN)?;
        let encrypted_length = usize::from(read_u16(input, 0)?);
        require_component_length(
            "encrypted identity authentication",
            encrypted_length,
            ENCRYPTED_IDENTITY_AUTH_LEN,
        )?;
        Ok(Self {
            encrypted_identity_auth: &input[2..],
        })
    }
}

/// Borrowed plaintext sealed inside RESPONSE and FINISH.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityAuth<'a> {
    pub ed25519_public_key: [u8; ED25519_PUBLIC_KEY_LEN],
    pub ml_dsa_public_key: &'a [u8],
    pub ed25519_signature: [u8; ED25519_SIGNATURE_LEN],
    pub ml_dsa_signature: &'a [u8],
    pub finished_mac: [u8; FINISHED_MAC_LEN],
}

impl<'a> IdentityAuth<'a> {
    /// Encodes canonical identity-authentication plaintext.
    ///
    /// # Errors
    ///
    /// Returns an error for an incorrect ML-DSA component size or short output.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, HandshakeError> {
        require_component_length(
            "ML-DSA-65 public key",
            self.ml_dsa_public_key.len(),
            ML_DSA_65_PUBLIC_KEY_LEN,
        )?;
        require_component_length(
            "ML-DSA-65 signature",
            self.ml_dsa_signature.len(),
            ML_DSA_65_SIGNATURE_LEN,
        )?;
        require_output(output, IDENTITY_AUTH_LEN)?;

        output[0..32].copy_from_slice(&self.ed25519_public_key);
        output[32..1_984].copy_from_slice(self.ml_dsa_public_key);
        output[1_984..2_048].copy_from_slice(&self.ed25519_signature);
        output[2_048..5_357].copy_from_slice(self.ml_dsa_signature);
        output[5_357..5_405].copy_from_slice(&self.finished_mac);
        Ok(IDENTITY_AUTH_LEN)
    }

    /// Decodes fixed-size identity-authentication plaintext without large copies.
    ///
    /// # Errors
    ///
    /// Returns an error unless `input` is exactly [`IDENTITY_AUTH_LEN`] bytes.
    pub fn decode(input: &'a [u8]) -> Result<Self, HandshakeError> {
        require_exact(input, IDENTITY_AUTH_LEN)?;
        Ok(Self {
            ed25519_public_key: copy_array(input, 0)?,
            ml_dsa_public_key: &input[32..1_984],
            ed25519_signature: copy_array(input, 1_984)?,
            ml_dsa_signature: &input[2_048..5_357],
            finished_mac: copy_array(input, 5_357)?,
        })
    }
}

/// Writes the exact hybrid shared-secret input in the current IETF order.
///
/// The result is `ML-KEM shared secret || X25519 shared secret`.
///
/// # Errors
///
/// Returns [`WireError::BufferTooSmall`] for an output shorter than 64 bytes.
pub fn encode_hybrid_shared_secret(
    ml_kem_shared_secret: &[u8; ML_KEM_SHARED_SECRET_LEN],
    x25519_shared_secret: &[u8; X25519_SHARED_SECRET_LEN],
    output: &mut [u8],
) -> Result<usize, HandshakeError> {
    require_output(output, HYBRID_SHARED_SECRET_LEN)?;
    output[..ML_KEM_SHARED_SECRET_LEN].copy_from_slice(ml_kem_shared_secret);
    output[ML_KEM_SHARED_SECRET_LEN..HYBRID_SHARED_SECRET_LEN]
        .copy_from_slice(x25519_shared_secret);
    Ok(HYBRID_SHARED_SECRET_LEN)
}

/// Handshake codec validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeError {
    Wire(WireError),
    NoKnownCipherSuite,
    UnknownCipherSuite(u16),
    InvalidMaxUdpPayload(u16),
    InvalidMaxPaths(u8),
    NonZeroReserved(u8),
    InvalidCookieLength {
        length: usize,
    },
    InvalidComponentLength {
        component: &'static str,
        expected: usize,
        actual: usize,
    },
}

impl From<WireError> for HandshakeError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => error.fmt(formatter),
            Self::NoKnownCipherSuite => formatter.write_str("no known cipher suite offered"),
            Self::UnknownCipherSuite(suite) => {
                write!(formatter, "unknown cipher suite: {suite:#06x}")
            }
            Self::InvalidMaxUdpPayload(value) => {
                write!(formatter, "invalid maximum UDP payload: {value}")
            }
            Self::InvalidMaxPaths(value) => write!(formatter, "invalid maximum paths: {value}"),
            Self::NonZeroReserved(value) => {
                write!(formatter, "non-zero reserved handshake byte: {value:#x}")
            }
            Self::InvalidCookieLength { length } => write!(
                formatter,
                "invalid RETRY cookie length: {length}, expected {MIN_RETRY_COOKIE_LEN}..={MAX_RETRY_COOKIE_LEN}"
            ),
            Self::InvalidComponentLength {
                component,
                expected,
                actual,
            } => write!(
                formatter,
                "invalid {component} length: expected {expected}, actual {actual}"
            ),
        }
    }
}

impl std::error::Error for HandshakeError {}

fn validate_transport_limits(max_udp_payload: u16, max_paths: u8) -> Result<(), HandshakeError> {
    if max_udp_payload < MIN_MAX_UDP_PAYLOAD {
        return Err(HandshakeError::InvalidMaxUdpPayload(max_udp_payload));
    }
    if max_paths == 0 || max_paths > MAX_NEGOTIATED_PATHS {
        return Err(HandshakeError::InvalidMaxPaths(max_paths));
    }
    Ok(())
}

fn validate_cookie(cookie: &[u8]) -> Result<(), HandshakeError> {
    if !(MIN_RETRY_COOKIE_LEN..=MAX_RETRY_COOKIE_LEN).contains(&cookie.len()) {
        return Err(HandshakeError::InvalidCookieLength {
            length: cookie.len(),
        });
    }
    Ok(())
}

fn require_component_length(
    component: &'static str,
    actual: usize,
    expected: usize,
) -> Result<(), HandshakeError> {
    if actual != expected {
        return Err(HandshakeError::InvalidComponentLength {
            component,
            expected,
            actual,
        });
    }
    Ok(())
}

fn require_output(output: &[u8], needed: usize) -> Result<(), HandshakeError> {
    if output.len() < needed {
        return Err(WireError::BufferTooSmall {
            needed,
            available: output.len(),
        }
        .into());
    }
    Ok(())
}

fn require_exact(input: &[u8], expected: usize) -> Result<(), HandshakeError> {
    if input.len() < expected {
        return Err(WireError::PacketTooShort {
            minimum: expected,
            actual: input.len(),
        }
        .into());
    }
    if input.len() != expected {
        return Err(WireError::LengthMismatch {
            expected,
            actual: input.len(),
        }
        .into());
    }
    Ok(())
}

fn u16_len(length: usize) -> Result<u16, HandshakeError> {
    u16::try_from(length).map_err(|_| {
        WireError::FrameValueTooLarge {
            length,
            maximum: usize::from(u16::MAX),
        }
        .into()
    })
}

fn copy_array<const N: usize>(input: &[u8], offset: usize) -> Result<[u8; N], HandshakeError> {
    let end = offset.checked_add(N).ok_or(WireError::LengthOverflow)?;
    let value = input.get(offset..end).ok_or(WireError::PacketTooShort {
        minimum: end,
        actual: input.len(),
    })?;
    <[u8; N]>::try_from(value).map_err(|_| WireError::LengthOverflow.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello() -> Hello {
        Hello {
            client_random: [0x11; RANDOM_LEN],
            identity_fingerprint: [0x22; IDENTITY_FINGERPRINT_LEN],
            cipher_suite_bitmap: KNOWN_CIPHER_SUITE_BITS,
            capabilities: 3,
            max_udp_payload: 1_200,
            max_paths: 2,
        }
    }

    #[test]
    fn hello_round_trip_is_fixed_size() {
        let original = hello();
        let mut output = [0_u8; HELLO_LEN];
        assert_eq!(original.encode(&mut output), Ok(HELLO_LEN));
        assert_eq!(Hello::decode(&output), Ok(original));
    }

    #[test]
    fn retry_and_init_round_trip_without_large_copies() {
        let cookie = [0x33; 48];
        let retry = Retry {
            server_random: [0x44; RANDOM_LEN],
            cookie: &cookie,
        };
        let mut retry_bytes = [0_u8; RETRY_FIXED_LEN + 48];
        let retry_len = retry.encode(&mut retry_bytes).expect("RETRY encodes");
        assert_eq!(Retry::decode(&retry_bytes[..retry_len]), Ok(retry));

        let ml_kem_key = [0x55; ML_KEM_768_ENCAPSULATION_KEY_LEN];
        let init = Init {
            hello: hello(),
            server_random: retry.server_random,
            cookie: &cookie,
            x25519_public_key: [0x66; X25519_PUBLIC_KEY_LEN],
            ml_kem_encapsulation_key: &ml_kem_key,
        };
        let mut init_bytes = [0_u8; INIT_FIXED_LEN + 48];
        let init_len = init.encode(&mut init_bytes).expect("INIT encodes");
        assert_eq!(Init::decode(&init_bytes[..init_len]), Ok(init));
    }

    #[test]
    fn response_and_finish_enforce_ciphertext_size() {
        let ml_kem_ciphertext = [0x77; ML_KEM_768_CIPHERTEXT_LEN];
        let encrypted_auth = [0x88; ENCRYPTED_IDENTITY_AUTH_LEN];
        let response = Response {
            selected_cipher_suite: CipherSuite::Aes256GcmSha384,
            negotiated_capabilities: 1,
            max_udp_payload: 1_400,
            max_paths: 2,
            identity_fingerprint: [0x99; IDENTITY_FINGERPRINT_LEN],
            x25519_public_key: [0xaa; X25519_PUBLIC_KEY_LEN],
            ml_kem_ciphertext: &ml_kem_ciphertext,
            encrypted_identity_auth: &encrypted_auth,
        };
        let mut response_bytes = [0_u8; RESPONSE_LEN];
        assert_eq!(response.encode(&mut response_bytes), Ok(RESPONSE_LEN));
        assert_eq!(Response::decode(&response_bytes), Ok(response));

        let finish = Finish {
            encrypted_identity_auth: &encrypted_auth,
        };
        let mut finish_bytes = [0_u8; FINISH_LEN];
        assert_eq!(finish.encode(&mut finish_bytes), Ok(FINISH_LEN));
        assert_eq!(Finish::decode(&finish_bytes), Ok(finish));
    }

    #[test]
    fn identity_auth_round_trip() {
        let ml_dsa_public_key = [0xbb; ML_DSA_65_PUBLIC_KEY_LEN];
        let ml_dsa_signature = [0xcc; ML_DSA_65_SIGNATURE_LEN];
        let auth = IdentityAuth {
            ed25519_public_key: [0xdd; ED25519_PUBLIC_KEY_LEN],
            ml_dsa_public_key: &ml_dsa_public_key,
            ed25519_signature: [0xee; ED25519_SIGNATURE_LEN],
            ml_dsa_signature: &ml_dsa_signature,
            finished_mac: [0xff; FINISHED_MAC_LEN],
        };
        let mut output = [0_u8; IDENTITY_AUTH_LEN];
        assert_eq!(auth.encode(&mut output), Ok(IDENTITY_AUTH_LEN));
        assert_eq!(IdentityAuth::decode(&output), Ok(auth));
    }

    #[test]
    fn hybrid_secret_uses_ml_kem_first() {
        let ml_kem = [0x11; ML_KEM_SHARED_SECRET_LEN];
        let x25519 = [0x22; X25519_SHARED_SECRET_LEN];
        let mut output = [0_u8; HYBRID_SHARED_SECRET_LEN];
        assert_eq!(
            encode_hybrid_shared_secret(&ml_kem, &x25519, &mut output),
            Ok(HYBRID_SHARED_SECRET_LEN)
        );
        assert_eq!(&output[..32], &ml_kem);
        assert_eq!(&output[32..], &x25519);
    }

    #[test]
    fn invalid_negotiation_and_component_sizes_are_rejected() {
        let mut invalid = hello();
        invalid.cipher_suite_bitmap = 0x8000;
        let mut output = [0_u8; HELLO_LEN];
        assert_eq!(
            invalid.encode(&mut output),
            Err(HandshakeError::NoKnownCipherSuite)
        );

        let init = Init {
            hello: hello(),
            server_random: [0; RANDOM_LEN],
            cookie: &[0; MIN_RETRY_COOKIE_LEN],
            x25519_public_key: [0; X25519_PUBLIC_KEY_LEN],
            ml_kem_encapsulation_key: &[0; 1],
        };
        let mut init_output = [0_u8; INIT_FIXED_LEN + MIN_RETRY_COOKIE_LEN];
        assert_eq!(
            init.encode(&mut init_output),
            Err(HandshakeError::InvalidComponentLength {
                component: "ML-KEM-768 encapsulation key",
                expected: ML_KEM_768_ENCAPSULATION_KEY_LEN,
                actual: 1,
            })
        );
    }
}
