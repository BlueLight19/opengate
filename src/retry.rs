//! Authenticated stateless `RETRY` cookies and bounded post-cookie admission.

use core::fmt;

use crate::crypto::{SHA384_OUTPUT_LEN, Sha384Digest, Sha384Provider};
use crate::handshake::{HELLO_LEN, Hello, RANDOM_LEN, RETRY_FIXED_LEN};
use crate::transcript::TranscriptSink;
use crate::wire::{
    AEAD_TAG_LEN, WireError,
    long::{LONG_HEADER_FIXED_LEN, MAX_LONG_CONNECTION_ID_LEN},
};

/// Current server-local cookie format.
pub const RETRY_COOKIE_FORMAT: u8 = 1;
/// Nonce size required from the cookie AEAD provider.
pub const RETRY_COOKIE_NONCE_LEN: usize = 12;
/// Fixed authenticated cookie size emitted by this profile.
pub const RETRY_COOKIE_LEN: usize = 226;
/// Largest possible OGTP UDP payload carrying this fixed cookie.
pub const MAX_RETRY_DATAGRAM_LEN: usize =
    LONG_HEADER_FIXED_LEN + 2 * MAX_LONG_CONNECTION_ID_LEN + RETRY_FIXED_LEN + RETRY_COOKIE_LEN;
/// Smallest valid OGTP UDP payload that can trigger one `RETRY`.
pub const MIN_HELLO_DATAGRAM_LEN: usize = LONG_HEADER_FIXED_LEN + HELLO_LEN;

const _: () = assert!(MAX_RETRY_DATAGRAM_LEN <= 3 * MIN_HELLO_DATAGRAM_LEN);

const RETRY_COOKIE_HEADER_LEN: usize = 1 + 4 + RETRY_COOKIE_NONCE_LEN;
const RETRY_COOKIE_PLAINTEXT_LEN: usize = 193;
const RETRY_COOKIE_SEALED_LEN: usize = RETRY_COOKIE_PLAINTEXT_LEN + AEAD_TAG_LEN;
const RETRY_COOKIE_AAD_CONTEXT: &[u8] = b"OGTP/1 retry cookie\x00";
const RETRY_COOKIE_AAD_LEN: usize = RETRY_COOKIE_AAD_CONTEXT.len() + RETRY_COOKIE_HEADER_LEN;

const ISSUED_AT_OFFSET: usize = 0;
const EXPIRES_AT_OFFSET: usize = 8;
const ADDRESS_FAMILY_OFFSET: usize = 16;
const ADDRESS_OFFSET: usize = 17;
const SOURCE_PORT_OFFSET: usize = 33;
const VERSION_OFFSET: usize = 35;
const INITIATOR_CID_LENGTH_OFFSET: usize = 39;
const INITIATOR_CID_OFFSET: usize = 40;
const RESPONDER_CID_LENGTH_OFFSET: usize = 60;
const RESPONDER_CID_OFFSET: usize = 61;
const CLIENT_RANDOM_OFFSET: usize = 81;
const SERVER_RANDOM_OFFSET: usize = 113;
const HELLO_HASH_OFFSET: usize = 145;

/// Source IP address bound into a `RETRY` cookie.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetrySourceAddress {
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
}

/// Complete public context authenticated by one stateless cookie.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RetryCookieBinding<'a> {
    pub source_address: RetrySourceAddress,
    pub source_port: u16,
    pub version: u32,
    pub initiator_connection_id: &'a [u8],
    pub responder_connection_id: &'a [u8],
    pub hello: Hello,
    pub server_random: [u8; RANDOM_LEN],
}

impl fmt::Debug for RetryCookieBinding<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetryCookieBinding")
            .field("source_address", &"<redacted>")
            .field("source_port", &"<redacted>")
            .field("version", &self.version)
            .field("initiator_connection_id", &"<redacted>")
            .field("responder_connection_id", &"<redacted>")
            .field("hello", &"<redacted>")
            .field("server_random", &"<redacted>")
            .finish()
    }
}

/// Result of authenticating and opening a cookie payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryCookieOpenResult {
    Opened(usize),
    Invalid,
}

/// Provider boundary for the standardized AEAD used by server-local cookies.
///
/// The provider selects an audited AEAD with at least a 256-bit key and a
/// 16-byte tag. Seal/open operations authenticate the supplied context. An
/// invalid tag is returned as [`RetryCookieOpenResult::Invalid`], while backend
/// failures use the provider error channel.
pub trait RetryCookieProvider: Sha384Provider {
    type Key;

    /// Seals `plaintext_length` bytes in place and appends a 16-byte tag.
    ///
    /// # Errors
    ///
    /// Returns a provider-specific error for an unusable key or backend
    /// failure.
    fn seal_retry_cookie(
        &self,
        key: &Self::Key,
        nonce: &[u8; RETRY_COOKIE_NONCE_LEN],
        additional_data: &[u8],
        plaintext_and_tag: &mut [u8],
        plaintext_length: usize,
    ) -> Result<usize, Self::Error>;

    /// Authenticates and opens one fixed cookie payload in place.
    ///
    /// # Errors
    ///
    /// Returns a provider-specific error only for a key/backend failure. Tag
    /// mismatch is an ordinary invalid-cookie result.
    fn open_retry_cookie(
        &self,
        key: &Self::Key,
        nonce: &[u8; RETRY_COOKIE_NONCE_LEN],
        additional_data: &[u8],
        ciphertext_and_tag: &mut [u8],
    ) -> Result<RetryCookieOpenResult, Self::Error>;
}

/// Time policy applied identically during issuance and validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryCookiePolicy {
    lifetime_seconds: u64,
    maximum_clock_skew_seconds: u64,
}

impl RetryCookiePolicy {
    /// Creates a strict non-zero cookie lifetime and bounded future-clock skew.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero lifetime or skew larger than the lifetime.
    pub const fn new(
        lifetime_seconds: u64,
        maximum_clock_skew_seconds: u64,
    ) -> Result<Self, RetryCookiePolicyError> {
        if lifetime_seconds == 0 {
            return Err(RetryCookiePolicyError::ZeroLifetime);
        }
        if maximum_clock_skew_seconds > lifetime_seconds {
            return Err(RetryCookiePolicyError::ClockSkewExceedsLifetime);
        }
        Ok(Self {
            lifetime_seconds,
            maximum_clock_skew_seconds,
        })
    }

    #[must_use]
    pub const fn lifetime_seconds(self) -> u64 {
        self.lifetime_seconds
    }

    #[must_use]
    pub const fn maximum_clock_skew_seconds(self) -> u64 {
        self.maximum_clock_skew_seconds
    }
}

/// Policy configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryCookiePolicyError {
    ZeroLifetime,
    ClockSkewExceedsLifetime,
}

impl fmt::Display for RetryCookiePolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroLifetime => formatter.write_str("RETRY cookie lifetime is zero"),
            Self::ClockSkewExceedsLifetime => {
                formatter.write_str("RETRY cookie clock skew exceeds its lifetime")
            }
        }
    }
}

impl std::error::Error for RetryCookiePolicyError {}

/// One opaque cookie key and its bounded issuance/acceptance schedule.
pub struct RetryCookieKey<K> {
    key_id: u32,
    key: K,
    nonce_scope: [u8; 8],
    next_nonce_counter: u32,
    activate_at: u64,
    seal_until: u64,
    accept_until: u64,
}

impl<K> RetryCookieKey<K> {
    /// Installs one scheduled key with a per-key unique nonce scope.
    ///
    /// `activate_at <= issue time < seal_until <= accept_until`. The caller
    /// must allocate a scope never used by another sealing process or restored
    /// snapshot under the same key.
    ///
    /// # Errors
    ///
    /// Returns an error unless the three timestamps are strictly usable.
    pub fn new(
        key_id: u32,
        key: K,
        nonce_scope: [u8; 8],
        activate_at: u64,
        seal_until: u64,
        accept_until: u64,
    ) -> Result<Self, RetryCookieKeyError> {
        if activate_at >= seal_until || seal_until > accept_until {
            return Err(RetryCookieKeyError::InvalidSchedule);
        }
        Ok(Self {
            key_id,
            key,
            nonce_scope,
            next_nonce_counter: 0,
            activate_at,
            seal_until,
            accept_until,
        })
    }

    #[must_use]
    pub const fn key_id(&self) -> u32 {
        self.key_id
    }

    #[must_use]
    pub const fn activate_at(&self) -> u64 {
        self.activate_at
    }

    #[must_use]
    pub const fn seal_until(&self) -> u64 {
        self.seal_until
    }

    #[must_use]
    pub const fn accept_until(&self) -> u64 {
        self.accept_until
    }
}

impl<K> fmt::Debug for RetryCookieKey<K> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetryCookieKey")
            .field("key_id", &self.key_id)
            .field("key", &"<redacted>")
            .field("nonce_scope", &"<redacted>")
            .field("next_nonce_counter", &"<redacted>")
            .field("activate_at", &self.activate_at)
            .field("seal_until", &self.seal_until)
            .field("accept_until", &self.accept_until)
            .finish()
    }
}

/// Key schedule configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryCookieKeyError {
    InvalidSchedule,
}

impl fmt::Display for RetryCookieKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid RETRY cookie key schedule")
    }
}

impl std::error::Error for RetryCookieKeyError {}

/// Fixed two-generation cookie key ring.
pub struct RetryCookieKeyRing<K> {
    active: RetryCookieKey<K>,
    previous: Option<RetryCookieKey<K>>,
}

impl<K> RetryCookieKeyRing<K> {
    #[must_use]
    pub const fn new(active: RetryCookieKey<K>) -> Self {
        Self {
            active,
            previous: None,
        }
    }

    /// Replaces the non-sealing active key and retains it for validation.
    ///
    /// # Errors
    ///
    /// Returns an error when rotation is early, the next key is not active at
    /// `now`, its ID collides, or an older validation key is still required.
    pub fn rotate(
        &mut self,
        next: RetryCookieKey<K>,
        now: u64,
    ) -> Result<(), RetryCookieRotationError> {
        if self
            .previous
            .as_ref()
            .is_some_and(|previous| now < previous.accept_until)
        {
            return Err(RetryCookieRotationError::PreviousKeyStillRequired);
        }
        if now < self.active.seal_until {
            return Err(RetryCookieRotationError::ActiveKeyStillSealing);
        }
        if now < next.activate_at || now >= next.seal_until {
            return Err(RetryCookieRotationError::NextKeyNotActive);
        }
        if next.key_id == self.active.key_id
            || self
                .previous
                .as_ref()
                .is_some_and(|previous| next.key_id == previous.key_id)
        {
            return Err(RetryCookieRotationError::DuplicateKeyId);
        }
        let old = core::mem::replace(&mut self.active, next);
        self.previous = Some(old);
        Ok(())
    }

    /// Drops the previous key only after its acceptance window closes.
    pub fn retire_previous(&mut self, now: u64) -> bool {
        if self
            .previous
            .as_ref()
            .is_some_and(|previous| now >= previous.accept_until)
        {
            self.previous = None;
            true
        } else {
            false
        }
    }

    #[must_use]
    pub const fn active(&self) -> &RetryCookieKey<K> {
        &self.active
    }

    #[must_use]
    pub const fn previous(&self) -> Option<&RetryCookieKey<K>> {
        self.previous.as_ref()
    }

    fn opening_key(&self, key_id: u32) -> Option<&RetryCookieKey<K>> {
        if self.active.key_id == key_id {
            Some(&self.active)
        } else {
            self.previous
                .as_ref()
                .filter(|previous| previous.key_id == key_id)
        }
    }
}

impl<K> fmt::Debug for RetryCookieKeyRing<K> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetryCookieKeyRing")
            .field("active", &self.active)
            .field("previous", &self.previous)
            .finish()
    }
}

/// Key-rotation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryCookieRotationError {
    PreviousKeyStillRequired,
    ActiveKeyStillSealing,
    NextKeyNotActive,
    DuplicateKeyId,
}

impl fmt::Display for RetryCookieRotationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PreviousKeyStillRequired => {
                formatter.write_str("previous RETRY cookie key is still required")
            }
            Self::ActiveKeyStillSealing => {
                formatter.write_str("active RETRY cookie key is still sealing")
            }
            Self::NextKeyNotActive => formatter.write_str("next RETRY cookie key is not active"),
            Self::DuplicateKeyId => formatter.write_str("duplicate RETRY cookie key ID"),
        }
    }
}

impl std::error::Error for RetryCookieRotationError {}

#[derive(Clone, Copy, Eq, PartialEq)]
struct OwnedRetryBinding {
    source_address: RetrySourceAddress,
    source_port: u16,
    version: u32,
    initiator_connection_id: [u8; MAX_LONG_CONNECTION_ID_LEN],
    initiator_connection_id_length: usize,
    responder_connection_id: [u8; MAX_LONG_CONNECTION_ID_LEN],
    responder_connection_id_length: usize,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct RetryAdmissionIdentity {
    binding: OwnedRetryBinding,
    server_random: [u8; RANDOM_LEN],
    hello_hash: Sha384Digest,
}

impl OwnedRetryBinding {
    fn from_borrowed(binding: &RetryCookieBinding<'_>) -> Result<Self, WireError> {
        validate_binding(binding)?;
        let mut owned = Self {
            source_address: binding.source_address,
            source_port: binding.source_port,
            version: binding.version,
            initiator_connection_id: [0; MAX_LONG_CONNECTION_ID_LEN],
            initiator_connection_id_length: binding.initiator_connection_id.len(),
            responder_connection_id: [0; MAX_LONG_CONNECTION_ID_LEN],
            responder_connection_id_length: binding.responder_connection_id.len(),
        };
        owned.initiator_connection_id[..owned.initiator_connection_id_length]
            .copy_from_slice(binding.initiator_connection_id);
        owned.responder_connection_id[..owned.responder_connection_id_length]
            .copy_from_slice(binding.responder_connection_id);
        Ok(owned)
    }
}

/// Capability returned only after successful cookie authentication and binding.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ValidatedRetryCookie {
    key_id: u32,
    issued_at: u64,
    expires_at: u64,
    validated_at: u64,
    identity: RetryAdmissionIdentity,
}

impl ValidatedRetryCookie {
    #[must_use]
    pub const fn key_id(&self) -> u32 {
        self.key_id
    }

    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    #[must_use]
    pub const fn validated_at(&self) -> u64 {
        self.validated_at
    }
}

impl fmt::Debug for ValidatedRetryCookie {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedRetryCookie")
            .field("key_id", &self.key_id)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("validated_at", &self.validated_at)
            .field("identity", &"<redacted>")
            .finish()
    }
}

/// Issues one fixed authenticated cookie into caller-owned storage.
///
/// The active per-key nonce counter is reserved before sealing and is never
/// rolled back after a provider failure.
///
/// # Errors
///
/// Returns an error for invalid binding/output, inactive key schedule, time
/// overflow, exhausted nonce space, lifetime/key-window mismatch, hash/provider
/// failure, or provider output-length mismatch.
pub fn issue_retry_cookie<P: RetryCookieProvider>(
    provider: &P,
    key_ring: &mut RetryCookieKeyRing<P::Key>,
    policy: RetryCookiePolicy,
    binding: &RetryCookieBinding<'_>,
    now: u64,
    output: &mut [u8],
) -> Result<usize, RetryCookieError<P::Error>> {
    if output.len() < RETRY_COOKIE_LEN {
        return Err(WireError::BufferTooSmall {
            needed: RETRY_COOKIE_LEN,
            available: output.len(),
        }
        .into());
    }
    validate_binding(binding)?;
    if binding.source_port == 0 {
        return Err(RetryCookieError::InvalidSourcePort);
    }
    if now < key_ring.active.activate_at || now >= key_ring.active.seal_until {
        return Err(RetryCookieError::ActiveKeyNotUsable);
    }
    let expires_at = now
        .checked_add(policy.lifetime_seconds)
        .ok_or(RetryCookieError::TimeOverflow)?;
    if expires_at > key_ring.active.accept_until {
        return Err(RetryCookieError::LifetimeExceedsKeyWindow);
    }

    let hello_hash = hash_hello(provider, binding.hello)?;
    let mut plaintext = [0_u8; RETRY_COOKIE_PLAINTEXT_LEN];
    encode_plaintext(binding, now, expires_at, &hello_hash, &mut plaintext)?;

    let counter = key_ring.active.next_nonce_counter;
    let next_counter = counter
        .checked_add(1)
        .ok_or(RetryCookieError::NonceExhausted)?;
    key_ring.active.next_nonce_counter = next_counter;
    let mut nonce = [0_u8; RETRY_COOKIE_NONCE_LEN];
    nonce[..8].copy_from_slice(&key_ring.active.nonce_scope);
    nonce[8..].copy_from_slice(&counter.to_be_bytes());

    output[0] = RETRY_COOKIE_FORMAT;
    output[1..5].copy_from_slice(&key_ring.active.key_id.to_be_bytes());
    output[5..RETRY_COOKIE_HEADER_LEN].copy_from_slice(&nonce);
    output[RETRY_COOKIE_HEADER_LEN..RETRY_COOKIE_HEADER_LEN + RETRY_COOKIE_PLAINTEXT_LEN]
        .copy_from_slice(&plaintext);
    plaintext.fill(0);

    let aad = cookie_aad(&output[..RETRY_COOKIE_HEADER_LEN]);
    let sealed = provider.seal_retry_cookie(
        &key_ring.active.key,
        &nonce,
        &aad,
        &mut output[RETRY_COOKIE_HEADER_LEN..RETRY_COOKIE_LEN],
        RETRY_COOKIE_PLAINTEXT_LEN,
    );
    let sealed_length = match sealed {
        Ok(length) => length,
        Err(error) => {
            output[..RETRY_COOKIE_LEN].fill(0);
            return Err(RetryCookieError::Provider(error));
        }
    };
    if sealed_length != RETRY_COOKIE_SEALED_LEN {
        output[..RETRY_COOKIE_LEN].fill(0);
        return Err(RetryCookieError::ProviderLengthMismatch {
            expected: RETRY_COOKIE_SEALED_LEN,
            actual: sealed_length,
        });
    }
    Ok(RETRY_COOKIE_LEN)
}

/// Authenticates, opens, expires, and binds one cookie atomically.
///
/// # Errors
///
/// Returns an error for a malformed/unknown token, unavailable key, invalid
/// tag, non-canonical plaintext, time-policy violation, binding mismatch,
/// provider failure, or provider output-length mismatch.
pub fn validate_retry_cookie<P: RetryCookieProvider>(
    provider: &P,
    key_ring: &RetryCookieKeyRing<P::Key>,
    policy: RetryCookiePolicy,
    binding: &RetryCookieBinding<'_>,
    now: u64,
    cookie: &[u8],
) -> Result<ValidatedRetryCookie, RetryCookieError<P::Error>> {
    validate_binding(binding)?;
    if binding.source_port == 0 {
        return Err(RetryCookieError::InvalidSourcePort);
    }
    if cookie.len() != RETRY_COOKIE_LEN {
        return Err(RetryCookieError::InvalidCookieLength(cookie.len()));
    }
    if cookie[0] != RETRY_COOKIE_FORMAT {
        return Err(RetryCookieError::UnknownFormat(cookie[0]));
    }
    let key_id = u32::from_be_bytes(
        cookie[1..5]
            .try_into()
            .map_err(|_| RetryCookieError::InvalidPlaintext)?,
    );
    let key = key_ring
        .opening_key(key_id)
        .ok_or(RetryCookieError::UnknownKey(key_id))?;
    let nonce: [u8; RETRY_COOKIE_NONCE_LEN] = cookie[5..RETRY_COOKIE_HEADER_LEN]
        .try_into()
        .map_err(|_| RetryCookieError::InvalidPlaintext)?;
    let aad = cookie_aad(&cookie[..RETRY_COOKIE_HEADER_LEN]);
    let mut candidate = [0_u8; RETRY_COOKIE_SEALED_LEN];
    candidate.copy_from_slice(&cookie[RETRY_COOKIE_HEADER_LEN..]);
    let opened = provider.open_retry_cookie(&key.key, &nonce, &aad, &mut candidate);
    let opened_length = match opened {
        Ok(RetryCookieOpenResult::Opened(length)) => length,
        Ok(RetryCookieOpenResult::Invalid) => {
            candidate.fill(0);
            return Err(RetryCookieError::AuthenticationFailed);
        }
        Err(error) => {
            candidate.fill(0);
            return Err(RetryCookieError::Provider(error));
        }
    };
    if opened_length != RETRY_COOKIE_PLAINTEXT_LEN {
        candidate.fill(0);
        return Err(RetryCookieError::ProviderLengthMismatch {
            expected: RETRY_COOKIE_PLAINTEXT_LEN,
            actual: opened_length,
        });
    }
    let result = validate_plaintext(
        provider,
        key_id,
        key,
        policy,
        binding,
        now,
        &candidate[..RETRY_COOKIE_PLAINTEXT_LEN],
    );
    candidate.fill(0);
    result
}

fn validate_plaintext<P: RetryCookieProvider>(
    provider: &P,
    key_id: u32,
    key: &RetryCookieKey<P::Key>,
    policy: RetryCookiePolicy,
    binding: &RetryCookieBinding<'_>,
    now: u64,
    plaintext: &[u8],
) -> Result<ValidatedRetryCookie, RetryCookieError<P::Error>> {
    let issued_at = read_u64(plaintext, ISSUED_AT_OFFSET)?;
    let expires_at = read_u64(plaintext, EXPIRES_AT_OFFSET)?;
    let expected_expiry = issued_at
        .checked_add(policy.lifetime_seconds)
        .ok_or(RetryCookieError::TimeOverflow)?;
    if expires_at != expected_expiry {
        return Err(RetryCookieError::LifetimeMismatch);
    }
    let latest_allowed_issue = now
        .checked_add(policy.maximum_clock_skew_seconds)
        .ok_or(RetryCookieError::TimeOverflow)?;
    if issued_at > latest_allowed_issue {
        return Err(RetryCookieError::NotYetValid);
    }
    if now >= expires_at {
        return Err(RetryCookieError::Expired);
    }
    if issued_at < key.activate_at
        || issued_at >= key.seal_until
        || expires_at > key.accept_until
        || now >= key.accept_until
    {
        return Err(RetryCookieError::KeyOutsideAcceptanceWindow);
    }

    let decoded_binding = decode_owned_binding(plaintext)?;
    let expected_binding = OwnedRetryBinding::from_borrowed(binding)?;
    let client_random: [u8; RANDOM_LEN] = plaintext
        [CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + RANDOM_LEN]
        .try_into()
        .map_err(|_| RetryCookieError::InvalidPlaintext)?;
    let server_random: [u8; RANDOM_LEN] = plaintext
        [SERVER_RANDOM_OFFSET..SERVER_RANDOM_OFFSET + RANDOM_LEN]
        .try_into()
        .map_err(|_| RetryCookieError::InvalidPlaintext)?;
    let received_hello_hash: Sha384Digest = plaintext
        [HELLO_HASH_OFFSET..HELLO_HASH_OFFSET + SHA384_OUTPUT_LEN]
        .try_into()
        .map_err(|_| RetryCookieError::InvalidPlaintext)?;
    let expected_hello_hash = hash_hello(provider, binding.hello)?;
    if decoded_binding != expected_binding
        || client_random != binding.hello.client_random
        || server_random != binding.server_random
        || received_hello_hash != expected_hello_hash
    {
        return Err(RetryCookieError::BindingMismatch);
    }

    Ok(ValidatedRetryCookie {
        key_id,
        issued_at,
        expires_at,
        validated_at: now,
        identity: RetryAdmissionIdentity {
            binding: decoded_binding,
            server_random,
            hello_hash: received_hello_hash,
        },
    })
}

fn hash_hello<P: Sha384Provider>(
    provider: &P,
    hello: Hello,
) -> Result<Sha384Digest, RetryCookieError<P::Error>> {
    let mut encoded = [0_u8; HELLO_LEN];
    hello
        .encode(&mut encoded)
        .map_err(RetryCookieError::Handshake)?;
    let mut context = provider
        .start_sha384()
        .map_err(RetryCookieError::Provider)?;
    context.update(&encoded);
    provider
        .finish_sha384(context)
        .map_err(RetryCookieError::Provider)
}

fn encode_plaintext(
    binding: &RetryCookieBinding<'_>,
    issued_at: u64,
    expires_at: u64,
    hello_hash: &Sha384Digest,
    output: &mut [u8; RETRY_COOKIE_PLAINTEXT_LEN],
) -> Result<(), WireError> {
    let owned = OwnedRetryBinding::from_borrowed(binding)?;
    output[ISSUED_AT_OFFSET..ISSUED_AT_OFFSET + 8].copy_from_slice(&issued_at.to_be_bytes());
    output[EXPIRES_AT_OFFSET..EXPIRES_AT_OFFSET + 8].copy_from_slice(&expires_at.to_be_bytes());
    match binding.source_address {
        RetrySourceAddress::Ipv4(address) => {
            output[ADDRESS_FAMILY_OFFSET] = 4;
            output[ADDRESS_OFFSET..ADDRESS_OFFSET + 4].copy_from_slice(&address);
        }
        RetrySourceAddress::Ipv6(address) => {
            output[ADDRESS_FAMILY_OFFSET] = 6;
            output[ADDRESS_OFFSET..ADDRESS_OFFSET + 16].copy_from_slice(&address);
        }
    }
    output[SOURCE_PORT_OFFSET..SOURCE_PORT_OFFSET + 2]
        .copy_from_slice(&binding.source_port.to_be_bytes());
    output[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&binding.version.to_be_bytes());
    output[INITIATOR_CID_LENGTH_OFFSET] = u8::try_from(owned.initiator_connection_id_length)
        .map_err(|_| WireError::LengthOverflow)?;
    output[INITIATOR_CID_OFFSET..INITIATOR_CID_OFFSET + MAX_LONG_CONNECTION_ID_LEN]
        .copy_from_slice(&owned.initiator_connection_id);
    output[RESPONDER_CID_LENGTH_OFFSET] = u8::try_from(owned.responder_connection_id_length)
        .map_err(|_| WireError::LengthOverflow)?;
    output[RESPONDER_CID_OFFSET..RESPONDER_CID_OFFSET + MAX_LONG_CONNECTION_ID_LEN]
        .copy_from_slice(&owned.responder_connection_id);
    output[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + RANDOM_LEN]
        .copy_from_slice(&binding.hello.client_random);
    output[SERVER_RANDOM_OFFSET..SERVER_RANDOM_OFFSET + RANDOM_LEN]
        .copy_from_slice(&binding.server_random);
    output[HELLO_HASH_OFFSET..HELLO_HASH_OFFSET + SHA384_OUTPUT_LEN].copy_from_slice(hello_hash);
    Ok(())
}

fn decode_owned_binding<E>(plaintext: &[u8]) -> Result<OwnedRetryBinding, RetryCookieError<E>> {
    if plaintext.len() != RETRY_COOKIE_PLAINTEXT_LEN {
        return Err(RetryCookieError::InvalidPlaintext);
    }
    let address = match plaintext[ADDRESS_FAMILY_OFFSET] {
        4 => {
            if plaintext[ADDRESS_OFFSET + 4..ADDRESS_OFFSET + 16]
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(RetryCookieError::InvalidPlaintext);
            }
            RetrySourceAddress::Ipv4(
                plaintext[ADDRESS_OFFSET..ADDRESS_OFFSET + 4]
                    .try_into()
                    .map_err(|_| RetryCookieError::InvalidPlaintext)?,
            )
        }
        6 => RetrySourceAddress::Ipv6(
            plaintext[ADDRESS_OFFSET..ADDRESS_OFFSET + 16]
                .try_into()
                .map_err(|_| RetryCookieError::InvalidPlaintext)?,
        ),
        _ => return Err(RetryCookieError::InvalidPlaintext),
    };
    let initiator_length = usize::from(plaintext[INITIATOR_CID_LENGTH_OFFSET]);
    let responder_length = usize::from(plaintext[RESPONDER_CID_LENGTH_OFFSET]);
    if initiator_length > MAX_LONG_CONNECTION_ID_LEN
        || responder_length > MAX_LONG_CONNECTION_ID_LEN
        || plaintext[INITIATOR_CID_OFFSET + initiator_length
            ..INITIATOR_CID_OFFSET + MAX_LONG_CONNECTION_ID_LEN]
            .iter()
            .any(|byte| *byte != 0)
        || plaintext[RESPONDER_CID_OFFSET + responder_length
            ..RESPONDER_CID_OFFSET + MAX_LONG_CONNECTION_ID_LEN]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(RetryCookieError::InvalidPlaintext);
    }
    let mut initiator_connection_id = [0_u8; MAX_LONG_CONNECTION_ID_LEN];
    initiator_connection_id.copy_from_slice(
        &plaintext[INITIATOR_CID_OFFSET..INITIATOR_CID_OFFSET + MAX_LONG_CONNECTION_ID_LEN],
    );
    let mut responder_connection_id = [0_u8; MAX_LONG_CONNECTION_ID_LEN];
    responder_connection_id.copy_from_slice(
        &plaintext[RESPONDER_CID_OFFSET..RESPONDER_CID_OFFSET + MAX_LONG_CONNECTION_ID_LEN],
    );
    Ok(OwnedRetryBinding {
        source_address: address,
        source_port: u16::from_be_bytes(
            plaintext[SOURCE_PORT_OFFSET..SOURCE_PORT_OFFSET + 2]
                .try_into()
                .map_err(|_| RetryCookieError::InvalidPlaintext)?,
        ),
        version: u32::from_be_bytes(
            plaintext[VERSION_OFFSET..VERSION_OFFSET + 4]
                .try_into()
                .map_err(|_| RetryCookieError::InvalidPlaintext)?,
        ),
        initiator_connection_id,
        initiator_connection_id_length: initiator_length,
        responder_connection_id,
        responder_connection_id_length: responder_length,
    })
}

fn validate_binding(binding: &RetryCookieBinding<'_>) -> Result<(), WireError> {
    for connection_id in [
        binding.initiator_connection_id,
        binding.responder_connection_id,
    ] {
        if connection_id.len() > MAX_LONG_CONNECTION_ID_LEN {
            return Err(WireError::ConnectionIdTooLong {
                length: connection_id.len(),
                maximum: MAX_LONG_CONNECTION_ID_LEN,
            });
        }
    }
    Ok(())
}

fn cookie_aad(header: &[u8]) -> [u8; RETRY_COOKIE_AAD_LEN] {
    let mut aad = [0_u8; RETRY_COOKIE_AAD_LEN];
    aad[..RETRY_COOKIE_AAD_CONTEXT.len()].copy_from_slice(RETRY_COOKIE_AAD_CONTEXT);
    aad[RETRY_COOKIE_AAD_CONTEXT.len()..].copy_from_slice(header);
    aad
}

fn read_u64<E>(input: &[u8], offset: usize) -> Result<u64, RetryCookieError<E>> {
    let end = offset
        .checked_add(8)
        .ok_or(RetryCookieError::InvalidPlaintext)?;
    Ok(u64::from_be_bytes(
        input
            .get(offset..end)
            .ok_or(RetryCookieError::InvalidPlaintext)?
            .try_into()
            .map_err(|_| RetryCookieError::InvalidPlaintext)?,
    ))
}

/// Cookie issuance or validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetryCookieError<E> {
    Wire(WireError),
    Handshake(crate::handshake::HandshakeError),
    Provider(E),
    ActiveKeyNotUsable,
    LifetimeExceedsKeyWindow,
    TimeOverflow,
    NonceExhausted,
    InvalidCookieLength(usize),
    UnknownFormat(u8),
    UnknownKey(u32),
    AuthenticationFailed,
    ProviderLengthMismatch { expected: usize, actual: usize },
    InvalidPlaintext,
    LifetimeMismatch,
    NotYetValid,
    Expired,
    KeyOutsideAcceptanceWindow,
    BindingMismatch,
    InvalidSourcePort,
}

impl<E> From<WireError> for RetryCookieError<E> {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl<E: fmt::Display> fmt::Display for RetryCookieError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => error.fmt(formatter),
            Self::Handshake(error) => error.fmt(formatter),
            Self::Provider(error) => write!(formatter, "RETRY cookie provider failure: {error}"),
            Self::ActiveKeyNotUsable => formatter.write_str("active RETRY cookie key not usable"),
            Self::LifetimeExceedsKeyWindow => {
                formatter.write_str("RETRY cookie lifetime exceeds key acceptance window")
            }
            Self::TimeOverflow => formatter.write_str("RETRY cookie timestamp overflow"),
            Self::NonceExhausted => formatter.write_str("RETRY cookie nonce space exhausted"),
            Self::InvalidCookieLength(length) => {
                write!(formatter, "invalid RETRY cookie length {length}")
            }
            Self::UnknownFormat(format) => {
                write!(formatter, "unknown RETRY cookie format {format}")
            }
            Self::UnknownKey(key_id) => write!(formatter, "unknown RETRY cookie key {key_id}"),
            Self::AuthenticationFailed => formatter.write_str("RETRY cookie authentication failed"),
            Self::ProviderLengthMismatch { expected, actual } => write!(
                formatter,
                "RETRY cookie provider length mismatch: expected {expected}, got {actual}"
            ),
            Self::InvalidPlaintext => formatter.write_str("invalid RETRY cookie plaintext"),
            Self::LifetimeMismatch => formatter.write_str("RETRY cookie lifetime mismatch"),
            Self::NotYetValid => formatter.write_str("RETRY cookie issued in the future"),
            Self::Expired => formatter.write_str("RETRY cookie expired"),
            Self::KeyOutsideAcceptanceWindow => {
                formatter.write_str("RETRY cookie key outside acceptance window")
            }
            Self::BindingMismatch => formatter.write_str("RETRY cookie binding mismatch"),
            Self::InvalidSourcePort => formatter.write_str("invalid zero UDP source port"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for RetryCookieError<E> {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdmissionSource {
    Ipv4([u8; 4]),
    Ipv6Prefix64([u8; 8]),
}

impl From<RetrySourceAddress> for AdmissionSource {
    fn from(address: RetrySourceAddress) -> Self {
        match address {
            RetrySourceAddress::Ipv4(value) => Self::Ipv4(value),
            RetrySourceAddress::Ipv6(value) => {
                Self::Ipv6Prefix64(value[..8].try_into().expect("fixed IPv6 prefix"))
            }
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct HandshakeAdmissionSlot {
    occupied: bool,
    generation: u64,
    deadline: u64,
    source: AdmissionSource,
    identity: RetryAdmissionIdentity,
}

impl HandshakeAdmissionSlot {
    const fn empty() -> Self {
        Self {
            occupied: false,
            generation: 0,
            deadline: 0,
            source: AdmissionSource::Ipv4([0; 4]),
            identity: RetryAdmissionIdentity {
                binding: OwnedRetryBinding {
                    source_address: RetrySourceAddress::Ipv4([0; 4]),
                    source_port: 0,
                    version: 0,
                    initiator_connection_id: [0; MAX_LONG_CONNECTION_ID_LEN],
                    initiator_connection_id_length: 0,
                    responder_connection_id: [0; MAX_LONG_CONNECTION_ID_LEN],
                    responder_connection_id_length: 0,
                },
                server_random: [0; RANDOM_LEN],
                hello_hash: [0; SHA384_OUTPUT_LEN],
            },
        }
    }

    fn clear(&mut self) {
        *self = Self::empty();
    }
}

/// Opaque fixed-table lease required to allocate an `INIT` reassembly slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandshakeAdmissionLease {
    slot: usize,
    generation: u64,
}

impl HandshakeAdmissionLease {
    #[cfg(test)]
    pub(crate) const fn for_test() -> Self {
        Self {
            slot: 0,
            generation: 1,
        }
    }
}

/// Idempotent result of post-cookie handshake admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeAdmissionStatus {
    New(HandshakeAdmissionLease),
    Existing(HandshakeAdmissionLease),
}

impl HandshakeAdmissionStatus {
    #[must_use]
    pub const fn lease(self) -> HandshakeAdmissionLease {
        match self {
            Self::New(lease) | Self::Existing(lease) => lease,
        }
    }
}

/// Fixed global and normalized-source post-cookie admission table.
///
/// IPv4 addresses are counted exactly. IPv6 addresses sharing the same /64
/// prefix share one quota. Identical endpoint/version/CID bindings are
/// idempotent and return the existing lease.
pub struct HandshakeAdmissionTable<const SLOTS: usize> {
    slots: [HandshakeAdmissionSlot; SLOTS],
    per_source_limit: usize,
    handshake_timeout_seconds: u64,
    next_generation: u64,
}

impl<const SLOTS: usize> HandshakeAdmissionTable<SLOTS> {
    /// Creates one fixed-capacity post-cookie admission table.
    ///
    /// # Errors
    ///
    /// Returns an error for zero slots, zero per-source capacity, a source
    /// limit greater than global capacity, or a zero timeout.
    pub fn new(
        per_source_limit: usize,
        handshake_timeout_seconds: u64,
    ) -> Result<Self, HandshakeAdmissionError> {
        if SLOTS == 0
            || per_source_limit == 0
            || per_source_limit > SLOTS
            || handshake_timeout_seconds == 0
        {
            return Err(HandshakeAdmissionError::InvalidConfiguration);
        }
        Ok(Self {
            slots: core::array::from_fn(|_| HandshakeAdmissionSlot::empty()),
            per_source_limit,
            handshake_timeout_seconds,
            next_generation: 1,
        })
    }

    /// Admits one validated cookie under global/source quotas.
    ///
    /// Expired entries are swept first. Replaying the same valid cookie binding
    /// returns its existing lease without consuming capacity.
    ///
    /// # Errors
    ///
    /// Returns an error for an expired capability, quota/capacity exhaustion,
    /// deadline overflow, or generation exhaustion.
    pub fn admit(
        &mut self,
        cookie: &ValidatedRetryCookie,
        now: u64,
    ) -> Result<HandshakeAdmissionStatus, HandshakeAdmissionError> {
        self.expire(now);
        if now < cookie.validated_at {
            return Err(HandshakeAdmissionError::ClockMovedBackwards);
        }
        if now >= cookie.expires_at {
            return Err(HandshakeAdmissionError::CookieExpired);
        }
        if let Some((index, slot)) = self
            .slots
            .iter()
            .enumerate()
            .find(|(_, slot)| slot.occupied && slot.identity == cookie.identity)
        {
            return Ok(HandshakeAdmissionStatus::Existing(
                HandshakeAdmissionLease {
                    slot: index,
                    generation: slot.generation,
                },
            ));
        }
        let source = AdmissionSource::from(cookie.identity.binding.source_address);
        let source_count = self
            .slots
            .iter()
            .filter(|slot| slot.occupied && slot.source == source)
            .count();
        if source_count >= self.per_source_limit {
            return Err(HandshakeAdmissionError::PerSourceLimitReached);
        }
        let index = self
            .slots
            .iter()
            .position(|slot| !slot.occupied)
            .ok_or(HandshakeAdmissionError::PoolExhausted)?;
        let deadline = now
            .checked_add(self.handshake_timeout_seconds)
            .ok_or(HandshakeAdmissionError::DeadlineOverflow)?;
        let generation = self.next_generation;
        let next_generation = generation
            .checked_add(1)
            .ok_or(HandshakeAdmissionError::GenerationExhausted)?;
        self.slots[index] = HandshakeAdmissionSlot {
            occupied: true,
            generation,
            deadline,
            source,
            identity: cookie.identity,
        };
        self.next_generation = next_generation;
        Ok(HandshakeAdmissionStatus::New(HandshakeAdmissionLease {
            slot: index,
            generation,
        }))
    }

    /// Releases an exact live generation. Stale or duplicate releases do
    /// nothing.
    pub fn release(&mut self, lease: HandshakeAdmissionLease) -> bool {
        let Some(slot) = self.slots.get_mut(lease.slot) else {
            return false;
        };
        if !slot.occupied || slot.generation != lease.generation {
            return false;
        }
        slot.clear();
        true
    }

    /// Sweeps all deadlines at or before `now` and returns the released count.
    pub fn expire(&mut self, now: u64) -> usize {
        let mut released = 0;
        for slot in &mut self.slots {
            if slot.occupied && now >= slot.deadline {
                slot.clear();
                released += 1;
            }
        }
        released
    }

    #[must_use]
    pub fn active(&self) -> usize {
        self.slots.iter().filter(|slot| slot.occupied).count()
    }
}

impl<const SLOTS: usize> fmt::Debug for HandshakeAdmissionTable<SLOTS> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandshakeAdmissionTable")
            .field("slots", &"<redacted>")
            .field("capacity", &SLOTS)
            .field("active", &self.active())
            .field("per_source_limit", &self.per_source_limit)
            .field("handshake_timeout_seconds", &self.handshake_timeout_seconds)
            .field("next_generation", &"<redacted>")
            .finish()
    }
}

/// Post-cookie admission failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeAdmissionError {
    InvalidConfiguration,
    ClockMovedBackwards,
    CookieExpired,
    PerSourceLimitReached,
    PoolExhausted,
    DeadlineOverflow,
    GenerationExhausted,
}

impl fmt::Display for HandshakeAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => {
                formatter.write_str("invalid handshake admission configuration")
            }
            Self::ClockMovedBackwards => {
                formatter.write_str("clock moved backwards after RETRY cookie validation")
            }
            Self::CookieExpired => formatter.write_str("validated RETRY cookie expired"),
            Self::PerSourceLimitReached => {
                formatter.write_str("per-source handshake admission limit reached")
            }
            Self::PoolExhausted => formatter.write_str("global handshake admission pool exhausted"),
            Self::DeadlineOverflow => formatter.write_str("handshake deadline overflow"),
            Self::GenerationExhausted => {
                formatter.write_str("handshake admission generation exhausted")
            }
        }
    }
}

impl std::error::Error for HandshakeAdmissionError {}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use sha2::{Digest, Sha384};

    use super::*;
    use crate::handshake::{
        CAPABILITY_MULTIPATH_BIT, CIPHER_SUITE_AES_256_GCM_SHA384_BIT, IDENTITY_FINGERPRINT_LEN,
    };

    #[derive(Clone)]
    struct Sha384Context(Sha384);

    impl TranscriptSink for Sha384Context {
        fn update(&mut self, bytes: &[u8]) {
            self.0.update(bytes);
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TestProviderError;

    impl fmt::Display for TestProviderError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("test provider failure")
        }
    }

    impl std::error::Error for TestProviderError {}

    #[derive(Default)]
    struct TestProvider {
        fail_seal: Cell<bool>,
        fail_open: Cell<bool>,
        wrong_seal_length: Cell<bool>,
        wrong_open_length: Cell<bool>,
    }

    impl Sha384Provider for TestProvider {
        type Context = Sha384Context;
        type Error = TestProviderError;

        fn start_sha384(&self) -> Result<Self::Context, Self::Error> {
            Ok(Sha384Context(Sha384::new()))
        }

        fn finish_sha384(&self, context: Self::Context) -> Result<Sha384Digest, Self::Error> {
            Ok(context.0.finalize().into())
        }
    }

    impl RetryCookieProvider for TestProvider {
        type Key = [u8; 32];

        fn seal_retry_cookie(
            &self,
            key: &Self::Key,
            nonce: &[u8; RETRY_COOKIE_NONCE_LEN],
            additional_data: &[u8],
            plaintext_and_tag: &mut [u8],
            plaintext_length: usize,
        ) -> Result<usize, Self::Error> {
            if self.fail_seal.replace(false) {
                return Err(TestProviderError);
            }
            for (index, byte) in plaintext_and_tag[..plaintext_length].iter_mut().enumerate() {
                *byte ^= key[index % key.len()] ^ nonce[index % nonce.len()];
            }
            let tag = test_tag(
                key,
                nonce,
                additional_data,
                &plaintext_and_tag[..plaintext_length],
            );
            plaintext_and_tag[plaintext_length..plaintext_length + AEAD_TAG_LEN]
                .copy_from_slice(&tag);
            if self.wrong_seal_length.replace(false) {
                Ok(plaintext_length)
            } else {
                Ok(plaintext_length + AEAD_TAG_LEN)
            }
        }

        fn open_retry_cookie(
            &self,
            key: &Self::Key,
            nonce: &[u8; RETRY_COOKIE_NONCE_LEN],
            additional_data: &[u8],
            ciphertext_and_tag: &mut [u8],
        ) -> Result<RetryCookieOpenResult, Self::Error> {
            if self.fail_open.replace(false) {
                return Err(TestProviderError);
            }
            let Some(plaintext_length) = ciphertext_and_tag.len().checked_sub(AEAD_TAG_LEN) else {
                return Ok(RetryCookieOpenResult::Invalid);
            };
            let expected = test_tag(
                key,
                nonce,
                additional_data,
                &ciphertext_and_tag[..plaintext_length],
            );
            let mut difference = 0_u8;
            for (left, right) in ciphertext_and_tag[plaintext_length..].iter().zip(expected) {
                difference |= *left ^ right;
            }
            if difference != 0 {
                return Ok(RetryCookieOpenResult::Invalid);
            }
            for (index, byte) in ciphertext_and_tag[..plaintext_length]
                .iter_mut()
                .enumerate()
            {
                *byte ^= key[index % key.len()] ^ nonce[index % nonce.len()];
            }
            if self.wrong_open_length.replace(false) {
                Ok(RetryCookieOpenResult::Opened(plaintext_length - 1))
            } else {
                Ok(RetryCookieOpenResult::Opened(plaintext_length))
            }
        }
    }

    fn test_tag(
        key: &[u8; 32],
        nonce: &[u8; RETRY_COOKIE_NONCE_LEN],
        additional_data: &[u8],
        ciphertext: &[u8],
    ) -> [u8; AEAD_TAG_LEN] {
        let mut hash = Sha384::new();
        hash.update(key);
        hash.update(nonce);
        hash.update(additional_data);
        hash.update(ciphertext);
        let digest = hash.finalize();
        digest[..AEAD_TAG_LEN].try_into().expect("fixed tag")
    }

    fn hello(seed: u8) -> Hello {
        Hello {
            client_random: [seed; RANDOM_LEN],
            identity_fingerprint: [seed.wrapping_add(1); IDENTITY_FINGERPRINT_LEN],
            cipher_suite_bitmap: CIPHER_SUITE_AES_256_GCM_SHA384_BIT,
            capabilities: CAPABILITY_MULTIPATH_BIT,
            max_udp_payload: 1_400,
            max_paths: 2,
        }
    }

    fn binding(seed: u8) -> RetryCookieBinding<'static> {
        RetryCookieBinding {
            source_address: RetrySourceAddress::Ipv4([192, 0, 2, seed]),
            source_port: 40_000 + u16::from(seed),
            version: 1,
            initiator_connection_id: b"initiator-cid",
            responder_connection_id: b"responder-cid",
            hello: hello(seed),
            server_random: [seed.wrapping_add(2); RANDOM_LEN],
        }
    }

    fn key(
        key_id: u32,
        key_byte: u8,
        activate_at: u64,
        seal_until: u64,
        accept_until: u64,
    ) -> RetryCookieKey<[u8; 32]> {
        RetryCookieKey::new(
            key_id,
            [key_byte; 32],
            u64::from(key_id).to_be_bytes(),
            activate_at,
            seal_until,
            accept_until,
        )
        .expect("valid test key")
    }

    fn issue_and_validate(
        provider: &TestProvider,
        ring: &mut RetryCookieKeyRing<[u8; 32]>,
        policy: RetryCookiePolicy,
        binding: &RetryCookieBinding<'_>,
        now: u64,
    ) -> ([u8; RETRY_COOKIE_LEN], ValidatedRetryCookie) {
        let mut cookie = [0_u8; RETRY_COOKIE_LEN];
        assert_eq!(
            issue_retry_cookie(provider, ring, policy, binding, now, &mut cookie),
            Ok(RETRY_COOKIE_LEN)
        );
        let validated = validate_retry_cookie(provider, ring, policy, binding, now, &cookie)
            .expect("cookie validates");
        (cookie, validated)
    }

    #[test]
    fn cookie_round_trip_binds_every_context_and_redacts_debug() {
        let provider = TestProvider::default();
        let policy = RetryCookiePolicy::new(30, 2).expect("valid policy");
        let mut ring = RetryCookieKeyRing::new(key(7, 0x55, 100, 200, 240));
        let expected = binding(1);
        let (cookie, validated) = issue_and_validate(&provider, &mut ring, policy, &expected, 110);
        assert_eq!(cookie.len(), RETRY_COOKIE_LEN);
        assert_eq!(validated.key_id(), 7);
        assert_eq!(validated.issued_at(), 110);
        assert_eq!(validated.expires_at(), 140);
        assert_eq!(validated.validated_at(), 110);

        let mut wrong_address = expected;
        wrong_address.source_address = RetrySourceAddress::Ipv4([198, 51, 100, 1]);
        assert_eq!(
            validate_retry_cookie(&provider, &ring, policy, &wrong_address, 111, &cookie),
            Err(RetryCookieError::BindingMismatch)
        );
        let mut wrong_hello = expected;
        wrong_hello.hello.capabilities = 0;
        assert_eq!(
            validate_retry_cookie(&provider, &ring, policy, &wrong_hello, 111, &cookie),
            Err(RetryCookieError::BindingMismatch)
        );
        let debug = format!("{validated:?} {ring:?} {expected:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("192, 0, 2"));
        assert!(!debug.contains("85, 85"));
    }

    #[test]
    fn tampering_expiry_future_time_and_policy_changes_fail_closed() {
        let provider = TestProvider::default();
        let policy = RetryCookiePolicy::new(30, 2).expect("valid policy");
        let mut ring = RetryCookieKeyRing::new(key(7, 0x55, 100, 200, 240));
        let expected = binding(1);
        let (mut cookie, _) = issue_and_validate(&provider, &mut ring, policy, &expected, 110);
        cookie[80] ^= 1;
        assert_eq!(
            validate_retry_cookie(&provider, &ring, policy, &expected, 111, &cookie),
            Err(RetryCookieError::AuthenticationFailed)
        );

        let (cookie, _) = issue_and_validate(&provider, &mut ring, policy, &expected, 110);
        assert_eq!(
            validate_retry_cookie(&provider, &ring, policy, &expected, 107, &cookie),
            Err(RetryCookieError::NotYetValid)
        );
        assert_eq!(
            validate_retry_cookie(&provider, &ring, policy, &expected, 140, &cookie),
            Err(RetryCookieError::Expired)
        );
        let changed_policy = RetryCookiePolicy::new(31, 2).expect("valid policy");
        assert_eq!(
            validate_retry_cookie(&provider, &ring, changed_policy, &expected, 111, &cookie,),
            Err(RetryCookieError::LifetimeMismatch)
        );
    }

    #[test]
    fn nonce_reservation_survives_provider_failure_and_lengths_are_enforced() {
        let provider = TestProvider::default();
        let policy = RetryCookiePolicy::new(20, 1).expect("valid policy");
        let mut ring = RetryCookieKeyRing::new(key(9, 0x44, 100, 200, 230));
        let expected = binding(2);
        let mut failed = [0xa5; RETRY_COOKIE_LEN];
        provider.fail_seal.set(true);
        assert_eq!(
            issue_retry_cookie(&provider, &mut ring, policy, &expected, 110, &mut failed),
            Err(RetryCookieError::Provider(TestProviderError))
        );
        assert!(failed.iter().all(|byte| *byte == 0));

        let (cookie, _) = issue_and_validate(&provider, &mut ring, policy, &expected, 110);
        assert_eq!(&cookie[13..17], &1_u32.to_be_bytes());

        provider.wrong_seal_length.set(true);
        let mut malformed = [0xa5; RETRY_COOKIE_LEN];
        assert_eq!(
            issue_retry_cookie(&provider, &mut ring, policy, &expected, 111, &mut malformed,),
            Err(RetryCookieError::ProviderLengthMismatch {
                expected: RETRY_COOKIE_SEALED_LEN,
                actual: RETRY_COOKIE_PLAINTEXT_LEN,
            })
        );
        assert!(malformed.iter().all(|byte| *byte == 0));

        provider.wrong_open_length.set(true);
        assert_eq!(
            validate_retry_cookie(&provider, &ring, policy, &expected, 111, &cookie),
            Err(RetryCookieError::ProviderLengthMismatch {
                expected: RETRY_COOKIE_PLAINTEXT_LEN,
                actual: RETRY_COOKIE_PLAINTEXT_LEN - 1,
            })
        );
    }

    #[test]
    fn rotation_retains_exactly_one_validation_generation() {
        let provider = TestProvider::default();
        let policy = RetryCookiePolicy::new(20, 1).expect("valid policy");
        let mut ring = RetryCookieKeyRing::new(key(1, 0x11, 100, 150, 180));
        let expected = binding(3);
        let (old_cookie, _) = issue_and_validate(&provider, &mut ring, policy, &expected, 139);
        assert_eq!(
            ring.rotate(key(2, 0x22, 150, 200, 230), 149),
            Err(RetryCookieRotationError::ActiveKeyStillSealing)
        );
        ring.rotate(key(2, 0x22, 150, 200, 230), 150)
            .expect("rotation succeeds");
        assert_eq!(ring.active().key_id(), 2);
        assert_eq!(ring.previous().map(RetryCookieKey::key_id), Some(1));
        validate_retry_cookie(&provider, &ring, policy, &expected, 155, &old_cookie)
            .expect("previous generation validates");
        assert_eq!(
            ring.rotate(key(3, 0x33, 170, 220, 250), 170),
            Err(RetryCookieRotationError::PreviousKeyStillRequired)
        );
        ring.rotate(key(3, 0x33, 200, 250, 280), 200)
            .expect("expired oldest generation is replaced");
        assert_eq!(ring.active().key_id(), 3);
        assert_eq!(ring.previous().map(RetryCookieKey::key_id), Some(2));
    }

    fn admission_cookie(
        address: RetrySourceAddress,
        port: u16,
        cid_seed: u8,
        context_seed: u8,
        expires_at: u64,
    ) -> ValidatedRetryCookie {
        let mut initiator_connection_id = [0_u8; MAX_LONG_CONNECTION_ID_LEN];
        initiator_connection_id[0] = cid_seed;
        ValidatedRetryCookie {
            key_id: 1,
            issued_at: 100,
            expires_at,
            validated_at: 100,
            identity: RetryAdmissionIdentity {
                binding: OwnedRetryBinding {
                    source_address: address,
                    source_port: port,
                    version: 1,
                    initiator_connection_id,
                    initiator_connection_id_length: 1,
                    responder_connection_id: [0x55; MAX_LONG_CONNECTION_ID_LEN],
                    responder_connection_id_length: 8,
                },
                server_random: [context_seed; RANDOM_LEN],
                hello_hash: [context_seed; SHA384_OUTPUT_LEN],
            },
        }
    }

    #[test]
    fn admission_is_fixed_idempotent_quota_limited_and_expiring() {
        let mut table = HandshakeAdmissionTable::<2>::new(1, 10).expect("valid table");
        let first = admission_cookie(RetrySourceAddress::Ipv4([192, 0, 2, 1]), 40_001, 1, 1, 200);
        let first_lease = match table.admit(&first, 110).expect("first admission") {
            HandshakeAdmissionStatus::New(lease) => lease,
            HandshakeAdmissionStatus::Existing(_) => panic!("new admission expected"),
        };
        assert_eq!(
            table.admit(&first, 111),
            Ok(HandshakeAdmissionStatus::Existing(first_lease))
        );
        let same_source =
            admission_cookie(RetrySourceAddress::Ipv4([192, 0, 2, 1]), 40_002, 2, 2, 200);
        assert_eq!(
            table.admit(&same_source, 111),
            Err(HandshakeAdmissionError::PerSourceLimitReached)
        );
        let second = admission_cookie(RetrySourceAddress::Ipv4([192, 0, 2, 2]), 40_003, 3, 3, 200);
        table.admit(&second, 111).expect("second source");
        let third = admission_cookie(RetrySourceAddress::Ipv4([192, 0, 2, 3]), 40_004, 4, 4, 200);
        assert_eq!(
            table.admit(&third, 111),
            Err(HandshakeAdmissionError::PoolExhausted)
        );
        assert_eq!(table.active(), 2);
        assert!(table.release(first_lease));
        assert!(!table.release(first_lease));
        assert_eq!(table.active(), 1);
        assert_eq!(table.expire(121), 1);
        assert_eq!(table.active(), 0);
        let debug = format!("{table:?}");
        assert!(debug.contains("slots: \"<redacted>\""));
    }

    #[test]
    fn ipv6_uses_prefix_quota_and_handshake_context_prevents_false_deduplication() {
        let mut table = HandshakeAdmissionTable::<3>::new(1, 10).expect("valid table");
        let first = admission_cookie(
            RetrySourceAddress::Ipv6([0x20, 1, 0x0d, 0xb8, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1]),
            40_001,
            1,
            1,
            200,
        );
        table.admit(&first, 110).expect("first prefix admission");
        let same_prefix = admission_cookie(
            RetrySourceAddress::Ipv6([0x20, 1, 0x0d, 0xb8, 0, 1, 0, 1, 0xff, 0, 0, 0, 0, 0, 0, 2]),
            40_002,
            2,
            2,
            200,
        );
        assert_eq!(
            table.admit(&same_prefix, 111),
            Err(HandshakeAdmissionError::PerSourceLimitReached)
        );

        let mut same_cids_new_context = first;
        same_cids_new_context.identity.server_random = [9; RANDOM_LEN];
        assert_eq!(
            table.admit(&same_cids_new_context, 111),
            Err(HandshakeAdmissionError::PerSourceLimitReached)
        );
    }

    #[test]
    fn invalid_configuration_and_expired_capability_are_rejected() {
        assert!(matches!(
            HandshakeAdmissionTable::<0>::new(1, 10),
            Err(HandshakeAdmissionError::InvalidConfiguration)
        ));
        assert_eq!(
            RetryCookiePolicy::new(0, 0),
            Err(RetryCookiePolicyError::ZeroLifetime)
        );
        assert!(matches!(
            RetryCookieKey::new(1, [0_u8; 32], [0; 8], 10, 10, 20),
            Err(RetryCookieKeyError::InvalidSchedule)
        ));
        let mut table = HandshakeAdmissionTable::<1>::new(1, 10).expect("valid table");
        let expired = admission_cookie(RetrySourceAddress::Ipv4([192, 0, 2, 1]), 40_001, 1, 1, 110);
        assert_eq!(
            table.admit(&expired, 99),
            Err(HandshakeAdmissionError::ClockMovedBackwards)
        );
        assert_eq!(
            table.admit(&expired, 110),
            Err(HandshakeAdmissionError::CookieExpired)
        );
    }

    #[test]
    fn one_maximum_retry_stays_below_three_times_the_smallest_hello() {
        assert_eq!(MIN_HELLO_DATAGRAM_LEN, 107);
        assert_eq!(MAX_RETRY_DATAGRAM_LEN, 317);
    }
}
