//! Fail-closed hybrid identity and manifest authentication orchestration.

use core::fmt;

use crate::crypto::{SHA384_OUTPUT_LEN, Sha384Digest, Sha384Provider};
use crate::handshake::{
    ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN, FINISHED_MAC_LEN, IDENTITY_FINGERPRINT_LEN,
    IdentityAuth, ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN,
};
use crate::manifest::{Manifest, ManifestHeader, feed_manifest_signature_input};
use crate::transcript::{AuthenticationRole, TranscriptSink, feed_signature_input};

/// Domain separator for an OGTP identity fingerprint.
pub const IDENTITY_FINGERPRINT_CONTEXT: &[u8] = b"OGTP/1 identity\x00";

/// Maximum encoded size of one OGTP contextualized signature message.
pub const MAX_CONTEXTUALIZED_SIGNATURE_INPUT_LEN: usize = 192;

/// Result of a provider verification operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationResult {
    Valid,
    Invalid,
}

/// Standardized verification operations required by OGTP authentication.
///
/// Ed25519 verification uses ordinary Ed25519, not Ed25519ph. ML-DSA-65 uses
/// its ordinary signing mode. HMAC comparison must be constant-time with
/// respect to the expected and received MAC values.
pub trait HybridAuthenticationProvider: Sha384Provider {
    type VerificationError;

    /// Verifies `HMAC-SHA-384(key, transcript_hash)`.
    ///
    /// # Errors
    ///
    /// Returns a provider-specific failure distinct from an invalid MAC.
    fn verify_hmac_sha384(
        &self,
        key: &[u8; FINISHED_MAC_LEN],
        transcript_hash: &[u8; SHA384_OUTPUT_LEN],
        received_mac: &[u8; FINISHED_MAC_LEN],
    ) -> Result<VerificationResult, Self::VerificationError>;

    /// Verifies an ordinary Ed25519 signature over the exact message bytes.
    ///
    /// # Errors
    ///
    /// Returns a provider-specific failure distinct from an invalid signature.
    fn verify_ed25519(
        &self,
        public_key: &[u8; ED25519_PUBLIC_KEY_LEN],
        message: &[u8],
        signature: &[u8; ED25519_SIGNATURE_LEN],
    ) -> Result<VerificationResult, Self::VerificationError>;

    /// Verifies an ordinary ML-DSA-65 signature over the exact message bytes.
    ///
    /// The codec has already enforced the fixed public-key and signature
    /// lengths before this method is called.
    ///
    /// # Errors
    ///
    /// Returns a provider-specific failure distinct from an invalid signature.
    fn verify_ml_dsa_65(
        &self,
        public_key: &[u8; ML_DSA_65_PUBLIC_KEY_LEN],
        message: &[u8],
        signature: &[u8; ML_DSA_65_SIGNATURE_LEN],
    ) -> Result<VerificationResult, Self::VerificationError>;
}

/// Fixed-size peer identity installed only after fingerprint, Finished, and
/// both signature checks succeed.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedIdentity {
    fingerprint: [u8; IDENTITY_FINGERPRINT_LEN],
    ed25519_public_key: [u8; ED25519_PUBLIC_KEY_LEN],
    ml_dsa_65_public_key: [u8; ML_DSA_65_PUBLIC_KEY_LEN],
}

impl AuthenticatedIdentity {
    /// Returns the trust-anchor-bound identity fingerprint.
    #[must_use]
    pub const fn fingerprint(&self) -> &[u8; IDENTITY_FINGERPRINT_LEN] {
        &self.fingerprint
    }

    /// Returns the authenticated Ed25519 public key.
    #[must_use]
    pub const fn ed25519_public_key(&self) -> &[u8; ED25519_PUBLIC_KEY_LEN] {
        &self.ed25519_public_key
    }

    /// Returns the authenticated ML-DSA-65 public key.
    #[must_use]
    pub const fn ml_dsa_65_public_key(&self) -> &[u8; ML_DSA_65_PUBLIC_KEY_LEN] {
        &self.ml_dsa_65_public_key
    }

    #[cfg(test)]
    pub(crate) const fn for_test() -> Self {
        Self {
            fingerprint: [0; IDENTITY_FINGERPRINT_LEN],
            ed25519_public_key: [0; ED25519_PUBLIC_KEY_LEN],
            ml_dsa_65_public_key: [0; ML_DSA_65_PUBLIC_KEY_LEN],
        }
    }
}

impl fmt::Debug for AuthenticatedIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedIdentity")
            .field("key_material", &"<redacted>")
            .finish()
    }
}

/// Capability token proving that both manifest signatures matched one
/// authenticated peer identity.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct VerifiedManifest {
    header: ManifestHeader,
}

impl VerifiedManifest {
    /// Returns the verified signed object geometry.
    #[must_use]
    pub const fn header(&self) -> ManifestHeader {
        self.header
    }
}

impl fmt::Debug for VerifiedManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedManifest")
            .field("object_size", &self.header.object_size)
            .field("chunk_size", &self.header.chunk_size)
            .field("chunk_count", &self.header.chunk_count)
            .field("identifiers_and_root", &"<redacted>")
            .finish()
    }
}

/// Borrowed transcript, Finished, and trust inputs for one peer-authentication
/// decision.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PeerAuthenticationContext<'a> {
    pub role: AuthenticationRole,
    pub signature_transcript_hash: &'a [u8; SHA384_OUTPUT_LEN],
    pub finished_transcript_hash: &'a [u8; SHA384_OUTPUT_LEN],
    pub finished_key: &'a [u8; FINISHED_MAC_LEN],
    pub announced_fingerprint: &'a [u8; IDENTITY_FINGERPRINT_LEN],
    pub trust_anchor_fingerprint: &'a [u8; IDENTITY_FINGERPRINT_LEN],
}

impl fmt::Debug for PeerAuthenticationContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerAuthenticationContext")
            .field("role", &self.role)
            .field(
                "transcript_hashes_finished_key_and_fingerprints",
                &"<redacted>",
            )
            .finish()
    }
}

/// Authenticates one decrypted handshake identity block atomically.
///
/// The cheap fingerprint checks run first, followed by Finished HMAC, Ed25519,
/// and ML-DSA-65. No key material is returned unless every check succeeds.
/// `signature_transcript_hash` and `finished_transcript_hash` must be the named
/// transcript snapshots defined in `CRYPTO.md` for `role`.
///
/// # Errors
///
/// Returns a mismatch, invalid authenticator, fixed-input overflow, invariant
/// failure, or provider-specific hashing/verification error.
pub fn authenticate_peer_identity<P: HybridAuthenticationProvider>(
    provider: &P,
    authentication: PeerAuthenticationContext<'_>,
    identity_auth: &IdentityAuth<'_>,
) -> Result<AuthenticatedIdentity, AuthenticationError<P::Error, P::VerificationError>> {
    let ml_dsa_65_public_key = identity_auth
        .ml_dsa_public_key
        .try_into()
        .map_err(|_| AuthenticationError::CodecInvariantViolation)?;
    let ml_dsa_65_signature = identity_auth
        .ml_dsa_signature
        .try_into()
        .map_err(|_| AuthenticationError::CodecInvariantViolation)?;
    let computed_fingerprint = compute_identity_fingerprint(
        provider,
        &identity_auth.ed25519_public_key,
        ml_dsa_65_public_key,
    )
    .map_err(AuthenticationError::HashProvider)?;
    if !fingerprints_equal(&computed_fingerprint, authentication.announced_fingerprint) {
        return Err(AuthenticationError::AnnouncedFingerprintMismatch);
    }
    if !fingerprints_equal(
        &computed_fingerprint,
        authentication.trust_anchor_fingerprint,
    ) {
        return Err(AuthenticationError::TrustAnchorMismatch);
    }

    require_valid(
        provider
            .verify_hmac_sha384(
                authentication.finished_key,
                authentication.finished_transcript_hash,
                &identity_auth.finished_mac,
            )
            .map_err(AuthenticationError::VerificationProvider)?,
        AuthenticationError::InvalidFinishedMac,
    )?;

    let signature_input = handshake_signature_input(
        authentication.role,
        authentication.signature_transcript_hash,
    )
    .ok_or(AuthenticationError::SignatureInputOverflow)?;
    require_valid(
        provider
            .verify_ed25519(
                &identity_auth.ed25519_public_key,
                signature_input.as_slice(),
                &identity_auth.ed25519_signature,
            )
            .map_err(AuthenticationError::VerificationProvider)?,
        AuthenticationError::InvalidEd25519Signature,
    )?;
    require_valid(
        provider
            .verify_ml_dsa_65(
                ml_dsa_65_public_key,
                signature_input.as_slice(),
                ml_dsa_65_signature,
            )
            .map_err(AuthenticationError::VerificationProvider)?,
        AuthenticationError::InvalidMlDsa65Signature,
    )?;

    Ok(AuthenticatedIdentity {
        fingerprint: computed_fingerprint,
        ed25519_public_key: identity_auth.ed25519_public_key,
        ml_dsa_65_public_key: *ml_dsa_65_public_key,
    })
}

/// Verifies both signatures on a canonical manifest against one authenticated
/// peer identity.
///
/// The returned token is created only after signer binding and both signature
/// algorithms succeed. It can be used to install transfer and Merkle state.
///
/// # Errors
///
/// Returns an identity mismatch, invalid signature, fixed-input overflow,
/// invariant failure, or provider-specific hashing/verification error.
pub fn verify_manifest<P: HybridAuthenticationProvider>(
    provider: &P,
    identity: &AuthenticatedIdentity,
    manifest: &Manifest<'_>,
) -> Result<VerifiedManifest, AuthenticationError<P::Error, P::VerificationError>> {
    if !fingerprints_equal(
        &manifest.header.signer_identity_fingerprint,
        &identity.fingerprint,
    ) {
        return Err(AuthenticationError::ManifestSignerMismatch);
    }

    let manifest_hash = hash_bytes(provider, manifest.unsigned_content())?;
    let signature_input = manifest_signature_input(&manifest_hash)
        .ok_or(AuthenticationError::SignatureInputOverflow)?;
    let ed25519_signature = manifest
        .ed25519_signature()
        .try_into()
        .map_err(|_| AuthenticationError::CodecInvariantViolation)?;
    let ml_dsa_65_signature = manifest
        .ml_dsa_65_signature()
        .try_into()
        .map_err(|_| AuthenticationError::CodecInvariantViolation)?;
    require_valid(
        provider
            .verify_ed25519(
                &identity.ed25519_public_key,
                signature_input.as_slice(),
                ed25519_signature,
            )
            .map_err(AuthenticationError::VerificationProvider)?,
        AuthenticationError::InvalidEd25519Signature,
    )?;
    require_valid(
        provider
            .verify_ml_dsa_65(
                &identity.ml_dsa_65_public_key,
                signature_input.as_slice(),
                ml_dsa_65_signature,
            )
            .map_err(AuthenticationError::VerificationProvider)?,
        AuthenticationError::InvalidMlDsa65Signature,
    )?;
    Ok(VerifiedManifest {
        header: manifest.header,
    })
}

/// Computes the canonical SHA-384 identity fingerprint.
///
/// # Errors
///
/// Returns a provider-specific SHA-384 failure.
pub fn identity_fingerprint<P: Sha384Provider>(
    provider: &P,
    ed25519_public_key: &[u8; ED25519_PUBLIC_KEY_LEN],
    ml_dsa_65_public_key: &[u8; ML_DSA_65_PUBLIC_KEY_LEN],
) -> Result<Sha384Digest, P::Error> {
    compute_identity_fingerprint(provider, ed25519_public_key, ml_dsa_65_public_key)
}

fn compute_identity_fingerprint<P: Sha384Provider>(
    provider: &P,
    ed25519_public_key: &[u8; ED25519_PUBLIC_KEY_LEN],
    ml_dsa_65_public_key: &[u8; ML_DSA_65_PUBLIC_KEY_LEN],
) -> Result<Sha384Digest, P::Error> {
    let mut context = provider.start_sha384()?;
    context.update(IDENTITY_FINGERPRINT_CONTEXT);
    context.update(ed25519_public_key);
    context.update(ml_dsa_65_public_key);
    provider.finish_sha384(context)
}

fn hash_bytes<P: HybridAuthenticationProvider>(
    provider: &P,
    bytes: &[u8],
) -> Result<Sha384Digest, AuthenticationError<P::Error, P::VerificationError>> {
    let mut context = provider
        .start_sha384()
        .map_err(AuthenticationError::HashProvider)?;
    context.update(bytes);
    provider
        .finish_sha384(context)
        .map_err(AuthenticationError::HashProvider)
}

fn require_valid<H, V>(
    result: VerificationResult,
    invalid_error: AuthenticationError<H, V>,
) -> Result<(), AuthenticationError<H, V>> {
    match result {
        VerificationResult::Valid => Ok(()),
        VerificationResult::Invalid => Err(invalid_error),
    }
}

fn fingerprints_equal(
    left: &[u8; IDENTITY_FINGERPRINT_LEN],
    right: &[u8; IDENTITY_FINGERPRINT_LEN],
) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

/// Builds the exact bounded message signed for handshake peer authentication.
///
/// Returning `None` is a fail-closed guard against a future context expansion
/// exceeding [`MAX_CONTEXTUALIZED_SIGNATURE_INPUT_LEN`].
#[must_use]
pub fn handshake_signature_input(
    role: AuthenticationRole,
    transcript_hash: &[u8; SHA384_OUTPUT_LEN],
) -> Option<ContextualizedSignatureInput> {
    let mut input = ContextualizedSignatureInput::new();
    feed_signature_input(&mut input, role, transcript_hash);
    (!input.overflowed).then_some(input)
}

/// Builds the exact bounded message signed for a canonical manifest.
///
/// Returning `None` is a fail-closed guard against a future context expansion
/// exceeding [`MAX_CONTEXTUALIZED_SIGNATURE_INPUT_LEN`].
#[must_use]
pub fn manifest_signature_input(
    manifest_hash: &Sha384Digest,
) -> Option<ContextualizedSignatureInput> {
    let mut input = ContextualizedSignatureInput::new();
    feed_manifest_signature_input(&mut input, manifest_hash);
    (!input.overflowed).then_some(input)
}

/// Fixed-capacity canonical message consumed by both identity signature
/// algorithms.
pub struct ContextualizedSignatureInput {
    bytes: [u8; MAX_CONTEXTUALIZED_SIGNATURE_INPUT_LEN],
    length: usize,
    overflowed: bool,
}

impl ContextualizedSignatureInput {
    const fn new() -> Self {
        Self {
            bytes: [0; MAX_CONTEXTUALIZED_SIGNATURE_INPUT_LEN],
            length: 0,
            overflowed: false,
        }
    }

    /// Returns the exact contextualized message bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    fn as_slice(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for ContextualizedSignatureInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextualizedSignatureInput")
            .field("length", &self.length)
            .field("overflowed", &self.overflowed)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl TranscriptSink for ContextualizedSignatureInput {
    fn update(&mut self, bytes: &[u8]) {
        let Some(end) = self.length.checked_add(bytes.len()) else {
            self.overflowed = true;
            return;
        };
        let Some(destination) = self.bytes.get_mut(self.length..end) else {
            self.overflowed = true;
            return;
        };
        destination.copy_from_slice(bytes);
        self.length = end;
    }
}

/// Hybrid authentication orchestration failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticationError<H, V> {
    HashProvider(H),
    VerificationProvider(V),
    AnnouncedFingerprintMismatch,
    TrustAnchorMismatch,
    InvalidFinishedMac,
    InvalidEd25519Signature,
    InvalidMlDsa65Signature,
    ManifestSignerMismatch,
    SignatureInputOverflow,
    CodecInvariantViolation,
}

impl<H: fmt::Display, V: fmt::Display> fmt::Display for AuthenticationError<H, V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HashProvider(error) => write!(formatter, "SHA-384 provider failure: {error}"),
            Self::VerificationProvider(error) => {
                write!(formatter, "authentication provider failure: {error}")
            }
            Self::AnnouncedFingerprintMismatch => {
                formatter.write_str("identity keys do not match announced fingerprint")
            }
            Self::TrustAnchorMismatch => {
                formatter.write_str("identity keys do not match trust anchor")
            }
            Self::InvalidFinishedMac => formatter.write_str("invalid Finished MAC"),
            Self::InvalidEd25519Signature => formatter.write_str("invalid Ed25519 signature"),
            Self::InvalidMlDsa65Signature => formatter.write_str("invalid ML-DSA-65 signature"),
            Self::ManifestSignerMismatch => {
                formatter.write_str("manifest signer does not match authenticated peer")
            }
            Self::SignatureInputOverflow => {
                formatter.write_str("contextualized signature input overflow")
            }
            Self::CodecInvariantViolation => {
                formatter.write_str("authenticated codec invariant violation")
            }
        }
    }
}

impl<H, V> std::error::Error for AuthenticationError<H, V>
where
    H: std::error::Error + 'static,
    V: std::error::Error + 'static,
{
}

#[cfg(test)]
mod tests {
    use core::cell::{Cell, RefCell};

    use sha2::{Digest, Sha384};

    use super::*;
    use crate::manifest::{MAX_SIGNED_MANIFEST_LEN, MERKLE_ROOT_LEN, MIN_CHUNK_SIZE};

    const ED25519_KEY: [u8; ED25519_PUBLIC_KEY_LEN] = [0x11; ED25519_PUBLIC_KEY_LEN];
    const ML_DSA_KEY: [u8; ML_DSA_65_PUBLIC_KEY_LEN] = [0x22; ML_DSA_65_PUBLIC_KEY_LEN];
    const ED25519_SIGNATURE: [u8; ED25519_SIGNATURE_LEN] = [0x33; ED25519_SIGNATURE_LEN];
    const ML_DSA_SIGNATURE: [u8; ML_DSA_65_SIGNATURE_LEN] = [0x44; ML_DSA_65_SIGNATURE_LEN];
    const FINISHED_MAC: [u8; FINISHED_MAC_LEN] = [0x55; FINISHED_MAC_LEN];

    struct Sha384Context(Sha384);

    impl TranscriptSink for Sha384Context {
        fn update(&mut self, bytes: &[u8]) {
            self.0.update(bytes);
        }
    }

    struct TestProvider {
        hash_failure: Cell<bool>,
        verification_failure: Cell<bool>,
        hmac_result: Cell<VerificationResult>,
        ed25519_result: Cell<VerificationResult>,
        ml_dsa_result: Cell<VerificationResult>,
        calls: RefCell<Vec<&'static str>>,
        messages: RefCell<Vec<Vec<u8>>>,
    }

    impl TestProvider {
        fn valid() -> Self {
            Self {
                hash_failure: Cell::new(false),
                verification_failure: Cell::new(false),
                hmac_result: Cell::new(VerificationResult::Valid),
                ed25519_result: Cell::new(VerificationResult::Valid),
                ml_dsa_result: Cell::new(VerificationResult::Valid),
                calls: RefCell::new(Vec::new()),
                messages: RefCell::new(Vec::new()),
            }
        }

        fn clear_observations(&self) {
            self.calls.borrow_mut().clear();
            self.messages.borrow_mut().clear();
        }
    }

    impl Sha384Provider for TestProvider {
        type Context = Sha384Context;
        type Error = &'static str;

        fn start_sha384(&self) -> Result<Self::Context, Self::Error> {
            if self.hash_failure.get() {
                Err("injected hash failure")
            } else {
                Ok(Sha384Context(Sha384::new()))
            }
        }

        fn finish_sha384(&self, context: Self::Context) -> Result<Sha384Digest, Self::Error> {
            Ok(context.0.finalize().into())
        }
    }

    impl HybridAuthenticationProvider for TestProvider {
        type VerificationError = &'static str;

        fn verify_hmac_sha384(
            &self,
            _key: &[u8; FINISHED_MAC_LEN],
            _transcript_hash: &[u8; SHA384_OUTPUT_LEN],
            _received_mac: &[u8; FINISHED_MAC_LEN],
        ) -> Result<VerificationResult, Self::VerificationError> {
            self.calls.borrow_mut().push("hmac");
            if self.verification_failure.get() {
                Err("injected verification failure")
            } else {
                Ok(self.hmac_result.get())
            }
        }

        fn verify_ed25519(
            &self,
            _public_key: &[u8; ED25519_PUBLIC_KEY_LEN],
            message: &[u8],
            _signature: &[u8; ED25519_SIGNATURE_LEN],
        ) -> Result<VerificationResult, Self::VerificationError> {
            self.calls.borrow_mut().push("ed25519");
            self.messages.borrow_mut().push(message.to_vec());
            if self.verification_failure.get() {
                Err("injected verification failure")
            } else {
                Ok(self.ed25519_result.get())
            }
        }

        fn verify_ml_dsa_65(
            &self,
            _public_key: &[u8; ML_DSA_65_PUBLIC_KEY_LEN],
            message: &[u8],
            _signature: &[u8; ML_DSA_65_SIGNATURE_LEN],
        ) -> Result<VerificationResult, Self::VerificationError> {
            self.calls.borrow_mut().push("ml-dsa");
            self.messages.borrow_mut().push(message.to_vec());
            if self.verification_failure.get() {
                Err("injected verification failure")
            } else {
                Ok(self.ml_dsa_result.get())
            }
        }
    }

    fn identity_auth() -> IdentityAuth<'static> {
        IdentityAuth {
            ed25519_public_key: ED25519_KEY,
            ml_dsa_public_key: &ML_DSA_KEY,
            ed25519_signature: ED25519_SIGNATURE,
            ml_dsa_signature: &ML_DSA_SIGNATURE,
            finished_mac: FINISHED_MAC,
        }
    }

    fn fingerprint(provider: &TestProvider) -> [u8; IDENTITY_FINGERPRINT_LEN] {
        identity_fingerprint(provider, &ED25519_KEY, &ML_DSA_KEY)
            .expect("test hash provider succeeds")
    }

    fn authenticate(
        provider: &TestProvider,
        announced: &[u8; IDENTITY_FINGERPRINT_LEN],
        trusted: &[u8; IDENTITY_FINGERPRINT_LEN],
    ) -> Result<AuthenticatedIdentity, AuthenticationError<&'static str, &'static str>> {
        authenticate_peer_identity(
            provider,
            PeerAuthenticationContext {
                role: AuthenticationRole::Responder,
                signature_transcript_hash: &[0x66; SHA384_OUTPUT_LEN],
                finished_transcript_hash: &[0x77; SHA384_OUTPUT_LEN],
                finished_key: &[0x88; FINISHED_MAC_LEN],
                announced_fingerprint: announced,
                trust_anchor_fingerprint: trusted,
            },
            &identity_auth(),
        )
    }

    fn encoded_manifest(
        signer: [u8; IDENTITY_FINGERPRINT_LEN],
        output: &mut [u8; MAX_SIGNED_MANIFEST_LEN],
    ) -> usize {
        ManifestHeader {
            object_id: [0x91; 32],
            object_size: u64::from(MIN_CHUNK_SIZE) + 7,
            chunk_size: MIN_CHUNK_SIZE,
            chunk_count: 2,
            merkle_root: [0x92; MERKLE_ROOT_LEN],
            signer_identity_fingerprint: signer,
        }
        .encode_signed(
            "authenticated.bin",
            &ED25519_SIGNATURE,
            &ML_DSA_SIGNATURE,
            output,
        )
        .expect("test manifest encodes")
    }

    #[test]
    fn fingerprint_matches_independent_sha384_encoding() {
        let provider = TestProvider::valid();
        let actual = fingerprint(&provider);
        let mut reference = Sha384::new();
        reference.update(IDENTITY_FINGERPRINT_CONTEXT);
        reference.update(ED25519_KEY);
        reference.update(ML_DSA_KEY);
        let expected: [u8; SHA384_OUTPUT_LEN] = reference.finalize().into();
        assert_eq!(actual, expected);
    }

    #[test]
    fn identity_installs_only_after_finished_and_both_signatures() {
        let provider = TestProvider::valid();
        let expected = fingerprint(&provider);
        provider.clear_observations();
        let identity =
            authenticate(&provider, &expected, &expected).expect("identity authenticates");

        assert_eq!(identity.fingerprint(), &expected);
        assert_eq!(identity.ed25519_public_key(), &ED25519_KEY);
        assert_eq!(identity.ml_dsa_65_public_key(), &ML_DSA_KEY);
        assert_eq!(*provider.calls.borrow(), ["hmac", "ed25519", "ml-dsa"]);
        let messages = provider.messages.borrow();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0], messages[1]);
        assert!(messages[0].starts_with(&[0x20; 64]));
        assert!(
            messages[0]
                .windows(b"OGTP/1 responder authentication".len())
                .any(|window| window == b"OGTP/1 responder authentication")
        );
        let debug = format!("{identity:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("11111111"));
    }

    #[test]
    fn cheap_failures_short_circuit_expensive_verification() {
        let provider = TestProvider::valid();
        let expected = fingerprint(&provider);
        provider.clear_observations();

        let wrong = [0xff; IDENTITY_FINGERPRINT_LEN];
        assert_eq!(
            authenticate(&provider, &wrong, &expected),
            Err(AuthenticationError::AnnouncedFingerprintMismatch)
        );
        assert!(provider.calls.borrow().is_empty());
        assert_eq!(
            authenticate(&provider, &expected, &wrong),
            Err(AuthenticationError::TrustAnchorMismatch)
        );
        assert!(provider.calls.borrow().is_empty());

        provider.hmac_result.set(VerificationResult::Invalid);
        assert_eq!(
            authenticate(&provider, &expected, &expected),
            Err(AuthenticationError::InvalidFinishedMac)
        );
        assert_eq!(*provider.calls.borrow(), ["hmac"]);
        provider.hmac_result.set(VerificationResult::Valid);
        provider.clear_observations();

        provider.ed25519_result.set(VerificationResult::Invalid);
        assert_eq!(
            authenticate(&provider, &expected, &expected),
            Err(AuthenticationError::InvalidEd25519Signature)
        );
        assert_eq!(*provider.calls.borrow(), ["hmac", "ed25519"]);
        provider.ed25519_result.set(VerificationResult::Valid);
        provider.clear_observations();

        provider.ml_dsa_result.set(VerificationResult::Invalid);
        assert_eq!(
            authenticate(&provider, &expected, &expected),
            Err(AuthenticationError::InvalidMlDsa65Signature)
        );
        assert_eq!(*provider.calls.borrow(), ["hmac", "ed25519", "ml-dsa"]);
    }

    #[test]
    fn provider_failures_are_distinct_from_invalid_authenticators() {
        let provider = TestProvider::valid();
        let expected = fingerprint(&provider);
        provider.hash_failure.set(true);
        assert_eq!(
            authenticate(&provider, &expected, &expected),
            Err(AuthenticationError::HashProvider("injected hash failure"))
        );
        provider.hash_failure.set(false);
        provider.verification_failure.set(true);
        assert_eq!(
            authenticate(&provider, &expected, &expected),
            Err(AuthenticationError::VerificationProvider(
                "injected verification failure"
            ))
        );
    }

    #[test]
    fn manifest_token_requires_peer_binding_and_both_signatures() {
        let provider = TestProvider::valid();
        let expected = fingerprint(&provider);
        let identity =
            authenticate(&provider, &expected, &expected).expect("identity authenticates");
        provider.clear_observations();

        let mut encoded = [0_u8; MAX_SIGNED_MANIFEST_LEN];
        let length = encoded_manifest(expected, &mut encoded);
        let manifest = Manifest::decode(&encoded[..length]).expect("manifest decodes");
        let verified = verify_manifest(&provider, &identity, &manifest).expect("manifest verifies");
        assert_eq!(verified.header(), manifest.header);
        assert_eq!(*provider.calls.borrow(), ["ed25519", "ml-dsa"]);
        let messages = provider.messages.borrow();
        assert_eq!(messages[0], messages[1]);
        assert!(
            messages[0]
                .windows(b"OGTP/1 object manifest".len())
                .any(|window| window == b"OGTP/1 object manifest")
        );
        drop(messages);

        provider.clear_observations();
        let mut wrong_encoded = [0_u8; MAX_SIGNED_MANIFEST_LEN];
        let wrong_length = encoded_manifest([0xaa; IDENTITY_FINGERPRINT_LEN], &mut wrong_encoded);
        let wrong = Manifest::decode(&wrong_encoded[..wrong_length]).expect("manifest decodes");
        assert_eq!(
            verify_manifest(&provider, &identity, &wrong),
            Err(AuthenticationError::ManifestSignerMismatch)
        );
        assert!(provider.calls.borrow().is_empty());

        provider.ed25519_result.set(VerificationResult::Invalid);
        assert_eq!(
            verify_manifest(&provider, &identity, &manifest),
            Err(AuthenticationError::InvalidEd25519Signature)
        );
        assert_eq!(*provider.calls.borrow(), ["ed25519"]);
    }

    #[test]
    fn contextualized_inputs_fit_fixed_stack_storage() {
        let handshake =
            handshake_signature_input(AuthenticationRole::Initiator, &[0x11; SHA384_OUTPUT_LEN])
                .expect("handshake signature input fits");
        let manifest = manifest_signature_input(&[0x22; SHA384_OUTPUT_LEN])
            .expect("manifest signature input fits");
        assert!(handshake.as_slice().len() < MAX_CONTEXTUALIZED_SIGNATURE_INPUT_LEN);
        assert!(manifest.as_slice().len() < MAX_CONTEXTUALIZED_SIGNATURE_INPUT_LEN);
        assert_ne!(handshake.as_slice(), manifest.as_slice());

        let context = PeerAuthenticationContext {
            role: AuthenticationRole::Initiator,
            signature_transcript_hash: &[0x11; SHA384_OUTPUT_LEN],
            finished_transcript_hash: &[0x22; SHA384_OUTPUT_LEN],
            finished_key: &[0x33; FINISHED_MAC_LEN],
            announced_fingerprint: &[0x44; IDENTITY_FINGERPRINT_LEN],
            trust_anchor_fingerprint: &[0x55; IDENTITY_FINGERPRINT_LEN],
        };
        let debug = format!("{context:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("33333333"));
    }
}
