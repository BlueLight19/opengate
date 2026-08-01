//! Provider-neutral hybrid key exchange and handshake AEAD orchestration.

use core::fmt;

use crate::authentication::AuthenticatedIdentity;
use crate::crypto::{Sha384Digest, Sha384Provider};
use crate::handshake::{
    CipherSuite, ENCRYPTED_IDENTITY_AUTH_LEN, HYBRID_SHARED_SECRET_LEN, IDENTITY_AUTH_LEN,
    IdentityAuth, ML_KEM_768_CIPHERTEXT_LEN, ML_KEM_768_ENCAPSULATION_KEY_LEN,
    ML_KEM_SHARED_SECRET_LEN, X25519_PUBLIC_KEY_LEN, X25519_SHARED_SECRET_LEN,
};
use crate::handshake_state::InitiatorTranscriptMilestone;
use crate::kdf::{
    AEAD_IV_LEN, AEAD_KEY_LEN, HASH_LEN, LABEL_DERIVED, LABEL_FINISHED,
    LABEL_INITIATOR_APPLICATION, LABEL_INITIATOR_HANDSHAKE, LABEL_IV, LABEL_KEY,
    LABEL_RESPONDER_APPLICATION, LABEL_RESPONDER_HANDSHAKE, LabelError, encode_expand_label,
};
use crate::transcript::AuthenticationRole;
use crate::wire::WireError;

const MAX_EXPAND_LABEL_LEN: usize = 80;

/// Result of opening one handshake AEAD value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeAeadOpenResult {
    Opened(usize),
    Invalid,
}

/// Provider boundary for hybrid KEM, HKDF-SHA-384, HMAC, and handshake AEAD.
///
/// Implementations must use X25519, ML-KEM-768, HKDF-SHA-384, and the selected
/// AES-256-GCM or ChaCha20-Poly1305 suite. Random key generation, private-key
/// storage, canonical ML-KEM validation, constant-time operations, and physical
/// key erasure belong to the provider.
pub trait HandshakeCryptoProvider: Sha384Provider {
    type X25519PrivateKey;
    type MlKem768DecapsulationKey;

    /// Generates one ephemeral X25519 key pair.
    ///
    /// # Errors
    ///
    /// Returns a provider-specific RNG, key-generation, or backend failure.
    fn generate_x25519_key_pair(
        &self,
        public_key: &mut [u8; X25519_PUBLIC_KEY_LEN],
    ) -> Result<Self::X25519PrivateKey, Self::Error>;

    /// Computes one X25519 shared secret into caller-owned fixed storage.
    ///
    /// # Errors
    ///
    /// Returns a provider-specific key/backend failure. The orchestration also
    /// rejects an all-zero output independently.
    fn x25519_shared_secret(
        &self,
        private_key: &Self::X25519PrivateKey,
        peer_public_key: &[u8; X25519_PUBLIC_KEY_LEN],
        output: &mut [u8; X25519_SHARED_SECRET_LEN],
    ) -> Result<(), Self::Error>;

    /// Generates an ML-KEM-768 encapsulation/decapsulation key pair.
    ///
    /// # Errors
    ///
    /// Returns a provider-specific RNG, key-generation, or backend failure.
    fn generate_ml_kem_768_key_pair(
        &self,
        encapsulation_key: &mut [u8; ML_KEM_768_ENCAPSULATION_KEY_LEN],
    ) -> Result<Self::MlKem768DecapsulationKey, Self::Error>;

    /// Encapsulates to an exact ML-KEM-768 public key.
    ///
    /// # Errors
    ///
    /// Returns a provider-specific canonical-key, RNG, or backend failure.
    fn encapsulate_ml_kem_768(
        &self,
        encapsulation_key: &[u8; ML_KEM_768_ENCAPSULATION_KEY_LEN],
        ciphertext: &mut [u8; ML_KEM_768_CIPHERTEXT_LEN],
        shared_secret: &mut [u8; ML_KEM_SHARED_SECRET_LEN],
    ) -> Result<(), Self::Error>;

    /// Decapsulates one exact ML-KEM-768 ciphertext.
    ///
    /// # Errors
    ///
    /// Returns a provider-specific key or backend failure. Implementations must
    /// preserve ML-KEM implicit-rejection semantics.
    fn decapsulate_ml_kem_768(
        &self,
        decapsulation_key: &Self::MlKem768DecapsulationKey,
        ciphertext: &[u8; ML_KEM_768_CIPHERTEXT_LEN],
        shared_secret: &mut [u8; ML_KEM_SHARED_SECRET_LEN],
    ) -> Result<(), Self::Error>;

    /// Computes HKDF-Extract-SHA-384 into exactly 48 bytes.
    ///
    /// # Errors
    ///
    /// Returns a provider-specific key/backend failure.
    fn hkdf_extract_sha384(
        &self,
        salt: &[u8; HASH_LEN],
        input_key_material: &[u8],
        output: &mut [u8; HASH_LEN],
    ) -> Result<(), Self::Error>;

    /// Computes HKDF-Expand-SHA-384 for the exact caller-owned output length.
    ///
    /// # Errors
    ///
    /// Returns a provider-specific key/backend failure.
    fn hkdf_expand_sha384(
        &self,
        pseudorandom_key: &[u8; HASH_LEN],
        info: &[u8],
        output: &mut [u8],
    ) -> Result<(), Self::Error>;

    /// Computes HMAC-SHA-384 for a Finished value.
    ///
    /// # Errors
    ///
    /// Returns a provider-specific key/backend failure.
    fn hmac_sha384(
        &self,
        key: &[u8; HASH_LEN],
        message: &[u8],
        output: &mut [u8; HASH_LEN],
    ) -> Result<(), Self::Error>;

    /// Seals a handshake plaintext in place and appends a 16-byte tag.
    ///
    /// # Errors
    ///
    /// Returns a provider-specific key or backend failure.
    fn seal_handshake_aead(
        &self,
        suite: CipherSuite,
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; AEAD_IV_LEN],
        additional_data: &[u8],
        plaintext_and_tag: &mut [u8],
        plaintext_length: usize,
    ) -> Result<usize, Self::Error>;

    /// Authenticates and opens a handshake ciphertext in place.
    ///
    /// # Errors
    ///
    /// Returns a provider-specific error only for a key/backend failure. An
    /// invalid tag uses [`HandshakeAeadOpenResult::Invalid`].
    fn open_handshake_aead(
        &self,
        suite: CipherSuite,
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; AEAD_IV_LEN],
        additional_data: &[u8],
        ciphertext_and_tag: &mut [u8],
    ) -> Result<HandshakeAeadOpenResult, Self::Error>;
}

struct SecretBytes<const N: usize>([u8; N]);

impl<const N: usize> SecretBytes<N> {
    const fn zeroed() -> Self {
        Self([0; N])
    }

    const fn as_array(&self) -> &[u8; N] {
        &self.0
    }

    const fn as_mut_array(&mut self) -> &mut [u8; N] {
        &mut self.0
    }

    fn copy_out(&self) -> [u8; N] {
        self.0
    }
}

impl<const N: usize> Drop for SecretBytes<N> {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes(<redacted>)")
    }
}

/// Ephemeral initiator state retained between `INIT` and `RESPONSE`.
pub struct InitiatorHybridState<P: HandshakeCryptoProvider> {
    x25519_private: P::X25519PrivateKey,
    ml_kem_decapsulation: P::MlKem768DecapsulationKey,
    x25519_public: [u8; X25519_PUBLIC_KEY_LEN],
    ml_kem_encapsulation: [u8; ML_KEM_768_ENCAPSULATION_KEY_LEN],
}

impl<P: HandshakeCryptoProvider> InitiatorHybridState<P> {
    #[must_use]
    pub const fn x25519_public_key(&self) -> &[u8; X25519_PUBLIC_KEY_LEN] {
        &self.x25519_public
    }

    #[must_use]
    pub const fn ml_kem_encapsulation_key(&self) -> &[u8; ML_KEM_768_ENCAPSULATION_KEY_LEN] {
        &self.ml_kem_encapsulation
    }

    /// Completes both hybrid branches and derives the handshake schedule.
    ///
    /// The state is consumed on every result so ephemeral private keys cannot
    /// be reused after a failed or successful `RESPONSE`.
    ///
    /// # Errors
    ///
    /// Returns an error for provider/KDF failure or all-zero X25519 output.
    pub fn complete(
        self,
        provider: &P,
        suite: CipherSuite,
        responder_x25519_public_key: &[u8; X25519_PUBLIC_KEY_LEN],
        ml_kem_ciphertext: &[u8; ML_KEM_768_CIPHERTEXT_LEN],
        pre_auth_hash: &Sha384Digest,
    ) -> Result<HandshakeSecrets, HandshakeCryptoError<P::Error>> {
        let mut x25519 = SecretBytes::<X25519_SHARED_SECRET_LEN>::zeroed();
        provider
            .x25519_shared_secret(
                &self.x25519_private,
                responder_x25519_public_key,
                x25519.as_mut_array(),
            )
            .map_err(HandshakeCryptoError::Provider)?;
        reject_all_zero_x25519(x25519.as_array())?;
        let mut ml_kem = SecretBytes::<ML_KEM_SHARED_SECRET_LEN>::zeroed();
        provider
            .decapsulate_ml_kem_768(
                &self.ml_kem_decapsulation,
                ml_kem_ciphertext,
                ml_kem.as_mut_array(),
            )
            .map_err(HandshakeCryptoError::Provider)?;
        derive_hybrid_handshake_secrets(provider, suite, &ml_kem, &x25519, pre_auth_hash)
    }
}

impl<P: HandshakeCryptoProvider> fmt::Debug for InitiatorHybridState<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InitiatorHybridState")
            .field("x25519_private", &"<redacted>")
            .field("ml_kem_decapsulation", &"<redacted>")
            .field("x25519_public", &"<redacted>")
            .field("ml_kem_encapsulation", &"<redacted>")
            .finish()
    }
}

/// Generates both initiator ephemeral key pairs in fixed output storage.
///
/// # Errors
///
/// Returns a provider-specific RNG, key-generation, or backend failure.
pub fn generate_initiator_hybrid_state<P: HandshakeCryptoProvider>(
    provider: &P,
) -> Result<InitiatorHybridState<P>, HandshakeCryptoError<P::Error>> {
    let mut x25519_public_key = [0_u8; X25519_PUBLIC_KEY_LEN];
    let x25519_private_key = provider
        .generate_x25519_key_pair(&mut x25519_public_key)
        .map_err(HandshakeCryptoError::Provider)?;
    let mut ml_kem_encapsulation_key = [0_u8; ML_KEM_768_ENCAPSULATION_KEY_LEN];
    let ml_kem_decapsulation_key = provider
        .generate_ml_kem_768_key_pair(&mut ml_kem_encapsulation_key)
        .map_err(HandshakeCryptoError::Provider)?;
    Ok(InitiatorHybridState {
        x25519_private: x25519_private_key,
        ml_kem_decapsulation: ml_kem_decapsulation_key,
        x25519_public: x25519_public_key,
        ml_kem_encapsulation: ml_kem_encapsulation_key,
    })
}

/// Responder public values plus installed directional handshake secrets.
pub struct ResponderHybridResult {
    x25519_public_key: [u8; X25519_PUBLIC_KEY_LEN],
    ml_kem_ciphertext: [u8; ML_KEM_768_CIPHERTEXT_LEN],
    secrets: HandshakeSecrets,
}

impl ResponderHybridResult {
    #[must_use]
    pub const fn x25519_public_key(&self) -> &[u8; X25519_PUBLIC_KEY_LEN] {
        &self.x25519_public_key
    }

    #[must_use]
    pub const fn ml_kem_ciphertext(&self) -> &[u8; ML_KEM_768_CIPHERTEXT_LEN] {
        &self.ml_kem_ciphertext
    }

    #[must_use]
    pub const fn secrets(&self) -> &HandshakeSecrets {
        &self.secrets
    }

    #[must_use]
    pub const fn secrets_mut(&mut self) -> &mut HandshakeSecrets {
        &mut self.secrets
    }

    #[must_use]
    pub fn into_secrets(self) -> HandshakeSecrets {
        self.secrets
    }
}

impl fmt::Debug for ResponderHybridResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponderHybridResult")
            .field("x25519_public_key", &"<redacted>")
            .field("ml_kem_ciphertext", &"<redacted>")
            .field("secrets", &"<redacted>")
            .finish()
    }
}

/// Generates the responder key share, completes both branches, and derives
/// directional handshake secrets atomically.
///
/// # Errors
///
/// Returns an error for provider/KDF failure or all-zero X25519 output.
pub fn respond_to_initiator<P: HandshakeCryptoProvider>(
    provider: &P,
    suite: CipherSuite,
    initiator_x25519_public_key: &[u8; X25519_PUBLIC_KEY_LEN],
    ml_kem_encapsulation_key: &[u8; ML_KEM_768_ENCAPSULATION_KEY_LEN],
    pre_auth_hash: &Sha384Digest,
) -> Result<ResponderHybridResult, HandshakeCryptoError<P::Error>> {
    let mut x25519_public_key = [0_u8; X25519_PUBLIC_KEY_LEN];
    let x25519_private_key = provider
        .generate_x25519_key_pair(&mut x25519_public_key)
        .map_err(HandshakeCryptoError::Provider)?;
    let mut x25519 = SecretBytes::<X25519_SHARED_SECRET_LEN>::zeroed();
    provider
        .x25519_shared_secret(
            &x25519_private_key,
            initiator_x25519_public_key,
            x25519.as_mut_array(),
        )
        .map_err(HandshakeCryptoError::Provider)?;
    reject_all_zero_x25519(x25519.as_array())?;
    let mut ml_kem_ciphertext = [0_u8; ML_KEM_768_CIPHERTEXT_LEN];
    let mut ml_kem = SecretBytes::<ML_KEM_SHARED_SECRET_LEN>::zeroed();
    provider
        .encapsulate_ml_kem_768(
            ml_kem_encapsulation_key,
            &mut ml_kem_ciphertext,
            ml_kem.as_mut_array(),
        )
        .map_err(HandshakeCryptoError::Provider)?;
    let secrets =
        derive_hybrid_handshake_secrets(provider, suite, &ml_kem, &x25519, pre_auth_hash)?;
    Ok(ResponderHybridResult {
        x25519_public_key,
        ml_kem_ciphertext,
        secrets,
    })
}

/// One sender direction of the handshake schedule.
pub struct DirectionalHandshakeSecrets {
    traffic_secret: [u8; HASH_LEN],
    finished_key: [u8; HASH_LEN],
    aead_key: [u8; AEAD_KEY_LEN],
    aead_iv: [u8; AEAD_IV_LEN],
    seal_reserved: bool,
}

impl DirectionalHandshakeSecrets {
    #[must_use]
    pub const fn finished_key(&self) -> &[u8; HASH_LEN] {
        &self.finished_key
    }
}

impl Drop for DirectionalHandshakeSecrets {
    fn drop(&mut self) {
        self.traffic_secret.fill(0);
        self.finished_key.fill(0);
        self.aead_key.fill(0);
        self.aead_iv.fill(0);
        self.seal_reserved = true;
    }
}

impl fmt::Debug for DirectionalHandshakeSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DirectionalHandshakeSecrets(<redacted>)")
    }
}

/// Installed handshake schedule, including the deferred master secret.
pub struct HandshakeSecrets {
    suite: CipherSuite,
    initiator: DirectionalHandshakeSecrets,
    responder: DirectionalHandshakeSecrets,
    master_secret: [u8; HASH_LEN],
}

impl HandshakeSecrets {
    #[must_use]
    pub const fn suite(&self) -> CipherSuite {
        self.suite
    }

    #[must_use]
    pub const fn initiator(&self) -> &DirectionalHandshakeSecrets {
        &self.initiator
    }

    #[must_use]
    pub const fn responder(&self) -> &DirectionalHandshakeSecrets {
        &self.responder
    }

    /// Computes one role-correct Finished HMAC.
    ///
    /// # Errors
    ///
    /// Returns a provider-specific HMAC/backend failure.
    pub fn compute_finished<P: HandshakeCryptoProvider>(
        &self,
        provider: &P,
        sender: AuthenticationRole,
        transcript_hash: &Sha384Digest,
    ) -> Result<Sha384Digest, HandshakeCryptoError<P::Error>> {
        let mut output = SecretBytes::<HASH_LEN>::zeroed();
        provider
            .hmac_sha384(
                self.direction(sender).finished_key(),
                transcript_hash,
                output.as_mut_array(),
            )
            .map_err(HandshakeCryptoError::Provider)?;
        Ok(output.copy_out())
    }

    /// Derives both application traffic secrets and consumes all handshake
    /// traffic material. Completed-transcript and authenticated-peer
    /// capabilities are mandatory.
    ///
    /// # Errors
    ///
    /// Returns a label-encoding or provider HKDF failure.
    pub fn derive_application_secrets<P: HandshakeCryptoProvider>(
        self,
        provider: &P,
        completed_transcript: &InitiatorTranscriptMilestone,
        _authenticated_peer: &AuthenticatedIdentity,
    ) -> Result<ApplicationSecrets, HandshakeCryptoError<P::Error>> {
        let mut initiator = SecretBytes::<HASH_LEN>::zeroed();
        derive_secret(
            provider,
            &self.master_secret,
            LABEL_INITIATOR_APPLICATION,
            completed_transcript.full(),
            initiator.as_mut_array(),
        )?;
        let mut responder = SecretBytes::<HASH_LEN>::zeroed();
        derive_secret(
            provider,
            &self.master_secret,
            LABEL_RESPONDER_APPLICATION,
            completed_transcript.full(),
            responder.as_mut_array(),
        )?;
        Ok(ApplicationSecrets {
            initiator: initiator.copy_out(),
            responder: responder.copy_out(),
        })
    }

    const fn direction(&self, sender: AuthenticationRole) -> &DirectionalHandshakeSecrets {
        match sender {
            AuthenticationRole::Initiator => &self.initiator,
            AuthenticationRole::Responder => &self.responder,
        }
    }

    const fn direction_mut(
        &mut self,
        sender: AuthenticationRole,
    ) -> &mut DirectionalHandshakeSecrets {
        match sender {
            AuthenticationRole::Initiator => &mut self.initiator,
            AuthenticationRole::Responder => &mut self.responder,
        }
    }
}

impl Drop for HandshakeSecrets {
    fn drop(&mut self) {
        self.master_secret.fill(0);
    }
}

impl fmt::Debug for HandshakeSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandshakeSecrets")
            .field("suite", &self.suite)
            .field("initiator", &"<redacted>")
            .field("responder", &"<redacted>")
            .field("master_secret", &"<redacted>")
            .finish()
    }
}

/// Directional application traffic secrets at epoch zero.
pub struct ApplicationSecrets {
    initiator: [u8; HASH_LEN],
    responder: [u8; HASH_LEN],
}

impl ApplicationSecrets {
    #[must_use]
    pub const fn initiator(&self) -> &[u8; HASH_LEN] {
        &self.initiator
    }

    #[must_use]
    pub const fn responder(&self) -> &[u8; HASH_LEN] {
        &self.responder
    }
}

impl Drop for ApplicationSecrets {
    fn drop(&mut self) {
        self.initiator.fill(0);
        self.responder.fill(0);
    }
}

impl fmt::Debug for ApplicationSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApplicationSecrets(<redacted>)")
    }
}

/// Opened fixed authentication plaintext. Storage is cleared on drop.
pub struct OpenedIdentityAuth {
    storage: [u8; ENCRYPTED_IDENTITY_AUTH_LEN],
}

impl OpenedIdentityAuth {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.storage[..IDENTITY_AUTH_LEN]
    }

    /// Decodes the already size-checked plaintext.
    ///
    /// # Errors
    ///
    /// Returns an identity-auth codec error if its fixed invariant is broken.
    pub fn decode(&self) -> Result<IdentityAuth<'_>, crate::handshake::HandshakeError> {
        IdentityAuth::decode(self.as_bytes())
    }
}

impl Drop for OpenedIdentityAuth {
    fn drop(&mut self) {
        self.storage.fill(0);
    }
}

impl fmt::Debug for OpenedIdentityAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenedIdentityAuth(<redacted>)")
    }
}

/// Seals responder authentication for `RESPONSE` exactly once.
///
/// `pre_auth_hash` is both `TH_pre_auth` and the RESPONSE AEAD AAD.
///
/// # Errors
///
/// Returns an error for invalid plaintext/output, repeat sealing, provider
/// failure, length mismatch, or nonce construction failure.
pub fn seal_responder_identity_auth<P: HandshakeCryptoProvider>(
    provider: &P,
    secrets: &mut HandshakeSecrets,
    message_id: u32,
    pre_auth_hash: &Sha384Digest,
    plaintext: IdentityAuth<'_>,
    output: &mut [u8],
) -> Result<usize, HandshakeCryptoError<P::Error>> {
    seal_identity_auth(
        provider,
        secrets,
        AuthenticationRole::Responder,
        message_id,
        pre_auth_hash,
        plaintext,
        output,
    )
}

/// Seals initiator authentication for `FINISH` exactly once.
///
/// `initiator_signature_hash` is `TH_i_signature` and the FINISH AEAD AAD.
///
/// # Errors
///
/// Returns an error for invalid plaintext/output, repeat sealing, provider
/// failure, length mismatch, or nonce construction failure.
pub fn seal_initiator_identity_auth<P: HandshakeCryptoProvider>(
    provider: &P,
    secrets: &mut HandshakeSecrets,
    message_id: u32,
    initiator_signature_hash: &Sha384Digest,
    plaintext: IdentityAuth<'_>,
    output: &mut [u8],
) -> Result<usize, HandshakeCryptoError<P::Error>> {
    seal_identity_auth(
        provider,
        secrets,
        AuthenticationRole::Initiator,
        message_id,
        initiator_signature_hash,
        plaintext,
        output,
    )
}

/// Opens responder authentication from `RESPONSE` into fixed candidate storage.
///
/// # Errors
///
/// Returns an error for ciphertext size, invalid tag, provider/length failure,
/// or malformed opened plaintext.
pub fn open_responder_identity_auth<P: HandshakeCryptoProvider>(
    provider: &P,
    secrets: &HandshakeSecrets,
    message_id: u32,
    pre_auth_hash: &Sha384Digest,
    ciphertext: &[u8],
) -> Result<OpenedIdentityAuth, HandshakeCryptoError<P::Error>> {
    open_identity_auth(
        provider,
        secrets,
        AuthenticationRole::Responder,
        message_id,
        pre_auth_hash,
        ciphertext,
    )
}

/// Opens initiator authentication from `FINISH` into fixed candidate storage.
///
/// # Errors
///
/// Returns an error for ciphertext size, invalid tag, provider/length failure,
/// or malformed opened plaintext.
pub fn open_initiator_identity_auth<P: HandshakeCryptoProvider>(
    provider: &P,
    secrets: &HandshakeSecrets,
    message_id: u32,
    initiator_signature_hash: &Sha384Digest,
    ciphertext: &[u8],
) -> Result<OpenedIdentityAuth, HandshakeCryptoError<P::Error>> {
    open_identity_auth(
        provider,
        secrets,
        AuthenticationRole::Initiator,
        message_id,
        initiator_signature_hash,
        ciphertext,
    )
}

fn seal_identity_auth<P: HandshakeCryptoProvider>(
    provider: &P,
    secrets: &mut HandshakeSecrets,
    sender: AuthenticationRole,
    message_id: u32,
    aad: &Sha384Digest,
    plaintext: IdentityAuth<'_>,
    output: &mut [u8],
) -> Result<usize, HandshakeCryptoError<P::Error>> {
    if output.len() < ENCRYPTED_IDENTITY_AUTH_LEN {
        return Err(WireError::BufferTooSmall {
            needed: ENCRYPTED_IDENTITY_AUTH_LEN,
            available: output.len(),
        }
        .into());
    }
    if let Err(error) = plaintext.encode(&mut output[..IDENTITY_AUTH_LEN]) {
        output[..ENCRYPTED_IDENTITY_AUTH_LEN].fill(0);
        return Err(HandshakeCryptoError::Handshake(error));
    }
    let suite = secrets.suite;
    let direction = secrets.direction_mut(sender);
    if direction.seal_reserved {
        output[..ENCRYPTED_IDENTITY_AUTH_LEN].fill(0);
        return Err(HandshakeCryptoError::HandshakeCiphertextAlreadySealed(
            sender,
        ));
    }
    direction.seal_reserved = true;
    let nonce = handshake_nonce(&direction.aead_iv, message_id);
    let sealed = provider.seal_handshake_aead(
        suite,
        &direction.aead_key,
        &nonce,
        aad,
        &mut output[..ENCRYPTED_IDENTITY_AUTH_LEN],
        IDENTITY_AUTH_LEN,
    );
    let length = match sealed {
        Ok(length) => length,
        Err(error) => {
            output[..ENCRYPTED_IDENTITY_AUTH_LEN].fill(0);
            return Err(HandshakeCryptoError::Provider(error));
        }
    };
    if length != ENCRYPTED_IDENTITY_AUTH_LEN {
        output[..ENCRYPTED_IDENTITY_AUTH_LEN].fill(0);
        return Err(HandshakeCryptoError::ProviderLengthMismatch {
            expected: ENCRYPTED_IDENTITY_AUTH_LEN,
            actual: length,
        });
    }
    Ok(length)
}

fn open_identity_auth<P: HandshakeCryptoProvider>(
    provider: &P,
    secrets: &HandshakeSecrets,
    sender: AuthenticationRole,
    message_id: u32,
    aad: &Sha384Digest,
    ciphertext: &[u8],
) -> Result<OpenedIdentityAuth, HandshakeCryptoError<P::Error>> {
    if ciphertext.len() != ENCRYPTED_IDENTITY_AUTH_LEN {
        return Err(HandshakeCryptoError::InvalidCiphertextLength {
            expected: ENCRYPTED_IDENTITY_AUTH_LEN,
            actual: ciphertext.len(),
        });
    }
    let direction = secrets.direction(sender);
    let nonce = handshake_nonce(&direction.aead_iv, message_id);
    let mut candidate = OpenedIdentityAuth {
        storage: [0; ENCRYPTED_IDENTITY_AUTH_LEN],
    };
    candidate.storage.copy_from_slice(ciphertext);
    let opened = provider.open_handshake_aead(
        secrets.suite,
        &direction.aead_key,
        &nonce,
        aad,
        &mut candidate.storage,
    );
    let length = match opened {
        Ok(HandshakeAeadOpenResult::Opened(length)) => length,
        Ok(HandshakeAeadOpenResult::Invalid) => {
            return Err(HandshakeCryptoError::AuthenticationFailed);
        }
        Err(error) => return Err(HandshakeCryptoError::Provider(error)),
    };
    if length != IDENTITY_AUTH_LEN {
        return Err(HandshakeCryptoError::ProviderLengthMismatch {
            expected: IDENTITY_AUTH_LEN,
            actual: length,
        });
    }
    candidate.storage[IDENTITY_AUTH_LEN..].fill(0);
    IdentityAuth::decode(candidate.as_bytes()).map_err(HandshakeCryptoError::Handshake)?;
    Ok(candidate)
}

fn derive_hybrid_handshake_secrets<P: HandshakeCryptoProvider>(
    provider: &P,
    suite: CipherSuite,
    ml_kem: &SecretBytes<ML_KEM_SHARED_SECRET_LEN>,
    x25519: &SecretBytes<X25519_SHARED_SECRET_LEN>,
    pre_auth_hash: &Sha384Digest,
) -> Result<HandshakeSecrets, HandshakeCryptoError<P::Error>> {
    let mut hybrid = SecretBytes::<HYBRID_SHARED_SECRET_LEN>::zeroed();
    hybrid.0[..ML_KEM_SHARED_SECRET_LEN].copy_from_slice(ml_kem.as_array());
    hybrid.0[ML_KEM_SHARED_SECRET_LEN..].copy_from_slice(x25519.as_array());
    derive_handshake_secrets(provider, suite, hybrid.as_array(), pre_auth_hash)
}

fn derive_handshake_secrets<P: HandshakeCryptoProvider>(
    provider: &P,
    suite: CipherSuite,
    hybrid_shared_secret: &[u8; HYBRID_SHARED_SECRET_LEN],
    pre_auth_hash: &Sha384Digest,
) -> Result<HandshakeSecrets, HandshakeCryptoError<P::Error>> {
    let zero = [0_u8; HASH_LEN];
    let empty_hash = hash_empty(provider)?;
    let mut early_secret = SecretBytes::<HASH_LEN>::zeroed();
    provider
        .hkdf_extract_sha384(&zero, &zero, early_secret.as_mut_array())
        .map_err(HandshakeCryptoError::Provider)?;
    let mut derived_early = SecretBytes::<HASH_LEN>::zeroed();
    derive_secret(
        provider,
        early_secret.as_array(),
        LABEL_DERIVED,
        &empty_hash,
        derived_early.as_mut_array(),
    )?;
    let mut handshake_secret = SecretBytes::<HASH_LEN>::zeroed();
    provider
        .hkdf_extract_sha384(
            derived_early.as_array(),
            hybrid_shared_secret,
            handshake_secret.as_mut_array(),
        )
        .map_err(HandshakeCryptoError::Provider)?;

    let initiator = derive_direction(
        provider,
        handshake_secret.as_array(),
        LABEL_INITIATOR_HANDSHAKE,
        pre_auth_hash,
    )?;
    let responder = derive_direction(
        provider,
        handshake_secret.as_array(),
        LABEL_RESPONDER_HANDSHAKE,
        pre_auth_hash,
    )?;
    let mut derived_handshake = SecretBytes::<HASH_LEN>::zeroed();
    derive_secret(
        provider,
        handshake_secret.as_array(),
        LABEL_DERIVED,
        &empty_hash,
        derived_handshake.as_mut_array(),
    )?;
    let mut master_secret = SecretBytes::<HASH_LEN>::zeroed();
    provider
        .hkdf_extract_sha384(
            derived_handshake.as_array(),
            &zero,
            master_secret.as_mut_array(),
        )
        .map_err(HandshakeCryptoError::Provider)?;
    Ok(HandshakeSecrets {
        suite,
        initiator,
        responder,
        master_secret: master_secret.copy_out(),
    })
}

fn derive_direction<P: HandshakeCryptoProvider>(
    provider: &P,
    handshake_secret: &[u8; HASH_LEN],
    label: &str,
    pre_auth_hash: &Sha384Digest,
) -> Result<DirectionalHandshakeSecrets, HandshakeCryptoError<P::Error>> {
    let mut traffic = SecretBytes::<HASH_LEN>::zeroed();
    derive_secret(
        provider,
        handshake_secret,
        label,
        pre_auth_hash,
        traffic.as_mut_array(),
    )?;
    let mut finished = SecretBytes::<HASH_LEN>::zeroed();
    expand_label(
        provider,
        traffic.as_array(),
        LABEL_FINISHED,
        &[],
        finished.as_mut_array(),
    )?;
    let mut key = SecretBytes::<AEAD_KEY_LEN>::zeroed();
    expand_label(
        provider,
        traffic.as_array(),
        LABEL_KEY,
        &[],
        key.as_mut_array(),
    )?;
    let mut iv = SecretBytes::<AEAD_IV_LEN>::zeroed();
    expand_label(
        provider,
        traffic.as_array(),
        LABEL_IV,
        &[],
        iv.as_mut_array(),
    )?;
    Ok(DirectionalHandshakeSecrets {
        traffic_secret: traffic.copy_out(),
        finished_key: finished.copy_out(),
        aead_key: key.copy_out(),
        aead_iv: iv.copy_out(),
        seal_reserved: false,
    })
}

fn derive_secret<P: HandshakeCryptoProvider>(
    provider: &P,
    secret: &[u8; HASH_LEN],
    label: &str,
    transcript_hash: &Sha384Digest,
    output: &mut [u8; HASH_LEN],
) -> Result<(), HandshakeCryptoError<P::Error>> {
    expand_label(provider, secret, label, transcript_hash, output)
}

fn expand_label<P: HandshakeCryptoProvider>(
    provider: &P,
    secret: &[u8; HASH_LEN],
    label: &str,
    context: &[u8],
    output: &mut [u8],
) -> Result<(), HandshakeCryptoError<P::Error>> {
    let mut info = [0_u8; MAX_EXPAND_LABEL_LEN];
    let output_length = u16::try_from(output.len()).map_err(|_| LabelError::LengthOverflow)?;
    let written = encode_expand_label(output_length, label, context, &mut info)?;
    provider
        .hkdf_expand_sha384(secret, &info[..written], output)
        .map_err(HandshakeCryptoError::Provider)
}

fn hash_empty<P: Sha384Provider>(
    provider: &P,
) -> Result<Sha384Digest, HandshakeCryptoError<P::Error>> {
    let context = provider
        .start_sha384()
        .map_err(HandshakeCryptoError::Provider)?;
    provider
        .finish_sha384(context)
        .map_err(HandshakeCryptoError::Provider)
}

fn reject_all_zero_x25519<E>(
    shared_secret: &[u8; X25519_SHARED_SECRET_LEN],
) -> Result<(), HandshakeCryptoError<E>> {
    let non_zero = shared_secret
        .iter()
        .copied()
        .fold(0_u8, |accumulator, byte| accumulator | byte);
    if non_zero == 0 {
        return Err(HandshakeCryptoError::AllZeroX25519SharedSecret);
    }
    Ok(())
}

/// Forms `IV XOR left_pad_96(message_id)` for RESPONSE or FINISH.
#[must_use]
pub fn handshake_nonce(iv: &[u8; AEAD_IV_LEN], message_id: u32) -> [u8; AEAD_IV_LEN] {
    let mut nonce = *iv;
    for (target, source) in nonce[AEAD_IV_LEN - 4..]
        .iter_mut()
        .zip(message_id.to_be_bytes())
    {
        *target ^= source;
    }
    nonce
}

/// Hybrid key-exchange, KDF, or handshake-AEAD failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandshakeCryptoError<E> {
    Wire(WireError),
    Handshake(crate::handshake::HandshakeError),
    Label(LabelError),
    Provider(E),
    AllZeroX25519SharedSecret,
    HandshakeCiphertextAlreadySealed(AuthenticationRole),
    InvalidCiphertextLength { expected: usize, actual: usize },
    AuthenticationFailed,
    ProviderLengthMismatch { expected: usize, actual: usize },
}

impl<E> From<WireError> for HandshakeCryptoError<E> {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl<E> From<LabelError> for HandshakeCryptoError<E> {
    fn from(error: LabelError) -> Self {
        Self::Label(error)
    }
}

impl<E: fmt::Display> fmt::Display for HandshakeCryptoError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => error.fmt(formatter),
            Self::Handshake(error) => error.fmt(formatter),
            Self::Label(error) => error.fmt(formatter),
            Self::Provider(error) => {
                write!(formatter, "handshake crypto provider failure: {error}")
            }
            Self::AllZeroX25519SharedSecret => formatter.write_str("all-zero X25519 shared secret"),
            Self::HandshakeCiphertextAlreadySealed(role) => {
                write!(formatter, "{role:?} handshake ciphertext already sealed")
            }
            Self::InvalidCiphertextLength { expected, actual } => write!(
                formatter,
                "invalid handshake ciphertext length: expected {expected}, got {actual}"
            ),
            Self::AuthenticationFailed => {
                formatter.write_str("handshake AEAD authentication failed")
            }
            Self::ProviderLengthMismatch { expected, actual } => write!(
                formatter,
                "handshake crypto provider length mismatch: expected {expected}, got {actual}"
            ),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for HandshakeCryptoError<E> {}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha384};

    use super::*;
    use crate::crypto::SHA384_OUTPUT_LEN;
    use crate::handshake::{
        ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN, FINISHED_MAC_LEN, ML_DSA_65_PUBLIC_KEY_LEN,
        ML_DSA_65_SIGNATURE_LEN,
    };
    use crate::transcript::TranscriptSink;

    type HmacSha384 = Hmac<Sha384>;

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
        next_x25519: Cell<u8>,
        zero_x25519: Cell<bool>,
        fail_seal: Cell<bool>,
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

    impl HandshakeCryptoProvider for TestProvider {
        type X25519PrivateKey = [u8; X25519_PUBLIC_KEY_LEN];
        type MlKem768DecapsulationKey = u8;

        fn generate_x25519_key_pair(
            &self,
            public_key: &mut [u8; X25519_PUBLIC_KEY_LEN],
        ) -> Result<Self::X25519PrivateKey, Self::Error> {
            let seed = self.next_x25519.get().wrapping_add(1);
            self.next_x25519.set(seed);
            public_key.fill(seed);
            Ok(*public_key)
        }

        fn x25519_shared_secret(
            &self,
            private_key: &Self::X25519PrivateKey,
            peer_public_key: &[u8; X25519_PUBLIC_KEY_LEN],
            output: &mut [u8; X25519_SHARED_SECRET_LEN],
        ) -> Result<(), Self::Error> {
            if self.zero_x25519.get() {
                output.fill(0);
            } else {
                for ((result, private), peer) in
                    output.iter_mut().zip(private_key).zip(peer_public_key)
                {
                    *result = *private ^ *peer;
                }
            }
            Ok(())
        }

        fn generate_ml_kem_768_key_pair(
            &self,
            encapsulation_key: &mut [u8; ML_KEM_768_ENCAPSULATION_KEY_LEN],
        ) -> Result<Self::MlKem768DecapsulationKey, Self::Error> {
            encapsulation_key.fill(0x31);
            Ok(0x31)
        }

        fn encapsulate_ml_kem_768(
            &self,
            encapsulation_key: &[u8; ML_KEM_768_ENCAPSULATION_KEY_LEN],
            ciphertext: &mut [u8; ML_KEM_768_CIPHERTEXT_LEN],
            shared_secret: &mut [u8; ML_KEM_SHARED_SECRET_LEN],
        ) -> Result<(), Self::Error> {
            ciphertext.fill(encapsulation_key[0] ^ 0x5a);
            ml_kem_test_secret(encapsulation_key[0], ciphertext, shared_secret);
            Ok(())
        }

        fn decapsulate_ml_kem_768(
            &self,
            decapsulation_key: &Self::MlKem768DecapsulationKey,
            ciphertext: &[u8; ML_KEM_768_CIPHERTEXT_LEN],
            shared_secret: &mut [u8; ML_KEM_SHARED_SECRET_LEN],
        ) -> Result<(), Self::Error> {
            ml_kem_test_secret(*decapsulation_key, ciphertext, shared_secret);
            Ok(())
        }

        fn hkdf_extract_sha384(
            &self,
            salt: &[u8; HASH_LEN],
            input_key_material: &[u8],
            output: &mut [u8; HASH_LEN],
        ) -> Result<(), Self::Error> {
            let mut mac = HmacSha384::new_from_slice(salt).expect("HMAC key");
            mac.update(input_key_material);
            output.copy_from_slice(&mac.finalize().into_bytes());
            Ok(())
        }

        fn hkdf_expand_sha384(
            &self,
            pseudorandom_key: &[u8; HASH_LEN],
            info: &[u8],
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            let mut previous = [0_u8; HASH_LEN];
            let mut previous_length = 0;
            let mut written = 0;
            let mut counter = 1_u8;
            while written < output.len() {
                let mut mac =
                    HmacSha384::new_from_slice(pseudorandom_key).expect("HKDF pseudorandom key");
                mac.update(&previous[..previous_length]);
                mac.update(info);
                mac.update(&[counter]);
                previous.copy_from_slice(&mac.finalize().into_bytes());
                previous_length = HASH_LEN;
                let take = (output.len() - written).min(HASH_LEN);
                output[written..written + take].copy_from_slice(&previous[..take]);
                written += take;
                counter = counter.checked_add(1).expect("bounded test output");
            }
            previous.fill(0);
            Ok(())
        }

        fn hmac_sha384(
            &self,
            key: &[u8; HASH_LEN],
            message: &[u8],
            output: &mut [u8; HASH_LEN],
        ) -> Result<(), Self::Error> {
            let mut mac = HmacSha384::new_from_slice(key).expect("HMAC key");
            mac.update(message);
            output.copy_from_slice(&mac.finalize().into_bytes());
            Ok(())
        }

        fn seal_handshake_aead(
            &self,
            _suite: CipherSuite,
            key: &[u8; AEAD_KEY_LEN],
            nonce: &[u8; AEAD_IV_LEN],
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
            let tag = aead_test_tag(
                key,
                nonce,
                additional_data,
                &plaintext_and_tag[..plaintext_length],
            );
            plaintext_and_tag[plaintext_length..plaintext_length + 16].copy_from_slice(&tag);
            if self.wrong_seal_length.replace(false) {
                Ok(plaintext_length)
            } else {
                Ok(plaintext_length + 16)
            }
        }

        fn open_handshake_aead(
            &self,
            _suite: CipherSuite,
            key: &[u8; AEAD_KEY_LEN],
            nonce: &[u8; AEAD_IV_LEN],
            additional_data: &[u8],
            ciphertext_and_tag: &mut [u8],
        ) -> Result<HandshakeAeadOpenResult, Self::Error> {
            let Some(plaintext_length) = ciphertext_and_tag.len().checked_sub(16) else {
                return Ok(HandshakeAeadOpenResult::Invalid);
            };
            let expected = aead_test_tag(
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
                return Ok(HandshakeAeadOpenResult::Invalid);
            }
            for (index, byte) in ciphertext_and_tag[..plaintext_length]
                .iter_mut()
                .enumerate()
            {
                *byte ^= key[index % key.len()] ^ nonce[index % nonce.len()];
            }
            if self.wrong_open_length.replace(false) {
                Ok(HandshakeAeadOpenResult::Opened(plaintext_length - 1))
            } else {
                Ok(HandshakeAeadOpenResult::Opened(plaintext_length))
            }
        }
    }

    fn ml_kem_test_secret(
        key_seed: u8,
        ciphertext: &[u8; ML_KEM_768_CIPHERTEXT_LEN],
        output: &mut [u8; ML_KEM_SHARED_SECRET_LEN],
    ) {
        let mut hash = Sha384::new();
        hash.update([key_seed]);
        hash.update(ciphertext);
        output.copy_from_slice(&hash.finalize()[..ML_KEM_SHARED_SECRET_LEN]);
    }

    fn aead_test_tag(
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; AEAD_IV_LEN],
        additional_data: &[u8],
        ciphertext: &[u8],
    ) -> [u8; 16] {
        let mut hash = Sha384::new();
        hash.update(key);
        hash.update(nonce);
        hash.update(additional_data);
        hash.update(ciphertext);
        hash.finalize()[..16].try_into().expect("fixed tag")
    }

    struct IdentityAuthFixture {
        seed: u8,
        ml_dsa_public_key: [u8; ML_DSA_65_PUBLIC_KEY_LEN],
        ml_dsa_signature: [u8; ML_DSA_65_SIGNATURE_LEN],
    }

    impl IdentityAuthFixture {
        fn new(seed: u8) -> Self {
            Self {
                seed,
                ml_dsa_public_key: [seed.wrapping_add(1); ML_DSA_65_PUBLIC_KEY_LEN],
                ml_dsa_signature: [seed.wrapping_add(3); ML_DSA_65_SIGNATURE_LEN],
            }
        }

        fn value(&self) -> IdentityAuth<'_> {
            IdentityAuth {
                ed25519_public_key: [self.seed; ED25519_PUBLIC_KEY_LEN],
                ml_dsa_public_key: &self.ml_dsa_public_key,
                ed25519_signature: [self.seed.wrapping_add(2); ED25519_SIGNATURE_LEN],
                ml_dsa_signature: &self.ml_dsa_signature,
                finished_mac: [self.seed.wrapping_add(4); FINISHED_MAC_LEN],
            }
        }
    }

    fn hybrid_pair(provider: &TestProvider) -> (HandshakeSecrets, HandshakeSecrets, Sha384Digest) {
        let pre_auth_hash = [0xa5; SHA384_OUTPUT_LEN];
        let initiator = generate_initiator_hybrid_state(provider).expect("initiator key share");
        let initiator_x25519 = *initiator.x25519_public_key();
        let initiator_ml_kem = *initiator.ml_kem_encapsulation_key();
        let responder = respond_to_initiator(
            provider,
            CipherSuite::Aes256GcmSha384,
            &initiator_x25519,
            &initiator_ml_kem,
            &pre_auth_hash,
        )
        .expect("responder key exchange");
        let responder_x25519 = *responder.x25519_public_key();
        let ciphertext = *responder.ml_kem_ciphertext();
        let initiator_secrets = initiator
            .complete(
                provider,
                CipherSuite::Aes256GcmSha384,
                &responder_x25519,
                &ciphertext,
                &pre_auth_hash,
            )
            .expect("initiator key exchange");
        (initiator_secrets, responder.into_secrets(), pre_auth_hash)
    }

    #[test]
    fn both_hybrid_sides_install_identical_directional_secrets() {
        let provider = TestProvider::default();
        let (initiator, responder, hash) = hybrid_pair(&provider);
        assert_eq!(
            initiator.initiator.traffic_secret,
            responder.initiator.traffic_secret
        );
        assert_eq!(
            initiator.responder.traffic_secret,
            responder.responder.traffic_secret
        );
        assert_eq!(initiator.master_secret, responder.master_secret);
        assert_eq!(
            initiator
                .compute_finished(&provider, AuthenticationRole::Responder, &hash)
                .expect("Finished"),
            responder
                .compute_finished(&provider, AuthenticationRole::Responder, &hash)
                .expect("Finished")
        );
        let debug = format!("{initiator:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("165, 165"));
    }

    #[test]
    fn responder_and_initiator_auth_ciphertexts_use_directional_keys() {
        let provider = TestProvider::default();
        let (mut initiator, mut responder, pre_auth_hash) = hybrid_pair(&provider);
        let responder_fixture = IdentityAuthFixture::new(0x41);
        let responder_auth = responder_fixture.value();
        let mut response_ciphertext = [0_u8; ENCRYPTED_IDENTITY_AUTH_LEN];
        assert_eq!(
            seal_responder_identity_auth(
                &provider,
                &mut responder,
                7,
                &pre_auth_hash,
                responder_auth,
                &mut response_ciphertext,
            ),
            Ok(ENCRYPTED_IDENTITY_AUTH_LEN)
        );
        let opened = open_responder_identity_auth(
            &provider,
            &initiator,
            7,
            &pre_auth_hash,
            &response_ciphertext,
        )
        .expect("responder auth opens");
        assert_eq!(opened.decode().expect("identity auth"), responder_auth);
        assert!(format!("{opened:?}").contains("<redacted>"));

        let initiator_signature_hash = [0xb6; SHA384_OUTPUT_LEN];
        let initiator_fixture = IdentityAuthFixture::new(0x51);
        let initiator_auth = initiator_fixture.value();
        let mut finish_ciphertext = [0_u8; ENCRYPTED_IDENTITY_AUTH_LEN];
        seal_initiator_identity_auth(
            &provider,
            &mut initiator,
            8,
            &initiator_signature_hash,
            initiator_auth,
            &mut finish_ciphertext,
        )
        .expect("initiator auth seals");
        let opened = open_initiator_identity_auth(
            &provider,
            &responder,
            8,
            &initiator_signature_hash,
            &finish_ciphertext,
        )
        .expect("initiator auth opens");
        assert_eq!(opened.decode().expect("identity auth"), initiator_auth);
    }

    #[test]
    fn aead_tampering_role_snapshot_and_reseal_fail_closed() {
        let provider = TestProvider::default();
        let (initiator, mut responder, pre_auth_hash) = hybrid_pair(&provider);
        let fixture = IdentityAuthFixture::new(0x61);
        let auth = fixture.value();
        let mut ciphertext = [0_u8; ENCRYPTED_IDENTITY_AUTH_LEN];
        seal_responder_identity_auth(
            &provider,
            &mut responder,
            9,
            &pre_auth_hash,
            auth,
            &mut ciphertext,
        )
        .expect("seals");

        let mut tampered = ciphertext;
        tampered[100] ^= 1;
        assert!(matches!(
            open_responder_identity_auth(&provider, &initiator, 9, &pre_auth_hash, &tampered),
            Err(HandshakeCryptoError::AuthenticationFailed)
        ));
        let wrong_hash = [0x77; SHA384_OUTPUT_LEN];
        assert!(matches!(
            open_responder_identity_auth(&provider, &initiator, 9, &wrong_hash, &ciphertext),
            Err(HandshakeCryptoError::AuthenticationFailed)
        ));
        assert!(matches!(
            open_initiator_identity_auth(&provider, &initiator, 9, &pre_auth_hash, &ciphertext),
            Err(HandshakeCryptoError::AuthenticationFailed)
        ));

        let mut repeated_output = [0xa5; ENCRYPTED_IDENTITY_AUTH_LEN];
        assert_eq!(
            seal_responder_identity_auth(
                &provider,
                &mut responder,
                9,
                &pre_auth_hash,
                auth,
                &mut repeated_output,
            ),
            Err(HandshakeCryptoError::HandshakeCiphertextAlreadySealed(
                AuthenticationRole::Responder
            ))
        );
        assert!(repeated_output.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn provider_seal_failure_consumes_direction_and_clears_output() {
        let provider = TestProvider::default();
        let (_, mut responder, hash) = hybrid_pair(&provider);
        let fixture = IdentityAuthFixture::new(0x71);
        let auth = fixture.value();
        provider.fail_seal.set(true);
        let mut output = [0xa5; ENCRYPTED_IDENTITY_AUTH_LEN];
        assert_eq!(
            seal_responder_identity_auth(&provider, &mut responder, 10, &hash, auth, &mut output,),
            Err(HandshakeCryptoError::Provider(TestProviderError))
        );
        assert!(output.iter().all(|byte| *byte == 0));
        assert!(matches!(
            seal_responder_identity_auth(&provider, &mut responder, 10, &hash, auth, &mut output,),
            Err(HandshakeCryptoError::HandshakeCiphertextAlreadySealed(_))
        ));
    }

    #[test]
    fn provider_lengths_are_checked_without_exposing_plaintext() {
        let provider = TestProvider::default();
        let (_initiator, mut responder, hash) = hybrid_pair(&provider);
        let fixture = IdentityAuthFixture::new(0x81);
        let auth = fixture.value();
        provider.wrong_seal_length.set(true);
        let mut output = [0xa5; ENCRYPTED_IDENTITY_AUTH_LEN];
        assert_eq!(
            seal_responder_identity_auth(&provider, &mut responder, 11, &hash, auth, &mut output,),
            Err(HandshakeCryptoError::ProviderLengthMismatch {
                expected: ENCRYPTED_IDENTITY_AUTH_LEN,
                actual: IDENTITY_AUTH_LEN,
            })
        );
        assert!(output.iter().all(|byte| *byte == 0));

        let (initiator, mut responder, _) = hybrid_pair(&provider);
        seal_responder_identity_auth(&provider, &mut responder, 12, &hash, auth, &mut output)
            .expect("valid seal");
        provider.wrong_open_length.set(true);
        assert!(matches!(
            open_responder_identity_auth(&provider, &initiator, 12, &hash, &output),
            Err(HandshakeCryptoError::ProviderLengthMismatch {
                expected,
                actual,
            }) if expected == IDENTITY_AUTH_LEN && actual == IDENTITY_AUTH_LEN - 1
        ));
    }

    #[test]
    fn all_zero_x25519_output_is_rejected() {
        let provider = TestProvider::default();
        let initiator = generate_initiator_hybrid_state(&provider).expect("initiator");
        provider.zero_x25519.set(true);
        assert!(matches!(
            respond_to_initiator(
                &provider,
                CipherSuite::Aes256GcmSha384,
                initiator.x25519_public_key(),
                initiator.ml_kem_encapsulation_key(),
                &[0x55; SHA384_OUTPUT_LEN],
            ),
            Err(HandshakeCryptoError::AllZeroX25519SharedSecret)
        ));
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII"), 16).expect("hex")
            })
            .collect()
    }

    fn vector(name: &str) -> Vec<u8> {
        let prefix = format!("{name}=");
        let encoded = include_str!("../test-vectors/kdf-sha384-v1.txt")
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .unwrap_or_else(|| panic!("missing vector {name}"));
        decode_hex(encoded)
    }

    #[test]
    fn installed_schedule_matches_the_published_kdf_vector() {
        let provider = TestProvider::default();
        let hybrid: [u8; HYBRID_SHARED_SECRET_LEN] =
            vector("hybrid").try_into().expect("hybrid vector length");
        let pre_auth: Sha384Digest = vector("pre_auth_hash")
            .try_into()
            .expect("hash vector length");
        let secrets =
            derive_handshake_secrets(&provider, CipherSuite::Aes256GcmSha384, &hybrid, &pre_auth)
                .expect("schedule");
        assert_eq!(secrets.initiator.traffic_secret, vector("i_hs")[..]);
        assert_eq!(secrets.responder.traffic_secret, vector("r_hs")[..]);
        assert_eq!(secrets.initiator.finished_key, vector("i_finished_key")[..]);
        assert_eq!(secrets.responder.finished_key, vector("r_finished_key")[..]);
        assert_eq!(secrets.initiator.aead_key, vector("i_handshake_key")[..]);
        assert_eq!(secrets.initiator.aead_iv, vector("i_handshake_iv")[..]);
        assert_eq!(secrets.responder.aead_key, vector("r_handshake_key")[..]);
        assert_eq!(secrets.responder.aead_iv, vector("r_handshake_iv")[..]);
        let full_hash: Sha384Digest = vector("full_hash").try_into().expect("hash vector length");
        let application = secrets
            .derive_application_secrets(
                &provider,
                &InitiatorTranscriptMilestone::for_test(full_hash),
                &AuthenticatedIdentity::for_test(),
            )
            .expect("application secrets");
        assert_eq!(
            application.initiator().as_slice(),
            vector("i_ap").as_slice()
        );
        assert_eq!(
            application.responder().as_slice(),
            vector("r_ap").as_slice()
        );
    }

    #[test]
    fn handshake_nonce_xors_only_the_low_four_bytes() {
        let iv = [0xa5; AEAD_IV_LEN];
        let nonce = handshake_nonce(&iv, 0x0102_0304);
        assert_eq!(&nonce[..8], &[0xa5; 8]);
        assert_eq!(&nonce[8..], &[0xa4, 0xa7, 0xa6, 0xa1]);
    }
}
