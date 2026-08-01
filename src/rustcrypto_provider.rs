//! Feature-gated `RustCrypto` handshake and authentication provider.
//!
//! This module supplies a concrete software implementation of
//! [`HandshakeCryptoProvider`] and hybrid Ed25519 + ML-DSA-65 identity
//! authentication.
//! It is intended for interoperability, testing, and further review. Enabling
//! it does not make an OGTP deployment production-ready: the selected ML-KEM
//! and ML-DSA implementations currently document that they have not received
//! an independent audit.

use core::fmt;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce, Tag as AesTag};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce, Tag as ChaChaTag};
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as _, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
};
use getrandom::SysRng;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ml_dsa::{
    Keypair as _, MlDsa65, Seed as MlDsaSeed, Signature as MlDsaSignature,
    SigningKey as MlDsaSigningKey, Verifier as _, VerifyingKey as MlDsaVerifyingKey,
};
use ml_kem::kem::{Decapsulate, KeyExport, TryKeyInit};
use ml_kem::ml_kem_768::{
    Ciphertext as MlKem768Ciphertext, DecapsulationKey as MlKem768DecapsulationKey,
    EncapsulationKey as MlKem768EncapsulationKey,
};
use ml_kem::{B32, Seed};
use sha2::{Digest, Sha384};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519PrivateKey};
use zeroize::{Zeroize, Zeroizing};

use crate::authentication::{
    HybridAuthenticationProvider, VerificationResult, handshake_signature_input,
    identity_fingerprint, manifest_signature_input,
};
use crate::crypto::{ForkableSha384Provider, SHA384_OUTPUT_LEN, Sha384Digest, Sha384Provider};
use crate::handshake::{
    CipherSuite, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN, FINISHED_MAC_LEN,
    IDENTITY_FINGERPRINT_LEN, ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN,
    ML_KEM_768_CIPHERTEXT_LEN, ML_KEM_768_ENCAPSULATION_KEY_LEN, ML_KEM_SHARED_SECRET_LEN,
    X25519_PUBLIC_KEY_LEN, X25519_SHARED_SECRET_LEN,
};
use crate::handshake_crypto::{HandshakeAeadOpenResult, HandshakeCryptoProvider};
use crate::kdf::{AEAD_IV_LEN, AEAD_KEY_LEN, HASH_LEN};
use crate::transcript::{AuthenticationRole, TranscriptSink};
use crate::wire::AEAD_TAG_LEN;

const ML_KEM_SEED_LEN: usize = 64;
const ML_KEM_ENCAPSULATION_RANDOMNESS_LEN: usize = 32;
/// Seed length used by each identity signature algorithm.
pub const IDENTITY_SEED_LEN: usize = 32;

/// RustCrypto-backed SHA-384 running context.
#[derive(Clone)]
pub struct RustCryptoSha384Context(Sha384);

impl fmt::Debug for RustCryptoSha384Context {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RustCryptoSha384Context(<redacted>)")
    }
}

impl TranscriptSink for RustCryptoSha384Context {
    fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
}

/// Concrete software provider for the OGTP hybrid handshake.
#[derive(Clone, Copy, Debug, Default)]
pub struct RustCryptoHandshakeProvider;

/// Preferred name for the complete handshake and authentication provider.
pub type RustCryptoProvider = RustCryptoHandshakeProvider;

/// Failure reported by [`RustCryptoHandshakeProvider`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RustCryptoProviderError {
    /// The operating system could not supply cryptographic entropy.
    EntropyUnavailable,
    /// A peer supplied a non-canonical ML-KEM-768 encapsulation key.
    InvalidMlKemEncapsulationKey,
    /// HKDF rejected an input or output length.
    HkdfFailure,
    /// HMAC rejected an input or failed internally.
    HmacFailure,
    /// A canonical contextualized signature message exceeded its fixed bound.
    SignatureInputOverflow,
    /// Ed25519 could not produce a signature.
    Ed25519SigningFailure,
    /// Randomized ML-DSA-65 signing failed, including entropy failure.
    MlDsa65SigningFailure,
    /// An AEAD operation failed for a reason other than an invalid tag.
    AeadFailure,
}

impl fmt::Display for RustCryptoProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EntropyUnavailable => formatter.write_str("operating-system entropy unavailable"),
            Self::InvalidMlKemEncapsulationKey => {
                formatter.write_str("invalid ML-KEM-768 encapsulation key")
            }
            Self::HkdfFailure => formatter.write_str("HKDF-SHA-384 failure"),
            Self::HmacFailure => formatter.write_str("HMAC-SHA-384 failure"),
            Self::SignatureInputOverflow => {
                formatter.write_str("contextualized signature input overflow")
            }
            Self::Ed25519SigningFailure => formatter.write_str("Ed25519 signing failure"),
            Self::MlDsa65SigningFailure => formatter.write_str("ML-DSA-65 signing failure"),
            Self::AeadFailure => formatter.write_str("handshake AEAD failure"),
        }
    }
}

impl std::error::Error for RustCryptoProviderError {}

/// Fixed-size pair of ordinary Ed25519 and ML-DSA-65 signatures.
pub struct RustCryptoHybridSignature {
    ed25519: [u8; ED25519_SIGNATURE_LEN],
    ml_dsa_65: [u8; ML_DSA_65_SIGNATURE_LEN],
}

impl RustCryptoHybridSignature {
    /// Returns the Ed25519 signature bytes.
    #[must_use]
    pub const fn ed25519(&self) -> &[u8; ED25519_SIGNATURE_LEN] {
        &self.ed25519
    }

    /// Returns the ML-DSA-65 signature bytes.
    #[must_use]
    pub const fn ml_dsa_65(&self) -> &[u8; ML_DSA_65_SIGNATURE_LEN] {
        &self.ml_dsa_65
    }

    /// Consumes the value and returns both fixed-size signature arrays.
    #[must_use]
    pub fn into_parts(self) -> ([u8; ED25519_SIGNATURE_LEN], [u8; ML_DSA_65_SIGNATURE_LEN]) {
        (self.ed25519, self.ml_dsa_65)
    }
}

impl fmt::Debug for RustCryptoHybridSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RustCryptoHybridSignature(<redacted>)")
    }
}

/// Non-cloneable sender identity containing both signature private keys.
///
/// The ML-DSA expanded key is retained to avoid repeating expensive key
/// expansion for every handshake or manifest. The type is fixed-size and does
/// not allocate when `ml-dsa` is built with OGTP's selected feature set.
pub struct RustCryptoIdentityKeyPair {
    ed25519: Ed25519SigningKey,
    ml_dsa_65: MlDsaSigningKey<MlDsa65>,
    ml_dsa_65_public_key: [u8; ML_DSA_65_PUBLIC_KEY_LEN],
}

impl RustCryptoIdentityKeyPair {
    /// Generates independent Ed25519 and ML-DSA-65 keys from operating-system
    /// entropy.
    ///
    /// # Errors
    ///
    /// Returns [`RustCryptoProviderError::EntropyUnavailable`] without
    /// constructing a partial identity if either seed cannot be filled.
    pub fn generate() -> Result<Self, RustCryptoProviderError> {
        let mut ed25519_seed = Zeroizing::new([0_u8; IDENTITY_SEED_LEN]);
        let mut ml_dsa_65_seed = Zeroizing::new([0_u8; IDENTITY_SEED_LEN]);
        fill_entropy(&mut ed25519_seed[..])?;
        fill_entropy(&mut ml_dsa_65_seed[..])?;
        Ok(Self::from_seed_bytes(&ed25519_seed, &ml_dsa_65_seed))
    }

    /// Reconstructs an identity from independent 32-byte algorithm seeds.
    ///
    /// The caller remains responsible for protecting and zeroizing the source
    /// seed buffers. This type does not expose seed export.
    #[must_use]
    pub fn from_seed_bytes(
        ed25519_seed: &[u8; IDENTITY_SEED_LEN],
        ml_dsa_65_seed: &[u8; IDENTITY_SEED_LEN],
    ) -> Self {
        let ed25519 = Ed25519SigningKey::from_bytes(ed25519_seed);
        let mut encoded_ml_dsa_65_seed = MlDsaSeed::from(*ml_dsa_65_seed);
        let ml_dsa_65 = MlDsaSigningKey::<MlDsa65>::from_seed(&encoded_ml_dsa_65_seed);
        encoded_ml_dsa_65_seed.as_mut_slice().zeroize();
        let encoded_public_key = ml_dsa_65.verifying_key().encode();
        let mut ml_dsa_65_public_key = [0_u8; ML_DSA_65_PUBLIC_KEY_LEN];
        ml_dsa_65_public_key.copy_from_slice(encoded_public_key.as_slice());
        Self {
            ed25519,
            ml_dsa_65,
            ml_dsa_65_public_key,
        }
    }

    /// Returns the Ed25519 public key.
    #[must_use]
    pub fn ed25519_public_key(&self) -> [u8; ED25519_PUBLIC_KEY_LEN] {
        self.ed25519.verifying_key().to_bytes()
    }

    /// Returns the ML-DSA-65 public key.
    #[must_use]
    pub const fn ml_dsa_65_public_key(&self) -> &[u8; ML_DSA_65_PUBLIC_KEY_LEN] {
        &self.ml_dsa_65_public_key
    }

    /// Computes the canonical hybrid identity fingerprint.
    ///
    /// # Errors
    ///
    /// Returns the selected SHA-384 provider's error.
    pub fn fingerprint<P: Sha384Provider>(
        &self,
        provider: &P,
    ) -> Result<[u8; IDENTITY_FINGERPRINT_LEN], P::Error> {
        identity_fingerprint(
            provider,
            &self.ed25519_public_key(),
            &self.ml_dsa_65_public_key,
        )
    }

    /// Signs the canonical handshake authentication message for `role`.
    ///
    /// ML-DSA uses its randomized FIPS 204 mode and requests fresh operating-
    /// system entropy for every call.
    ///
    /// # Errors
    ///
    /// Returns an error for contextualization overflow, Ed25519 failure, or
    /// ML-DSA-65 signing and entropy failure.
    pub fn sign_handshake(
        &self,
        role: AuthenticationRole,
        transcript_hash: &[u8; SHA384_OUTPUT_LEN],
    ) -> Result<RustCryptoHybridSignature, RustCryptoProviderError> {
        let input = handshake_signature_input(role, transcript_hash)
            .ok_or(RustCryptoProviderError::SignatureInputOverflow)?;
        self.sign_contextualized(input.as_bytes())
    }

    /// Hashes and signs the exact canonical unsigned manifest bytes.
    ///
    /// ML-DSA uses its randomized FIPS 204 mode and requests fresh operating-
    /// system entropy for every call.
    ///
    /// # Errors
    ///
    /// Returns an error for contextualization overflow, Ed25519 failure, or
    /// ML-DSA-65 signing and entropy failure.
    pub fn sign_manifest(
        &self,
        unsigned_manifest: &[u8],
    ) -> Result<RustCryptoHybridSignature, RustCryptoProviderError> {
        let manifest_hash: Sha384Digest = Sha384::digest(unsigned_manifest).into();
        let input = manifest_signature_input(&manifest_hash)
            .ok_or(RustCryptoProviderError::SignatureInputOverflow)?;
        self.sign_contextualized(input.as_bytes())
    }

    fn sign_contextualized(
        &self,
        message: &[u8],
    ) -> Result<RustCryptoHybridSignature, RustCryptoProviderError> {
        let ed25519: Ed25519Signature = self
            .ed25519
            .try_sign(message)
            .map_err(|_| RustCryptoProviderError::Ed25519SigningFailure)?;
        let ml_dsa_65 = self
            .ml_dsa_65
            .expanded_key()
            .sign_randomized(message, &[], &mut SysRng)
            .map_err(|_| RustCryptoProviderError::MlDsa65SigningFailure)?;
        let encoded_ml_dsa_65 = ml_dsa_65.encode();
        let mut ml_dsa_65_bytes = [0_u8; ML_DSA_65_SIGNATURE_LEN];
        ml_dsa_65_bytes.copy_from_slice(encoded_ml_dsa_65.as_slice());
        Ok(RustCryptoHybridSignature {
            ed25519: ed25519.to_bytes(),
            ml_dsa_65: ml_dsa_65_bytes,
        })
    }
}

impl fmt::Debug for RustCryptoIdentityKeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RustCryptoIdentityKeyPair(<redacted>)")
    }
}

impl Sha384Provider for RustCryptoHandshakeProvider {
    type Context = RustCryptoSha384Context;
    type Error = RustCryptoProviderError;

    fn start_sha384(&self) -> Result<Self::Context, Self::Error> {
        Ok(RustCryptoSha384Context(Sha384::new()))
    }

    fn finish_sha384(&self, context: Self::Context) -> Result<Sha384Digest, Self::Error> {
        Ok(context.0.finalize().into())
    }
}

impl ForkableSha384Provider for RustCryptoHandshakeProvider {
    fn fork_sha384(&self, context: &Self::Context) -> Result<Self::Context, Self::Error> {
        Ok(context.clone())
    }
}

impl HybridAuthenticationProvider for RustCryptoHandshakeProvider {
    type VerificationError = RustCryptoProviderError;

    fn verify_hmac_sha384(
        &self,
        key: &[u8; FINISHED_MAC_LEN],
        transcript_hash: &[u8; SHA384_OUTPUT_LEN],
        received_mac: &[u8; FINISHED_MAC_LEN],
    ) -> Result<VerificationResult, Self::VerificationError> {
        let mut hmac = <Hmac<Sha384> as Mac>::new_from_slice(key)
            .map_err(|_| RustCryptoProviderError::HmacFailure)?;
        hmac.update(transcript_hash);
        Ok(if hmac.verify_slice(received_mac).is_ok() {
            VerificationResult::Valid
        } else {
            VerificationResult::Invalid
        })
    }

    fn verify_ed25519(
        &self,
        public_key: &[u8; ED25519_PUBLIC_KEY_LEN],
        message: &[u8],
        signature: &[u8; ED25519_SIGNATURE_LEN],
    ) -> Result<VerificationResult, Self::VerificationError> {
        let Ok(public_key) = Ed25519VerifyingKey::from_bytes(public_key) else {
            return Ok(VerificationResult::Invalid);
        };
        let signature = Ed25519Signature::from_bytes(signature);
        Ok(if public_key.verify_strict(message, &signature).is_ok() {
            VerificationResult::Valid
        } else {
            VerificationResult::Invalid
        })
    }

    fn verify_ml_dsa_65(
        &self,
        public_key: &[u8; ML_DSA_65_PUBLIC_KEY_LEN],
        message: &[u8],
        signature: &[u8; ML_DSA_65_SIGNATURE_LEN],
    ) -> Result<VerificationResult, Self::VerificationError> {
        let Ok(public_key) =
            <MlDsaVerifyingKey<MlDsa65> as ml_dsa::KeyInit>::new_from_slice(public_key)
        else {
            return Ok(VerificationResult::Invalid);
        };
        let Ok(signature) = MlDsaSignature::<MlDsa65>::try_from(signature.as_slice()) else {
            return Ok(VerificationResult::Invalid);
        };
        Ok(if public_key.verify(message, &signature).is_ok() {
            VerificationResult::Valid
        } else {
            VerificationResult::Invalid
        })
    }
}

impl HandshakeCryptoProvider for RustCryptoHandshakeProvider {
    type X25519PrivateKey = X25519PrivateKey;
    type MlKem768DecapsulationKey = MlKem768DecapsulationKey;

    fn generate_x25519_key_pair(
        &self,
        public_key: &mut [u8; X25519_PUBLIC_KEY_LEN],
    ) -> Result<Self::X25519PrivateKey, Self::Error> {
        let mut seed = Zeroizing::new([0_u8; X25519_SHARED_SECRET_LEN]);
        fill_entropy(&mut seed[..])?;
        let private_key = X25519PrivateKey::from(*seed);
        *public_key = X25519PublicKey::from(&private_key).to_bytes();
        Ok(private_key)
    }

    fn x25519_shared_secret(
        &self,
        private_key: &Self::X25519PrivateKey,
        peer_public_key: &[u8; X25519_PUBLIC_KEY_LEN],
        output: &mut [u8; X25519_SHARED_SECRET_LEN],
    ) -> Result<(), Self::Error> {
        let peer_public_key = X25519PublicKey::from(*peer_public_key);
        let shared_secret = private_key.diffie_hellman(&peer_public_key);
        output.copy_from_slice(shared_secret.as_bytes());
        Ok(())
    }

    fn generate_ml_kem_768_key_pair(
        &self,
        encapsulation_key: &mut [u8; ML_KEM_768_ENCAPSULATION_KEY_LEN],
    ) -> Result<Self::MlKem768DecapsulationKey, Self::Error> {
        let mut seed = Zeroizing::new([0_u8; ML_KEM_SEED_LEN]);
        fill_entropy(&mut seed[..])?;
        let decapsulation_key = MlKem768DecapsulationKey::from_seed(Seed::from(*seed));
        let encoded = decapsulation_key.encapsulation_key().to_bytes();
        encapsulation_key.copy_from_slice(encoded.as_slice());
        Ok(decapsulation_key)
    }

    fn encapsulate_ml_kem_768(
        &self,
        encapsulation_key: &[u8; ML_KEM_768_ENCAPSULATION_KEY_LEN],
        ciphertext: &mut [u8; ML_KEM_768_CIPHERTEXT_LEN],
        shared_secret: &mut [u8; ML_KEM_SHARED_SECRET_LEN],
    ) -> Result<(), Self::Error> {
        let encapsulation_key = MlKem768EncapsulationKey::new_from_slice(encapsulation_key)
            .map_err(|_| RustCryptoProviderError::InvalidMlKemEncapsulationKey)?;
        let mut randomness = Zeroizing::new([0_u8; ML_KEM_ENCAPSULATION_RANDOMNESS_LEN]);
        fill_entropy(&mut randomness[..])?;
        // FIPS 203 requires all 32 bytes supplied to this deterministic
        // primitive to be fresh uniform randomness. Keeping the call behind
        // this fallible entropy gate avoids the dependency's panic-on-RNG-
        // error convenience API.
        let (encoded_ciphertext, mut secret) =
            encapsulation_key.encapsulate_deterministic(&B32::from(*randomness));
        ciphertext.copy_from_slice(encoded_ciphertext.as_slice());
        shared_secret.copy_from_slice(secret.as_slice());
        secret.as_mut_slice().zeroize();
        Ok(())
    }

    fn decapsulate_ml_kem_768(
        &self,
        decapsulation_key: &Self::MlKem768DecapsulationKey,
        ciphertext: &[u8; ML_KEM_768_CIPHERTEXT_LEN],
        shared_secret: &mut [u8; ML_KEM_SHARED_SECRET_LEN],
    ) -> Result<(), Self::Error> {
        let ciphertext = MlKem768Ciphertext::from(*ciphertext);
        let mut secret = decapsulation_key.decapsulate(&ciphertext);
        shared_secret.copy_from_slice(secret.as_slice());
        secret.as_mut_slice().zeroize();
        Ok(())
    }

    fn hkdf_extract_sha384(
        &self,
        salt: &[u8; HASH_LEN],
        input_key_material: &[u8],
        output: &mut [u8; HASH_LEN],
    ) -> Result<(), Self::Error> {
        let (mut pseudorandom_key, _) = Hkdf::<Sha384>::extract(Some(salt), input_key_material);
        output.copy_from_slice(pseudorandom_key.as_slice());
        pseudorandom_key.as_mut_slice().zeroize();
        Ok(())
    }

    fn hkdf_expand_sha384(
        &self,
        pseudorandom_key: &[u8; HASH_LEN],
        info: &[u8],
        output: &mut [u8],
    ) -> Result<(), Self::Error> {
        let hkdf = Hkdf::<Sha384>::from_prk(pseudorandom_key)
            .map_err(|_| RustCryptoProviderError::HkdfFailure)?;
        hkdf.expand(info, output)
            .map_err(|_| RustCryptoProviderError::HkdfFailure)
    }

    fn hmac_sha384(
        &self,
        key: &[u8; HASH_LEN],
        message: &[u8],
        output: &mut [u8; HASH_LEN],
    ) -> Result<(), Self::Error> {
        let mut hmac = <Hmac<Sha384> as Mac>::new_from_slice(key)
            .map_err(|_| RustCryptoProviderError::HmacFailure)?;
        hmac.update(message);
        let mut tag = hmac.finalize().into_bytes();
        output.copy_from_slice(tag.as_slice());
        tag.as_mut_slice().zeroize();
        Ok(())
    }

    fn seal_handshake_aead(
        &self,
        suite: CipherSuite,
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; AEAD_IV_LEN],
        additional_data: &[u8],
        plaintext_and_tag: &mut [u8],
        plaintext_length: usize,
    ) -> Result<usize, Self::Error> {
        let expected_length = plaintext_length
            .checked_add(AEAD_TAG_LEN)
            .ok_or(RustCryptoProviderError::AeadFailure)?;
        if plaintext_and_tag.len() != expected_length {
            return Err(RustCryptoProviderError::AeadFailure);
        }
        let (plaintext, tag_output) = plaintext_and_tag.split_at_mut(plaintext_length);
        match suite {
            CipherSuite::Aes256GcmSha384 => {
                let cipher = Aes256Gcm::new_from_slice(key)
                    .map_err(|_| RustCryptoProviderError::AeadFailure)?;
                let tag = cipher
                    .encrypt_in_place_detached(
                        AesNonce::from_slice(nonce),
                        additional_data,
                        plaintext,
                    )
                    .map_err(|_| RustCryptoProviderError::AeadFailure)?;
                tag_output.copy_from_slice(tag.as_slice());
            }
            CipherSuite::ChaCha20Poly1305Sha384 => {
                let cipher = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| RustCryptoProviderError::AeadFailure)?;
                let tag = cipher
                    .encrypt_in_place_detached(
                        ChaChaNonce::from_slice(nonce),
                        additional_data,
                        plaintext,
                    )
                    .map_err(|_| RustCryptoProviderError::AeadFailure)?;
                tag_output.copy_from_slice(tag.as_slice());
            }
        }
        Ok(expected_length)
    }

    fn open_handshake_aead(
        &self,
        suite: CipherSuite,
        key: &[u8; AEAD_KEY_LEN],
        nonce: &[u8; AEAD_IV_LEN],
        additional_data: &[u8],
        ciphertext_and_tag: &mut [u8],
    ) -> Result<HandshakeAeadOpenResult, Self::Error> {
        let Some(plaintext_length) = ciphertext_and_tag.len().checked_sub(AEAD_TAG_LEN) else {
            return Ok(HandshakeAeadOpenResult::Invalid);
        };
        let (ciphertext, tag) = ciphertext_and_tag.split_at_mut(plaintext_length);
        let opened = match suite {
            CipherSuite::Aes256GcmSha384 => {
                let cipher = Aes256Gcm::new_from_slice(key)
                    .map_err(|_| RustCryptoProviderError::AeadFailure)?;
                cipher.decrypt_in_place_detached(
                    AesNonce::from_slice(nonce),
                    additional_data,
                    ciphertext,
                    AesTag::from_slice(tag),
                )
            }
            CipherSuite::ChaCha20Poly1305Sha384 => {
                let cipher = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| RustCryptoProviderError::AeadFailure)?;
                cipher.decrypt_in_place_detached(
                    ChaChaNonce::from_slice(nonce),
                    additional_data,
                    ciphertext,
                    ChaChaTag::from_slice(tag),
                )
            }
        };
        if opened.is_err() {
            return Ok(HandshakeAeadOpenResult::Invalid);
        }
        tag.zeroize();
        Ok(HandshakeAeadOpenResult::Opened(plaintext_length))
    }
}

fn fill_entropy(output: &mut [u8]) -> Result<(), RustCryptoProviderError> {
    getrandom::fill(output).map_err(|_| {
        output.zeroize();
        RustCryptoProviderError::EntropyUnavailable
    })
}
