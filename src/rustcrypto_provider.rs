//! Feature-gated `RustCrypto` handshake provider.
//!
//! This module supplies a concrete software implementation of
//! [`HandshakeCryptoProvider`].
//! It is intended for interoperability, testing, and further review. Enabling
//! it does not make an OGTP deployment production-ready: the selected ML-KEM
//! implementation currently documents that it has not received an independent
//! audit.

use core::fmt;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce, Tag as AesTag};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce, Tag as ChaChaTag};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ml_kem::kem::{Decapsulate, KeyExport, TryKeyInit};
use ml_kem::ml_kem_768::{
    Ciphertext as MlKem768Ciphertext, DecapsulationKey as MlKem768DecapsulationKey,
    EncapsulationKey as MlKem768EncapsulationKey,
};
use ml_kem::{B32, Seed};
use sha2::{Digest, Sha384};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519PrivateKey};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{ForkableSha384Provider, Sha384Digest, Sha384Provider};
use crate::handshake::{
    CipherSuite, ML_KEM_768_CIPHERTEXT_LEN, ML_KEM_768_ENCAPSULATION_KEY_LEN,
    ML_KEM_SHARED_SECRET_LEN, X25519_PUBLIC_KEY_LEN, X25519_SHARED_SECRET_LEN,
};
use crate::handshake_crypto::{HandshakeAeadOpenResult, HandshakeCryptoProvider};
use crate::kdf::{AEAD_IV_LEN, AEAD_KEY_LEN, HASH_LEN};
use crate::transcript::TranscriptSink;
use crate::wire::AEAD_TAG_LEN;

const ML_KEM_SEED_LEN: usize = 64;
const ML_KEM_ENCAPSULATION_RANDOMNESS_LEN: usize = 32;

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
            Self::AeadFailure => formatter.write_str("handshake AEAD failure"),
        }
    }
}

impl std::error::Error for RustCryptoProviderError {}

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
