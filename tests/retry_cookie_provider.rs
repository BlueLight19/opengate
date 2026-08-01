use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use ogtp::crypto::{Sha384Digest, Sha384Provider};
use ogtp::handshake::{CAPABILITY_MULTIPATH_BIT, CIPHER_SUITE_AES_256_GCM_SHA384_BIT, Hello};
use ogtp::protection::ProviderError;
use ogtp::retry::{
    RETRY_COOKIE_LEN, RetryCookieBinding, RetryCookieKey, RetryCookieKeyRing,
    RetryCookieOpenResult, RetryCookiePolicy, RetryCookieProvider, RetrySourceAddress,
    issue_retry_cookie, validate_retry_cookie,
};
use ogtp::transcript::TranscriptSink;
use ogtp::wire::AEAD_TAG_LEN;
use sha2::{Digest, Sha384};

#[derive(Clone)]
struct Sha384Context(Sha384);

impl TranscriptSink for Sha384Context {
    fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
}

struct RustCryptoCookieProvider;

impl Sha384Provider for RustCryptoCookieProvider {
    type Context = Sha384Context;
    type Error = ProviderError;

    fn start_sha384(&self) -> Result<Self::Context, Self::Error> {
        Ok(Sha384Context(Sha384::new()))
    }

    fn finish_sha384(&self, context: Self::Context) -> Result<Sha384Digest, Self::Error> {
        Ok(context.0.finalize().into())
    }
}

impl RetryCookieProvider for RustCryptoCookieProvider {
    type Key = [u8; 32];

    fn seal_retry_cookie(
        &self,
        key: &Self::Key,
        nonce: &[u8; 12],
        additional_data: &[u8],
        plaintext_and_tag: &mut [u8],
        plaintext_length: usize,
    ) -> Result<usize, Self::Error> {
        if plaintext_and_tag.len() != plaintext_length + AEAD_TAG_LEN {
            return Err(ProviderError::Internal);
        }
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ProviderError::InvalidKey)?;
        let (plaintext, tag_output) = plaintext_and_tag.split_at_mut(plaintext_length);
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(nonce), additional_data, plaintext)
            .map_err(|_| ProviderError::Internal)?;
        tag_output.copy_from_slice(&tag);
        Ok(plaintext_length + AEAD_TAG_LEN)
    }

    fn open_retry_cookie(
        &self,
        key: &Self::Key,
        nonce: &[u8; 12],
        additional_data: &[u8],
        ciphertext_and_tag: &mut [u8],
    ) -> Result<RetryCookieOpenResult, Self::Error> {
        let Some(plaintext_length) = ciphertext_and_tag.len().checked_sub(AEAD_TAG_LEN) else {
            return Ok(RetryCookieOpenResult::Invalid);
        };
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ProviderError::InvalidKey)?;
        let (ciphertext, tag) = ciphertext_and_tag.split_at_mut(plaintext_length);
        if cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(nonce),
                additional_data,
                ciphertext,
                Tag::from_slice(tag),
            )
            .is_err()
        {
            return Ok(RetryCookieOpenResult::Invalid);
        }
        Ok(RetryCookieOpenResult::Opened(plaintext_length))
    }
}

#[test]
fn aes_256_gcm_adapter_opens_and_rejects_tampering() {
    let provider = RustCryptoCookieProvider;
    let policy = RetryCookiePolicy::new(20, 1).expect("valid policy");
    let active = RetryCookieKey::new(
        7,
        [0x42; 32],
        [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80],
        100,
        200,
        230,
    )
    .expect("valid key schedule");
    let mut ring = RetryCookieKeyRing::new(active);
    let binding = RetryCookieBinding {
        source_address: RetrySourceAddress::Ipv6([
            0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1,
        ]),
        source_port: 44_443,
        version: 1,
        initiator_connection_id: b"initiator-cid",
        responder_connection_id: b"responder-cid",
        hello: Hello {
            client_random: [0x11; 32],
            identity_fingerprint: [0x22; 48],
            cipher_suite_bitmap: CIPHER_SUITE_AES_256_GCM_SHA384_BIT,
            capabilities: CAPABILITY_MULTIPATH_BIT,
            max_udp_payload: 1_400,
            max_paths: 2,
        },
        server_random: [0x33; 32],
    };
    let mut cookie = [0_u8; RETRY_COOKIE_LEN];
    assert_eq!(
        issue_retry_cookie(&provider, &mut ring, policy, &binding, 110, &mut cookie),
        Ok(RETRY_COOKIE_LEN)
    );
    let validated = validate_retry_cookie(&provider, &ring, policy, &binding, 111, &cookie)
        .expect("AES-GCM cookie validates");
    assert_eq!(validated.key_id(), 7);
    cookie[RETRY_COOKIE_LEN - 1] ^= 1;
    assert!(validate_retry_cookie(&provider, &ring, policy, &binding, 111, &cookie).is_err());
}
