use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit as BlockKeyInit};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, Nonce as AesNonce, Tag as AesTag};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce, Tag as ChaChaTag};
use ogtp::handshake::CipherSuite;
use ogtp::protection::{
    AuthenticationFailureUsage, EncryptionUsage, HEADER_PROTECTION_MASK_LEN,
    HEADER_PROTECTION_SAMPLE_LEN, PacketCryptoProvider, PathProtection, ProviderError,
    open_short_payload, packet_nonce, protect_short_packet, remove_short_header_protection,
};
use ogtp::wire::{AEAD_TAG_LEN, SHORT_HEADER_LEN, ShortHeader};

struct RustCryptoProvider;

impl PacketCryptoProvider for RustCryptoProvider {
    type AeadKey = [u8; 32];
    type HeaderProtectionKey = [u8; 32];

    fn seal_in_place(
        &self,
        suite: CipherSuite,
        key: &Self::AeadKey,
        nonce: &[u8; 12],
        additional_data: &[u8],
        payload_and_tag: &mut [u8],
        plaintext_length: usize,
    ) -> Result<usize, ProviderError> {
        if payload_and_tag.len() != plaintext_length + AEAD_TAG_LEN {
            return Err(ProviderError::Internal);
        }
        let (plaintext, tag_output) = payload_and_tag.split_at_mut(plaintext_length);
        let tag = match suite {
            CipherSuite::Aes256GcmSha384 => {
                let cipher =
                    Aes256Gcm::new_from_slice(key).map_err(|_| ProviderError::InvalidKey)?;
                cipher
                    .encrypt_in_place_detached(
                        AesNonce::from_slice(nonce),
                        additional_data,
                        plaintext,
                    )
                    .map_err(|_| ProviderError::Internal)?
                    .to_vec()
            }
            CipherSuite::ChaCha20Poly1305Sha384 => {
                let cipher =
                    ChaCha20Poly1305::new_from_slice(key).map_err(|_| ProviderError::InvalidKey)?;
                cipher
                    .encrypt_in_place_detached(
                        ChaChaNonce::from_slice(nonce),
                        additional_data,
                        plaintext,
                    )
                    .map_err(|_| ProviderError::Internal)?
                    .to_vec()
            }
        };
        tag_output.copy_from_slice(&tag);
        Ok(payload_and_tag.len())
    }

    fn open_in_place(
        &self,
        suite: CipherSuite,
        key: &Self::AeadKey,
        nonce: &[u8; 12],
        additional_data: &[u8],
        ciphertext_and_tag: &mut [u8],
    ) -> Result<usize, ProviderError> {
        let plaintext_length = ciphertext_and_tag
            .len()
            .checked_sub(AEAD_TAG_LEN)
            .ok_or(ProviderError::AuthenticationFailed)?;
        let (ciphertext, tag) = ciphertext_and_tag.split_at_mut(plaintext_length);
        match suite {
            CipherSuite::Aes256GcmSha384 => {
                let cipher =
                    Aes256Gcm::new_from_slice(key).map_err(|_| ProviderError::InvalidKey)?;
                cipher
                    .decrypt_in_place_detached(
                        AesNonce::from_slice(nonce),
                        additional_data,
                        ciphertext,
                        AesTag::from_slice(tag),
                    )
                    .map_err(|_| ProviderError::AuthenticationFailed)?;
            }
            CipherSuite::ChaCha20Poly1305Sha384 => {
                let cipher =
                    ChaCha20Poly1305::new_from_slice(key).map_err(|_| ProviderError::InvalidKey)?;
                cipher
                    .decrypt_in_place_detached(
                        ChaChaNonce::from_slice(nonce),
                        additional_data,
                        ciphertext,
                        ChaChaTag::from_slice(tag),
                    )
                    .map_err(|_| ProviderError::AuthenticationFailed)?;
            }
        }
        Ok(plaintext_length)
    }

    fn header_protection_mask(
        &self,
        suite: CipherSuite,
        key: &Self::HeaderProtectionKey,
        sample: &[u8; HEADER_PROTECTION_SAMPLE_LEN],
    ) -> Result<[u8; HEADER_PROTECTION_MASK_LEN], ProviderError> {
        let mut mask = [0_u8; HEADER_PROTECTION_MASK_LEN];
        match suite {
            CipherSuite::Aes256GcmSha384 => {
                let cipher = Aes256::new_from_slice(key).map_err(|_| ProviderError::InvalidKey)?;
                let mut block = aes::Block::clone_from_slice(sample);
                cipher.encrypt_block(&mut block);
                mask.copy_from_slice(&block[..HEADER_PROTECTION_MASK_LEN]);
            }
            CipherSuite::ChaCha20Poly1305Sha384 => {
                let counter = u32::from_le_bytes(
                    sample[..4]
                        .try_into()
                        .map_err(|_| ProviderError::Internal)?,
                );
                let mut cipher = ChaCha20::new_from_slices(key, &sample[4..])
                    .map_err(|_| ProviderError::InvalidKey)?;
                cipher.seek(u64::from(counter) * 64);
                cipher.apply_keystream(&mut mask);
            }
        }
        Ok(mask)
    }
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex input length");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = core::str::from_utf8(pair).expect("ASCII hex");
            u8::from_str_radix(text, 16).expect("valid hex")
        })
        .collect()
}

fn vector(name: &str) -> Vec<u8> {
    let prefix = format!("{name}=");
    let value = include_str!("../test-vectors/packet-protection-v1.txt")
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing vector {name}"));
    decode_hex(value)
}

fn fixed_vector<const N: usize>(name: &str) -> [u8; N] {
    vector(name)
        .try_into()
        .unwrap_or_else(|value: Vec<u8>| panic!("{name} has length {}, expected {N}", value.len()))
}

fn verify_suite(suite: CipherSuite, prefix: &str) {
    let provider = RustCryptoProvider;
    let key = fixed_vector("path_key");
    let iv = fixed_vector("path_iv");
    let hp = fixed_vector("path_hp");
    let protection = PathProtection {
        suite,
        aead_key: &key,
        header_protection_key: &hp,
        iv: &iv,
    };
    let packet_number = u64::from_be_bytes(fixed_vector("packet_number"));
    let unprotected_header = vector("unprotected_header");
    let header = ShortHeader::decode_unprotected(&unprotected_header).expect("valid vector header");
    let plaintext = vector("plaintext");
    let mut packet = vec![0_u8; SHORT_HEADER_LEN + plaintext.len() + AEAD_TAG_LEN];
    packet[SHORT_HEADER_LEN..SHORT_HEADER_LEN + plaintext.len()].copy_from_slice(&plaintext);

    assert_eq!(
        packet_nonce(&iv, packet_number).expect("valid PN"),
        fixed_vector("nonce")
    );
    let mut usage = EncryptionUsage::default();
    let packet_capacity = packet.len();
    let packet_length = protect_short_packet(
        &provider,
        &protection,
        header,
        packet_number,
        plaintext.len(),
        &mut packet,
        &mut usage,
    )
    .expect("vector packet protects");
    assert_eq!(packet_length, packet_capacity);
    assert_eq!(packet, vector(&format!("{prefix}_packet")));
    assert_eq!(
        &packet[SHORT_HEADER_LEN..SHORT_HEADER_LEN + HEADER_PROTECTION_SAMPLE_LEN],
        vector(&format!("{prefix}_sample"))
    );
    assert_eq!(
        &packet[..SHORT_HEADER_LEN],
        vector(&format!("{prefix}_protected_header"))
    );
    assert_eq!(
        &packet[SHORT_HEADER_LEN..],
        vector(&format!("{prefix}_ciphertext_tag"))
    );

    let decoded = remove_short_header_protection(&provider, &protection, &mut packet)
        .expect("vector header opens");
    assert_eq!(decoded, header);
    let mut failures = AuthenticationFailureUsage::default();
    let opened = open_short_payload(
        &provider,
        &protection,
        decoded,
        packet_number,
        &mut packet,
        &mut failures,
    )
    .expect("vector payload opens");
    assert_eq!(opened.packet_number, packet_number);
    assert_eq!(
        &packet[SHORT_HEADER_LEN..SHORT_HEADER_LEN + opened.plaintext_length],
        plaintext
    );
}

#[test]
fn aes_256_gcm_packet_vector_is_reproducible() {
    verify_suite(CipherSuite::Aes256GcmSha384, "aes");
}

#[test]
fn chacha20_poly1305_packet_vector_is_reproducible() {
    verify_suite(CipherSuite::ChaCha20Poly1305Sha384, "chacha");
}
