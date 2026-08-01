#![cfg(feature = "rustcrypto-provider")]

use core::mem::size_of;

use ogtp::crypto::{SHA384_OUTPUT_LEN, Sha384Provider};
use ogtp::handshake::{
    CipherSuite, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN, ENCRYPTED_IDENTITY_AUTH_LEN,
    FINISHED_MAC_LEN, IdentityAuth, ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN,
    ML_KEM_768_CIPHERTEXT_LEN, ML_KEM_768_ENCAPSULATION_KEY_LEN, ML_KEM_SHARED_SECRET_LEN,
};
use ogtp::handshake_crypto::{
    HandshakeCryptoError, HandshakeCryptoProvider, InitiatorHybridState,
    generate_initiator_hybrid_state, open_initiator_identity_auth, open_responder_identity_auth,
    respond_to_initiator, seal_initiator_identity_auth, seal_responder_identity_auth,
};
use ogtp::kdf::{HASH_LEN, LABEL_DERIVED, encode_expand_label};
use ogtp::rustcrypto_provider::{RustCryptoHandshakeProvider, RustCryptoProviderError};
use ogtp::transcript::AuthenticationRole;

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

fn verify_suite(suite: CipherSuite) {
    let provider = RustCryptoHandshakeProvider;
    let pre_auth_hash = [0xa5; SHA384_OUTPUT_LEN];
    let initiator = generate_initiator_hybrid_state(&provider).expect("initiator key share");
    let initiator_x25519 = *initiator.x25519_public_key();
    let initiator_ml_kem = *initiator.ml_kem_encapsulation_key();
    let responder = respond_to_initiator(
        &provider,
        suite,
        &initiator_x25519,
        &initiator_ml_kem,
        &pre_auth_hash,
    )
    .expect("responder key share");
    let responder_x25519 = *responder.x25519_public_key();
    let ciphertext = *responder.ml_kem_ciphertext();
    let mut initiator_secrets = initiator
        .complete(
            &provider,
            suite,
            &responder_x25519,
            &ciphertext,
            &pre_auth_hash,
        )
        .expect("initiator hybrid completion");
    let mut responder_secrets = responder.into_secrets();

    for role in [AuthenticationRole::Initiator, AuthenticationRole::Responder] {
        let transcript_hash = [role as u8 + 0x31; SHA384_OUTPUT_LEN];
        assert_eq!(
            initiator_secrets
                .compute_finished(&provider, role, &transcript_hash)
                .expect("initiator Finished"),
            responder_secrets
                .compute_finished(&provider, role, &transcript_hash)
                .expect("responder Finished")
        );
    }

    let responder_auth = IdentityAuthFixture::new(0x21);
    let mut responder_ciphertext = [0_u8; ENCRYPTED_IDENTITY_AUTH_LEN];
    seal_responder_identity_auth(
        &provider,
        &mut responder_secrets,
        7,
        &pre_auth_hash,
        responder_auth.value(),
        &mut responder_ciphertext,
    )
    .expect("seal responder authentication");
    let opened = open_responder_identity_auth(
        &provider,
        &initiator_secrets,
        7,
        &pre_auth_hash,
        &responder_ciphertext,
    )
    .expect("open responder authentication");
    assert_eq!(
        opened.decode().expect("decode responder auth"),
        responder_auth.value()
    );

    let mut tampered = responder_ciphertext;
    tampered[ENCRYPTED_IDENTITY_AUTH_LEN / 2] ^= 1;
    assert!(matches!(
        open_responder_identity_auth(&provider, &initiator_secrets, 7, &pre_auth_hash, &tampered,),
        Err(HandshakeCryptoError::AuthenticationFailed)
    ));

    let initiator_signature_hash = [0x6c; SHA384_OUTPUT_LEN];
    let initiator_auth = IdentityAuthFixture::new(0x72);
    let mut initiator_ciphertext = [0_u8; ENCRYPTED_IDENTITY_AUTH_LEN];
    seal_initiator_identity_auth(
        &provider,
        &mut initiator_secrets,
        9,
        &initiator_signature_hash,
        initiator_auth.value(),
        &mut initiator_ciphertext,
    )
    .expect("seal initiator authentication");
    let opened = open_initiator_identity_auth(
        &provider,
        &responder_secrets,
        9,
        &initiator_signature_hash,
        &initiator_ciphertext,
    )
    .expect("open initiator authentication");
    assert_eq!(
        opened.decode().expect("decode initiator auth"),
        initiator_auth.value()
    );
}

#[test]
fn real_hybrid_handshake_interoperates_for_both_suites() {
    verify_suite(CipherSuite::Aes256GcmSha384);
    verify_suite(CipherSuite::ChaCha20Poly1305Sha384);
}

#[test]
fn published_hkdf_extract_stages_are_reproduced() {
    let provider = RustCryptoHandshakeProvider;
    let vector = include_str!("../test-vectors/kdf-sha384-v1.txt");
    let value = |name: &str| {
        let encoded = vector
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .expect("vector field");
        decode_hex(encoded)
    };
    let empty_context = provider.start_sha384().expect("SHA-384 context");
    assert_eq!(
        &provider
            .finish_sha384(empty_context)
            .expect("empty SHA-384 digest")[..],
        value("empty_hash")
    );
    let zero = [0_u8; HASH_LEN];
    let mut early_secret = [0_u8; HASH_LEN];
    provider
        .hkdf_extract_sha384(&zero, &zero, &mut early_secret)
        .expect("early extract");
    assert_eq!(&early_secret[..], value("early_secret"));

    let empty_hash: [u8; HASH_LEN] = value("empty_hash").try_into().expect("empty hash");
    let mut info = [0_u8; 80];
    let written = encode_expand_label(
        u16::try_from(HASH_LEN).expect("SHA-384 length fits u16"),
        LABEL_DERIVED,
        &empty_hash,
        &mut info,
    )
    .expect("derived label");
    let mut derived_early = [0_u8; HASH_LEN];
    provider
        .hkdf_expand_sha384(&early_secret, &info[..written], &mut derived_early)
        .expect("derived early expand");
    assert_eq!(&derived_early[..], value("derived_early"));

    let hybrid = value("hybrid");
    let mut handshake_secret = [0_u8; HASH_LEN];
    provider
        .hkdf_extract_sha384(&derived_early, &hybrid, &mut handshake_secret)
        .expect("handshake extract");
    assert_eq!(&handshake_secret[..], value("handshake_secret"));
}

#[test]
fn published_aead_vectors_match_the_provider_buffer_layout() {
    let provider = RustCryptoHandshakeProvider;
    let vector = include_str!("../test-vectors/packet-protection-v1.txt");
    let value = |name: &str| {
        let encoded = vector
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .expect("vector field");
        decode_hex(encoded)
    };
    let key: [u8; 32] = value("path_key").try_into().expect("AEAD key");
    let nonce: [u8; 12] = value("nonce").try_into().expect("AEAD nonce");
    let additional_data = value("unprotected_header");
    let plaintext = value("plaintext");
    for (suite, expected_name) in [
        (CipherSuite::Aes256GcmSha384, "aes_ciphertext_tag"),
        (CipherSuite::ChaCha20Poly1305Sha384, "chacha_ciphertext_tag"),
    ] {
        let mut protected = vec![0_u8; plaintext.len() + 16];
        protected[..plaintext.len()].copy_from_slice(&plaintext);
        assert_eq!(
            provider
                .seal_handshake_aead(
                    suite,
                    &key,
                    &nonce,
                    &additional_data,
                    &mut protected,
                    plaintext.len(),
                )
                .expect("seal vector"),
            protected.len()
        );
        assert_eq!(protected, value(expected_name));
        assert_eq!(
            provider
                .open_handshake_aead(suite, &key, &nonce, &additional_data, &mut protected,)
                .expect("open vector"),
            ogtp::handshake_crypto::HandshakeAeadOpenResult::Opened(plaintext.len())
        );
        assert_eq!(&protected[..plaintext.len()], &plaintext);
    }
}

#[test]
fn malformed_ml_kem_inputs_preserve_implicit_rejection() {
    let provider = RustCryptoHandshakeProvider;
    let mut ciphertext = [0x44; ML_KEM_768_CIPHERTEXT_LEN];
    let mut shared_secret = [0x55; ML_KEM_SHARED_SECRET_LEN];
    assert_eq!(
        provider.encapsulate_ml_kem_768(
            &[0xff; ML_KEM_768_ENCAPSULATION_KEY_LEN],
            &mut ciphertext,
            &mut shared_secret,
        ),
        Err(RustCryptoProviderError::InvalidMlKemEncapsulationKey)
    );
    assert_eq!(ciphertext, [0x44; ML_KEM_768_CIPHERTEXT_LEN]);
    assert_eq!(shared_secret, [0x55; ML_KEM_SHARED_SECRET_LEN]);

    let mut encapsulation_key = [0_u8; ML_KEM_768_ENCAPSULATION_KEY_LEN];
    let decapsulation_key = provider
        .generate_ml_kem_768_key_pair(&mut encapsulation_key)
        .expect("ML-KEM key pair");
    provider
        .decapsulate_ml_kem_768(
            &decapsulation_key,
            &[0xff; ML_KEM_768_CIPHERTEXT_LEN],
            &mut shared_secret,
        )
        .expect("implicit rejection is not an input-validity error");
}

#[test]
fn retained_concrete_handshake_state_stays_below_the_protocol_slot_budget() {
    assert!(
        size_of::<InitiatorHybridState<RustCryptoHandshakeProvider>>() <= 16 * 1024,
        "retained initiator key state must fit one handshake slot"
    );
}

fn decode_hex(encoded: &str) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0, "even hexadecimal length");
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("hexadecimal digit");
            let low = (pair[1] as char).to_digit(16).expect("hexadecimal digit");
            u8::try_from((high << 4) | low).expect("one byte")
        })
        .collect()
}
