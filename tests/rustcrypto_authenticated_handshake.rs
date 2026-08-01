#![cfg(feature = "rustcrypto-provider")]

use ogtp::authentication::{PeerAuthenticationContext, authenticate_peer_identity};
use ogtp::handshake::{
    CAPABILITY_MULTIPATH_BIT, CIPHER_SUITE_AES_256_GCM_SHA384_BIT,
    CIPHER_SUITE_CHACHA20_POLY1305_SHA384_BIT, CipherSuite, ENCRYPTED_IDENTITY_AUTH_LEN,
    FINISH_LEN, Finish, HELLO_LEN, Hello, INIT_FIXED_LEN, Init, RESPONSE_FIXED_LEN, RESPONSE_LEN,
    Response, Retry,
};
use ogtp::handshake_crypto::{
    generate_initiator_hybrid_state, open_initiator_identity_auth, open_responder_identity_auth,
    prepare_responder_hybrid,
};
use ogtp::handshake_state::{HandshakeTranscript, HandshakeTranscriptStage};
use ogtp::rustcrypto_provider::{
    RustCryptoIdentityKeyPair, RustCryptoProvider, seal_initiator_authenticated_identity,
    seal_responder_authenticated_identity,
};
use ogtp::transcript::{AuthenticationRole, SessionContext};

const COOKIE: [u8; 32] = [0x3c; 32];
const RESPONSE_MESSAGE_ID: u32 = 0x1020_3040;
const FINISH_MESSAGE_ID: u32 = 0x5060_7080;

#[test]
fn real_mutual_authenticated_wire_handshake_completes_for_both_suites() {
    verify_mutual_handshake(CipherSuite::Aes256GcmSha384);
    verify_mutual_handshake(CipherSuite::ChaCha20Poly1305Sha384);
}

// Keeping both peers in one linear scenario makes every wire/transcript
// correspondence reviewable without hiding state transitions in helpers.
#[allow(clippy::too_many_lines)]
fn verify_mutual_handshake(suite: CipherSuite) {
    let provider = RustCryptoProvider::default();
    let initiator_identity = RustCryptoIdentityKeyPair::from_seed_bytes(&[0x11; 32], &[0x12; 32]);
    let responder_identity = RustCryptoIdentityKeyPair::from_seed_bytes(&[0x21; 32], &[0x22; 32]);
    let initiator_fingerprint = initiator_identity
        .fingerprint(&provider)
        .expect("initiator fingerprint");
    let responder_fingerprint = responder_identity
        .fingerprint(&provider)
        .expect("responder fingerprint");

    let session = SessionContext {
        version: 1,
        initiator_connection_id: b"initiator-cid",
        responder_connection_id: b"responder-cid",
    };
    let mut initiator_transcript =
        HandshakeTranscript::new(&provider, session).expect("initiator transcript");
    let mut responder_transcript =
        HandshakeTranscript::new(&provider, session).expect("responder transcript");

    let hello = Hello {
        client_random: [0x31; 32],
        identity_fingerprint: initiator_fingerprint,
        cipher_suite_bitmap: CIPHER_SUITE_AES_256_GCM_SHA384_BIT
            | CIPHER_SUITE_CHACHA20_POLY1305_SHA384_BIT,
        capabilities: CAPABILITY_MULTIPATH_BIT,
        max_udp_payload: 1_200,
        max_paths: 2,
    };
    let mut hello_bytes = [0_u8; HELLO_LEN];
    hello
        .encode(&mut hello_bytes)
        .expect("HELLO encodes exactly");
    initiator_transcript
        .record_hello(&provider, &hello_bytes)
        .expect("initiator records HELLO");
    responder_transcript
        .record_hello(&provider, &hello_bytes)
        .expect("responder records HELLO");

    let retry = Retry {
        server_random: [0x42; 32],
        cookie: &COOKIE,
    };
    let mut retry_bytes = [0_u8; 66];
    let retry_length = retry.encode(&mut retry_bytes).expect("RETRY encodes");
    initiator_transcript
        .record_retry(&provider, &retry_bytes[..retry_length])
        .expect("initiator records RETRY");
    responder_transcript
        .record_retry(&provider, &retry_bytes[..retry_length])
        .expect("responder records RETRY");

    let initiator_hybrid =
        generate_initiator_hybrid_state(&provider).expect("initiator hybrid state");
    let init = Init {
        hello,
        server_random: retry.server_random,
        cookie: &COOKIE,
        x25519_public_key: *initiator_hybrid.x25519_public_key(),
        ml_kem_encapsulation_key: initiator_hybrid.ml_kem_encapsulation_key(),
    };
    let mut init_bytes = [0_u8; INIT_FIXED_LEN + COOKIE.len()];
    let init_length = init.encode(&mut init_bytes).expect("INIT encodes");
    initiator_transcript
        .record_init(&provider, &init_bytes[..init_length])
        .expect("initiator records INIT");
    responder_transcript
        .record_init(&provider, &init_bytes[..init_length])
        .expect("responder records INIT");

    let prepared_responder = prepare_responder_hybrid(
        &provider,
        initiator_hybrid.x25519_public_key(),
        initiator_hybrid.ml_kem_encapsulation_key(),
    )
    .expect("responder prepares public hybrid values");
    let responder_x25519 = *prepared_responder.x25519_public_key();
    let ml_kem_ciphertext = *prepared_responder.ml_kem_ciphertext();
    let placeholder_ciphertext = [0_u8; ENCRYPTED_IDENTITY_AUTH_LEN];
    let response_prefix = Response {
        selected_cipher_suite: suite,
        negotiated_capabilities: CAPABILITY_MULTIPATH_BIT,
        max_udp_payload: 1_200,
        max_paths: 2,
        identity_fingerprint: responder_fingerprint,
        x25519_public_key: responder_x25519,
        ml_kem_ciphertext: &ml_kem_ciphertext,
        encrypted_identity_auth: &placeholder_ciphertext,
    };
    let mut response_bytes = [0_u8; RESPONSE_LEN];
    response_prefix
        .encode(&mut response_bytes)
        .expect("RESPONSE prefix encodes");
    let initiator_pre_auth = initiator_transcript
        .record_response(&provider, &response_bytes)
        .expect("initiator records RESPONSE prefix");
    let responder_pre_auth = responder_transcript
        .record_response(&provider, &response_bytes)
        .expect("responder records RESPONSE prefix");
    assert_eq!(initiator_pre_auth, responder_pre_auth);

    let responder_hybrid = prepared_responder
        .complete(&provider, suite, &responder_pre_auth)
        .expect("responder binds prepared secrets to transcript");
    let mut responder_secrets = responder_hybrid.into_secrets();
    let mut initiator_secrets = initiator_hybrid
        .complete(
            &provider,
            suite,
            &responder_x25519,
            &ml_kem_ciphertext,
            &initiator_pre_auth,
        )
        .expect("initiator completes hybrid exchange");

    let mut responder_ciphertext = [0_u8; ENCRYPTED_IDENTITY_AUTH_LEN];
    let responder_sender_milestone = seal_responder_authenticated_identity(
        &provider,
        &responder_identity,
        &mut responder_transcript,
        &mut responder_secrets,
        RESPONSE_MESSAGE_ID,
        &mut responder_ciphertext,
    )
    .expect("responder signs, computes Finished, and seals");
    let response = Response {
        encrypted_identity_auth: &responder_ciphertext,
        ..response_prefix
    };
    let mut final_response_bytes = [0_u8; RESPONSE_LEN];
    response
        .encode(&mut final_response_bytes)
        .expect("final RESPONSE encodes");
    assert_eq!(
        &final_response_bytes[..RESPONSE_FIXED_LEN],
        &response_bytes[..RESPONSE_FIXED_LEN]
    );
    let decoded_response = Response::decode(&final_response_bytes).expect("RESPONSE decodes");
    let opened_responder = open_responder_identity_auth(
        &provider,
        &initiator_secrets,
        RESPONSE_MESSAGE_ID,
        &initiator_pre_auth,
        decoded_response.encrypted_identity_auth,
    )
    .expect("initiator opens responder identity");
    let responder_receiver_milestone = initiator_transcript
        .record_responder_auth(&provider, opened_responder.as_bytes())
        .expect("initiator commits responder authentication");
    assert_eq!(responder_sender_milestone, responder_receiver_milestone);
    let authenticated_responder = authenticate_peer_identity(
        &provider,
        PeerAuthenticationContext {
            role: AuthenticationRole::Responder,
            signature_transcript_hash: responder_receiver_milestone.authentication.signature(),
            finished_transcript_hash: responder_receiver_milestone.authentication.finished(),
            finished_key: initiator_secrets.responder().finished_key(),
            announced_fingerprint: &responder_fingerprint,
            trust_anchor_fingerprint: &responder_fingerprint,
        },
        &opened_responder
            .decode()
            .expect("responder identity decodes"),
    )
    .expect("initiator authenticates responder");

    let mut initiator_ciphertext = [0_u8; ENCRYPTED_IDENTITY_AUTH_LEN];
    let initiator_sender_milestone = seal_initiator_authenticated_identity(
        &provider,
        &initiator_identity,
        &mut initiator_transcript,
        &mut initiator_secrets,
        FINISH_MESSAGE_ID,
        &mut initiator_ciphertext,
    )
    .expect("initiator signs, computes Finished, and seals");
    let finish = Finish {
        encrypted_identity_auth: &initiator_ciphertext,
    };
    let mut finish_bytes = [0_u8; FINISH_LEN];
    finish.encode(&mut finish_bytes).expect("FINISH encodes");
    let decoded_finish = Finish::decode(&finish_bytes).expect("FINISH decodes");
    let opened_initiator = open_initiator_identity_auth(
        &provider,
        &responder_secrets,
        FINISH_MESSAGE_ID,
        responder_sender_milestone.initiator_signature(),
        decoded_finish.encrypted_identity_auth,
    )
    .expect("responder opens initiator identity");
    let initiator_receiver_milestone = responder_transcript
        .record_initiator_auth(&provider, opened_initiator.as_bytes())
        .expect("responder commits initiator authentication");
    assert_eq!(initiator_sender_milestone, initiator_receiver_milestone);
    let authenticated_initiator = authenticate_peer_identity(
        &provider,
        PeerAuthenticationContext {
            role: AuthenticationRole::Initiator,
            signature_transcript_hash: initiator_receiver_milestone.authentication.signature(),
            finished_transcript_hash: initiator_receiver_milestone.authentication.finished(),
            finished_key: responder_secrets.initiator().finished_key(),
            announced_fingerprint: &initiator_fingerprint,
            trust_anchor_fingerprint: &initiator_fingerprint,
        },
        &opened_initiator
            .decode()
            .expect("initiator identity decodes"),
    )
    .expect("responder authenticates initiator");

    assert_eq!(
        initiator_transcript.stage(),
        HandshakeTranscriptStage::Complete
    );
    assert_eq!(
        responder_transcript.stage(),
        HandshakeTranscriptStage::Complete
    );
    assert_eq!(initiator_sender_milestone, initiator_receiver_milestone);

    let initiator_application = initiator_secrets
        .derive_application_secrets(
            &provider,
            &initiator_sender_milestone,
            &authenticated_responder,
        )
        .expect("initiator application secrets");
    let responder_application = responder_secrets
        .derive_application_secrets(
            &provider,
            &initiator_receiver_milestone,
            &authenticated_initiator,
        )
        .expect("responder application secrets");
    assert_eq!(
        initiator_application.initiator(),
        responder_application.initiator()
    );
    assert_eq!(
        initiator_application.responder(),
        responder_application.responder()
    );
}
