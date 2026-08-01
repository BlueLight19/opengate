#![cfg(feature = "rustcrypto-provider")]

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use hmac::{Hmac, Mac};
use ml_dsa::{Keypair as _, MlDsa65, Seed as MlDsaSeed, SigningKey as MlDsaSigningKey};
use ml_kem::kem::{Decapsulate as _, KeyExport as _};
use ml_kem::ml_kem_768::DecapsulationKey as MlKem768DecapsulationKey;
use ml_kem::{B32 as MlKemRandomness, Seed as MlKemSeed};
use ogtp::authentication::{
    PeerAuthenticationContext, authenticate_peer_identity, handshake_signature_input,
    identity_fingerprint,
};
use ogtp::crypto::{SHA384_OUTPUT_LEN, Sha384Digest};
use ogtp::handshake::{
    CAPABILITY_MULTIPATH_BIT, CIPHER_SUITE_AES_256_GCM_SHA384_BIT,
    CIPHER_SUITE_CHACHA20_POLY1305_SHA384_BIT, CipherSuite, ED25519_PUBLIC_KEY_LEN,
    ED25519_SIGNATURE_LEN, ENCRYPTED_IDENTITY_AUTH_LEN, FINISH_LEN, Finish, HELLO_LEN, Hello,
    IDENTITY_AUTH_LEN, IDENTITY_FINGERPRINT_LEN, INIT_FIXED_LEN, IdentityAuth, IdentityAuthContent,
    Init, ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN, ML_KEM_768_CIPHERTEXT_LEN,
    ML_KEM_768_ENCAPSULATION_KEY_LEN, RESPONSE_FIXED_LEN, RESPONSE_LEN, Response, Retry,
    X25519_PUBLIC_KEY_LEN,
};
use ogtp::handshake_crypto::handshake_nonce;
use ogtp::handshake_state::HandshakeTranscript;
use ogtp::kdf::{
    AEAD_IV_LEN, AEAD_KEY_LEN, HASH_LEN, LABEL_DERIVED, LABEL_FINISHED,
    LABEL_INITIATOR_APPLICATION, LABEL_INITIATOR_HANDSHAKE, LABEL_IV, LABEL_KEY,
    LABEL_RESPONDER_APPLICATION, LABEL_RESPONDER_HANDSHAKE, encode_expand_label,
};
use ogtp::rustcrypto_provider::RustCryptoProvider;
use ogtp::transcript::{AuthenticationRole, SessionContext};
use ogtp::wire::AEAD_TAG_LEN;
use sha2::{Digest, Sha384};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519PrivateKey};

type HmacSha384 = Hmac<Sha384>;

const INITIATOR_ED25519_SEED: [u8; 32] = [0x11; 32];
const INITIATOR_ML_DSA_SEED: [u8; 32] = [0x12; 32];
const RESPONDER_ED25519_SEED: [u8; 32] = [0x21; 32];
const RESPONDER_ML_DSA_SEED: [u8; 32] = [0x22; 32];
const CLIENT_RANDOM: [u8; 32] = [0x31; 32];
const SERVER_RANDOM: [u8; 32] = [0x42; 32];
const COOKIE: [u8; 32] = [0x53; 32];
const INITIATOR_X25519_PRIVATE_SEED: [u8; 32] = [0x64; 32];
const RESPONDER_X25519_PRIVATE_SEED: [u8; 32] = [0x75; 32];
const INITIATOR_ML_KEM_SEED: [u8; 64] = [0x86; 64];
const RESPONDER_ML_KEM_RANDOMNESS: [u8; 32] = [0x97; 32];
const RESPONSE_MESSAGE_ID: u32 = 0x1020_3040;
const FINISH_MESSAGE_ID: u32 = 0x5060_7080;

struct HybridFixture {
    initiator_x25519_public_key: [u8; X25519_PUBLIC_KEY_LEN],
    responder_x25519_public_key: [u8; X25519_PUBLIC_KEY_LEN],
    ml_kem_encapsulation_key: [u8; ML_KEM_768_ENCAPSULATION_KEY_LEN],
    ml_kem_ciphertext: [u8; ML_KEM_768_CIPHERTEXT_LEN],
    shared_secret: [u8; 64],
}

impl HybridFixture {
    fn build() -> Self {
        let initiator_x25519 = X25519PrivateKey::from(INITIATOR_X25519_PRIVATE_SEED);
        let responder_x25519 = X25519PrivateKey::from(RESPONDER_X25519_PRIVATE_SEED);
        let initiator_x25519_public_key = X25519PublicKey::from(&initiator_x25519).to_bytes();
        let responder_x25519_public_key = X25519PublicKey::from(&responder_x25519).to_bytes();
        let initiator_x25519_shared =
            initiator_x25519.diffie_hellman(&X25519PublicKey::from(responder_x25519_public_key));
        let responder_x25519_shared =
            responder_x25519.diffie_hellman(&X25519PublicKey::from(initiator_x25519_public_key));
        assert_eq!(
            initiator_x25519_shared.as_bytes(),
            responder_x25519_shared.as_bytes()
        );

        let ml_kem_decapsulation =
            MlKem768DecapsulationKey::from_seed(MlKemSeed::from(INITIATOR_ML_KEM_SEED));
        let encoded_ml_kem_key = ml_kem_decapsulation.encapsulation_key().to_bytes();
        let mut ml_kem_encapsulation_key = [0_u8; ML_KEM_768_ENCAPSULATION_KEY_LEN];
        ml_kem_encapsulation_key.copy_from_slice(encoded_ml_kem_key.as_slice());
        let (encoded_ciphertext, responder_ml_kem_shared) = ml_kem_decapsulation
            .encapsulation_key()
            .encapsulate_deterministic(&MlKemRandomness::from(RESPONDER_ML_KEM_RANDOMNESS));
        let initiator_ml_kem_shared = ml_kem_decapsulation.decapsulate(&encoded_ciphertext);
        assert_eq!(
            initiator_ml_kem_shared.as_slice(),
            responder_ml_kem_shared.as_slice()
        );
        let mut ml_kem_ciphertext = [0_u8; ML_KEM_768_CIPHERTEXT_LEN];
        ml_kem_ciphertext.copy_from_slice(encoded_ciphertext.as_slice());
        let mut shared_secret = [0_u8; 64];
        shared_secret[..32].copy_from_slice(responder_ml_kem_shared.as_slice());
        shared_secret[32..].copy_from_slice(responder_x25519_shared.as_bytes());
        Self {
            initiator_x25519_public_key,
            responder_x25519_public_key,
            ml_kem_encapsulation_key,
            ml_kem_ciphertext,
            shared_secret,
        }
    }
}

struct VectorIdentity {
    ed25519: Ed25519SigningKey,
    ml_dsa: MlDsaSigningKey<MlDsa65>,
    ed25519_public_key: [u8; ED25519_PUBLIC_KEY_LEN],
    ml_dsa_public_key: [u8; ML_DSA_65_PUBLIC_KEY_LEN],
    fingerprint: [u8; IDENTITY_FINGERPRINT_LEN],
}

impl VectorIdentity {
    #[allow(clippy::trivially_copy_pass_by_ref)] // Mirrors the provider APIs exercised below.
    fn from_seeds(
        provider: &RustCryptoProvider,
        ed25519_seed: &[u8; 32],
        ml_dsa_seed: &[u8; 32],
    ) -> Self {
        let ed25519 = Ed25519SigningKey::from_bytes(ed25519_seed);
        let ml_dsa = MlDsaSigningKey::<MlDsa65>::from_seed(&MlDsaSeed::from(*ml_dsa_seed));
        let ed25519_public_key = ed25519.verifying_key().to_bytes();
        let encoded_ml_dsa = ml_dsa.verifying_key().encode();
        let mut ml_dsa_public_key = [0_u8; ML_DSA_65_PUBLIC_KEY_LEN];
        ml_dsa_public_key.copy_from_slice(encoded_ml_dsa.as_slice());
        let fingerprint = identity_fingerprint(provider, &ed25519_public_key, &ml_dsa_public_key)
            .expect("RustCrypto SHA-384 fingerprint");
        Self {
            ed25519,
            ml_dsa,
            ed25519_public_key,
            ml_dsa_public_key,
            fingerprint,
        }
    }

    fn sign(&self, role: AuthenticationRole, transcript_hash: &Sha384Digest) -> VectorSignatures {
        let input = handshake_signature_input(role, transcript_hash)
            .expect("fixed handshake signature input");
        let ed25519 = self.ed25519.sign(input.as_bytes()).to_bytes();
        let ml_dsa = self
            .ml_dsa
            .expanded_key()
            .sign_deterministic(input.as_bytes(), &[])
            .expect("valid empty ML-DSA context")
            .encode();
        let mut ml_dsa_bytes = [0_u8; ML_DSA_65_SIGNATURE_LEN];
        ml_dsa_bytes.copy_from_slice(ml_dsa.as_slice());
        VectorSignatures {
            ed25519,
            ml_dsa: ml_dsa_bytes,
        }
    }
}

struct VectorSignatures {
    ed25519: [u8; ED25519_SIGNATURE_LEN],
    ml_dsa: [u8; ML_DSA_65_SIGNATURE_LEN],
}

impl VectorSignatures {
    fn content<'a>(&'a self, identity: &'a VectorIdentity) -> IdentityAuthContent<'a> {
        IdentityAuthContent {
            ed25519_public_key: identity.ed25519_public_key,
            ml_dsa_public_key: &identity.ml_dsa_public_key,
            ed25519_signature: self.ed25519,
            ml_dsa_signature: &self.ml_dsa,
        }
    }

    fn digest(&self) -> Sha384Digest {
        digest_parts(&[&self.ed25519, &self.ml_dsa])
    }
}

struct KeySchedule {
    initiator_finished_key: [u8; HASH_LEN],
    responder_finished_key: [u8; HASH_LEN],
    initiator_handshake_key: [u8; AEAD_KEY_LEN],
    initiator_handshake_iv: [u8; AEAD_IV_LEN],
    responder_handshake_key: [u8; AEAD_KEY_LEN],
    responder_handshake_iv: [u8; AEAD_IV_LEN],
    master_secret: [u8; HASH_LEN],
}

struct SuiteVector {
    name: &'static str,
    pre_auth_hash: Sha384Digest,
    responder_signatures: Sha384Digest,
    responder_finished_hash: Sha384Digest,
    responder_finished_mac: [u8; HASH_LEN],
    responder_plaintext: Sha384Digest,
    responder_ciphertext: Vec<u8>,
    response_wire: Vec<u8>,
    initiator_signature_hash: Sha384Digest,
    initiator_signatures: Sha384Digest,
    initiator_finished_hash: Sha384Digest,
    initiator_finished_mac: [u8; HASH_LEN],
    initiator_plaintext: Sha384Digest,
    initiator_ciphertext: Vec<u8>,
    finish_wire: Vec<u8>,
    full_hash: Sha384Digest,
    schedule: KeySchedule,
    initiator_application_secret: [u8; HASH_LEN],
    responder_application_secret: [u8; HASH_LEN],
}

#[test]
fn published_encrypted_handshake_vectors_are_reproducible() {
    let generated = render_vectors();
    assert_eq!(
        generated,
        include_str!("../test-vectors/encrypted-handshake-v1.txt"),
        "the frozen vector must match the deterministic construction"
    );
}

#[allow(clippy::too_many_lines)] // The linear field order is the vector file format.
fn render_vectors() -> String {
    let provider = RustCryptoProvider::default();
    let hybrid = HybridFixture::build();
    let initiator =
        VectorIdentity::from_seeds(&provider, &INITIATOR_ED25519_SEED, &INITIATOR_ML_DSA_SEED);
    let responder =
        VectorIdentity::from_seeds(&provider, &RESPONDER_ED25519_SEED, &RESPONDER_ML_DSA_SEED);
    let aes = build_suite_vector(
        &provider,
        &initiator,
        &responder,
        &hybrid,
        CipherSuite::Aes256GcmSha384,
        "aes_256_gcm_sha384",
    );
    let chacha = build_suite_vector(
        &provider,
        &initiator,
        &responder,
        &hybrid,
        CipherSuite::ChaCha20Poly1305Sha384,
        "chacha20_poly1305_sha384",
    );

    let mut output = String::new();
    output.push_str("# OGTP/1 draft 0.2 encrypted authenticated-handshake vector\n");
    output.push_str("# All values are synthetic and contain no production secret material.\n");
    output.push_str("# ML-DSA signatures use the FIPS 204 deterministic variant only so this vector is byte-exact.\n");
    output.push_str(
        "# Production OGTP signing remains randomized. X25519 and ML-KEM values are derived\n",
    );
    output.push_str(
        "# from the published deterministic test seeds and form the published hybrid secret.\n\n",
    );
    field(&mut output, "version", &1_u32.to_be_bytes());
    field(&mut output, "initiator_connection_id", b"initiator-cid");
    field(&mut output, "responder_connection_id", b"responder-cid");
    field(
        &mut output,
        "initiator_ed25519_seed",
        &INITIATOR_ED25519_SEED,
    );
    field(
        &mut output,
        "initiator_ml_dsa_65_seed",
        &INITIATOR_ML_DSA_SEED,
    );
    field(
        &mut output,
        "responder_ed25519_seed",
        &RESPONDER_ED25519_SEED,
    );
    field(
        &mut output,
        "responder_ml_dsa_65_seed",
        &RESPONDER_ML_DSA_SEED,
    );
    field(&mut output, "client_random", &CLIENT_RANDOM);
    field(&mut output, "server_random", &SERVER_RANDOM);
    field(&mut output, "cookie", &COOKIE);
    field(
        &mut output,
        "initiator_x25519_private_seed",
        &INITIATOR_X25519_PRIVATE_SEED,
    );
    field(
        &mut output,
        "initiator_x25519_public_key",
        &hybrid.initiator_x25519_public_key,
    );
    field(
        &mut output,
        "responder_x25519_private_seed",
        &RESPONDER_X25519_PRIVATE_SEED,
    );
    field(
        &mut output,
        "responder_x25519_public_key",
        &hybrid.responder_x25519_public_key,
    );
    field(
        &mut output,
        "initiator_ml_kem_768_seed",
        &INITIATOR_ML_KEM_SEED,
    );
    field(
        &mut output,
        "responder_ml_kem_768_randomness",
        &RESPONDER_ML_KEM_RANDOMNESS,
    );
    render_public_value(
        &mut output,
        "initiator_ml_kem_768_encapsulation_key",
        &hybrid.ml_kem_encapsulation_key,
    );
    render_public_value(
        &mut output,
        "responder_ml_kem_768_ciphertext",
        &hybrid.ml_kem_ciphertext,
    );
    field(&mut output, "hybrid_shared_secret", &hybrid.shared_secret);
    field(
        &mut output,
        "response_message_id",
        &RESPONSE_MESSAGE_ID.to_be_bytes(),
    );
    field(
        &mut output,
        "finish_message_id",
        &FINISH_MESSAGE_ID.to_be_bytes(),
    );
    field(
        &mut output,
        "initiator_ed25519_public_key",
        &initiator.ed25519_public_key,
    );
    field(
        &mut output,
        "initiator_ml_dsa_65_public_key_sha384",
        &digest(&initiator.ml_dsa_public_key),
    );
    field(
        &mut output,
        "initiator_identity_fingerprint",
        &initiator.fingerprint,
    );
    field(
        &mut output,
        "responder_ed25519_public_key",
        &responder.ed25519_public_key,
    );
    field(
        &mut output,
        "responder_ml_dsa_65_public_key_sha384",
        &digest(&responder.ml_dsa_public_key),
    );
    field(
        &mut output,
        "responder_identity_fingerprint",
        &responder.fingerprint,
    );
    output.push('\n');
    render_suite(&mut output, &aes);
    render_suite(&mut output, &chacha);
    output
}

#[allow(clippy::too_many_lines, clippy::trivially_copy_pass_by_ref)] // The linear scenario keeps both transcript directions reviewable.
fn build_suite_vector(
    provider: &RustCryptoProvider,
    initiator: &VectorIdentity,
    responder: &VectorIdentity,
    hybrid: &HybridFixture,
    suite: CipherSuite,
    name: &'static str,
) -> SuiteVector {
    let session = SessionContext {
        version: 1,
        initiator_connection_id: b"initiator-cid",
        responder_connection_id: b"responder-cid",
    };
    let mut transcript = HandshakeTranscript::new(provider, session).expect("transcript");
    let hello = Hello {
        client_random: CLIENT_RANDOM,
        identity_fingerprint: initiator.fingerprint,
        cipher_suite_bitmap: CIPHER_SUITE_AES_256_GCM_SHA384_BIT
            | CIPHER_SUITE_CHACHA20_POLY1305_SHA384_BIT,
        capabilities: CAPABILITY_MULTIPATH_BIT,
        max_udp_payload: 1_200,
        max_paths: 2,
    };
    let mut hello_bytes = [0_u8; HELLO_LEN];
    hello.encode(&mut hello_bytes).expect("HELLO");
    transcript
        .record_hello(provider, &hello_bytes)
        .expect("record HELLO");

    let retry = Retry {
        server_random: SERVER_RANDOM,
        cookie: &COOKIE,
    };
    let mut retry_bytes = [0_u8; 66];
    let retry_len = retry.encode(&mut retry_bytes).expect("RETRY");
    transcript
        .record_retry(provider, &retry_bytes[..retry_len])
        .expect("record RETRY");

    let init = Init {
        hello,
        server_random: SERVER_RANDOM,
        cookie: &COOKIE,
        x25519_public_key: hybrid.initiator_x25519_public_key,
        ml_kem_encapsulation_key: &hybrid.ml_kem_encapsulation_key,
    };
    let mut init_bytes = [0_u8; INIT_FIXED_LEN + COOKIE.len()];
    let init_len = init.encode(&mut init_bytes).expect("INIT");
    transcript
        .record_init(provider, &init_bytes[..init_len])
        .expect("record INIT");

    let placeholder = [0_u8; ENCRYPTED_IDENTITY_AUTH_LEN];
    let response_prefix = Response {
        selected_cipher_suite: suite,
        negotiated_capabilities: CAPABILITY_MULTIPATH_BIT,
        max_udp_payload: 1_200,
        max_paths: 2,
        identity_fingerprint: responder.fingerprint,
        x25519_public_key: hybrid.responder_x25519_public_key,
        ml_kem_ciphertext: &hybrid.ml_kem_ciphertext,
        encrypted_identity_auth: &placeholder,
    };
    let mut placeholder_response = [0_u8; RESPONSE_LEN];
    response_prefix
        .encode(&mut placeholder_response)
        .expect("placeholder RESPONSE");
    let pre_auth_hash = transcript
        .record_response(provider, &placeholder_response)
        .expect("record RESPONSE prefix");
    let schedule = derive_schedule(&pre_auth_hash, &hybrid.shared_secret);

    let responder_signatures = responder.sign(AuthenticationRole::Responder, &pre_auth_hash);
    let prepared_responder = transcript
        .prepare_responder_auth(provider, responder_signatures.content(responder))
        .expect("prepare responder auth");
    let responder_finished_hash = *prepared_responder.authentication().finished();
    let responder_finished_mac = hmac(&schedule.responder_finished_key, &responder_finished_hash);
    let responder_auth = IdentityAuth {
        ed25519_public_key: responder.ed25519_public_key,
        ml_dsa_public_key: &responder.ml_dsa_public_key,
        ed25519_signature: responder_signatures.ed25519,
        ml_dsa_signature: &responder_signatures.ml_dsa,
        finished_mac: responder_finished_mac,
    };
    let mut responder_plaintext = [0_u8; IDENTITY_AUTH_LEN];
    responder_auth
        .encode(&mut responder_plaintext)
        .expect("responder plaintext");
    let responder_ciphertext = seal(
        suite,
        &schedule.responder_handshake_key,
        &schedule.responder_handshake_iv,
        RESPONSE_MESSAGE_ID,
        &pre_auth_hash,
        &responder_plaintext,
    );
    let responder_milestone = prepared_responder
        .commit(provider, &responder_finished_mac)
        .expect("commit responder auth");
    authenticate_peer_identity(
        provider,
        PeerAuthenticationContext {
            role: AuthenticationRole::Responder,
            signature_transcript_hash: responder_milestone.authentication.signature(),
            finished_transcript_hash: responder_milestone.authentication.finished(),
            finished_key: &schedule.responder_finished_key,
            announced_fingerprint: &responder.fingerprint,
            trust_anchor_fingerprint: &responder.fingerprint,
        },
        &responder_auth,
    )
    .expect("deterministic responder identity verifies");

    let response = Response {
        encrypted_identity_auth: &responder_ciphertext,
        ..response_prefix
    };
    let mut response_wire = vec![0_u8; RESPONSE_LEN];
    response.encode(&mut response_wire).expect("RESPONSE");
    assert_eq!(
        &response_wire[..RESPONSE_FIXED_LEN],
        &placeholder_response[..RESPONSE_FIXED_LEN]
    );

    let initiator_signature_hash = *responder_milestone.initiator_signature();
    let initiator_signatures =
        initiator.sign(AuthenticationRole::Initiator, &initiator_signature_hash);
    let prepared_initiator = transcript
        .prepare_initiator_auth(provider, initiator_signatures.content(initiator))
        .expect("prepare initiator auth");
    let initiator_finished_hash = *prepared_initiator.authentication().finished();
    let initiator_finished_mac = hmac(&schedule.initiator_finished_key, &initiator_finished_hash);
    let initiator_auth = IdentityAuth {
        ed25519_public_key: initiator.ed25519_public_key,
        ml_dsa_public_key: &initiator.ml_dsa_public_key,
        ed25519_signature: initiator_signatures.ed25519,
        ml_dsa_signature: &initiator_signatures.ml_dsa,
        finished_mac: initiator_finished_mac,
    };
    let mut initiator_plaintext = [0_u8; IDENTITY_AUTH_LEN];
    initiator_auth
        .encode(&mut initiator_plaintext)
        .expect("initiator plaintext");
    let initiator_ciphertext = seal(
        suite,
        &schedule.initiator_handshake_key,
        &schedule.initiator_handshake_iv,
        FINISH_MESSAGE_ID,
        &initiator_signature_hash,
        &initiator_plaintext,
    );
    let initiator_milestone = prepared_initiator
        .commit(provider, &initiator_finished_mac)
        .expect("commit initiator auth");
    authenticate_peer_identity(
        provider,
        PeerAuthenticationContext {
            role: AuthenticationRole::Initiator,
            signature_transcript_hash: initiator_milestone.authentication.signature(),
            finished_transcript_hash: initiator_milestone.authentication.finished(),
            finished_key: &schedule.initiator_finished_key,
            announced_fingerprint: &initiator.fingerprint,
            trust_anchor_fingerprint: &initiator.fingerprint,
        },
        &initiator_auth,
    )
    .expect("deterministic initiator identity verifies");

    let finish = Finish {
        encrypted_identity_auth: &initiator_ciphertext,
    };
    let mut finish_wire = vec![0_u8; FINISH_LEN];
    finish.encode(&mut finish_wire).expect("FINISH");
    let full_hash = *initiator_milestone.full();
    let initiator_application_secret = derive(
        &schedule.master_secret,
        LABEL_INITIATOR_APPLICATION,
        &full_hash,
    );
    let responder_application_secret = derive(
        &schedule.master_secret,
        LABEL_RESPONDER_APPLICATION,
        &full_hash,
    );

    SuiteVector {
        name,
        pre_auth_hash,
        responder_signatures: responder_signatures.digest(),
        responder_finished_hash,
        responder_finished_mac,
        responder_plaintext: digest(&responder_plaintext),
        responder_ciphertext,
        response_wire,
        initiator_signature_hash,
        initiator_signatures: initiator_signatures.digest(),
        initiator_finished_hash,
        initiator_finished_mac,
        initiator_plaintext: digest(&initiator_plaintext),
        initiator_ciphertext,
        finish_wire,
        full_hash,
        schedule,
        initiator_application_secret,
        responder_application_secret,
    }
}

fn derive_schedule(pre_auth_hash: &Sha384Digest, hybrid_shared_secret: &[u8; 64]) -> KeySchedule {
    let zero = [0_u8; HASH_LEN];
    let empty_hash = digest(&[]);
    let early_secret = extract(&zero, &zero);
    let derived_early = derive(&early_secret, LABEL_DERIVED, &empty_hash);
    let handshake_secret = extract(&derived_early, hybrid_shared_secret);
    let initiator_handshake = derive(&handshake_secret, LABEL_INITIATOR_HANDSHAKE, pre_auth_hash);
    let responder_handshake = derive(&handshake_secret, LABEL_RESPONDER_HANDSHAKE, pre_auth_hash);
    let derived_handshake = derive(&handshake_secret, LABEL_DERIVED, &empty_hash);
    KeySchedule {
        initiator_finished_key: expand_label(&initiator_handshake, LABEL_FINISHED, &[]),
        responder_finished_key: expand_label(&responder_handshake, LABEL_FINISHED, &[]),
        initiator_handshake_key: expand_label(&initiator_handshake, LABEL_KEY, &[]),
        initiator_handshake_iv: expand_label(&initiator_handshake, LABEL_IV, &[]),
        responder_handshake_key: expand_label(&responder_handshake, LABEL_KEY, &[]),
        responder_handshake_iv: expand_label(&responder_handshake, LABEL_IV, &[]),
        master_secret: extract(&derived_handshake, &zero),
    }
}

fn extract(salt: &[u8], input_key_material: &[u8]) -> [u8; HASH_LEN] {
    let mut mac = <HmacSha384 as Mac>::new_from_slice(salt).expect("HMAC key");
    mac.update(input_key_material);
    mac.finalize().into_bytes().into()
}

fn expand_label<const N: usize>(secret: &[u8], label: &str, context: &[u8]) -> [u8; N] {
    let mut info = [0_u8; 512];
    let written = encode_expand_label(
        u16::try_from(N).expect("vector output length fits"),
        label,
        context,
        &mut info,
    )
    .expect("canonical label");
    expand(secret, &info[..written])
}

fn expand<const N: usize>(secret: &[u8], info: &[u8]) -> [u8; N] {
    let mut output = [0_u8; N];
    let mut previous = [0_u8; HASH_LEN];
    let mut previous_length = 0;
    let mut written = 0;
    let mut counter = 1_u8;
    while written < output.len() {
        let mut mac = <HmacSha384 as Mac>::new_from_slice(secret).expect("HMAC key");
        mac.update(&previous[..previous_length]);
        mac.update(info);
        mac.update(&[counter]);
        previous = mac.finalize().into_bytes().into();
        previous_length = previous.len();
        let take = (output.len() - written).min(previous.len());
        output[written..written + take].copy_from_slice(&previous[..take]);
        written += take;
        counter = counter.checked_add(1).expect("HKDF output below limit");
    }
    output
}

fn derive(secret: &[u8], label: &str, transcript_hash: &[u8]) -> [u8; HASH_LEN] {
    expand_label(secret, label, transcript_hash)
}

fn hmac(key: &[u8], value: &[u8]) -> [u8; SHA384_OUTPUT_LEN] {
    let mut mac = <HmacSha384 as Mac>::new_from_slice(key).expect("HMAC key");
    mac.update(value);
    mac.finalize().into_bytes().into()
}

fn seal(
    suite: CipherSuite,
    key: &[u8; AEAD_KEY_LEN],
    iv: &[u8; AEAD_IV_LEN],
    message_id: u32,
    additional_data: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let nonce = handshake_nonce(iv, message_id);
    let mut output = plaintext.to_vec();
    let tag = match suite {
        CipherSuite::Aes256GcmSha384 => Aes256Gcm::new_from_slice(key)
            .expect("AES key")
            .encrypt_in_place_detached(AesNonce::from_slice(&nonce), additional_data, &mut output)
            .expect("AES vector sealing")
            .to_vec(),
        CipherSuite::ChaCha20Poly1305Sha384 => ChaCha20Poly1305::new_from_slice(key)
            .expect("ChaCha key")
            .encrypt_in_place_detached(
                ChaChaNonce::from_slice(&nonce),
                additional_data,
                &mut output,
            )
            .expect("ChaCha vector sealing")
            .to_vec(),
    };
    output.extend_from_slice(&tag);
    assert_eq!(output.len(), plaintext.len() + AEAD_TAG_LEN);
    output
}

#[allow(clippy::too_many_lines)] // The linear field order is the vector file format.
fn render_suite(output: &mut String, vector: &SuiteVector) {
    output.push('[');
    output.push_str(vector.name);
    output.push_str("]\n");
    field(output, "pre_auth_hash", &vector.pre_auth_hash);
    field(
        output,
        "initiator_finished_key",
        &vector.schedule.initiator_finished_key,
    );
    field(
        output,
        "responder_finished_key",
        &vector.schedule.responder_finished_key,
    );
    field(
        output,
        "initiator_handshake_key",
        &vector.schedule.initiator_handshake_key,
    );
    field(
        output,
        "initiator_handshake_iv",
        &vector.schedule.initiator_handshake_iv,
    );
    field(
        output,
        "responder_handshake_key",
        &vector.schedule.responder_handshake_key,
    );
    field(
        output,
        "responder_handshake_iv",
        &vector.schedule.responder_handshake_iv,
    );
    field(
        output,
        "responder_signatures_sha384",
        &vector.responder_signatures,
    );
    field(
        output,
        "responder_finished_hash",
        &vector.responder_finished_hash,
    );
    field(
        output,
        "responder_finished_mac",
        &vector.responder_finished_mac,
    );
    field(
        output,
        "responder_identity_plaintext_sha384",
        &vector.responder_plaintext,
    );
    render_ciphertext(
        output,
        "response_identity_ciphertext",
        &vector.responder_ciphertext,
    );
    field(
        output,
        "response_wire_sha384",
        &digest(&vector.response_wire),
    );
    field(
        output,
        "initiator_signature_hash",
        &vector.initiator_signature_hash,
    );
    field(
        output,
        "initiator_signatures_sha384",
        &vector.initiator_signatures,
    );
    field(
        output,
        "initiator_finished_hash",
        &vector.initiator_finished_hash,
    );
    field(
        output,
        "initiator_finished_mac",
        &vector.initiator_finished_mac,
    );
    field(
        output,
        "initiator_identity_plaintext_sha384",
        &vector.initiator_plaintext,
    );
    render_ciphertext(
        output,
        "finish_identity_ciphertext",
        &vector.initiator_ciphertext,
    );
    field(output, "finish_wire_sha384", &digest(&vector.finish_wire));
    field(output, "full_hash", &vector.full_hash);
    field(
        output,
        "initiator_application_secret",
        &vector.initiator_application_secret,
    );
    field(
        output,
        "responder_application_secret",
        &vector.responder_application_secret,
    );
    output.push('\n');
}

fn render_ciphertext(output: &mut String, name: &str, value: &[u8]) {
    text_field(output, &format!("{name}_length"), &value.len().to_string());
    field(output, &format!("{name}_sha384"), &digest(value));
    field(output, &format!("{name}_prefix_32"), &value[..32]);
    field(
        output,
        &format!("{name}_suffix_32"),
        &value[value.len() - 32..],
    );
}

fn render_public_value(output: &mut String, name: &str, value: &[u8]) {
    render_ciphertext(output, name, value);
}

fn field(output: &mut String, name: &str, value: &[u8]) {
    text_field(output, name, &hex(value));
}

fn text_field(output: &mut String, name: &str, value: &str) {
    output.push_str(name);
    output.push('=');
    output.push_str(value);
    output.push('\n');
}

fn hex(value: &[u8]) -> String {
    use core::fmt::Write as _;

    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        write!(output, "{byte:02x}").expect("String writes are infallible");
    }
    output
}

fn digest(value: &[u8]) -> Sha384Digest {
    Sha384::digest(value).into()
}

fn digest_parts(parts: &[&[u8]]) -> Sha384Digest {
    let mut digest = Sha384::new();
    for part in parts {
        digest.update(part);
    }
    digest.finalize().into()
}
