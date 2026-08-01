#![cfg(feature = "rustcrypto-provider")]

use core::mem::size_of;

use ogtp::authentication::{
    AuthenticationError, HybridAuthenticationProvider, PeerAuthenticationContext,
    VerificationResult, authenticate_peer_identity, handshake_signature_input, verify_manifest,
};
use ogtp::handshake::{
    ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN, FINISHED_MAC_LEN, IDENTITY_FINGERPRINT_LEN,
    IdentityAuth, ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN,
};
use ogtp::handshake_crypto::HandshakeCryptoProvider;
use ogtp::manifest::{MAX_SIGNED_MANIFEST_LEN, MIN_CHUNK_SIZE, Manifest, ManifestHeader};
use ogtp::rustcrypto_provider::{
    RustCryptoHybridSignature, RustCryptoIdentityKeyPair, RustCryptoProvider,
};
use ogtp::transcript::AuthenticationRole;

const ROLE: AuthenticationRole = AuthenticationRole::Responder;
const SIGNATURE_TRANSCRIPT_HASH: [u8; 48] = [0x31; 48];
const FINISHED_TRANSCRIPT_HASH: [u8; 48] = [0x42; 48];
const FINISHED_KEY: [u8; FINISHED_MAC_LEN] = [0x53; FINISHED_MAC_LEN];

struct AuthenticationFixture {
    key_pair: RustCryptoIdentityKeyPair,
    signature: RustCryptoHybridSignature,
    fingerprint: [u8; IDENTITY_FINGERPRINT_LEN],
    finished_mac: [u8; FINISHED_MAC_LEN],
}

impl AuthenticationFixture {
    fn new() -> Self {
        let provider = RustCryptoProvider::default();
        let key_pair = RustCryptoIdentityKeyPair::from_seed_bytes(&[0x64; 32], &[0x75; 32]);
        let signature = key_pair
            .sign_handshake(ROLE, &SIGNATURE_TRANSCRIPT_HASH)
            .expect("hybrid handshake signing succeeds");
        let fingerprint = key_pair
            .fingerprint(&provider)
            .expect("software SHA-384 succeeds");
        let mut finished_mac = [0_u8; FINISHED_MAC_LEN];
        provider
            .hmac_sha384(&FINISHED_KEY, &FINISHED_TRANSCRIPT_HASH, &mut finished_mac)
            .expect("software HMAC succeeds");
        Self {
            key_pair,
            signature,
            fingerprint,
            finished_mac,
        }
    }

    fn identity_auth(&self) -> IdentityAuth<'_> {
        IdentityAuth {
            ed25519_public_key: self.key_pair.ed25519_public_key(),
            ml_dsa_public_key: self.key_pair.ml_dsa_65_public_key(),
            ed25519_signature: *self.signature.ed25519(),
            ml_dsa_signature: self.signature.ml_dsa_65(),
            finished_mac: self.finished_mac,
        }
    }

    fn context(&self) -> PeerAuthenticationContext<'_> {
        PeerAuthenticationContext {
            role: ROLE,
            signature_transcript_hash: &SIGNATURE_TRANSCRIPT_HASH,
            finished_transcript_hash: &FINISHED_TRANSCRIPT_HASH,
            finished_key: &FINISHED_KEY,
            announced_fingerprint: &self.fingerprint,
            trust_anchor_fingerprint: &self.fingerprint,
        }
    }
}

#[test]
fn real_hybrid_identity_authentication_is_atomic_and_fail_closed() {
    let provider = RustCryptoProvider::default();
    let fixture = AuthenticationFixture::new();
    let identity =
        authenticate_peer_identity(&provider, fixture.context(), &fixture.identity_auth())
            .expect("both real signatures and Finished authenticate");
    assert_eq!(identity.fingerprint(), &fixture.fingerprint);
    assert_eq!(
        identity.ed25519_public_key(),
        &fixture.key_pair.ed25519_public_key()
    );
    assert_eq!(
        identity.ml_dsa_65_public_key(),
        fixture.key_pair.ml_dsa_65_public_key()
    );

    let mut invalid_finished = fixture.identity_auth();
    invalid_finished.finished_mac[0] ^= 1;
    assert_eq!(
        authenticate_peer_identity(&provider, fixture.context(), &invalid_finished),
        Err(AuthenticationError::InvalidFinishedMac)
    );

    let mut invalid_ed25519 = fixture.identity_auth();
    invalid_ed25519.ed25519_signature[0] ^= 1;
    assert_eq!(
        authenticate_peer_identity(&provider, fixture.context(), &invalid_ed25519),
        Err(AuthenticationError::InvalidEd25519Signature)
    );

    let mut invalid_ml_dsa_signature = *fixture.signature.ml_dsa_65();
    invalid_ml_dsa_signature[0] ^= 1;
    let mut invalid_ml_dsa = fixture.identity_auth();
    invalid_ml_dsa.ml_dsa_signature = &invalid_ml_dsa_signature;
    assert_eq!(
        authenticate_peer_identity(&provider, fixture.context(), &invalid_ml_dsa),
        Err(AuthenticationError::InvalidMlDsa65Signature)
    );

    let wrong_trust_anchor = [0_u8; IDENTITY_FINGERPRINT_LEN];
    let mut untrusted_context = fixture.context();
    untrusted_context.trust_anchor_fingerprint = &wrong_trust_anchor;
    assert_eq!(
        authenticate_peer_identity(&provider, untrusted_context, &fixture.identity_auth()),
        Err(AuthenticationError::TrustAnchorMismatch)
    );
}

#[test]
fn malformed_and_weak_verification_inputs_are_invalid_not_provider_failures() {
    let provider = RustCryptoProvider::default();
    let fixture = AuthenticationFixture::new();
    let message =
        handshake_signature_input(ROLE, &SIGNATURE_TRANSCRIPT_HASH).expect("fixed context fits");

    assert_eq!(
        provider.verify_ed25519(
            &[0_u8; ED25519_PUBLIC_KEY_LEN],
            message.as_bytes(),
            fixture.signature.ed25519(),
        ),
        Ok(VerificationResult::Invalid)
    );
    assert_eq!(
        provider.verify_ml_dsa_65(
            fixture.key_pair.ml_dsa_65_public_key(),
            message.as_bytes(),
            &[0xff; ML_DSA_65_SIGNATURE_LEN],
        ),
        Ok(VerificationResult::Invalid)
    );
}

#[test]
fn signed_manifest_is_bound_to_the_authenticated_hybrid_identity() {
    let provider = RustCryptoProvider::default();
    let fixture = AuthenticationFixture::new();
    let identity =
        authenticate_peer_identity(&provider, fixture.context(), &fixture.identity_auth())
            .expect("identity authenticates");
    let header = ManifestHeader {
        object_id: [0x86; 32],
        object_size: u64::from(MIN_CHUNK_SIZE),
        chunk_size: MIN_CHUNK_SIZE,
        chunk_count: 1,
        merkle_root: [0x97; 48],
        signer_identity_fingerprint: fixture.fingerprint,
    };
    let display_name = "bounded-object.bin";
    let mut unsigned = [0_u8; 512];
    let unsigned_length = header
        .encode_unsigned(display_name, &mut unsigned)
        .expect("unsigned manifest encodes");
    let signature = fixture
        .key_pair
        .sign_manifest(&unsigned[..unsigned_length])
        .expect("manifest signing succeeds");

    let mut signed = [0_u8; MAX_SIGNED_MANIFEST_LEN];
    let signed_length = header
        .encode_signed(
            display_name,
            signature.ed25519(),
            signature.ml_dsa_65(),
            &mut signed,
        )
        .expect("signed manifest encodes");
    let manifest = Manifest::decode(&signed[..signed_length]).expect("manifest decodes");
    let verified =
        verify_manifest(&provider, &identity, &manifest).expect("both manifest signatures verify");
    assert_eq!(verified.header(), header);

    signed[unsigned_length] ^= 1;
    let manifest = Manifest::decode(&signed[..signed_length]).expect("tampered manifest decodes");
    assert_eq!(
        verify_manifest(&provider, &identity, &manifest),
        Err(AuthenticationError::InvalidEd25519Signature)
    );
    signed[unsigned_length] ^= 1;

    signed[unsigned_length + ED25519_SIGNATURE_LEN] ^= 1;
    let manifest = Manifest::decode(&signed[..signed_length]).expect("tampered manifest decodes");
    assert_eq!(
        verify_manifest(&provider, &identity, &manifest),
        Err(AuthenticationError::InvalidMlDsa65Signature)
    );
}

#[test]
fn rfc_8032_vector_and_fixed_memory_bounds_hold() {
    let provider = RustCryptoProvider::default();
    let ed25519_seed = fixed_hex(
        "9d61b19deffd5a60ba844af492ec2cc4\
         4449c5697b326919703bac031cae7f60",
    );
    let expected_public_key = fixed_hex(
        "d75a980182b10ab7d54bfed3c964073a\
         0ee172f3daa62325af021a68f707511a",
    );
    let expected_signature = fixed_hex(
        "e5564300c360ac729086e2cc806e828a\
         84877f1eb8e5d974d873e06522490155\
         5fb8821590a33bacc61e39701cf9b46b\
         d25bf5f0595bbe24655141438e7a100b",
    );
    let key_pair = RustCryptoIdentityKeyPair::from_seed_bytes(&ed25519_seed, &[0xa8; 32]);
    assert_eq!(key_pair.ed25519_public_key(), expected_public_key);
    assert_eq!(
        provider.verify_ed25519(&expected_public_key, b"", &expected_signature),
        Ok(VerificationResult::Valid)
    );

    assert_eq!(
        size_of::<RustCryptoHybridSignature>(),
        ED25519_SIGNATURE_LEN + ML_DSA_65_SIGNATURE_LEN
    );
    assert!(
        size_of::<RustCryptoIdentityKeyPair>() <= 96 * 1024,
        "expanded identity key must remain explicitly bounded"
    );

    let generated = RustCryptoIdentityKeyPair::generate().expect("operating-system entropy works");
    assert_ne!(
        generated.ed25519_public_key(),
        [0_u8; ED25519_PUBLIC_KEY_LEN]
    );
    assert_ne!(
        generated.ml_dsa_65_public_key(),
        &[0_u8; ML_DSA_65_PUBLIC_KEY_LEN]
    );
}

fn fixed_hex<const N: usize>(value: &str) -> [u8; N] {
    let compact: String = value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    assert_eq!(compact.len(), N * 2);
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16)
            .expect("test vector contains hexadecimal bytes");
    }
    output
}
