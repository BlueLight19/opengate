use core::convert::Infallible;

use hmac::{Hmac, Mac};
use ogtp::authentication::identity_fingerprint;
use ogtp::crypto::{SHA384_OUTPUT_LEN, Sha384Digest, Sha384Provider};
use ogtp::handshake::{ED25519_PUBLIC_KEY_LEN, IDENTITY_FINGERPRINT_LEN, ML_DSA_65_PUBLIC_KEY_LEN};
use ogtp::transcript::{AuthenticationRole, TranscriptSink, feed_signature_input};
use sha2::{Digest, Sha384};

type HmacSha384 = Hmac<Sha384>;

struct Sha384Context(Sha384);

impl TranscriptSink for Sha384Context {
    fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
}

struct RustCryptoSha384;

impl Sha384Provider for RustCryptoSha384 {
    type Context = Sha384Context;
    type Error = Infallible;

    fn start_sha384(&self) -> Result<Self::Context, Self::Error> {
        Ok(Sha384Context(Sha384::new()))
    }

    fn finish_sha384(&self, context: Self::Context) -> Result<Sha384Digest, Self::Error> {
        Ok(context.0.finalize().into())
    }
}

#[derive(Default)]
struct Recorder(Vec<u8>);

impl TranscriptSink for Recorder {
    fn update(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }
}

fn raw_vector(name: &str) -> &str {
    let prefix = format!("{name}=");
    include_str!("../test-vectors/authentication-v1.txt")
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing vector {name}"))
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

fn fixed_vector<const N: usize>(name: &str) -> [u8; N] {
    decode_hex(raw_vector(name))
        .try_into()
        .unwrap_or_else(|value: Vec<u8>| panic!("{name} has length {}, expected {N}", value.len()))
}

#[test]
fn published_identity_and_finished_inputs_are_reproducible() {
    let ed25519_public_key = fixed_vector::<ED25519_PUBLIC_KEY_LEN>("ed25519_public_key");
    let ml_dsa_65_public_key = core::array::from_fn::<_, ML_DSA_65_PUBLIC_KEY_LEN, _>(|index| {
        u8::try_from((index * 29 + 3) & 0xff).expect("masked byte fits")
    });
    let fingerprint = identity_fingerprint(
        &RustCryptoSha384,
        &ed25519_public_key,
        &ml_dsa_65_public_key,
    )
    .expect("SHA-384 provider is infallible");
    assert_eq!(
        fingerprint,
        fixed_vector::<IDENTITY_FINGERPRINT_LEN>("identity_fingerprint")
    );

    let signature_hash = fixed_vector("responder_signature_transcript_hash");
    let mut signature_input = Recorder::default();
    feed_signature_input(
        &mut signature_input,
        AuthenticationRole::Responder,
        &signature_hash,
    );
    assert_eq!(
        signature_input.0,
        decode_hex(raw_vector("responder_signature_input"))
    );

    let finished_key = fixed_vector::<SHA384_OUTPUT_LEN>("responder_finished_key");
    let finished_hash = fixed_vector::<SHA384_OUTPUT_LEN>("responder_finished_transcript_hash");
    let mut hmac = HmacSha384::new_from_slice(&finished_key).expect("fixed HMAC key is valid");
    hmac.update(&finished_hash);
    assert_eq!(
        &hmac.finalize().into_bytes()[..],
        decode_hex(raw_vector("responder_finished_mac"))
    );
}
