use core::convert::Infallible;

use ogtp::handshake::IDENTITY_FINGERPRINT_LEN;
use ogtp::manifest::{MERKLE_ROOT_LEN, ManifestHeader, OBJECT_ID_LEN};
use ogtp::merkle::{MerkleHash, MerkleReducer, Sha384Provider};
use ogtp::transcript::TranscriptSink;
use sha2::{Digest, Sha384};

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

    fn finish_sha384(&self, context: Self::Context) -> Result<MerkleHash, Self::Error> {
        Ok(context.0.finalize().into())
    }
}

fn raw_vector(name: &str) -> &str {
    let prefix = format!("{name}=");
    include_str!("../test-vectors/merkle-reducer-v1.txt")
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
fn published_bounded_merkle_reduction_is_reproducible() {
    let header = ManifestHeader {
        object_id: fixed_vector::<OBJECT_ID_LEN>("object_id"),
        object_size: u64::from_be_bytes(fixed_vector("object_size")),
        chunk_size: u32::from_be_bytes(fixed_vector("chunk_size")),
        chunk_count: u32::from_be_bytes(fixed_vector("chunk_count")),
        merkle_root: fixed_vector::<MERKLE_ROOT_LEN>("root_sha384"),
        signer_identity_fingerprint: [0x55; IDENTITY_FINGERPRINT_LEN],
    };
    let provider = RustCryptoSha384;
    let mut reducer = MerkleReducer::new(header).expect("vector geometry is valid");

    for chunk_index in 0..header.chunk_count {
        let chunk_length = if chunk_index + 1 == header.chunk_count {
            usize::try_from(
                header.object_size - u64::from(chunk_index) * u64::from(header.chunk_size),
            )
            .expect("final chunk length fits")
        } else {
            usize::try_from(header.chunk_size).expect("chunk size fits")
        };
        let chunk = (0..chunk_length)
            .map(|offset| {
                u8::try_from(
                    (usize::try_from(chunk_index).expect("index fits") * 17 + offset * 31 + 7)
                        & 0xff,
                )
                .expect("masked byte fits")
            })
            .collect::<Vec<_>>();
        let hashed = reducer
            .hash_chunk(&provider, chunk_index, &chunk)
            .expect("vector chunk hashes");
        assert_eq!(
            hashed.digest(),
            &fixed_vector::<MERKLE_ROOT_LEN>(&format!("leaf_{chunk_index}"))
        );
        reducer
            .push_hashed_chunk(&provider, hashed)
            .expect("vector leaf reduces");
    }

    assert_eq!(
        reducer
            .computed_root(&provider)
            .expect("vector root computes"),
        header.merkle_root
    );
    reducer
        .verify_manifest_root(&provider)
        .expect("vector root verifies");
}
