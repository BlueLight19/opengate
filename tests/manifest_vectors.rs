use ogtp::handshake::{ED25519_SIGNATURE_LEN, IDENTITY_FINGERPRINT_LEN, ML_DSA_65_SIGNATURE_LEN};
use ogtp::manifest::{
    MAX_SIGNED_MANIFEST_LEN, MERKLE_ROOT_LEN, Manifest, ManifestFragment, ManifestHeader,
    feed_chunk_leaf_input, feed_empty_root_input, feed_manifest_signature_input,
    feed_merkle_node_input,
};
use ogtp::transcript::TranscriptSink;
use ogtp::wire::control::{ControlFrameIter, ControlType, encode_control_frame};
use sha2::{Digest, Sha384};

#[derive(Default)]
struct Recorder(Vec<u8>);

impl TranscriptSink for Recorder {
    fn update(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
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

fn raw_vector(name: &str) -> &str {
    let prefix = format!("{name}=");
    include_str!("../test-vectors/manifest-v1.txt")
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing vector {name}"))
}

fn vector(name: &str) -> Vec<u8> {
    decode_hex(raw_vector(name))
}

fn fixed_vector<const N: usize>(name: &str) -> [u8; N] {
    vector(name)
        .try_into()
        .unwrap_or_else(|value: Vec<u8>| panic!("{name} has length {}, expected {N}", value.len()))
}

fn header() -> ManifestHeader {
    ManifestHeader {
        object_id: fixed_vector("object_id"),
        object_size: u64::from_be_bytes(fixed_vector("object_size")),
        chunk_size: u32::from_be_bytes(fixed_vector("chunk_size")),
        chunk_count: u32::from_be_bytes(fixed_vector("chunk_count")),
        merkle_root: fixed_vector("merkle_root"),
        signer_identity_fingerprint: fixed_vector::<IDENTITY_FINGERPRINT_LEN>("signer_fingerprint"),
    }
}

#[test]
fn published_signed_manifest_is_reproducible() {
    let display_name = core::str::from_utf8(&vector("display_name"))
        .expect("vector display name is UTF-8")
        .to_owned();
    let mut unsigned = [0_u8; 512];
    let unsigned_len = header()
        .encode_unsigned(&display_name, &mut unsigned)
        .expect("unsigned manifest encodes");
    assert_eq!(&unsigned[..unsigned_len], vector("unsigned_manifest"));
    let unsigned_hash = Sha384::digest(&unsigned[..unsigned_len]);
    assert_eq!(&unsigned_hash[..], vector("unsigned_sha384"));

    let mut signature_input = Recorder::default();
    feed_manifest_signature_input(&mut signature_input, &unsigned_hash.into());
    assert_eq!(signature_input.0, vector("signature_input"));

    let ed25519 = [0xed; ED25519_SIGNATURE_LEN];
    let ml_dsa = [0xda; ML_DSA_65_SIGNATURE_LEN];
    let mut signed = [0_u8; MAX_SIGNED_MANIFEST_LEN];
    let signed_len = header()
        .encode_signed(&display_name, &ed25519, &ml_dsa, &mut signed)
        .expect("signed manifest encodes");
    let published_length = raw_vector("signed_manifest_length")
        .parse::<usize>()
        .expect("decimal manifest length");
    assert_eq!(signed_len, published_length);
    assert_eq!(
        &Sha384::digest(&signed[..signed_len])[..],
        vector("signed_manifest_sha384")
    );

    let decoded = Manifest::decode(&signed[..signed_len]).expect("signed manifest decodes");
    assert_eq!(decoded.header, header());
    assert_eq!(decoded.display_name, display_name);
    assert_eq!(decoded.ed25519_signature(), ed25519);
    assert_eq!(decoded.ml_dsa_65_signature(), ml_dsa);

    let fragment = ManifestFragment {
        object_slot: 0x0102_0304,
        manifest_length: u16::try_from(signed_len).expect("manifest length fits"),
        fragment_offset: 0,
        fragment: &signed[..64],
    };
    let mut fragment_value = [0_u8; 128];
    let fragment_len = fragment
        .encode(&mut fragment_value)
        .expect("manifest fragment encodes");
    assert_eq!(
        &fragment_value[..fragment_len],
        vector("first_fragment_value")
    );
    let mut tlv = [0_u8; 128];
    let tlv_len = encode_control_frame(
        ControlType::Manifest as u8,
        &fragment_value[..fragment_len],
        &mut tlv,
    )
    .expect("fragment TLV encodes");
    assert_eq!(&tlv[..tlv_len], vector("first_fragment_tlv"));
    let frame = ControlFrameIter::new(&tlv[..tlv_len])
        .next()
        .expect("one frame")
        .expect("valid frame");
    assert_eq!(frame.known_type(), Some(ControlType::Manifest));
    assert_eq!(ManifestFragment::decode(frame.value), Ok(fragment));
}

#[test]
fn published_merkle_inputs_are_reproducible() {
    let object_id = fixed_vector("object_id");
    let mut leaf = Recorder::default();
    feed_chunk_leaf_input(&mut leaf, &object_id, 3, b"OGTP manifest vector chunk")
        .expect("vector chunk length fits");
    assert_eq!(leaf.0, vector("leaf_input"));
    let leaf_hash: [u8; MERKLE_ROOT_LEN] = Sha384::digest(&leaf.0).into();
    assert_eq!(leaf_hash, fixed_vector("leaf_sha384"));

    let mut node = Recorder::default();
    feed_merkle_node_input(&mut node, 1, &leaf_hash, &[0x55; MERKLE_ROOT_LEN]);
    assert_eq!(node.0, vector("node_input"));
    assert_eq!(&Sha384::digest(&node.0)[..], vector("node_sha384"));

    let mut empty = Recorder::default();
    feed_empty_root_input(&mut empty, &object_id);
    assert_eq!(empty.0, vector("empty_input"));
    assert_eq!(&Sha384::digest(&empty.0)[..], vector("empty_sha384"));
}
