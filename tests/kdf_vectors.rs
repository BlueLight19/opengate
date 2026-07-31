use hmac::{Hmac, Mac};
use ogtp::kdf::{
    HASH_LEN, LABEL_DERIVED, LABEL_FINISHED, LABEL_HEADER_PROTECTION, LABEL_INITIATOR_APPLICATION,
    LABEL_INITIATOR_HANDSHAKE, LABEL_IV, LABEL_KEY, LABEL_PATH, LABEL_RESPONDER_APPLICATION,
    LABEL_RESPONDER_HANDSHAKE, LABEL_TRAFFIC_UPDATE, encode_expand_label,
};
use sha2::{Digest, Sha384};

type HmacSha384 = Hmac<Sha384>;

fn extract(salt: &[u8], input_key_material: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha384::new_from_slice(salt).expect("HMAC accepts arbitrary key sizes");
    mac.update(input_key_material);
    mac.finalize().into_bytes().to_vec()
}

fn expand(secret: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(length);
    let mut previous = Vec::new();
    let mut counter = 1_u8;
    while output.len() < length {
        let mut mac = HmacSha384::new_from_slice(secret).expect("valid HKDF PRK");
        mac.update(&previous);
        mac.update(info);
        mac.update(&[counter]);
        previous = mac.finalize().into_bytes().to_vec();
        output.extend_from_slice(&previous);
        counter = counter
            .checked_add(1)
            .expect("test output is below HKDF limit");
    }
    output.truncate(length);
    output
}

fn expand_label(secret: &[u8], label: &str, context: &[u8], length: usize) -> Vec<u8> {
    let mut info = [0_u8; 512];
    let written = encode_expand_label(
        u16::try_from(length).expect("test length fits"),
        label,
        context,
        &mut info,
    )
    .expect("test label is canonical");
    expand(secret, &info[..written], length)
}

fn derive(secret: &[u8], label: &str, transcript_hash: &[u8]) -> Vec<u8> {
    expand_label(secret, label, transcript_hash, HASH_LEN)
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
    let value = include_str!("../test-vectors/kdf-sha384-v1.txt")
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing vector {name}"));
    decode_hex(value)
}

#[test]
fn published_key_schedule_vector_is_reproducible() {
    let zero = [0_u8; HASH_LEN];
    let empty_hash = Sha384::digest([]).to_vec();
    assert_eq!(empty_hash, vector("empty_hash"));

    let hybrid = vector("hybrid");
    let pre_auth_hash = vector("pre_auth_hash");
    let full_hash = vector("full_hash");
    let dcid = vector("path_dcid");

    let early_secret = extract(&zero, &zero);
    assert_eq!(early_secret, vector("early_secret"));
    let derived_early = derive(&early_secret, LABEL_DERIVED, &empty_hash);
    assert_eq!(derived_early, vector("derived_early"));
    let handshake_secret = extract(&derived_early, &hybrid);
    assert_eq!(handshake_secret, vector("handshake_secret"));

    let initiator_handshake = derive(&handshake_secret, LABEL_INITIATOR_HANDSHAKE, &pre_auth_hash);
    let responder_handshake = derive(&handshake_secret, LABEL_RESPONDER_HANDSHAKE, &pre_auth_hash);
    assert_eq!(initiator_handshake, vector("i_hs"));
    assert_eq!(responder_handshake, vector("r_hs"));
    assert_eq!(
        expand_label(&initiator_handshake, LABEL_FINISHED, &[], HASH_LEN),
        vector("i_finished_key")
    );
    assert_eq!(
        expand_label(&responder_handshake, LABEL_FINISHED, &[], HASH_LEN),
        vector("r_finished_key")
    );
    assert_eq!(
        expand_label(&initiator_handshake, LABEL_KEY, &[], 32),
        vector("i_handshake_key")
    );
    assert_eq!(
        expand_label(&initiator_handshake, LABEL_IV, &[], 12),
        vector("i_handshake_iv")
    );
    assert_eq!(
        expand_label(&responder_handshake, LABEL_KEY, &[], 32),
        vector("r_handshake_key")
    );
    assert_eq!(
        expand_label(&responder_handshake, LABEL_IV, &[], 12),
        vector("r_handshake_iv")
    );

    let derived_handshake = derive(&handshake_secret, LABEL_DERIVED, &empty_hash);
    assert_eq!(derived_handshake, vector("derived_handshake"));
    let master_secret = extract(&derived_handshake, &zero);
    assert_eq!(master_secret, vector("master_secret"));
    let initiator_application = derive(&master_secret, LABEL_INITIATOR_APPLICATION, &full_hash);
    let responder_application = derive(&master_secret, LABEL_RESPONDER_APPLICATION, &full_hash);
    assert_eq!(initiator_application, vector("i_ap"));
    assert_eq!(responder_application, vector("r_ap"));

    let initiator_path = expand_label(&initiator_application, LABEL_PATH, &dcid, HASH_LEN);
    let responder_path = expand_label(&responder_application, LABEL_PATH, &dcid, HASH_LEN);
    assert_eq!(initiator_path, vector("i_path_0001020304050607"));
    assert_eq!(responder_path, vector("r_path_0001020304050607"));
    assert_eq!(
        expand_label(&initiator_path, LABEL_KEY, &[], 32),
        vector("i_path_key")
    );
    assert_eq!(
        expand_label(&initiator_path, LABEL_IV, &[], 12),
        vector("i_path_iv")
    );
    assert_eq!(
        expand_label(&initiator_path, LABEL_HEADER_PROTECTION, &[], 32),
        vector("i_path_hp")
    );
    assert_eq!(
        expand_label(&initiator_application, LABEL_TRAFFIC_UPDATE, &[], HASH_LEN,),
        vector("next_i_ap")
    );
}
