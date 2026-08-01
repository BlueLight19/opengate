use ogtp::flow::{CREDIT_VALUE_LEN, Credit};
use ogtp::wire::control::{
    ChunkRange, Commit, CommitHeader, ControlFrameIter, ControlType, Resume, ResumeHeader,
    encode_control_frame,
};

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
    let value = include_str!("../test-vectors/control-values-v1.txt")
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing vector {name}"));
    decode_hex(value)
}

fn wrap(frame_type: ControlType, value: &[u8]) -> Vec<u8> {
    let mut output = vec![0_u8; value.len() + 3];
    let written = encode_control_frame(frame_type as u8, value, &mut output)
        .expect("published value fits a CONTROL TLV");
    output.truncate(written);
    output
}

#[test]
fn published_credit_value_is_reproducible() {
    let credit = Credit {
        sequence: 0x0102_0304_0506_0708,
        max_uncommitted_bytes: 0x4000_0000,
        max_inflight_fragments: 0x0001_0000,
    };
    let mut value = [0_u8; CREDIT_VALUE_LEN];
    credit.encode(&mut value).expect("CREDIT value encodes");

    assert_eq!(value.as_slice(), vector("credit_value"));
    assert_eq!(wrap(ControlType::Credit, &value), vector("credit_tlv"));
    let published_tlv = vector("credit_tlv");
    let frame = ControlFrameIter::new(&published_tlv)
        .next()
        .expect("vector contains a frame")
        .expect("frame is structurally valid");
    assert_eq!(frame.known_type(), Some(ControlType::Credit));
    assert_eq!(Credit::decode(frame.value), Ok(credit));
}

#[test]
fn published_commit_value_is_reproducible() {
    let header = CommitHeader {
        sequence: 0x1112_1314_1516_1718,
        object_slot: 0x0102_0304,
        object_complete: true,
    };
    let ranges = [
        ChunkRange { start: 0, count: 3 },
        ChunkRange { start: 5, count: 2 },
    ];
    let mut value = [0_u8; 64];
    let written = header
        .encode(&ranges, &mut value)
        .expect("COMMIT value encodes");

    assert_eq!(&value[..written], vector("commit_value"));
    assert_eq!(
        wrap(ControlType::Commit, &value[..written]),
        vector("commit_tlv")
    );
    let published_value = vector("commit_value");
    let decoded = Commit::decode(&published_value).expect("published COMMIT decodes");
    assert_eq!(decoded.header, header);
    assert_eq!(decoded.ranges().collect::<Vec<_>>(), ranges);
}

#[test]
fn published_resume_value_is_reproducible() {
    let header = ResumeHeader {
        sequence: 0x2122_2324_2526_2728,
        object_slot: 0x0102_0304,
        window_start: 0x1000,
        window_chunk_count: 0x100,
        final_window: true,
    };
    let ranges = [
        ChunkRange {
            start: 0,
            count: 10,
        },
        ChunkRange {
            start: 20,
            count: 5,
        },
    ];
    let mut value = [0_u8; 64];
    let written = header
        .encode(&ranges, &mut value)
        .expect("RESUME value encodes");

    assert_eq!(&value[..written], vector("resume_value"));
    assert_eq!(
        wrap(ControlType::Resume, &value[..written]),
        vector("resume_tlv")
    );
    let published_value = vector("resume_value");
    let decoded = Resume::decode(&published_value).expect("published RESUME decodes");
    assert_eq!(decoded.header, header);
    assert_eq!(decoded.ranges().collect::<Vec<_>>(), ranges);
}
