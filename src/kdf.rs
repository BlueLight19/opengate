//! Canonical HKDF label encoding for the OGTP/1 key schedule.
//!
//! This module only serializes HKDF `info` values. It deliberately does not
//! implement SHA-384, HMAC, HKDF, or any other cryptographic primitive.

use core::fmt;

pub const HASH_LEN: usize = 48;
pub const AEAD_KEY_LEN: usize = 32;
pub const AEAD_IV_LEN: usize = 12;
pub const HEADER_PROTECTION_KEY_LEN: usize = 32;
pub const LABEL_PREFIX: &[u8] = b"ogtp1 ";

pub const LABEL_DERIVED: &str = "derived";
pub const LABEL_INITIATOR_HANDSHAKE: &str = "i hs";
pub const LABEL_RESPONDER_HANDSHAKE: &str = "r hs";
pub const LABEL_INITIATOR_APPLICATION: &str = "i ap";
pub const LABEL_RESPONDER_APPLICATION: &str = "r ap";
pub const LABEL_FINISHED: &str = "finished";
pub const LABEL_PATH: &str = "path";
pub const LABEL_KEY: &str = "key";
pub const LABEL_IV: &str = "iv";
pub const LABEL_HEADER_PROTECTION: &str = "hp";
pub const LABEL_TRAFFIC_UPDATE: &str = "traffic upd";

/// Encodes the `info` argument for OGTP-Expand-Label.
///
/// The canonical structure is:
///
/// ```text
/// Output Length u16 | Label Length u8 | "ogtp1 " || Label
///                   | Context Length u8 | Context
/// ```
///
/// # Errors
///
/// Returns an error for an empty/non-ASCII/oversized label, an oversized
/// context, arithmetic overflow, or an undersized output buffer.
pub fn encode_expand_label(
    output_length: u16,
    label: &str,
    context: &[u8],
    output: &mut [u8],
) -> Result<usize, LabelError> {
    if label.is_empty() {
        return Err(LabelError::EmptyLabel);
    }
    if !label.is_ascii() {
        return Err(LabelError::NonAsciiLabel);
    }
    let full_label_length = LABEL_PREFIX
        .len()
        .checked_add(label.len())
        .ok_or(LabelError::LengthOverflow)?;
    let full_label_length =
        u8::try_from(full_label_length).map_err(|_| LabelError::LabelTooLong)?;
    let context_length = u8::try_from(context.len()).map_err(|_| LabelError::ContextTooLong)?;
    let needed = 2_usize
        .checked_add(1)
        .and_then(|value| value.checked_add(usize::from(full_label_length)))
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(context.len()))
        .ok_or(LabelError::LengthOverflow)?;
    if output.len() < needed {
        return Err(LabelError::BufferTooSmall {
            needed,
            available: output.len(),
        });
    }

    output[0..2].copy_from_slice(&output_length.to_be_bytes());
    output[2] = full_label_length;
    let mut cursor = 3;
    output[cursor..cursor + LABEL_PREFIX.len()].copy_from_slice(LABEL_PREFIX);
    cursor += LABEL_PREFIX.len();
    output[cursor..cursor + label.len()].copy_from_slice(label.as_bytes());
    cursor += label.len();
    output[cursor] = context_length;
    cursor += 1;
    output[cursor..needed].copy_from_slice(context);
    Ok(needed)
}

/// HKDF label-encoding errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LabelError {
    EmptyLabel,
    NonAsciiLabel,
    LabelTooLong,
    ContextTooLong,
    LengthOverflow,
    BufferTooSmall { needed: usize, available: usize },
}

impl fmt::Display for LabelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyLabel => formatter.write_str("HKDF label is empty"),
            Self::NonAsciiLabel => formatter.write_str("HKDF label is not ASCII"),
            Self::LabelTooLong => formatter.write_str("HKDF label is too long"),
            Self::ContextTooLong => formatter.write_str("HKDF context is too long"),
            Self::LengthOverflow => formatter.write_str("HKDF label length overflow"),
            Self::BufferTooSmall { needed, available } => {
                write!(
                    formatter,
                    "buffer too small: need {needed}, have {available}"
                )
            }
        }
    }
}

impl std::error::Error for LabelError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_label_matches_canonical_bytes() {
        let mut output = [0_u8; 64];
        let written = encode_expand_label(32, LABEL_KEY, &[], &mut output).expect("label encodes");
        assert_eq!(
            &output[..written],
            &[
                0x00, 0x20, 0x09, b'o', b'g', b't', b'p', b'1', b' ', b'k', b'e', b'y', 0x00
            ]
        );
    }

    #[test]
    fn context_is_length_prefixed_without_copying_elsewhere() {
        let context = [0xa5; HASH_LEN];
        let mut output = [0_u8; 128];
        let hash_len_u16 = u16::try_from(HASH_LEN).expect("SHA-384 output length fits u16");
        let hash_len_u8 = u8::try_from(HASH_LEN).expect("SHA-384 output length fits u8");
        let written = encode_expand_label(
            hash_len_u16,
            LABEL_INITIATOR_HANDSHAKE,
            &context,
            &mut output,
        )
        .expect("label encodes");
        assert_eq!(output[0..2], [0, hash_len_u8]);
        assert_eq!(output[2], 10);
        assert_eq!(&output[3..13], b"ogtp1 i hs");
        assert_eq!(output[13], hash_len_u8);
        assert_eq!(&output[14..written], &context);
    }

    #[test]
    fn invalid_labels_and_contexts_are_rejected() {
        let mut output = [0_u8; 512];
        assert_eq!(
            encode_expand_label(32, "", &[], &mut output),
            Err(LabelError::EmptyLabel)
        );
        assert_eq!(
            encode_expand_label(32, "clé", &[], &mut output),
            Err(LabelError::NonAsciiLabel)
        );
        assert_eq!(
            encode_expand_label(32, "key", &[0; 256], &mut output),
            Err(LabelError::ContextTooLong)
        );
    }
}
