//! Streaming canonical transcript framing for OGTP/1.

use core::fmt;

use crate::handshake::FINISHED_MAC_LEN;
use crate::wire::{WireError, long::MAX_LONG_CONNECTION_ID_LEN};

pub const TRANSCRIPT_RECORD_HEADER_LEN: usize = 5;
pub const SIGNATURE_CONTEXT_PREFIX_LEN: usize = 64;
pub const RESPONDER_SIGNATURE_CONTEXT: &[u8] = b"OGTP/1 responder authentication";
pub const INITIATOR_SIGNATURE_CONTEXT: &[u8] = b"OGTP/1 initiator authentication";

/// Canonical transcript record types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TranscriptRecordType {
    Hello = 0x00,
    Retry = 0x01,
    Init = 0x02,
    ResponsePrefix = 0x03,
    ResponderAuthContent = 0x04,
    ResponderFinished = 0x05,
    InitiatorAuthContent = 0x06,
    InitiatorFinished = 0x07,
    SessionContext = 0xff,
}

/// Destination for streaming transcript bytes into a hash or test recorder.
pub trait TranscriptSink {
    fn update(&mut self, bytes: &[u8]);
}

/// Streams one canonical record into `sink` without allocation.
///
/// # Errors
///
/// Returns an error if `value` exceeds the 32-bit transcript length field.
pub fn feed_record(
    sink: &mut impl TranscriptSink,
    record_type: TranscriptRecordType,
    value: &[u8],
) -> Result<(), TranscriptError> {
    let value_length = u32::try_from(value.len()).map_err(|_| TranscriptError::ValueTooLong {
        length: value.len(),
    })?;
    let mut header = [0_u8; TRANSCRIPT_RECORD_HEADER_LEN];
    header[0] = record_type as u8;
    header[1..5].copy_from_slice(&value_length.to_be_bytes());
    sink.update(&header);
    sink.update(value);
    Ok(())
}

/// Session identifiers bound into the first transcript record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionContext<'a> {
    pub version: u32,
    pub initiator_connection_id: &'a [u8],
    pub responder_connection_id: &'a [u8],
}

impl SessionContext<'_> {
    /// Encodes the canonical session-context value.
    ///
    /// # Errors
    ///
    /// Returns an error for a Connection ID over 20 bytes, arithmetic overflow,
    /// or an undersized output buffer.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, TranscriptError> {
        validate_connection_id(self.initiator_connection_id)?;
        validate_connection_id(self.responder_connection_id)?;
        let needed = 6_usize
            .checked_add(self.initiator_connection_id.len())
            .and_then(|value| value.checked_add(self.responder_connection_id.len()))
            .ok_or(WireError::LengthOverflow)?;
        if output.len() < needed {
            return Err(WireError::BufferTooSmall {
                needed,
                available: output.len(),
            }
            .into());
        }
        output[0..4].copy_from_slice(&self.version.to_be_bytes());
        output[4] = u8::try_from(self.initiator_connection_id.len()).map_err(|_| {
            TranscriptError::ConnectionIdTooLong {
                length: self.initiator_connection_id.len(),
            }
        })?;
        let mut cursor = 5;
        output[cursor..cursor + self.initiator_connection_id.len()]
            .copy_from_slice(self.initiator_connection_id);
        cursor += self.initiator_connection_id.len();
        output[cursor] = u8::try_from(self.responder_connection_id.len()).map_err(|_| {
            TranscriptError::ConnectionIdTooLong {
                length: self.responder_connection_id.len(),
            }
        })?;
        cursor += 1;
        output[cursor..needed].copy_from_slice(self.responder_connection_id);
        Ok(needed)
    }
}

/// Authentication side used to choose the signature context string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationRole {
    Initiator,
    Responder,
}

/// Streams the contextualized Ed25519/ML-DSA signature input.
pub fn feed_signature_input(
    sink: &mut impl TranscriptSink,
    role: AuthenticationRole,
    transcript_hash: &[u8; FINISHED_MAC_LEN],
) {
    sink.update(&[0x20; SIGNATURE_CONTEXT_PREFIX_LEN]);
    sink.update(match role {
        AuthenticationRole::Initiator => INITIATOR_SIGNATURE_CONTEXT,
        AuthenticationRole::Responder => RESPONDER_SIGNATURE_CONTEXT,
    });
    sink.update(&[0]);
    sink.update(transcript_hash);
}

/// Transcript framing failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TranscriptError {
    Wire(WireError),
    ValueTooLong { length: usize },
    ConnectionIdTooLong { length: usize },
}

impl From<WireError> for TranscriptError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl fmt::Display for TranscriptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => error.fmt(formatter),
            Self::ValueTooLong { length } => {
                write!(formatter, "transcript value too long: {length}")
            }
            Self::ConnectionIdTooLong { length } => write!(
                formatter,
                "transcript Connection ID too long: {length}, maximum {MAX_LONG_CONNECTION_ID_LEN}"
            ),
        }
    }
}

impl std::error::Error for TranscriptError {}

fn validate_connection_id(connection_id: &[u8]) -> Result<(), TranscriptError> {
    if connection_id.len() > MAX_LONG_CONNECTION_ID_LEN {
        return Err(TranscriptError::ConnectionIdTooLong {
            length: connection_id.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder(Vec<u8>);

    impl TranscriptSink for Recorder {
        fn update(&mut self, bytes: &[u8]) {
            self.0.extend_from_slice(bytes);
        }
    }

    #[test]
    fn canonical_record_has_type_and_u32_length() {
        let mut recorder = Recorder::default();
        feed_record(&mut recorder, TranscriptRecordType::Hello, b"abc")
            .expect("record length fits");
        assert_eq!(recorder.0, [0, 0, 0, 0, 3, b'a', b'b', b'c']);
    }

    #[test]
    fn session_context_binds_version_and_both_connection_ids() {
        let context = SessionContext {
            version: 1,
            initiator_connection_id: b"init",
            responder_connection_id: b"resp",
        };
        let mut value = [0_u8; 64];
        let written = context.encode(&mut value).expect("context fits");
        assert_eq!(
            &value[..written],
            &[
                0, 0, 0, 1, 4, b'i', b'n', b'i', b't', 4, b'r', b'e', b's', b'p'
            ]
        );
    }

    #[test]
    fn signature_input_is_contextualized() {
        let hash = [0xa5; FINISHED_MAC_LEN];
        let mut recorder = Recorder::default();
        feed_signature_input(&mut recorder, AuthenticationRole::Responder, &hash);
        assert_eq!(
            &recorder.0[..SIGNATURE_CONTEXT_PREFIX_LEN],
            &[0x20; SIGNATURE_CONTEXT_PREFIX_LEN]
        );
        assert_eq!(
            &recorder.0[SIGNATURE_CONTEXT_PREFIX_LEN
                ..SIGNATURE_CONTEXT_PREFIX_LEN + RESPONDER_SIGNATURE_CONTEXT.len()],
            RESPONDER_SIGNATURE_CONTEXT
        );
        assert_eq!(recorder.0[recorder.0.len() - FINISHED_MAC_LEN - 1], 0);
        assert_eq!(&recorder.0[recorder.0.len() - FINISHED_MAC_LEN..], &hash);
    }
}
