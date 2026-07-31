//! Allocation-free codec for path and MTU probes.

use super::WireError;

/// Size of a PROBE before optional zero padding.
pub const PROBE_BASE_LEN: usize = 17;
/// Number of unpredictable token bytes in every PROBE.
pub const PROBE_TOKEN_LEN: usize = 16;

/// Assigned PROBE kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProbeKind {
    PathChallenge = 0x00,
    PathResponse = 0x01,
    MtuProbe = 0x02,
    MtuAck = 0x03,
}

impl ProbeKind {
    const fn from_wire(value: u8) -> Result<Self, WireError> {
        match value {
            0x00 => Ok(Self::PathChallenge),
            0x01 => Ok(Self::PathResponse),
            0x02 => Ok(Self::MtuProbe),
            0x03 => Ok(Self::MtuAck),
            _ => Err(WireError::UnknownProbeKind(value)),
        }
    }
}

/// Borrowed canonical PROBE plaintext.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeFrame<'a> {
    pub kind: ProbeKind,
    pub token: [u8; PROBE_TOKEN_LEN],
    pub padding: &'a [u8],
}

impl<'a> ProbeFrame<'a> {
    /// Encodes a PROBE and fills its requested padding with zeroes.
    ///
    /// # Errors
    ///
    /// Returns an error for arithmetic overflow or an undersized output buffer.
    pub fn encode(
        kind: ProbeKind,
        token: [u8; PROBE_TOKEN_LEN],
        padding_length: usize,
        output: &mut [u8],
    ) -> Result<usize, WireError> {
        let needed = PROBE_BASE_LEN
            .checked_add(padding_length)
            .ok_or(WireError::LengthOverflow)?;
        if output.len() < needed {
            return Err(WireError::BufferTooSmall {
                needed,
                available: output.len(),
            });
        }

        output[0] = kind as u8;
        output[1..PROBE_BASE_LEN].copy_from_slice(&token);
        output[PROBE_BASE_LEN..needed].fill(0);
        Ok(needed)
    }

    /// Decodes a canonical PROBE plaintext without copying its padding.
    ///
    /// # Errors
    ///
    /// Returns an error if the frame is truncated, its kind is unknown, or its
    /// authenticated padding contains a non-zero byte.
    pub fn decode(input: &'a [u8]) -> Result<Self, WireError> {
        if input.len() < PROBE_BASE_LEN {
            return Err(WireError::PacketTooShort {
                minimum: PROBE_BASE_LEN,
                actual: input.len(),
            });
        }
        let kind = ProbeKind::from_wire(input[0])?;
        let mut token = [0_u8; PROBE_TOKEN_LEN];
        token.copy_from_slice(&input[1..PROBE_BASE_LEN]);
        let padding = &input[PROBE_BASE_LEN..];
        if padding.iter().any(|byte| *byte != 0) {
            return Err(WireError::NonZeroProbePadding);
        }
        Ok(Self {
            kind,
            token,
            padding,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padded_probe_round_trip() {
        let token = [0xa5; PROBE_TOKEN_LEN];
        let mut output = [0xff; 64];
        let written =
            ProbeFrame::encode(ProbeKind::MtuProbe, token, 23, &mut output).expect("probe fits");
        let decoded = ProbeFrame::decode(&output[..written]).expect("probe decodes");

        assert_eq!(decoded.kind, ProbeKind::MtuProbe);
        assert_eq!(decoded.token, token);
        assert_eq!(decoded.padding, &[0; 23]);
    }

    #[test]
    fn unknown_kind_and_non_zero_padding_are_rejected() {
        let mut unknown = [0_u8; PROBE_BASE_LEN];
        unknown[0] = 0xff;
        assert_eq!(
            ProbeFrame::decode(&unknown),
            Err(WireError::UnknownProbeKind(0xff))
        );

        let mut padded = [0_u8; PROBE_BASE_LEN + 1];
        padded[0] = ProbeKind::PathChallenge as u8;
        padded[PROBE_BASE_LEN] = 1;
        assert_eq!(
            ProbeFrame::decode(&padded),
            Err(WireError::NonZeroProbePadding)
        );
    }
}
