//! AddressDBFieldCodec ported from DBTraceOverlaySpaceAdapter.AddressDBFieldCodec.
//!
//! Codec for encoding/decoding Address values in the trace database.

use std::io::{self, Read, Write};

/// Encode an address (space_id, offset) into bytes.
pub fn encode_address(space_id: u16, offset: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10);
    buf.extend_from_slice(&space_id.to_be_bytes());
    buf.extend_from_slice(&offset.to_be_bytes());
    buf
}

/// Decode an address from bytes, returning (space_id, offset).
pub fn decode_address(data: &[u8]) -> io::Result<(u16, u64)> {
    if data.len() < 10 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "address data too short"));
    }
    let space_id = u16::from_be_bytes([data[0], data[1]]);
    let offset = u64::from_be_bytes(data[2..10].try_into().unwrap());
    Ok((space_id, offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip() {
        let encoded = encode_address(42, 0xDEADBEEF);
        let (sid, off) = decode_address(&encoded).unwrap();
        assert_eq!(sid, 42);
        assert_eq!(off, 0xDEADBEEF);
    }

    #[test]
    fn test_decode_short_fails() {
        assert!(decode_address(&[1, 2, 3]).is_err());
    }
}
