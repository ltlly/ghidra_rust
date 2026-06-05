//! Lightweight Base64 encoding/decoding for BSim elastic queries.
//!
//! Ports `ghidra.features.bsim.query.elastic.Base64Lite`.

const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// A lightweight Base64 encoder/decoder without padding.
///
/// Used by BSim's Elasticsearch backend for encoding binary
/// signature vectors.
pub struct Base64Lite;

impl Base64Lite {
    /// Encode bytes to Base64 string (no padding).
    pub fn encode(data: &[u8]) -> String {
        let mut result = String::with_capacity((data.len() * 4 + 2) / 3);
        for chunk in data.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
            let triple = (b0 << 16) | (b1 << 8) | b2;

            result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
            result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
            if chunk.len() > 1 {
                result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
            }
            if chunk.len() > 2 {
                result.push(CHARS[(triple & 0x3F) as usize] as char);
            }
        }
        result
    }

    /// Decode Base64 string to bytes (no padding expected).
    pub fn decode(s: &str) -> Result<Vec<u8>, &'static str> {
        let bytes = s.as_bytes();
        let mut result = Vec::with_capacity((bytes.len() * 3) / 4);
        let mut buf: u32 = 0;
        let mut bits: u32 = 0;

        for &b in bytes {
            let val = Self::char_to_val(b).ok_or("invalid base64 character")?;
            buf = (buf << 6) | val;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                result.push(((buf >> bits) & 0xFF) as u8);
            }
        }
        Ok(result)
    }

    fn char_to_val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(0), // padding
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let data = b"Hello, World!";
        let encoded = Base64Lite::encode(data);
        let decoded = Base64Lite::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_empty() {
        let encoded = Base64Lite::encode(b"");
        assert!(encoded.is_empty());
        let decoded = Base64Lite::decode(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_single_byte() {
        let data = [0xFF_u8];
        let encoded = Base64Lite::encode(&data);
        let decoded = Base64Lite::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }
}
