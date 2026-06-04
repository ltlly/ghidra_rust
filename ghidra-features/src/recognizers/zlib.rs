//! ZlibRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a ZLIB compressed file.
#[derive(Debug, Clone, Copy)]
pub struct ZlibRecognizer;

impl Recognizer for ZlibRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..2] == [0x78, 0x01][..] {
                return Some("File appears to be a ZLIB compressed file".to_string());
            }
        }
        None
    }

    fn bytes_required(&self) -> usize {
        2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recognize() {
        assert!(ZlibRecognizer.recognize(&[0x78, 0x01]).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 2];
        assert!(ZlibRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x00; 1];
        assert!(ZlibRecognizer.recognize(&data).is_none());
    }
}
