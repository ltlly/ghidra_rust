//! ZooRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a Zoo archive.
#[derive(Debug, Clone, Copy)]
pub struct ZooRecognizer;

impl Recognizer for ZooRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..4] == [0xdc, 0xa7, 0xc4, 0xfd][..] {
                return Some("File appears to be a Zoo archive".to_string());
            }
        }
        None
    }

    fn bytes_required(&self) -> usize {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recognize() {
        assert!(ZooRecognizer.recognize(&[0xdc, 0xa7, 0xc4, 0xfd]).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 4];
        assert!(ZooRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x00; 3];
        assert!(ZooRecognizer.recognize(&data).is_none());
    }
}
