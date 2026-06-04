//! CramFSRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a CramFS filesystem image.
#[derive(Debug, Clone, Copy)]
pub struct CramFSRecognizer;

impl Recognizer for CramFSRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..4] == [0x45, 0x3d, 0xcd, 0x28][..] {
                return Some("File appears to be a CramFS filesystem image".to_string());
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
        assert!(CramFSRecognizer.recognize(&[0x45, 0x3d, 0xcd, 0x28]).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 4];
        assert!(CramFSRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x00; 3];
        assert!(CramFSRecognizer.recognize(&data).is_none());
    }
}
