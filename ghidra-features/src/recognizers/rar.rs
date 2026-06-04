//! RarRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a RAR compressed file.
#[derive(Debug, Clone, Copy)]
pub struct RarRecognizer;

impl Recognizer for RarRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..6] == [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07][..] {
                return Some("File appears to be a RAR compressed file".to_string());
            }
        }
        None
    }

    fn bytes_required(&self) -> usize {
        6
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recognize() {
        assert!(RarRecognizer.recognize(&[0x52, 0x61, 0x72, 0x21, 0x1a, 0x07]).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 6];
        assert!(RarRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x00; 5];
        assert!(RarRecognizer.recognize(&data).is_none());
    }
}
