//! AceRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be an ACE compressed file.
#[derive(Debug, Clone, Copy)]
pub struct AceRecognizer;

impl Recognizer for AceRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..7] == [0x2a, 0x2a, 0x41, 0x43, 0x45, 0x2a, 0x2a][..] {
                return Some("File appears to be an ACE compressed file".to_string());
            }
        }
        None
    }

    fn bytes_required(&self) -> usize {
        7
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recognize() {
        assert!(AceRecognizer.recognize(&[0x2a, 0x2a, 0x41, 0x43, 0x45, 0x2a, 0x2a]).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 7];
        assert!(AceRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x00; 6];
        assert!(AceRecognizer.recognize(&data).is_none());
    }
}
