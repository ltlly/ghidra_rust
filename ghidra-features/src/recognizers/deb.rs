//! DebRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a Debian package.
#[derive(Debug, Clone, Copy)]
pub struct DebRecognizer;

impl Recognizer for DebRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..7] == [0x21, 0x3c, 0x61, 0x72, 0x63, 0x68, 0x3e][..] {
                return Some("File appears to be a Debian package".to_string());
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
        assert!(DebRecognizer.recognize(&[0x21, 0x3c, 0x61, 0x72, 0x63, 0x68, 0x3e]).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 7];
        assert!(DebRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x00; 6];
        assert!(DebRecognizer.recognize(&data).is_none());
    }
}
