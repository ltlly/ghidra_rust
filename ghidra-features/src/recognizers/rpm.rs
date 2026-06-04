//! RpmRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be an RPM package.
#[derive(Debug, Clone, Copy)]
pub struct RpmRecognizer;

impl Recognizer for RpmRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..4] == [0xed, 0xab, 0xee, 0xdb][..] {
                return Some("File appears to be an RPM package".to_string());
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
        assert!(RpmRecognizer.recognize(&[0xed, 0xab, 0xee, 0xdb]).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 4];
        assert!(RpmRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x00; 3];
        assert!(RpmRecognizer.recognize(&data).is_none());
    }
}
