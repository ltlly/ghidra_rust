//! DmgRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be an Apple disk image (DMG).
#[derive(Debug, Clone, Copy)]
pub struct DmgRecognizer;

impl Recognizer for DmgRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..2] == [0x78, 0x01][..] {
                return Some("File appears to be an Apple disk image (DMG)".to_string());
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
        assert!(DmgRecognizer.recognize(&[0x78, 0x01]).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 2];
        assert!(DmgRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x00; 1];
        assert!(DmgRecognizer.recognize(&data).is_none());
    }
}
