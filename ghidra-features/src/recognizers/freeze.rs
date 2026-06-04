//! FreezeRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a Freeze/Melt compressed file.
#[derive(Debug, Clone, Copy)]
pub struct FreezeRecognizer;

impl Recognizer for FreezeRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..2] == [0x1f, 0x9e][..] {
                return Some("File appears to be a Freeze/Melt compressed file".to_string());
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
        assert!(FreezeRecognizer.recognize(&[0x1f, 0x9e]).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 2];
        assert!(FreezeRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x00; 1];
        assert!(FreezeRecognizer.recognize(&data).is_none());
    }
}
