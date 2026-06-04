//! LhaRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be an LHA compressed file.
#[derive(Debug, Clone, Copy)]
pub struct LhaRecognizer;

impl Recognizer for LhaRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..3] == [0x2d, 0x6c, 0x68][..] {
                return Some("File appears to be an LHA compressed file".to_string());
            }
        }
        None
    }

    fn bytes_required(&self) -> usize {
        3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recognize() {
        assert!(LhaRecognizer.recognize(&[0x2d, 0x6c, 0x68]).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 3];
        assert!(LhaRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x00; 2];
        assert!(LhaRecognizer.recognize(&data).is_none());
    }
}
