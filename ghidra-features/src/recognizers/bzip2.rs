//! Bzip2Recognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a BZIP2 compressed file.
#[derive(Debug, Clone, Copy)]
pub struct Bzip2Recognizer;

impl Recognizer for Bzip2Recognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..3] == [0x42, 0x5a, 0x68][..] {
                return Some("File appears to be a BZIP2 compressed file".to_string());
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
        assert!(Bzip2Recognizer.recognize(&[0x42, 0x5a, 0x68]).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 3];
        assert!(Bzip2Recognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x00; 2];
        assert!(Bzip2Recognizer.recognize(&data).is_none());
    }
}
