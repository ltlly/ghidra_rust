//! PakArcRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a PAK archive file.
#[derive(Debug, Clone, Copy)]
pub struct PakArcRecognizer;

impl Recognizer for PakArcRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..4] == [0x50, 0x41, 0x4b, 0x20][..] {
                return Some("File appears to be a PAK archive file".to_string());
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
        assert!(PakArcRecognizer.recognize(&[0x50, 0x41, 0x4b, 0x20]).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 4];
        assert!(PakArcRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x00; 3];
        assert!(PakArcRecognizer.recognize(&data).is_none());
    }
}
