//! CabarcRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a Microsoft cabinet file.
#[derive(Debug, Clone, Copy)]
pub struct CabarcRecognizer;

impl Recognizer for CabarcRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..4] == [0x4d, 0x53, 0x43, 0x46][..] {
                return Some("File appears to be a Microsoft cabinet file".to_string());
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
        assert!(CabarcRecognizer.recognize(&[0x4d, 0x53, 0x43, 0x46]).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 4];
        assert!(CabarcRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x00; 3];
        assert!(CabarcRecognizer.recognize(&data).is_none());
    }
}
