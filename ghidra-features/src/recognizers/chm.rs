//! CHMRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a Microsoft HTML help file.
#[derive(Debug, Clone, Copy)]
pub struct CHMRecognizer;

impl Recognizer for CHMRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..4] == [0x49, 0x54, 0x53, 0x46][..] {
                return Some("File appears to be a Microsoft HTML help file".to_string());
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
        assert!(CHMRecognizer.recognize(&[0x49, 0x54, 0x53, 0x46]).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 4];
        assert!(CHMRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x00; 3];
        assert!(CHMRecognizer.recognize(&data).is_none());
    }
}
