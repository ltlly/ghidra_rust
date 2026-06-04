//! ArjRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be an ARJ compressed file.
#[derive(Debug, Clone, Copy)]
pub struct ArjRecognizer;

impl Recognizer for ArjRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..2] == [0x60, 0xea][..] {
                return Some("File appears to be an ARJ compressed file".to_string());
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
        assert!(ArjRecognizer.recognize(&[0x60, 0xea]).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 2];
        assert!(ArjRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x00; 1];
        assert!(ArjRecognizer.recognize(&data).is_none());
    }
}
