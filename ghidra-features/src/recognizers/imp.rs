//! ImpRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be an IMP compressed file.
#[derive(Debug, Clone, Copy)]
pub struct ImpRecognizer;

impl Recognizer for ImpRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..2] == [0x1a, 0x02][..] {
                return Some("File appears to be an IMP compressed file".to_string());
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
        assert!(ImpRecognizer.recognize(&[0x1a, 0x02]).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 2];
        assert!(ImpRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x00; 1];
        assert!(ImpRecognizer.recognize(&data).is_none());
    }
}
