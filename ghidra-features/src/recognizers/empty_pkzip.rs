//! EmptyPkzipRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be an empty PKZIP archive.
///
/// This recognizer checks for the ZIP end-of-central-directory record
/// at the expected offset (last 22 bytes of the file). It matches only
/// when the file is very short (likely an empty archive).
#[derive(Debug, Clone, Copy)]
pub struct EmptyPkzipRecognizer;

impl Recognizer for EmptyPkzipRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() == 22 {
            // Check for end-of-central-directory signature
            if bytes[0..4] == [0x50, 0x4b, 0x05, 0x06] {
                return Some("File appears to be an empty PKZIP archive".to_string());
            }
        }
        None
    }

    fn bytes_required(&self) -> usize {
        22
    }

    fn priority(&self) -> i32 {
        110 // Higher than standard PKZIP recognizer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recognize_empty_zip() {
        let mut data = vec![0u8; 22];
        data[0..4].copy_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
        assert!(EmptyPkzipRecognizer.recognize(&data).is_some());
    }

    #[test]
    fn test_no_match_wrong_signature() {
        let data = vec![0u8; 22];
        assert!(EmptyPkzipRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_no_match_wrong_size() {
        let mut data = vec![0u8; 100];
        data[0..4].copy_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
        assert!(EmptyPkzipRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_priority() {
        assert_eq!(EmptyPkzipRecognizer.priority(), 110);
    }
}
