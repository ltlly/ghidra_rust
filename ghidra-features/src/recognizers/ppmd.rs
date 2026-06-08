//! PpmdRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a PPMD compressed file.
///
/// Detects the PPMd magic bytes `8f af ac 8c`.
#[derive(Debug, Clone, Copy)]
pub struct PpmdRecognizer;

impl Recognizer for PpmdRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..4] == [0x8f, 0xaf, 0xac, 0x8c][..] {
                return Some("File appears to be a PPMD compressed file".to_string());
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
        assert!(PpmdRecognizer
            .recognize(&[0x8f, 0xaf, 0xac, 0x8c])
            .is_some());
    }

    #[test]
    fn test_recognize_with_extra_bytes() {
        assert!(PpmdRecognizer
            .recognize(&[0x8f, 0xaf, 0xac, 0x8c, 0x00, 0x00])
            .is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 4];
        assert!(PpmdRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x8f, 0xaf, 0xac];
        assert!(PpmdRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_partial_match() {
        // First 3 bytes match but 4th doesn't
        let data = [0x8f, 0xaf, 0xac, 0x00];
        assert!(PpmdRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_description() {
        let desc = PpmdRecognizer.recognize(&[0x8f, 0xaf, 0xac, 0x8c]).unwrap();
        assert!(desc.contains("PPMD"));
    }

    #[test]
    fn test_bytes_required() {
        assert_eq!(PpmdRecognizer.bytes_required(), 4);
    }
}
