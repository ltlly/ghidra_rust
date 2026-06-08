//! SbcRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a SBC compressed file.
///
/// Detects the SBC magic bytes `53 42 43 1c`.
#[derive(Debug, Clone, Copy)]
pub struct SbcRecognizer;

impl Recognizer for SbcRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..4] == [0x53, 0x42, 0x43, 0x1c][..] {
                return Some("File appears to be a SBC compressed file".to_string());
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
        assert!(SbcRecognizer.recognize(&[0x53, 0x42, 0x43, 0x1c]).is_some());
    }

    #[test]
    fn test_recognize_with_extra_bytes() {
        assert!(SbcRecognizer
            .recognize(&[0x53, 0x42, 0x43, 0x1c, 0x00, 0x00])
            .is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 4];
        assert!(SbcRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x53, 0x42, 0x43];
        assert!(SbcRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_partial_match() {
        // First 3 bytes match but 4th doesn't
        let data = [0x53, 0x42, 0x43, 0x00];
        assert!(SbcRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_description() {
        let desc = SbcRecognizer.recognize(&[0x53, 0x42, 0x43, 0x1c]).unwrap();
        assert!(desc.contains("SBC"));
    }

    #[test]
    fn test_bytes_required() {
        assert_eq!(SbcRecognizer.bytes_required(), 4);
    }
}
