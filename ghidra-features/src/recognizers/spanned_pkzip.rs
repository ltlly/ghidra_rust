//! SpannedPkzipRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a spanned PKZIP compressed file.
///
/// Detects the spanned PKZIP magic bytes `50 4b 07 08` (PK\x07\x08),
/// which indicates a split/spanned ZIP archive.
#[derive(Debug, Clone, Copy)]
pub struct SpannedPkzipRecognizer;

impl Recognizer for SpannedPkzipRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..4] == [0x50, 0x4b, 0x07, 0x08][..] {
                return Some("File appears to be a spanned PKZIP compressed file".to_string());
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
        assert!(SpannedPkzipRecognizer
            .recognize(&[0x50, 0x4b, 0x07, 0x08])
            .is_some());
    }

    #[test]
    fn test_recognize_with_extra_bytes() {
        assert!(SpannedPkzipRecognizer
            .recognize(&[0x50, 0x4b, 0x07, 0x08, 0xff, 0xff])
            .is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 4];
        assert!(SpannedPkzipRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x50, 0x4b, 0x07];
        assert!(SpannedPkzipRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_not_regular_pkzip() {
        // Regular PKZIP starts with 50 4b 03 04, not 50 4b 07 08
        let data = [0x50, 0x4b, 0x03, 0x04];
        assert!(SpannedPkzipRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_description() {
        let desc = SpannedPkzipRecognizer
            .recognize(&[0x50, 0x4b, 0x07, 0x08])
            .unwrap();
        assert!(desc.contains("spanned PKZIP"));
    }

    #[test]
    fn test_bytes_required() {
        assert_eq!(SpannedPkzipRecognizer.bytes_required(), 4);
    }
}
