//! SevenZipRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a 7-ZIP compressed file.
///
/// Detects the 7-Zip magic bytes `37 7a bc af 27 1c`.
#[derive(Debug, Clone, Copy)]
pub struct SevenZipRecognizer;

impl Recognizer for SevenZipRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..6] == [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c][..] {
                return Some("File appears to be a 7-ZIP compressed file".to_string());
            }
        }
        None
    }

    fn bytes_required(&self) -> usize {
        6
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recognize() {
        assert!(SevenZipRecognizer
            .recognize(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])
            .is_some());
    }

    #[test]
    fn test_recognize_with_extra_bytes() {
        assert!(SevenZipRecognizer
            .recognize(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x00])
            .is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 6];
        assert!(SevenZipRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x37, 0x7a, 0xbc, 0xaf, 0x27];
        assert!(SevenZipRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_description() {
        let desc = SevenZipRecognizer
            .recognize(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])
            .unwrap();
        assert!(desc.contains("7-ZIP"));
    }

    #[test]
    fn test_bytes_required() {
        assert_eq!(SevenZipRecognizer.bytes_required(), 6);
    }
}
