//! PkzipRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a PKZIP, WINZIP, or JAR compressed file.
///
/// Checks for the ZIP local file header signature `PK\x03\x04`.
#[derive(Debug, Clone, Copy)]
pub struct PkzipRecognizer;

impl Recognizer for PkzipRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..4] == [0x50, 0x4b, 0x03, 0x04] {
                return Some(
                    "File appears to be a PKZIP, WINZIP, or JAR compressed file".to_string(),
                );
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
        let data = [0x50, 0x4b, 0x03, 0x04, 0x00];
        assert!(PkzipRecognizer.recognize(&data).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00, 0x00, 0x00, 0x00];
        assert!(PkzipRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x50, 0x4b, 0x03];
        assert!(PkzipRecognizer.recognize(&data).is_none());
    }
}
