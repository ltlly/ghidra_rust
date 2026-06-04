//! GzipRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a GZIP compressed file.
#[derive(Debug, Clone, Copy)]
pub struct GzipRecognizer;

impl Recognizer for GzipRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..2] == [0x1f, 0x8b][..] {
                return Some("File appears to be a GZIP compressed file".to_string());
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
        assert!(GzipRecognizer.recognize(&[0x1f, 0x8b]).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 2];
        assert!(GzipRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x00; 1];
        assert!(GzipRecognizer.recognize(&data).is_none());
    }
}
