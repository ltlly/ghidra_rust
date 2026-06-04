//! MSWIMRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a Microsoft Windows Imaging Format file.
#[derive(Debug, Clone, Copy)]
pub struct MSWIMRecognizer;

impl Recognizer for MSWIMRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..5] == [0x4d, 0x53, 0x57, 0x49, 0x4d][..] {
                return Some("File appears to be a Microsoft Windows Imaging Format file".to_string());
            }
        }
        None
    }

    fn bytes_required(&self) -> usize {
        5
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recognize() {
        assert!(MSWIMRecognizer.recognize(&[0x4d, 0x53, 0x57, 0x49, 0x4d]).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 5];
        assert!(MSWIMRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x00; 4];
        assert!(MSWIMRecognizer.recognize(&data).is_none());
    }
}
