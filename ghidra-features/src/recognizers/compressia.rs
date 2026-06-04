//! CompressiaRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a Compressia compressed file.
#[derive(Debug, Clone, Copy)]
pub struct CompressiaRecognizer;

impl Recognizer for CompressiaRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..10] == [0x43, 0x4f, 0x4d, 0x50, 0x52, 0x45, 0x53, 0x53, 0x49, 0x41][..] {
                return Some("File appears to be a Compressia compressed file".to_string());
            }
        }
        None
    }

    fn bytes_required(&self) -> usize {
        10
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recognize() {
        assert!(CompressiaRecognizer.recognize(&[0x43, 0x4f, 0x4d, 0x50, 0x52, 0x45, 0x53, 0x53, 0x49, 0x41]).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 10];
        assert!(CompressiaRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x00; 9];
        assert!(CompressiaRecognizer.recognize(&data).is_none());
    }
}
