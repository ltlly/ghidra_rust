//! MacromediaFlashRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a Macromedia Flash file.
#[derive(Debug, Clone, Copy)]
pub struct MacromediaFlashRecognizer;

impl Recognizer for MacromediaFlashRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..3] == [0x43, 0x57, 0x53][..] {
                return Some("File appears to be a Macromedia Flash file".to_string());
            }
        }
        None
    }

    fn bytes_required(&self) -> usize {
        3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recognize() {
        assert!(MacromediaFlashRecognizer.recognize(&[0x43, 0x57, 0x53]).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 3];
        assert!(MacromediaFlashRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x00; 2];
        assert!(MacromediaFlashRecognizer.recognize(&data).is_none());
    }
}
