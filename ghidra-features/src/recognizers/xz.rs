//! XzRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be an XZ compressed file.
#[derive(Debug, Clone, Copy)]
pub struct XzRecognizer;

impl Recognizer for XzRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..6] == [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00][..] {
                return Some("File appears to be an XZ compressed file".to_string());
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
        assert!(XzRecognizer.recognize(&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 6];
        assert!(XzRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x00; 5];
        assert!(XzRecognizer.recognize(&data).is_none());
    }
}
