//! XarRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a XAR archive.
#[derive(Debug, Clone, Copy)]
pub struct XarRecognizer;

impl Recognizer for XarRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..4] == [0x78, 0x61, 0x72, 0x21][..] {
                return Some("File appears to be a XAR archive".to_string());
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
        assert!(XarRecognizer.recognize(&[0x78, 0x61, 0x72, 0x21]).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 4];
        assert!(XarRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x00; 3];
        assert!(XarRecognizer.recognize(&data).is_none());
    }
}
