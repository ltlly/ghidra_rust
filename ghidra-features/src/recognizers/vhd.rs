//! VHDRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a VHD (Virtual PC) file.
#[derive(Debug, Clone, Copy)]
pub struct VHDRecognizer;

impl Recognizer for VHDRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..8] == [0x63, 0x6f, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x78][..] {
                return Some("File appears to be a VHD (Virtual PC) file".to_string());
            }
        }
        None
    }

    fn bytes_required(&self) -> usize {
        8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recognize() {
        assert!(VHDRecognizer.recognize(&[0x63, 0x6f, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x78]).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 8];
        assert!(VHDRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x00; 7];
        assert!(VHDRecognizer.recognize(&data).is_none());
    }
}
