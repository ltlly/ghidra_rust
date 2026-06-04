//! CpioRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a CPIO archive.
#[derive(Debug, Clone, Copy)]
pub struct CpioRecognizer;

impl Recognizer for CpioRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..2] == [0x71, 0xc7][..] {
                return Some("File appears to be a CPIO archive".to_string());
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
        assert!(CpioRecognizer.recognize(&[0x71, 0xc7]).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 2];
        assert!(CpioRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x00; 1];
        assert!(CpioRecognizer.recognize(&data).is_none());
    }
}
