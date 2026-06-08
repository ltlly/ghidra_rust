//! UharcRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a UHARC or WinUHA compressed file.
///
/// Detects UHARC magic bytes `55 48 41` followed by version byte
/// 0x04, 0x05, or 0x06.
#[derive(Debug, Clone, Copy)]
pub struct UharcRecognizer;

impl Recognizer for UharcRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[0] == 0x55
                && bytes[1] == 0x48
                && bytes[2] == 0x41
                && (bytes[3] == 0x04 || bytes[3] == 0x05 || bytes[3] == 0x06)
            {
                return Some("File appears to be a UHARC or WinUHA compressed file".to_string());
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
    fn test_recognize_v4() {
        assert!(UharcRecognizer
            .recognize(&[0x55, 0x48, 0x41, 0x04])
            .is_some());
    }

    #[test]
    fn test_recognize_v5() {
        assert!(UharcRecognizer
            .recognize(&[0x55, 0x48, 0x41, 0x05])
            .is_some());
    }

    #[test]
    fn test_recognize_v6() {
        assert!(UharcRecognizer
            .recognize(&[0x55, 0x48, 0x41, 0x06])
            .is_some());
    }

    #[test]
    fn test_recognize_with_extra_bytes() {
        assert!(UharcRecognizer
            .recognize(&[0x55, 0x48, 0x41, 0x05, 0x00, 0x00])
            .is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 4];
        assert!(UharcRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x55, 0x48, 0x41];
        assert!(UharcRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_invalid_version() {
        // Version byte 0x03 is not recognized
        let data = [0x55, 0x48, 0x41, 0x03];
        assert!(UharcRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_invalid_version_07() {
        // Version byte 0x07 is not recognized
        let data = [0x55, 0x48, 0x41, 0x07];
        assert!(UharcRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_description() {
        let desc = UharcRecognizer
            .recognize(&[0x55, 0x48, 0x41, 0x04])
            .unwrap();
        assert!(desc.contains("UHARC"));
    }

    #[test]
    fn test_bytes_required() {
        assert_eq!(UharcRecognizer.bytes_required(), 4);
    }
}
