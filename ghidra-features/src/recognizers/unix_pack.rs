//! UnixPackRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a UNIX Pack compressed file.
///
/// Detects the UNIX pack magic bytes `1f 1e 00`.
#[derive(Debug, Clone, Copy)]
pub struct UnixPackRecognizer;

impl Recognizer for UnixPackRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..3] == [0x1f, 0x1e, 0x00][..] {
                return Some("File appears to be a UNIX Pack compressed file".to_string());
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
        assert!(UnixPackRecognizer.recognize(&[0x1f, 0x1e, 0x00]).is_some());
    }

    #[test]
    fn test_recognize_with_extra_bytes() {
        assert!(UnixPackRecognizer
            .recognize(&[0x1f, 0x1e, 0x00, 0xff, 0xff])
            .is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 3];
        assert!(UnixPackRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x1f, 0x1e];
        assert!(UnixPackRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_not_gzip() {
        let data = [0x1f, 0x8b, 0x00];
        assert!(UnixPackRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_not_unix_compress() {
        let data = [0x1f, 0x9d, 0x00];
        assert!(UnixPackRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_description() {
        let desc = UnixPackRecognizer.recognize(&[0x1f, 0x1e, 0x00]).unwrap();
        assert!(desc.contains("UNIX Pack"));
    }

    #[test]
    fn test_bytes_required() {
        assert_eq!(UnixPackRecognizer.bytes_required(), 3);
    }
}
