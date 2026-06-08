//! UnixCompressRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a UNIX Compress compressed file.
///
/// Detects the classic UNIX compress magic bytes `1f 9d`.
#[derive(Debug, Clone, Copy)]
pub struct UnixCompressRecognizer;

impl Recognizer for UnixCompressRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if bytes[..2] == [0x1f, 0x9d][..] {
                return Some("File appears to be a UNIX Compress compressed file".to_string());
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
        assert!(UnixCompressRecognizer.recognize(&[0x1f, 0x9d]).is_some());
    }

    #[test]
    fn test_recognize_with_extra_bytes() {
        assert!(UnixCompressRecognizer
            .recognize(&[0x1f, 0x9d, 0x00, 0x00])
            .is_some());
    }

    #[test]
    fn test_no_match() {
        let data = [0x00; 2];
        assert!(UnixCompressRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = [0x1f];
        assert!(UnixCompressRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_not_gzip() {
        // Gzip is 1f 8b, not 1f 9d
        let data = [0x1f, 0x8b];
        assert!(UnixCompressRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_description() {
        let desc = UnixCompressRecognizer.recognize(&[0x1f, 0x9d]).unwrap();
        assert!(desc.contains("UNIX Compress"));
    }

    #[test]
    fn test_bytes_required() {
        assert_eq!(UnixCompressRecognizer.bytes_required(), 2);
    }
}
