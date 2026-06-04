//! TarRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a TAR archive.
#[derive(Debug, Clone, Copy)]
pub struct TarRecognizer;

impl Recognizer for TarRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            let sig: &[u8] = b"ustar";
            if &bytes[257..257 + sig.len()] == sig {
                return Some("File appears to be a TAR archive".to_string());
            }
        }
        None
    }

    fn bytes_required(&self) -> usize {
        257 + 5 // "ustar" is 5 bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recognize() {
        let mut data = vec![0u8; 300];
        data[257..262].copy_from_slice(b"ustar");
        assert!(TarRecognizer.recognize(&data).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = vec![0u8; 277];
        assert!(TarRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = vec![0u8; 10];
        assert!(TarRecognizer.recognize(&data).is_none());
    }
}
