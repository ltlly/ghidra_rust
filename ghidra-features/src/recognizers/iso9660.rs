//! ISO9660Recognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be an ISO 9660 CD-ROM image.
#[derive(Debug, Clone, Copy)]
pub struct ISO9660Recognizer;

impl Recognizer for ISO9660Recognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            let sig: &[u8] = &[0x01, 0x43, 0x44, 0x30, 0x30, 0x31];
            if &bytes[32769..32769 + sig.len()] == sig {
                return Some("File appears to be an ISO 9660 CD-ROM image".to_string());
            }
        }
        None
    }

    fn bytes_required(&self) -> usize {
        32769 + 6
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recognize() {
        let mut data = vec![0u8; 32789];
        let sig: &[u8] = &[0x01, 0x43, 0x44, 0x30, 0x30, 0x31];
        data[32769..32769 + sig.len()].copy_from_slice(sig);
        assert!(ISO9660Recognizer.recognize(&data).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = vec![0u8; 32789];
        assert!(ISO9660Recognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_too_short() {
        let data = vec![0u8; 10];
        assert!(ISO9660Recognizer.recognize(&data).is_none());
    }
}
