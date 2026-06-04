//! SqliteRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a SQLite database.
#[derive(Debug, Clone, Copy)]
pub struct SqliteRecognizer;

impl Recognizer for SqliteRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.bytes_required() {
            if &bytes[..16] == b"SQLite format 3\0" {
                return Some("File appears to be a SQLite database".to_string());
            }
        }
        None
    }

    fn bytes_required(&self) -> usize {
        16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recognize() {
        let mut data = vec![0u8; 100];
        data[..16].copy_from_slice(b"SQLite format 3\0");
        assert!(SqliteRecognizer.recognize(&data).is_some());
    }

    #[test]
    fn test_no_match() {
        let data = vec![0u8; 100];
        assert!(SqliteRecognizer.recognize(&data).is_none());
    }
}
