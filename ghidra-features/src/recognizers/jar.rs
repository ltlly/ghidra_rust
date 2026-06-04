//! JarRecognizer - ported from Ghidra Java.

use super::types::Recognizer;

/// File appears to be a JAR (Java Archive) file.
///
/// JAR files use the same magic bytes as ZIP (PK\x03\x04) but include
/// a META-INF/MANIFEST.MF entry. This recognizer has higher priority
/// than the generic PKZIP recognizer to allow more specific reporting.
#[derive(Debug, Clone, Copy)]
pub struct JarRecognizer;

impl Recognizer for JarRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= 4 && bytes[..4] == [0x50, 0x4b, 0x03, 0x04] {
            // Look for META-INF/MANIFEST.MF signature in the local file headers.
            // A JAR will contain this at some offset. We scan for it.
            let needle = b"META-INF/MANIFEST.MF";
            if bytes.len() > 30 + needle.len() {
                for window in bytes.windows(needle.len()) {
                    if window == needle {
                        return Some("File appears to be a JAR (Java Archive) file".to_string());
                    }
                }
            }
        }
        None
    }

    fn bytes_required(&self) -> usize {
        4
    }

    fn priority(&self) -> i32 {
        105 // Slightly higher than generic PKZIP
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recognize_jar() {
        // ZIP header + some filler + META-INF/MANIFEST.MF
        let mut data = vec![0x50, 0x4b, 0x03, 0x04];
        data.extend_from_slice(&[0u8; 30]);
        data.extend_from_slice(b"META-INF/MANIFEST.MF");
        assert!(JarRecognizer.recognize(&data).is_some());
    }

    #[test]
    fn test_no_match_plain_zip() {
        let data = [0x50, 0x4b, 0x03, 0x04, 0x00, 0x00];
        assert!(JarRecognizer.recognize(&data).is_none());
    }

    #[test]
    fn test_no_match_wrong_magic() {
        let data = b"This is not a ZIP file";
        assert!(JarRecognizer.recognize(data).is_none());
    }
}
