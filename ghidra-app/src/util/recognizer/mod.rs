//! Format recognition helpers (ported from `ghidra.app.util.recognizer`).

use serde::{Deserialize, Serialize};

/// Result of a format recognition attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecognitionResult {
    /// Format name (e.g. "ELF", "PE", "Mach-O").
    pub format: String,
    /// Confidence level (0.0 to 1.0).
    pub confidence: f64,
    /// Human-readable description.
    pub description: String,
}

/// Trait for binary format recognizers.
pub trait FormatRecognizer: Send + Sync {
    /// Name of this recognizer.
    fn name(&self) -> &str;

    /// Check whether the given data matches this format.
    fn recognize(&self, data: &[u8]) -> Option<RecognitionResult>;
}

/// Recognizer that checks magic bytes at the start of data.
pub struct MagicBytesRecognizer {
    format_name: String,
    magic: Vec<u8>,
    description: String,
}

impl MagicBytesRecognizer {
    /// Create a new magic-bytes recognizer.
    pub fn new(
        format_name: impl Into<String>,
        magic: Vec<u8>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            format_name: format_name.into(),
            magic,
            description: description.into(),
        }
    }
}

impl FormatRecognizer for MagicBytesRecognizer {
    fn name(&self) -> &str {
        &self.format_name
    }

    fn recognize(&self, data: &[u8]) -> Option<RecognitionResult> {
        if data.len() >= self.magic.len() && data[..self.magic.len()] == self.magic[..] {
            Some(RecognitionResult {
                format: self.format_name.clone(),
                confidence: 1.0,
                description: self.description.clone(),
            })
        } else {
            None
        }
    }
}

/// Common magic-byte recognizers.
pub fn standard_recognizers() -> Vec<Box<dyn FormatRecognizer>> {
    vec![
        Box::new(MagicBytesRecognizer::new(
            "ELF",
            vec![0x7F, b'E', b'L', b'F'],
            "Executable and Linkable Format",
        )),
        Box::new(MagicBytesRecognizer::new(
            "PE",
            vec![0x4D, 0x5A],
            "Portable Executable (DOS header)",
        )),
        Box::new(MagicBytesRecognizer::new(
            "Mach-O (32-bit LE)",
            vec![0xFE, 0xED, 0xFA, 0xCE],
            "Mach-O 32-bit little-endian",
        )),
        Box::new(MagicBytesRecognizer::new(
            "Mach-O (64-bit LE)",
            vec![0xFE, 0xED, 0xFA, 0xCF],
            "Mach-O 64-bit little-endian",
        )),
        Box::new(MagicBytesRecognizer::new(
            "Java Class",
            vec![0xCA, 0xFE, 0xBA, 0xBE],
            "Java class file",
        )),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_bytes_recognize_elf() {
        let rec = MagicBytesRecognizer::new("ELF", vec![0x7F, b'E', b'L', b'F'], "ELF");
        let elf_data = vec![0x7F, b'E', b'L', b'F', 2, 1, 1, 0];
        let result = rec.recognize(&elf_data).unwrap();
        assert_eq!(result.format, "ELF");
        assert_eq!(result.confidence, 1.0);
    }

    #[test]
    fn magic_bytes_reject() {
        let rec = MagicBytesRecognizer::new("ELF", vec![0x7F, b'E', b'L', b'F'], "ELF");
        let mz_data = vec![0x4D, 0x5A, 0x90, 0x00];
        assert!(rec.recognize(&mz_data).is_none());
    }

    #[test]
    fn magic_bytes_short_data() {
        let rec = MagicBytesRecognizer::new("ELF", vec![0x7F, b'E', b'L', b'F'], "ELF");
        assert!(rec.recognize(&[0x7F, b'E']).is_none());
    }

    #[test]
    fn standard_recognizers_count() {
        let recs = standard_recognizers();
        assert!(recs.len() >= 5);
    }

    #[test]
    fn standard_recognizers_detect_formats() {
        let recs = standard_recognizers();
        let elf_data = vec![0x7F, b'E', b'L', b'F', 0, 0, 0, 0];
        let found = recs.iter().find_map(|r| r.recognize(&elf_data));
        assert!(found.is_some());
        assert_eq!(found.unwrap().format, "ELF");

        let pe_data = vec![0x4D, 0x5A, 0, 0];
        let found = recs.iter().find_map(|r| r.recognize(&pe_data));
        assert!(found.is_some());
        assert_eq!(found.unwrap().format, "PE");
    }
}
