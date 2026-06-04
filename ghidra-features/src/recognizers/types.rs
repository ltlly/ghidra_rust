//! Core types for file format recognizers.

/// Trait implemented by all file-format recognizers.
///
/// A recognizer inspects the first few bytes of a file and returns
/// a human-readable description if the format is identified.
///
/// Ported from Ghidra's Java `Recognizer` interface.
pub trait Recognizer: Send + Sync {
    /// Attempt to recognize the file format from the given bytes.
    ///
    /// Returns `Some(description)` if the format is identified, or `None`
    /// otherwise. The description is a human-readable string suitable for
    /// display to the user (e.g. "File appears to be a GZIP compressed file").
    fn recognize(&self, bytes: &[u8]) -> Option<String>;

    /// The priority of this recognizer.
    ///
    /// Higher values indicate higher priority. When multiple recognizers
    /// match, the one with the highest priority wins. The default priority
    /// used by most recognizers is 100.
    fn priority(&self) -> i32 {
        100
    }

    /// The minimum number of bytes required for recognition.
    ///
    /// The `recognize` method will only be called if the input slice
    /// contains at least this many bytes.
    fn bytes_required(&self) -> usize;
}

/// A simple recognizer that matches a fixed magic-byte pattern.
///
/// This is the most common type of recognizer -- it checks whether
/// the first N bytes of the file match a known signature.
///
/// # Example
///
/// ```
/// use ghidra_features::recognizers::{MagicRecognizer, Recognizer};
///
/// let gzip = MagicRecognizer::new("File appears to be a GZIP compressed file", &[0x1f, 0x8b]);
/// assert!(gzip.recognize(&[0x1f, 0x8b, 0x08, 0x00]).is_some());
/// assert!(gzip.recognize(&[0x00, 0x00]).is_none());
/// ```
pub struct MagicRecognizer {
    description: &'static str,
    magic: &'static [u8],
    priority: i32,
}

impl MagicRecognizer {
    /// Create a new magic-byte recognizer.
    pub const fn new(description: &'static str, magic: &'static [u8]) -> Self {
        Self {
            description,
            magic,
            priority: 100,
        }
    }

    /// Create a new magic-byte recognizer with a custom priority.
    pub const fn with_priority(description: &'static str, magic: &'static [u8], priority: i32) -> Self {
        Self {
            description,
            magic,
            priority,
        }
    }
}

impl Recognizer for MagicRecognizer {
    fn recognize(&self, bytes: &[u8]) -> Option<String> {
        if bytes.len() >= self.magic.len() && bytes[..self.magic.len()] == *self.magic {
            Some(self.description.to_string())
        } else {
            None
        }
    }

    fn priority(&self) -> i32 {
        self.priority
    }

    fn bytes_required(&self) -> usize {
        self.magic.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_recognizer_match() {
        let rec = MagicRecognizer::new("test format", &[0xCA, 0xFE]);
        assert_eq!(
            rec.recognize(&[0xCA, 0xFE, 0x00, 0x00]),
            Some("test format".to_string())
        );
    }

    #[test]
    fn test_magic_recognizer_no_match() {
        let rec = MagicRecognizer::new("test format", &[0xCA, 0xFE]);
        assert_eq!(rec.recognize(&[0xDE, 0xAD]), None);
    }

    #[test]
    fn test_magic_recognizer_too_short() {
        let rec = MagicRecognizer::new("test format", &[0xCA, 0xFE, 0xBA, 0xBE]);
        assert_eq!(rec.recognize(&[0xCA, 0xFE]), None);
    }

    #[test]
    fn test_magic_recognizer_priority() {
        let rec = MagicRecognizer::with_priority("high prio", &[0x01], 200);
        assert_eq!(rec.priority(), 200);
        assert_eq!(rec.bytes_required(), 1);
    }
}
