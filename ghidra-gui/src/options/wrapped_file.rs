//! Port of `ghidra.framework.options.WrappedFile`.
//!
//! A wrapper for persisting file path values as options. Stores a path
//! that can be serialized to/from a key/value state map.

use std::path::PathBuf;

use super::option_type::OptionType;
use super::option_value::OptionValue;
use super::wrapped_option::WrappedOption;

/// Wrapper for a file path that can be persisted as an option value.
///
/// Ported from Ghidra's `ghidra.framework.options.WrappedFile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedFile {
    /// The file path.
    path: PathBuf,
}

impl WrappedFile {
    /// Create a new wrapped file from a path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Get a reference to the stored file path.
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Consume the wrapper and return the path.
    pub fn into_path(self) -> PathBuf {
        self.path
    }

    /// Set the file path.
    pub fn set_path(&mut self, path: impl Into<PathBuf>) {
        self.path = path.into();
    }
}

impl Default for WrappedFile {
    fn default() -> Self {
        Self {
            path: PathBuf::from("."),
        }
    }
}

impl WrappedOption for WrappedFile {
    fn get_object(&self) -> OptionValue {
        OptionValue::String(self.path.to_string_lossy().to_string())
    }

    fn read_state(&mut self, state: &[(String, OptionValue)]) {
        for (key, val) in state {
            if key == "file" {
                if let OptionValue::String(s) = val {
                    self.path = PathBuf::from(s);
                }
            }
        }
    }

    fn write_state(&self) -> Vec<(String, OptionValue)> {
        vec![(
            "file".to_string(),
            OptionValue::String(self.path.to_string_lossy().to_string()),
        )]
    }

    fn option_type(&self) -> OptionType {
        OptionType::FileType
    }
}

impl std::fmt::Display for WrappedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WrappedFile: {}", self.path.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrapped_file_new() {
        let f = WrappedFile::new("/tmp/test.txt");
        assert_eq!(f.path().to_str(), Some("/tmp/test.txt"));
    }

    #[test]
    fn test_wrapped_file_default() {
        let f = WrappedFile::default();
        assert_eq!(f.path().to_str(), Some("."));
    }

    #[test]
    fn test_wrapped_file_option_type() {
        let f = WrappedFile::new("/home/user/data.bin");
        assert_eq!(f.option_type(), OptionType::FileType);
    }

    #[test]
    fn test_wrapped_file_get_object() {
        let f = WrappedFile::new("/tmp/test");
        match f.get_object() {
            OptionValue::String(s) => assert_eq!(s, "/tmp/test"),
            _ => panic!("Expected String option value"),
        }
    }

    #[test]
    fn test_wrapped_file_roundtrip() {
        let f = WrappedFile::new("/home/user/data.bin");
        let state = f.write_state();
        assert_eq!(state.len(), 1);

        let mut f2 = WrappedFile::default();
        f2.read_state(&state);
        assert_eq!(f2.path().to_str(), Some("/home/user/data.bin"));
    }

    #[test]
    fn test_wrapped_file_set_path() {
        let mut f = WrappedFile::new("/old/path");
        f.set_path("/new/path");
        assert_eq!(f.path().to_str(), Some("/new/path"));
    }

    #[test]
    fn test_wrapped_file_display() {
        let f = WrappedFile::new("/tmp/a.txt");
        let s = format!("{}", f);
        assert!(s.contains("a.txt"));
    }

    #[test]
    fn test_wrapped_file_into() {
        let f = WrappedFile::new("/some/path");
        let p = f.into_path();
        assert_eq!(p.to_str(), Some("/some/path"));
    }
}
