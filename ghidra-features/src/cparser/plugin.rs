//! Parse dialog model.
//!
//! Ported from `ghidra.app.plugin.core.cparser.ParseDialog`.
//!
//! Note: `CParserPlugin`, `CParserTask`, and `IncludeFileFinder` are
//! defined in the parent `cparser` module. This module provides only
//! the `ParseDialog` type which was missing.

use super::CParserOptions;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// ParseDialog -- dialog model for parse options
// ---------------------------------------------------------------------------

/// Model for the parse C source dialog.
///
/// Ported from `ghidra.app.plugin.core.cparser.ParseDialog`.
#[derive(Debug, Clone)]
pub struct ParseDialog {
    /// The title of the dialog.
    title: String,
    /// The selected source files.
    source_files: Vec<PathBuf>,
    /// The active options.
    options: CParserOptions,
    /// Whether the dialog was confirmed.
    confirmed: bool,
}

impl ParseDialog {
    /// Create a new parse dialog model.
    pub fn new() -> Self {
        Self {
            title: "Parse C Source".to_string(),
            source_files: Vec::new(),
            options: CParserOptions::default(),
            confirmed: false,
        }
    }

    /// Set the dialog title.
    pub fn set_title(&mut self, title: impl Into<String>) {
        self.title = title.into();
    }

    /// Get the dialog title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Add a source file.
    pub fn add_source_file(&mut self, path: impl Into<PathBuf>) {
        self.source_files.push(path.into());
    }

    /// Get the source files.
    pub fn source_files(&self) -> &[PathBuf] {
        &self.source_files
    }

    /// Get the options.
    pub fn options(&self) -> &CParserOptions {
        &self.options
    }

    /// Get mutable options.
    pub fn options_mut(&mut self) -> &mut CParserOptions {
        &mut self.options
    }

    /// Confirm the dialog.
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    /// Whether the dialog was confirmed.
    pub fn is_confirmed(&self) -> bool {
        self.confirmed
    }
}

impl Default for ParseDialog {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dialog() {
        let mut dialog = ParseDialog::new();
        assert_eq!(dialog.title(), "Parse C Source");
        assert!(!dialog.is_confirmed());
        assert!(dialog.source_files().is_empty());

        dialog.add_source_file("/path/to/header.h");
        assert_eq!(dialog.source_files().len(), 1);

        dialog.confirm();
        assert!(dialog.is_confirmed());
    }

    #[test]
    fn test_parse_dialog_options() {
        let mut dialog = ParseDialog::new();
        dialog.options_mut().parse_all = false;
        assert!(!dialog.options().parse_all);
    }
}
