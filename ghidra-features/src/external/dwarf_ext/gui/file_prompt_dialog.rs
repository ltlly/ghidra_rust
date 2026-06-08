//! FilePromptDialog -- prompts the user to enter a file/directory path.
//!
//! Ported from `ghidra.app.util.bin.format.dwarf.external.gui.FilePromptDialog`.
//!
//! In the Java version this is a Swing `DialogComponentProvider` that
//! shows a text field and a browse button, allowing the user to type
//! a path or pick one via a `GhidraFileChooser`.  In Rust we provide:
//!
//! - [`FileChooserMode`] -- whether to pick files, directories, or both
//! - [`FilePromptResult`] -- the outcome of the dialog
//! - [`FilePromptConfig`] -- configuration for the dialog
//! - [`FilePromptHandler`] -- trait for UI-framework-specific rendering
//!
//! The actual dialog display is delegated to a [`FilePromptHandler`]
//! implementation, which can be backed by any UI framework (egui, iced,
//! native dialogs, terminal prompts, etc.).

use std::path::PathBuf;

/// The file selection mode for the dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileChooserMode {
    /// Allow selection of files only.
    FilesOnly,
    /// Allow selection of directories only.
    DirectoriesOnly,
    /// Allow selection of both files and directories.
    FilesAndDirectories,
}

/// The result of a file prompt dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilePromptResult {
    /// The user selected a path.
    Selected(PathBuf),
    /// The user cancelled the dialog.
    Cancelled,
}

impl FilePromptResult {
    /// Returns `true` if the result is a selection.
    pub fn is_selected(&self) -> bool {
        matches!(self, FilePromptResult::Selected(_))
    }

    /// Returns `true` if the result was cancelled.
    pub fn is_cancelled(&self) -> bool {
        matches!(self, FilePromptResult::Cancelled)
    }

    /// Returns the selected path, or `None` if cancelled.
    pub fn path(&self) -> Option<&std::path::Path> {
        match self {
            FilePromptResult::Selected(p) => Some(p),
            FilePromptResult::Cancelled => None,
        }
    }
}

/// Configuration for a file prompt dialog.
#[derive(Debug, Clone)]
pub struct FilePromptConfig {
    /// The dialog title.
    title: String,
    /// The prompt text (may be HTML in the Java version).
    prompt: String,
    /// Text for the approve/choose button in the file chooser.
    approve_button_text: String,
    /// Initial directory for the file chooser.
    initial_directory: Option<PathBuf>,
    /// Initial value for the text field.
    initial_value: Option<PathBuf>,
    /// The file selection mode.
    chooser_mode: FileChooserMode,
}

impl FilePromptConfig {
    /// Creates a new configuration for choosing a directory.
    ///
    /// This is the Rust equivalent of `FilePromptDialog.chooseDirectory()`.
    pub fn choose_directory(
        title: impl Into<String>,
        prompt: impl Into<String>,
        initial_value: Option<PathBuf>,
    ) -> Self {
        Self {
            title: title.into(),
            prompt: prompt.into(),
            approve_button_text: "Choose".to_string(),
            initial_directory: None,
            initial_value,
            chooser_mode: FileChooserMode::DirectoriesOnly,
        }
    }

    /// Creates a new configuration for choosing a file.
    ///
    /// This is the Rust equivalent of `FilePromptDialog.chooseFile()`.
    pub fn choose_file(
        title: impl Into<String>,
        prompt: impl Into<String>,
        approve_button_text: impl Into<String>,
        initial_directory: Option<PathBuf>,
        initial_value: Option<PathBuf>,
        chooser_mode: FileChooserMode,
    ) -> Self {
        Self {
            title: title.into(),
            prompt: prompt.into(),
            approve_button_text: approve_button_text.into(),
            initial_directory,
            initial_value,
            chooser_mode,
        }
    }

    /// Returns the dialog title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the prompt text.
    pub fn prompt(&self) -> &str {
        &self.prompt
    }

    /// Returns the approve button text.
    pub fn approve_button_text(&self) -> &str {
        &self.approve_button_text
    }

    /// Returns the initial directory.
    pub fn initial_directory(&self) -> Option<&std::path::Path> {
        self.initial_directory.as_deref()
    }

    /// Returns the initial value.
    pub fn initial_value(&self) -> Option<&std::path::Path> {
        self.initial_value.as_deref()
    }

    /// Returns the file chooser mode.
    pub fn chooser_mode(&self) -> FileChooserMode {
        self.chooser_mode
    }
}

/// Trait for UI-framework-specific file prompt dialog implementations.
///
/// Implementors provide the actual dialog display logic.  The
/// [`FilePromptConfig`] describes what the dialog should look like;
/// the handler is responsible for rendering it and returning the result.
pub trait FilePromptHandler {
    /// Shows a file prompt dialog with the given configuration.
    ///
    /// Returns the result of the dialog (selected path or cancelled).
    fn show(&self, config: &FilePromptConfig) -> FilePromptResult;
}

/// A simple handler that uses a pre-configured path (useful for tests
/// or headless environments).
#[derive(Debug, Clone)]
pub struct MockFilePromptHandler {
    /// The path to return when the dialog is "shown".
    result: FilePromptResult,
}

impl MockFilePromptHandler {
    /// Creates a handler that always returns the given path.
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            result: FilePromptResult::Selected(path.into()),
        }
    }

    /// Creates a handler that always cancels.
    pub fn cancelled() -> Self {
        Self {
            result: FilePromptResult::Cancelled,
        }
    }
}

impl FilePromptHandler for MockFilePromptHandler {
    fn show(&self, _config: &FilePromptConfig) -> FilePromptResult {
        self.result.clone()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_prompt_result_selected() {
        let result = FilePromptResult::Selected(PathBuf::from("/tmp/test"));
        assert!(result.is_selected());
        assert!(!result.is_cancelled());
        assert_eq!(result.path(), Some(std::path::Path::new("/tmp/test")));
    }

    #[test]
    fn test_file_prompt_result_cancelled() {
        let result = FilePromptResult::Cancelled;
        assert!(!result.is_selected());
        assert!(result.is_cancelled());
        assert_eq!(result.path(), None);
    }

    #[test]
    fn test_choose_directory_config() {
        let config = FilePromptConfig::choose_directory(
            "Choose Directory",
            "Select a directory:",
            Some(PathBuf::from("/usr/lib")),
        );

        assert_eq!(config.title(), "Choose Directory");
        assert_eq!(config.prompt(), "Select a directory:");
        assert_eq!(config.approve_button_text(), "Choose");
        assert_eq!(
            config.initial_value(),
            Some(std::path::Path::new("/usr/lib"))
        );
        assert_eq!(config.chooser_mode(), FileChooserMode::DirectoriesOnly);
    }

    #[test]
    fn test_choose_file_config() {
        let config = FilePromptConfig::choose_file(
            "Choose File",
            "Select a file:",
            "Open",
            Some(PathBuf::from("/home")),
            None,
            FileChooserMode::FilesOnly,
        );

        assert_eq!(config.title(), "Choose File");
        assert_eq!(config.approve_button_text(), "Open");
        assert_eq!(config.initial_directory(), Some(std::path::Path::new("/home")));
        assert_eq!(config.initial_value(), None);
        assert_eq!(config.chooser_mode(), FileChooserMode::FilesOnly);
    }

    #[test]
    fn test_file_chooser_mode_equality() {
        assert_eq!(FileChooserMode::FilesOnly, FileChooserMode::FilesOnly);
        assert_ne!(FileChooserMode::FilesOnly, FileChooserMode::DirectoriesOnly);
    }

    #[test]
    fn test_mock_handler_with_path() {
        let handler = MockFilePromptHandler::with_path("/tmp/test");
        let config = FilePromptConfig::choose_directory("Title", "Prompt", None);
        let result = handler.show(&config);
        assert_eq!(result.path(), Some(std::path::Path::new("/tmp/test")));
    }

    #[test]
    fn test_mock_handler_cancelled() {
        let handler = MockFilePromptHandler::cancelled();
        let config = FilePromptConfig::choose_directory("Title", "Prompt", None);
        let result = handler.show(&config);
        assert!(result.is_cancelled());
    }

    #[test]
    fn test_config_none_values() {
        let config = FilePromptConfig::choose_directory("Title", "Prompt", None);
        assert_eq!(config.initial_directory(), None);
        assert_eq!(config.initial_value(), None);
    }
}
