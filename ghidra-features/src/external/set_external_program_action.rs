//! SetExternalProgramAction -- action for setting the external program
//! path for a library.
//!
//! Ported from
//! `ghidra.app.plugin.core.symboltree.actions.SetExternalProgramAction`.
//!
//! This context-sensitive action is enabled when exactly one
//! [`LibrarySymbolNode`] is selected in the symbol tree.  When
//! triggered it opens a file chooser dialog that allows the user to
//! select a program file (from the Ghidra project) to associate with
//! the selected external library.  The association is stored as the
//! library's external path via [`SetExternalNameCmd`].
//!
//! # Examples
//!
//! ```rust
//! use ghidra_features::external::SetExternalProgramAction;
//!
//! let action = SetExternalProgramAction::new("SymbolTreePlugin");
//! assert_eq!(action.name(), "Set External Program");
//! assert!(!action.is_enabled()); // disabled by default
//! ```

use std::fmt;

use super::external_manager_db::ExternalManagerDB;
use super::set_external_name_cmd::SetExternalNameCmd;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors that can occur during the set-external-program action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetExternalProgramError {
    /// No node was selected.
    NoSelection,
    /// The selected node is not a library node.
    NotLibraryNode(String),
    /// No file was chosen.
    NoFileChosen,
    /// The chosen path is the same as the current path.
    PathUnchanged(String),
    /// The command execution failed.
    CommandFailed(String),
    /// General error.
    Other(String),
}

impl fmt::Display for SetExternalProgramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SetExternalProgramError::NoSelection => write!(f, "No node selected"),
            SetExternalProgramError::NotLibraryNode(name) => {
                write!(f, "Node '{}' is not a library node", name)
            }
            SetExternalProgramError::NoFileChosen => write!(f, "No file was chosen"),
            SetExternalProgramError::PathUnchanged(path) => {
                write!(f, "Path '{}' is already set", path)
            }
            SetExternalProgramError::CommandFailed(msg) => {
                write!(f, "Command failed: {}", msg)
            }
            SetExternalProgramError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for SetExternalProgramError {}

// ---------------------------------------------------------------------------
// File chooser result
// ---------------------------------------------------------------------------

/// The result of the file chooser dialog.
///
/// In the Java implementation this comes from `ProgramFileChooser`.
/// Here we represent the selected domain file as a path string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChosenFile {
    /// The project-relative path of the chosen file.
    pub path: String,
    /// The display name of the chosen file.
    pub display_name: String,
}

impl ChosenFile {
    /// Create a new chosen file.
    pub fn new(path: impl Into<String>, display_name: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            display_name: display_name.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// SetExternalProgramAction
// ---------------------------------------------------------------------------

/// Action for setting the external program path for a library.
///
/// This is the Rust port of Ghidra's `SetExternalProgramAction`.
/// It is a context-sensitive action that:
///
/// 1. Checks whether exactly one library node is selected.
/// 2. When triggered, opens a file chooser for selecting a program file.
/// 3. Executes a `SetExternalNameCmd` to associate the file with the library.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::set_external_program_action::SetExternalProgramAction;
///
/// let action = SetExternalProgramAction::new("SymbolTreePlugin");
///
/// // The action is disabled by default (as in the Java implementation)
/// assert!(!action.is_enabled());
///
/// // Enable it
/// let mut action = action;
/// action.set_enabled(true);
/// assert!(action.is_enabled());
///
/// // Check if action is enabled for a library node name
/// assert!(action.is_library_node("libc.so"));
/// ```
#[derive(Debug, Clone)]
pub struct SetExternalProgramAction {
    /// The action name.
    name: String,
    /// The owning plugin name.
    plugin_name: String,
    /// Whether the action is enabled (disabled by default).
    enabled: bool,
}

impl SetExternalProgramAction {
    /// Create a new set-external-program action.
    ///
    /// Note: this action is disabled by default, matching the Java
    /// implementation where `setEnabled(false)` is called in the
    /// constructor.
    ///
    /// * `plugin_name` -- the name of the owning plugin (used for
    ///   menu grouping and help location).
    pub fn new(plugin_name: impl Into<String>) -> Self {
        Self {
            name: "Set External Program".to_string(),
            plugin_name: plugin_name.into(),
            enabled: false,
        }
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the owning plugin name.
    pub fn plugin_name(&self) -> &str {
        &self.plugin_name
    }

    /// Returns whether the action is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set whether the action is enabled.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Check if the given node name represents a library node.
    ///
    /// In the Java implementation this checks if the selected object
    /// is an instance of `LibrarySymbolNode`.  Here we accept the node
    /// type as a boolean parameter.
    pub fn is_library_node(&self, _node_name: &str) -> bool {
        // In the Java implementation, this checks instanceof LibrarySymbolNode.
        // Here we accept any non-empty name as a valid library node.
        !_node_name.is_empty()
    }

    /// Get the search text for the file chooser dialog.
    ///
    /// In the Java implementation, `dialog.setSearchText(externalName)`
    /// is called with the library name to pre-populate the search.
    pub fn search_text_for_library(&self, library_name: &str) -> String {
        library_name.to_string()
    }

    /// Get the dialog title for the file chooser.
    ///
    /// In the Java implementation the title is
    /// `"Choose External Program (" + externalName + ")"`.
    pub fn dialog_title(&self, library_name: &str) -> String {
        format!("Choose External Program ({})", library_name)
    }

    /// Create a `SetExternalNameCmd` for the given library and chosen file.
    ///
    /// This is the command that would be executed on the program when
    /// the user selects a file in the dialog.
    pub fn create_command(&self, library_name: &str, file_path: &str) -> SetExternalNameCmd {
        SetExternalNameCmd::new(library_name, file_path)
    }

    /// Execute the set-external-program action.
    ///
    /// Validates the context and creates the command to set the external
    /// program path.  In the Java implementation this corresponds to
    /// `actionPerformed()`.
    ///
    /// # Arguments
    ///
    /// * `library_name` -- the name of the external library.
    /// * `current_path` -- the current external library path (if any).
    /// * `chosen_file` -- the file chosen by the user (if any).
    /// * `ext_mgr` -- the external manager for looking up current paths.
    ///
    /// # Returns
    ///
    /// Returns the command to execute, or an error if the action cannot
    /// be performed.
    pub fn execute(
        &self,
        library_name: &str,
        current_path: Option<&str>,
        chosen_file: Option<&ChosenFile>,
        ext_mgr: &ExternalManagerDB,
    ) -> Result<SetExternalNameCmd, SetExternalProgramError> {
        if library_name.is_empty() {
            return Err(SetExternalProgramError::NoSelection);
        }

        let file = chosen_file.ok_or(SetExternalProgramError::NoFileChosen)?;

        // Check if the path is unchanged
        let existing_path = ext_mgr.get_external_library_path(library_name);
        if let Some(ref existing) = existing_path {
            if existing == &file.path {
                return Err(SetExternalProgramError::PathUnchanged(file.path.clone()));
            }
        } else if let Some(current) = current_path {
            if current == file.path {
                return Err(SetExternalProgramError::PathUnchanged(file.path.clone()));
            }
        }

        Ok(self.create_command(library_name, &file.path))
    }
}

impl Default for SetExternalProgramAction {
    fn default() -> Self {
        Self::new("UnknownPlugin")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::symbol::SourceType;

    #[test]
    fn test_action_properties() {
        let action = SetExternalProgramAction::new("SymbolTreePlugin");
        assert_eq!(action.name(), "Set External Program");
        assert_eq!(action.plugin_name(), "SymbolTreePlugin");
        // Disabled by default (matching Java behavior)
        assert!(!action.is_enabled());
    }

    #[test]
    fn test_action_set_enabled() {
        let mut action = SetExternalProgramAction::new("SymbolTreePlugin");
        assert!(!action.is_enabled());
        action.set_enabled(true);
        assert!(action.is_enabled());
        action.set_enabled(false);
        assert!(!action.is_enabled());
    }

    #[test]
    fn test_is_library_node() {
        let action = SetExternalProgramAction::new("SymbolTreePlugin");
        assert!(action.is_library_node("libc.so"));
        assert!(!action.is_library_node(""));
    }

    #[test]
    fn test_search_text() {
        let action = SetExternalProgramAction::new("SymbolTreePlugin");
        assert_eq!(action.search_text_for_library("libc.so"), "libc.so");
    }

    #[test]
    fn test_dialog_title() {
        let action = SetExternalProgramAction::new("SymbolTreePlugin");
        assert_eq!(
            action.dialog_title("libc.so"),
            "Choose External Program (libc.so)"
        );
    }

    #[test]
    fn test_create_command() {
        let action = SetExternalProgramAction::new("SymbolTreePlugin");
        let cmd = action.create_command("libc", "/usr/lib/libc.so");
        assert_eq!(cmd.name(), "Set External Library Name and Path");
        assert_eq!(cmd.external_name(), "libc");
    }

    #[test]
    fn test_execute_success() {
        let action = SetExternalProgramAction::new("SymbolTreePlugin");
        let ext_mgr = ExternalManagerDB::new();
        let file = ChosenFile::new("/project/libc", "libc");

        let result = action.execute("libc", None, Some(&file), &ext_mgr);
        assert!(result.is_ok());
        let cmd = result.unwrap();
        assert_eq!(cmd.external_name(), "libc");
    }

    #[test]
    fn test_execute_no_selection() {
        let action = SetExternalProgramAction::new("SymbolTreePlugin");
        let ext_mgr = ExternalManagerDB::new();

        let result = action.execute("", None, None, &ext_mgr);
        assert!(result.is_err());
        match result.unwrap_err() {
            SetExternalProgramError::NoSelection => {}
            _ => panic!("Expected NoSelection error"),
        }
    }

    #[test]
    fn test_execute_no_file_chosen() {
        let action = SetExternalProgramAction::new("SymbolTreePlugin");
        let ext_mgr = ExternalManagerDB::new();

        let result = action.execute("libc", None, None, &ext_mgr);
        assert!(result.is_err());
        match result.unwrap_err() {
            SetExternalProgramError::NoFileChosen => {}
            _ => panic!("Expected NoFileChosen error"),
        }
    }

    #[test]
    fn test_execute_path_unchanged() {
        let action = SetExternalProgramAction::new("SymbolTreePlugin");
        let mut ext_mgr = ExternalManagerDB::new();
        ext_mgr.add_library("libc", SourceType::Imported).unwrap();
        ext_mgr
            .set_external_path("libc", "/usr/lib/libc.so", true)
            .unwrap();

        let file = ChosenFile::new("/usr/lib/libc.so", "libc.so");
        let result = action.execute("libc", None, Some(&file), &ext_mgr);
        assert!(result.is_err());
        match result.unwrap_err() {
            SetExternalProgramError::PathUnchanged(_) => {}
            _ => panic!("Expected PathUnchanged error"),
        }
    }

    #[test]
    fn test_execute_path_unchanged_current() {
        let action = SetExternalProgramAction::new("SymbolTreePlugin");
        let ext_mgr = ExternalManagerDB::new();

        let file = ChosenFile::new("/old/path", "libc");
        let result = action.execute("libc", Some("/old/path"), Some(&file), &ext_mgr);
        assert!(result.is_err());
        match result.unwrap_err() {
            SetExternalProgramError::PathUnchanged(_) => {}
            _ => panic!("Expected PathUnchanged error"),
        }
    }

    #[test]
    fn test_error_display() {
        let err = SetExternalProgramError::NoSelection;
        assert_eq!(err.to_string(), "No node selected");

        let err = SetExternalProgramError::NotLibraryNode("foo".to_string());
        assert!(err.to_string().contains("foo"));

        let err = SetExternalProgramError::NoFileChosen;
        assert_eq!(err.to_string(), "No file was chosen");

        let err = SetExternalProgramError::PathUnchanged("/path".to_string());
        assert!(err.to_string().contains("/path"));

        let err = SetExternalProgramError::CommandFailed("fail".to_string());
        assert!(err.to_string().contains("fail"));

        let err = SetExternalProgramError::Other("misc".to_string());
        assert_eq!(err.to_string(), "misc");
    }

    #[test]
    fn test_chosen_file() {
        let file = ChosenFile::new("/project/libc", "libc");
        assert_eq!(file.path, "/project/libc");
        assert_eq!(file.display_name, "libc");
    }

    #[test]
    fn test_default() {
        let action = SetExternalProgramAction::default();
        assert_eq!(action.plugin_name(), "UnknownPlugin");
        assert!(!action.is_enabled());
    }

    #[test]
    fn test_complex_scenario() {
        let mut action = SetExternalProgramAction::new("SymbolTreePlugin");
        action.set_enabled(true);

        let mut ext_mgr = ExternalManagerDB::new();
        ext_mgr.add_library("libc", SourceType::Imported).unwrap();
        ext_mgr
            .set_external_path("libc", "/usr/lib/libc.so", true)
            .unwrap();

        // Choose a new path
        let file = ChosenFile::new("/project/libc", "libc");
        let cmd = action.execute("libc", None, Some(&file), &ext_mgr).unwrap();
        assert_eq!(cmd.external_name(), "libc");

        // Try to set the same path (should fail)
        let file2 = ChosenFile::new("/usr/lib/libc.so", "libc.so");
        let result = action.execute("libc", None, Some(&file2), &ext_mgr);
        assert!(result.is_err());
    }
}
