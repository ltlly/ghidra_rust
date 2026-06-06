//! Framework main: application configuration, data-tree dialogs, and project browsing.
//!
//! Ported from `ghidra.framework.main` and `ghidra.framework.main.datatree`.
//!
//! Provides application configuration types, data-tree dialog enums,
//! and data-flavor handler service interfaces for drag-and-drop in the
//! Ghidra project tree.

use std::fmt;

// ---------------------------------------------------------------------------
// GhidraApplicationConfiguration
// ---------------------------------------------------------------------------

/// Configuration for a Ghidra application instance.
///
/// Controls application-level settings such as whether the application
/// runs in headless mode, the application title, and display factory.
#[derive(Debug, Clone)]
pub struct GhidraApplicationConfiguration {
    /// Application title.
    pub title: String,
    /// Whether the application is running in headless (CLI) mode.
    pub headless: bool,
    /// Whether to show the splash screen.
    pub show_splash: bool,
    /// Whether to display the application information window.
    pub show_info: bool,
}

impl GhidraApplicationConfiguration {
    /// Create a default GUI configuration.
    pub fn gui() -> Self {
        Self {
            title: "Ghidra".into(),
            headless: false,
            show_splash: true,
            show_info: true,
        }
    }

    /// Create a headless (CLI) configuration.
    pub fn headless() -> Self {
        Self {
            title: "Ghidra Headless".into(),
            headless: true,
            show_splash: false,
            show_info: false,
        }
    }
}

impl Default for GhidraApplicationConfiguration {
    fn default() -> Self {
        Self::gui()
    }
}

// ---------------------------------------------------------------------------
// DataTreeDialogType
// ---------------------------------------------------------------------------

/// The type of data-tree dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataTreeDialogType {
    /// Save dialog (select a location to save to).
    SAVE,
    /// Open dialog (select a file to open).
    OPEN,
    /// Choose folder dialog.
    CHOOSE_FOLDER,
    /// Choose file dialog.
    CHOOSE_FILE,
}

impl fmt::Display for DataTreeDialogType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SAVE => write!(f, "Save"),
            Self::OPEN => write!(f, "Open"),
            Self::CHOOSE_FOLDER => write!(f, "Choose Folder"),
            Self::CHOOSE_FILE => write!(f, "Choose File"),
        }
    }
}

// ---------------------------------------------------------------------------
// DataTreeDialog
// ---------------------------------------------------------------------------

/// Configuration for a data-tree dialog.
#[derive(Debug, Clone)]
pub struct DataTreeDialog {
    /// The dialog title.
    pub title: String,
    /// The dialog type.
    pub dialog_type: DataTreeDialogType,
    /// Whether to allow creating new folders.
    pub allow_new_folders: bool,
    /// Whether to filter by file type.
    pub file_type_filter: Option<String>,
}

impl DataTreeDialog {
    /// Create a save dialog.
    pub fn save(title: &str) -> Self {
        Self {
            title: title.to_string(),
            dialog_type: DataTreeDialogType::SAVE,
            allow_new_folders: true,
            file_type_filter: None,
        }
    }

    /// Create an open dialog.
    pub fn open(title: &str) -> Self {
        Self {
            title: title.to_string(),
            dialog_type: DataTreeDialogType::OPEN,
            allow_new_folders: false,
            file_type_filter: None,
        }
    }

    /// Create a folder chooser dialog.
    pub fn choose_folder(title: &str) -> Self {
        Self {
            title: title.to_string(),
            dialog_type: DataTreeDialogType::CHOOSE_FOLDER,
            allow_new_folders: true,
            file_type_filter: None,
        }
    }

    /// Set a file type filter.
    pub fn with_file_type_filter(mut self, filter: &str) -> Self {
        self.file_type_filter = Some(filter.to_string());
        self
    }

    /// Set whether to allow new folders.
    pub fn with_allow_new_folders(mut self, allow: bool) -> Self {
        self.allow_new_folders = allow;
        self
    }
}

// ---------------------------------------------------------------------------
// GhidraDataFlavorHandlerService
// ---------------------------------------------------------------------------

/// Trait for handling data-flavor drag-and-drop operations in the project tree.
pub trait DataFlavorHandler: Send + Sync {
    /// Human-readable name for this handler.
    fn name(&self) -> &str;

    /// Whether this handler can handle the given MIME type.
    fn can_handle(&self, mime_type: &str) -> bool;

    /// Handle a drop operation with the given data.
    fn handle_drop(&self, data: &[u8], target_path: &str) -> Result<(), String>;
}

/// Service that manages data-flavor handlers for drag-and-drop.
#[derive(Default)]
pub struct GhidraDataFlavorHandlerService {
    handlers: Vec<Box<dyn DataFlavorHandler>>,
}

impl std::fmt::Debug for GhidraDataFlavorHandlerService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GhidraDataFlavorHandlerService")
            .field("handler_count", &self.handlers.len())
            .finish()
    }
}

impl GhidraDataFlavorHandlerService {
    /// Create a new empty service.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a handler.
    pub fn add_handler(&mut self, handler: Box<dyn DataFlavorHandler>) {
        self.handlers.push(handler);
    }

    /// Find a handler that can process the given MIME type.
    pub fn find_handler(&self, mime_type: &str) -> Option<&dyn DataFlavorHandler> {
        self.handlers
            .iter()
            .find(|h| h.can_handle(mime_type))
            .map(|h| h.as_ref())
    }

    /// Number of registered handlers.
    pub fn handler_count(&self) -> usize {
        self.handlers.len()
    }
}

// ---------------------------------------------------------------------------
// ArchiveProvider
// ---------------------------------------------------------------------------

/// Trait for providing access to archive files in the project tree.
pub trait ArchiveProvider: Send + Sync {
    /// Whether this provider can handle the given file extension.
    fn can_handle(&self, extension: &str) -> bool;

    /// Open the archive and return a list of contained file paths.
    fn list_contents(&self, archive_path: &str) -> Result<Vec<String>, String>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_application_config_gui() {
        let config = GhidraApplicationConfiguration::gui();
        assert_eq!(config.title, "Ghidra");
        assert!(!config.headless);
        assert!(config.show_splash);
    }

    #[test]
    fn test_application_config_headless() {
        let config = GhidraApplicationConfiguration::headless();
        assert!(config.headless);
        assert!(!config.show_splash);
        assert!(!config.show_info);
    }

    #[test]
    fn test_application_config_default() {
        let config = GhidraApplicationConfiguration::default();
        assert!(!config.headless);
    }

    #[test]
    fn test_dialog_type_display() {
        assert_eq!(DataTreeDialogType::SAVE.to_string(), "Save");
        assert_eq!(DataTreeDialogType::OPEN.to_string(), "Open");
        assert_eq!(DataTreeDialogType::CHOOSE_FOLDER.to_string(), "Choose Folder");
        assert_eq!(DataTreeDialogType::CHOOSE_FILE.to_string(), "Choose File");
    }

    #[test]
    fn test_data_tree_dialog_save() {
        let dialog = DataTreeDialog::save("Save Program");
        assert_eq!(dialog.title, "Save Program");
        assert_eq!(dialog.dialog_type, DataTreeDialogType::SAVE);
        assert!(dialog.allow_new_folders);
    }

    #[test]
    fn test_data_tree_dialog_open() {
        let dialog = DataTreeDialog::open("Open Program");
        assert_eq!(dialog.dialog_type, DataTreeDialogType::OPEN);
        assert!(!dialog.allow_new_folders);
    }

    #[test]
    fn test_data_tree_dialog_builder() {
        let dialog = DataTreeDialog::open("Import")
            .with_file_type_filter("gzf")
            .with_allow_new_folders(true);
        assert_eq!(dialog.file_type_filter, Some("gzf".into()));
        assert!(dialog.allow_new_folders);
    }

    #[test]
    fn test_flavor_handler_service() {
        let mut service = GhidraDataFlavorHandlerService::new();
        assert_eq!(service.handler_count(), 0);
        assert!(service.find_handler("text/plain").is_none());
    }
}
