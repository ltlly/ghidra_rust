//! File handler extension point for the filesystem browser.
//!
//! Ported from `ghidra.plugins.fsbrowser.FSBFileHandler`,
//! `FSBFileHandlerContext`, and concrete handler implementations.
//!
//! File handlers allow plugins to add context-menu actions and handle
//! focus/default-action events for files in the browser tree.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use super::GFile;

// ---------------------------------------------------------------------------
// FsbAction -- an action that can be performed on a file
// ---------------------------------------------------------------------------

/// Represents an action that can be performed on a file in the browser.
#[derive(Debug, Clone)]
pub struct FsbAction {
    /// Unique action identifier.
    pub action_id: String,
    /// Human-readable action name (shown in menus).
    pub name: String,
    /// Optional description.
    pub description: String,
    /// Menu group (for ordering).
    pub group: String,
}

impl FsbAction {
    /// Create a new action.
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            action_id: id.into(),
            description: name.clone(),
            name,
            group: String::new(),
        }
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Set the menu group.
    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        self.group = group.into();
        self
    }
}

// ---------------------------------------------------------------------------
// FsbFileHandler -- extension point trait
// ---------------------------------------------------------------------------

/// Extension point for adding file handling capabilities to the
/// filesystem browser.
///
/// Implementors register themselves and are called when files are
/// focused, double-clicked, or shown in context menus.
///
/// Ported from `ghidra.plugins.fsbrowser.FSBFileHandler`.
pub trait FsbFileHandler: std::fmt::Debug + Send + Sync {
    /// Initialize the handler with context.
    fn init(&mut self, context: &FsbFileHandlerContext);

    /// Return actions to add to the browser component.
    fn create_actions(&self) -> Vec<FsbAction> {
        Vec::new()
    }

    /// Called when a file node is focused in the tree.
    /// Returns true if the handler took action.
    fn file_focused(&self, _file: &GFile) -> bool {
        false
    }

    /// Called when a file node receives a default action (double-click).
    /// Returns true if the handler took action.
    fn file_default_action(&self, _file: &GFile) -> bool {
        false
    }

    /// Return actions to show in the context menu popup.
    fn get_popup_actions(&self) -> Vec<FsbAction> {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// FsbFileHandlerContext -- context provided to handlers
// ---------------------------------------------------------------------------

/// Context provided to [`FsbFileHandler`] instances during initialization.
///
/// Contains references to services and the browser that the handler
/// needs.
///
/// Ported from `ghidra.plugins.fsbrowser.FSBFileHandlerContext`.
#[derive(Debug)]
pub struct FsbFileHandlerContext {
    /// Path to the Ghidra installation.
    pub ghidra_home: Option<PathBuf>,
    /// Whether the browser is in a front-end tool context.
    pub is_front_end: bool,
    /// The filesystem type being browsed.
    pub fs_type: String,
}

impl FsbFileHandlerContext {
    /// Create a new context.
    pub fn new(fs_type: impl Into<String>) -> Self {
        Self {
            ghidra_home: None,
            is_front_end: false,
            fs_type: fs_type.into(),
        }
    }

    /// Set the Ghidra home directory.
    pub fn with_ghidra_home(mut self, home: PathBuf) -> Self {
        self.ghidra_home = Some(home);
        self
    }

    /// Set whether this is a front-end context.
    pub fn with_front_end(mut self, is_front_end: bool) -> Self {
        self.is_front_end = is_front_end;
        self
    }
}

// ---------------------------------------------------------------------------
// HandlerRegistry -- registry of file handlers
// ---------------------------------------------------------------------------

/// Registry of file handler extension points.
///
/// Manages the lifecycle of file handler instances and dispatches
/// events to them.
#[derive(Debug)]
pub struct HandlerRegistry {
    /// Registered handlers.
    handlers: Vec<Box<dyn FsbFileHandler>>,
}

impl HandlerRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    /// Register a handler.
    pub fn register(&mut self, handler: Box<dyn FsbFileHandler>) {
        self.handlers.push(handler);
    }

    /// Initialize all handlers with the given context.
    pub fn init_all(&mut self, context: &FsbFileHandlerContext) {
        for handler in &mut self.handlers {
            handler.init(context);
        }
    }

    /// Collect all actions from all handlers.
    pub fn all_actions(&self) -> Vec<FsbAction> {
        self.handlers
            .iter()
            .flat_map(|h| h.create_actions())
            .collect()
    }

    /// Dispatch a file focus event.
    /// Returns true if any handler took action.
    pub fn dispatch_focus(&self, file: &GFile) -> bool {
        self.handlers.iter().any(|h| h.file_focused(file))
    }

    /// Dispatch a file default-action event.
    /// Returns true if any handler took action.
    pub fn dispatch_default_action(&self, file: &GFile) -> bool {
        self.handlers.iter().any(|h| h.file_default_action(file))
    }

    /// Collect all popup menu actions from all handlers.
    pub fn popup_actions(&self) -> Vec<FsbAction> {
        self.handlers
            .iter()
            .flat_map(|h| h.get_popup_actions())
            .collect()
    }

    /// Get the number of registered handlers.
    pub fn handler_count(&self) -> usize {
        self.handlers.len()
    }
}

impl Default for HandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Built-in: ImportHandler -- imports files into the project
// ---------------------------------------------------------------------------

/// Handler that imports files from the filesystem browser into the
/// Ghidra project.
///
/// Ported from `ghidra.plugins.fsbrowser.ImportFSBFileHandler`.
#[derive(Debug, Default)]
pub struct ImportHandler;

impl FsbFileHandler for ImportHandler {
    fn init(&mut self, _context: &FsbFileHandlerContext) {}

    fn create_actions(&self) -> Vec<FsbAction> {
        vec![FsbAction::new("ImportFile", "Import")
            .with_description("Import file into the current project")
            .with_group("import")]
    }

    fn file_default_action(&self, file: &GFile) -> bool {
        // Only import files, not directories
        !file.is_directory
    }
}

// ---------------------------------------------------------------------------
// Built-in: OpenWithHandler -- opens files with associated viewer
// ---------------------------------------------------------------------------

/// Handler that opens files using an associated viewer or editor.
///
/// Ported from `ghidra.plugins.fsbrowser.OpenWithFSBFileHandler`.
#[derive(Debug, Default)]
pub struct OpenWithHandler;

impl FsbFileHandler for OpenWithHandler {
    fn init(&mut self, _context: &FsbFileHandlerContext) {}

    fn create_actions(&self) -> Vec<FsbAction> {
        vec![FsbAction::new("OpenWith", "Open With...")
            .with_description("Open file with a specific viewer")
            .with_group("open")]
    }

    fn get_popup_actions(&self) -> Vec<FsbAction> {
        vec![FsbAction::new("OpenWithPopup", "Open With...")
            .with_description("Choose a viewer for this file")
            .with_group("open")]
    }
}

// ---------------------------------------------------------------------------
// Built-in: ExportHandler -- exports files to disk
// ---------------------------------------------------------------------------

/// Handler that exports files from the filesystem browser to disk.
///
/// Ported from `ghidra.plugins.fsbrowser.ExportFSBFileHandler`.
#[derive(Debug, Default)]
pub struct ExportHandler;

impl FsbFileHandler for ExportHandler {
    fn init(&mut self, _context: &FsbFileHandlerContext) {}

    fn create_actions(&self) -> Vec<FsbAction> {
        vec![FsbAction::new("ExportFile", "Export...")
            .with_description("Export file to disk")
            .with_group("export")]
    }

    fn get_popup_actions(&self) -> Vec<FsbAction> {
        vec![FsbAction::new("ExportPopup", "Export File...")
            .with_description("Export the selected file to disk")
            .with_group("export")]
    }
}

// ---------------------------------------------------------------------------
// Built-in: ExtractAllHandler -- extracts all files to disk
// ---------------------------------------------------------------------------

/// Handler that extracts all files from a mounted filesystem to disk.
///
/// Ported from `ghidra.plugins.fsbrowser.GFileSystemExtractAllTask` and
/// the extract-all action in `FSBComponentProvider`.
#[derive(Debug, Default)]
pub struct ExtractAllHandler;

impl FsbFileHandler for ExtractAllHandler {
    fn init(&mut self, _context: &FsbFileHandlerContext) {}

    fn create_actions(&self) -> Vec<FsbAction> {
        vec![FsbAction::new("ExtractAll", "Extract All...")
            .with_description("Extract all files from this filesystem to disk")
            .with_group("extract")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsbrowser::Fsrl;

    fn make_file(name: &str) -> GFile {
        GFile::file(name, Fsrl::new(format!("fs:/{name}"), name), 100)
    }

    fn make_dir(name: &str) -> GFile {
        GFile::directory(name, Fsrl::new(format!("fs:/{name}"), name))
    }

    #[test]
    fn test_action_creation() {
        let action = FsbAction::new("test", "Test Action")
            .with_description("A test action")
            .with_group("group1");
        assert_eq!(action.action_id, "test");
        assert_eq!(action.name, "Test Action");
        assert_eq!(action.description, "A test action");
        assert_eq!(action.group, "group1");
    }

    #[test]
    fn test_handler_registry_empty() {
        let registry = HandlerRegistry::new();
        assert_eq!(registry.handler_count(), 0);
        assert!(registry.all_actions().is_empty());
    }

    #[test]
    fn test_handler_registry_register_and_init() {
        let mut registry = HandlerRegistry::new();
        registry.register(Box::new(ImportHandler));
        registry.register(Box::new(ExportHandler));
        assert_eq!(registry.handler_count(), 2);

        let context = FsbFileHandlerContext::new("ZIP");
        registry.init_all(&context);

        let actions = registry.all_actions();
        assert_eq!(actions.len(), 2);
    }

    #[test]
    fn test_import_handler_focus_and_default() {
        let handler = ImportHandler;
        let file = make_file("test.bin");
        let dir = make_dir("subdir");

        // Files trigger default action
        assert!(handler.file_default_action(&file));
        // Directories do not
        assert!(!handler.file_default_action(&dir));
    }

    #[test]
    fn test_open_with_handler_popup() {
        let handler = OpenWithHandler;
        let popup_actions = handler.get_popup_actions();
        assert_eq!(popup_actions.len(), 1);
        assert_eq!(popup_actions[0].action_id, "OpenWithPopup");
    }

    #[test]
    fn test_export_handler_actions() {
        let handler = ExportHandler;
        let actions = handler.create_actions();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].action_id, "ExportFile");

        let popup = handler.get_popup_actions();
        assert_eq!(popup.len(), 1);
    }

    #[test]
    fn test_extract_all_handler() {
        let handler = ExtractAllHandler;
        let actions = handler.create_actions();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].name, "Extract All...");
    }

    #[test]
    fn test_context_creation() {
        let ctx = FsbFileHandlerContext::new("TAR")
            .with_ghidra_home(PathBuf::from("/opt/ghidra"))
            .with_front_end(true);
        assert_eq!(ctx.fs_type, "TAR");
        assert_eq!(ctx.ghidra_home, Some(PathBuf::from("/opt/ghidra")));
        assert!(ctx.is_front_end);
    }

    #[test]
    fn test_dispatch_focus_no_handlers() {
        let registry = HandlerRegistry::new();
        let file = make_file("test.bin");
        assert!(!registry.dispatch_focus(&file));
    }

    #[test]
    fn test_dispatch_default_action_with_handlers() {
        let mut registry = HandlerRegistry::new();
        registry.register(Box::new(ImportHandler));
        let file = make_file("test.bin");
        assert!(registry.dispatch_default_action(&file));
    }

    #[test]
    fn test_popup_actions_from_multiple_handlers() {
        let mut registry = HandlerRegistry::new();
        registry.register(Box::new(OpenWithHandler));
        registry.register(Box::new(ExportHandler));

        let popup = registry.popup_actions();
        assert_eq!(popup.len(), 2);
    }
}
