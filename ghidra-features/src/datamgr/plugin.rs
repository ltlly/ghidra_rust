//! DataTypeManagerPlugin -- ported from `DataTypeManagerPlugin.java`.
//!
//! The top-level plugin for managing data types in Ghidra.  It
//! coordinates the data type handler, editor manager, and provides
//! the plugin lifecycle.

use super::handler::DataTypeManagerHandler;
use super::editor::DataTypeEditorManager;
use super::tree::ArchiveRootNode;
use super::sync::DataTypeSynchronizer;

/// The data type manager plugin.
///
/// Ported from Ghidra's `DataTypeManagerPlugin` which extends `ProgramPlugin`.
///
/// # Example
///
/// ```
/// use ghidra_features::datamgr::plugin::*;
///
/// let mut plugin = DataTypeManagerPlugin::new("DataTypeManager");
/// assert_eq!(plugin.name(), "DataTypeManager");
/// assert!(!plugin.is_disposed());
/// ```
#[derive(Debug)]
pub struct DataTypeManagerPlugin {
    /// The plugin name.
    name: String,
    /// The central handler.
    handler: DataTypeManagerHandler,
    /// The editor manager.
    editor_manager: DataTypeEditorManager,
    /// The synchronizer.
    synchronizer: DataTypeSynchronizer,
    /// The tree root.
    tree_root: ArchiveRootNode,
    /// The active program name.
    active_program: Option<String>,
    /// Whether the plugin is disposed.
    disposed: bool,
}

impl DataTypeManagerPlugin {
    /// The options category.
    pub const OPTIONS_CATEGORY: &'static str = "Data Type Manager";

    /// Creates a new data type manager plugin.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            handler: DataTypeManagerHandler::new("DataTypeManager"),
            editor_manager: DataTypeEditorManager::new(),
            synchronizer: DataTypeSynchronizer::new("program", "archive", true),
            tree_root: ArchiveRootNode::new(),
            active_program: None,
            disposed: false,
        }
    }

    /// Returns the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    // -- Handler --

    /// Returns a reference to the data type manager handler.
    pub fn handler(&self) -> &DataTypeManagerHandler {
        &self.handler
    }

    /// Returns a mutable reference to the handler.
    pub fn handler_mut(&mut self) -> &mut DataTypeManagerHandler {
        &mut self.handler
    }

    // -- Editor Manager --

    /// Returns a reference to the editor manager.
    pub fn editor_manager(&self) -> &DataTypeEditorManager {
        &self.editor_manager
    }

    /// Returns a mutable reference to the editor manager.
    pub fn editor_manager_mut(&mut self) -> &mut DataTypeEditorManager {
        &mut self.editor_manager
    }

    // -- Synchronizer --

    /// Returns a reference to the synchronizer.
    pub fn synchronizer(&self) -> &DataTypeSynchronizer {
        &self.synchronizer
    }

    // -- Tree --

    /// Returns a reference to the tree root.
    pub fn tree_root(&self) -> &ArchiveRootNode {
        &self.tree_root
    }

    /// Returns a mutable reference to the tree root.
    pub fn tree_root_mut(&mut self) -> &mut ArchiveRootNode {
        &mut self.tree_root
    }

    // -- Program lifecycle --

    /// Sets the active program.
    pub fn program_activated(&mut self, program_name: String) {
        self.active_program = Some(program_name);
    }

    /// Called when the active program is closed.
    pub fn program_closed(&mut self) {
        self.active_program = None;
        self.editor_manager.dismiss_editors(None);
    }

    /// Returns the active program name.
    pub fn active_program(&self) -> Option<&str> {
        self.active_program.as_deref()
    }

    // -- Data type operations --

    /// Finds a data type by name in the handler's indexer.
    pub fn find_data_type(&self, name: &str) -> bool {
        // Search through all archives for a type with the given name.
        self.handler
            .all_archives()
            .iter()
            .any(|archive| archive.data_type_manager().contains(name))
    }

    /// Returns the number of open archives.
    pub fn archive_count(&self) -> usize {
        self.handler.all_archives().len()
    }

    /// Checks if there are unsaved editor changes.
    pub fn has_unsaved_editor_changes(&self) -> bool {
        self.editor_manager.has_editor_changes(None)
    }

    // -- Disposal --

    /// Disposes the plugin.
    pub fn dispose(&mut self) {
        self.editor_manager.dispose();
        self.active_program = None;
        self.disposed = true;
    }
}

impl Default for DataTypeManagerPlugin {
    fn default() -> Self {
        Self::new("DataTypeManager")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = DataTypeManagerPlugin::new("TestDTM");
        assert_eq!(plugin.name(), "TestDTM");
        assert!(!plugin.is_disposed());
        assert!(plugin.active_program().is_none());
    }

    #[test]
    fn test_plugin_program_lifecycle() {
        let mut plugin = DataTypeManagerPlugin::new("Test");
        assert!(plugin.active_program().is_none());

        plugin.program_activated("test.exe".to_string());
        assert_eq!(plugin.active_program(), Some("test.exe"));

        plugin.program_closed();
        assert!(plugin.active_program().is_none());
    }

    #[test]
    fn test_plugin_handler() {
        let plugin = DataTypeManagerPlugin::new("Test");
        assert_eq!(plugin.handler().all_archives().len(), 0);
    }

    #[test]
    fn test_plugin_editor_manager() {
        let plugin = DataTypeManagerPlugin::new("Test");
        assert!(!plugin.editor_manager().is_edit_in_progress());
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = DataTypeManagerPlugin::new("Test");
        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_plugin_constants() {
        assert_eq!(
            DataTypeManagerPlugin::OPTIONS_CATEGORY,
            "Data Type Manager"
        );
    }
}
