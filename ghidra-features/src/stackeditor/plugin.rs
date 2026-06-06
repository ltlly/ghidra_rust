//! Stack Editor Manager Plugin -- popup edit sessions for function stack frames.
//!
//! Ported from `ghidra.app.plugin.core.stackeditor.StackEditorManagerPlugin`.

use ghidra_core::Address;
use super::manager::StackEditorManager;

/// Plugin that manages stack editor sessions.
///
/// Registers the "Edit Stack Frame" action and manages the lifecycle of
/// stack editor providers.
#[derive(Debug)]
pub struct StackEditorManagerPlugin {
    /// Plugin name.
    pub name: String,
    /// Whether numeric values should be displayed in hex.
    pub show_hex: bool,
    /// The editor manager that handles open editors.
    editor_mgr: StackEditorManager,
}

impl StackEditorManagerPlugin {
    /// Create a new stack editor plugin.
    pub fn new() -> Self {
        Self {
            name: "Stack Editor".to_string(),
            show_hex: true,
            editor_mgr: StackEditorManager::new(),
        }
    }

    /// Open a stack editor for a function at the given address.
    pub fn edit(&mut self, function_address: Address, frame_size: usize) {
        self.editor_mgr.open_session(
            function_address,
            frame_size,
            true,  // grows_negative
            4,     // return_address_offset
            0,     // parameter_offset
            16,    // local_size
            8,     // param_size
        );
    }

    /// Whether the plugin can close (no dirty sessions).
    pub fn can_close(&self) -> bool {
        self.editor_mgr.can_close_all()
    }

    /// Close the plugin and all editors.
    pub fn close(&mut self) {
        self.editor_mgr.close_all();
    }

    /// Close all sessions associated with a program (by checking all open functions).
    pub fn close_sessions_for_program(&mut self) {
        self.editor_mgr.close_all();
    }

    /// Get the help topic.
    pub fn help_topic(&self) -> &str {
        "StackEditor"
    }

    /// Toggle hex display.
    pub fn set_show_hex(&mut self, show: bool) {
        self.show_hex = show;
    }

    /// Get the number of open editors.
    pub fn open_editor_count(&self) -> usize {
        self.editor_mgr.session_count()
    }

    /// Get the underlying editor manager.
    pub fn editor_manager(&self) -> &StackEditorManager {
        &self.editor_mgr
    }

    /// Get a mutable reference to the underlying editor manager.
    pub fn editor_manager_mut(&mut self) -> &mut StackEditorManager {
        &mut self.editor_mgr
    }
}

impl Default for StackEditorManagerPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = StackEditorManagerPlugin::new();
        assert_eq!(plugin.name, "Stack Editor");
        assert!(plugin.show_hex);
        assert_eq!(plugin.open_editor_count(), 0);
    }

    #[test]
    fn test_plugin_edit() {
        let mut plugin = StackEditorManagerPlugin::new();
        plugin.edit(Address::new(0x1000), 64);
        assert_eq!(plugin.open_editor_count(), 1);
    }

    #[test]
    fn test_plugin_close() {
        let mut plugin = StackEditorManagerPlugin::new();
        plugin.edit(Address::new(0x1000), 64);
        assert!(plugin.can_close()); // not dirty by default
        plugin.close();
        assert_eq!(plugin.open_editor_count(), 0);
    }

    #[test]
    fn test_plugin_help() {
        let plugin = StackEditorManagerPlugin::new();
        assert_eq!(plugin.help_topic(), "StackEditor");
    }

    #[test]
    fn test_plugin_hex_toggle() {
        let mut plugin = StackEditorManagerPlugin::new();
        assert!(plugin.show_hex);
        plugin.set_show_hex(false);
        assert!(!plugin.show_hex);
    }

    #[test]
    fn test_plugin_multiple_sessions() {
        let mut plugin = StackEditorManagerPlugin::new();
        plugin.edit(Address::new(0x1000), 64);
        plugin.edit(Address::new(0x2000), 128);
        assert_eq!(plugin.open_editor_count(), 2);
    }

    #[test]
    fn test_plugin_editor_manager() {
        let mut plugin = StackEditorManagerPlugin::new();
        plugin.edit(Address::new(0x1000), 64);
        assert!(plugin.editor_manager().is_open(Address::new(0x1000)));
    }
}
