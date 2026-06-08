//! BSim server dialog for managing database server definitions.
//!
//! Ports `ghidra.features.bsim.gui.search.dialog.BSimServerDialog`.
//!
//! Provides the data model and state for a dialog that lets users:
//! - Add / remove BSim database server definitions
//! - Toggle JDBC data-source connections
//! - Change passwords
//! - View server connection status

use super::search_plugin::{BSimServerEntry, BSimServerManager};
use super::{BSimServerInfo, ConnectionType};

/// State for the BSim Server Manager dialog.
///
/// Ports `ghidra.features.bsim.gui.search.dialog.BSimServerDialog`.
#[derive(Debug)]
pub struct BSimServerDialog {
    /// The server manager being edited.
    pub server_manager: BSimServerManager,
    /// Currently selected server index (in display order).
    selected_index: Option<usize>,
    /// Whether the dialog is visible.
    visible: bool,
    /// Preferred dialog width.
    pub preferred_width: u32,
    /// Preferred dialog height.
    pub preferred_height: u32,
    /// Pending operations to apply on dismiss.
    pending_ops: Vec<ServerDialogOperation>,
}

/// Operations that can be performed in the server dialog.
#[derive(Debug, Clone)]
pub enum ServerDialogOperation {
    /// Add a new server definition.
    AddServer {
        /// Server name.
        name: String,
        /// Server connection info.
        info: BSimServerInfo,
    },
    /// Remove a server definition.
    RemoveServer {
        /// Server name to remove.
        name: String,
    },
    /// Toggle the connection to a JDBC data source.
    ToggleConnection {
        /// Server name.
        name: String,
    },
    /// Change password for a server.
    ChangePassword {
        /// Server name.
        name: String,
    },
}

impl BSimServerDialog {
    /// Create a new server dialog state.
    pub fn new(server_manager: BSimServerManager) -> Self {
        Self {
            server_manager,
            selected_index: None,
            visible: false,
            preferred_width: 600,
            preferred_height: 400,
            pending_ops: Vec::new(),
        }
    }

    /// Show the dialog.
    pub fn show(&mut self) {
        self.visible = true;
    }

    /// Dismiss the dialog, applying pending operations.
    pub fn dismiss(&mut self) {
        self.visible = false;
        self.pending_ops.clear();
    }

    /// Whether the dialog is currently visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Get the currently selected server index.
    pub fn selected_index(&self) -> Option<usize> {
        self.selected_index
    }

    /// Set the selected server index.
    pub fn set_selected_index(&mut self, index: Option<usize>) {
        self.selected_index = index;
    }

    /// Whether a server is currently selected.
    pub fn has_selection(&self) -> bool {
        self.selected_index.is_some()
    }

    /// Get the name of the currently selected server.
    pub fn selected_server_name(&self) -> Option<&str> {
        self.selected_index
            .and_then(|idx| self.server_manager.server_names().get(idx).copied())
    }

    /// Define a new BSim server (add).
    pub fn define_server(&mut self, name: impl Into<String>, info: BSimServerInfo) {
        let name = name.into();
        self.pending_ops.push(ServerDialogOperation::AddServer {
            name: name.clone(),
            info: info.clone(),
        });
        self.server_manager.add_server(&name, info);
    }

    /// Delete the currently selected BSim server.
    pub fn delete_selected_server(&mut self) -> bool {
        if let Some(name) = self.selected_server_name().map(|s| s.to_string()) {
            self.pending_ops
                .push(ServerDialogOperation::RemoveServer { name: name.clone() });
            self.server_manager.remove_server(&name);
            // Adjust selection
            let count = self.server_manager.server_count();
            if count == 0 {
                self.selected_index = None;
            } else if let Some(idx) = self.selected_index {
                if idx >= count {
                    self.selected_index = Some(count - 1);
                }
            }
            true
        } else {
            false
        }
    }

    /// Toggle the connection for the selected server.
    pub fn toggle_selected_connection(&mut self) -> bool {
        if let Some(name) = self.selected_server_name().map(|s| s.to_string()) {
            self.pending_ops
                .push(ServerDialogOperation::ToggleConnection { name: name.clone() });
            if let Some(entry) = self.server_manager.get_server_mut(&name) {
                entry.connected = !entry.connected;
                return true;
            }
        }
        false
    }

    /// Whether a non-active JDBC data source is selected.
    ///
    /// Used to enable/disable the connection toggle action.
    pub fn is_non_active_jdbc_selected(&self) -> bool {
        if let Some(name) = self.selected_server_name() {
            if let Some(entry) = self.server_manager.get_server(name) {
                return matches!(
                    entry.info.connection_type,
                    ConnectionType::PostgreSQL | ConnectionType::File
                ) && !entry.connected;
            }
        }
        false
    }

    /// Get the pending operations.
    pub fn pending_operations(&self) -> &[ServerDialogOperation] {
        &self.pending_ops
    }

    /// Get the server display entries (ordered by registration).
    pub fn server_entries(&self) -> Vec<(&str, &BSimServerEntry)> {
        self.server_manager
            .server_names()
            .into_iter()
            .filter_map(|name| {
                self.server_manager
                    .get_server(name)
                    .map(|entry| (name, entry))
            })
            .collect()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_info() -> BSimServerInfo {
        BSimServerInfo {
            url: "localhost:5432".to_string(),
            database_name: "bsim_db".to_string(),
            connection_type: ConnectionType::PostgreSQL,
            use_ssl: false,
            username: None,
        }
    }

    fn elastic_info() -> BSimServerInfo {
        BSimServerInfo {
            url: "localhost:9200".to_string(),
            database_name: "bsim_elastic".to_string(),
            connection_type: ConnectionType::Elastic,
            use_ssl: true,
            username: Some("elastic".to_string()),
        }
    }

    #[test]
    fn dialog_new() {
        let mgr = BSimServerManager::new();
        let dialog = BSimServerDialog::new(mgr);
        assert!(!dialog.is_visible());
        assert!(!dialog.has_selection());
        assert_eq!(dialog.preferred_width, 600);
        assert_eq!(dialog.preferred_height, 400);
    }

    #[test]
    fn dialog_show_dismiss() {
        let mgr = BSimServerManager::new();
        let mut dialog = BSimServerDialog::new(mgr);
        dialog.show();
        assert!(dialog.is_visible());
        dialog.dismiss();
        assert!(!dialog.is_visible());
    }

    #[test]
    fn dialog_define_server() {
        let mgr = BSimServerManager::new();
        let mut dialog = BSimServerDialog::new(mgr);
        dialog.define_server("local", sample_info());
        assert_eq!(dialog.server_manager.server_count(), 1);
        assert_eq!(dialog.pending_operations().len(), 1);
    }

    #[test]
    fn dialog_selection() {
        let mgr = BSimServerManager::new();
        let mut dialog = BSimServerDialog::new(mgr);
        dialog.define_server("s1", sample_info());
        dialog.define_server("s2", elastic_info());

        dialog.set_selected_index(Some(0));
        assert!(dialog.has_selection());
        // Selection maps to server name
        let name = dialog.selected_server_name().unwrap();
        assert!(name == "s1" || name == "s2"); // order depends on HashMap
    }

    #[test]
    fn dialog_delete_selected() {
        let mgr = BSimServerManager::new();
        let mut dialog = BSimServerDialog::new(mgr);
        dialog.define_server("s1", sample_info());
        dialog.set_selected_index(Some(0));

        assert!(dialog.delete_selected_server());
        assert_eq!(dialog.server_manager.server_count(), 0);
        assert!(dialog.selected_index().is_none());
    }

    #[test]
    fn dialog_delete_no_selection() {
        let mgr = BSimServerManager::new();
        let mut dialog = BSimServerDialog::new(mgr);
        dialog.define_server("s1", sample_info());
        // No selection
        assert!(!dialog.delete_selected_server());
    }

    #[test]
    fn dialog_toggle_connection() {
        let mgr = BSimServerManager::new();
        let mut dialog = BSimServerDialog::new(mgr);
        dialog.define_server("local", sample_info());
        dialog.set_selected_index(Some(0));

        // Toggle on
        assert!(dialog.toggle_selected_connection());
        let name = dialog.selected_server_name().unwrap().to_string();
        assert!(dialog.server_manager.get_server(&name).unwrap().connected);

        // Toggle off
        assert!(dialog.toggle_selected_connection());
        assert!(!dialog.server_manager.get_server(&name).unwrap().connected);
    }

    #[test]
    fn dialog_jdbc_selected_check() {
        let mgr = BSimServerManager::new();
        let mut dialog = BSimServerDialog::new(mgr);
        dialog.define_server("postgres", sample_info());
        dialog.set_selected_index(Some(0));

        // Initially not connected, PostgreSQL type => should be true
        assert!(dialog.is_non_active_jdbc_selected());

        // Connect it
        dialog.toggle_selected_connection();
        assert!(!dialog.is_non_active_jdbc_selected());
    }

    #[test]
    fn dialog_elastic_not_jdbc() {
        let mgr = BSimServerManager::new();
        let mut dialog = BSimServerDialog::new(mgr);
        dialog.define_server("elastic", elastic_info());
        dialog.set_selected_index(Some(0));

        // Elastic is not JDBC
        assert!(!dialog.is_non_active_jdbc_selected());
    }

    #[test]
    fn dialog_server_entries() {
        let mgr = BSimServerManager::new();
        let mut dialog = BSimServerDialog::new(mgr);
        dialog.define_server("a", sample_info());
        dialog.define_server("b", elastic_info());

        let entries = dialog.server_entries();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn dialog_pending_operations_cleared_on_dismiss() {
        let mgr = BSimServerManager::new();
        let mut dialog = BSimServerDialog::new(mgr);
        dialog.define_server("s1", sample_info());
        assert_eq!(dialog.pending_operations().len(), 1);
        dialog.dismiss();
        assert_eq!(dialog.pending_operations().len(), 0);
    }

    #[test]
    fn server_dialog_operation_variants() {
        let op = ServerDialogOperation::AddServer {
            name: "test".to_string(),
            info: sample_info(),
        };
        match op {
            ServerDialogOperation::AddServer { name, .. } => assert_eq!(name, "test"),
            _ => panic!("wrong variant"),
        }

        let op = ServerDialogOperation::RemoveServer {
            name: "del".to_string(),
        };
        match op {
            ServerDialogOperation::RemoveServer { name } => assert_eq!(name, "del"),
            _ => panic!("wrong variant"),
        }

        let op = ServerDialogOperation::ToggleConnection {
            name: "toggle".to_string(),
        };
        assert!(matches!(op, ServerDialogOperation::ToggleConnection { .. }));

        let op = ServerDialogOperation::ChangePassword {
            name: "pw".to_string(),
        };
        assert!(matches!(op, ServerDialogOperation::ChangePassword { .. }));
    }
}
