//! Table service plugin.
//!
//! This module provides the Rust analogue of
//! `ghidra.app.plugin.core.table.TableServicePlugin`, which manages
//! table component providers and table-chooser dialogs for each
//! loaded program.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use super::dialog::TableServiceTableChooserDialog;
use super::provider::TableComponentProvider;
use super::traits::TableChooserExecutor;

// ---------------------------------------------------------------------------
// PluginState
// ---------------------------------------------------------------------------

/// Lifecycle state of the table service plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginState {
    /// The plugin is being constructed.
    Initializing,
    /// The plugin is active and accepting requests.
    Active,
    /// The plugin has been disposed.
    Disposed,
}

// ---------------------------------------------------------------------------
// TableServicePlugin
// ---------------------------------------------------------------------------

/// Plugin that provides a generic results table service.
///
/// This is the Rust equivalent of
/// `ghidra.app.plugin.core.table.TableServicePlugin`.  It manages:
///
/// - [`TableComponentProvider`] instances per program
/// - [`TableServiceTableChooserDialog`] instances per program
/// - Automatic cleanup when a program is closed
///
/// # Usage
///
/// ```ignore
/// let mut plugin = TableServicePlugin::new("TableServicePlugin");
///
/// // Register a table view for a program.
/// let provider_id = plugin.show_table("test.exe", "Search Text \"foo\"", "Search Results", None);
///
/// // Close all tables for a program.
/// plugin.program_closed("test.exe");
/// ```
pub struct TableServicePlugin {
    /// Plugin identifier.
    id: String,
    /// Current plugin state.
    state: PluginState,
    /// Table component providers per program.
    program_providers: HashMap<String, Vec<TableComponentProvider>>,
    /// Table-chooser dialogs per program.
    program_dialogs: HashMap<String, Vec<TableServiceTableChooserDialog>>,
    /// Global provider ID counter.
    next_provider_id: u64,
    /// Global dialog ID counter.
    next_dialog_id: u64,
    /// Debounce interval for update notifications (milliseconds).
    update_interval_ms: u64,
    /// Whether an update is pending.
    update_pending: bool,
}

impl TableServicePlugin {
    /// Creates a new `TableServicePlugin`.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            state: PluginState::Initializing,
            program_providers: HashMap::new(),
            program_dialogs: HashMap::new(),
            next_provider_id: 1,
            next_dialog_id: 1,
            update_interval_ms: 1000,
            update_pending: false,
        }
    }

    /// Activates the plugin.
    pub fn activate(&mut self) {
        self.state = PluginState::Active;
    }

    /// Disposes the plugin, cleaning up all managed resources.
    pub fn dispose(&mut self) {
        self.program_providers.clear();
        self.program_dialogs.clear();
        self.state = PluginState::Disposed;
    }

    /// Returns the plugin ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the current plugin state.
    pub fn state(&self) -> PluginState {
        self.state
    }

    // -- Program lifecycle -------------------------------------------------

    /// Called when a program is closed.
    ///
    /// Closes all providers and dialogs for the given program.
    pub fn program_closed(&mut self, program: &str) {
        self.clear_table_component_providers(program);
        self.clear_table_dialogs(program);
    }

    /// Called when a program is deactivated.
    pub fn program_deactivated(&mut self, _program: &str) {
        // In the Java version this removes a domain object listener.
        // In the Rust model this is a no-op.
    }

    /// Called when a program is activated.
    pub fn program_activated(&mut self, _program: &str) {
        // In the Java version this adds a domain object listener.
        // In the Rust model this is a no-op.
    }

    // -- Provider management -----------------------------------------------

    /// Creates and registers a new table component provider.
    ///
    /// Returns the provider ID.
    pub fn show_table(
        &mut self,
        program: &str,
        title: &str,
        table_type_name: &str,
        window_sub_menu: Option<String>,
    ) -> String {
        let id = format!("{}_{}", self.id, self.next_provider_id);
        self.next_provider_id += 1;

        let mut provider = TableComponentProvider::new(
            &id,
            title,
            table_type_name,
            program,
            window_sub_menu,
        );
        provider.set_visible(true);

        self.add_provider(program, provider);
        id
    }

    /// Creates and registers a new table component provider with markers.
    ///
    /// Returns the provider ID.
    pub fn show_table_with_markers(
        &mut self,
        program: &str,
        title: &str,
        table_type_name: &str,
        marker_color: (u8, u8, u8, u8),
        window_sub_menu: Option<String>,
    ) -> String {
        let id = format!("{}_{}", self.id, self.next_provider_id);
        self.next_provider_id += 1;

        let mut provider = TableComponentProvider::new(
            &id,
            title,
            table_type_name,
            program,
            window_sub_menu,
        );
        provider.set_visible(true);
        provider.create_marker_set(table_type_name, marker_color);

        self.add_provider(program, provider);
        id
    }

    fn add_provider(&mut self, program: &str, provider: TableComponentProvider) {
        self.program_providers
            .entry(program.to_string())
            .or_insert_with(Vec::new)
            .push(provider);
    }

    /// Removes a provider by ID.
    ///
    /// Returns `true` if the provider was found and removed.
    pub fn remove_provider(&mut self, provider_id: &str) -> bool {
        for providers in self.program_providers.values_mut() {
            if let Some(idx) = providers.iter().position(|p| p.id() == provider_id) {
                providers.remove(idx);
                return true;
            }
        }
        false
    }

    /// Returns all managed component providers.
    pub fn get_managed_components(&self) -> Vec<&TableComponentProvider> {
        self.program_providers
            .values()
            .flat_map(|v| v.iter())
            .collect()
    }

    /// Returns all managed component providers for a specific program.
    pub fn get_providers_for_program(&self, program: &str) -> &[TableComponentProvider] {
        self.program_providers
            .get(program)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    fn clear_table_component_providers(&mut self, program: &str) {
        if let Some(mut providers) = self.program_providers.remove(program) {
            for provider in &mut providers {
                provider.close_component();
            }
        }
    }

    // -- Dialog management -------------------------------------------------

    /// Creates a new table-chooser dialog.
    ///
    /// Returns the dialog ID.
    pub fn create_table_chooser_dialog(
        &mut self,
        program: &str,
        title: &str,
        executor: Option<Arc<dyn TableChooserExecutor>>,
        is_modal: bool,
    ) -> String {
        let id = format!("{}_dialog_{}", self.id, self.next_dialog_id);
        self.next_dialog_id += 1;

        let dialog = TableServiceTableChooserDialog::new(
            &self.id,
            title,
            executor,
            Some(program.to_string()),
            is_modal,
        );

        self.program_dialogs
            .entry(program.to_string())
            .or_insert_with(Vec::new)
            .push(dialog);

        id
    }

    /// Removes a dialog by its plugin ID and dialog reference.
    pub fn remove_dialog(&mut self, dialog_plugin_id: &str) {
        for dialogs in self.program_dialogs.values_mut() {
            if let Some(idx) = dialogs.iter().position(|d| d.plugin_id() == dialog_plugin_id) {
                dialogs.remove(idx);
                return;
            }
        }
    }

    fn clear_table_dialogs(&mut self, program: &str) {
        if let Some(mut dialogs) = self.program_dialogs.remove(program) {
            for dialog in &mut dialogs {
                dialog.close();
            }
        }
    }

    /// Returns all managed dialogs for a specific program.
    pub fn get_dialogs_for_program(&self, program: &str) -> &[TableServiceTableChooserDialog] {
        self.program_dialogs
            .get(program)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    // -- Update management -------------------------------------------------

    /// Notifies the plugin that a domain object has changed.
    ///
    /// This triggers a deferred refresh of all providers.
    pub fn domain_object_changed(&mut self) {
        self.update_pending = true;
    }

    /// Processes pending updates by refreshing all providers.
    ///
    /// Returns the number of providers refreshed.
    pub fn process_update(&mut self) -> usize {
        if !self.update_pending {
            return 0;
        }

        let mut count = 0;
        for providers in self.program_providers.values_mut() {
            for provider in providers.iter_mut() {
                provider.refresh(provider.row_count());
                count += 1;
            }
        }
        self.update_pending = false;
        count
    }

    /// Returns whether an update is pending.
    pub fn is_update_pending(&self) -> bool {
        self.update_pending
    }

    /// Returns the update interval in milliseconds.
    pub fn update_interval_ms(&self) -> u64 {
        self.update_interval_ms
    }

    /// Sets the update interval in milliseconds.
    pub fn set_update_interval_ms(&mut self, ms: u64) {
        self.update_interval_ms = ms;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::traits::AddressableRowObject;
    use ghidra_core::addr::Address;

    #[test]
    fn test_plugin_lifecycle() {
        let mut plugin = TableServicePlugin::new("TableServicePlugin");
        assert_eq!(plugin.state(), PluginState::Initializing);

        plugin.activate();
        assert_eq!(plugin.state(), PluginState::Active);

        plugin.dispose();
        assert_eq!(plugin.state(), PluginState::Disposed);
    }

    #[test]
    fn test_plugin_show_table() {
        let mut plugin = TableServicePlugin::new("TableServicePlugin");
        plugin.activate();

        let id = plugin.show_table("test.exe", "Search Text \"foo\"", "Search Results", None);
        assert!(!id.is_empty());

        let components = plugin.get_managed_components();
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].title(), "Search Text \"foo\"");
        assert_eq!(components[0].name(), "Search Results");
    }

    #[test]
    fn test_plugin_show_table_with_markers() {
        let mut plugin = TableServicePlugin::new("TableServicePlugin");
        plugin.activate();

        let id = plugin.show_table_with_markers(
            "test.exe",
            "Search",
            "Results",
            (255, 0, 0, 255),
            None,
        );
        assert!(!id.is_empty());

        let components = plugin.get_managed_components();
        assert_eq!(components.len(), 1);
        assert!(components[0].marker_set().is_some());
    }

    #[test]
    fn test_plugin_program_closed() {
        let mut plugin = TableServicePlugin::new("TableServicePlugin");
        plugin.activate();

        plugin.show_table("prog1.exe", "T1", "R1", None);
        plugin.show_table("prog2.exe", "T2", "R2", None);
        assert_eq!(plugin.get_managed_components().len(), 2);

        plugin.program_closed("prog1.exe");
        let remaining = plugin.get_managed_components();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].title(), "T2");
    }

    #[test]
    fn test_plugin_dialog_management() {
        let mut plugin = TableServicePlugin::new("TableServicePlugin");
        plugin.activate();

        let _id = plugin.create_table_chooser_dialog("test.exe", "Choose", None, false);
        assert_eq!(plugin.get_dialogs_for_program("test.exe").len(), 1);

        plugin.clear_table_dialogs("test.exe");
        assert_eq!(plugin.get_dialogs_for_program("test.exe").len(), 0);
    }

    struct TestExec;
    impl AddressableRowObject for TestExec {
        fn address(&self) -> Address { Address::new(0) }
    }
    impl TableChooserExecutor for TestExec {
        fn button_name(&self) -> &str { "Go" }
        fn execute(&self, _row: &dyn AddressableRowObject) -> bool { false }
    }

    #[test]
    fn test_plugin_create_dialog_with_executor() {
        let mut plugin = TableServicePlugin::new("TableServicePlugin");
        plugin.activate();

        let executor: Arc<dyn TableChooserExecutor> = Arc::new(TestExec);
        let _id = plugin.create_table_chooser_dialog("test.exe", "Action", Some(executor), true);
        assert_eq!(plugin.get_dialogs_for_program("test.exe").len(), 1);
    }

    #[test]
    fn test_plugin_update() {
        let mut plugin = TableServicePlugin::new("TableServicePlugin");
        plugin.activate();

        plugin.show_table("test.exe", "T", "R", None);
        assert!(!plugin.is_update_pending());

        plugin.domain_object_changed();
        assert!(plugin.is_update_pending());

        let count = plugin.process_update();
        assert_eq!(count, 1);
        assert!(!plugin.is_update_pending());
    }

    #[test]
    fn test_plugin_remove_provider() {
        let mut plugin = TableServicePlugin::new("TableServicePlugin");
        plugin.activate();

        let id = plugin.show_table("test.exe", "T", "R", None);
        assert_eq!(plugin.get_managed_components().len(), 1);

        assert!(plugin.remove_provider(&id));
        assert_eq!(plugin.get_managed_components().len(), 0);

        // Removing non-existent should return false.
        assert!(!plugin.remove_provider("nonexistent"));
    }

    #[test]
    fn test_plugin_providers_for_program() {
        let mut plugin = TableServicePlugin::new("TableServicePlugin");
        plugin.activate();

        plugin.show_table("p1.exe", "T1", "R1", None);
        plugin.show_table("p1.exe", "T2", "R2", None);
        plugin.show_table("p2.exe", "T3", "R3", None);

        assert_eq!(plugin.get_providers_for_program("p1.exe").len(), 2);
        assert_eq!(plugin.get_providers_for_program("p2.exe").len(), 1);
        assert_eq!(plugin.get_providers_for_program("p3.exe").len(), 0);
    }
}
