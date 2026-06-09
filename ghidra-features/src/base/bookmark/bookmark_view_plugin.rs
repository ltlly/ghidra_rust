//! BookmarkView Plugin -- view-specific extension of the bookmark plugin.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.bookmark.BookmarkPlugin`
//! view-related functionality.
//!
//! This module extends [`BookmarkPlugin`] with view-specific behavior
//! including:
//! - Managing the visibility of the bookmark provider
//! - Handling program activation/deactivation for view updates
//! - Coordinating filter dialog display
//! - Managing delete actions with selection awareness
//! - Providing context menu actions for bookmarks
//!
//! # Architecture
//!
//! The BookmarkView plugin acts as a coordinator between:
//! - The bookmark data model ([`BookmarkManager`])
//! - The bookmark provider/view ([`BookmarkProviderModel`])
//! - The bookmark table ([`BookmarkTableModel`])
//! - Navigation markers ([`BookmarkNavigator`])
//!
//! It extends the base plugin with GUI-specific behaviors that are
//! only relevant when a view is active.

use std::collections::HashMap;

use ghidra_core::addr::Address;

use super::commands::{AddressSet, BookmarkCommand, BookmarkDeleteCmd, BookmarkEditCmd};
use super::model::{Bookmark, BookmarkManager};
use super::navigator::BookmarkNavigator;
use super::plugin::{
    BookmarkActionState, BookmarkPlugin, BookmarkPluginState, BookmarkTransientState, CreateBookmarkRequest,
    NavUpdater, PluginStatus, ProgramEvent, TIMER_DELAY, MIN_TIMEOUT, MAX_TIMEOUT,
};
use super::provider::{BookmarkFilterState, BookmarkProviderEntry, BookmarkProviderModel};
use super::table::BookmarkTableModel;
use super::types::BookmarkType;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of delete actions shown in popup menus.
pub const MAX_DELETE_ACTIONS: usize = 10;

// ---------------------------------------------------------------------------
// BookmarkViewPlugin
// ---------------------------------------------------------------------------

/// View-specific extension of the bookmark plugin.
///
/// This struct wraps [`BookmarkPlugin`] and adds view-specific functionality
/// such as managing the provider visibility, handling filter dialogs,
/// and coordinating delete actions with the current selection.
///
/// Ported from the view-related methods in Ghidra's `BookmarkPlugin`.
#[derive(Debug)]
pub struct BookmarkViewPlugin {
    /// The underlying bookmark plugin.
    inner: BookmarkPlugin,
    /// Whether the provider is currently visible.
    provider_visible: bool,
    /// The current program selection (address ranges).
    current_selection: Option<AddressSet>,
    /// Whether the plugin is in the process of loading.
    loading: bool,
}

impl BookmarkViewPlugin {
    /// Creates a new BookmarkViewPlugin.
    pub fn new() -> Self {
        Self {
            inner: BookmarkPlugin::new(),
            provider_visible: false,
            current_selection: None,
            loading: false,
        }
    }

    /// Returns a reference to the inner plugin.
    pub fn inner(&self) -> &BookmarkPlugin {
        &self.inner
    }

    /// Returns a mutable reference to the inner plugin.
    pub fn inner_mut(&mut self) -> &mut BookmarkPlugin {
        &mut self.inner
    }

    // -- Lifecycle ----------------------------------------------------------

    /// Initializes the plugin.
    pub fn init(&mut self) {
        self.inner.init();
    }

    /// Disposes the plugin.
    pub fn dispose(&mut self) {
        self.inner.dispose();
        self.provider_visible = false;
        self.current_selection = None;
    }

    /// Returns the plugin status.
    pub fn status(&self) -> PluginStatus {
        self.inner.status()
    }

    // -- Provider visibility ------------------------------------------------

    /// Returns whether the provider is visible.
    pub fn is_provider_visible(&self) -> bool {
        self.provider_visible
    }

    /// Sets the provider visibility.
    pub fn set_bookmarks_visible(&mut self, visible: bool) {
        self.provider_visible = visible;
        self.inner.set_provider_visible(visible);
    }

    // -- Program lifecycle --------------------------------------------------

    /// Called when a program is activated.
    pub fn program_activated(&mut self, program_name: String, mgr: BookmarkManager) {
        self.loading = true;
        self.inner.program_activated(program_name, mgr);
        self.loading = false;
    }

    /// Called when a program is deactivated.
    pub fn program_deactivated(&mut self) {
        self.inner.program_deactivated();
        self.current_selection = None;
    }

    // -- Program events -----------------------------------------------------

    /// Handles a program event.
    pub fn handle_event(&mut self, event: ProgramEvent, bookmark: Option<Bookmark>) {
        if self.loading {
            return;
        }
        self.inner.handle_event(event, bookmark);
    }

    // -- Actions ------------------------------------------------------------

    /// Shows the add-bookmark dialog at the given address.
    pub fn show_add_bookmark_dialog(&mut self, address: Address) -> CreateBookmarkRequest {
        self.inner.show_add_bookmark_dialog(address)
    }

    /// Sets a note bookmark at the given address (or across selection).
    pub fn set_note(
        &mut self,
        addr: Option<Address>,
        category: &str,
        comment: &str,
    ) -> Vec<Box<dyn BookmarkCommand>> {
        self.inner.set_note(addr, category, comment)
    }

    /// Deletes a bookmark by ID.
    pub fn delete_bookmark(&self, bookmark_id: u64) -> BookmarkDeleteCmd {
        self.inner.delete_bookmark(bookmark_id)
    }

    /// Deletes bookmarks from the selected rows.
    ///
    /// This corresponds to the `delete()` method in `BookmarkProvider`.
    pub fn delete_selected(&self, bookmark_ids: &[u64]) -> Vec<BookmarkDeleteCmd> {
        bookmark_ids
            .iter()
            .map(|&id| BookmarkDeleteCmd::by_id(id))
            .collect()
    }

    /// Filters bookmarks by showing/hiding types.
    pub fn filter_bookmarks(&mut self, visible_types: Vec<String>) {
        self.inner.filter_bookmarks(visible_types);
    }

    // -- Selection ----------------------------------------------------------

    /// Sets the current program selection.
    pub fn set_current_selection(&mut self, selection: Option<AddressSet>) {
        self.current_selection = selection;
    }

    /// Returns the current program selection.
    pub fn current_selection(&self) -> Option<&AddressSet> {
        self.current_selection.as_ref()
    }

    // -- Accessors ----------------------------------------------------------

    /// Returns a reference to the table model.
    pub fn table_model(&self) -> &BookmarkTableModel {
        self.inner.table_model()
    }

    /// Returns a mutable reference to the table model.
    pub fn table_model_mut(&mut self) -> &mut BookmarkTableModel {
        self.inner.table_model_mut()
    }

    /// Returns a reference to the provider model.
    pub fn provider_model(&self) -> &BookmarkProviderModel {
        self.inner.provider_model()
    }

    /// Returns a mutable reference to the provider model.
    pub fn provider_model_mut(&mut self) -> &mut BookmarkProviderModel {
        self.inner.provider_model_mut()
    }

    /// Returns a reference to the bookmark manager.
    pub fn bookmark_manager(&self) -> Option<&BookmarkManager> {
        self.inner.bookmark_manager()
    }

    /// Returns a mutable reference to the bookmark manager.
    pub fn bookmark_manager_mut(&mut self) -> Option<&mut BookmarkManager> {
        self.inner.bookmark_manager_mut()
    }

    /// Returns the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.inner.current_program()
    }

    // -- Save/Restore -------------------------------------------------------

    /// Saves plugin configuration state.
    pub fn save_config_state(&self) -> BookmarkPluginState {
        self.inner.save_config_state()
    }

    /// Restores plugin configuration state.
    pub fn restore_config_state(&mut self, state: &BookmarkPluginState) {
        self.inner.restore_config_state(state);
    }

    /// Gets the transient state (filter state for cross-program persistence).
    pub fn get_transient_state(&self) -> BookmarkTransientState {
        self.inner.get_transient_state()
    }

    /// Restores the transient state.
    pub fn restore_transient_state(&mut self, state: &BookmarkTransientState) {
        self.inner.restore_transient_state(state);
    }

    // -- Reload -------------------------------------------------------------

    /// Reloads all bookmark data.
    pub fn reload(&mut self) {
        self.inner.reload();
    }
}

impl Default for BookmarkViewPlugin {
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

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn make_plugin_with_program() -> BookmarkViewPlugin {
        let mut plugin = BookmarkViewPlugin::new();
        plugin.init();

        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(&addr(0x1000), "Note", "Cat1", "First");
        mgr.set_bookmark(&addr(0x2000), "Warning", "", "Watch out");
        mgr.set_bookmark(&addr(0x3000), "Note", "Cat2", "Third");
        mgr.set_bookmark(&addr(0x4000), "Error", "Bug", "Crash");

        plugin.program_activated("test.exe".into(), mgr);
        plugin
    }

    // ====================================================================
    // BookmarkViewPlugin lifecycle
    // ====================================================================

    #[test]
    fn test_view_plugin_new() {
        let plugin = BookmarkViewPlugin::new();
        assert_eq!(plugin.status(), PluginStatus::Uninitialized);
        assert!(plugin.current_program().is_none());
        assert!(plugin.bookmark_manager().is_none());
        assert!(!plugin.is_provider_visible());
    }

    #[test]
    fn test_view_plugin_init() {
        let mut plugin = BookmarkViewPlugin::new();
        plugin.init();
        assert_eq!(plugin.status(), PluginStatus::Active);
    }

    #[test]
    fn test_view_plugin_dispose() {
        let mut plugin = make_plugin_with_program();
        plugin.dispose();
        assert_eq!(plugin.status(), PluginStatus::Disposed);
        assert!(plugin.current_program().is_none());
        assert!(plugin.bookmark_manager().is_none());
        assert!(!plugin.is_provider_visible());
    }

    // ====================================================================
    // Provider visibility
    // ====================================================================

    #[test]
    fn test_provider_visibility() {
        let mut plugin = BookmarkViewPlugin::new();
        assert!(!plugin.is_provider_visible());
        plugin.set_bookmarks_visible(true);
        assert!(plugin.is_provider_visible());
        plugin.set_bookmarks_visible(false);
        assert!(!plugin.is_provider_visible());
    }

    // ====================================================================
    // Program lifecycle
    // ====================================================================

    #[test]
    fn test_program_activated() {
        let plugin = make_plugin_with_program();
        assert_eq!(plugin.current_program(), Some("test.exe"));
        assert!(plugin.bookmark_manager().is_some());
        assert_eq!(
            plugin.bookmark_manager().unwrap().get_bookmark_count(),
            4
        );
    }

    #[test]
    fn test_program_deactivated() {
        let mut plugin = make_plugin_with_program();
        plugin.program_deactivated();
        assert!(plugin.current_program().is_none());
        assert!(plugin.bookmark_manager().is_none());
    }

    // ====================================================================
    // Actions
    // ====================================================================

    #[test]
    fn test_show_add_bookmark_dialog() {
        let mut plugin = make_plugin_with_program();
        let req = plugin.show_add_bookmark_dialog(addr(0x1000));
        assert_eq!(req.address, addr(0x1000));
    }

    #[test]
    fn test_set_note() {
        let mut plugin = make_plugin_with_program();
        let cmds = plugin.set_note(Some(addr(0x5000)), "Todo", "Fix this");
        assert_eq!(cmds.len(), 2); // delete + edit
    }

    #[test]
    fn test_delete_bookmark() {
        let plugin = make_plugin_with_program();
        let cmd = plugin.delete_bookmark(1);
        assert_eq!(cmd.name(), "Delete Bookmark");
    }

    #[test]
    fn test_delete_selected() {
        let plugin = make_plugin_with_program();
        let cmds = plugin.delete_selected(&[1, 2, 3]);
        assert_eq!(cmds.len(), 3);
    }

    #[test]
    fn test_filter_bookmarks() {
        let mut plugin = make_plugin_with_program();
        plugin.filter_bookmarks(vec!["Note".to_string()]);
    }

    // ====================================================================
    // Selection
    // ====================================================================

    #[test]
    fn test_selection_none_by_default() {
        let plugin = BookmarkViewPlugin::new();
        assert!(plugin.current_selection().is_none());
    }

    #[test]
    fn test_set_selection() {
        let mut plugin = BookmarkViewPlugin::new();
        let mut addrs = AddressSet::new();
        addrs.add_range(addr(0x1000), addr(0x2000));
        plugin.set_current_selection(Some(addrs));
        assert!(plugin.current_selection().is_some());
    }

    // ====================================================================
    // Save/Restore
    // ====================================================================

    #[test]
    fn test_save_restore_config_state() {
        let mut plugin = make_plugin_with_program();
        let state = plugin.save_config_state();
        assert!(!state.filter_types.is_empty());

        let mut plugin2 = BookmarkViewPlugin::new();
        plugin2.init();
        plugin2.restore_config_state(&state);
    }

    #[test]
    fn test_transient_state_roundtrip() {
        let mut plugin = make_plugin_with_program();
        let state = plugin.get_transient_state();

        let mut plugin2 = BookmarkViewPlugin::new();
        plugin2.init();
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(&addr(0x1000), "Note", "", "test");
        plugin2.program_activated("test.exe".into(), mgr);
        plugin2.restore_transient_state(&state);
    }

    // ====================================================================
    // Reload
    // ====================================================================

    #[test]
    fn test_reload() {
        let mut plugin = make_plugin_with_program();
        plugin.reload();
        // Should not crash.
    }

    // ====================================================================
    // Event handling
    // ====================================================================

    #[test]
    fn test_handle_bookmark_added() {
        let mut plugin = make_plugin_with_program();
        let bm = Bookmark::new(99, addr(0x5000), "Note", "", "New");
        plugin.bookmark_manager_mut().unwrap().add_bookmark(bm.clone());
        plugin.handle_event(ProgramEvent::BookmarkAdded, Some(bm));
        assert_eq!(
            plugin.bookmark_manager().unwrap().get_bookmark_count(),
            5
        );
    }

    #[test]
    fn test_handle_bookmark_removed() {
        let mut plugin = make_plugin_with_program();
        let bm = plugin
            .bookmark_manager()
            .unwrap()
            .get_bookmark(1)
            .unwrap()
            .clone();
        plugin.handle_event(ProgramEvent::BookmarkRemoved, Some(bm));
    }

    #[test]
    fn test_handle_restored() {
        let mut plugin = make_plugin_with_program();
        plugin.handle_event(ProgramEvent::Restored, None);
    }

    // ====================================================================
    // Default
    // ====================================================================

    #[test]
    fn test_default() {
        let plugin = BookmarkViewPlugin::default();
        assert_eq!(plugin.status(), PluginStatus::Uninitialized);
    }
}
