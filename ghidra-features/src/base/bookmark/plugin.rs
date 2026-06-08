//! Bookmark Plugin -- top-level plugin coordinating bookmark management.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.bookmark.BookmarkPlugin`.
//!
//! Manages the lifecycle of the bookmark provider, handles program events
//! (bookmark added/changed/removed, program activated/deactivated),
//! dispatches bookmark actions (add, delete, filter), and maintains
//! bookmark navigators for marker margin display.
//!
//! # Key Types
//!
//! - [`BookmarkPlugin`] -- Plugin that owns the bookmark provider and navigators
//! - [`BookmarkPluginState`] -- Persisted configuration
//! - [`NavUpdater`] -- Deferred marker update scheduler

use std::collections::{HashMap, HashSet};
use std::fmt;

use ghidra_core::addr::Address;

use super::commands::{AddressSet, BookmarkCommand, BookmarkDeleteCmd, BookmarkEditCmd};
use super::model::{Bookmark, BookmarkManager};
use super::navigator::BookmarkNavigator;
use super::provider::{BookmarkFilterState, BookmarkProviderModel};
use super::table::BookmarkTableModel;
use super::types::BookmarkType;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default timer delay for repaint manager (ms).
pub const TIMER_DELAY: u64 = 500;

/// Minimum timeout for nav updater (ms).
pub const MIN_TIMEOUT: u64 = 1000;

/// Maximum timeout for nav updater (ms).
pub const MAX_TIMEOUT: u64 = 1000 * 60 * 20;

// ---------------------------------------------------------------------------
// ProgramEvent -- events from the domain object
// ---------------------------------------------------------------------------

/// Events that the bookmark plugin subscribes to from the program.
///
/// Corresponds to Ghidra's `ProgramEvent` enum values used in
/// `BookmarkPlugin.createDomainObjectListener()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramEvent {
    /// The program was restored from disk.
    Restored,
    /// A memory block was moved.
    MemoryBlockMoved,
    /// A memory block was removed.
    MemoryBlockRemoved,
    /// A bookmark was added.
    BookmarkAdded,
    /// A bookmark was changed.
    BookmarkChanged,
    /// A bookmark was removed.
    BookmarkRemoved,
    /// A bookmark type was added.
    BookmarkTypeAdded,
    /// A bookmark type was removed.
    BookmarkTypeRemoved,
}

// ---------------------------------------------------------------------------
// PluginStatus -- plugin lifecycle states
// ---------------------------------------------------------------------------

/// Lifecycle state of the bookmark plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PluginStatus {
    /// Plugin is uninitialized.
    Uninitialized,
    /// Plugin is active and processing events.
    Active,
    /// Plugin has been disposed.
    Disposed,
}

// ---------------------------------------------------------------------------
// BookmarkTransientState -- filter state for tool save/restore
// ---------------------------------------------------------------------------

/// Transient state for the bookmark plugin, preserved across program switches.
///
/// Corresponds to Ghidra's `BookmarkPlugin.BookmarkTransientState`.
#[derive(Debug, Clone)]
pub struct BookmarkTransientState {
    /// The filter state to preserve.
    pub filter_state: BookmarkFilterState,
}

impl BookmarkTransientState {
    /// Creates a new transient state from the given filter state.
    pub fn new(filter_state: BookmarkFilterState) -> Self {
        Self { filter_state }
    }
}

// ---------------------------------------------------------------------------
// NavUpdater -- deferred marker update scheduler
// ---------------------------------------------------------------------------

/// Schedules deferred updates to bookmark marker sets.
///
/// Corresponds to Ghidra's inner `NavUpdater` class. When bookmarks
/// change, the updater collects the affected type strings and, after a
/// debounce delay, rebuilds the marker sets for those types.
#[derive(Debug)]
pub struct NavUpdater {
    /// Set of type strings that need marker updates.
    pending_types: HashSet<String>,
    /// Whether an update is currently running.
    running: bool,
    /// The program name this updater is tracking (if any).
    program: Option<String>,
    /// Minimum debounce interval in milliseconds.
    min_timeout: u64,
    /// Maximum debounce interval in milliseconds.
    max_timeout: u64,
}

impl NavUpdater {
    /// Creates a new NavUpdater with default timeouts.
    pub fn new() -> Self {
        Self {
            pending_types: HashSet::new(),
            running: false,
            program: None,
            min_timeout: MIN_TIMEOUT,
            max_timeout: MAX_TIMEOUT,
        }
    }

    /// Adds a type string for pending update.
    ///
    /// If `type_string` is `None`, all known types are queued.
    pub fn add_type(&mut self, type_string: Option<&str>, all_types: &[String]) {
        if let Some(ts) = type_string {
            self.pending_types.insert(ts.to_string());
        } else {
            for t in all_types {
                self.pending_types.insert(t.clone());
            }
        }
    }

    /// Returns the set of pending type strings.
    pub fn pending_types(&self) -> &HashSet<String> {
        &self.pending_types
    }

    /// Takes the pending types, leaving the set empty.
    pub fn take_pending_types(&mut self) -> HashSet<String> {
        std::mem::take(&mut self.pending_types)
    }

    /// Returns true if an update is currently running.
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Sets the running flag.
    pub fn set_running(&mut self, running: bool) {
        self.running = running;
    }

    /// Sets the program this updater tracks.
    pub fn set_program(&mut self, program: Option<String>) {
        self.program = program;
        self.pending_types.clear();
    }

    /// Returns the program name, if any.
    pub fn program(&self) -> Option<&str> {
        self.program.as_deref()
    }

    /// Returns true if there are pending types to update.
    pub fn has_pending(&self) -> bool {
        !self.pending_types.is_empty()
    }
}

impl Default for NavUpdater {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// BookmarkPlugin
// ---------------------------------------------------------------------------

/// Plugin for adding, deleting, editing, and showing bookmarks.
///
/// Ported from Ghidra's `BookmarkPlugin`. This plugin:
/// - Creates and manages the [`BookmarkProvider`] (table panel)
/// - Handles program activation/deactivation events
/// - Dispatches bookmark add/edit/delete commands
/// - Maintains [`BookmarkNavigator`] instances for marker display
/// - Persists filter state across tool save/restore
///
/// # Architecture
///
/// The plugin owns the data model ([`BookmarkManager`]), the display
/// provider ([`BookmarkProviderModel`], [`BookmarkTableModel`]), and
/// the marker navigators ([`BookmarkNavigator`]). Program events flow
/// through the plugin to update all these components.
#[derive(Debug)]
pub struct BookmarkPlugin {
    /// The bookmark table model.
    table_model: BookmarkTableModel,
    /// The provider data model.
    provider_model: BookmarkProviderModel,
    /// Bookmark navigators keyed by type string.
    navigators: HashMap<String, BookmarkNavigator>,
    /// The bookmark manager for the current program.
    bookmark_manager: Option<BookmarkManager>,
    /// The deferred marker update scheduler.
    nav_updater: NavUpdater,
    /// Current program name (if any).
    current_program: Option<String>,
    /// The add-bookmark action.
    add_action: BookmarkActionState,
    /// The delete-bookmark action.
    delete_action: BookmarkActionState,
    /// The filter action.
    filter_action: BookmarkActionState,
    /// Plugin lifecycle status.
    status: PluginStatus,
    /// Whether the provider is currently visible.
    provider_visible: bool,
}

/// State of a single bookmark action.
#[derive(Debug, Clone)]
pub struct BookmarkActionState {
    /// Action name.
    pub name: String,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// Action description.
    pub description: String,
}

impl BookmarkActionState {
    /// Creates a new action state.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            enabled: false,
        }
    }
}

impl BookmarkPlugin {
    /// Creates a new BookmarkPlugin.
    pub fn new() -> Self {
        let add_action = BookmarkActionState::new("Add Bookmark", "Add Notes bookmark to current location");
        let delete_action = BookmarkActionState::new("Delete Bookmarks", "Delete Selected Bookmarks");
        let filter_action = BookmarkActionState::new("Filter Bookmarks", "Adjust Filters");

        Self {
            table_model: BookmarkTableModel::new(),
            provider_model: BookmarkProviderModel::new(),
            navigators: HashMap::new(),
            bookmark_manager: None,
            nav_updater: NavUpdater::new(),
            current_program: None,
            add_action,
            delete_action,
            filter_action,
            status: PluginStatus::Uninitialized,
            provider_visible: false,
        }
    }

    // -- Lifecycle ----------------------------------------------------------

    /// Initializes the plugin (called after services are available).
    ///
    /// Corresponds to Ghidra's `BookmarkPlugin.init()`.
    pub fn init(&mut self) {
        self.status = PluginStatus::Active;
        self.add_action.enabled = true;
        self.delete_action.enabled = true;
    }

    /// Disposes the plugin, releasing all resources.
    ///
    /// Corresponds to Ghidra's `BookmarkPlugin.dispose()`.
    pub fn dispose(&mut self) {
        self.navigators.clear();
        self.bookmark_manager = None;
        self.current_program = None;
        self.status = PluginStatus::Disposed;
    }

    /// Returns the plugin status.
    pub fn status(&self) -> PluginStatus {
        self.status
    }

    // -- Program lifecycle --------------------------------------------------

    /// Called when a program is activated.
    ///
    /// Corresponds to Ghidra's `BookmarkPlugin.programActivated(Program)`.
    pub fn program_activated(&mut self, program_name: String, mut mgr: BookmarkManager) {
        // Define built-in bookmark types.
        BookmarkNavigator::define_bookmark_types(&mut mgr);

        // Initialize table model.
        self.table_model.initialize(&mgr);
        self.table_model.load(&mgr);

        // Initialize provider model.
        self.provider_model.populate(&mgr);

        // Store the manager, then create navigators (which clone the manager).
        self.bookmark_manager = Some(mgr);
        let types: Vec<BookmarkType> = self
            .bookmark_manager
            .as_ref()
            .unwrap()
            .get_bookmark_types()
            .into_iter()
            .cloned()
            .collect();
        for bmt in &types {
            self.ensure_navigator(bmt);
        }

        // Update marker sets from the manager.
        for nav in self.navigators.values_mut() {
            nav.update_markers();
        }

        self.nav_updater
            .set_program(Some(program_name.clone()));
        self.current_program = Some(program_name);
    }

    /// Called when a program is deactivated.
    ///
    /// Corresponds to Ghidra's `BookmarkPlugin.programDeactivated(Program)`.
    pub fn program_deactivated(&mut self) {
        self.nav_updater.set_program(None);
        self.navigators.clear();
        self.bookmark_manager = None;
        self.current_program = None;
    }

    // -- Program events -----------------------------------------------------

    /// Handles a program event.
    ///
    /// Corresponds to the `DomainObjectListener` in `BookmarkPlugin`.
    pub fn handle_event(&mut self, event: ProgramEvent, bookmark: Option<Bookmark>) {
        match event {
            ProgramEvent::Restored
            | ProgramEvent::MemoryBlockMoved
            | ProgramEvent::MemoryBlockRemoved => {
                self.reload();
            }
            ProgramEvent::BookmarkTypeRemoved => {
                // Trigger repaint.
            }
            ProgramEvent::BookmarkAdded => {
                if let Some(bm) = bookmark {
                    self.bookmark_added(bm);
                } else {
                    self.reload();
                }
            }
            ProgramEvent::BookmarkChanged => {
                if let Some(bm) = bookmark {
                    self.bookmark_changed(bm);
                } else {
                    self.reload();
                }
            }
            ProgramEvent::BookmarkRemoved => {
                if let Some(bm) = bookmark {
                    self.bookmark_removed(bm);
                } else {
                    self.reload();
                }
            }
            ProgramEvent::BookmarkTypeAdded => {
                if let Some(bm) = bookmark {
                    self.type_added(bm.type_string().to_string());
                }
            }
        }
    }

    fn bookmark_added(&mut self, bookmark: Bookmark) {
        let type_string = bookmark.type_string().to_string();

        // Ensure navigator exists (clone type info before borrowing self).
        let bmt_info = self
            .bookmark_manager
            .as_ref()
            .and_then(|mgr| mgr.get_bookmark_type(&type_string).cloned());

        if let Some(bmt) = bmt_info {
            self.ensure_navigator(&bmt);
            if let Some(nav) = self.navigators.get_mut(&type_string) {
                nav.add(bookmark.address());
            }
        }

        // Update models.
        if let Some(mgr) = &self.bookmark_manager {
            let id = bookmark.id();
            self.provider_model.populate(mgr);
            self.table_model.bookmark_added(mgr, id);
        }

        self.schedule_update(Some(&type_string));
    }

    fn bookmark_changed(&mut self, bookmark: Bookmark) {
        let type_string = bookmark.type_string().to_string();

        // Ensure navigator exists.
        let bmt_info = self
            .bookmark_manager
            .as_ref()
            .and_then(|mgr| mgr.get_bookmark_type(&type_string).cloned());

        if let Some(bmt) = bmt_info {
            self.ensure_navigator(&bmt);
            if let Some(nav) = self.navigators.get_mut(&type_string) {
                nav.add(bookmark.address());
            }
        }

        // Update models.
        if let Some(mgr) = &self.bookmark_manager {
            let id = bookmark.id();
            self.provider_model.populate(mgr);
            self.table_model.bookmark_changed(mgr, id);
        }

        self.schedule_update(Some(&type_string));
    }

    fn bookmark_removed(&mut self, bookmark: Bookmark) {
        let type_string = bookmark.type_string().to_string();

        // Update navigator (check if any bookmarks remain at this address).
        let has_remaining = self
            .bookmark_manager
            .as_ref()
            .map_or(false, |mgr| {
                !mgr.get_bookmarks_by_type(bookmark.address(), &type_string).is_empty()
            });

        if !has_remaining {
            if let Some(nav) = self.navigators.get_mut(&type_string) {
                nav.clear(bookmark.address());
            }
        }

        // Update models.
        if let Some(mgr) = &self.bookmark_manager {
            let id = bookmark.id();
            self.provider_model.populate(mgr);
            self.table_model.bookmark_removed(mgr, id);
        }

        self.schedule_update(Some(&type_string));
    }

    fn type_added(&mut self, type_string: String) {
        // Get type info before mutable borrows.
        let bmt_info = self
            .bookmark_manager
            .as_ref()
            .and_then(|mgr| mgr.get_bookmark_type(&type_string).cloned());

        if let Some(bmt) = bmt_info {
            self.ensure_navigator(&bmt);
        }

        self.table_model.type_added(&type_string);
        self.schedule_update(Some(&type_string));
    }

    /// Ensures a navigator exists for the given bookmark type.
    ///
    /// Clones the BookmarkManager if a new navigator needs to be created.
    fn ensure_navigator(&mut self, bmt: &BookmarkType) {
        let type_string = bmt.type_string().to_string();
        if self.navigators.contains_key(&type_string) {
            return;
        }
        if let Some(mgr) = &self.bookmark_manager {
            let nav = BookmarkNavigator::new(mgr.clone(), bmt);
            self.navigators.insert(type_string, nav);
        }
    }

    /// Reloads all bookmark data from the manager.
    ///
    /// Corresponds to Ghidra's `BookmarkPlugin.reload()`.
    pub fn reload(&mut self) {
        self.schedule_update(None);
        if let Some(mgr) = &self.bookmark_manager {
            self.provider_model.populate(mgr);
            self.table_model.load(mgr);
        }
    }

    // -- Actions ------------------------------------------------------------

    /// Shows the add-bookmark dialog at the given address.
    ///
    /// Corresponds to Ghidra's `BookmarkPlugin.showAddBookmarkDialog()`.
    pub fn show_add_bookmark_dialog(&mut self, address: Address) -> CreateBookmarkRequest {
        CreateBookmarkRequest {
            address,
            has_selection: false,
        }
    }

    /// Sets a note bookmark at the given address (or across selection).
    ///
    /// Corresponds to Ghidra's `BookmarkPlugin.setNote()`.
    pub fn set_note(
        &mut self,
        addr: Option<Address>,
        category: &str,
        comment: &str,
    ) -> Vec<Box<dyn BookmarkCommand>> {
        if let Some(address) = addr {
            // Single address: delete existing note, then add new one.
            vec![
                Box::new(BookmarkDeleteCmd::at_address_by_type(address, BookmarkType::NOTE)) as Box<dyn BookmarkCommand>,
                Box::new(BookmarkEditCmd::at_address(address, BookmarkType::NOTE, category, comment)) as Box<dyn BookmarkCommand>,
            ]
        } else {
            // Would operate on current selection ranges; return empty for now.
            Vec::new()
        }
    }

    /// Deletes a bookmark by ID.
    ///
    /// Corresponds to Ghidra's `BookmarkPlugin.deleteBookmark()`.
    pub fn delete_bookmark(&self, bookmark_id: u64) -> BookmarkDeleteCmd {
        BookmarkDeleteCmd::by_id(bookmark_id)
    }

    /// Filters bookmarks by showing/hiding types.
    ///
    /// Corresponds to Ghidra's `BookmarkPlugin.filterBookmarks()`.
    pub fn filter_bookmarks(&mut self, visible_types: Vec<String>) {
        let filter = BookmarkFilterState::with_types(visible_types);
        self.provider_model.set_filter(filter);
    }

    // -- Navigator management -----------------------------------------------

    /// Schedules a deferred marker update for the given type.
    fn schedule_update(&mut self, type_string: Option<&str>) {
        let all_types: Vec<String> = self
            .navigators
            .keys()
            .cloned()
            .collect();
        self.nav_updater.add_type(type_string, &all_types);
    }

    /// Processes pending nav updates.
    ///
    /// This would be called by a timer in the real GUI; here it is
    /// exposed for manual invocation.
    pub fn process_nav_updates(&mut self) {
        let pending = self.nav_updater.take_pending_types();
        if pending.is_empty() {
            return;
        }

        for type_string in &pending {
            if let Some(nav) = self.navigators.get_mut(type_string) {
                nav.update_markers();
            }
        }
    }

    // -- Accessors ----------------------------------------------------------

    /// Returns a reference to the table model.
    pub fn table_model(&self) -> &BookmarkTableModel {
        &self.table_model
    }

    /// Returns a mutable reference to the table model.
    pub fn table_model_mut(&mut self) -> &mut BookmarkTableModel {
        &mut self.table_model
    }

    /// Returns a reference to the provider model.
    pub fn provider_model(&self) -> &BookmarkProviderModel {
        &self.provider_model
    }

    /// Returns a mutable reference to the provider model.
    pub fn provider_model_mut(&mut self) -> &mut BookmarkProviderModel {
        &mut self.provider_model
    }

    /// Returns a reference to the bookmark manager.
    pub fn bookmark_manager(&self) -> Option<&BookmarkManager> {
        self.bookmark_manager.as_ref()
    }

    /// Returns a mutable reference to the bookmark manager.
    pub fn bookmark_manager_mut(&mut self) -> Option<&mut BookmarkManager> {
        self.bookmark_manager.as_mut()
    }

    /// Returns a reference to the navigator for the given type.
    pub fn navigator(&self, type_string: &str) -> Option<&BookmarkNavigator> {
        self.navigators.get(type_string)
    }

    /// Returns the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Returns whether the provider is visible.
    pub fn is_provider_visible(&self) -> bool {
        self.provider_visible
    }

    /// Sets the provider visibility.
    pub fn set_provider_visible(&mut self, visible: bool) {
        self.provider_visible = visible;
    }

    /// Returns a reference to the add action.
    pub fn add_action(&self) -> &BookmarkActionState {
        &self.add_action
    }

    /// Returns a reference to the delete action.
    pub fn delete_action(&self) -> &BookmarkActionState {
        &self.delete_action
    }

    /// Returns a reference to the filter action.
    pub fn filter_action(&self) -> &BookmarkActionState {
        &self.filter_action
    }

    /// Returns all navigator type strings.
    pub fn navigator_types(&self) -> Vec<&str> {
        self.navigators.keys().map(|s| s.as_str()).collect()
    }

    // -- Save/Restore -------------------------------------------------------

    /// Saves plugin configuration state.
    pub fn save_config_state(&self) -> BookmarkPluginState {
        BookmarkPluginState {
            filter_types: self
                .table_model
                .get_active_types()
                .iter()
                .cloned()
                .collect(),
        }
    }

    /// Restores plugin configuration state.
    pub fn restore_config_state(&mut self, state: &BookmarkPluginState) {
        if !state.filter_types.is_empty() {
            for ts in &state.filter_types {
                self.table_model.show_type(ts);
            }
        }
    }

    /// Gets the transient state (filter state for cross-program persistence).
    pub fn get_transient_state(&self) -> BookmarkTransientState {
        BookmarkTransientState::new(self.table_model.get_filter_state().into())
    }

    /// Restores the transient state.
    pub fn restore_transient_state(&mut self, state: &BookmarkTransientState) {
        let fs = super::model::FilterState::new(
            state.filter_state.visible_types().clone(),
        );
        self.table_model.restore_filter_state(&fs);
        self.reload();
    }
}

impl Default for BookmarkPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CreateBookmarkRequest -- dialog request data
// ---------------------------------------------------------------------------

/// Data needed to show the create-bookmark dialog.
///
/// This is a simplified version of what the Java dialog receives.
#[derive(Debug, Clone)]
pub struct CreateBookmarkRequest {
    /// The address to bookmark.
    pub address: Address,
    /// Whether there is a current selection.
    pub has_selection: bool,
}

// ---------------------------------------------------------------------------
// BookmarkPluginState -- persisted configuration
// ---------------------------------------------------------------------------

/// Persisted state for the bookmark plugin.
///
/// Ported from `BookmarkPlugin.readConfigState()` / `writeConfigState()`.
#[derive(Debug, Clone)]
pub struct BookmarkPluginState {
    /// The set of visible bookmark type strings.
    pub filter_types: Vec<String>,
}

impl Default for BookmarkPluginState {
    fn default() -> Self {
        Self {
            filter_types: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// FilterState conversion
// ---------------------------------------------------------------------------

impl From<super::model::FilterState> for BookmarkFilterState {
    fn from(fs: super::model::FilterState) -> Self {
        BookmarkFilterState::with_types(fs.bookmark_types().iter().cloned())
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

    fn make_plugin_with_program() -> BookmarkPlugin {
        let mut plugin = BookmarkPlugin::new();
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
    // BookmarkPlugin lifecycle
    // ====================================================================

    #[test]
    fn test_plugin_new() {
        let plugin = BookmarkPlugin::new();
        assert_eq!(plugin.status(), PluginStatus::Uninitialized);
        assert!(plugin.current_program().is_none());
        assert!(plugin.bookmark_manager().is_none());
    }

    #[test]
    fn test_plugin_init() {
        let mut plugin = BookmarkPlugin::new();
        plugin.init();
        assert_eq!(plugin.status(), PluginStatus::Active);
        assert!(plugin.add_action().enabled);
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = make_plugin_with_program();
        plugin.dispose();
        assert_eq!(plugin.status(), PluginStatus::Disposed);
        assert!(plugin.current_program().is_none());
        assert!(plugin.bookmark_manager().is_none());
    }

    #[test]
    fn test_plugin_program_activated() {
        let plugin = make_plugin_with_program();
        assert_eq!(plugin.current_program(), Some("test.exe"));
        assert!(plugin.bookmark_manager().is_some());
        assert_eq!(
            plugin.bookmark_manager().unwrap().get_bookmark_count(),
            4
        );
    }

    #[test]
    fn test_plugin_program_deactivated() {
        let mut plugin = make_plugin_with_program();
        plugin.program_deactivated();
        assert!(plugin.current_program().is_none());
        assert!(plugin.bookmark_manager().is_none());
    }

    // ====================================================================
    // Navigator management
    // ====================================================================

    #[test]
    fn test_navigators_created_on_activation() {
        let plugin = make_plugin_with_program();
        // Built-in types should have navigators.
        assert!(plugin.navigator("Note").is_some());
        assert!(plugin.navigator("Warning").is_some());
        assert!(plugin.navigator("Error").is_some());
    }

    #[test]
    fn test_navigator_types() {
        let plugin = make_plugin_with_program();
        let types = plugin.navigator_types();
        assert!(types.contains(&"Note"));
        assert!(types.contains(&"Warning"));
    }

    // ====================================================================
    // Event handling
    // ====================================================================

    #[test]
    fn test_handle_bookmark_added() {
        let mut plugin = make_plugin_with_program();
        let bm = Bookmark::new(99, addr(0x5000), "Note", "", "New");
        // Add bookmark to manager first (simulating external addition)
        plugin.bookmark_manager_mut().unwrap().add_bookmark(bm.clone());
        plugin.handle_event(ProgramEvent::BookmarkAdded, Some(bm));
        assert_eq!(
            plugin.bookmark_manager().unwrap().get_bookmark_count(),
            5
        );
    }

    #[test]
    fn test_handle_bookmark_changed() {
        let mut plugin = make_plugin_with_program();
        let bm = plugin
            .bookmark_manager()
            .unwrap()
            .get_bookmark(1)
            .unwrap()
            .clone();
        plugin.handle_event(ProgramEvent::BookmarkChanged, Some(bm));
        // Should not crash.
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
        // Should not crash; triggers reload.
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
    fn test_set_note_single_address() {
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
    fn test_filter_bookmarks() {
        let mut plugin = make_plugin_with_program();
        plugin.filter_bookmarks(vec!["Note".to_string()]);
        // After filtering, only Note bookmarks should be visible in provider model.
    }

    // ====================================================================
    // Save/Restore
    // ====================================================================

    #[test]
    fn test_save_restore_config_state() {
        let mut plugin = make_plugin_with_program();
        let state = plugin.save_config_state();
        assert!(!state.filter_types.is_empty());

        let mut plugin2 = BookmarkPlugin::new();
        plugin2.init();
        plugin2.restore_config_state(&state);
    }

    #[test]
    fn test_transient_state_roundtrip() {
        let mut plugin = make_plugin_with_program();
        let state = plugin.get_transient_state();

        let mut plugin2 = BookmarkPlugin::new();
        plugin2.init();
        let mut mgr = BookmarkManager::new();
        mgr.set_bookmark(&addr(0x1000), "Note", "", "test");
        plugin2.program_activated("test.exe".into(), mgr);
        plugin2.restore_transient_state(&state);
    }

    // ====================================================================
    // NavUpdater
    // ====================================================================

    #[test]
    fn test_nav_updater_new() {
        let updater = NavUpdater::new();
        assert!(!updater.is_running());
        assert!(!updater.has_pending());
        assert!(updater.program().is_none());
    }

    #[test]
    fn test_nav_updater_add_type() {
        let mut updater = NavUpdater::new();
        updater.add_type(Some("Note"), &[]);
        assert!(updater.has_pending());
        assert!(updater.pending_types().contains("Note"));
    }

    #[test]
    fn test_nav_updater_add_all_types() {
        let mut updater = NavUpdater::new();
        let all = vec!["Note".to_string(), "Warning".to_string()];
        updater.add_type(None, &all);
        assert_eq!(updater.pending_types().len(), 2);
    }

    #[test]
    fn test_nav_updater_take_pending() {
        let mut updater = NavUpdater::new();
        updater.add_type(Some("Note"), &[]);
        let taken = updater.take_pending_types();
        assert!(taken.contains("Note"));
        assert!(!updater.has_pending());
    }

    #[test]
    fn test_nav_updater_set_program() {
        let mut updater = NavUpdater::new();
        updater.add_type(Some("Note"), &[]);
        updater.set_program(Some("test.exe".into()));
        assert_eq!(updater.program(), Some("test.exe"));
        assert!(!updater.has_pending());
    }

    // ====================================================================
    // BookmarkTransientState
    // ====================================================================

    #[test]
    fn test_transient_state_new() {
        let filter = BookmarkFilterState::with_types(["Note"]);
        let state = BookmarkTransientState::new(filter);
        assert!(state.filter_state.is_visible("Note"));
    }

    // ====================================================================
    // BookmarkPluginState
    // ====================================================================

    #[test]
    fn test_plugin_state_default() {
        let state = BookmarkPluginState::default();
        assert!(state.filter_types.is_empty());
    }

    // ====================================================================
    // BookmarkActionState
    // ====================================================================

    #[test]
    fn test_action_state_new() {
        let action = BookmarkActionState::new("Test", "Description");
        assert_eq!(action.name, "Test");
        assert_eq!(action.description, "Description");
        assert!(!action.enabled);
    }

    // ====================================================================
    // Provider visibility
    // ====================================================================

    #[test]
    fn test_provider_visibility() {
        let mut plugin = BookmarkPlugin::new();
        assert!(!plugin.is_provider_visible());
        plugin.set_provider_visible(true);
        assert!(plugin.is_provider_visible());
    }

    // ====================================================================
    // Process nav updates
    // ====================================================================

    #[test]
    fn test_process_nav_updates() {
        let mut plugin = make_plugin_with_program();
        // Trigger a schedule.
        plugin.schedule_update(Some("Note"));
        // Process.
        plugin.process_nav_updates();
        // No pending after processing.
        assert!(!plugin.nav_updater.has_pending());
    }

    #[test]
    fn test_process_nav_updates_empty() {
        let mut plugin = make_plugin_with_program();
        plugin.process_nav_updates();
        // Should be a no-op.
    }
}
