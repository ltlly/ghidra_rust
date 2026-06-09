//! Rename Plugin -- manages rename operations, dialog lifecycle, and history.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.rename.RenamePlugin`.
//!
//! The `RenameServicePlugin` is the central service that manages rename
//! operations across labels, functions, and namespaces. It owns the dialog
//! manager, the rename history, and coordinates between the action context,
//! command creation, and execution.
//!
//! # Architecture
//!
//! ```text
//! RenameServicePlugin
//!   |-- inner: RenamePlugin        (action enablement + command creation)
//!   |-- dialog: RenameDialogManager (dialog lifecycle)
//!   |-- history: RenameHistory      (rename change history)
//!   `-- options: RenamePluginOptions (auto-follow-rename, etc.)
//! ```
//!
//! # Example
//!
//! ```
//! use ghidra_features::base::rename::rename_plugin::RenameServicePlugin;
//!
//! let mut plugin = RenameServicePlugin::new("Rename");
//! plugin.init();
//! assert_eq!(plugin.name(), "Rename");
//! assert!(!plugin.is_disposed());
//! ```

use std::collections::HashMap;
use std::fmt;

use ghidra_core::addr::Address;
use ghidra_core::symbol::{SourceType, SymbolType};

use super::plugin::{RenameAction, RenameActionContext, RenamePlugin};
use super::rename_dialog::{RenameDialogManager, RenameDialogResult};

// ---------------------------------------------------------------------------
// RenamePluginOptions -- plugin configuration
// ---------------------------------------------------------------------------

/// Options for the rename plugin.
///
/// Ported from the options management in `RenamePlugin.java`.
#[derive(Debug, Clone)]
pub struct RenamePluginOptions {
    /// Whether to follow a rename into the symbol tree.
    pub follow_rename_in_tree: bool,
    /// Whether to show a confirmation dialog before applying renames
    /// to analysis-generated symbols.
    pub confirm_analysis_rename: bool,
}

impl Default for RenamePluginOptions {
    fn default() -> Self {
        Self {
            follow_rename_in_tree: false,
            confirm_analysis_rename: true,
        }
    }
}

impl RenamePluginOptions {
    /// Create new options with default values.
    pub fn new() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// RenameHistoryEntry -- a record of a rename change
// ---------------------------------------------------------------------------

/// A single entry in the rename change history.
///
/// Ported from the history tracking in Ghidra's rename plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenameHistoryEntry {
    /// The address of the renamed symbol (if applicable).
    pub address: Option<Address>,
    /// The symbol ID that was renamed.
    pub symbol_id: u64,
    /// The old name.
    pub old_name: String,
    /// The new name.
    pub new_name: String,
    /// The source of the rename.
    pub source: SourceType,
    /// The action that was performed.
    pub action: RenameAction,
    /// A monotonically increasing sequence number for ordering.
    pub sequence: u64,
}

impl RenameHistoryEntry {
    /// Whether this rename changed from a default-generated name.
    pub fn is_naming_from_default(&self) -> bool {
        super::cmd::is_default_label_name(&self.old_name)
            || super::cmd::is_default_function_name(&self.old_name)
    }
}

// ---------------------------------------------------------------------------
// RenameHistory -- per-symbol rename change history tracking
// ---------------------------------------------------------------------------

/// Stores rename history for all symbols.
///
/// Ported from the history tracking in Ghidra's rename plugin.
#[derive(Debug, Default)]
pub struct RenameHistory {
    /// Entries keyed by symbol ID.
    entries: HashMap<u64, Vec<RenameHistoryEntry>>,
    /// Monotonically increasing counter for ordering.
    next_sequence: u64,
}

impl RenameHistory {
    /// Create an empty history store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a rename change.
    pub fn record(
        &mut self,
        symbol_id: u64,
        address: Option<Address>,
        old_name: impl Into<String>,
        new_name: impl Into<String>,
        source: SourceType,
        action: RenameAction,
    ) {
        let seq = self.next_sequence;
        self.next_sequence += 1;
        let entry = RenameHistoryEntry {
            address,
            symbol_id,
            old_name: old_name.into(),
            new_name: new_name.into(),
            source,
            action,
            sequence: seq,
        };
        self.entries.entry(symbol_id).or_default().push(entry);
    }

    /// Get all history entries for a symbol.
    pub fn get_history(&self, symbol_id: u64) -> &[RenameHistoryEntry] {
        self.entries
            .get(&symbol_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Total number of history entries across all symbols.
    pub fn total_entries(&self) -> usize {
        self.entries.values().map(|v| v.len()).sum()
    }

    /// Number of tracked symbols.
    pub fn tracked_symbols(&self) -> usize {
        self.entries.len()
    }

    /// Get the most recent rename for a symbol, if any.
    pub fn last_rename(&self, symbol_id: u64) -> Option<&RenameHistoryEntry> {
        self.entries.get(&symbol_id).and_then(|v| v.last())
    }

    /// Get all entries in chronological order.
    pub fn all_entries(&self) -> Vec<&RenameHistoryEntry> {
        let mut all: Vec<&RenameHistoryEntry> = self.entries.values().flatten().collect();
        all.sort_by_key(|e| e.sequence);
        all
    }

    /// Clear all history.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.next_sequence = 0;
    }
}

// ---------------------------------------------------------------------------
// RenameServicePlugin -- the main plugin
// ---------------------------------------------------------------------------

/// The rename management plugin.
///
/// Ported from `ghidra.app.plugin.core.rename.RenamePlugin`.
///
/// Manages rename operations for labels, functions, and namespaces.
/// Supports action enablement, command creation, dialog lifecycle,
/// and rename history tracking.
///
/// # Lifecycle
///
/// 1. [`RenameServicePlugin::new`] -- creates the plugin.
/// 2. [`RenameServicePlugin::init`] -- initializes the plugin.
/// 3. Use the plugin's methods to perform renames.
/// 4. [`RenameServicePlugin::dispose`] -- cleans up resources.
#[derive(Debug)]
pub struct RenameServicePlugin {
    /// The plugin name.
    name: String,
    /// The inner rename plugin (action enablement + command creation).
    inner: RenamePlugin,
    /// The dialog manager.
    dialog_manager: RenameDialogManager,
    /// Plugin options.
    options: RenamePluginOptions,
    /// Rename change history.
    history: RenameHistory,
    /// Whether the plugin has been initialized.
    initialized: bool,
    /// Whether the plugin has been disposed.
    disposed: bool,
}

impl RenameServicePlugin {
    /// Create a new rename plugin.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            inner: RenamePlugin::new(),
            dialog_manager: RenameDialogManager::new(),
            options: RenamePluginOptions::default(),
            history: RenameHistory::new(),
            initialized: false,
            disposed: false,
        }
    }

    /// Get the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Initialize the plugin.
    pub fn init(&mut self) {
        if self.initialized {
            return;
        }
        self.initialized = true;
    }

    /// Dispose the plugin, releasing all resources.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.dialog_manager.close();
        self.history.clear();
        self.disposed = true;
    }

    /// Whether the plugin has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    // -- Options --

    /// Get the current plugin options.
    pub fn options(&self) -> &RenamePluginOptions {
        &self.options
    }

    /// Get a mutable reference to the plugin options.
    pub fn options_mut(&mut self) -> &mut RenamePluginOptions {
        &mut self.options
    }

    // -- Inner plugin delegation --

    /// Get a reference to the inner rename plugin.
    pub fn inner(&self) -> &RenamePlugin {
        &self.inner
    }

    /// Get the available rename actions for the given context.
    pub fn available_actions(&self, ctx: &RenameActionContext) -> Vec<RenameAction> {
        self.inner.available_actions(ctx)
    }

    // -- Dialog management --

    /// Open the rename label dialog for the given context.
    pub fn open_rename_label_dialog(
        &mut self,
        ctx: &RenameActionContext,
        current_name: Option<&str>,
    ) {
        let name = current_name.unwrap_or("");
        self.dialog_manager
            .open_label(ctx.address, name);
    }

    /// Open the rename function dialog for the given context.
    pub fn open_rename_function_dialog(
        &mut self,
        ctx: &RenameActionContext,
        current_name: Option<&str>,
    ) {
        let name = current_name.unwrap_or("");
        self.dialog_manager
            .open_function(ctx.address, name);
    }

    /// Open the rename namespace dialog for the given context.
    pub fn open_rename_namespace_dialog(
        &mut self,
        namespace_symbol_id: u64,
        current_name: &str,
    ) {
        self.dialog_manager
            .open_namespace(namespace_symbol_id, current_name);
    }

    /// Get a reference to the dialog manager.
    pub fn dialog_manager(&self) -> &RenameDialogManager {
        &self.dialog_manager
    }

    /// Get a mutable reference to the dialog manager.
    pub fn dialog_manager_mut(&mut self) -> &mut RenameDialogManager {
        &mut self.dialog_manager
    }

    /// Apply the current dialog and return the result.
    ///
    /// Returns the dialog result if changes were applied, or `None` if
    /// no dialog was open or the user cancelled.
    pub fn apply_dialog(&mut self) -> Option<RenameDialogResult> {
        self.dialog_manager.confirm()
    }

    /// Cancel the current dialog.
    pub fn cancel_dialog(&mut self) {
        self.dialog_manager.cancel();
    }

    /// Close the current dialog without applying or cancelling.
    pub fn close_dialog(&mut self) {
        self.dialog_manager.close();
    }

    // -- History --

    /// Get the rename history.
    pub fn history(&self) -> &RenameHistory {
        &self.history
    }

    /// Get a mutable reference to the rename history.
    pub fn history_mut(&mut self) -> &mut RenameHistory {
        &mut self.history
    }

    /// Record a rename in the history.
    pub fn record_rename(
        &mut self,
        symbol_id: u64,
        address: Option<Address>,
        old_name: impl Into<String>,
        new_name: impl Into<String>,
        source: SourceType,
        action: RenameAction,
    ) {
        self.history
            .record(symbol_id, address, old_name, new_name, source, action);
    }

    /// Show rename history for a symbol.
    ///
    /// Returns the history entries for the given symbol.
    pub fn show_rename_history(&self, symbol_id: u64) -> &[RenameHistoryEntry] {
        self.history.get_history(symbol_id)
    }

    // -- Convenience: determine action from context --

    /// Determine the primary rename action for a given context.
    ///
    /// Returns the most specific rename action available, or `None` if
    /// no rename action is available.
    pub fn primary_action(&self, ctx: &RenameActionContext) -> Option<RenameAction> {
        let actions = self.available_actions(ctx);
        // Prefer RenameFunction > RenameLabel > RenameNamespace > SetLabelPrimary
        actions.into_iter().min_by_key(|a| match a {
            RenameAction::RenameFunction => 0,
            RenameAction::RenameLabel => 1,
            RenameAction::RenameNamespace => 2,
            RenameAction::SetLabelPrimary => 3,
            RenameAction::MoveToNamespace => 4,
            RenameAction::RenameAndMove => 5,
        })
    }
}

impl Default for RenameServicePlugin {
    fn default() -> Self {
        Self::new("RenameServicePlugin")
    }
}

impl fmt::Display for RenameServicePlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RenameServicePlugin({}, history_entries={})",
            self.name,
            self.history.total_entries()
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn label_context(addr_offset: u64) -> RenameActionContext {
        RenameActionContext::on_label(
            Address::new(addr_offset),
            SourceType::UserDefined,
            false,
            false,
        )
    }

    fn function_context(addr_offset: u64) -> RenameActionContext {
        RenameActionContext::on_function(
            Address::new(addr_offset),
            SourceType::UserDefined,
            false,
        )
    }

    fn namespace_context() -> RenameActionContext {
        RenameActionContext::on_namespace(Address::new(0), SymbolType::Namespace)
    }

    // ====================================================================
    // RenamePluginOptions
    // ====================================================================

    #[test]
    fn test_plugin_options_default() {
        let opts = RenamePluginOptions::new();
        assert!(!opts.follow_rename_in_tree);
        assert!(opts.confirm_analysis_rename);
    }

    // ====================================================================
    // RenameHistoryEntry
    // ====================================================================

    #[test]
    fn test_history_entry_naming_from_default() {
        let entry = RenameHistoryEntry {
            address: Some(Address::new(0x1000)),
            symbol_id: 1,
            old_name: "LAB_00401000".to_string(),
            new_name: "main".to_string(),
            source: SourceType::UserDefined,
            action: RenameAction::RenameLabel,
            sequence: 0,
        };
        assert!(entry.is_naming_from_default());

        let entry2 = RenameHistoryEntry {
            address: Some(Address::new(0x1000)),
            symbol_id: 2,
            old_name: "old_name".to_string(),
            new_name: "new_name".to_string(),
            source: SourceType::UserDefined,
            action: RenameAction::RenameLabel,
            sequence: 1,
        };
        assert!(!entry2.is_naming_from_default());
    }

    // ====================================================================
    // RenameHistory
    // ====================================================================

    #[test]
    fn test_history_empty() {
        let history = RenameHistory::new();
        assert_eq!(history.total_entries(), 0);
        assert_eq!(history.tracked_symbols(), 0);
    }

    #[test]
    fn test_history_record_and_retrieve() {
        let mut history = RenameHistory::new();
        history.record(
            1,
            Some(Address::new(0x1000)),
            "old",
            "new",
            SourceType::UserDefined,
            RenameAction::RenameLabel,
        );
        history.record(
            1,
            Some(Address::new(0x1000)),
            "new",
            "newer",
            SourceType::UserDefined,
            RenameAction::RenameLabel,
        );
        history.record(
            2,
            Some(Address::new(0x2000)),
            "func_old",
            "func_new",
            SourceType::UserDefined,
            RenameAction::RenameFunction,
        );

        assert_eq!(history.total_entries(), 3);
        assert_eq!(history.tracked_symbols(), 2);

        let sym1 = history.get_history(1);
        assert_eq!(sym1.len(), 2);

        let sym2 = history.get_history(2);
        assert_eq!(sym2.len(), 1);

        assert!(history.get_history(999).is_empty());
    }

    #[test]
    fn test_history_last_rename() {
        let mut history = RenameHistory::new();
        assert!(history.last_rename(1).is_none());

        history.record(
            1,
            Some(Address::new(0x1000)),
            "old",
            "new",
            SourceType::UserDefined,
            RenameAction::RenameLabel,
        );
        history.record(
            1,
            Some(Address::new(0x1000)),
            "new",
            "newer",
            SourceType::UserDefined,
            RenameAction::RenameLabel,
        );

        let last = history.last_rename(1).unwrap();
        assert_eq!(last.new_name, "newer");
    }

    #[test]
    fn test_history_all_entries_sorted() {
        let mut history = RenameHistory::new();
        history.record(
            2,
            Some(Address::new(0x2000)),
            "b",
            "bb",
            SourceType::UserDefined,
            RenameAction::RenameLabel,
        );
        history.record(
            1,
            Some(Address::new(0x1000)),
            "a",
            "aa",
            SourceType::UserDefined,
            RenameAction::RenameLabel,
        );

        let all = history.all_entries();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].new_name, "bb"); // first recorded
        assert_eq!(all[1].new_name, "aa"); // second recorded
    }

    #[test]
    fn test_history_clear() {
        let mut history = RenameHistory::new();
        history.record(
            1,
            Some(Address::new(0x1000)),
            "old",
            "new",
            SourceType::UserDefined,
            RenameAction::RenameLabel,
        );
        assert_eq!(history.total_entries(), 1);
        history.clear();
        assert_eq!(history.total_entries(), 0);
    }

    // ====================================================================
    // RenameServicePlugin -- lifecycle
    // ====================================================================

    #[test]
    fn test_plugin_creation() {
        let plugin = RenameServicePlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert!(!plugin.is_initialized());
        assert!(!plugin.is_disposed());
        assert_eq!(plugin.history().total_entries(), 0);
    }

    #[test]
    fn test_plugin_init_dispose() {
        let mut plugin = RenameServicePlugin::new("TestPlugin");
        plugin.init();
        assert!(plugin.is_initialized());
        plugin.init(); // no-op
        assert!(plugin.is_initialized());

        plugin.dispose();
        assert!(plugin.is_disposed());
        plugin.dispose(); // no-op
        assert!(plugin.is_disposed());
    }

    // ====================================================================
    // RenameServicePlugin -- actions
    // ====================================================================

    #[test]
    fn test_plugin_available_actions_on_label() {
        let plugin = RenameServicePlugin::new("TestPlugin");
        let ctx = label_context(0x1000);
        let actions = plugin.available_actions(&ctx);
        assert!(actions.contains(&RenameAction::RenameLabel));
        assert!(!actions.contains(&RenameAction::RenameFunction));
    }

    #[test]
    fn test_plugin_available_actions_on_function() {
        let plugin = RenameServicePlugin::new("TestPlugin");
        let ctx = function_context(0x1000);
        let actions = plugin.available_actions(&ctx);
        assert!(actions.contains(&RenameAction::RenameFunction));
        assert!(!actions.contains(&RenameAction::RenameLabel));
    }

    // ====================================================================
    // RenameServicePlugin -- dialog
    // ====================================================================

    #[test]
    fn test_plugin_open_rename_label_dialog() {
        let mut plugin = RenameServicePlugin::new("TestPlugin");
        let ctx = label_context(0x1000);
        assert!(!plugin.dialog_manager().is_open());

        plugin.open_rename_label_dialog(&ctx, Some("old_label"));
        assert!(plugin.dialog_manager().is_open());
    }

    #[test]
    fn test_plugin_open_rename_function_dialog() {
        let mut plugin = RenameServicePlugin::new("TestPlugin");
        let ctx = function_context(0x1000);
        assert!(!plugin.dialog_manager().is_open());

        plugin.open_rename_function_dialog(&ctx, Some("old_func"));
        assert!(plugin.dialog_manager().is_open());
    }

    #[test]
    fn test_plugin_open_rename_namespace_dialog() {
        let mut plugin = RenameServicePlugin::new("TestPlugin");
        assert!(!plugin.dialog_manager().is_open());

        plugin.open_rename_namespace_dialog(42, "OldNS");
        assert!(plugin.dialog_manager().is_open());
    }

    #[test]
    fn test_plugin_apply_dialog() {
        let mut plugin = RenameServicePlugin::new("TestPlugin");
        let ctx = label_context(0x1000);
        plugin.open_rename_label_dialog(&ctx, Some("old_label"));

        plugin.dialog_manager_mut().dialog_mut().unwrap().set_new_name("new_label");
        let result = plugin.apply_dialog();
        assert!(result.is_some());
        assert_eq!(result.unwrap().new_name, "new_label");
        assert!(!plugin.dialog_manager().is_open());
    }

    #[test]
    fn test_plugin_cancel_dialog() {
        let mut plugin = RenameServicePlugin::new("TestPlugin");
        let ctx = label_context(0x1000);
        plugin.open_rename_label_dialog(&ctx, Some("old_label"));
        plugin.dialog_manager_mut().dialog_mut().unwrap().set_new_name("new_label");

        plugin.cancel_dialog();
        assert!(!plugin.dialog_manager().is_open());
    }

    #[test]
    fn test_plugin_close_dialog() {
        let mut plugin = RenameServicePlugin::new("TestPlugin");
        let ctx = label_context(0x1000);
        plugin.open_rename_label_dialog(&ctx, Some("old_label"));

        plugin.close_dialog();
        assert!(!plugin.dialog_manager().is_open());
    }

    // ====================================================================
    // RenameServicePlugin -- history
    // ====================================================================

    #[test]
    fn test_plugin_record_rename() {
        let mut plugin = RenameServicePlugin::new("TestPlugin");
        plugin.record_rename(
            1,
            Some(Address::new(0x1000)),
            "old",
            "new",
            SourceType::UserDefined,
            RenameAction::RenameLabel,
        );
        assert_eq!(plugin.history().total_entries(), 1);
    }

    #[test]
    fn test_plugin_show_rename_history() {
        let mut plugin = RenameServicePlugin::new("TestPlugin");
        plugin.record_rename(
            1,
            Some(Address::new(0x1000)),
            "old",
            "new",
            SourceType::UserDefined,
            RenameAction::RenameLabel,
        );

        let hist = plugin.show_rename_history(1);
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].new_name, "new");
    }

    // ====================================================================
    // RenameServicePlugin -- primary action
    // ====================================================================

    #[test]
    fn test_plugin_primary_action_on_label() {
        let plugin = RenameServicePlugin::new("TestPlugin");
        let ctx = label_context(0x1000);
        let action = plugin.primary_action(&ctx);
        assert_eq!(action, Some(RenameAction::RenameLabel));
    }

    #[test]
    fn test_plugin_primary_action_on_function() {
        let plugin = RenameServicePlugin::new("TestPlugin");
        let ctx = function_context(0x1000);
        let action = plugin.primary_action(&ctx);
        assert_eq!(action, Some(RenameAction::RenameFunction));
    }

    #[test]
    fn test_plugin_primary_action_on_namespace() {
        let plugin = RenameServicePlugin::new("TestPlugin");
        let ctx = namespace_context();
        let action = plugin.primary_action(&ctx);
        assert_eq!(action, Some(RenameAction::RenameNamespace));
    }

    #[test]
    fn test_plugin_primary_action_empty_context() {
        let plugin = RenameServicePlugin::new("TestPlugin");
        let ctx = RenameActionContext::empty(Address::new(0x1000));
        let action = plugin.primary_action(&ctx);
        assert!(action.is_none());
    }

    // ====================================================================
    // Display
    // ====================================================================

    #[test]
    fn test_plugin_display() {
        let plugin = RenameServicePlugin::new("MyPlugin");
        let display = format!("{}", plugin);
        assert!(display.contains("MyPlugin"));
        assert!(display.contains("history_entries=0"));
    }

    // ====================================================================
    // Integration
    // ====================================================================

    #[test]
    fn test_full_workflow() {
        let mut plugin = RenameServicePlugin::new("TestPlugin");
        plugin.init();

        // Open a rename dialog for a label
        let ctx = label_context(0x401000);
        plugin.open_rename_label_dialog(&ctx, Some("LAB_00401000"));
        plugin.dialog_manager_mut().dialog_mut().unwrap().set_new_name("main");
        let result = plugin.apply_dialog().unwrap();
        assert_eq!(result.new_name, "main");

        // Record in history
        plugin.record_rename(
            1,
            Some(Address::new(0x401000)),
            "LAB_00401000",
            "main",
            SourceType::UserDefined,
            RenameAction::RenameLabel,
        );

        // Verify history
        let hist = plugin.show_rename_history(1);
        assert_eq!(hist.len(), 1);
        assert!(hist[0].is_naming_from_default());

        plugin.dispose();
        assert!(plugin.is_disposed());
    }
}
