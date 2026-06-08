//! Label manager plugin with action registration and callbacks.
//!
//! Ported from Ghidra's `LabelMgrPlugin` (`LabelMgrPlugin.java`).
//!
//! This module provides the complete plugin that ties together all label
//! management actions: add, edit, remove, set operand label, and label
//! history. It handles action registration, callback dispatch, and
//! context queries for enablement logic.

use std::collections::HashMap;

use ghidra_core::addr::Address;
use ghidra_core::symbol::{SourceType, SymbolType};

use super::actions::{LabelAction, LabelActionContext};
use super::all_history_action::AllHistoryAction;
use super::dialogs::LabelHistoryTask;
use super::history::{LabelHistoryAction as HistoryActionKind, LabelHistoryEntry};

// ---------------------------------------------------------------------------
// Action registration
// ---------------------------------------------------------------------------

/// Configuration for a registered action.
///
/// Mirrors the `DockingAction` setup in `LabelMgrPlugin.setupActions()`.
#[derive(Debug, Clone)]
pub struct RegisteredAction {
    /// The label action type.
    pub action: LabelAction,
    /// The display name shown in the popup menu.
    pub display_name: String,
    /// The popup menu path (e.g., ["Add Label..."]).
    pub popup_path: Vec<String>,
    /// The popup menu group (for ordering).
    pub popup_group: String,
    /// The key binding character, if any.
    pub key_binding: Option<char>,
    /// Whether the action uses a shared key binding type.
    pub shared_key_binding: bool,
    /// Whether the action is currently enabled.
    pub enabled: bool,
}

impl RegisteredAction {
    /// Creates a new registered action with defaults for the given action type.
    pub fn for_action(action: LabelAction) -> Self {
        let display_name = action.display_name().to_string();
        let popup_path = vec![display_name.clone()];
        let popup_group = "Label".to_string();

        let (key_binding, shared_key_binding) = match action {
            LabelAction::AddLabel | LabelAction::EditLabel => (Some('L'), false),
            LabelAction::RemoveLabel => (None, true), // DELETE key, shared
            LabelAction::ShowLabelHistory => (Some('H'), false),
            LabelAction::SetOperandLabel => (Some('L'), false), // Ctrl+Alt+L
            _ => (None, false),
        };

        Self {
            action,
            display_name,
            popup_path,
            popup_group,
            key_binding,
            shared_key_binding,
            enabled: true,
        }
    }

    /// Returns whether the action is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Sets the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

// ---------------------------------------------------------------------------
// Symbol info (lightweight representation for context queries)
// ---------------------------------------------------------------------------

/// Lightweight symbol information used for context queries.
///
/// This replaces direct access to Ghidra's `Symbol` object for
/// determining action enablement and callback behavior.
#[derive(Debug, Clone)]
pub struct SymbolInfo {
    /// The address of the symbol.
    pub address: Address,
    /// The symbol name.
    pub name: String,
    /// The symbol type.
    pub symbol_type: SymbolType,
    /// The source type.
    pub source: SourceType,
    /// Whether the symbol is external.
    pub is_external: bool,
    /// Whether the symbol is dynamic.
    pub is_dynamic: bool,
    /// The parent namespace ID (0 for global).
    pub namespace_id: u64,
}

impl SymbolInfo {
    /// Creates a new symbol info.
    pub fn new(
        address: Address,
        name: impl Into<String>,
        symbol_type: SymbolType,
        source: SourceType,
    ) -> Self {
        Self {
            address,
            name: name.into(),
            symbol_type,
            source,
            is_external: false,
            is_dynamic: false,
            namespace_id: 0,
        }
    }

    /// Returns whether this is a label symbol.
    pub fn is_label(&self) -> bool {
        self.symbol_type == SymbolType::Label
    }

    /// Returns whether this is a function symbol.
    pub fn is_function(&self) -> bool {
        self.symbol_type == SymbolType::Function
    }

    /// Returns the display name (with namespace if applicable).
    pub fn display_name(&self, include_namespace: bool) -> &str {
        // In a full implementation, this would prepend the namespace.
        &self.name
    }
}

// ---------------------------------------------------------------------------
// ProgramLocation types
// ---------------------------------------------------------------------------

/// The type of listing field the cursor is on.
///
/// This models the various `ProgramLocation` subclasses from Ghidra
/// that are checked in the label plugin's enablement logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListingFieldType {
    /// On a label field (shows symbol names).
    LabelField,
    /// On an operand field (shows operand expressions).
    OperandField,
    /// On a code unit field (shows bytes, mnemonics, etc.).
    CodeUnitField,
    /// On a function field.
    FunctionField,
    /// Unknown or other field.
    Other,
}

/// Context for a cursor position in the listing.
///
/// This models Ghidra's `ListingActionContext` and `ProgramLocation`
/// for use in action enablement and callbacks. It contains all the
/// information needed by the label plugin to determine which actions
/// are available and how to perform them.
#[derive(Debug, Clone)]
pub struct ListingContext {
    /// The address at the cursor.
    pub address: Address,
    /// The type of field the cursor is on.
    pub field_type: ListingFieldType,
    /// The operand index (for operand fields).
    pub operand_index: Option<i32>,
    /// The reference address (for operand field references).
    pub ref_address: Option<Address>,
    /// The component path (for data structure fields).
    pub component_path: Vec<i32>,
    /// The symbol at this location, if any.
    pub symbol: Option<SymbolInfo>,
    /// Whether this is a variable reference.
    pub is_variable_reference: bool,
    /// Whether this is an external reference.
    pub is_external_reference: bool,
}

impl ListingContext {
    /// Creates an empty context at the given address.
    pub fn empty(address: Address) -> Self {
        Self {
            address,
            field_type: ListingFieldType::Other,
            operand_index: None,
            ref_address: None,
            component_path: Vec::new(),
            symbol: None,
            is_variable_reference: false,
            is_external_reference: false,
        }
    }

    /// Creates a context for a label field location.
    pub fn label_field(address: Address, symbol: SymbolInfo) -> Self {
        Self {
            address,
            field_type: ListingFieldType::LabelField,
            operand_index: None,
            ref_address: None,
            component_path: Vec::new(),
            symbol: Some(symbol),
            is_variable_reference: false,
            is_external_reference: false,
        }
    }

    /// Creates a context for an operand field location.
    pub fn operand_field(
        address: Address,
        operand_index: i32,
        ref_address: Option<Address>,
    ) -> Self {
        Self {
            address,
            field_type: ListingFieldType::OperandField,
            operand_index: Some(operand_index),
            ref_address,
            component_path: Vec::new(),
            symbol: None,
            is_variable_reference: false,
            is_external_reference: false,
        }
    }

    /// Returns the symbol at this location, if any.
    pub fn get_symbol(&self) -> Option<&SymbolInfo> {
        self.symbol.as_ref()
    }

    /// Returns true if there is a symbol at this location.
    pub fn has_symbol(&self) -> bool {
        self.symbol.is_some()
    }

    /// Returns true if the cursor is on a function location.
    pub fn is_on_function(&self) -> bool {
        self.field_type == ListingFieldType::FunctionField
            || self.symbol.as_ref().map_or(false, |s| s.is_function())
    }

    /// Returns true if the cursor is on a variable reference.
    pub fn is_on_variable_reference(&self) -> bool {
        self.is_variable_reference
    }

    /// Returns true if the cursor is on an external reference.
    pub fn is_on_external_reference(&self) -> bool {
        self.is_external_reference
    }

    /// Returns true if the address is external.
    pub fn is_external_address(&self) -> bool {
        self.address.is_external_address()
    }
}

// ---------------------------------------------------------------------------
// LabelPlugin
// ---------------------------------------------------------------------------

/// The label manager plugin.
///
/// This is the Rust equivalent of Ghidra's `LabelMgrPlugin`. It manages
/// all label-related actions and provides the callbacks that those actions
/// invoke. It contains:
///
/// - A set of registered actions (add, edit, remove, etc.)
/// - The label data (labels and history)
/// - An optional `AddEditDialog` for label editing
/// - Callback methods for each action type
///
/// # Architecture
///
/// In Ghidra's Java implementation, `LabelMgrPlugin` extends `Plugin` and
/// registers `DockingAction` instances. Each action calls back into the
/// plugin when triggered. This Rust port models the same pattern:
///
/// - `LabelPlugin` owns the actions and label data
/// - `perform_*` methods are the callbacks for each action
/// - `is_*_enabled` methods determine enablement for each action
///
/// # Example
///
/// ```
/// use ghidra_features::base::label::LabelPlugin;
/// use ghidra_features::base::label::LabelAction;
/// use ghidra_core::addr::Address;
///
/// let mut plugin = LabelPlugin::new("LabelMgrPlugin");
///
/// // Add a label
/// plugin.add_label(Address::new(0x1000), "main");
///
/// // Check if actions are enabled
/// let ctx = plugin.build_context(Address::new(0x1000));
/// let enabled = plugin.get_enabled_actions(&ctx);
/// assert!(enabled.contains(&LabelAction::EditLabel));
/// assert!(enabled.contains(&LabelAction::RemoveLabel));
/// assert!(!enabled.contains(&LabelAction::AddLabel));
/// ```
pub struct LabelPlugin {
    /// The plugin name.
    name: String,
    /// Registered actions.
    actions: Vec<RegisteredAction>,
    /// All-history action (separate because it has different behavior).
    all_history_action: AllHistoryAction,
    /// Labels by address (offset -> label info).
    labels: HashMap<u64, SymbolInfo>,
    /// Label history by address (offset -> entries).
    history: HashMap<u64, Vec<LabelHistoryEntry>>,
    /// Next symbol ID.
    next_id: u64,
    /// Whether to record history.
    record_history: bool,
    /// The last callback result message.
    last_status: Option<String>,
    /// Accumulated callback log for testing.
    callback_log: Vec<String>,
}

impl LabelPlugin {
    /// Creates a new LabelPlugin.
    ///
    /// Mirrors `LabelMgrPlugin(PluginTool tool)` in Java, which calls
    /// `setupActions()` and creates the `AddEditDialog`.
    pub fn new(name: impl Into<String>) -> Self {
        let mut plugin = Self {
            name: name.into(),
            actions: Vec::new(),
            all_history_action: AllHistoryAction::new(),
            labels: HashMap::new(),
            history: HashMap::new(),
            next_id: 1,
            record_history: true,
            last_status: None,
            callback_log: Vec::new(),
        };
        plugin.setup_actions();
        plugin
    }

    /// Returns the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Sets up all actions.
    ///
    /// Mirrors `setupActions()` in Java which creates and registers
    /// all the DockingAction instances.
    fn setup_actions(&mut self) {
        // AddLabelAction
        let mut add_action = RegisteredAction::for_action(LabelAction::AddLabel);
        add_action.popup_path = vec!["Add Label...".to_string()];
        add_action.popup_group = "Label".to_string();
        self.actions.push(add_action);

        // EditLabelAction
        let mut edit_action = RegisteredAction::for_action(LabelAction::EditLabel);
        edit_action.popup_path = vec!["Edit Label...".to_string()];
        edit_action.popup_group = "Label".to_string();
        self.actions.push(edit_action);

        // EditExternalLabelAction
        let mut ext_action = RegisteredAction::for_action(LabelAction::EditLabel);
        ext_action.display_name = "Edit External Location".to_string();
        ext_action.popup_path = vec!["Edit External Location".to_string()];
        ext_action.popup_group = "0External".to_string();
        ext_action.key_binding = Some('L');
        self.actions.push(ext_action);

        // RemoveLabelAction
        let mut remove_action = RegisteredAction::for_action(LabelAction::RemoveLabel);
        remove_action.popup_path = vec!["Remove Label".to_string()];
        remove_action.popup_group = "Label".to_string();
        self.actions.push(remove_action);

        // SetOperandLabelAction
        let mut operand_action = RegisteredAction::for_action(LabelAction::SetOperandLabel);
        operand_action.popup_path = vec!["Set Associated Label...".to_string()];
        operand_action.popup_group = "Label".to_string();
        self.actions.push(operand_action);

        // LabelHistoryAction
        let mut history_action = RegisteredAction::for_action(LabelAction::ShowLabelHistory);
        history_action.popup_path = vec!["Show Label History...".to_string()];
        history_action.popup_group = "Label".to_string();
        self.actions.push(history_action);
    }

    /// Returns the registered actions.
    pub fn actions(&self) -> &[RegisteredAction] {
        &self.actions
    }

    /// Returns a mutable reference to the registered actions.
    pub fn actions_mut(&mut self) -> &mut Vec<RegisteredAction> {
        &mut self.actions
    }

    /// Returns the all-history action.
    pub fn all_history_action(&self) -> &AllHistoryAction {
        &self.all_history_action
    }

    /// Returns a mutable reference to the all-history action.
    pub fn all_history_action_mut(&mut self) -> &mut AllHistoryAction {
        &mut self.all_history_action
    }

    // -- Label operations --------------------------------------------------

    /// Adds a label at the given address.
    ///
    /// Mirrors `addLabelCallback(ListingActionContext context)` which
    /// calls `getAddEditDialog().addLabel(address, program)`.
    pub fn add_label(&mut self, address: Address, name: impl Into<String>) -> u64 {
        let name = name.into();
        let id = self.next_id;
        self.next_id += 1;

        let symbol = SymbolInfo::new(address, &name, SymbolType::Label, SourceType::UserDefined);
        self.labels.insert(address.offset, symbol);

        if self.record_history {
            self.record_history_entry(&address, HistoryActionKind::Add, &name);
        }

        self.callback_log
            .push(format!("add_label(0x{:X}, {})", address.offset, name));
        id
    }

    /// Edits the label at the given address.
    ///
    /// Mirrors `editLabelCallback(ListingActionContext context)` which
    /// determines whether to open the add or edit dialog.
    pub fn edit_label(&mut self, address: Address, new_name: impl Into<String>) -> bool {
        let new_name = new_name.into();

        if let Some(label) = self.labels.get_mut(&address.offset) {
            let old_name = label.name.clone();

            // If the label has default source and is a label type, treat as add.
            if label.source == SourceType::Default && label.symbol_type == SymbolType::Label {
                label.name = new_name.clone();
                label.source = SourceType::UserDefined;
            } else {
                label.name = new_name.clone();
            }

            if self.record_history {
                self.record_history_entry(&address, HistoryActionKind::Rename, &old_name);
            }

            self.callback_log
                .push(format!("edit_label(0x{:X}, {})", address.offset, new_name));
            return true;
        }

        // No label exists -- treat as add.
        self.add_label(address, &new_name);
        true
    }

    /// Removes the label at the given address.
    ///
    /// Mirrors `removeLabelCallback(ListingActionContext context)` which
    /// creates a `DeleteLabelCmd` and executes it.
    pub fn remove_label(&mut self, address: Address) -> bool {
        if let Some(label) = self.labels.remove(&address.offset) {
            if self.record_history {
                self.record_history_entry(&address, HistoryActionKind::Remove, &label.name);
            }

            self.callback_log
                .push(format!("remove_label(0x{:X})", address.offset));
            return true;
        }
        false
    }

    /// Returns the symbol info at the given address.
    pub fn get_symbol(&self, address: &Address) -> Option<&SymbolInfo> {
        self.labels.get(&address.offset)
    }

    /// Returns the number of labels.
    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    // -- History -----------------------------------------------------------

    fn record_history_entry(&mut self, address: &Address, action: HistoryActionKind, label: &str) {
        let entry = LabelHistoryEntry::new(*address, action, label, "user", chrono_timestamp());
        self.history.entry(address.offset).or_default().push(entry);
    }

    /// Returns the label history at the given address.
    pub fn get_label_history(&self, address: &Address) -> &[LabelHistoryEntry] {
        self.history
            .get(&address.offset)
            .map_or(&[], |v| v.as_slice())
    }

    /// Returns true if the given address has label history.
    ///
    /// Mirrors `hasLabelHistory(ListingActionContext context)` in Java.
    pub fn has_label_history(&self, address: &Address) -> bool {
        self.history
            .get(&address.offset)
            .map_or(false, |v| !v.is_empty())
    }

    /// Returns all label history entries across all addresses.
    pub fn get_all_label_history(&self) -> Vec<&LabelHistoryEntry> {
        self.history.values().flatten().collect()
    }

    /// Executes a label history search task.
    ///
    /// Mirrors the `LabelHistoryTask` execution in Java. If a pattern
    /// is provided, filters by label name.
    pub fn search_label_history(&self, pattern: Option<&str>) -> LabelHistoryTask {
        let all: Vec<LabelHistoryEntry> = self.history.values().flatten().cloned().collect();

        let mut task = if pattern.is_some() {
            LabelHistoryTask::for_all()
        } else {
            LabelHistoryTask::for_all()
        };

        let filtered = if let Some(pat) = pattern {
            let pat_lower = pat.to_lowercase();
            all.into_iter()
                .filter(|e| e.label.to_lowercase().contains(&pat_lower))
                .collect()
        } else {
            all
        };

        task.set_results(filtered);
        task
    }

    // -- Context queries ---------------------------------------------------

    /// Builds a context for the given address from stored label data.
    pub fn build_context(&self, address: Address) -> LabelActionContext {
        if let Some(label) = self.labels.get(&address.offset) {
            LabelActionContext::on_symbol(
                address,
                label.symbol_type,
                label.source,
                label.is_external,
            )
        } else {
            LabelActionContext::empty(address)
        }
    }

    /// Returns the list of enabled actions for the given context.
    pub fn get_enabled_actions(&self, ctx: &LabelActionContext) -> Vec<LabelAction> {
        let mut actions = Vec::new();

        if super::actions::is_add_label_enabled(ctx) {
            actions.push(LabelAction::AddLabel);
        }
        if let Some(action) = super::actions::is_edit_label_enabled(ctx) {
            actions.push(action);
        }
        if super::actions::is_remove_label_enabled(ctx) {
            actions.push(LabelAction::RemoveLabel);
        }
        if super::actions::is_label_history_enabled(ctx) {
            actions.push(LabelAction::ShowLabelHistory);
        }

        actions
    }

    /// Returns the symbol from a listing context.
    ///
    /// Mirrors `getSymbol(ListingActionContext context)` in Java.
    pub fn get_symbol_from_context<'a>(&self, ctx: &'a ListingContext) -> Option<&'a SymbolInfo> {
        ctx.symbol.as_ref()
    }

    /// Returns true if the context has a symbol.
    pub fn is_on_symbol(&self, ctx: &ListingContext) -> bool {
        ctx.has_symbol()
    }

    /// Returns true if the context is on a function.
    pub fn is_on_function(&self, ctx: &ListingContext) -> bool {
        ctx.is_on_function()
    }

    /// Returns true if the context is on a variable reference.
    pub fn is_on_variable_reference(&self, ctx: &ListingContext) -> bool {
        ctx.is_on_variable_reference()
    }

    /// Returns true if the context is on an external reference.
    pub fn is_on_external_reference(&self, ctx: &ListingContext) -> bool {
        ctx.is_on_external_reference()
    }

    // -- Callbacks ---------------------------------------------------------

    /// The add label callback.
    ///
    /// Mirrors `addLabelCallback(ListingActionContext context)`.
    pub fn add_label_callback(&mut self, ctx: &ListingContext) {
        self.callback_log
            .push(format!("add_label_callback(0x{:X})", ctx.address.offset));
        // In Ghidra: getAddEditDialog().addLabel(context.getAddress(), context.getProgram())
        // The dialog is shown; we just record the intent.
    }

    /// The edit label callback.
    ///
    /// Mirrors `editLabelCallback(ListingActionContext context)`.
    pub fn edit_label_callback(&mut self, ctx: &ListingContext) {
        self.callback_log
            .push(format!("edit_label_callback(0x{:X})", ctx.address.offset));

        // In Ghidra:
        // 1. Get the symbol at the context location
        // 2. If it's a default-source label, open add dialog
        // 3. If it's a user label, open edit dialog
        // 4. If no symbol but inside a component, edit field name
        // 5. If no symbol and no component, open add dialog
    }

    /// The remove label callback.
    ///
    /// Mirrors `removeLabelCallback(ListingActionContext context)`.
    pub fn remove_label_callback(&mut self, ctx: &ListingContext) -> bool {
        self.callback_log
            .push(format!("remove_label_callback(0x{:X})", ctx.address.offset));

        if let Some(ref symbol) = ctx.symbol {
            let address = symbol.address;
            self.remove_label(address)
        } else {
            self.set_status("No symbol to remove");
            false
        }
    }

    /// The set operand label callback.
    ///
    /// Mirrors `setOperandLabelCallback(ListingActionContext context)`.
    pub fn set_operand_label_callback(&mut self, ctx: &ListingContext) {
        self.callback_log.push(format!(
            "set_operand_label_callback(0x{:X})",
            ctx.address.offset
        ));
        // In Ghidra: shows SymbolChooserDialog
    }

    // -- Status ------------------------------------------------------------

    /// Sets the status message.
    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.last_status = Some(msg.into());
    }

    /// Returns the last status message.
    pub fn status(&self) -> Option<&str> {
        self.last_status.as_deref()
    }

    /// Clears the status message.
    pub fn clear_status(&mut self) {
        self.last_status = None;
    }

    /// Returns the callback log (for testing).
    pub fn callback_log(&self) -> &[String] {
        &self.callback_log
    }

    /// Clears the callback log.
    pub fn clear_callback_log(&mut self) {
        self.callback_log.clear();
    }

    // -- Dispose -----------------------------------------------------------

    /// Disposes of the plugin and its resources.
    ///
    /// Mirrors `dispose()` in Java which disposes the `AddEditDialog`.
    pub fn dispose(&mut self) {
        self.labels.clear();
        self.history.clear();
        self.actions.clear();
        self.callback_log.push("dispose".to_string());
    }
}

impl Default for LabelPlugin {
    fn default() -> Self {
        Self::new("LabelMgrPlugin")
    }
}

/// Returns a simple timestamp string.
fn chrono_timestamp() -> String {
    "now".to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    // -- Plugin construction --

    #[test]
    fn test_plugin_new() {
        let plugin = LabelPlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert_eq!(plugin.label_count(), 0);
    }

    #[test]
    fn test_plugin_default() {
        let plugin = LabelPlugin::default();
        assert_eq!(plugin.name(), "LabelMgrPlugin");
    }

    #[test]
    fn test_plugin_setup_actions() {
        let plugin = LabelPlugin::new("TestPlugin");
        // Should have: AddLabel, EditLabel, EditExternal, RemoveLabel, SetOperandLabel, LabelHistory
        assert_eq!(plugin.actions().len(), 6);
    }

    // -- Label operations --

    #[test]
    fn test_add_label() {
        let mut plugin = LabelPlugin::new("TestPlugin");
        let id = plugin.add_label(addr(0x1000), "main");
        assert_eq!(id, 1);
        assert_eq!(plugin.label_count(), 1);

        let symbol = plugin.get_symbol(&addr(0x1000)).unwrap();
        assert_eq!(symbol.name, "main");
        assert_eq!(symbol.symbol_type, SymbolType::Label);
        assert_eq!(symbol.source, SourceType::UserDefined);
    }

    #[test]
    fn test_add_multiple_labels() {
        let mut plugin = LabelPlugin::new("TestPlugin");
        plugin.add_label(addr(0x1000), "main");
        plugin.add_label(addr(0x2000), "helper");
        plugin.add_label(addr(0x3000), "init");

        assert_eq!(plugin.label_count(), 3);
        assert!(plugin.get_symbol(&addr(0x1000)).is_some());
        assert!(plugin.get_symbol(&addr(0x2000)).is_some());
        assert!(plugin.get_symbol(&addr(0x3000)).is_some());
    }

    #[test]
    fn test_edit_label() {
        let mut plugin = LabelPlugin::new("TestPlugin");
        plugin.add_label(addr(0x1000), "old_name");

        assert!(plugin.edit_label(addr(0x1000), "new_name"));
        let symbol = plugin.get_symbol(&addr(0x1000)).unwrap();
        assert_eq!(symbol.name, "new_name");
    }

    #[test]
    fn test_edit_label_nonexistent_treated_as_add() {
        let mut plugin = LabelPlugin::new("TestPlugin");
        assert!(plugin.edit_label(addr(0x1000), "new_label"));

        // Should have added the label.
        assert_eq!(plugin.label_count(), 1);
        let symbol = plugin.get_symbol(&addr(0x1000)).unwrap();
        assert_eq!(symbol.name, "new_label");
    }

    #[test]
    fn test_edit_default_label() {
        let mut plugin = LabelPlugin::new("TestPlugin");
        // Add with default source
        let symbol = SymbolInfo::new(
            addr(0x1000),
            "LAB_00001000",
            SymbolType::Label,
            SourceType::Default,
        );
        plugin.labels.insert(0x1000, symbol);

        plugin.edit_label(addr(0x1000), "my_label");
        let symbol = plugin.get_symbol(&addr(0x1000)).unwrap();
        assert_eq!(symbol.name, "my_label");
        assert_eq!(symbol.source, SourceType::UserDefined);
    }

    #[test]
    fn test_remove_label() {
        let mut plugin = LabelPlugin::new("TestPlugin");
        plugin.add_label(addr(0x1000), "test");

        assert!(plugin.remove_label(addr(0x1000)));
        assert_eq!(plugin.label_count(), 0);
        assert!(plugin.get_symbol(&addr(0x1000)).is_none());
    }

    #[test]
    fn test_remove_label_nonexistent() {
        let mut plugin = LabelPlugin::new("TestPlugin");
        assert!(!plugin.remove_label(addr(0x1000)));
    }

    // -- History --

    #[test]
    fn test_label_history_recorded() {
        let mut plugin = LabelPlugin::new("TestPlugin");
        plugin.add_label(addr(0x1000), "test");
        plugin.edit_label(addr(0x1000), "renamed");
        plugin.remove_label(addr(0x1000));

        let history = plugin.get_label_history(&addr(0x1000));
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].action, HistoryActionKind::Add);
        assert_eq!(history[1].action, HistoryActionKind::Rename);
        assert_eq!(history[2].action, HistoryActionKind::Remove);
    }

    #[test]
    fn test_label_history_disabled() {
        let mut plugin = LabelPlugin::new("TestPlugin");
        plugin.record_history = false;
        plugin.add_label(addr(0x1000), "test");
        assert!(!plugin.has_label_history(&addr(0x1000)));
    }

    #[test]
    fn test_has_label_history() {
        let mut plugin = LabelPlugin::new("TestPlugin");
        assert!(!plugin.has_label_history(&addr(0x1000)));
        plugin.add_label(addr(0x1000), "test");
        assert!(plugin.has_label_history(&addr(0x1000)));
    }

    #[test]
    fn test_get_all_label_history() {
        let mut plugin = LabelPlugin::new("TestPlugin");
        plugin.add_label(addr(0x1000), "a");
        plugin.add_label(addr(0x2000), "b");
        let all = plugin.get_all_label_history();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_search_label_history() {
        let mut plugin = LabelPlugin::new("TestPlugin");
        plugin.add_label(addr(0x1000), "main");
        plugin.add_label(addr(0x2000), "helper");
        plugin.add_label(addr(0x3000), "main_loop");

        let task = plugin.search_label_history(Some("main"));
        assert!(task.is_completed());
        assert_eq!(task.results().len(), 2);
    }

    #[test]
    fn test_search_label_history_no_filter() {
        let mut plugin = LabelPlugin::new("TestPlugin");
        plugin.add_label(addr(0x1000), "a");
        plugin.add_label(addr(0x2000), "b");

        let task = plugin.search_label_history(None);
        assert!(task.is_completed());
        assert_eq!(task.results().len(), 2);
    }

    // -- Context queries --

    #[test]
    fn test_build_context_with_label() {
        let mut plugin = LabelPlugin::new("TestPlugin");
        plugin.add_label(addr(0x1000), "test");

        let ctx = plugin.build_context(addr(0x1000));
        assert!(ctx.has_symbol());
        assert_eq!(ctx.symbol_type, Some(SymbolType::Label));
    }

    #[test]
    fn test_build_context_empty() {
        let plugin = LabelPlugin::new("TestPlugin");
        let ctx = plugin.build_context(addr(0x1000));
        assert!(!ctx.has_symbol());
    }

    #[test]
    fn test_get_enabled_actions_on_empty() {
        let plugin = LabelPlugin::new("TestPlugin");
        let ctx = LabelActionContext::empty(addr(0x1000));
        let actions = plugin.get_enabled_actions(&ctx);
        assert!(actions.contains(&LabelAction::AddLabel));
        assert!(actions.contains(&LabelAction::ShowLabelHistory));
        assert!(!actions.contains(&LabelAction::RemoveLabel));
    }

    #[test]
    fn test_get_enabled_actions_on_label() {
        let mut plugin = LabelPlugin::new("TestPlugin");
        plugin.add_label(addr(0x1000), "test");

        let ctx = plugin.build_context(addr(0x1000));
        let actions = plugin.get_enabled_actions(&ctx);
        assert!(!actions.contains(&LabelAction::AddLabel));
        assert!(actions.contains(&LabelAction::EditLabel));
        assert!(actions.contains(&LabelAction::RemoveLabel));
        assert!(actions.contains(&LabelAction::ShowLabelHistory));
    }

    // -- Context queries with ListingContext --

    #[test]
    fn test_is_on_symbol() {
        let plugin = LabelPlugin::new("TestPlugin");
        let symbol = SymbolInfo::new(
            addr(0x1000),
            "test",
            SymbolType::Label,
            SourceType::UserDefined,
        );
        let ctx = ListingContext::label_field(addr(0x1000), symbol);
        assert!(plugin.is_on_symbol(&ctx));
    }

    #[test]
    fn test_is_on_function() {
        let plugin = LabelPlugin::new("TestPlugin");
        let symbol = SymbolInfo::new(
            addr(0x1000),
            "main",
            SymbolType::Function,
            SourceType::UserDefined,
        );
        let ctx = ListingContext::label_field(addr(0x1000), symbol);
        assert!(plugin.is_on_function(&ctx));
    }

    #[test]
    fn test_is_on_external_reference() {
        let plugin = LabelPlugin::new("TestPlugin");
        let mut ctx = ListingContext::empty(addr(0x1000));
        ctx.is_external_reference = true;
        assert!(plugin.is_on_external_reference(&ctx));
    }

    // -- Callbacks --

    #[test]
    fn test_add_label_callback() {
        let mut plugin = LabelPlugin::new("TestPlugin");
        let ctx = ListingContext::empty(addr(0x1000));
        plugin.add_label_callback(&ctx);
        assert_eq!(plugin.callback_log().len(), 1);
        assert!(plugin.callback_log()[0].contains("add_label_callback"));
    }

    #[test]
    fn test_edit_label_callback() {
        let mut plugin = LabelPlugin::new("TestPlugin");
        let ctx = ListingContext::empty(addr(0x1000));
        plugin.edit_label_callback(&ctx);
        assert!(plugin.callback_log()[0].contains("edit_label_callback"));
    }

    #[test]
    fn test_remove_label_callback_with_symbol() {
        let mut plugin = LabelPlugin::new("TestPlugin");
        plugin.add_label(addr(0x1000), "test");

        let symbol = SymbolInfo::new(
            addr(0x1000),
            "test",
            SymbolType::Label,
            SourceType::UserDefined,
        );
        let ctx = ListingContext::label_field(addr(0x1000), symbol);
        assert!(plugin.remove_label_callback(&ctx));
        assert_eq!(plugin.label_count(), 0);
    }

    #[test]
    fn test_remove_label_callback_without_symbol() {
        let mut plugin = LabelPlugin::new("TestPlugin");
        let ctx = ListingContext::empty(addr(0x1000));
        assert!(!plugin.remove_label_callback(&ctx));
        assert_eq!(plugin.status(), Some("No symbol to remove"));
    }

    #[test]
    fn test_set_operand_label_callback() {
        let mut plugin = LabelPlugin::new("TestPlugin");
        let ctx = ListingContext::empty(addr(0x1000));
        plugin.set_operand_label_callback(&ctx);
        assert!(plugin.callback_log()[0].contains("set_operand_label_callback"));
    }

    // -- Status --

    #[test]
    fn test_status() {
        let mut plugin = LabelPlugin::new("TestPlugin");
        assert!(plugin.status().is_none());

        plugin.set_status("Test status");
        assert_eq!(plugin.status(), Some("Test status"));

        plugin.clear_status();
        assert!(plugin.status().is_none());
    }

    // -- Dispose --

    #[test]
    fn test_dispose() {
        let mut plugin = LabelPlugin::new("TestPlugin");
        plugin.add_label(addr(0x1000), "test");
        assert_eq!(plugin.label_count(), 1);

        plugin.dispose();
        assert_eq!(plugin.label_count(), 0);
        assert_eq!(plugin.actions().len(), 0);
        assert!(plugin.callback_log().last().unwrap().contains("dispose"));
    }

    // -- RegisteredAction --

    #[test]
    fn test_registered_action_for_add() {
        let action = RegisteredAction::for_action(LabelAction::AddLabel);
        assert_eq!(action.display_name, "Add Label...");
        assert_eq!(action.key_binding, Some('L'));
        assert!(action.is_enabled());
    }

    #[test]
    fn test_registered_action_for_remove() {
        let action = RegisteredAction::for_action(LabelAction::RemoveLabel);
        assert_eq!(action.display_name, "Remove Label");
        assert!(action.shared_key_binding);
    }

    #[test]
    fn test_registered_action_set_enabled() {
        let mut action = RegisteredAction::for_action(LabelAction::AddLabel);
        assert!(action.is_enabled());
        action.set_enabled(false);
        assert!(!action.is_enabled());
    }

    // -- SymbolInfo --

    #[test]
    fn test_symbol_info() {
        let symbol = SymbolInfo::new(
            addr(0x1000),
            "main",
            SymbolType::Function,
            SourceType::UserDefined,
        );
        assert_eq!(symbol.address, addr(0x1000));
        assert_eq!(symbol.name, "main");
        assert!(symbol.is_function());
        assert!(!symbol.is_label());
        assert!(!symbol.is_external);
        assert!(!symbol.is_dynamic);
    }

    // -- ListingContext --

    #[test]
    fn test_listing_context_empty() {
        let ctx = ListingContext::empty(addr(0x1000));
        assert!(!ctx.has_symbol());
        assert!(!ctx.is_on_function());
        assert!(!ctx.is_on_variable_reference());
    }

    #[test]
    fn test_listing_context_label_field() {
        let symbol = SymbolInfo::new(
            addr(0x1000),
            "test",
            SymbolType::Label,
            SourceType::UserDefined,
        );
        let ctx = ListingContext::label_field(addr(0x1000), symbol);
        assert!(ctx.has_symbol());
        assert_eq!(ctx.field_type, ListingFieldType::LabelField);
    }

    #[test]
    fn test_listing_context_operand_field() {
        let ctx = ListingContext::operand_field(addr(0x1000), 0, Some(addr(0x2000)));
        assert_eq!(ctx.field_type, ListingFieldType::OperandField);
        assert_eq!(ctx.operand_index, Some(0));
        assert_eq!(ctx.ref_address, Some(addr(0x2000)));
    }

    // -- Full workflow --

    #[test]
    fn test_full_workflow() {
        let mut plugin = LabelPlugin::new("TestPlugin");

        // Add a label
        plugin.add_label(addr(0x1000), "main");
        assert_eq!(plugin.label_count(), 1);

        // Check enabled actions
        let ctx = plugin.build_context(addr(0x1000));
        let actions = plugin.get_enabled_actions(&ctx);
        assert!(actions.contains(&LabelAction::EditLabel));
        assert!(actions.contains(&LabelAction::RemoveLabel));

        // Edit the label
        plugin.edit_label(addr(0x1000), "main_entry");
        let symbol = plugin.get_symbol(&addr(0x1000)).unwrap();
        assert_eq!(symbol.name, "main_entry");

        // Check history
        assert_eq!(plugin.get_label_history(&addr(0x1000)).len(), 2);

        // Remove the label
        plugin.remove_label(addr(0x1000));
        assert_eq!(plugin.label_count(), 0);

        // Check final history
        assert_eq!(plugin.get_label_history(&addr(0x1000)).len(), 3);

        // Dispose
        plugin.dispose();
    }
}
