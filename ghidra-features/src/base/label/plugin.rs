//! Label manager plugin logic.
//!
//! Ported from Ghidra's `LabelMgrPlugin`, this module provides the core
//! business logic for label management -- adding, editing, and removing
//! labels, querying label history, and determining action enablement.
//!
//! GUI-specific code (dialogs, Swing utilities) is abstracted behind traits.

use std::collections::HashMap;

use ghidra_core::addr::Address;
use ghidra_core::symbol::{LabelSymbol, SourceType, SymbolApi};

use super::actions::{LabelAction, LabelActionContext};

// ---------------------------------------------------------------------------
// LabelManager
// ---------------------------------------------------------------------------

/// Manages label operations on a program.
///
/// This is the Rust equivalent of the core logic in Ghidra's `LabelMgrPlugin`,
/// without the Swing/AWT GUI dependencies. It provides:
/// - Adding, editing, and removing labels
/// - Querying label history
/// - Determining which actions are enabled for a given context
pub struct LabelManager {
    /// All labels by address.
    labels: HashMap<u64, LabelSymbol>,
    /// Label history by address.
    history: HashMap<u64, Vec<LabelHistoryEntry>>,
    /// Next label ID.
    next_id: u64,
    /// Whether to record history.
    record_history: bool,
}

/// A label history entry stored by the manager.
#[derive(Debug, Clone)]
pub struct LabelHistoryEntry {
    /// The address of the change.
    pub address: Address,
    /// The action taken.
    pub action: LabelHistoryAction,
    /// The label name.
    pub label: String,
    /// The timestamp.
    pub timestamp: String,
}

/// History action kind stored internally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelHistoryAction {
    Add,
    Remove,
    Rename,
}

impl LabelManager {
    /// Creates a new LabelManager.
    pub fn new() -> Self {
        Self {
            labels: HashMap::new(),
            history: HashMap::new(),
            next_id: 1,
            record_history: true,
        }
    }

    /// Enables or disables history recording.
    pub fn set_record_history(&mut self, record: bool) {
        self.record_history = record;
    }

    /// Returns whether history recording is enabled.
    pub fn is_recording_history(&self) -> bool {
        self.record_history
    }

    // -- Label operations -------------------------------------------------

    /// Adds a label at the given address.
    ///
    /// Returns the new label symbol.
    pub fn add_label(&mut self, address: &Address, name: &str, source: SourceType) -> &LabelSymbol {
        let id = self.next_id;
        self.next_id += 1;

        let label = LabelSymbol::with_options(id, name, *address, 0, source);
        self.labels.insert(address.offset, label);

        if self.record_history {
            self.add_history(address, LabelHistoryAction::Add, name);
        }

        self.labels.get(&address.offset).unwrap()
    }

    /// Edits the label at the given address.
    ///
    /// Returns true if the label was found and renamed.
    pub fn edit_label(&mut self, address: &Address, new_name: &str, source: SourceType) -> bool {
        if let Some(label) = self.labels.get_mut(&address.offset) {
            let old_name = label.get_name();
            if let Err(e) = label.set_name(new_name, source) {
                eprintln!("Failed to rename label: {}", e);
                return false;
            }

            if self.record_history {
                self.add_history(address, LabelHistoryAction::Rename, &old_name);
            }
            return true;
        }
        false
    }

    /// Removes the label at the given address.
    ///
    /// Returns true if the label was found and removed.
    pub fn remove_label(&mut self, address: &Address) -> bool {
        if let Some(label) = self.labels.remove(&address.offset) {
            if self.record_history {
                self.add_history(address, LabelHistoryAction::Remove, &label.get_name());
            }
            return true;
        }
        false
    }

    /// Returns a reference to the label at the given address, if any.
    pub fn get_label(&self, address: &Address) -> Option<&LabelSymbol> {
        self.labels.get(&address.offset)
    }

    /// Returns the number of labels.
    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    // -- History ----------------------------------------------------------

    fn add_history(&mut self, address: &Address, action: LabelHistoryAction, label: &str) {
        let entry = LabelHistoryEntry {
            address: *address,
            action,
            label: label.to_string(),
            timestamp: chrono_timestamp(),
        };
        self.history.entry(address.offset).or_default().push(entry);
    }

    /// Returns the label history at the given address.
    pub fn get_label_history(&self, address: &Address) -> &[LabelHistoryEntry] {
        self.history
            .get(&address.offset)
            .map_or(&[], |v| v.as_slice())
    }

    /// Returns true if the given address has label history.
    pub fn has_label_history(&self, address: &Address) -> bool {
        self.history
            .get(&address.offset)
            .map_or(false, |v| !v.is_empty())
    }

    /// Returns all label history entries across all addresses.
    pub fn get_all_label_history(&self) -> Vec<&LabelHistoryEntry> {
        self.history.values().flatten().collect()
    }

    // -- Context queries --------------------------------------------------

    /// Returns the label action context for a given address.
    ///
    /// This builds a `LabelActionContext` from the label data at the address,
    /// suitable for checking action enablement.
    pub fn get_context(&self, address: &Address) -> LabelActionContext {
        if let Some(label) = self.labels.get(&address.offset) {
            LabelActionContext::on_symbol(
                *address,
                label.get_symbol_type(),
                label.get_source(),
                label.is_external(),
            )
        } else {
            LabelActionContext::empty(*address)
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
}

impl Default for LabelManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns a simple timestamp string. In a real implementation this would use
/// the system clock.
fn chrono_timestamp() -> String {
    // Simple placeholder; real impl would use chrono or std::time.
    "now".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::symbol::SymbolType;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_add_label() {
        let mut mgr = LabelManager::new();
        mgr.add_label(&addr(0x1000), "main", SourceType::UserDefined);
        assert_eq!(mgr.label_count(), 1);
        let label = mgr.get_label(&addr(0x1000)).unwrap();
        assert_eq!(label.get_name(), "main");
    }

    #[test]
    fn test_edit_label() {
        let mut mgr = LabelManager::new();
        mgr.add_label(&addr(0x1000), "old_name", SourceType::UserDefined);
        assert!(mgr.edit_label(&addr(0x1000), "new_name", SourceType::UserDefined));
        let label = mgr.get_label(&addr(0x1000)).unwrap();
        assert_eq!(label.get_name(), "new_name");
    }

    #[test]
    fn test_edit_nonexistent_label() {
        let mut mgr = LabelManager::new();
        assert!(!mgr.edit_label(&addr(0x1000), "name", SourceType::UserDefined));
    }

    #[test]
    fn test_remove_label() {
        let mut mgr = LabelManager::new();
        mgr.add_label(&addr(0x1000), "test", SourceType::UserDefined);
        assert!(mgr.remove_label(&addr(0x1000)));
        assert_eq!(mgr.label_count(), 0);
        assert!(mgr.get_label(&addr(0x1000)).is_none());
    }

    #[test]
    fn test_remove_nonexistent_label() {
        let mut mgr = LabelManager::new();
        assert!(!mgr.remove_label(&addr(0x1000)));
    }

    #[test]
    fn test_label_history_recorded() {
        let mut mgr = LabelManager::new();
        mgr.add_label(&addr(0x1000), "test", SourceType::UserDefined);
        mgr.edit_label(&addr(0x1000), "renamed", SourceType::UserDefined);
        mgr.remove_label(&addr(0x1000));

        let history = mgr.get_label_history(&addr(0x1000));
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].action, LabelHistoryAction::Add);
        assert_eq!(history[1].action, LabelHistoryAction::Rename);
        assert_eq!(history[2].action, LabelHistoryAction::Remove);
    }

    #[test]
    fn test_label_history_disabled() {
        let mut mgr = LabelManager::new();
        mgr.set_record_history(false);
        mgr.add_label(&addr(0x1000), "test", SourceType::UserDefined);
        assert!(!mgr.has_label_history(&addr(0x1000)));
    }

    #[test]
    fn test_has_label_history() {
        let mut mgr = LabelManager::new();
        assert!(!mgr.has_label_history(&addr(0x1000)));
        mgr.add_label(&addr(0x1000), "test", SourceType::UserDefined);
        assert!(mgr.has_label_history(&addr(0x1000)));
    }

    #[test]
    fn test_get_all_label_history() {
        let mut mgr = LabelManager::new();
        mgr.add_label(&addr(0x1000), "a", SourceType::UserDefined);
        mgr.add_label(&addr(0x2000), "b", SourceType::UserDefined);
        let all = mgr.get_all_label_history();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_get_context_with_label() {
        let mut mgr = LabelManager::new();
        mgr.add_label(&addr(0x1000), "test", SourceType::UserDefined);
        let ctx = mgr.get_context(&addr(0x1000));
        assert!(ctx.has_symbol());
        assert_eq!(ctx.symbol_type, Some(SymbolType::Label));
    }

    #[test]
    fn test_get_context_empty() {
        let mgr = LabelManager::new();
        let ctx = mgr.get_context(&addr(0x1000));
        assert!(!ctx.has_symbol());
    }

    #[test]
    fn test_get_enabled_actions_on_empty() {
        let mgr = LabelManager::new();
        let ctx = LabelActionContext::empty(addr(0x1000));
        let actions = mgr.get_enabled_actions(&ctx);
        assert!(actions.contains(&LabelAction::AddLabel));
        assert!(actions.contains(&LabelAction::ShowLabelHistory));
        assert!(!actions.contains(&LabelAction::RemoveLabel));
    }

    #[test]
    fn test_get_enabled_actions_on_label() {
        let mut mgr = LabelManager::new();
        mgr.add_label(&addr(0x1000), "test", SourceType::UserDefined);
        let ctx = mgr.get_context(&addr(0x1000));
        let actions = mgr.get_enabled_actions(&ctx);
        assert!(!actions.contains(&LabelAction::AddLabel));
        assert!(actions.contains(&LabelAction::EditLabel));
        assert!(actions.contains(&LabelAction::RemoveLabel));
        assert!(actions.contains(&LabelAction::ShowLabelHistory));
    }
}
