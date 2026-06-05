//! Label history tracking, label manager plugin, and edit label actions.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.label` Java package:
//! `LabelHistoryTableModel`, `LabelHistoryPanel`, `LabelHistoryDialog`,
//! `LabelHistoryTask`, `LabelHistoryListener`, `LabelHistoryInputDialog`,
//! `LabelMgrPlugin`, `EditLabelAction`, `EditExternalLabelAction`,
//! `AddLabelAction`, `RemoveLabelAction`, `SetOperandLabelAction`,
//! `AllHistoryAction`, `SymbolChooserDialog`.

use super::{LabelInfo, LabelManager, LabelScope, LabelValidator};
use ghidra_core::Address;
use std::collections::BTreeMap;

// ============================================================================
// LabelHistoryEntry -- a single history change
// ============================================================================

/// A single label history entry.
///
/// Ported from `ghidra.app.plugin.core.label.LabelHistoryTableModel`.
#[derive(Debug, Clone)]
pub struct LabelHistoryEntry {
    /// The address of the label.
    pub address: Address,
    /// The old label name (None if this is the first name).
    pub old_name: Option<String>,
    /// The new label name.
    pub new_name: String,
    /// The timestamp (unix millis).
    pub timestamp: u64,
    /// Who performed the change.
    pub user: String,
}

impl LabelHistoryEntry {
    /// Create a new label history entry for a creation event.
    pub fn created(
        address: Address,
        name: impl Into<String>,
        timestamp: u64,
        user: impl Into<String>,
    ) -> Self {
        Self {
            address,
            old_name: None,
            new_name: name.into(),
            timestamp,
            user: user.into(),
        }
    }

    /// Create a new label history entry for a rename event.
    pub fn renamed(
        address: Address,
        old_name: impl Into<String>,
        new_name: impl Into<String>,
        timestamp: u64,
        user: impl Into<String>,
    ) -> Self {
        Self {
            address,
            old_name: Some(old_name.into()),
            new_name: new_name.into(),
            timestamp,
            user: user.into(),
        }
    }

    /// The display description for this entry.
    pub fn description(&self) -> String {
        match &self.old_name {
            Some(old) => format!("{} -> {}", old, self.new_name),
            None => format!("Created: {}", self.new_name),
        }
    }
}

// ============================================================================
// LabelHistoryTable -- table model for label history
// ============================================================================

/// Table model for displaying label history.
///
/// Ported from `ghidra.app.plugin.core.label.LabelHistoryTableModel`.
#[derive(Debug, Default)]
pub struct LabelHistoryTable {
    /// All history entries.
    entries: Vec<LabelHistoryEntry>,
}

impl LabelHistoryTable {
    /// Create a new empty label history table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a history entry.
    pub fn add_entry(&mut self, entry: LabelHistoryEntry) {
        self.entries.push(entry);
    }

    /// Get all entries for a specific address.
    pub fn get_history_for(&self, address: Address) -> Vec<&LabelHistoryEntry> {
        self.entries
            .iter()
            .filter(|e| e.address == address)
            .collect()
    }

    /// Get all entries.
    pub fn all_entries(&self) -> &[LabelHistoryEntry] {
        &self.entries
    }

    /// Total number of entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// ============================================================================
// LabelHistory -- tracks history for all labels
// ============================================================================

/// Tracks the complete label history for a program.
///
/// Ported from `ghidra.app.plugin.core.label.LabelHistoryTask`.
#[derive(Debug, Default)]
pub struct LabelHistory {
    /// History indexed by address offset.
    history: BTreeMap<u64, Vec<LabelHistoryEntry>>,
}

impl LabelHistory {
    /// Create a new label history tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a label creation.
    pub fn record_created(
        &mut self,
        address: Address,
        name: impl Into<String>,
        timestamp: u64,
        user: impl Into<String>,
    ) {
        let entry = LabelHistoryEntry::created(address, name, timestamp, user);
        self.history
            .entry(address.offset)
            .or_default()
            .push(entry);
    }

    /// Record a label rename.
    pub fn record_renamed(
        &mut self,
        address: Address,
        old_name: impl Into<String>,
        new_name: impl Into<String>,
        timestamp: u64,
        user: impl Into<String>,
    ) {
        let entry = LabelHistoryEntry::renamed(address, old_name, new_name, timestamp, user);
        self.history
            .entry(address.offset)
            .or_default()
            .push(entry);
    }

    /// Record a label deletion.
    pub fn record_deleted(
        &mut self,
        address: Address,
        name: impl Into<String>,
        timestamp: u64,
        user: impl Into<String>,
    ) {
        let entry = LabelHistoryEntry {
            address,
            old_name: Some(name.into()),
            new_name: String::new(),
            timestamp,
            user: user.into(),
        };
        self.history
            .entry(address.offset)
            .or_default()
            .push(entry);
    }

    /// Get history for a specific address.
    pub fn get_history(&self, address: Address) -> Vec<&LabelHistoryEntry> {
        self.history
            .get(&address.offset)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Total number of tracked addresses.
    pub fn tracked_addresses(&self) -> usize {
        self.history.len()
    }

    /// Total number of history entries.
    pub fn total_entries(&self) -> usize {
        self.history.values().map(|v| v.len()).sum()
    }
}

// ============================================================================
// EditLabelAction -- action to edit a label
// ============================================================================

/// Action to edit (rename) a label.
///
/// Ported from `ghidra.app.plugin.core.label.EditLabelAction`.
#[derive(Debug, Clone)]
pub struct EditLabelAction {
    /// The address of the label to edit.
    pub address: Address,
    /// The current name.
    pub current_name: String,
    /// The new name.
    pub new_name: String,
    /// Whether to make this the primary label.
    pub set_primary: bool,
    /// The new scope (if changing).
    pub new_scope: Option<LabelScope>,
}

impl EditLabelAction {
    /// Create a new edit label action.
    pub fn new(
        address: Address,
        current_name: impl Into<String>,
        new_name: impl Into<String>,
    ) -> Self {
        Self {
            address,
            current_name: current_name.into(),
            new_name: new_name.into(),
            set_primary: false,
            new_scope: None,
        }
    }

    /// Validate the new name.
    pub fn is_valid(&self) -> bool {
        LabelValidator::is_valid_label_name(&self.new_name)
    }

    /// Execute the edit action on a label manager.
    pub fn execute(
        &self,
        manager: &mut LabelManager,
        history: &mut LabelHistory,
        timestamp: u64,
        user: &str,
    ) -> Result<(), String> {
        if !self.is_valid() {
            return Err(format!("Invalid label name: '{}'", self.new_name));
        }

        manager.rename_label(self.address, &self.current_name, &self.new_name)?;
        history.record_renamed(
            self.address,
            &self.current_name,
            &self.new_name,
            timestamp,
            user,
        );
        Ok(())
    }
}

// ============================================================================
// AddLabelAction -- action to add a label
// ============================================================================

/// Action to add a label at an address.
///
/// Ported from `ghidra.app.plugin.core.label.AddLabelAction`.
#[derive(Debug, Clone)]
pub struct AddLabelAction {
    /// The address.
    pub address: Address,
    /// The label name.
    pub name: String,
    /// The scope.
    pub scope: LabelScope,
    /// Whether this is the primary label.
    pub primary: bool,
}

impl AddLabelAction {
    /// Create a new add-label action.
    pub fn new(address: Address, name: impl Into<String>, scope: LabelScope) -> Self {
        Self {
            address,
            name: name.into(),
            scope,
            primary: true,
        }
    }

    /// Validate the label name.
    pub fn is_valid(&self) -> bool {
        LabelValidator::is_valid_label_name(&self.name)
    }

    /// Execute the action.
    pub fn execute(
        &self,
        manager: &mut LabelManager,
        history: &mut LabelHistory,
        timestamp: u64,
        user: &str,
    ) -> Result<(), String> {
        if !self.is_valid() {
            return Err(format!("Invalid label name: '{}'", self.name));
        }

        let label = LabelInfo {
            name: self.name.clone(),
            address: self.address,
            scope: self.scope,
            primary: self.primary,
        };
        manager.add_label(label);
        history.record_created(self.address, &self.name, timestamp, user);
        Ok(())
    }
}

// ============================================================================
// RemoveLabelAction -- action to remove a label
// ============================================================================

/// Action to remove a label.
///
/// Ported from `ghidra.app.plugin.core.label.RemoveLabelAction`.
#[derive(Debug, Clone)]
pub struct RemoveLabelAction {
    /// The address of the label.
    pub address: Address,
    /// The name of the label to remove.
    pub name: String,
}

impl RemoveLabelAction {
    /// Create a new remove-label action.
    pub fn new(address: Address, name: impl Into<String>) -> Self {
        Self {
            address,
            name: name.into(),
        }
    }

    /// Execute the action.
    pub fn execute(
        &self,
        manager: &mut LabelManager,
        history: &mut LabelHistory,
        timestamp: u64,
        user: &str,
    ) -> Result<(), String> {
        match manager.remove_label(self.address, &self.name) {
            Some(_) => {
                history.record_deleted(self.address, &self.name, timestamp, user);
                Ok(())
            }
            None => Err(format!(
                "Label '{}' not found at address {}",
                self.name, self.address
            )),
        }
    }
}

// ============================================================================
// SetOperandLabelAction -- action to set a label on an operand
// ============================================================================

/// Action to set an operand-level label.
///
/// Ported from `ghidra.app.plugin.core.label.SetOperandLabelAction`.
#[derive(Debug, Clone)]
pub struct SetOperandLabelAction {
    /// The address of the instruction.
    pub address: Address,
    /// The operand index.
    pub operand_index: usize,
    /// The label name.
    pub name: String,
}

impl SetOperandLabelAction {
    /// Create a new set-operand-label action.
    pub fn new(address: Address, operand_index: usize, name: impl Into<String>) -> Self {
        Self {
            address,
            operand_index,
            name: name.into(),
        }
    }

    /// Validate the label name.
    pub fn is_valid(&self) -> bool {
        LabelValidator::is_valid_label_name(&self.name)
    }
}

// ============================================================================
// LabelMgrPlugin -- the label manager plugin
// ============================================================================

/// The label manager plugin orchestrates label operations.
///
/// Ported from `ghidra.app.plugin.core.label.LabelMgrPlugin`.
#[derive(Debug)]
pub struct LabelMgrPlugin {
    /// The label manager.
    pub manager: LabelManager,
    /// The label history tracker.
    pub history: LabelHistory,
    /// Whether the plugin is disposed.
    disposed: bool,
}

impl LabelMgrPlugin {
    /// Create a new label manager plugin.
    pub fn new() -> Self {
        Self {
            manager: LabelManager::new(),
            history: LabelHistory::new(),
            disposed: false,
        }
    }

    /// Add a label and record in history.
    pub fn add_label(
        &mut self,
        address: Address,
        name: &str,
        scope: LabelScope,
        timestamp: u64,
        user: &str,
    ) -> Result<(), String> {
        let action = AddLabelAction::new(address, name, scope);
        action.execute(&mut self.manager, &mut self.history, timestamp, user)
    }

    /// Rename a label and record in history.
    pub fn rename_label(
        &mut self,
        address: Address,
        old_name: &str,
        new_name: &str,
        timestamp: u64,
        user: &str,
    ) -> Result<(), String> {
        let action = EditLabelAction::new(address, old_name, new_name);
        action.execute(&mut self.manager, &mut self.history, timestamp, user)
    }

    /// Remove a label and record in history.
    pub fn remove_label(
        &mut self,
        address: Address,
        name: &str,
        timestamp: u64,
        user: &str,
    ) -> Result<(), String> {
        let action = RemoveLabelAction::new(address, name);
        action.execute(&mut self.manager, &mut self.history, timestamp, user)
    }

    /// Get label history for an address.
    pub fn get_history(&self, address: Address) -> Vec<&LabelHistoryEntry> {
        self.history.get_history(address)
    }

    /// Dispose the plugin.
    pub fn dispose(&mut self) {
        self.disposed = true;
    }

    /// Whether the plugin is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }
}

impl Default for LabelMgrPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// AllHistoryAction -- retrieve all history for the program
// ============================================================================

/// Action to retrieve all label history entries.
///
/// Ported from `ghidra.app.plugin.core.label.AllHistoryAction`.
#[derive(Debug)]
pub struct AllHistoryAction;

impl AllHistoryAction {
    /// Get all history entries from the label history tracker.
    pub fn get_all_entries(history: &LabelHistory) -> usize {
        history.total_entries()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_history_entry_created() {
        let entry = LabelHistoryEntry::created(Address::new(0x1000), "main", 1000, "user");
        assert_eq!(entry.old_name, None);
        assert_eq!(entry.new_name, "main");
        assert_eq!(entry.description(), "Created: main");
    }

    #[test]
    fn test_label_history_entry_renamed() {
        let entry =
            LabelHistoryEntry::renamed(Address::new(0x1000), "old", "new", 2000, "user");
        assert_eq!(entry.old_name, Some("old".into()));
        assert_eq!(entry.new_name, "new");
        assert_eq!(entry.description(), "old -> new");
    }

    #[test]
    fn test_label_history_record_created() {
        let mut history = LabelHistory::new();
        history.record_created(Address::new(0x1000), "main", 1000, "user");
        assert_eq!(history.tracked_addresses(), 1);
        assert_eq!(history.total_entries(), 1);

        let entries = history.get_history(Address::new(0x1000));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].new_name, "main");
    }

    #[test]
    fn test_label_history_record_renamed() {
        let mut history = LabelHistory::new();
        history.record_created(Address::new(0x1000), "old", 1000, "user");
        history.record_renamed(Address::new(0x1000), "old", "new", 2000, "user");
        assert_eq!(history.total_entries(), 2);
    }

    #[test]
    fn test_label_history_record_deleted() {
        let mut history = LabelHistory::new();
        history.record_created(Address::new(0x1000), "main", 1000, "user");
        history.record_deleted(Address::new(0x1000), "main", 2000, "user");
        assert_eq!(history.total_entries(), 2);

        let entries = history.get_history(Address::new(0x1000));
        assert_eq!(entries[1].new_name, ""); // deletion marker
    }

    #[test]
    fn test_label_history_empty() {
        let history = LabelHistory::new();
        assert_eq!(history.get_history(Address::new(0x1000)).len(), 0);
    }

    #[test]
    fn test_label_history_table() {
        let mut table = LabelHistoryTable::new();
        table.add_entry(LabelHistoryEntry::created(
            Address::new(0x1000),
            "main",
            1000,
            "user",
        ));
        table.add_entry(LabelHistoryEntry::renamed(
            Address::new(0x2000),
            "old",
            "new",
            2000,
            "user",
        ));
        assert_eq!(table.entry_count(), 2);
        assert_eq!(table.get_history_for(Address::new(0x1000)).len(), 1);
    }

    #[test]
    fn test_edit_label_action() {
        let action = EditLabelAction::new(Address::new(0x1000), "old_name", "new_name");
        assert!(action.is_valid());

        let bad = EditLabelAction::new(Address::new(0x1000), "old", "123bad");
        assert!(!bad.is_valid());
    }

    #[test]
    fn test_edit_label_action_execute() {
        let mut mgr = LabelManager::new();
        let mut history = LabelHistory::new();
        mgr.add_label(LabelInfo::primary("old_name", Address::new(0x1000)));

        let action = EditLabelAction::new(Address::new(0x1000), "old_name", "new_name");
        action
            .execute(&mut mgr, &mut history, 1000, "user")
            .unwrap();
        assert_eq!(
            mgr.get_label_name(Address::new(0x1000)),
            Some("new_name")
        );
        assert_eq!(history.total_entries(), 1);
    }

    #[test]
    fn test_edit_label_action_invalid() {
        let mut mgr = LabelManager::new();
        let mut history = LabelHistory::new();
        mgr.add_label(LabelInfo::primary("good", Address::new(0x1000)));

        let action = EditLabelAction::new(Address::new(0x1000), "good", "123");
        assert!(action.execute(&mut mgr, &mut history, 1000, "user").is_err());
    }

    #[test]
    fn test_add_label_action() {
        let action = AddLabelAction::new(Address::new(0x1000), "main", LabelScope::Global);
        assert!(action.is_valid());

        let mut mgr = LabelManager::new();
        let mut history = LabelHistory::new();
        action.execute(&mut mgr, &mut history, 1000, "user").unwrap();
        assert_eq!(mgr.get_label_name(Address::new(0x1000)), Some("main"));
    }

    #[test]
    fn test_remove_label_action() {
        let mut mgr = LabelManager::new();
        let mut history = LabelHistory::new();
        mgr.add_label(LabelInfo::primary("main", Address::new(0x1000)));

        let action = RemoveLabelAction::new(Address::new(0x1000), "main");
        action.execute(&mut mgr, &mut history, 1000, "user").unwrap();
        assert!(mgr.get_labels_at(Address::new(0x1000)).is_empty());
        assert_eq!(history.total_entries(), 1);
    }

    #[test]
    fn test_remove_label_not_found() {
        let mut mgr = LabelManager::new();
        let mut history = LabelHistory::new();

        let action = RemoveLabelAction::new(Address::new(0x1000), "missing");
        assert!(action.execute(&mut mgr, &mut history, 1000, "user").is_err());
    }

    #[test]
    fn test_set_operand_label_action() {
        let action = SetOperandLabelAction::new(Address::new(0x1000), 0, "operand_label");
        assert!(action.is_valid());
        assert_eq!(action.operand_index, 0);
    }

    #[test]
    fn test_label_mgr_plugin() {
        let mut plugin = LabelMgrPlugin::new();
        assert!(!plugin.is_disposed());

        plugin
            .add_label(
                Address::new(0x1000),
                "main",
                LabelScope::Global,
                1000,
                "user",
            )
            .unwrap();
        assert_eq!(
            plugin.manager.get_label_name(Address::new(0x1000)),
            Some("main")
        );

        plugin
            .rename_label(Address::new(0x1000), "main", "entry", 2000, "user")
            .unwrap();
        assert_eq!(
            plugin.manager.get_label_name(Address::new(0x1000)),
            Some("entry")
        );

        let history = plugin.get_history(Address::new(0x1000));
        assert_eq!(history.len(), 2); // created + renamed

        plugin
            .remove_label(Address::new(0x1000), "entry", 3000, "user")
            .unwrap();
        let history = plugin.get_history(Address::new(0x1000));
        assert_eq!(history.len(), 3); // created + renamed + deleted

        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_all_history_action() {
        let mut history = LabelHistory::new();
        history.record_created(Address::new(0x1000), "a", 1000, "u");
        history.record_created(Address::new(0x2000), "b", 2000, "u");
        assert_eq!(AllHistoryAction::get_all_entries(&history), 2);
    }

    #[test]
    fn test_label_history_table_clear() {
        let mut table = LabelHistoryTable::new();
        table.add_entry(LabelHistoryEntry::created(
            Address::new(0x1000),
            "main",
            1000,
            "user",
        ));
        assert_eq!(table.entry_count(), 1);
        table.clear();
        assert_eq!(table.entry_count(), 0);
    }
}
