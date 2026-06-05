//! Label Management -- create, rename, and manage labels.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.label` Java package.
//!
//! Provides the logic for creating, renaming, and managing labels at addresses
//! in a program's listing. Includes support for primary/secondary labels,
//! label scoping (global vs. local), and name validation.
//!
//! # Architecture
//!
//! - [`LabelInfo`] -- metadata about a label (name, address, scope, primary).
//! - [`LabelManager`] -- manages label CRUD operations.
//! - [`LabelValidator`] -- validates label names against naming rules.
//! - [`LabelScope`] -- the visibility scope of a label.

/// Label history tracking, label manager plugin, and edit label actions.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.label` Java package.
pub mod history;

/// Symbol chooser -- search and select symbols from the program's symbol table.
///
/// Ported from `ghidra.app.plugin.core.label.SymbolChooserDialog`.
pub mod symbol_chooser;

use ghidra_core::Address;
use std::collections::BTreeMap;

// ============================================================================
// LabelScope -- visibility scope
// ============================================================================

/// The visibility scope of a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LabelScope {
    /// Globally visible label.
    Global,
    /// Local to the current function.
    Local,
    /// Default scope (platform-dependent).
    Default,
}

// ============================================================================
// LabelInfo -- a single label's metadata
// ============================================================================

/// Metadata for a label at an address.
#[derive(Debug, Clone)]
pub struct LabelInfo {
    /// The label name.
    pub name: String,
    /// The address this label applies to.
    pub address: Address,
    /// The scope of this label.
    pub scope: LabelScope,
    /// Whether this is the primary label at the address.
    pub primary: bool,
}

impl LabelInfo {
    /// Create a new label.
    pub fn new(name: impl Into<String>, address: Address, scope: LabelScope) -> Self {
        Self {
            name: name.into(),
            address,
            scope,
            primary: true,
        }
    }

    /// Create a primary label.
    pub fn primary(name: impl Into<String>, address: Address) -> Self {
        Self::new(name, address, LabelScope::Global)
    }

    /// Create a local label.
    pub fn local(name: impl Into<String>, address: Address) -> Self {
        Self::new(name, address, LabelScope::Local)
    }
}

// ============================================================================
// LabelManager -- manages labels in a program
// ============================================================================

/// Manages labels for a program's listing.
#[derive(Debug, Default)]
pub struct LabelManager {
    /// All labels, indexed by address offset.
    labels: BTreeMap<u64, Vec<LabelInfo>>,
}

impl LabelManager {
    /// Create a new empty label manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a label at an address.
    pub fn add_label(&mut self, label: LabelInfo) {
        let entry = self.labels.entry(label.address.offset).or_default();

        // If adding a primary label, demote any existing primary
        if label.primary {
            for existing in entry.iter_mut() {
                if existing.primary {
                    existing.primary = false;
                }
            }
        }

        entry.push(label);
    }

    /// Remove all labels at the given address.
    pub fn remove_labels_at(&mut self, address: Address) -> Vec<LabelInfo> {
        self.labels
            .remove(&address.offset)
            .unwrap_or_default()
    }

    /// Remove a specific label by name at the given address.
    pub fn remove_label(&mut self, address: Address, name: &str) -> Option<LabelInfo> {
        if let Some(labels) = self.labels.get_mut(&address.offset) {
            if let Some(pos) = labels.iter().position(|l| l.name == name) {
                let removed = labels.remove(pos);
                if labels.is_empty() {
                    self.labels.remove(&address.offset);
                }
                return Some(removed);
            }
        }
        None
    }

    /// Rename a label at an address.
    pub fn rename_label(
        &mut self,
        address: Address,
        old_name: &str,
        new_name: &str,
    ) -> Result<(), String> {
        if !LabelValidator::is_valid_label_name(new_name) {
            return Err(format!("Invalid label name: '{}'", new_name));
        }
        if let Some(labels) = self.labels.get_mut(&address.offset) {
            if let Some(label) = labels.iter_mut().find(|l| l.name == old_name) {
                label.name = new_name.to_string();
                return Ok(());
            }
        }
        Err(format!("Label '{}' not found at address {}", old_name, address))
    }

    /// Get all labels at the given address.
    pub fn get_labels_at(&self, address: Address) -> Vec<&LabelInfo> {
        self.labels
            .get(&address.offset)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Get the primary label at the given address.
    pub fn get_primary_label(&self, address: Address) -> Option<&LabelInfo> {
        self.labels
            .get(&address.offset)
            .and_then(|v| v.iter().find(|l| l.primary))
    }

    /// Get the primary label name at the given address.
    pub fn get_label_name(&self, address: Address) -> Option<&str> {
        self.get_primary_label(address).map(|l| l.name.as_str())
    }

    /// Return the total number of label entries (addresses with labels).
    pub fn address_count(&self) -> usize {
        self.labels.len()
    }

    /// Return the total number of individual labels.
    pub fn label_count(&self) -> usize {
        self.labels.values().map(|v| v.len()).sum()
    }
}

// ============================================================================
// LabelValidator -- validates label names
// ============================================================================

/// Validates label names against Ghidra naming rules.
pub struct LabelValidator;

impl LabelValidator {
    /// Check whether the given string is a valid label name.
    ///
    /// Rules:
    /// - Must not be empty.
    /// - Must start with a letter or underscore.
    /// - May contain letters, digits, underscores, and dots.
    pub fn is_valid_label_name(name: &str) -> bool {
        if name.is_empty() {
            return false;
        }
        let first = name.chars().next().unwrap();
        if !first.is_ascii_alphabetic() && first != '_' {
            return false;
        }
        name.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    }

    /// Suggest a valid label name based on the given input.
    pub fn sanitize_label_name(name: &str) -> String {
        let mut result: String = name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '.' { c } else { '_' })
            .collect();

        // Ensure starts with letter or underscore
        if let Some(first) = result.chars().next() {
            if first.is_ascii_digit() {
                result.insert(0, '_');
            }
        }

        if result.is_empty() {
            result = "_label".to_string();
        }

        result
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_get_label() {
        let mut mgr = LabelManager::new();
        mgr.add_label(LabelInfo::primary("main", Address::new(0x1000)));
        let labels = mgr.get_labels_at(Address::new(0x1000));
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].name, "main");
    }

    #[test]
    fn test_primary_label() {
        let mut mgr = LabelManager::new();
        mgr.add_label(LabelInfo::primary("main", Address::new(0x1000)));
        mgr.add_label(LabelInfo {
            name: "alt".into(),
            address: Address::new(0x1000),
            scope: LabelScope::Global,
            primary: false,
        });
        let primary = mgr.get_primary_label(Address::new(0x1000)).unwrap();
        assert_eq!(primary.name, "main");
    }

    #[test]
    fn test_demote_primary_on_new_primary() {
        let mut mgr = LabelManager::new();
        mgr.add_label(LabelInfo::primary("old", Address::new(0x1000)));
        mgr.add_label(LabelInfo::primary("new", Address::new(0x1000)));
        let primary = mgr.get_primary_label(Address::new(0x1000)).unwrap();
        assert_eq!(primary.name, "new");
    }

    #[test]
    fn test_rename_label() {
        let mut mgr = LabelManager::new();
        mgr.add_label(LabelInfo::primary("old_name", Address::new(0x1000)));
        mgr.rename_label(Address::new(0x1000), "old_name", "new_name").unwrap();
        assert_eq!(mgr.get_label_name(Address::new(0x1000)), Some("new_name"));
    }

    #[test]
    fn test_rename_invalid_name() {
        let mut mgr = LabelManager::new();
        mgr.add_label(LabelInfo::primary("good", Address::new(0x1000)));
        assert!(mgr.rename_label(Address::new(0x1000), "good", "123bad").is_err());
    }

    #[test]
    fn test_remove_label() {
        let mut mgr = LabelManager::new();
        mgr.add_label(LabelInfo::primary("test", Address::new(0x1000)));
        let removed = mgr.remove_label(Address::new(0x1000), "test");
        assert!(removed.is_some());
        assert!(mgr.get_labels_at(Address::new(0x1000)).is_empty());
    }

    #[test]
    fn test_remove_labels_at() {
        let mut mgr = LabelManager::new();
        mgr.add_label(LabelInfo::primary("a", Address::new(0x1000)));
        mgr.add_label(LabelInfo::local("b", Address::new(0x1000)));
        let removed = mgr.remove_labels_at(Address::new(0x1000));
        assert_eq!(removed.len(), 2);
    }

    #[test]
    fn test_label_validator_valid() {
        assert!(LabelValidator::is_valid_label_name("main"));
        assert!(LabelValidator::is_valid_label_name("_start"));
        assert!(LabelValidator::is_valid_label_name("FUN_001000"));
        assert!(LabelValidator::is_valid_label_name("lab.local"));
    }

    #[test]
    fn test_label_validator_invalid() {
        assert!(!LabelValidator::is_valid_label_name(""));
        assert!(!LabelValidator::is_valid_label_name("123"));
        assert!(!LabelValidator::is_valid_label_name("no spaces"));
        assert!(!LabelValidator::is_valid_label_name("no-dashes"));
    }

    #[test]
    fn test_sanitize_label_name() {
        assert_eq!(LabelValidator::sanitize_label_name("good"), "good");
        assert_eq!(LabelValidator::sanitize_label_name("123"), "_123");
        assert_eq!(LabelValidator::sanitize_label_name("a-b"), "a_b");
        assert_eq!(LabelValidator::sanitize_label_name(""), "_label");
    }

    #[test]
    fn test_counts() {
        let mut mgr = LabelManager::new();
        mgr.add_label(LabelInfo::primary("a", Address::new(0x1000)));
        mgr.add_label(LabelInfo::primary("b", Address::new(0x2000)));
        mgr.add_label(LabelInfo::local("c", Address::new(0x2000)));
        assert_eq!(mgr.address_count(), 2);
        assert_eq!(mgr.label_count(), 3);
    }
}
