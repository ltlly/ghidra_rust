//! Data type association actions.
//!
//! Ported from the `ghidra.app.plugin.core.datamgr.actions.associate`
//! Java package.
//!
//! When a data type in a program was originally imported from an archive
//! (e.g., a standard C library), an *association* tracks the link between
//! the program's copy and the archive's original.  This module provides
//! actions for managing those associations:
//!
//! - **Sync** -- check for differences between the program and archive copies
//! - **Commit** -- push local changes back to the archive
//! - **Revert** -- discard local changes and restore the archive version
//! - **Update** -- pull archive changes into the program
//! - **Disassociate** -- sever the link entirely

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// AssociationState
// ---------------------------------------------------------------------------

/// The synchronization state of a data type association.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssociationState {
    /// The program and archive copies are identical.
    Synchronized,
    /// The program copy has been modified locally.
    ModifiedLocally,
    /// The archive copy has been updated since last sync.
    ArchiveUpdated,
    /// Both the program and archive copies have changed (conflict).
    Conflict,
    /// The data type has been disassociated.
    Disassociated,
    /// The association is new (type was just created).
    New,
}

impl AssociationState {
    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Synchronized => "Synchronized",
            Self::ModifiedLocally => "Modified Locally",
            Self::ArchiveUpdated => "Archive Updated",
            Self::Conflict => "Conflict",
            Self::Disassociated => "Disassociated",
            Self::New => "New",
        }
    }

    /// Whether this state allows committing changes.
    pub fn can_commit(&self) -> bool {
        matches!(self, Self::ModifiedLocally)
    }

    /// Whether this state allows reverting to archive version.
    pub fn can_revert(&self) -> bool {
        matches!(self, Self::ModifiedLocally | Self::Conflict)
    }

    /// Whether this state allows updating from the archive.
    pub fn can_update(&self) -> bool {
        matches!(self, Self::ArchiveUpdated | Self::Conflict)
    }

    /// Whether this state allows disassociating.
    pub fn can_disassociate(&self) -> bool {
        !matches!(self, Self::Disassociated | Self::New)
    }
}

impl std::fmt::Display for AssociationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// DataTypeAssociation
// ---------------------------------------------------------------------------

/// An association between a program data type and its source archive.
///
/// Ported from the association model classes in the
/// `ghidra.app.plugin.core.datamgr.actions.associate` package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataTypeAssociation {
    /// The name of the data type.
    pub type_name: String,
    /// The category path in the program.
    pub program_category_path: String,
    /// The category path in the archive.
    pub archive_category_path: String,
    /// The source archive name.
    pub archive_name: String,
    /// The current synchronization state.
    pub state: AssociationState,
    /// The last time this association was checked (epoch millis).
    pub last_checked: u64,
    /// Whether the program type has been modified since last sync.
    pub program_modified: bool,
    /// Whether the archive type has been modified since last sync.
    pub archive_modified: bool,
}

impl DataTypeAssociation {
    /// Create a new association.
    pub fn new(
        type_name: impl Into<String>,
        archive_name: impl Into<String>,
    ) -> Self {
        Self {
            type_name: type_name.into(),
            program_category_path: String::new(),
            archive_category_path: String::new(),
            archive_name: archive_name.into(),
            state: AssociationState::New,
            last_checked: 0,
            program_modified: false,
            archive_modified: false,
        }
    }

    /// The full path in the program.
    pub fn program_full_path(&self) -> String {
        if self.program_category_path.is_empty() || self.program_category_path == "/" {
            format!("/{}", self.type_name)
        } else {
            format!("{}/{}", self.program_category_path, self.type_name)
        }
    }

    /// The full path in the archive.
    pub fn archive_full_path(&self) -> String {
        if self.archive_category_path.is_empty() || self.archive_category_path == "/" {
            format!("/{}", self.type_name)
        } else {
            format!("{}/{}", self.archive_category_path, self.type_name)
        }
    }
}

// ---------------------------------------------------------------------------
// AssociationManager
// ---------------------------------------------------------------------------

/// Manages data type associations between a program and its source archives.
///
/// Ported from the synchronization and action infrastructure in
/// `ghidra.app.plugin.core.datamgr.actions.associate`.
///
/// # Example
///
/// ```
/// use ghidra_features::datamgr::associate::*;
///
/// let mut mgr = AssociationManager::new();
/// let mut assoc = DataTypeAssociation::new("time_t", "clib.gdt");
/// assoc.state = AssociationState::Synchronized;
/// mgr.add_association(assoc);
///
/// let synced = mgr.associations_in_state(AssociationState::Synchronized);
/// assert_eq!(synced.len(), 1);
/// ```
#[derive(Debug, Clone)]
pub struct AssociationManager {
    /// All associations: (type_name, archive_name) -> association.
    associations: HashMap<(String, String), DataTypeAssociation>,
    /// Events log.
    events: Vec<String>,
}

impl AssociationManager {
    /// Create a new empty association manager.
    pub fn new() -> Self {
        Self {
            associations: HashMap::new(),
            events: Vec::new(),
        }
    }

    /// Add an association.
    pub fn add_association(&mut self, assoc: DataTypeAssociation) {
        let key = (assoc.type_name.clone(), assoc.archive_name.clone());
        self.associations.insert(key, assoc);
    }

    /// Get an association by type name and archive name.
    pub fn get_association(
        &self,
        type_name: &str,
        archive_name: &str,
    ) -> Option<&DataTypeAssociation> {
        self.associations
            .get(&(type_name.to_string(), archive_name.to_string()))
    }

    /// Get a mutable reference to an association.
    pub fn get_association_mut(
        &mut self,
        type_name: &str,
        archive_name: &str,
    ) -> Option<&mut DataTypeAssociation> {
        self.associations
            .get_mut(&(type_name.to_string(), archive_name.to_string()))
    }

    /// Get all associations.
    pub fn all_associations(&self) -> Vec<&DataTypeAssociation> {
        self.associations.values().collect()
    }

    /// Get associations in a specific state.
    pub fn associations_in_state(
        &self,
        state: AssociationState,
    ) -> Vec<&DataTypeAssociation> {
        self.associations
            .values()
            .filter(|a| a.state == state)
            .collect()
    }

    /// Get associations from a specific archive.
    pub fn associations_for_archive(
        &self,
        archive_name: &str,
    ) -> Vec<&DataTypeAssociation> {
        self.associations
            .values()
            .filter(|a| a.archive_name == archive_name)
            .collect()
    }

    /// Commit local changes to the archive.
    ///
    /// Only works for associations in `ModifiedLocally` state.
    pub fn commit(
        &mut self,
        type_name: &str,
        archive_name: &str,
    ) -> Result<String, String> {
        let key = (type_name.to_string(), archive_name.to_string());
        let assoc = self
            .associations
            .get_mut(&key)
            .ok_or_else(|| format!("Association not found: {}/{}", archive_name, type_name))?;

        if !assoc.state.can_commit() {
            return Err(format!(
                "Cannot commit in state '{}'",
                assoc.state.label()
            ));
        }

        assoc.state = AssociationState::Synchronized;
        assoc.program_modified = false;
        assoc.last_checked = current_time_millis();

        let msg = format!("Committed '{}' to archive '{}'", type_name, archive_name);
        self.events.push(msg.clone());
        Ok(msg)
    }

    /// Revert local changes to the archive version.
    pub fn revert(
        &mut self,
        type_name: &str,
        archive_name: &str,
    ) -> Result<String, String> {
        let key = (type_name.to_string(), archive_name.to_string());
        let assoc = self
            .associations
            .get_mut(&key)
            .ok_or_else(|| format!("Association not found: {}/{}", archive_name, type_name))?;

        if !assoc.state.can_revert() {
            return Err(format!(
                "Cannot revert in state '{}'",
                assoc.state.label()
            ));
        }

        assoc.state = AssociationState::Synchronized;
        assoc.program_modified = false;
        assoc.last_checked = current_time_millis();

        let msg = format!(
            "Reverted '{}' to archive version from '{}'",
            type_name, archive_name
        );
        self.events.push(msg.clone());
        Ok(msg)
    }

    /// Update from the archive.
    pub fn update(
        &mut self,
        type_name: &str,
        archive_name: &str,
    ) -> Result<String, String> {
        let key = (type_name.to_string(), archive_name.to_string());
        let assoc = self
            .associations
            .get_mut(&key)
            .ok_or_else(|| format!("Association not found: {}/{}", archive_name, type_name))?;

        if !assoc.state.can_update() {
            return Err(format!(
                "Cannot update in state '{}'",
                assoc.state.label()
            ));
        }

        assoc.state = AssociationState::Synchronized;
        assoc.archive_modified = false;
        assoc.last_checked = current_time_millis();

        let msg = format!(
            "Updated '{}' from archive '{}'",
            type_name, archive_name
        );
        self.events.push(msg.clone());
        Ok(msg)
    }

    /// Disassociate a data type from its archive.
    pub fn disassociate(
        &mut self,
        type_name: &str,
        archive_name: &str,
    ) -> Result<String, String> {
        let key = (type_name.to_string(), archive_name.to_string());
        let assoc = self
            .associations
            .get_mut(&key)
            .ok_or_else(|| format!("Association not found: {}/{}", archive_name, type_name))?;

        if !assoc.state.can_disassociate() {
            return Err(format!(
                "Cannot disassociate in state '{}'",
                assoc.state.label()
            ));
        }

        assoc.state = AssociationState::Disassociated;

        let msg = format!(
            "Disassociated '{}' from archive '{}'",
            type_name, archive_name
        );
        self.events.push(msg.clone());
        Ok(msg)
    }

    /// Remove an association entirely.
    pub fn remove(
        &mut self,
        type_name: &str,
        archive_name: &str,
    ) -> bool {
        self.associations
            .remove(&(type_name.to_string(), archive_name.to_string()))
            .is_some()
    }

    /// Get the total number of associations.
    pub fn count(&self) -> usize {
        self.associations.len()
    }

    /// Get the event log.
    pub fn events(&self) -> &[String] {
        &self.events
    }

    /// Get a summary of association states.
    pub fn state_summary(&self) -> HashMap<AssociationState, usize> {
        let mut summary = HashMap::new();
        for assoc in self.associations.values() {
            *summary.entry(assoc.state).or_insert(0) += 1;
        }
        summary
    }

    /// Simulate a sync check (update states based on modification flags).
    pub fn sync_check(&mut self) {
        for assoc in self.associations.values_mut() {
            if assoc.state == AssociationState::Disassociated
                || assoc.state == AssociationState::New
            {
                continue;
            }

            assoc.state = match (assoc.program_modified, assoc.archive_modified) {
                (false, false) => AssociationState::Synchronized,
                (true, false) => AssociationState::ModifiedLocally,
                (false, true) => AssociationState::ArchiveUpdated,
                (true, true) => AssociationState::Conflict,
            };
            assoc.last_checked = current_time_millis();
        }
        self.events.push("Sync check completed".to_string());
    }
}

impl Default for AssociationManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Simulated current time in milliseconds.
fn current_time_millis() -> u64 {
    // In a real implementation, this would use System.currentTimeMillis().
    // For the port, we use a simple counter or timestamp.
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_association_state_labels() {
        assert_eq!(AssociationState::Synchronized.label(), "Synchronized");
        assert_eq!(AssociationState::ModifiedLocally.label(), "Modified Locally");
        assert_eq!(AssociationState::Conflict.label(), "Conflict");
    }

    #[test]
    fn test_association_state_permissions() {
        assert!(AssociationState::ModifiedLocally.can_commit());
        assert!(!AssociationState::Synchronized.can_commit());

        assert!(AssociationState::ModifiedLocally.can_revert());
        assert!(AssociationState::Conflict.can_revert());
        assert!(!AssociationState::Synchronized.can_revert());

        assert!(AssociationState::ArchiveUpdated.can_update());
        assert!(AssociationState::Conflict.can_update());
        assert!(!AssociationState::Synchronized.can_update());

        assert!(AssociationState::Synchronized.can_disassociate());
        assert!(!AssociationState::Disassociated.can_disassociate());
    }

    #[test]
    fn test_association_paths() {
        let mut assoc = DataTypeAssociation::new("time_t", "clib.gdt");
        assoc.program_category_path = "/Standard".to_string();
        assoc.archive_category_path = "/".to_string();
        assert_eq!(assoc.program_full_path(), "/Standard/time_t");
        assert_eq!(assoc.archive_full_path(), "/time_t");
    }

    #[test]
    fn test_association_manager_add_get() {
        let mut mgr = AssociationManager::new();
        let mut assoc = DataTypeAssociation::new("int", "builtin.gdt");
        assoc.state = AssociationState::Synchronized;
        mgr.add_association(assoc);

        assert_eq!(mgr.count(), 1);
        let got = mgr.get_association("int", "builtin.gdt").unwrap();
        assert_eq!(got.state, AssociationState::Synchronized);
    }

    #[test]
    fn test_association_manager_by_state() {
        let mut mgr = AssociationManager::new();

        let mut a1 = DataTypeAssociation::new("int", "archive.gdt");
        a1.state = AssociationState::Synchronized;
        mgr.add_association(a1);

        let mut a2 = DataTypeAssociation::new("float", "archive.gdt");
        a2.state = AssociationState::ModifiedLocally;
        mgr.add_association(a2);

        assert_eq!(
            mgr.associations_in_state(AssociationState::Synchronized).len(),
            1
        );
        assert_eq!(
            mgr.associations_in_state(AssociationState::ModifiedLocally).len(),
            1
        );
    }

    #[test]
    fn test_commit() {
        let mut mgr = AssociationManager::new();
        let mut assoc = DataTypeAssociation::new("my_type", "archive.gdt");
        assoc.state = AssociationState::ModifiedLocally;
        mgr.add_association(assoc);

        let result = mgr.commit("my_type", "archive.gdt");
        assert!(result.is_ok());

        let assoc = mgr.get_association("my_type", "archive.gdt").unwrap();
        assert_eq!(assoc.state, AssociationState::Synchronized);
    }

    #[test]
    fn test_commit_wrong_state() {
        let mut mgr = AssociationManager::new();
        let assoc = DataTypeAssociation::new("my_type", "archive.gdt");
        mgr.add_association(assoc);

        let result = mgr.commit("my_type", "archive.gdt");
        assert!(result.is_err());
    }

    #[test]
    fn test_revert() {
        let mut mgr = AssociationManager::new();
        let mut assoc = DataTypeAssociation::new("my_type", "archive.gdt");
        assoc.state = AssociationState::Conflict;
        mgr.add_association(assoc);

        let result = mgr.revert("my_type", "archive.gdt");
        assert!(result.is_ok());

        let assoc = mgr.get_association("my_type", "archive.gdt").unwrap();
        assert_eq!(assoc.state, AssociationState::Synchronized);
    }

    #[test]
    fn test_update() {
        let mut mgr = AssociationManager::new();
        let mut assoc = DataTypeAssociation::new("my_type", "archive.gdt");
        assoc.state = AssociationState::ArchiveUpdated;
        mgr.add_association(assoc);

        let result = mgr.update("my_type", "archive.gdt");
        assert!(result.is_ok());

        let assoc = mgr.get_association("my_type", "archive.gdt").unwrap();
        assert_eq!(assoc.state, AssociationState::Synchronized);
    }

    #[test]
    fn test_disassociate() {
        let mut mgr = AssociationManager::new();
        let mut assoc = DataTypeAssociation::new("my_type", "archive.gdt");
        assoc.state = AssociationState::Synchronized;
        mgr.add_association(assoc);

        let result = mgr.disassociate("my_type", "archive.gdt");
        assert!(result.is_ok());

        let assoc = mgr.get_association("my_type", "archive.gdt").unwrap();
        assert_eq!(assoc.state, AssociationState::Disassociated);
    }

    #[test]
    fn test_remove() {
        let mut mgr = AssociationManager::new();
        let assoc = DataTypeAssociation::new("int", "archive.gdt");
        mgr.add_association(assoc);
        assert_eq!(mgr.count(), 1);

        assert!(mgr.remove("int", "archive.gdt"));
        assert_eq!(mgr.count(), 0);
        assert!(!mgr.remove("int", "archive.gdt"));
    }

    #[test]
    fn test_not_found() {
        let mgr = AssociationManager::new();
        assert!(mgr.get_association("nonexistent", "archive.gdt").is_none());
    }

    #[test]
    fn test_by_archive() {
        let mut mgr = AssociationManager::new();
        let mut a1 = DataTypeAssociation::new("int", "archive1.gdt");
        a1.state = AssociationState::Synchronized;
        mgr.add_association(a1);
        let mut a2 = DataTypeAssociation::new("float", "archive2.gdt");
        a2.state = AssociationState::Synchronized;
        mgr.add_association(a2);

        assert_eq!(mgr.associations_for_archive("archive1.gdt").len(), 1);
        assert_eq!(mgr.associations_for_archive("archive2.gdt").len(), 1);
    }

    #[test]
    fn test_sync_check() {
        let mut mgr = AssociationManager::new();

        let mut a1 = DataTypeAssociation::new("int", "archive.gdt");
        a1.state = AssociationState::Synchronized;
        a1.program_modified = true;
        mgr.add_association(a1);

        let mut a2 = DataTypeAssociation::new("float", "archive.gdt");
        a2.state = AssociationState::Synchronized;
        a2.archive_modified = true;
        mgr.add_association(a2);

        let mut a3 = DataTypeAssociation::new("char", "archive.gdt");
        a3.state = AssociationState::Synchronized;
        a3.program_modified = true;
        a3.archive_modified = true;
        mgr.add_association(a3);

        mgr.sync_check();

        assert_eq!(
            mgr.get_association("int", "archive.gdt").unwrap().state,
            AssociationState::ModifiedLocally
        );
        assert_eq!(
            mgr.get_association("float", "archive.gdt").unwrap().state,
            AssociationState::ArchiveUpdated
        );
        assert_eq!(
            mgr.get_association("char", "archive.gdt").unwrap().state,
            AssociationState::Conflict
        );
    }

    #[test]
    fn test_state_summary() {
        let mut mgr = AssociationManager::new();

        let mut a1 = DataTypeAssociation::new("a", "archive.gdt");
        a1.state = AssociationState::Synchronized;
        mgr.add_association(a1);

        let mut a2 = DataTypeAssociation::new("b", "archive.gdt");
        a2.state = AssociationState::Synchronized;
        mgr.add_association(a2);

        let mut a3 = DataTypeAssociation::new("c", "archive.gdt");
        a3.state = AssociationState::ModifiedLocally;
        mgr.add_association(a3);

        let summary = mgr.state_summary();
        assert_eq!(summary.get(&AssociationState::Synchronized), Some(&2));
        assert_eq!(summary.get(&AssociationState::ModifiedLocally), Some(&1));
    }

    #[test]
    fn test_events() {
        let mut mgr = AssociationManager::new();
        let mut assoc = DataTypeAssociation::new("my_type", "archive.gdt");
        assoc.state = AssociationState::ModifiedLocally;
        mgr.add_association(assoc);

        mgr.commit("my_type", "archive.gdt").unwrap();
        assert!(!mgr.events().is_empty());
    }
}
