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

// ---------------------------------------------------------------------------
// SyncAction -- abstract base for sync operations
// ---------------------------------------------------------------------------

/// The kind of synchronization operation.
///
/// Ported from the `SyncAction` abstract class and its concrete
/// subclasses in `ghidra.app.plugin.core.datamgr.actions.associate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SyncOperation {
    /// Push local changes back to the source archive.
    Commit,
    /// Pull archive changes into the program.
    Update,
    /// Discard local changes and revert to the archive version.
    Revert,
    /// Sever the association link entirely.
    Disassociate,
}

impl SyncOperation {
    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Commit => "Commit",
            Self::Update => "Update",
            Self::Revert => "Revert",
            Self::Disassociate => "Disassociate",
        }
    }

    /// The menu order for this operation (used for sorting in UI).
    pub fn menu_order(&self) -> u32 {
        match self {
            Self::Commit => 1,
            Self::Update => 2,
            Self::Revert => 3,
            Self::Disassociate => 4,
        }
    }

    /// Check whether this operation is appropriate for the given state.
    pub fn is_appropriate(&self, state: AssociationState) -> bool {
        match self {
            Self::Commit => state.can_commit(),
            Self::Update => state.can_update(),
            Self::Revert => state.can_revert(),
            Self::Disassociate => state.can_disassociate(),
        }
    }

    /// The confirmation message for this operation.
    pub fn confirmation_message(&self, count: usize) -> String {
        match self {
            Self::Commit => format!("Commit {} data type(s) to archive?", count),
            Self::Update => format!("Update {} data type(s) from archive?", count),
            Self::Revert => format!("Revert {} data type(s) to archive version?", count),
            Self::Disassociate => format!("Disassociate {} data type(s) from archive?", count),
        }
    }

    /// The help topic for this operation.
    pub fn help_topic(&self) -> &'static str {
        match self {
            Self::Commit => "Commit_Data_Types",
            Self::Update => "Update_Data_Types",
            Self::Revert => "Revert_Data_Types",
            Self::Disassociate => "Disassociate_Data_Types",
        }
    }

    /// Window title for the confirmation dialog.
    pub fn title(&self, source_name: &str, client_name: &str) -> String {
        match self {
            Self::Commit => format!(
                "Commit Datatype Changes In \"{}\" To Archive \"{}\"", client_name, source_name
            ),
            Self::Update => format!(
                "Update Datatype Changes From Archive \"{}\" To \"{}\"", source_name, client_name
            ),
            Self::Revert => format!(
                "Revert Datatype Changes In \"{}\" From Archive \"{}\"", client_name, source_name
            ),
            Self::Disassociate => format!(
                "Disassociate Data Types From Archive \"{}\"", source_name
            ),
        }
    }

    /// Menu label including the source archive name.
    pub fn menu_label(&self, source_name: &str) -> String {
        match self {
            Self::Commit => format!("Commit Data Types To/{}", source_name),
            Self::Update => format!("Update Data Types From/{}", source_name),
            Self::Revert => format!("Revert Data Types From/{}", source_name),
            Self::Disassociate => format!("Disassociate From/{}", source_name),
        }
    }
}

impl std::fmt::Display for SyncOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// SyncActionResult -- result of executing a sync action
// ---------------------------------------------------------------------------

/// Result of executing a sync action on one or more data types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncActionResult {
    /// The operation that was performed.
    pub operation: SyncOperation,
    /// The archive name involved.
    pub archive_name: String,
    /// Names of data types that were processed.
    pub processed_types: Vec<String>,
    /// Any error messages encountered.
    pub errors: Vec<String>,
    /// Whether the operation succeeded for all types.
    pub all_succeeded: bool,
}

impl SyncActionResult {
    /// Create a successful result.
    pub fn success(operation: SyncOperation, archive_name: impl Into<String>, types: Vec<String>) -> Self {
        let count = types.len();
        Self {
            operation,
            archive_name: archive_name.into(),
            processed_types: types,
            errors: Vec::new(),
            all_succeeded: true,
        }
    }

    /// Create a result with errors.
    pub fn with_errors(
        operation: SyncOperation,
        archive_name: impl Into<String>,
        types: Vec<String>,
        errors: Vec<String>,
    ) -> Self {
        Self {
            operation,
            archive_name: archive_name.into(),
            processed_types: types,
            errors,
            all_succeeded: false,
        }
    }

    /// Summary message.
    pub fn summary(&self) -> String {
        if self.all_succeeded {
            format!(
                "{}: {} type(s) processed successfully",
                self.operation.label(),
                self.processed_types.len()
            )
        } else {
            format!(
                "{}: {} type(s) processed, {} error(s)",
                self.operation.label(),
                self.processed_types.len(),
                self.errors.len()
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Batch sync operations
// ---------------------------------------------------------------------------

/// Execute a batch commit operation on associations in the given state.
pub fn batch_commit(mgr: &mut AssociationManager, archive_name: &str) -> SyncActionResult {
    let to_commit: Vec<String> = mgr
        .associations_for_archive(archive_name)
        .iter()
        .filter(|a| a.state.can_commit())
        .map(|a| a.type_name.clone())
        .collect();

    let mut errors = Vec::new();
    for type_name in &to_commit {
        if let Err(e) = mgr.commit(type_name, archive_name) {
            errors.push(e);
        }
    }

    if errors.is_empty() {
        SyncActionResult::success(SyncOperation::Commit, archive_name, to_commit)
    } else {
        SyncActionResult::with_errors(SyncOperation::Commit, archive_name, to_commit, errors)
    }
}

/// Execute a batch update operation.
pub fn batch_update(mgr: &mut AssociationManager, archive_name: &str) -> SyncActionResult {
    let to_update: Vec<String> = mgr
        .associations_for_archive(archive_name)
        .iter()
        .filter(|a| a.state.can_update())
        .map(|a| a.type_name.clone())
        .collect();

    let mut errors = Vec::new();
    for type_name in &to_update {
        if let Err(e) = mgr.update(type_name, archive_name) {
            errors.push(e);
        }
    }

    if errors.is_empty() {
        SyncActionResult::success(SyncOperation::Update, archive_name, to_update)
    } else {
        SyncActionResult::with_errors(SyncOperation::Update, archive_name, to_update, errors)
    }
}

/// Execute a batch revert operation.
pub fn batch_revert(mgr: &mut AssociationManager, archive_name: &str) -> SyncActionResult {
    let to_revert: Vec<String> = mgr
        .associations_for_archive(archive_name)
        .iter()
        .filter(|a| a.state.can_revert())
        .map(|a| a.type_name.clone())
        .collect();

    let mut errors = Vec::new();
    for type_name in &to_revert {
        if let Err(e) = mgr.revert(type_name, archive_name) {
            errors.push(e);
        }
    }

    if errors.is_empty() {
        SyncActionResult::success(SyncOperation::Revert, archive_name, to_revert)
    } else {
        SyncActionResult::with_errors(SyncOperation::Revert, archive_name, to_revert, errors)
    }
}

/// Execute a batch disassociate operation.
pub fn batch_disassociate(mgr: &mut AssociationManager, archive_name: &str) -> SyncActionResult {
    let to_dis: Vec<String> = mgr
        .associations_for_archive(archive_name)
        .iter()
        .filter(|a| a.state.can_disassociate())
        .map(|a| a.type_name.clone())
        .collect();

    let mut errors = Vec::new();
    for type_name in &to_dis {
        if let Err(e) = mgr.disassociate(type_name, archive_name) {
            errors.push(e);
        }
    }

    if errors.is_empty() {
        SyncActionResult::success(SyncOperation::Disassociate, archive_name, to_dis)
    } else {
        SyncActionResult::with_errors(SyncOperation::Disassociate, archive_name, to_dis, errors)
    }
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

    // -- SyncOperation tests --

    #[test]
    fn test_sync_operation_labels() {
        assert_eq!(SyncOperation::Commit.label(), "Commit");
        assert_eq!(SyncOperation::Update.label(), "Update");
        assert_eq!(SyncOperation::Revert.label(), "Revert");
        assert_eq!(SyncOperation::Disassociate.label(), "Disassociate");
    }

    #[test]
    fn test_sync_operation_menu_order() {
        assert!(SyncOperation::Commit.menu_order() < SyncOperation::Update.menu_order());
        assert!(SyncOperation::Update.menu_order() < SyncOperation::Revert.menu_order());
    }

    #[test]
    fn test_sync_operation_is_appropriate() {
        assert!(SyncOperation::Commit.is_appropriate(AssociationState::ModifiedLocally));
        assert!(!SyncOperation::Commit.is_appropriate(AssociationState::Synchronized));

        assert!(SyncOperation::Update.is_appropriate(AssociationState::ArchiveUpdated));
        assert!(!SyncOperation::Update.is_appropriate(AssociationState::Synchronized));

        assert!(SyncOperation::Revert.is_appropriate(AssociationState::Conflict));
        assert!(!SyncOperation::Revert.is_appropriate(AssociationState::Synchronized));

        assert!(SyncOperation::Disassociate.is_appropriate(AssociationState::Synchronized));
        assert!(!SyncOperation::Disassociate.is_appropriate(AssociationState::Disassociated));
    }

    #[test]
    fn test_sync_operation_confirmation_message() {
        let msg = SyncOperation::Commit.confirmation_message(5);
        assert!(msg.contains("5"));
        assert!(msg.contains("Commit"));
    }

    #[test]
    fn test_sync_operation_help_topic() {
        assert_eq!(SyncOperation::Commit.help_topic(), "Commit_Data_Types");
        assert_eq!(SyncOperation::Revert.help_topic(), "Revert_Data_Types");
    }

    #[test]
    fn test_sync_operation_title() {
        let title = SyncOperation::Commit.title("clib.gdt", "my_program");
        assert!(title.contains("clib.gdt"));
        assert!(title.contains("my_program"));
    }

    #[test]
    fn test_sync_operation_menu_label() {
        let label = SyncOperation::Update.menu_label("clib.gdt");
        assert!(label.contains("clib.gdt"));
        assert!(label.contains("Update"));
    }

    #[test]
    fn test_sync_operation_display() {
        assert_eq!(format!("{}", SyncOperation::Commit), "Commit");
    }

    // -- SyncActionResult tests --

    #[test]
    fn test_sync_action_result_success() {
        let result = SyncActionResult::success(
            SyncOperation::Commit,
            "archive.gdt",
            vec!["int".to_string(), "float".to_string()],
        );
        assert!(result.all_succeeded);
        assert!(result.errors.is_empty());
        assert_eq!(result.processed_types.len(), 2);
    }

    #[test]
    fn test_sync_action_result_with_errors() {
        let result = SyncActionResult::with_errors(
            SyncOperation::Update,
            "archive.gdt",
            vec!["int".to_string()],
            vec!["error 1".to_string()],
        );
        assert!(!result.all_succeeded);
        assert_eq!(result.errors.len(), 1);
    }

    #[test]
    fn test_sync_action_result_summary() {
        let result = SyncActionResult::success(
            SyncOperation::Commit,
            "archive.gdt",
            vec!["a".to_string(), "b".to_string()],
        );
        let summary = result.summary();
        assert!(summary.contains("Commit"));
        assert!(summary.contains("2"));
    }

    // -- Batch operation tests --

    #[test]
    fn test_batch_commit() {
        let mut mgr = AssociationManager::new();
        let mut a1 = DataTypeAssociation::new("int", "archive.gdt");
        a1.state = AssociationState::ModifiedLocally;
        mgr.add_association(a1);

        let mut a2 = DataTypeAssociation::new("float", "archive.gdt");
        a2.state = AssociationState::Synchronized;
        mgr.add_association(a2);

        let result = batch_commit(&mut mgr, "archive.gdt");
        assert!(result.all_succeeded);
        assert_eq!(result.processed_types.len(), 1);
        assert_eq!(
            mgr.get_association("int", "archive.gdt").unwrap().state,
            AssociationState::Synchronized
        );
    }

    #[test]
    fn test_batch_update() {
        let mut mgr = AssociationManager::new();
        let mut a1 = DataTypeAssociation::new("int", "archive.gdt");
        a1.state = AssociationState::ArchiveUpdated;
        mgr.add_association(a1);

        let result = batch_update(&mut mgr, "archive.gdt");
        assert!(result.all_succeeded);
        assert_eq!(result.processed_types.len(), 1);
    }

    #[test]
    fn test_batch_revert() {
        let mut mgr = AssociationManager::new();
        let mut a1 = DataTypeAssociation::new("int", "archive.gdt");
        a1.state = AssociationState::Conflict;
        mgr.add_association(a1);

        let result = batch_revert(&mut mgr, "archive.gdt");
        assert!(result.all_succeeded);
        assert_eq!(result.processed_types.len(), 1);
    }

    #[test]
    fn test_batch_disassociate() {
        let mut mgr = AssociationManager::new();
        let mut a1 = DataTypeAssociation::new("int", "archive.gdt");
        a1.state = AssociationState::Synchronized;
        mgr.add_association(a1);

        let result = batch_disassociate(&mut mgr, "archive.gdt");
        assert!(result.all_succeeded);
        assert_eq!(result.processed_types.len(), 1);
        assert_eq!(
            mgr.get_association("int", "archive.gdt").unwrap().state,
            AssociationState::Disassociated
        );
    }

    #[test]
    fn test_batch_empty_archive() {
        let mut mgr = AssociationManager::new();
        let result = batch_commit(&mut mgr, "empty.gdt");
        assert!(result.all_succeeded);
        assert_eq!(result.processed_types.len(), 0);
    }
}
