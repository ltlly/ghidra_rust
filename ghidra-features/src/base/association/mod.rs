//! Association management for Ghidra programs.
//!
//! This module ports Ghidra's `ghidra.feature.vt.api.main` association
//! types and `ghidra.feature.vt.api.db.AssociationDatabaseManager` from
//! the Version Tracking feature to Rust. It provides:
//!
//! - [`Association`] -- a mapping between a source and destination address
//! - [`AssociationType`] -- the kind of association (function-to-function, etc.)
//! - [`AssociationStatus`] -- the lifecycle state of an association
//! - [`AssociationManager`] -- manages all associations with indexed lookup
//! - [`AssociationTableAdapter`] -- tabular model for displaying associations
//!
//! # Architecture
//!
//! Associations are the core data structure of Ghidra's Version Tracking
//! feature. An association links an address in one program (the "source")
//! to an address in another program (the "destination"), representing that
//! the two locations correspond semantically (e.g., the same function in
//! two different builds of a binary).
//!
//! The [`AssociationManager`] maintains primary (by ID) and secondary
//! (by source/destination address) indexes for efficient lookup. It
//! supports the full lifecycle: creation, voting, acceptance, rejection,
//! and clearing.

use ghidra_core::addr::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// AssociationType -- the kind of association
// ---------------------------------------------------------------------------

/// The kind of an association.
///
/// Matches Ghidra's `VTAssociationType`. Each type represents a different
/// kind of semantic correspondence between two programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssociationType {
    /// A function-to-function association.
    Function,
    /// A data-to-data association.
    Data,
    /// An external library association.
    ExternalLibrary,
}

impl fmt::Display for AssociationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssociationType::Function => write!(f, "Function"),
            AssociationType::Data => write!(f, "Data"),
            AssociationType::ExternalLibrary => write!(f, "ExternalLibrary"),
        }
    }
}

// ---------------------------------------------------------------------------
// AssociationStatus -- lifecycle state of an association
// ---------------------------------------------------------------------------

/// The lifecycle state of an association.
///
/// Matches Ghidra's `VTAssociationStatus`. The state machine is:
///
/// ```text
///  Available ──accept──> Accepted ──clear──> Available
///      │                   │
///      └──reject──> Rejected ──clear──> Available
///  Available ──block──> Blocked
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssociationStatus {
    /// The association is available for user action.
    Available,
    /// The association has been accepted by the user.
    Accepted,
    /// The association is blocked (conflict with another accepted association).
    Blocked,
    /// The association has been rejected by the user.
    Rejected,
}

impl AssociationStatus {
    /// Whether associations in this state can have markup items applied.
    pub fn can_apply(&self) -> bool {
        matches!(self, AssociationStatus::Accepted | AssociationStatus::Available)
    }

    /// Whether the association is blocked from user action.
    pub fn is_blocked(&self) -> bool {
        matches!(self, AssociationStatus::Blocked | AssociationStatus::Rejected)
    }

    /// Human-readable display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            AssociationStatus::Available => "Available",
            AssociationStatus::Accepted => "Accepted",
            AssociationStatus::Blocked => "Blocked",
            AssociationStatus::Rejected => "Rejected",
        }
    }
}

impl fmt::Display for AssociationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ---------------------------------------------------------------------------
// Association -- a single source-to-destination mapping
// ---------------------------------------------------------------------------

/// A single association between a source and destination address.
///
/// Corresponds to Ghidra's `VTAssociation`. Each association has a unique
/// ID, a type, source and destination addresses, a status, and a vote
/// count that records how many correlators support this match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Association {
    /// Unique identifier.
    id: u64,
    /// The kind of association.
    association_type: AssociationType,
    /// Address in the source program.
    source_address: Address,
    /// Address in the destination program.
    destination_address: Address,
    /// Current lifecycle state.
    status: AssociationStatus,
    /// Number of correlator votes supporting this association.
    vote_count: i32,
    /// Human-readable description of the match source.
    source_description: Option<String>,
}

impl Association {
    /// Create a new association with default (Available) status.
    pub fn new(
        id: u64,
        association_type: AssociationType,
        source_address: Address,
        destination_address: Address,
    ) -> Self {
        Self {
            id,
            association_type,
            source_address,
            destination_address,
            status: AssociationStatus::Available,
            vote_count: 0,
            source_description: None,
        }
    }

    /// The unique ID.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The association type.
    pub fn association_type(&self) -> AssociationType {
        self.association_type
    }

    /// The source address.
    pub fn source_address(&self) -> Address {
        self.source_address
    }

    /// The destination address.
    pub fn destination_address(&self) -> Address {
        self.destination_address
    }

    /// The current status.
    pub fn status(&self) -> AssociationStatus {
        self.status
    }

    /// The vote count.
    pub fn vote_count(&self) -> i32 {
        self.vote_count
    }

    /// Set the vote count.
    pub fn set_vote_count(&mut self, count: i32) {
        self.vote_count = count;
    }

    /// Increment the vote count by one.
    pub fn increment_vote(&mut self) {
        self.vote_count += 1;
    }

    /// Optional source description.
    pub fn source_description(&self) -> Option<&str> {
        self.source_description.as_deref()
    }

    /// Set the source description.
    pub fn set_source_description(&mut self, desc: impl Into<String>) {
        self.source_description = Some(desc.into());
    }

    /// Mark the association as accepted.
    ///
    /// # Errors
    ///
    /// Returns an error if the association is blocked.
    pub fn set_accepted(&mut self) -> Result<(), AssociationError> {
        if self.status.is_blocked() {
            return Err(AssociationError::InvalidStateTransition {
                from: self.status,
                action: "accept".to_string(),
            });
        }
        self.status = AssociationStatus::Accepted;
        Ok(())
    }

    /// Mark the association as rejected.
    ///
    /// # Errors
    ///
    /// Returns an error if the association is already accepted.
    pub fn set_rejected(&mut self) -> Result<(), AssociationError> {
        if self.status == AssociationStatus::Accepted {
            return Err(AssociationError::InvalidStateTransition {
                from: self.status,
                action: "reject".to_string(),
            });
        }
        self.status = AssociationStatus::Rejected;
        Ok(())
    }

    /// Clear the status back to Available.
    ///
    /// # Errors
    ///
    /// Returns an error if the current status is not Accepted or Rejected.
    pub fn clear_status(&mut self) -> Result<(), AssociationError> {
        match self.status {
            AssociationStatus::Accepted | AssociationStatus::Rejected => {
                self.status = AssociationStatus::Available;
                Ok(())
            }
            _ => Err(AssociationError::InvalidStateTransition {
                from: self.status,
                action: "clear".to_string(),
            }),
        }
    }

    /// Block the association (internal, called when a conflicting association
    /// is accepted).
    pub(crate) fn set_blocked(&mut self) {
        if self.status == AssociationStatus::Available {
            self.status = AssociationStatus::Blocked;
        }
    }
}

// ---------------------------------------------------------------------------
// AssociationError
// ---------------------------------------------------------------------------

/// Errors that can occur when manipulating associations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssociationError {
    /// An invalid state transition was attempted.
    InvalidStateTransition {
        /// The current status.
        from: AssociationStatus,
        /// The action attempted.
        action: String,
    },
    /// An association with the given ID was not found.
    NotFound(u64),
    /// An association already exists for the given source address.
    DuplicateSource {
        /// The existing association's ID.
        existing_id: u64,
        /// The conflicting source address.
        source: Address,
    },
}

impl fmt::Display for AssociationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssociationError::InvalidStateTransition { from, action } => {
                write!(
                    f,
                    "Cannot {} association in state {}",
                    action,
                    from.display_name()
                )
            }
            AssociationError::NotFound(id) => {
                write!(f, "Association not found: {}", id)
            }
            AssociationError::DuplicateSource {
                existing_id,
                source,
            } => {
                write!(
                    f,
                    "Association {} already exists for source {:?}",
                    existing_id, source
                )
            }
        }
    }
}

impl std::error::Error for AssociationError {}

// ---------------------------------------------------------------------------
// AssociationHook -- callback for association lifecycle events
// ---------------------------------------------------------------------------

/// Callback trait for association lifecycle events.
///
/// Corresponds to Ghidra's `AssociationHook`.
pub trait AssociationHook: Send + Sync {
    /// Called when an association is accepted.
    fn association_accepted(&self, association: &Association);
    /// Called when an association's status is cleared.
    fn association_cleared(&self, association: &Association);
}

// ---------------------------------------------------------------------------
// AssociationManager -- manages all associations
// ---------------------------------------------------------------------------

/// Manages all associations between a source and destination program.
///
/// Corresponds to Ghidra's `AssociationDatabaseManager`. Provides
/// indexed storage and CRUD operations for associations, with efficient
/// lookup by ID, source address, and destination address.
pub struct AssociationManager {
    /// Primary storage: id -> association.
    associations: HashMap<u64, Association>,
    /// Secondary index: source address -> association IDs.
    by_source: HashMap<u64, Vec<u64>>,
    /// Secondary index: destination address -> association IDs.
    by_dest: HashMap<u64, Vec<u64>>,
    /// Next available ID.
    next_id: u64,
    /// Optional hook for lifecycle events.
    hook: Option<Box<dyn AssociationHook>>,
}

impl fmt::Debug for AssociationManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AssociationManager")
            .field("associations", &self.associations)
            .field("by_source", &self.by_source)
            .field("by_dest", &self.by_dest)
            .field("next_id", &self.next_id)
            .field("hook", &self.hook.as_ref().map(|_| "<hook>"))
            .finish()
    }
}

impl AssociationManager {
    /// Create a new empty association manager.
    pub fn new() -> Self {
        Self {
            associations: HashMap::new(),
            by_source: HashMap::new(),
            by_dest: HashMap::new(),
            next_id: 1,
            hook: None,
        }
    }

    /// Set a hook for association lifecycle events.
    pub fn set_hook(&mut self, hook: Box<dyn AssociationHook>) {
        self.hook = Some(hook);
    }

    /// The total number of associations.
    pub fn count(&self) -> usize {
        self.associations.len()
    }

    /// Whether there are no associations.
    pub fn is_empty(&self) -> bool {
        self.associations.is_empty()
    }

    /// Get an association by ID.
    pub fn get(&self, id: u64) -> Option<&Association> {
        self.associations.get(&id)
    }

    /// Get an association by ID (mutable).
    pub fn get_mut(&mut self, id: u64) -> Option<&mut Association> {
        self.associations.get_mut(&id)
    }

    /// Get or create an association for the given source and destination.
    ///
    /// If an association already exists with the same source and destination
    /// addresses, it is returned (with its vote count incremented).
    /// Otherwise, a new association is created.
    pub fn get_or_create(
        &mut self,
        association_type: AssociationType,
        source: Address,
        destination: Address,
    ) -> u64 {
        // Check if there's already an association for this exact source+destination pair
        if let Some(ids) = self.by_source.get(&source.offset) {
            for &existing_id in ids {
                if let Some(assoc) = self.associations.get(&existing_id) {
                    if assoc.destination_address().offset == destination.offset {
                        self.associations
                            .get_mut(&existing_id)
                            .unwrap()
                            .increment_vote();
                        return existing_id;
                    }
                }
            }
        }

        let id = self.next_id;
        self.next_id += 1;

        let assoc = Association::new(id, association_type, source, destination);
        self.associations.insert(id, assoc);
        self.by_source
            .entry(source.offset)
            .or_default()
            .push(id);
        self.by_dest
            .entry(destination.offset)
            .or_default()
            .push(id);

        id
    }

    /// Remove an association by ID.
    ///
    /// Returns the removed association, if found.
    pub fn remove(&mut self, id: u64) -> Option<Association> {
        if let Some(assoc) = self.associations.remove(&id) {
            // Remove from secondary indexes
            if let Some(ids) = self.by_source.get_mut(&assoc.source_address().offset) {
                ids.retain(|&x| x != id);
                if ids.is_empty() {
                    self.by_source.remove(&assoc.source_address().offset);
                }
            }
            if let Some(ids) = self.by_dest.get_mut(&assoc.destination_address().offset) {
                ids.retain(|&x| x != id);
                if ids.is_empty() {
                    self.by_dest.remove(&assoc.destination_address().offset);
                }
            }
            Some(assoc)
        } else {
            None
        }
    }

    /// Accept an association by ID.
    ///
    /// When an association is accepted, any other association with the
    /// same destination address that is still Available is blocked.
    pub fn accept(&mut self, id: u64) -> Result<(), AssociationError> {
        let assoc = self
            .associations
            .get(&id)
            .ok_or(AssociationError::NotFound(id))?;
        let dest_offset = assoc.destination_address().offset;

        // First, perform the state transition
        self.associations
            .get_mut(&id)
            .unwrap()
            .set_accepted()?;

        // Block other associations with the same destination
        if let Some(ids) = self.by_dest.get(&dest_offset).cloned() {
            for other_id in ids {
                if other_id == id {
                    continue;
                }
                if let Some(other) = self.associations.get_mut(&other_id) {
                    if other.status() == AssociationStatus::Available {
                        other.set_blocked();
                    }
                }
            }
        }

        // Fire hook
        if let Some(ref hook) = self.hook {
            if let Some(assoc) = self.associations.get(&id) {
                hook.association_accepted(assoc);
            }
        }

        Ok(())
    }

    /// Reject an association by ID.
    pub fn reject(&mut self, id: u64) -> Result<(), AssociationError> {
        let assoc = self
            .associations
            .get_mut(&id)
            .ok_or(AssociationError::NotFound(id))?;
        assoc.set_rejected()
    }

    /// Clear an association's status back to Available.
    pub fn clear(&mut self, id: u64) -> Result<(), AssociationError> {
        let assoc = self
            .associations
            .get_mut(&id)
            .ok_or(AssociationError::NotFound(id))?;
        let dest_offset = assoc.destination_address().offset;

        // Record the current status before clearing
        let was_accepted = assoc.status() == AssociationStatus::Accepted;
        assoc.clear_status()?;

        // If this was previously accepted, un-block other associations
        // with the same destination that were blocked by this acceptance.
        if was_accepted {
            // Check if any other association for this destination is still accepted
            let dest_ids = self.by_dest.get(&dest_offset).cloned().unwrap_or_default();
            let still_has_accepted = dest_ids
                .iter()
                .any(|&oid| {
                    oid != id
                        && self
                            .associations
                            .get(&oid)
                            .map(|a| a.status() == AssociationStatus::Accepted)
                            .unwrap_or(false)
                });

            if !still_has_accepted {
                // Unblock all blocked associations for this destination.
                // Blocked associations cannot go through clear_status() since
                // they were never Accepted or Rejected -- set status directly.
                for other_id in &dest_ids {
                    if *other_id == id {
                        continue;
                    }
                    if let Some(other) = self.associations.get_mut(other_id) {
                        if other.status() == AssociationStatus::Blocked {
                            other.status = AssociationStatus::Available;
                        }
                    }
                }
            }
        }

        // Fire hook
        if let Some(ref hook) = self.hook {
            if let Some(assoc) = self.associations.get(&id) {
                hook.association_cleared(assoc);
            }
        }

        Ok(())
    }

    /// Find associations by source address.
    pub fn by_source(&self, source: &Address) -> Vec<&Association> {
        self.by_source
            .get(&source.offset)
            .map(|ids| {
                ids.iter()
                    .filter_map(|&id| self.associations.get(&id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Find associations by destination address.
    pub fn by_destination(&self, dest: &Address) -> Vec<&Association> {
        self.by_dest
            .get(&dest.offset)
            .map(|ids| {
                ids.iter()
                    .filter_map(|&id| self.associations.get(&id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all associations as a vector.
    pub fn all(&self) -> Vec<&Association> {
        self.associations.values().collect()
    }

    /// Get all association IDs.
    pub fn all_ids(&self) -> Vec<u64> {
        self.associations.keys().copied().collect()
    }

    /// Get all associations with a given status.
    pub fn by_status(&self, status: AssociationStatus) -> Vec<&Association> {
        self.associations
            .values()
            .filter(|a| a.status() == status)
            .collect()
    }

    /// Get all associations of a given type.
    pub fn by_type(&self, assoc_type: AssociationType) -> Vec<&Association> {
        self.associations
            .values()
            .filter(|a| a.association_type() == assoc_type)
            .collect()
    }

    /// Accept all available associations.
    ///
    /// Returns the number of associations that were accepted.
    pub fn accept_all(&mut self) -> usize {
        let ids: Vec<u64> = self
            .associations
            .iter()
            .filter(|(_, a)| a.status() == AssociationStatus::Available)
            .map(|(&id, _)| id)
            .collect();
        let count = ids.len();
        for id in ids {
            self.accept(id).ok();
        }
        count
    }

    /// Clear all accepted/rejected associations back to Available.
    pub fn clear_all(&mut self) {
        let ids: Vec<u64> = self.associations.keys().copied().collect();
        for id in ids {
            self.clear(id).ok();
        }
    }

    /// Remove all associations.
    pub fn clear_entries(&mut self) {
        self.associations.clear();
        self.by_source.clear();
        self.by_dest.clear();
    }
}

impl Default for AssociationManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AssociationTableAdapter -- tabular display model
// ---------------------------------------------------------------------------

/// Column definitions for the association table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssociationColumn {
    /// Association ID.
    Id,
    /// Association type.
    Type,
    /// Source address.
    SourceAddress,
    /// Destination address.
    DestAddress,
    /// Status.
    Status,
    /// Vote count.
    VoteCount,
}

impl AssociationColumn {
    /// All columns in display order.
    pub fn all() -> &'static [AssociationColumn] {
        &[
            AssociationColumn::Id,
            AssociationColumn::Type,
            AssociationColumn::SourceAddress,
            AssociationColumn::DestAddress,
            AssociationColumn::Status,
            AssociationColumn::VoteCount,
        ]
    }

    /// The column header text.
    pub fn header(&self) -> &'static str {
        match self {
            AssociationColumn::Id => "ID",
            AssociationColumn::Type => "Type",
            AssociationColumn::SourceAddress => "Source Address",
            AssociationColumn::DestAddress => "Dest Address",
            AssociationColumn::Status => "Status",
            AssociationColumn::VoteCount => "Votes",
        }
    }
}

/// A row in the association table.
#[derive(Debug, Clone)]
pub struct AssociationRow {
    /// The association ID.
    pub id: u64,
    /// The association type.
    pub assoc_type: AssociationType,
    /// The source address.
    pub source: Address,
    /// The destination address.
    pub destination: Address,
    /// The status.
    pub status: AssociationStatus,
    /// The vote count.
    pub vote_count: i32,
}

/// A tabular model for displaying associations.
///
/// Corresponds to Ghidra's association table in the Version Tracking UI.
#[derive(Debug)]
pub struct AssociationTableAdapter {
    /// Cached rows for display.
    rows: Vec<AssociationRow>,
    /// Current sort column.
    sort_column: AssociationColumn,
    /// Sort ascending.
    sort_ascending: bool,
}

impl AssociationTableAdapter {
    /// Create a new empty table adapter.
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            sort_column: AssociationColumn::Id,
            sort_ascending: true,
        }
    }

    /// Refresh the table from the given association manager.
    pub fn update(&mut self, manager: &AssociationManager) {
        self.rows = manager
            .all()
            .into_iter()
            .map(|a| AssociationRow {
                id: a.id(),
                assoc_type: a.association_type(),
                source: a.source_address(),
                destination: a.destination_address(),
                status: a.status(),
                vote_count: a.vote_count(),
            })
            .collect();
        self.sort();
    }

    /// The number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Get a row by index.
    pub fn get_row(&self, index: usize) -> Option<&AssociationRow> {
        self.rows.get(index)
    }

    /// Get the association ID at a row index.
    pub fn get_id_at(&self, index: usize) -> Option<u64> {
        self.rows.get(index).map(|r| r.id)
    }

    /// Get a cell value as a string.
    pub fn get_cell_value(&self, row: usize, column: AssociationColumn) -> Option<String> {
        let r = self.rows.get(row)?;
        Some(match column {
            AssociationColumn::Id => r.id.to_string(),
            AssociationColumn::Type => r.assoc_type.to_string(),
            AssociationColumn::SourceAddress => format!("0x{:x}", r.source.offset),
            AssociationColumn::DestAddress => format!("0x{:x}", r.destination.offset),
            AssociationColumn::Status => r.status.to_string(),
            AssociationColumn::VoteCount => r.vote_count.to_string(),
        })
    }

    /// Set the sort column and direction.
    pub fn set_sort(&mut self, column: AssociationColumn, ascending: bool) {
        self.sort_column = column;
        self.sort_ascending = ascending;
        self.sort();
    }

    fn sort(&mut self) {
        let asc = self.sort_ascending;
        match self.sort_column {
            AssociationColumn::Id => {
                self.rows.sort_by(|a, b| {
                    if asc {
                        a.id.cmp(&b.id)
                    } else {
                        b.id.cmp(&a.id)
                    }
                });
            }
            AssociationColumn::Type => {
                self.rows.sort_by(|a, b| {
                    let cmp = a.assoc_type.to_string().cmp(&b.assoc_type.to_string());
                    if asc {
                        cmp
                    } else {
                        cmp.reverse()
                    }
                });
            }
            AssociationColumn::SourceAddress => {
                self.rows.sort_by(|a, b| {
                    let cmp = a.source.offset.cmp(&b.source.offset);
                    if asc {
                        cmp
                    } else {
                        cmp.reverse()
                    }
                });
            }
            AssociationColumn::DestAddress => {
                self.rows.sort_by(|a, b| {
                    let cmp = a
                        .destination
                        .offset
                        .cmp(&b.destination.offset);
                    if asc {
                        cmp
                    } else {
                        cmp.reverse()
                    }
                });
            }
            AssociationColumn::Status => {
                self.rows.sort_by(|a, b| {
                    let cmp = a.status.to_string().cmp(&b.status.to_string());
                    if asc {
                        cmp
                    } else {
                        cmp.reverse()
                    }
                });
            }
            AssociationColumn::VoteCount => {
                self.rows.sort_by(|a, b| {
                    let cmp = a.vote_count.cmp(&b.vote_count);
                    if asc {
                        cmp
                    } else {
                        cmp.reverse()
                    }
                });
            }
        }
    }

    /// Clear the table.
    pub fn clear(&mut self) {
        self.rows.clear();
    }
}

impl Default for AssociationTableAdapter {
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

    // -----------------------------------------------------------------------
    // AssociationType / AssociationStatus
    // -----------------------------------------------------------------------

    #[test]
    fn test_association_type_display() {
        assert_eq!(AssociationType::Function.to_string(), "Function");
        assert_eq!(AssociationType::Data.to_string(), "Data");
        assert_eq!(
            AssociationType::ExternalLibrary.to_string(),
            "ExternalLibrary"
        );
    }

    #[test]
    fn test_association_status_properties() {
        assert!(AssociationStatus::Available.can_apply());
        assert!(AssociationStatus::Accepted.can_apply());
        assert!(!AssociationStatus::Blocked.can_apply());
        assert!(!AssociationStatus::Rejected.can_apply());

        assert!(!AssociationStatus::Available.is_blocked());
        assert!(!AssociationStatus::Accepted.is_blocked());
        assert!(AssociationStatus::Blocked.is_blocked());
        assert!(AssociationStatus::Rejected.is_blocked());
    }

    #[test]
    fn test_association_status_display() {
        assert_eq!(AssociationStatus::Available.to_string(), "Available");
        assert_eq!(AssociationStatus::Accepted.to_string(), "Accepted");
    }

    // -----------------------------------------------------------------------
    // Association
    // -----------------------------------------------------------------------

    #[test]
    fn test_association_new() {
        let assoc = Association::new(
            1,
            AssociationType::Function,
            Address::new(0x1000),
            Address::new(0x2000),
        );
        assert_eq!(assoc.id(), 1);
        assert_eq!(assoc.association_type(), AssociationType::Function);
        assert_eq!(assoc.source_address(), Address::new(0x1000));
        assert_eq!(assoc.destination_address(), Address::new(0x2000));
        assert_eq!(assoc.status(), AssociationStatus::Available);
        assert_eq!(assoc.vote_count(), 0);
    }

    #[test]
    fn test_association_vote_count() {
        let mut assoc = Association::new(
            1,
            AssociationType::Data,
            Address::new(0x100),
            Address::new(0x200),
        );
        assert_eq!(assoc.vote_count(), 0);

        assoc.increment_vote();
        assert_eq!(assoc.vote_count(), 1);

        assoc.set_vote_count(5);
        assert_eq!(assoc.vote_count(), 5);
    }

    #[test]
    fn test_association_source_description() {
        let mut assoc = Association::new(
            1,
            AssociationType::Function,
            Address::new(0x100),
            Address::new(0x200),
        );
        assert!(assoc.source_description().is_none());

        assoc.set_source_description("Exact Match Hash");
        assert_eq!(
            assoc.source_description(),
            Some("Exact Match Hash")
        );
    }

    #[test]
    fn test_association_accept_reject_clear() {
        let mut assoc = Association::new(
            1,
            AssociationType::Function,
            Address::new(0x100),
            Address::new(0x200),
        );

        // Accept
        assert!(assoc.set_accepted().is_ok());
        assert_eq!(assoc.status(), AssociationStatus::Accepted);

        // Cannot reject an accepted association
        assert!(assoc.set_rejected().is_err());

        // Clear
        assert!(assoc.clear_status().is_ok());
        assert_eq!(assoc.status(), AssociationStatus::Available);

        // Reject
        assert!(assoc.set_rejected().is_ok());
        assert_eq!(assoc.status(), AssociationStatus::Rejected);

        // Clear again
        assert!(assoc.clear_status().is_ok());
        assert_eq!(assoc.status(), AssociationStatus::Available);
    }

    #[test]
    fn test_association_cannot_clear_available() {
        let mut assoc = Association::new(
            1,
            AssociationType::Function,
            Address::new(0x100),
            Address::new(0x200),
        );
        assert!(assoc.clear_status().is_err());
    }

    #[test]
    fn test_association_blocked_from_available() {
        let mut assoc = Association::new(
            1,
            AssociationType::Function,
            Address::new(0x100),
            Address::new(0x200),
        );
        assoc.set_blocked();
        assert_eq!(assoc.status(), AssociationStatus::Blocked);

        // Blocked associations cannot be accepted
        assert!(assoc.set_accepted().is_err());
    }

    // -----------------------------------------------------------------------
    // AssociationError
    // -----------------------------------------------------------------------

    #[test]
    fn test_association_error_display() {
        let err = AssociationError::InvalidStateTransition {
            from: AssociationStatus::Accepted,
            action: "reject".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("reject"));
        assert!(msg.contains("Accepted"));
    }

    #[test]
    fn test_association_error_not_found() {
        let err = AssociationError::NotFound(42);
        assert_eq!(format!("{}", err), "Association not found: 42");
    }

    // -----------------------------------------------------------------------
    // AssociationManager
    // -----------------------------------------------------------------------

    #[test]
    fn test_manager_get_or_create() {
        let mut mgr = AssociationManager::new();
        assert!(mgr.is_empty());

        let id = mgr.get_or_create(
            AssociationType::Function,
            Address::new(0x1000),
            Address::new(0x2000),
        );
        assert_eq!(id, 1);
        assert_eq!(mgr.count(), 1);

        // Getting same source returns same ID with incremented vote
        let id2 = mgr.get_or_create(
            AssociationType::Function,
            Address::new(0x1000),
            Address::new(0x2000),
        );
        assert_eq!(id2, 1);
        assert_eq!(mgr.count(), 1);
        assert_eq!(mgr.get(1).unwrap().vote_count(), 1);

        // Different source creates new ID
        let id3 = mgr.get_or_create(
            AssociationType::Data,
            Address::new(0x3000),
            Address::new(0x4000),
        );
        assert_eq!(id3, 2);
        assert_eq!(mgr.count(), 2);
    }

    #[test]
    fn test_manager_remove() {
        let mut mgr = AssociationManager::new();
        let id = mgr.get_or_create(
            AssociationType::Function,
            Address::new(0x1000),
            Address::new(0x2000),
        );

        let removed = mgr.remove(id);
        assert!(removed.is_some());
        assert!(mgr.is_empty());

        // Secondary indexes are also cleaned up
        assert!(mgr.by_source(&Address::new(0x1000)).is_empty());
        assert!(mgr.by_destination(&Address::new(0x2000)).is_empty());
    }

    #[test]
    fn test_manager_accept_and_block() {
        let mut mgr = AssociationManager::new();

        // Two associations with the same destination
        let id1 = mgr.get_or_create(
            AssociationType::Function,
            Address::new(0x1000),
            Address::new(0x9000),
        );
        let id2 = mgr.get_or_create(
            AssociationType::Function,
            Address::new(0x2000),
            Address::new(0x9000),
        );

        // Accept the first one
        assert!(mgr.accept(id1).is_ok());
        assert_eq!(mgr.get(id1).unwrap().status(), AssociationStatus::Accepted);

        // The second should be blocked
        assert_eq!(mgr.get(id2).unwrap().status(), AssociationStatus::Blocked);
    }

    #[test]
    fn test_manager_reject() {
        let mut mgr = AssociationManager::new();
        let id = mgr.get_or_create(
            AssociationType::Function,
            Address::new(0x1000),
            Address::new(0x2000),
        );

        assert!(mgr.reject(id).is_ok());
        assert_eq!(mgr.get(id).unwrap().status(), AssociationStatus::Rejected);
    }

    #[test]
    fn test_manager_clear_with_unblock() {
        let mut mgr = AssociationManager::new();

        let id1 = mgr.get_or_create(
            AssociationType::Function,
            Address::new(0x1000),
            Address::new(0x9000),
        );
        let id2 = mgr.get_or_create(
            AssociationType::Function,
            Address::new(0x2000),
            Address::new(0x9000),
        );

        // Accept id1 -> id2 blocked
        mgr.accept(id1).unwrap();
        assert_eq!(mgr.get(id2).unwrap().status(), AssociationStatus::Blocked);

        // Clear id1 -> id2 should be un-blocked back to Available
        mgr.clear(id1).unwrap();
        assert_eq!(mgr.get(id1).unwrap().status(), AssociationStatus::Available);
        assert_eq!(mgr.get(id2).unwrap().status(), AssociationStatus::Available);
    }

    #[test]
    fn test_manager_lookup_by_source_and_dest() {
        let mut mgr = AssociationManager::new();
        mgr.get_or_create(
            AssociationType::Function,
            Address::new(0x1000),
            Address::new(0x2000),
        );
        mgr.get_or_create(
            AssociationType::Data,
            Address::new(0x1000),
            Address::new(0x3000),
        );

        let by_src = mgr.by_source(&Address::new(0x1000));
        assert_eq!(by_src.len(), 2);

        let by_dest = mgr.by_destination(&Address::new(0x2000));
        assert_eq!(by_dest.len(), 1);
        assert_eq!(by_dest[0].association_type(), AssociationType::Function);
    }

    #[test]
    fn test_manager_by_status() {
        let mut mgr = AssociationManager::new();
        let id1 = mgr.get_or_create(
            AssociationType::Function,
            Address::new(0x1000),
            Address::new(0x2000),
        );
        let id2 = mgr.get_or_create(
            AssociationType::Data,
            Address::new(0x3000),
            Address::new(0x4000),
        );
        mgr.accept(id1).unwrap();

        let accepted = mgr.by_status(AssociationStatus::Accepted);
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].id(), id1);

        let available = mgr.by_status(AssociationStatus::Available);
        assert_eq!(available.len(), 1);
        assert_eq!(available[0].id(), id2);
    }

    #[test]
    fn test_manager_by_type() {
        let mut mgr = AssociationManager::new();
        mgr.get_or_create(
            AssociationType::Function,
            Address::new(0x1000),
            Address::new(0x2000),
        );
        mgr.get_or_create(
            AssociationType::Function,
            Address::new(0x3000),
            Address::new(0x4000),
        );
        mgr.get_or_create(
            AssociationType::Data,
            Address::new(0x5000),
            Address::new(0x6000),
        );

        assert_eq!(
            mgr.by_type(AssociationType::Function).len(),
            2
        );
        assert_eq!(mgr.by_type(AssociationType::Data).len(), 1);
    }

    #[test]
    fn test_manager_accept_all() {
        let mut mgr = AssociationManager::new();
        mgr.get_or_create(
            AssociationType::Function,
            Address::new(0x1000),
            Address::new(0x2000),
        );
        mgr.get_or_create(
            AssociationType::Function,
            Address::new(0x3000),
            Address::new(0x4000),
        );

        let count = mgr.accept_all();
        assert_eq!(count, 2);
        assert_eq!(
            mgr.by_status(AssociationStatus::Accepted).len(),
            2
        );
    }

    #[test]
    fn test_manager_not_found() {
        let mut mgr = AssociationManager::new();
        let err = mgr.accept(999).unwrap_err();
        assert_eq!(err, AssociationError::NotFound(999));
    }

    // -----------------------------------------------------------------------
    // AssociationTableAdapter
    // -----------------------------------------------------------------------

    #[test]
    fn test_table_adapter_empty() {
        let adapter = AssociationTableAdapter::new();
        assert_eq!(adapter.row_count(), 0);
        assert!(adapter.get_row(0).is_none());
    }

    #[test]
    fn test_table_adapter_update() {
        let mut mgr = AssociationManager::new();
        mgr.get_or_create(
            AssociationType::Function,
            Address::new(0x1000),
            Address::new(0x2000),
        );
        mgr.get_or_create(
            AssociationType::Data,
            Address::new(0x3000),
            Address::new(0x4000),
        );

        let mut adapter = AssociationTableAdapter::new();
        adapter.update(&mgr);

        assert_eq!(adapter.row_count(), 2);
    }

    #[test]
    fn test_table_adapter_cell_values() {
        let mut mgr = AssociationManager::new();
        let id = mgr.get_or_create(
            AssociationType::Function,
            Address::new(0x1000),
            Address::new(0x2000),
        );

        let mut adapter = AssociationTableAdapter::new();
        adapter.update(&mgr);

        assert_eq!(
            adapter.get_cell_value(0, AssociationColumn::Id),
            Some(id.to_string())
        );
        assert_eq!(
            adapter.get_cell_value(0, AssociationColumn::Type),
            Some("Function".to_string())
        );
        assert_eq!(
            adapter.get_cell_value(0, AssociationColumn::SourceAddress),
            Some("0x1000".to_string())
        );
        assert_eq!(
            adapter.get_cell_value(0, AssociationColumn::DestAddress),
            Some("0x2000".to_string())
        );
        assert_eq!(
            adapter.get_cell_value(0, AssociationColumn::Status),
            Some("Available".to_string())
        );
        assert_eq!(
            adapter.get_cell_value(0, AssociationColumn::VoteCount),
            Some("0".to_string())
        );
    }

    #[test]
    fn test_table_adapter_sort_by_id() {
        let mut mgr = AssociationManager::new();
        mgr.get_or_create(
            AssociationType::Function,
            Address::new(0x3000),
            Address::new(0x4000),
        );
        mgr.get_or_create(
            AssociationType::Function,
            Address::new(0x1000),
            Address::new(0x2000),
        );

        let mut adapter = AssociationTableAdapter::new();
        adapter.update(&mgr);

        // Default sort: by ID ascending
        assert_eq!(adapter.get_id_at(0), Some(1));
        assert_eq!(adapter.get_id_at(1), Some(2));

        // Sort descending
        adapter.set_sort(AssociationColumn::Id, false);
        assert_eq!(adapter.get_id_at(0), Some(2));
        assert_eq!(adapter.get_id_at(1), Some(1));
    }

    #[test]
    fn test_table_adapter_sort_by_source() {
        let mut mgr = AssociationManager::new();
        mgr.get_or_create(
            AssociationType::Function,
            Address::new(0x3000),
            Address::new(0x4000),
        );
        mgr.get_or_create(
            AssociationType::Function,
            Address::new(0x1000),
            Address::new(0x2000),
        );

        let mut adapter = AssociationTableAdapter::new();
        adapter.update(&mgr);
        adapter.set_sort(AssociationColumn::SourceAddress, true);

        let first_src = adapter.get_cell_value(0, AssociationColumn::SourceAddress);
        assert_eq!(first_src, Some("0x1000".to_string()));
    }

    #[test]
    fn test_table_adapter_clear() {
        let mut mgr = AssociationManager::new();
        mgr.get_or_create(
            AssociationType::Function,
            Address::new(0x1000),
            Address::new(0x2000),
        );

        let mut adapter = AssociationTableAdapter::new();
        adapter.update(&mgr);
        assert_eq!(adapter.row_count(), 1);

        adapter.clear();
        assert_eq!(adapter.row_count(), 0);
    }

    #[test]
    fn test_association_column_headers() {
        assert_eq!(AssociationColumn::Id.header(), "ID");
        assert_eq!(AssociationColumn::Type.header(), "Type");
        assert_eq!(
            AssociationColumn::SourceAddress.header(),
            "Source Address"
        );
        assert_eq!(
            AssociationColumn::DestAddress.header(),
            "Dest Address"
        );
        assert_eq!(AssociationColumn::Status.header(), "Status");
        assert_eq!(AssociationColumn::VoteCount.header(), "Votes");
    }

    #[test]
    fn test_association_column_all() {
        assert_eq!(AssociationColumn::all().len(), 6);
    }
}
