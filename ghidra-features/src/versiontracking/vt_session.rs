//! VTSession trait -- the interface for version tracking sessions.
//!
//! Corresponds to Ghidra's `VTSession` Java interface.

use std::sync::Arc;

use ghidra_core::addr::Address;
use ghidra_core::program::Program;

use crate::versiontracking::association::{AssociationHook, VtAssociation, VtAssociationManager};
use crate::versiontracking::error::VtResult;
use crate::versiontracking::match_set::VtMatchSet;
use crate::versiontracking::types::{VtAssociationType, VtMatchTag};
use crate::versiontracking::vt_match::VtMatchImpl;
use crate::versiontracking::vt_match_set::{VtMatchSetImpl, VtMatchSetTrait};

/// Trait for the main version tracking session interface.
///
/// This is the Rust equivalent of Ghidra's `VTSession` Java interface.
pub trait VtSessionTrait: Send + Sync {
    /// Returns the AssociationManager.
    fn association_manager(&self) -> &VtAssociationManager;

    /// Returns a mutable reference to the AssociationManager.
    fn association_manager_mut(&mut self) -> &mut VtAssociationManager;

    /// Creates a new VTMatchSet that will contain all the matches discovered
    /// by some ProgramCorrelator algorithm run.
    fn create_match_set(&mut self, correlator_name: &str) -> u64;

    /// Returns a list of all VTMatchSets contained in this VTSession.
    fn match_sets(&self) -> Vec<&VtMatchSetImpl>;

    /// Returns the source program associated with this VTSession.
    fn source_program(&self) -> &Program;

    /// Returns the destination program associated with this VTSession.
    fn destination_program(&self) -> &Program;

    /// Returns the name of this VTSession.
    fn name(&self) -> &str;

    /// Saves this VTSession.
    fn save(&mut self) -> VtResult<()>;

    /// Creates a new match tag with the given name.
    fn create_match_tag(&mut self, name: &str) -> VtMatchTag;

    /// Deletes the given VTMatchTag from this session.
    fn delete_match_tag(&mut self, tag: &VtMatchTag);

    /// Returns a set of all VTMatchTags in this session.
    fn match_tags(&self) -> &[VtMatchTag];

    /// Returns the built-in VTMatchSet used to store manually created VTMatches.
    fn manual_match_set(&self) -> &VtMatchSet;

    /// Returns the built-in VTMatchSet used to store implied VTMatches.
    fn implied_match_set(&self) -> &VtMatchSet;

    /// Returns a mutable reference to the manual match set.
    fn manual_match_set_mut(&mut self) -> &mut VtMatchSet;

    /// Returns a mutable reference to the implied match set.
    fn implied_match_set_mut(&mut self) -> &mut VtMatchSet;

    /// Returns a list of all VTMatches for the given association.
    fn get_matches_for_association(&self, association: &VtAssociation) -> Vec<&VtMatchImpl>;

    /// Adds an Association hook.
    fn add_association_hook(&mut self, hook: Arc<dyn AssociationHook>);

    /// Removes the given Association hook.
    fn remove_association_hook(&mut self, hook: &Arc<dyn AssociationHook>);

    /// Updates the source program.
    fn update_source_program(&mut self, new_program: Program);

    /// Updates the destination program.
    fn update_destination_program(&mut self, new_program: Program);

    /// Returns the total match count across all match sets.
    fn total_match_count(&self) -> usize;

    /// Returns whether the session has unsaved changes.
    fn is_dirty(&self) -> bool;

    /// Marks the session as saved.
    fn mark_saved(&mut self);
}

/// A concrete implementation of VtSessionTrait.
pub struct VtSessionImpl {
    /// Session name
    name: String,
    /// Source program
    source_program: Arc<Program>,
    /// Destination program
    destination_program: Arc<Program>,
    /// Match sets
    match_sets: Vec<VtMatchSetImpl>,
    /// Association manager
    association_manager: VtAssociationManager,
    /// Match tags
    tags: Vec<VtMatchTag>,
    /// Manual match set
    manual_match_set: VtMatchSet,
    /// Implied match set
    implied_match_set: VtMatchSet,
    /// Association hooks
    hooks: Vec<Arc<dyn AssociationHook>>,
    /// Dirty flag
    dirty: bool,
    /// Next match set ID
    next_match_set_id: u64,
}

impl VtSessionImpl {
    /// Create a new session implementation.
    pub fn new(
        name: impl Into<String>,
        source_program: Program,
        destination_program: Program,
    ) -> Self {
        Self {
            name: name.into(),
            source_program: Arc::new(source_program),
            destination_program: Arc::new(destination_program),
            match_sets: Vec::new(),
            association_manager: VtAssociationManager::new(),
            tags: Vec::new(),
            manual_match_set: VtMatchSet::new(0, "Manual"),
            implied_match_set: VtMatchSet::new(0, "Implied"),
            hooks: Vec::new(),
            dirty: false,
            next_match_set_id: 1,
        }
    }

    /// Get a match set by ID.
    pub fn get_match_set(&self, id: u64) -> Option<&VtMatchSetImpl> {
        self.match_sets.iter().find(|ms| ms.id == id)
    }

    /// Get a mutable match set by ID.
    pub fn get_match_set_mut(&mut self, id: u64) -> Option<&mut VtMatchSetImpl> {
        self.match_sets.iter_mut().find(|ms| ms.id == id)
    }

    /// Get or create an association.
    pub fn get_or_create_association(
        &mut self,
        association_type: VtAssociationType,
        source_address: Address,
        destination_address: Address,
    ) -> &VtAssociation {
        self.association_manager
            .get_or_create_association(association_type, source_address, destination_address);
        self.dirty = true;
        self.association_manager
            .get_association(self.association_manager.count() as u64)
            .unwrap()
    }

    /// Accept an association.
    pub fn accept_association(&mut self, association_id: u64) -> VtResult<()> {
        self.association_manager.accept_association(association_id)?;
        self.dirty = true;
        Ok(())
    }

    /// Clear an association.
    pub fn clear_association(&mut self, association_id: u64) -> VtResult<()> {
        self.association_manager.clear_association(association_id)?;
        self.dirty = true;
        Ok(())
    }
}

impl VtSessionTrait for VtSessionImpl {
    fn association_manager(&self) -> &VtAssociationManager {
        &self.association_manager
    }

    fn association_manager_mut(&mut self) -> &mut VtAssociationManager {
        &mut self.association_manager
    }

    fn create_match_set(&mut self, correlator_name: &str) -> u64 {
        let id = self.next_match_set_id;
        self.next_match_set_id += 1;
        let mut ms = VtMatchSetImpl::new(id, correlator_name);
        ms.set_session_id(0); // Will be set when persisted
        self.match_sets.push(ms);
        self.dirty = true;
        id
    }

    fn match_sets(&self) -> Vec<&VtMatchSetImpl> {
        self.match_sets.iter().collect()
    }

    fn source_program(&self) -> &Program {
        &self.source_program
    }

    fn destination_program(&self) -> &Program {
        &self.destination_program
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn save(&mut self) -> VtResult<()> {
        // In a full implementation, this would persist to storage
        self.dirty = false;
        Ok(())
    }

    fn create_match_tag(&mut self, name: &str) -> VtMatchTag {
        let tag = VtMatchTag::new(name);
        self.tags.push(tag.clone());
        self.dirty = true;
        tag
    }

    fn delete_match_tag(&mut self, tag: &VtMatchTag) {
        self.tags.retain(|t| t != tag);
        self.dirty = true;
    }

    fn match_tags(&self) -> &[VtMatchTag] {
        &self.tags
    }

    fn manual_match_set(&self) -> &VtMatchSet {
        &self.manual_match_set
    }

    fn implied_match_set(&self) -> &VtMatchSet {
        &self.implied_match_set
    }

    fn manual_match_set_mut(&mut self) -> &mut VtMatchSet {
        &mut self.manual_match_set
    }

    fn implied_match_set_mut(&mut self) -> &mut VtMatchSet {
        &mut self.implied_match_set
    }

    fn get_matches_for_association(&self, association: &VtAssociation) -> Vec<&VtMatchImpl> {
        self.match_sets
            .iter()
            .flat_map(|ms| ms.get_matches_for_association(association))
            .collect()
    }

    fn add_association_hook(&mut self, hook: Arc<dyn AssociationHook>) {
        self.hooks.push(hook);
    }

    fn remove_association_hook(&mut self, hook: &Arc<dyn AssociationHook>) {
        // Note: Arc comparison by pointer for removal
        self.hooks.retain(|h| !Arc::ptr_eq(h, hook));
    }

    fn update_source_program(&mut self, new_program: Program) {
        self.source_program = Arc::new(new_program);
        self.dirty = true;
    }

    fn update_destination_program(&mut self, new_program: Program) {
        self.destination_program = Arc::new(new_program);
        self.dirty = true;
    }

    fn total_match_count(&self) -> usize {
        self.manual_match_set.match_count()
            + self.implied_match_set.match_count()
            + self.match_sets.iter().map(|ms| ms.match_count()).sum::<usize>()
    }

    fn is_dirty(&self) -> bool {
        self.dirty
    }

    fn mark_saved(&mut self) {
        self.dirty = false;
    }
}

impl std::fmt::Debug for VtSessionImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VtSessionImpl")
            .field("name", &self.name)
            .field("match_sets", &self.match_sets.len())
            .field("tags", &self.tags.len())
            .field("dirty", &self.dirty)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;

    fn make_program(name: &str) -> Program {
        Program::new(name, Address::new(0x1000))
    }

    #[test]
    fn test_session_create() {
        let session = VtSessionImpl::new("test.vt", make_program("src"), make_program("dst"));
        assert_eq!(session.name(), "test.vt");
        assert!(session.match_sets().is_empty());
        assert_eq!(session.total_match_count(), 0);
        assert!(!session.is_dirty());
    }

    #[test]
    fn test_session_match_sets() {
        let mut session = VtSessionImpl::new("test", make_program("src"), make_program("dst"));
        let id = session.create_match_set("ExactMatch");
        assert_eq!(session.match_sets().len(), 1);
        assert_eq!(session.get_match_set(id).unwrap().correlator_name, "ExactMatch");
    }

    #[test]
    fn test_session_tags() {
        let mut session = VtSessionImpl::new("test", make_program("src"), make_program("dst"));
        let tag = session.create_match_tag("verified");
        assert_eq!(session.match_tags().len(), 1);
        session.delete_match_tag(&tag);
        assert_eq!(session.match_tags().len(), 0);
    }

    #[test]
    fn test_session_dirty_flag() {
        let mut session = VtSessionImpl::new("test", make_program("src"), make_program("dst"));
        assert!(!session.is_dirty());
        session.create_match_set("Test");
        assert!(session.is_dirty());
        session.mark_saved();
        assert!(!session.is_dirty());
    }

    #[test]
    fn test_session_programs() {
        let session = VtSessionImpl::new("test", make_program("src"), make_program("dst"));
        assert_eq!(session.source_program().name, "src");
        assert_eq!(session.destination_program().name, "dst");
    }

    #[test]
    fn test_session_update_programs() {
        let mut session = VtSessionImpl::new("test", make_program("src"), make_program("dst"));
        assert!(!session.is_dirty());
        session.update_source_program(make_program("new_src"));
        assert!(session.is_dirty());
        assert_eq!(session.source_program().name, "new_src");
    }
}
