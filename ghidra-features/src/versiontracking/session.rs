//! VTSession -- the main container for a version tracking session.

use std::sync::Arc;
use ghidra_core::addr::Address;
use ghidra_core::program::Program;
use crate::versiontracking::association::{AssociationHook, VtAssociationManager};
use crate::versiontracking::error::VtError;
use crate::versiontracking::match_set::VtMatchSet;
use crate::versiontracking::types::{VtAssociationType, VtMatchTag};

pub struct VtSession {
    name: String,
    source_program: Arc<Program>,
    destination_program: Arc<Program>,
    match_sets: Vec<VtMatchSet>,
    association_manager: VtAssociationManager,
    tags: Vec<VtMatchTag>,
    manual_match_set: VtMatchSet,
    implied_match_set: VtMatchSet,
    hooks: Vec<Arc<dyn AssociationHook>>,
    dirty: bool,
    next_match_set_id: u64,
}

impl VtSession {
    pub fn new(name: impl Into<String>, source_program: Program, destination_program: Program) -> Self {
        Self { name: name.into(), source_program: Arc::new(source_program), destination_program: Arc::new(destination_program),
            match_sets: Vec::new(), association_manager: VtAssociationManager::new(), tags: Vec::new(),
            manual_match_set: VtMatchSet::new(0, "Manual"), implied_match_set: VtMatchSet::new(0, "Implied"),
            hooks: Vec::new(), dirty: false, next_match_set_id: 1 }
    }
    pub fn name(&self) -> &str { &self.name }
    pub fn set_name(&mut self, name: impl Into<String>) { self.name = name.into(); self.dirty = true; }
    pub fn source_program(&self) -> &Program { &self.source_program }
    pub fn destination_program(&self) -> &Program { &self.destination_program }
    pub fn update_source_program(&mut self, new_program: Program) { self.source_program = Arc::new(new_program); self.dirty = true; }
    pub fn update_destination_program(&mut self, new_program: Program) { self.destination_program = Arc::new(new_program); self.dirty = true; }
    pub fn create_match_set(&mut self, correlator_name: impl Into<String>) -> u64 {
        let id = self.next_match_set_id; self.next_match_set_id += 1;
        self.match_sets.push(VtMatchSet::new(id, correlator_name)); self.dirty = true; id
    }
    pub fn match_sets(&self) -> &[VtMatchSet] { &self.match_sets }
    pub fn get_match_set(&self, id: u64) -> Option<&VtMatchSet> { self.match_sets.iter().find(|ms| ms.id == id) }
    pub fn get_match_set_mut(&mut self, id: u64) -> Option<&mut VtMatchSet> { self.match_sets.iter_mut().find(|ms| ms.id == id) }
    pub fn manual_match_set(&self) -> &VtMatchSet { &self.manual_match_set }
    pub fn implied_match_set(&self) -> &VtMatchSet { &self.implied_match_set }
    pub fn manual_match_set_mut(&mut self) -> &mut VtMatchSet { &mut self.manual_match_set }
    pub fn implied_match_set_mut(&mut self) -> &mut VtMatchSet { &mut self.implied_match_set }
    pub fn total_match_count(&self) -> usize {
        self.manual_match_set.match_count() + self.implied_match_set.match_count() + self.match_sets.iter().map(|ms| ms.match_count()).sum::<usize>()
    }
    pub fn create_match_tag(&mut self, name: impl Into<String>) -> VtMatchTag { let tag = VtMatchTag::new(name); self.tags.push(tag.clone()); self.dirty = true; tag }
    pub fn delete_match_tag(&mut self, tag: &VtMatchTag) { self.tags.retain(|t| t != tag); self.dirty = true; }
    pub fn get_match_tags(&self) -> &[VtMatchTag] { &self.tags }
    pub fn association_manager(&self) -> &VtAssociationManager { &self.association_manager }
    pub fn association_manager_mut(&mut self) -> &mut VtAssociationManager { &mut self.association_manager }
    pub fn get_or_create_association(&mut self, association_type: VtAssociationType, source_address: Address, destination_address: Address) {
        self.association_manager.get_or_create_association(association_type, source_address, destination_address); self.dirty = true;
    }
    pub fn accept_association(&mut self, association_id: u64) -> Result<(), VtError> {
        self.association_manager.accept_association(association_id)?; self.dirty = true; Ok(())
    }
    pub fn clear_association(&mut self, association_id: u64) -> Result<(), VtError> {
        self.association_manager.clear_association(association_id)?; self.dirty = true; Ok(())
    }
    pub fn add_association_hook(&mut self, hook: Arc<dyn AssociationHook>) { self.hooks.push(hook); }
    pub fn is_dirty(&self) -> bool { self.dirty }
    pub fn mark_saved(&mut self) { self.dirty = false; }
}

impl std::fmt::Debug for VtSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VtSession").field("name", &self.name).field("match_sets", &self.match_sets.len()).field("dirty", &self.dirty).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_program(name: &str) -> Program { Program::new(name, Address::new(0x1000)) }
    fn addr(v: u64) -> Address { Address::new(v) }

    #[test]
    fn test_session_create() {
        let session = VtSession::new("test.vt", make_program("src"), make_program("dst"));
        assert_eq!(session.name(), "test.vt");
        assert!(session.match_sets().is_empty());
        assert_eq!(session.total_match_count(), 0);
        assert!(!session.is_dirty());
    }

    #[test]
    fn test_session_match_sets() {
        let mut session = VtSession::new("test", make_program("src"), make_program("dst"));
        let id = session.create_match_set("ExactMatch");
        assert_eq!(session.match_sets().len(), 1);
        assert_eq!(session.get_match_set(id).unwrap().correlator_name, "ExactMatch");
    }

    #[test]
    fn test_session_tags() {
        let mut session = VtSession::new("test", make_program("src"), make_program("dst"));
        let tag = session.create_match_tag("verified");
        assert_eq!(session.get_match_tags().len(), 1);
        session.delete_match_tag(&tag);
        assert_eq!(session.get_match_tags().len(), 0);
    }

    #[test]
    fn test_session_dirty_flag() {
        let mut session = VtSession::new("test", make_program("src"), make_program("dst"));
        assert!(!session.is_dirty());
        session.create_match_set("Test");
        assert!(session.is_dirty());
        session.mark_saved();
        assert!(!session.is_dirty());
    }
}
