//! VTAssociation and VTAssociationManager.

use std::collections::HashMap;
use ghidra_core::addr::Address;
use crate::versiontracking::error::{VtError, VtResult};
use crate::versiontracking::types::{VtAssociationMarkupStatus, VtAssociationStatus, VtAssociationType};

#[derive(Debug, Clone)]
pub struct VtAssociation {
    pub id: u64,
    pub association_type: VtAssociationType,
    pub source_address: Address,
    pub destination_address: Address,
    status: VtAssociationStatus,
    markup_status: VtAssociationMarkupStatus,
    vote_count: i32,
}

impl VtAssociation {
    pub fn new(id: u64, association_type: VtAssociationType, source_address: Address, destination_address: Address) -> Self {
        Self { id, association_type, source_address, destination_address, status: VtAssociationStatus::Available,
            markup_status: VtAssociationMarkupStatus::new_none(), vote_count: 0 }
    }
    pub fn association_type(&self) -> VtAssociationType { self.association_type }
    pub fn source_address(&self) -> Address { self.source_address }
    pub fn destination_address(&self) -> Address { self.destination_address }
    pub fn status(&self) -> VtAssociationStatus { self.status }
    pub fn markup_status(&self) -> VtAssociationMarkupStatus { self.markup_status }
    pub fn set_markup_status(&mut self, status: VtAssociationMarkupStatus) { self.markup_status = status; }
    pub fn has_applied_markup_items(&self) -> bool { self.status == VtAssociationStatus::Accepted && self.markup_status.has_applied_markup() }
    pub fn set_accepted(&mut self) -> Result<(), VtError> {
        if self.status.is_blocked() { return Err(VtError::AssociationStatusError { message: format!("Cannot accept: status is {}", self.status.display_name()) }); }
        self.status = VtAssociationStatus::Accepted; Ok(())
    }
    pub fn clear_status(&mut self) -> Result<(), VtError> {
        match self.status { VtAssociationStatus::Accepted | VtAssociationStatus::Rejected => { self.status = VtAssociationStatus::Available; Ok(()) }
            _ => Err(VtError::AssociationStatusError { message: format!("Cannot clear: status is {}", self.status.display_name()) }) }
    }
    pub fn set_rejected(&mut self) -> Result<(), VtError> {
        if self.status == VtAssociationStatus::Accepted { return Err(VtError::AssociationStatusError { message: "Cannot reject accepted".to_string() }); }
        self.status = VtAssociationStatus::Rejected; Ok(())
    }
    pub fn vote_count(&self) -> i32 { self.vote_count }
    pub fn set_vote_count(&mut self, count: i32) { self.vote_count = count; }
    pub(crate) fn set_blocked(&mut self) { if self.status == VtAssociationStatus::Available { self.status = VtAssociationStatus::Blocked; } }
}

pub trait AssociationHook: Send + Sync {
    fn association_accepted(&self, association: &VtAssociation);
    fn association_cleared(&self, association: &VtAssociation);
    fn markup_item_status_changed(&self, item: &crate::versiontracking::markup::VtMarkupItem);
}

#[derive(Debug)]
pub struct VtAssociationManager { associations: HashMap<u64, VtAssociation>, by_source: HashMap<Address, Vec<u64>>, by_dest: HashMap<Address, Vec<u64>>, next_id: u64 }

impl VtAssociationManager {
    pub fn new() -> Self { Self { associations: HashMap::new(), by_source: HashMap::new(), by_dest: HashMap::new(), next_id: 1 } }
    pub fn count(&self) -> usize { self.associations.len() }
    pub fn get_or_create_association(&mut self, association_type: VtAssociationType, source_address: Address, destination_address: Address) -> &VtAssociation {
        if let Some(ids) = self.by_source.get(&source_address) {
            for &id in ids { if let Some(assoc) = self.associations.get(&id) { if assoc.destination_address == destination_address { return self.associations.get(&id).unwrap(); } } }
        }
        let id = self.next_id; self.next_id += 1;
        self.associations.insert(id, VtAssociation::new(id, association_type, source_address, destination_address));
        self.by_source.entry(source_address).or_default().push(id);
        self.by_dest.entry(destination_address).or_default().push(id);
        self.associations.get(&id).unwrap()
    }
    pub fn get_association(&self, id: u64) -> Option<&VtAssociation> { self.associations.get(&id) }
    pub fn get_association_mut(&mut self, id: u64) -> Option<&mut VtAssociation> { self.associations.get_mut(&id) }
    pub fn get_related_associations(&self, id: u64) -> Vec<&VtAssociation> {
        let assoc = match self.associations.get(&id) { Some(a) => a, None => return Vec::new() };
        let src = assoc.source_address; let dst = assoc.destination_address;
        let mut related = Vec::new(); let mut seen = std::collections::HashSet::new();
        if let Some(ids) = self.by_source.get(&src) { for &rid in ids { if rid != id && seen.insert(rid) { if let Some(a) = self.associations.get(&rid) { related.push(a); } } } }
        if let Some(ids) = self.by_dest.get(&dst) { for &rid in ids { if rid != id && seen.insert(rid) { if let Some(a) = self.associations.get(&rid) { related.push(a); } } } }
        related
    }
    pub fn all_associations(&self) -> Vec<&VtAssociation> { self.associations.values().collect() }
    pub fn accepted_associations(&self) -> Vec<&VtAssociation> { self.associations.values().filter(|a| a.status() == VtAssociationStatus::Accepted).collect() }
    pub fn accept_association(&mut self, id: u64) -> Result<(), VtError> {
        let related_ids: Vec<u64> = {
            let assoc = self.associations.get(&id).ok_or_else(|| VtError::AssociationStatusError { message: format!("Association {} not found", id) })?;
            let src = assoc.source_address; let dst = assoc.destination_address;
            let mut ids = Vec::new();
            if let Some(s) = self.by_source.get(&src) { ids.extend(s.iter().copied()); }
            if let Some(d) = self.by_dest.get(&dst) { ids.extend(d.iter().copied()); }
            ids.sort_unstable(); ids.dedup(); ids
        };
        for rid in &related_ids { if *rid != id { if let Some(a) = self.associations.get_mut(rid) { a.set_blocked(); } } }
        let assoc = self.associations.get_mut(&id).ok_or_else(|| VtError::AssociationStatusError { message: format!("Association {} not found", id) })?;
        assoc.set_accepted()
    }
    pub fn clear_association(&mut self, id: u64) -> Result<(), VtError> {
        let assoc = self.associations.get_mut(&id).ok_or_else(|| VtError::AssociationStatusError { message: format!("Association {} not found", id) })?;
        assoc.clear_status()?;
        let src = assoc.source_address; let dst = assoc.destination_address;
        let has_accepted_src = self.by_source.get(&src).map(|ids| ids.iter().any(|&rid| rid != id && self.associations.get(&rid).map(|a| a.status() == VtAssociationStatus::Accepted).unwrap_or(false))).unwrap_or(false);
        if !has_accepted_src { if let Some(ids) = self.by_source.get(&src) { for &rid in ids { if rid != id { if let Some(a) = self.associations.get_mut(&rid) { if a.status() == VtAssociationStatus::Blocked { a.status = VtAssociationStatus::Available; } } } } } }
        let has_accepted_dst = self.by_dest.get(&dst).map(|ids| ids.iter().any(|&rid| rid != id && self.associations.get(&rid).map(|a| a.status() == VtAssociationStatus::Accepted).unwrap_or(false))).unwrap_or(false);
        if !has_accepted_dst { if let Some(ids) = self.by_dest.get(&dst) { for &rid in ids { if rid != id { if let Some(a) = self.associations.get_mut(&rid) { if a.status() == VtAssociationStatus::Blocked { a.status = VtAssociationStatus::Available; } } } } } }
        Ok(())
    }
    pub fn remove_association(&mut self, id: u64) -> bool {
        if let Some(assoc) = self.associations.remove(&id) {
            if let Some(ids) = self.by_source.get_mut(&assoc.source_address) { ids.retain(|&i| i != id); }
            if let Some(ids) = self.by_dest.get_mut(&assoc.destination_address) { ids.retain(|&i| i != id); }
            true
        } else { false }
    }
}

impl Default for VtAssociationManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(v: u64) -> Address { Address::new(v) }

    #[test]
    fn test_association_lifecycle() {
        let mut assoc = VtAssociation::new(1, VtAssociationType::Function, addr(0x1000), addr(0x2000));
        assert_eq!(assoc.status(), VtAssociationStatus::Available);
        assoc.set_accepted().unwrap();
        assert_eq!(assoc.status(), VtAssociationStatus::Accepted);
        assoc.clear_status().unwrap();
        assert_eq!(assoc.status(), VtAssociationStatus::Available);
    }

    #[test]
    fn test_association_manager_create_and_get() {
        let mut mgr = VtAssociationManager::new();
        let _ = mgr.get_or_create_association(VtAssociationType::Function, addr(0x1000), addr(0x2000));
        assert_eq!(mgr.count(), 1);
        let _ = mgr.get_or_create_association(VtAssociationType::Function, addr(0x1000), addr(0x2000));
        assert_eq!(mgr.count(), 1);
    }

    #[test]
    fn test_association_manager_accept_blocks_competitors() {
        let mut mgr = VtAssociationManager::new();
        let _ = mgr.get_or_create_association(VtAssociationType::Function, addr(0x1000), addr(0x2000));
        let _ = mgr.get_or_create_association(VtAssociationType::Function, addr(0x1000), addr(0x3000));
        mgr.accept_association(1).unwrap();
        assert_eq!(mgr.get_association(1).unwrap().status(), VtAssociationStatus::Accepted);
        assert_eq!(mgr.get_association(2).unwrap().status(), VtAssociationStatus::Blocked);
    }

    #[test]
    fn test_association_manager_clear_unblocks() {
        let mut mgr = VtAssociationManager::new();
        let _ = mgr.get_or_create_association(VtAssociationType::Function, addr(0x1000), addr(0x2000));
        let _ = mgr.get_or_create_association(VtAssociationType::Function, addr(0x1000), addr(0x3000));
        mgr.accept_association(1).unwrap();
        mgr.clear_association(1).unwrap();
        assert_eq!(mgr.get_association(2).unwrap().status(), VtAssociationStatus::Available);
    }
}
