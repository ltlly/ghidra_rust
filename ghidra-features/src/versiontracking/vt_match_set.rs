//! VTMatchSet trait -- the interface for match sets.
//!
//! Corresponds to Ghidra's `VTMatchSet` Java interface.

use ghidra_core::addr::Address;

use crate::versiontracking::association::VtAssociation;
use crate::versiontracking::impl_module::ProgramCorrelatorInfoImpl;
use crate::versiontracking::vt_match::VtMatchImpl;

/// Trait for all the matches generated from a single program correlator run.
///
/// This is the Rust equivalent of Ghidra's `VTMatchSet` Java interface.
pub trait VtMatchSetTrait: Send + Sync {
    /// Returns the session ID that contains this match set.
    fn session_id(&self) -> u64;

    /// Creates a match based on the given info and adds it to this match set.
    fn add_match(&mut self, vt_match: VtMatchImpl) -> u64;

    /// Returns a collection of all VTMatches contained in this match set.
    fn get_matches(&self) -> Vec<&VtMatchImpl>;

    /// Returns information about the program correlator that was used to
    /// generate the matches for this match set.
    fn program_correlator_info(&self) -> &ProgramCorrelatorInfoImpl;

    /// Returns the number of matches contained in this match set.
    fn match_count(&self) -> usize;

    /// Returns a unique id for this match set.
    fn id(&self) -> u64;

    /// Returns a collection of all matches for the given association.
    fn get_matches_for_association(&self, association: &VtAssociation) -> Vec<&VtMatchImpl>;

    /// Returns a collection of matches for the given source and destination address.
    fn get_matches_for_addresses(
        &self,
        source_address: Address,
        destination_address: Address,
    ) -> Vec<&VtMatchImpl>;

    /// Deletes the given match from this match set.
    fn delete_match(&mut self, match_id: u64) -> bool;

    /// Removes a match from this match set.
    fn remove_match(&mut self, match_id: u64) -> bool;

    /// Returns whether this match set has any removable matches.
    fn has_removable_matches(&self) -> bool {
        true
    }
}

/// A concrete implementation of VtMatchSetTrait for use in non-database contexts.
#[derive(Debug, Clone)]
pub struct VtMatchSetImpl {
    /// Match set ID
    pub id: u64,
    /// Correlator name
    pub correlator_name: String,
    /// Program correlator info
    pub correlator_info: ProgramCorrelatorInfoImpl,
    /// Matches indexed by ID
    matches: std::collections::HashMap<u64, VtMatchImpl>,
    /// Next match ID
    next_match_id: u64,
    /// Session ID
    session_id: u64,
}

impl VtMatchSetImpl {
    /// Create a new match set implementation.
    pub fn new(id: u64, correlator_name: impl Into<String>) -> Self {
        let name = correlator_name.into();
        Self {
            id,
            correlator_info: ProgramCorrelatorInfoImpl::new(&name, &name),
            correlator_name: name,
            matches: std::collections::HashMap::new(),
            next_match_id: 1,
            session_id: 0,
        }
    }

    /// Set the session ID.
    pub fn set_session_id(&mut self, session_id: u64) {
        self.session_id = session_id;
    }

    /// Get a match by ID.
    pub fn get_match(&self, id: u64) -> Option<&VtMatchImpl> {
        self.matches.get(&id)
    }

    /// Get a mutable match by ID.
    pub fn get_match_mut(&mut self, id: u64) -> Option<&mut VtMatchImpl> {
        self.matches.get_mut(&id)
    }

    /// Returns matches sorted by similarity score (highest first).
    pub fn get_matches_by_score(&self) -> Vec<&VtMatchImpl> {
        let mut m: Vec<&VtMatchImpl> = self.matches.values().collect();
        m.sort_by(|a, b| b.sim_score.cmp(&a.sim_score));
        m
    }

    /// Clear all matches.
    pub fn clear(&mut self) {
        self.matches.clear();
    }

    /// Returns whether this match set is empty.
    pub fn is_empty(&self) -> bool {
        self.matches.is_empty()
    }
}

impl VtMatchSetTrait for VtMatchSetImpl {
    fn session_id(&self) -> u64 {
        self.session_id
    }

    fn add_match(&mut self, mut vt_match: VtMatchImpl) -> u64 {
        let match_id = self.next_match_id;
        self.next_match_id += 1;
        vt_match.match_set_id = self.id;
        self.matches.insert(match_id, vt_match);
        match_id
    }

    fn get_matches(&self) -> Vec<&VtMatchImpl> {
        self.matches.values().collect()
    }

    fn program_correlator_info(&self) -> &ProgramCorrelatorInfoImpl {
        &self.correlator_info
    }

    fn match_count(&self) -> usize {
        self.matches.len()
    }

    fn id(&self) -> u64 {
        self.id
    }

    fn get_matches_for_association(&self, association: &VtAssociation) -> Vec<&VtMatchImpl> {
        self.matches
            .values()
            .filter(|m| m.association_id == association.id)
            .collect()
    }

    fn get_matches_for_addresses(
        &self,
        source_address: Address,
        destination_address: Address,
    ) -> Vec<&VtMatchImpl> {
        self.matches
            .values()
            .filter(|m| m.source_addr == source_address && m.dest_addr == destination_address)
            .collect()
    }

    fn delete_match(&mut self, match_id: u64) -> bool {
        self.matches.remove(&match_id).is_some()
    }

    fn remove_match(&mut self, match_id: u64) -> bool {
        self.matches.remove(&match_id).is_some()
    }
}

impl std::fmt::Display for VtMatchSetImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MatchSet({}: {} matches)",
            self.correlator_name,
            self.matches.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::versiontracking::types::{VtAssociationType, VtScore};

    fn addr(v: u64) -> Address { Address::new(v) }

    fn make_match(src: u64, dst: u64, sim: f64) -> VtMatchImpl {
        VtMatchImpl::new(
            0, 0,
            addr(src), addr(dst),
            VtAssociationType::Function,
            VtScore::new(sim),
            VtScore::new(sim * 0.9),
        )
    }

    #[test]
    fn test_match_set_add_and_get() {
        let mut ms = VtMatchSetImpl::new(1, "ExactMatch");
        let id = ms.add_match(make_match(0x1000, 0x2000, 1.0));
        assert_eq!(ms.match_count(), 1);
        let m = ms.get_match(id).unwrap();
        assert_eq!(m.source_addr, addr(0x1000));
    }

    #[test]
    fn test_match_set_sorted_by_score() {
        let mut ms = VtMatchSetImpl::new(1, "Test");
        ms.add_match(make_match(0x1000, 0x2000, 0.5));
        ms.add_match(make_match(0x1100, 0x2100, 0.9));
        ms.add_match(make_match(0x1200, 0x2200, 0.7));
        let sorted = ms.get_matches_by_score();
        assert_eq!(sorted.len(), 3);
        assert!((sorted[0].sim_score.score() - 0.9).abs() < 0.01);
    }

    #[test]
    fn test_match_set_delete() {
        let mut ms = VtMatchSetImpl::new(1, "Test");
        let id = ms.add_match(make_match(0x1000, 0x2000, 0.5));
        assert_eq!(ms.match_count(), 1);
        assert!(ms.delete_match(id));
        assert_eq!(ms.match_count(), 0);
    }

    #[test]
    fn test_match_set_display() {
        let mut ms = VtMatchSetImpl::new(1, "ExactMatch");
        ms.add_match(make_match(0x1000, 0x2000, 1.0));
        assert!(format!("{}", ms).contains("ExactMatch"));
    }

    #[test]
    fn test_match_set_session_id() {
        let mut ms = VtMatchSetImpl::new(1, "Test");
        assert_eq!(ms.session_id(), 0);
        ms.set_session_id(42);
        assert_eq!(ms.session_id(), 42);
    }
}
