//! VTMatch and VTMatchSet.

use std::collections::HashMap;
use std::fmt;
use ghidra_core::addr::Address;
use crate::versiontracking::types::{VtAssociationType, VtMatchTag, VtScore};

#[derive(Debug, Clone)]
pub struct VtMatch {
    pub association_id: u64, pub match_set_id: u64,
    pub source_address: Address, pub destination_address: Address,
    pub association_type: VtAssociationType,
    pub similarity_score: VtScore, pub confidence_score: VtScore,
    pub source_length: u64, pub destination_length: u64,
    pub length_type: String, pub tag: VtMatchTag,
}

impl VtMatch {
    pub const BYTES_LENGTH_TYPE: &'static str = "bytes";
    pub const INSTRUCTIONS_LENGTH_TYPE: &'static str = "instructions";
    pub const AL_LINES_LENGTH_TYPE: &'static str = "AL lines";
}

impl fmt::Display for VtMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} <-> {} (sim={}, conf={})", self.association_type, self.source_address, self.destination_address, self.similarity_score, self.confidence_score)
    }
}

#[derive(Debug, Clone)]
pub struct VtMatchSet { pub id: u64, pub correlator_name: String, matches: HashMap<u64, VtMatch>, next_match_id: u64 }

impl VtMatchSet {
    pub fn new(id: u64, correlator_name: impl Into<String>) -> Self { Self { id, correlator_name: correlator_name.into(), matches: HashMap::new(), next_match_id: 1 } }
    pub fn add_match(&mut self, mut vt_match: VtMatch) -> u64 { let match_id = self.next_match_id; self.next_match_id += 1; vt_match.match_set_id = self.id; self.matches.insert(match_id, vt_match); match_id }
    pub fn get_match(&self, id: u64) -> Option<&VtMatch> { self.matches.get(&id) }
    pub fn get_matches(&self) -> Vec<&VtMatch> { self.matches.values().collect() }
    pub fn get_matches_by_score(&self) -> Vec<&VtMatch> { let mut m: Vec<&VtMatch> = self.matches.values().collect(); m.sort_by(|a, b| b.similarity_score.cmp(&a.similarity_score)); m }
    pub fn match_count(&self) -> usize { self.matches.len() }
    pub fn delete_match(&mut self, id: u64) -> bool { self.matches.remove(&id).is_some() }
    pub fn get_matches_for_association(&self, association_id: u64) -> Vec<&VtMatch> { self.matches.values().filter(|m| m.association_id == association_id).collect() }
    pub fn clear(&mut self) { self.matches.clear(); }
    pub fn is_empty(&self) -> bool { self.matches.is_empty() }
}

impl fmt::Display for VtMatchSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "MatchSet({}: {} matches)", self.correlator_name, self.matches.len()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(v: u64) -> Address { Address::new(v) }

    fn make_match(src: u64, dst: u64, sim: f64) -> VtMatch {
        VtMatch { association_id: 0, match_set_id: 0, source_address: addr(src), destination_address: addr(dst),
            association_type: VtAssociationType::Function, similarity_score: VtScore::new(sim), confidence_score: VtScore::new(sim * 0.9),
            source_length: 100, destination_length: 100, length_type: "bytes".to_string(), tag: VtMatchTag::untagged() }
    }

    #[test]
    fn test_match_set_add_and_get() {
        let mut ms = VtMatchSet::new(1, "ExactMatch");
        let id = ms.add_match(make_match(0x1000, 0x2000, 1.0));
        assert_eq!(ms.match_count(), 1);
        let m = ms.get_match(id).unwrap();
        assert_eq!(m.source_address, addr(0x1000));
    }

    #[test]
    fn test_match_set_sorted_by_score() {
        let mut ms = VtMatchSet::new(1, "Test");
        ms.add_match(make_match(0x1000, 0x2000, 0.5));
        ms.add_match(make_match(0x1100, 0x2100, 0.9));
        ms.add_match(make_match(0x1200, 0x2200, 0.7));
        let sorted = ms.get_matches_by_score();
        assert_eq!(sorted.len(), 3);
        assert!((sorted[0].similarity_score.score() - 0.9).abs() < 0.01);
    }

    #[test]
    fn test_match_set_display() {
        let mut ms = VtMatchSet::new(1, "ExactMatch");
        ms.add_match(make_match(0x1000, 0x2000, 1.0));
        assert!(format!("{}", ms).contains("ExactMatch"));
    }
}
