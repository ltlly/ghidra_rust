//! VTMatchDB -- database-backed VTMatch implementation.
//!
//! Corresponds to Ghidra's `VTMatchDB` Java class.

use crate::versiontracking::association::VtAssociation;
use crate::versiontracking::match_set::VtMatchSet;
use crate::versiontracking::types::{VtAssociationType, VtMatchTag, VtScore};
use crate::versiontracking::vt_match::{VtMatchImpl, VtMatchTrait};
use ghidra_core::addr::Address;

/// Database-backed match record.
///
/// Maps to a row in the match table and provides typed accessors
/// for all match fields. This is the Rust equivalent of Ghidra's
/// `VTMatchDB` Java class.
#[derive(Debug, Clone)]
pub struct VtMatchDB {
    /// Database key
    pub key: i64,
    /// The association ID this match references
    pub association_id: i64,
    /// The match set ID this match belongs to
    pub match_set_id: i64,
    /// Source address offset
    pub source_address: u64,
    /// Destination address offset
    pub destination_address: u64,
    /// Association type (0=Function, 1=Data)
    pub association_type: i32,
    /// Similarity score as string
    pub similarity_score_str: String,
    /// Confidence score as string
    pub confidence_score_str: String,
    /// Source length in bytes
    pub source_length: i32,
    /// Destination length in bytes
    pub destination_length: i32,
    /// Length type string (bytes/instructions/AL lines)
    pub length_type: String,
    /// Tag key (-1 if untagged)
    pub tag_key: i64,
    /// Cached hash
    hash: Option<u64>,
}

impl VtMatchDB {
    /// Create a new match DB record.
    pub fn new(key: i64, association_id: i64, match_set_id: i64) -> Self {
        Self {
            key,
            association_id,
            match_set_id,
            source_address: 0,
            destination_address: 0,
            association_type: 0,
            similarity_score_str: "0.000".to_string(),
            confidence_score_str: "0.000".to_string(),
            source_length: 0,
            destination_length: 0,
            length_type: "bytes".to_string(),
            tag_key: -1,
            hash: None,
        }
    }

    /// Create from a VtMatchImpl.
    pub fn from_match(key: i64, vt_match: &VtMatchImpl) -> Self {
        Self {
            key,
            association_id: vt_match.association_id as i64,
            match_set_id: vt_match.match_set_id as i64,
            source_address: vt_match.source_addr.get_offset(),
            destination_address: vt_match.dest_addr.get_offset(),
            association_type: match vt_match.assoc_type {
                VtAssociationType::Function => 0,
                VtAssociationType::Data => 1,
            },
            similarity_score_str: vt_match.sim_score.to_storage_string(),
            confidence_score_str: vt_match.conf_score.to_storage_string(),
            source_length: vt_match.src_length,
            destination_length: vt_match.dst_length,
            length_type: vt_match.len_type.clone(),
            tag_key: -1,
            hash: None,
        }
    }

    /// Convert to VtMatchImpl.
    pub fn to_match(&self) -> VtMatchImpl {
        VtMatchImpl {
            association_id: self.association_id as u64,
            match_set_id: self.match_set_id as u64,
            source_addr: Address::new(self.source_address),
            dest_addr: Address::new(self.destination_address),
            assoc_type: self.association_type_enum(),
            sim_score: self.similarity_score(),
            conf_score: self.confidence_score(),
            src_length: self.source_length,
            dst_length: self.destination_length,
            len_type: self.length_type.clone(),
            match_tag: None,
        }
    }

    /// Returns the similarity score.
    pub fn similarity_score(&self) -> VtScore {
        VtScore::from_str(&self.similarity_score_str).unwrap_or(VtScore::new(0.0))
    }

    /// Returns the confidence score.
    pub fn confidence_score(&self) -> VtScore {
        VtScore::from_str(&self.confidence_score_str).unwrap_or(VtScore::new(0.0))
    }

    /// Returns the association type.
    pub fn association_type_enum(&self) -> VtAssociationType {
        if self.association_type == 0 {
            VtAssociationType::Function
        } else {
            VtAssociationType::Data
        }
    }

    /// Returns whether this match is tagged.
    pub fn is_tagged(&self) -> bool {
        self.tag_key >= 0
    }

    /// Set the tag key.
    pub fn set_tag_key(&mut self, key: i64) {
        self.tag_key = key;
        self.hash = None; // Invalidate cache
    }

    /// Invalidate the cached hash.
    pub fn invalidate_hash(&mut self) {
        self.hash = None;
    }

    /// Update the record from a VtMatchImpl.
    pub fn update_from_match(&mut self, vt_match: &VtMatchImpl) {
        self.source_address = vt_match.source_addr.get_offset();
        self.destination_address = vt_match.dest_addr.get_offset();
        self.association_type = match vt_match.assoc_type {
            VtAssociationType::Function => 0,
            VtAssociationType::Data => 1,
        };
        self.similarity_score_str = vt_match.sim_score.to_storage_string();
        self.confidence_score_str = vt_match.conf_score.to_storage_string();
        self.source_length = vt_match.src_length;
        self.destination_length = vt_match.dst_length;
        self.length_type = vt_match.len_type.clone();
        self.hash = None;
    }

    /// Refresh from a record (simulates DB refresh).
    pub fn refresh(&mut self, association_id: i64, match_set_id: i64) {
        self.association_id = association_id;
        self.match_set_id = match_set_id;
        self.hash = None;
    }
}

impl std::fmt::Display for VtMatchDB {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MatchDB(key={}, assoc={}, src=0x{:x}, dst=0x{:x}, sim={})",
            self.key, self.association_id, self.source_address,
            self.destination_address, self.similarity_score_str
        )
    }
}

impl std::hash::Hash for VtMatchDB {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.key.hash(state);
        self.association_id.hash(state);
        self.match_set_id.hash(state);
    }
}

impl PartialEq for VtMatchDB {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
            && self.association_id == other.association_id
            && self.match_set_id == other.match_set_id
    }
}

impl Eq for VtMatchDB {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_db_create() {
        let m = VtMatchDB::new(1, 10, 5);
        assert_eq!(m.key, 1);
        assert_eq!(m.association_id, 10);
        assert_eq!(m.match_set_id, 5);
    }

    #[test]
    fn test_match_db_from_vt_match() {
        let vt_match = VtMatchImpl::new(
            10, 5,
            Address::new(0x1000), Address::new(0x2000),
            VtAssociationType::Function,
            VtScore::new(0.95),
            VtScore::new(0.85),
        );
        let db = VtMatchDB::from_match(1, &vt_match);
        assert_eq!(db.source_address, 0x1000);
        assert_eq!(db.destination_address, 0x2000);
        assert_eq!(db.association_type, 0);
        assert!((db.similarity_score().score() - 0.95).abs() < 0.01);
    }

    #[test]
    fn test_match_db_roundtrip() {
        let vt_match = VtMatchImpl::new(
            10, 5,
            Address::new(0x1000), Address::new(0x2000),
            VtAssociationType::Data,
            VtScore::new(0.75),
            VtScore::new(0.65),
        );
        let db = VtMatchDB::from_match(1, &vt_match);
        let restored = db.to_match();
        assert_eq!(restored.association_id, 10);
        assert_eq!(restored.assoc_type, VtAssociationType::Data);
        assert!((restored.sim_score.score() - 0.75).abs() < 0.01);
    }

    #[test]
    fn test_match_db_tag() {
        let mut m = VtMatchDB::new(1, 10, 5);
        assert!(!m.is_tagged());
        m.set_tag_key(42);
        assert!(m.is_tagged());
        assert_eq!(m.tag_key, 42);
    }

    #[test]
    fn test_match_db_display() {
        let m = VtMatchDB::new(1, 10, 5);
        let display = format!("{}", m);
        assert!(display.contains("MatchDB"));
        assert!(display.contains("key=1"));
    }

    #[test]
    fn test_match_db_update() {
        let mut m = VtMatchDB::new(1, 10, 5);
        let vt_match = VtMatchImpl::new(
            10, 5,
            Address::new(0x3000), Address::new(0x4000),
            VtAssociationType::Function,
            VtScore::new(0.99),
            VtScore::new(0.95),
        );
        m.update_from_match(&vt_match);
        assert_eq!(m.source_address, 0x3000);
        assert_eq!(m.destination_address, 0x4000);
    }

    #[test]
    fn test_match_db_equality() {
        let m1 = VtMatchDB::new(1, 10, 5);
        let m2 = VtMatchDB::new(1, 10, 5);
        let m3 = VtMatchDB::new(2, 10, 5);
        assert_eq!(m1, m2);
        assert_ne!(m1, m3);
    }
}
