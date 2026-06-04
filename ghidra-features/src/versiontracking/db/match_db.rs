//! Database-backed VTMatch.

use crate::versiontracking::match_set::VtMatch;
use crate::versiontracking::types::{VtAssociationType, VtMatchTag, VtScore};
use ghidra_core::addr::Address;

/// Database-backed match record.
///
/// Maps to a row in the match table and provides typed accessors
/// for all match fields.
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
        }
    }

    /// Create from a VtMatch.
    pub fn from_match(key: i64, vt_match: &VtMatch) -> Self {
        Self {
            key,
            association_id: vt_match.association_id as i64,
            match_set_id: vt_match.match_set_id as i64,
            source_address: vt_match.source_address.get_offset(),
            destination_address: vt_match.destination_address.get_offset(),
            association_type: match vt_match.association_type {
                VtAssociationType::Function => 0,
                VtAssociationType::Data => 1,
            },
            similarity_score_str: vt_match.similarity_score.to_storage_string(),
            confidence_score_str: vt_match.confidence_score.to_storage_string(),
            source_length: vt_match.source_length as i32,
            destination_length: vt_match.destination_length as i32,
            length_type: vt_match.length_type.clone(),
            tag_key: -1,
        }
    }

    /// Convert to VtMatch.
    pub fn to_match(&self) -> VtMatch {
        VtMatch {
            association_id: self.association_id as u64,
            match_set_id: self.match_set_id as u64,
            source_address: Address::new(self.source_address),
            destination_address: Address::new(self.destination_address),
            association_type: if self.association_type == 0 {
                VtAssociationType::Function
            } else {
                VtAssociationType::Data
            },
            similarity_score: VtScore::from_str(&self.similarity_score_str).unwrap_or(VtScore::new(0.0)),
            confidence_score: VtScore::from_str(&self.confidence_score_str).unwrap_or(VtScore::new(0.0)),
            source_length: self.source_length as u64,
            destination_length: self.destination_length as u64,
            length_type: self.length_type.clone(),
            tag: VtMatchTag::untagged(),
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
        let vt_match = VtMatch {
            association_id: 10,
            match_set_id: 5,
            source_address: Address::new(0x1000),
            destination_address: Address::new(0x2000),
            association_type: VtAssociationType::Function,
            similarity_score: VtScore::new(0.95),
            confidence_score: VtScore::new(0.85),
            source_length: 100,
            destination_length: 120,
            length_type: "bytes".to_string(),
            tag: VtMatchTag::untagged(),
        };
        let db = VtMatchDB::from_match(1, &vt_match);
        assert_eq!(db.source_address, 0x1000);
        assert_eq!(db.destination_address, 0x2000);
        assert_eq!(db.association_type, 0);
        assert!((db.similarity_score().score() - 0.95).abs() < 0.01);
    }

    #[test]
    fn test_match_db_roundtrip() {
        let vt_match = VtMatch {
            association_id: 10,
            match_set_id: 5,
            source_address: Address::new(0x1000),
            destination_address: Address::new(0x2000),
            association_type: VtAssociationType::Data,
            similarity_score: VtScore::new(0.75),
            confidence_score: VtScore::new(0.65),
            source_length: 50,
            destination_length: 60,
            length_type: "instructions".to_string(),
            tag: VtMatchTag::new("test"),
        };
        let db = VtMatchDB::from_match(1, &vt_match);
        let restored = db.to_match();
        assert_eq!(restored.association_id, 10);
        assert_eq!(restored.association_type, VtAssociationType::Data);
        assert!((restored.similarity_score.score() - 0.75).abs() < 0.01);
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
}
