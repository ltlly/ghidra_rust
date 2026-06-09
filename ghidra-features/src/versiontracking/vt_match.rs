//! VTMatch trait -- the interface for version tracking matches.
//!
//! Corresponds to Ghidra's `VTMatch` Java interface.

use ghidra_core::addr::Address;

use crate::versiontracking::association::VtAssociation;
use crate::versiontracking::match_set::VtMatchSet;
use crate::versiontracking::types::{VtAssociationType, VtMatchTag, VtScore};

/// Trait for version tracking matches.
///
/// A VTMatch is a scoring by some algorithm that indicates a possibility
/// that one function or data item in one program matches a function or data
/// item in another program. It consists of an association (a pairing of
/// functions or data from one program to another) and a scoring of how
/// likely the pairing is correct.
///
/// This is the Rust equivalent of Ghidra's `VTMatch` Java interface.
pub trait VtMatchTrait: Send + Sync {
    /// Returns the VTMatchSet that contains this match.
    fn match_set(&self) -> &VtMatchSet;

    /// Returns the VTAssociation that this match is suggesting.
    fn association(&self) -> &VtAssociation;

    /// Returns the tag that has been applied to this match, or None if not tagged.
    fn tag(&self) -> Option<&VtMatchTag>;

    /// Sets the tag for this match. Any previous tag is replaced.
    /// A value of None will remove any existing tag.
    fn set_tag(&mut self, tag: Option<VtMatchTag>);

    /// Returns a score that attempts to indicate how similar the associated
    /// items are to each other in a normalized score between 0 and 1.
    ///
    /// Note that short functions may have high similarity scores even though
    /// they are not really a match.
    fn similarity_score(&self) -> &VtScore;

    /// Returns a confidence score which is generally a combination of the
    /// similarity score and some measure of the length of the functions.
    ///
    /// Note that this score is not normalized and all that it indicates is
    /// that higher numbers are more likely to be correct than lower numbers.
    /// Comparing scores from different algorithms is meaningless.
    fn confidence_score(&self) -> &VtScore;

    /// Returns the address in the source program for a match.
    fn source_address(&self) -> Address;

    /// Returns the address in the destination program for a match.
    fn destination_address(&self) -> Address;

    /// Returns the length of the source function or data.
    fn source_length(&self) -> i32;

    /// Returns the length of the destination function or data.
    fn destination_length(&self) -> i32;

    /// Returns the association type (Function or Data).
    fn association_type(&self) -> VtAssociationType;

    /// Returns the length type string (bytes, instructions, or AL lines).
    fn length_type(&self) -> &str;
}

/// Length type constants for matches.
pub mod length_type {
    /// Length measured in bytes.
    pub const BYTES: &str = "bytes";
    /// Length measured in instructions.
    pub const INSTRUCTIONS: &str = "instructions";
    /// Length measured in AL lines.
    pub const AL_LINES: &str = "AL lines";
}

/// A concrete implementation of VTMatchTrait for use in non-database contexts.
#[derive(Debug, Clone)]
pub struct VtMatchImpl {
    /// Association ID
    pub association_id: u64,
    /// Match set ID
    pub match_set_id: u64,
    /// Source address
    pub source_addr: Address,
    /// Destination address
    pub dest_addr: Address,
    /// Association type
    pub assoc_type: VtAssociationType,
    /// Similarity score
    pub sim_score: VtScore,
    /// Confidence score
    pub conf_score: VtScore,
    /// Source length
    pub src_length: i32,
    /// Destination length
    pub dst_length: i32,
    /// Length type
    pub len_type: String,
    /// Tag (if any)
    pub match_tag: Option<VtMatchTag>,
}

impl VtMatchImpl {
    /// Length type constant for bytes.
    pub const BYTES_LENGTH_TYPE: &'static str = "bytes";
    /// Length type constant for instructions.
    pub const INSTRUCTIONS_LENGTH_TYPE: &'static str = "instructions";
    /// Length type constant for AL lines.
    pub const AL_LINES_LENGTH_TYPE: &'static str = "AL lines";

    /// Create a new match implementation.
    pub fn new(
        association_id: u64,
        match_set_id: u64,
        source_addr: Address,
        dest_addr: Address,
        assoc_type: VtAssociationType,
        sim_score: VtScore,
        conf_score: VtScore,
    ) -> Self {
        Self {
            association_id,
            match_set_id,
            source_addr,
            dest_addr,
            assoc_type,
            sim_score,
            conf_score,
            src_length: 0,
            dst_length: 0,
            len_type: Self::BYTES_LENGTH_TYPE.to_string(),
            match_tag: None,
        }
    }

    /// Returns whether this match is tagged.
    pub fn is_tagged(&self) -> bool {
        self.match_tag.is_some()
    }
}

impl std::fmt::Display for VtMatchImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] 0x{:x} <-> 0x{:x} (sim={}, conf={})",
            self.assoc_type, self.source_addr.offset, self.dest_addr.offset,
            self.sim_score, self.conf_score
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(v: u64) -> Address { Address::new(v) }

    #[test]
    fn test_vt_match_impl_creation() {
        let m = VtMatchImpl::new(
            1, 10,
            addr(0x1000), addr(0x2000),
            VtAssociationType::Function,
            VtScore::new(0.95),
            VtScore::new(0.85),
        );
        assert_eq!(m.association_id, 1);
        assert_eq!(m.match_set_id, 10);
        assert_eq!(m.source_addr, addr(0x1000));
        assert_eq!(m.dest_addr, addr(0x2000));
        assert_eq!(m.assoc_type, VtAssociationType::Function);
    }

    #[test]
    fn test_vt_match_impl_tag() {
        let mut m = VtMatchImpl::new(
            1, 10,
            addr(0x1000), addr(0x2000),
            VtAssociationType::Function,
            VtScore::new(0.95),
            VtScore::new(0.85),
        );
        assert!(!m.is_tagged());
        m.match_tag = Some(VtMatchTag::new("verified"));
        assert!(m.is_tagged());
    }

    #[test]
    fn test_vt_match_impl_length_type() {
        let m = VtMatchImpl::new(
            1, 10,
            addr(0x1000), addr(0x2000),
            VtAssociationType::Function,
            VtScore::new(0.95),
            VtScore::new(0.85),
        );
        assert_eq!(m.len_type, VtMatchImpl::BYTES_LENGTH_TYPE);
    }

    #[test]
    fn test_vt_match_impl_display() {
        let m = VtMatchImpl::new(
            1, 10,
            addr(0x1000), addr(0x2000),
            VtAssociationType::Function,
            VtScore::new(0.95),
            VtScore::new(0.85),
        );
        let display = format!("{}", m);
        assert!(display.contains("Function"));
        assert!(display.contains("0x1000"));
        assert!(display.contains("0x2000"));
    }

    #[test]
    fn test_length_type_constants() {
        assert_eq!(length_type::BYTES, "bytes");
        assert_eq!(length_type::INSTRUCTIONS, "instructions");
        assert_eq!(length_type::AL_LINES, "AL lines");
    }
}
