//! VTMatchInfo -- additional metadata for a version tracking match.
//!
//! Corresponds to Ghidra's `VTMatchInfo` Java class.
//!
//! A `VtMatchInfo` bundles extra detail that is stored alongside each match:
//! the association type, similarity/confidence scores, source and destination
//! addresses, lengths, tag, and the match set it belongs to.

use std::fmt;

use ghidra_core::addr::Address;

use crate::versiontracking::types::{
    VtAssociationType, VtMatchInfo, VtMatchTag, VtScore,
};

/// Extension methods for the `VtMatchInfo` struct defined in `types.rs`.
///
/// These are implemented via a trait so that `VtMatchInfo` stays a plain data
/// struct in `types.rs` while gaining richer behaviour here.
pub trait VtMatchInfoExt {
    /// Create a new match info for a function match.
    fn function_match_info(
        similarity: f64,
        confidence: f64,
        source_address: u64,
        destination_address: u64,
        source_length: u64,
        destination_length: u64,
        length_type: impl Into<String>,
    ) -> VtMatchInfo;

    /// Create a new match info for a data match.
    fn data_match_info(
        similarity: f64,
        confidence: f64,
        source_address: u64,
        destination_address: u64,
        source_length: u64,
        destination_length: u64,
        length_type: impl Into<String>,
    ) -> VtMatchInfo;

    /// Create a match info with default scores.
    fn with_defaults(association_type: VtAssociationType) -> VtMatchInfo;

    /// Create a match info associated with a specific match set.
    fn with_match_set(
        association_type: VtAssociationType,
        match_set_id: u64,
    ) -> VtMatchInfo;

    /// Set the tag on this match info.
    fn set_tag(&mut self, tag: VtMatchTag);

    /// Whether the similarity score is at or above a given threshold.
    fn is_high_similarity(&self, threshold: f64) -> bool;

    /// Whether the confidence score is at or above a given threshold.
    fn is_high_confidence(&self, threshold: f64) -> bool;

    /// Whether source and destination lengths are the same.
    fn has_same_length(&self) -> bool;

    /// The absolute difference between source and destination lengths.
    fn length_delta(&self) -> u64;

    /// Ratio of the shorter length to the longer (1.0 if equal).
    fn length_ratio(&self) -> f64;

    /// Whether this match info has valid source and destination addresses.
    fn has_addresses(&self) -> bool;

    /// Get the source address as an `Address`.
    fn source_addr(&self) -> Address;

    /// Get the destination address as an `Address`.
    fn dest_addr(&self) -> Address;

    /// Whether this match info belongs to a match set.
    fn has_match_set(&self) -> bool;

    /// Get the match set ID, or 0 if none.
    fn match_set_id(&self) -> u64;

    /// Format a brief one-line summary.
    fn summary_line(&self) -> String;

    /// Format a detailed multi-line summary (matching Java's toString).
    fn detailed_string(&self) -> String;
}

impl VtMatchInfoExt for VtMatchInfo {
    fn function_match_info(
        similarity: f64,
        confidence: f64,
        source_address: u64,
        destination_address: u64,
        source_length: u64,
        destination_length: u64,
        length_type: impl Into<String>,
    ) -> VtMatchInfo {
        VtMatchInfo {
            association_type: VtAssociationType::Function,
            tag: VtMatchTag::untagged(),
            similarity_score: VtScore::new(similarity),
            confidence_score: VtScore::new(confidence),
            source_address,
            destination_address,
            source_length,
            destination_length,
            length_type: length_type.into(),
            match_set_id: 0,
        }
    }

    fn data_match_info(
        similarity: f64,
        confidence: f64,
        source_address: u64,
        destination_address: u64,
        source_length: u64,
        destination_length: u64,
        length_type: impl Into<String>,
    ) -> VtMatchInfo {
        VtMatchInfo {
            association_type: VtAssociationType::Data,
            tag: VtMatchTag::untagged(),
            similarity_score: VtScore::new(similarity),
            confidence_score: VtScore::new(confidence),
            source_address,
            destination_address,
            source_length,
            destination_length,
            length_type: length_type.into(),
            match_set_id: 0,
        }
    }

    fn with_defaults(association_type: VtAssociationType) -> VtMatchInfo {
        VtMatchInfo {
            association_type,
            tag: VtMatchTag::untagged(),
            similarity_score: VtScore::new(0.0),
            confidence_score: VtScore::new(0.0),
            source_address: 0,
            destination_address: 0,
            source_length: 0,
            destination_length: 0,
            length_type: "bytes".to_string(),
            match_set_id: 0,
        }
    }

    fn with_match_set(
        association_type: VtAssociationType,
        match_set_id: u64,
    ) -> VtMatchInfo {
        VtMatchInfo {
            association_type,
            tag: VtMatchTag::untagged(),
            similarity_score: VtScore::new(0.0),
            confidence_score: VtScore::new(0.0),
            source_address: 0,
            destination_address: 0,
            source_length: 0,
            destination_length: 0,
            length_type: "bytes".to_string(),
            match_set_id,
        }
    }

    fn set_tag(&mut self, tag: VtMatchTag) {
        self.tag = tag;
    }

    fn is_high_similarity(&self, threshold: f64) -> bool {
        self.similarity_score.score() >= threshold
    }

    fn is_high_confidence(&self, threshold: f64) -> bool {
        self.confidence_score.score() >= threshold
    }

    fn has_same_length(&self) -> bool {
        self.source_length == self.destination_length
    }

    fn length_delta(&self) -> u64 {
        if self.source_length >= self.destination_length {
            self.source_length - self.destination_length
        } else {
            self.destination_length - self.source_length
        }
    }

    fn length_ratio(&self) -> f64 {
        let max_len = self.source_length.max(self.destination_length);
        if max_len == 0 {
            1.0
        } else {
            self.source_length.min(self.destination_length) as f64 / max_len as f64
        }
    }

    fn has_addresses(&self) -> bool {
        self.source_address != 0 || self.destination_address != 0
    }

    fn source_addr(&self) -> Address {
        Address::new(self.source_address)
    }

    fn dest_addr(&self) -> Address {
        Address::new(self.destination_address)
    }

    fn has_match_set(&self) -> bool {
        self.match_set_id != 0
    }

    fn match_set_id(&self) -> u64 {
        self.match_set_id
    }

    fn summary_line(&self) -> String {
        format!(
            "[{}] sim={:.3} conf={:.3} src_len={} dst_len={} ({})",
            self.association_type,
            self.similarity_score.score(),
            self.confidence_score.score(),
            self.source_length,
            self.destination_length,
            self.length_type,
        )
    }

    fn detailed_string(&self) -> String {
        let sim = self.similarity_score.score();
        let conf = self.confidence_score.score();
        format!(
            "\nMatchInfo: \
             \n  Type               = {}\
             \n  Similarity Score   = {}\
             \n  Confidence Score   = {}\
             \n  SourceAddress      = 0x{:x}\
             \n  DestinationAddress = 0x{:x}\
             \n  SourceLength       = {}\
             \n  DestinationLength  = {}\
             \n  Tagged             = {}",
            self.association_type,
            sim,
            conf,
            self.source_address,
            self.destination_address,
            self.source_length,
            self.destination_length,
            self.tag,
        )
    }
}

/// A builder for constructing `VtMatchInfo` instances step-by-step.
#[derive(Debug, Clone)]
pub struct VtMatchInfoBuilder {
    association_type: VtAssociationType,
    tag: VtMatchTag,
    similarity: f64,
    confidence: f64,
    source_address: u64,
    destination_address: u64,
    source_length: u64,
    destination_length: u64,
    length_type: String,
    match_set_id: u64,
}

impl VtMatchInfoBuilder {
    /// Start building a match info for the given association type.
    pub fn new(association_type: VtAssociationType) -> Self {
        Self {
            association_type,
            tag: VtMatchTag::untagged(),
            similarity: 0.0,
            confidence: 0.0,
            source_address: 0,
            destination_address: 0,
            source_length: 0,
            destination_length: 0,
            length_type: "bytes".to_string(),
            match_set_id: 0,
        }
    }

    /// Set the tag.
    pub fn tag(mut self, tag: VtMatchTag) -> Self {
        self.tag = tag;
        self
    }

    /// Set the similarity score.
    pub fn similarity(mut self, score: f64) -> Self {
        self.similarity = score;
        self
    }

    /// Set the confidence score.
    pub fn confidence(mut self, score: f64) -> Self {
        self.confidence = score;
        self
    }

    /// Set the source address.
    pub fn source_address(mut self, addr: u64) -> Self {
        self.source_address = addr;
        self
    }

    /// Set the destination address.
    pub fn destination_address(mut self, addr: u64) -> Self {
        self.destination_address = addr;
        self
    }

    /// Set the source length.
    pub fn source_length(mut self, len: u64) -> Self {
        self.source_length = len;
        self
    }

    /// Set the destination length.
    pub fn destination_length(mut self, len: u64) -> Self {
        self.destination_length = len;
        self
    }

    /// Set both lengths to the same value.
    pub fn lengths(mut self, len: u64) -> Self {
        self.source_length = len;
        self.destination_length = len;
        self
    }

    /// Set the length type string.
    pub fn length_type(mut self, lt: impl Into<String>) -> Self {
        self.length_type = lt.into();
        self
    }

    /// Set the match set ID.
    pub fn match_set_id(mut self, id: u64) -> Self {
        self.match_set_id = id;
        self
    }

    /// Build the `VtMatchInfo`.
    pub fn build(self) -> VtMatchInfo {
        VtMatchInfo {
            association_type: self.association_type,
            tag: self.tag,
            similarity_score: VtScore::new(self.similarity),
            confidence_score: VtScore::new(self.confidence),
            source_address: self.source_address,
            destination_address: self.destination_address,
            source_length: self.source_length,
            destination_length: self.destination_length,
            length_type: self.length_type,
            match_set_id: self.match_set_id,
        }
    }
}

impl fmt::Display for VtMatchInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VtMatchInfo[type={}, sim={}, conf={}, src_addr=0x{:x}, dst_addr=0x{:x}, src_len={}, dst_len={}, len_type={}, tag={}]",
            self.association_type,
            self.similarity_score,
            self.confidence_score,
            self.source_address,
            self.destination_address,
            self.source_length,
            self.destination_length,
            self.length_type,
            self.tag,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_match_info() {
        let info = VtMatchInfo::function_match_info(0.95, 0.85, 0x1000, 0x2000, 100, 100, "bytes");
        assert_eq!(info.association_type, VtAssociationType::Function);
        assert!((info.similarity_score.score() - 0.95).abs() < 0.001);
        assert!((info.confidence_score.score() - 0.85).abs() < 0.001);
        assert_eq!(info.source_address, 0x1000);
        assert_eq!(info.destination_address, 0x2000);
        assert_eq!(info.source_length, 100);
        assert_eq!(info.destination_length, 100);
        assert_eq!(info.length_type, "bytes");
        assert!(info.tag.is_untagged());
        assert_eq!(info.match_set_id, 0);
    }

    #[test]
    fn test_data_match_info() {
        let info = VtMatchInfo::data_match_info(0.8, 0.7, 0x3000, 0x4000, 4, 4, "bytes");
        assert_eq!(info.association_type, VtAssociationType::Data);
        assert!((info.similarity_score.score() - 0.8).abs() < 0.001);
        assert_eq!(info.source_address, 0x3000);
        assert_eq!(info.destination_address, 0x4000);
    }

    #[test]
    fn test_with_defaults() {
        let info = VtMatchInfo::with_defaults(VtAssociationType::Function);
        assert_eq!(info.association_type, VtAssociationType::Function);
        assert!((info.similarity_score.score() - 0.0).abs() < f64::EPSILON);
        assert!((info.confidence_score.score() - 0.0).abs() < f64::EPSILON);
        assert_eq!(info.source_address, 0);
        assert_eq!(info.destination_address, 0);
        assert_eq!(info.source_length, 0);
        assert_eq!(info.destination_length, 0);
        assert_eq!(info.length_type, "bytes");
        assert!(info.tag.is_untagged());
        assert_eq!(info.match_set_id, 0);
    }

    #[test]
    fn test_with_match_set() {
        let info = VtMatchInfo::with_match_set(VtAssociationType::Function, 42);
        assert_eq!(info.match_set_id, 42);
        assert!(info.has_match_set());
    }

    #[test]
    fn test_set_tag() {
        let mut info = VtMatchInfo::with_defaults(VtAssociationType::Function);
        assert!(info.tag.is_untagged());
        info.set_tag(VtMatchTag::new("verified"));
        assert_eq!(info.tag.name(), "verified");
        assert!(!info.tag.is_untagged());
    }

    #[test]
    fn test_high_similarity_and_confidence() {
        let info = VtMatchInfo::function_match_info(0.95, 0.85, 0, 0, 100, 100, "bytes");
        assert!(info.is_high_similarity(0.9));
        assert!(!info.is_high_similarity(1.0));
        assert!(info.is_high_confidence(0.8));
        assert!(!info.is_high_confidence(0.9));
    }

    #[test]
    fn test_same_length() {
        let info = VtMatchInfo::function_match_info(1.0, 1.0, 0, 0, 100, 100, "bytes");
        assert!(info.has_same_length());
        assert_eq!(info.length_delta(), 0);
        assert!((info.length_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_different_length() {
        let info = VtMatchInfo::function_match_info(0.8, 0.7, 0, 0, 100, 80, "bytes");
        assert!(!info.has_same_length());
        assert_eq!(info.length_delta(), 20);
        assert!((info.length_ratio() - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_length_ratio_zero_lengths() {
        let info = VtMatchInfo::with_defaults(VtAssociationType::Function);
        assert!((info.length_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_has_addresses() {
        let mut info = VtMatchInfo::with_defaults(VtAssociationType::Function);
        assert!(!info.has_addresses());
        info.source_address = 0x1000;
        assert!(info.has_addresses());
    }

    #[test]
    fn test_source_dest_addr() {
        let info = VtMatchInfo::function_match_info(1.0, 1.0, 0x1000, 0x2000, 10, 10, "bytes");
        assert_eq!(info.source_addr(), Address::new(0x1000));
        assert_eq!(info.dest_addr(), Address::new(0x2000));
    }

    #[test]
    fn test_summary_line() {
        let info = VtMatchInfo::function_match_info(0.95, 0.85, 0, 0, 100, 100, "instructions");
        let summary = info.summary_line();
        assert!(summary.contains("Function"));
        assert!(summary.contains("instructions"));
    }

    #[test]
    fn test_detailed_string() {
        let info = VtMatchInfo::function_match_info(0.9, 0.8, 0x1000, 0x2000, 50, 50, "bytes");
        let detail = info.detailed_string();
        assert!(detail.contains("MatchInfo"));
        assert!(detail.contains("Function"));
        assert!(detail.contains("0x1000"));
        assert!(detail.contains("0x2000"));
    }

    #[test]
    fn test_builder() {
        let info = VtMatchInfoBuilder::new(VtAssociationType::Data)
            .similarity(0.75)
            .confidence(0.6)
            .source_address(0x3000)
            .destination_address(0x4000)
            .source_length(8)
            .destination_length(8)
            .length_type("bytes")
            .build();
        assert_eq!(info.association_type, VtAssociationType::Data);
        assert!((info.similarity_score.score() - 0.75).abs() < 0.001);
        assert!((info.confidence_score.score() - 0.6).abs() < 0.001);
        assert_eq!(info.source_address, 0x3000);
        assert_eq!(info.destination_address, 0x4000);
        assert_eq!(info.source_length, 8);
    }

    #[test]
    fn test_builder_lengths_shorthand() {
        let info = VtMatchInfoBuilder::new(VtAssociationType::Function)
            .similarity(1.0)
            .confidence(1.0)
            .lengths(64)
            .build();
        assert_eq!(info.source_length, 64);
        assert_eq!(info.destination_length, 64);
    }

    #[test]
    fn test_builder_tag_and_match_set() {
        let info = VtMatchInfoBuilder::new(VtAssociationType::Function)
            .tag(VtMatchTag::new("verified"))
            .match_set_id(7)
            .build();
        assert_eq!(info.tag.name(), "verified");
        assert_eq!(info.match_set_id, 7);
        assert!(info.has_match_set());
    }

    #[test]
    fn test_display() {
        let info = VtMatchInfo::function_match_info(0.9, 0.8, 0x1000, 0x2000, 50, 50, "bytes");
        let display = format!("{}", info);
        assert!(display.contains("VtMatchInfo"));
        assert!(display.contains("Function"));
        assert!(display.contains("0x1000"));
        assert!(display.contains("0x2000"));
    }
}
