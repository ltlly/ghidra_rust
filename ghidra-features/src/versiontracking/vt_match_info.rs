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

/// Validation errors for `VtMatchInfo`.
#[derive(Debug, Clone, PartialEq)]
pub enum VtMatchInfoValidationError {
    /// Similarity score is outside the valid range [0.0, 1.0].
    InvalidSimilarityScore(f64),
    /// Confidence score is outside the valid range [0.0, 1.0].
    InvalidConfidenceScore(f64),
}

impl fmt::Display for VtMatchInfoValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSimilarityScore(s) => write!(f, "invalid similarity score: {}", s),
            Self::InvalidConfidenceScore(c) => write!(f, "invalid confidence score: {}", c),
        }
    }
}

impl std::error::Error for VtMatchInfoValidationError {}

/// Extension: validation and comparison on `VtMatchInfo`.
impl VtMatchInfo {
    /// Validate that scores are within the expected range [0.0, 1.0].
    pub fn validate(&self) -> Result<(), VtMatchInfoValidationError> {
        let sim = self.similarity_score.score();
        if sim < 0.0 || sim > 1.0 {
            return Err(VtMatchInfoValidationError::InvalidSimilarityScore(sim));
        }
        let conf = self.confidence_score.score();
        if conf < 0.0 || conf > 1.0 {
            return Err(VtMatchInfoValidationError::InvalidConfidenceScore(conf));
        }
        Ok(())
    }

    /// Compare two match infos and determine which is "better".
    ///
    /// First compares by similarity score, then breaks ties by confidence.
    pub fn is_better_than(&self, other: &VtMatchInfo) -> bool {
        let sim_ord = self.similarity_score.cmp(&other.similarity_score);
        if sim_ord != std::cmp::Ordering::Equal {
            return sim_ord == std::cmp::Ordering::Greater;
        }
        self.confidence_score > other.confidence_score
    }
}

// ---------------------------------------------------------------------------
// VtMatchInfoFilter
// ---------------------------------------------------------------------------

/// A filter for selecting match infos that meet specified criteria.
///
/// All criteria are combined with AND logic -- a match info must satisfy
/// every set criterion to pass the filter.
#[derive(Debug, Clone)]
pub struct VtMatchInfoFilter {
    min_similarity: Option<f64>,
    min_confidence: Option<f64>,
    association_type: Option<VtAssociationType>,
    min_length: Option<u64>,
    max_length: Option<u64>,
    match_set_id: Option<u64>,
    tagged_only: bool,
    untagged_only: bool,
}

impl VtMatchInfoFilter {
    /// Create a new filter with no criteria (matches everything).
    pub fn new() -> Self {
        Self {
            min_similarity: None,
            min_confidence: None,
            association_type: None,
            min_length: None,
            max_length: None,
            match_set_id: None,
            tagged_only: false,
            untagged_only: false,
        }
    }

    /// Set the minimum similarity score threshold.
    pub fn min_similarity(mut self, threshold: f64) -> Self {
        self.min_similarity = Some(threshold);
        self
    }

    /// Set the minimum confidence score threshold.
    pub fn min_confidence(mut self, threshold: f64) -> Self {
        self.min_confidence = Some(threshold);
        self
    }

    /// Restrict to a specific association type.
    pub fn association_type(mut self, assoc_type: VtAssociationType) -> Self {
        self.association_type = Some(assoc_type);
        self
    }

    /// Set the minimum source length.
    pub fn min_length(mut self, min: u64) -> Self {
        self.min_length = Some(min);
        self
    }

    /// Set the maximum source length.
    pub fn max_length(mut self, max: u64) -> Self {
        self.max_length = Some(max);
        self
    }

    /// Restrict to a specific match set ID.
    pub fn match_set_id(mut self, id: u64) -> Self {
        self.match_set_id = Some(id);
        self
    }

    /// Only include tagged match infos.
    pub fn tagged_only(mut self) -> Self {
        self.tagged_only = true;
        self.untagged_only = false;
        self
    }

    /// Only include untagged match infos.
    pub fn untagged_only(mut self) -> Self {
        self.untagged_only = true;
        self.tagged_only = false;
        self
    }

    /// Check whether a single match info passes this filter.
    pub fn matches(&self, info: &VtMatchInfo) -> bool {
        if let Some(min_sim) = self.min_similarity {
            if info.similarity_score.score() < min_sim {
                return false;
            }
        }
        if let Some(min_conf) = self.min_confidence {
            if info.confidence_score.score() < min_conf {
                return false;
            }
        }
        if let Some(ref at) = self.association_type {
            if info.association_type != *at {
                return false;
            }
        }
        if let Some(min_len) = self.min_length {
            let len = info.source_length.min(info.destination_length);
            if len < min_len {
                return false;
            }
        }
        if let Some(max_len) = self.max_length {
            let len = info.source_length.max(info.destination_length);
            if len > max_len {
                return false;
            }
        }
        if let Some(ms_id) = self.match_set_id {
            if info.match_set_id != ms_id {
                return false;
            }
        }
        if self.tagged_only && info.tag.is_untagged() {
            return false;
        }
        if self.untagged_only && !info.tag.is_untagged() {
            return false;
        }
        true
    }

    /// Filter a slice of match infos, returning only those that pass.
    pub fn filter<'a>(&self, infos: &'a [VtMatchInfo]) -> Vec<&'a VtMatchInfo> {
        infos.iter().filter(|info| self.matches(info)).collect()
    }

    /// Filter and consume, returning owned match infos that pass.
    pub fn filter_owned(&self, infos: Vec<VtMatchInfo>) -> Vec<VtMatchInfo> {
        infos.into_iter().filter(|info| self.matches(info)).collect()
    }
}

impl Default for VtMatchInfoFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for VtMatchInfoFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VtMatchInfoFilter[")?;
        let mut first = true;
        macro_rules! field {
            ($label:expr, $val:expr) => {
                if let Some(v) = $val {
                    if !first { write!(f, ", ")?; }
                    write!(f, "{}={}", $label, v)?;
                    first = false;
                }
            };
        }
        field!("min_sim", &self.min_similarity);
        field!("min_conf", &self.min_confidence);
        field!("type", &self.association_type);
        field!("min_len", &self.min_length);
        field!("max_len", &self.max_length);
        field!("match_set", &self.match_set_id);
        if self.tagged_only {
            if !first { write!(f, ", ")?; }
            write!(f, "tagged_only")?;
        }
        if self.untagged_only {
            if !first { write!(f, ", ")?; }
            write!(f, "untagged_only")?;
        }
        write!(f, "]")
    }
}

// ---------------------------------------------------------------------------
// VtMatchInfoAggregator
// ---------------------------------------------------------------------------

/// Aggregates statistics over a collection of `VtMatchInfo` records.
#[derive(Debug, Clone)]
pub struct VtMatchInfoAggregator {
    count: usize,
    total_similarity: f64,
    total_confidence: f64,
    max_similarity: VtScore,
    max_confidence: VtScore,
    min_similarity: VtScore,
    function_count: usize,
    data_count: usize,
    same_length_count: usize,
    tagged_count: usize,
}

impl VtMatchInfoAggregator {
    /// Build an aggregator from a slice of match infos.
    pub fn from_slice(infos: &[VtMatchInfo]) -> Self {
        let mut agg = Self {
            count: 0,
            total_similarity: 0.0,
            total_confidence: 0.0,
            max_similarity: VtScore::new(0.0),
            max_confidence: VtScore::new(0.0),
            min_similarity: VtScore::new(1.0),
            function_count: 0,
            data_count: 0,
            same_length_count: 0,
            tagged_count: 0,
        };
        for info in infos {
            agg.add(info);
        }
        agg
    }

    /// Add a single match info to the aggregation.
    pub fn add(&mut self, info: &VtMatchInfo) {
        self.count += 1;
        let sim = info.similarity_score.score();
        let conf = info.confidence_score.score();
        self.total_similarity += sim;
        self.total_confidence += conf;
        if sim > self.max_similarity.score() {
            self.max_similarity = VtScore::new(sim);
        }
        if sim < self.min_similarity.score() {
            self.min_similarity = VtScore::new(sim);
        }
        if conf > self.max_confidence.score() {
            self.max_confidence = VtScore::new(conf);
        }
        match info.association_type {
            VtAssociationType::Function => self.function_count += 1,
            VtAssociationType::Data => self.data_count += 1,
        }
        if info.has_same_length() {
            self.same_length_count += 1;
        }
        if !info.tag.is_untagged() {
            self.tagged_count += 1;
        }
    }

    /// Number of match infos aggregated.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Average similarity score.
    pub fn avg_similarity(&self) -> f64 {
        if self.count == 0 { 0.0 } else { self.total_similarity / self.count as f64 }
    }

    /// Average confidence score.
    pub fn avg_confidence(&self) -> f64 {
        if self.count == 0 { 0.0 } else { self.total_confidence / self.count as f64 }
    }

    /// Maximum similarity score seen.
    pub fn max_similarity(&self) -> &VtScore {
        &self.max_similarity
    }

    /// Maximum confidence score seen.
    pub fn max_confidence(&self) -> &VtScore {
        &self.max_confidence
    }

    /// Minimum similarity score seen.
    pub fn min_similarity(&self) -> &VtScore {
        &self.min_similarity
    }

    /// Number of function-type associations.
    pub fn function_count(&self) -> usize {
        self.function_count
    }

    /// Number of data-type associations.
    pub fn data_count(&self) -> usize {
        self.data_count
    }

    /// Number of match infos where source and destination lengths are equal.
    pub fn same_length_count(&self) -> usize {
        self.same_length_count
    }

    /// Number of tagged match infos.
    pub fn tagged_count(&self) -> usize {
        self.tagged_count
    }

    /// Count items above similarity threshold from a slice (companion to aggregator).
    pub fn high_similarity_count_from_slice(infos: &[VtMatchInfo], threshold: f64) -> usize {
        infos.iter().filter(|i| i.similarity_score.score() >= threshold).count()
    }

    /// Count items by association type.
    pub fn count_by_type(&self, assoc_type: VtAssociationType) -> usize {
        match assoc_type {
            VtAssociationType::Function => self.function_count,
            VtAssociationType::Data => self.data_count,
        }
    }
}

impl fmt::Display for VtMatchInfoAggregator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VtMatchInfoAggregator[count={}, avg_sim={:.3}, avg_conf={:.3}, max_sim={}, max_conf={}, funcs={}, data={}]",
            self.count,
            self.avg_similarity(),
            self.avg_confidence(),
            self.max_similarity,
            self.max_confidence,
            self.function_count,
            self.data_count,
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

    // ======================================================================
    // Validation tests
    // ======================================================================

    #[test]
    fn test_validate_valid() {
        let info = VtMatchInfo::function_match_info(0.9, 0.8, 0x1000, 0x2000, 50, 50, "bytes");
        assert!(info.validate().is_ok());
    }

    #[test]
    fn test_validate_similarity_out_of_range() {
        let mut info = VtMatchInfo::with_defaults(VtAssociationType::Function);
        info.similarity_score = VtScore::new(1.5);
        assert!(info.validate().is_err());
    }

    #[test]
    fn test_validate_negative_similarity() {
        let mut info = VtMatchInfo::with_defaults(VtAssociationType::Function);
        info.similarity_score = VtScore::new(-0.1);
        assert!(info.validate().is_err());
    }

    #[test]
    fn test_is_better_than_similarity() {
        let high = VtMatchInfo::function_match_info(0.95, 0.5, 0, 0, 10, 10, "bytes");
        let low = VtMatchInfo::function_match_info(0.5, 0.95, 0, 0, 10, 10, "bytes");
        assert!(high.is_better_than(&low));
    }

    #[test]
    fn test_is_better_than_confidence_tiebreak() {
        let a = VtMatchInfo::function_match_info(0.9, 0.95, 0, 0, 10, 10, "bytes");
        let b = VtMatchInfo::function_match_info(0.9, 0.85, 0, 0, 10, 10, "bytes");
        assert!(a.is_better_than(&b));
    }

    // ======================================================================
    // Builder tests (extra)
    // ======================================================================

    #[test]
    fn test_builder_validation_fails_on_bad_score() {
        let info = VtMatchInfoBuilder::new(VtAssociationType::Function)
            .similarity(2.0)
            .confidence(0.5)
            .build();
        assert!(info.validate().is_err());
    }

    // ======================================================================
    // VtMatchInfoFilter tests
    // ======================================================================

    fn make_info_collection() -> Vec<VtMatchInfo> {
        vec![
            VtMatchInfo::function_match_info(0.95, 0.90, 0x1000, 0x2000, 100, 100, "bytes"),
            VtMatchInfo::function_match_info(0.40, 0.30, 0x1100, 0x2100, 50, 60, "bytes"),
            VtMatchInfo::data_match_info(0.85, 0.75, 0x3000, 0x4000, 4, 4, "bytes"),
            VtMatchInfo::data_match_info(0.20, 0.10, 0x3100, 0x4100, 8, 8, "bytes"),
            VtMatchInfo::function_match_info(0.70, 0.60, 0x1200, 0x2200, 80, 80, "instructions"),
        ]
    }

    #[test]
    fn test_filter_min_similarity() {
        let infos = make_info_collection();
        let filter = VtMatchInfoFilter::new().min_similarity(0.7);
        let results = filter.filter(&infos);
        assert_eq!(results.len(), 3); // 0.95, 0.85, 0.70
    }

    #[test]
    fn test_filter_min_confidence() {
        let infos = make_info_collection();
        let filter = VtMatchInfoFilter::new().min_confidence(0.6);
        let results = filter.filter(&infos);
        assert_eq!(results.len(), 3); // 0.90, 0.75, 0.60
    }

    #[test]
    fn test_filter_association_type() {
        let infos = make_info_collection();
        let filter = VtMatchInfoFilter::new().association_type(VtAssociationType::Function);
        let results = filter.filter(&infos);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_filter_min_length() {
        let infos = make_info_collection();
        let filter = VtMatchInfoFilter::new().min_length(60);
        let results = filter.filter(&infos);
        // 100/100, 50/60 (min=50 fails), 4/4 (fails), 8/8 (fails), 80/80
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_filter_combined() {
        let infos = make_info_collection();
        let filter = VtMatchInfoFilter::new()
            .min_similarity(0.5)
            .association_type(VtAssociationType::Data);
        let results = filter.filter(&infos);
        assert_eq!(results.len(), 1); // only the 0.85 data match
    }

    // ======================================================================
    // VtMatchInfoAggregator tests
    // ======================================================================

    #[test]
    fn test_aggregator_count() {
        let infos = make_info_collection();
        let agg = VtMatchInfoAggregator::from_slice(&infos);
        assert_eq!(agg.count(), 5);
    }

    #[test]
    fn test_aggregator_empty() {
        let agg = VtMatchInfoAggregator::from_slice(&[]);
        assert_eq!(agg.count(), 0);
        assert!((agg.avg_similarity() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_aggregator_avg_similarity() {
        let infos = make_info_collection();
        let agg = VtMatchInfoAggregator::from_slice(&infos);
        let avg = agg.avg_similarity();
        // (0.95 + 0.40 + 0.85 + 0.20 + 0.70) / 5 = 3.10 / 5 = 0.62
        assert!((avg - 0.62).abs() < 0.01);
    }

    #[test]
    fn test_aggregator_max_confidence() {
        let infos = make_info_collection();
        let agg = VtMatchInfoAggregator::from_slice(&infos);
        assert!((agg.max_confidence().score() - 0.90).abs() < 0.01);
    }

    #[test]
    fn test_aggregator_high_similarity_count() {
        let infos = make_info_collection();
        assert_eq!(VtMatchInfoAggregator::high_similarity_count_from_slice(&infos, 0.7), 3); // 0.95, 0.85, 0.70
    }

    #[test]
    fn test_aggregator_count_by_type() {
        let infos = make_info_collection();
        let agg = VtMatchInfoAggregator::from_slice(&infos);
        assert_eq!(agg.count_by_type(VtAssociationType::Function), 3);
        assert_eq!(agg.count_by_type(VtAssociationType::Data), 2);
    }

    #[test]
    fn test_aggregator_display() {
        let infos = make_info_collection();
        let agg = VtMatchInfoAggregator::from_slice(&infos);
        let d = format!("{}", agg);
        assert!(d.contains("count=5"));
    }

    // ======================================================================
    // Edge case tests
    // ======================================================================

    #[test]
    fn test_length_ratio_both_zero() {
        let info = VtMatchInfo::with_defaults(VtAssociationType::Function);
        assert!((info.length_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_length_ratio_one_zero() {
        let info = VtMatchInfo::function_match_info(1.0, 1.0, 0, 0, 0, 50, "bytes");
        assert!((info.length_ratio() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_filter_no_results() {
        let infos = make_info_collection();
        let filter = VtMatchInfoFilter::new().min_similarity(0.99);
        let results = filter.filter(&infos);
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_filter_match_set_id() {
        let mut infos = make_info_collection();
        infos[0].match_set_id = 42;
        infos[2].match_set_id = 42;
        let filter = VtMatchInfoFilter::new().match_set_id(42);
        let results = filter.filter(&infos);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_aggregator_avg_confidence() {
        let infos = make_info_collection();
        let agg = VtMatchInfoAggregator::from_slice(&infos);
        let avg = agg.avg_confidence();
        // (0.90 + 0.30 + 0.75 + 0.10 + 0.60) / 5 = 2.65 / 5 = 0.53
        assert!((avg - 0.53).abs() < 0.01);
    }
}
