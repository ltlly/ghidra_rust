//! VTMatchInfo -- additional metadata for a version tracking match.
//!
//! Corresponds to Ghidra's `VTMatchInfo` Java class.
//!
//! A `VtMatchInfo` bundles extra detail that is stored alongside each match:
//! the association type, similarity/confidence scores, source and destination
//! lengths, and the length type used for the comparison.

use std::fmt;

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
        source_length: u64,
        destination_length: u64,
        length_type: impl Into<String>,
    ) -> VtMatchInfo;

    /// Create a new match info for a data match.
    fn data_match_info(
        similarity: f64,
        confidence: f64,
        source_length: u64,
        destination_length: u64,
        length_type: impl Into<String>,
    ) -> VtMatchInfo;

    /// Create a match info with default scores.
    fn with_defaults(association_type: VtAssociationType) -> VtMatchInfo;

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

    /// Format a brief one-line summary.
    fn summary_line(&self) -> String;
}

impl VtMatchInfoExt for VtMatchInfo {
    fn function_match_info(
        similarity: f64,
        confidence: f64,
        source_length: u64,
        destination_length: u64,
        length_type: impl Into<String>,
    ) -> VtMatchInfo {
        VtMatchInfo {
            association_type: VtAssociationType::Function,
            similarity_score: VtScore::new(similarity),
            confidence_score: VtScore::new(confidence),
            source_length,
            destination_length,
            length_type: length_type.into(),
        }
    }

    fn data_match_info(
        similarity: f64,
        confidence: f64,
        source_length: u64,
        destination_length: u64,
        length_type: impl Into<String>,
    ) -> VtMatchInfo {
        VtMatchInfo {
            association_type: VtAssociationType::Data,
            similarity_score: VtScore::new(similarity),
            confidence_score: VtScore::new(confidence),
            source_length,
            destination_length,
            length_type: length_type.into(),
        }
    }

    fn with_defaults(association_type: VtAssociationType) -> VtMatchInfo {
        VtMatchInfo {
            association_type,
            similarity_score: VtScore::new(0.0),
            confidence_score: VtScore::new(0.0),
            source_length: 0,
            destination_length: 0,
            length_type: "bytes".to_string(),
        }
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
}

/// A builder for constructing `VtMatchInfo` instances step-by-step.
#[derive(Debug, Clone)]
pub struct VtMatchInfoBuilder {
    association_type: VtAssociationType,
    similarity: f64,
    confidence: f64,
    source_length: u64,
    destination_length: u64,
    length_type: String,
}

impl VtMatchInfoBuilder {
    /// Start building a match info for the given association type.
    pub fn new(association_type: VtAssociationType) -> Self {
        Self {
            association_type,
            similarity: 0.0,
            confidence: 0.0,
            source_length: 0,
            destination_length: 0,
            length_type: "bytes".to_string(),
        }
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

    /// Build the `VtMatchInfo`.
    pub fn build(self) -> VtMatchInfo {
        VtMatchInfo {
            association_type: self.association_type,
            similarity_score: VtScore::new(self.similarity),
            confidence_score: VtScore::new(self.confidence),
            source_length: self.source_length,
            destination_length: self.destination_length,
            length_type: self.length_type,
        }
    }
}

impl fmt::Display for VtMatchInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VtMatchInfo[type={}, sim={}, conf={}, src_len={}, dst_len={}, len_type={}]",
            self.association_type,
            self.similarity_score,
            self.confidence_score,
            self.source_length,
            self.destination_length,
            self.length_type,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_match_info() {
        let info = VtMatchInfo::function_match_info(0.95, 0.85, 100, 100, "bytes");
        assert_eq!(info.association_type, VtAssociationType::Function);
        assert!((info.similarity_score.score() - 0.95).abs() < 0.001);
        assert!((info.confidence_score.score() - 0.85).abs() < 0.001);
        assert_eq!(info.source_length, 100);
        assert_eq!(info.destination_length, 100);
        assert_eq!(info.length_type, "bytes");
    }

    #[test]
    fn test_data_match_info() {
        let info = VtMatchInfo::data_match_info(0.8, 0.7, 4, 4, "bytes");
        assert_eq!(info.association_type, VtAssociationType::Data);
        assert!((info.similarity_score.score() - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_with_defaults() {
        let info = VtMatchInfo::with_defaults(VtAssociationType::Function);
        assert_eq!(info.association_type, VtAssociationType::Function);
        assert!((info.similarity_score.score() - 0.0).abs() < f64::EPSILON);
        assert!((info.confidence_score.score() - 0.0).abs() < f64::EPSILON);
        assert_eq!(info.source_length, 0);
        assert_eq!(info.destination_length, 0);
        assert_eq!(info.length_type, "bytes");
    }

    #[test]
    fn test_high_similarity_and_confidence() {
        let info = VtMatchInfo::function_match_info(0.95, 0.85, 100, 100, "bytes");
        assert!(info.is_high_similarity(0.9));
        assert!(!info.is_high_similarity(1.0));
        assert!(info.is_high_confidence(0.8));
        assert!(!info.is_high_confidence(0.9));
    }

    #[test]
    fn test_same_length() {
        let info = VtMatchInfo::function_match_info(1.0, 1.0, 100, 100, "bytes");
        assert!(info.has_same_length());
        assert_eq!(info.length_delta(), 0);
        assert!((info.length_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_different_length() {
        let info = VtMatchInfo::function_match_info(0.8, 0.7, 100, 80, "bytes");
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
    fn test_summary_line() {
        let info = VtMatchInfo::function_match_info(0.95, 0.85, 100, 100, "instructions");
        let summary = info.summary_line();
        assert!(summary.contains("Function"));
        assert!(summary.contains("instructions"));
    }

    #[test]
    fn test_builder() {
        let info = VtMatchInfoBuilder::new(VtAssociationType::Data)
            .similarity(0.75)
            .confidence(0.6)
            .source_length(8)
            .destination_length(8)
            .length_type("bytes")
            .build();
        assert_eq!(info.association_type, VtAssociationType::Data);
        assert!((info.similarity_score.score() - 0.75).abs() < 0.001);
        assert!((info.confidence_score.score() - 0.6).abs() < 0.001);
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
    fn test_display() {
        let info = VtMatchInfo::function_match_info(0.9, 0.8, 50, 50, "bytes");
        let display = format!("{}", info);
        assert!(display.contains("VtMatchInfo"));
        assert!(display.contains("Function"));
    }
}
