//! Child match record for BSim hierarchical function matching.
//!
//! Ports `ghidra.features.bsim.query.ChildMatchRecord`.

use std::cmp::Ordering;

/// A record that pairs a match result with its children-vector for
/// hierarchical significance scoring.
///
/// When BSim evaluates a function match it can take callees into
/// account.  The [`ChildMatchRecord`] stores the aggregated LSH
/// vector that includes children and the resulting similarity /
/// significance scores.
#[derive(Debug, Clone)]
pub struct ChildMatchRecord {
    /// The similar function match result (match description + similarity note).
    pub similar_function: MatchReference,
    /// The LSH vector that includes children contributions.
    pub vec_with_children: Vec<f64>,
    /// Significance score that includes children.
    pub significance_with_children: f64,
    /// Similarity score that includes children.
    pub similarity_with_children: f64,
}

/// A lightweight reference to a BSim match result.
///
/// In the Java code this holds a `BSimMatchResult` reference.
/// In Rust we store the essential identifying data.
#[derive(Debug, Clone)]
pub struct MatchReference {
    /// Entry point of the queried function.
    pub query_entry: u64,
    /// Entry point of the matched function.
    pub match_entry: u64,
    /// Name of the matched function.
    pub match_name: String,
    /// URL of the executable that contains the match.
    pub executable_url: String,
    /// Base similarity score (without children).
    pub base_similarity: f64,
    /// Base significance score (without children).
    pub base_significance: f64,
}

impl MatchReference {
    /// Create a new match reference.
    pub fn new(
        query_entry: u64,
        match_entry: u64,
        match_name: impl Into<String>,
        executable_url: impl Into<String>,
    ) -> Self {
        Self {
            query_entry,
            match_entry,
            match_name: match_name.into(),
            executable_url: executable_url.into(),
            base_similarity: 0.0,
            base_significance: 0.0,
        }
    }
}

impl ChildMatchRecord {
    /// Create a new child match record.
    pub fn new(similar_function: MatchReference, vec_with_children: Vec<f64>) -> Self {
        Self {
            similar_function,
            vec_with_children,
            significance_with_children: 0.0,
            similarity_with_children: 0.0,
        }
    }

    /// Get the similar function reference.
    pub fn similar_function(&self) -> &MatchReference {
        &self.similar_function
    }

    /// Get the children-aggregated vector.
    pub fn vec_with_children(&self) -> &[f64] {
        &self.vec_with_children
    }

    /// Set the significance score that includes children.
    pub fn set_significance_with_children(&mut self, significance: f64) {
        self.significance_with_children = significance;
    }

    /// Get the significance score that includes children.
    pub fn significance_with_children(&self) -> f64 {
        self.significance_with_children
    }

    /// Set the similarity score that includes children.
    pub fn set_similarity_with_children(&mut self, similarity: f64) {
        self.similarity_with_children = similarity;
    }

    /// Get the similarity score that includes children.
    pub fn similarity_with_children(&self) -> f64 {
        self.similarity_with_children
    }
}

impl PartialEq for ChildMatchRecord {
    fn eq(&self, other: &Self) -> bool {
        self.significance_with_children
            == other.significance_with_children
    }
}

impl Eq for ChildMatchRecord {}

impl PartialOrd for ChildMatchRecord {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ChildMatchRecord {
    /// Compare by significance in descending order (highest significance first).
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .significance_with_children
            .partial_cmp(&self.significance_with_children)
            .unwrap_or(Ordering::Equal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(significance: f64) -> ChildMatchRecord {
        let mut rec = ChildMatchRecord::new(
            MatchReference::new(0x1000, 0x2000, "match_fn", "http://exe"),
            vec![1.0, 2.0, 3.0],
        );
        rec.significance_with_children = significance;
        rec
    }

    #[test]
    fn test_new_record() {
        let rec = make_record(0.5);
        assert_eq!(rec.similar_function().query_entry, 0x1000);
        assert_eq!(rec.similar_function().match_entry, 0x2000);
        assert_eq!(rec.similar_function().match_name, "match_fn");
        assert_eq!(rec.vec_with_children().len(), 3);
    }

    #[test]
    fn test_significance_accessor() {
        let mut rec = make_record(0.0);
        rec.set_significance_with_children(0.85);
        assert!((rec.significance_with_children() - 0.85).abs() < f64::EPSILON);
    }

    #[test]
    fn test_similarity_accessor() {
        let mut rec = make_record(0.0);
        rec.set_similarity_with_children(0.92);
        assert!((rec.similarity_with_children() - 0.92).abs() < f64::EPSILON);
    }

    #[test]
    fn test_ordering_descending() {
        let mut records = vec![
            make_record(0.3),
            make_record(0.9),
            make_record(0.6),
        ];
        records.sort();
        assert!((records[0].significance_with_children() - 0.9).abs() < f64::EPSILON);
        assert!((records[1].significance_with_children() - 0.6).abs() < f64::EPSILON);
        assert!((records[2].significance_with_children() - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn test_equality() {
        let a = make_record(0.5);
        let b = make_record(0.5);
        assert_eq!(a, b);
    }

    #[test]
    fn test_match_reference_builder() {
        let m = MatchReference::new(0, 1, "fn1", "exe1");
        assert_eq!(m.query_entry, 0);
        assert_eq!(m.match_entry, 1);
        assert_eq!(m.match_name, "fn1");
        assert_eq!(m.executable_url, "exe1");
    }
}
