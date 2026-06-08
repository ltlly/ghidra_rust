//! FID match types and scoring.
//!
//! Ported from Ghidra's `FidMatch`, `FidMatchImpl`, `FidMatchScore`,
//! `FidSearchResult`, and related Java classes.

/// The score of an FID match.
#[derive(Debug, Clone, PartialEq)]
pub struct FidMatchScore {
    /// Confidence score (0.0 to 1.0).
    pub confidence: f64,
    /// The hash family that matched.
    pub hash_family: String,
    /// Whether the name also matched.
    pub name_matched: bool,
}

impl FidMatchScore {
    pub fn new(confidence: f64, hash_family: String, name_matched: bool) -> Self {
        Self { confidence, hash_family, name_matched }
    }

    /// Whether this match is considered reliable.
    pub fn is_reliable(&self) -> bool {
        self.confidence >= 0.8 && self.name_matched
    }
}

/// A result from an FID search.
#[derive(Debug, Clone)]
pub struct FidSearchResult {
    /// The function address that was searched.
    pub address: u64,
    /// The matched function name.
    pub function_name: String,
    /// The library the match came from.
    pub library_name: String,
    /// Match score.
    pub score: FidMatchScore,
}

impl FidSearchResult {
    pub fn new(address: u64, function_name: String, library_name: String, score: FidMatchScore) -> Self {
        Self { address, function_name, library_name, score }
    }
}

/// Hash family for FID matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashFamily {
    /// Full function body hash.
    FullBody,
    /// Trimmed hash (excluding common prefixes/suffixes).
    Trimmed,
    /// Instruction-only hash.
    InstructionOnly,
    /// Byte pattern hash.
    BytePattern,
    /// Custom hash family.
    Custom(u32),
}

impl HashFamily {
    pub fn name(&self) -> &'static str {
        match self {
            Self::FullBody => "FullBody",
            Self::Trimmed => "Trimmed",
            Self::InstructionOnly => "InstructionOnly",
            Self::BytePattern => "BytePattern",
            Self::Custom(_) => "Custom",
        }
    }
}

/// Analysis of name matching between source and candidate.
#[derive(Debug, Clone)]
pub struct MatchNameAnalysis {
    /// The original function name.
    pub original_name: String,
    /// The matched function name.
    pub matched_name: String,
    /// Whether the names are identical.
    pub exact_match: bool,
    /// Name similarity score (0.0 to 1.0).
    pub similarity: f64,
}

impl MatchNameAnalysis {
    pub fn new(original_name: String, matched_name: String) -> Self {
        let exact = original_name == matched_name;
        Self {
            original_name,
            matched_name,
            exact_match: exact,
            similarity: if exact { 1.0 } else { 0.0 },
        }
    }
}

/// Name versions for tracking name changes.
#[derive(Debug, Clone)]
pub struct NameVersions {
    /// Original name.
    pub original: String,
    /// Normalized version (lowercase, stripped prefix/suffix).
    pub normalized: String,
    /// Demangled version (if applicable).
    pub demangled: Option<String>,
}

impl NameVersions {
    pub fn new(original: String) -> Self {
        let normalized = original.to_lowercase();
        Self { original, normalized, demangled: None }
    }
}

/// Location reference for FID matches.
#[derive(Debug, Clone)]
pub struct Location {
    /// The address.
    pub address: u64,
    /// The function name at this location.
    pub function_name: String,
    /// The library name.
    pub library_name: String,
}

impl Location {
    pub fn new(address: u64, function_name: String, library_name: String) -> Self {
        Self { address, function_name, library_name }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_score() {
        let s = FidMatchScore::new(0.95, "FullBody".into(), true);
        assert!(s.is_reliable());
        let s2 = FidMatchScore::new(0.5, "FullBody".into(), false);
        assert!(!s2.is_reliable());
    }

    #[test]
    fn test_hash_family() {
        assert_eq!(HashFamily::FullBody.name(), "FullBody");
        assert_eq!(HashFamily::Trimmed.name(), "Trimmed");
        assert_ne!(HashFamily::FullBody, HashFamily::Trimmed);
    }

    #[test]
    fn test_match_name_analysis() {
        let a = MatchNameAnalysis::new("main".into(), "main".into());
        assert!(a.exact_match);
        assert_eq!(a.similarity, 1.0);

        let b = MatchNameAnalysis::new("main".into(), "Main".into());
        assert!(!b.exact_match);
    }

    #[test]
    fn test_name_versions() {
        let nv = NameVersions::new("MyFunction".into());
        assert_eq!(nv.normalized, "myfunction");
        assert!(nv.demangled.is_none());
    }

    #[test]
    fn test_search_result() {
        let r = FidSearchResult::new(
            0x401000,
            "main".into(),
            "libc".into(),
            FidMatchScore::new(0.9, "FullBody".into(), true),
        );
        assert_eq!(r.address, 0x401000);
        assert_eq!(r.function_name, "main");
    }

    #[test]
    fn test_location() {
        let loc = Location::new(0x1000, "func".into(), "lib".into());
        assert_eq!(loc.address, 0x1000);
    }
}
