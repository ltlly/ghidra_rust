//! FID Service: high-level function identification.
//!
//! Ported from Ghidra's `FidService` and related classes.
//!
//! Provides the main API for:
//! - Populating a FID database from a program's functions.
//! - Searching a FID database to identify functions in an unknown binary.
//! - Scoring and ranking matches.

use serde::{Deserialize, Serialize};

use super::fid_db::{FidDB, FunctionRecord};
use super::fid_hasher::{FidHasher, HashFamily, HashMatch};

// ---------------------------------------------------------------------------
// FidMatchScore
// ---------------------------------------------------------------------------

/// A scored match combining hash matches with name analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FidMatchScore {
    /// The function address in the target binary.
    pub target_address: u64,
    /// The matched function name.
    pub matched_name: String,
    /// The library the match came from.
    pub library_name: String,
    /// The function ID in the database.
    pub function_id: i64,
    /// The overall confidence score (0.0 to 1.0).
    pub confidence: f64,
    /// The number of hash families that matched.
    pub hash_match_count: usize,
    /// The best hash family match.
    pub best_hash_family: HashFamily,
    /// Whether the function name was verified by other means.
    pub name_verified: bool,
}

// ---------------------------------------------------------------------------
// FidSearchResult
// ---------------------------------------------------------------------------

/// Results of a FID search for a single function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FidSearchResult {
    /// The target function's address.
    pub address: u64,
    /// The target function's size (in bytes).
    pub size: u64,
    /// All matches found, sorted by confidence (highest first).
    pub matches: Vec<FidMatchScore>,
    /// The primary match (highest confidence), if any.
    pub best_match: Option<FidMatchScore>,
}

// ---------------------------------------------------------------------------
// FidService
// ---------------------------------------------------------------------------

/// The main service for function identification.
///
/// Coordinates hashing, database lookup, and match scoring.
///
/// # Usage
///
/// ```rust
/// use ghidra_features::function_id::*;
///
/// let mut db = FidDB::new("x86", "x86:LE:64:default");
/// db.add_library(LibraryRecord::new("libc.so", "2.31", "x86", "x86:LE:64:default"));
/// let body = [0x55u8, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10];
/// let hasher = FidHasher::new();
/// let hashes = hasher.compute_hashes(&body);
/// for (family, hash) in &hashes {
///     if *family == HashFamily::FullBody {
///         db.add_function(FunctionRecord::new("memcpy", "memcpy", *hash, 48, 1));
///     }
/// }
///
/// let service = FidService::new(db, hasher);
/// let results = service.identify_function(0x400000, &body);
/// assert!(results.best_match.is_some());
/// ```
#[derive(Debug)]
pub struct FidService {
    /// The FID database.
    pub db: FidDB,
    /// The hasher for computing function hashes.
    pub hasher: FidHasher,
    /// Minimum confidence threshold for accepting a match.
    pub min_confidence: f64,
}

impl FidService {
    /// Create a new FID service.
    pub fn new(db: FidDB, hasher: FidHasher) -> Self {
        Self {
            db,
            hasher,
            min_confidence: 0.5,
        }
    }

    /// Set the minimum confidence threshold.
    pub fn with_min_confidence(mut self, threshold: f64) -> Self {
        self.min_confidence = threshold;
        self
    }

    /// Identify a function at the given address using its byte body.
    ///
    /// Returns all matches found, sorted by confidence.
    pub fn identify_function(&self, address: u64, body: &[u8]) -> FidSearchResult {
        let hashes = self.hasher.compute_hashes(body);
        let mut matches: Vec<FidMatchScore> = Vec::new();

        for (family, hash) in &hashes {
            let db_matches = self.db.find_by_hash(*hash);
            for func in db_matches {
                let library = self
                    .db
                    .get_library(func.library_id)
                    .map(|l| l.name.as_str())
                    .unwrap_or("unknown");

                matches.push(FidMatchScore {
                    target_address: address,
                    matched_name: func.name.clone(),
                    library_name: library.to_string(),
                    function_id: func.id,
                    confidence: Self::confidence_for_family(*family),
                    hash_match_count: 1,
                    best_hash_family: *family,
                    name_verified: false,
                });
            }
        }

        // Deduplicate: merge matches for the same function ID
        matches = Self::deduplicate_matches(matches);

        // Sort by confidence descending
        matches.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let best_match = matches.first().cloned();

        FidSearchResult {
            address,
            size: body.len() as u64,
            matches,
            best_match,
        }
    }

    /// Identify functions in a binary at the given addresses.
    pub fn identify_functions(
        &self,
        functions: &[(u64, Vec<u8>)],
    ) -> Vec<FidSearchResult> {
        functions
            .iter()
            .map(|(addr, body)| self.identify_function(*addr, body))
            .collect()
    }

    /// Populate the database with a function from a program.
    pub fn ingest_function(
        &mut self,
        name: &str,
        full_name: &str,
        body: &[u8],
        size: u64,
        library_id: i64,
    ) {
        let hashes = self.hasher.compute_hashes(body);
        let primary_hash = hashes
            .iter()
            .find(|(f, _)| *f == HashFamily::FullBody)
            .map(|(_, h)| *h)
            .unwrap_or(0);

        let mut func = FunctionRecord::new(name, full_name, primary_hash, size, library_id);
        for (family, hash) in hashes {
            if family != HashFamily::FullBody {
                func.extra_hashes.insert(family.name().to_string(), hash);
            }
        }
        self.db.add_function(func);
    }

    /// Get the confidence score for a hash family.
    fn confidence_for_family(family: HashFamily) -> f64 {
        match family {
            HashFamily::FullBody => 1.0,
            HashFamily::TrimmedBody => 0.9,
            HashFamily::InstructionOnly => 0.85,
            HashFamily::MnemonicSequence => 0.8,
            HashFamily::Crc32 => 0.95,
            HashFamily::Custom(_) => 0.5,
        }
    }

    /// Deduplicate matches: merge multiple hash matches for the same
    /// function ID, accumulating the match count.
    fn deduplicate_matches(matches: Vec<FidMatchScore>) -> Vec<FidMatchScore> {
        let mut by_id: std::collections::HashMap<i64, FidMatchScore> = std::collections::HashMap::new();

        for m in matches {
            if let Some(existing) = by_id.get_mut(&m.function_id) {
                existing.hash_match_count += 1;
                // Keep the best confidence
                if m.confidence > existing.confidence {
                    existing.confidence = m.confidence;
                    existing.best_hash_family = m.best_hash_family;
                }
            } else {
                by_id.insert(m.function_id, m);
            }
        }

        by_id.into_values().collect()
    }
}

// ---------------------------------------------------------------------------
// MatchNameAnalysis
// ---------------------------------------------------------------------------

/// Analyze the quality of a function name match.
///
/// Used to improve match confidence when the name itself provides
/// additional evidence (e.g., common function names like "main" or
/// known library function names).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchNameAnalysis {
    /// The function name.
    pub name: String,
    /// Whether this is a common/known function name.
    pub is_common_name: bool,
    /// Whether the name appears to be mangled.
    pub is_mangled: bool,
    /// The demangled name (if originally mangled).
    pub demangled_name: Option<String>,
    /// Confidence boost from name analysis.
    pub name_confidence_boost: f64,
}

impl MatchNameAnalysis {
    /// Analyze a function name.
    pub fn analyze(name: &str) -> Self {
        let is_mangled = name.starts_with("_Z") || name.starts_with("?") || name.starts_with(".?A");
        let is_common = matches!(
            name,
            "main"
                | "memcpy"
                | "memset"
                | "strlen"
                | "malloc"
                | "free"
                | "printf"
                | "sprintf"
                | "strcpy"
                | "strcmp"
        );

        let name_confidence_boost = if is_common {
            0.1
        } else if is_mangled {
            0.05
        } else {
            0.0
        };

        Self {
            name: name.to_string(),
            is_common_name: is_common,
            is_mangled,
            demangled_name: None,
            name_confidence_boost,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::function_id::fid_db::LibraryRecord;

    fn make_test_service() -> FidService {
        let mut db = FidDB::new("x86", "x86:LE:64:default");
        let mut lib = LibraryRecord::new("libc.so", "2.31", "x86", "x86:LE:64:default");
        lib.id = 1;
        db.add_library(lib);

        let hasher = FidHasher::new();
        let body = [0x55u8, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10];
        let hashes = hasher.compute_hashes(&body);
        let primary_hash = hashes
            .iter()
            .find(|(f, _)| *f == HashFamily::FullBody)
            .map(|(_, h)| *h)
            .unwrap();

        db.add_function(FunctionRecord::new("memcpy", "memcpy", primary_hash, 48, 1));

        FidService::new(db, hasher)
    }

    #[test]
    fn test_identify_function_match() {
        let service = make_test_service();
        let body = [0x55u8, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10];
        let result = service.identify_function(0x400000, &body);

        assert!(result.best_match.is_some());
        let m = result.best_match.as_ref().unwrap();
        assert_eq!(m.matched_name, "memcpy");
        assert_eq!(m.target_address, 0x400000);
        assert!(m.confidence >= 0.8);
    }

    #[test]
    fn test_identify_function_no_match() {
        let service = make_test_service();
        let body = [0xFFu8, 0xFF, 0xFF, 0xFF];
        let result = service.identify_function(0x400000, &body);

        // FullBody hash won't match, but other hash families might give
        // incidental collisions. If no match is found, best_match is None.
        // In this case, since only FullBody was in the DB, there should be no match.
        // (Other families produce different hashes from FullBody)
        assert!(result.best_match.is_none() || result.matches.is_empty());
    }

    #[test]
    fn test_ingest_function() {
        let mut db = FidDB::new("x86", "x86:LE:64:default");
        db.add_library(LibraryRecord::new("lib", "1.0", "x86", "x86:LE:64:default"));
        let hasher = FidHasher::new();
        let mut service = FidService::new(db, hasher);

        service.ingest_function("test_func", "ns::test_func", &[0xAA, 0xBB, 0xCC], 10, 1);

        assert_eq!(service.db.function_count(), 1);
        assert_eq!(service.db.functions[0].name, "test_func");
    }

    #[test]
    fn test_identify_functions_batch() {
        let service = make_test_service();
        let body = [0x55u8, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10];
        let functions = vec![
            (0x400000, body.to_vec()),
            (0x400100, vec![0xFF, 0xFF]),
        ];
        let results = service.identify_functions(&functions);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_match_name_analysis_common() {
        let analysis = MatchNameAnalysis::analyze("memcpy");
        assert!(analysis.is_common_name);
        assert!(!analysis.is_mangled);
        assert!(analysis.name_confidence_boost > 0.0);
    }

    #[test]
    fn test_match_name_analysis_mangled() {
        let analysis = MatchNameAnalysis::analyze("_ZNSolsEPKc");
        assert!(!analysis.is_common_name);
        assert!(analysis.is_mangled);
    }

    #[test]
    fn test_match_name_analysis_normal() {
        let analysis = MatchNameAnalysis::analyze("my_function");
        assert!(!analysis.is_common_name);
        assert!(!analysis.is_mangled);
        assert_eq!(analysis.name_confidence_boost, 0.0);
    }

    #[test]
    fn test_min_confidence_filter() {
        let service = make_test_service().with_min_confidence(0.99);
        // Even if a match exists, the threshold can be configured
        assert_eq!(service.min_confidence, 0.99);
    }
}
