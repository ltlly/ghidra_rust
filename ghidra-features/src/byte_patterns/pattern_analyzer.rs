//! Byte-pattern-based function start analyzer.
//!
//! Ported from Ghidra's `FunctionStartAnalyzer`, `FunctionStartPreFuncAnalyzer`,
//! `FunctionStartFuncAnalyzer`, `FunctionStartPostAnalyzer`, and
//! `FunctionStartDataPostAnalyzer`.
//!
//! The analyzer uses byte patterns (from a [`FuncDB`](super::func_db::FuncDB))
//! to identify function start addresses in a binary.  Patterns are applied
//! by scanning the binary's code sections and matching against known
//! function prologues.

use serde::{Deserialize, Serialize};

use super::func_db::FuncDB;

// ---------------------------------------------------------------------------
// PatternConstraint -- filters for pattern applicability
// ---------------------------------------------------------------------------

/// Constraints that filter when and where a byte pattern can be applied.
///
/// Ported from Ghidra's `PatternConstraint` class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternConstraint {
    /// Required alignment of the candidate address (1, 2, 4, 8, 16, ...).
    pub alignment: u32,
    /// Minimum number of matching bytes required.
    pub min_pattern_bytes: usize,
    /// Whether to check alignment.
    pub check_alignment: bool,
    /// Whether the candidate must not be in a data section.
    pub must_be_code: bool,
    /// Context register constraints (name -> required value).
    pub context_constraints: Vec<ContextConstraint>,
}

/// A single context register constraint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextConstraint {
    /// Name of the context register (e.g., `ISAModeSwitch`).
    pub register_name: String,
    /// Required value (0 or 1 typically).
    pub required_value: u32,
}

impl Default for PatternConstraint {
    fn default() -> Self {
        Self {
            alignment: 1,
            min_pattern_bytes: 2,
            check_alignment: false,
            must_be_code: true,
            context_constraints: Vec::new(),
        }
    }
}

impl PatternConstraint {
    /// Create a new constraint with the given alignment.
    pub fn with_alignment(alignment: u32) -> Self {
        Self {
            alignment,
            check_alignment: true,
            ..Default::default()
        }
    }

    /// Check whether `address` satisfies the alignment requirement.
    pub fn is_aligned(&self, address: u64) -> bool {
        if !self.check_alignment {
            return true;
        }
        address % (self.alignment as u64) == 0
    }

    /// Check whether `address` satisfies all constraints.
    pub fn is_valid(&self, address: u64, _is_code: bool) -> bool {
        if !self.is_aligned(address) {
            return false;
        }
        // In a real implementation, must_be_code and context_constraints would
        // be checked against the program's memory and context registers.
        true
    }
}

// ---------------------------------------------------------------------------
// PatternMatchResult
// ---------------------------------------------------------------------------

/// The result of matching a byte pattern at a specific address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatchResult {
    /// The address where the pattern matched.
    pub address: u64,
    /// The name of the function this pattern identifies.
    pub function_name: String,
    /// The library this function belongs to.
    pub library_name: String,
    /// The size of the function (from the pattern database).
    pub function_size: u64,
    /// The confidence of the match (0.0 to 1.0).
    pub confidence: f64,
}

// ---------------------------------------------------------------------------
// FunctionStartAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer that uses byte patterns to identify function starts.
///
/// Scans executable code sections of the binary and matches against patterns
/// stored in a [`FuncDB`].
///
/// # Usage
///
/// ```rust
/// use ghidra_features::byte_patterns::*;
///
/// let mut db = FuncDB::new();
/// let mut lib = LibraryRecord::new("libc.so", "2.31");
/// lib.add_function(FuncRecord::new("memcpy", "libc.so",
///     vec![0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10], 48));
/// db.add_library(lib);
///
/// let analyzer = FunctionStartAnalyzer::new(&db);
/// let binary = vec![0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10, 0xFF, 0xFF];
/// let results = analyzer.analyze(&binary, 0x400000);
/// assert_eq!(results.len(), 1);
/// ```
#[derive(Debug)]
pub struct FunctionStartAnalyzer<'a> {
    /// The function database to match against.
    pub func_db: &'a FuncDB,
    /// Constraints for pattern matching.
    pub constraint: PatternConstraint,
    /// Step size when scanning (default: 1 byte).
    pub scan_step: usize,
}

impl<'a> FunctionStartAnalyzer<'a> {
    /// Create a new analyzer with default constraints.
    pub fn new(func_db: &'a FuncDB) -> Self {
        Self {
            func_db,
            constraint: PatternConstraint::default(),
            scan_step: 1,
        }
    }

    /// Create a new analyzer with specific constraints.
    pub fn with_constraint(func_db: &'a FuncDB, constraint: PatternConstraint) -> Self {
        Self {
            func_db,
            constraint,
            scan_step: 1,
        }
    }

    /// Analyze a byte buffer starting at `base_address`.
    ///
    /// Returns all matches found.
    pub fn analyze(&self, data: &[u8], base_address: u64) -> Vec<PatternMatchResult> {
        let mut results = Vec::new();
        let step = self.scan_step;

        for offset in (0..data.len()).step_by(step) {
            let addr = base_address + offset as u64;
            if !self.constraint.is_valid(addr, true) {
                continue;
            }

            let remaining = &data[offset..];
            let matches = self.func_db.match_bytes(remaining);
            for m in matches {
                results.push(PatternMatchResult {
                    address: addr,
                    function_name: m.name.clone(),
                    library_name: m.library_name.clone(),
                    function_size: m.function_size,
                    confidence: self.calculate_confidence(m.significant_bytes(), m.pattern_length()),
                });
            }
        }

        results
    }

    /// Calculate a confidence score for a match based on the number of
    /// significant (non-wildcard) bytes.
    fn calculate_confidence(&self, significant: usize, total: usize) -> f64 {
        if total == 0 {
            return 0.0;
        }
        (significant as f64 / total as f64).min(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::byte_patterns::func_db::{FuncDB, FuncRecord, LibraryRecord};

    fn make_test_db() -> FuncDB {
        let mut db = FuncDB::new();
        let mut lib = LibraryRecord::new("libc.so", "2.31");
        lib.add_function(FuncRecord::new(
            "memcpy",
            "libc.so",
            vec![0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10],
            48,
        ));
        lib.add_function(FuncRecord::new(
            "strlen",
            "libc.so",
            vec![0x55, 0x31, 0xC0],
            32,
        ));
        db.add_library(lib);
        db
    }

    #[test]
    fn test_analyzer_finds_match() {
        let db = make_test_db();
        let analyzer = FunctionStartAnalyzer::new(&db);
        let data = vec![
            0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10, 0xFF, 0xFF,
        ];
        let results = analyzer.analyze(&data, 0x400000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].function_name, "memcpy");
        assert_eq!(results[0].address, 0x400000);
    }

    #[test]
    fn test_analyzer_no_match() {
        let db = make_test_db();
        let analyzer = FunctionStartAnalyzer::new(&db);
        let data = vec![0xFF, 0xFF, 0xFF, 0xFF];
        let results = analyzer.analyze(&data, 0x400000);
        assert!(results.is_empty());
    }

    #[test]
    fn test_analyzer_match_at_offset() {
        let db = make_test_db();
        let analyzer = FunctionStartAnalyzer::new(&db);
        let data = vec![0xFF, 0x55, 0x31, 0xC0, 0xFF];
        let results = analyzer.analyze(&data, 0x400000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, 0x400001);
        assert_eq!(results[0].function_name, "strlen");
    }

    #[test]
    fn test_analyzer_multiple_matches() {
        let db = make_test_db();
        let analyzer = FunctionStartAnalyzer::new(&db);
        // Two strlen patterns in the data
        let data = vec![0x55, 0x31, 0xC0, 0x00, 0x55, 0x31, 0xC0];
        let results = analyzer.analyze(&data, 0x1000);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_pattern_constraint_alignment() {
        let c = PatternConstraint::with_alignment(16);
        assert!(c.is_aligned(0x1000));
        assert!(c.is_aligned(0x2010));
        assert!(!c.is_aligned(0x2001));
    }

    #[test]
    fn test_pattern_constraint_default() {
        let c = PatternConstraint::default();
        assert!(c.is_aligned(0x1234)); // alignment = 1, always true
        assert_eq!(c.min_pattern_bytes, 2);
    }
}
