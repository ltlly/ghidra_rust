//! BSim query staging -- splitting large queries into manageable pieces.
//!
//! Ports Ghidra's `ghidra.features.bsim.query.protocol` staging types:
//! - [`StagingManager`] -- abstract base for staged queries
//! - [`FunctionStaging`] -- splits function-similarity queries by batches
//! - [`NullStaging`] -- pass-through (no staging, single query)

use serde::{Deserialize, Serialize};

use super::description::FunctionDescription;

// ============================================================================
// StagingManager (trait)
// ============================================================================

/// Abstract manager for splitting a (presumably large) query into smaller
/// pieces.
///
/// After configuration via `set_query`, call `initialize` to build the
/// first stage, then repeatedly call `next_stage` until it returns `false`.
///
/// Port of `ghidra.features.bsim.query.protocol.StagingManager`.
pub trait StagingManager {
    /// Get the total number of separate queries being staged.
    fn total_size(&self) -> usize;

    /// Get the number of queries already sent.
    fn queries_made(&self) -> usize;

    /// Get the current staged query (as a batch of function descriptions).
    fn get_query(&self) -> &[FunctionDescription];

    /// Establish the first query stage.
    ///
    /// Returns `true` if the initial query was constructed successfully.
    fn initialize(&mut self) -> bool;

    /// Advance to the next query stage.
    ///
    /// Returns `true` if a new stage was constructed; `false` when all
    /// stages have been exhausted.
    fn next_stage(&mut self) -> bool;

    /// Whether staging is complete (no more stages to process).
    fn is_complete(&self) -> bool {
        self.queries_made() >= self.total_size()
    }
}

// ============================================================================
// FunctionStaging
// ============================================================================

/// Splits a list of function descriptions into batches for staged querying.
///
/// This is useful when querying a large number of functions against a BSim
/// database. The staging manager breaks the list into batches of a
/// configurable maximum size.
///
/// Port of `ghidra.features.bsim.query.protocol.FunctionStaging`.
#[derive(Debug, Clone)]
pub struct FunctionStaging {
    /// All functions to be queried.
    all_functions: Vec<FunctionDescription>,
    /// Maximum number of functions per stage.
    batch_size: usize,
    /// Current stage index (0-based).
    current_stage: usize,
    /// Total number of stages.
    total_stages: usize,
    /// Number of stages already processed.
    queries_made: usize,
}

impl FunctionStaging {
    /// Create a new function staging manager.
    ///
    /// `batch_size` controls the maximum number of functions per stage.
    pub fn new(functions: Vec<FunctionDescription>, batch_size: usize) -> Self {
        let batch_size = batch_size.max(1);
        let total_stages = (functions.len() + batch_size - 1) / batch_size;
        Self {
            all_functions: functions,
            batch_size,
            current_stage: 0,
            total_stages,
            queries_made: 0,
        }
    }

    /// Create with a default batch size of 10.
    pub fn with_defaults(functions: Vec<FunctionDescription>) -> Self {
        Self::new(functions, 10)
    }

    /// Get the functions for the current stage.
    fn current_batch(&self) -> &[FunctionDescription] {
        let start = self.current_stage * self.batch_size;
        let end = (start + self.batch_size).min(self.all_functions.len());
        if start < self.all_functions.len() {
            &self.all_functions[start..end]
        } else {
            &[]
        }
    }

    /// Get all functions (before staging).
    pub fn all_functions(&self) -> &[FunctionDescription] {
        &self.all_functions
    }

    /// Get the batch size.
    pub fn batch_size(&self) -> usize {
        self.batch_size
    }
}

impl StagingManager for FunctionStaging {
    fn total_size(&self) -> usize {
        self.total_stages
    }

    fn queries_made(&self) -> usize {
        self.queries_made
    }

    fn get_query(&self) -> &[FunctionDescription] {
        self.current_batch()
    }

    fn initialize(&mut self) -> bool {
        if self.all_functions.is_empty() {
            return false;
        }
        self.current_stage = 0;
        self.queries_made = 0;
        true
    }

    fn next_stage(&mut self) -> bool {
        self.queries_made += 1;
        self.current_stage += 1;
        self.current_stage < self.total_stages
    }
}

// ============================================================================
// NullStaging
// ============================================================================

/// A pass-through staging manager that processes all functions in a single
/// query (no actual staging).
///
/// Port of `ghidra.features.bsim.query.protocol.NullStaging`.
#[derive(Debug, Clone)]
pub struct NullStaging {
    /// All functions to be queried.
    functions: Vec<FunctionDescription>,
    /// Whether the query has been submitted.
    submitted: bool,
}

impl NullStaging {
    /// Create a new null-staging manager with the given functions.
    pub fn new(functions: Vec<FunctionDescription>) -> Self {
        Self {
            functions,
            submitted: false,
        }
    }
}

impl StagingManager for NullStaging {
    fn total_size(&self) -> usize {
        1
    }

    fn queries_made(&self) -> usize {
        if self.submitted { 1 } else { 0 }
    }

    fn get_query(&self) -> &[FunctionDescription] {
        &self.functions
    }

    fn initialize(&mut self) -> bool {
        self.submitted = false;
        !self.functions.is_empty()
    }

    fn next_stage(&mut self) -> bool {
        self.submitted = true;
        false // only one stage
    }
}

// ============================================================================
// ExeSpecifier
// ============================================================================

/// Specifies an executable by name, architecture, and/or MD5.
///
/// Used by staging managers to restrict queries to specific executables.
///
/// Port of `ghidra.features.bsim.query.protocol.ExeSpecifier`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExeSpecifier {
    /// The executable name (exact match).
    pub exe_name: Option<String>,
    /// The architecture string (exact match).
    pub architecture: Option<String>,
    /// The compiler string (exact match).
    pub compiler: Option<String>,
    /// The MD5 hash (exact match).
    pub md5: Option<String>,
}

impl ExeSpecifier {
    /// Create a specifier matching any executable.
    pub fn any() -> Self {
        Self::default()
    }

    /// Create a specifier matching by name.
    pub fn by_name(name: impl Into<String>) -> Self {
        Self {
            exe_name: Some(name.into()),
            ..Default::default()
        }
    }

    /// Create a specifier matching by MD5.
    pub fn by_md5(md5: impl Into<String>) -> Self {
        Self {
            md5: Some(md5.into()),
            ..Default::default()
        }
    }

    /// Whether this specifier has any constraints.
    pub fn has_constraints(&self) -> bool {
        self.exe_name.is_some()
            || self.architecture.is_some()
            || self.compiler.is_some()
            || self.md5.is_some()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_func(name: &str, addr: u64) -> FunctionDescription {
        FunctionDescription::new(0, name, Some(addr))
    }

    fn make_funcs(n: usize) -> Vec<FunctionDescription> {
        (0..n)
            .map(|i| make_func(&format!("func_{}", i), (i as u64) * 0x100))
            .collect()
    }

    #[test]
    fn function_staging_single_batch() {
        let funcs = make_funcs(5);
        let mut staging = FunctionStaging::new(funcs, 10);
        assert_eq!(staging.total_size(), 1);
        assert!(staging.initialize());
        assert_eq!(staging.get_query().len(), 5);
        assert!(!staging.next_stage());
    }

    #[test]
    fn function_staging_multiple_batches() {
        let funcs = make_funcs(25);
        let mut staging = FunctionStaging::new(funcs, 10);
        assert_eq!(staging.total_size(), 3);
        assert!(staging.initialize());
        assert_eq!(staging.get_query().len(), 10);
        assert!(staging.next_stage());
        assert_eq!(staging.get_query().len(), 10);
        assert!(staging.next_stage());
        assert_eq!(staging.get_query().len(), 5);
        assert!(!staging.next_stage());
    }

    #[test]
    fn function_staging_exact_batch_boundary() {
        let funcs = make_funcs(20);
        let mut staging = FunctionStaging::new(funcs, 10);
        assert_eq!(staging.total_size(), 2);
        assert!(staging.initialize());
        assert_eq!(staging.get_query().len(), 10);
        assert!(staging.next_stage());
        assert_eq!(staging.get_query().len(), 10);
        assert!(!staging.next_stage());
    }

    #[test]
    fn function_staging_empty() {
        let funcs = Vec::new();
        let mut staging = FunctionStaging::new(funcs, 10);
        assert_eq!(staging.total_size(), 0);
        assert!(!staging.initialize());
    }

    #[test]
    fn function_staging_one_function_per_batch() {
        let funcs = make_funcs(3);
        let mut staging = FunctionStaging::new(funcs, 1);
        assert_eq!(staging.total_size(), 3);
        assert!(staging.initialize());
        assert_eq!(staging.get_query().len(), 1);
        assert!(staging.next_stage());
        assert_eq!(staging.get_query().len(), 1);
        assert!(staging.next_stage());
        assert_eq!(staging.get_query().len(), 1);
        assert!(!staging.next_stage());
    }

    #[test]
    fn null_staging_sends_all_at_once() {
        let funcs = make_funcs(100);
        let mut staging = NullStaging::new(funcs);
        assert_eq!(staging.total_size(), 1);
        assert!(staging.initialize());
        assert_eq!(staging.get_query().len(), 100);
        assert!(!staging.next_stage());
    }

    #[test]
    fn null_staging_empty() {
        let mut staging = NullStaging::new(Vec::new());
        assert!(!staging.initialize());
    }

    #[test]
    fn exe_specifier_any() {
        let spec = ExeSpecifier::any();
        assert!(!spec.has_constraints());
    }

    #[test]
    fn exe_specifier_by_name() {
        let spec = ExeSpecifier::by_name("test.exe");
        assert!(spec.has_constraints());
        assert_eq!(spec.exe_name.as_deref(), Some("test.exe"));
    }

    #[test]
    fn exe_specifier_by_md5() {
        let spec = ExeSpecifier::by_md5("aabbccdd");
        assert!(spec.has_constraints());
        assert_eq!(spec.md5.as_deref(), Some("aabbccdd"));
    }
}
