//! High-level facade API for BSim operations.
//!
//! Ports `ghidra.features.bsim.query.facade` from Ghidra's Java source.
//!
//! Provides a simplified interface for common BSim operations.

use super::client::BSimClientFactory;
use super::description::{
    BSimExecutableInfo, BSimFunctionDescription, BSimResultSet, SimilarityMetric,
};
use super::function_database::FunctionDatabase;
use super::server_config::ServerConfig;
use super::BSimResult;

/// High-level BSim API facade.
///
/// Wraps the lower-level `FunctionDatabase` interface with convenience methods
/// for common operations like searching, ingesting, and managing executables.
pub struct BSimFacade {
    database: Box<dyn FunctionDatabase>,
}

impl BSimFacade {
    /// Create a new BSim facade with the given backend configuration.
    pub fn new(config: &ServerConfig) -> BSimResult<Self> {
        let mut database = BSimClientFactory::create_from_config(config)?;
        database.open()?;
        Ok(Self { database })
    }

    /// Create a facade from an existing database.
    pub fn from_database(database: Box<dyn FunctionDatabase>) -> Self {
        Self { database }
    }

    /// Search for functions similar to the given function.
    pub fn search_similar(
        &self,
        function: &BSimFunctionDescription,
        max_results: usize,
    ) -> BSimResult<BSimResultSet> {
        self.database.query_similar(
            function,
            SimilarityMetric::Combined,
            max_results,
            0.5,
        )
    }

    /// Search for functions with a specific metric and threshold.
    pub fn search_with_metric(
        &self,
        function: &BSimFunctionDescription,
        metric: SimilarityMetric,
        max_results: usize,
        min_similarity: f64,
    ) -> BSimResult<BSimResultSet> {
        self.database
            .query_similar(function, metric, max_results, min_similarity)
    }

    /// Register an executable and ingest its functions.
    pub fn register_and_ingest(
        &mut self,
        executable: &BSimExecutableInfo,
        functions: &[BSimFunctionDescription],
    ) -> BSimResult<usize> {
        self.database.register_executable(executable)?;
        self.database.ingest_functions(functions)
    }

    /// Remove an executable and all its functions.
    pub fn remove_executable(&mut self, executable_id: &str) -> BSimResult<()> {
        self.database.remove_executable(executable_id)
    }

    /// Get all functions for an executable.
    pub fn get_functions(
        &self,
        executable_id: &str,
    ) -> BSimResult<Vec<BSimFunctionDescription>> {
        self.database.get_functions_for_executable(executable_id)
    }

    /// Get executable info.
    pub fn get_executable_info(
        &self,
        executable_id: &str,
    ) -> BSimResult<Option<BSimExecutableInfo>> {
        self.database.get_executable_info(executable_id)
    }

    /// Get the total function count.
    pub fn function_count(&self) -> BSimResult<usize> {
        self.database.function_count()
    }

    /// Get the total executable count.
    pub fn executable_count(&self) -> BSimResult<usize> {
        self.database.executable_count()
    }

    /// Search by function hash.
    pub fn lookup_by_hash(
        &self,
        function_hash: &str,
    ) -> BSimResult<Option<BSimFunctionDescription>> {
        self.database.query_by_hash(function_hash)
    }

    /// Get a reference to the underlying database.
    pub fn database(&self) -> &dyn FunctionDatabase {
        self.database.as_ref()
    }

    /// Get a mutable reference to the underlying database.
    pub fn database_mut(&mut self) -> &mut dyn FunctionDatabase {
        self.database.as_mut()
    }

    /// Close the facade and its underlying database.
    pub fn close(&mut self) -> BSimResult<()> {
        self.database.close()
    }
}

/// Compare two function signatures and compute a similarity score.
///
/// Ports `ghidra.features.bsim.query.CompareSignatures`.
pub fn compare_signatures(
    sig1: &super::description::FunctionSignatureInfo,
    sig2: &super::description::FunctionSignatureInfo,
) -> f64 {
    // Compute Jaccard similarity on mnemonic sets.
    let set1: std::collections::HashSet<&str> = sig1.mnemonic_sequence.iter().map(|s| s.as_str()).collect();
    let set2: std::collections::HashSet<&str> = sig2.mnemonic_sequence.iter().map(|s| s.as_str()).collect();

    if set1.is_empty() && set2.is_empty() {
        return 1.0;
    }
    if set1.is_empty() || set2.is_empty() {
        return 0.0;
    }

    let intersection = set1.intersection(&set2).count();
    let union = set1.union(&set2).count();

    intersection as f64 / union as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::description::FunctionSignatureInfo;

    #[test]
    fn test_facade_new() {
        let config = ServerConfig::postgresql("localhost", "bsim");
        let facade = BSimFacade::new(&config);
        assert!(facade.is_ok());
    }

    #[test]
    fn test_facade_search_similar() {
        let config = ServerConfig::postgresql("localhost", "bsim");
        let facade = BSimFacade::new(&config).unwrap();
        let func = BSimFunctionDescription::new("exe1", "main", 0x1000);
        let results = facade.search_similar(&func, 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_facade_register_and_ingest() {
        let config = ServerConfig::postgresql("localhost", "bsim");
        let mut facade = BSimFacade::new(&config).unwrap();
        let exe = BSimExecutableInfo::new("exe1", "test.exe");
        let funcs = vec![
            BSimFunctionDescription::new("exe1", "main", 0x1000),
            BSimFunctionDescription::new("exe1", "helper", 0x2000),
        ];
        let count = facade.register_and_ingest(&exe, &funcs).unwrap();
        assert_eq!(count, 2);
        assert_eq!(facade.function_count().unwrap(), 2);
    }

    #[test]
    fn test_facade_remove_executable() {
        let config = ServerConfig::postgresql("localhost", "bsim");
        let mut facade = BSimFacade::new(&config).unwrap();
        let exe = BSimExecutableInfo::new("exe1", "test.exe");
        let funcs = vec![BSimFunctionDescription::new("exe1", "main", 0x1000)];
        facade.register_and_ingest(&exe, &funcs).unwrap();

        facade.remove_executable("exe1").unwrap();
        assert_eq!(facade.function_count().unwrap(), 0);
    }

    #[test]
    fn test_compare_signatures_identical() {
        let sig1 = FunctionSignatureInfo::new().with_mnemonics(
            vec!["push".into(), "mov".into(), "call".into()],
        );
        let sig2 = FunctionSignatureInfo::new().with_mnemonics(
            vec!["push".into(), "mov".into(), "call".into()],
        );
        let score = compare_signatures(&sig1, &sig2);
        assert!((score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compare_signatures_different() {
        let sig1 = FunctionSignatureInfo::new().with_mnemonics(
            vec!["push".into(), "mov".into()],
        );
        let sig2 = FunctionSignatureInfo::new().with_mnemonics(
            vec!["xor".into(), "jmp".into()],
        );
        let score = compare_signatures(&sig1, &sig2);
        assert!((score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compare_signatures_partial() {
        let sig1 = FunctionSignatureInfo::new().with_mnemonics(
            vec!["push".into(), "mov".into(), "call".into()],
        );
        let sig2 = FunctionSignatureInfo::new().with_mnemonics(
            vec!["push".into(), "mov".into(), "ret".into()],
        );
        let score = compare_signatures(&sig1, &sig2);
        // intersection = {push, mov} = 2, union = {push, mov, call, ret} = 4
        assert!((score - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compare_signatures_empty() {
        let sig1 = FunctionSignatureInfo::new();
        let sig2 = FunctionSignatureInfo::new();
        let score = compare_signatures(&sig1, &sig2);
        assert!((score - 1.0).abs() < f64::EPSILON);
    }
}
