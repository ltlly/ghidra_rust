//! Core trait for BSim function database backends.
//!
//! Ports `ghidra.features.bsim.query.FunctionDatabase`.

use super::description::{BSimExecutableInfo, BSimFunctionDescription, BSimResultSet, SimilarityMetric};
use super::BSimResult;

/// The core interface for all BSim database backends.
///
/// Implementations include PostgreSQL, Elasticsearch, and file-based storage.
/// All operations are on function-level descriptions and their similarity.
pub trait FunctionDatabase: Send + Sync {
    /// Open a connection to the database.
    fn open(&mut self) -> BSimResult<()>;

    /// Close the connection.
    fn close(&mut self) -> BSimResult<()>;

    /// Whether the database is currently connected.
    fn is_open(&self) -> bool;

    /// Register a new executable in the database.
    fn register_executable(&mut self, info: &BSimExecutableInfo) -> BSimResult<()>;

    /// Remove an executable and all its functions from the database.
    fn remove_executable(&mut self, executable_id: &str) -> BSimResult<()>;

    /// Check if an executable is registered.
    fn has_executable(&self, executable_id: &str) -> BSimResult<bool>;

    /// Insert or update function descriptions.
    fn ingest_functions(&mut self, functions: &[BSimFunctionDescription]) -> BSimResult<usize>;

    /// Query for functions similar to the given description.
    fn query_similar(
        &self,
        description: &BSimFunctionDescription,
        metric: SimilarityMetric,
        max_results: usize,
        min_similarity: f64,
    ) -> BSimResult<BSimResultSet>;

    /// Query for a specific function by its hash.
    fn query_by_hash(&self, function_hash: &str) -> BSimResult<Option<BSimFunctionDescription>>;

    /// Get all function descriptions for an executable.
    fn get_functions_for_executable(
        &self,
        executable_id: &str,
    ) -> BSimResult<Vec<BSimFunctionDescription>>;

    /// Get information about a registered executable.
    fn get_executable_info(&self, executable_id: &str) -> BSimResult<Option<BSimExecutableInfo>>;

    /// Get the total number of functions in the database.
    fn function_count(&self) -> BSimResult<usize>;

    /// Get the total number of executables in the database.
    fn executable_count(&self) -> BSimResult<usize>;

    /// Run a custom query.
    fn execute_query(&self, query: &str) -> BSimResult<BSimResultSet>;

    /// Whether the backend supports the given similarity metric natively.
    fn supports_metric(&self, metric: SimilarityMetric) -> bool;
}

/// A stub implementation for testing.
#[derive(Debug, Clone, Default)]
pub struct StubFunctionDatabase {
    open: bool,
    functions: Vec<BSimFunctionDescription>,
    executables: Vec<BSimExecutableInfo>,
}

impl StubFunctionDatabase {
    /// Create a new stub database.
    pub fn new() -> Self {
        Self::default()
    }
}

impl FunctionDatabase for StubFunctionDatabase {
    fn open(&mut self) -> BSimResult<()> {
        self.open = true;
        Ok(())
    }

    fn close(&mut self) -> BSimResult<()> {
        self.open = false;
        Ok(())
    }

    fn is_open(&self) -> bool {
        self.open
    }

    fn register_executable(&mut self, info: &BSimExecutableInfo) -> BSimResult<()> {
        self.executables.push(info.clone());
        Ok(())
    }

    fn remove_executable(&mut self, executable_id: &str) -> BSimResult<()> {
        self.executables.retain(|e| e.executable_id != executable_id);
        self.functions.retain(|f| f.executable_id != executable_id);
        Ok(())
    }

    fn has_executable(&self, executable_id: &str) -> BSimResult<bool> {
        Ok(self.executables.iter().any(|e| e.executable_id == executable_id))
    }

    fn ingest_functions(&mut self, functions: &[BSimFunctionDescription]) -> BSimResult<usize> {
        let count = functions.len();
        self.functions.extend_from_slice(functions);
        Ok(count)
    }

    fn query_similar(
        &self,
        _description: &BSimFunctionDescription,
        _metric: SimilarityMetric,
        max_results: usize,
        _min_similarity: f64,
    ) -> BSimResult<BSimResultSet> {
        Ok(BSimResultSet {
            results: self.functions.iter().take(max_results).cloned().collect(),
            total_matches: self.functions.len().min(max_results),
            query_time_ms: 0,
        })
    }

    fn query_by_hash(&self, function_hash: &str) -> BSimResult<Option<BSimFunctionDescription>> {
        Ok(self.functions.iter().find(|f| f.function_hash == function_hash).cloned())
    }

    fn get_functions_for_executable(
        &self,
        executable_id: &str,
    ) -> BSimResult<Vec<BSimFunctionDescription>> {
        Ok(self.functions.iter().filter(|f| f.executable_id == executable_id).cloned().collect())
    }

    fn get_executable_info(&self, executable_id: &str) -> BSimResult<Option<BSimExecutableInfo>> {
        Ok(self.executables.iter().find(|e| e.executable_id == executable_id).cloned())
    }

    fn function_count(&self) -> BSimResult<usize> {
        Ok(self.functions.len())
    }

    fn executable_count(&self) -> BSimResult<usize> {
        Ok(self.executables.len())
    }

    fn execute_query(&self, _query: &str) -> BSimResult<BSimResultSet> {
        Ok(BSimResultSet::empty())
    }

    fn supports_metric(&self, _metric: SimilarityMetric) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stub_database_open_close() {
        let mut db = StubFunctionDatabase::new();
        assert!(!db.is_open());
        db.open().unwrap();
        assert!(db.is_open());
        db.close().unwrap();
        assert!(!db.is_open());
    }

    #[test]
    fn test_stub_database_register_executable() {
        let mut db = StubFunctionDatabase::new();
        db.open().unwrap();

        let info = BSimExecutableInfo::new("exe1", "test.exe");
        db.register_executable(&info).unwrap();
        assert!(db.has_executable("exe1").unwrap());
        assert!(!db.has_executable("exe2").unwrap());
        assert_eq!(db.executable_count().unwrap(), 1);
    }

    #[test]
    fn test_stub_database_ingest_and_query() {
        let mut db = StubFunctionDatabase::new();
        db.open().unwrap();

        let func = BSimFunctionDescription::new("exe1", "func1", 0x1000);
        db.ingest_functions(&[func]).unwrap();
        assert_eq!(db.function_count().unwrap(), 1);

        let results = db.get_functions_for_executable("exe1").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].function_name, "func1");
    }

    #[test]
    fn test_stub_database_remove_executable() {
        let mut db = StubFunctionDatabase::new();
        db.open().unwrap();

        let info = BSimExecutableInfo::new("exe1", "test.exe");
        db.register_executable(&info).unwrap();
        let func = BSimFunctionDescription::new("exe1", "func1", 0x1000);
        db.ingest_functions(&[func]).unwrap();

        db.remove_executable("exe1").unwrap();
        assert!(!db.has_executable("exe1").unwrap());
        assert_eq!(db.function_count().unwrap(), 0);
    }
}
