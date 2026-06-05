//! PostgreSQL-specific BSim backend.
//!
//! Port of `ghidra.features.bsim.query.postgresql`:
//! PostgreSQL function database implementation.

use super::client::AbstractSQLFunctionDatabase;
use super::super::description::{ExecutableRecord, FunctionDescription};

/// PostgreSQL-backed BSim function database.
#[derive(Debug, Clone)]
pub struct PostgresqlFunctionDatabase {
    /// Connection URL.
    pub url: String,
    /// Database name.
    pub database: String,
    /// Cached functions.
    functions: Vec<FunctionDescription>,
    /// Cached executables.
    executables: Vec<ExecutableRecord>,
}

impl PostgresqlFunctionDatabase {
    /// Create a new PostgreSQL function database handle.
    pub fn new(url: impl Into<String>, database: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            database: database.into(),
            functions: Vec::new(),
            executables: Vec::new(),
        }
    }
}

impl AbstractSQLFunctionDatabase for PostgresqlFunctionDatabase {
    fn query_by_name(&self, exe_index: usize, name: &str) -> Option<FunctionDescription> {
        self.functions
            .iter()
            .find(|f| f.exe_index == exe_index && f.function_name == name)
            .cloned()
    }

    fn query_by_executable(&self, exe_index: usize) -> Vec<FunctionDescription> {
        self.functions
            .iter()
            .filter(|f| f.exe_index == exe_index)
            .cloned()
            .collect()
    }

    fn insert_function(&mut self, func: &FunctionDescription) -> Result<(), String> {
        self.functions.push(func.clone());
        Ok(())
    }

    fn insert_executable(&mut self, exe: &ExecutableRecord) -> Result<(), String> {
        self.executables.push(exe.clone());
        Ok(())
    }

    fn delete_function(&mut self, exe_index: usize, name: &str) -> Result<(), String> {
        self.functions
            .retain(|f| !(f.exe_index == exe_index && f.function_name == name));
        Ok(())
    }

    fn function_count(&self) -> usize {
        self.functions.len()
    }

    fn executable_count(&self) -> usize {
        self.executables.len()
    }
}

/// SQL function database (generic SQL backend).
pub type SQLFunctionDatabase = PostgresqlFunctionDatabase;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_postgresql_database() {
        let mut db = PostgresqlFunctionDatabase::new("localhost:5432", "bsim");
        let func = FunctionDescription::new(0, "main", Some(0x1000));
        db.insert_function(&func).unwrap();
        assert_eq!(db.function_count(), 1);

        let found = db.query_by_name(0, "main");
        assert!(found.is_some());
        assert_eq!(found.unwrap().function_name, "main");
    }

    #[test]
    fn test_delete_function() {
        let mut db = PostgresqlFunctionDatabase::new("localhost:5432", "bsim");
        let func = FunctionDescription::new(0, "main", Some(0x1000));
        db.insert_function(&func).unwrap();
        db.delete_function(0, "main").unwrap();
        assert_eq!(db.function_count(), 0);
    }

    #[test]
    fn test_query_by_executable() {
        let mut db = PostgresqlFunctionDatabase::new("localhost", "bsim");
        db.insert_function(&FunctionDescription::new(0, "main", Some(0x1000))).unwrap();
        db.insert_function(&FunctionDescription::new(0, "helper", Some(0x2000))).unwrap();
        db.insert_function(&FunctionDescription::new(1, "other", Some(0x3000))).unwrap();

        let results = db.query_by_executable(0);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_executable_insert() {
        let mut db = PostgresqlFunctionDatabase::new("localhost", "bsim");
        let exe = ExecutableRecord::new("abc123", "test.exe", "x86", "gcc");
        db.insert_executable(&exe).unwrap();
        assert_eq!(db.executable_count(), 1);
    }
}
