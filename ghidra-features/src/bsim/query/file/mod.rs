//! H2/file-based local BSim database.
//!
//! Port of `ghidra.features.bsim.query.file`:
//! - [`H2FileFunctionDatabase`]: file-based function database
//! - [`VectorStore`]: local vector storage
//! - [`VectorStoreEntry`]: individual vector entries

use serde::{Deserialize, Serialize};

use super::client::AbstractSQLFunctionDatabase;
use super::super::description::{ExecutableRecord, FunctionDescription};

/// An entry in a vector store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorStoreEntry {
    /// Function name.
    pub function_name: String,
    /// Executable index.
    pub exe_index: usize,
    /// Feature vector (hash -> weight pairs).
    pub vector: Vec<(u64, f64)>,
    /// Storage offset in the file.
    pub offset: u64,
}

impl VectorStoreEntry {
    /// Create a new vector store entry.
    pub fn new(function_name: impl Into<String>, exe_index: usize) -> Self {
        Self {
            function_name: function_name.into(),
            exe_index,
            vector: Vec::new(),
            offset: 0,
        }
    }
}

/// Local file-based vector storage.
#[derive(Debug, Clone)]
pub struct VectorStore {
    /// Path to the store directory.
    pub path: String,
    /// Entries in the store.
    entries: Vec<VectorStoreEntry>,
}

impl VectorStore {
    /// Create a new vector store at the given path.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            entries: Vec::new(),
        }
    }

    /// Add an entry to the store.
    pub fn add_entry(&mut self, entry: VectorStoreEntry) {
        self.entries.push(entry);
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get all entries.
    pub fn entries(&self) -> &[VectorStoreEntry] {
        &self.entries
    }
}

/// H2 file-based BSim function database.
#[derive(Debug, Clone)]
pub struct H2FileFunctionDatabase {
    /// Path to the database file.
    pub db_path: String,
    /// Functions stored in the database.
    functions: Vec<FunctionDescription>,
    /// Executables stored in the database.
    executables: Vec<ExecutableRecord>,
    /// Vector store for feature vectors.
    pub vector_store: VectorStore,
}

impl H2FileFunctionDatabase {
    /// Create a new H2 file function database.
    pub fn new(db_path: impl Into<String>) -> Self {
        let path = db_path.into();
        Self {
            vector_store: VectorStore::new(format!("{}.vectors", path)),
            db_path: path,
            functions: Vec::new(),
            executables: Vec::new(),
        }
    }
}

impl AbstractSQLFunctionDatabase for H2FileFunctionDatabase {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_store_entry() {
        let mut entry = VectorStoreEntry::new("main", 0);
        entry.vector.push((100, 0.5));
        assert_eq!(entry.function_name, "main");
        assert_eq!(entry.vector.len(), 1);
    }

    #[test]
    fn test_vector_store() {
        let mut store = VectorStore::new("/tmp/vectors");
        assert!(store.is_empty());
        store.add_entry(VectorStoreEntry::new("f1", 0));
        store.add_entry(VectorStoreEntry::new("f2", 1));
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_h2_database() {
        let mut db = H2FileFunctionDatabase::new("/tmp/test.bsim");
        assert_eq!(db.db_path, "/tmp/test.bsim");

        let func = FunctionDescription::new(0, "main", Some(0x1000));
        db.insert_function(&func).unwrap();
        assert_eq!(db.function_count(), 1);

        let found = db.query_by_name(0, "main");
        assert!(found.is_some());
    }

    #[test]
    fn test_h2_delete() {
        let mut db = H2FileFunctionDatabase::new("/tmp/test.bsim");
        db.insert_function(&FunctionDescription::new(0, "f1", None)).unwrap();
        db.delete_function(0, "f1").unwrap();
        assert_eq!(db.function_count(), 0);
    }
}
