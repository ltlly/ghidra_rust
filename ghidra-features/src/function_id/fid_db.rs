//! FID database structures: function records, library records, and relations.
//!
//! Ported from Ghidra's `ghidra.feature.fid.db` package.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// FunctionRecord
// ---------------------------------------------------------------------------

/// A single function record in the FID database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionRecord {
    /// Unique ID in the database.
    pub id: i64,
    /// The function name (possibly demangled).
    pub name: String,
    /// Full namespace-qualified name.
    pub full_name: String,
    /// The namespace (e.g., "std::__1", "boost::filesystem").
    pub namespace: String,
    /// Function size in bytes.
    pub size: u64,
    /// Primary hash of the function body.
    pub hash: u64,
    /// Additional hashes from different hash families.
    pub extra_hashes: HashMap<String, u64>,
    /// The library this function belongs to.
    pub library_id: i64,
    /// Calling convention (e.g., "cdecl", "stdcall", "thiscall").
    pub calling_convention: String,
    /// Whether this function is a thunk (trampoline).
    pub is_thunk: bool,
    /// Function parameter count.
    pub param_count: u32,
}

impl FunctionRecord {
    /// Create a new function record with minimal fields.
    pub fn new(
        name: impl Into<String>,
        full_name: impl Into<String>,
        hash: u64,
        size: u64,
        library_id: i64,
    ) -> Self {
        let name = name.into();
        Self {
            id: 0,
            name: name.clone(),
            full_name: full_name.into(),
            namespace: String::new(),
            size,
            hash,
            extra_hashes: HashMap::new(),
            library_id,
            calling_convention: "unknown".into(),
            is_thunk: false,
            param_count: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// LibraryRecord
// ---------------------------------------------------------------------------

/// Metadata about a library in the FID database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibraryRecord {
    /// Unique ID in the database.
    pub id: i64,
    /// The library name (e.g., "kernel32.dll", "libc.so.6").
    pub name: String,
    /// The library version.
    pub version: String,
    /// The processor / architecture (e.g., "x86", "ARM").
    pub processor: String,
    /// The language (e.g., "x86:LE:64:default").
    pub language: String,
    /// The compiler used to build the library (e.g., "MSVC", "GCC").
    pub compiler: String,
    /// Number of functions in this library.
    pub function_count: u32,
    /// Hash of the library file.
    pub file_hash: String,
}

impl LibraryRecord {
    /// Create a new library record.
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        processor: impl Into<String>,
        language: impl Into<String>,
    ) -> Self {
        Self {
            id: 0,
            name: name.into(),
            version: version.into(),
            processor: processor.into(),
            language: language.into(),
            compiler: String::new(),
            function_count: 0,
            file_hash: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// RelationType
// ---------------------------------------------------------------------------

/// The type of relationship between two functions in the FID database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelationType {
    /// An exact match (same hash).
    ExactMatch,
    /// A strong match (hashes match with high confidence).
    StrongMatch,
    /// A weak match (partial match or different hash family).
    WeakMatch,
    /// A thunk / trampoline relationship.
    Thunk,
    /// An alias (same address in different versions).
    Alias,
}

// ---------------------------------------------------------------------------
// RelationRecord
// ---------------------------------------------------------------------------

/// A relation between two function records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationRecord {
    /// Unique ID.
    pub id: i64,
    /// First function ID.
    pub function_id_a: i64,
    /// Second function ID.
    pub function_id_b: i64,
    /// The type of relation.
    pub relation_type: RelationType,
    /// Confidence score (0.0 to 1.0).
    pub confidence: f64,
}

// ---------------------------------------------------------------------------
// FidDB
// ---------------------------------------------------------------------------

/// A function identification database.
///
/// Stores function signatures (hashes, names, metadata) from known libraries.
/// Can be queried to identify functions in unknown binaries.
///
/// # Usage
///
/// ```rust
/// use ghidra_features::function_id::*;
///
/// let mut db = FidDB::new("x86", "x86:LE:64:default");
///
/// let mut lib = LibraryRecord::new("libc.so", "2.31", "x86", "x86:LE:64:default");
/// lib.id = 1;
/// db.add_library(lib);
///
/// let func = FunctionRecord::new("memcpy", "memcpy", 0xDEADBEEF, 48, 1);
/// db.add_function(func);
///
/// let matches = db.find_by_hash(0xDEADBEEF);
/// assert_eq!(matches.len(), 1);
/// assert_eq!(matches[0].name, "memcpy");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FidDB {
    /// The processor / architecture this database covers.
    pub processor: String,
    /// The language specification.
    pub language: String,
    /// Functions indexed by ID.
    pub functions: Vec<FunctionRecord>,
    /// Libraries indexed by ID.
    pub libraries: Vec<LibraryRecord>,
    /// Relations between functions.
    pub relations: Vec<RelationRecord>,
    /// Hash index: primary hash -> function indices.
    hash_index: HashMap<u64, Vec<usize>>,
    /// Name index: function name -> function indices.
    name_index: HashMap<String, Vec<usize>>,
}

impl FidDB {
    /// Create a new empty FID database.
    pub fn new(
        processor: impl Into<String>,
        language: impl Into<String>,
    ) -> Self {
        Self {
            processor: processor.into(),
            language: language.into(),
            functions: Vec::new(),
            libraries: Vec::new(),
            relations: Vec::new(),
            hash_index: HashMap::new(),
            name_index: HashMap::new(),
        }
    }

    /// Add a library to the database.
    pub fn add_library(&mut self, library: LibraryRecord) {
        self.libraries.push(library);
    }

    /// Add a function to the database and update indices.
    pub fn add_function(&mut self, func: FunctionRecord) {
        let idx = self.functions.len();
        self.hash_index
            .entry(func.hash)
            .or_default()
            .push(idx);
        self.name_index
            .entry(func.name.clone())
            .or_default()
            .push(idx);
        self.functions.push(func);
    }

    /// Find functions by primary hash.
    pub fn find_by_hash(&self, hash: u64) -> Vec<&FunctionRecord> {
        self.hash_index
            .get(&hash)
            .map(|indices| indices.iter().map(|&i| &self.functions[i]).collect())
            .unwrap_or_default()
    }

    /// Find functions by name.
    pub fn find_by_name(&self, name: &str) -> Vec<&FunctionRecord> {
        self.name_index
            .get(name)
            .map(|indices| indices.iter().map(|&i| &self.functions[i]).collect())
            .unwrap_or_default()
    }

    /// Find functions by library ID.
    pub fn find_by_library(&self, library_id: i64) -> Vec<&FunctionRecord> {
        self.functions
            .iter()
            .filter(|f| f.library_id == library_id)
            .collect()
    }

    /// Look up a library by ID.
    pub fn get_library(&self, id: i64) -> Option<&LibraryRecord> {
        self.libraries.iter().find(|l| l.id == id)
    }

    /// Total number of functions in the database.
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Total number of libraries in the database.
    pub fn library_count(&self) -> usize {
        self.libraries.len()
    }
}

// ---------------------------------------------------------------------------
// FidFile -- a persisted FID database file
// ---------------------------------------------------------------------------

/// Represents a FID database file on disk.
///
/// In Ghidra this is backed by a `.fidb` SQLite database. Here we provide
/// serialization to/from JSON for portability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FidFile {
    /// File path.
    pub path: String,
    /// The database contents.
    pub database: FidDB,
    /// File version.
    pub version: u32,
    /// Creation timestamp (seconds since epoch).
    pub created_at: u64,
}

impl FidFile {
    /// Create a new FID file wrapper.
    pub fn new(path: impl Into<String>, database: FidDB) -> Self {
        Self {
            path: path.into(),
            database,
            version: 1,
            created_at: 0,
        }
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fid_db_find_by_hash() {
        let mut db = FidDB::new("x86", "x86:LE:64:default");

        let mut lib = LibraryRecord::new("libc.so", "2.31", "x86", "x86:LE:64:default");
        lib.id = 1;
        db.add_library(lib);

        db.add_function(FunctionRecord::new("memcpy", "memcpy", 0xABC, 48, 1));
        db.add_function(FunctionRecord::new("memset", "memset", 0xDEF, 64, 1));

        let matches = db.find_by_hash(0xABC);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "memcpy");

        let no_match = db.find_by_hash(0x999);
        assert!(no_match.is_empty());
    }

    #[test]
    fn test_fid_db_find_by_name() {
        let mut db = FidDB::new("x86", "x86:LE:64:default");
        db.add_function(FunctionRecord::new("strlen", "std::strlen", 0x111, 32, 1));
        db.add_function(FunctionRecord::new("strlen", "strlen", 0x222, 28, 1));

        let matches = db.find_by_name("strlen");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_fid_db_find_by_library() {
        let mut db = FidDB::new("x86", "x86:LE:64:default");
        db.add_library(LibraryRecord::new("lib1", "1.0", "x86", "x86:LE:64:default"));
        db.add_library(LibraryRecord::new("lib2", "1.0", "x86", "x86:LE:64:default"));

        db.add_function(FunctionRecord::new("f1", "f1", 0x100, 10, 1));
        db.add_function(FunctionRecord::new("f2", "f2", 0x200, 10, 1));
        db.add_function(FunctionRecord::new("f3", "f3", 0x300, 10, 2));

        let lib1_funcs = db.find_by_library(1);
        assert_eq!(lib1_funcs.len(), 2);
        let lib2_funcs = db.find_by_library(2);
        assert_eq!(lib2_funcs.len(), 1);
    }

    #[test]
    fn test_fid_db_counts() {
        let mut db = FidDB::new("x86", "x86:LE:64:default");
        db.add_library(LibraryRecord::new("lib1", "1.0", "x86", "x86:LE:64:default"));
        db.add_library(LibraryRecord::new("lib2", "2.0", "x86", "x86:LE:64:default"));
        db.add_function(FunctionRecord::new("f1", "f1", 0x100, 10, 1));
        db.add_function(FunctionRecord::new("f2", "f2", 0x200, 10, 1));

        assert_eq!(db.function_count(), 2);
        assert_eq!(db.library_count(), 2);
    }

    #[test]
    fn test_fid_file_json_roundtrip() {
        let mut db = FidDB::new("x86", "x86:LE:64:default");
        db.add_function(FunctionRecord::new("test", "test", 0xABCD, 16, 1));

        let file = FidFile::new("/tmp/test.fidb", db);
        let json = file.to_json().unwrap();
        let parsed = FidFile::from_json(&json).unwrap();
        assert_eq!(parsed.database.function_count(), 1);
        assert_eq!(parsed.database.functions[0].name, "test");
    }

    #[test]
    fn test_relation_type() {
        let rel = RelationRecord {
            id: 1,
            function_id_a: 10,
            function_id_b: 20,
            relation_type: RelationType::ExactMatch,
            confidence: 1.0,
        };
        assert_eq!(rel.relation_type, RelationType::ExactMatch);
    }

    #[test]
    fn test_library_record_new() {
        let lib = LibraryRecord::new("kernel32.dll", "10.0.19041", "x86", "x86:LE:64:default");
        assert_eq!(lib.name, "kernel32.dll");
        assert_eq!(lib.version, "10.0.19041");
        assert_eq!(lib.processor, "x86");
    }
}
