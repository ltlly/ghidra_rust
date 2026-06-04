//! Function byte-pattern database.
//!
//! Ported from Ghidra's `FuncDB`, `FuncRecord`, `LibraryRecord`, and
//! `FuncDBsmall` classes.
//!
//! A `FuncDB` stores function byte-pattern signatures for a set of
//! libraries. Each library has a [`LibraryRecord`] containing
//! [`FuncRecord`]s.  Patterns can be matched against a binary to
//! identify known functions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// FuncRecord
// ---------------------------------------------------------------------------

/// A single function signature record in the database.
///
/// Stores the byte pattern for a function together with metadata about the
/// function's name, size, and the library it came from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuncRecord {
    /// Name of the function (possibly demangled).
    pub name: String,
    /// Full namespace-qualified name.
    pub full_name: String,
    /// Library name this function belongs to.
    pub library_name: String,
    /// The byte pattern of the function's first N bytes (or selected
    /// characteristic bytes).
    pub byte_pattern: Vec<u8>,
    /// Wildcard mask: `true` = this byte is part of the pattern;
    /// `false` = wildcard (any byte matches).
    pub mask: Vec<bool>,
    /// Size of the function in bytes.
    pub function_size: u64,
    /// Address of the function within the original library (offset).
    pub library_offset: u64,
    /// Hash of the function body (for quick rejection).
    pub body_hash: u64,
    /// Alignment requirement (e.g., 16 for functions aligned to 16 bytes).
    pub alignment: u32,
}

impl FuncRecord {
    /// Create a new function record with a byte pattern.
    pub fn new(
        name: impl Into<String>,
        library_name: impl Into<String>,
        byte_pattern: Vec<u8>,
        function_size: u64,
    ) -> Self {
        let name = name.into();
        let mask = vec![true; byte_pattern.len()];
        Self {
            full_name: name.clone(),
            name,
            library_name: library_name.into(),
            byte_pattern,
            mask,
            function_size,
            library_offset: 0,
            body_hash: 0,
            alignment: 1,
        }
    }

    /// The length of the byte pattern.
    pub fn pattern_length(&self) -> usize {
        self.byte_pattern.len()
    }

    /// Check whether a byte slice matches this record's pattern.
    ///
    /// Returns `true` if every non-masked byte matches the pattern.
    pub fn matches(&self, data: &[u8]) -> bool {
        if data.len() < self.byte_pattern.len() {
            return false;
        }
        for i in 0..self.byte_pattern.len() {
            if self.mask[i] && data[i] != self.byte_pattern[i] {
                return false;
            }
        }
        true
    }

    /// The number of significant (non-wildcard) bytes in the pattern.
    pub fn significant_bytes(&self) -> usize {
        self.mask.iter().filter(|&&m| m).count()
    }
}

// ---------------------------------------------------------------------------
// LibraryRecord
// ---------------------------------------------------------------------------

/// A record of functions from a single library.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibraryRecord {
    /// The name of the library (e.g., "kernel32.dll").
    pub name: String,
    /// The version string of the library.
    pub version: String,
    /// Functions in this library, keyed by function name.
    pub functions: HashMap<String, FuncRecord>,
}

impl LibraryRecord {
    /// Create a new library record.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            functions: HashMap::new(),
        }
    }

    /// Add a function to this library record.
    pub fn add_function(&mut self, record: FuncRecord) {
        self.functions.insert(record.name.clone(), record);
    }

    /// Look up a function by name.
    pub fn get_function(&self, name: &str) -> Option<&FuncRecord> {
        self.functions.get(name)
    }

    /// Number of functions in this library.
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }
}

// ---------------------------------------------------------------------------
// FuncDB
// ---------------------------------------------------------------------------

/// A database of function byte-pattern signatures across multiple libraries.
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
/// let matches = db.match_bytes(&[0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10, 0xFF, 0xFF]);
/// assert_eq!(matches.len(), 1);
/// assert_eq!(matches[0].name, "memcpy");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuncDB {
    /// Libraries in the database, keyed by library name.
    pub libraries: HashMap<String, LibraryRecord>,
    /// A flat index of all function patterns, sorted by pattern length
    /// (longest first) for efficient matching.
    pattern_index: Vec<(String, String)>, // (library_name, func_name)
}

impl FuncDB {
    /// Create a new empty function database.
    pub fn new() -> Self {
        Self {
            libraries: HashMap::new(),
            pattern_index: Vec::new(),
        }
    }

    /// Add a library to the database.
    pub fn add_library(&mut self, library: LibraryRecord) {
        let lib_name = library.name.clone();
        for func_name in library.functions.keys() {
            self.pattern_index.push((lib_name.clone(), func_name.clone()));
        }
        self.libraries.insert(lib_name, library);
        self.rebuild_index();
    }

    /// Look up a function by library name and function name.
    pub fn get_function(&self, library: &str, function: &str) -> Option<&FuncRecord> {
        self.libraries
            .get(library)
            .and_then(|lib| lib.get_function(function))
    }

    /// Match a byte slice against all patterns in the database.
    ///
    /// Returns references to all matching [`FuncRecord`]s.
    pub fn match_bytes(&self, data: &[u8]) -> Vec<&FuncRecord> {
        let mut results = Vec::new();
        for (lib_name, func_name) in &self.pattern_index {
            if let Some(lib) = self.libraries.get(lib_name) {
                if let Some(func) = lib.get_function(func_name) {
                    if func.matches(data) {
                        results.push(func);
                    }
                }
            }
        }
        results
    }

    /// Total number of functions across all libraries.
    pub fn total_functions(&self) -> usize {
        self.libraries.values().map(|l| l.function_count()).sum()
    }

    /// Total number of libraries.
    pub fn library_count(&self) -> usize {
        self.libraries.len()
    }

    /// Rebuild the internal index sorted by pattern length (longest first).
    fn rebuild_index(&mut self) {
        self.pattern_index.clear();
        for lib in self.libraries.values() {
            for func in lib.functions.values() {
                self.pattern_index
                    .push((lib.name.clone(), func.name.clone()));
            }
        }
        self.pattern_index.sort_by(|a, b| {
            let len_a = self.libraries[&a.0].functions[&a.1].pattern_length();
            let len_b = self.libraries[&b.0].functions[&b.1].pattern_length();
            len_b.cmp(&len_a) // longest first
        });
    }
}

impl Default for FuncDB {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_func_record_matches() {
        let rec = FuncRecord::new("test_func", "test.lib", vec![0x55, 0x89, 0xE5], 10);
        assert!(rec.matches(&[0x55, 0x89, 0xE5]));
        assert!(rec.matches(&[0x55, 0x89, 0xE5, 0xFF])); // longer is OK
        assert!(!rec.matches(&[0x55, 0x89, 0xEC])); // last byte differs
        assert!(!rec.matches(&[0x55, 0x89])); // too short
    }

    #[test]
    fn test_func_record_with_wildcards() {
        let mut rec = FuncRecord::new("wild", "lib", vec![0x55, 0x00, 0xE5], 10);
        rec.mask = vec![true, false, true]; // middle byte is wildcard
        assert!(rec.matches(&[0x55, 0xFF, 0xE5])); // wildcard byte
        assert!(!rec.matches(&[0x54, 0xFF, 0xE5])); // first byte differs
        assert_eq!(rec.significant_bytes(), 2);
    }

    #[test]
    fn test_library_record_basic() {
        let mut lib = LibraryRecord::new("kernel32.dll", "10.0");
        lib.add_function(FuncRecord::new("CreateFileW", "kernel32.dll", vec![0xFF, 0x25], 32));
        lib.add_function(FuncRecord::new("ReadFile", "kernel32.dll", vec![0xFF, 0x15], 48));

        assert_eq!(lib.function_count(), 2);
        assert!(lib.get_function("CreateFileW").is_some());
        assert!(lib.get_function("NonExistent").is_none());
    }

    #[test]
    fn test_func_db_match_bytes() {
        let mut db = FuncDB::new();
        let mut lib = LibraryRecord::new("libc.so", "2.31");
        lib.add_function(FuncRecord::new(
            "memcpy",
            "libc.so",
            vec![0x55, 0x48, 0x89, 0xE5],
            48,
        ));
        lib.add_function(FuncRecord::new(
            "strlen",
            "libc.so",
            vec![0x55, 0x31, 0xC0],
            32,
        ));
        db.add_library(lib);

        let matches = db.match_bytes(&[0x55, 0x48, 0x89, 0xE5, 0xFF]);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "memcpy");
    }

    #[test]
    fn test_func_db_total_functions() {
        let mut db = FuncDB::new();
        let mut lib1 = LibraryRecord::new("lib1", "1.0");
        lib1.add_function(FuncRecord::new("f1", "lib1", vec![0x01], 10));
        lib1.add_function(FuncRecord::new("f2", "lib1", vec![0x02], 10));
        let mut lib2 = LibraryRecord::new("lib2", "1.0");
        lib2.add_function(FuncRecord::new("f3", "lib2", vec![0x03], 10));

        db.add_library(lib1);
        db.add_library(lib2);

        assert_eq!(db.total_functions(), 3);
        assert_eq!(db.library_count(), 2);
    }

    #[test]
    fn test_func_db_no_match() {
        let mut db = FuncDB::new();
        let mut lib = LibraryRecord::new("lib", "1.0");
        lib.add_function(FuncRecord::new("fn", "lib", vec![0xAA, 0xBB], 10));
        db.add_library(lib);

        let matches = db.match_bytes(&[0xCC, 0xDD, 0xEE]);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_pattern_index_longest_first() {
        let mut db = FuncDB::new();
        let mut lib = LibraryRecord::new("lib", "1.0");
        lib.add_function(FuncRecord::new("short", "lib", vec![0x01, 0x02], 10));
        lib.add_function(FuncRecord::new("long", "lib", vec![0x01, 0x02, 0x03, 0x04, 0x05], 10));
        db.add_library(lib);

        // The index should have "long" before "short" (longest first)
        assert_eq!(db.pattern_index[0].1, "long");
        assert_eq!(db.pattern_index[1].1, "short");
    }
}
