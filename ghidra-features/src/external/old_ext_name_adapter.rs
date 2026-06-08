//! OldExtNameAdapter -- legacy external name table adapter.
//!
//! Ported from `ghidra.program.database.external.OldExtNameAdapter`.
//!
//! Handles migration of the old "External Program Names" database table
//! (schema version 0) which stored external library names and their
//! associated file paths.  During an upgrade, records are moved from the
//! old table into the new symbol-based storage.

use std::collections::BTreeMap;
use std::fmt;

/// Column index for the external library name in the old table.
pub const EXT_NAME_COL: usize = 0;

/// Column index for the external pathname in the old table.
pub const EXT_PATHNAME_COL: usize = 1;

/// The table name used by the legacy schema.
pub const EXT_NAME_TABLE_NAME: &str = "External Program Names";

/// Errors that can arise when working with the old external name adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OldAdapterError {
    /// The required table was not found in the database.
    MissingTable(String),
    /// The table version is newer than expected.
    NewerVersion,
    /// The table version is older and requires upgrade.
    UpgradeRequired,
    /// A general I/O or data error.
    Other(String),
}

impl fmt::Display for OldAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OldAdapterError::MissingTable(name) => {
                write!(f, "Missing table: {}", name)
            }
            OldAdapterError::NewerVersion => {
                write!(f, "Newer database version not supported")
            }
            OldAdapterError::UpgradeRequired => {
                write!(f, "Database upgrade required")
            }
            OldAdapterError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for OldAdapterError {}

/// A single record from the old external name table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtNameRecord {
    /// Row key.
    pub key: i64,
    /// The external library name.
    pub name: String,
    /// The associated file path (may be empty).
    pub pathname: String,
}

/// Adapter for reading and migrating the legacy "External Program Names"
/// table.
///
/// # Schema (version 0)
///
/// | Column | Type   | Description             |
/// |--------|--------|-------------------------|
/// | 0      | String | External Name           |
/// | 1      | String | External Pathname       |
///
/// The primary key column is labelled `"Key"`.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::old_ext_name_adapter::*;
///
/// let mut adapter = OldExtNameAdapter::new();
/// adapter.add_record(1, "libc", "/usr/lib/libc.so");
/// adapter.add_record(2, "libm", "/usr/lib/libm.so");
///
/// assert_eq!(adapter.record_count(), 2);
///
/// let records: Vec<_> = adapter.records().cloned().collect();
/// assert_eq!(records[0].name, "libc");
/// ```
#[derive(Debug, Clone)]
pub struct OldExtNameAdapter {
    /// In-memory representation of the legacy table rows, keyed by row id.
    records: BTreeMap<i64, ExtNameRecord>,
}

impl OldExtNameAdapter {
    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    /// Create an empty adapter (no legacy table present).
    pub fn new() -> Self {
        Self {
            records: BTreeMap::new(),
        }
    }

    /// Attempt to open an adapter from the given table data.
    ///
    /// Returns [`OldAdapterError::MissingTable`] if the table is absent,
    /// or [`OldAdapterError::NewerVersion`] if the schema version is
    /// greater than 0.
    pub fn open(
        table_name: &str,
        schema_version: u32,
    ) -> Result<Self, OldAdapterError> {
        if table_name != EXT_NAME_TABLE_NAME {
            return Err(OldAdapterError::MissingTable(table_name.to_string()));
        }
        if schema_version != 0 {
            return Err(OldAdapterError::NewerVersion);
        }
        Ok(Self::new())
    }

    // ------------------------------------------------------------------
    // Record access
    // ------------------------------------------------------------------

    /// Add a record to the adapter (used during table loading or testing).
    pub fn add_record(&mut self, key: i64, name: impl Into<String>, pathname: impl Into<String>) {
        self.records.insert(
            key,
            ExtNameRecord {
                key,
                name: name.into(),
                pathname: pathname.into(),
            },
        );
    }

    /// Returns the total number of records.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Returns an iterator over all records, ordered by key.
    pub fn records(&self) -> impl Iterator<Item = &ExtNameRecord> {
        self.records.values()
    }

    /// Returns `true` if the adapter has no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Look up a record by key.
    pub fn get(&self, key: i64) -> Option<&ExtNameRecord> {
        self.records.get(&key)
    }

    /// Get the external name for a given key.
    pub fn get_name(&self, key: i64) -> Option<&str> {
        self.records.get(&key).map(|r| r.name.as_str())
    }

    /// Get the external pathname for a given key.
    pub fn get_pathname(&self, key: i64) -> Option<&str> {
        self.records.get(&key).map(|r| r.pathname.as_str())
    }

    // ------------------------------------------------------------------
    // Migration
    // ------------------------------------------------------------------

    /// Simulate the table move operation that Ghidra performs during
    /// upgrade.  This consumes the adapter and returns the records in
    /// key order, ready to be inserted into the new storage.
    pub fn into_records(self) -> Vec<ExtNameRecord> {
        self.records.into_values().collect()
    }

    /// Build a name map (key -> name) for use by the reference adapter
    /// during upgrade.
    pub fn name_map(&self) -> BTreeMap<i64, String> {
        self.records
            .values()
            .map(|r| (r.key, r.name.clone()))
            .collect()
    }
}

impl Default for OldExtNameAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_adapter() {
        let adapter = OldExtNameAdapter::new();
        assert_eq!(adapter.record_count(), 0);
        assert!(adapter.is_empty());
    }

    #[test]
    fn test_add_and_get_records() {
        let mut adapter = OldExtNameAdapter::new();
        adapter.add_record(1, "libc", "/usr/lib/libc.so");
        adapter.add_record(2, "libm", "/usr/lib/libm.so");
        adapter.add_record(3, "libdl", "");

        assert_eq!(adapter.record_count(), 3);
        assert!(!adapter.is_empty());

        assert_eq!(adapter.get_name(1), Some("libc"));
        assert_eq!(adapter.get_pathname(1), Some("/usr/lib/libc.so"));

        assert_eq!(adapter.get_name(2), Some("libm"));
        assert_eq!(adapter.get_pathname(3), Some(""));
        assert_eq!(adapter.get_name(99), None);
    }

    #[test]
    fn test_open_valid() {
        let adapter = OldExtNameAdapter::open(EXT_NAME_TABLE_NAME, 0);
        assert!(adapter.is_ok());
    }

    #[test]
    fn test_open_wrong_table() {
        let err = OldExtNameAdapter::open("Wrong Table", 0);
        assert!(matches!(
            err,
            Err(OldAdapterError::MissingTable(ref s)) if s == "Wrong Table"
        ));
    }

    #[test]
    fn test_open_newer_version() {
        let err = OldExtNameAdapter::open(EXT_NAME_TABLE_NAME, 1);
        assert!(matches!(err, Err(OldAdapterError::NewerVersion)));
    }

    #[test]
    fn test_records_iterator() {
        let mut adapter = OldExtNameAdapter::new();
        adapter.add_record(10, "aaa", "path_a");
        adapter.add_record(5, "bbb", "path_b");

        let names: Vec<_> = adapter.records().map(|r| r.name.as_str()).collect();
        // BTreeMap iterates in key order
        assert_eq!(names, vec!["bbb", "aaa"]);
    }

    #[test]
    fn test_name_map() {
        let mut adapter = OldExtNameAdapter::new();
        adapter.add_record(1, "libc", "/usr/lib/libc.so");
        adapter.add_record(2, "libm", "");

        let map = adapter.name_map();
        assert_eq!(map.get(&1), Some(&"libc".to_string()));
        assert_eq!(map.get(&2), Some(&"libm".to_string()));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_into_records() {
        let mut adapter = OldExtNameAdapter::new();
        adapter.add_record(1, "libc", "/usr/lib/libc.so");
        adapter.add_record(2, "libm", "");

        let records = adapter.into_records();
        assert_eq!(records.len(), 2);
        // Records come out in key order
        assert_eq!(records[0].key, 1);
        assert_eq!(records[0].name, "libc");
        assert_eq!(records[1].key, 2);
        assert_eq!(records[1].name, "libm");
    }

    #[test]
    fn test_record_equality() {
        let r1 = ExtNameRecord {
            key: 1,
            name: "libc".into(),
            pathname: "/usr/lib".into(),
        };
        let r2 = ExtNameRecord {
            key: 1,
            name: "libc".into(),
            pathname: "/usr/lib".into(),
        };
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_error_display() {
        let e = OldAdapterError::MissingTable("test".into());
        assert!(e.to_string().contains("test"));

        let e = OldAdapterError::NewerVersion;
        assert!(e.to_string().contains("Newer"));

        let e = OldAdapterError::UpgradeRequired;
        assert!(e.to_string().contains("upgrade"));

        let e = OldAdapterError::Other("details".into());
        assert!(e.to_string().contains("details"));
    }
}
