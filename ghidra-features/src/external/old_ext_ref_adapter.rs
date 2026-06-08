//! OldExtRefAdapter -- legacy external references table adapter.
//!
//! Ported from `ghidra.program.database.external.OldExtRefAdapter`.
//!
//! Handles migration of the old "External References" database table
//! (schema version 0) which stored external reference records linking
//! program addresses to external library symbols.  During an upgrade,
//! records are moved from the old table into the new reference manager.

use std::collections::BTreeMap;
use std::fmt;

/// Column index for the "From Address" field.
pub const FROM_ADDR_COL: usize = 0;

/// Column index for the "Op Index" field.
pub const OP_INDEX_COL: usize = 1;

/// Column index for the "User Defined" field.
pub const USER_DEFINED_COL: usize = 2;

/// Column index for the "External Name ID" field.
pub const EXT_NAME_ID_COL: usize = 3;

/// Column index for the "Label" field.
pub const LABEL_COL: usize = 4;

/// Column index for the "External To" (address) field.
pub const EXT_TO_ADDR_COL: usize = 5;

/// Column index for the "External To Exists" (boolean) field.
pub const EXT_ADDR_EXISTS_COL: usize = 6;

/// The table name used by the legacy schema.
pub const EXT_REF_TABLE_NAME: &str = "External References";

/// Errors that can arise when working with the old external reference adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OldRefAdapterError {
    /// The required table was not found in the database.
    MissingTable(String),
    /// The table version is newer than expected.
    NewerVersion,
    /// The table version is older and requires upgrade.
    UpgradeRequired,
    /// A general I/O or data error.
    Other(String),
}

impl fmt::Display for OldRefAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OldRefAdapterError::MissingTable(name) => {
                write!(f, "Missing table: {}", name)
            }
            OldRefAdapterError::NewerVersion => {
                write!(f, "Newer database version not supported")
            }
            OldRefAdapterError::UpgradeRequired => {
                write!(f, "Database upgrade required")
            }
            OldRefAdapterError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for OldRefAdapterError {}

/// A single record from the old external references table.
///
/// Each record represents a reference from a program address to an
/// external location (identified by library name ID and label).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtRefRecord {
    /// Row key.
    pub key: i64,
    /// The address in the program that references the external symbol.
    pub from_address: u64,
    /// The operand index at the from address.
    pub op_index: i16,
    /// Whether this reference was user-defined.
    pub user_defined: bool,
    /// The key into the external name table (see [`OldExtNameAdapter`]).
    pub ext_name_id: u64,
    /// The label of the external symbol.
    pub label: String,
    /// The address in the external program (if known).
    pub ext_to_address: Option<u64>,
}

/// Adapter for reading and migrating the legacy "External References"
/// table.
///
/// # Schema (version 0)
///
/// | Column | Type    | Description          |
/// |--------|---------|----------------------|
/// | 0      | Long    | From Address         |
/// | 1      | Short   | Op Index             |
/// | 2      | Boolean | User Defined         |
/// | 3      | Long    | External Name ID     |
/// | 4      | String  | Label                |
/// | 5      | Long    | External To          |
/// | 6      | Boolean | External To Exists   |
///
/// The primary key column is labelled `"Key"`.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::old_ext_ref_adapter::*;
///
/// let mut adapter = OldExtRefAdapter::new();
/// adapter.add_record(
///     1,
///     0x00401000,
///     0,
///     false,
///     42,
///     "printf",
///     Some(0x1000),
/// );
///
/// assert_eq!(adapter.record_count(), 1);
/// let rec = adapter.get(1).unwrap();
/// assert_eq!(rec.label, "printf");
/// ```
#[derive(Debug, Clone)]
pub struct OldExtRefAdapter {
    /// In-memory representation of the legacy table rows, keyed by row id.
    records: BTreeMap<i64, ExtRefRecord>,
}

impl OldExtRefAdapter {
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
    /// Returns [`OldRefAdapterError::MissingTable`] if the table is absent,
    /// or [`OldRefAdapterError::NewerVersion`] if the schema version is
    /// greater than 0.
    pub fn open(
        table_name: &str,
        schema_version: u32,
    ) -> Result<Self, OldRefAdapterError> {
        if table_name != EXT_REF_TABLE_NAME {
            return Err(OldRefAdapterError::MissingTable(table_name.to_string()));
        }
        if schema_version != 0 {
            return Err(OldRefAdapterError::NewerVersion);
        }
        Ok(Self::new())
    }

    // ------------------------------------------------------------------
    // Record access
    // ------------------------------------------------------------------

    /// Add a record to the adapter.
    #[allow(clippy::too_many_arguments)]
    pub fn add_record(
        &mut self,
        key: i64,
        from_address: u64,
        op_index: i16,
        user_defined: bool,
        ext_name_id: u64,
        label: impl Into<String>,
        ext_to_address: Option<u64>,
    ) {
        self.records.insert(
            key,
            ExtRefRecord {
                key,
                from_address,
                op_index,
                user_defined,
                ext_name_id,
                label: label.into(),
                ext_to_address,
            },
        );
    }

    /// Returns the total number of records.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Returns an iterator over all records, ordered by key.
    pub fn records(&self) -> impl Iterator<Item = &ExtRefRecord> {
        self.records.values()
    }

    /// Returns `true` if the adapter has no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Look up a record by key.
    pub fn get(&self, key: i64) -> Option<&ExtRefRecord> {
        self.records.get(&key)
    }

    // ------------------------------------------------------------------
    // Migration
    // ------------------------------------------------------------------

    /// Consume the adapter and return all records in key order.
    pub fn into_records(self) -> Vec<ExtRefRecord> {
        self.records.into_values().collect()
    }
}

impl Default for OldExtRefAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_adapter() {
        let adapter = OldExtRefAdapter::new();
        assert_eq!(adapter.record_count(), 0);
        assert!(adapter.is_empty());
    }

    #[test]
    fn test_add_and_get_records() {
        let mut adapter = OldExtRefAdapter::new();
        adapter.add_record(1, 0x00401000, 0, false, 42, "printf", Some(0x1000));
        adapter.add_record(2, 0x00401010, 1, true, 43, "malloc", None);
        adapter.add_record(3, 0x00401020, 0, false, 42, "puts", Some(0x2000));

        assert_eq!(adapter.record_count(), 3);
        assert!(!adapter.is_empty());

        let rec = adapter.get(1).unwrap();
        assert_eq!(rec.from_address, 0x00401000);
        assert_eq!(rec.op_index, 0);
        assert!(!rec.user_defined);
        assert_eq!(rec.ext_name_id, 42);
        assert_eq!(rec.label, "printf");
        assert_eq!(rec.ext_to_address, Some(0x1000));

        let rec2 = adapter.get(2).unwrap();
        assert!(rec2.user_defined);
        assert_eq!(rec2.ext_to_address, None);

        assert!(adapter.get(99).is_none());
    }

    #[test]
    fn test_open_valid() {
        let adapter = OldExtRefAdapter::open(EXT_REF_TABLE_NAME, 0);
        assert!(adapter.is_ok());
    }

    #[test]
    fn test_open_wrong_table() {
        let err = OldExtRefAdapter::open("Wrong Table", 0);
        assert!(matches!(
            err,
            Err(OldRefAdapterError::MissingTable(ref s)) if s == "Wrong Table"
        ));
    }

    #[test]
    fn test_open_newer_version() {
        let err = OldExtRefAdapter::open(EXT_REF_TABLE_NAME, 1);
        assert!(matches!(err, Err(OldRefAdapterError::NewerVersion)));
    }

    #[test]
    fn test_records_iterator() {
        let mut adapter = OldExtRefAdapter::new();
        adapter.add_record(10, 0x1000, 0, false, 1, "aaa", None);
        adapter.add_record(5, 0x2000, 0, false, 2, "bbb", None);

        let labels: Vec<_> = adapter.records().map(|r| r.label.as_str()).collect();
        // BTreeMap iterates in key order
        assert_eq!(labels, vec!["bbb", "aaa"]);
    }

    #[test]
    fn test_into_records() {
        let mut adapter = OldExtRefAdapter::new();
        adapter.add_record(1, 0x401000, 0, false, 42, "printf", Some(0x1000));
        adapter.add_record(2, 0x401010, 0, false, 43, "malloc", None);

        let records = adapter.into_records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].key, 1);
        assert_eq!(records[0].label, "printf");
        assert_eq!(records[1].key, 2);
        assert_eq!(records[1].label, "malloc");
    }

    #[test]
    fn test_record_equality() {
        let r1 = ExtRefRecord {
            key: 1,
            from_address: 0x1000,
            op_index: 0,
            user_defined: false,
            ext_name_id: 42,
            label: "printf".into(),
            ext_to_address: Some(0x2000),
        };
        let r2 = ExtRefRecord {
            key: 1,
            from_address: 0x1000,
            op_index: 0,
            user_defined: false,
            ext_name_id: 42,
            label: "printf".into(),
            ext_to_address: Some(0x2000),
        };
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_record_not_equal() {
        let r1 = ExtRefRecord {
            key: 1,
            from_address: 0x1000,
            op_index: 0,
            user_defined: false,
            ext_name_id: 42,
            label: "printf".into(),
            ext_to_address: Some(0x2000),
        };
        let r2 = ExtRefRecord {
            key: 1,
            from_address: 0x1000,
            op_index: 0,
            user_defined: false,
            ext_name_id: 42,
            label: "puts".into(),
            ext_to_address: Some(0x2000),
        };
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_error_display() {
        let e = OldRefAdapterError::MissingTable("test".into());
        assert!(e.to_string().contains("test"));

        let e = OldRefAdapterError::NewerVersion;
        assert!(e.to_string().contains("Newer"));

        let e = OldRefAdapterError::UpgradeRequired;
        assert!(e.to_string().contains("upgrade"));

        let e = OldRefAdapterError::Other("details".into());
        assert!(e.to_string().contains("details"));
    }

    #[test]
    fn test_ext_to_address_none() {
        let mut adapter = OldExtRefAdapter::new();
        adapter.add_record(1, 0x1000, 0, true, 10, "unknown", None);

        let rec = adapter.get(1).unwrap();
        assert!(rec.ext_to_address.is_none());
    }

    #[test]
    fn test_multiple_references_same_library() {
        let mut adapter = OldExtRefAdapter::new();
        adapter.add_record(1, 0x1000, 0, false, 42, "printf", Some(0x1000));
        adapter.add_record(2, 0x1010, 0, false, 42, "puts", Some(0x2000));
        adapter.add_record(3, 0x1020, 0, false, 42, "malloc", Some(0x3000));

        // All point to the same library (ext_name_id = 42)
        let same_lib: Vec<_> = adapter
            .records()
            .filter(|r| r.ext_name_id == 42)
            .collect();
        assert_eq!(same_lib.len(), 3);
    }
}
