//! TraceDynamicTable -- snap-indexed dynamic key-value tables for traces.
//!
//! Ported from Ghidra's `ghidra.trace.model.TraceDynamicTable` and the
//! `DBTracePropertyMap` / `DBTraceObjectValue` database implementations.
//!
//! This module provides a flexible, schema-optional table that stores
//! typed values keyed by (snap, string-key) pairs. It supports
//! temporal queries (value at a given snap), range queries, and
//! schema evolution (adding/removing columns over time). Each table
//! is associated with a path prefix (e.g., a process or thread object)
//! and can hold heterogeneous value types.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

// ---------------------------------------------------------------------------
// DynamicValue
// ---------------------------------------------------------------------------

/// A typed value stored in a dynamic table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DynamicValue {
    /// A boolean value.
    Bool(bool),
    /// A signed 64-bit integer.
    I64(i64),
    /// An unsigned 64-bit integer.
    U64(u64),
    /// A 64-bit floating point value.
    F64(f64),
    /// A UTF-8 string.
    String(String),
    /// A byte vector.
    Bytes(Vec<u8>),
    /// A null / absent value.
    Null,
}

impl fmt::Display for DynamicValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(v) => write!(f, "{v}"),
            Self::I64(v) => write!(f, "{v}"),
            Self::U64(v) => write!(f, "{v}"),
            Self::F64(v) => write!(f, "{v}"),
            Self::String(v) => write!(f, "{v}"),
            Self::Bytes(v) => write!(f, "<{} bytes>", v.len()),
            Self::Null => write!(f, "null"),
        }
    }
}

impl DynamicValue {
    /// Whether this is a null value.
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Try to interpret as a bool.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to interpret as i64.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::I64(v) => Some(*v),
            Self::U64(v) => i64::try_from(*v).ok(),
            _ => None,
        }
    }

    /// Try to interpret as u64.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::U64(v) => Some(*v),
            Self::I64(v) => u64::try_from(*v).ok(),
            _ => None,
        }
    }

    /// Try to interpret as f64.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::F64(v) => Some(*v),
            Self::I64(v) => Some(*v as f64),
            Self::U64(v) => Some(*v as f64),
            _ => None,
        }
    }

    /// Try to interpret as a string slice.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(v) => Some(v.as_str()),
            _ => None,
        }
    }

    /// Try to interpret as bytes.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(v) => Some(v.as_slice()),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// ColumnSchema
// ---------------------------------------------------------------------------

/// Schema definition for a column in a dynamic table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnSchema {
    /// Column name (key).
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Whether this column is required.
    pub required: bool,
    /// The snap at which this column was introduced.
    pub introduced_snap: i64,
    /// The snap at which this column was removed, if applicable.
    pub removed_snap: Option<i64>,
}

impl ColumnSchema {
    /// Create a new column schema.
    pub fn new(name: impl Into<String>, snap: i64) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            required: false,
            introduced_snap: snap,
            removed_snap: None,
        }
    }

    /// Set a description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Mark as required.
    pub fn with_required(mut self, required: bool) -> Self {
        self.required = required;
        self
    }

    /// Mark as removed at a given snap.
    pub fn with_removed_at(mut self, snap: i64) -> Self {
        self.removed_snap = Some(snap);
        self
    }

    /// Whether this column is active at the given snap.
    pub fn is_active_at(&self, snap: i64) -> bool {
        snap >= self.introduced_snap
            && self
                .removed_snap
                .map_or(true, |removed| snap < removed)
    }
}

// ---------------------------------------------------------------------------
// DynamicRow
// ---------------------------------------------------------------------------

/// A single row in the dynamic table, holding values for multiple columns
/// at a specific snap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicRow {
    /// The snap at which this row was written.
    pub snap: i64,
    /// Column values for this row.
    pub values: BTreeMap<String, DynamicValue>,
}

impl DynamicRow {
    /// Create a new empty row.
    pub fn new(snap: i64) -> Self {
        Self {
            snap,
            values: BTreeMap::new(),
        }
    }

    /// Set a value.
    pub fn set(&mut self, key: impl Into<String>, value: DynamicValue) {
        self.values.insert(key.into(), value);
    }

    /// Get a value.
    pub fn get(&self, key: &str) -> Option<&DynamicValue> {
        self.values.get(key)
    }

    /// The number of values in this row.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether the row has no values.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

// ---------------------------------------------------------------------------
// DynamicTableEntry
// ---------------------------------------------------------------------------

/// A dynamic table entry that stores temporal key-value data.
///
/// Ported from Ghidra's trace property maps and dynamic object values.
/// Each table is identified by a path prefix and manages rows indexed
/// by snap, with optional schema tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicTableEntry {
    /// The path this table is associated with (e.g., "Processes[0]").
    pub path: String,
    /// Human-readable table name.
    pub name: String,
    /// Column schema definitions.
    columns: BTreeMap<String, ColumnSchema>,
    /// Rows indexed by snap.
    rows: BTreeMap<i64, DynamicRow>,
}

impl DynamicTableEntry {
    /// Create a new dynamic table.
    pub fn new(path: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            name: name.into(),
            columns: BTreeMap::new(),
            rows: BTreeMap::new(),
        }
    }

    // -- Schema --

    /// Define a new column.
    pub fn add_column(&mut self, col: ColumnSchema) {
        self.columns.insert(col.name.clone(), col);
    }

    /// Remove a column definition (marks as removed at `snap`).
    pub fn remove_column(&mut self, name: &str, snap: i64) {
        if let Some(col) = self.columns.get_mut(name) {
            col.removed_snap = Some(snap);
        }
    }

    /// Get a column schema by name.
    pub fn column(&self, name: &str) -> Option<&ColumnSchema> {
        self.columns.get(name)
    }

    /// All column names active at `snap`.
    pub fn active_columns_at(&self, snap: i64) -> Vec<&str> {
        self.columns
            .values()
            .filter(|c| c.is_active_at(snap))
            .map(|c| c.name.as_str())
            .collect()
    }

    /// The total number of columns (including removed).
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    // -- Data --

    /// Set a value at a given snap.
    pub fn set(&mut self, snap: i64, key: impl Into<String>, value: DynamicValue) {
        let row = self.rows.entry(snap).or_insert_with(|| DynamicRow::new(snap));
        row.set(key, value);
    }

    /// Get the value for a key at the given snap (exact match).
    pub fn get_exact(&self, snap: i64, key: &str) -> Option<&DynamicValue> {
        self.rows.get(&snap).and_then(|r| r.get(key))
    }

    /// Get the value for a key at or before the given snap (temporal lookup).
    pub fn get_at(&self, snap: i64, key: &str) -> Option<&DynamicValue> {
        self.rows
            .range(..=snap)
            .rev()
            .find_map(|(_, row)| row.get(key))
    }

    /// Get the entire row at the given snap.
    pub fn row_at(&self, snap: i64) -> Option<&DynamicRow> {
        self.rows.get(&snap)
    }

    /// Get the snap at which a key was last set at or before `snap`.
    pub fn snap_of(&self, snap: i64, key: &str) -> Option<i64> {
        self.rows
            .range(..=snap)
            .rev()
            .find(|(_, row)| row.values.contains_key(key))
            .map(|(&s, _)| s)
    }

    /// Remove a key at a specific snap (sets it to Null).
    pub fn remove(&mut self, snap: i64, key: &str) {
        let row = self.rows.entry(snap).or_insert_with(|| DynamicRow::new(snap));
        row.set(key, DynamicValue::Null);
    }

    /// The number of rows (distinct snaps with data).
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// All snaps that have data.
    pub fn snaps(&self) -> Vec<i64> {
        self.rows.keys().copied().collect()
    }

    /// All rows.
    pub fn rows(&self) -> &BTreeMap<i64, DynamicRow> {
        &self.rows
    }

    /// Get all values for a key across all snaps.
    pub fn history_of(&self, key: &str) -> Vec<(i64, &DynamicValue)> {
        self.rows
            .iter()
            .filter_map(|(&snap, row)| row.get(key).map(|v| (snap, v)))
            .collect()
    }

    /// Clear all data.
    pub fn clear(&mut self) {
        self.rows.clear();
    }

    /// Clear data in the given lifespan range.
    pub fn clear_range(&mut self, span: &Lifespan) {
        let keys: Vec<i64> = self
            .rows
            .range(span.lmin()..=span.lmax())
            .map(|(&k, _)| k)
            .collect();
        for k in keys {
            self.rows.remove(&k);
        }
    }
}

// ---------------------------------------------------------------------------
// TraceDynamicTableManager
// ---------------------------------------------------------------------------

/// Manages multiple dynamic tables for a trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceDynamicTableManager {
    /// Tables indexed by path.
    tables: BTreeMap<String, DynamicTableEntry>,
}

impl TraceDynamicTableManager {
    /// Create a new manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create a table for the given path.
    pub fn get_or_create(&mut self, path: &str, name: &str) -> &mut DynamicTableEntry {
        self.tables
            .entry(path.to_string())
            .or_insert_with(|| DynamicTableEntry::new(path, name))
    }

    /// Get a table by path.
    pub fn table(&self, path: &str) -> Option<&DynamicTableEntry> {
        self.tables.get(path)
    }

    /// Get a mutable table by path.
    pub fn table_mut(&mut self, path: &str) -> Option<&mut DynamicTableEntry> {
        self.tables.get_mut(path)
    }

    /// Remove a table.
    pub fn remove_table(&mut self, path: &str) -> Option<DynamicTableEntry> {
        self.tables.remove(path)
    }

    /// The number of tables.
    pub fn table_count(&self) -> usize {
        self.tables.len()
    }

    /// All table paths.
    pub fn table_paths(&self) -> Vec<&str> {
        self.tables.keys().map(|s| s.as_str()).collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynamic_value_display() {
        assert_eq!(DynamicValue::Bool(true).to_string(), "true");
        assert_eq!(DynamicValue::I64(-42).to_string(), "-42");
        assert_eq!(DynamicValue::U64(0xFF).to_string(), "255");
        assert_eq!(DynamicValue::String("hi".into()).to_string(), "hi");
        assert_eq!(DynamicValue::Null.to_string(), "null");
        assert_eq!(DynamicValue::Bytes(vec![1, 2, 3]).to_string(), "<3 bytes>");
    }

    #[test]
    fn test_dynamic_value_conversions() {
        let b = DynamicValue::Bool(true);
        assert_eq!(b.as_bool(), Some(true));
        assert!(b.as_i64().is_none());

        let i = DynamicValue::I64(-5);
        assert_eq!(i.as_i64(), Some(-5));
        assert!(i.as_u64().is_none()); // negative

        let u = DynamicValue::U64(42);
        assert_eq!(u.as_u64(), Some(42));
        assert_eq!(u.as_i64(), Some(42));

        let f = DynamicValue::F64(3.14);
        assert!(f.as_f64().is_some());

        let s = DynamicValue::String("hello".into());
        assert_eq!(s.as_str(), Some("hello"));

        let bytes = DynamicValue::Bytes(vec![1, 2]);
        assert_eq!(bytes.as_bytes(), Some([1u8, 2u8].as_slice()));

        assert!(DynamicValue::Null.is_null());
    }

    #[test]
    fn test_column_schema_active() {
        let col = ColumnSchema::new("status", 0)
            .with_description("execution status")
            .with_required(true);

        assert!(col.is_active_at(0));
        assert!(col.is_active_at(100));

        let removed = col.clone().with_removed_at(50);
        assert!(removed.is_active_at(49));
        assert!(!removed.is_active_at(50));
        assert!(!removed.is_active_at(100));
    }

    #[test]
    fn test_dynamic_row() {
        let mut row = DynamicRow::new(5);
        assert!(row.is_empty());

        row.set("pc", DynamicValue::U64(0x401000));
        row.set("sp", DynamicValue::U64(0x7FFF0000));
        row.set("running", DynamicValue::Bool(true));

        assert_eq!(row.len(), 3);
        assert_eq!(row.get("pc").unwrap().as_u64(), Some(0x401000));
        assert!(row.get("missing").is_none());
    }

    #[test]
    fn test_dynamic_table_set_get() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.set(0, "pc", DynamicValue::U64(0x401000));
        table.set(0, "sp", DynamicValue::U64(0x7FFF0000));
        table.set(5, "pc", DynamicValue::U64(0x402000));

        assert_eq!(table.get_exact(0, "pc").unwrap().as_u64(), Some(0x401000));
        assert_eq!(table.get_exact(5, "pc").unwrap().as_u64(), Some(0x402000));
        assert!(table.get_exact(3, "pc").is_none()); // exact miss

        // Temporal lookup
        assert_eq!(table.get_at(3, "pc").unwrap().as_u64(), Some(0x401000));
        assert_eq!(table.get_at(5, "pc").unwrap().as_u64(), Some(0x402000));
        assert_eq!(table.get_at(100, "pc").unwrap().as_u64(), Some(0x402000));
    }

    #[test]
    fn test_dynamic_table_snap_of() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.set(0, "pc", DynamicValue::U64(0x401000));
        table.set(5, "pc", DynamicValue::U64(0x402000));

        assert_eq!(table.snap_of(3, "pc"), Some(0));
        assert_eq!(table.snap_of(5, "pc"), Some(5));
        assert_eq!(table.snap_of(100, "pc"), Some(5));
        assert!(table.snap_of(0, "sp").is_none());
    }

    #[test]
    fn test_dynamic_table_remove() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.set(0, "pc", DynamicValue::U64(0x401000));
        table.remove(5, "pc");

        assert_eq!(table.get_exact(5, "pc").unwrap(), &DynamicValue::Null);
        // Temporal lookup at 100 finds Null from snap 5
        assert_eq!(table.get_at(100, "pc").unwrap(), &DynamicValue::Null);
    }

    #[test]
    fn test_dynamic_table_history() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.set(0, "pc", DynamicValue::U64(0x401000));
        table.set(5, "pc", DynamicValue::U64(0x402000));
        table.set(10, "pc", DynamicValue::U64(0x403000));

        let history = table.history_of("pc");
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].0, 0);
        assert_eq!(history[1].0, 5);
        assert_eq!(history[2].0, 10);
    }

    #[test]
    fn test_dynamic_table_schema() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.add_column(ColumnSchema::new("pc", 0).with_description("program counter"));
        table.add_column(ColumnSchema::new("sp", 0).with_description("stack pointer"));
        table.add_column(ColumnSchema::new("status", 5).with_description("run status"));

        assert_eq!(table.column_count(), 3);
        assert_eq!(table.active_columns_at(0).len(), 2); // pc, sp
        assert_eq!(table.active_columns_at(5).len(), 3); // pc, sp, status

        table.remove_column("sp", 10);
        assert_eq!(table.active_columns_at(10).len(), 2); // pc, status
        assert_eq!(table.active_columns_at(9).len(), 3);
    }

    #[test]
    fn test_dynamic_table_row_at() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.set(0, "pc", DynamicValue::U64(0x401000));
        table.set(5, "sp", DynamicValue::U64(0x7FFF0000));

        let row = table.row_at(0).unwrap();
        assert_eq!(row.len(), 1);
        assert_eq!(row.snap, 0);

        let row5 = table.row_at(5).unwrap();
        assert_eq!(row5.len(), 1);

        assert!(table.row_at(3).is_none());
    }

    #[test]
    fn test_dynamic_table_clear() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.set(0, "pc", DynamicValue::U64(0x401000));
        table.set(5, "pc", DynamicValue::U64(0x402000));
        table.set(10, "pc", DynamicValue::U64(0x403000));

        assert_eq!(table.row_count(), 3);

        table.clear_range(&Lifespan::span(3, 7));
        assert_eq!(table.row_count(), 2);
        assert!(table.row_at(5).is_none());
        assert!(table.row_at(0).is_some());
        assert!(table.row_at(10).is_some());

        table.clear();
        assert_eq!(table.row_count(), 0);
    }

    #[test]
    fn test_dynamic_table_snaps() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.set(0, "a", DynamicValue::Bool(true));
        table.set(5, "b", DynamicValue::Bool(false));
        table.set(10, "c", DynamicValue::Bool(true));

        assert_eq!(table.snaps(), vec![0, 5, 10]);
    }

    #[test]
    fn test_dynamic_table_manager() {
        let mut mgr = TraceDynamicTableManager::new();
        assert_eq!(mgr.table_count(), 0);

        {
            let t = mgr.get_or_create("P[0]", "state");
            t.set(0, "pc", DynamicValue::U64(0x401000));
        }

        assert_eq!(mgr.table_count(), 1);
        assert!(mgr.table("P[0]").is_some());
        assert!(mgr.table("P[1]").is_none());
        assert_eq!(mgr.table_paths(), vec!["P[0]"]);

        mgr.remove_table("P[0]");
        assert_eq!(mgr.table_count(), 0);
    }

    #[test]
    fn test_dynamic_table_serde() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.set(0, "pc", DynamicValue::U64(0x401000));
        table.add_column(ColumnSchema::new("pc", 0));

        let json = serde_json::to_string(&table).unwrap();
        let back: DynamicTableEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.path, "P[0]");
        assert_eq!(back.get_exact(0, "pc").unwrap().as_u64(), Some(0x401000));
        assert_eq!(back.column_count(), 1);
    }

    #[test]
    fn test_dynamic_table_manager_serde() {
        let mut mgr = TraceDynamicTableManager::new();
        mgr.get_or_create("P[0]", "state")
            .set(0, "pc", DynamicValue::U64(0x401000));

        let json = serde_json::to_string(&mgr).unwrap();
        let back: TraceDynamicTableManager = serde_json::from_str(&json).unwrap();
        assert_eq!(back.table_count(), 1);
    }

    #[test]
    fn test_dynamic_value_f64_conversions() {
        let from_i = DynamicValue::I64(42).as_f64();
        assert_eq!(from_i, Some(42.0));

        let from_u = DynamicValue::U64(100).as_f64();
        assert_eq!(from_u, Some(100.0));
    }

    #[test]
    fn test_dynamic_table_multiple_keys_at_snap() {
        let mut table = DynamicTableEntry::new("P[0]", "regs");
        table.set(0, "RAX", DynamicValue::U64(1));
        table.set(0, "RBX", DynamicValue::U64(2));
        table.set(0, "RCX", DynamicValue::U64(3));

        let row = table.row_at(0).unwrap();
        assert_eq!(row.len(), 3);
        assert_eq!(row.get("RAX").unwrap().as_u64(), Some(1));
        assert_eq!(row.get("RBX").unwrap().as_u64(), Some(2));
        assert_eq!(row.get("RCX").unwrap().as_u64(), Some(3));
    }

    #[test]
    fn test_dynamic_table_empty_get() {
        let table = DynamicTableEntry::new("P[0]", "empty");
        assert!(table.get_at(0, "anything").is_none());
        assert!(table.get_exact(0, "anything").is_none());
        assert!(table.snap_of(0, "anything").is_none());
        assert!(table.row_at(0).is_none());
    }
}
