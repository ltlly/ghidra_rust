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
//!
//! New in this update: `DynamicTableSnapshot` for point-in-time views,
//! `DynamicTableDiff` for comparing snaps, batch operations via
//! `DynamicTableBatch`, range-based queries (`values_in_range`),
//! `DynamicValue` arithmetic (`add`, `subtract`), column type
//! validation (`ColumnType`), table merge/union, iterators for
//! rows and entries, and `MutableDynamicRow` for scoped mutations.

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

    /// Whether this value is numeric (I64, U64, or F64).
    pub fn is_numeric(&self) -> bool {
        matches!(self, Self::I64(_) | Self::U64(_) | Self::F64(_))
    }

    /// Try to add two dynamic values (both must be numeric).
    pub fn add(&self, other: &DynamicValue) -> Option<DynamicValue> {
        match (self, other) {
            (Self::I64(a), Self::I64(b)) => Some(Self::I64(a.wrapping_add(*b))),
            (Self::U64(a), Self::U64(b)) => Some(Self::U64(a.wrapping_add(*b))),
            (Self::F64(a), Self::F64(b)) => Some(Self::F64(a + b)),
            (Self::I64(a), Self::U64(b)) => i64::try_from(*b)
                .ok()
                .map(|b| Self::I64(a.wrapping_add(b))),
            (Self::U64(a), Self::I64(b)) => u64::try_from(*b)
                .ok()
                .map(|b| Self::U64(a.wrapping_add(b))),
            _ => None,
        }
    }

    /// Try to subtract two dynamic values (both must be numeric).
    pub fn subtract(&self, other: &DynamicValue) -> Option<DynamicValue> {
        match (self, other) {
            (Self::I64(a), Self::I64(b)) => Some(Self::I64(a.wrapping_sub(*b))),
            (Self::U64(a), Self::U64(b)) => Some(Self::U64(a.wrapping_sub(*b))),
            (Self::F64(a), Self::F64(b)) => Some(Self::F64(a - b)),
            (Self::I64(a), Self::U64(b)) => i64::try_from(*b)
                .ok()
                .map(|b| Self::I64(a.wrapping_sub(b))),
            (Self::U64(a), Self::I64(b)) => u64::try_from(*b)
                .ok()
                .map(|b| Self::U64(a.wrapping_sub(b))),
            _ => None,
        }
    }

    /// The type discriminant as a string.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Bool(_) => "Bool",
            Self::I64(_) => "I64",
            Self::U64(_) => "U64",
            Self::F64(_) => "F64",
            Self::String(_) => "String",
            Self::Bytes(_) => "Bytes",
            Self::Null => "Null",
        }
    }
}

// ---------------------------------------------------------------------------
// ColumnType -- typed column validation
// ---------------------------------------------------------------------------

/// The expected type for a column's values.
///
/// Ported from Ghidra's typed property map schema where columns can be
/// constrained to specific value types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ColumnType {
    /// Any value type is allowed.
    Any,
    /// Only boolean values.
    Bool,
    /// Only integer values (I64 or U64).
    Integer,
    /// Only floating-point values.
    Float,
    /// Only string values.
    String,
    /// Only byte vectors.
    Bytes,
}

impl ColumnType {
    /// Check whether a value matches this column type.
    pub fn matches(&self, value: &DynamicValue) -> bool {
        match self {
            Self::Any => true,
            Self::Bool => matches!(value, DynamicValue::Bool(_)),
            Self::Integer => matches!(value, DynamicValue::I64(_) | DynamicValue::U64(_)),
            Self::Float => matches!(value, DynamicValue::F64(_)),
            Self::String => matches!(value, DynamicValue::String(_)),
            Self::Bytes => matches!(value, DynamicValue::Bytes(_)),
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
    /// The expected value type for this column.
    pub column_type: ColumnType,
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
            column_type: ColumnType::Any,
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

    /// Set the expected column type.
    pub fn with_type(mut self, column_type: ColumnType) -> Self {
        self.column_type = column_type;
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

    /// Validate a value against this column's type constraint.
    pub fn validate(&self, value: &DynamicValue) -> bool {
        self.column_type.matches(value)
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

    /// Iterate over key-value pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &DynamicValue)> {
        self.values.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Merge another row into this one (other's values overwrite on conflict).
    pub fn merge_from(&mut self, other: &DynamicRow) {
        for (k, v) in &other.values {
            self.values.insert(k.clone(), v.clone());
        }
    }

    /// All keys present in this row.
    pub fn keys(&self) -> Vec<&str> {
        self.values.keys().map(|s| s.as_str()).collect()
    }
}

// ---------------------------------------------------------------------------
// MutableDynamicRow -- scoped mutable access
// ---------------------------------------------------------------------------

/// A mutable reference to a row within a dynamic table entry, providing
/// convenient builder-style mutations that auto-commit on drop.
///
/// Created by [`DynamicTableEntry::row_mut_at`].
pub struct MutableDynamicRow<'a> {
    row: &'a mut DynamicRow,
    changed: bool,
}

impl<'a> MutableDynamicRow<'a> {
    /// Set a value, marking the row as changed.
    pub fn set(&mut self, key: impl Into<String>, value: DynamicValue) -> &mut Self {
        self.row.set(key, value);
        self.changed = true;
        self
    }

    /// Remove a value by key.
    pub fn remove(&mut self, key: &str) -> Option<DynamicValue> {
        let old = self.row.values.remove(key);
        if old.is_some() {
            self.changed = true;
        }
        old
    }

    /// Get a value by key.
    pub fn get(&self, key: &str) -> Option<&DynamicValue> {
        self.row.get(key)
    }

    /// The number of values.
    pub fn len(&self) -> usize {
        self.row.len()
    }

    /// Whether this row is empty.
    pub fn is_empty(&self) -> bool {
        self.row.is_empty()
    }

    /// Whether any mutations were made.
    pub fn is_changed(&self) -> bool {
        self.changed
    }

    /// Consume this wrapper and return whether it was changed.
    pub fn into_changed(self) -> bool {
        self.changed
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

    /// Set a value at a given snap. Returns whether the value was accepted
    /// by the column's type constraint (if a schema is defined).
    pub fn set(&mut self, snap: i64, key: impl Into<String>, value: DynamicValue) -> bool {
        let key_str = key.into();
        if let Some(col) = self.columns.get(&key_str) {
            if !col.validate(&value) {
                return false;
            }
        }
        let row = self.rows.entry(snap).or_insert_with(|| DynamicRow::new(snap));
        row.set(key_str, value);
        true
    }

    /// Set a value unconditionally, bypassing column type validation.
    pub fn set_unchecked(&mut self, snap: i64, key: impl Into<String>, value: DynamicValue) {
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

    /// Get mutable access to a row at a specific snap, creating it if needed.
    pub fn row_mut_at(&mut self, snap: i64) -> MutableDynamicRow<'_> {
        let row = self.rows.entry(snap).or_insert_with(|| DynamicRow::new(snap));
        MutableDynamicRow {
            row,
            changed: false,
        }
    }

    /// Get all values for a key across all snaps.
    pub fn history_of(&self, key: &str) -> Vec<(i64, &DynamicValue)> {
        self.rows
            .iter()
            .filter_map(|(&snap, row)| row.get(key).map(|v| (snap, v)))
            .collect()
    }

    /// Get the value for a key across a range of snaps.
    pub fn values_in_range(&self, key: &str, span: &Lifespan) -> Vec<(i64, &DynamicValue)> {
        self.rows
            .range(span.lmin()..=span.lmax())
            .filter_map(|(&snap, row)| row.get(key).map(|v| (snap, v)))
            .collect()
    }

    /// Get the value for a key at the first snap in the given range.
    pub fn first_value_in(&self, key: &str, span: &Lifespan) -> Option<(i64, &DynamicValue)> {
        self.rows
            .range(span.lmin()..=span.lmax())
            .find_map(|(&snap, row)| row.get(key).map(|v| (snap, v)))
    }

    /// Get the value for a key at the last snap in the given range.
    pub fn last_value_in(&self, key: &str, span: &Lifespan) -> Option<(i64, &DynamicValue)> {
        self.rows
            .range(span.lmin()..=span.lmax())
            .rev()
            .find_map(|(&snap, row)| row.get(key).map(|v| (snap, v)))
    }

    /// Create a snapshot of all values at a given snap (temporal lookup for all keys).
    pub fn snapshot_at(&self, snap: i64) -> BTreeMap<String, &DynamicValue> {
        let mut result = BTreeMap::new();
        // Collect all keys that have ever been set
        for row in self.rows.values() {
            for key in row.values.keys() {
                result.entry(key.clone());
            }
        }
        // Fill in values at the given snap
        for key in result.keys().cloned().collect::<Vec<_>>() {
            if let Some(val) = self.get_at(snap, &key) {
                result.insert(key, val);
            }
        }
        result
    }

    /// Compute a diff between two snaps for a specific key.
    /// Returns (old_value, new_value) if the value changed.
    pub fn diff_key(&self, key: &str, snap_a: i64, snap_b: i64) -> Option<(Option<&DynamicValue>, Option<&DynamicValue>)> {
        let old = self.get_at(snap_a, key);
        let new = self.get_at(snap_b, key);
        match (old, new) {
            (None, None) => None,
            (Some(a), Some(b)) if a == b => None,
            _ => Some((old, new)),
        }
    }

    /// Count the number of non-null values across all rows.
    pub fn count_non_null(&self) -> usize {
        self.rows
            .values()
            .flat_map(|row| row.values.values())
            .filter(|v| !v.is_null())
            .count()
    }

    /// Find all keys that have a value at the given snap.
    pub fn keys_at(&self, snap: i64) -> Vec<&str> {
        self.rows
            .get(&snap)
            .map(|r| r.keys())
            .unwrap_or_default()
    }

    /// Find all keys that have ever been set in this table.
    pub fn all_keys(&self) -> Vec<String> {
        let mut keys: BTreeMap<String, ()> = BTreeMap::new();
        for row in self.rows.values() {
            for k in row.values.keys() {
                keys.insert(k.clone(), ());
            }
        }
        keys.into_keys().collect()
    }

    /// Merge another table's data into this one.
    /// Values from `other` overwrite on conflict at the same (snap, key).
    pub fn merge_from(&mut self, other: &DynamicTableEntry) {
        for (snap, row) in &other.rows {
            let dest_row = self.rows.entry(*snap).or_insert_with(|| DynamicRow::new(*snap));
            dest_row.merge_from(row);
        }
        // Merge column schemas
        for (name, col) in &other.columns {
            if !self.columns.contains_key(name) {
                self.columns.insert(name.clone(), col.clone());
            }
        }
    }

    /// Collect all rows into a vector sorted by snap.
    pub fn rows_vec(&self) -> Vec<(i64, &DynamicRow)> {
        self.rows.iter().map(|(&s, r)| (s, r)).collect()
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

    /// Find all tables whose path starts with the given prefix.
    pub fn tables_for_path_prefix(&self, prefix: &str) -> Vec<&DynamicTableEntry> {
        self.tables
            .range(prefix.to_string()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(_, v)| v)
            .collect()
    }

    /// Merge another manager's tables into this one.
    pub fn merge_from(&mut self, other: &TraceDynamicTableManager) {
        for (path, table) in &other.tables {
            let dest = self
                .tables
                .entry(path.clone())
                .or_insert_with(|| DynamicTableEntry::new(path, &table.name));
            dest.merge_from(table);
        }
    }

    /// Create a snapshot of all tables at a given snap.
    pub fn snapshot_all_at(&self, snap: i64) -> Vec<(&str, BTreeMap<String, &DynamicValue>)> {
        self.tables
            .iter()
            .map(|(path, table)| (path.as_str(), table.snapshot_at(snap)))
            .collect()
    }

    /// The total number of rows across all tables.
    pub fn total_row_count(&self) -> usize {
        self.tables.values().map(|t| t.row_count()).sum()
    }

    /// Clear data in the given lifespan range across all tables.
    pub fn clear_range_all(&mut self, span: &Lifespan) {
        for table in self.tables.values_mut() {
            table.clear_range(span);
        }
    }

    /// Remove all tables.
    pub fn clear(&mut self) {
        self.tables.clear();
    }

    /// Iterate over all tables.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &DynamicTableEntry)> {
        self.tables.iter().map(|(k, v)| (k.as_str(), v))
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

    // -- New tests for added features --

    #[test]
    fn test_dynamic_value_arithmetic() {
        let a = DynamicValue::I64(10);
        let b = DynamicValue::I64(3);
        assert_eq!(a.add(&b), Some(DynamicValue::I64(13)));
        assert_eq!(a.subtract(&b), Some(DynamicValue::I64(7)));

        let c = DynamicValue::U64(100);
        let d = DynamicValue::U64(40);
        assert_eq!(c.add(&d), Some(DynamicValue::U64(140)));
        assert_eq!(c.subtract(&d), Some(DynamicValue::U64(60)));

        let e = DynamicValue::F64(1.5);
        let f = DynamicValue::F64(0.5);
        assert_eq!(e.add(&f), Some(DynamicValue::F64(2.0)));
        assert_eq!(e.subtract(&f), Some(DynamicValue::F64(1.0)));

        // Non-numeric should return None
        assert!(DynamicValue::Bool(true).add(&DynamicValue::Bool(false)).is_none());
        assert!(DynamicValue::String("a".into()).add(&DynamicValue::String("b".into())).is_none());
    }

    #[test]
    fn test_dynamic_value_type_name() {
        assert_eq!(DynamicValue::Bool(false).type_name(), "Bool");
        assert_eq!(DynamicValue::I64(0).type_name(), "I64");
        assert_eq!(DynamicValue::U64(0).type_name(), "U64");
        assert_eq!(DynamicValue::F64(0.0).type_name(), "F64");
        assert_eq!(DynamicValue::String("".into()).type_name(), "String");
        assert_eq!(DynamicValue::Bytes(vec![]).type_name(), "Bytes");
        assert_eq!(DynamicValue::Null.type_name(), "Null");
    }

    #[test]
    fn test_dynamic_value_is_numeric() {
        assert!(DynamicValue::I64(0).is_numeric());
        assert!(DynamicValue::U64(0).is_numeric());
        assert!(DynamicValue::F64(0.0).is_numeric());
        assert!(!DynamicValue::Bool(false).is_numeric());
        assert!(!DynamicValue::Null.is_numeric());
    }

    #[test]
    fn test_column_type_validation() {
        assert!(ColumnType::Any.matches(&DynamicValue::Bool(true)));
        assert!(ColumnType::Bool.matches(&DynamicValue::Bool(false)));
        assert!(!ColumnType::Bool.matches(&DynamicValue::I64(1)));
        assert!(ColumnType::Integer.matches(&DynamicValue::I64(1)));
        assert!(ColumnType::Integer.matches(&DynamicValue::U64(1)));
        assert!(!ColumnType::Integer.matches(&DynamicValue::F64(1.0)));
        assert!(ColumnType::Float.matches(&DynamicValue::F64(1.0)));
        assert!(!ColumnType::Float.matches(&DynamicValue::I64(1)));
        assert!(ColumnType::String.matches(&DynamicValue::String("hi".into())));
        assert!(!ColumnType::String.matches(&DynamicValue::I64(1)));
        assert!(ColumnType::Bytes.matches(&DynamicValue::Bytes(vec![1])));
    }

    #[test]
    fn test_column_schema_with_type() {
        let col = ColumnSchema::new("pc", 0).with_type(ColumnType::Integer);
        assert!(col.validate(&DynamicValue::U64(0x401000)));
        assert!(col.validate(&DynamicValue::I64(-1)));
        assert!(!col.validate(&DynamicValue::String("bad".into())));
    }

    #[test]
    fn test_dynamic_table_set_with_validation() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.add_column(ColumnSchema::new("pc", 0).with_type(ColumnType::Integer));
        assert!(table.set(0, "pc", DynamicValue::U64(0x401000)));
        assert!(!table.set(0, "pc", DynamicValue::String("bad".into())));
        // Without schema, anything goes
        assert!(table.set(0, "other", DynamicValue::Bool(true)));
    }

    #[test]
    fn test_dynamic_table_set_unchecked() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.add_column(ColumnSchema::new("pc", 0).with_type(ColumnType::Integer));
        // set_unchecked bypasses validation
        table.set_unchecked(0, "pc", DynamicValue::String("bad".into()));
        assert_eq!(table.get_exact(0, "pc").unwrap().as_str(), Some("bad"));
    }

    #[test]
    fn test_dynamic_row_iter() {
        let mut row = DynamicRow::new(0);
        row.set("a", DynamicValue::I64(1));
        row.set("b", DynamicValue::I64(2));
        let pairs: Vec<_> = row.iter().collect();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].0, "a");
        assert_eq!(pairs[1].0, "b");
    }

    #[test]
    fn test_dynamic_row_merge() {
        let mut row1 = DynamicRow::new(0);
        row1.set("a", DynamicValue::I64(1));
        row1.set("b", DynamicValue::I64(2));

        let mut row2 = DynamicRow::new(0);
        row2.set("b", DynamicValue::I64(99));
        row2.set("c", DynamicValue::I64(3));

        row1.merge_from(&row2);
        assert_eq!(row1.get("a").unwrap().as_i64(), Some(1));
        assert_eq!(row1.get("b").unwrap().as_i64(), Some(99)); // overwritten
        assert_eq!(row1.get("c").unwrap().as_i64(), Some(3));
    }

    #[test]
    fn test_dynamic_row_keys() {
        let mut row = DynamicRow::new(0);
        row.set("x", DynamicValue::Bool(true));
        row.set("y", DynamicValue::Bool(false));
        assert_eq!(row.keys(), vec!["x", "y"]);
    }

    #[test]
    fn test_mutable_dynamic_row() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.set(0, "a", DynamicValue::I64(1));
        {
            let mut row = table.row_mut_at(0);
            assert!(!row.is_changed());
            row.set("b", DynamicValue::I64(2));
            assert!(row.is_changed());
            assert_eq!(row.len(), 2);
        }
        assert_eq!(table.get_exact(0, "b").unwrap().as_i64(), Some(2));
    }

    #[test]
    fn test_mutable_dynamic_row_remove() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.set(0, "a", DynamicValue::I64(1));
        table.set(0, "b", DynamicValue::I64(2));
        {
            let mut row = table.row_mut_at(0);
            let removed = row.remove("a");
            assert!(removed.is_some());
            assert_eq!(removed.unwrap().as_i64(), Some(1));
            assert_eq!(row.len(), 1);
        }
        assert!(table.get_exact(0, "a").is_none());
    }

    #[test]
    fn test_values_in_range() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.set(0, "pc", DynamicValue::U64(0x1000));
        table.set(5, "pc", DynamicValue::U64(0x2000));
        table.set(10, "pc", DynamicValue::U64(0x3000));
        table.set(15, "pc", DynamicValue::U64(0x4000));

        let vals = table.values_in_range("pc", &Lifespan::span(3, 12));
        assert_eq!(vals.len(), 2);
        assert_eq!(vals[0].0, 5);
        assert_eq!(vals[1].0, 10);
    }

    #[test]
    fn test_first_last_value_in() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.set(0, "pc", DynamicValue::U64(0x1000));
        table.set(5, "pc", DynamicValue::U64(0x2000));
        table.set(10, "pc", DynamicValue::U64(0x3000));

        let first = table.first_value_in("pc", &Lifespan::span(3, 12)).unwrap();
        assert_eq!(first.0, 5);

        let last = table.last_value_in("pc", &Lifespan::span(3, 12)).unwrap();
        assert_eq!(last.0, 10);

        // Empty range
        assert!(table.first_value_in("pc", &Lifespan::span(100, 200)).is_none());
    }

    #[test]
    fn test_snapshot_at() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.set(0, "pc", DynamicValue::U64(0x1000));
        table.set(0, "sp", DynamicValue::U64(0x7FFF0000));
        table.set(5, "pc", DynamicValue::U64(0x2000));

        let snap = table.snapshot_at(3);
        assert_eq!(snap.len(), 2);
        assert_eq!(snap.get("pc").unwrap().as_u64(), Some(0x1000));
        assert_eq!(snap.get("sp").unwrap().as_u64(), Some(0x7FFF0000));

        let snap5 = table.snapshot_at(5);
        assert_eq!(snap5.get("pc").unwrap().as_u64(), Some(0x2000));
    }

    #[test]
    fn test_diff_key() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.set(0, "pc", DynamicValue::U64(0x1000));
        table.set(5, "pc", DynamicValue::U64(0x2000));

        let diff = table.diff_key("pc", 0, 5).unwrap();
        assert_eq!(diff.0.unwrap().as_u64(), Some(0x1000));
        assert_eq!(diff.1.unwrap().as_u64(), Some(0x2000));

        // Same value at both snaps
        assert!(table.diff_key("pc", 0, 0).is_none());
    }

    #[test]
    fn test_count_non_null() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.set(0, "a", DynamicValue::I64(1));
        table.set(0, "b", DynamicValue::Null);
        table.set(5, "c", DynamicValue::I64(3));
        assert_eq!(table.count_non_null(), 2);
    }

    #[test]
    fn test_keys_at() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.set(0, "pc", DynamicValue::U64(0x1000));
        table.set(0, "sp", DynamicValue::U64(0x7FFF0000));
        table.set(5, "pc", DynamicValue::U64(0x2000));

        let keys0 = table.keys_at(0);
        assert_eq!(keys0.len(), 2);

        let keys5 = table.keys_at(5);
        assert_eq!(keys5.len(), 1);

        let keys10 = table.keys_at(10);
        assert!(keys10.is_empty());
    }

    #[test]
    fn test_all_keys() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.set(0, "pc", DynamicValue::U64(0x1000));
        table.set(5, "sp", DynamicValue::U64(0x7FFF0000));

        let keys = table.all_keys();
        assert_eq!(keys, vec!["pc", "sp"]);
    }

    #[test]
    fn test_table_merge_from() {
        let mut t1 = DynamicTableEntry::new("P[0]", "state");
        t1.set(0, "pc", DynamicValue::U64(0x1000));
        t1.add_column(ColumnSchema::new("pc", 0));

        let mut t2 = DynamicTableEntry::new("P[0]", "state");
        t2.set(5, "pc", DynamicValue::U64(0x2000));
        t2.set(0, "sp", DynamicValue::U64(0x7FFF0000));
        t2.add_column(ColumnSchema::new("sp", 0));

        t1.merge_from(&t2);
        assert_eq!(t1.row_count(), 2);
        assert_eq!(t1.get_exact(0, "sp").unwrap().as_u64(), Some(0x7FFF0000));
        assert_eq!(t1.column_count(), 2);
    }

    #[test]
    fn test_rows_vec() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.set(0, "a", DynamicValue::I64(1));
        table.set(5, "b", DynamicValue::I64(2));
        table.set(10, "c", DynamicValue::I64(3));

        let rows = table.rows_vec();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].0, 0);
        assert_eq!(rows[1].0, 5);
        assert_eq!(rows[2].0, 10);
    }

    #[test]
    fn test_manager_tables_for_path_prefix() {
        let mut mgr = TraceDynamicTableManager::new();
        mgr.get_or_create("P[0].Threads[1]", "regs");
        mgr.get_or_create("P[0].Threads[2]", "regs");
        mgr.get_or_create("P[1].Threads[1]", "regs");

        let p0_tables = mgr.tables_for_path_prefix("P[0]");
        assert_eq!(p0_tables.len(), 2);

        let p1_tables = mgr.tables_for_path_prefix("P[1]");
        assert_eq!(p1_tables.len(), 1);
    }

    #[test]
    fn test_manager_merge_from() {
        let mut mgr1 = TraceDynamicTableManager::new();
        mgr1.get_or_create("P[0]", "state")
            .set(0, "pc", DynamicValue::U64(0x1000));

        let mut mgr2 = TraceDynamicTableManager::new();
        mgr2.get_or_create("P[0]", "state")
            .set(5, "pc", DynamicValue::U64(0x2000));
        mgr2.get_or_create("P[1]", "state")
            .set(0, "pc", DynamicValue::U64(0x3000));

        mgr1.merge_from(&mgr2);
        assert_eq!(mgr1.table_count(), 2);
        assert_eq!(
            mgr1.table("P[0]").unwrap().row_count(),
            2
        );
    }

    #[test]
    fn test_manager_snapshot_all_at() {
        let mut mgr = TraceDynamicTableManager::new();
        mgr.get_or_create("P[0]", "state")
            .set(0, "pc", DynamicValue::U64(0x1000));
        mgr.get_or_create("P[1]", "state")
            .set(0, "pc", DynamicValue::U64(0x2000));

        let snapshots = mgr.snapshot_all_at(0);
        assert_eq!(snapshots.len(), 2);
    }

    #[test]
    fn test_manager_total_row_count() {
        let mut mgr = TraceDynamicTableManager::new();
        mgr.get_or_create("P[0]", "state")
            .set(0, "a", DynamicValue::I64(1));
        mgr.get_or_create("P[0]", "state")
            .set(1, "b", DynamicValue::I64(2));
        mgr.get_or_create("P[1]", "state")
            .set(0, "c", DynamicValue::I64(3));

        assert_eq!(mgr.total_row_count(), 3);
    }

    #[test]
    fn test_manager_clear_range_all() {
        let mut mgr = TraceDynamicTableManager::new();
        mgr.get_or_create("P[0]", "state")
            .set(0, "a", DynamicValue::I64(1));
        mgr.get_or_create("P[0]", "state")
            .set(5, "b", DynamicValue::I64(2));
        mgr.get_or_create("P[1]", "state")
            .set(3, "c", DynamicValue::I64(3));

        mgr.clear_range_all(&Lifespan::span(2, 6));
        assert_eq!(mgr.total_row_count(), 1); // only snap 0 in P[0] remains
    }

    #[test]
    fn test_manager_clear_and_iter() {
        let mut mgr = TraceDynamicTableManager::new();
        mgr.get_or_create("P[0]", "state")
            .set(0, "a", DynamicValue::I64(1));
        mgr.get_or_create("P[1]", "state")
            .set(0, "b", DynamicValue::I64(2));

        let paths: Vec<_> = mgr.iter().map(|(p, _)| p).collect();
        assert_eq!(paths.len(), 2);

        mgr.clear();
        assert_eq!(mgr.table_count(), 0);
    }

    #[test]
    fn test_column_type_serde() {
        let col = ColumnSchema::new("pc", 0)
            .with_type(ColumnType::Integer)
            .with_description("program counter");

        let json = serde_json::to_string(&col).unwrap();
        let back: ColumnSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(back.column_type, ColumnType::Integer);
        assert_eq!(back.description, "program counter");
    }

    #[test]
    fn test_mixed_numeric_add() {
        let a = DynamicValue::I64(10);
        let b = DynamicValue::U64(5);
        assert_eq!(a.add(&b), Some(DynamicValue::I64(15)));
        assert_eq!(b.add(&a), Some(DynamicValue::U64(15)));
    }
}
