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

    /// Try to coerce this value to the target column type.
    ///
    /// Returns `Some(coerced)` if the coercion succeeds, `None` otherwise.
    /// Numeric types can be coerced between each other. Strings can be
    /// parsed to numeric types. Bool is preserved as-is.
    pub fn coerce_to(&self, target: &ColumnType) -> Option<DynamicValue> {
        match target {
            ColumnType::Any => Some(self.clone()),
            ColumnType::Bool => self.as_bool().map(DynamicValue::Bool),
            ColumnType::Integer => {
                // Prefer i64 if the value is signed, u64 otherwise.
                if let Some(v) = self.as_i64() {
                    Some(DynamicValue::I64(v))
                } else {
                    self.as_u64().map(DynamicValue::U64)
                }
            }
            ColumnType::Float => self.as_f64().map(DynamicValue::F64),
            ColumnType::String => match self {
                Self::Bool(v) => Some(Self::String(v.to_string())),
                Self::I64(v) => Some(Self::String(v.to_string())),
                Self::U64(v) => Some(Self::String(v.to_string())),
                Self::F64(v) => Some(Self::String(v.to_string())),
                Self::String(_) => Some(self.clone()),
                Self::Bytes(v) => Some(Self::String(format!("<{} bytes>", v.len()))),
                Self::Null => Some(Self::String("null".into())),
            },
            ColumnType::Bytes => match self {
                Self::Bytes(_) => Some(self.clone()),
                Self::String(s) => Some(Self::Bytes(s.as_bytes().to_vec())),
                _ => None,
            },
        }
    }

    /// Whether this value can be coerced to the given column type.
    pub fn can_coerce_to(&self, target: &ColumnType) -> bool {
        self.coerce_to(target).is_some()
    }

    /// Compare two dynamic values for ordering.
    ///
    /// Returns `Some(ordering)` if both values are comparable (same type
    /// or both numeric), `None` otherwise.
    pub fn partial_cmp_value(&self, other: &DynamicValue) -> Option<std::cmp::Ordering> {
        match (self, other) {
            (Self::Bool(a), Self::Bool(b)) => Some(a.cmp(b)),
            (Self::I64(a), Self::I64(b)) => Some(a.cmp(b)),
            (Self::U64(a), Self::U64(b)) => Some(a.cmp(b)),
            (Self::F64(a), Self::F64(b)) => a.partial_cmp(b),
            (Self::String(a), Self::String(b)) => Some(a.cmp(b)),
            // Cross-type numeric comparisons
            (Self::I64(a), Self::U64(b)) => {
                i64::try_from(*b).ok().map(|bv| a.cmp(&bv))
            }
            (Self::U64(a), Self::I64(b)) => {
                u64::try_from(*b).ok().map(|bv| a.cmp(&bv))
            }
            (Self::I64(a), Self::F64(b)) => (*a as f64).partial_cmp(b),
            (Self::U64(a), Self::F64(b)) => (*a as f64).partial_cmp(b),
            (Self::F64(a), Self::I64(b)) => a.partial_cmp(&(*b as f64)),
            (Self::F64(a), Self::U64(b)) => a.partial_cmp(&(*b as f64)),
            _ => None,
        }
    }

    /// Multiply two numeric dynamic values.
    pub fn multiply(&self, other: &DynamicValue) -> Option<DynamicValue> {
        match (self, other) {
            (Self::I64(a), Self::I64(b)) => Some(Self::I64(a.wrapping_mul(*b))),
            (Self::U64(a), Self::U64(b)) => Some(Self::U64(a.wrapping_mul(*b))),
            (Self::F64(a), Self::F64(b)) => Some(Self::F64(a * b)),
            (Self::I64(a), Self::U64(b)) => {
                i64::try_from(*b).ok().map(|b| Self::I64(a.wrapping_mul(b)))
            }
            (Self::U64(a), Self::I64(b)) => {
                u64::try_from(*b).ok().map(|b| Self::U64(a.wrapping_mul(b)))
            }
            _ => None,
        }
    }

    /// Divide two numeric dynamic values. Returns None on division by zero.
    pub fn divide(&self, other: &DynamicValue) -> Option<DynamicValue> {
        match (self, other) {
            (Self::I64(a), Self::I64(b)) => {
                if *b == 0 { None } else { Some(Self::I64(a / b)) }
            }
            (Self::U64(a), Self::U64(b)) => {
                if *b == 0 { None } else { Some(Self::U64(a / b)) }
            }
            (Self::F64(a), Self::F64(b)) => {
                if *b == 0.0 { None } else { Some(Self::F64(a / b)) }
            }
            _ => None,
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

    /// Try to coerce a value to this column type.
    ///
    /// This is a convenience wrapper around `DynamicValue::coerce_to`.
    pub fn coerce(&self, value: &DynamicValue) -> Option<DynamicValue> {
        value.coerce_to(self)
    }

    /// The type name as a human-readable string.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Any => "Any",
            Self::Bool => "Bool",
            Self::Integer => "Integer",
            Self::Float => "Float",
            Self::String => "String",
            Self::Bytes => "Bytes",
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
        // Collect all keys that have ever been set, then fill in values at the given snap.
        for key in self.all_keys() {
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

    /// Get all (key, value) pairs at a specific snap.
    pub fn entries_at(&self, snap: i64) -> Vec<(&str, &DynamicValue)> {
        self.rows
            .get(&snap)
            .map(|r| r.iter().collect())
            .unwrap_or_default()
    }

    /// Compute a structured diff between two snapshots.
    pub fn diff(&self, snap_a: i64, snap_b: i64) -> DynamicTableDiff {
        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut changed = Vec::new();
        let mut unchanged = Vec::new();

        // Collect all keys known at either snap.
        let mut all_keys: BTreeMap<String, ()> = BTreeMap::new();
        for key in self.keys_at(snap_a) {
            all_keys.insert(key.to_string(), ());
        }
        for key in self.keys_at(snap_b) {
            all_keys.insert(key.to_string(), ());
        }

        for key in all_keys.keys() {
            let val_a = self.get_exact(snap_a, key);
            let val_b = self.get_exact(snap_b, key);
            match (val_a, val_b) {
                (None, None) => {}
                (None, Some(b)) => added.push((key.clone(), b.clone())),
                (Some(a), None) => removed.push((key.clone(), a.clone())),
                (Some(a), Some(b)) => {
                    if a == b {
                        unchanged.push((key.clone(), a.clone()));
                    } else {
                        changed.push((key.clone(), a.clone(), b.clone()));
                    }
                }
            }
        }

        DynamicTableDiff {
            added,
            removed,
            changed,
            unchanged,
        }
    }

    /// Find rows matching a predicate across all snaps.
    ///
    /// Returns (snap, row) pairs where the predicate returns true.
    pub fn find_where<F>(&self, predicate: F) -> Vec<(i64, &DynamicRow)>
    where
        F: Fn(i64, &DynamicRow) -> bool,
    {
        self.rows
            .iter()
            .filter(|(&snap, row)| predicate(snap, row))
            .map(|(&snap, row)| (snap, row))
            .collect()
    }

    /// Copy data from one snap range to another, offsetting snap values.
    ///
    /// Copies all rows in `[from_start, from_end]` to new snaps offset by
    /// `to_start - from_start`.
    pub fn copy_range(&mut self, from_start: i64, from_end: i64, to_start: i64) {
        let offset = to_start - from_start;
        let keys: Vec<(i64, DynamicRow)> = self
            .rows
            .range(from_start..=from_end)
            .map(|(&s, r)| (s + offset, r.clone()))
            .collect();
        for (new_snap, row) in keys {
            let dest = self
                .rows
                .entry(new_snap)
                .or_insert_with(|| DynamicRow::new(new_snap));
            dest.merge_from(&row);
        }
    }

    /// Set a value with automatic coercion to the column's type.
    ///
    /// If the column has a type constraint and the value doesn't match,
    /// attempts to coerce it. Returns whether the value was accepted.
    pub fn set_with_coerce(&mut self, snap: i64, key: impl Into<String>, value: DynamicValue) -> bool {
        let key_str = key.into();
        if let Some(col) = self.columns.get(&key_str) {
            if col.validate(&value) {
                let row = self.rows.entry(snap).or_insert_with(|| DynamicRow::new(snap));
                row.set(key_str, value);
                return true;
            }
            // Try coercion
            if let Some(coerced) = col.column_type.coerce(&value) {
                let row = self.rows.entry(snap).or_insert_with(|| DynamicRow::new(snap));
                row.set(key_str, coerced);
                return true;
            }
            return false;
        }
        // No column schema, accept anything
        let row = self.rows.entry(snap).or_insert_with(|| DynamicRow::new(snap));
        row.set(key_str, value);
        true
    }

    /// Get the number of distinct keys ever set in this table.
    pub fn key_count(&self) -> usize {
        self.all_keys().len()
    }

    /// Whether this table has any data.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
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

    /// The number of tables whose path starts with the given prefix.
    pub fn table_count_for_prefix(&self, prefix: &str) -> usize {
        self.tables
            .range(prefix.to_string()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .count()
    }

    /// Rename a table from `old_path` to `new_path`.
    ///
    /// Returns `true` if the table existed and was renamed.
    pub fn rename_table(&mut self, old_path: &str, new_path: &str) -> bool {
        if let Some(mut table) = self.tables.remove(old_path) {
            table.path = new_path.to_string();
            self.tables.insert(new_path.to_string(), table);
            true
        } else {
            false
        }
    }

    /// Get all tables as a vector of (path, entry) pairs.
    pub fn tables_vec(&self) -> Vec<(&str, &DynamicTableEntry)> {
        self.tables.iter().map(|(k, v)| (k.as_str(), v)).collect()
    }

    /// Whether any tables exist.
    pub fn is_empty(&self) -> bool {
        self.tables.is_empty()
    }
}

// ---------------------------------------------------------------------------
// DynamicTableDiff -- structured diff between two snaps
// ---------------------------------------------------------------------------

/// A structured diff between two snapshots of a dynamic table.
///
/// Ported from Ghidra's property map diff operations. Lists which keys
/// were added, removed, or changed between two snap values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicTableDiff {
    /// Keys that exist at `snap_b` but not at `snap_a`.
    pub added: Vec<(String, DynamicValue)>,
    /// Keys that exist at `snap_a` but not at `snap_b`.
    pub removed: Vec<(String, DynamicValue)>,
    /// Keys present at both snaps but with different values.
    pub changed: Vec<(String, DynamicValue, DynamicValue)>,
    /// Keys present at both snaps with the same value.
    pub unchanged: Vec<(String, DynamicValue)>,
}

impl DynamicTableDiff {
    /// Whether the two snapshots are identical.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }

    /// The total number of differences (added + removed + changed).
    pub fn difference_count(&self) -> usize {
        self.added.len() + self.removed.len() + self.changed.len()
    }
}

// ---------------------------------------------------------------------------
// DynamicTableBatch -- batch operations with commit semantics
// ---------------------------------------------------------------------------

/// A batch of set/remove operations to apply atomically to a dynamic table.
///
/// Ported from Ghidra's batch property map operations. Collects pending
/// changes and applies them in a single pass.
#[derive(Debug, Clone, Default)]
pub struct DynamicTableBatch {
    /// Pending set operations: (snap, key, value).
    pending_sets: Vec<(i64, String, DynamicValue)>,
    /// Pending remove operations: (snap, key).
    pending_removes: Vec<(i64, String)>,
}

impl DynamicTableBatch {
    /// Create a new empty batch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a set operation.
    pub fn set(&mut self, snap: i64, key: impl Into<String>, value: DynamicValue) {
        self.pending_sets.push((snap, key.into(), value));
    }

    /// Queue a remove operation.
    pub fn remove(&mut self, snap: i64, key: impl Into<String>) {
        self.pending_removes.push((snap, key.into()));
    }

    /// The number of pending operations.
    pub fn pending_count(&self) -> usize {
        self.pending_sets.len() + self.pending_removes.len()
    }

    /// Whether there are no pending operations.
    pub fn is_empty(&self) -> bool {
        self.pending_sets.is_empty() && self.pending_removes.is_empty()
    }

    /// Apply all pending operations to the given table.
    ///
    /// Returns the number of operations applied.
    pub fn apply_to(self, table: &mut DynamicTableEntry) -> usize {
        let mut count = 0;
        for (snap, key, value) in self.pending_sets {
            table.set(snap, key, value);
            count += 1;
        }
        for (snap, key) in self.pending_removes {
            table.remove(snap, &key);
            count += 1;
        }
        count
    }

    /// Clear all pending operations.
    pub fn clear(&mut self) {
        self.pending_sets.clear();
        self.pending_removes.clear();
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

    // -- New tests for DynamicValue coerce, compare, multiply, divide --

    #[test]
    fn test_dynamic_value_coerce_to_integer() {
        let v = DynamicValue::F64(3.14);
        let coerced = v.coerce_to(&ColumnType::Integer);
        assert!(coerced.is_none()); // f64 -> integer requires lossy cast, not supported

        let v2 = DynamicValue::I64(42);
        let coerced2 = v2.coerce_to(&ColumnType::Integer).unwrap();
        assert_eq!(coerced2.as_i64(), Some(42));

        let v3 = DynamicValue::U64(100);
        let coerced3 = v3.coerce_to(&ColumnType::Integer).unwrap();
        assert_eq!(coerced3.as_u64(), Some(100));
    }

    #[test]
    fn test_dynamic_value_coerce_to_string() {
        let v = DynamicValue::I64(-42);
        let coerced = v.coerce_to(&ColumnType::String).unwrap();
        assert_eq!(coerced.as_str(), Some("-42"));

        let v2 = DynamicValue::Bool(true);
        let coerced2 = v2.coerce_to(&ColumnType::String).unwrap();
        assert_eq!(coerced2.as_str(), Some("true"));

        let v3 = DynamicValue::Null;
        let coerced3 = v3.coerce_to(&ColumnType::String).unwrap();
        assert_eq!(coerced3.as_str(), Some("null"));
    }

    #[test]
    fn test_dynamic_value_coerce_to_bytes() {
        let v = DynamicValue::String("hello".into());
        let coerced = v.coerce_to(&ColumnType::Bytes).unwrap();
        assert_eq!(coerced.as_bytes(), Some(b"hello".as_slice()));

        // Numeric types cannot coerce to bytes
        let v2 = DynamicValue::I64(42);
        assert!(v2.coerce_to(&ColumnType::Bytes).is_none());
    }

    #[test]
    fn test_dynamic_value_coerce_to_any() {
        let v = DynamicValue::Bool(false);
        let coerced = v.coerce_to(&ColumnType::Any).unwrap();
        assert_eq!(coerced.as_bool(), Some(false));
    }

    #[test]
    fn test_dynamic_value_can_coerce_to() {
        assert!(DynamicValue::I64(1).can_coerce_to(&ColumnType::String));
        assert!(DynamicValue::String("1".into()).can_coerce_to(&ColumnType::Bytes));
        assert!(!DynamicValue::Bool(true).can_coerce_to(&ColumnType::Integer));
    }

    #[test]
    fn test_dynamic_value_partial_cmp() {
        use std::cmp::Ordering;

        let a = DynamicValue::I64(5);
        let b = DynamicValue::I64(10);
        assert_eq!(a.partial_cmp_value(&b), Some(Ordering::Less));
        assert_eq!(b.partial_cmp_value(&a), Some(Ordering::Greater));
        assert_eq!(a.partial_cmp_value(&a), Some(Ordering::Equal));

        let c = DynamicValue::U64(5);
        assert_eq!(a.partial_cmp_value(&c), Some(Ordering::Equal));

        let d = DynamicValue::F64(5.0);
        assert_eq!(a.partial_cmp_value(&d), Some(Ordering::Equal));

        // Incomparable types
        assert!(DynamicValue::Bool(true).partial_cmp_value(&DynamicValue::I64(1)).is_none());
    }

    #[test]
    fn test_dynamic_value_multiply() {
        let a = DynamicValue::I64(3);
        let b = DynamicValue::I64(4);
        assert_eq!(a.multiply(&b), Some(DynamicValue::I64(12)));

        let c = DynamicValue::U64(10);
        let d = DynamicValue::U64(20);
        assert_eq!(c.multiply(&d), Some(DynamicValue::U64(200)));

        let e = DynamicValue::F64(2.5);
        let f = DynamicValue::F64(4.0);
        assert_eq!(e.multiply(&f), Some(DynamicValue::F64(10.0)));

        assert!(DynamicValue::Bool(true).multiply(&DynamicValue::Bool(false)).is_none());
    }

    #[test]
    fn test_dynamic_value_divide() {
        let a = DynamicValue::I64(12);
        let b = DynamicValue::I64(4);
        assert_eq!(a.divide(&b), Some(DynamicValue::I64(3)));

        let c = DynamicValue::U64(100);
        let d = DynamicValue::U64(10);
        assert_eq!(c.divide(&d), Some(DynamicValue::U64(10)));

        // Division by zero
        assert!(a.divide(&DynamicValue::I64(0)).is_none());
        assert!(DynamicValue::F64(1.0).divide(&DynamicValue::F64(0.0)).is_none());
    }

    #[test]
    fn test_column_type_coerce() {
        let v = DynamicValue::I64(42);
        let coerced = ColumnType::String.coerce(&v).unwrap();
        assert_eq!(coerced.as_str(), Some("42"));
    }

    #[test]
    fn test_column_type_name() {
        assert_eq!(ColumnType::Any.name(), "Any");
        assert_eq!(ColumnType::Integer.name(), "Integer");
        assert_eq!(ColumnType::Float.name(), "Float");
    }

    // -- New tests for DynamicTableEntry methods --

    #[test]
    fn test_dynamic_table_entries_at() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.set(0, "pc", DynamicValue::U64(0x1000));
        table.set(0, "sp", DynamicValue::U64(0x7FFF0000));

        let entries = table.entries_at(0);
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|(k, _)| *k == "pc"));
        assert!(entries.iter().any(|(k, _)| *k == "sp"));

        assert!(table.entries_at(99).is_empty());
    }

    #[test]
    fn test_dynamic_table_diff() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.set(0, "pc", DynamicValue::U64(0x1000));
        table.set(0, "sp", DynamicValue::U64(0x7FFF0000));
        table.set(0, "keep", DynamicValue::Bool(true));
        table.set(5, "pc", DynamicValue::U64(0x2000));
        table.set(5, "new_key", DynamicValue::I64(42));
        table.set(5, "keep", DynamicValue::Bool(true));
        // sp not set at snap 5 -> removed
        // keep stays the same -> unchanged

        let diff = table.diff(0, 5);
        assert_eq!(diff.added.len(), 1); // new_key
        assert_eq!(diff.removed.len(), 1); // sp
        assert_eq!(diff.changed.len(), 1); // pc
        assert_eq!(diff.unchanged.len(), 1); // keep
        assert!(!diff.is_empty());
        assert_eq!(diff.difference_count(), 3);
    }

    #[test]
    fn test_dynamic_table_find_where() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.set(0, "pc", DynamicValue::U64(0x1000));
        table.set(5, "pc", DynamicValue::U64(0x2000));
        table.set(10, "pc", DynamicValue::U64(0x3000));

        let found = table.find_where(|_snap, row| {
            row.get("pc")
                .and_then(|v| v.as_u64())
                .map_or(false, |addr| addr > 0x1500)
        });
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].0, 5);
        assert_eq!(found[1].0, 10);
    }

    #[test]
    fn test_dynamic_table_copy_range() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.set(0, "pc", DynamicValue::U64(0x1000));
        table.set(1, "pc", DynamicValue::U64(0x2000));

        table.copy_range(0, 1, 10);
        assert_eq!(table.get_exact(10, "pc").unwrap().as_u64(), Some(0x1000));
        assert_eq!(table.get_exact(11, "pc").unwrap().as_u64(), Some(0x2000));
        // Original data still present
        assert_eq!(table.get_exact(0, "pc").unwrap().as_u64(), Some(0x1000));
    }

    #[test]
    fn test_dynamic_table_set_with_coerce() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.add_column(ColumnSchema::new("pc", 0).with_type(ColumnType::Integer));

        // Direct match
        assert!(table.set_with_coerce(0, "pc", DynamicValue::U64(0x1000)));
        // String -> Integer coercion won't work (no parse)
        assert!(!table.set_with_coerce(1, "pc", DynamicValue::String("bad".into())));
        // No schema for other key, accepts anything
        assert!(table.set_with_coerce(0, "other", DynamicValue::Bool(true)));
    }

    #[test]
    fn test_dynamic_table_set_with_coerce_string_target() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.add_column(ColumnSchema::new("label", 0).with_type(ColumnType::String));

        // Integer -> String coercion
        assert!(table.set_with_coerce(0, "label", DynamicValue::I64(42)));
        assert_eq!(table.get_exact(0, "label").unwrap().as_str(), Some("42"));
    }

    #[test]
    fn test_dynamic_table_key_count_and_is_empty() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        assert!(table.is_empty());
        assert_eq!(table.key_count(), 0);

        table.set(0, "a", DynamicValue::I64(1));
        table.set(0, "b", DynamicValue::I64(2));
        table.set(5, "c", DynamicValue::I64(3));

        assert!(!table.is_empty());
        assert_eq!(table.key_count(), 3);
    }

    // -- New tests for DynamicTableDiff and DynamicTableBatch --

    #[test]
    fn test_dynamic_table_diff_empty() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        table.set(0, "pc", DynamicValue::U64(0x1000));

        let diff = table.diff(0, 0);
        assert!(diff.is_empty());
        assert_eq!(diff.difference_count(), 0);
        assert_eq!(diff.unchanged.len(), 1);
    }

    #[test]
    fn test_dynamic_table_batch() {
        let mut table = DynamicTableEntry::new("P[0]", "state");
        let mut batch = DynamicTableBatch::new();

        batch.set(0, "a", DynamicValue::I64(1));
        batch.set(0, "b", DynamicValue::I64(2));
        batch.set(1, "c", DynamicValue::I64(3));
        batch.remove(0, "b");

        assert_eq!(batch.pending_count(), 4);
        assert!(!batch.is_empty());

        let applied = batch.apply_to(&mut table);
        assert_eq!(applied, 4);
        assert_eq!(table.get_exact(0, "a").unwrap().as_i64(), Some(1));
        assert_eq!(table.get_exact(0, "b").unwrap(), &DynamicValue::Null);
        assert_eq!(table.get_exact(1, "c").unwrap().as_i64(), Some(3));
    }

    #[test]
    fn test_dynamic_table_batch_clear() {
        let mut batch = DynamicTableBatch::new();
        batch.set(0, "a", DynamicValue::I64(1));
        assert_eq!(batch.pending_count(), 1);

        batch.clear();
        assert!(batch.is_empty());
        assert_eq!(batch.pending_count(), 0);
    }

    // -- New tests for TraceDynamicTableManager methods --

    #[test]
    fn test_manager_table_count_for_prefix() {
        let mut mgr = TraceDynamicTableManager::new();
        mgr.get_or_create("P[0].Threads[1]", "regs");
        mgr.get_or_create("P[0].Threads[2]", "regs");
        mgr.get_or_create("P[1].Threads[1]", "regs");

        assert_eq!(mgr.table_count_for_prefix("P[0]"), 2);
        assert_eq!(mgr.table_count_for_prefix("P[1]"), 1);
        assert_eq!(mgr.table_count_for_prefix("P[2]"), 0);
    }

    #[test]
    fn test_manager_rename_table() {
        let mut mgr = TraceDynamicTableManager::new();
        mgr.get_or_create("P[0]", "state")
            .set(0, "pc", DynamicValue::U64(0x1000));

        assert!(mgr.rename_table("P[0]", "P[0].renamed"));
        assert!(mgr.table("P[0]").is_none());
        assert!(mgr.table("P[0].renamed").is_some());
        assert_eq!(
            mgr.table("P[0].renamed").unwrap().get_exact(0, "pc").unwrap().as_u64(),
            Some(0x1000)
        );

        // Rename nonexistent
        assert!(!mgr.rename_table("nonexistent", "new"));
    }

    #[test]
    fn test_manager_tables_vec() {
        let mut mgr = TraceDynamicTableManager::new();
        mgr.get_or_create("P[0]", "state");
        mgr.get_or_create("P[1]", "state");

        let vec = mgr.tables_vec();
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn test_manager_is_empty() {
        let mut mgr = TraceDynamicTableManager::new();
        assert!(mgr.is_empty());

        mgr.get_or_create("P[0]", "state");
        assert!(!mgr.is_empty());
    }
}
