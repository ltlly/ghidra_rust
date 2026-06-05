//! ValStr - a typed value with its string representation.
//!
//! Ported from Ghidra's `ghidra.debug.api.ValStr`.
//! Pairs a typed value with its string representation, commonly used
//! in the debugger for displaying register values, memory contents,
//! and watch expressions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// A value paired with its string representation.
///
/// This is used throughout the debugger to maintain both the parsed
/// (typed) value and the human-readable string for the same value.
/// This avoids repeated parsing/formatting and ensures consistency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValStr<T> {
    /// The typed value.
    pub val: Option<T>,
    /// The string representation.
    pub str: String,
}

impl<T> ValStr<T> {
    /// Create a new ValStr from a value (using its Display implementation).
    pub fn from_value(val: T) -> Self
    where
        T: fmt::Display,
    {
        Self {
            str: val.to_string(),
            val: Some(val),
        }
    }

    /// Create a ValStr from just a string (no parsed value).
    pub fn from_string(s: impl Into<String>) -> Self {
        Self {
            val: None,
            str: s.into(),
        }
    }

    /// Create a ValStr with both value and string explicitly set.
    pub fn new(val: T, str: impl Into<String>) -> Self {
        Self {
            val: Some(val),
            str: str.into(),
        }
    }

    /// Whether this has a parsed value.
    pub fn has_value(&self) -> bool {
        self.val.is_some()
    }

    /// Get the value, if present.
    pub fn value(&self) -> Option<&T> {
        self.val.as_ref()
    }

    /// Get the string representation.
    pub fn string(&self) -> &str {
        &self.str
    }

    /// Map the value to a different type.
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> ValStr<U> {
        ValStr {
            val: self.val.map(f),
            str: self.str,
        }
    }
}

impl ValStr<String> {
    /// Create a ValStr where both the value and string are the same.
    pub fn str(value: impl Into<String>) -> Self {
        let s = value.into();
        Self {
            val: Some(s.clone()),
            str: s,
        }
    }
}

impl<T: fmt::Display> fmt::Display for ValStr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.str)
    }
}

/// A decoder for parsing strings into typed ValStr values.
pub trait ValStrDecoder {
    /// The value type.
    type Value;

    /// Decode a string into a ValStr.
    fn decode(&self, s: &str) -> ValStr<Self::Value>;
}

/// A hex decoder that parses hex strings into u64 values.
#[derive(Debug, Default)]
pub struct HexDecoder;

impl ValStrDecoder for HexDecoder {
    type Value = u64;

    fn decode(&self, s: &str) -> ValStr<u64> {
        let clean = s.trim().trim_start_matches("0x").trim_start_matches("0X");
        match u64::from_str_radix(clean, 16) {
            Ok(val) => ValStr::new(val, s.to_string()),
            Err(_) => ValStr::from_string(s),
        }
    }
}

/// A decimal decoder that parses decimal strings into i64 values.
#[derive(Debug, Default)]
pub struct DecimalDecoder;

impl ValStrDecoder for DecimalDecoder {
    type Value = i64;

    fn decode(&self, s: &str) -> ValStr<i64> {
        match s.trim().parse::<i64>() {
            Ok(val) => ValStr::new(val, s.to_string()),
            Err(_) => ValStr::from_string(s),
        }
    }
}

/// A collection of ValStr entries for displaying multiple values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValStrTable<T> {
    entries: Vec<ValStrEntry<T>>,
}

impl<T> Default for ValStrTable<T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<T> ValStrTable<T> {
    /// Create a new empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry.
    pub fn push(&mut self, name: impl Into<String>, val_str: ValStr<T>) {
        self.entries.push(ValStrEntry {
            name: name.into(),
            val_str,
        });
    }

    /// Get all entries.
    pub fn entries(&self) -> &[ValStrEntry<T>] {
        &self.entries
    }

    /// Find an entry by name.
    pub fn find(&self, name: &str) -> Option<&ValStrEntry<T>> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A named entry in a ValStr table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValStrEntry<T> {
    /// The name/label for this value.
    pub name: String,
    /// The value with its string representation.
    pub val_str: ValStr<T>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_val_str_from_value() {
        let vs = ValStr::from_value(42u64);
        assert_eq!(vs.val, Some(42));
        assert_eq!(vs.str, "42");
        assert!(vs.has_value());
    }

    #[test]
    fn test_val_str_from_string() {
        let vs: ValStr<u64> = ValStr::from_string("unknown");
        assert!(vs.val.is_none());
        assert_eq!(vs.str, "unknown");
        assert!(!vs.has_value());
    }

    #[test]
    fn test_val_str_str() {
        let vs = ValStr::str("hello");
        assert_eq!(vs.val.as_deref(), Some("hello"));
        assert_eq!(vs.str, "hello");
    }

    #[test]
    fn test_val_str_display() {
        let vs = ValStr::new(42u64, "0x2A");
        assert_eq!(format!("{}", vs), "0x2A");
    }

    #[test]
    fn test_val_str_map() {
        let vs = ValStr::new(42u64, "42");
        let mapped = vs.map(|v| v as i64 + 1);
        assert_eq!(mapped.val, Some(43));
    }

    #[test]
    fn test_hex_decoder() {
        let decoder = HexDecoder;
        let vs = decoder.decode("0xFF");
        assert_eq!(vs.val, Some(255));

        let vs2 = decoder.decode("AB");
        assert_eq!(vs2.val, Some(0xAB));
    }

    #[test]
    fn test_decimal_decoder() {
        let decoder = DecimalDecoder;
        let vs = decoder.decode("42");
        assert_eq!(vs.val, Some(42));

        let vs2 = decoder.decode("-5");
        assert_eq!(vs2.val, Some(-5));
    }

    #[test]
    fn test_val_str_table() {
        let mut table = ValStrTable::new();
        table.push("RAX", ValStr::new(0x1234u64, "0x1234"));
        table.push("RBX", ValStr::new(0x5678u64, "0x5678"));
        assert_eq!(table.len(), 2);
        assert!(!table.is_empty());

        let rax = table.find("RAX").unwrap();
        assert_eq!(rax.val_str.val, Some(0x1234));
        assert!(table.find("RCX").is_none());
    }

    #[test]
    fn test_hex_decoder_invalid() {
        let decoder = HexDecoder;
        let vs = decoder.decode("not_hex");
        assert!(!vs.has_value());
    }
}
