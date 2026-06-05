//! Value storage types for the target object system.
//!
//! Ported from Ghidra's `ValueBox`, `ValueShape`, `ValueSpace`, `ValueTriple`,
//! `ImmutableValueBox`, `ImmutableValueShape`.
//!
//! These types represent how object values are stored and shaped
//! within the trace database's target object tree.

use serde::{Deserialize, Serialize};

/// A boxed value that can be stored in a target object.
///
/// `ValueBox` wraps a primitive value (string, integer, boolean, etc.)
/// with metadata about its type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ValueBox {
    /// A null/absent value.
    Null,
    /// A string value.
    String(String),
    /// A boolean value.
    Bool(bool),
    /// A signed integer value.
    Long(i64),
    /// An unsigned integer value.
    ULong(u64),
    /// A floating-point value.
    Double(f64),
    /// A raw byte array.
    Bytes(Vec<u8>),
}

impl ValueBox {
    /// Check if this is a null value.
    pub fn is_null(&self) -> bool {
        matches!(self, ValueBox::Null)
    }

    /// Try to get a string reference.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            ValueBox::String(s) => Some(s),
            _ => None,
        }
    }

    /// Try to get a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            ValueBox::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Try to get a signed integer.
    pub fn as_long(&self) -> Option<i64> {
        match self {
            ValueBox::Long(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get an unsigned integer.
    pub fn as_ulong(&self) -> Option<u64> {
        match self {
            ValueBox::ULong(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get a floating-point value.
    pub fn as_double(&self) -> Option<f64> {
        match self {
            ValueBox::Double(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get a byte slice.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            ValueBox::Bytes(b) => Some(b),
            _ => None,
        }
    }
}

impl Default for ValueBox {
    fn default() -> Self {
        ValueBox::Null
    }
}

/// An immutable version of ValueBox that does not allow mutation after creation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImmutableValueBox(ValueBox);

impl ImmutableValueBox {
    /// Create a new immutable value box.
    pub fn new(value: ValueBox) -> Self {
        Self(value)
    }

    /// Get a reference to the inner value.
    pub fn get(&self) -> &ValueBox {
        &self.0
    }

    /// Consume and return the inner value.
    pub fn into_inner(self) -> ValueBox {
        self.0
    }
}

/// The shape/type of a value in the target object hierarchy.
///
/// Describes whether a value is a primitive, a map, or an index range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValueShape {
    /// A primitive (scalar) value.
    Primitive,
    /// A map (object with named children).
    Map,
    /// An index range (array-like, with indexed children).
    Range,
    /// A set (collection of values without ordering).
    Set,
}

/// The value space defines where a value lives in the object hierarchy.
///
/// Each value exists in a "space" determined by the path component that
/// references it: it can be identified by name (string key), by index
/// (integer key), or as the root.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValueSpace {
    /// The root value space.
    Root,
    /// A value addressed by a string key.
    ByName(String),
    /// A value addressed by an integer index.
    ByIndex(i64),
    /// A value addressed by an address (offset + snap).
    ByAddress {
        /// The address offset.
        offset: u64,
        /// The snap (time).
        snap: i64,
    },
}

/// A triple of (value, shape, space) representing a fully-qualified value
/// in the target object hierarchy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueTriple {
    /// The value itself.
    pub value: ValueBox,
    /// The shape of the value.
    pub shape: ValueShape,
    /// The space in which this value lives.
    pub space: ValueSpace,
}

impl ValueTriple {
    /// Create a new value triple.
    pub fn new(value: ValueBox, shape: ValueShape, space: ValueSpace) -> Self {
        Self {
            value,
            shape,
            space,
        }
    }

    /// Create a primitive value in the root space.
    pub fn primitive_root(value: ValueBox) -> Self {
        Self {
            value,
            shape: ValueShape::Primitive,
            space: ValueSpace::Root,
        }
    }

    /// Create a map value named by the given key.
    pub fn named_map(key: impl Into<String>) -> Self {
        Self {
            value: ValueBox::Null,
            shape: ValueShape::Map,
            space: ValueSpace::ByName(key.into()),
        }
    }

    /// Create a range value at the given index.
    pub fn indexed(index: i64) -> Self {
        Self {
            value: ValueBox::Null,
            shape: ValueShape::Range,
            space: ValueSpace::ByIndex(index),
        }
    }
}

/// A cache entry that stores one write-behind value.
#[derive(Debug, Clone)]
pub struct CachedValueEntry {
    /// The path components leading to this value.
    pub path: Vec<ValueSpace>,
    /// The cached value.
    pub value: ValueBox,
    /// The shape of the cached value.
    pub shape: ValueShape,
    /// Whether this entry has been modified since last write.
    pub dirty: bool,
}

impl CachedValueEntry {
    /// Create a new cached value entry.
    pub fn new(path: Vec<ValueSpace>, value: ValueBox, shape: ValueShape) -> Self {
        Self {
            path,
            value,
            shape,
            dirty: true,
        }
    }

    /// Mark this entry as clean (written to database).
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    /// Check if this entry is dirty.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_box_types() {
        let s = ValueBox::String("hello".into());
        assert_eq!(s.as_str(), Some("hello"));

        let b = ValueBox::Bool(true);
        assert_eq!(b.as_bool(), Some(true));

        let l = ValueBox::Long(-42);
        assert_eq!(l.as_long(), Some(-42));

        let n = ValueBox::Null;
        assert!(n.is_null());
        assert!(n.as_str().is_none());
    }

    #[test]
    fn test_immutable_value_box() {
        let imm = ImmutableValueBox::new(ValueBox::Long(100));
        assert_eq!(imm.get().as_long(), Some(100));
    }

    #[test]
    fn test_value_triple() {
        let t = ValueTriple::primitive_root(ValueBox::ULong(0x400000));
        assert_eq!(t.shape, ValueShape::Primitive);
        assert_eq!(t.space, ValueSpace::Root);
    }

    #[test]
    fn test_cached_entry() {
        let mut entry = CachedValueEntry::new(
            vec![ValueSpace::ByName("process".into())],
            ValueBox::String("running".into()),
            ValueShape::Primitive,
        );
        assert!(entry.is_dirty());
        entry.mark_clean();
        assert!(!entry.is_dirty());
    }
}
