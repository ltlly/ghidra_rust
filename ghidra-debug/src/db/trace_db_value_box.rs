//! ValueBox, ValueShape, ValueSpace, ValueTriple - value storage primitives
//! for target object values in the trace database.
//!
//! Ported from Ghidra's `ghidra.trace.database.target` package:
//! - `ValueBox`: Mutable wrapper around a value with change tracking
//! - `ValueShape`: Describes the spatial shape of a value
//! - `ValueSpace`: Defines the address space for a value
//! - `ValueTriple`: A triple of (entry-key, child, value)
//! - `ImmutableValueBox`: An immutable value wrapper
//! - `ImmutableValueShape`: An immutable shape wrapper

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A mutable wrapper around a value with optional change tracking.
///
/// Ported from Ghidra's `ValueBox`. Stores a value and tracks whether
/// it has been modified since the last checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueBox<T> {
    /// The wrapped value.
    value: T,
    /// Whether this value has been modified.
    dirty: bool,
}

impl<T> ValueBox<T> {
    /// Create a new value box.
    pub fn new(value: T) -> Self {
        Self {
            value,
            dirty: false,
        }
    }

    /// Get a reference to the inner value.
    pub fn get(&self) -> &T {
        &self.value
    }

    /// Get a mutable reference. Marks the value as dirty.
    pub fn get_mut(&mut self) -> &mut T {
        self.dirty = true;
        &mut self.value
    }

    /// Set the value, marking it dirty.
    pub fn set(&mut self, value: T) {
        self.value = value;
        self.dirty = true;
    }

    /// Replace the value and return the old one.
    pub fn replace(&mut self, value: T) -> T {
        self.dirty = true;
        std::mem::replace(&mut self.value, value)
    }

    /// Check if this value has been modified.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Clear the dirty flag.
    pub fn clear_dirty(&mut self) {
        self.dirty = false;
    }

    /// Consume the box and return the inner value.
    pub fn into_inner(self) -> T {
        self.value
    }
}

impl<T: Default> Default for ValueBox<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

/// An immutable wrapper around a value.
///
/// Ported from Ghidra's `ImmutableValueBox`. Used for values that
/// should not be modified after creation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ImmutableValueBox<T> {
    /// The wrapped value.
    value: T,
}

impl<T> ImmutableValueBox<T> {
    /// Create a new immutable value box.
    pub fn new(value: T) -> Self {
        Self { value }
    }

    /// Get a reference to the inner value.
    pub fn get(&self) -> &T {
        &self.value
    }

    /// Consume the box and return the inner value.
    pub fn into_inner(self) -> T {
        self.value
    }
}

/// Describes the spatial shape of a value in the target tree.
///
/// Ported from Ghidra's `ValueShape`. A shape specifies the
/// address range, lifespan, and kind of a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueShape {
    /// The entry key in the parent's map.
    pub entry_key: String,
    /// The lifespan of this value (range of snapshots).
    pub lifespan: Lifespan,
    /// Whether this value has a spatial (address-based) component.
    pub has_range: bool,
    /// Minimum address, if spatial.
    pub min_address: Option<u64>,
    /// Maximum address, if spatial.
    pub max_address: Option<u64>,
}

impl ValueShape {
    /// Create a new non-spatial value shape.
    pub fn new(entry_key: impl Into<String>, lifespan: Lifespan) -> Self {
        Self {
            entry_key: entry_key.into(),
            lifespan,
            has_range: false,
            min_address: None,
            max_address: None,
        }
    }

    /// Create a spatial value shape with an address range.
    pub fn with_range(
        entry_key: impl Into<String>,
        lifespan: Lifespan,
        min_address: u64,
        max_address: u64,
    ) -> Self {
        Self {
            entry_key: entry_key.into(),
            lifespan,
            has_range: true,
            min_address: Some(min_address),
            max_address: Some(max_address),
        }
    }

    /// Check if this shape has an address range.
    pub fn is_spatial(&self) -> bool {
        self.has_range
    }

    /// Get the address range length, if spatial.
    pub fn range_length(&self) -> Option<u64> {
        if self.has_range {
            match (self.min_address, self.max_address) {
                (Some(min), Some(max)) => Some(max.saturating_sub(min).saturating_add(1)),
                _ => None,
            }
        } else {
            None
        }
    }
}

/// An immutable shape wrapper.
///
/// Ported from Ghidra's `ImmutableValueShape`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ImmutableValueShape {
    /// The entry key.
    pub entry_key: String,
    /// Whether spatial.
    pub has_range: bool,
    /// Min address.
    pub min_address: u64,
    /// Max address.
    pub max_address: u64,
}

impl ImmutableValueShape {
    /// Create a new immutable shape.
    pub fn new(entry_key: impl Into<String>) -> Self {
        Self {
            entry_key: entry_key.into(),
            has_range: false,
            min_address: 0,
            max_address: 0,
        }
    }

    /// Create with an address range.
    pub fn with_range(
        entry_key: impl Into<String>,
        min_address: u64,
        max_address: u64,
    ) -> Self {
        Self {
            entry_key: entry_key.into(),
            has_range: true,
            min_address,
            max_address,
        }
    }
}

/// Defines the address space context for a value.
///
/// Ported from Ghidra's `ValueSpace`. Associates a value with a
/// specific address space (e.g., "register", "ram1").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueSpace {
    /// The space name (e.g., "register", "ram").
    pub name: String,
    /// Whether this is a register space.
    pub is_register_space: bool,
    /// The thread key associated with register spaces.
    pub thread_key: Option<u64>,
    /// The frame level for register spaces.
    pub frame_level: Option<i32>,
}

impl ValueSpace {
    /// Create a new value space.
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        let is_register_space = name == "register";
        Self {
            name,
            is_register_space,
            thread_key: None,
            frame_level: None,
        }
    }

    /// Create a register space.
    pub fn register_space(thread_key: u64, frame_level: i32) -> Self {
        Self {
            name: "register".to_string(),
            is_register_space: true,
            thread_key: Some(thread_key),
            frame_level: Some(frame_level),
        }
    }

    /// Check if this is a register space.
    pub fn is_register(&self) -> bool {
        self.is_register_space
    }
}

/// A triple of (entry-key, child-object, value).
///
/// Ported from Ghidra's `ValueTriple`. Used to bundle the three
/// components of a value entry in the target tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueTriple {
    /// The entry key in the parent's map.
    pub entry_key: String,
    /// The child object ID, if any.
    pub child_id: Option<u64>,
    /// The value, if it is a primitive (not an object reference).
    pub value: Option<serde_json::Value>,
}

impl ValueTriple {
    /// Create a value triple with an object child.
    pub fn with_child(entry_key: impl Into<String>, child_id: u64) -> Self {
        Self {
            entry_key: entry_key.into(),
            child_id: Some(child_id),
            value: None,
        }
    }

    /// Create a value triple with a primitive value.
    pub fn with_value(entry_key: impl Into<String>, value: serde_json::Value) -> Self {
        Self {
            entry_key: entry_key.into(),
            child_id: None,
            value: Some(value),
        }
    }

    /// Check if this triple references a child object.
    pub fn is_object_ref(&self) -> bool {
        self.child_id.is_some()
    }

    /// Check if this triple has a primitive value.
    pub fn is_primitive(&self) -> bool {
        self.value.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_box_basic() {
        let mut vb = ValueBox::new(42u32);
        assert_eq!(*vb.get(), 42);
        assert!(!vb.is_dirty());

        vb.set(100);
        assert_eq!(*vb.get(), 100);
        assert!(vb.is_dirty());
    }

    #[test]
    fn test_value_box_replace() {
        let mut vb = ValueBox::new("hello");
        let old = vb.replace("world");
        assert_eq!(old, "hello");
        assert_eq!(*vb.get(), "world");
        assert!(vb.is_dirty());
    }

    #[test]
    fn test_value_box_clear_dirty() {
        let mut vb = ValueBox::new(1);
        vb.set(2);
        assert!(vb.is_dirty());
        vb.clear_dirty();
        assert!(!vb.is_dirty());
    }

    #[test]
    fn test_value_box_default() {
        let vb = ValueBox::<u32>::default();
        assert_eq!(*vb.get(), 0);
    }

    #[test]
    fn test_immutable_value_box() {
        let ivb = ImmutableValueBox::new("immutable");
        assert_eq!(*ivb.get(), "immutable");
        let inner = ivb.into_inner();
        assert_eq!(inner, "immutable");
    }

    #[test]
    fn test_value_shape_non_spatial() {
        let shape = ValueShape::new("key", Lifespan::span(0, 10));
        assert!(!shape.is_spatial());
        assert_eq!(shape.range_length(), None);
    }

    #[test]
    fn test_value_shape_spatial() {
        let shape = ValueShape::with_range("key", Lifespan::span(0, 10), 0x1000, 0x1FFF);
        assert!(shape.is_spatial());
        assert_eq!(shape.range_length(), Some(0x1000));
    }

    #[test]
    fn test_immutable_value_shape() {
        let shape = ImmutableValueShape::with_range("key", 0, 0xFF);
        assert!(shape.has_range);
        assert_eq!(shape.entry_key, "key");
    }

    #[test]
    fn test_value_space_memory() {
        let vs = ValueSpace::new("ram");
        assert_eq!(vs.name, "ram");
        assert!(!vs.is_register());
    }

    #[test]
    fn test_value_space_register() {
        let vs = ValueSpace::register_space(42, 0);
        assert!(vs.is_register());
        assert_eq!(vs.thread_key, Some(42));
        assert_eq!(vs.frame_level, Some(0));
    }

    #[test]
    fn test_value_triple_child() {
        let vt = ValueTriple::with_child("key", 99);
        assert!(vt.is_object_ref());
        assert!(!vt.is_primitive());
        assert_eq!(vt.child_id, Some(99));
    }

    #[test]
    fn test_value_triple_primitive() {
        let vt = ValueTriple::with_value("key", serde_json::json!(42));
        assert!(!vt.is_object_ref());
        assert!(vt.is_primitive());
    }
}
