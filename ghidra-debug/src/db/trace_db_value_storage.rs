//! Immutable value types and value storage for trace objects.
//!
//! Ported from Ghidra's `ghidra.trace.database.target` package:
//! - ImmutableValueBox
//! - ImmutableValueShape
//! - ValueBox
//! - ValueShape
//! - ValueSpace
//! - ValueTriple
//!
//! These provide the value storage primitives for the trace object system.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A boxed value that is immutable once created.
///
/// Ported from Ghidra's `ImmutableValueBox`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImmutableValueBox<T: Clone> {
    /// The stored value.
    value: T,
}

impl<T: Clone> ImmutableValueBox<T> {
    /// Create a new immutable value box.
    pub fn new(value: T) -> Self {
        Self { value }
    }

    /// Get a reference to the stored value.
    pub fn get(&self) -> &T {
        &self.value
    }

    /// Consume the box and return the value.
    pub fn into_inner(self) -> T {
        self.value
    }
}

impl<T: Clone + PartialEq> PartialEq for ImmutableValueBox<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T: Clone + Eq> Eq for ImmutableValueBox<T> {}

impl<T: Clone + std::hash::Hash> std::hash::Hash for ImmutableValueBox<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}

/// The shape (position and extent) of a value in the trace database.
///
/// Ported from Ghidra's `ImmutableValueShape`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ImmutableValueShape {
    /// The address space name.
    pub space: String,
    /// The minimum address offset.
    pub min_address: u64,
    /// The maximum address offset.
    pub max_address: u64,
    /// The lifespan.
    pub lifespan: Lifespan,
}

impl ImmutableValueShape {
    /// Create a new value shape.
    pub fn new(
        space: impl Into<String>,
        min_address: u64,
        max_address: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            space: space.into(),
            min_address,
            max_address,
            lifespan,
        }
    }

    /// Create a point shape (single address).
    pub fn point(space: impl Into<String>, address: u64, snap: i64) -> Self {
        Self {
            space: space.into(),
            min_address: address,
            max_address: address,
            lifespan: Lifespan::span(snap, snap),
        }
    }

    /// Whether this shape contains the given address and snap.
    pub fn contains(&self, space: &str, address: u64, snap: i64) -> bool {
        self.space == space
            && address >= self.min_address
            && address <= self.max_address
            && self.lifespan.contains(snap)
    }

    /// Whether this shape overlaps another shape.
    pub fn overlaps(&self, other: &ImmutableValueShape) -> bool {
        self.space == other.space
            && self.min_address <= other.max_address
            && other.min_address <= self.max_address
            && self.lifespan.intersects(&other.lifespan)
    }

    /// The size of the address range.
    pub fn size(&self) -> u64 {
        self.max_address - self.min_address + 1
    }
}

/// A mutable value box that supports updates.
///
/// Ported from Ghidra's `ValueBox`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueBox<T: Clone> {
    /// The stored value.
    value: T,
    /// Whether this value has been modified since creation.
    dirty: bool,
}

impl<T: Clone> ValueBox<T> {
    /// Create a new value box.
    pub fn new(value: T) -> Self {
        Self {
            value,
            dirty: false,
        }
    }

    /// Get a reference to the stored value.
    pub fn get(&self) -> &T {
        &self.value
    }

    /// Set the value, marking it as dirty.
    pub fn set(&mut self, value: T) {
        self.value = value;
        self.dirty = true;
    }

    /// Whether this value has been modified.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Clear the dirty flag.
    pub fn clear_dirty(&mut self) {
        self.dirty = false;
    }
}

/// The shape of a value in the trace database (mutable version).
///
/// Ported from Ghidra's `ValueShape`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueShape {
    /// The address space name.
    pub space: String,
    /// The minimum address offset.
    pub min_address: u64,
    /// The maximum address offset.
    pub max_address: u64,
    /// The lifespan.
    pub lifespan: Lifespan,
}

impl ValueShape {
    /// Create a new value shape.
    pub fn new(
        space: impl Into<String>,
        min_address: u64,
        max_address: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            space: space.into(),
            min_address,
            max_address,
            lifespan,
        }
    }

    /// Convert to an immutable shape.
    pub fn to_immutable(&self) -> ImmutableValueShape {
        ImmutableValueShape {
            space: self.space.clone(),
            min_address: self.min_address,
            max_address: self.max_address,
            lifespan: self.lifespan.clone(),
        }
    }
}

/// A value space that organizes values by their spatial coordinates.
///
/// Ported from Ghidra's `ValueSpace`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValueSpace<T: Clone> {
    /// The address space name.
    pub space: String,
    /// The values in this space, stored as (shape, value) pairs.
    entries: Vec<(ImmutableValueShape, T)>,
}

impl<T: Clone> ValueSpace<T> {
    /// Create a new value space.
    pub fn new(space: impl Into<String>) -> Self {
        Self {
            space: space.into(),
            entries: Vec::new(),
        }
    }

    /// Insert a value with the given shape.
    pub fn insert(&mut self, shape: ImmutableValueShape, value: T) {
        self.entries.push((shape, value));
    }

    /// Get the value at the given address and snap.
    pub fn get(&self, address: u64, snap: i64) -> Option<&T> {
        self.entries
            .iter()
            .find(|(shape, _)| shape.contains(&self.space, address, snap))
            .map(|(_, value)| value)
    }

    /// Get all values intersecting the given range.
    pub fn get_intersecting(
        &self,
        min_address: u64,
        max_address: u64,
        span: &Lifespan,
    ) -> Vec<&T> {
        self.entries
            .iter()
            .filter(|(shape, _)| {
                shape.space == self.space
                    && shape.min_address <= max_address
                    && shape.max_address >= min_address
                    && shape.lifespan.intersects(span)
            })
            .map(|(_, value)| value)
            .collect()
    }

    /// Remove all entries that overlap with the given shape.
    pub fn remove_overlapping(&mut self, shape: &ImmutableValueShape) {
        self.entries.retain(|(s, _)| !s.overlaps(shape));
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether this space is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A triple of (shape, write-behind cache, committed) for value management.
///
/// Ported from Ghidra's `ValueTriple`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueTriple<T: Clone> {
    /// The shape of this value.
    pub shape: ImmutableValueShape,
    /// The write-behind cache value (latest modification).
    pub cached: Option<T>,
    /// The committed value (last persisted to database).
    pub committed: Option<T>,
}

impl<T: Clone> ValueTriple<T> {
    /// Create a new value triple with a committed value.
    pub fn new(shape: ImmutableValueShape, committed: T) -> Self {
        Self {
            shape,
            cached: None,
            committed: Some(committed),
        }
    }

    /// Create a value triple with only a cached value.
    pub fn cached_only(shape: ImmutableValueShape, cached: T) -> Self {
        Self {
            shape,
            cached: Some(cached),
            committed: None,
        }
    }

    /// Get the latest value (cached if available, otherwise committed).
    pub fn latest(&self) -> Option<&T> {
        self.cached.as_ref().or(self.committed.as_ref())
    }

    /// Whether this triple has uncommitted changes.
    pub fn is_dirty(&self) -> bool {
        self.cached.is_some()
    }

    /// Commit the cached value.
    pub fn commit(&mut self) {
        if let Some(cached) = self.cached.take() {
            self.committed = Some(cached);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_immutable_value_box() {
        let box1 = ImmutableValueBox::new(42);
        assert_eq!(*box1.get(), 42);
        assert_eq!(box1.clone(), box1);
    }

    #[test]
    fn test_immutable_value_shape() {
        let shape = ImmutableValueShape::new("ram", 0x1000, 0x2000, Lifespan::span(0, 10));
        assert!(shape.contains("ram", 0x1500, 5));
        assert!(!shape.contains("ram", 0x3000, 5));
        assert!(!shape.contains("register", 0x1500, 5));
        assert!(!shape.contains("ram", 0x1500, 15));
        assert_eq!(shape.size(), 0x1001);
    }

    #[test]
    fn test_immutable_value_shape_point() {
        let shape = ImmutableValueShape::point("ram", 0x1000, 5);
        assert!(shape.contains("ram", 0x1000, 5));
        assert!(!shape.contains("ram", 0x1001, 5));
    }

    #[test]
    fn test_immutable_value_shape_overlaps() {
        let s1 = ImmutableValueShape::new("ram", 0x1000, 0x2000, Lifespan::span(0, 10));
        let s2 = ImmutableValueShape::new("ram", 0x1500, 0x2500, Lifespan::span(5, 15));
        let s3 = ImmutableValueShape::new("ram", 0x3000, 0x4000, Lifespan::span(0, 10));

        assert!(s1.overlaps(&s2));
        assert!(!s1.overlaps(&s3));
    }

    #[test]
    fn test_value_box() {
        let mut vb = ValueBox::new(10);
        assert_eq!(*vb.get(), 10);
        assert!(!vb.is_dirty());

        vb.set(20);
        assert_eq!(*vb.get(), 20);
        assert!(vb.is_dirty());

        vb.clear_dirty();
        assert!(!vb.is_dirty());
    }

    #[test]
    fn test_value_space() {
        let mut space = ValueSpace::<i32>::new("ram");
        let shape = ImmutableValueShape::new("ram", 0x1000, 0x1000, Lifespan::span(0, 10));
        space.insert(shape, 42);

        assert_eq!(space.get(0x1000, 5), Some(&42));
        assert_eq!(space.get(0x2000, 5), None);
        assert_eq!(space.get(0x1000, 15), None);
        assert_eq!(space.len(), 1);
    }

    #[test]
    fn test_value_space_intersecting() {
        let mut space = ValueSpace::<String>::new("ram");
        space.insert(
            ImmutableValueShape::new("ram", 0x1000, 0x1000, Lifespan::span(0, 10)),
            "a".to_string(),
        );
        space.insert(
            ImmutableValueShape::new("ram", 0x2000, 0x2000, Lifespan::span(0, 10)),
            "b".to_string(),
        );
        space.insert(
            ImmutableValueShape::new("ram", 0x3000, 0x3000, Lifespan::span(5, 15)),
            "c".to_string(),
        );

        let results = space.get_intersecting(0x500, 0x2500, &Lifespan::span(3, 12));
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_value_space_remove_overlapping() {
        let mut space = ValueSpace::<i32>::new("ram");
        let shape = ImmutableValueShape::new("ram", 0x1000, 0x2000, Lifespan::span(0, 10));
        space.insert(shape.clone(), 42);

        let overlap = ImmutableValueShape::new("ram", 0x1500, 0x2500, Lifespan::span(5, 15));
        space.remove_overlapping(&overlap);
        assert!(space.is_empty());
    }

    #[test]
    fn test_value_triple() {
        let shape = ImmutableValueShape::new("ram", 0x1000, 0x1000, Lifespan::span(0, 10));
        let mut triple = ValueTriple::new(shape, 42);

        assert_eq!(triple.latest(), Some(&42));
        assert!(!triple.is_dirty());

        triple.cached = Some(100);
        assert!(triple.is_dirty());
        assert_eq!(triple.latest(), Some(&100));

        triple.commit();
        assert!(!triple.is_dirty());
        assert_eq!(triple.committed, Some(100));
    }

    #[test]
    fn test_value_triple_cached_only() {
        let shape = ImmutableValueShape::new("ram", 0x1000, 0x1000, Lifespan::span(0, 10));
        let triple = ValueTriple::<i32>::cached_only(shape, 42);
        assert!(triple.is_dirty());
        assert_eq!(triple.latest(), Some(&42));
    }
}
