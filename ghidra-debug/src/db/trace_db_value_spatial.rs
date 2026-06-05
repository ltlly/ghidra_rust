//! Spatial indexing types for trace object values.
//!
//! Ported from Ghidra's `ghidra.trace.database.target` package:
//! ValueTriple, ValueBox, ValueShape, ValueSpace, ImmutableValueBox,
//! ImmutableValueShape.
//!
//! These types implement the spatial/hyperbox indexing used by the R*-tree
//! to efficiently query trace object values by parent, child, entry key,
//! snap, and address dimensions.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A record address in the trace database (space id + offset).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RecAddress {
    /// The address space id.
    pub space_id: i32,
    /// The offset within the space.
    pub offset: u64,
}

impl RecAddress {
    /// Create a new record address.
    pub fn new(space_id: i32, offset: u64) -> Self {
        Self { space_id, offset }
    }

    /// A minimum sentinel address.
    pub fn min_value() -> Self {
        Self {
            space_id: i32::MIN,
            offset: 0,
        }
    }

    /// A maximum sentinel address.
    pub fn max_value() -> Self {
        Self {
            space_id: i32::MAX,
            offset: u64::MAX,
        }
    }
}

impl Ord for RecAddress {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let c = self.space_id.cmp(&other.space_id);
        if c != std::cmp::Ordering::Equal {
            return c;
        }
        self.offset.cmp(&other.offset)
    }
}

impl PartialOrd for RecAddress {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for RecAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}:{:#x})", self.space_id, self.offset)
    }
}

// ---------------------------------------------------------------------------
// ValueTriple – a 5-dimensional point in the spatial index
// ---------------------------------------------------------------------------

/// A 5-dimensional point encoding the coordinates of a trace object value
/// in the R*-tree index.
///
/// Dimensions: parent key, child key, entry key, snap, address.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValueTriple {
    /// The key of the parent object.
    pub parent_key: i64,
    /// The key of the child object.
    pub child_key: i64,
    /// The entry key (attribute or element name).
    pub entry_key: String,
    /// The snap (time point).
    pub snap: i64,
    /// The record address (space + offset).
    pub address: RecAddress,
}

impl ValueTriple {
    /// Create a new value triple.
    pub fn new(
        parent_key: i64,
        child_key: i64,
        entry_key: impl Into<String>,
        snap: i64,
        address: RecAddress,
    ) -> Self {
        Self {
            parent_key,
            child_key,
            entry_key: entry_key.into(),
            snap,
            address,
        }
    }

    /// Componentwise minimum of two triples (for lower corner).
    pub fn min(a: &Self, b: &Self) -> Self {
        Self {
            parent_key: a.parent_key.min(b.parent_key),
            child_key: a.child_key.min(b.child_key),
            entry_key: if a.entry_key <= b.entry_key {
                a.entry_key.clone()
            } else {
                b.entry_key.clone()
            },
            snap: a.snap.min(b.snap),
            address: std::cmp::min(a.address, b.address),
        }
    }

    /// Componentwise maximum of two triples (for upper corner).
    pub fn max(a: &Self, b: &Self) -> Self {
        Self {
            parent_key: a.parent_key.max(b.parent_key),
            child_key: a.child_key.max(b.child_key),
            entry_key: if a.entry_key >= b.entry_key {
                a.entry_key.clone()
            } else {
                b.entry_key.clone()
            },
            snap: a.snap.max(b.snap),
            address: std::cmp::max(a.address, b.address),
        }
    }

    /// Midpoint of two triples (for R*-tree center calculations).
    pub fn mid(a: &Self, b: &Self) -> Self {
        Self {
            parent_key: (a.parent_key / 2) + (b.parent_key / 2),
            child_key: (a.child_key / 2) + (b.child_key / 2),
            entry_key: String::new(), // no meaningful midpoint for strings
            snap: (a.snap / 2) + (b.snap / 2),
            address: RecAddress::new(
                (a.address.space_id / 2) + (b.address.space_id / 2),
                (a.address.offset / 2) + (b.address.offset / 2),
            ),
        }
    }
}

impl PartialOrd for ValueTriple {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ValueTriple {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.parent_key
            .cmp(&other.parent_key)
            .then_with(|| self.child_key.cmp(&other.child_key))
            .then_with(|| self.entry_key.cmp(&other.entry_key))
            .then_with(|| self.snap.cmp(&other.snap))
            .then_with(|| self.address.cmp(&other.address))
    }
}

impl fmt::Display for ValueTriple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "({}, {}, {}, {}, {})",
            self.parent_key, self.child_key, self.entry_key, self.snap, self.address
        )
    }
}

// ---------------------------------------------------------------------------
// ValueBox – a hyper-box defined by lower and upper ValueTriple corners
// ---------------------------------------------------------------------------

/// An axis-aligned hyper-box in the 5-dimensional value space, defined by
/// lower and upper corner triples. Used as entries in the R*-tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueBox {
    /// Lower corner (minimum in each dimension).
    pub l_corner: ValueTriple,
    /// Upper corner (maximum in each dimension).
    pub u_corner: ValueTriple,
}

impl ValueBox {
    /// Create a new value box from corners.
    pub fn new(l_corner: ValueTriple, u_corner: ValueTriple) -> Self {
        Self { l_corner, u_corner }
    }

    /// Create an immutable copy (identity function for ImmutableValueBox compat).
    pub fn immutable(&self) -> Self {
        self.clone()
    }

    /// Get the bounds (identity for a box).
    pub fn get_bounds(&self) -> &Self {
        self
    }

    /// Get the center of this box.
    pub fn center(&self) -> ValueTriple {
        ValueTriple::mid(&self.l_corner, &self.u_corner)
    }

    /// Compute the union bounding box of two boxes.
    pub fn union(&self, other: &Self) -> Self {
        Self {
            l_corner: ValueTriple::min(&self.l_corner, &other.l_corner),
            u_corner: ValueTriple::max(&self.u_corner, &other.u_corner),
        }
    }

    /// Compute the intersection of two boxes.
    /// Returns None if the intersection is empty.
    pub fn intersection(&self, other: &Self) -> Option<Self> {
        let lc = ValueTriple::max(&self.l_corner, &other.l_corner);
        let uc = ValueTriple::min(&self.u_corner, &other.u_corner);
        if lc <= uc {
            Some(Self {
                l_corner: lc,
                u_corner: uc,
            })
        } else {
            None
        }
    }

    /// Check if this box contains a point.
    pub fn contains_point(&self, point: &ValueTriple) -> bool {
        self.l_corner <= *point && *point <= self.u_corner
    }

    /// Check if this box intersects another.
    pub fn intersects(&self, other: &Self) -> bool {
        self.intersection(other).is_some()
    }

    /// Compute the margin (sum of side lengths) for R*-tree optimization.
    pub fn margin(&self) -> u128 {
        let d_parent = (self.u_corner.parent_key - self.l_corner.parent_key) as u128;
        let d_child = (self.u_corner.child_key - self.l_corner.child_key) as u128;
        let d_snap = (self.u_corner.snap - self.l_corner.snap) as u128;
        let d_addr = (self.u_corner.address.offset.wrapping_sub(self.l_corner.address.offset))
            as u128;
        d_parent + d_child + d_snap + d_addr
    }

    /// Compute the area (product of side lengths) for R*-tree optimization.
    pub fn area(&self) -> u128 {
        let d_parent = (self.u_corner.parent_key - self.l_corner.parent_key).max(1) as u128;
        let d_child = (self.u_corner.child_key - self.l_corner.child_key).max(1) as u128;
        let d_snap = (self.u_corner.snap - self.l_corner.snap).max(1) as u128;
        let d_addr = (self.u_corner.address.offset.wrapping_sub(self.l_corner.address.offset))
            .max(1) as u128;
        d_parent * d_child * d_snap * d_addr
    }

    /// A human-readable description.
    pub fn description(&self) -> String {
        format!("[{}, {}]", self.l_corner, self.u_corner)
    }
}

impl fmt::Display for ValueBox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

// ---------------------------------------------------------------------------
// ValueShape – metadata about a trace object value's bounding properties
// ---------------------------------------------------------------------------

/// Trait describing the shape/bounding properties of a value in the
/// trace object tree. Analogous to Java's `ValueShape` interface.
pub trait ValueShape: fmt::Debug {
    /// Get the bounding box for this value.
    fn get_bounds(&self) -> ValueBox;

    /// Get the entry key (attribute name).
    fn entry_key(&self) -> &str;

    /// If the value is an address or range, the address space id (-1 for non-address).
    fn address_space_id(&self) -> i32;

    /// The minimum address offset.
    fn min_address_offset(&self) -> u64;

    /// The maximum address offset.
    fn max_address_offset(&self) -> u64;

    /// Whether this shape represents an address value.
    fn is_address(&self) -> bool {
        self.address_space_id() >= 0
    }
}

// ---------------------------------------------------------------------------
// ImmutableValueShape – an owned, immutable value shape
// ---------------------------------------------------------------------------

/// An immutable implementation of `ValueShape`, storing all properties
/// as plain fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImmutableValueShape {
    /// The entry key (attribute name).
    pub entry_key: String,
    /// The bounding box.
    pub bounds: ValueBox,
    /// The address space id (-1 for non-address values).
    pub address_space_id: i32,
    /// Minimum address offset.
    pub min_address_offset: u64,
    /// Maximum address offset.
    pub max_address_offset: u64,
}

impl ImmutableValueShape {
    /// Create a new immutable value shape.
    pub fn new(
        entry_key: impl Into<String>,
        bounds: ValueBox,
        address_space_id: i32,
        min_address_offset: u64,
        max_address_offset: u64,
    ) -> Self {
        Self {
            entry_key: entry_key.into(),
            bounds,
            address_space_id,
            min_address_offset,
            max_address_offset,
        }
    }

    /// Extract the address space id from an address offset.
    pub fn space_id_for_offset(offset: u64) -> i32 {
        // Default heuristic: if offset is within 32-bit range, use space 0
        if offset <= u32::MAX as u64 {
            0
        } else {
            1
        }
    }
}

impl ValueShape for ImmutableValueShape {
    fn get_bounds(&self) -> ValueBox {
        self.bounds.clone()
    }

    fn entry_key(&self) -> &str {
        &self.entry_key
    }

    fn address_space_id(&self) -> i32 {
        self.address_space_id
    }

    fn min_address_offset(&self) -> u64 {
        self.min_address_offset
    }

    fn max_address_offset(&self) -> u64 {
        self.max_address_offset
    }
}

// ---------------------------------------------------------------------------
// ValueSpace – singleton providing the spatial operations
// ---------------------------------------------------------------------------

/// The spatial operations context for the 5-dimensional value space.
///
/// Analogous to Java's `ValueSpace` enum. Provides the full bounding box
/// and operations for R*-tree management.
#[derive(Debug)]
pub struct ValueSpace;

impl ValueSpace {
    /// The singleton instance.
    pub const INSTANCE: Self = Self;

    /// The parent key dimension index.
    pub const DIM_PARENT_KEY: usize = 0;
    /// The child key dimension index.
    pub const DIM_CHILD_KEY: usize = 1;
    /// The entry key dimension index.
    pub const DIM_ENTRY_KEY: usize = 2;
    /// The snap dimension index.
    pub const DIM_SNAP: usize = 3;
    /// The address dimension index.
    pub const DIM_ADDRESS: usize = 4;
    /// Total number of dimensions.
    pub const NUM_DIMENSIONS: usize = 5;

    /// Get the full bounding box (covers entire space).
    pub fn full_box(&self) -> ValueBox {
        ValueBox {
            l_corner: ValueTriple {
                parent_key: i64::MIN,
                child_key: i64::MIN,
                entry_key: String::new(),
                snap: i64::MIN,
                address: RecAddress::min_value(),
            },
            u_corner: ValueTriple {
                parent_key: i64::MAX,
                child_key: i64::MAX,
                entry_key: String::from("\u{10FFFF}"),
                snap: i64::MAX,
                address: RecAddress::max_value(),
            },
        }
    }

    /// Compute the center of a box.
    pub fn box_center(&self, box_val: &ValueBox) -> ValueTriple {
        ValueTriple::mid(&box_val.l_corner, &box_val.u_corner)
    }

    /// Compute the union bounding box of two boxes.
    pub fn box_union(&self, a: &ValueBox, b: &ValueBox) -> ValueBox {
        a.union(b)
    }

    /// Compute the intersection of two boxes.
    pub fn box_intersection(&self, a: &ValueBox, b: &ValueBox) -> Option<ValueBox> {
        a.intersection(b)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_triple(pk: i64, ck: i64, ek: &str, snap: i64, offset: u64) -> ValueTriple {
        ValueTriple::new(pk, ck, ek, snap, RecAddress::new(0, offset))
    }

    #[test]
    fn test_value_triple_ordering() {
        let a = make_triple(1, 2, "a", 0, 0);
        let b = make_triple(1, 2, "a", 0, 1);
        assert!(a < b);

        let c = make_triple(1, 2, "b", 0, 0);
        assert!(a < c);
    }

    #[test]
    fn test_value_triple_min_max() {
        let a = make_triple(1, 5, "a", 10, 100);
        let b = make_triple(3, 2, "z", 5, 200);

        let min = ValueTriple::min(&a, &b);
        assert_eq!(min.parent_key, 1);
        assert_eq!(min.child_key, 2);
        assert_eq!(min.snap, 5);

        let max = ValueTriple::max(&a, &b);
        assert_eq!(max.parent_key, 3);
        assert_eq!(max.child_key, 5);
        assert_eq!(max.snap, 10);
    }

    #[test]
    fn test_value_box_contains() {
        let box_val = ValueBox::new(make_triple(0, 0, "", 0, 0), make_triple(10, 10, "z", 100, 1000));
        let inside = make_triple(5, 5, "m", 50, 500);
        let outside = make_triple(15, 5, "m", 50, 500);

        assert!(box_val.contains_point(&inside));
        assert!(!box_val.contains_point(&outside));
    }

    #[test]
    fn test_value_box_intersection() {
        let a = ValueBox::new(make_triple(0, 0, "", 0, 0), make_triple(10, 10, "", 100, 1000));
        let b = ValueBox::new(make_triple(5, 5, "", 50, 500), make_triple(15, 15, "", 150, 1500));

        let ix = a.intersection(&b).unwrap();
        assert_eq!(ix.l_corner.parent_key, 5);
        assert_eq!(ix.u_corner.parent_key, 10);
        assert_eq!(ix.l_corner.snap, 50);
        assert_eq!(ix.u_corner.snap, 100);
    }

    #[test]
    fn test_value_box_no_intersection() {
        let a = ValueBox::new(make_triple(0, 0, "", 0, 0), make_triple(5, 5, "", 50, 500));
        let b = ValueBox::new(make_triple(10, 10, "", 100, 1000), make_triple(15, 15, "", 150, 1500));

        assert!(a.intersection(&b).is_none());
        assert!(!a.intersects(&b));
    }

    #[test]
    fn test_value_box_union() {
        let a = ValueBox::new(make_triple(0, 0, "", 0, 0), make_triple(10, 10, "", 100, 1000));
        let b = ValueBox::new(make_triple(5, 5, "", 50, 500), make_triple(15, 15, "", 150, 1500));

        let u = a.union(&b);
        assert_eq!(u.l_corner.parent_key, 0);
        assert_eq!(u.u_corner.parent_key, 15);
    }

    #[test]
    fn test_value_box_margin_and_area() {
        let b = ValueBox::new(make_triple(0, 0, "", 0, 0), make_triple(10, 10, "", 100, 1000));
        assert!(b.margin() > 0);
        assert!(b.area() > 0);
    }

    #[test]
    fn test_value_space_full_box() {
        let space = ValueSpace;
        let full = space.full_box();
        assert_eq!(full.l_corner.parent_key, i64::MIN);
        assert_eq!(full.u_corner.parent_key, i64::MAX);
    }

    #[test]
    fn test_value_space_center() {
        let space = ValueSpace;
        let b = ValueBox::new(make_triple(0, 0, "", 0, 0), make_triple(100, 100, "", 1000, 10000));
        let center = space.box_center(&b);
        assert_eq!(center.parent_key, 50);
        assert_eq!(center.snap, 500);
    }

    #[test]
    fn test_rec_address_ordering() {
        let a = RecAddress::new(0, 100);
        let b = RecAddress::new(1, 0);
        assert!(a < b);

        let c = RecAddress::new(0, 200);
        assert!(a < c);
    }

    #[test]
    fn test_immutable_value_shape() {
        let shape = ImmutableValueShape::new(
            "regs",
            ValueBox::new(
                make_triple(0, 0, "", 0, 0),
                make_triple(10, 10, "", 100, 1000),
            ),
            -1,
            0,
            0,
        );
        assert_eq!(shape.entry_key(), "regs");
        assert!(!shape.is_address());

        let addr_shape = ImmutableValueShape::new(
            "Memory",
            ValueBox::new(
                make_triple(0, 0, "", 0, 0x400000),
                make_triple(10, 10, "", 100, 0x401000),
            ),
            0,
            0x400000,
            0x401000,
        );
        assert!(addr_shape.is_address());
        assert_eq!(addr_shape.min_address_offset(), 0x400000);
    }

    #[test]
    fn test_value_box_display() {
        let b = ValueBox::new(make_triple(1, 2, "a", 0, 0), make_triple(3, 4, "b", 100, 1000));
        let s = b.to_string();
        assert!(s.contains("1, 2"));
        assert!(s.contains("3, 4"));
    }
}
