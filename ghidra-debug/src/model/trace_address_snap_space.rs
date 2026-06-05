//! TraceAddressSnapSpace - Euclidean 2D space for R*-tree spatial indexing.
//!
//! Ported from Ghidra's `TraceAddressSnapSpace`.
//!
//! This provides the metric space for R*-tree indexing of trace objects
//! that have both an address dimension and a snap (time) dimension. It
//! supports distance, midpoint, and comparison operations on both axes.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

/// A 2D range representing an (address, snap) bounding box in the trace space.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AddressSnapRange {
    /// Minimum address offset (x-axis lower bound).
    pub min_addr: u64,
    /// Maximum address offset (x-axis upper bound).
    pub max_addr: u64,
    /// Minimum snap (y-axis lower bound).
    pub min_snap: i64,
    /// Maximum snap (y-axis upper bound).
    pub max_snap: i64,
}

impl AddressSnapRange {
    /// Create a new address-snap range.
    pub fn new(min_addr: u64, max_addr: u64, min_snap: i64, max_snap: i64) -> Self {
        Self {
            min_addr,
            max_addr,
            min_snap,
            max_snap,
        }
    }

    /// Create a point range (single address and snap).
    pub fn point(addr: u64, snap: i64) -> Self {
        Self {
            min_addr: addr,
            max_addr: addr,
            min_snap: snap,
            max_snap: snap,
        }
    }

    /// Check if this range intersects another range.
    pub fn intersects(&self, other: &AddressSnapRange) -> bool {
        self.min_addr <= other.max_addr
            && self.max_addr >= other.min_addr
            && self.min_snap <= other.max_snap
            && self.max_snap >= other.min_snap
    }

    /// Check if this range contains the given point.
    pub fn contains_point(&self, addr: u64, snap: i64) -> bool {
        addr >= self.min_addr && addr <= self.max_addr && snap >= self.min_snap && snap <= self.max_snap
    }

    /// Compute the area (in address space) of this range.
    pub fn address_size(&self) -> u64 {
        if self.max_addr >= self.min_addr {
            self.max_addr - self.min_addr
        } else {
            0
        }
    }

    /// Compute the area (in snap space) of this range.
    pub fn snap_size(&self) -> i64 {
        self.max_snap - self.min_snap
    }

    /// Check if this range is a single point.
    pub fn is_point(&self) -> bool {
        self.min_addr == self.max_addr && self.min_snap == self.max_snap
    }
}

/// The 2D Euclidean space for address-snap coordinates.
///
/// Provides metric operations for R*-tree indexing. Each address space
/// has its own `TraceAddressSnapSpace` singleton. This is parameterized
/// on the address type (stored as `u64` for simplicity).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceAddressSnapSpace {
    /// The name of the address space this belongs to.
    pub space_name: String,
    /// The full range for this space.
    pub full_range: AddressSnapRange,
}

impl TraceAddressSnapSpace {
    /// Create a new address-snap space for the given address space name.
    pub fn new(space_name: impl Into<String>) -> Self {
        Self {
            space_name: space_name.into(),
            full_range: AddressSnapRange::new(
                u64::MIN,
                u64::MAX,
                i64::MIN,
                i64::MAX,
            ),
        }
    }

    /// Create a bounded address-snap space.
    pub fn with_bounds(
        space_name: impl Into<String>,
        min_addr: u64,
        max_addr: u64,
        min_snap: i64,
        max_snap: i64,
    ) -> Self {
        Self {
            space_name: space_name.into(),
            full_range: AddressSnapRange::new(min_addr, max_addr, min_snap, max_snap),
        }
    }

    /// Compare two address values (x-axis).
    ///
    /// Returns the ordering: Less, Equal, or Greater.
    pub fn compare_x(&self, x1: u64, x2: u64) -> std::cmp::Ordering {
        x1.cmp(&x2)
    }

    /// Compare two snap values (y-axis).
    pub fn compare_y(&self, y1: i64, y2: i64) -> std::cmp::Ordering {
        y1.cmp(&y2)
    }

    /// Compute the distance between two address values (x-axis).
    ///
    /// Uses unsigned subtraction to handle wrap-around correctly.
    pub fn dist_x(&self, x1: u64, x2: u64) -> f64 {
        if x2 > x1 {
            (x2 - x1) as f64
        } else {
            (x1 - x2) as f64
        }
    }

    /// Compute the distance between two snap values (y-axis).
    pub fn dist_y(&self, y1: i64, y2: i64) -> f64 {
        (y2 as f64 - y1 as f64).abs()
    }

    /// Compute the midpoint of two address values (x-axis).
    pub fn mid_x(&self, x1: u64, x2: u64) -> u64 {
        if x2 > x1 {
            x1 + (x2 - x1) / 2
        } else {
            x2 + (x1 - x2) / 2
        }
    }

    /// Compute the midpoint of two snap values (y-axis).
    pub fn mid_y(&self, y1: i64, y2: i64) -> i64 {
        y1 + (y2 - y1) / 2
    }

    /// Get the full range for this space.
    pub fn get_full(&self) -> &AddressSnapRange {
        &self.full_range
    }

    /// Compute the distance between two points in 2D.
    pub fn dist_2d(&self, x1: u64, y1: i64, x2: u64, y2: i64) -> f64 {
        let dx = self.dist_x(x1, x2);
        let dy = self.dist_y(y1, y2);
        (dx * dx + dy * dy).sqrt()
    }

    /// Compute the midpoint of two points in 2D.
    pub fn mid_2d(&self, x1: u64, y1: i64, x2: u64, y2: i64) -> (u64, i64) {
        (self.mid_x(x1, x2), self.mid_y(y1, y2))
    }
}

/// A cache of `TraceAddressSnapSpace` instances, keyed by space name.
///
/// Uses a static mutex-protected HashMap to ensure only one instance
/// exists per address space name.
static SPACE_CACHE: OnceLock<Mutex<HashMap<String, TraceAddressSnapSpace>>> = OnceLock::new();

/// Get (or create) the `TraceAddressSnapSpace` for a given address space name.
///
/// Because this synchronizes on a cache of spaces, it should only be called
/// by space constructors, never by entry constructors.
pub fn for_address_space(space_name: &str) -> TraceAddressSnapSpace {
    let cache = SPACE_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = cache.lock().unwrap();
    map.entry(space_name.to_string())
        .or_insert_with(|| TraceAddressSnapSpace::new(space_name))
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_snap_range_creation() {
        let range = AddressSnapRange::new(0x1000, 0x2000, 0, 100);
        assert_eq!(range.min_addr, 0x1000);
        assert_eq!(range.max_addr, 0x2000);
        assert_eq!(range.min_snap, 0);
        assert_eq!(range.max_snap, 100);
        assert!(!range.is_point());
    }

    #[test]
    fn test_address_snap_range_point() {
        let point = AddressSnapRange::point(0x4000, 5);
        assert!(point.is_point());
        assert!(point.contains_point(0x4000, 5));
        assert!(!point.contains_point(0x4001, 5));
    }

    #[test]
    fn test_address_snap_range_intersection() {
        let r1 = AddressSnapRange::new(0x1000, 0x2000, 0, 50);
        let r2 = AddressSnapRange::new(0x1500, 0x2500, 25, 75);
        let r3 = AddressSnapRange::new(0x3000, 0x4000, 0, 50);

        assert!(r1.intersects(&r2));
        assert!(r2.intersects(&r1));
        assert!(!r1.intersects(&r3));
    }

    #[test]
    fn test_address_snap_range_contains_point() {
        let range = AddressSnapRange::new(0x1000, 0x2000, 0, 100);
        assert!(range.contains_point(0x1500, 50));
        assert!(range.contains_point(0x1000, 0));
        assert!(range.contains_point(0x2000, 100));
        assert!(!range.contains_point(0x2001, 50));
        assert!(!range.contains_point(0x1500, 101));
    }

    #[test]
    fn test_space_creation() {
        let space = TraceAddressSnapSpace::new("ram");
        assert_eq!(space.space_name, "ram");
        assert_eq!(space.full_range.min_addr, u64::MIN);
        assert_eq!(space.full_range.max_addr, u64::MAX);
    }

    #[test]
    fn test_space_bounded() {
        let space = TraceAddressSnapSpace::with_bounds("register", 0, 256, 0, 1000);
        assert_eq!(space.space_name, "register");
        assert_eq!(space.get_full().max_addr, 256);
    }

    #[test]
    fn test_compare_x() {
        let space = TraceAddressSnapSpace::new("ram");
        assert_eq!(space.compare_x(100, 200), std::cmp::Ordering::Less);
        assert_eq!(space.compare_x(200, 100), std::cmp::Ordering::Greater);
        assert_eq!(space.compare_x(100, 100), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_compare_y() {
        let space = TraceAddressSnapSpace::new("ram");
        assert_eq!(space.compare_y(0, 10), std::cmp::Ordering::Less);
        assert_eq!(space.compare_y(10, 0), std::cmp::Ordering::Greater);
        assert_eq!(space.compare_y(5, 5), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_dist_x() {
        let space = TraceAddressSnapSpace::new("ram");
        assert!((space.dist_x(100, 200) - 100.0).abs() < f64::EPSILON);
        assert!((space.dist_x(200, 100) - 100.0).abs() < f64::EPSILON);
        assert!((space.dist_x(100, 100) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_dist_y() {
        let space = TraceAddressSnapSpace::new("ram");
        assert!((space.dist_y(0, 10) - 10.0).abs() < f64::EPSILON);
        assert!((space.dist_y(10, 0) - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_mid_x() {
        let space = TraceAddressSnapSpace::new("ram");
        assert_eq!(space.mid_x(100, 200), 150);
        assert_eq!(space.mid_x(0, 100), 50);
    }

    #[test]
    fn test_mid_y() {
        let space = TraceAddressSnapSpace::new("ram");
        assert_eq!(space.mid_y(0, 100), 50);
        assert_eq!(space.mid_y(-10, 10), 0);
    }

    #[test]
    fn test_dist_2d() {
        let space = TraceAddressSnapSpace::new("ram");
        let d = space.dist_2d(0, 0, 3, 4);
        assert!((d - 5.0).abs() < 1e-10);
    }

    #[test]
    fn test_mid_2d() {
        let space = TraceAddressSnapSpace::new("ram");
        let (mx, my) = space.mid_2d(100, 0, 200, 100);
        assert_eq!(mx, 150);
        assert_eq!(my, 50);
    }

    #[test]
    fn test_for_address_space_cache() {
        let s1 = for_address_space("ram");
        let s2 = for_address_space("ram");
        assert_eq!(s1.space_name, s2.space_name);

        let s3 = for_address_space("register");
        assert_ne!(s1.space_name, s3.space_name);
    }

    #[test]
    fn test_full_range() {
        let space = TraceAddressSnapSpace::new("ram");
        let full = space.get_full();
        assert_eq!(full.min_addr, u64::MIN);
        assert_eq!(full.max_addr, u64::MAX);
        assert_eq!(full.min_snap, i64::MIN);
        assert_eq!(full.max_snap, i64::MAX);
    }

    #[test]
    fn test_address_size_and_snap_size() {
        let range = AddressSnapRange::new(0x1000, 0x2000, 10, 60);
        assert_eq!(range.address_size(), 0x1000);
        assert_eq!(range.snap_size(), 50);
    }

    #[test]
    fn test_range_serialization() {
        let range = AddressSnapRange::new(0x1000, 0x2000, 0, 100);
        let json = serde_json::to_string(&range).unwrap();
        let deserialized: AddressSnapRange = serde_json::from_str(&json).unwrap();
        assert_eq!(range, deserialized);
    }
}
