//! Spatial data structures (R*-tree, hyper-box, 2D rectangles).
//!
//! Ported from Ghidra's `ghidra.util.database.spatial` and related packages.
//!
//! Provides bounding shapes, spatial maps, and R*-tree-based
//! spatial indexing for efficient range queries.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Bounding shapes
// ---------------------------------------------------------------------------

/// A 2D point.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Point2D {
    /// X coordinate.
    pub x: f64,
    /// Y coordinate.
    pub y: f64,
}

impl Point2D {
    /// Create a new 2D point.
    pub fn new(x: f64, y: f64) -> Self {
        Self { x, y }
    }
}

/// A 2D axis-aligned rectangle.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Rectangle2D {
    /// Minimum point.
    pub min: Point2D,
    /// Maximum point.
    pub max: Point2D,
}

impl Rectangle2D {
    /// Create a new rectangle.
    pub fn new(min: Point2D, max: Point2D) -> Self {
        Self { min, max }
    }

    /// Create a rectangle from coordinates.
    pub fn from_coords(x_min: f64, y_min: f64, x_max: f64, y_max: f64) -> Self {
        Self {
            min: Point2D::new(x_min, y_min),
            max: Point2D::new(x_max, y_max),
        }
    }

    /// The area of the rectangle.
    pub fn area(&self) -> f64 {
        (self.max.x - self.min.x) * (self.max.y - self.min.y)
    }

    /// The width.
    pub fn width(&self) -> f64 {
        self.max.x - self.min.x
    }

    /// The height.
    pub fn height(&self) -> f64 {
        self.max.y - self.min.y
    }

    /// Compute the minimum bounding rectangle of this and another.
    pub fn mbr(&self, other: &Rectangle2D) -> Rectangle2D {
        Rectangle2D {
            min: Point2D::new(self.min.x.min(other.min.x), self.min.y.min(other.min.y)),
            max: Point2D::new(self.max.x.max(other.max.x), self.max.y.max(other.max.y)),
        }
    }

    /// Whether this rectangle contains a point.
    pub fn contains_point(&self, p: &Point2D) -> bool {
        p.x >= self.min.x && p.x <= self.max.x && p.y >= self.min.y && p.y <= self.max.y
    }

    /// Whether this rectangle intersects another.
    pub fn intersects(&self, other: &Rectangle2D) -> bool {
        self.min.x <= other.max.x
            && self.max.x >= other.min.x
            && self.min.y <= other.max.y
            && self.max.y >= other.min.y
    }

    /// The margin (perimeter) of the rectangle.
    pub fn margin(&self) -> f64 {
        2.0 * (self.width() + self.height())
    }
}

/// A hyper-box in N-dimensional space.
///
/// Ported from Ghidra's `HyperBox`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HyperBox {
    /// Minimum coordinates (one per dimension).
    pub min: Vec<f64>,
    /// Maximum coordinates (one per dimension).
    pub max: Vec<f64>,
}

impl HyperBox {
    /// Create a new hyper-box.
    pub fn new(min: Vec<f64>, max: Vec<f64>) -> Self {
        assert_eq!(min.len(), max.len(), "HyperBox: dimension mismatch");
        Self { min, max }
    }

    /// The number of dimensions.
    pub fn dimensions(&self) -> usize {
        self.min.len()
    }

    /// The volume (product of side lengths).
    pub fn volume(&self) -> f64 {
        self.min
            .iter()
            .zip(self.max.iter())
            .map(|(lo, hi)| hi - lo)
            .product()
    }

    /// Compute the MBR with another hyper-box.
    pub fn mbr(&self, other: &HyperBox) -> HyperBox {
        let min = self
            .min
            .iter()
            .zip(other.min.iter())
            .map(|(a, b)| a.min(*b))
            .collect();
        let max = self
            .max
            .iter()
            .zip(other.max.iter())
            .map(|(a, b)| a.max(*b))
            .collect();
        HyperBox { min, max }
    }

    /// Whether this hyper-box contains a point.
    pub fn contains_point(&self, point: &[f64]) -> bool {
        point.len() == self.dimensions()
            && point
                .iter()
                .zip(self.min.iter())
                .zip(self.max.iter())
                .all(|((p, lo), hi)| *p >= *lo && *p <= *hi)
    }

    /// Whether this hyper-box intersects another.
    pub fn intersects(&self, other: &HyperBox) -> bool {
        self.min
            .iter()
            .zip(self.max.iter())
            .zip(other.min.iter())
            .zip(other.max.iter())
            .all(|(((lo1, hi1), lo2), hi2)| lo1 <= hi2 && lo2 <= hi1)
    }
}

// ---------------------------------------------------------------------------
// R*-tree node
// ---------------------------------------------------------------------------

/// A data record in an R*-tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RTreeDataRecord<D> {
    /// The data associated with this record.
    pub data: D,
    /// The bounding rectangle.
    pub bounds: Rectangle2D,
}

/// An R*-tree node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RTreeNode<D> {
    /// An internal node with child subtrees.
    Internal {
        /// Bounding rectangle covering all children.
        bounds: Rectangle2D,
        /// Child nodes.
        children: Vec<RTreeNode<D>>,
    },
    /// A leaf node containing data.
    Leaf {
        /// Data records.
        records: Vec<RTreeDataRecord<D>>,
    },
}

impl<D: Clone> RTreeNode<D> {
    /// Get the bounding rectangle of this node.
    pub fn bounds(&self) -> Rectangle2D {
        match self {
            Self::Internal { bounds, .. } => *bounds,
            Self::Leaf { records } => {
                let mut mbr = records[0].bounds;
                for r in &records[1..] {
                    mbr = mbr.mbr(&r.bounds);
                }
                mbr
            }
        }
    }

    /// Whether this is a leaf node.
    pub fn is_leaf(&self) -> bool {
        matches!(self, Self::Leaf { .. })
    }

    /// Query all data records whose bounds intersect the query rectangle.
    pub fn query(&self, query: &Rectangle2D) -> Vec<&D> {
        match self {
            Self::Internal { children, .. } => {
                let mut results = Vec::new();
                for child in children {
                    if child.bounds().intersects(query) {
                        results.extend(child.query(query));
                    }
                }
                results
            }
            Self::Leaf { records } => records
                .iter()
                .filter(|r| r.bounds.intersects(query))
                .map(|r| &r.data)
                .collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// SpatialMap trait
// ---------------------------------------------------------------------------

/// A spatial map interface.
pub trait SpatialMap<D> {
    /// Insert data with bounds.
    fn insert(&mut self, data: D, bounds: Rectangle2D);

    /// Query all entries whose bounds intersect the query.
    fn query(&self, query: &Rectangle2D) -> Vec<&D>;

    /// The number of entries.
    fn len(&self) -> usize;

    /// Whether the map is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A simple vector-backed spatial map (not an R*-tree, but implements the interface).
#[derive(Debug, Clone, Default)]
pub struct SimpleSpatialMap<D> {
    entries: Vec<RTreeDataRecord<D>>,
}

impl<D> SimpleSpatialMap<D> {
    /// Create a new empty spatial map.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<D> SpatialMap<D> for SimpleSpatialMap<D> {
    fn insert(&mut self, data: D, bounds: Rectangle2D) {
        self.entries.push(RTreeDataRecord { data, bounds });
    }

    fn query(&self, query: &Rectangle2D) -> Vec<&D> {
        self.entries
            .iter()
            .filter(|r| r.bounds.intersects(query))
            .map(|r| &r.data)
            .collect()
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Point2D --

    #[test]
    fn test_point2d() {
        let p = Point2D::new(3.0, 4.0);
        assert_eq!(p.x, 3.0);
        assert_eq!(p.y, 4.0);
    }

    // -- Rectangle2D --

    #[test]
    fn test_rectangle_area() {
        let r = Rectangle2D::from_coords(0.0, 0.0, 10.0, 5.0);
        assert_eq!(r.area(), 50.0);
        assert_eq!(r.width(), 10.0);
        assert_eq!(r.height(), 5.0);
    }

    #[test]
    fn test_rectangle_contains_point() {
        let r = Rectangle2D::from_coords(0.0, 0.0, 10.0, 10.0);
        assert!(r.contains_point(&Point2D::new(5.0, 5.0)));
        assert!(!r.contains_point(&Point2D::new(15.0, 5.0)));
    }

    #[test]
    fn test_rectangle_intersects() {
        let a = Rectangle2D::from_coords(0.0, 0.0, 10.0, 10.0);
        let b = Rectangle2D::from_coords(5.0, 5.0, 15.0, 15.0);
        let c = Rectangle2D::from_coords(20.0, 20.0, 30.0, 30.0);

        assert!(a.intersects(&b));
        assert!(!a.intersects(&c));
    }

    #[test]
    fn test_rectangle_mbr() {
        let a = Rectangle2D::from_coords(0.0, 0.0, 10.0, 10.0);
        let b = Rectangle2D::from_coords(5.0, -5.0, 20.0, 8.0);
        let mbr = a.mbr(&b);
        assert_eq!(mbr.min, Point2D::new(0.0, -5.0));
        assert_eq!(mbr.max, Point2D::new(20.0, 10.0));
    }

    #[test]
    fn test_rectangle_margin() {
        let r = Rectangle2D::from_coords(0.0, 0.0, 3.0, 4.0);
        assert_eq!(r.margin(), 14.0);
    }

    // -- HyperBox --

    #[test]
    fn test_hyper_box_volume() {
        let hb = HyperBox::new(vec![0.0, 0.0, 0.0], vec![2.0, 3.0, 4.0]);
        assert_eq!(hb.volume(), 24.0);
        assert_eq!(hb.dimensions(), 3);
    }

    #[test]
    fn test_hyper_box_contains() {
        let hb = HyperBox::new(vec![0.0, 0.0], vec![10.0, 10.0]);
        assert!(hb.contains_point(&[5.0, 5.0]));
        assert!(!hb.contains_point(&[15.0, 5.0]));
        assert!(!hb.contains_point(&[5.0, 5.0, 5.0])); // wrong dimension
    }

    #[test]
    fn test_hyper_box_intersects() {
        let a = HyperBox::new(vec![0.0, 0.0], vec![10.0, 10.0]);
        let b = HyperBox::new(vec![5.0, 5.0], vec![15.0, 15.0]);
        let c = HyperBox::new(vec![20.0, 20.0], vec![30.0, 30.0]);
        assert!(a.intersects(&b));
        assert!(!a.intersects(&c));
    }

    #[test]
    fn test_hyper_box_mbr() {
        let a = HyperBox::new(vec![0.0, 0.0], vec![10.0, 10.0]);
        let b = HyperBox::new(vec![5.0, -5.0], vec![20.0, 8.0]);
        let mbr = a.mbr(&b);
        assert_eq!(mbr.min, vec![0.0, -5.0]);
        assert_eq!(mbr.max, vec![20.0, 10.0]);
    }

    // -- R*-tree --

    #[test]
    fn test_rtree_leaf_query() {
        let leaf = RTreeNode::Leaf {
            records: vec![
                RTreeDataRecord {
                    data: "a",
                    bounds: Rectangle2D::from_coords(0.0, 0.0, 5.0, 5.0),
                },
                RTreeDataRecord {
                    data: "b",
                    bounds: Rectangle2D::from_coords(10.0, 10.0, 15.0, 15.0),
                },
            ],
        };

        let q1 = Rectangle2D::from_coords(2.0, 2.0, 4.0, 4.0);
        let results = leaf.query(&q1);
        assert_eq!(results, vec![&"a"]);

        let q2 = Rectangle2D::from_coords(0.0, 0.0, 20.0, 20.0);
        let results = leaf.query(&q2);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_rtree_internal_query() {
        let tree = RTreeNode::Internal {
            bounds: Rectangle2D::from_coords(0.0, 0.0, 20.0, 20.0),
            children: vec![
                RTreeNode::Leaf {
                    records: vec![RTreeDataRecord {
                        data: "left",
                        bounds: Rectangle2D::from_coords(0.0, 0.0, 5.0, 5.0),
                    }],
                },
                RTreeNode::Leaf {
                    records: vec![RTreeDataRecord {
                        data: "right",
                        bounds: Rectangle2D::from_coords(10.0, 10.0, 15.0, 15.0),
                    }],
                },
            ],
        };

        let q = Rectangle2D::from_coords(3.0, 3.0, 12.0, 12.0);
        let results = tree.query(&q);
        assert_eq!(results.len(), 2);

        let q2 = Rectangle2D::from_coords(0.0, 0.0, 2.0, 2.0);
        let results2 = tree.query(&q2);
        assert_eq!(results2.len(), 1);
        assert_eq!(results2[0], &"left");
    }

    #[test]
    fn test_rtree_is_leaf() {
        let leaf: RTreeNode<i32> = RTreeNode::Leaf { records: vec![] };
        assert!(leaf.is_leaf());

        let internal: RTreeNode<i32> = RTreeNode::Internal {
            bounds: Rectangle2D::from_coords(0.0, 0.0, 1.0, 1.0),
            children: vec![],
        };
        assert!(!internal.is_leaf());
    }

    // -- SpatialMap --

    #[test]
    fn test_simple_spatial_map() {
        let mut map = SimpleSpatialMap::new();
        map.insert("a", Rectangle2D::from_coords(0.0, 0.0, 5.0, 5.0));
        map.insert("b", Rectangle2D::from_coords(10.0, 10.0, 15.0, 15.0));
        assert_eq!(map.len(), 2);
        assert!(!map.is_empty());

        let q = Rectangle2D::from_coords(3.0, 3.0, 4.0, 4.0);
        let results = map.query(&q);
        assert_eq!(results, vec![&"a"]);

        let q2 = Rectangle2D::from_coords(0.0, 0.0, 20.0, 20.0);
        let results2 = map.query(&q2);
        assert_eq!(results2.len(), 2);
    }

    #[test]
    fn test_spatial_map_empty_query() {
        let map = SimpleSpatialMap::<i32>::new();
        let q = Rectangle2D::from_coords(0.0, 0.0, 1.0, 1.0);
        assert!(map.query(&q).is_empty());
    }

    #[test]
    fn test_spatial_map_serde() {
        let rect = Rectangle2D::from_coords(1.0, 2.0, 3.0, 4.0);
        let json = serde_json::to_string(&rect).unwrap();
        let back: Rectangle2D = serde_json::from_str(&json).unwrap();
        assert_eq!(rect, back);
    }
}
