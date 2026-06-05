//! Spatial query types for the target object value R*-tree.
//!
//! Ported from Ghidra's `TraceObjectValueQuery` in
//! `ghidra.trace.database.target`. Provides hyper-box queries over the
//! multi-dimensional value storage (parent, child, entry key, snap, address).

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A dimension used in spatial queries over the value R*-tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QueryDimension {
    /// The parent object key dimension.
    ParentKey,
    /// The child object key dimension.
    ChildKey,
    /// The entry key (string) dimension.
    EntryKey,
    /// The snap (time) dimension.
    Snap,
    /// The address dimension.
    Address,
}

/// Direction of query traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HyperDirection {
    /// Default forward traversal.
    Default,
    /// Reverse traversal.
    Reverse,
}

/// A value triple used as a query bound (parent_key, child_key, entry_key, snap, address).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryBound {
    /// Parent object key.
    pub parent_key: i64,
    /// Child object key.
    pub child_key: i64,
    /// Entry key string.
    pub entry_key: String,
    /// Snap value.
    pub snap: i64,
    /// Address offset (packed as u64).
    pub address_offset: u64,
}

impl QueryBound {
    /// Create a new query bound.
    pub fn new(
        parent_key: i64,
        child_key: i64,
        entry_key: impl Into<String>,
        snap: i64,
        address_offset: u64,
    ) -> Self {
        Self {
            parent_key,
            child_key,
            entry_key: entry_key.into(),
            snap,
            address_offset,
        }
    }

    /// A minimum bound (all values at minimum).
    pub fn min() -> Self {
        Self {
            parent_key: i64::MIN,
            child_key: i64::MIN,
            entry_key: String::new(),
            snap: i64::MIN,
            address_offset: u64::MIN,
        }
    }

    /// A maximum bound (all values at maximum).
    pub fn max() -> Self {
        Self {
            parent_key: i64::MAX,
            child_key: i64::MAX,
            entry_key: String::new(),
            snap: i64::MAX,
            address_offset: u64::MAX,
        }
    }
}

/// A spatial query over the object value R*-tree.
///
/// Ported from Ghidra's `TraceObjectValueQuery`. Specifies a hyper-rectangular
/// region in the multi-dimensional value space to match against.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceObjectValueQuery {
    /// Lower bound of the query region.
    pub lower: QueryBound,
    /// Upper bound of the query region.
    pub upper: QueryBound,
    /// The traversal direction.
    pub direction: HyperDirection,
}

impl TraceObjectValueQuery {
    /// Create a new query with explicit bounds.
    pub fn new(lower: QueryBound, upper: QueryBound, direction: HyperDirection) -> Self {
        Self {
            lower,
            upper,
            direction,
        }
    }

    /// A query matching all values.
    pub fn all() -> Self {
        Self::new(
            QueryBound::min(),
            QueryBound::max(),
            HyperDirection::Default,
        )
    }

    /// Query for values of a specific parent object in a given lifespan.
    pub fn values_for_parent(parent_key: i64, lifespan: &Lifespan) -> Self {
        Self::new(
            QueryBound::new(
                parent_key,
                i64::MIN,
                "",         // empty string is lexicographic minimum
                lifespan.lmin(),
                u64::MIN,
            ),
            QueryBound::new(
                parent_key,
                i64::MAX,
                "\u{10FFFF}",  // maximum valid Unicode string
                lifespan.lmax(),
                u64::MAX,
            ),
            HyperDirection::Default,
        )
    }

    /// Query for values of a specific parent with entry key range and lifespan.
    pub fn values_for_parent_keyed(
        parent_key: i64,
        min_key: &str,
        max_key: &str,
        lifespan: &Lifespan,
    ) -> Self {
        Self::new(
            QueryBound::new(parent_key, i64::MIN, min_key, lifespan.lmin(), u64::MIN),
            QueryBound::new(parent_key, i64::MAX, max_key, lifespan.lmax(), u64::MAX),
            HyperDirection::Default,
        )
    }

    /// Query for canonical parents of a child object.
    pub fn canonical_parents(child_key: i64, entry_key: &str, lifespan: &Lifespan) -> Self {
        Self::new(
            QueryBound::new(
                i64::MIN,
                child_key,
                entry_key,
                lifespan.lmin(),
                u64::MIN,
            ),
            QueryBound::new(
                i64::MAX,
                child_key,
                entry_key,
                lifespan.lmax(),
                u64::MAX,
            ),
            HyperDirection::Default,
        )
    }

    /// Query for all parents of a child object.
    pub fn parents(child_key: i64, lifespan: &Lifespan) -> Self {
        Self::new(
            QueryBound::new(i64::MIN, child_key, "", lifespan.lmin(), u64::MIN),
            QueryBound::new(i64::MAX, child_key, "", lifespan.lmax(), u64::MAX),
            HyperDirection::Default,
        )
    }

    /// Query for values at a specific entry key, snap, and address.
    pub fn at(entry_key: &str, snap: i64, address_offset: u64) -> Self {
        Self::new(
            QueryBound::new(i64::MIN, i64::MIN, entry_key, snap, address_offset),
            QueryBound::new(i64::MAX, i64::MAX, entry_key, snap, address_offset),
            HyperDirection::Default,
        )
    }

    /// Query for values intersecting a key range, lifespan, and address range.
    pub fn intersecting(
        min_key: &str,
        max_key: &str,
        lifespan: &Lifespan,
        min_addr: u64,
        max_addr: u64,
    ) -> Self {
        Self::new(
            QueryBound::new(i64::MIN, i64::MIN, min_key, lifespan.lmin(), min_addr),
            QueryBound::new(i64::MAX, i64::MAX, max_key, lifespan.lmax(), max_addr),
            HyperDirection::Default,
        )
    }

    /// Test whether a value record matches this query.
    pub fn test_data(
        &self,
        parent_key: i64,
        child_key: i64,
        entry_key: &str,
        snap: i64,
        address_offset: u64,
    ) -> bool {
        parent_key >= self.lower.parent_key
            && parent_key <= self.upper.parent_key
            && child_key >= self.lower.child_key
            && child_key <= self.upper.child_key
            && entry_key >= self.lower.entry_key.as_str()
            && entry_key <= self.upper.entry_key.as_str()
            && snap >= self.lower.snap
            && snap <= self.upper.snap
            && address_offset >= self.lower.address_offset
            && address_offset <= self.upper.address_offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_all() {
        let q = TraceObjectValueQuery::all();
        assert_eq!(q.direction, HyperDirection::Default);
        assert_eq!(q.lower.parent_key, i64::MIN);
        assert_eq!(q.upper.parent_key, i64::MAX);
    }

    #[test]
    fn test_query_values_for_parent() {
        let q = TraceObjectValueQuery::values_for_parent(42, &Lifespan::span(0, 100));
        assert_eq!(q.lower.parent_key, 42);
        assert_eq!(q.upper.parent_key, 42);
        assert_eq!(q.lower.snap, 0);
        assert_eq!(q.upper.snap, 100);
    }

    #[test]
    fn test_query_values_for_parent_keyed() {
        let q = TraceObjectValueQuery::values_for_parent_keyed(
            10,
            "a",
            "z",
            &Lifespan::span(5, 50),
        );
        assert_eq!(q.lower.entry_key, "a");
        assert_eq!(q.upper.entry_key, "z");
    }

    #[test]
    fn test_query_canonical_parents() {
        let q = TraceObjectValueQuery::canonical_parents(42, "child_key", &Lifespan::span(0, 100));
        assert_eq!(q.lower.child_key, 42);
        assert_eq!(q.upper.child_key, 42);
        assert_eq!(q.lower.entry_key, "child_key");
    }

    #[test]
    fn test_query_parents() {
        let q = TraceObjectValueQuery::parents(42, &Lifespan::span(0, 100));
        assert_eq!(q.lower.child_key, 42);
    }

    #[test]
    fn test_query_at() {
        let q = TraceObjectValueQuery::at("name", 10, 0x1000);
        assert_eq!(q.lower.entry_key, "name");
        assert_eq!(q.lower.snap, 10);
        assert_eq!(q.lower.address_offset, 0x1000);
    }

    #[test]
    fn test_query_intersecting() {
        let q = TraceObjectValueQuery::intersecting("a", "z", &Lifespan::span(0, 100), 0, 0xFFFF);
        assert_eq!(q.lower.entry_key, "a");
        assert_eq!(q.upper.entry_key, "z");
        assert_eq!(q.lower.address_offset, 0);
        assert_eq!(q.upper.address_offset, 0xFFFF);
    }

    #[test]
    fn test_query_test_data() {
        let q = TraceObjectValueQuery::values_for_parent(10, &Lifespan::span(0, 100));
        assert!(q.test_data(10, 5, "name", 50, 0));
        assert!(!q.test_data(11, 5, "name", 50, 0)); // wrong parent
        assert!(!q.test_data(10, 5, "name", 150, 0)); // outside lifespan
    }

    #[test]
    fn test_query_bound_min_max() {
        let min = QueryBound::min();
        let max = QueryBound::max();
        assert_eq!(min.parent_key, i64::MIN);
        assert_eq!(max.parent_key, i64::MAX);
        assert_eq!(min.snap, i64::MIN);
        assert_eq!(max.snap, i64::MAX);
    }
}
