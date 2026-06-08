//! Grouping visual graph for vertex grouping support.
//!
//! Port of `ghidra.graph.graphs.GroupingVisualGraph`.


use crate::graph::visual_graph::{VisualEdge, VisualVertex};

/// A visual graph with support for vertex grouping.
///
/// Subclasses implement `find_matching_vertex` to allow graph
/// transformations that trigger vertex additions and removals while
/// maintaining group membership.
pub trait GroupingVisualGraph<V: VisualVertex, E: VisualEdge<V>>: Send + Sync {
    /// Find a vertex that matches the given vertex (may be a different instance).
    fn find_matching_vertex(&self, v: &V) -> Option<V>;

    /// Find a matching vertex, ignoring vertices in the given set.
    ///
    /// This is useful during graph transformations when duplicate vertices
    /// may be in the graph at the same time.
    fn find_matching_vertex_ignoring(&self, v: &V, ignore: &[V]) -> Option<V>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::default_edge::DefaultGEdge;
    use crate::graph::visual_graph::Point2D;

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct V {
        id: u32,
        group: u32,
        loc: Point2D,
    }
    impl VisualVertex for V {
        fn get_location(&self) -> Point2D {
            self.loc
        }
        fn set_location(&mut self, loc: Point2D) {
            self.loc = loc;
        }
    }

    struct TestGroupGraph {
        vertices: Vec<V>,
    }

    impl GroupingVisualGraph<V, DefaultGEdge<V>> for TestGroupGraph {
        fn find_matching_vertex(&self, v: &V) -> Option<V> {
            self.vertices
                .iter()
                .find(|tv| tv.group == v.group)
                .cloned()
        }

        fn find_matching_vertex_ignoring(&self, v: &V, ignore: &[V]) -> Option<V> {
            self.vertices
                .iter()
                .find(|tv| tv.group == v.group && !ignore.contains(tv))
                .cloned()
        }
    }

    #[test]
    fn test_find_matching() {
        let g = TestGroupGraph {
            vertices: vec![
                V { id: 1, group: 10, loc: Point2D::new(0.0, 0.0) },
                V { id: 2, group: 20, loc: Point2D::new(10.0, 0.0) },
            ],
        };
        let query = V { id: 99, group: 10, loc: Point2D::new(0.0, 0.0) };
        let found = g.find_matching_vertex(&query);
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, 1);
    }

    #[test]
    fn test_find_matching_not_found() {
        let g = TestGroupGraph {
            vertices: vec![
                V { id: 1, group: 10, loc: Point2D::new(0.0, 0.0) },
            ],
        };
        let query = V { id: 99, group: 99, loc: Point2D::new(0.0, 0.0) };
        assert!(g.find_matching_vertex(&query).is_none());
    }

    #[test]
    fn test_find_matching_ignoring() {
        let g = TestGroupGraph {
            vertices: vec![
                V { id: 1, group: 10, loc: Point2D::new(0.0, 0.0) },
                V { id: 2, group: 10, loc: Point2D::new(10.0, 0.0) },
            ],
        };
        let query = V { id: 99, group: 10, loc: Point2D::new(0.0, 0.0) };
        let ignore = vec![V { id: 1, group: 10, loc: Point2D::new(0.0, 0.0) }];
        let found = g.find_matching_vertex_ignoring(&query, &ignore);
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, 2);
    }

    #[test]
    fn test_find_matching_ignoring_all() {
        let g = TestGroupGraph {
            vertices: vec![
                V { id: 1, group: 10, loc: Point2D::new(0.0, 0.0) },
            ],
        };
        let query = V { id: 99, group: 10, loc: Point2D::new(0.0, 0.0) };
        let ignore = vec![V { id: 1, group: 10, loc: Point2D::new(0.0, 0.0) }];
        assert!(g.find_matching_vertex_ignoring(&query, &ignore).is_none());
    }
}
