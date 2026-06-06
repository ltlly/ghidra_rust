//! Port of `DijkstraShortestPathsAlgorithm`.
use std::collections::HashMap;
/// Struct porting `DijkstraShortestPathsAlgorithm`.
#[derive(Debug, Clone)]
pub struct DijkstraShortestPathsAlgorithm {
    /// max_distance.
    pub max_distance: f64,
    /// metric.
    pub metric: String,
    /// source.
    pub source: String,
}

impl DijkstraShortestPathsAlgorithm {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for DijkstraShortestPathsAlgorithm {
    fn default() -> Self {
        Self {
            max_distance: 0,
            metric: String::new(),
            source: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_dijkstra_shortest_paths_algorithm_new() { let _ = DijkstraShortestPathsAlgorithm::new(); }
}
