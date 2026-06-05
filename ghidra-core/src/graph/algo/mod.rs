//! Graph algorithms ported from Ghidra's `ghidra.graph.algo` package.
//!
//! Includes:
//! - [`GraphNavigator`] for direction-agnostic traversal
//! - [`DepthFirstSorter`] for pre-order and post-order DFS
//! - [`DijkstraShortestPaths`] for weighted shortest path computation
//! - [`JohnsonCircuitsAlgorithm`] for finding all elementary circuits
//! - [`find_paths_iterative`] and [`find_paths_recursive`] for path finding
//! - [`TarjanSCC`] for strongly-connected components on generic graphs
//! - [`ChkDominanceAlgorithm`] / [`ChkPostDominanceAlgorithm`] for dominance
//! - [`astar`] for A* search and topological sort

pub mod astar;
pub mod graph_navigator;
pub mod depth_first_sorter;
pub mod dijkstra;
pub mod johnson_circuits;
pub mod find_paths;
pub mod tarjan_scc;
pub mod chk_dominance;

pub use astar::{AStarSearch, AddressHeuristic, EuclideanHeuristic, find_sccs, topological_sort};
pub use graph_navigator::GraphNavigator;
pub use depth_first_sorter::DepthFirstSorter;
pub use dijkstra::DijkstraShortestPaths;
pub use johnson_circuits::JohnsonCircuitsAlgorithm;
pub use find_paths::{FindPathsAlgorithm, find_paths_iterative, find_paths_recursive};
pub use tarjan_scc::TarjanSCC;
pub use chk_dominance::{ChkDominanceAlgorithm, ChkPostDominanceAlgorithm};
