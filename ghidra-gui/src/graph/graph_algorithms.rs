//! High-level graph algorithm convenience methods.
//!
//! Ports `ghidra.graph.GraphAlgorithms`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;

use super::{GDirectedGraph, GEdge};

/// Graph direction for algorithms that operate in a specific direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphDirection {
    /// Follow outgoing edges (forward direction).
    Forward,
    /// Follow incoming edges (backward direction).
    Reverse,
}

/// Compute the set of dominators for each vertex in the graph.
///
/// A node `a` dominates node `b` if all paths from the entry to `b`
/// pass through `a`. The result maps each vertex to its set of dominators.
///
/// Ports the dominator computation from `GraphAlgorithms`.
pub fn compute_dominators<V, E, G>(graph: &G, entry: &V) -> HashMap<V, HashSet<V>>
where
    V: Eq + Hash + Clone,
    E: GEdge<V> + Clone,
    G: GDirectedGraph<V, E>,
{
    let all_verts: HashSet<V> = graph.vertices().into_iter().collect();

    // Initialize: entry dominates only itself.
    let mut doms: HashMap<V, HashSet<V>> = HashMap::new();
    for v in &all_verts {
        if v == entry {
            doms.insert(v.clone(), {
                let mut s = HashSet::new();
                s.insert(v.clone());
                s
            });
        } else {
            doms.insert(v.clone(), all_verts.clone());
        }
    }

    // Iterative dataflow until fixed point.
    let mut changed = true;
    while changed {
        changed = false;
        for v in &all_verts {
            if v == entry {
                continue;
            }
            let preds: Vec<V> = graph.predecessors(v);
            if preds.is_empty() {
                continue;
            }
            // Intersection of all predecessors' dominator sets.
            let mut new_dom: HashSet<V> = match doms.get(&preds[0]) {
                Some(s) => s.clone(),
                None => all_verts.clone(),
            };
            for p in &preds[1..] {
                if let Some(pdom) = doms.get(p) {
                    new_dom = new_dom.intersection(pdom).cloned().collect();
                }
            }
            // Add self.
            new_dom.insert(v.clone());

            if doms.get(v) != Some(&new_dom) {
                doms.insert(v.clone(), new_dom);
                changed = true;
            }
        }
    }

    doms
}

/// Compute the dominance frontier for each vertex.
///
/// The dominance frontier of a node `d` is the set of all nodes `w`
/// such that `d` dominates a predecessor of `w` but does not strictly
/// dominate `w` itself.
pub fn compute_dominance_frontiers<V, E, G>(
    graph: &G,
    doms: &HashMap<V, HashSet<V>>,
) -> HashMap<V, HashSet<V>>
where
    V: Eq + Hash + Clone,
    E: GEdge<V> + Clone,
    G: GDirectedGraph<V, E>,
{
    let mut frontiers: HashMap<V, HashSet<V>> = HashMap::new();

    for v in &graph.vertices() {
        frontiers.entry(v.clone()).or_default();
    }

    for v in &graph.vertices() {
        let preds = graph.predecessors(v);
        if preds.len() >= 2 {
            for p in &preds {
                let p_doms = match doms.get(p) {
                    Some(s) => s,
                    None => continue,
                };
                let mut runner = p.clone();
                loop {
                    if runner == *v || !p_doms.contains(&runner) {
                        break;
                    }
                    // runner != v and p dominates runner => runner is not the idom of v
                    // Actually, the standard algorithm: walk up the dominator tree from p
                    // until we reach a node that strictly dominates v or is v itself.
                    frontiers.entry(runner.clone()).or_default().insert(v.clone());
                    // Move to immediate dominator (simplified: use first dominator that
                    // is not runner itself).
                    let runner_doms = match doms.get(&runner) {
                        Some(s) => s,
                        None => break,
                    };
                    let mut found_idom = false;
                    for candidate in runner_doms.iter() {
                        if *candidate != runner
                            && runner_doms.contains(candidate)
                        {
                            // candidate dominates runner; check if it's closer
                            let cand_doms = match doms.get(candidate) {
                                Some(s) => s,
                                None => continue,
                            };
                            // candidate strictly dominates runner if runner in candidate's dom set
                            // and candidate != runner
                            if cand_doms.contains(&runner) {
                                runner = candidate.clone();
                                found_idom = true;
                                break;
                            }
                        }
                    }
                    if !found_idom {
                        break;
                    }
                }
            }
        }
    }

    frontiers
}

/// Compute the graph density: |E| / (|V| * (|V| - 1)).
///
/// Returns 0.0 for graphs with fewer than 2 vertices.
pub fn graph_density<V, E, G>(graph: &G) -> f64
where
    V: Eq + Hash + Clone,
    E: GEdge<V> + Clone,
    G: GDirectedGraph<V, E>,
{
    let v = graph.vertex_count() as f64;
    if v <= 1.0 {
        return 0.0;
    }
    let e = graph.edge_count() as f64;
    e / (v * (v - 1.0))
}

/// Compute the set of vertices reachable from the given start in the specified direction.
pub fn reachable_set<V, E, G>(
    graph: &G,
    start: &V,
    direction: GraphDirection,
) -> HashSet<V>
where
    V: Eq + Hash + Clone,
    E: GEdge<V> + Clone,
    G: GDirectedGraph<V, E>,
{
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(start.clone());
    visited.insert(start.clone());

    while let Some(current) = queue.pop_front() {
        let neighbors = match direction {
            GraphDirection::Forward => graph.successors(&current),
            GraphDirection::Reverse => graph.predecessors(&current),
        };
        for n in neighbors {
            if visited.insert(n.clone()) {
                queue.push_back(n);
            }
        }
    }

    visited
}

/// Find all source vertices (zero in-degree).
pub fn sources<V, E, G>(graph: &G) -> Vec<V>
where
    V: Eq + Hash + Clone,
    E: GEdge<V> + Clone,
    G: GDirectedGraph<V, E>,
{
    graph
        .vertices()
        .into_iter()
        .filter(|v| graph.in_degree(v) == 0)
        .collect()
}

/// Find all sink vertices (zero out-degree).
pub fn sinks<V, E, G>(graph: &G) -> Vec<V>
where
    V: Eq + Hash + Clone,
    E: GEdge<V> + Clone,
    G: GDirectedGraph<V, E>,
{
    graph
        .vertices()
        .into_iter()
        .filter(|v| graph.out_degree(v) == 0)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{DefaultDirectedGraph, DefaultGEdge};

    fn make_linear_graph() -> DefaultDirectedGraph<i32, DefaultGEdge<i32>> {
        let mut g = DefaultDirectedGraph::new();
        g.add_edge(DefaultGEdge::new(1, 2));
        g.add_edge(DefaultGEdge::new(2, 3));
        g.add_edge(DefaultGEdge::new(3, 4));
        g
    }

    #[test]
    fn test_dominators_linear() {
        let g = make_linear_graph();
        let doms = compute_dominators(&g, &1);
        // In a linear chain, each node is dominated by all predecessors + itself.
        assert!(doms.get(&1).unwrap().contains(&1));
        assert!(doms.get(&2).unwrap().contains(&1));
        assert!(doms.get(&2).unwrap().contains(&2));
        assert!(doms.get(&4).unwrap().contains(&1));
        assert!(doms.get(&4).unwrap().contains(&2));
        assert!(doms.get(&4).unwrap().contains(&3));
        assert!(doms.get(&4).unwrap().contains(&4));
    }

    #[test]
    fn test_dominators_diamond() {
        //    1
        //   / \
        //  2   3
        //   \ /
        //    4
        let mut g = DefaultDirectedGraph::new();
        g.add_edge(DefaultGEdge::new(1, 2));
        g.add_edge(DefaultGEdge::new(1, 3));
        g.add_edge(DefaultGEdge::new(2, 4));
        g.add_edge(DefaultGEdge::new(3, 4));

        let doms = compute_dominators(&g, &1);
        assert!(doms.get(&4).unwrap().contains(&1));
        // 2 and 3 do not dominate 4 (path via the other exists).
        assert!(!doms.get(&4).unwrap().contains(&2));
        assert!(!doms.get(&4).unwrap().contains(&3));
    }

    #[test]
    fn test_graph_density() {
        let g = make_linear_graph();
        let d = graph_density(&g);
        // 3 edges / (4 * 3) = 0.25
        assert!((d - 0.25).abs() < 1e-10);
    }

    #[test]
    fn test_reachable_forward() {
        let g = make_linear_graph();
        let r = reachable_set(&g, &2, GraphDirection::Forward);
        assert!(r.contains(&2));
        assert!(r.contains(&3));
        assert!(r.contains(&4));
        assert!(!r.contains(&1));
    }

    #[test]
    fn test_reachable_reverse() {
        let g = make_linear_graph();
        let r = reachable_set(&g, &3, GraphDirection::Reverse);
        assert!(r.contains(&1));
        assert!(r.contains(&2));
        assert!(r.contains(&3));
        assert!(!r.contains(&4));
    }

    #[test]
    fn test_sources_and_sinks() {
        let g = make_linear_graph();
        assert_eq!(sources(&g), vec![1]);
        assert_eq!(sinks(&g), vec![4]);
    }

    #[test]
    fn test_empty_graph() {
        let g = DefaultDirectedGraph::<i32, DefaultGEdge<i32>>::new();
        assert_eq!(graph_density(&g), 0.0);
        assert!(sources(&g).is_empty());
        assert!(sinks(&g).is_empty());
    }
}
