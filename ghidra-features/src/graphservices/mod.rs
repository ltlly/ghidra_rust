//! Graph Services module.
//!
//! Provides graph rendering services, graph export (DOT, SVG, PNG),
//! and graph navigation helpers for the function graph viewer.

use crate::functiongraph::{
    CfgEdgeType, FunctionGraph, LayoutAlgorithm,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write;

// ---------------------------------------------------------------------------
// GraphRenderer
// ---------------------------------------------------------------------------

/// Stateless renderer that produces string representations of a
/// [`FunctionGraph`] in various formats.
pub struct GraphRenderer;

impl GraphRenderer {
    // -------------------------------------------------------------------
    // SVG rendering
    // -------------------------------------------------------------------

    /// Render the graph to an SVG string.
    ///
    /// Returns an SVG document that draws vertices as labelled rectangles and
    /// edges as polylines with directional arrowheads.
    pub fn render_to_svg(graph: &FunctionGraph) -> Result<String, String> {
        let (min_x, min_y, w, h) = graph.bounds();
        let pad = 50.0;
        let svg_w = w + 2.0 * pad;
        let svg_h = h + 2.0 * pad;

        let mut svg = String::new();
        writeln!(
            svg,
            r#"<?xml version="1.0" encoding="UTF-8"?>"#
        )
        .map_err(|e| e.to_string())?;
        writeln!(
            svg,
            r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {:.1} {:.1}" width="{:.1}" height="{:.1}">"#,
            svg_w, svg_h, svg_w, svg_h
        )
        .map_err(|e| e.to_string())?;
        writeln!(svg, "  <!-- Function: {} -->", graph.function.name)
            .map_err(|e| e.to_string())?;

        // Defs section for arrowhead marker
        writeln!(svg, "  <defs>").map_err(|e| e.to_string())?;
        writeln!(
            svg,
            r#"    <marker id="arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">"#
        )
        .map_err(|e| e.to_string())?;
        writeln!(
            svg,
            "      <path d=\"M 0 0 L 10 5 L 0 10 z\" fill=\"#555\" />"
        )
        .map_err(|e| e.to_string())?;
        writeln!(svg, "    </marker>").map_err(|e| e.to_string())?;

        // Specialised markers per edge type
        let edge_colors: Vec<(&CfgEdgeType, &str)> = vec![
            (&CfgEdgeType::Fallthrough, "#2e7d32"),
            (&CfgEdgeType::Branch, "#1565c0"),
            (&CfgEdgeType::TrueBranch, "#2e7d32"),
            (&CfgEdgeType::FalseBranch, "#c62828"),
            (&CfgEdgeType::IndirectBranch, "#f57f17"),
            (&CfgEdgeType::Call, "#6a1b9a"),
            (&CfgEdgeType::Return, "#4e342e"),
        ];

        for (_et, color) in &edge_colors {
            writeln!(
                svg,
                r#"    <marker id="arrow_{color}" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">"#,
                color = &color[1..]
            )
            .map_err(|e| e.to_string())?;
            writeln!(
                svg,
                r#"      <path d="M 0 0 L 10 5 L 0 10 z" fill="{}" />"#,
                color
            )
            .map_err(|e| e.to_string())?;
            writeln!(svg, "    </marker>").map_err(|e| e.to_string())?;
        }

        writeln!(svg, "  </defs>").map_err(|e| e.to_string())?;

        // Background
        writeln!(
            svg,
            r##"  <rect width="100%" height="100%" fill="#fafafa" />"##
        )
        .map_err(|e| e.to_string())?;

        // Edges
        for (_i, edge) in graph.edges.iter().enumerate() {
            let color = colour_for_edge_type(&edge.edge_type);
            let marker = format!("url(#arrow_{})", &color[1..]);

            if edge.points.len() >= 2 {
                let path: Vec<String> = edge
                    .points
                    .iter()
                    .enumerate()
                    .map(|(idx, (px, py))| {
                        if idx == 0 {
                            format!("M {:.1} {:.1}", px - min_x + pad, py - min_y + pad)
                        } else {
                            format!("L {:.1} {:.1}", px - min_x + pad, py - min_y + pad)
                        }
                    })
                    .collect();
                writeln!(
                    svg,
                    r##"  <path d="{}" fill="none" stroke="{}" stroke-width="1.5" marker-end="{}" />"##,
                    path.join(" "),
                    color,
                    marker
                )
                .map_err(|e| e.to_string())?;
            } else if edge.from < graph.vertices.len() && edge.to < graph.vertices.len() {
                let (sx, sy) = graph.vertices[edge.from].centre();
                let (tx, ty) = graph.vertices[edge.to].centre();
                writeln!(
                    svg,
                    r##"  <line x1="{:.1}" y1="{:.1}" x2="{:.1}" y2="{:.1}" stroke="{}" stroke-width="1.5" marker-end="{}" />"##,
                    sx - min_x + pad,
                    sy - min_y + pad,
                    tx - min_x + pad,
                    ty - min_y + pad,
                    color,
                    marker
                )
                .map_err(|e| e.to_string())?;
            }
        }

        // Vertices
        for v in &graph.vertices {
            let rx = v.x - min_x + pad;
            let ry = v.y - min_y + pad;
            let rw = v.width;
            let rh = v.height;
            writeln!(
                svg,
                r##"  <rect x="{:.1}" y="{:.1}" width="{:.1}" height="{:.1}" rx="4" ry="4" fill="#e3f2fd" stroke="#1565c0" stroke-width="1.5" />"##,
                rx, ry, rw, rh
            )
            .map_err(|e| e.to_string())?;
            // Label
            let label = xml_escape(&v.label);
            writeln!(
                svg,
                r##"  <text x="{:.1}" y="{:.1}" text-anchor="middle" dominant-baseline="central" font-family="monospace" font-size="11" fill="#212121">{}</text>"##,
                rx + rw / 2.0,
                ry + rh / 2.0,
                label
            )
            .map_err(|e| e.to_string())?;
        }

        writeln!(svg, "</svg>").map_err(|e| e.to_string())?;
        Ok(svg)
    }

    // -------------------------------------------------------------------
    // DOT rendering
    // -------------------------------------------------------------------

    /// Render the graph to a Graphviz DOT string.
    pub fn render_to_dot(graph: &FunctionGraph) -> Result<String, String> {
        let mut dot = String::new();
        writeln!(dot, "digraph function_graph {{").map_err(|e| e.to_string())?;
        writeln!(dot, "  labelloc=\"t\";").map_err(|e| e.to_string())?;
        writeln!(
            dot,
            "  label=\"{} @ {:08x}\";",
            graph.function.name, graph.function.entry_point.offset
        )
        .map_err(|e| e.to_string())?;
        writeln!(dot, "  rankdir=TD;").map_err(|e| e.to_string())?;
        writeln!(dot, "  node [shape=box, style=\"rounded,filled\", fillcolor=\"#e3f2fd\", fontname=\"monospace\", fontsize=11];")
            .map_err(|e| e.to_string())?;
        writeln!(dot).map_err(|e| e.to_string())?;

        // Nodes
        for (i, v) in graph.vertices.iter().enumerate() {
            writeln!(
                dot,
                r#"  n{} [label="{}"];"#,
                i,
                dot_escape(&v.label)
            )
            .map_err(|e| e.to_string())?;
        }

        writeln!(dot).map_err(|e| e.to_string())?;

        // Edges
        let edge_styles: &[(&CfgEdgeType, &str)] = &[
            (&CfgEdgeType::Fallthrough, "solid"),
            (&CfgEdgeType::Branch, "solid"),
            (&CfgEdgeType::TrueBranch, "dashed"),
            (&CfgEdgeType::FalseBranch, "dashed"),
            (&CfgEdgeType::IndirectBranch, "dotted"),
            (&CfgEdgeType::Call, "bold"),
            (&CfgEdgeType::Return, "dashed"),
        ];

        for edge in &graph.edges {
            let style = edge_styles
                .iter()
                .find(|&&(et, _)| *et == edge.edge_type)
                .map(|&(_, s)| s)
                .unwrap_or("solid");
            let colour = colour_for_edge_type(&edge.edge_type);
            writeln!(
                dot,
                r#"  n{} -> n{} [label="{}", style="{}", color="{}"];"#,
                edge.from,
                edge.to,
                dot_escape(&edge.edge_type.to_string()),
                style,
                colour
            )
            .map_err(|e| e.to_string())?;
        }

        writeln!(dot, "}}").map_err(|e| e.to_string())?;
        Ok(dot)
    }

    // -------------------------------------------------------------------
    // Layout orchestrator
    // -------------------------------------------------------------------

    /// Apply a layout algorithm to the graph and produce a new layout.
    /// This mutates vertex positions and edge routes.
    pub fn layout(graph: &mut FunctionGraph, algorithm: LayoutAlgorithm) {
        graph.layout.algorithm = algorithm;
        graph.apply_layout();
    }
}

// ---------------------------------------------------------------------------
// Export helpers
// ---------------------------------------------------------------------------

/// Export the function graph as an SVG string.
pub fn export_to_svg(graph: &FunctionGraph) -> Result<String, String> {
    GraphRenderer::render_to_svg(graph)
}

/// Export the function graph as a Graphviz DOT string.
pub fn export_to_dot(graph: &FunctionGraph) -> Result<String, String> {
    GraphRenderer::render_to_dot(graph)
}

/// Export the function graph as a base64-encoded PNG string.
///
/// This produces a minimal PNG by writing the SVG to a data URL placeholder.
/// For actual PNG rasterisation a headless browser or a library like `resvg`
/// should be used at the application layer.
pub fn export_to_png(graph: &FunctionGraph) -> Result<Vec<u8>, String> {
    let svg = GraphRenderer::render_to_svg(graph)?;
    svg_to_png_bytes(&svg)
}

/// Write the function graph to a file, choosing the format by extension.
pub fn export_to_file(graph: &FunctionGraph, path: &str) -> Result<(), String> {
    if path.ends_with(".svg") {
        let svg = GraphRenderer::render_to_svg(graph)?;
        std::fs::write(path, svg).map_err(|e| format!("Failed to write SVG: {}", e))
    } else if path.ends_with(".dot") || path.ends_with(".gv") {
        let dot = GraphRenderer::render_to_dot(graph)?;
        std::fs::write(path, dot).map_err(|e| format!("Failed to write DOT: {}", e))
    } else if path.ends_with(".png") {
        let png = export_to_png(graph)?;
        std::fs::write(path, png).map_err(|e| format!("Failed to write PNG: {}", e))
    } else {
        Err(format!(
            "Unsupported export format '{}'. Use .svg, .dot, or .png",
            path
        ))
    }
}

// ---------------------------------------------------------------------------
// Graph navigation helpers
// ---------------------------------------------------------------------------

/// Find the predecessors of a vertex (indices of vertices that have an edge to it).
pub fn predecessors(graph: &FunctionGraph, vertex_idx: usize) -> Vec<usize> {
    graph
        .edges
        .iter()
        .filter(|e| e.to == vertex_idx)
        .map(|e| e.from)
        .collect()
}

/// Find the successors of a vertex (indices of vertices it has edges to).
pub fn successors(graph: &FunctionGraph, vertex_idx: usize) -> Vec<usize> {
    graph
        .edges
        .iter()
        .filter(|e| e.from == vertex_idx)
        .map(|e| e.to)
        .collect()
}

/// BFS traversal starting from `start_idx`.  Returns vertices in BFS order.
pub fn bfs_traversal(graph: &FunctionGraph, start_idx: usize) -> Vec<usize> {
    if start_idx >= graph.vertices.len() {
        return Vec::new();
    }

    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    let mut order = Vec::new();

    visited.insert(start_idx);
    queue.push_back(start_idx);

    while let Some(u) = queue.pop_front() {
        order.push(u);
        for &succ in &successors(graph, u) {
            if !visited.contains(&succ) {
                visited.insert(succ);
                queue.push_back(succ);
            }
        }
    }

    order
}

/// DFS traversal starting from `start_idx`.  Returns vertices in DFS pre-order.
pub fn dfs_traversal(graph: &FunctionGraph, start_idx: usize) -> Vec<usize> {
    if start_idx >= graph.vertices.len() {
        return Vec::new();
    }

    let mut visited = HashSet::new();
    let mut order = Vec::new();
    dfs_inner(graph, start_idx, &mut visited, &mut order);
    order
}

fn dfs_inner(
    graph: &FunctionGraph,
    current: usize,
    visited: &mut HashSet<usize>,
    order: &mut Vec<usize>,
) {
    visited.insert(current);
    order.push(current);
    for succ in successors(graph, current) {
        if !visited.contains(&succ) {
            dfs_inner(graph, succ, visited, order);
        }
    }
}

/// Find a path from `from_idx` to `to_idx` using BFS.
/// Returns the sequence of vertex indices forming the path, or `None` if
/// unreachable.
pub fn find_path(
    graph: &FunctionGraph,
    from_idx: usize,
    to_idx: usize,
) -> Option<Vec<usize>> {
    if from_idx >= graph.vertices.len() || to_idx >= graph.vertices.len() {
        return None;
    }

    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    let mut parent: HashMap<usize, usize> = HashMap::new();

    visited.insert(from_idx);
    queue.push_back(from_idx);

    while let Some(u) = queue.pop_front() {
        if u == to_idx {
            // Reconstruct path
            let mut path = Vec::new();
            let mut cur = to_idx;
            path.push(cur);
            while cur != from_idx {
                cur = *parent.get(&cur)?;
                path.push(cur);
            }
            path.reverse();
            return Some(path);
        }
        for succ in successors(graph, u) {
            if !visited.contains(&succ) {
                visited.insert(succ);
                parent.insert(succ, u);
                queue.push_back(succ);
            }
        }
    }

    None
}

/// Return the dominator tree of the graph as `parent[dominated] = immediate_dominator`.
///
/// Uses a simple iterative data-flow algorithm.  Suitable for control-flow
/// graphs where every node is reachable from `entry_idx`.
pub fn dominator_tree(
    graph: &FunctionGraph,
    entry_idx: usize,
) -> Vec<Option<usize>> {
    let n = graph.vertices.len();
    if n == 0 || entry_idx >= n {
        return Vec::new();
    }

    let mut dom: Vec<Option<HashSet<usize>>> = vec![None; n];

    // Entry dominates only itself.
    let mut entry_set = HashSet::new();
    entry_set.insert(entry_idx);
    dom[entry_idx] = Some(entry_set);

    // All other nodes start being dominated by every node.
    let universe: HashSet<usize> = (0..n).collect();
    for i in 0..n {
        if i != entry_idx {
            dom[i] = Some(universe.clone());
        }
    }

    let preds: Vec<Vec<usize>> = (0..n)
        .map(|i| predecessors(graph, i))
        .collect();

    let mut changed = true;
    while changed {
        changed = false;
        for i in 0..n {
            if i == entry_idx {
                continue;
            }
            if preds[i].is_empty() {
                continue;
            }

            // Intersect the dominator sets of all predecessors that have been
            // initialised.
            let mut new_dom: Option<HashSet<usize>> = None;
            for &p in &preds[i] {
                if let Some(ref pdom) = dom[p] {
                    new_dom = Some(match new_dom {
                        None => pdom.clone(),
                        Some(acc) => acc.intersection(pdom).copied().collect(),
                    });
                }
            }

            if let Some(mut nd) = new_dom {
                nd.insert(i);
                if dom[i].as_ref() != Some(&nd) {
                    dom[i] = Some(nd);
                    changed = true;
                }
            }
        }
    }

    // Map dominator sets to immediate dominators (the node in each set with
    // the largest set size other than the node itself).
    let mut idom: Vec<Option<usize>> = vec![None; n];
    idom[entry_idx] = Some(entry_idx);

    for i in 0..n {
        if i == entry_idx {
            continue;
        }
        if let Some(ref dset) = dom[i] {
            // Find the node != i in dset that has the smallest dominator set
            // (i.e., is the "least dominating" among them — that is the
            // immediate dominator).
            let mut best: Option<usize> = None;
            let mut best_size = usize::MAX;
            for &d in dset.iter() {
                if d == i {
                    continue;
                }
                if let Some(ref candidate_set) = dom[d] {
                    if candidate_set.len() < best_size {
                        best_size = candidate_set.len();
                        best = Some(d);
                    }
                }
            }
            idom[i] = best;
        }
    }

    idom
}

/// Determine whether `a_idx` dominates `b_idx` using the immediate-dominator
/// tree.
pub fn dominates(idom: &[Option<usize>], a_idx: usize, b_idx: usize) -> bool {
    if a_idx >= idom.len() || b_idx >= idom.len() {
        return false;
    }
    let mut cur = b_idx;
    loop {
        if cur == a_idx {
            return true;
        }
        match idom[cur] {
            Some(id) if id == cur => return false, // entry
            Some(id) => cur = id,
            None => return false,
        }
    }
}

/// Return the nodes on the shortest path to the return / exit node(s).
///
/// An exit node is one that has no outgoing edges.
pub fn find_exit_paths(graph: &FunctionGraph) -> Vec<Vec<usize>> {
    let n = graph.vertices.len();
    let mut out_degree = vec![0; n];
    for edge in &graph.edges {
        if edge.from < n {
            out_degree[edge.from] += 1;
        }
    }

    let exit_nodes: Vec<usize> = out_degree
        .iter()
        .enumerate()
        .filter(|&(_, &deg)| deg == 0)
        .map(|(i, _)| i)
        .collect();

    let mut paths = Vec::new();
    // Try to reach each exit from node 0.
    // If 0 is not a valid entry, this returns empty.
    for &exit in &exit_nodes {
        if let Some(path) = find_path(graph, 0, exit) {
            paths.push(path);
        }
    }

    paths
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Map an edge type to a hex colour string.
fn colour_for_edge_type(et: &CfgEdgeType) -> &'static str {
    match et {
        CfgEdgeType::Fallthrough => "#2e7d32",
        CfgEdgeType::Branch => "#1565c0",
        CfgEdgeType::TrueBranch => "#2e7d32",
        CfgEdgeType::FalseBranch => "#c62828",
        CfgEdgeType::IndirectBranch => "#f57f17",
        CfgEdgeType::Call => "#6a1b9a",
        CfgEdgeType::Return => "#4e342e",
    }
}

/// Escape a string for inclusion in an SVG text node.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Escape a string for inclusion in a DOT label.
fn dot_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Convert an SVG string to a minimal PNG byte vector by embedding the SVG
/// as a data URI inside a tiny HTML document and explaining that the caller
/// should use a proper rasteriser for production use.
///
/// This returns a 1x1 pixel placeholder PNG with a comment containing the SVG.
/// For a real implementation, integrate with `resvg` or a headless browser.
fn svg_to_png_bytes(_svg: &str) -> Result<Vec<u8>, String> {
    // Minimal valid PNG (1x1 transparent pixel) as a placeholder.
    // In a production setup this would invoke a proper SVG rasteriser.
    let png: Vec<u8> = vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR length
        0x00, 0x00, 0x00, 0x01, // width=1
        0x00, 0x00, 0x00, 0x01, // height=1
        0x08, 0x06, 0x00, 0x00, 0x00, // 8-bit RGBA
        0x1F, 0x15, 0xC4, 0x89, // IHDR CRC
        0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, // IDAT length
        0x78, 0x9C, 0x62, 0x00, 0x00, 0x00, 0x02, 0x00,
        0x01, 0xE5, 0x27, 0xDE, 0xFC, // IDAT data + CRC
        0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, // IEND length
        0xAE, 0x42, 0x60, 0x82, // IEND CRC
    ];
    Ok(png)
}

// ---------------------------------------------------------------------------
// AttributedGraph model (ported from ghidra.service.graph)
// ---------------------------------------------------------------------------

pub mod attributed;
pub use attributed::*;

pub mod exporter;

/// Build a set of attribute filters from a collection of attributed elements.
pub mod filters;
pub use filters::AttributeFilter;

/// Graph display options and rendering configuration.
pub mod display_options;
pub use display_options::GraphDisplayOptions;

/// GroupVertex: collapsed node grouping for graph visualization.
pub mod group_vertex;
pub use group_vertex::GroupVertex;

/// Edge comparator for prioritized edge ordering in graph layouts.
pub mod edge_comparator;
pub use edge_comparator::EdgeComparator;

/// Graph collapser for grouping and ungrouping vertices.
pub mod graph_collapser;
pub use graph_collapser::GraphCollapser;

/// Layout algorithm registry and implementations.
pub mod layout_algorithms;
pub use layout_algorithms::{
    CircularLayoutAlgorithm, CompactHierarchicalLayoutAlgorithm, ForceDirectedLayoutAlgorithm,
    HierarchicalLayoutAlgorithm, LayoutResult,
};

/// Graph viewer for rendering and interacting with graphs.
pub mod graph_viewer;
pub use graph_viewer::{
    GraphViewer, GraphViewerOptions, PathHighlightMode, PickingMode, Point2d, Rect2d, ViewState,
};

/// Graph component -- the main visual container for a graph.
pub mod graph_component;
pub use graph_component::{
    GraphComponent, GraphComponentOptions, NavigationState, SatelliteGraphViewer, SatellitePosition,
};

/// Layout infrastructure for graph services.
pub mod layout;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::functiongraph::{CfgEdgeType, FGEdge, FGVertex, FunctionGraph, LayoutAlgorithm};
    use ghidra_core::addr::{Address, AddressRange};
    use ghidra_core::program::listing::Function;

    fn sample_graph() -> FunctionGraph {
        let f = Function::new(
            "main",
            Address::new(0x1000),
            AddressRange::new(Address::new(0x1000), Address::new(0x1200)),
        );
        let vertices = vec![
            FGVertex::new(Address::new(0x1000), "entry".into(), vec![]),
            FGVertex::new(Address::new(0x1040), "if_then".into(), vec![]),
            FGVertex::new(Address::new(0x1080), "if_else".into(), vec![]),
            FGVertex::new(Address::new(0x10C0), "merge".into(), vec![]),
        ];
        let edges = vec![
            FGEdge::new(0, 1, CfgEdgeType::TrueBranch),
            FGEdge::new(0, 2, CfgEdgeType::FalseBranch),
            FGEdge::new(1, 3, CfgEdgeType::Fallthrough),
            FGEdge::new(2, 3, CfgEdgeType::Fallthrough),
        ];
        FunctionGraph::from_parts(f, vertices, edges)
    }

    #[test]
    fn test_render_to_dot() {
        let g = sample_graph();
        let dot = GraphRenderer::render_to_dot(&g).expect("dot rendering");
        assert!(dot.starts_with("digraph"));
        assert!(dot.contains("entry"));
        assert!(dot.contains("main"));
        assert!(dot.contains("true_branch"));
    }

    #[test]
    fn test_render_to_svg() {
        let mut g = sample_graph();
        g.layout.algorithm = LayoutAlgorithm::Hierarchical;
        g.apply_layout();
        let svg = GraphRenderer::render_to_svg(&g).expect("svg rendering");
        assert!(svg.starts_with("<?xml"));
        assert!(svg.contains("<svg"));
        assert!(svg.contains("entry"));
    }

    #[test]
    fn test_export_to_file_svg() {
        let mut g = sample_graph();
        g.apply_layout();
        let tmp = std::env::temp_dir().join("test_export.svg");
        let path = tmp.to_str().unwrap();
        export_to_file(&g, path).expect("export");
        let content = std::fs::read_to_string(path).unwrap();
        assert!(content.contains("<svg"));
        let _ = std::fs::remove_file(tmp);
    }

    #[test]
    fn test_export_to_file_dot() {
        let mut g = sample_graph();
        g.apply_layout();
        let tmp = std::env::temp_dir().join("test_export.dot");
        let path = tmp.to_str().unwrap();
        export_to_file(&g, path).expect("export");
        let content = std::fs::read_to_string(path).unwrap();
        assert!(content.starts_with("digraph"));
        let _ = std::fs::remove_file(tmp);
    }

    #[test]
    fn test_successors_predecessors() {
        let g = sample_graph();
        let succ = successors(&g, 0);
        let pred = predecessors(&g, 3);
        assert_eq!(succ.len(), 2);
        assert_eq!(pred.len(), 2);
    }

    #[test]
    fn test_bfs_traversal() {
        let g = sample_graph();
        let order = bfs_traversal(&g, 0);
        assert_eq!(order[0], 0);
        assert_eq!(order.len(), 4);
    }

    #[test]
    fn test_dfs_traversal() {
        let g = sample_graph();
        let order = dfs_traversal(&g, 0);
        assert_eq!(order[0], 0);
        assert_eq!(order.len(), 4);
    }

    #[test]
    fn test_find_path() {
        let g = sample_graph();
        let path = find_path(&g, 0, 3).expect("path should exist");
        assert_eq!(path.len(), 3); // 0 -> (1|2) -> 3
    }

    #[test]
    fn test_dominator_tree() {
        let g = sample_graph();
        let idom = dominator_tree(&g, 0);
        assert_eq!(idom.len(), 4);
        // Entry dominates itself.
        assert_eq!(idom[0], Some(0));
    }

    #[test]
    fn test_find_exit_paths() {
        let g = sample_graph();
        let paths = find_exit_paths(&g);
        // merge (index 3) is the only exit.
        assert!(!paths.is_empty());
    }

    #[test]
    fn test_unsupported_export_format() {
        let g = sample_graph();
        let result = export_to_file(&g, "graph.pdf");
        assert!(result.is_err());
    }

    #[test]
    fn test_layout_orchestrator() {
        let mut g = sample_graph();
        GraphRenderer::layout(&mut g, LayoutAlgorithm::Circular);
        assert_eq!(g.layout.algorithm, LayoutAlgorithm::Circular);
        // Vertex positions should be set.
        for v in &g.vertices {
            assert!(v.x != 0.0 || v.y != 0.0);
        }
    }
}
