//! Graph exporters.
//!
//! Ported from Ghidra's `ghidra.graph.exporter` Java package.
//!
//! Each exporter serializes an [`AttributedGraph`] into a specific file
//! format. Supported formats:
//!
//! - DOT (Graphviz)
//! - JSON
//! - CSV edge list
//! - CSV adjacency list
//! - GML
//! - GraphML
//! - DIMACS
//! - Matrix (adjacency matrix)

use super::attributed::{Attributed, AttributedGraph};
use std::collections::HashMap;
use std::fmt::Write;
use std::fs;
use std::path::Path;

/// Trait for graph exporters.
pub trait GraphExporter: Send + Sync {
    /// Export the graph to the given file path.
    fn export(&self, graph: &AttributedGraph, path: &Path) -> std::io::Result<()>;

    /// Export the graph to a String.
    fn export_to_string(&self, graph: &AttributedGraph) -> std::io::Result<String>;

    /// The file extension for this format (e.g. "dot", "json", "csv").
    fn file_extension(&self) -> &str;

    /// The human-readable name of this export format.
    fn name(&self) -> &str;

    /// A description of this export format.
    fn description(&self) -> &str;
}

// ---------------------------------------------------------------------------
// DOT (Graphviz)
// ---------------------------------------------------------------------------

/// Export a graph in DOT (Graphviz) format.
pub struct DotGraphExporter;

impl GraphExporter for DotGraphExporter {
    fn export(&self, graph: &AttributedGraph, path: &Path) -> std::io::Result<()> {
        let content = self.export_to_string(graph)?;
        fs::write(path, content)
    }

    fn export_to_string(&self, graph: &AttributedGraph) -> std::io::Result<String> {
        let mut out = String::new();
        writeln!(out, "digraph \"{}\" {{", graph.name()).unwrap();

        for v in graph.vertices() {
            write!(out, "  \"{}\"", v.id()).unwrap();
            let attrs = format_dot_attrs(v.attributes());
            if !attrs.is_empty() {
                write!(out, " [{}]", attrs).unwrap();
            }
            writeln!(out, ";").unwrap();
        }

        for e in graph.edges() {
            write!(out, "  \"{}\" -> \"{}\"", e.source_id(), e.target_id()).unwrap();
            let attrs = format_dot_attrs(e.attributes());
            if !attrs.is_empty() {
                write!(out, " [{}]", attrs).unwrap();
            }
            writeln!(out, ";").unwrap();
        }

        writeln!(out, "}}").unwrap();
        Ok(out)
    }

    fn file_extension(&self) -> &str { "dot" }
    fn name(&self) -> &str { "DOT" }
    fn description(&self) -> &str { "Graphviz DOT format" }
}

fn format_dot_attrs(attrs: &HashMap<String, String>) -> String {
    // Rename "Name" to "label" for DOT
    let parts: Vec<String> = attrs
        .iter()
        .map(|(k, v)| {
            let key = if k == "Name" { "label" } else { k };
            format!("{}=\"{}\"", key, escape_dot(v))
        })
        .collect();
    parts.join(", ")
}

fn escape_dot(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

/// Export a graph in JSON format.
pub struct JsonGraphExporter;

impl GraphExporter for JsonGraphExporter {
    fn export(&self, graph: &AttributedGraph, path: &Path) -> std::io::Result<()> {
        let content = self.export_to_string(graph)?;
        fs::write(path, content)
    }

    fn export_to_string(&self, graph: &AttributedGraph) -> std::io::Result<String> {
        let mut out = String::new();
        writeln!(out, "{{").unwrap();
        writeln!(out, "  \"name\": \"{}\",", escape_json(graph.name())).unwrap();
        writeln!(
            out,
            "  \"type\": \"{}\",",
            escape_json(graph.graph_type())
        )
        .unwrap();

        // Vertices
        writeln!(out, "  \"vertices\": [").unwrap();
        let verts: Vec<_> = graph.vertices().collect();
        for (i, v) in verts.iter().enumerate() {
            write!(out, "    {{\"id\": \"{}\"", escape_json(v.id())).unwrap();
            for (key, val) in v.attributes() {
                write!(out, ", \"{}\": \"{}\"", escape_json(key), escape_json(val)).unwrap();
            }
            if i < verts.len() - 1 {
                writeln!(out, "}},").unwrap();
            } else {
                writeln!(out, "}}").unwrap();
            }
        }
        writeln!(out, "  ],").unwrap();

        // Edges
        writeln!(out, "  \"edges\": [").unwrap();
        let edgs: Vec<_> = graph.edges().collect();
        for (i, e) in edgs.iter().enumerate() {
            write!(
                out,
                "    {{\"id\": \"{}\", \"source\": \"{}\", \"target\": \"{}\"",
                escape_json(e.id()),
                escape_json(e.source_id()),
                escape_json(e.target_id())
            )
            .unwrap();
            for (key, val) in e.attributes() {
                write!(out, ", \"{}\": \"{}\"", escape_json(key), escape_json(val)).unwrap();
            }
            if i < edgs.len() - 1 {
                writeln!(out, "}},").unwrap();
            } else {
                writeln!(out, "}}").unwrap();
            }
        }
        writeln!(out, "  ]").unwrap();
        writeln!(out, "}}").unwrap();
        Ok(out)
    }

    fn file_extension(&self) -> &str { "json" }
    fn name(&self) -> &str { "JSON" }
    fn description(&self) -> &str { "JSON graph export" }
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

// ---------------------------------------------------------------------------
// CSV Edge List
// ---------------------------------------------------------------------------

/// Export a graph as a CSV edge list (source, target, [attributes...]).
pub struct CsvEdgeListExporter {
    delimiter: char,
}

impl CsvEdgeListExporter {
    /// Create with a comma delimiter.
    pub fn new() -> Self {
        Self { delimiter: ',' }
    }

    /// Create with a custom delimiter.
    pub fn with_delimiter(delimiter: char) -> Self {
        Self { delimiter }
    }
}

impl Default for CsvEdgeListExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl GraphExporter for CsvEdgeListExporter {
    fn export(&self, graph: &AttributedGraph, path: &Path) -> std::io::Result<()> {
        let content = self.export_to_string(graph)?;
        fs::write(path, content)
    }

    fn export_to_string(&self, graph: &AttributedGraph) -> std::io::Result<String> {
        let d = self.delimiter;
        let mut out = String::new();
        writeln!(out, "Source{d}Target{d}EdgeType").unwrap();
        for e in graph.edges() {
            writeln!(
                out,
                "{}{d}{}{d}{}",
                e.source_id(),
                e.target_id(),
                e.edge_type().unwrap_or("")
            )
            .unwrap();
        }
        Ok(out)
    }

    fn file_extension(&self) -> &str { "csv" }
    fn name(&self) -> &str { "CSV:Edge List" }
    fn description(&self) -> &str { "CSV edge list format" }
}

// ---------------------------------------------------------------------------
// CSV Adjacency List
// ---------------------------------------------------------------------------

/// Export a graph as a CSV adjacency list (vertex, neighbor1, neighbor2, ...).
pub struct CsvAdjacencyListExporter;

impl GraphExporter for CsvAdjacencyListExporter {
    fn export(&self, graph: &AttributedGraph, path: &Path) -> std::io::Result<()> {
        let content = self.export_to_string(graph)?;
        fs::write(path, content)
    }

    fn export_to_string(&self, graph: &AttributedGraph) -> std::io::Result<String> {
        let mut out = String::new();
        for v in graph.vertices() {
            write!(out, "{}", v.id()).unwrap();
            let incident = graph.incident_edges(v.id());
            for e_id in incident {
                if let Some(edge) = graph.edge(e_id) {
                    write!(out, ",{}", edge.target_id()).unwrap();
                }
            }
            writeln!(out).unwrap();
        }
        Ok(out)
    }

    fn file_extension(&self) -> &str { "csv" }
    fn name(&self) -> &str { "CSV:Adjacency List" }
    fn description(&self) -> &str { "CSV adjacency list format" }
}

// ---------------------------------------------------------------------------
// GML (Graph Modelling Language)
// ---------------------------------------------------------------------------

/// Export a graph in GML format.
pub struct GmlGraphExporter;

impl GraphExporter for GmlGraphExporter {
    fn export(&self, graph: &AttributedGraph, path: &Path) -> std::io::Result<()> {
        let content = self.export_to_string(graph)?;
        fs::write(path, content)
    }

    fn export_to_string(&self, graph: &AttributedGraph) -> std::io::Result<String> {
        let mut out = String::new();
        writeln!(out, "graph [").unwrap();
        writeln!(out, "  directed 1").unwrap();

        for v in graph.vertices() {
            writeln!(out, "  node [").unwrap();
            writeln!(out, "    id \"{}\"", v.id()).unwrap();
            for (key, val) in v.attributes() {
                writeln!(out, "    {} \"{}\"", key, val).unwrap();
            }
            writeln!(out, "  ]").unwrap();
        }

        for e in graph.edges() {
            writeln!(out, "  edge [").unwrap();
            writeln!(out, "    source \"{}\"", e.source_id()).unwrap();
            writeln!(out, "    target \"{}\"", e.target_id()).unwrap();
            for (key, val) in e.attributes() {
                writeln!(out, "    {} \"{}\"", key, val).unwrap();
            }
            writeln!(out, "  ]").unwrap();
        }

        writeln!(out, "]").unwrap();
        Ok(out)
    }

    fn file_extension(&self) -> &str { "gml" }
    fn name(&self) -> &str { "GML" }
    fn description(&self) -> &str { "Graph Modelling Language" }
}

// ---------------------------------------------------------------------------
// GraphML
// ---------------------------------------------------------------------------

/// Export a graph in GraphML format.
pub struct GraphMlExporter;

impl GraphExporter for GraphMlExporter {
    fn export(&self, graph: &AttributedGraph, path: &Path) -> std::io::Result<()> {
        let content = self.export_to_string(graph)?;
        fs::write(path, content)
    }

    fn export_to_string(&self, graph: &AttributedGraph) -> std::io::Result<String> {
        let mut out = String::new();
        writeln!(out, r#"<?xml version="1.0" encoding="UTF-8"?>"#).unwrap();
        writeln!(
            out,
            r#"<graphml xmlns="http://graphml.graphstruct.org/xmlns">"#
        )
        .unwrap();

        // Collect all attribute keys
        let mut attr_keys = Vec::new();
        for v in graph.vertices() {
            for key in v.attributes().keys() {
                if !attr_keys.contains(key) {
                    attr_keys.push(key.clone());
                }
            }
        }
        for e in graph.edges() {
            for key in e.attributes().keys() {
                if !attr_keys.contains(key) {
                    attr_keys.push(key.clone());
                }
            }
        }

        for key in &attr_keys {
            writeln!(
                out,
                r#"  <key id="{}" for="all" attr.name="{}" attr.type="string" />"#,
                key, key
            )
            .unwrap();
        }

        writeln!(out, r#"  <graph id="{}" edgedefault="directed">"#, graph.name()).unwrap();

        for v in graph.vertices() {
            write!(out, r#"    <node id="{}">"#, v.id()).unwrap();
            for (key, val) in v.attributes() {
                write!(
                    out,
                    r#"<data key="{}">{}</data>"#,
                    key,
                    escape_xml(val)
                )
                .unwrap();
            }
            writeln!(out, "</node>").unwrap();
        }

        for (i, e) in graph.edges().enumerate() {
            write!(
                out,
                r#"    <edge id="e{}" source="{}" target="{}">"#,
                i,
                e.source_id(),
                e.target_id()
            )
            .unwrap();
            for (key, val) in e.attributes() {
                write!(
                    out,
                    r#"<data key="{}">{}</data>"#,
                    key,
                    escape_xml(val)
                )
                .unwrap();
            }
            writeln!(out, "</edge>").unwrap();
        }

        writeln!(out, "  </graph>").unwrap();
        writeln!(out, "</graphml>").unwrap();
        Ok(out)
    }

    fn file_extension(&self) -> &str { "graphml" }
    fn name(&self) -> &str { "GraphML" }
    fn description(&self) -> &str { "GraphML XML format" }
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// ---------------------------------------------------------------------------
// DIMACS
// ---------------------------------------------------------------------------

/// Export a graph in DIMACS format.
pub struct DimacsGraphExporter;

impl GraphExporter for DimacsGraphExporter {
    fn export(&self, graph: &AttributedGraph, path: &Path) -> std::io::Result<()> {
        let content = self.export_to_string(graph)?;
        fs::write(path, content)
    }

    fn export_to_string(&self, graph: &AttributedGraph) -> std::io::Result<String> {
        let mut out = String::new();
        writeln!(out, "c DIMACS graph export").unwrap();
        writeln!(
            out,
            "p edge {} {}",
            graph.vertex_count(),
            graph.edge_count()
        )
        .unwrap();

        // Map vertex ids to numeric indices
        let id_to_idx: HashMap<&str, usize> = graph
            .vertex_ids()
            .enumerate()
            .map(|(i, id)| (id, i + 1))
            .collect();

        for e in graph.edges() {
            let src = id_to_idx.get(e.source_id()).unwrap_or(&0);
            let tgt = id_to_idx.get(e.target_id()).unwrap_or(&0);
            writeln!(out, "e {} {}", src, tgt).unwrap();
        }

        Ok(out)
    }

    fn file_extension(&self) -> &str { "dimacs" }
    fn name(&self) -> &str { "DIMACS" }
    fn description(&self) -> &str { "DIMACS graph format" }
}

// ---------------------------------------------------------------------------
// Matrix (Adjacency Matrix)
// ---------------------------------------------------------------------------

/// Export a graph as an adjacency matrix in CSV format.
pub struct MatrixGraphExporter;

impl GraphExporter for MatrixGraphExporter {
    fn export(&self, graph: &AttributedGraph, path: &Path) -> std::io::Result<()> {
        let content = self.export_to_string(graph)?;
        fs::write(path, content)
    }

    fn export_to_string(&self, graph: &AttributedGraph) -> std::io::Result<String> {
        let ids: Vec<&str> = graph.vertex_ids().collect();
        let n = ids.len();
        let id_to_idx: HashMap<&str, usize> =
            ids.iter().enumerate().map(|(i, id)| (*id, i)).collect();

        let mut matrix = vec![vec![0u32; n]; n];
        for e in graph.edges() {
            if let (Some(&si), Some(&ti)) = (
                id_to_idx.get(e.source_id()),
                id_to_idx.get(e.target_id()),
            ) {
                matrix[si][ti] += 1;
            }
        }

        let mut out = String::new();
        // Header
        write!(out, "").unwrap();
        for id in &ids {
            write!(out, ",{}", id).unwrap();
        }
        writeln!(out).unwrap();

        for (i, id) in ids.iter().enumerate() {
            write!(out, "{}", id).unwrap();
            for j in 0..n {
                write!(out, ",{}", matrix[i][j]).unwrap();
            }
            writeln!(out).unwrap();
        }

        Ok(out)
    }

    fn file_extension(&self) -> &str { "csv" }
    fn name(&self) -> &str { "Matrix" }
    fn description(&self) -> &str { "Adjacency matrix in CSV format" }
}

// ---------------------------------------------------------------------------
// Exporter registry
// ---------------------------------------------------------------------------

/// Get all available graph exporters.
pub fn all_exporters() -> Vec<Box<dyn GraphExporter>> {
    vec![
        Box::new(DotGraphExporter),
        Box::new(JsonGraphExporter),
        Box::new(CsvEdgeListExporter::new()),
        Box::new(CsvAdjacencyListExporter),
        Box::new(GmlGraphExporter),
        Box::new(GraphMlExporter),
        Box::new(DimacsGraphExporter),
        Box::new(MatrixGraphExporter),
    ]
}

/// Find an exporter by file extension.
pub fn find_exporter(extension: &str) -> Option<Box<dyn GraphExporter>> {
    all_exporters()
        .into_iter()
        .find(|e| e.file_extension() == extension)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graphservices::attributed::AttributedVertex;

    fn sample_attributed_graph() -> AttributedGraph {
        let mut g = AttributedGraph::new("test_graph", "cfg");
        g.add_vertex(AttributedVertex::new("A", "Entry"));
        g.add_vertex(AttributedVertex::new("B", "Block1"));
        g.add_vertex(AttributedVertex::new("C", "Exit"));
        g.add_edge("A", "B", Some("fallthrough".to_string()));
        g.add_edge("B", "C", Some("branch".to_string()));
        g.add_edge("A", "C", Some("jump".to_string()));
        g
    }

    #[test]
    fn test_dot_export() {
        let g = sample_attributed_graph();
        let dot = DotGraphExporter.export_to_string(&g).unwrap();
        assert!(dot.starts_with("digraph"));
        assert!(dot.contains("\"A\""));
        assert!(dot.contains("\"B\""));
        assert!(dot.contains("->"));
    }

    #[test]
    fn test_json_export() {
        let g = sample_attributed_graph();
        let json = JsonGraphExporter.export_to_string(&g).unwrap();
        assert!(json.contains("\"vertices\""));
        assert!(json.contains("\"edges\""));
        assert!(json.contains("\"A\""));
    }

    #[test]
    fn test_csv_edge_list_export() {
        let g = sample_attributed_graph();
        let csv = CsvEdgeListExporter::new().export_to_string(&g).unwrap();
        let lines: Vec<&str> = csv.trim().lines().collect();
        assert_eq!(lines.len(), 4); // header + 3 edges
        assert!(lines[0].contains("Source"));
    }

    #[test]
    fn test_csv_adjacency_list_export() {
        let g = sample_attributed_graph();
        let csv = CsvAdjacencyListExporter.export_to_string(&g).unwrap();
        let lines: Vec<&str> = csv.trim().lines().collect();
        assert_eq!(lines.len(), 3); // 3 vertices
    }

    #[test]
    fn test_gml_export() {
        let g = sample_attributed_graph();
        let gml = GmlGraphExporter.export_to_string(&g).unwrap();
        assert!(gml.contains("graph ["));
        assert!(gml.contains("node ["));
        assert!(gml.contains("edge ["));
    }

    #[test]
    fn test_graphml_export() {
        let g = sample_attributed_graph();
        let xml = GraphMlExporter.export_to_string(&g).unwrap();
        assert!(xml.contains("<?xml"));
        assert!(xml.contains("<graphml"));
        assert!(xml.contains("<node"));
        assert!(xml.contains("<edge"));
    }

    #[test]
    fn test_dimacs_export() {
        let g = sample_attributed_graph();
        let dimacs = DimacsGraphExporter.export_to_string(&g).unwrap();
        assert!(dimacs.contains("p edge 3 3"));
        assert!(dimacs.contains("e "));
    }

    #[test]
    fn test_matrix_export() {
        let g = sample_attributed_graph();
        let matrix = MatrixGraphExporter.export_to_string(&g).unwrap();
        let lines: Vec<&str> = matrix.trim().lines().collect();
        assert_eq!(lines.len(), 4); // header + 3 rows
    }

    #[test]
    fn test_find_exporter() {
        assert!(find_exporter("dot").is_some());
        assert!(find_exporter("json").is_some());
        assert!(find_exporter("gml").is_some());
        assert!(find_exporter("unknown").is_none());
    }

    #[test]
    fn test_all_exporters() {
        let exporters = all_exporters();
        assert!(exporters.len() >= 7);
    }

    #[test]
    fn test_export_to_file() {
        let g = sample_attributed_graph();
        let tmp = std::env::temp_dir().join("test_attributed_graph.dot");
        DotGraphExporter.export(&g, &tmp).unwrap();
        let content = fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("digraph"));
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_escape_json() {
        assert_eq!(escape_json("hello\"world"), "hello\\\"world");
        assert_eq!(escape_json("line\nbreak"), "line\\nbreak");
    }

    #[test]
    fn test_escape_xml() {
        assert_eq!(escape_xml("a<b>c"), "a&lt;b&gt;c");
        assert_eq!(escape_xml("a&b"), "a&amp;b");
    }
}
