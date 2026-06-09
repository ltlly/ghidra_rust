//! CSV and URL graph export utilities.
//!
//! Port of `ghidra.graph.ExportCsvGraphUrl` and related export helpers.
//!
//! Provides functions to export a graph's vertices and edges as CSV
//! text, and to produce URL-encoded representations suitable for
//! clipboard sharing or file output.

use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;

use super::traits::GEdge;

/// A separator character for CSV output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsvSeparator {
    /// Comma separator.
    Comma,
    /// Tab separator.
    Tab,
    /// Semicolon separator.
    Semicolon,
}

impl CsvSeparator {
    /// Return the separator character as a string.
    pub fn as_str(&self) -> &str {
        match self {
            CsvSeparator::Comma => ",",
            CsvSeparator::Tab => "\t",
            CsvSeparator::Semicolon => ";",
        }
    }
}

impl Default for CsvSeparator {
    fn default() -> Self {
        CsvSeparator::Comma
    }
}

/// Options for CSV graph export.
#[derive(Debug, Clone)]
pub struct CsvExportOptions {
    /// The field separator.
    pub separator: CsvSeparator,
    /// Whether to include a header row.
    pub include_header: bool,
    /// Whether to quote all fields.
    pub quote_all: bool,
}

impl Default for CsvExportOptions {
    fn default() -> Self {
        Self {
            separator: CsvSeparator::default(),
            include_header: true,
            quote_all: false,
        }
    }
}

/// Escape a CSV field value.
fn escape_csv_field(value: &str, separator: &str, quote_all: bool) -> String {
    if quote_all
        || value.contains(separator)
        || value.contains('"')
        || value.contains('\n')
        || value.contains('\r')
    {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// Export vertices as CSV text.
///
/// Each vertex is rendered using the provided `vertex_to_fields` function,
/// which returns a list of field values for that vertex.
pub fn export_vertices_csv<V>(
    vertices: &HashSet<V>,
    vertex_to_fields: &dyn Fn(&V) -> Vec<String>,
    options: &CsvExportOptions,
) -> String
where
    V: Clone + Debug + Eq + Hash,
{
    let sep = options.separator.as_str();
    let mut lines = Vec::new();

    if options.include_header {
        lines.push(format!(
            "{}",
            escape_csv_field("vertex_id", sep, options.quote_all)
        ));
    }

    let mut sorted: Vec<&V> = vertices.iter().collect();
    sorted.sort_by(|a, b| format!("{:?}", a).cmp(&format!("{:?}", b)));

    for v in sorted {
        let fields = vertex_to_fields(v);
        let escaped: Vec<String> = fields
            .iter()
            .map(|f| escape_csv_field(f, sep, options.quote_all))
            .collect();
        lines.push(escaped.join(sep));
    }

    lines.join("\n")
}

/// Export edges as CSV text.
///
/// Each edge is rendered as `start_id, end_id` (plus any extra fields
/// from the `edge_to_fields` function).
pub fn export_edges_csv<V, E>(
    edges: &[E],
    vertex_id: &dyn Fn(&V) -> String,
    edge_to_fields: &dyn Fn(&E) -> Vec<String>,
    options: &CsvExportOptions,
) -> String
where
    V: Clone + Debug + Eq + Hash,
    E: GEdge<V>,
{
    let sep = options.separator.as_str();
    let mut lines = Vec::new();

    if options.include_header {
        let header = vec![
            escape_csv_field("start", sep, options.quote_all),
            escape_csv_field("end", sep, options.quote_all),
        ];
        // Add generic extra column headers if edge_to_fields is non-trivial
        // (we can't know the names without introspection, so skip).
        lines.push(header.join(sep));
    }

    for e in edges {
        let start_id = vertex_id(e.start());
        let end_id = vertex_id(e.end());
        let mut fields = vec![
            escape_csv_field(&start_id, sep, options.quote_all),
            escape_csv_field(&end_id, sep, options.quote_all),
        ];
        for extra in edge_to_fields(e) {
            fields.push(escape_csv_field(&extra, sep, options.quote_all));
        }
        lines.push(fields.join(sep));
    }

    lines.join("\n")
}

/// Export a full graph (vertices + edges) as CSV text.
///
/// Returns a string with two sections separated by a blank line:
/// 1. Vertices CSV
/// 2. Edges CSV
pub fn export_graph_csv<V, E>(
    vertices: &HashSet<V>,
    edges: &[E],
    vertex_to_fields: &dyn Fn(&V) -> Vec<String>,
    vertex_id: &dyn Fn(&V) -> String,
    edge_to_fields: &dyn Fn(&E) -> Vec<String>,
    options: &CsvExportOptions,
) -> String
where
    V: Clone + Debug + Eq + Hash,
    E: GEdge<V>,
{
    let vertices_csv = export_vertices_csv(vertices, vertex_to_fields, options);
    let edges_csv = export_edges_csv(edges, vertex_id, edge_to_fields, options);
    format!("{}\n\n{}", vertices_csv, edges_csv)
}

/// Encode a string for use in a URL query parameter.
pub fn url_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~' => {
                result.push(byte as char);
            }
            b' ' => {
                result.push('+');
            }
            _ => {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

/// Export a graph as a URL-safe string.
///
/// The URL format is: `csvgraph://vertices=<url-encoded>&edges=<url-encoded>`
pub fn export_graph_url<V, E>(
    vertices: &HashSet<V>,
    edges: &[E],
    vertex_to_fields: &dyn Fn(&V) -> Vec<String>,
    vertex_id: &dyn Fn(&V) -> String,
    edge_to_fields: &dyn Fn(&E) -> Vec<String>,
) -> String
where
    V: Clone + Debug + Eq + Hash,
    E: GEdge<V>,
{
    let options = CsvExportOptions {
        separator: CsvSeparator::Comma,
        include_header: false,
        quote_all: false,
    };
    let v_csv = export_vertices_csv(vertices, vertex_to_fields, &options);
    let e_csv = export_edges_csv(edges, vertex_id, edge_to_fields, &options);
    format!(
        "csvgraph://vertices={}&edges={}",
        url_encode(&v_csv),
        url_encode(&e_csv)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::default_edge::DefaultGEdge;
    use std::collections::HashSet;

    fn test_vertices() -> HashSet<i32> {
        [1, 2, 3].iter().copied().collect()
    }

    fn test_edges() -> Vec<DefaultGEdge<i32>> {
        vec![
            DefaultGEdge::new(1, 2),
            DefaultGEdge::new(2, 3),
        ]
    }

    #[test]
    fn test_escape_csv_field_simple() {
        assert_eq!(escape_csv_field("hello", ",", false), "hello");
    }

    #[test]
    fn test_escape_csv_field_with_comma() {
        assert_eq!(escape_csv_field("a,b", ",", false), "\"a,b\"");
    }

    #[test]
    fn test_escape_csv_field_with_quote() {
        assert_eq!(escape_csv_field("a\"b", ",", false), "\"a\"\"b\"");
    }

    #[test]
    fn test_escape_csv_field_quote_all() {
        assert_eq!(escape_csv_field("hello", ",", true), "\"hello\"");
    }

    #[test]
    fn test_export_vertices_csv() {
        let vertices = test_vertices();
        let csv = export_vertices_csv(
            &vertices,
            &|v| vec![format!("v{}", v)],
            &CsvExportOptions::default(),
        );
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 4); // header + 3 vertices
        assert_eq!(lines[0], "vertex_id");
    }

    #[test]
    fn test_export_vertices_csv_no_header() {
        let vertices = test_vertices();
        let opts = CsvExportOptions {
            include_header: false,
            ..Default::default()
        };
        let csv = export_vertices_csv(&vertices, &|v| vec![format!("{}", v)], &opts);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 3);
    }

    #[test]
    fn test_export_edges_csv() {
        let edges = test_edges();
        let csv = export_edges_csv(
            &edges,
            &|v| format!("{}", v),
            &|_| vec![],
            &CsvExportOptions::default(),
        );
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 3); // header + 2 edges
    }

    #[test]
    fn test_export_graph_csv() {
        let vertices = test_vertices();
        let edges = test_edges();
        let csv = export_graph_csv(
            &vertices,
            &edges,
            &|v| vec![format!("{}", v)],
            &|v| format!("{}", v),
            &|_| vec![],
            &CsvExportOptions::default(),
        );
        // Should contain both sections
        assert!(csv.contains("vertex_id"));
        assert!(csv.contains("start"));
    }

    #[test]
    fn test_url_encode_simple() {
        assert_eq!(url_encode("hello"), "hello");
    }

    #[test]
    fn test_url_encode_space() {
        assert_eq!(url_encode("hello world"), "hello+world");
    }

    #[test]
    fn test_url_encode_special() {
        assert_eq!(url_encode("a,b"), "a%2Cb");
    }

    #[test]
    fn test_export_graph_url() {
        let vertices = test_vertices();
        let edges = test_edges();
        let url = export_graph_url(
            &vertices,
            &edges,
            &|v| vec![format!("{}", v)],
            &|v| format!("{}", v),
            &|_| vec![],
        );
        assert!(url.starts_with("csvgraph://"));
        assert!(url.contains("vertices="));
        assert!(url.contains("edges="));
    }

    #[test]
    fn test_csv_separator() {
        assert_eq!(CsvSeparator::Comma.as_str(), ",");
        assert_eq!(CsvSeparator::Tab.as_str(), "\t");
        assert_eq!(CsvSeparator::Semicolon.as_str(), ";");
    }

    #[test]
    fn test_csv_separator_default() {
        assert_eq!(CsvSeparator::default(), CsvSeparator::Comma);
    }

    #[test]
    fn test_export_edges_with_extra_fields() {
        let edges = test_edges();
        let csv = export_edges_csv(
            &edges,
            &|v| format!("{}", v),
            &|e| vec![format!("weight={}", 1)],
            &CsvExportOptions::default(),
        );
        assert!(csv.contains("weight=1"));
    }
}
