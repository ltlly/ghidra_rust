//! Extended graph type service types.
//!
//! Ports additional types from `ghidra.service.graph` that are not yet
//! in the main `graph_type_service` module.
//!
//! These include:
//! - [`GraphDisplayProvider`] -- provider for graph display functionality
//! - [`GraphExporter`] -- export a graph to various formats (DOT, SVG, etc.)
//! - [`DefaultGraphDisplayProvider`] -- default implementation
//! - [`ExportFormat`] -- supported export formats

use serde::{Deserialize, Serialize};

/// Supported graph export formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportFormat {
    /// DOT format (Graphviz).
    Dot,
    /// SVG vector graphics.
    Svg,
    /// PNG raster image.
    Png,
    /// JSON adjacency list.
    Json,
    /// GML (Graph Modelling Language).
    Gml,
}

impl ExportFormat {
    /// Get the file extension for this format.
    pub fn extension(&self) -> &'static str {
        match self {
            ExportFormat::Dot => "dot",
            ExportFormat::Svg => "svg",
            ExportFormat::Png => "png",
            ExportFormat::Json => "json",
            ExportFormat::Gml => "gml",
        }
    }

    /// Get the MIME type for this format.
    pub fn mime_type(&self) -> &'static str {
        match self {
            ExportFormat::Dot => "text/vnd.graphviz",
            ExportFormat::Svg => "image/svg+xml",
            ExportFormat::Png => "image/png",
            ExportFormat::Json => "application/json",
            ExportFormat::Gml => "application/gml",
        }
    }

    /// Get a human-readable name for this format.
    pub fn display_name(&self) -> &'static str {
        match self {
            ExportFormat::Dot => "Graphviz DOT",
            ExportFormat::Svg => "SVG Image",
            ExportFormat::Png => "PNG Image",
            ExportFormat::Json => "JSON Adjacency List",
            ExportFormat::Gml => "GML",
        }
    }
}

/// A vertex in a graph export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportVertex {
    /// Vertex ID.
    pub id: String,
    /// Display label.
    pub label: String,
    /// Shape (e.g., "ellipse", "box", "diamond").
    pub shape: String,
    /// Color (hex string, e.g., "#FF0000").
    pub color: String,
    /// Additional attributes.
    pub attributes: Vec<(String, String)>,
}

impl ExportVertex {
    /// Create a new export vertex.
    pub fn new(id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            shape: "ellipse".to_string(),
            color: "#FFFFFF".to_string(),
            attributes: Vec::new(),
        }
    }
}

/// An edge in a graph export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEdge {
    /// Source vertex ID.
    pub source: String,
    /// Target vertex ID.
    pub target: String,
    /// Edge label (optional).
    pub label: Option<String>,
    /// Line style (e.g., "solid", "dashed", "dotted").
    pub line_style: String,
    /// Color.
    pub color: String,
}

impl ExportEdge {
    /// Create a new export edge.
    pub fn new(
        source: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            source: source.into(),
            target: target.into(),
            label: None,
            line_style: "solid".to_string(),
            color: "#000000".to_string(),
        }
    }

    /// Set the edge label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

/// Export data for a graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphExportData {
    /// Graph title.
    pub title: String,
    /// Export format.
    pub format: ExportFormat,
    /// Vertices.
    pub vertices: Vec<ExportVertex>,
    /// Edges.
    pub edges: Vec<ExportEdge>,
    /// Layout algorithm name.
    pub layout: String,
}

impl GraphExportData {
    /// Create new export data.
    pub fn new(title: impl Into<String>, format: ExportFormat) -> Self {
        Self {
            title: title.into(),
            format,
            vertices: Vec::new(),
            edges: Vec::new(),
            layout: "dot".to_string(),
        }
    }

    /// Export the graph as DOT format.
    pub fn to_dot(&self) -> String {
        let mut out = format!("digraph \"{}\" {{\n", self.title);
        out.push_str("  node [shape=ellipse];\n");
        for v in &self.vertices {
            out.push_str(&format!(
                "  \"{}\" [label=\"{}\", shape=\"{}\", style=filled, fillcolor=\"{}\"];\n",
                v.id, v.label, v.shape, v.color
            ));
        }
        for e in &self.edges {
            let label_attr = e
                .label
                .as_ref()
                .map(|l| format!(", label=\"{}\"", l))
                .unwrap_or_default();
            out.push_str(&format!(
                "  \"{}\" -> \"{}\" [style=\"{}\", color=\"{}\"{}];\n",
                e.source, e.target, e.line_style, e.color, label_attr
            ));
        }
        out.push_str("}\n");
        out
    }

    /// Export the graph as JSON adjacency list.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let adjacency: Vec<serde_json::Value> = self
            .vertices
            .iter()
            .map(|v| {
                let neighbors: Vec<&str> = self
                    .edges
                    .iter()
                    .filter(|e| e.source == v.id)
                    .map(|e| e.target.as_str())
                    .collect();
                serde_json::json!({
                    "id": v.id,
                    "label": v.label,
                    "neighbors": neighbors,
                })
            })
            .collect();
        serde_json::to_string_pretty(&adjacency)
    }
}

/// Trait for graph display providers.
///
/// A display provider creates or finds a display surface where a graph
/// can be rendered.
pub trait GraphDisplayProvider: Send + Sync {
    /// Get the name of this provider.
    fn name(&self) -> &str;

    /// Whether this provider is available (e.g., GUI is present).
    fn is_available(&self) -> bool;
}

/// A default graph display provider that logs messages.
#[derive(Debug, Clone, Default)]
pub struct DefaultGraphDisplayProvider;

impl DefaultGraphDisplayProvider {
    /// Create a new default display provider.
    pub fn new() -> Self {
        Self
    }
}

impl GraphDisplayProvider for DefaultGraphDisplayProvider {
    fn name(&self) -> &str {
        "DefaultGraphDisplayProvider"
    }

    fn is_available(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_format_properties() {
        assert_eq!(ExportFormat::Dot.extension(), "dot");
        assert_eq!(ExportFormat::Svg.mime_type(), "image/svg+xml");
        assert_eq!(ExportFormat::Json.display_name(), "JSON Adjacency List");
    }

    #[test]
    fn test_export_vertex() {
        let v = ExportVertex::new("v1", "Node A");
        assert_eq!(v.id, "v1");
        assert_eq!(v.shape, "ellipse");
    }

    #[test]
    fn test_export_edge() {
        let e = ExportEdge::new("a", "b").with_label("connects");
        assert!(e.label.is_some());
        assert_eq!(e.line_style, "solid");
    }

    #[test]
    fn test_graph_export_data() {
        let mut data = GraphExportData::new("test_graph", ExportFormat::Dot);
        data.vertices.push(ExportVertex::new("a", "A"));
        data.vertices.push(ExportVertex::new("b", "B"));
        data.edges.push(ExportEdge::new("a", "b"));

        let dot = data.to_dot();
        assert!(dot.contains("digraph"));
        assert!(dot.contains("\"a\""));
        assert!(dot.contains("->"));
    }

    #[test]
    fn test_graph_export_dot_with_label() {
        let mut data = GraphExportData::new("g", ExportFormat::Dot);
        data.vertices.push(ExportVertex::new("a", "A"));
        data.vertices.push(ExportVertex::new("b", "B"));
        data.edges.push(ExportEdge::new("a", "b").with_label("edge1"));

        let dot = data.to_dot();
        assert!(dot.contains("edge1"));
    }

    #[test]
    fn test_graph_export_json() {
        let mut data = GraphExportData::new("g", ExportFormat::Json);
        data.vertices.push(ExportVertex::new("a", "A"));
        data.vertices.push(ExportVertex::new("b", "B"));
        data.edges.push(ExportEdge::new("a", "b"));

        let json = data.to_json().unwrap();
        assert!(json.contains("a"));
        assert!(json.contains("neighbors"));
    }

    #[test]
    fn test_default_display_provider() {
        let p = DefaultGraphDisplayProvider::new();
        assert_eq!(p.name(), "DefaultGraphDisplayProvider");
        assert!(p.is_available());
    }
}
