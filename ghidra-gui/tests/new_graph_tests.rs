//! Integration tests for newly ported graph framework modules.
//!
//! Tests the graph export and display provider types.

use ghidra_gui::graph::graph_type_service_ext::{
    DefaultGraphDisplayProvider, ExportEdge, ExportFormat, ExportVertex,
    GraphDisplayProvider, GraphExportData,
};

#[test]
fn test_export_format_all_variants() {
    let formats = [
        ExportFormat::Dot,
        ExportFormat::Svg,
        ExportFormat::Png,
        ExportFormat::Json,
        ExportFormat::Gml,
    ];
    assert_eq!(formats.len(), 5);

    // All should have unique extensions
    let extensions: Vec<&str> = formats.iter().map(|f| f.extension()).collect();
    let mut unique_exts = extensions.clone();
    unique_exts.sort();
    unique_exts.dedup();
    assert_eq!(extensions.len(), unique_exts.len());
}

#[test]
fn test_export_format_properties() {
    assert_eq!(ExportFormat::Dot.extension(), "dot");
    assert_eq!(ExportFormat::Svg.extension(), "svg");
    assert_eq!(ExportFormat::Png.extension(), "png");
    assert_eq!(ExportFormat::Json.extension(), "json");
    assert_eq!(ExportFormat::Gml.extension(), "gml");

    assert_eq!(ExportFormat::Dot.mime_type(), "text/vnd.graphviz");
    assert_eq!(ExportFormat::Svg.mime_type(), "image/svg+xml");
}

#[test]
fn test_export_vertex_builder() {
    let v = ExportVertex::new("v1", "Node A");
    assert_eq!(v.id, "v1");
    assert_eq!(v.label, "Node A");
    assert_eq!(v.shape, "ellipse");
    assert_eq!(v.color, "#FFFFFF");
    assert!(v.attributes.is_empty());
}

#[test]
fn test_export_edge_builder() {
    let e = ExportEdge::new("a", "b").with_label("edge_label");
    assert_eq!(e.source, "a");
    assert_eq!(e.target, "b");
    assert_eq!(e.label.as_deref(), Some("edge_label"));
    assert_eq!(e.line_style, "solid");
    assert_eq!(e.color, "#000000");
}

#[test]
fn test_graph_export_data_dot_format() {
    let mut data = GraphExportData::new("test_graph", ExportFormat::Dot);
    data.vertices.push(ExportVertex::new("a", "Alpha"));
    data.vertices.push(ExportVertex::new("b", "Beta"));
    data.vertices.push(ExportVertex::new("c", "Gamma"));
    data.edges.push(ExportEdge::new("a", "b").with_label("link1"));
    data.edges.push(ExportEdge::new("b", "c"));

    let dot = data.to_dot();
    assert!(dot.contains("digraph \"test_graph\""));
    assert!(dot.contains("\"a\" [label=\"Alpha\""));
    assert!(dot.contains("\"b\" [label=\"Beta\""));
    assert!(dot.contains("\"a\" -> \"b\""));
    assert!(dot.contains("link1"));
    assert!(dot.contains("\"b\" -> \"c\""));
    assert!(dot.ends_with("}\n"));
}

#[test]
fn test_graph_export_data_json_format() {
    let mut data = GraphExportData::new("g", ExportFormat::Json);
    data.vertices.push(ExportVertex::new("a", "A"));
    data.vertices.push(ExportVertex::new("b", "B"));
    data.edges.push(ExportEdge::new("a", "b"));

    let json = data.to_json().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let arr = parsed.as_array().unwrap();
    assert_eq!(arr.len(), 2);

    // First vertex should have neighbor "b"
    let first = &arr[0];
    assert_eq!(first["id"], "a");
    let neighbors = first["neighbors"].as_array().unwrap();
    assert_eq!(neighbors.len(), 1);
    assert_eq!(neighbors[0], "b");
}

#[test]
fn test_graph_export_data_empty() {
    let data = GraphExportData::new("empty", ExportFormat::Dot);
    let dot = data.to_dot();
    assert!(dot.contains("digraph"));
    assert!(!dot.contains("->"));
}

#[test]
fn test_graph_export_serialization() {
    let mut data = GraphExportData::new("g", ExportFormat::Dot);
    data.vertices.push(ExportVertex::new("v1", "V1"));
    data.edges.push(ExportEdge::new("v1", "v1").with_label("self-loop"));

    let json = serde_json::to_string(&data).unwrap();
    let back: GraphExportData = serde_json::from_str(&json).unwrap();
    assert_eq!(back.title, "g");
    assert_eq!(back.vertices.len(), 1);
    assert_eq!(back.edges.len(), 1);
    assert_eq!(back.edges[0].label.as_deref(), Some("self-loop"));
}

#[test]
fn test_default_display_provider() {
    let provider = DefaultGraphDisplayProvider::new();
    assert_eq!(provider.name(), "DefaultGraphDisplayProvider");
    assert!(provider.is_available());
}
