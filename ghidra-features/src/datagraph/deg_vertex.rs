//! Vertex types for the data exploration graph.
//!
//! Ported from Ghidra's `datagraph.data.graph.DegVertex` and related Java classes.

use std::collections::HashMap;

/// The kind of data vertex in the graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VertexKind {
    /// A code (instruction/function) vertex.
    Code,
    /// A data (variable/structure) vertex.
    Data,
    /// A group vertex representing collapsed nodes.
    Group,
}

/// A vertex in the data exploration graph.
#[derive(Debug, Clone)]
pub struct DegVertex {
    /// Unique identifier.
    pub id: u64,
    /// Display label.
    pub label: String,
    /// The kind of vertex.
    pub kind: VertexKind,
    /// The address this vertex represents.
    pub address: u64,
    /// Whether this vertex is expanded (showing children).
    pub expanded: bool,
    /// Whether this vertex is currently visible.
    pub visible: bool,
    /// Attributes for display.
    pub attributes: HashMap<String, String>,
}

impl DegVertex {
    /// Create a new data exploration vertex.
    pub fn new(id: u64, label: String, kind: VertexKind, address: u64) -> Self {
        Self {
            id,
            label,
            kind,
            address,
            expanded: false,
            visible: true,
            attributes: HashMap::new(),
        }
    }

    /// Create a code vertex.
    pub fn code(id: u64, address: u64) -> Self {
        Self::new(id, format!("Code@0x{:x}", address), VertexKind::Code, address)
    }

    /// Create a data vertex.
    pub fn data(id: u64, address: u64, label: String) -> Self {
        Self::new(id, label, VertexKind::Data, address)
    }

    /// Toggle the expanded state.
    pub fn toggle_expanded(&mut self) {
        self.expanded = !self.expanded;
    }
}

impl PartialEq for DegVertex {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for DegVertex {}

impl std::hash::Hash for DegVertex {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

/// A code vertex (represents a function or instruction block).
#[derive(Debug, Clone)]
pub struct CodeDegVertex {
    /// The underlying data vertex.
    pub vertex: DegVertex,
    /// The function name if applicable.
    pub function_name: Option<String>,
    /// Block size in bytes.
    pub block_size: usize,
}

impl CodeDegVertex {
    /// Create a new code vertex.
    pub fn new(id: u64, address: u64) -> Self {
        Self {
            vertex: DegVertex::code(id, address),
            function_name: None,
            block_size: 0,
        }
    }
}

/// A data vertex (represents a data element).
#[derive(Debug, Clone)]
pub struct DataDegVertex {
    /// The underlying data vertex.
    pub vertex: DegVertex,
    /// The data type name.
    pub data_type: String,
    /// The size in bytes.
    pub size: usize,
}

impl DataDegVertex {
    /// Create a new data vertex.
    pub fn new(id: u64, address: u64, data_type: String, size: usize) -> Self {
        Self {
            vertex: DegVertex::data(id, address, data_type.clone()),
            data_type,
            size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deg_vertex_creation() {
        let v = DegVertex::new(1, "test".to_string(), VertexKind::Data, 0x1000);
        assert_eq!(v.id, 1);
        assert_eq!(v.kind, VertexKind::Data);
        assert_eq!(v.address, 0x1000);
        assert!(!v.expanded);
        assert!(v.visible);
    }

    #[test]
    fn test_code_vertex() {
        let v = DegVertex::code(1, 0x401000);
        assert_eq!(v.kind, VertexKind::Code);
        assert!(v.label.contains("401000"));
    }

    #[test]
    fn test_data_vertex() {
        let v = DegVertex::data(2, 0x100, "int".to_string());
        assert_eq!(v.kind, VertexKind::Data);
        assert_eq!(v.label, "int");
    }

    #[test]
    fn test_toggle_expanded() {
        let mut v = DegVertex::code(1, 0x1000);
        assert!(!v.expanded);
        v.toggle_expanded();
        assert!(v.expanded);
    }

    #[test]
    fn test_vertex_equality() {
        let v1 = DegVertex::new(1, "a".to_string(), VertexKind::Data, 0x100);
        let v2 = DegVertex::new(1, "b".to_string(), VertexKind::Code, 0x200);
        assert_eq!(v1, v2); // Same ID
    }

    #[test]
    fn test_code_deg_vertex() {
        let v = CodeDegVertex::new(1, 0x401000);
        assert_eq!(v.vertex.kind, VertexKind::Code);
        assert!(v.function_name.is_none());
    }

    #[test]
    fn test_data_deg_vertex() {
        let v = DataDegVertex::new(1, 0x100, "int32".to_string(), 4);
        assert_eq!(v.data_type, "int32");
        assert_eq!(v.size, 4);
    }
}
