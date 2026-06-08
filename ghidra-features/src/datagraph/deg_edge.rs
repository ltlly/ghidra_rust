//! Edge types for the data exploration graph.
//!
//! Ported from Ghidra's `datagraph.data.graph.DegEdge` Java class.

/// The kind of edge in the data exploration graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    /// A data reference edge (one data item references another).
    DataReference,
    /// A pointer edge (one data item points to another).
    Pointer,
    /// A containment edge (one data item contains another).
    Containment,
    /// A code reference edge.
    CodeReference,
    /// A call edge (function call).
    Call,
}

/// An edge in the data exploration graph.
#[derive(Debug, Clone)]
pub struct DegEdge {
    /// Unique identifier.
    pub id: u64,
    /// Source vertex ID.
    pub source_id: u64,
    /// Target vertex ID.
    pub target_id: u64,
    /// The kind of edge.
    pub kind: EdgeKind,
    /// Display label.
    pub label: String,
    /// Whether this edge is highlighted.
    pub highlighted: bool,
    /// Edge weight (for display thickness).
    pub weight: f64,
}

impl DegEdge {
    /// Create a new edge.
    pub fn new(id: u64, source_id: u64, target_id: u64, kind: EdgeKind) -> Self {
        Self {
            id,
            source_id,
            target_id,
            kind,
            label: String::new(),
            highlighted: false,
            weight: 1.0,
        }
    }

    /// Create a data reference edge.
    pub fn data_ref(id: u64, source_id: u64, target_id: u64) -> Self {
        Self::new(id, source_id, target_id, EdgeKind::DataReference)
    }

    /// Create a pointer edge.
    pub fn pointer(id: u64, source_id: u64, target_id: u64) -> Self {
        Self::new(id, source_id, target_id, EdgeKind::Pointer)
    }

    /// Create a containment edge.
    pub fn containment(id: u64, source_id: u64, target_id: u64) -> Self {
        Self::new(id, source_id, target_id, EdgeKind::Containment)
    }
}

impl PartialEq for DegEdge {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for DegEdge {}

impl std::hash::Hash for DegEdge {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edge_creation() {
        let e = DegEdge::new(1, 10, 20, EdgeKind::DataReference);
        assert_eq!(e.id, 1);
        assert_eq!(e.source_id, 10);
        assert_eq!(e.target_id, 20);
        assert_eq!(e.kind, EdgeKind::DataReference);
        assert!(!e.highlighted);
        assert_eq!(e.weight, 1.0);
    }

    #[test]
    fn test_data_ref_edge() {
        let e = DegEdge::data_ref(1, 10, 20);
        assert_eq!(e.kind, EdgeKind::DataReference);
    }

    #[test]
    fn test_pointer_edge() {
        let e = DegEdge::pointer(2, 10, 30);
        assert_eq!(e.kind, EdgeKind::Pointer);
    }

    #[test]
    fn test_containment_edge() {
        let e = DegEdge::containment(3, 20, 30);
        assert_eq!(e.kind, EdgeKind::Containment);
    }

    #[test]
    fn test_edge_equality() {
        let e1 = DegEdge::new(1, 10, 20, EdgeKind::Call);
        let e2 = DegEdge::new(1, 30, 40, EdgeKind::Pointer);
        assert_eq!(e1, e2); // Same ID
    }
}
