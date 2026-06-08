//! Function Call Graph direction -- incoming, outgoing, or both.
//!
//! Ported from Ghidra's `functioncalls.graph.FcgDirection` Java enum.
//!
//! Represents whether a vertex is an incoming vertex (the start/from on an edge),
//! an outgoing vertex (the end/to on an edge), or if it is both (the source).

/// Direction of a vertex in the function call graph.
///
/// The ordering is top-to-bottom: `In` -> `InAndOut` -> `Out`.
///
/// Ported from `functioncalls.graph.FcgDirection`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FcgDirection {
    /// The vertex is an incoming vertex (caller / predecessor).
    In,
    /// The vertex is both incoming and outgoing (the source / root).
    InAndOut,
    /// The vertex is an outgoing vertex (callee / successor).
    Out,
}

impl FcgDirection {
    /// Returns `true` if this direction represents the source node
    /// (both incoming and outgoing).
    pub fn is_source(self) -> bool {
        self == FcgDirection::InAndOut
    }

    /// Returns `true` if this direction is incoming only.
    pub fn is_in(self) -> bool {
        self == FcgDirection::In
    }

    /// Returns `true` if this direction is outgoing only.
    pub fn is_out(self) -> bool {
        self == FcgDirection::Out
    }
}

impl std::fmt::Display for FcgDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FcgDirection::In => write!(f, "In"),
            FcgDirection::InAndOut => write!(f, "In/Out"),
            FcgDirection::Out => write!(f, "Out"),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_source() {
        assert!(FcgDirection::InAndOut.is_source());
        assert!(!FcgDirection::In.is_source());
        assert!(!FcgDirection::Out.is_source());
    }

    #[test]
    fn test_is_in() {
        assert!(FcgDirection::In.is_in());
        assert!(!FcgDirection::InAndOut.is_in());
        assert!(!FcgDirection::Out.is_in());
    }

    #[test]
    fn test_is_out() {
        assert!(FcgDirection::Out.is_out());
        assert!(!FcgDirection::In.is_out());
        assert!(!FcgDirection::InAndOut.is_out());
    }

    #[test]
    fn test_display() {
        assert_eq!(FcgDirection::In.to_string(), "In");
        assert_eq!(FcgDirection::InAndOut.to_string(), "In/Out");
        assert_eq!(FcgDirection::Out.to_string(), "Out");
    }

    #[test]
    fn test_ordering() {
        assert!(FcgDirection::In < FcgDirection::InAndOut);
        assert!(FcgDirection::InAndOut < FcgDirection::Out);
    }
}
