//! Function Call Graph vertex.
//!
//! Ported from Ghidra's `functioncalls.graph.FcgVertex` Java class.
//!
//! A vertex represents a function in the call graph, with its level
//! (distance + direction from the source) and expansion state
//! (whether incoming/outgoing connections are shown).

use super::fcg_direction::FcgDirection;
use super::fcg_level::FcgLevel;

/// A vertex in the function call graph.
///
/// Ported from `functioncalls.graph.FcgVertex`.
#[derive(Debug, Clone)]
pub struct FcgVertex {
    /// The function name.
    name: String,
    /// The function entry point address.
    address: u64,
    /// The level (row + direction) of this vertex.
    level: FcgLevel,
    /// Whether incoming edges are expanded (shown).
    incoming_expanded: bool,
    /// Whether outgoing edges are expanded (shown).
    outgoing_expanded: bool,
    /// Whether this vertex has incoming references.
    has_incoming_references: bool,
    /// Whether this vertex has outgoing references.
    has_outgoing_references: bool,
    /// Whether there are too many incoming references to display.
    too_many_incoming_references: bool,
    /// Whether there are too many outgoing references to display.
    too_many_outgoing_references: bool,
    /// Alpha/opacity for animation (0.0 = transparent, 1.0 = opaque).
    alpha: f64,
    /// Whether this vertex is currently hovered.
    hovered: bool,
    /// Whether to use truncated function names.
    use_truncated_names: bool,
    /// Maximum name length before truncation.
    max_name_length: usize,
}

impl FcgVertex {
    /// Create a new vertex.
    pub fn new(name: impl Into<String>, address: u64, level: FcgLevel) -> Self {
        Self {
            name: name.into(),
            address,
            level,
            incoming_expanded: false,
            outgoing_expanded: false,
            has_incoming_references: false,
            has_outgoing_references: false,
            too_many_incoming_references: false,
            too_many_outgoing_references: false,
            alpha: 1.0,
            hovered: false,
            use_truncated_names: true,
            max_name_length: 40,
        }
    }

    /// Get the function name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the display name (potentially truncated).
    pub fn display_name(&self) -> String {
        if self.use_truncated_names && self.name.len() > self.max_name_length {
            let half = self.max_name_length / 2;
            format!("{}...{}", &self.name[..half], &self.name[self.name.len() - half..])
        } else {
            self.name.clone()
        }
    }

    /// Set whether to use truncated names.
    pub fn set_use_truncated_names(&mut self, use_truncated: bool) {
        self.use_truncated_names = use_truncated;
    }

    /// Set the maximum name length for truncation.
    pub fn set_max_name_length(&mut self, max_len: usize) {
        self.max_name_length = max_len;
    }

    /// Get the function entry point address.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Get the level of this vertex.
    pub fn level(&self) -> &FcgLevel {
        &self.level
    }

    /// Get the row (degree) of this vertex.
    pub fn degree(&self) -> i32 {
        self.level.row()
    }

    /// Get the direction of this vertex.
    pub fn direction(&self) -> FcgDirection {
        self.level.direction()
    }

    /// Set the hover state.
    pub fn set_hovered(&mut self, hovered: bool) {
        self.hovered = hovered;
    }

    /// Check if this vertex is hovered.
    pub fn is_hovered(&self) -> bool {
        self.hovered
    }

    /// Set whether this vertex has incoming references.
    pub fn set_has_incoming_references(&mut self, has_incoming: bool) {
        self.has_incoming_references = has_incoming;
    }

    /// Set whether this vertex has outgoing references.
    pub fn set_has_outgoing_references(&mut self, has_outgoing: bool) {
        self.has_outgoing_references = has_outgoing;
    }

    /// Set whether there are too many incoming references.
    pub fn set_too_many_incoming_references(&mut self, too_many: bool) {
        self.too_many_incoming_references = too_many;
    }

    /// Set whether there are too many outgoing references.
    pub fn set_too_many_outgoing_references(&mut self, too_many: bool) {
        self.too_many_outgoing_references = too_many;
    }

    /// Check if there are too many incoming references.
    pub fn has_too_many_incoming_references(&self) -> bool {
        self.too_many_incoming_references
    }

    /// Check if there are too many outgoing references.
    pub fn has_too_many_outgoing_references(&self) -> bool {
        self.too_many_outgoing_references
    }

    /// Check if incoming edges are expanded.
    pub fn is_incoming_expanded(&self) -> bool {
        self.incoming_expanded
    }

    /// Check if outgoing edges are expanded.
    pub fn is_outgoing_expanded(&self) -> bool {
        self.outgoing_expanded
    }

    /// Set whether incoming edges are expanded.
    pub fn set_incoming_expanded(&mut self, expanded: bool) {
        self.incoming_expanded = expanded;
    }

    /// Set whether outgoing edges are expanded.
    pub fn set_outgoing_expanded(&mut self, expanded: bool) {
        self.outgoing_expanded = expanded;
    }

    /// Check if this vertex is fully expanded in its current direction.
    pub fn is_expanded(&self) -> bool {
        let direction = self.level.direction();
        if direction.is_source() {
            return self.incoming_expanded && self.outgoing_expanded;
        }
        if direction.is_in() {
            return self.incoming_expanded;
        }
        self.outgoing_expanded
    }

    /// Check if this vertex can expand in its current direction.
    pub fn can_expand(&self) -> bool {
        let direction = self.level.direction();
        if direction.is_source() {
            return self.can_expand_incoming_references()
                || self.can_expand_outgoing_references();
        }
        if direction.is_in() {
            return self.can_expand_incoming_references();
        }
        self.can_expand_outgoing_references()
    }

    /// Check if incoming references can be expanded.
    pub fn can_expand_incoming_references(&self) -> bool {
        self.has_incoming_references
            && !self.too_many_incoming_references
            && !self.incoming_expanded
    }

    /// Check if outgoing references can be expanded.
    pub fn can_expand_outgoing_references(&self) -> bool {
        self.has_outgoing_references
            && !self.too_many_outgoing_references
            && !self.outgoing_expanded
    }

    /// Get the alpha/opacity.
    pub fn alpha(&self) -> f64 {
        self.alpha
    }

    /// Set the alpha/opacity.
    pub fn set_alpha(&mut self, alpha: f64) {
        self.alpha = alpha;
    }
}

impl PartialEq for FcgVertex {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
    }
}

impl Eq for FcgVertex {}

impl std::hash::Hash for FcgVertex {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.address.hash(state);
    }
}

impl std::fmt::Display for FcgVertex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vertex_creation() {
        let v = FcgVertex::new("main", 0x1000, FcgLevel::source_level());
        assert_eq!(v.name(), "main");
        assert_eq!(v.address(), 0x1000);
        assert!(v.level().is_source());
        assert_eq!(v.alpha(), 1.0);
        assert!(!v.is_hovered());
    }

    #[test]
    fn test_vertex_display_name_truncated() {
        let long_name = "a_very_long_function_name_that_should_be_truncated";
        let mut v = FcgVertex::new(long_name, 0x1000, FcgLevel::source_level());
        v.set_max_name_length(20);
        let display = v.display_name();
        assert!(display.len() <= 25); // some margin for "..."
        assert!(display.contains("..."));
    }

    #[test]
    fn test_vertex_display_name_not_truncated() {
        let mut v = FcgVertex::new("short", 0x1000, FcgLevel::source_level());
        v.set_use_truncated_names(false);
        assert_eq!(v.display_name(), "short");
    }

    #[test]
    fn test_vertex_direction() {
        let v = FcgVertex::new("f", 0x1000, FcgLevel::new(2, FcgDirection::In));
        assert_eq!(v.direction(), FcgDirection::In);
        assert_eq!(v.degree(), 3); // row is distance + 1
    }

    #[test]
    fn test_expansion_state() {
        let mut v = FcgVertex::new("f", 0x1000, FcgLevel::source_level());
        assert!(!v.is_expanded());

        v.set_incoming_expanded(true);
        assert!(!v.is_expanded()); // source needs both

        v.set_outgoing_expanded(true);
        assert!(v.is_expanded());
    }

    #[test]
    fn test_can_expand() {
        let mut v = FcgVertex::new("f", 0x1000, FcgLevel::new(1, FcgDirection::In));
        assert!(!v.can_expand()); // no incoming references

        v.set_has_incoming_references(true);
        assert!(v.can_expand());

        v.set_incoming_expanded(true);
        assert!(!v.can_expand()); // already expanded
    }

    #[test]
    fn test_too_many_references() {
        let mut v = FcgVertex::new("f", 0x1000, FcgLevel::new(1, FcgDirection::In));
        v.set_has_incoming_references(true);
        assert!(v.can_expand_incoming_references());

        v.set_too_many_incoming_references(true);
        assert!(!v.can_expand_incoming_references());
    }

    #[test]
    fn test_equality_by_address() {
        let v1 = FcgVertex::new("foo", 0x1000, FcgLevel::source_level());
        let v2 = FcgVertex::new("bar", 0x1000, FcgLevel::new(1, FcgDirection::In));
        assert_eq!(v1, v2); // same address
    }

    #[test]
    fn test_hover_state() {
        let mut v = FcgVertex::new("f", 0x1000, FcgLevel::source_level());
        assert!(!v.is_hovered());
        v.set_hovered(true);
        assert!(v.is_hovered());
    }

    #[test]
    fn test_display() {
        let v = FcgVertex::new("main", 0x1000, FcgLevel::source_level());
        assert_eq!(v.to_string(), "main");
    }
}
