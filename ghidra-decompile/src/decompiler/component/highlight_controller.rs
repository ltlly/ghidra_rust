//! Highlight controller for the decompiler component.
//!
//! Ports `ghidra.app.decompiler.component.LocationClangHighlightController`
//! and related types.


/// A highlight applied to a token or range of tokens in the decompiler view.
#[derive(Debug, Clone)]
pub struct TokenHighlight {
    /// The node ID of the highlighted token.
    pub node_id: u64,
    /// The highlight color (CSS hex).
    pub color: String,
    /// Priority (higher priority highlights are drawn on top).
    pub priority: i32,
    /// Whether this is a primary (bright) or secondary (dim) highlight.
    pub is_primary: bool,
}

impl TokenHighlight {
    /// Create a new token highlight.
    pub fn new(node_id: u64, color: impl Into<String>, priority: i32) -> Self {
        Self {
            node_id,
            color: color.into(),
            priority,
            is_primary: true,
        }
    }

    /// Create a secondary (dimmer) highlight.
    pub fn secondary(node_id: u64, color: impl Into<String>, priority: i32) -> Self {
        Self {
            node_id,
            color: color.into(),
            priority,
            is_primary: false,
        }
    }
}

/// Manages multiple highlight layers in the decompiler view.
///
/// When the user clicks on a token in the decompiler, related tokens
/// are highlighted. This controller manages those highlights.
#[derive(Debug, Clone, Default)]
pub struct LocationClangHighlightController {
    /// Active primary highlights (e.g., clicked token).
    primary_highlights: Vec<TokenHighlight>,
    /// Active secondary highlights (e.g., related tokens).
    secondary_highlights: Vec<TokenHighlight>,
    /// Colors for primary highlight layers.
    primary_colors: Vec<String>,
    /// Colors for secondary highlight layers.
    secondary_colors: Vec<String>,
}

impl LocationClangHighlightController {
    /// Create a new highlight controller.
    pub fn new() -> Self {
        Self {
            primary_highlights: Vec::new(),
            secondary_highlights: Vec::new(),
            primary_colors: vec![
                "#FFDD44".to_string(),
                "#44DDFF".to_string(),
                "#DD44FF".to_string(),
                "#44FF44".to_string(),
            ],
            secondary_colors: vec![
                "#FFDD4466".to_string(),
                "#44DDFF66".to_string(),
                "#DD44FF66".to_string(),
                "#44FF4466".to_string(),
            ],
        }
    }

    /// Add a primary highlight for a token.
    pub fn add_primary_highlight(&mut self, node_id: u64) {
        let color_idx = self.primary_highlights.len() % self.primary_colors.len();
        let color = self.primary_colors[color_idx].clone();
        self.primary_highlights.push(TokenHighlight::new(node_id, color, 100));
    }

    /// Add a secondary highlight for a token.
    pub fn add_secondary_highlight(&mut self, node_id: u64) {
        let color_idx = self.secondary_highlights.len() % self.secondary_colors.len();
        let color = self.secondary_colors[color_idx].clone();
        self.secondary_highlights.push(TokenHighlight::secondary(node_id, color, 50));
    }

    /// Clear all highlights.
    pub fn clear(&mut self) {
        self.primary_highlights.clear();
        self.secondary_highlights.clear();
    }

    /// Get all active highlights (merged, sorted by priority).
    pub fn get_all_highlights(&self) -> Vec<&TokenHighlight> {
        let mut all: Vec<&TokenHighlight> = self.primary_highlights.iter()
            .chain(self.secondary_highlights.iter())
            .collect();
        all.sort_by(|a, b| b.priority.cmp(&a.priority));
        all
    }

    /// Check if a specific node is highlighted.
    pub fn is_highlighted(&self, node_id: u64) -> bool {
        self.primary_highlights.iter().any(|h| h.node_id == node_id)
            || self.secondary_highlights.iter().any(|h| h.node_id == node_id)
    }

    /// Get the number of active highlights.
    pub fn highlight_count(&self) -> usize {
        self.primary_highlights.len() + self.secondary_highlights.len()
    }
}

/// A null highlight controller that does nothing.
#[derive(Debug, Clone, Default)]
pub struct NullHighlightController;

impl NullHighlightController {
    pub fn new() -> Self { Self }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_highlight_controller() {
        let mut ctrl = LocationClangHighlightController::new();
        assert_eq!(ctrl.highlight_count(), 0);

        ctrl.add_primary_highlight(42);
        assert!(ctrl.is_highlighted(42));
        assert!(!ctrl.is_highlighted(99));

        ctrl.add_secondary_highlight(99);
        assert_eq!(ctrl.highlight_count(), 2);
    }

    #[test]
    fn test_clear_highlights() {
        let mut ctrl = LocationClangHighlightController::new();
        ctrl.add_primary_highlight(1);
        ctrl.add_secondary_highlight(2);
        ctrl.clear();
        assert_eq!(ctrl.highlight_count(), 0);
    }

    #[test]
    fn test_highlight_priority() {
        let mut ctrl = LocationClangHighlightController::new();
        ctrl.add_primary_highlight(1);
        ctrl.add_secondary_highlight(2);
        let all = ctrl.get_all_highlights();
        // Primary has priority 100, secondary has 50
        assert_eq!(all[0].priority, 100);
    }
}
