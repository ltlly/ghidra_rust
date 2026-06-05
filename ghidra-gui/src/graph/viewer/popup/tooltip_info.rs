//! Tooltip information for graph elements.
//!
//! Ports `ghidra.graph.viewer.popup.ToolTipInfo`.

/// Tooltip information for a graph vertex or edge.
#[derive(Debug, Clone)]
pub struct ToolTipInfo {
    /// The tooltip text (may be HTML).
    pub text: String,
    /// Maximum width of the tooltip in pixels.
    pub max_width: u32,
    /// Whether the tooltip has been explicitly set.
    pub is_custom: bool,
}

impl ToolTipInfo {
    /// Create tooltip info from text.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            max_width: 400,
            is_custom: false,
        }
    }

    /// Create custom tooltip info.
    pub fn custom(text: impl Into<String>, max_width: u32) -> Self {
        Self {
            text: text.into(),
            max_width,
            is_custom: true,
        }
    }

    /// Get the tooltip text.
    pub fn get_text(&self) -> &str {
        &self.text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tooltip_info() {
        let info = ToolTipInfo::new("Vertex 42");
        assert_eq!(info.get_text(), "Vertex 42");
        assert!(!info.is_custom);
    }

    #[test]
    fn test_custom_tooltip() {
        let info = ToolTipInfo::custom("<b>Bold</b>", 300);
        assert!(info.is_custom);
        assert_eq!(info.max_width, 300);
    }
}
