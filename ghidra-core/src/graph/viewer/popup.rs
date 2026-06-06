//! Popup (context menu) management for the graph viewer.
//!
//! Ports Ghidra's `ghidra.graph.viewer.popup` package.

use super::visual_types::Point2d;

// ============================================================================
// ToolTipInfo -- information for rendering a tooltip
// ============================================================================

/// Information needed to render a tooltip near a vertex or edge.
///
/// Ports `ghidra.graph.viewer.popup.ToolTipInfo`.
#[derive(Debug, Clone)]
pub struct ToolTipInfo {
    /// The text to display in the tooltip.
    pub text: String,
    /// The position where the tooltip should appear.
    pub position: Point2d,
    /// The vertex ID that the tooltip is for (if any).
    pub vertex_id: Option<usize>,
    /// The edge ID that the tooltip is for (if any).
    pub edge_id: Option<usize>,
}

impl ToolTipInfo {
    /// Create tooltip info for a vertex.
    pub fn for_vertex(vertex_id: usize, text: impl Into<String>, position: Point2d) -> Self {
        Self {
            text: text.into(),
            position,
            vertex_id: Some(vertex_id),
            edge_id: None,
        }
    }

    /// Create tooltip info for an edge.
    pub fn for_edge(edge_id: usize, text: impl Into<String>, position: Point2d) -> Self {
        Self {
            text: text.into(),
            position,
            vertex_id: None,
            edge_id: Some(edge_id),
        }
    }
}

// ============================================================================
// PopupSource -- identifies the source of a popup request
// ============================================================================

/// Identifies the source (vertex, edge, or background) of a popup request.
///
/// Ports `ghidra.graph.viewer.popup.PopupSource`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PopupSource {
    /// Popup triggered on a vertex.
    Vertex(usize),
    /// Popup triggered on an edge.
    Edge(usize),
    /// Popup triggered on the background.
    Background,
}

// ============================================================================
// PopupRegulator -- controls when and how popups appear
// ============================================================================

/// Controls popup display timing and positioning.
///
/// Ports `ghidra.graph.viewer.popup.PopupRegulator`.  Manages delay,
/// debouncing, and positioning of context menus and tooltips.
#[derive(Debug)]
pub struct PopupRegulator {
    /// Delay in milliseconds before showing a popup.
    popup_delay_ms: u64,
    /// Whether a popup is currently pending.
    pending: bool,
    /// The pending popup source.
    pending_source: Option<PopupSource>,
    /// The pending popup position.
    pending_position: Option<Point2d>,
    /// Whether popups are enabled.
    enabled: bool,
}

impl PopupRegulator {
    /// Create a new popup regulator.
    pub fn new() -> Self {
        Self {
            popup_delay_ms: 500,
            pending: false,
            pending_source: None,
            pending_position: None,
            enabled: true,
        }
    }

    /// Request a popup at the given position for the given source.
    pub fn request_popup(&mut self, source: PopupSource, position: Point2d) {
        if !self.enabled {
            return;
        }
        self.pending = true;
        self.pending_source = Some(source);
        self.pending_position = Some(position);
    }

    /// Check if a popup is pending.
    pub fn is_pending(&self) -> bool {
        self.pending
    }

    /// Consume the pending popup, returning (source, position) if available.
    pub fn consume_popup(&mut self) -> Option<(PopupSource, Point2d)> {
        if !self.pending {
            return None;
        }
        self.pending = false;
        match (self.pending_source.take(), self.pending_position.take()) {
            (Some(source), Some(position)) => Some((source, position)),
            _ => None,
        }
    }

    /// Cancel any pending popup.
    pub fn cancel(&mut self) {
        self.pending = false;
        self.pending_source = None;
        self.pending_position = None;
    }

    /// Set the popup delay in milliseconds.
    pub fn set_delay(&mut self, delay_ms: u64) {
        self.popup_delay_ms = delay_ms;
    }

    /// Get the popup delay.
    pub fn delay(&self) -> u64 {
        self.popup_delay_ms
    }

    /// Enable or disable popups.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            self.cancel();
        }
    }

    /// Whether popups are enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl Default for PopupRegulator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tooltip_info_vertex() {
        let info = ToolTipInfo::for_vertex(1, "hello", Point2d::new(10.0, 20.0));
        assert_eq!(info.vertex_id, Some(1));
        assert_eq!(info.edge_id, None);
    }

    #[test]
    fn test_popup_regulator_request_and_consume() {
        let mut regulator = PopupRegulator::new();
        regulator.request_popup(PopupSource::Vertex(5), Point2d::new(100.0, 200.0));
        assert!(regulator.is_pending());

        let result = regulator.consume_popup();
        assert!(result.is_some());
        let (source, pos) = result.unwrap();
        assert_eq!(source, PopupSource::Vertex(5));
        assert_eq!(pos, Point2d::new(100.0, 200.0));
        assert!(!regulator.is_pending());
    }

    #[test]
    fn test_popup_regulator_cancel() {
        let mut regulator = PopupRegulator::new();
        regulator.request_popup(PopupSource::Background, Point2d::default());
        regulator.cancel();
        assert!(!regulator.is_pending());
        assert!(regulator.consume_popup().is_none());
    }

    #[test]
    fn test_popup_regulator_disabled() {
        let mut regulator = PopupRegulator::new();
        regulator.set_enabled(false);
        regulator.request_popup(PopupSource::Vertex(1), Point2d::default());
        assert!(!regulator.is_pending()); // rejected because disabled
    }
}
