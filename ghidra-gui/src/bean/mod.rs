//! Bean component utilities.
//!
//! Ports Ghidra's `ghidra.util.bean` types for option editor panels and
//! chooser widgets.
//!
//! # Sub-modules
//!
//! - [`glass_pane_painter`] -- Overlay painter for drag/selection feedback

pub mod glass_pane_painter;
pub mod gglass_pane;

pub use glass_pane_painter::{GGlassPanePainter, PaintMode};
pub use gglass_pane::{GGlassPane as FullGGlassPane, DirtyRegion, PainterId as GlassPainterId};

/// Exception thrown when an option editor vetoes a proposed change.
///
/// Port of Ghidra's `ghidra.util.bean.opteditor.OptionsVetoException`.
#[derive(Debug, Clone)]
pub struct OptionsVetoException {
    /// The reason the change was vetoed.
    pub message: String,
}

impl OptionsVetoException {
    /// Create a new OptionsVetoException with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for OptionsVetoException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for OptionsVetoException {}

/// A glass pane overlay for the application window.
///
/// Port of Ghidra's `ghidra.util.bean.GGlassPane`. Used to paint
/// temporary overlays (drag-and-drop feedback, selection rectangles,
/// custom cursors) on top of the main content.
#[derive(Debug, Clone)]
pub struct GGlassPane {
    /// Whether the glass pane is currently visible.
    visible: bool,
    /// Opacity of the glass pane overlay (0.0 = transparent, 1.0 = opaque).
    pub opacity: f64,
    /// Whether mouse events should be captured by the glass pane.
    pub capture_mouse: bool,
    /// Description of what the glass pane is currently painting.
    pub paint_description: Option<String>,
}

impl GGlassPane {
    /// Create a new glass pane.
    pub fn new() -> Self {
        Self {
            visible: false,
            opacity: 0.3,
            capture_mouse: false,
            paint_description: None,
        }
    }

    /// Show the glass pane.
    pub fn show(&mut self) {
        self.visible = true;
    }

    /// Hide the glass pane.
    pub fn hide(&mut self) {
        self.visible = false;
        self.paint_description = None;
    }

    /// Whether the glass pane is currently visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set what the glass pane is painting (for debugging/UI purposes).
    pub fn set_paint_description(&mut self, desc: impl Into<String>) {
        self.paint_description = Some(desc.into());
    }
}

impl Default for GGlassPane {
    fn default() -> Self {
        Self::new()
    }
}

/// Select mode for choosers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelectMode {
    /// Select a single item.
    Single,
    /// Select multiple items.
    Multiple,
    /// Select a contiguous range of items.
    Contiguous,
}

impl Default for SelectMode {
    fn default() -> Self {
        Self::Single
    }
}

/// Abstract chooser base types for selection panels.
///
/// Ports Ghidra's `ghidra.util.bean.opteditor.AbstractChooser`.
#[derive(Debug, Clone)]
pub struct AbstractChooser {
    /// The title of the chooser.
    title: String,
    /// Whether the chooser allows multiple selections.
    select_mode: SelectMode,
    /// The currently selected items.
    selected_items: Vec<String>,
}

impl AbstractChooser {
    /// Create a new chooser.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            select_mode: SelectMode::default(),
            selected_items: Vec::new(),
        }
    }

    /// Set the selection mode.
    pub fn set_select_mode(&mut self, mode: SelectMode) {
        self.select_mode = mode;
    }

    /// Get the selection mode.
    pub fn select_mode(&self) -> SelectMode {
        self.select_mode
    }

    /// Get the title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Set the selected items.
    pub fn set_selected(&mut self, items: Vec<String>) {
        self.selected_items = items;
    }

    /// Get the selected items.
    pub fn selected(&self) -> &[String] {
        &self.selected_items
    }

    /// Get the first selected item, if any.
    pub fn first_selected(&self) -> Option<&str> {
        self.selected_items.first().map(|s| s.as_str())
    }

    /// Clear the selection.
    pub fn clear_selection(&mut self) {
        self.selected_items.clear();
    }

    /// Check if anything is selected.
    pub fn has_selection(&self) -> bool {
        !self.selected_items.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_options_veto_exception() {
        let exc = OptionsVetoException::new("Value out of range");
        assert_eq!(exc.to_string(), "Value out of range");
        assert_eq!(exc.message, "Value out of range");
    }

    #[test]
    fn test_gglass_pane_default() {
        let pane = GGlassPane::new();
        assert!(!pane.is_visible());
        assert!((pane.opacity - 0.3).abs() < 1e-6);
        assert!(!pane.capture_mouse);
    }

    #[test]
    fn test_gglass_pane_show_hide() {
        let mut pane = GGlassPane::new();
        pane.show();
        assert!(pane.is_visible());
        pane.set_paint_description("drag");
        assert_eq!(pane.paint_description.as_deref(), Some("drag"));
        pane.hide();
        assert!(!pane.is_visible());
        assert!(pane.paint_description.is_none());
    }

    #[test]
    fn test_abstract_chooser_basic() {
        let chooser = AbstractChooser::new("Select Option");
        assert_eq!(chooser.title(), "Select Option");
        assert_eq!(chooser.select_mode(), SelectMode::Single);
        assert!(!chooser.has_selection());
    }

    #[test]
    fn test_abstract_chooser_selection() {
        let mut chooser = AbstractChooser::new("Test");
        chooser.set_select_mode(SelectMode::Multiple);
        chooser.set_selected(vec!["a".into(), "b".into(), "c".into()]);

        assert!(chooser.has_selection());
        assert_eq!(chooser.selected().len(), 3);
        assert_eq!(chooser.first_selected(), Some("a"));

        chooser.clear_selection();
        assert!(!chooser.has_selection());
        assert!(chooser.first_selected().is_none());
    }
}
