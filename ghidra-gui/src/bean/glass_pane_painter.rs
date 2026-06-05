//! GGlassPanePainter -- paints overlays on the glass pane.
//!
//! Ports `ghidra.util.bean.GGlassPanePainter`.

/// Paint mode for the glass pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PaintMode {
    /// No painting.
    None,
    /// Paint a drag indicator.
    DragIndicator,
    /// Paint a selection rectangle.
    SelectionRect,
    /// Paint a custom overlay.
    Custom,
}

impl Default for PaintMode {
    fn default() -> Self {
        Self::None
    }
}

/// A painter that draws overlay graphics on a [`GGlassPane`].
///
/// Port of Ghidra's `ghidra.util.bean.GGlassPanePainter`. This component
/// handles the visual feedback during drag-and-drop operations, selection
/// rectangle painting, and other glass pane overlays.
#[derive(Debug, Clone)]
pub struct GGlassPanePainter {
    /// The current paint mode.
    mode: PaintMode,
    /// Origin point of the current drag/selection (x, y).
    origin: Option<(f64, f64)>,
    /// Current point of the drag/selection (x, y).
    current: Option<(f64, f64)>,
    /// Whether the paint is currently active.
    active: bool,
    /// Opacity for the overlay (0.0 - 1.0).
    opacity: f32,
    /// Label text to display near the overlay.
    label: Option<String>,
}

impl GGlassPanePainter {
    /// Create a new painter.
    pub fn new() -> Self {
        Self {
            mode: PaintMode::None,
            origin: None,
            current: None,
            active: false,
            opacity: 0.4,
            label: None,
        }
    }

    /// Begin painting a selection rectangle.
    pub fn begin_selection(&mut self, x: f64, y: f64) {
        self.mode = PaintMode::SelectionRect;
        self.origin = Some((x, y));
        self.current = Some((x, y));
        self.active = true;
    }

    /// Begin painting a drag indicator.
    pub fn begin_drag(&mut self, x: f64, y: f64) {
        self.mode = PaintMode::DragIndicator;
        self.origin = Some((x, y));
        self.current = Some((x, y));
        self.active = true;
    }

    /// Update the current position (for drag/selection tracking).
    pub fn update_position(&mut self, x: f64, y: f64) {
        if self.active {
            self.current = Some((x, y));
        }
    }

    /// End the current painting operation.
    pub fn end(&mut self) {
        self.active = false;
        self.origin = None;
        self.current = None;
        self.label = None;
        self.mode = PaintMode::None;
    }

    /// Whether the painter is currently active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get the current paint mode.
    pub fn mode(&self) -> PaintMode {
        self.mode
    }

    /// Get the bounding rectangle of the current paint region.
    ///
    /// Returns `(x, y, width, height)`.
    pub fn bounds(&self) -> Option<(f64, f64, f64, f64)> {
        if let (Some((ox, oy)), Some((cx, cy))) = (self.origin, self.current) {
            let x = ox.min(cx);
            let y = oy.min(cy);
            let w = (cx - ox).abs();
            let h = (cy - oy).abs();
            Some((x, y, w, h))
        } else {
            None
        }
    }

    /// Set the label text for the overlay.
    pub fn set_label(&mut self, label: impl Into<String>) {
        self.label = Some(label.into());
    }

    /// Get the label text.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Set the opacity.
    pub fn set_opacity(&mut self, opacity: f32) {
        self.opacity = opacity.clamp(0.0, 1.0);
    }

    /// Get the opacity.
    pub fn opacity(&self) -> f32 {
        self.opacity
    }
}

impl Default for GGlassPanePainter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn painter_default() {
        let p = GGlassPanePainter::new();
        assert!(!p.is_active());
        assert_eq!(p.mode(), PaintMode::None);
        assert!(p.bounds().is_none());
    }

    #[test]
    fn painter_selection() {
        let mut p = GGlassPanePainter::new();
        p.begin_selection(10.0, 20.0);
        assert!(p.is_active());
        assert_eq!(p.mode(), PaintMode::SelectionRect);

        p.update_position(100.0, 80.0);
        let bounds = p.bounds().unwrap();
        assert_eq!(bounds, (10.0, 20.0, 90.0, 60.0));

        p.end();
        assert!(!p.is_active());
    }

    #[test]
    fn painter_drag() {
        let mut p = GGlassPanePainter::new();
        p.begin_drag(50.0, 50.0);
        assert!(p.is_active());
        assert_eq!(p.mode(), PaintMode::DragIndicator);

        p.update_position(30.0, 70.0);
        let bounds = p.bounds().unwrap();
        assert_eq!(bounds, (30.0, 50.0, 20.0, 20.0));
    }

    #[test]
    fn painter_label() {
        let mut p = GGlassPanePainter::new();
        p.begin_drag(0.0, 0.0);
        p.set_label("dragging");
        assert_eq!(p.label(), Some("dragging"));
        p.end();
        assert!(p.label().is_none());
    }

    #[test]
    fn painter_opacity() {
        let mut p = GGlassPanePainter::new();
        assert_eq!(p.opacity(), 0.4);
        p.set_opacity(0.8);
        assert_eq!(p.opacity(), 0.8);
        p.set_opacity(1.5);
        assert_eq!(p.opacity(), 1.0);
        p.set_opacity(-0.1);
        assert_eq!(p.opacity(), 0.0);
    }

    #[test]
    fn paint_mode_variants() {
        assert_eq!(PaintMode::default(), PaintMode::None);
        assert_ne!(PaintMode::DragIndicator, PaintMode::SelectionRect);
    }
}
