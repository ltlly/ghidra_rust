//! Layout utility types.
//!
//! Ports Ghidra's `ghidra.util.layout` package, including:
//!
//! - [`BorderType`], [`BorderConfig`] -- border management
//! - [`ColumnLayout`] -- vertical column layout
//! - [`HorizontalLayout`] -- horizontal row layout
//! - [`VerticalLayout`] -- vertical stack layout
//! - [`PairLayout`] -- two-column label/value layout
//! - [`StretchLayout`] -- fills available space
//! - [`MiddleLayout`] -- centers content
//!
//! # Extended Layout Managers (from `managers` submodule)
//!
//! Additional layout managers ported from `ghidra.util.layout`:
//! - [`managers::ColumnLayout`] -- multi-column grid layout with distribution strategies
//! - [`managers::HorizontalLayout`] -- horizontal layout with vertical alignment
//! - [`managers::VerticalLayout`] -- vertical layout with horizontal alignment
//! - [`managers::MiddleLayout`] -- centered content layout
//! - [`managers::PairLayout`] -- label-component pairs
//! - [`managers::StretchLayout`] -- fixed/elastic split layout
//! - [`managers::ThreeColumnLayout`] -- fixed/elastic/fixed three-column layout
//! - [`managers::TwoColumnPairLayout`] -- two-column pair layout
//! - [`managers::VariableHeightPairLayout`] -- variable-height pair layout

pub mod managers;

/// Standard border types used in Ghidra GUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BorderType {
    /// No border.
    None,
    /// An etched border (raised or lowered).
    Etched,
    /// A titled border with a label.
    Titled,
    /// An empty border with padding.
    Empty,
    /// A line border with a single pixel.
    Line,
    /// A compound border (combination of borders).
    Compound,
}

impl Default for BorderType {
    fn default() -> Self {
        Self::None
    }
}

/// Configuration for a border.
#[derive(Debug, Clone)]
pub struct BorderConfig {
    /// The border type.
    pub border_type: BorderType,
    /// Title text (for titled borders).
    pub title: Option<String>,
    /// Padding in pixels.
    pub padding: u32,
    /// Whether the border is raised (for etched borders).
    pub raised: bool,
}

impl Default for BorderConfig {
    fn default() -> Self {
        Self {
            border_type: BorderType::default(),
            title: None,
            padding: 0,
            raised: true,
        }
    }
}

impl BorderConfig {
    /// Create an empty border with padding.
    pub fn empty(padding: u32) -> Self {
        Self {
            border_type: BorderType::Empty,
            padding,
            ..Default::default()
        }
    }

    /// Create a titled border.
    pub fn titled(title: impl Into<String>) -> Self {
        Self {
            border_type: BorderType::Titled,
            title: Some(title.into()),
            ..Default::default()
        }
    }

    /// Create an etched border.
    pub fn etched() -> Self {
        Self {
            border_type: BorderType::Etched,
            ..Default::default()
        }
    }
}

// ===========================================================================
// Layout Managers
// Ports `ghidra.util.layout` classes.
// ===========================================================================

/// A simple 2D rectangle for layout calculations.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LayoutRect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl LayoutRect {
    pub fn new(x: f64, y: f64, width: f64, height: f64) -> Self {
        Self { x, y, width, height }
    }
}

/// A layout strategy that positions children.
pub trait LayoutManager: std::fmt::Debug {
    /// Compute the positions of children given the available bounds.
    fn layout(&self, bounds: LayoutRect, child_count: usize) -> Vec<LayoutRect>;
}

/// Column layout: stacks children vertically.
///
/// Ports `ghidra.util.layout.ColumnLayout`.
#[derive(Debug, Clone)]
pub struct ColumnLayout {
    /// Gap between rows.
    pub gap: f64,
}

impl Default for ColumnLayout {
    fn default() -> Self {
        Self { gap: 4.0 }
    }
}

impl LayoutManager for ColumnLayout {
    fn layout(&self, bounds: LayoutRect, child_count: usize) -> Vec<LayoutRect> {
        if child_count == 0 {
            return Vec::new();
        }
        let total_gap = self.gap * (child_count - 1) as f64;
        let child_height = ((bounds.height - total_gap) / child_count as f64).max(0.0);
        (0..child_count)
            .map(|i| {
                LayoutRect::new(
                    bounds.x,
                    bounds.y + i as f64 * (child_height + self.gap),
                    bounds.width,
                    child_height,
                )
            })
            .collect()
    }
}

/// Horizontal layout: places children side by side.
///
/// Ports `ghidra.util.layout.HorizontalLayout`.
#[derive(Debug, Clone)]
pub struct HorizontalLayout {
    /// Gap between columns.
    pub gap: f64,
}

impl Default for HorizontalLayout {
    fn default() -> Self {
        Self { gap: 4.0 }
    }
}

impl LayoutManager for HorizontalLayout {
    fn layout(&self, bounds: LayoutRect, child_count: usize) -> Vec<LayoutRect> {
        if child_count == 0 {
            return Vec::new();
        }
        let total_gap = self.gap * (child_count - 1) as f64;
        let child_width = ((bounds.width - total_gap) / child_count as f64).max(0.0);
        (0..child_count)
            .map(|i| {
                LayoutRect::new(
                    bounds.x + i as f64 * (child_width + self.gap),
                    bounds.y,
                    child_width,
                    bounds.height,
                )
            })
            .collect()
    }
}

/// Vertical layout: stacks children vertically (alias for ColumnLayout).
///
/// Ports `ghidra.util.layout.VerticalLayout`.
pub type VerticalLayout = ColumnLayout;

/// Pair layout: two-column label-value layout.
///
/// Ports `ghidra.util.layout.PairLayout`.
#[derive(Debug, Clone)]
pub struct PairLayout {
    /// Width of the label column.
    pub label_width: f64,
    /// Gap between label and value columns.
    pub gap: f64,
    /// Vertical gap between rows.
    pub row_gap: f64,
}

impl Default for PairLayout {
    fn default() -> Self {
        Self {
            label_width: 150.0,
            gap: 8.0,
            row_gap: 4.0,
        }
    }
}

impl PairLayout {
    /// Compute the label and value rectangles for a row at `y`.
    pub fn row_rects(&self, bounds: LayoutRect, y: f64, row_height: f64) -> (LayoutRect, LayoutRect) {
        let label = LayoutRect::new(bounds.x, y, self.label_width, row_height);
        let value = LayoutRect::new(
            bounds.x + self.label_width + self.gap,
            y,
            bounds.width - self.label_width - self.gap,
            row_height,
        );
        (label, value)
    }
}

/// Stretch layout: fills the entire available space.
///
/// Ports `ghidra.util.layout.StretchLayout`.
#[derive(Debug, Clone, Copy, Default)]
pub struct StretchLayout;

impl LayoutManager for StretchLayout {
    fn layout(&self, bounds: LayoutRect, child_count: usize) -> Vec<LayoutRect> {
        (0..child_count).map(|_| bounds).collect()
    }
}

/// Middle layout: centers content.
///
/// Ports `ghidra.util.layout.MiddleLayout`.
#[derive(Debug, Clone)]
pub struct MiddleLayout {
    /// Fixed child width (0 = use bounds width).
    pub child_width: f64,
    /// Fixed child height (0 = use bounds height).
    pub child_height: f64,
}

impl Default for MiddleLayout {
    fn default() -> Self {
        Self {
            child_width: 0.0,
            child_height: 0.0,
        }
    }
}

impl LayoutManager for MiddleLayout {
    fn layout(&self, bounds: LayoutRect, child_count: usize) -> Vec<LayoutRect> {
        let w = if self.child_width > 0.0 {
            self.child_width
        } else {
            bounds.width
        };
        let h = if self.child_height > 0.0 {
            self.child_height
        } else {
            bounds.height
        };
        let x = bounds.x + (bounds.width - w) / 2.0;
        let y = bounds.y + (bounds.height - h) / 2.0;
        let rect = LayoutRect::new(x, y, w, h);
        (0..child_count).map(|_| rect).collect()
    }
}

/// Three-column layout: left, center, right.
///
/// Ports `ghidra.util.layout.ThreeColumnLayout`.
#[derive(Debug, Clone)]
pub struct ThreeColumnLayout {
    /// Width of the left column.
    pub left_width: f64,
    /// Width of the right column.
    pub right_width: f64,
    /// Gap between columns.
    pub gap: f64,
}

impl Default for ThreeColumnLayout {
    fn default() -> Self {
        Self {
            left_width: 100.0,
            right_width: 100.0,
            gap: 4.0,
        }
    }
}

impl ThreeColumnLayout {
    /// Compute the three column rectangles.
    pub fn column_rects(&self, bounds: LayoutRect) -> (LayoutRect, LayoutRect, LayoutRect) {
        let left = LayoutRect::new(bounds.x, bounds.y, self.left_width, bounds.height);
        let center = LayoutRect::new(
            bounds.x + self.left_width + self.gap,
            bounds.y,
            bounds.width - self.left_width - self.right_width - 2.0 * self.gap,
            bounds.height,
        );
        let right = LayoutRect::new(
            bounds.x + bounds.width - self.right_width,
            bounds.y,
            self.right_width,
            bounds.height,
        );
        (left, center, right)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_border_type_default() {
        assert_eq!(BorderType::default(), BorderType::None);
    }

    #[test]
    fn test_border_config_empty() {
        let config = BorderConfig::empty(10);
        assert_eq!(config.border_type, BorderType::Empty);
        assert_eq!(config.padding, 10);
    }

    #[test]
    fn test_border_config_titled() {
        let config = BorderConfig::titled("Options");
        assert_eq!(config.border_type, BorderType::Titled);
        assert_eq!(config.title.as_deref(), Some("Options"));
    }

    #[test]
    fn test_border_config_etched() {
        let config = BorderConfig::etched();
        assert_eq!(config.border_type, BorderType::Etched);
        assert!(config.raised);
    }

    // Layout manager tests.

    #[test]
    fn column_layout_two_children() {
        let layout = ColumnLayout::default();
        let bounds = LayoutRect::new(0.0, 0.0, 200.0, 100.0);
        let rects = layout.layout(bounds, 2);
        assert_eq!(rects.len(), 2);
        // total_gap = 4.0, child_height = (100 - 4) / 2 = 48.0
        assert!((rects[0].y - 0.0).abs() < 1e-6);
        assert!((rects[1].y - 52.0).abs() < 1e-6); // 48 + 4
        assert!((rects[0].width - 200.0).abs() < 1e-6);
    }

    #[test]
    fn horizontal_layout_three_children() {
        let layout = HorizontalLayout { gap: 10.0 };
        let bounds = LayoutRect::new(0.0, 0.0, 320.0, 50.0);
        let rects = layout.layout(bounds, 3);
        assert_eq!(rects.len(), 3);
        // total_gap = 20.0, child_width = (320 - 20) / 3 = 100.0
        assert!((rects[0].x - 0.0).abs() < 1e-6);
        assert!((rects[0].width - 100.0).abs() < 1e-6);
        assert!((rects[1].x - 110.0).abs() < 1e-6);
    }

    #[test]
    fn column_layout_empty() {
        let layout = ColumnLayout::default();
        let rects = layout.layout(LayoutRect::new(0.0, 0.0, 100.0, 100.0), 0);
        assert!(rects.is_empty());
    }

    #[test]
    fn stretch_layout_fills_bounds() {
        let layout = StretchLayout;
        let bounds = LayoutRect::new(10.0, 20.0, 300.0, 400.0);
        let rects = layout.layout(bounds, 3);
        assert_eq!(rects.len(), 3);
        for r in &rects {
            assert_eq!(*r, bounds);
        }
    }

    #[test]
    fn middle_layout_centers() {
        let layout = MiddleLayout {
            child_width: 100.0,
            child_height: 50.0,
        };
        let bounds = LayoutRect::new(0.0, 0.0, 200.0, 100.0);
        let rects = layout.layout(bounds, 1);
        assert_eq!(rects.len(), 1);
        assert!((rects[0].x - 50.0).abs() < 1e-6);
        assert!((rects[0].y - 25.0).abs() < 1e-6);
        assert_eq!(rects[0].width, 100.0);
        assert_eq!(rects[0].height, 50.0);
    }

    #[test]
    fn pair_layout_row_rects() {
        let layout = PairLayout::default();
        let bounds = LayoutRect::new(0.0, 0.0, 400.0, 100.0);
        let (label, value) = layout.row_rects(bounds, 10.0, 24.0);
        assert_eq!(label.width, 150.0);
        assert_eq!(label.x, 0.0);
        assert_eq!(value.x, 158.0); // label_width + gap
        assert_eq!(label.y, 10.0);
    }

    #[test]
    fn three_column_layout_rects() {
        let layout = ThreeColumnLayout {
            left_width: 100.0,
            right_width: 100.0,
            gap: 5.0,
        };
        let bounds = LayoutRect::new(0.0, 0.0, 400.0, 50.0);
        let (left, center, right) = layout.column_rects(bounds);
        assert_eq!(left.width, 100.0);
        assert_eq!(center.width, 190.0); // 400 - 100 - 100 - 2*5
        assert_eq!(right.width, 100.0);
    }
}
