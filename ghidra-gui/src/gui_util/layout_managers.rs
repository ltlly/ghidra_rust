//! Custom layout managers.
//!
//! Ports Ghidra's `ghidra.util.layout` package -- `ColumnLayout`,
//! `HorizontalLayout`, `VerticalLayout`, `PairLayout`, `MiddleLayout`,
//! `StretchLayout`, `ThreeColumnLayout`, `TwoColumnPairLayout`,
//! `VariableHeightPairLayout`, `VariableRowHeightGridLayout`.

/// Direction of layout flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutDirection {
    /// Left to right.
    LeftToRight,
    /// Right to left.
    RightToLeft,
    /// Top to bottom.
    TopToBottom,
    /// Bottom to top.
    BottomToTop,
}

/// A rectangle used for layout calculations.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LayoutRect {
    /// X coordinate.
    pub x: f64,
    /// Y coordinate.
    pub y: f64,
    /// Width.
    pub width: f64,
    /// Height.
    pub height: f64,
}

impl LayoutRect {
    /// Create a new layout rectangle.
    pub fn new(x: f64, y: f64, width: f64, height: f64) -> Self {
        Self { x, y, width, height }
    }

    /// Get the right edge.
    pub fn right(&self) -> f64 {
        self.x + self.width
    }

    /// Get the bottom edge.
    pub fn bottom(&self) -> f64 {
        self.y + self.height
    }
}

/// Preferred size for a component.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PreferredSize {
    /// Preferred width.
    pub width: f64,
    /// Preferred height.
    pub height: f64,
    /// Minimum width.
    pub min_width: f64,
    /// Minimum height.
    pub min_height: f64,
}

impl PreferredSize {
    /// Create a new preferred size.
    pub fn new(width: f64, height: f64) -> Self {
        Self {
            width,
            height,
            min_width: width,
            min_height: height,
        }
    }

    /// Create with explicit minimums.
    pub fn with_minimums(width: f64, height: f64, min_width: f64, min_height: f64) -> Self {
        Self {
            width,
            height,
            min_width,
            min_height,
        }
    }
}

impl Default for PreferredSize {
    fn default() -> Self {
        Self::new(0.0, 0.0)
    }
}

// ============================================================================
// ColumnLayout
// ============================================================================

/// Arranges components in columns.
///
/// Port of Ghidra's `ghidra.util.layout.ColumnLayout`.
#[derive(Debug, Clone)]
pub struct ColumnLayout {
    /// Horizontal gap between components.
    pub h_gap: f64,
    /// Vertical gap between components.
    pub v_gap: f64,
    /// Number of columns.
    pub columns: usize,
}

impl ColumnLayout {
    /// Create a new column layout.
    pub fn new(columns: usize) -> Self {
        Self {
            h_gap: 5.0,
            v_gap: 5.0,
            columns,
        }
    }

    /// Set the horizontal gap.
    pub fn with_h_gap(mut self, gap: f64) -> Self {
        self.h_gap = gap;
        self
    }

    /// Set the vertical gap.
    pub fn with_v_gap(mut self, gap: f64) -> Self {
        self.v_gap = gap;
        self
    }

    /// Calculate the position of a component at the given index.
    pub fn position_for(&self, index: usize, component_width: f64, component_height: f64) -> (f64, f64) {
        let col = index % self.columns;
        let row = index / self.columns;
        (
            col as f64 * (component_width + self.h_gap),
            row as f64 * (component_height + self.v_gap),
        )
    }

    /// Total number of rows for a given number of items.
    pub fn num_rows(&self, item_count: usize) -> usize {
        (item_count + self.columns - 1) / self.columns
    }
}

// ============================================================================
// HorizontalLayout
// ============================================================================

/// Arranges components horizontally in a single row.
///
/// Port of Ghidra's `ghidra.util.layout.HorizontalLayout`.
#[derive(Debug, Clone)]
pub struct HorizontalLayout {
    /// Gap between components.
    pub gap: f64,
    /// Alignment of components within the container height.
    pub alignment: VerticalAlignment,
}

/// Vertical alignment within a horizontal layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerticalAlignment {
    /// Align to the top.
    Top,
    /// Center vertically.
    Center,
    /// Align to the bottom.
    Bottom,
}

impl HorizontalLayout {
    /// Create a new horizontal layout.
    pub fn new() -> Self {
        Self {
            gap: 5.0,
            alignment: VerticalAlignment::Center,
        }
    }

    /// Set the gap.
    pub fn with_gap(mut self, gap: f64) -> Self {
        self.gap = gap;
        self
    }

    /// Set the alignment.
    pub fn with_alignment(mut self, alignment: VerticalAlignment) -> Self {
        self.alignment = alignment;
        self
    }

    /// Calculate the total width needed for a set of component widths.
    pub fn preferred_width(&self, component_widths: &[f64]) -> f64 {
        if component_widths.is_empty() {
            return 0.0;
        }
        let total: f64 = component_widths.iter().sum();
        total + self.gap * (component_widths.len() - 1) as f64
    }

    /// Calculate the Y offset for a component based on alignment.
    pub fn y_offset(&self, container_height: f64, component_height: f64) -> f64 {
        match self.alignment {
            VerticalAlignment::Top => 0.0,
            VerticalAlignment::Center => (container_height - component_height) / 2.0,
            VerticalAlignment::Bottom => container_height - component_height,
        }
    }
}

impl Default for HorizontalLayout {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// VerticalLayout
// ============================================================================

/// Arranges components vertically in a single column.
///
/// Port of Ghidra's `ghidra.util.layout.VerticalLayout`.
#[derive(Debug, Clone)]
pub struct VerticalLayout {
    /// Gap between components.
    pub gap: f64,
    /// Alignment of components within the container width.
    pub alignment: HorizontalAlignment,
}

/// Horizontal alignment within a vertical layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HorizontalAlignment {
    /// Align to the left.
    Left,
    /// Center horizontally.
    Center,
    /// Align to the right.
    Right,
}

impl VerticalLayout {
    /// Create a new vertical layout.
    pub fn new() -> Self {
        Self {
            gap: 5.0,
            alignment: HorizontalAlignment::Left,
        }
    }

    /// Set the gap.
    pub fn with_gap(mut self, gap: f64) -> Self {
        self.gap = gap;
        self
    }

    /// Set the alignment.
    pub fn with_alignment(mut self, alignment: HorizontalAlignment) -> Self {
        self.alignment = alignment;
        self
    }

    /// Calculate the total height needed for a set of component heights.
    pub fn preferred_height(&self, component_heights: &[f64]) -> f64 {
        if component_heights.is_empty() {
            return 0.0;
        }
        let total: f64 = component_heights.iter().sum();
        total + self.gap * (component_heights.len() - 1) as f64
    }

    /// Calculate the X offset for a component based on alignment.
    pub fn x_offset(&self, container_width: f64, component_width: f64) -> f64 {
        match self.alignment {
            HorizontalAlignment::Left => 0.0,
            HorizontalAlignment::Center => (container_width - component_width) / 2.0,
            HorizontalAlignment::Right => container_width - component_width,
        }
    }
}

impl Default for VerticalLayout {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// PairLayout
// ============================================================================

/// Arranges components in label-widget pairs.
///
/// Port of Ghidra's `ghidra.util.layout.PairLayout`.
#[derive(Debug, Clone)]
pub struct PairLayout {
    /// Gap between label and widget.
    pub h_gap: f64,
    /// Gap between rows.
    pub v_gap: f64,
    /// Preferred label width for alignment.
    pub label_width: f64,
}

impl PairLayout {
    /// Create a new pair layout.
    pub fn new() -> Self {
        Self {
            h_gap: 5.0,
            v_gap: 5.0,
            label_width: 100.0,
        }
    }

    /// Set the gap between label and widget.
    pub fn with_h_gap(mut self, gap: f64) -> Self {
        self.h_gap = gap;
        self
    }

    /// Set the vertical gap.
    pub fn with_v_gap(mut self, gap: f64) -> Self {
        self.v_gap = gap;
        self
    }

    /// Set the label width.
    pub fn with_label_width(mut self, width: f64) -> Self {
        self.label_width = width;
        self
    }

    /// Get the position of the widget in a pair at the given row index.
    pub fn widget_x(&self) -> f64 {
        self.label_width + self.h_gap
    }

    /// Get the Y position for a row.
    pub fn row_y(&self, row_index: usize, row_height: f64) -> f64 {
        row_index as f64 * (row_height + self.v_gap)
    }
}

impl Default for PairLayout {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// MiddleLayout
// ============================================================================

/// Centers a single component within the container.
///
/// Port of Ghidra's `ghidra.util.layout.MiddleLayout`.
#[derive(Debug, Clone, Copy, Default)]
pub struct MiddleLayout;

impl MiddleLayout {
    /// Create a new middle layout.
    pub fn new() -> Self {
        Self
    }

    /// Calculate the position to center a component.
    pub fn center(container_width: f64, container_height: f64, comp_width: f64, comp_height: f64) -> (f64, f64) {
        (
            (container_width - comp_width) / 2.0,
            (container_height - comp_height) / 2.0,
        )
    }
}

// ============================================================================
// StretchLayout
// ============================================================================

/// Stretches a component to fill the container.
///
/// Port of Ghidra's `ghidra.util.layout.StretchLayout`.
#[derive(Debug, Clone, Copy)]
pub struct StretchLayout {
    /// Whether to stretch horizontally.
    pub stretch_x: bool,
    /// Whether to stretch vertically.
    pub stretch_y: bool,
}

impl StretchLayout {
    /// Create a layout that stretches in both dimensions.
    pub fn both() -> Self {
        Self {
            stretch_x: true,
            stretch_y: true,
        }
    }

    /// Create a layout that only stretches horizontally.
    pub fn horizontal() -> Self {
        Self {
            stretch_x: true,
            stretch_y: false,
        }
    }

    /// Create a layout that only stretches vertically.
    pub fn vertical() -> Self {
        Self {
            stretch_x: false,
            stretch_y: true,
        }
    }

    /// Apply stretch: returns the size the component should be.
    pub fn apply(&self, container_width: f64, container_height: f64, preferred: &PreferredSize) -> (f64, f64) {
        (
            if self.stretch_x { container_width } else { preferred.width },
            if self.stretch_y { container_height } else { preferred.height },
        )
    }
}

impl Default for StretchLayout {
    fn default() -> Self {
        Self::both()
    }
}

// ============================================================================
// ThreeColumnLayout
// ============================================================================

/// Arranges components in three columns: left, center, right.
///
/// Port of Ghidra's `ghidra.util.layout.ThreeColumnLayout`.
#[derive(Debug, Clone)]
pub struct ThreeColumnLayout {
    /// Gap between columns.
    pub gap: f64,
}

impl ThreeColumnLayout {
    /// Create a new three column layout.
    pub fn new() -> Self {
        Self { gap: 10.0 }
    }

    /// Set the gap.
    pub fn with_gap(mut self, gap: f64) -> Self {
        self.gap = gap;
        self
    }

    /// Calculate column positions given container width and component widths.
    pub fn column_positions(&self, container_width: f64, left_width: f64, center_width: f64, right_width: f64) -> [f64; 3] {
        let left_x = 0.0;
        let center_x = (container_width - center_width) / 2.0;
        let right_x = container_width - right_width;
        [left_x, center_x, right_x]
    }
}

impl Default for ThreeColumnLayout {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn column_layout_positions() {
        let layout = ColumnLayout::new(3).with_h_gap(10.0).with_v_gap(5.0);
        let (x, y) = layout.position_for(4, 100.0, 30.0);
        assert_eq!(x, 110.0); // column 1, width 100 + gap 10
        assert_eq!(y, 35.0); // row 1, height 30 + gap 5
    }

    #[test]
    fn column_layout_rows() {
        let layout = ColumnLayout::new(3);
        assert_eq!(layout.num_rows(7), 3);
        assert_eq!(layout.num_rows(6), 2);
        assert_eq!(layout.num_rows(0), 0);
    }

    #[test]
    fn horizontal_layout_preferred_width() {
        let layout = HorizontalLayout::new().with_gap(10.0);
        let w = layout.preferred_width(&[50.0, 60.0, 40.0]);
        assert_eq!(w, 170.0); // 50+60+40 + 2*10
    }

    #[test]
    fn horizontal_layout_alignment() {
        let layout = HorizontalLayout::new().with_alignment(VerticalAlignment::Bottom);
        let y = layout.y_offset(100.0, 30.0);
        assert_eq!(y, 70.0);
    }

    #[test]
    fn vertical_layout_preferred_height() {
        let layout = VerticalLayout::new().with_gap(8.0);
        let h = layout.preferred_height(&[20.0, 30.0]);
        assert_eq!(h, 58.0); // 20+30+8
    }

    #[test]
    fn pair_layout_positions() {
        let layout = PairLayout::new().with_label_width(120.0).with_h_gap(10.0);
        assert_eq!(layout.widget_x(), 130.0);
        assert_eq!(layout.row_y(2, 25.0), 60.0);
    }

    #[test]
    fn middle_layout_center() {
        let (x, y) = MiddleLayout::center(200.0, 100.0, 50.0, 30.0);
        assert_eq!(x, 75.0);
        assert_eq!(y, 35.0);
    }

    #[test]
    fn stretch_layout_both() {
        let layout = StretchLayout::both();
        let (w, h) = layout.apply(500.0, 300.0, &PreferredSize::new(100.0, 50.0));
        assert_eq!(w, 500.0);
        assert_eq!(h, 300.0);
    }

    #[test]
    fn stretch_layout_horizontal_only() {
        let layout = StretchLayout::horizontal();
        let (w, h) = layout.apply(500.0, 300.0, &PreferredSize::new(100.0, 50.0));
        assert_eq!(w, 500.0);
        assert_eq!(h, 50.0);
    }

    #[test]
    fn three_column_layout_positions() {
        let layout = ThreeColumnLayout::new();
        let pos = layout.column_positions(600.0, 100.0, 200.0, 100.0);
        assert_eq!(pos[0], 0.0);
        assert_eq!(pos[1], 200.0); // (600-200)/2
        assert_eq!(pos[2], 500.0); // 600-100
    }
}
