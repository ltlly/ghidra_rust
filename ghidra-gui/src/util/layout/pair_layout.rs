//! PairLayout -- a two-column layout with label/value semantics.
//!
//! Ports `ghidra.util.layout.PairLayout`. Components are arranged in
//! two columns: left column (labels) and right column (values).
//! All rows share the same height (the maximum preferred height).

/// Minimum width for the right column.
pub const MINIMUM_RIGHT_COLUMN_WIDTH: f64 = 80.0;

/// Layout manager for arranging components into exactly two columns.
///
/// The right column and left column may have differing widths.
/// Each row is the same height -- the largest of all row heights.
///
/// Ports `ghidra.util.layout.PairLayout`.
#[derive(Debug, Clone)]
pub struct PairLayout {
    /// Gap between rows in pixels.
    pub vgap: f64,
    /// Gap between the two columns in pixels.
    pub hgap: f64,
    /// Minimum width of the right (value) column.
    pub min_right_column_width: f64,
}

impl Default for PairLayout {
    fn default() -> Self {
        Self {
            vgap: 0.0,
            hgap: 0.0,
            min_right_column_width: MINIMUM_RIGHT_COLUMN_WIDTH,
        }
    }
}

/// Size information for a single layout item (a label/value pair or single item).
#[derive(Debug, Clone)]
pub struct LayoutItemSize {
    /// Preferred width of the left (label) component.
    pub left_width: f64,
    /// Preferred width of the right (value) component.
    pub right_width: f64,
    /// Preferred height of this row (max of left and right heights).
    pub height: f64,
    /// Whether the left component is visible.
    pub left_visible: bool,
    /// Whether the right component is visible.
    pub right_visible: bool,
}

impl LayoutItemSize {
    /// Create a new layout item size.
    pub fn new(left_width: f64, right_width: f64, height: f64) -> Self {
        Self {
            left_width,
            right_width,
            height,
            left_visible: true,
            right_visible: true,
        }
    }

    /// Create an invisible layout item.
    pub fn invisible(left_width: f64, right_width: f64, height: f64) -> Self {
        Self {
            left_width,
            right_width,
            height,
            left_visible: false,
            right_visible: false,
        }
    }
}

/// The result of calculating a PairLayout arrangement.
#[derive(Debug, Clone)]
pub struct PairLayoutResult {
    /// Positions and sizes for left column components: (x, y, width, height).
    pub left_positions: Vec<(f64, f64, f64, f64)>,
    /// Positions and sizes for right column components: (x, y, width, height).
    pub right_positions: Vec<(f64, f64, f64, f64)>,
    /// The computed left column width.
    pub left_column_width: f64,
    /// The preferred size of the entire layout (width, height).
    pub preferred_size: (f64, f64),
}

impl PairLayout {
    /// Create a new PairLayout with custom gaps.
    pub fn new(vgap: f64, hgap: f64) -> Self {
        Self {
            vgap,
            hgap,
            ..Default::default()
        }
    }

    /// Create a new PairLayout with custom gaps and minimum right column width.
    pub fn with_right_width(vgap: f64, hgap: f64, min_right_width: f64) -> Self {
        Self {
            vgap,
            hgap,
            min_right_column_width: min_right_width,
        }
    }

    /// Compute the left column width from item sizes.
    fn compute_left_width(&self, items: &[LayoutItemSize]) -> f64 {
        items
            .iter()
            .filter(|i| i.left_visible)
            .map(|i| i.left_width)
            .fold(0.0_f64, f64::max)
    }

    /// Compute the row height from item sizes.
    fn compute_row_height(&self, items: &[LayoutItemSize]) -> f64 {
        items
            .iter()
            .filter(|i| i.left_visible || i.right_visible)
            .map(|i| i.height)
            .fold(0.0_f64, f64::max)
    }

    /// Count visible rows.
    fn visible_row_count(&self, items: &[LayoutItemSize]) -> usize {
        items
            .iter()
            .filter(|i| i.left_visible || i.right_visible)
            .count()
    }

    /// Calculate the preferred size of the layout.
    pub fn preferred_size(&self, items: &[LayoutItemSize]) -> (f64, f64) {
        let left_width = self.compute_left_width(items);
        let visible_rows = self.visible_row_count(items);
        if visible_rows == 0 {
            return (0.0, 0.0);
        }
        let row_height = self.compute_row_height(items);

        let preferred_right = items
            .iter()
            .filter(|i| i.right_visible)
            .map(|i| i.right_width)
            .fold(self.min_right_column_width, f64::max);

        let width = left_width + self.hgap + preferred_right;
        let height = row_height * visible_rows as f64 + self.vgap * (visible_rows as f64 - 1.0);
        (width, height)
    }

    /// Calculate positions for all components given a container size.
    pub fn layout(
        &self,
        container_width: f64,
        container_height: f64,
        items: &[LayoutItemSize],
    ) -> PairLayoutResult {
        let left_width = self.compute_left_width(items);
        let row_height = self.compute_row_height(items);
        let right_width = container_width - left_width - self.hgap;

        let mut left_positions = Vec::new();
        let mut right_positions = Vec::new();
        let mut y = 0.0_f64;

        for item in items {
            if !item.left_visible && !item.right_visible {
                // Invisible row: push placeholder positions but don't advance y
                left_positions.push((0.0, y, 0.0, 0.0));
                right_positions.push((0.0, y, 0.0, 0.0));
                continue;
            }

            left_positions.push((0.0, y, left_width, row_height));
            right_positions.push((left_width + self.hgap, y, right_width, row_height));
            y += row_height + self.vgap;
        }

        let preferred = self.preferred_size(items);

        PairLayoutResult {
            left_positions,
            right_positions,
            left_column_width: left_width,
            preferred_size: preferred,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pair_layout() {
        let layout = PairLayout::default();
        assert_eq!(layout.vgap, 0.0);
        assert_eq!(layout.hgap, 0.0);
        assert_eq!(layout.min_right_column_width, 80.0);
    }

    #[test]
    fn pair_layout_preferred_size() {
        let layout = PairLayout::new(5.0, 10.0);
        let items = vec![
            LayoutItemSize::new(50.0, 100.0, 20.0),
            LayoutItemSize::new(60.0, 80.0, 25.0),
        ];
        let (w, h) = layout.preferred_size(&items);
        // left_width=60, hgap=10, preferred_right=max(80,100)=100
        assert!((w - 170.0).abs() < 0.01);
        // 2 rows: max(20,25)=25 each, plus 1 gap of 5
        assert!((h - 55.0).abs() < 0.01);
    }

    #[test]
    fn pair_layout_positions() {
        let layout = PairLayout::new(5.0, 10.0);
        let items = vec![
            LayoutItemSize::new(50.0, 100.0, 20.0),
            LayoutItemSize::new(60.0, 80.0, 25.0),
        ];
        let result = layout.layout(300.0, 100.0, &items);

        assert_eq!(result.left_positions.len(), 2);
        assert_eq!(result.right_positions.len(), 2);
        assert_eq!(result.left_column_width, 60.0);

        // First left item at (0, 0)
        assert_eq!(result.left_positions[0].0, 0.0);
        assert_eq!(result.left_positions[0].1, 0.0);
        // First right item at (70, 0)
        assert!((result.right_positions[0].0 - 70.0).abs() < 0.01);
        // Second row starts at y = row_height + vgap = 25 + 5 = 30
        assert!((result.left_positions[1].1 - 30.0).abs() < 0.01);
    }

    #[test]
    fn pair_layout_invisible_rows() {
        let layout = PairLayout::new(5.0, 10.0);
        let items = vec![
            LayoutItemSize::new(50.0, 100.0, 20.0),
            LayoutItemSize::invisible(50.0, 100.0, 20.0),
            LayoutItemSize::new(60.0, 80.0, 25.0),
        ];
        let result = layout.layout(300.0, 100.0, &items);
        // Only visible rows contribute to y advancement
        // Row 0: y=0, row 2: y=25+5=30 (row 1 is invisible, doesn't advance)
        assert_eq!(result.left_positions[0].1, 0.0);
        assert!((result.left_positions[2].1 - 30.0).abs() < 0.01);
    }

    #[test]
    fn pair_layout_empty() {
        let layout = PairLayout::default();
        let items: Vec<LayoutItemSize> = vec![];
        let (w, h) = layout.preferred_size(&items);
        assert_eq!(w, 0.0);
        assert_eq!(h, 0.0);
    }

    #[test]
    fn pair_layout_custom_right_width() {
        let layout = PairLayout::with_right_width(2.0, 4.0, 120.0);
        assert_eq!(layout.min_right_column_width, 120.0);
        let items = vec![LayoutItemSize::new(40.0, 50.0, 15.0)];
        let (w, _h) = layout.preferred_size(&items);
        // right_width = max(120, 50) = 120
        assert!((w - 164.0).abs() < 0.01); // 40 + 4 + 120
    }
}
