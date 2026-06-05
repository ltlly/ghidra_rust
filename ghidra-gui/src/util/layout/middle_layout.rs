//! MiddleLayout -- centers a single component within its container.
//!
//! Ports `ghidra.util.layout.MiddleLayout`.

/// A layout that centers a single component in both axes.
///
/// Ports `ghidra.util.layout.MiddleLayout`.
#[derive(Debug, Clone, Copy, Default)]
pub struct MiddleLayout;

impl MiddleLayout {
    /// Create a new MiddleLayout.
    pub fn new() -> Self {
        Self
    }

    /// Calculate the position to center a component of given size
    /// within a container of given size.
    ///
    /// Returns `(x, y)` for the top-left corner of the component.
    pub fn center(
        container_width: f64,
        container_height: f64,
        component_width: f64,
        component_height: f64,
    ) -> (f64, f64) {
        let x = (container_width - component_width).max(0.0) / 2.0;
        let y = (container_height - component_height).max(0.0) / 2.0;
        (x, y)
    }

    /// Center a component horizontally within a container, keeping the y fixed.
    pub fn center_horizontal(
        container_width: f64,
        component_width: f64,
        y: f64,
    ) -> (f64, f64) {
        let x = (container_width - component_width).max(0.0) / 2.0;
        (x, y)
    }

    /// Center a component vertically within a container, keeping the x fixed.
    pub fn center_vertical(
        container_height: f64,
        component_height: f64,
        x: f64,
    ) -> (f64, f64) {
        let y = (container_height - component_height).max(0.0) / 2.0;
        (x, y)
    }
}

/// A stretch layout that stretches a component to fill the container
/// with optional insets.
///
/// Ports `ghidra.util.layout.StretchLayout`.
#[derive(Debug, Clone, Copy)]
pub struct StretchLayout {
    /// Inset from the left edge.
    pub left: f64,
    /// Inset from the top edge.
    pub top: f64,
    /// Inset from the right edge.
    pub right: f64,
    /// Inset from the bottom edge.
    pub bottom: f64,
}

impl StretchLayout {
    /// Create a StretchLayout with uniform insets.
    pub fn uniform(inset: f64) -> Self {
        Self {
            left: inset,
            top: inset,
            right: inset,
            bottom: inset,
        }
    }

    /// Create a StretchLayout with no insets (fills entire container).
    pub fn fill() -> Self {
        Self {
            left: 0.0,
            top: 0.0,
            right: 0.0,
            bottom: 0.0,
        }
    }

    /// Calculate the bounds for a stretched component.
    ///
    /// Returns `(x, y, width, height)`.
    pub fn compute(&self, container_width: f64, container_height: f64) -> (f64, f64, f64, f64) {
        let w = (container_width - self.left - self.right).max(0.0);
        let h = (container_height - self.top - self.bottom).max(0.0);
        (self.left, self.top, w, h)
    }
}

impl Default for StretchLayout {
    fn default() -> Self {
        Self::fill()
    }
}

/// A right-sided squishy buddy layout that places a fixed-width component
/// on the right side and lets the left component fill the remaining space.
///
/// Ports `ghidra.util.layout.RightSidedSquishyBuddyLayout`.
#[derive(Debug, Clone)]
pub struct RightSidedBuddyLayout {
    /// Width of the right component.
    pub right_width: f64,
    /// Gap between the two components.
    pub gap: f64,
    /// Padding around the container.
    pub padding: f64,
}

impl RightSidedBuddyLayout {
    /// Create a new layout.
    pub fn new(right_width: f64, gap: f64, padding: f64) -> Self {
        Self {
            right_width,
            gap,
            padding,
        }
    }

    /// Calculate bounds for the left (flexible) component.
    /// Returns `(x, y, width, height)`.
    pub fn left_bounds(&self, container_width: f64, container_height: f64) -> (f64, f64, f64, f64) {
        let w = (container_width - 2.0 * self.padding - self.gap - self.right_width).max(0.0);
        let h = (container_height - 2.0 * self.padding).max(0.0);
        (self.padding, self.padding, w, h)
    }

    /// Calculate bounds for the right (fixed-width) component.
    /// Returns `(x, y, width, height)`.
    pub fn right_bounds(&self, container_width: f64, container_height: f64) -> (f64, f64, f64, f64) {
        let x = container_width - self.padding - self.right_width;
        let h = (container_height - 2.0 * self.padding).max(0.0);
        (x, self.padding, self.right_width, h)
    }
}

impl Default for RightSidedBuddyLayout {
    fn default() -> Self {
        Self::new(100.0, 5.0, 5.0)
    }
}

/// A variable-height pair layout that allows each row to have its own height.
///
/// Ports `ghidra.util.layout.VariableHeightPairLayout`.
#[derive(Debug, Clone, Default)]
pub struct VariableHeightPairLayout {
    /// Gap between rows in pixels.
    pub vgap: f64,
    /// Gap between columns in pixels.
    pub hgap: f64,
}

impl VariableHeightPairLayout {
    /// Create a new layout.
    pub fn new(vgap: f64, hgap: f64) -> Self {
        Self { vgap, hgap }
    }

    /// Calculate positions for pairs of components.
    ///
    /// `pairs` is a list of `(left_width, left_height, right_width, right_height)` tuples.
    /// Returns positions as `((left_x, left_y), (right_x, right_y))`.
    pub fn layout(
        &self,
        container_width: f64,
        pairs: &[(f64, f64, f64, f64)],
    ) -> Vec<((f64, f64), (f64, f64))> {
        let left_width = pairs
            .iter()
            .map(|p| p.0)
            .fold(0.0_f64, f64::max);

        let right_x = left_width + self.hgap;

        let mut positions = Vec::new();
        let mut y = 0.0_f64;

        for &(_, lh, _, rh) in pairs {
            let row_height = lh.max(rh);
            positions.push(((0.0, y), (right_x, y)));
            y += row_height + self.vgap;
        }

        positions
    }
}

/// A variable row height grid layout.
///
/// Ports `ghidra.util.layout.VariableRowHeightGridLayout`.
#[derive(Debug, Clone)]
pub struct VariableRowHeightGridLayout {
    /// Number of columns.
    pub columns: usize,
    /// Gap between columns.
    pub hgap: f64,
    /// Gap between rows.
    pub vgap: f64,
}

impl VariableRowHeightGridLayout {
    /// Create a new grid layout.
    pub fn new(columns: usize, hgap: f64, vgap: f64) -> Self {
        Self {
            columns,
            hgap,
            vgap,
        }
    }

    /// Layout items in a grid with variable row heights.
    ///
    /// `item_heights` contains the preferred height of each item.
    /// Returns `(x, y, width, height)` for each item.
    pub fn layout(
        &self,
        container_width: f64,
        item_heights: &[f64],
    ) -> Vec<(f64, f64, f64, f64)> {
        let col_width =
            (container_width - (self.columns - 1) as f64 * self.hgap) / self.columns as f64;
        let mut result = Vec::new();

        // Group items into rows; each row has `columns` items.
        // Row height = max height in that row.
        let rows: Vec<&[f64]> = item_heights.chunks(self.columns).collect();
        let mut row_heights: Vec<f64> = Vec::new();
        for row in &rows {
            row_heights.push(row.iter().cloned().fold(0.0_f64, f64::max));
        }

        let mut y = 0.0_f64;
        for (row_idx, row) in rows.iter().enumerate() {
            let rh = row_heights[row_idx];
            for (col_idx, &ih) in row.iter().enumerate() {
                let x = col_idx as f64 * (col_width + self.hgap);
                result.push((x, y, col_width, ih));
            }
            y += rh + self.vgap;
        }

        result
    }
}

/// A maximize-specific-column grid layout that makes one column wider.
///
/// Ports `ghidra.util.layout.MaximizeSpecificColumnGridLayout`.
#[derive(Debug, Clone)]
pub struct MaximizeColumnGridLayout {
    /// Total number of columns.
    pub columns: usize,
    /// Index of the column to maximize.
    pub maximize_column: usize,
    /// Fraction of remaining space allocated to the maximized column (0.0-1.0).
    pub maximize_ratio: f64,
    /// Gap between columns.
    pub gap: f64,
}

impl MaximizeColumnGridLayout {
    /// Create a new layout.
    pub fn new(columns: usize, maximize_column: usize, maximize_ratio: f64, gap: f64) -> Self {
        Self {
            columns,
            maximize_column,
            maximize_ratio,
            gap,
        }
    }

    /// Calculate column widths.
    ///
    /// Returns a vector of widths for each column.
    pub fn column_widths(&self, container_width: f64) -> Vec<f64> {
        let available = container_width - (self.columns - 1) as f64 * self.gap;
        let other_columns = self.columns - 1;
        if other_columns == 0 {
            return vec![available];
        }
        let max_width = available * self.maximize_ratio;
        let remaining = available - max_width;
        let other_width = remaining / other_columns as f64;

        (0..self.columns)
            .map(|i| if i == self.maximize_column { max_width } else { other_width })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn middle_layout_center() {
        let (x, y) = MiddleLayout::center(200.0, 100.0, 40.0, 20.0);
        assert!((x - 80.0).abs() < 0.01);
        assert!((y - 40.0).abs() < 0.01);
    }

    #[test]
    fn middle_layout_center_horizontal() {
        let (x, y) = MiddleLayout::center_horizontal(200.0, 40.0, 10.0);
        assert!((x - 80.0).abs() < 0.01);
        assert_eq!(y, 10.0);
    }

    #[test]
    fn middle_layout_component_larger_than_container() {
        let (x, y) = MiddleLayout::center(50.0, 50.0, 100.0, 100.0);
        assert_eq!(x, 0.0);
        assert_eq!(y, 0.0);
    }

    #[test]
    fn stretch_layout_fill() {
        let layout = StretchLayout::fill();
        let (x, y, w, h) = layout.compute(200.0, 100.0);
        assert_eq!(x, 0.0);
        assert_eq!(y, 0.0);
        assert_eq!(w, 200.0);
        assert_eq!(h, 100.0);
    }

    #[test]
    fn stretch_layout_uniform() {
        let layout = StretchLayout::uniform(10.0);
        let (x, y, w, h) = layout.compute(200.0, 100.0);
        assert_eq!(x, 10.0);
        assert_eq!(y, 10.0);
        assert_eq!(w, 180.0);
        assert_eq!(h, 80.0);
    }

    #[test]
    fn right_sided_buddy_layout() {
        let layout = RightSidedBuddyLayout::new(100.0, 10.0, 5.0);
        let (lx, ly, lw, lh) = layout.left_bounds(400.0, 200.0);
        let (rx, ry, rw, rh) = layout.right_bounds(400.0, 200.0);

        assert_eq!(lx, 5.0);
        assert_eq!(ly, 5.0);
        assert!((lw - 280.0).abs() < 0.01); // 400 - 10 - 10 - 100
        assert_eq!(lh, 190.0);
        assert!((rx - 295.0).abs() < 0.01); // 400 - 5 - 100
        assert_eq!(rw, 100.0);
    }

    #[test]
    fn variable_height_pair_layout() {
        let layout = VariableHeightPairLayout::new(5.0, 10.0);
        let pairs = vec![(50.0, 20.0, 100.0, 30.0), (40.0, 25.0, 80.0, 15.0)];
        let positions = layout.layout(300.0, &pairs);
        assert_eq!(positions.len(), 2);
        // First row: y=0
        assert_eq!(positions[0].0 .1, 0.0);
        // Second row: y = max(20,30) + 5 = 35
        assert!((positions[1].0 .1 - 35.0).abs() < 0.01);
    }

    #[test]
    fn variable_row_height_grid() {
        let layout = VariableRowHeightGridLayout::new(3, 10.0, 5.0);
        let heights = vec![20.0, 30.0, 25.0, 15.0, 40.0, 10.0];
        let result = layout.layout(340.0, &heights);
        assert_eq!(result.len(), 6);
        // First row max height = 30, second row max height = 40
        // Items 0-2 are in row 0, items 3-5 in row 1
        // Row 1 y = 30 + 5 = 35
        assert!((result[3].1 - 35.0).abs() < 0.01);
    }

    #[test]
    fn maximize_column_grid() {
        let layout = MaximizeColumnGridLayout::new(3, 1, 0.5, 10.0);
        let widths = layout.column_widths(320.0);
        assert_eq!(widths.len(), 3);
        // Available = 320 - 20 = 300; maximized = 150; other = 75 each
        assert!((widths[0] - 75.0).abs() < 0.01);
        assert!((widths[1] - 150.0).abs() < 0.01);
        assert!((widths[2] - 75.0).abs() < 0.01);
    }

    #[test]
    fn maximize_column_single() {
        let layout = MaximizeColumnGridLayout::new(1, 0, 0.5, 10.0);
        let widths = layout.column_widths(200.0);
        assert_eq!(widths.len(), 1);
        assert_eq!(widths[0], 200.0);
    }
}
