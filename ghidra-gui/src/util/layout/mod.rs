//! Layout managers for arranging UI components.
//!
//! Ports `ghidra.util.layout` package.

/// A layout hint specifying how a component should be placed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LayoutHint {
    /// Fill the available space.
    Fill,
    /// Place in the center.
    Center,
    /// Place at the top.
    Top,
    /// Place at the bottom.
    Bottom,
    /// Place on the left.
    Left,
    /// Place on the right.
    Right,
}

impl Default for LayoutHint {
    fn default() -> Self {
        Self::Fill
    }
}

/// Dimension constraints for a layout component.
#[derive(Debug, Clone, Copy)]
pub struct LayoutConstraints {
    /// Minimum width.
    pub min_width: f64,
    /// Minimum height.
    pub min_height: f64,
    /// Preferred width.
    pub preferred_width: f64,
    /// Preferred height.
    pub preferred_height: f64,
    /// Maximum width (0 = unlimited).
    pub max_width: f64,
    /// Maximum height (0 = unlimited).
    pub max_height: f64,
}

impl Default for LayoutConstraints {
    fn default() -> Self {
        Self {
            min_width: 0.0,
            min_height: 0.0,
            preferred_width: 100.0,
            preferred_height: 30.0,
            max_width: 0.0,
            max_height: 0.0,
        }
    }
}

/// A two-column layout that places components in two vertical columns.
///
/// Ports `ghidra.util.layout.TwoColumnPairLayout`.
#[derive(Debug, Clone)]
pub struct TwoColumnLayout {
    /// Gap between columns in pixels.
    pub column_gap: f64,
    /// Gap between rows in pixels.
    pub row_gap: f64,
}

impl Default for TwoColumnLayout {
    fn default() -> Self {
        Self {
            column_gap: 10.0,
            row_gap: 5.0,
        }
    }
}

impl TwoColumnLayout {
    /// Calculate positions for a set of components.
    pub fn layout(&self, container_width: f64, component_heights: &[f64]) -> Vec<(f64, f64)> {
        let col_width = (container_width - self.column_gap) / 2.0;
        let mut positions = Vec::new();
        let mut y = 0.0;
        let mut col = 0;

        for &h in component_heights {
            let x = col as f64 * (col_width + self.column_gap);
            positions.push((x, y));
            if col == 1 {
                y += h + self.row_gap;
                col = 0;
            } else {
                col += 1;
            }
        }
        positions
    }
}

/// A vertical layout that stacks components top-to-bottom.
#[derive(Debug, Clone)]
pub struct VerticalLayout {
    /// Gap between components in pixels.
    pub gap: f64,
    /// Padding around the container.
    pub padding: f64,
}

impl Default for VerticalLayout {
    fn default() -> Self {
        Self {
            gap: 5.0,
            padding: 10.0,
        }
    }
}

impl VerticalLayout {
    /// Calculate positions for components.
    pub fn layout(&self, _container_width: f64, component_heights: &[f64]) -> Vec<(f64, f64)> {
        let mut positions = Vec::new();
        let mut y = self.padding;
        for &h in component_heights {
            positions.push((self.padding, y));
            y += h + self.gap;
        }
        positions
    }

    /// Calculate total height needed.
    pub fn total_height(&self, component_heights: &[f64]) -> f64 {
        let sum: f64 = component_heights.iter().sum();
        let gaps = if component_heights.is_empty() {
            0.0
        } else {
            (component_heights.len() - 1) as f64 * self.gap
        };
        sum + gaps + 2.0 * self.padding
    }
}

/// A horizontal layout that places components left-to-right.
#[derive(Debug, Clone)]
pub struct HorizontalLayout {
    /// Gap between components in pixels.
    pub gap: f64,
    /// Padding around the container.
    pub padding: f64,
}

impl Default for HorizontalLayout {
    fn default() -> Self {
        Self {
            gap: 5.0,
            padding: 10.0,
        }
    }
}

impl HorizontalLayout {
    /// Calculate positions for components.
    pub fn layout(&self, _container_height: f64, component_widths: &[f64]) -> Vec<(f64, f64)> {
        let mut positions = Vec::new();
        let mut x = self.padding;
        for &w in component_widths {
            positions.push((x, self.padding));
            x += w + self.gap;
        }
        positions
    }

    /// Calculate total width needed.
    pub fn total_width(&self, component_widths: &[f64]) -> f64 {
        let sum: f64 = component_widths.iter().sum();
        let gaps = if component_widths.is_empty() {
            0.0
        } else {
            (component_widths.len() - 1) as f64 * self.gap
        };
        sum + gaps + 2.0 * self.padding
    }
}

/// A three-column layout.
#[derive(Debug, Clone)]
pub struct ThreeColumnLayout {
    /// Gap between columns in pixels.
    pub gap: f64,
    /// The ratio of the middle column to the total width (0.0 - 1.0).
    pub middle_ratio: f64,
}

impl Default for ThreeColumnLayout {
    fn default() -> Self {
        Self {
            gap: 10.0,
            middle_ratio: 0.4,
        }
    }
}

impl ThreeColumnLayout {
    /// Calculate column widths given a container width.
    pub fn column_widths(&self, container_width: f64) -> (f64, f64, f64) {
        let available = container_width - 2.0 * self.gap;
        let middle = available * self.middle_ratio;
        let side = (available - middle) / 2.0;
        (side, middle, side)
    }
}

/// A column layout that places items in a grid with a fixed number of columns.
#[derive(Debug, Clone)]
pub struct ColumnLayout {
    /// Number of columns.
    pub columns: usize,
    /// Gap between items (both horizontal and vertical).
    pub gap: f64,
}

impl Default for ColumnLayout {
    fn default() -> Self {
        Self {
            columns: 3,
            gap: 5.0,
        }
    }
}

impl ColumnLayout {
    /// Calculate positions for items in a grid.
    pub fn layout(&self, container_width: f64, item_width: f64, item_height: f64, count: usize) -> Vec<(f64, f64)> {
        let col_width = (container_width - (self.columns - 1) as f64 * self.gap) / self.columns as f64;
        let scale = if item_width > 0.0 { col_width / item_width } else { 1.0 };
        let scaled_height = item_height * scale;

        let mut positions = Vec::new();
        for i in 0..count {
            let col = i % self.columns;
            let row = i / self.columns;
            let x = col as f64 * (col_width + self.gap);
            let y = row as f64 * (scaled_height + self.gap);
            positions.push((x, y));
        }
        positions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vertical_layout_positions() {
        let layout = VerticalLayout::default();
        let heights = vec![20.0, 30.0, 40.0];
        let positions = layout.layout(200.0, &heights);
        assert_eq!(positions.len(), 3);
        assert!((positions[0].1 - 10.0).abs() < 0.01); // padding
        assert!((positions[1].1 - 35.0).abs() < 0.01); // 10 + 20 + 5
        assert!((positions[2].1 - 70.0).abs() < 0.01); // 35 + 30 + 5
    }

    #[test]
    fn vertical_layout_total_height() {
        let layout = VerticalLayout::default();
        let heights = vec![20.0, 30.0];
        let total = layout.total_height(&heights);
        // padding(10) + 20 + gap(5) + 30 + padding(10) = 75
        assert!((total - 75.0).abs() < 0.01);
    }

    #[test]
    fn horizontal_layout_positions() {
        let layout = HorizontalLayout::default();
        let widths = vec![50.0, 60.0, 70.0];
        let positions = layout.layout(100.0, &widths);
        assert_eq!(positions.len(), 3);
        assert!((positions[0].0 - 10.0).abs() < 0.01);
        assert!((positions[1].0 - 65.0).abs() < 0.01);
    }

    #[test]
    fn horizontal_layout_total_width() {
        let layout = HorizontalLayout::default();
        let widths = vec![50.0, 60.0];
        let total = layout.total_width(&widths);
        assert!((total - 135.0).abs() < 0.01); // 10 + 50 + 5 + 60 + 10
    }

    #[test]
    fn two_column_layout() {
        let layout = TwoColumnLayout::default();
        let heights = vec![20.0, 30.0, 40.0, 50.0];
        let positions = layout.layout(200.0, &heights);
        assert_eq!(positions.len(), 4);
        // First two items are at y=0, next two at y=max(20,30)+gap
    }

    #[test]
    fn three_column_layout_widths() {
        let layout = ThreeColumnLayout::default();
        let (left, mid, right) = layout.column_widths(300.0);
        assert!((left + mid + right + 20.0 - 300.0).abs() < 0.01);
        assert!((mid - 112.0).abs() < 1.0); // 0.4 * 280
    }

    #[test]
    fn column_layout_grid() {
        let layout = ColumnLayout { columns: 3, gap: 10.0 };
        let positions = layout.layout(320.0, 100.0, 50.0, 6);
        assert_eq!(positions.len(), 6);
        // 6 items in 3 columns = 2 rows
    }

    #[test]
    fn layout_constraints_default() {
        let c = LayoutConstraints::default();
        assert_eq!(c.preferred_width, 100.0);
        assert_eq!(c.preferred_height, 30.0);
    }
}
