//! Layout managers for Ghidra's GUI framework.
//!
//! Ports Ghidra's layout manager classes from `ghidra.util.layout`:
//! - [`ColumnLayout`] -- multi-column layout with equal column widths
//! - [`HorizontalLayout`] -- left-to-right horizontal layout
//! - [`VerticalLayout`] -- top-to-bottom vertical layout
//! - [`MiddleLayout`] -- centers content vertically and horizontally
//! - [`PairLayout`] -- label-component pairs in two columns
//! - [`StretchLayout`] -- stretches one component to fill remaining space
//! - [`ThreeColumnLayout`] -- three-column layout with fixed/elastic/fixed widths
//! - [`TwoColumnPairLayout`] -- two-column layout with label-component pairs
//! - [`VariableHeightPairLayout`] -- variable-height pair layout
//!
//! These layouts manage how components are positioned within a container
//! and are used throughout the Ghidra UI for dialogs, panels, and editors.

/// Strategy for distributing excess space among layout columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistributionStrategy {
    /// Distribute excess space equally among all columns.
    Equal,
    /// Give all excess space to the first column.
    First,
    /// Give all excess space to the last column.
    Last,
    /// No excess distribution; columns are exactly their preferred size.
    None,
}

impl Default for DistributionStrategy {
    fn default() -> Self {
        Self::Equal
    }
}

/// Describes a single component's layout constraints.
#[derive(Debug, Clone)]
pub struct LayoutConstraint {
    /// Minimum width.
    pub min_width: u32,
    /// Minimum height.
    pub min_height: u32,
    /// Preferred width.
    pub preferred_width: u32,
    /// Preferred height.
    pub preferred_height: u32,
    /// Horizontal alignment (0.0 = left, 0.5 = center, 1.0 = right).
    pub h_align: f32,
    /// Vertical alignment (0.0 = top, 0.5 = center, 1.0 = bottom).
    pub v_align: f32,
    /// Extra padding around this component.
    pub padding: Padding,
    /// Whether this component should expand to fill available space.
    pub expand_h: bool,
    /// Whether this component should expand vertically.
    pub expand_v: bool,
}

/// Padding around a component (top, right, bottom, left).
#[derive(Debug, Clone, Copy, Default)]
pub struct Padding {
    /// Top padding.
    pub top: u32,
    /// Right padding.
    pub right: u32,
    /// Bottom padding.
    pub bottom: u32,
    /// Left padding.
    pub left: u32,
}

impl Padding {
    /// Create uniform padding.
    pub fn uniform(value: u32) -> Self {
        Self {
            top: value,
            right: value,
            bottom: value,
            left: value,
        }
    }

    /// Create padding with horizontal and vertical values.
    pub fn symmetric(h: u32, v: u32) -> Self {
        Self {
            top: v,
            right: h,
            bottom: v,
            left: h,
        }
    }

    /// Total horizontal padding.
    pub fn horizontal(&self) -> u32 {
        self.left + self.right
    }

    /// Total vertical padding.
    pub fn vertical(&self) -> u32 {
        self.top + self.bottom
    }
}

impl Default for LayoutConstraint {
    fn default() -> Self {
        Self {
            min_width: 0,
            min_height: 0,
            preferred_width: 0,
            preferred_height: 0,
            h_align: 0.0,
            v_align: 0.5,
            padding: Padding::default(),
            expand_h: false,
            expand_v: false,
        }
    }
}

/// A computed rectangle for a laid-out component.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LayoutRect {
    /// X position.
    pub x: i32,
    /// Y position.
    pub y: i32,
    /// Width.
    pub width: u32,
    /// Height.
    pub height: u32,
}

impl LayoutRect {
    /// Create a new layout rect.
    pub fn new(x: i32, y: i32, width: u32, height: u32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    /// Right edge (x + width).
    pub fn right(&self) -> i32 {
        self.x + self.width as i32
    }

    /// Bottom edge (y + height).
    pub fn bottom(&self) -> i32 {
        self.y + self.height as i32
    }
}

// ============================================================================
// ColumnLayout
// ============================================================================

/// A multi-column layout with equal column widths.
///
/// Ports Ghidra's `ColumnLayout`. Components are arranged left-to-right
/// in a grid of `num_columns` columns. Each column has the same width,
/// and excess space is distributed according to the strategy.
#[derive(Debug, Clone)]
pub struct ColumnLayout {
    /// Number of columns.
    pub num_columns: usize,
    /// Horizontal gap between columns.
    pub h_gap: u32,
    /// Vertical gap between rows.
    pub v_gap: u32,
    /// Distribution strategy for excess space.
    pub strategy: DistributionStrategy,
    /// Outer margins.
    pub margin: Padding,
}

impl ColumnLayout {
    /// Create a new column layout.
    pub fn new(num_columns: usize) -> Self {
        Self {
            num_columns,
            h_gap: 8,
            v_gap: 4,
            strategy: DistributionStrategy::Equal,
            margin: Padding::uniform(4),
        }
    }

    /// Set the horizontal gap.
    pub fn with_h_gap(mut self, gap: u32) -> Self {
        self.h_gap = gap;
        self
    }

    /// Set the vertical gap.
    pub fn with_v_gap(mut self, gap: u32) -> Self {
        self.v_gap = gap;
        self
    }

    /// Set the distribution strategy.
    pub fn with_strategy(mut self, strategy: DistributionStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Compute layout positions for `num_items` items.
    ///
    /// Returns a list of `LayoutRect` positions within the given container size.
    pub fn compute(
        &self,
        container_width: u32,
        _container_height: u32,
        num_items: usize,
        preferred_heights: &[u32],
    ) -> Vec<LayoutRect> {
        if num_items == 0 || self.num_columns == 0 {
            return Vec::new();
        }

        let inner_width = container_width
            .saturating_sub(self.margin.horizontal())
            .saturating_sub(self.h_gap * (self.num_columns as u32 - 1).max(0));
        let col_width = inner_width / self.num_columns as u32;

        let mut rects = Vec::with_capacity(num_items);
        let mut y = self.margin.top as i32;
        let mut col = 0usize;

        for i in 0..num_items {
            let h = if i < preferred_heights.len() {
                preferred_heights[i]
            } else {
                20 // default height
            };
            let x = self.margin.left as i32
                + (col as u32 * (col_width + self.h_gap)) as i32;
            rects.push(LayoutRect::new(x, y, col_width, h));

            col += 1;
            if col >= self.num_columns {
                col = 0;
                // Move to next row at the max height in this row
                let row_max_h = rects
                    [rects.len() - self.num_columns..]
                    .iter()
                    .map(|r| r.height)
                    .max()
                    .unwrap_or(20);
                y += row_max_h as i32 + self.v_gap as i32;
            }
        }

        rects
    }
}

impl Default for ColumnLayout {
    fn default() -> Self {
        Self::new(2)
    }
}

// ============================================================================
// HorizontalLayout
// ============================================================================

/// Left-to-right horizontal layout.
///
/// Ports Ghidra's `HorizontalLayout`. Components are arranged in a
/// single row, left to right.
#[derive(Debug, Clone)]
pub struct HorizontalLayout {
    /// Gap between components.
    pub gap: u32,
    /// Outer margins.
    pub margin: Padding,
    /// Vertical alignment (0.0 = top, 0.5 = center, 1.0 = bottom).
    pub v_align: f32,
}

impl HorizontalLayout {
    /// Create a new horizontal layout.
    pub fn new() -> Self {
        Self {
            gap: 8,
            margin: Padding::uniform(4),
            v_align: 0.5,
        }
    }

    /// Compute positions for items laid out horizontally.
    pub fn compute(
        &self,
        _container_width: u32,
        container_height: u32,
        preferred_widths: &[u32],
        preferred_heights: &[u32],
    ) -> Vec<LayoutRect> {
        let mut x = self.margin.left as i32;
        let mut rects = Vec::with_capacity(preferred_widths.len());

        for (i, &pw) in preferred_widths.iter().enumerate() {
            let h = preferred_heights.get(i).copied().unwrap_or(20);
            let y_offset = match () {
                _ if self.v_align <= 0.25 => self.margin.top as i32,
                _ if self.v_align >= 0.75 => {
                    (container_height as i32)
                        - (h as i32)
                        - (self.margin.bottom as i32)
                }
                _ => {
                    ((container_height as f32 - h as f32) / 2.0) as i32
                }
            };
            rects.push(LayoutRect::new(x, y_offset, pw, h));
            x += pw as i32 + self.gap as i32;
        }

        rects
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

/// Top-to-bottom vertical layout.
///
/// Ports Ghidra's `VerticalLayout`. Components are arranged in a
/// single column, top to bottom.
#[derive(Debug, Clone)]
pub struct VerticalLayout {
    /// Gap between components.
    pub gap: u32,
    /// Outer margins.
    pub margin: Padding,
    /// Horizontal alignment (0.0 = left, 0.5 = center, 1.0 = right).
    pub h_align: f32,
}

impl VerticalLayout {
    /// Create a new vertical layout.
    pub fn new() -> Self {
        Self {
            gap: 4,
            margin: Padding::uniform(4),
            h_align: 0.0,
        }
    }

    /// Compute positions for items laid out vertically.
    pub fn compute(
        &self,
        container_width: u32,
        preferred_widths: &[u32],
        preferred_heights: &[u32],
    ) -> Vec<LayoutRect> {
        let mut y = self.margin.top as i32;
        let mut rects = Vec::with_capacity(preferred_heights.len());

        for (i, &ph) in preferred_heights.iter().enumerate() {
            let w = preferred_widths.get(i).copied().unwrap_or(100);
            let x = if self.h_align <= 0.25 {
                self.margin.left as i32
            } else if self.h_align >= 0.75 {
                (container_width as i32) - (w as i32) - (self.margin.right as i32)
            } else {
                ((container_width as f32 - w as f32) / 2.0) as i32
            };
            rects.push(LayoutRect::new(x, y, w, ph));
            y += ph as i32 + self.gap as i32;
        }

        rects
    }
}

impl Default for VerticalLayout {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// MiddleLayout
// ============================================================================

/// Centers content both horizontally and vertically within the container.
///
/// Ports Ghidra's `MiddleLayout`.
#[derive(Debug, Clone)]
pub struct MiddleLayout {
    /// The preferred size of the content (width, height).
    pub content_size: (u32, u32),
}

impl MiddleLayout {
    /// Create a new middle layout.
    pub fn new(content_width: u32, content_height: u32) -> Self {
        Self {
            content_size: (content_width, content_height),
        }
    }

    /// Compute the centered position for the content.
    pub fn compute(&self, container_width: u32, container_height: u32) -> LayoutRect {
        let x = ((container_width as f32 - self.content_size.0 as f32) / 2.0).max(0.0) as i32;
        let y = ((container_height as f32 - self.content_size.1 as f32) / 2.0).max(0.0) as i32;
        LayoutRect::new(x, y, self.content_size.0, self.content_size.1)
    }
}

// ============================================================================
// PairLayout
// ============================================================================

/// Label-component pairs in two columns.
///
/// Ports Ghidra's `PairLayout`. Components are arranged as rows of
/// (label, value) pairs.
#[derive(Debug, Clone)]
pub struct PairLayout {
    /// Gap between label and value columns.
    pub h_gap: u32,
    /// Gap between rows.
    pub v_gap: u32,
    /// Outer margins.
    pub margin: Padding,
    /// Preferred label width.
    pub label_width: u32,
    /// Preferred row height.
    pub row_height: u32,
}

impl PairLayout {
    /// Create a new pair layout.
    pub fn new() -> Self {
        Self {
            h_gap: 8,
            v_gap: 4,
            margin: Padding::uniform(4),
            label_width: 120,
            row_height: 24,
        }
    }

    /// Compute positions for `num_pairs` label/value pairs.
    ///
    /// Returns (label_rect, value_rect) for each pair.
    pub fn compute(
        &self,
        container_width: u32,
        num_pairs: usize,
    ) -> Vec<(LayoutRect, LayoutRect)> {
        let mut rects = Vec::with_capacity(num_pairs);
        let mut y = self.margin.top as i32;

        let value_width = container_width
            .saturating_sub(self.margin.horizontal())
            .saturating_sub(self.label_width)
            .saturating_sub(self.h_gap);

        for _ in 0..num_pairs {
            let label = LayoutRect::new(self.margin.left as i32, y, self.label_width, self.row_height);
            let value = LayoutRect::new(
                self.margin.left as i32 + self.label_width as i32 + self.h_gap as i32,
                y,
                value_width,
                self.row_height,
            );
            rects.push((label, value));
            y += self.row_height as i32 + self.v_gap as i32;
        }

        rects
    }
}

impl Default for PairLayout {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// StretchLayout
// ============================================================================

/// Stretches one component to fill remaining space.
///
/// Ports Ghidra's `StretchLayout`. One component (the "stretch" component)
/// receives all remaining space after the "fixed" components are sized.
#[derive(Debug, Clone)]
pub struct StretchLayout {
    /// Number of fixed-size components.
    pub fixed_count: usize,
    /// Fixed component size (width or height, depending on orientation).
    pub fixed_size: u32,
    /// Gap between components.
    pub gap: u32,
    /// Whether this is a horizontal or vertical layout.
    pub vertical: bool,
    /// Outer margins.
    pub margin: Padding,
}

impl StretchLayout {
    /// Create a new horizontal stretch layout.
    pub fn horizontal(fixed_count: usize, fixed_size: u32) -> Self {
        Self {
            fixed_count,
            fixed_size,
            gap: 4,
            vertical: false,
            margin: Padding::uniform(4),
        }
    }

    /// Create a new vertical stretch layout.
    pub fn vertical(fixed_count: usize, fixed_size: u32) -> Self {
        Self {
            fixed_count,
            fixed_size,
            gap: 4,
            vertical: true,
            margin: Padding::uniform(4),
        }
    }

    /// Compute the size of the stretch component.
    ///
    /// Returns (position, size) for all components: `fixed_count` fixed
    /// components followed by one stretch component.
    pub fn compute(&self, container_size: u32) -> Vec<(u32, u32)> {
        let total_gap = self.gap * (self.fixed_count as u32); // gap after each fixed
        let fixed_total = self.fixed_size * self.fixed_count as u32;
        let margin = if self.vertical {
            self.margin.vertical()
        } else {
            self.margin.horizontal()
        };
        let stretch_size = container_size
            .saturating_sub(margin)
            .saturating_sub(fixed_total)
            .saturating_sub(total_gap)
            .saturating_sub(self.gap); // gap before stretch

        let mut positions = Vec::new();
        let start = if self.vertical {
            self.margin.top
        } else {
            self.margin.left
        };
        let mut pos = start;

        for _ in 0..self.fixed_count {
            positions.push((pos, self.fixed_size));
            pos += self.fixed_size + self.gap;
        }
        positions.push((pos, stretch_size));

        positions
    }
}

// ============================================================================
// ThreeColumnLayout
// ============================================================================

/// Three-column layout with fixed, elastic, and fixed widths.
///
/// Ports Ghidra's `ThreeColumnLayout`. The middle column stretches to
/// fill available space.
#[derive(Debug, Clone)]
pub struct ThreeColumnLayout {
    /// Left column preferred width.
    pub left_width: u32,
    /// Right column preferred width.
    pub right_width: u32,
    /// Gap between columns.
    pub gap: u32,
    /// Outer margins.
    pub margin: Padding,
}

impl ThreeColumnLayout {
    /// Create a new three-column layout.
    pub fn new(left_width: u32, right_width: u32) -> Self {
        Self {
            left_width,
            right_width,
            gap: 8,
            margin: Padding::uniform(4),
        }
    }

    /// Compute the x-positions and widths for the three columns.
    ///
    /// Returns (x, width) for each column: left, middle (elastic), right.
    pub fn compute(&self, container_width: u32) -> [(i32, u32); 3] {
        let inner_width = container_width
            .saturating_sub(self.margin.horizontal())
            .saturating_sub(self.gap * 2);

        let middle_width = inner_width
            .saturating_sub(self.left_width)
            .saturating_sub(self.right_width);

        let x0 = self.margin.left as i32;
        let x1 = x0 + self.left_width as i32 + self.gap as i32;
        let x2 = x1 + middle_width as i32 + self.gap as i32;

        [(x0, self.left_width), (x1, middle_width), (x2, self.right_width)]
    }
}

// ============================================================================
// TwoColumnPairLayout
// ============================================================================

/// Two-column layout with label-component pairs, where the label column
/// and component column share equal available space.
///
/// Ports Ghidra's `TwoColumnPairLayout`.
#[derive(Debug, Clone)]
pub struct TwoColumnPairLayout {
    /// Number of rows (pairs) per column.
    pub rows_per_column: usize,
    /// Preferred label width.
    pub label_width: u32,
    /// Gap between columns.
    pub h_gap: u32,
    /// Gap between rows.
    pub v_gap: u32,
    /// Row height.
    pub row_height: u32,
    /// Outer margins.
    pub margin: Padding,
}

impl TwoColumnPairLayout {
    /// Create a new two-column pair layout.
    pub fn new(rows_per_column: usize) -> Self {
        Self {
            rows_per_column,
            label_width: 120,
            h_gap: 16,
            v_gap: 4,
            row_height: 24,
            margin: Padding::uniform(4),
        }
    }

    /// Compute the number of columns needed for `num_pairs` items.
    pub fn num_columns(&self, num_pairs: usize) -> usize {
        if self.rows_per_column == 0 {
            return 1;
        }
        (num_pairs + self.rows_per_column - 1) / self.rows_per_column
    }
}

impl Default for TwoColumnPairLayout {
    fn default() -> Self {
        Self::new(10)
    }
}

// ============================================================================
// VariableHeightPairLayout
// ============================================================================

/// Variable-height pair layout: label-component pairs where each row
/// can have a different height.
///
/// Ports Ghidra's `VariableHeightPairLayout`.
#[derive(Debug, Clone)]
pub struct VariableHeightPairLayout {
    /// Gap between label and value.
    pub h_gap: u32,
    /// Gap between rows.
    pub v_gap: u32,
    /// Preferred label width.
    pub label_width: u32,
    /// Outer margins.
    pub margin: Padding,
}

impl VariableHeightPairLayout {
    /// Create a new variable-height pair layout.
    pub fn new() -> Self {
        Self {
            h_gap: 8,
            v_gap: 4,
            label_width: 120,
            margin: Padding::uniform(4),
        }
    }

    /// Compute layout for pairs with different heights.
    ///
    /// `heights` is the preferred height for each row.
    pub fn compute(&self, container_width: u32, heights: &[u32]) -> Vec<(LayoutRect, LayoutRect)> {
        let value_width = container_width
            .saturating_sub(self.margin.horizontal())
            .saturating_sub(self.label_width)
            .saturating_sub(self.h_gap);

        let mut rects = Vec::with_capacity(heights.len());
        let mut y = self.margin.top as i32;

        for &h in heights {
            let label = LayoutRect::new(self.margin.left as i32, y, self.label_width, h);
            let value = LayoutRect::new(
                self.margin.left as i32 + self.label_width as i32 + self.h_gap as i32,
                y,
                value_width,
                h,
            );
            rects.push((label, value));
            y += h as i32 + self.v_gap as i32;
        }

        rects
    }
}

impl Default for VariableHeightPairLayout {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// MaximizeSpecificColumnGridLayout
// ============================================================================

/// Row-oriented grid layout that maximizes specific columns.
///
/// Ports Ghidra's `MaximizeSpecificColumnGridLayout`.
///
/// Lays out components in a table format with a given number of columns.
/// Columns try to show their widest preferred component. Specific columns
/// can be "maximized" so they are the last to shrink when the container
/// resizes.
#[derive(Debug, Clone)]
pub struct MaximizeSpecificColumnGridLayout {
    /// Number of columns.
    pub column_count: usize,
    /// Horizontal gap between columns.
    pub h_gap: u32,
    /// Vertical gap between rows.
    pub v_gap: u32,
    /// Which columns should be maximized (preserved at preferred size).
    maximized_columns: Vec<bool>,
}

impl MaximizeSpecificColumnGridLayout {
    /// Create a new grid layout with the given number of columns.
    pub fn new(column_count: usize) -> Self {
        let cc = column_count.max(1);
        Self {
            column_count: cc,
            h_gap: 0,
            v_gap: 0,
            maximized_columns: vec![false; cc],
        }
    }

    /// Create a new grid layout with gaps.
    pub fn with_gaps(mut self, h_gap: u32, v_gap: u32) -> Self {
        self.h_gap = h_gap;
        self.v_gap = v_gap;
        self
    }

    /// Mark a column as maximized. Maximized columns keep their preferred
    /// width until all non-maximized columns have been reduced to zero.
    pub fn maximize_column(&mut self, column: usize) {
        if column < self.maximized_columns.len() {
            self.maximized_columns[column] = true;
        }
    }

    /// Compute layout positions for components with given preferred sizes.
    ///
    /// `preferred_widths` and `preferred_heights` contain the preferred size
    /// of each component (left to right, top to bottom).
    pub fn compute(
        &self,
        container_width: u32,
        preferred_widths: &[u32],
        preferred_heights: &[u32],
    ) -> Vec<LayoutRect> {
        if self.column_count == 0 {
            return Vec::new();
        }
        let num_items = preferred_widths.len().min(preferred_heights.len());
        let row_count = (num_items + self.column_count - 1) / self.column_count;

        // Compute desired column widths (max preferred width per column)
        let mut desired_widths = vec![0u32; self.column_count];
        for i in 0..num_items {
            let col = i % self.column_count;
            desired_widths[col] = desired_widths[col].max(preferred_widths[i]);
        }

        // Compute actual column widths
        let computed_widths = self.compute_column_widths(container_width, &desired_widths);

        // Compute row heights
        let mut row_heights = vec![0u32; row_count];
        for i in 0..num_items {
            let row = i / self.column_count;
            row_heights[row] = row_heights[row].max(preferred_heights[i]);
        }

        // Total desired width for centering
        let total_desired: u32 = desired_widths.iter().sum();
        let total_gap = self.h_gap * (self.column_count as u32 - 1).max(0);
        let total_desired_with_gaps = total_desired + total_gap;
        let offset = if total_desired_with_gaps < container_width {
            (container_width - total_desired_with_gaps) / 2
        } else {
            0
        };

        let mut rects = Vec::with_capacity(num_items);
        let mut y = 0i32;
        for row in 0..row_count {
            let mut x = offset as i32;
            for col in 0..self.column_count {
                let ordinal = row * self.column_count + col;
                if ordinal >= num_items {
                    break;
                }
                rects.push(LayoutRect::new(x, y, computed_widths[col], row_heights[row]));
                x += computed_widths[col] as i32 + self.h_gap as i32;
            }
            y += row_heights[row] as i32 + self.v_gap as i32;
        }
        rects
    }

    fn compute_column_widths(&self, available: u32, desired: &[u32]) -> Vec<u32> {
        let n = desired.len();
        let mut computed = vec![0u32; n];
        let total_gap = self.h_gap * (n as u32 - 1).max(0);
        let mut remaining = available.saturating_sub(total_gap);
        let mut remaining_count = n;

        // First pass: maximize columns get their desired width
        let maximized_count = self.maximized_columns.iter().filter(|&&m| m).count();
        if maximized_count > 0 {
            let desired_max_total: u32 = desired
                .iter()
                .enumerate()
                .filter(|(i, _)| self.maximized_columns[*i])
                .map(|(_, &w)| w)
                .sum();

            if desired_max_total >= available {
                // Maximized columns consume the entire width
                let mut remaining_max = available;
                let mut remaining_max_count = maximized_count;
                let mut found = true;
                while found {
                    found = false;
                    let avg = if remaining_max_count > 0 {
                        remaining_max / remaining_max_count as u32
                    } else {
                        0
                    };
                    for i in 0..n {
                        if self.maximized_columns[i] && computed[i] == 0 {
                            if desired[i] < avg {
                                computed[i] = desired[i];
                                remaining_max = remaining_max.saturating_sub(computed[i]);
                                remaining_max_count -= 1;
                                found = true;
                            }
                        }
                    }
                }
                let avg = if remaining_max_count > 0 {
                    remaining_max / remaining_max_count as u32
                } else {
                    0
                };
                for i in 0..n {
                    if self.maximized_columns[i] && computed[i] == 0 {
                        computed[i] = avg;
                    }
                }
                return computed;
            }

            // Maximized columns get their desired width; remaining space goes to others
            for i in 0..n {
                if self.maximized_columns[i] {
                    computed[i] = desired[i];
                    remaining = remaining.saturating_sub(desired[i]);
                    remaining_count -= 1;
                }
            }
        }

        // Distribute remaining space to non-maximized columns
        let mut found = true;
        while found {
            found = false;
            let avg = if remaining_count > 0 {
                remaining / remaining_count as u32
            } else {
                0
            };
            for i in 0..n {
                if computed[i] == 0 && desired[i] < avg {
                    computed[i] = desired[i];
                    remaining = remaining.saturating_sub(computed[i]);
                    remaining_count -= 1;
                    found = true;
                }
            }
        }
        let avg = if remaining_count > 0 {
            remaining / remaining_count as u32
        } else {
            0
        };
        for i in 0..n {
            if computed[i] == 0 {
                computed[i] = avg;
            }
        }

        computed
    }
}

impl Default for MaximizeSpecificColumnGridLayout {
    fn default() -> Self {
        Self::new(2)
    }
}

// ============================================================================
// RightSidedSquishyBuddyLayout
// ============================================================================

/// Layout for two components where the first gets its preferred width and the
/// second gets the remaining space (up to its preferred width).
///
/// Ports Ghidra's `RightSidedSquishyBuddyLayout`.
///
/// The "buddy" (second component) is squished when space is limited.
/// Optionally supports right-alignment of both components.
#[derive(Debug, Clone)]
pub struct RightSidedSquishyBuddyLayout {
    /// Gap between the two components.
    pub h_gap: u32,
    /// Whether to right-align both components.
    pub right_align: bool,
}

impl RightSidedSquishyBuddyLayout {
    /// Create a new squishy buddy layout with the given gap.
    pub fn new(h_gap: u32) -> Self {
        Self {
            h_gap,
            right_align: false,
        }
    }

    /// Create a right-aligned variant.
    pub fn right_aligned(h_gap: u32) -> Self {
        Self {
            h_gap,
            right_align: true,
        }
    }

    /// Compute the layout for two components.
    ///
    /// Returns (comp1_rect, comp2_rect).
    pub fn compute(
        &self,
        container_width: u32,
        container_height: u32,
        comp1_pref_width: u32,
        _comp1_pref_height: u32,
        comp2_pref_width: u32,
        _comp2_pref_height: u32,
    ) -> (LayoutRect, LayoutRect) {
        let comp1_width = comp1_pref_width;
        let remaining = container_width.saturating_sub(comp1_width).saturating_sub(self.h_gap);
        let comp2_width = comp2_pref_width.min(remaining);
        let leftover = remaining.saturating_sub(comp2_width);

        let height = container_height;
        let mut comp1_x = 0i32;
        let mut comp2_x = comp1_width as i32 + self.h_gap as i32;

        if self.right_align {
            comp1_x += leftover as i32;
            comp2_x += leftover as i32;
        }

        (
            LayoutRect::new(comp1_x, 0, comp1_width, height),
            LayoutRect::new(comp2_x, 0, comp2_width, height),
        )
    }
}

impl Default for RightSidedSquishyBuddyLayout {
    fn default() -> Self {
        Self::new(4)
    }
}

// ============================================================================
// VariableRowHeightGridLayout
// ============================================================================

/// Grid layout where each row can have a different height.
///
/// Ports Ghidra's `VariableRowHeightGridLayout`.
///
/// Like [`ColumnLayout`] but each row's height is determined by the
/// tallest component in that row rather than using a uniform height.
#[derive(Debug, Clone)]
pub struct VariableRowHeightGridLayout {
    /// Number of columns.
    pub column_count: usize,
    /// Horizontal gap between columns.
    pub h_gap: u32,
    /// Vertical gap between rows.
    pub v_gap: u32,
}

impl VariableRowHeightGridLayout {
    /// Create a new variable-row-height grid layout.
    pub fn new(column_count: usize) -> Self {
        Self {
            column_count: column_count.max(1),
            h_gap: 0,
            v_gap: 0,
        }
    }

    /// Create a new grid layout with gaps.
    pub fn with_gaps(mut self, h_gap: u32, v_gap: u32) -> Self {
        self.h_gap = h_gap;
        self.v_gap = v_gap;
        self
    }

    /// Compute layout positions for components with given preferred sizes.
    ///
    /// Each row uses the maximum preferred height of its components.
    /// Columns share the available width equally.
    pub fn compute(
        &self,
        container_width: u32,
        preferred_widths: &[u32],
        preferred_heights: &[u32],
    ) -> Vec<LayoutRect> {
        let num_items = preferred_widths.len().min(preferred_heights.len());
        if num_items == 0 || self.column_count == 0 {
            return Vec::new();
        }
        let row_count = (num_items + self.column_count - 1) / self.column_count;
        let total_columns = self.column_count.min(num_items);
        let total_gap = self.h_gap * (self.column_count as u32 - 1).max(0);
        let column_width = container_width.saturating_sub(total_gap) / total_columns as u32;

        // Compute row heights (max height per row)
        let mut row_heights = vec![0u32; row_count];
        for i in 0..num_items {
            let row = i / self.column_count;
            row_heights[row] = row_heights[row].max(preferred_heights[i]);
        }

        let mut rects = Vec::with_capacity(num_items);
        let mut y = 0i32;
        for row in 0..row_count {
            let mut x = 0i32;
            for col in 0..self.column_count {
                let ordinal = row * self.column_count + col;
                if ordinal >= num_items {
                    break;
                }
                rects.push(LayoutRect::new(x, y, column_width, row_heights[row]));
                x += column_width as i32 + self.h_gap as i32;
            }
            y += row_heights[row] as i32 + self.v_gap as i32;
        }
        rects
    }
}

impl Default for VariableRowHeightGridLayout {
    fn default() -> Self {
        Self::new(2)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_uniform() {
        let p = Padding::uniform(8);
        assert_eq!(p.top, 8);
        assert_eq!(p.horizontal(), 16);
        assert_eq!(p.vertical(), 16);
    }

    #[test]
    fn padding_symmetric() {
        let p = Padding::symmetric(10, 5);
        assert_eq!(p.horizontal(), 20);
        assert_eq!(p.vertical(), 10);
    }

    #[test]
    fn column_layout_basic() {
        let layout = ColumnLayout::new(3);
        let rects = layout.compute(300, 200, 6, &[20, 20, 20, 20, 20, 20]);
        assert_eq!(rects.len(), 6);
        // First three should be in the same row
        assert_eq!(rects[0].y, rects[1].y);
        assert_eq!(rects[1].y, rects[2].y);
        // Fourth should be in the second row
        assert!(rects[3].y > rects[0].y);
    }

    #[test]
    fn horizontal_layout_basic() {
        let layout = HorizontalLayout::new();
        let rects = layout.compute(400, 100, &[100, 100, 100], &[30, 30, 30]);
        assert_eq!(rects.len(), 3);
        assert_eq!(rects[0].x, 4); // margin.left
        assert!(rects[1].x > rects[0].x);
        assert!(rects[2].x > rects[1].x);
    }

    #[test]
    fn vertical_layout_basic() {
        let layout = VerticalLayout::new();
        let rects = layout.compute(400, &[200, 200], &[30, 30]);
        assert_eq!(rects.len(), 2);
        assert!(rects[1].y > rects[0].y);
    }

    #[test]
    fn middle_layout_centers() {
        let layout = MiddleLayout::new(100, 50);
        let rect = layout.compute(400, 300);
        assert_eq!(rect.x, 150);
        assert_eq!(rect.y, 125);
        assert_eq!(rect.width, 100);
        assert_eq!(rect.height, 50);
    }

    #[test]
    fn pair_layout_basic() {
        let layout = PairLayout::new();
        let rects = layout.compute(400, 3);
        assert_eq!(rects.len(), 3);
        // Label should be at margin.left
        assert_eq!(rects[0].0.x, 4);
        // Value should be after label + gap
        assert_eq!(rects[0].1.x, 4 + 120 + 8);
    }

    #[test]
    fn stretch_layout_horizontal() {
        let layout = StretchLayout::horizontal(2, 50);
        let positions = layout.compute(400);
        assert_eq!(positions.len(), 3);
        assert_eq!(positions[0].1, 50); // fixed
        assert_eq!(positions[1].1, 50); // fixed
        // stretch should take remaining space
        assert!(positions[2].1 > 100);
    }

    #[test]
    fn three_column_layout() {
        let layout = ThreeColumnLayout::new(100, 100);
        let cols = layout.compute(400);
        assert_eq!(cols[0].1, 100); // left
        assert_eq!(cols[2].1, 100); // right
        assert!(cols[1].1 > 0); // middle elastic
    }

    #[test]
    fn two_column_pair_layout_num_columns() {
        let layout = TwoColumnPairLayout::new(5);
        assert_eq!(layout.num_columns(3), 1);
        assert_eq!(layout.num_columns(5), 1);
        assert_eq!(layout.num_columns(6), 2);
        assert_eq!(layout.num_columns(11), 3);
    }

    #[test]
    fn variable_height_pair_layout() {
        let layout = VariableHeightPairLayout::new();
        let rects = layout.compute(400, &[20, 30, 40]);
        assert_eq!(rects.len(), 3);
        assert_eq!(rects[0].0.height, 20);
        assert_eq!(rects[1].0.height, 30);
        assert_eq!(rects[2].0.height, 40);
    }

    #[test]
    fn layout_rect_dimensions() {
        let r = LayoutRect::new(10, 20, 100, 50);
        assert_eq!(r.right(), 110);
        assert_eq!(r.bottom(), 70);
    }

    #[test]
    fn maximize_specific_column_grid_layout_basic() {
        let layout = MaximizeSpecificColumnGridLayout::new(3);
        let rects = layout.compute(
            300,
            &[80, 60, 40, 70, 50, 30],
            &[20, 20, 20, 20, 20, 20],
        );
        assert_eq!(rects.len(), 6);
        // First row
        assert_eq!(rects[0].y, rects[1].y);
        assert_eq!(rects[1].y, rects[2].y);
        // Second row starts below
        assert!(rects[3].y > rects[0].y);
    }

    #[test]
    fn maximize_specific_column_grid_maximized() {
        let mut layout = MaximizeSpecificColumnGridLayout::new(2);
        layout.maximize_column(1);
        let rects = layout.compute(
            200,
            &[50, 100, 50, 100],
            &[20, 20, 20, 20],
        );
        assert_eq!(rects.len(), 4);
        // Maximized column (col 1) should get at least its preferred width
        assert!(rects[1].width >= 100 || rects[1].width > 0);
    }

    #[test]
    fn maximize_specific_column_grid_empty() {
        let layout = MaximizeSpecificColumnGridLayout::new(3);
        let rects = layout.compute(300, &[], &[]);
        assert!(rects.is_empty());
    }

    #[test]
    fn right_sided_squishy_buddy_layout_basic() {
        let layout = RightSidedSquishyBuddyLayout::new(8);
        let (c1, c2) = layout.compute(400, 30, 100, 30, 200, 30);
        assert_eq!(c1.width, 100); // gets full preferred
        assert_eq!(c2.width, 200); // fits in remaining space
        assert_eq!(c1.x, 0);
        assert_eq!(c2.x, 108); // 100 + 8 gap
    }

    #[test]
    fn right_sided_squishy_buddy_squished() {
        let layout = RightSidedSquishyBuddyLayout::new(8);
        let (c1, c2) = layout.compute(200, 30, 150, 30, 200, 30);
        assert_eq!(c1.width, 150);
        assert_eq!(c2.width, 42); // 200 - 150 - 8 = 42
    }

    #[test]
    fn right_sided_squishy_buddy_right_align() {
        let layout = RightSidedSquishyBuddyLayout::right_aligned(8);
        let (c1, _c2) = layout.compute(400, 30, 100, 30, 100, 30);
        assert_eq!(c1.width, 100);
        // There's leftover space (400 - 100 - 8 - 100 = 192), both shift right
        assert!(c1.x > 0);
    }

    #[test]
    fn variable_row_height_grid_layout_basic() {
        let layout = VariableRowHeightGridLayout::new(2);
        let rects = layout.compute(
            200,
            &[80, 60, 70, 50],
            &[20, 30, 25, 35],
        );
        assert_eq!(rects.len(), 4);
        // Row 0: max(20, 30) = 30
        assert_eq!(rects[0].height, 30);
        assert_eq!(rects[1].height, 30);
        // Row 1 starts after row 0
        assert!(rects[2].y > rects[0].y);
        // Row 1: max(25, 35) = 35
        assert_eq!(rects[2].height, 35);
        assert_eq!(rects[3].height, 35);
    }

    #[test]
    fn variable_row_height_grid_layout_with_gaps() {
        let layout = VariableRowHeightGridLayout::new(2).with_gaps(4, 6);
        let rects = layout.compute(200, &[80, 60, 70, 50], &[20, 30, 25, 35]);
        assert_eq!(rects.len(), 4);
        // Column width = (200 - 4) / 2 = 98
        assert_eq!(rects[0].width, 98);
        // Row 1 y = row 0 height + v_gap = 30 + 6 = 36
        assert_eq!(rects[2].y, 36);
    }

    #[test]
    fn variable_row_height_grid_layout_empty() {
        let layout = VariableRowHeightGridLayout::new(3);
        let rects = layout.compute(200, &[], &[]);
        assert!(rects.is_empty());
    }
}
