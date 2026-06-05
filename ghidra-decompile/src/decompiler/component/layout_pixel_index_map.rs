//! Layout pixel index map -- maps between pixel positions and field indices.
//!
//! Port of Ghidra's `ghidra.app.decompiler.component.LayoutPixelIndexMap`
//! and `VerticalLayoutPixelIndexMap`.
//!
//! These types provide a bidirectional mapping between:
//! - Pixel Y-coordinates (screen positions)
//! - Layout indices (line numbers in the decompiler output)
//!
//! This is used by the decompiler panel to convert mouse clicks into
//! line/token positions and vice versa.

/// Bidirectional mapping between pixel positions and layout indices.
///
/// Port of `ghidra.app.decompiler.component.LayoutPixelIndexMap`.
#[derive(Debug, Clone)]
pub struct LayoutPixelIndexMap {
    /// Array of starting pixel offsets for each line.
    /// `line_starts[i]` is the Y-pixel where line `i` begins.
    line_starts: Vec<i32>,
    /// Array of heights for each line.
    line_heights: Vec<i32>,
}

impl LayoutPixelIndexMap {
    /// Create a new empty pixel index map.
    pub fn new() -> Self {
        Self {
            line_starts: Vec::new(),
            line_heights: Vec::new(),
        }
    }

    /// Create a pixel index map with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            line_starts: Vec::with_capacity(capacity),
            line_heights: Vec::with_capacity(capacity),
        }
    }

    /// Add a line with its starting Y position and height.
    pub fn add_line(&mut self, y_start: i32, height: i32) {
        self.line_starts.push(y_start);
        self.line_heights.push(height);
    }

    /// Get the number of lines.
    pub fn line_count(&self) -> usize {
        self.line_starts.len()
    }

    /// Get the Y pixel start for a given line index.
    pub fn y_start(&self, index: usize) -> Option<i32> {
        self.line_starts.get(index).copied()
    }

    /// Get the height of a given line.
    pub fn line_height(&self, index: usize) -> Option<i32> {
        self.line_heights.get(index).copied()
    }

    /// Get the total height (sum of all line heights plus gaps).
    pub fn total_height(&self) -> i32 {
        if self.line_starts.is_empty() {
            return 0;
        }
        let last_idx = self.line_starts.len() - 1;
        self.line_starts[last_idx] + self.line_heights[last_idx]
    }

    /// Convert a pixel Y position to a line index.
    ///
    /// Returns the index of the line that contains the given pixel offset.
    /// If the pixel is above all lines, returns 0. If below all lines,
    /// returns the last index.
    pub fn pixel_to_index(&self, y_pixel: i32) -> usize {
        if self.line_starts.is_empty() {
            return 0;
        }

        // Binary search for the line containing this pixel.
        let mut low = 0;
        let mut high = self.line_starts.len();

        while low < high {
            let mid = low + (high - low) / 2;
            let line_end = self.line_starts[mid] + self.line_heights[mid];
            if y_pixel < self.line_starts[mid] {
                high = mid;
            } else if y_pixel >= line_end {
                low = mid + 1;
            } else {
                return mid;
            }
        }

        // Clamp to valid range.
        low.min(self.line_starts.len() - 1)
    }

    /// Convert a line index to the Y pixel position (top of line).
    pub fn index_to_pixel(&self, index: usize) -> i32 {
        self.line_starts.get(index).copied().unwrap_or(0)
    }

    /// Check if a pixel position falls within a given line.
    pub fn pixel_in_line(&self, y_pixel: i32, line_index: usize) -> bool {
        if let (Some(&start), Some(&height)) = (
            self.line_starts.get(line_index),
            self.line_heights.get(line_index),
        ) {
            y_pixel >= start && y_pixel < start + height
        } else {
            false
        }
    }

    /// Get the vertical offset within a line given a pixel Y position.
    pub fn offset_in_line(&self, y_pixel: i32, line_index: usize) -> i32 {
        if let Some(&start) = self.line_starts.get(line_index) {
            (y_pixel - start).max(0)
        } else {
            0
        }
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.line_starts.clear();
        self.line_heights.clear();
    }

    /// Build a simple uniform-height map for the given line count and height.
    pub fn uniform(line_count: usize, line_height: i32) -> Self {
        let mut map = Self::with_capacity(line_count);
        for i in 0..line_count {
            map.add_line(i as i32 * line_height, line_height);
        }
        map
    }
}

impl Default for LayoutPixelIndexMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Vertical layout pixel index map with variable-height lines.
///
/// Port of `ghidra.app.decompiler.component.VerticalLayoutPixelIndexMap`.
/// This variant supports lines with different heights (e.g., wrapped lines
/// or lines with inline data).
#[derive(Debug, Clone)]
pub struct VerticalLayoutPixelIndexMap {
    inner: LayoutPixelIndexMap,
    /// The line gap in pixels.
    pub line_gap: i32,
}

impl VerticalLayoutPixelIndexMap {
    /// Create a new vertical layout pixel index map.
    pub fn new(line_gap: i32) -> Self {
        Self {
            inner: LayoutPixelIndexMap::new(),
            line_gap,
        }
    }

    /// Add a line with its content height (gap is added automatically).
    pub fn add_line(&mut self, content_height: i32) {
        let y_start = self.inner.total_height();
        self.inner.add_line(y_start, content_height + self.line_gap);
    }

    /// Get the number of lines.
    pub fn line_count(&self) -> usize {
        self.inner.line_count()
    }

    /// Convert a pixel Y position to a line index.
    pub fn pixel_to_index(&self, y_pixel: i32) -> usize {
        self.inner.pixel_to_index(y_pixel)
    }

    /// Convert a line index to the Y pixel position.
    pub fn index_to_pixel(&self, index: usize) -> i32 {
        self.inner.index_to_pixel(index)
    }

    /// Get the content height of a line (excluding gap).
    pub fn content_height(&self, index: usize) -> Option<i32> {
        self.inner.line_height(index).map(|h| (h - self.line_gap).max(0))
    }

    /// Get the total height including all gaps.
    pub fn total_height(&self) -> i32 {
        self.inner.total_height()
    }

    /// Check if a pixel position falls within a given line.
    pub fn pixel_in_line(&self, y_pixel: i32, line_index: usize) -> bool {
        self.inner.pixel_in_line(y_pixel, line_index)
    }

    /// Build a uniform-height map.
    pub fn uniform(line_count: usize, line_height: i32, line_gap: i32) -> Self {
        let mut map = Self::new(line_gap);
        for _ in 0..line_count {
            map.add_line(line_height);
        }
        map
    }
}

impl Default for VerticalLayoutPixelIndexMap {
    fn default() -> Self {
        Self::new(2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_map() {
        let map = LayoutPixelIndexMap::new();
        assert_eq!(map.line_count(), 0);
        assert_eq!(map.total_height(), 0);
        assert_eq!(map.pixel_to_index(100), 0);
    }

    #[test]
    fn test_uniform_map() {
        let map = LayoutPixelIndexMap::uniform(5, 20);
        assert_eq!(map.line_count(), 5);
        assert_eq!(map.total_height(), 100);
        assert_eq!(map.pixel_to_index(0), 0);
        assert_eq!(map.pixel_to_index(10), 0);
        assert_eq!(map.pixel_to_index(20), 1);
        assert_eq!(map.pixel_to_index(50), 2);
        assert_eq!(map.pixel_to_index(99), 4);
    }

    #[test]
    fn test_index_to_pixel() {
        let map = LayoutPixelIndexMap::uniform(5, 20);
        assert_eq!(map.index_to_pixel(0), 0);
        assert_eq!(map.index_to_pixel(1), 20);
        assert_eq!(map.index_to_pixel(4), 80);
    }

    #[test]
    fn test_pixel_in_line() {
        let map = LayoutPixelIndexMap::uniform(3, 30);
        assert!(map.pixel_in_line(0, 0));
        assert!(map.pixel_in_line(29, 0));
        assert!(!map.pixel_in_line(30, 0));
        assert!(map.pixel_in_line(30, 1));
        assert!(!map.pixel_in_line(100, 0));
    }

    #[test]
    fn test_offset_in_line() {
        let map = LayoutPixelIndexMap::uniform(3, 30);
        assert_eq!(map.offset_in_line(0, 0), 0);
        assert_eq!(map.offset_in_line(15, 0), 15);
        assert_eq!(map.offset_in_line(45, 1), 15);
    }

    #[test]
    fn test_variable_height() {
        let mut map = LayoutPixelIndexMap::new();
        map.add_line(0, 20);
        map.add_line(20, 40);
        map.add_line(60, 15);
        assert_eq!(map.pixel_to_index(0), 0);
        assert_eq!(map.pixel_to_index(25), 1);
        assert_eq!(map.pixel_to_index(55), 1);
        assert_eq!(map.pixel_to_index(65), 2);
        assert_eq!(map.total_height(), 75);
    }

    #[test]
    fn test_out_of_bounds() {
        let map = LayoutPixelIndexMap::uniform(3, 20);
        // Below all lines -> last index
        assert_eq!(map.pixel_to_index(1000), 2);
        // Negative -> 0
        assert_eq!(map.pixel_to_index(-10), 0);
    }

    #[test]
    fn test_vertical_map() {
        let mut map = VerticalLayoutPixelIndexMap::new(4);
        map.add_line(16); // line 0: y=0..20 (16+4)
        map.add_line(24); // line 1: y=20..48 (24+4)
        map.add_line(16); // line 2: y=48..68 (16+4)
        assert_eq!(map.line_count(), 3);
        assert_eq!(map.pixel_to_index(0), 0);
        assert_eq!(map.pixel_to_index(19), 0);
        assert_eq!(map.pixel_to_index(20), 1);
        assert_eq!(map.pixel_to_index(47), 1);
        assert_eq!(map.pixel_to_index(48), 2);
        assert_eq!(map.content_height(0), Some(16));
        assert_eq!(map.content_height(1), Some(24));
        assert_eq!(map.total_height(), 68);
    }

    #[test]
    fn test_vertical_map_uniform() {
        let map = VerticalLayoutPixelIndexMap::uniform(4, 16, 4);
        assert_eq!(map.line_count(), 4);
        assert_eq!(map.total_height(), 80); // 4 * (16 + 4)
        assert_eq!(map.pixel_to_index(0), 0);
        assert_eq!(map.pixel_to_index(20), 1);
        assert_eq!(map.pixel_to_index(40), 2);
    }

    #[test]
    fn test_clear() {
        let mut map = LayoutPixelIndexMap::uniform(5, 20);
        assert_eq!(map.line_count(), 5);
        map.clear();
        assert_eq!(map.line_count(), 0);
    }
}
