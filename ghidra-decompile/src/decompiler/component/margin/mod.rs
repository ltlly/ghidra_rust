//! Decompiler margin providers.
//!
//! Ports `ghidra.app.decompiler.component.margin` package.

/// A margin provider renders content in the margin area next to the
/// decompiler output (e.g., line numbers, breakpoints).
pub trait DecompilerMarginProvider: Send + Sync {
    /// The name of this margin provider.
    fn name(&self) -> &str;

    /// Width of the margin in pixels.
    fn width(&self) -> f64;

    /// Render the margin for a given line number.
    fn render_line(&self, line_number: usize) -> MarginRenderItem;

    /// Whether this margin is visible.
    fn is_visible(&self) -> bool;

    /// Set visibility.
    fn set_visible(&mut self, visible: bool);
}

/// A single render item in the margin.
#[derive(Debug, Clone)]
pub struct MarginRenderItem {
    /// Text to display (if any).
    pub text: Option<String>,
    /// Whether to draw a marker (e.g., breakpoint dot).
    pub marker: bool,
    /// Marker color (CSS hex).
    pub marker_color: String,
    /// Whether this line is highlighted.
    pub highlighted: bool,
}

impl MarginRenderItem {
    /// Create an empty render item.
    pub fn empty() -> Self {
        Self {
            text: None,
            marker: false,
            marker_color: String::new(),
            highlighted: false,
        }
    }

    /// Create a text-only render item.
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: Some(text.into()),
            marker: false,
            marker_color: String::new(),
            highlighted: false,
        }
    }

    /// Create a marker render item.
    pub fn marker(color: impl Into<String>) -> Self {
        Self {
            text: None,
            marker: true,
            marker_color: color.into(),
            highlighted: false,
        }
    }
}

/// Line number margin provider.
#[derive(Debug, Clone)]
pub struct LineNumberMarginProvider {
    /// Whether the margin is visible.
    visible: bool,
    /// Starting line number.
    pub start_line: usize,
    /// Width of the margin in pixels.
    margin_width: f64,
    /// Text color.
    pub text_color: String,
}

impl LineNumberMarginProvider {
    /// Create a new line number margin provider.
    pub fn new() -> Self {
        Self {
            visible: true,
            start_line: 1,
            margin_width: 40.0,
            text_color: "#888888".to_string(),
        }
    }

    /// Set the starting line number.
    pub fn with_start_line(mut self, start: usize) -> Self {
        self.start_line = start;
        self
    }
}

impl Default for LineNumberMarginProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DecompilerMarginProvider for LineNumberMarginProvider {
    fn name(&self) -> &str {
        "Line Numbers"
    }

    fn width(&self) -> f64 {
        self.margin_width
    }

    fn render_line(&self, line_number: usize) -> MarginRenderItem {
        MarginRenderItem::text(format!("{}", self.start_line + line_number))
    }

    fn is_visible(&self) -> bool {
        self.visible
    }

    fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }
}

/// A pixel-to-line mapping for efficient line lookups.
#[derive(Debug, Clone)]
pub struct LayoutPixelIndexMap {
    /// Entries: (pixel_y_offset, line_number).
    entries: Vec<(f64, usize)>,
}

impl LayoutPixelIndexMap {
    /// Create a new empty map.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add an entry mapping a pixel offset to a line number.
    pub fn add(&mut self, pixel_offset: f64, line_number: usize) {
        self.entries.push((pixel_offset, line_number));
    }

    /// Look up the line number for a given pixel offset.
    ///
    /// Returns the line number of the closest entry at or before the offset.
    pub fn lookup(&self, pixel_offset: f64) -> Option<usize> {
        let mut best: Option<usize> = None;
        for &(offset, line) in &self.entries {
            if offset <= pixel_offset {
                best = Some(line);
            } else {
                break;
            }
        }
        best
    }

    /// Number of entries in the map.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Sort entries by pixel offset (must be called before lookup).
    pub fn sort(&mut self) {
        self.entries.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    }
}

impl Default for LayoutPixelIndexMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Vertical layout pixel index map for margin rendering.
#[derive(Debug, Clone)]
pub struct VerticalLayoutPixelIndexMap {
    map: LayoutPixelIndexMap,
    /// Line height in pixels.
    pub line_height: f64,
}

impl VerticalLayoutPixelIndexMap {
    /// Create a new vertical layout map.
    pub fn new(line_height: f64) -> Self {
        Self {
            map: LayoutPixelIndexMap::new(),
            line_height,
        }
    }

    /// Add a line at the given y offset.
    pub fn add_line(&mut self, y_offset: f64, line_number: usize) {
        self.map.add(y_offset, line_number);
    }

    /// Look up the line number for a pixel offset.
    pub fn lookup(&self, pixel_offset: f64) -> Option<usize> {
        self.map.lookup(pixel_offset)
    }

    /// Sort the internal map.
    pub fn sort(&mut self) {
        self.map.sort();
    }

    /// Get the y offset for a specific line number.
    pub fn line_to_pixel(&self, line_number: usize) -> f64 {
        line_number as f64 * self.line_height
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_number_margin_provider() {
        let provider = LineNumberMarginProvider::new();
        assert_eq!(provider.name(), "Line Numbers");
        assert!(provider.is_visible());
        assert_eq!(provider.width(), 40.0);

        let item = provider.render_line(0);
        assert_eq!(item.text.as_deref(), Some("1"));

        let item = provider.render_line(4);
        assert_eq!(item.text.as_deref(), Some("5"));
    }

    #[test]
    fn line_number_margin_custom_start() {
        let provider = LineNumberMarginProvider::new().with_start_line(100);
        let item = provider.render_line(0);
        assert_eq!(item.text.as_deref(), Some("100"));
    }

    #[test]
    fn margin_render_item_empty() {
        let item = MarginRenderItem::empty();
        assert!(item.text.is_none());
        assert!(!item.marker);
    }

    #[test]
    fn margin_render_item_text() {
        let item = MarginRenderItem::text("42");
        assert_eq!(item.text.as_deref(), Some("42"));
    }

    #[test]
    fn margin_render_item_marker() {
        let item = MarginRenderItem::marker("#FF0000");
        assert!(item.marker);
        assert_eq!(item.marker_color, "#FF0000");
    }

    #[test]
    fn layout_pixel_index_map() {
        let mut map = LayoutPixelIndexMap::new();
        map.add(0.0, 1);
        map.add(20.0, 2);
        map.add(40.0, 3);
        map.sort();

        assert_eq!(map.lookup(0.0), Some(1));
        assert_eq!(map.lookup(10.0), Some(1));
        assert_eq!(map.lookup(20.0), Some(2));
        assert_eq!(map.lookup(35.0), Some(2));
        assert_eq!(map.lookup(40.0), Some(3));
        assert_eq!(map.lookup(-1.0), None);
    }

    #[test]
    fn vertical_layout_map() {
        let mut map = VerticalLayoutPixelIndexMap::new(16.0);
        map.add_line(0.0, 1);
        map.add_line(16.0, 2);
        map.add_line(32.0, 3);
        map.sort();

        assert_eq!(map.lookup(8.0), Some(1));
        assert_eq!(map.lookup(24.0), Some(2));
        assert_eq!(map.line_to_pixel(5), 80.0);
    }

    #[test]
    fn margin_visibility() {
        let mut provider = LineNumberMarginProvider::new();
        assert!(provider.is_visible());
        provider.set_visible(false);
        assert!(!provider.is_visible());
    }
}
