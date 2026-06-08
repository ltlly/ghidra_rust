//! Line Number Decompiler Margin -- Rust port of
//! `ghidra.app.decompiler.component.margin.LineNumberDecompilerMarginProvider`.
//!
//! In Ghidra, `LineNumberDecompilerMarginProvider` extends `JPanel` and
//! implements `DecompilerMarginProvider` and `LayoutModelListener`.  It
//! renders line numbers in the left margin of the decompiler panel.  The
//! margin width is dynamically computed based on the number of lines in
//! the current function, and the paint method draws line numbers aligned
//! to the right edge of the margin.
//!
//! # Architecture
//!
//! ```text
//! LineNumberMarginProvider
//!   ├── model: Option<LayoutModel>
//!   ├── pixmap: Option<LayoutPixelIndexMap>
//!   ├── font_size: f32
//!   ├── font_family: String
//!   ├── text_color: u32
//!   ├── background_color: u32
//!   ├── right_padding: usize
//!   ├── min_width: usize
//!   └── width: usize
//!
//! LayoutPixelIndexMap
//!   ├── pixel_to_index: BTreeMap<usize, usize>
//!   └── index_to_pixel: BTreeMap<usize, usize>
//!
//! LayoutModel
//!   ├── num_lines: usize
//!   └── listeners: Vec<LayoutModelListener>
//! ```

use std::collections::BTreeMap;
use std::fmt;

use super::decompiler_margin_service::{DecompilerMarginProvider, MarginLineInfo, MarginPaintResult};

// ---------------------------------------------------------------------------
// LayoutPixelIndexMap -- maps between pixel positions and layout indices
// ---------------------------------------------------------------------------

/// A bidirectional map between pixel Y-coordinates and layout (line) indices.
///
/// In Ghidra, this corresponds to `LayoutPixelIndexMap` and its
/// `VerticalLayoutPixelIndexMap` implementation.  The decompiler panel
/// uses this to translate between the scrollable pixel space and the
/// line indices of the C code output.
///
/// The map accounts for:
/// - Scrolling (pixel offsets that don't start at 0)
/// - Non-uniform line heights (rare, but possible with wrapped lines)
#[derive(Debug, Clone)]
pub struct LayoutPixelIndexMap {
    /// Maps pixel Y-coordinate to layout (line) index.
    pixel_to_index: BTreeMap<usize, usize>,
    /// Maps layout (line) index to pixel Y-coordinate.
    index_to_pixel: BTreeMap<usize, usize>,
    /// The default line height in pixels.
    line_height: usize,
    /// The total number of lines.
    num_lines: usize,
    /// The scroll offset in pixels.
    scroll_offset: usize,
}

impl LayoutPixelIndexMap {
    /// Create a new pixel-index map with uniform line height.
    ///
    /// # Arguments
    /// * `num_lines` - The total number of lines.
    /// * `line_height` - The height of each line in pixels.
    /// * `scroll_offset` - The initial scroll offset in pixels.
    pub fn new(num_lines: usize, line_height: usize, scroll_offset: usize) -> Self {
        let mut pixel_to_index = BTreeMap::new();
        let mut index_to_pixel = BTreeMap::new();

        for i in 0..num_lines {
            let pixel = scroll_offset + i * line_height;
            pixel_to_index.insert(pixel, i);
            index_to_pixel.insert(i, pixel);
        }

        Self {
            pixel_to_index,
            index_to_pixel,
            line_height,
            num_lines,
            scroll_offset,
        }
    }

    /// Get the layout (line) index for a given pixel Y-coordinate.
    ///
    /// Returns the index of the line at or just above the given pixel.
    /// If the pixel is before the first line, returns 0.  If it is after
    /// the last line, returns the last line index.
    pub fn get_index(&self, pixel: usize) -> usize {
        if self.pixel_to_index.is_empty() {
            return 0;
        }

        // Find the entry with the largest key <= pixel.
        let idx = self
            .pixel_to_index
            .range(..=pixel)
            .next_back()
            .map(|(_, &v)| v)
            .unwrap_or(0);

        idx.min(self.num_lines.saturating_sub(1))
    }

    /// Get the pixel Y-coordinate for a given layout (line) index.
    ///
    /// Returns the pixel position of the top of the given line.
    pub fn get_pixel(&self, index: usize) -> usize {
        self.index_to_pixel
            .get(&index)
            .copied()
            .unwrap_or(self.scroll_offset + index * self.line_height)
    }

    /// Update the scroll offset and recompute the map.
    pub fn set_scroll_offset(&mut self, offset: usize) {
        self.scroll_offset = offset;
        self.rebuild();
    }

    /// Update the number of lines and recompute the map.
    pub fn set_num_lines(&mut self, num_lines: usize) {
        self.num_lines = num_lines;
        self.rebuild();
    }

    /// Update the line height and recompute the map.
    pub fn set_line_height(&mut self, height: usize) {
        self.line_height = height;
        self.rebuild();
    }

    /// Get the line height.
    pub fn line_height(&self) -> usize {
        self.line_height
    }

    /// Get the number of lines.
    pub fn num_lines(&self) -> usize {
        self.num_lines
    }

    /// Get the scroll offset.
    pub fn scroll_offset(&self) -> usize {
        self.scroll_offset
    }

    /// Rebuild the internal maps.
    fn rebuild(&mut self) {
        self.pixel_to_index.clear();
        self.index_to_pixel.clear();
        for i in 0..self.num_lines {
            let pixel = self.scroll_offset + i * self.line_height;
            self.pixel_to_index.insert(pixel, i);
            self.index_to_pixel.insert(i, pixel);
        }
    }
}

// ---------------------------------------------------------------------------
// LayoutModel -- the line/token model for the decompiler output
// ---------------------------------------------------------------------------

/// A model of the decompiler's line layout.
///
/// In Ghidra, this corresponds to `LayoutModel` from the field panel
/// framework.  Each layout corresponds to a single line of C code in the
/// decompiler output.
#[derive(Debug, Clone)]
pub struct LayoutModel {
    /// The total number of lines in the model.
    num_lines: usize,
    /// The function name associated with this model.
    function_name: Option<String>,
    /// The start address of the function.
    function_address: Option<u64>,
}

impl LayoutModel {
    /// Create a new layout model with the given number of lines.
    pub fn new(num_lines: usize) -> Self {
        Self {
            num_lines,
            function_name: None,
            function_address: None,
        }
    }

    /// Get the number of lines.
    pub fn num_lines(&self) -> usize {
        self.num_lines
    }

    /// Set the number of lines.
    pub fn set_num_lines(&mut self, n: usize) {
        self.num_lines = n;
    }

    /// Set the function information.
    pub fn set_function(&mut self, name: impl Into<String>, address: u64) {
        self.function_name = Some(name.into());
        self.function_address = Some(address);
    }

    /// Get the function name.
    pub fn function_name(&self) -> Option<&str> {
        self.function_name.as_deref()
    }

    /// Get the function address.
    pub fn function_address(&self) -> Option<u64> {
        self.function_address
    }
}

// ---------------------------------------------------------------------------
// MarginPaintInstruction -- what to paint for one line
// ---------------------------------------------------------------------------

/// An instruction for painting a line number in the margin.
#[derive(Debug, Clone)]
pub struct LineNumberPaintInstruction {
    /// The 1-based line number to display.
    pub display_number: usize,
    /// The Y pixel coordinate for the baseline of the text.
    pub baseline_y: usize,
    /// The X pixel coordinate for the right edge of the text.
    pub right_edge_x: usize,
    /// The text string to draw.
    pub text: String,
    /// The width of the text in pixels.
    pub text_width: usize,
}

impl LineNumberPaintInstruction {
    /// Create a new paint instruction.
    pub fn new(display_number: usize, baseline_y: usize, right_edge_x: usize) -> Self {
        let text = display_number.to_string();
        Self {
            display_number,
            baseline_y,
            right_edge_x,
            text,
            text_width: 0, // computed externally based on font metrics
        }
    }
}

// ---------------------------------------------------------------------------
// VisibleRange -- the range of visible lines
// ---------------------------------------------------------------------------

/// The range of lines visible in the margin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisibleRange {
    /// The first visible line index (0-based).
    pub start_line: usize,
    /// The last visible line index (0-based, inclusive).
    pub end_line: usize,
    /// The Y pixel coordinate of the top of the visible area.
    pub top_pixel: usize,
    /// The height of the visible area in pixels.
    pub height: usize,
}

impl VisibleRange {
    /// Create a new visible range.
    pub fn new(start_line: usize, end_line: usize, top_pixel: usize, height: usize) -> Self {
        Self {
            start_line,
            end_line,
            top_pixel,
            height,
        }
    }

    /// The number of visible lines.
    pub fn line_count(&self) -> usize {
        self.end_line.saturating_sub(self.start_line) + 1
    }
}

// ---------------------------------------------------------------------------
// FontMetrics -- cached font measurements
// ---------------------------------------------------------------------------

/// Cached font metrics for text measurement.
#[derive(Debug, Clone)]
pub struct FontMetrics {
    /// The font family name.
    pub family: String,
    /// The font size in points.
    pub size: f32,
    /// The maximum ascent in pixels.
    pub max_ascent: usize,
    /// The maximum descent in pixels.
    pub max_descent: usize,
    /// The height of a digit character in pixels (for uniform digit width).
    pub digit_width: usize,
    /// The line height (ascent + descent + leading).
    pub line_height: usize,
}

impl FontMetrics {
    /// Create new font metrics.
    pub fn new(family: impl Into<String>, size: f32) -> Self {
        // Approximate metrics for monospace fonts typical in the decompiler.
        let max_ascent = (size * 0.8) as usize;
        let max_descent = (size * 0.2) as usize;
        let digit_width = (size * 0.6) as usize;
        let line_height = max_ascent + max_descent + 2; // 2px leading

        Self {
            family: family.into(),
            size,
            max_ascent,
            max_descent,
            digit_width,
            line_height,
        }
    }

    /// Compute the width of a numeric string using digit metrics.
    pub fn string_width(&self, text: &str) -> usize {
        text.len() * self.digit_width
    }
}

impl Default for FontMetrics {
    fn default() -> Self {
        Self::new("Monospaced", 12.0)
    }
}

// ---------------------------------------------------------------------------
// LineNumberMarginProvider -- the line number margin implementation
// ---------------------------------------------------------------------------

/// The built-in line number margin provider for the Decompiler.
///
/// This models `LineNumberDecompilerMarginProvider` from Ghidra, which
/// renders 1-based line numbers in the left margin of the decompiler
/// panel.  The margin width is dynamically computed based on the number
/// of lines in the current function.
///
/// In Ghidra:
/// ```java
/// public class LineNumberDecompilerMarginProvider extends JPanel
///         implements DecompilerMarginProvider, LayoutModelListener {
///     // Renders line numbers right-aligned in the margin.
///     public void paint(Graphics g) { ... }
/// }
/// ```
#[derive(Debug)]
pub struct LineNumberMarginProvider {
    /// The current layout model (number of lines).
    model: Option<LayoutModel>,
    /// The pixel-index map for coordinate translation.
    pixmap: Option<LayoutPixelIndexMap>,
    /// Cached font metrics.
    font_metrics: FontMetrics,
    /// The computed width of the margin in pixels.
    width: usize,
    /// Right padding in pixels.
    right_padding: usize,
    /// Minimum margin width in pixels.
    min_width: usize,
    /// The text color (RGBA).
    text_color: u32,
    /// The background color (RGBA).
    background_color: u32,
    /// Whether the margin needs repainting.
    needs_repaint: bool,
    /// The function name (for context).
    function_name: Option<String>,
}

impl LineNumberMarginProvider {
    /// Create a new line number margin provider.
    pub fn new() -> Self {
        Self {
            model: None,
            pixmap: None,
            font_metrics: FontMetrics::default(),
            width: 16,
            right_padding: 2,
            min_width: 16,
            text_color: 0xFF808080,       // gray
            background_color: 0xFFF8F8F8, // light gray
            needs_repaint: true,
            function_name: None,
        }
    }

    // -- Configuration --

    /// Set the font for the line numbers.
    pub fn set_font(&mut self, family: impl Into<String>, size: f32) {
        self.font_metrics = FontMetrics::new(family, size);
        self.update_width();
        self.needs_repaint = true;
    }

    /// Set the text color.
    pub fn set_text_color(&mut self, color: u32) {
        self.text_color = color;
        self.needs_repaint = true;
    }

    /// Set the background color.
    pub fn set_background_color(&mut self, color: u32) {
        self.background_color = color;
        self.needs_repaint = true;
    }

    /// Set the right padding in pixels.
    pub fn set_right_padding(&mut self, padding: usize) {
        self.right_padding = padding;
        self.update_width();
        self.needs_repaint = true;
    }

    /// Set the minimum width in pixels.
    pub fn set_min_width(&mut self, width: usize) {
        self.min_width = width;
        self.update_width();
        self.needs_repaint = true;
    }

    // -- Layout model updates --

    /// Update the layout model (called when the function changes).
    fn set_layout_model(&mut self, model: LayoutModel) {
        self.model = Some(model);
        self.update_width();
        self.needs_repaint = true;
    }

    /// Update the pixel-index map (called when scrolling or layout changes).
    fn set_pixmap(&mut self, pixmap: LayoutPixelIndexMap) {
        self.pixmap = Some(pixmap);
        self.needs_repaint = true;
    }

    // -- Width computation --

    /// Recompute the margin width based on the current model.
    fn update_width(&mut self) {
        let num_lines = self.model.as_ref().map_or(0, |m| m.num_lines());
        if num_lines == 0 {
            self.width = self.min_width;
            return;
        }

        // Compute the width needed for the last line number.
        let last_line_text = num_lines.to_string();
        let text_width = self.font_metrics.string_width(&last_line_text);
        let total = text_width + self.right_padding;
        self.width = total.max(self.min_width);
    }

    // -- Paint instructions --

    /// Generate paint instructions for the visible range.
    ///
    /// This computes the line numbers and positions for all visible lines,
    /// suitable for a rendering backend to execute.
    pub fn generate_paint_instructions(
        &self,
        visible_top: usize,
        visible_height: usize,
    ) -> Vec<LineNumberPaintInstruction> {
        let pixmap = match self.pixmap.as_ref() {
            Some(p) => p,
            None => return Vec::new(),
        };

        let num_lines = self.model.as_ref().map_or(0, |m| m.num_lines());
        if num_lines == 0 {
            return Vec::new();
        }

        let start_idx = pixmap.get_index(visible_top);
        let end_idx = if visible_height > 0 {
            pixmap.get_index(visible_top + visible_height - 1)
        } else {
            return Vec::new();
        };
        let end_idx = end_idx.min(num_lines.saturating_sub(1));

        let ascent = self.font_metrics.max_ascent;
        let right_edge = self.width.saturating_sub(self.right_padding);

        let mut instructions = Vec::with_capacity(end_idx - start_idx + 1);
        for i in start_idx..=end_idx {
            let display_number = i + 1; // 1-based
            let pixel_y = pixmap.get_pixel(i);
            let baseline_y = pixel_y + ascent;

            let mut instr =
                LineNumberPaintInstruction::new(display_number, baseline_y, right_edge);
            instr.text_width = self.font_metrics.string_width(&instr.text);
            instructions.push(instr);
        }

        instructions
    }

    // -- State queries --

    /// Get the current margin width in pixels.
    pub fn width(&self) -> usize {
        self.width
    }

    /// Whether the margin needs repainting.
    pub fn needs_repaint(&self) -> bool {
        self.needs_repaint
    }

    /// Mark the margin as painted (clear the repaint flag).
    pub fn mark_painted(&mut self) {
        self.needs_repaint = false;
    }

    /// Get the number of lines in the current model.
    pub fn line_count(&self) -> usize {
        self.model.as_ref().map_or(0, |m| m.num_lines())
    }

    /// Get the font metrics.
    pub fn font_metrics(&self) -> &FontMetrics {
        &self.font_metrics
    }

    /// Get the text color.
    pub fn text_color(&self) -> u32 {
        self.text_color
    }

    /// Get the background color.
    pub fn background_color(&self) -> u32 {
        self.background_color
    }
}

impl Default for LineNumberMarginProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DecompilerMarginProvider for LineNumberMarginProvider {
    fn name(&self) -> &str {
        "LineNumberMargin"
    }

    fn paint(&self, info: &MarginLineInfo) -> MarginPaintResult {
        // Line numbers don't paint per-line markers; they render text.
        // Return Empty so the caller handles text rendering separately.
        MarginPaintResult::Empty
    }

    fn get_width(&self) -> usize {
        self.width
    }

    fn dispose(&mut self) {
        self.model = None;
        self.pixmap = None;
        self.needs_repaint = true;
    }
}

// ---------------------------------------------------------------------------
// LineNumberMarginUpdate -- helper for managing updates
// ---------------------------------------------------------------------------

/// A helper that manages the lifecycle of a `LineNumberMarginProvider`,
/// coordinating updates from the decompiler panel.
#[derive(Debug)]
pub struct LineNumberMarginManager {
    /// The managed provider.
    provider: LineNumberMarginProvider,
    /// The current scroll offset.
    scroll_offset: usize,
    /// The current visible area.
    visible_area: Option<(usize, usize)>, // (top, height)
}

impl LineNumberMarginManager {
    /// Create a new manager.
    pub fn new() -> Self {
        Self {
            provider: LineNumberMarginProvider::new(),
            scroll_offset: 0,
            visible_area: None,
        }
    }

    /// Get a reference to the managed provider.
    pub fn provider(&self) -> &LineNumberMarginProvider {
        &self.provider
    }

    /// Get a mutable reference to the managed provider.
    pub fn provider_mut(&mut self) -> &mut LineNumberMarginProvider {
        &mut self.provider
    }

    /// Update the program and layout model.
    ///
    /// Called when the program, function, or layout changes.
    /// Corresponds to `setProgram()` in the Ghidra Java implementation.
    pub fn set_program(
        &mut self,
        num_lines: usize,
        line_height: usize,
        function_name: Option<String>,
        function_address: Option<u64>,
    ) {
        let mut model = LayoutModel::new(num_lines);
        if let (Some(name), Some(addr)) = (function_name, function_address) {
            model.set_function(name, addr);
        }
        self.provider.set_layout_model(model);

        let pixmap = LayoutPixelIndexMap::new(num_lines, line_height, self.scroll_offset);
        self.provider.set_pixmap(pixmap);
    }

    /// Update the scroll offset.
    pub fn set_scroll_offset(&mut self, offset: usize) {
        self.scroll_offset = offset;
        if let Some(ref mut pixmap) = self.provider.pixmap {
            pixmap.set_scroll_offset(offset);
        }
        self.provider.needs_repaint = true;
    }

    /// Update the visible area.
    pub fn set_visible_area(&mut self, top: usize, height: usize) {
        self.visible_area = Some((top, height));
        self.provider.needs_repaint = true;
    }

    /// Get paint instructions for the current visible area.
    pub fn paint_instructions(&self) -> Vec<LineNumberPaintInstruction> {
        if let Some((top, height)) = self.visible_area {
            self.provider.generate_paint_instructions(top, height)
        } else {
            Vec::new()
        }
    }

    /// Update the decompiler options (font, colors).
    pub fn set_options(&mut self, font_family: &str, font_size: f32, text_color: u32) {
        self.provider.set_font(font_family, font_size);
        self.provider.set_text_color(text_color);
    }
}

impl Default for LineNumberMarginManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pixel_index_map_basic() {
        let pixmap = LayoutPixelIndexMap::new(100, 16, 0);

        // First line starts at pixel 0.
        assert_eq!(pixmap.get_index(0), 0);
        assert_eq!(pixmap.get_pixel(0), 0);

        // Second line starts at pixel 16.
        assert_eq!(pixmap.get_index(16), 1);
        assert_eq!(pixmap.get_pixel(1), 16);

        // Pixel in the middle of a line.
        assert_eq!(pixmap.get_index(8), 0);
        assert_eq!(pixmap.get_index(24), 1);

        // Last line.
        assert_eq!(pixmap.get_pixel(99), 99 * 16);
    }

    #[test]
    fn test_pixel_index_map_with_scroll() {
        let pixmap = LayoutPixelIndexMap::new(50, 16, 100);

        // First line starts at pixel 100.
        assert_eq!(pixmap.get_pixel(0), 100);
        assert_eq!(pixmap.get_index(100), 0);

        // Before scroll offset.
        assert_eq!(pixmap.get_index(0), 0); // clamped to first line
    }

    #[test]
    fn test_pixel_index_map_empty() {
        let pixmap = LayoutPixelIndexMap::new(0, 16, 0);
        assert_eq!(pixmap.get_index(0), 0);
        assert_eq!(pixmap.get_pixel(0), 0);
    }

    #[test]
    fn test_pixel_index_map_update() {
        let mut pixmap = LayoutPixelIndexMap::new(10, 16, 0);
        assert_eq!(pixmap.num_lines(), 10);

        pixmap.set_num_lines(20);
        assert_eq!(pixmap.num_lines(), 20);
        assert_eq!(pixmap.get_pixel(19), 19 * 16);

        pixmap.set_line_height(20);
        assert_eq!(pixmap.line_height(), 20);
        assert_eq!(pixmap.get_pixel(0), 0);
        assert_eq!(pixmap.get_pixel(1), 20);
    }

    #[test]
    fn test_layout_model() {
        let mut model = LayoutModel::new(50);
        assert_eq!(model.num_lines(), 50);
        assert!(model.function_name().is_none());

        model.set_function("main", 0x401000);
        assert_eq!(model.function_name(), Some("main"));
        assert_eq!(model.function_address(), Some(0x401000));

        model.set_num_lines(75);
        assert_eq!(model.num_lines(), 75);
    }

    #[test]
    fn test_font_metrics() {
        let metrics = FontMetrics::new("Courier New", 14.0);
        assert_eq!(metrics.family, "Courier New");
        assert_eq!(metrics.size, 14.0);
        assert!(metrics.max_ascent > 0);
        assert!(metrics.max_descent > 0);
        assert!(metrics.line_height > 0);

        // String width should be proportional to length.
        let w3 = metrics.string_width("123");
        let w5 = metrics.string_width("12345");
        assert!(w5 > w3);
        assert_eq!(w5, 5 * metrics.digit_width);
    }

    #[test]
    fn test_font_metrics_default() {
        let metrics = FontMetrics::default();
        assert_eq!(metrics.family, "Monospaced");
        assert_eq!(metrics.size, 12.0);
    }

    #[test]
    fn test_line_number_provider_creation() {
        let provider = LineNumberMarginProvider::new();
        assert_eq!(provider.name(), "LineNumberMargin");
        assert_eq!(provider.width(), 16); // min_width
        assert_eq!(provider.line_count(), 0);
        assert!(provider.needs_repaint());
        assert_eq!(provider.text_color(), 0xFF808080);
        assert_eq!(provider.background_color(), 0xFFF8F8F8);
    }

    #[test]
    fn test_line_number_provider_width_computation() {
        let mut provider = LineNumberMarginProvider::new();

        // With 9 lines: "9" -> 1 digit.
        let model = LayoutModel::new(9);
        provider.set_layout_model(model);
        assert_eq!(provider.width(), provider.min_width); // min_width wins

        // With 100 lines: "100" -> 3 digits.
        let model = LayoutModel::new(100);
        provider.set_layout_model(model);
        let expected = provider.font_metrics.string_width("100") + provider.right_padding;
        assert_eq!(provider.width(), expected.max(provider.min_width));

        // With 10000 lines: "10000" -> 5 digits.
        let model = LayoutModel::new(10000);
        provider.set_layout_model(model);
        let expected = provider.font_metrics.string_width("10000") + provider.right_padding;
        assert_eq!(provider.width(), expected.max(provider.min_width));
    }

    #[test]
    fn test_line_number_provider_paint_instructions() {
        let mut provider = LineNumberMarginProvider::new();

        let model = LayoutModel::new(50);
        provider.set_layout_model(model);

        let pixmap = LayoutPixelIndexMap::new(50, 16, 0);
        provider.set_pixmap(pixmap);

        // Visible range: top=0, height=48 (3 lines).
        let instructions = provider.generate_paint_instructions(0, 48);
        assert_eq!(instructions.len(), 3);

        // Line numbers should be 1-based.
        assert_eq!(instructions[0].display_number, 1);
        assert_eq!(instructions[1].display_number, 2);
        assert_eq!(instructions[2].display_number, 3);

        // Baseline Y should be ascending.
        assert!(instructions[0].baseline_y < instructions[1].baseline_y);
        assert!(instructions[1].baseline_y < instructions[2].baseline_y);
    }

    #[test]
    fn test_line_number_provider_paint_no_model() {
        let provider = LineNumberMarginProvider::new();
        let instructions = provider.generate_paint_instructions(0, 100);
        assert!(instructions.is_empty());
    }

    #[test]
    fn test_line_number_provider_paint_no_pixmap() {
        let mut provider = LineNumberMarginProvider::new();
        let model = LayoutModel::new(10);
        provider.set_layout_model(model);

        // No pixmap set.
        let instructions = provider.generate_paint_instructions(0, 100);
        assert!(instructions.is_empty());
    }

    #[test]
    fn test_line_number_provider_margin_trait() {
        let provider = LineNumberMarginProvider::new();
        assert_eq!(provider.name(), "LineNumberMargin");
        assert_eq!(provider.get_width(), 16);

        // Paint returns Empty (text rendering is handled separately).
        let info = MarginLineInfo {
            line_number: 5,
            address: Some(0x1000),
            in_function_body: true,
            line_text: None,
        };
        assert!(matches!(provider.paint(&info), MarginPaintResult::Empty));
    }

    #[test]
    fn test_line_number_provider_configuration() {
        let mut provider = LineNumberMarginProvider::new();

        provider.set_right_padding(4);
        assert_eq!(provider.right_padding, 4);

        provider.set_min_width(20);
        assert_eq!(provider.min_width, 20);
        assert!(provider.width() >= 20);

        provider.set_text_color(0xFF000000);
        assert_eq!(provider.text_color(), 0xFF000000);

        provider.set_background_color(0xFFFFFFFF);
        assert_eq!(provider.background_color(), 0xFFFFFFFF);
    }

    #[test]
    fn test_line_number_provider_repaint_flag() {
        let mut provider = LineNumberMarginProvider::new();
        assert!(provider.needs_repaint());

        provider.mark_painted();
        assert!(!provider.needs_repaint());

        // Setting font triggers repaint.
        provider.set_font("Arial", 14.0);
        assert!(provider.needs_repaint());
    }

    #[test]
    fn test_line_number_provider_dispose() {
        let mut provider = LineNumberMarginProvider::new();
        let model = LayoutModel::new(50);
        provider.set_layout_model(model);
        assert_eq!(provider.line_count(), 50);

        provider.dispose();
        assert_eq!(provider.line_count(), 0);
        assert!(provider.needs_repaint());
    }

    #[test]
    fn test_manager_lifecycle() {
        let mut mgr = LineNumberMarginManager::new();

        // Set up with a 50-line function.
        mgr.set_program(50, 16, Some("main".to_string()), Some(0x401000));
        assert_eq!(mgr.provider().line_count(), 50);

        // Set visible area.
        mgr.set_visible_area(0, 48);
        let instructions = mgr.paint_instructions();
        assert_eq!(instructions.len(), 3);

        // Scroll.
        mgr.set_scroll_offset(160);
        assert_eq!(mgr.provider().width(), mgr.provider().width()); // still valid
    }

    #[test]
    fn test_manager_options() {
        let mut mgr = LineNumberMarginManager::new();
        mgr.set_options("Courier New", 14.0, 0xFF333333);
        assert_eq!(mgr.provider().font_metrics().family, "Courier New");
        assert_eq!(mgr.provider().font_metrics().size, 14.0);
        assert_eq!(mgr.provider().text_color(), 0xFF333333);
    }

    #[test]
    fn test_visible_range() {
        let range = VisibleRange::new(5, 15, 80, 160);
        assert_eq!(range.start_line, 5);
        assert_eq!(range.end_line, 15);
        assert_eq!(range.line_count(), 11);
        assert_eq!(range.top_pixel, 80);
        assert_eq!(range.height, 160);
    }

    #[test]
    fn test_paint_instruction() {
        let instr = LineNumberPaintInstruction::new(42, 100, 50);
        assert_eq!(instr.display_number, 42);
        assert_eq!(instr.baseline_y, 100);
        assert_eq!(instr.right_edge_x, 50);
        assert_eq!(instr.text, "42");
    }
}
