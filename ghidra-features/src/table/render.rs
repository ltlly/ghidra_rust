//! Cell renderers for table display.
//!
//! Ported from `ghidra.util.table`:
//! - `GhidraTableCellRenderer` -- base renderer for Ghidra tables.
//! - `CodeUnitTableCellRenderer` -- renders code unit cells with
//!   multi-line listing support.
//! - `CompositeGhidraTableCellRenderer` -- composites multiple renderers.
//! - `PreviewDataTableCellRenderer` -- renders preview data cells.

/// Rendering style for table cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderStyle {
    /// Plain text rendering.
    Plain,
    /// Monospaced font for hex bytes.
    Monospaced,
    /// Colored by address space.
    AddressColored,
    /// Fixed-width with syntax-style formatting.
    Syntax,
}

/// Alignment within a table cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellAlignment {
    /// Left-aligned.
    Left,
    /// Center-aligned.
    Center,
    /// Right-aligned.
    Right,
}

// ---------------------------------------------------------------------------
// GhidraTableCellRenderer
// ---------------------------------------------------------------------------

/// Base cell renderer for Ghidra tables.
///
/// Ported from `ghidra.util.table.GhidraTableCellRenderer`.  Provides
/// configurable rendering style, alignment, and filter string extraction.
#[derive(Debug, Clone)]
pub struct GhidraTableCellRenderer {
    style: RenderStyle,
    alignment: CellAlignment,
    fixed_width_font: bool,
}

impl Default for GhidraTableCellRenderer {
    fn default() -> Self {
        Self {
            style: RenderStyle::Plain,
            alignment: CellAlignment::Left,
            fixed_width_font: false,
        }
    }
}

impl GhidraTableCellRenderer {
    /// Creates a new renderer with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the rendering style.
    pub fn with_style(mut self, style: RenderStyle) -> Self {
        self.style = style;
        self
    }

    /// Sets the cell alignment.
    pub fn with_alignment(mut self, alignment: CellAlignment) -> Self {
        self.alignment = alignment;
        self
    }

    /// Enables or disables fixed-width font rendering.
    pub fn with_fixed_width_font(mut self, fixed: bool) -> Self {
        self.fixed_width_font = fixed;
        self
    }

    /// Returns the rendering style.
    pub fn style(&self) -> RenderStyle {
        self.style
    }

    /// Returns whether fixed-width font is enabled.
    pub fn is_fixed_width_font(&self) -> bool {
        self.fixed_width_font
    }

    /// Returns the cell alignment.
    pub fn alignment(&self) -> CellAlignment {
        self.alignment
    }

    /// Extracts the filter string from a cell value.
    ///
    /// This is used for text-based filtering of table rows.
    pub fn get_filter_string(&self, value: &str) -> String {
        value.to_string()
    }
}

// ---------------------------------------------------------------------------
// CodeUnitTableCellRenderer
// ---------------------------------------------------------------------------

/// Renders code unit cells with multi-line listing support.
///
/// Ported from `ghidra.util.table.CodeUnitTableCellRenderer`.
#[derive(Debug, Clone)]
pub struct CodeUnitTableCellRenderer {
    base: GhidraTableCellRenderer,
}

impl Default for CodeUnitTableCellRenderer {
    fn default() -> Self {
        Self {
            base: GhidraTableCellRenderer::new()
                .with_style(RenderStyle::Syntax)
                .with_fixed_width_font(true),
        }
    }
}

impl CodeUnitTableCellRenderer {
    /// Creates a new code unit cell renderer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the base renderer.
    pub fn base(&self) -> &GhidraTableCellRenderer {
        &self.base
    }

    /// Format a code unit value for display.
    pub fn format_value(&self, text: &str, line_count: usize) -> String {
        if line_count <= 1 {
            text.to_string()
        } else {
            let lines: Vec<&str> = text.lines().take(line_count).collect();
            lines.join("\n")
        }
    }
}

// ---------------------------------------------------------------------------
// CompositeGhidraTableCellRenderer
// ---------------------------------------------------------------------------

/// Composites multiple cell renderers, selecting based on value type.
///
/// Ported from `ghidra.util.table.CompositeGhidraTableCellRenderer`.
#[derive(Debug, Clone)]
pub struct CompositeGhidraTableCellRenderer {
    renderers: Vec<GhidraTableCellRenderer>,
    default_renderer: GhidraTableCellRenderer,
}

impl CompositeGhidraTableCellRenderer {
    /// Creates a new composite renderer.
    pub fn new() -> Self {
        Self {
            renderers: Vec::new(),
            default_renderer: GhidraTableCellRenderer::default(),
        }
    }

    /// Adds a renderer to the composite.
    pub fn add_renderer(&mut self, renderer: GhidraTableCellRenderer) {
        self.renderers.push(renderer);
    }

    /// Returns the number of renderers in the composite.
    pub fn renderer_count(&self) -> usize {
        self.renderers.len()
    }

    /// Returns the default renderer.
    pub fn default_renderer(&self) -> &GhidraTableCellRenderer {
        &self.default_renderer
    }
}

impl Default for CompositeGhidraTableCellRenderer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PreviewDataTableCellRenderer
// ---------------------------------------------------------------------------

/// Renders preview data cells with multi-line support.
///
/// Ported from `ghidra.util.table.PreviewDataTableCellRenderer`.
#[derive(Debug, Clone)]
pub struct PreviewDataTableCellRenderer {
    base: GhidraTableCellRenderer,
    max_lines: usize,
}

impl Default for PreviewDataTableCellRenderer {
    fn default() -> Self {
        Self {
            base: GhidraTableCellRenderer::new().with_style(RenderStyle::Syntax),
            max_lines: 10,
        }
    }
}

impl PreviewDataTableCellRenderer {
    /// Creates a new preview data cell renderer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum number of lines to render.
    pub fn with_max_lines(mut self, max: usize) -> Self {
        self.max_lines = max;
        self
    }

    /// Returns the maximum number of lines.
    pub fn max_lines(&self) -> usize {
        self.max_lines
    }

    /// Format preview text, truncating to max lines.
    pub fn format_preview(&self, text: &str) -> String {
        let lines: Vec<&str> = text.lines().take(self.max_lines).collect();
        let result = lines.join("\n");
        if text.lines().count() > self.max_lines {
            format!("{}...", result)
        } else {
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ghidra_cell_renderer_default() {
        let r = GhidraTableCellRenderer::new();
        assert_eq!(r.style(), RenderStyle::Plain);
        assert_eq!(r.alignment(), CellAlignment::Left);
        assert!(!r.is_fixed_width_font());
    }

    #[test]
    fn test_ghidra_cell_renderer_builder() {
        let r = GhidraTableCellRenderer::new()
            .with_style(RenderStyle::Monospaced)
            .with_alignment(CellAlignment::Right)
            .with_fixed_width_font(true);
        assert_eq!(r.style(), RenderStyle::Monospaced);
        assert_eq!(r.alignment(), CellAlignment::Right);
        assert!(r.is_fixed_width_font());
    }

    #[test]
    fn test_ghidra_cell_renderer_filter() {
        let r = GhidraTableCellRenderer::new();
        assert_eq!(r.get_filter_string("hello"), "hello");
    }

    #[test]
    fn test_code_unit_renderer_format() {
        let r = CodeUnitTableCellRenderer::new();
        assert_eq!(r.format_value("MOV EAX, 1", 1), "MOV EAX, 1");
        assert_eq!(r.format_value("line1\nline2\nline3", 2), "line1\nline2");
    }

    #[test]
    fn test_code_unit_renderer_style() {
        let r = CodeUnitTableCellRenderer::new();
        assert_eq!(r.base().style(), RenderStyle::Syntax);
        assert!(r.base().is_fixed_width_font());
    }

    #[test]
    fn test_composite_renderer() {
        let mut c = CompositeGhidraTableCellRenderer::new();
        assert_eq!(c.renderer_count(), 0);
        c.add_renderer(GhidraTableCellRenderer::new());
        c.add_renderer(GhidraTableCellRenderer::new().with_style(RenderStyle::Monospaced));
        assert_eq!(c.renderer_count(), 2);
    }

    #[test]
    fn test_preview_renderer_default() {
        let r = PreviewDataTableCellRenderer::new();
        assert_eq!(r.max_lines(), 10);
    }

    #[test]
    fn test_preview_renderer_truncate() {
        let r = PreviewDataTableCellRenderer::new().with_max_lines(2);
        let text = "line1\nline2\nline3\nline4";
        assert_eq!(r.format_preview(text), "line1\nline2...");
    }

    #[test]
    fn test_preview_renderer_no_truncate() {
        let r = PreviewDataTableCellRenderer::new().with_max_lines(5);
        let text = "line1\nline2";
        assert_eq!(r.format_preview(text), "line1\nline2");
    }

    #[test]
    fn test_preview_renderer_single_line() {
        let r = PreviewDataTableCellRenderer::new();
        assert_eq!(r.format_preview("hello"), "hello");
    }
}
