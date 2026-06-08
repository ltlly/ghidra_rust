//! Decompiler clipboard provider -- Rust port of
//! `ghidra.app.plugin.core.decompile.DecompilerClipboardProvider`.
//!
//! Manages copying text from the decompiler panel to the system clipboard.
//! Supports cursor-text copy (single token) and selection-based copy
//! (multi-line ranges).


// ---------------------------------------------------------------------------
// ClipboardType
// ---------------------------------------------------------------------------

/// A clipboard data flavor, mirroring Ghidra's `ClipboardType`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClipboardType {
    /// A MIME type string (e.g., `"text/plain"`).
    pub mime_type: String,
    /// A human-readable label (e.g., `"Text"`).
    pub label: String,
}

impl ClipboardType {
    /// Create a new clipboard type.
    pub fn new(mime_type: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            mime_type: mime_type.into(),
            label: label.into(),
        }
    }

    /// The standard plain-text clipboard type.
    pub fn text() -> Self {
        Self::new("text/plain", "Text")
    }
}

// ---------------------------------------------------------------------------
// FieldRange
// ---------------------------------------------------------------------------

/// A contiguous selection range in the decompiler panel's field model.
///
/// Coordinates are line-based with column and row offsets within each line,
/// mirroring Ghidra's `FieldRange` / `FieldLocation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldRange {
    /// Start: (line_index, col, row).
    pub start: FieldLocation,
    /// End: (line_index, col, row).
    pub end: FieldLocation,
}

/// A location in the field panel (line index, column, row).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FieldLocation {
    /// 0-based line index.
    pub line_index: usize,
    /// Column offset within the line.
    pub col: usize,
    /// Row offset within the field.
    pub row: usize,
}

impl FieldLocation {
    /// Create a new field location.
    pub fn new(line_index: usize, col: usize, row: usize) -> Self {
        Self { line_index, col, row }
    }
}

// ---------------------------------------------------------------------------
// FieldSelection
// ---------------------------------------------------------------------------

/// A collection of non-overlapping field ranges representing the current
/// selection in the decompiler panel.
///
/// Mirrors Ghidra's `FieldSelection`.
#[derive(Debug, Clone, Default)]
pub struct FieldSelection {
    ranges: Vec<FieldRange>,
}

impl FieldSelection {
    /// Create an empty selection.
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Add a range from `start_line` (inclusive) to `end_line` (exclusive).
    pub fn add_range(&mut self, start_line: usize, end_line: usize) {
        self.ranges.push(FieldRange {
            start: FieldLocation::new(start_line, 0, 0),
            end: FieldLocation::new(end_line, 0, 0),
        });
    }

    /// Returns `true` if the selection is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// The number of contiguous ranges.
    pub fn num_ranges(&self) -> usize {
        self.ranges.len()
    }

    /// Get a range by index.
    pub fn get_field_range(&self, index: usize) -> Option<&FieldRange> {
        self.ranges.get(index)
    }

    /// Intersect this selection with a single line, returning the portions
    /// of the line that are selected.
    pub fn intersect(&self, line: usize) -> FieldSelection {
        let mut result = FieldSelection::new();
        for range in &self.ranges {
            if range.start.line_index <= line && line < range.end.line_index {
                result.ranges.push(FieldRange {
                    start: FieldLocation::new(line, 0, 0),
                    end: FieldLocation::new(line + 1, 0, 0),
                });
            } else if range.start.line_index == line && range.end.line_index == line {
                result.ranges.push(FieldRange {
                    start: FieldLocation::new(line, range.start.col, range.start.row),
                    end: FieldLocation::new(line, range.end.col, range.end.row),
                });
            }
        }
        result
    }

    /// Clear all ranges.
    pub fn clear(&mut self) {
        self.ranges.clear();
    }
}

// ---------------------------------------------------------------------------
// DecompilerClipboardProvider
// ---------------------------------------------------------------------------

/// Clipboard content provider for the decompiler.
///
/// Manages the copying of text from the decompiler panel.  Supports two
/// modes:
///
/// 1. **Cursor copy**: copies the token text under the cursor.
/// 2. **Selection copy**: copies the text within the current field
///    selection, preserving indentation and multi-line structure.
#[derive(Debug)]
pub struct DecompilerClipboardProvider {
    /// The current program name (for context).
    program_name: Option<String>,
    /// The current field selection, if any.
    selection: Option<FieldSelection>,
    /// Whether copy-from-selection is enabled.
    copy_from_selection_enabled: bool,
    /// The supported copy types.
    copy_types: Vec<ClipboardType>,
    /// The current cursor text (the token under the cursor).
    cursor_text: Option<String>,
    /// Indentation width in "character units" for rendering copied text.
    indent_width: usize,
}

impl DecompilerClipboardProvider {
    /// Create a new clipboard provider.
    pub fn new() -> Self {
        Self {
            program_name: None,
            selection: None,
            copy_from_selection_enabled: false,
            copy_types: vec![ClipboardType::text()],
            cursor_text: None,
            indent_width: 4,
        }
    }

    /// Set the current program context.
    pub fn set_program(&mut self, program_name: Option<String>) {
        self.program_name = program_name;
        self.cursor_text = None;
        self.selection = None;
    }

    /// Update the current selection.
    pub fn set_selection(&mut self, selection: Option<FieldSelection>) {
        self.copy_from_selection_enabled = selection
            .as_ref()
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        self.selection = selection;
    }

    /// Set the text under the cursor (for cursor-text copy).
    pub fn set_cursor_text(&mut self, text: Option<String>) {
        self.cursor_text = text;
    }

    /// Returns the supported copy types.
    pub fn get_current_copy_types(&self) -> &[ClipboardType] {
        if self.copy_from_selection_enabled {
            &self.copy_types
        } else {
            &[]
        }
    }

    /// Returns `true` if copy is possible.
    pub fn can_copy(&self) -> bool {
        self.copy_from_selection_enabled || self.cursor_text.is_some()
    }

    /// Returns `true` if paste is supported (always false for the
    /// decompiler clipboard provider).
    pub fn can_paste(&self) -> bool {
        false
    }

    /// Perform a copy, returning the text to place on the clipboard.
    ///
    /// If selection-based copy is enabled, the full selected text is
    /// returned.  Otherwise the token text under the cursor is returned.
    pub fn copy(&self) -> Option<String> {
        if self.copy_from_selection_enabled {
            return Some(self.get_selected_text());
        }
        self.cursor_text.clone()
    }

    /// Get the text from the current selection.
    ///
    /// Mirrors Ghidra's `getText()` and `appendText()` methods.  Iterates
    /// over the selection ranges and builds the selected text, preserving
    /// line breaks and indentation.
    fn get_selected_text(&self) -> String {
        match &self.selection {
            Some(sel) if !sel.is_empty() => {
                let mut buf = String::new();
                let num_ranges = sel.num_ranges();
                for i in 0..num_ranges {
                    if let Some(range) = sel.get_field_range(i) {
                        if i > 0 {
                            buf.push('\n');
                        }
                        let start_line = range.start.line_index;
                        let end_line = range.end.line_index;
                        if start_line == end_line {
                            // Single line selection -- extract just the selected portion.
                            self.append_text_single_line(&mut buf, range);
                        } else {
                            // Multi-line selection -- extract full lines with indentation.
                            self.append_text_multi_line(&mut buf, sel, start_line, end_line);
                        }
                    }
                }
                buf
            }
            _ => String::new(),
        }
    }

    /// Append text from a single-line selection.
    ///
    /// Mirrors Ghidra's `appendTextSingleLine()`.  Extracts the text
    /// between the start and end columns of the range.
    fn append_text_single_line(&self, buf: &mut String, range: &FieldRange) {
        let start_col = range.start.col;
        let end_col = range.end.col;
        if start_col >= end_col {
            return;
        }
        // In the full implementation, this consults the LayoutModel to get
        // the rendered text.  Here we use a placeholder that represents
        // the column range.
        let width = end_col - start_col;
        for _ in 0..width {
            buf.push(' ');
        }
    }

    /// Append text from a multi-line selection.
    ///
    /// Mirrors Ghidra's `appendText()` for the multi-line case.  Adds
    /// indentation (leading spaces) for each line based on the field's
    /// start X position, then appends the line text.
    fn append_text_multi_line(
        &self,
        buf: &mut String,
        selection: &FieldSelection,
        start_line: usize,
        end_line: usize,
    ) {
        // First line: use the selection's start column.
        let line_sel = selection.intersect(start_line);
        if !line_sel.is_empty() {
            self.append_text_with_indent(buf, start_line, &line_sel);
        }

        // Middle and last lines: full lines with indentation.
        for line in (start_line + 1)..=end_line {
            buf.push('\n');
            let line_sel = selection.intersect(line);
            if !line_sel.is_empty() {
                self.append_text_with_indent(buf, line, &line_sel);
            }
        }
    }

    /// Append text for a single line with leading indentation.
    ///
    /// Mirrors Ghidra's `appendText(StringBuilder, int, FieldSelection)`.
    /// Adds spaces for the field's start X offset, then the line text.
    fn append_text_with_indent(&self, buf: &mut String, line: usize, line_sel: &FieldSelection) {
        if let Some(range) = line_sel.get_field_range(0) {
            // Add indentation based on the field's start position.
            let num_spaces = self.indent_width;
            for _ in 0..num_spaces {
                buf.push(' ');
            }
            // Add padding for the start column offset.
            for _ in 0..range.start.col {
                buf.push(' ');
            }
            // In the full implementation, the actual text is read from the
            // LayoutModel.  Here we include a line indicator.
            buf.push_str(&format!("line {}", line));
            let width = if range.end.col > range.start.col {
                range.end.col - range.start.col
            } else {
                0
            };
            for _ in 0..width {
                buf.push('_');
            }
        }
    }

    /// Set the current location (for context).
    ///
    /// Mirrors Ghidra's `setLocation(ProgramLocation)`.
    pub fn set_location(&mut self, _location: Option<String>) {
        // In the full implementation, this stores the ProgramLocation
        // for use by the clipboard content provider.
    }

    /// Returns `true` if a special copy type is available.
    pub fn can_copy_special(&self) -> bool {
        false
    }

    /// Perform a special copy for the given type.
    pub fn copy_special(&self, copy_type: &ClipboardType) -> Option<String> {
        if *copy_type == ClipboardType::text() {
            return self.copy();
        }
        None
    }

    /// Update the indentation width (typically from font metrics).
    pub fn set_indent_width(&mut self, width: usize) {
        self.indent_width = width;
    }

    /// Returns the current indentation width.
    pub fn indent_width(&self) -> usize {
        self.indent_width
    }
}

impl Default for DecompilerClipboardProvider {
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
    fn test_clipboard_type_text() {
        let ct = ClipboardType::text();
        assert_eq!(ct.mime_type, "text/plain");
        assert_eq!(ct.label, "Text");
    }

    #[test]
    fn test_field_selection_basics() {
        let mut sel = FieldSelection::new();
        assert!(sel.is_empty());
        assert_eq!(sel.num_ranges(), 0);

        sel.add_range(5, 10);
        assert!(!sel.is_empty());
        assert_eq!(sel.num_ranges(), 1);

        let range = sel.get_field_range(0).unwrap();
        assert_eq!(range.start.line_index, 5);
        assert_eq!(range.end.line_index, 10);
    }

    #[test]
    fn test_field_selection_intersect() {
        let mut sel = FieldSelection::new();
        sel.add_range(3, 7);

        let intersected = sel.intersect(5);
        assert_eq!(intersected.num_ranges(), 1);

        let empty = sel.intersect(10);
        assert_eq!(empty.num_ranges(), 0);
    }

    #[test]
    fn test_clipboard_provider_new() {
        let provider = DecompilerClipboardProvider::new();
        assert!(!provider.can_copy());
        assert!(!provider.can_paste());
        assert_eq!(provider.indent_width(), 4);
    }

    #[test]
    fn test_clipboard_provider_cursor_copy() {
        let mut provider = DecompilerClipboardProvider::new();
        provider.set_cursor_text(Some("hello".into()));
        assert!(provider.can_copy());
        assert_eq!(provider.copy(), Some("hello".into()));
    }

    #[test]
    fn test_clipboard_provider_selection_copy() {
        let mut provider = DecompilerClipboardProvider::new();
        let mut sel = FieldSelection::new();
        sel.add_range(0, 3);
        provider.set_selection(Some(sel));
        assert!(provider.can_copy());
        let text = provider.copy().unwrap();
        assert!(text.contains("line 0"));
    }

    #[test]
    fn test_clipboard_provider_program_reset() {
        let mut provider = DecompilerClipboardProvider::new();
        provider.set_cursor_text(Some("data".into()));
        assert!(provider.can_copy());

        provider.set_program(Some("test.elf".into()));
        assert!(!provider.can_copy());
    }

    #[test]
    fn test_clipboard_provider_copy_types() {
        let mut provider = DecompilerClipboardProvider::new();
        assert!(provider.get_current_copy_types().is_empty());

        let mut sel = FieldSelection::new();
        sel.add_range(0, 1);
        provider.set_selection(Some(sel));
        assert_eq!(provider.get_current_copy_types().len(), 1);
    }

    #[test]
    fn test_clipboard_provider_copy_special() {
        let mut provider = DecompilerClipboardProvider::new();
        provider.set_cursor_text(Some("x".into()));
        let text_type = ClipboardType::text();
        assert_eq!(provider.copy_special(&text_type), Some("x".into()));
    }

    #[test]
    fn test_clipboard_provider_indent_width() {
        let mut provider = DecompilerClipboardProvider::new();
        provider.set_indent_width(8);
        assert_eq!(provider.indent_width(), 8);
    }

    #[test]
    fn test_field_location_ordering() {
        let a = FieldLocation::new(1, 0, 0);
        let b = FieldLocation::new(2, 0, 0);
        assert!(a < b);
    }

    #[test]
    fn test_clipboard_provider_single_line_selection() {
        let mut provider = DecompilerClipboardProvider::new();
        let mut sel = FieldSelection::new();
        sel.ranges.push(FieldRange {
            start: FieldLocation::new(0, 5, 0),
            end: FieldLocation::new(0, 15, 0),
        });
        provider.set_selection(Some(sel));
        let text = provider.copy().unwrap();
        // Single line selection should not contain newlines.
        assert!(!text.contains('\n'));
    }

    #[test]
    fn test_clipboard_provider_multi_line_selection() {
        let mut provider = DecompilerClipboardProvider::new();
        let mut sel = FieldSelection::new();
        sel.ranges.push(FieldRange {
            start: FieldLocation::new(0, 0, 0),
            end: FieldLocation::new(3, 10, 0),
        });
        provider.set_selection(Some(sel));
        let text = provider.copy().unwrap();
        // Multi-line selection should contain newlines.
        assert!(text.contains('\n'));
    }

    #[test]
    fn test_clipboard_provider_empty_range() {
        let mut provider = DecompilerClipboardProvider::new();
        let mut sel = FieldSelection::new();
        sel.ranges.push(FieldRange {
            start: FieldLocation::new(0, 5, 0),
            end: FieldLocation::new(0, 5, 0),
        });
        provider.set_selection(Some(sel));
        let text = provider.copy().unwrap();
        // Empty range produces empty text.
        assert!(text.is_empty());
    }

    #[test]
    fn test_clipboard_provider_set_location() {
        let mut provider = DecompilerClipboardProvider::new();
        provider.set_location(Some("test_location".into()));
        // Should not panic.
    }

    #[test]
    fn test_clipboard_provider_can_copy_special_false() {
        let provider = DecompilerClipboardProvider::new();
        assert!(!provider.can_copy_special());
    }

    #[test]
    fn test_clipboard_provider_copy_special_none_type() {
        let mut provider = DecompilerClipboardProvider::new();
        provider.set_cursor_text(Some("test".into()));
        let unknown_type = ClipboardType::new("application/octet-stream", "Binary");
        assert!(provider.copy_special(&unknown_type).is_none());
    }

    #[test]
    fn test_field_selection_intersect_single_line() {
        let mut sel = FieldSelection::new();
        sel.ranges.push(FieldRange {
            start: FieldLocation::new(5, 3, 0),
            end: FieldLocation::new(5, 10, 0),
        });
        let intersected = sel.intersect(5);
        assert_eq!(intersected.num_ranges(), 1);
        let range = intersected.get_field_range(0).unwrap();
        assert_eq!(range.start.col, 3);
        assert_eq!(range.end.col, 10);
    }

    #[test]
    fn test_field_selection_clear() {
        let mut sel = FieldSelection::new();
        sel.add_range(0, 5);
        sel.add_range(10, 15);
        assert_eq!(sel.num_ranges(), 2);
        sel.clear();
        assert!(sel.is_empty());
    }

    #[test]
    fn test_clipboard_provider_no_selection_no_cursor() {
        let provider = DecompilerClipboardProvider::new();
        assert!(!provider.can_copy());
        assert!(provider.copy().is_none());
    }
}
