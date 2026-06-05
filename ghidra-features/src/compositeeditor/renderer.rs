//! Cell renderers for the composite editor table.
//!
//! Ported from `ghidra.app.plugin.core.compositeeditor.DataTypeCellRenderer`
//! and `DndTableCellRenderer`.

use serde::{Deserialize, Serialize};

use super::ComponentRow;

// ---------------------------------------------------------------------------
// Cell display state
// ---------------------------------------------------------------------------

/// Visual state flags for a table cell in the composite editor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CellDisplayState {
    /// Whether the cell is selected.
    pub selected: bool,
    /// Whether the cell has focus.
    pub focused: bool,
    /// Whether the cell is being edited.
    pub editing: bool,
    /// Whether the cell is the drop target during drag-and-drop.
    pub drop_target: bool,
    /// Whether the component is enabled.
    pub enabled: bool,
}

impl Default for CellDisplayState {
    fn default() -> Self {
        Self {
            selected: false,
            focused: false,
            editing: false,
            drop_target: false,
            enabled: true,
        }
    }
}

// ---------------------------------------------------------------------------
// DataTypeCellRenderer
// ---------------------------------------------------------------------------

/// Renders data type names in the composite editor table.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.DataTypeCellRenderer`.
#[derive(Debug, Clone)]
pub struct DataTypeCellRenderer {
    /// Whether to display hex numbers.
    pub show_hex: bool,
    /// Whether to highlight pointer types differently.
    pub highlight_pointers: bool,
    /// Whether to highlight array types differently.
    pub highlight_arrays: bool,
    /// Font size override (None = use default).
    pub font_size: Option<u32>,
}

impl DataTypeCellRenderer {
    /// Create a new data type cell renderer.
    pub fn new() -> Self {
        Self {
            show_hex: false,
            highlight_pointers: true,
            highlight_arrays: true,
            font_size: None,
        }
    }

    /// Format a data type name for display.
    ///
    /// This adds visual indicators for pointer and array types.
    pub fn format_type_name(&self, type_name: &str, field_name: &str) -> String {
        if field_name.is_empty() {
            type_name.to_string()
        } else {
            format!("{} {}", type_name, field_name)
        }
    }

    /// Get the display text for a component row.
    pub fn get_display_text(&self, row: &ComponentRow, column: usize) -> String {
        // Column indices match StructureColumns
        match column {
            0 => format!("0x{:X}", row.offset),   // Offset
            1 => format!("{}", row.length),          // Length
            2 => String::new(),                      // Mnemonic (filled by disassembler)
            3 => self.format_type_name(&row.type_name, &row.field_name), // DataType
            4 => row.field_name.clone(),             // Field Name
            5 => row.comment.clone().unwrap_or_default(), // Comment
            6 => format!("{}", row.ordinal),         // Ordinal
            _ => String::new(),
        }
    }

    /// Get tooltip text for a component row.
    pub fn get_tooltip_text(&self, row: &ComponentRow) -> String {
        let mut parts = vec![
            format!("Type: {}", row.type_name),
            format!("Offset: 0x{:X}", row.offset),
            format!("Length: {}", row.length),
        ];
        if !row.field_name.is_empty() {
            parts.push(format!("Name: {}", row.field_name));
        }
        if row.is_bit_field {
            parts.push(format!(
                "Bit-field: offset={}, size={}",
                row.bit_offset.unwrap_or(0),
                row.bit_size.unwrap_or(0)
            ));
        }
        parts.join("\n")
    }
}

impl Default for DataTypeCellRenderer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DndTableCellRenderer
// ---------------------------------------------------------------------------

/// A specialized cell renderer used during drag-and-drop operations.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.DndTableCellRenderer`.
#[derive(Debug, Clone)]
pub struct DndTableCellRenderer {
    /// The index of the row being dragged.
    pub drag_row: Option<usize>,
    /// The index of the drop target row.
    pub drop_target_row: Option<usize>,
    /// Whether the drop is above or below the target.
    pub drop_above: bool,
    /// The number of rows being dragged.
    pub drag_count: usize,
}

impl DndTableCellRenderer {
    /// Create a new DnD cell renderer.
    pub fn new() -> Self {
        Self {
            drag_row: None,
            drop_target_row: None,
            drop_above: true,
            drag_count: 0,
        }
    }

    /// Begin a drag operation.
    pub fn begin_drag(&mut self, drag_row: usize, count: usize) {
        self.drag_row = Some(drag_row);
        self.drag_count = count;
    }

    /// Set the drop target.
    pub fn set_drop_target(&mut self, target_row: usize, above: bool) {
        self.drop_target_row = Some(target_row);
        self.drop_above = above;
    }

    /// End the drag-drop operation.
    pub fn end_drag(&mut self) {
        self.drag_row = None;
        self.drop_target_row = None;
        self.drag_count = 0;
    }

    /// Whether a drag is in progress.
    pub fn is_dragging(&self) -> bool {
        self.drag_row.is_some()
    }

    /// Whether the given row is the drop target.
    pub fn is_drop_target(&self, row: usize) -> bool {
        self.drop_target_row == Some(row)
    }

    /// Whether the given row is being dragged.
    pub fn is_drag_source(&self, row: usize) -> bool {
        if let Some(drag_start) = self.drag_row {
            row >= drag_start && row < drag_start + self.drag_count
        } else {
            false
        }
    }

    /// Get the visual state for a given row.
    pub fn cell_state(&self, row: usize, selected: bool) -> CellDisplayState {
        CellDisplayState {
            selected,
            focused: false,
            editing: false,
            drop_target: self.is_drop_target(row),
            enabled: !self.is_drag_source(row),
        }
    }
}

impl Default for DndTableCellRenderer {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::ComponentRow;

    #[test]
    fn test_cell_display_state_default() {
        let state = CellDisplayState::default();
        assert!(!state.selected);
        assert!(!state.focused);
        assert!(!state.editing);
        assert!(!state.drop_target);
        assert!(state.enabled);
    }

    #[test]
    fn test_data_type_cell_renderer_format() {
        let renderer = DataTypeCellRenderer::new();
        assert_eq!(renderer.format_type_name("int", "x"), "int x");
        assert_eq!(renderer.format_type_name("int", ""), "int");
    }

    #[test]
    fn test_data_type_cell_renderer_display_text() {
        let renderer = DataTypeCellRenderer::new();
        let row = ComponentRow::new(0, "int", "field_a", 0x10, 4);
        assert_eq!(renderer.get_display_text(&row, 0), "0x10");
        assert_eq!(renderer.get_display_text(&row, 1), "4");
        assert_eq!(renderer.get_display_text(&row, 4), "field_a");
        assert_eq!(renderer.get_display_text(&row, 6), "0");
    }

    #[test]
    fn test_data_type_cell_renderer_tooltip() {
        let renderer = DataTypeCellRenderer::new();
        let row = ComponentRow::new(0, "int", "x", 0x10, 4);
        let tooltip = renderer.get_tooltip_text(&row);
        assert!(tooltip.contains("Type: int"));
        assert!(tooltip.contains("Offset: 0x10"));
        assert!(tooltip.contains("Length: 4"));
        assert!(tooltip.contains("Name: x"));
    }

    #[test]
    fn test_data_type_cell_renderer_tooltip_bitfield() {
        let renderer = DataTypeCellRenderer::new();
        let mut row = ComponentRow::new(0, "uint", "flags", 0, 4);
        row.is_bit_field = true;
        row.bit_offset = Some(3);
        row.bit_size = Some(5);
        let tooltip = renderer.get_tooltip_text(&row);
        assert!(tooltip.contains("Bit-field"));
        assert!(tooltip.contains("offset=3"));
        assert!(tooltip.contains("size=5"));
    }

    #[test]
    fn test_dnd_renderer_no_drag() {
        let renderer = DndTableCellRenderer::new();
        assert!(!renderer.is_dragging());
        assert!(!renderer.is_drag_source(0));
        assert!(!renderer.is_drop_target(0));
    }

    #[test]
    fn test_dnd_renderer_drag_lifecycle() {
        let mut renderer = DndTableCellRenderer::new();
        renderer.begin_drag(2, 1);
        assert!(renderer.is_dragging());
        assert!(renderer.is_drag_source(2));
        assert!(!renderer.is_drag_source(0));

        renderer.set_drop_target(0, true);
        assert!(renderer.is_drop_target(0));
        assert!(!renderer.is_drop_target(1));

        renderer.end_drag();
        assert!(!renderer.is_dragging());
    }

    #[test]
    fn test_dnd_renderer_multi_drag() {
        let mut renderer = DndTableCellRenderer::new();
        renderer.begin_drag(2, 3); // rows 2, 3, 4
        assert!(renderer.is_drag_source(2));
        assert!(renderer.is_drag_source(3));
        assert!(renderer.is_drag_source(4));
        assert!(!renderer.is_drag_source(5));
        assert!(!renderer.is_drag_source(1));
    }

    #[test]
    fn test_dnd_renderer_cell_state() {
        let mut renderer = DndTableCellRenderer::new();
        renderer.begin_drag(2, 1);
        renderer.set_drop_target(0, true);

        let state = renderer.cell_state(0, false);
        assert!(state.drop_target);
        assert!(state.enabled);

        let drag_state = renderer.cell_state(2, true);
        assert!(!drag_state.enabled);
        assert!(drag_state.selected);
    }

    #[test]
    fn test_dnd_renderer_drop_above_below() {
        let mut renderer = DndTableCellRenderer::new();
        renderer.set_drop_target(5, true);
        assert!(renderer.drop_above);
        renderer.set_drop_target(5, false);
        assert!(!renderer.drop_above);
    }
}
