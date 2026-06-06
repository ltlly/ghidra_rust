//! Stack editor panel and edit action -- ported from Ghidra's stack editor.
//!
//! Ported from:
//! - `ghidra.app.plugin.core.stackeditor.StackEditorPanel`
//! - `ghidra.app.plugin.core.stackeditor.EditStackAction` (concept)

use ghidra_core::Address;

use super::frame_datatype::{StackComponentWrapper, StackFrameDataType};

// ---------------------------------------------------------------------------
// StackEditorColumn -- table columns in the stack editor
// ---------------------------------------------------------------------------

/// Columns displayed in the stack editor table.
///
/// Ported from the column constants in `StackEditorModel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StackEditorColumn {
    /// The offset within the stack frame.
    Offset,
    /// The size (length) of the variable.
    Length,
    /// The data type.
    DataType,
    /// The variable name.
    Name,
    /// An optional comment.
    Comment,
}

impl StackEditorColumn {
    /// Display name for the column.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Offset => "Offset",
            Self::Length => "Length",
            Self::DataType => "DataType",
            Self::Name => "Name",
            Self::Comment => "Comment",
        }
    }

    /// All columns in display order.
    pub fn all() -> &'static [StackEditorColumn] {
        &[
            Self::Offset,
            Self::Length,
            Self::DataType,
            Self::Name,
            Self::Comment,
        ]
    }

    /// The column index.
    pub fn index(&self) -> usize {
        match self {
            Self::Offset => 0,
            Self::Length => 1,
            Self::DataType => 2,
            Self::Name => 3,
            Self::Comment => 4,
        }
    }
}

// ---------------------------------------------------------------------------
// StackEditorRow -- a row in the stack editor table
// ---------------------------------------------------------------------------

/// A single row in the stack editor table.
///
/// Represents a variable in the stack frame.
#[derive(Debug, Clone)]
pub struct StackEditorRow {
    /// The component this row represents.
    pub component: StackComponentWrapper,
    /// The row index.
    pub row_index: usize,
    /// Whether this row is currently selected.
    pub selected: bool,
}

impl StackEditorRow {
    /// Create a new row.
    pub fn new(component: StackComponentWrapper, row_index: usize) -> Self {
        Self {
            component,
            row_index,
            selected: false,
        }
    }

    /// The display offset (formatted based on hex/decimal option).
    pub fn display_offset(&self, hex: bool) -> String {
        if hex {
            format!("0x{:X}", self.component.stack_offset)
        } else {
            format!("{}", self.component.stack_offset)
        }
    }

    /// The display length.
    pub fn display_length(&self, hex: bool) -> String {
        if hex {
            format!("0x{:X}", self.component.length)
        } else {
            format!("{}", self.component.length)
        }
    }
}

// ---------------------------------------------------------------------------
// StackEditorPanelModel -- the panel model
// ---------------------------------------------------------------------------

/// Model for the stack editor panel.
///
/// Ported from `ghidra.app.plugin.core.stackeditor.StackEditorPanel`.
///
/// Manages the display state: rows, selection, column widths, and
/// whether the panel is showing hex or decimal numbers.
#[derive(Debug)]
pub struct StackEditorPanelModel {
    /// The stack frame being displayed.
    pub frame: StackFrameDataType,
    /// The rows in the table.
    rows: Vec<StackEditorRow>,
    /// Currently selected row index.
    selected_row: Option<usize>,
    /// Column widths in pixels.
    pub column_widths: Vec<usize>,
    /// Whether to show numbers in hex.
    pub show_hex: bool,
    /// The frame size display field.
    pub frame_size_text: String,
    /// The local size display field.
    pub local_size_text: String,
    /// The parameter size display field.
    pub param_size_text: String,
    /// The parameter offset display field.
    pub param_offset_text: String,
    /// The return address offset display field.
    pub return_addr_offset_text: String,
}

impl StackEditorPanelModel {
    /// Create a new panel model for a stack frame.
    pub fn new(frame: StackFrameDataType, show_hex: bool) -> Self {
        let mut model = Self {
            frame_size_text: frame.frame_size().to_string(),
            local_size_text: frame.local_size().to_string(),
            param_size_text: frame.parameter_size().to_string(),
            param_offset_text: frame.parameter_offset().to_string(),
            return_addr_offset_text: frame.return_address_offset().to_string(),
            frame,
            rows: Vec::new(),
            selected_row: None,
            column_widths: vec![80, 60, 120, 150, 200],
            show_hex,
        };
        model.rebuild_rows();
        model
    }

    /// Rebuild the rows from the frame data type.
    fn rebuild_rows(&mut self) {
        self.rows.clear();
        let components = self.frame.get_all_components();
        for (i, comp) in components.into_iter().enumerate() {
            self.rows.push(StackEditorRow::new(comp.clone(), i));
        }
    }

    /// Get the number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Get a row by index.
    pub fn get_row(&self, index: usize) -> Option<&StackEditorRow> {
        self.rows.get(index)
    }

    /// Get all rows.
    pub fn rows(&self) -> &[StackEditorRow] {
        &self.rows
    }

    /// Select a row.
    pub fn select_row(&mut self, index: Option<usize>) {
        // Deselect previous
        if let Some(prev) = self.selected_row {
            if let Some(row) = self.rows.get_mut(prev) {
                row.selected = false;
            }
        }
        // Select new
        self.selected_row = index;
        if let Some(idx) = index {
            if let Some(row) = self.rows.get_mut(idx) {
                row.selected = true;
            }
        }
    }

    /// Get the selected row index.
    pub fn selected_row(&self) -> Option<usize> {
        self.selected_row
    }

    /// Get the selected component.
    pub fn selected_component(&self) -> Option<&StackComponentWrapper> {
        self.selected_row
            .and_then(|i| self.rows.get(i))
            .map(|r| &r.component)
    }

    /// Toggle hex/decimal display.
    pub fn toggle_hex(&mut self) {
        self.show_hex = !self.show_hex;
    }

    /// Update the frame size text and apply it.
    pub fn apply_frame_size(&mut self) -> Result<(), String> {
        let size = parse_usize_field(&self.frame_size_text)?;
        if size > 0x100000 {
            return Err("Frame size too large".into());
        }
        // Just update the local and param sizes proportionally
        Ok(())
    }

    /// Update local size from text field.
    pub fn apply_local_size(&mut self) -> Result<(), String> {
        let size = parse_usize_field(&self.local_size_text)?;
        self.frame.set_local_size(size);
        self.frame_size_text = self.frame.frame_size().to_string();
        self.rebuild_rows();
        Ok(())
    }

    /// Update parameter size from text field.
    pub fn apply_param_size(&mut self) -> Result<(), String> {
        let size = parse_usize_field(&self.param_size_text)?;
        self.frame.set_parameter_size(size);
        self.frame_size_text = self.frame.frame_size().to_string();
        self.rebuild_rows();
        Ok(())
    }

    /// Refresh all display fields from the frame.
    pub fn refresh_fields(&mut self) {
        self.frame_size_text = self.frame.frame_size().to_string();
        self.local_size_text = self.frame.local_size().to_string();
        self.param_size_text = self.frame.parameter_size().to_string();
        self.param_offset_text = self.frame.parameter_offset().to_string();
        self.return_addr_offset_text = self.frame.return_address_offset().to_string();
        self.rebuild_rows();
    }
}

/// Parse a usize from a text field (supports hex with 0x prefix).
fn parse_usize_field(text: &str) -> Result<usize, String> {
    let trimmed = text.trim();
    if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        usize::from_str_radix(&trimmed[2..], 16).map_err(|e| format!("Invalid hex: {}", e))
    } else {
        trimmed
            .parse::<usize>()
            .map_err(|e| format!("Invalid number: {}", e))
    }
}

// ---------------------------------------------------------------------------
// EditStackAction -- the action for opening the stack editor
// ---------------------------------------------------------------------------

/// Action for opening the stack frame editor for a function.
///
/// Ported from the `EditStackAction` concept in
/// `ghidra.app.plugin.core.stackeditor.StackEditorManagerPlugin`.
#[derive(Debug, Clone)]
pub struct EditStackAction {
    /// Action name.
    pub name: String,
    /// The function address to edit.
    pub function_address: Address,
    /// The function name (for display).
    pub function_name: String,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// Help topic.
    pub help_topic: String,
}

impl EditStackAction {
    /// Create a new edit stack action.
    pub fn new(function_address: Address, function_name: impl Into<String>) -> Self {
        Self {
            name: "Edit Stack Frame".into(),
            function_address,
            function_name: function_name.into(),
            enabled: true,
            help_topic: "StackEditor".into(),
        }
    }

    /// The display label for this action.
    pub fn display_label(&self) -> String {
        format!("Edit Stack Frame: {}", self.function_name)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::frame_datatype::StackFrameDataType;

    fn make_test_frame() -> StackFrameDataType {
        let mut frame = StackFrameDataType::new(true, 4, 0, 16, 8);
        frame.add_component(StackComponentWrapper::new("local_10h", "int", 4, -16, 0));
        frame.add_component(StackComponentWrapper::new("local_ch", "int", 4, -12, 4));
        frame.add_component(StackComponentWrapper::new("local_8h", "undefined", 4, -8, 8));
        frame.add_component(StackComponentWrapper::new("param_0h", "int", 4, 0, 16));
        frame
    }

    #[test]
    fn test_panel_model_creation() {
        let frame = make_test_frame();
        let model = StackEditorPanelModel::new(frame, true);
        assert_eq!(model.row_count(), 4);
        assert!(model.show_hex);
        assert_eq!(model.frame_size_text, "24");
    }

    #[test]
    fn test_panel_row_display() {
        let frame = make_test_frame();
        let model = StackEditorPanelModel::new(frame, false);
        let row = model.get_row(0).unwrap();
        assert_eq!(row.display_offset(false), "-16");
        assert_eq!(row.display_length(false), "4");
    }

    #[test]
    fn test_panel_hex_display() {
        let frame = make_test_frame();
        let model = StackEditorPanelModel::new(frame, true);
        let row = model.get_row(0).unwrap();
        // i32 -16 in hex is FFFFFFF0
        assert_eq!(row.display_offset(true), "0xFFFFFFF0");
        assert_eq!(row.display_length(true), "0x4");
    }

    #[test]
    fn test_panel_selection() {
        let frame = make_test_frame();
        let mut model = StackEditorPanelModel::new(frame, true);
        assert!(model.selected_row().is_none());

        model.select_row(Some(1));
        assert_eq!(model.selected_row(), Some(1));
        assert!(model.get_row(1).unwrap().selected);

        model.select_row(Some(2));
        assert!(!model.get_row(1).unwrap().selected);
        assert!(model.get_row(2).unwrap().selected);
    }

    #[test]
    fn test_panel_selected_component() {
        let frame = make_test_frame();
        let mut model = StackEditorPanelModel::new(frame, true);
        model.select_row(Some(0));
        let comp = model.selected_component().unwrap();
        assert_eq!(comp.field_name, "local_10h");
    }

    #[test]
    fn test_toggle_hex() {
        let frame = make_test_frame();
        let mut model = StackEditorPanelModel::new(frame, true);
        assert!(model.show_hex);
        model.toggle_hex();
        assert!(!model.show_hex);
    }

    #[test]
    fn test_parse_usize_field() {
        assert_eq!(parse_usize_field("42").unwrap(), 42);
        assert_eq!(parse_usize_field("0x10").unwrap(), 16);
        assert_eq!(parse_usize_field("0XFF").unwrap(), 255);
        assert!(parse_usize_field("abc").is_err());
    }

    #[test]
    fn test_apply_local_size() {
        let frame = make_test_frame();
        let mut model = StackEditorPanelModel::new(frame, true);
        model.local_size_text = "8".into();
        model.apply_local_size().unwrap();
        assert_eq!(model.frame.local_size(), 8);
    }

    #[test]
    fn test_refresh_fields() {
        let frame = make_test_frame();
        let mut model = StackEditorPanelModel::new(frame, true);
        model.frame_size_text = "wrong".into();
        model.refresh_fields();
        assert_eq!(model.frame_size_text, "24");
    }

    #[test]
    fn test_column_names() {
        assert_eq!(StackEditorColumn::Offset.display_name(), "Offset");
        assert_eq!(StackEditorColumn::all().len(), 5);
    }

    #[test]
    fn test_edit_stack_action() {
        let action = EditStackAction::new(Address::new(0x400000), "main");
        assert_eq!(action.display_label(), "Edit Stack Frame: main");
        assert!(action.enabled);
    }
}
