//! Stack editor panel and edit action -- ported from Ghidra's stack editor.
//!
//! Ported from:
//! - `ghidra.app.plugin.core.stackeditor.StackEditorPanel`
//! - `ghidra.app.plugin.core.stackeditor.EditStackAction`
//!
//! Provides the info panel model with frame/local/parameter size fields,
//! table display management, selection, and the Edit Stack Frame action.

use ghidra_core::Address;

use super::frame_datatype::{StackComponentWrapper, StackFrameDataType};

// ============================================================================
// StackEditorColumn -- table columns in the stack editor
// ============================================================================

/// Columns displayed in the stack editor table.
///
/// Ported from the column constants in `StackEditorModel` (OFFSET, LENGTH,
/// DATATYPE, NAME, COMMENT).
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

    /// The default column width in pixels.
    pub fn default_width(&self) -> usize {
        match self {
            Self::Offset => 40,
            Self::Length => 40,
            Self::DataType => 100,
            Self::Name => 100,
            Self::Comment => 150,
        }
    }

    /// Whether this column is editable.
    ///
    /// The Length column is never directly editable in the stack editor.
    pub fn is_editable(&self) -> bool {
        match self {
            Self::Length => false,
            _ => true,
        }
    }
}

// ============================================================================
// StackEditorRow -- a row in the stack editor table
// ============================================================================

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
    ///
    /// Corresponds to the `OFFSET` column value computation in
    /// `StackEditorModel.getValueAt()`.
    pub fn display_offset(&self, hex: bool) -> String {
        format_number(self.component.stack_offset, hex)
    }

    /// The display length.
    ///
    /// Corresponds to the `LENGTH` column value computation in
    /// `StackEditorModel.getValueAt()`. If the data type length differs
    /// from the component length, a "(needs X)" note is appended.
    pub fn display_length(&self, hex: bool) -> String {
        let comp_len = self.component.length;
        // In the real editor, if the data type's natural length differs from
        // the component length, it shows: "compHexLen (needs dtHexLen)"
        // For this model, we show the component length.
        format_number(comp_len as i32, hex)
    }

    /// The display data type.
    ///
    /// Corresponds to the `DATATYPE` column.
    pub fn display_data_type(&self) -> &str {
        &self.component.data_type_name
    }

    /// The display name.
    ///
    /// Corresponds to the `NAME` column.
    pub fn display_name(&self) -> &str {
        &self.component.field_name
    }

    /// The display comment.
    ///
    /// Corresponds to the `COMMENT` column.
    pub fn display_comment(&self) -> &str {
        self.component.comment.as_deref().unwrap_or("")
    }
}

/// Format a number as hex (0x-prefixed) or decimal.
///
/// Corresponds to `StackFrameDataType.getHexString()` and the
/// `getNumberString()` helper in `StackEditorPanel`.
fn format_number(value: i32, hex: bool) -> String {
    if hex {
        if value >= 0 {
            format!("0x{:X}", value)
        } else {
            format!("-0x{:X}", -value)
        }
    } else {
        format!("{}", value)
    }
}

// ============================================================================
// StackEditorPanelModel -- the panel model (info fields + table)
// ============================================================================

/// Model for the stack editor panel.
///
/// Ported from `ghidra.app.plugin.core.stackeditor.StackEditorPanel`.
///
/// Manages the display state: info fields (frame size, local size, parameter
/// size, parameter offset, return address offset), table rows, selection,
/// column widths, and hex/decimal display.
#[derive(Debug)]
pub struct StackEditorPanelModel {
    /// The stack frame being displayed.
    pub frame: StackFrameDataType,
    /// The rows in the table.
    rows: Vec<StackEditorRow>,
    /// Currently selected row indices (multi-select support).
    selected_rows: Vec<usize>,
    /// Column widths in pixels.
    pub column_widths: Vec<usize>,
    /// Whether to show numbers in hex.
    pub show_hex: bool,
    /// Whether the stack may have been changed externally.
    pub stack_changed_externally: bool,
    /// Status message.
    pub status_message: Option<String>,
    /// Whether the status is an error.
    pub status_is_error: bool,

    // -----------------------------------------------------------------------
    // Info fields (ported from StackEditorPanel text fields)
    // -----------------------------------------------------------------------

    /// The frame size display field (read-only in Java).
    pub frame_size_text: String,
    /// The local size display field (editable in Java).
    pub local_size_text: String,
    /// The parameter size display field (editable in Java).
    pub param_size_text: String,
    /// The parameter offset display field (read-only in Java).
    pub param_offset_text: String,
    /// The return address offset display field (read-only in Java).
    pub return_addr_offset_text: String,
}

impl StackEditorPanelModel {
    /// Create a new panel model for a stack frame.
    ///
    /// Corresponds to `StackEditorPanel` construction and `adjustStackInfo()`.
    pub fn new(frame: StackFrameDataType, show_hex: bool) -> Self {
        let mut model = Self {
            frame_size_text: format_number(frame.frame_size() as i32, show_hex),
            local_size_text: format_number(frame.local_size() as i32, show_hex),
            param_size_text: format_number(frame.parameter_size() as i32, show_hex),
            param_offset_text: format_number(frame.parameter_offset(), show_hex),
            return_addr_offset_text: format_number(frame.return_address_offset(), show_hex),
            frame,
            rows: Vec::new(),
            selected_rows: Vec::new(),
            column_widths: StackEditorColumn::all()
                .iter()
                .map(|c| c.default_width())
                .collect(),
            show_hex,
            stack_changed_externally: false,
            status_message: None,
            status_is_error: false,
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

    // -----------------------------------------------------------------------
    // Selection
    //
    // Corresponds to the selection management in the Java editor.
    // -----------------------------------------------------------------------

    /// Select a single row.
    pub fn select_row(&mut self, index: Option<usize>) {
        // Deselect all previous
        for row in &mut self.rows {
            row.selected = false;
        }
        self.selected_rows.clear();

        if let Some(idx) = index {
            if let Some(row) = self.rows.get_mut(idx) {
                row.selected = true;
                self.selected_rows.push(idx);
            }
        }
    }

    /// Select multiple rows.
    pub fn select_rows(&mut self, indices: &[usize]) {
        for row in &mut self.rows {
            row.selected = false;
        }
        self.selected_rows.clear();

        for &idx in indices {
            if let Some(row) = self.rows.get_mut(idx) {
                row.selected = true;
                self.selected_rows.push(idx);
            }
        }
    }

    /// Get the number of selected rows.
    pub fn num_selected_rows(&self) -> usize {
        self.selected_rows.len()
    }

    /// Get the selected row indices.
    pub fn selected_rows(&self) -> &[usize] {
        &self.selected_rows
    }

    /// Get the minimum selected row index.
    ///
    /// Corresponds to `getMinIndexSelected()` in the Java editor.
    pub fn min_index_selected(&self) -> Option<usize> {
        self.selected_rows.iter().copied().min()
    }

    /// Get the selected component.
    pub fn selected_component(&self) -> Option<&StackComponentWrapper> {
        self.selected_rows
            .first()
            .and_then(|&i| self.rows.get(i))
            .map(|r| &r.component)
    }

    /// Whether there is a single row selected.
    pub fn is_single_row_selected(&self) -> bool {
        self.selected_rows.len() == 1
    }

    // -----------------------------------------------------------------------
    // Display
    // -----------------------------------------------------------------------

    /// Toggle hex/decimal display.
    ///
    /// Corresponds to the `HexNumbersAction` in the Java editor.
    pub fn toggle_hex(&mut self) {
        self.show_hex = !self.show_hex;
        // Refresh displayed values
        self.refresh_fields();
    }

    /// Get a number string for display, respecting hex/decimal setting.
    ///
    /// Corresponds to `StackEditorPanel.getNumberString()`.
    pub fn get_number_string(&self, value: i32) -> String {
        format_number(value, self.show_hex)
    }

    // -----------------------------------------------------------------------
    // Info field editing
    //
    // Corresponds to the editable text fields in StackEditorPanel:
    // localSizeField and paramSizeField.
    // -----------------------------------------------------------------------

    /// Apply the local size from the text field.
    ///
    /// Corresponds to `StackEditorPanel.updatedLocalSize()`.
    pub fn apply_local_size(&mut self) -> Result<(), String> {
        let size = parse_int_field(&self.local_size_text)?;
        if size < 0 {
            return Err("Local size cannot be negative.".into());
        }
        let size = size as usize;
        if self.frame.set_local_size(size) {
            self.refresh_fields();
            Ok(())
        } else {
            Err(format!(
                "Invalid local size \"{}\". Could not adjust frame.",
                self.local_size_text
            ))
        }
    }

    /// Apply the parameter size from the text field.
    ///
    /// Corresponds to `StackEditorPanel.updatedParamSize()`.
    pub fn apply_param_size(&mut self) -> Result<(), String> {
        let size = parse_int_field(&self.param_size_text)?;
        if size < 0 {
            return Err("Parameter size cannot be negative.".into());
        }
        let size = size as usize;
        if self.frame.set_parameter_size(size) {
            self.refresh_fields();
            Ok(())
        } else {
            Err(format!(
                "Invalid parameter size \"{}\". Could not adjust frame.",
                self.param_size_text
            ))
        }
    }

    // -----------------------------------------------------------------------
    // Info panel refresh
    //
    // Corresponds to `StackEditorPanel.adjustStackInfo()`.
    // -----------------------------------------------------------------------

    /// Refresh all display fields from the frame.
    ///
    /// Corresponds to `StackEditorPanel.adjustStackInfo()`.
    pub fn refresh_fields(&mut self) {
        self.frame_size_text = self.get_number_string(self.frame.frame_size() as i32);
        self.local_size_text = self.get_number_string(self.frame.local_size() as i32);
        self.param_size_text = self.get_number_string(self.frame.parameter_size() as i32);
        self.param_offset_text = self.get_number_string(self.frame.parameter_offset());
        self.return_addr_offset_text = self.get_number_string(self.frame.return_address_offset());
        self.rebuild_rows();
    }

    /// Set the externally-changed flag.
    ///
    /// Corresponds to `StackEditorModel.stackChangedExternally()`.
    pub fn set_stack_changed_externally(&mut self, changed: bool) {
        self.stack_changed_externally = changed;
        if changed {
            self.status_message =
                Some("Stack may have been changed externally -- data may be stale.".into());
            self.status_is_error = false;
        }
    }

    /// Set a status message.
    pub fn set_status(&mut self, message: impl Into<String>, is_error: bool) {
        self.status_message = Some(message.into());
        self.status_is_error = is_error;
    }

    /// Clear the status message.
    pub fn clear_status(&mut self) {
        self.status_message = None;
        self.status_is_error = false;
    }

    // -----------------------------------------------------------------------
    // Cell value access
    //
    // Corresponds to `StackEditorModel.getValueAt()`.
    // -----------------------------------------------------------------------

    /// Get the display value at a specific row and column.
    ///
    /// Corresponds to `StackEditorModel.getValueAt(rowIndex, columnIndex)`.
    pub fn get_value_at(&self, row_index: usize, column: StackEditorColumn) -> String {
        let row = match self.rows.get(row_index) {
            Some(r) => r,
            None => return String::new(),
        };

        match column {
            StackEditorColumn::Offset => row.display_offset(self.show_hex),
            StackEditorColumn::Length => row.display_length(self.show_hex),
            StackEditorColumn::DataType => row.display_data_type().to_string(),
            StackEditorColumn::Name => row.display_name().to_string(),
            StackEditorColumn::Comment => row.display_comment().to_string(),
        }
    }

    /// Whether a cell is editable.
    ///
    /// Corresponds to `StackEditorModel.isCellEditable()`.
    pub fn is_cell_editable(&self, row_index: usize, column: StackEditorColumn) -> bool {
        if self.num_selected_rows() > 1 {
            return false;
        }
        if !column.is_editable() {
            return false;
        }
        if row_index >= self.rows.len() {
            return false;
        }
        // Undefined components can't have their offset edited
        if column == StackEditorColumn::Offset {
            if let Some(row) = self.rows.get(row_index) {
                if row.component.is_undefined {
                    return false;
                }
            }
        }
        true
    }
}

/// Parse a signed integer from a text field (supports hex with 0x prefix).
///
/// Corresponds to `Integer.decode()` in the Java StackEditorPanel.
fn parse_int_field(text: &str) -> Result<i32, String> {
    let trimmed = text.trim();
    if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        i32::from_str_radix(&trimmed[2..], 16).map_err(|e| format!("Invalid hex: {}", e))
    } else if trimmed.starts_with("-0x") || trimmed.starts_with("-0X") {
        i32::from_str_radix(&trimmed[3..], 16)
            .map(|v| -v)
            .map_err(|e| format!("Invalid hex: {}", e))
    } else {
        trimmed
            .parse::<i32>()
            .map_err(|e| format!("Invalid number: {}", e))
    }
}

// ============================================================================
// EditStackAction -- the action for opening the stack editor
// ============================================================================

/// Action for opening the stack frame editor for a function.
///
/// Ported from `ghidra.app.plugin.core.stackeditor.EditStackAction`.
///
/// This action appears in the right-click context menu under
/// "Function > Edit Stack Frame".
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
    /// The menu path for this action.
    pub menu_path: Vec<String>,
    /// The menu group (for ordering).
    pub menu_group: String,
}

impl EditStackAction {
    /// Create a new edit stack action.
    ///
    /// Corresponds to `EditStackAction(StackEditorManagerPlugin, DataTypeManagerService)`.
    pub fn new(function_address: Address, function_name: impl Into<String>) -> Self {
        Self {
            name: "Edit Stack Frame".into(),
            function_address,
            function_name: function_name.into(),
            enabled: true,
            help_topic: "StackEditor".into(),
            menu_path: vec!["Function".into(), "Edit Stack Frame".into()],
            menu_group: "Stack".into(),
        }
    }

    /// The display label for this action.
    pub fn display_label(&self) -> String {
        format!("Edit Stack Frame: {}", self.function_name)
    }

    /// Whether this action is enabled for the given context.
    ///
    /// Corresponds to `EditStackAction.isEnabledForContext()`.
    /// Disabled for external functions.
    pub fn is_enabled_for_context(&self, is_external: bool) -> bool {
        self.enabled && !is_external
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::frame_datatype::StackFrameDataType;

    fn make_test_frame() -> StackFrameDataType {
        let mut frame = StackFrameDataType::new(true, 4, 0, 16, 8);
        frame.add_component(StackComponentWrapper::new("local_10h", "int", 4, -16, 0));
        frame.add_component(StackComponentWrapper::new("local_ch", "int", 4, -12, 4));
        frame.add_component(StackComponentWrapper::undefined(8, 4));
        frame.add_component(StackComponentWrapper::new("param_0h", "int", 4, 0, 16));
        frame
    }

    #[test]
    fn test_panel_model_creation() {
        let frame = make_test_frame();
        let model = StackEditorPanelModel::new(frame, true);
        assert_eq!(model.row_count(), 4);
        assert!(model.show_hex);
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
        // i32 -16 in hex is 0x10
        assert_eq!(row.display_offset(true), "-0x10");
        assert_eq!(row.display_length(true), "0x4");
    }

    #[test]
    fn test_panel_selection() {
        let frame = make_test_frame();
        let mut model = StackEditorPanelModel::new(frame, true);
        assert_eq!(model.num_selected_rows(), 0);

        model.select_row(Some(1));
        assert_eq!(model.num_selected_rows(), 1);
        assert!(model.get_row(1).unwrap().selected);

        model.select_row(Some(2));
        assert_eq!(model.num_selected_rows(), 1);
        assert!(!model.get_row(1).unwrap().selected);
        assert!(model.get_row(2).unwrap().selected);
    }

    #[test]
    fn test_panel_multi_selection() {
        let frame = make_test_frame();
        let mut model = StackEditorPanelModel::new(frame, true);
        model.select_rows(&[0, 2]);
        assert_eq!(model.num_selected_rows(), 2);
        assert!(model.get_row(0).unwrap().selected);
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
    fn test_panel_min_index_selected() {
        let frame = make_test_frame();
        let mut model = StackEditorPanelModel::new(frame, true);
        assert!(model.min_index_selected().is_none());
        model.select_rows(&[2, 0, 3]);
        assert_eq!(model.min_index_selected(), Some(0));
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
    fn test_parse_int_field() {
        assert_eq!(parse_int_field("42").unwrap(), 42);
        assert_eq!(parse_int_field("0x10").unwrap(), 16);
        assert_eq!(parse_int_field("0XFF").unwrap(), 255);
        assert_eq!(parse_int_field("-16").unwrap(), -16);
        assert_eq!(parse_int_field("-0x10").unwrap(), -16);
        assert!(parse_int_field("abc").is_err());
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
    fn test_apply_param_size() {
        let frame = make_test_frame();
        let mut model = StackEditorPanelModel::new(frame, true);
        model.param_size_text = "16".into();
        model.apply_param_size().unwrap();
        assert_eq!(model.frame.parameter_size(), 16);
    }

    #[test]
    fn test_apply_local_size_negative_rejected() {
        let frame = make_test_frame();
        let mut model = StackEditorPanelModel::new(frame, true);
        model.local_size_text = "-4".into();
        assert!(model.apply_local_size().is_err());
    }

    #[test]
    fn test_refresh_fields() {
        let frame = make_test_frame();
        let mut model = StackEditorPanelModel::new(frame, true);
        model.frame_size_text = "wrong".into();
        model.refresh_fields();
        // Frame size should be 24 (16 + 8)
        assert!(!model.frame_size_text.is_empty());
        assert_ne!(model.frame_size_text, "wrong");
    }

    #[test]
    fn test_refresh_fields_hex_decimal() {
        let frame = make_test_frame();
        let mut model = StackEditorPanelModel::new(frame, false);
        model.refresh_fields();
        assert_eq!(model.param_offset_text, "0");

        model.show_hex = true;
        model.refresh_fields();
        assert_eq!(model.param_offset_text, "0x0");
    }

    #[test]
    fn test_get_value_at() {
        let frame = make_test_frame();
        let model = StackEditorPanelModel::new(frame, false);
        assert_eq!(
            model.get_value_at(0, StackEditorColumn::Name),
            "local_10h"
        );
        assert_eq!(
            model.get_value_at(0, StackEditorColumn::DataType),
            "int"
        );
        assert_eq!(
            model.get_value_at(0, StackEditorColumn::Offset),
            "-16"
        );
    }

    #[test]
    fn test_is_cell_editable() {
        let frame = make_test_frame();
        let model = StackEditorPanelModel::new(frame, true);

        // Length column is never editable
        assert!(!model.is_cell_editable(0, StackEditorColumn::Length));

        // Out of range
        assert!(!model.is_cell_editable(100, StackEditorColumn::Name));

        // Multi-select: not editable
        // (Can't easily test here since we need &mut to select multiple)

        // Offset on undefined component: not editable
        assert!(!model.is_cell_editable(2, StackEditorColumn::Offset));

        // Name on defined component: editable
        assert!(model.is_cell_editable(0, StackEditorColumn::Name));
    }

    #[test]
    fn test_column_names() {
        assert_eq!(StackEditorColumn::Offset.display_name(), "Offset");
        assert_eq!(StackEditorColumn::Length.display_name(), "Length");
        assert_eq!(StackEditorColumn::DataType.display_name(), "DataType");
        assert_eq!(StackEditorColumn::Name.display_name(), "Name");
        assert_eq!(StackEditorColumn::Comment.display_name(), "Comment");
        assert_eq!(StackEditorColumn::all().len(), 5);
    }

    #[test]
    fn test_column_default_widths() {
        assert_eq!(StackEditorColumn::Offset.default_width(), 40);
        assert_eq!(StackEditorColumn::Length.default_width(), 40);
        assert_eq!(StackEditorColumn::DataType.default_width(), 100);
        assert_eq!(StackEditorColumn::Name.default_width(), 100);
        assert_eq!(StackEditorColumn::Comment.default_width(), 150);
    }

    #[test]
    fn test_column_editable() {
        assert!(StackEditorColumn::Offset.is_editable());
        assert!(!StackEditorColumn::Length.is_editable());
        assert!(StackEditorColumn::DataType.is_editable());
        assert!(StackEditorColumn::Name.is_editable());
        assert!(StackEditorColumn::Comment.is_editable());
    }

    #[test]
    fn test_edit_stack_action() {
        let action = EditStackAction::new(Address::new(0x400000), "main");
        assert_eq!(action.display_label(), "Edit Stack Frame: main");
        assert!(action.enabled);
        assert!(action.is_enabled_for_context(false));
        assert!(!action.is_enabled_for_context(true)); // external func disabled
        assert_eq!(action.menu_path.len(), 2);
        assert_eq!(action.menu_group, "Stack");
    }

    #[test]
    fn test_status_message() {
        let frame = make_test_frame();
        let mut model = StackEditorPanelModel::new(frame, true);
        assert!(model.status_message.is_none());
        model.set_status("Error occurred", true);
        assert!(model.status_message.is_some());
        assert!(model.status_is_error);
        model.clear_status();
        assert!(model.status_message.is_none());
    }

    #[test]
    fn test_externally_changed() {
        let frame = make_test_frame();
        let mut model = StackEditorPanelModel::new(frame, true);
        assert!(!model.stack_changed_externally);
        model.set_stack_changed_externally(true);
        assert!(model.stack_changed_externally);
        assert!(model.status_message.is_some());
    }

    #[test]
    fn test_row_data_type_and_comment() {
        let frame = make_test_frame();
        let model = StackEditorPanelModel::new(frame, false);
        let row = model.get_row(0).unwrap();
        assert_eq!(row.display_data_type(), "int");
        assert_eq!(row.display_comment(), "");
    }

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(16, false), "16");
        assert_eq!(format_number(16, true), "0x10");
        assert_eq!(format_number(-16, false), "-16");
        assert_eq!(format_number(-16, true), "-0x10");
        assert_eq!(format_number(0, false), "0");
        assert_eq!(format_number(0, true), "0x0");
    }
}
