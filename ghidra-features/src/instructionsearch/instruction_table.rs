// ===========================================================================
// Instruction Table -- ported from Ghidra's
// `ghidra.app.plugin.core.instructionsearch.ui` package.
//
// Includes:
// - InstructionTable              -- the main table model
// - AbstractInstructionTable      -- abstract base for instruction tables
// - InstructionTableDataObject    -- a row in the table
// - InstructionTableCellRenderer  -- cell rendering logic
// - InstructionTableModel         -- table data model
// - InstructionTableObserver      -- observer for table changes
// - InstructionTablePanel         -- panel that contains the table
// - PreviewTable                  -- preview of search results
// - PreviewTablePanel             -- panel for the preview table
// ===========================================================================

use ghidra_core::Address;

use super::MaskContainer;

// ---------------------------------------------------------------------------
// InstructionTableDataObject
// ---------------------------------------------------------------------------

/// A single row in the instruction table.
///
/// Ported from
/// `ghidra.app.plugin.core.instructionsearch.ui.InstructionTableDataObject`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionTableDataObject {
    /// The address of the instruction.
    pub address: Address,
    /// The instruction bytes.
    pub bytes: Vec<u8>,
    /// The instruction mnemonic (e.g., "MOV", "ADD").
    pub mnemonic: String,
    /// The operands as text.
    pub operands: String,
    /// Whether this row is selected for inclusion in the search pattern.
    pub selected: bool,
    /// Mask containers for the operands.
    pub operand_masks: Vec<MaskContainer>,
    /// Row index in the table.
    pub row_index: usize,
    /// Whether this instruction is marked as "masked" (will not be included in search).
    pub masked: bool,
}

impl InstructionTableDataObject {
    /// Create a new table row.
    pub fn new(
        address: Address,
        bytes: Vec<u8>,
        mnemonic: String,
        operands: String,
        row_index: usize,
    ) -> Self {
        Self {
            address,
            bytes,
            mnemonic,
            operands,
            selected: true,
            operand_masks: Vec::new(),
            row_index,
            masked: false,
        }
    }

    /// Get the full instruction text (mnemonic + operands).
    pub fn full_text(&self) -> String {
        if self.operands.is_empty() {
            self.mnemonic.clone()
        } else {
            format!("{} {}", self.mnemonic, self.operands)
        }
    }

    /// Get the hex representation of the instruction bytes.
    pub fn hex_string(&self) -> String {
        self.bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Add a mask container for an operand.
    pub fn add_operand_mask(&mut self, mask: MaskContainer) {
        self.operand_masks.push(mask);
    }

    /// Toggle the masked state.
    pub fn toggle_mask(&mut self) {
        self.masked = !self.masked;
    }
}

// ---------------------------------------------------------------------------
// InstructionTableModel
// ---------------------------------------------------------------------------

/// The table model that holds instruction data objects.
///
/// Ported from
/// `ghidra.app.plugin.core.instructionsearch.ui.InstructionTableModel`.
#[derive(Debug, Clone)]
pub struct InstructionTableModel {
    /// The rows in the table.
    pub rows: Vec<InstructionTableDataObject>,
    /// Column names.
    pub columns: Vec<String>,
}

impl InstructionTableModel {
    /// Create a new table model.
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            columns: vec![
                "Selected".into(),
                "Address".into(),
                "Bytes".into(),
                "Mnemonic".into(),
                "Operands".into(),
                "Masked".into(),
            ],
        }
    }

    /// Add a row to the table.
    pub fn add_row(&mut self, row: InstructionTableDataObject) {
        self.rows.push(row);
    }

    /// Get the number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Get a reference to a row.
    pub fn get_row(&self, index: usize) -> Option<&InstructionTableDataObject> {
        self.rows.get(index)
    }

    /// Get a mutable reference to a row.
    pub fn get_row_mut(&mut self, index: usize) -> Option<&mut InstructionTableDataObject> {
        self.rows.get_mut(index)
    }

    /// Select all rows.
    pub fn select_all(&mut self) {
        for row in &mut self.rows {
            row.selected = true;
        }
    }

    /// Deselect all rows.
    pub fn deselect_all(&mut self) {
        for row in &mut self.rows {
            row.selected = false;
        }
    }

    /// Get the selected rows.
    pub fn selected_rows(&self) -> Vec<&InstructionTableDataObject> {
        self.rows.iter().filter(|r| r.selected).collect()
    }

    /// Get the selected row count.
    pub fn selected_count(&self) -> usize {
        self.rows.iter().filter(|r| r.selected).count()
    }

    /// Toggle selection of a row.
    pub fn toggle_selection(&mut self, index: usize) {
        if let Some(row) = self.rows.get_mut(index) {
            row.selected = !row.selected;
        }
    }

    /// Clear all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
    }
}

impl Default for InstructionTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// InstructionTableObserver
// ---------------------------------------------------------------------------

/// Trait for observing changes in the instruction table.
///
/// Ported from
/// `ghidra.app.plugin.core.instructionsearch.ui.InstructionTableObserver`.
pub trait InstructionTableObserver: Send + Sync {
    /// Called when a row is selected/deselected.
    fn on_selection_changed(&mut self, index: usize, selected: bool);

    /// Called when a row is masked/unmasked.
    fn on_mask_changed(&mut self, index: usize, masked: bool);

    /// Called when the table data changes.
    fn on_data_changed(&mut self);
}

// ---------------------------------------------------------------------------
// InstructionTableCellRenderer
// ---------------------------------------------------------------------------

/// Cell renderer for the instruction table.
///
/// Ported from
/// `ghidra.app.plugin.core.instructionsearch.ui.InstructionTableCellRenderer`.
#[derive(Debug, Clone)]
pub struct InstructionTableCellRenderer {
    /// Whether to highlight selected rows.
    pub highlight_selected: bool,
    /// Whether to show masked rows differently.
    pub dim_masked: bool,
    /// The font name.
    pub font_name: String,
    /// The font size.
    pub font_size: f32,
}

impl InstructionTableCellRenderer {
    /// Create a new renderer with defaults.
    pub fn new() -> Self {
        Self {
            highlight_selected: true,
            dim_masked: true,
            font_name: "Monospaced".into(),
            font_size: 12.0,
        }
    }

    /// Render a cell value as a string.
    pub fn render_cell(&self, row: &InstructionTableDataObject, column: usize) -> String {
        match column {
            0 => {
                if row.selected { "X" } else { " " }.to_string()
            }
            1 => format!("{:08X}", row.address.offset),
            2 => row.hex_string(),
            3 => row.mnemonic.clone(),
            4 => row.operands.clone(),
            5 => {
                if row.masked { "M" } else { " " }.to_string()
            }
            _ => String::new(),
        }
    }
}

impl Default for InstructionTableCellRenderer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// InstructionTable / AbstractInstructionTable
// ---------------------------------------------------------------------------

/// Abstract base for instruction tables.
///
/// Ported from
/// `ghidra.app.plugin.core.instructionsearch.ui.AbstractInstructionTable`.
#[derive(Debug, Clone)]
pub struct AbstractInstructionTable {
    /// The table model.
    pub model: InstructionTableModel,
    /// The cell renderer.
    pub renderer: InstructionTableCellRenderer,
    /// Whether the table is editable.
    pub editable: bool,
}

impl AbstractInstructionTable {
    /// Create a new abstract table.
    pub fn new() -> Self {
        Self {
            model: InstructionTableModel::new(),
            renderer: InstructionTableCellRenderer::new(),
            editable: true,
        }
    }

    /// Get the display text for a cell.
    pub fn cell_text(&self, row: usize, col: usize) -> Option<String> {
        self.model
            .get_row(row)
            .map(|r| self.renderer.render_cell(r, col))
    }
}

impl Default for AbstractInstructionTable {
    fn default() -> Self {
        Self::new()
    }
}

/// The concrete instruction table.
///
/// Ported from
/// `ghidra.app.plugin.core.instructionsearch.ui.InstructionTable`.
#[derive(Debug, Clone)]
pub struct InstructionTable {
    /// The abstract table base.
    pub base: AbstractInstructionTable,
    /// Observers watching for changes.
    pub observer_count: usize,
}

impl InstructionTable {
    /// Create a new instruction table.
    pub fn new() -> Self {
        Self {
            base: AbstractInstructionTable::new(),
            observer_count: 0,
        }
    }

    /// Add instructions from a disassembly result.
    pub fn load_instructions(&mut self, instructions: Vec<(Address, Vec<u8>, String, String)>) {
        for (i, (addr, bytes, mnemonic, operands)) in instructions.into_iter().enumerate() {
            self.base
                .model
                .add_row(InstructionTableDataObject::new(
                    addr, bytes, mnemonic, operands, i,
                ));
        }
    }
}

impl Default for InstructionTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// InstructionTablePanel
// ---------------------------------------------------------------------------

/// Panel that contains the instruction table.
///
/// Ported from
/// `ghidra.app.plugin.core.instructionsearch.ui.InstructionTablePanel`.
#[derive(Debug, Clone)]
pub struct InstructionTablePanel {
    /// The instruction table.
    pub table: InstructionTable,
    /// Panel width.
    pub width: u32,
    /// Panel height.
    pub height: u32,
    /// Whether the panel is visible.
    pub visible: bool,
}

impl InstructionTablePanel {
    /// Create a new panel.
    pub fn new() -> Self {
        Self {
            table: InstructionTable::new(),
            width: 800,
            height: 400,
            visible: true,
        }
    }
}

impl Default for InstructionTablePanel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PreviewTable
// ---------------------------------------------------------------------------

/// Preview table that shows the byte pattern that will be searched for.
///
/// Ported from
/// `ghidra.app.plugin.core.instructionsearch.ui.PreviewTable`.
#[derive(Debug, Clone)]
pub struct PreviewTable {
    /// The preview data rows.
    pub rows: Vec<PreviewRow>,
    /// The combined search bytes.
    pub search_bytes: Vec<u8>,
    /// The combined mask bytes.
    pub mask_bytes: Vec<u8>,
}

/// A row in the preview table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewRow {
    /// The address.
    pub address: Address,
    /// The instruction bytes (value).
    pub value_bytes: Vec<u8>,
    /// The mask bytes.
    pub mask: Vec<u8>,
    /// The mnemonic.
    pub mnemonic: String,
}

impl PreviewTable {
    /// Create a new preview table.
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            search_bytes: Vec::new(),
            mask_bytes: Vec::new(),
        }
    }

    /// Add a preview row.
    pub fn add_row(&mut self, row: PreviewRow) {
        self.rows.push(row);
    }

    /// Build the combined search pattern from all rows.
    pub fn build_pattern(&mut self) {
        self.search_bytes.clear();
        self.mask_bytes.clear();
        for row in &self.rows {
            self.search_bytes.extend_from_slice(&row.value_bytes);
            self.mask_bytes.extend_from_slice(&row.mask);
        }
    }

    /// Get the pattern as a hex string.
    pub fn pattern_hex(&self) -> String {
        self.search_bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Get the mask as a hex string.
    pub fn mask_hex(&self) -> String {
        self.mask_bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl Default for PreviewTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PreviewTablePanel
// ---------------------------------------------------------------------------

/// Panel that contains the preview table.
///
/// Ported from
/// `ghidra.app.plugin.core.instructionsearch.ui.PreviewTablePanel`.
#[derive(Debug, Clone)]
pub struct PreviewTablePanel {
    /// The preview table.
    pub table: PreviewTable,
    /// Whether the panel is visible.
    pub visible: bool,
}

impl PreviewTablePanel {
    /// Create a new panel.
    pub fn new() -> Self {
        Self {
            table: PreviewTable::new(),
            visible: true,
        }
    }

    /// Update the preview from the instruction table model.
    pub fn update_from_model(&mut self, model: &InstructionTableModel) {
        self.table.rows.clear();
        for row in model.selected_rows() {
            if !row.masked {
                let mask = vec![0xFF; row.bytes.len()];
                self.table.add_row(PreviewRow {
                    address: row.address,
                    value_bytes: row.bytes.clone(),
                    mask,
                    mnemonic: row.mnemonic.clone(),
                });
            }
        }
        self.table.build_pattern();
    }
}

impl Default for PreviewTablePanel {
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
    fn test_table_data_object() {
        let row = InstructionTableDataObject::new(
            Address::new(0x400000),
            vec![0x90, 0xC3],
            "RET".into(),
            String::new(),
            0,
        );
        assert_eq!(row.full_text(), "RET");
        assert_eq!(row.hex_string(), "90 C3");
        assert!(row.selected);
        assert!(!row.masked);
    }

    #[test]
    fn test_instruction_table_model() {
        let mut model = InstructionTableModel::new();
        model.add_row(InstructionTableDataObject::new(
            Address::new(0x400000),
            vec![0x90],
            "NOP".into(),
            String::new(),
            0,
        ));
        model.add_row(InstructionTableDataObject::new(
            Address::new(0x400001),
            vec![0xC3],
            "RET".into(),
            String::new(),
            1,
        ));
        assert_eq!(model.row_count(), 2);
        assert_eq!(model.selected_count(), 2);

        model.toggle_selection(0);
        assert_eq!(model.selected_count(), 1);

        model.select_all();
        assert_eq!(model.selected_count(), 2);

        model.deselect_all();
        assert_eq!(model.selected_count(), 0);
    }

    #[test]
    fn test_cell_renderer() {
        let renderer = InstructionTableCellRenderer::new();
        let row = InstructionTableDataObject::new(
            Address::new(0x400000),
            vec![0x90],
            "NOP".into(),
            String::new(),
            0,
        );
        assert_eq!(renderer.render_cell(&row, 0), "X"); // selected
        assert_eq!(renderer.render_cell(&row, 1), "00400000"); // address
        assert_eq!(renderer.render_cell(&row, 2), "90"); // bytes
        assert_eq!(renderer.render_cell(&row, 3), "NOP"); // mnemonic
    }

    #[test]
    fn test_preview_table() {
        let mut preview = PreviewTable::new();
        preview.add_row(PreviewRow {
            address: Address::new(0x400000),
            value_bytes: vec![0x90, 0xC3],
            mask: vec![0xFF, 0xFF],
            mnemonic: "NOP; RET".into(),
        });
        preview.build_pattern();
        assert_eq!(preview.pattern_hex(), "90 C3");
        assert_eq!(preview.mask_hex(), "FF FF");
    }

    #[test]
    fn test_preview_table_panel_update() {
        let mut panel = PreviewTablePanel::new();
        let mut model = InstructionTableModel::new();
        model.add_row(InstructionTableDataObject::new(
            Address::new(0x400000),
            vec![0x48, 0x89, 0xE5],
            "MOV".into(),
            "RBP, RSP".into(),
            0,
        ));
        panel.update_from_model(&model);
        assert_eq!(panel.table.rows.len(), 1);
        assert_eq!(panel.table.search_bytes, vec![0x48, 0x89, 0xE5]);
    }

    #[test]
    fn test_instruction_table_load() {
        let mut table = InstructionTable::new();
        table.load_instructions(vec![
            (
                Address::new(0x400000),
                vec![0x90],
                "NOP".into(),
                String::new(),
            ),
            (
                Address::new(0x400001),
                vec![0xC3],
                "RET".into(),
                String::new(),
            ),
        ]);
        assert_eq!(table.base.model.row_count(), 2);
    }
}
