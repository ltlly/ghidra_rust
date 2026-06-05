//! Instruction search UI panel model.
//!
//! Ported from `ghidra.app.plugin.core.instructionsearch.ui.InstructionSearchMainPanel`,
//! `InstructionTablePanel`, `PreviewTablePanel`, `ControlPanel`,
//! `MessagePanel`.

use super::model::{InstructionMetadata, MaskContainer};
use super::SearchFormat;

/// Mode of the instruction search panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchPanelMode {
    /// Building the search pattern from program instructions.
    BuildPattern,
    /// Manually entering a hex/binary pattern.
    ManualEntry,
    /// Previewing matches in the program.
    Preview,
}

impl Default for SearchPanelMode {
    fn default() -> Self {
        SearchPanelMode::BuildPattern
    }
}

/// Selection mode for the instruction table.
///
/// Ported from `ghidra.app.plugin.core.instructionsearch.ui.SelectionModeWidget`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionMode {
    /// Select individual instructions.
    Individual,
    /// Select a range of instructions.
    Range,
    /// Select all instructions.
    All,
}

impl Default for SelectionMode {
    fn default() -> Self {
        SelectionMode::Individual
    }
}

/// Endianness for byte display.
///
/// Ported from `ghidra.app.plugin.core.instructionsearch.ui.EndianFlipWidget`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayEndian {
    /// Big-endian display.
    Big,
    /// Little-endian display.
    Little,
}

impl Default for DisplayEndian {
    fn default() -> Self {
        DisplayEndian::Little
    }
}

/// A row in the instruction table.
///
/// Ported from the table model in `InstructionTablePanel`.
#[derive(Debug, Clone)]
pub struct InstructionTableRow {
    /// Whether this row is selected for the search pattern.
    pub selected: bool,
    /// The instruction metadata.
    pub instruction: InstructionMetadata,
    /// The raw bytes.
    pub bytes: Vec<u8>,
    /// The address of the instruction.
    pub address: u64,
    /// The mnemonic (e.g., "MOV", "ADD").
    pub mnemonic: String,
}

impl InstructionTableRow {
    /// Create a new row.
    pub fn new(instruction: InstructionMetadata, bytes: Vec<u8>, address: u64, mnemonic: impl Into<String>) -> Self {
        Self {
            selected: false,
            instruction,
            bytes,
            address,
            mnemonic: mnemonic.into(),
        }
    }
}

/// Model for the main search panel.
///
/// Ported from `ghidra.app.plugin.core.instructionsearch.ui.InstructionSearchMainPanel`.
#[derive(Debug)]
pub struct InstructionSearchPanelModel {
    /// Current panel mode.
    pub mode: SearchPanelMode,
    /// Selected format.
    pub format: SearchFormat,
    /// Selection mode.
    pub selection_mode: SelectionMode,
    /// Display endianness.
    pub endian: DisplayEndian,
    /// Instructions in the table.
    pub rows: Vec<InstructionTableRow>,
    /// Search results for preview.
    pub preview_results: Vec<(u64, Vec<u8>)>,
    /// Message text.
    pub message: Option<String>,
    /// Whether to show undefined bytes.
    pub show_undefined: bool,
    /// User-entered hex/binary pattern string.
    pub pattern_string: String,
}

impl InstructionSearchPanelModel {
    /// Create a new panel model.
    pub fn new() -> Self {
        Self {
            mode: SearchPanelMode::default(),
            format: SearchFormat::default(),
            selection_mode: SelectionMode::default(),
            endian: DisplayEndian::default(),
            rows: Vec::new(),
            preview_results: Vec::new(),
            message: None,
            show_undefined: false,
            pattern_string: String::new(),
        }
    }

    /// Add an instruction row.
    pub fn add_row(&mut self, row: InstructionTableRow) {
        self.rows.push(row);
    }

    /// Remove a row.
    pub fn remove_row(&mut self, index: usize) -> Option<InstructionTableRow> {
        if index < self.rows.len() {
            Some(self.rows.remove(index))
        } else {
            None
        }
    }

    /// Toggle selection of a row.
    pub fn toggle_selection(&mut self, index: usize) {
        if let Some(row) = self.rows.get_mut(index) {
            row.selected = !row.selected;
        }
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

    /// Get selected rows.
    pub fn selected_rows(&self) -> Vec<&InstructionTableRow> {
        self.rows.iter().filter(|r| r.selected).collect()
    }

    /// Get selected count.
    pub fn selected_count(&self) -> usize {
        self.rows.iter().filter(|r| r.selected).count()
    }

    /// Build the combined mask/value from selected rows.
    pub fn build_pattern(&self) -> Vec<MaskContainer> {
        self.selected_rows()
            .iter()
            .map(|r| {
                let value = r.bytes.clone();
                let mask = vec![0xFFu8; value.len()];
                MaskContainer { mask, value }
            })
            .collect()
    }

    /// Get the total byte count of selected instructions.
    pub fn selected_byte_count(&self) -> usize {
        self.selected_rows().iter().map(|r| r.bytes.len()).sum()
    }

    /// Set a status message.
    pub fn set_message(&mut self, msg: impl Into<String>) {
        self.message = Some(msg.into());
    }

    /// Clear the message.
    pub fn clear_message(&mut self) {
        self.message = None;
    }

    /// Whether there are any rows.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Clear all data.
    pub fn clear(&mut self) {
        self.rows.clear();
        self.preview_results.clear();
        self.pattern_string.clear();
        self.message = None;
    }
}

impl Default for InstructionSearchPanelModel {
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
    use super::super::model::OperandMetadata;
    use ghidra_core::Address;

    fn sample_metadata(addr: u64) -> InstructionMetadata {
        InstructionMetadata {
            addr: Address::new(addr),
            mnemonic: "MOV".to_string(),
            is_instruction: true,
            mnemonic_masked: false,
            mask_container: MaskContainer {
                mask: vec![0xFF, 0xFF],
                value: vec![0x89, 0xE5],
            },
            operands: vec![
                OperandMetadata {
                    op_type: 1,
                    mask_container: Some(MaskContainer {
                        mask: vec![0x07],
                        value: vec![0x05],
                    }),
                    text_rep: "EBP".to_string(),
                    masked: false,
                },
            ],
        }
    }

    #[test]
    fn test_panel_mode_default() {
        assert_eq!(SearchPanelMode::default(), SearchPanelMode::BuildPattern);
    }

    #[test]
    fn test_selection_mode_default() {
        assert_eq!(SelectionMode::default(), SelectionMode::Individual);
    }

    #[test]
    fn test_display_endian_default() {
        assert_eq!(DisplayEndian::default(), DisplayEndian::Little);
    }

    #[test]
    fn test_instruction_table_row() {
        let row = InstructionTableRow::new(
            sample_metadata(0x1000),
            vec![0x89, 0xE5],
            0x1000,
            "MOV",
        );
        assert!(!row.selected);
        assert_eq!(row.address, 0x1000);
        assert_eq!(row.mnemonic, "MOV");
        assert_eq!(row.bytes.len(), 2);
    }

    #[test]
    fn test_panel_model_lifecycle() {
        let mut model = InstructionSearchPanelModel::new();
        assert!(model.is_empty());
        assert_eq!(model.mode, SearchPanelMode::BuildPattern);

        model.add_row(InstructionTableRow::new(
            sample_metadata(0x1000),
            vec![0x89, 0xE5],
            0x1000,
            "MOV",
        ));
        model.add_row(InstructionTableRow::new(
            sample_metadata(0x1002),
            vec![0x83, 0xEC],
            0x1002,
            "SUB",
        ));
        assert!(!model.is_empty());
        assert_eq!(model.rows.len(), 2);
    }

    #[test]
    fn test_panel_model_selection() {
        let mut model = InstructionSearchPanelModel::new();
        model.add_row(InstructionTableRow::new(sample_metadata(0x1000), vec![0x89, 0xE5], 0x1000, "MOV"));
        model.add_row(InstructionTableRow::new(sample_metadata(0x1002), vec![0x83, 0xEC], 0x1002, "SUB"));

        model.toggle_selection(0);
        assert_eq!(model.selected_count(), 1);

        model.select_all();
        assert_eq!(model.selected_count(), 2);

        model.deselect_all();
        assert_eq!(model.selected_count(), 0);
    }

    #[test]
    fn test_panel_model_build_pattern() {
        let mut model = InstructionSearchPanelModel::new();
        model.add_row(InstructionTableRow::new(sample_metadata(0x1000), vec![0x89, 0xE5], 0x1000, "MOV"));
        model.add_row(InstructionTableRow::new(sample_metadata(0x1002), vec![0x83, 0xEC], 0x1002, "SUB"));
        model.select_all();

        let pattern = model.build_pattern();
        assert_eq!(pattern.len(), 2);
        assert_eq!(pattern[0].value, vec![0x89, 0xE5]);
        assert_eq!(pattern[1].value, vec![0x83, 0xEC]);
    }

    #[test]
    fn test_panel_model_byte_count() {
        let mut model = InstructionSearchPanelModel::new();
        model.add_row(InstructionTableRow::new(sample_metadata(0x1000), vec![0x89, 0xE5], 0x1000, "MOV"));
        model.add_row(InstructionTableRow::new(sample_metadata(0x1002), vec![0x83, 0xEC, 0x04], 0x1002, "SUB"));
        model.select_all();
        assert_eq!(model.selected_byte_count(), 5);
    }

    #[test]
    fn test_panel_model_messages() {
        let mut model = InstructionSearchPanelModel::new();
        assert!(model.message.is_none());

        model.set_message("Found 3 matches");
        assert!(model.message.is_some());

        model.clear_message();
        assert!(model.message.is_none());
    }

    #[test]
    fn test_panel_model_remove_row() {
        let mut model = InstructionSearchPanelModel::new();
        model.add_row(InstructionTableRow::new(sample_metadata(0x1000), vec![0x89, 0xE5], 0x1000, "MOV"));
        model.add_row(InstructionTableRow::new(sample_metadata(0x1002), vec![0x83, 0xEC], 0x1002, "SUB"));

        let removed = model.remove_row(0);
        assert!(removed.is_some());
        assert_eq!(model.rows.len(), 1);
        assert_eq!(model.rows[0].address, 0x1002);
    }

    #[test]
    fn test_panel_model_clear() {
        let mut model = InstructionSearchPanelModel::new();
        model.add_row(InstructionTableRow::new(sample_metadata(0x1000), vec![0x89, 0xE5], 0x1000, "MOV"));
        model.set_message("test");

        model.clear();
        assert!(model.is_empty());
        assert!(model.message.is_none());
    }
}
