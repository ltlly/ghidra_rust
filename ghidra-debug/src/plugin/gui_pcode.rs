//! Pcode stepper UI types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.pcode` package.
//! Provides data model types for the p-code stepper panel, which displays
//! individual p-code operations for a given instruction.

use serde::{Deserialize, Serialize};

/// The kind of a p-code row in the stepper display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PcodeRowKind {
    /// A regular p-code operation.
    Op,
    /// A branch target row.
    Branch,
    /// A fallthrough row.
    Fallthrough,
    /// An enum (lookup) row.
    Enum,
    /// A unique space reference row.
    Unique,
}

/// A single p-code operation row for display.
///
/// Ported from Ghidra's `PcodeRow` and its subclasses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeRow {
    /// The kind of row.
    pub kind: PcodeRowKind,
    /// The p-code operation mnemonic (e.g., "INT_ADD", "STORE", "CBRANCH").
    pub mnemonic: String,
    /// The raw p-code op number.
    pub op_number: u32,
    /// The sequence number within the instruction.
    pub seq_num: u32,
    /// Input varnodes (offset, size pairs).
    pub inputs: Vec<PcodeVarnode>,
    /// Output varnode, if any.
    pub output: Option<PcodeVarnode>,
    /// The target address for branch/fallthrough rows.
    pub target_address: Option<u64>,
    /// Whether this row is currently selected.
    pub selected: bool,
}

impl PcodeRow {
    /// Create a new p-code row.
    pub fn new(kind: PcodeRowKind, mnemonic: impl Into<String>, op_number: u32, seq_num: u32) -> Self {
        Self {
            kind,
            mnemonic: mnemonic.into(),
            op_number,
            seq_num,
            inputs: Vec::new(),
            output: None,
            target_address: None,
            selected: false,
        }
    }

    /// Add an input varnode.
    pub fn with_input(mut self, offset: u64, size: u32) -> Self {
        self.inputs.push(PcodeVarnode { offset, size });
        self
    }

    /// Set the output varnode.
    pub fn with_output(mut self, offset: u64, size: u32) -> Self {
        self.output = Some(PcodeVarnode { offset, size });
        self
    }

    /// Set the target address.
    pub fn with_target(mut self, addr: u64) -> Self {
        self.target_address = Some(addr);
        self
    }

    /// Mark as selected.
    pub fn select(mut self) -> Self {
        self.selected = true;
        self
    }

    /// Whether this is a branch operation.
    pub fn is_branch(&self) -> bool {
        self.kind == PcodeRowKind::Branch
    }

    /// Whether this is a fallthrough operation.
    pub fn is_fallthrough(&self) -> bool {
        self.kind == PcodeRowKind::Fallthrough
    }

    /// A display string for this row.
    pub fn display_string(&self) -> String {
        let mut s = format!("{} {}", self.seq_num, self.mnemonic);
        for input in &self.inputs {
            s.push_str(&format!(" [0x{:x}:{}]", input.offset, input.size));
        }
        if let Some(out) = &self.output {
            s.push_str(&format!(" -> [0x{:x}:{}]", out.offset, out.size));
        }
        if let Some(target) = self.target_address {
            s.push_str(&format!(" @ 0x{:x}", target));
        }
        s
    }
}

/// A varnode (variable-sized node) in p-code.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PcodeVarnode {
    /// The offset (register offset, stack offset, or address).
    pub offset: u64,
    /// The size in bytes.
    pub size: u32,
}

impl PcodeVarnode {
    /// Create a new varnode.
    pub fn new(offset: u64, size: u32) -> Self {
        Self { offset, size }
    }

    /// A display string.
    pub fn display(&self) -> String {
        format!("[0x{:x}:{}]", self.offset, self.size)
    }
}

/// The model for the p-code stepper panel.
///
/// Contains the list of p-code operations for the currently displayed
/// instruction.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PcodeStepperModel {
    /// The address of the instruction being displayed.
    pub instruction_address: u64,
    /// The raw instruction bytes.
    pub instruction_bytes: Vec<u8>,
    /// The p-code rows.
    pub rows: Vec<PcodeRow>,
    /// The currently selected row index.
    pub selected_index: Option<usize>,
}

impl PcodeStepperModel {
    /// Create a new empty stepper model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the instruction being displayed.
    pub fn set_instruction(&mut self, address: u64, bytes: Vec<u8>) {
        self.instruction_address = address;
        self.instruction_bytes = bytes;
        self.rows.clear();
        self.selected_index = None;
    }

    /// Add a p-code row.
    pub fn add_row(&mut self, row: PcodeRow) {
        self.rows.push(row);
    }

    /// Select a row by index.
    pub fn select(&mut self, index: usize) {
        if index < self.rows.len() {
            self.selected_index = Some(index);
        }
    }

    /// Get the selected row.
    pub fn selected_row(&self) -> Option<&PcodeRow> {
        self.selected_index.and_then(|i| self.rows.get(i))
    }

    /// The number of rows.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether there are no rows.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcode_row_display() {
        let row = PcodeRow::new(PcodeRowKind::Op, "INT_ADD", 1, 0)
            .with_input(0, 8)
            .with_input(8, 8)
            .with_output(16, 8);

        let display = row.display_string();
        assert!(display.contains("INT_ADD"));
        assert!(display.contains("[0x0:8]"));
        assert!(display.contains("-> [0x10:8]"));
    }

    #[test]
    fn test_pcode_row_branch() {
        let row = PcodeRow::new(PcodeRowKind::Branch, "CBRANCH", 3, 2)
            .with_target(0x400100);
        assert!(row.is_branch());
        assert_eq!(row.target_address, Some(0x400100));
    }

    #[test]
    fn test_stepper_model() {
        let mut model = PcodeStepperModel::new();
        model.set_instruction(0x400000, vec![0x55, 0x48, 0x89, 0xe5]);

        model.add_row(PcodeRow::new(PcodeRowKind::Op, "COPY", 0, 0));
        model.add_row(PcodeRow::new(PcodeRowKind::Op, "INT_ADD", 1, 1));
        model.add_row(
            PcodeRow::new(PcodeRowKind::Fallthrough, "BRANCH", 2, 2)
                .with_target(0x400004),
        );

        assert_eq!(model.len(), 3);
        assert!(model.is_empty() == false);

        model.select(1);
        let selected = model.selected_row().unwrap();
        assert_eq!(selected.mnemonic, "INT_ADD");
    }

    #[test]
    fn test_varnode_display() {
        let vn = PcodeVarnode::new(0x7fff0000, 4);
        assert_eq!(vn.display(), "[0x7fff0000:4]");
    }

    #[test]
    fn test_select_out_of_bounds() {
        let mut model = PcodeStepperModel::new();
        model.add_row(PcodeRow::new(PcodeRowKind::Op, "NOP", 0, 0));
        model.select(5); // out of bounds
        assert!(model.selected_row().is_none());
    }

    #[test]
    fn test_stepper_model_serde() {
        let mut model = PcodeStepperModel::new();
        model.set_instruction(0x400000, vec![0x90]);
        model.add_row(PcodeRow::new(PcodeRowKind::Op, "NOP", 0, 0));

        let json = serde_json::to_string(&model).unwrap();
        let back: PcodeStepperModel = serde_json::from_str(&json).unwrap();
        assert_eq!(back.instruction_address, 0x400000);
        assert_eq!(back.len(), 1);
    }
}
