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

// ---------------------------------------------------------------------------
// UniqueRow: displays unique-space varnode values during p-code stepping
// ---------------------------------------------------------------------------

/// How a unique-space varnode is referenced by the currently selected p-code op.
///
/// Ported from Ghidra's `UniqueRow.RefType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UniqueRefType {
    /// Not referenced by the selected op.
    None,
    /// Read by the selected op.
    Read,
    /// Written by the selected op.
    Write,
    /// Both read and written.
    ReadWrite,
}

impl UniqueRefType {
    /// Determine the ref type from read/write flags.
    pub fn from_rw(is_read: bool, is_write: bool) -> Self {
        match (is_read, is_write) {
            (true, true) => Self::ReadWrite,
            (true, false) => Self::Read,
            (false, true) => Self::Write,
            (false, false) => Self::None,
        }
    }
}

/// A row in the unique space table, representing a unique varnode's value.
///
/// Ported from Ghidra's `UniqueRow`. Displays unique-space intermediate
/// values during p-code stepping. Each row represents a unique varnode
/// with its current value (if concrete) and optional data type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniqueRow {
    /// The varnode's address offset in the unique space.
    pub offset: u64,
    /// The varnode size in bytes.
    pub size: u32,
    /// The concrete bytes, if the value can be resolved.
    pub bytes: Option<Vec<u8>>,
    /// The display name (e.g., "$U100:4").
    pub name: String,
    /// How this varnode is referenced by the selected op.
    pub ref_type: UniqueRefType,
    /// The optional data type for display formatting.
    pub data_type: Option<String>,
    /// Whether this row is currently highlighted.
    pub highlighted: bool,
}

impl UniqueRow {
    /// Create a new unique row.
    pub fn new(offset: u64, size: u32) -> Self {
        Self {
            offset,
            size,
            bytes: None,
            name: format!("$U{:x}:{}", offset, size),
            ref_type: UniqueRefType::None,
            data_type: None,
            highlighted: false,
        }
    }

    /// Set the concrete bytes.
    pub fn with_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.bytes = Some(bytes);
        self
    }

    /// Set the data type for display.
    pub fn with_data_type(mut self, data_type: impl Into<String>) -> Self {
        self.data_type = Some(data_type.into());
        self
    }

    /// Set the reference type.
    pub fn with_ref_type(mut self, ref_type: UniqueRefType) -> Self {
        self.ref_type = ref_type;
        self
    }

    /// Get the display string for the bytes (hex formatted).
    pub fn bytes_display(&self) -> String {
        match &self.bytes {
            Some(bytes) => {
                if bytes.len() > 20 {
                    let prefix: Vec<String> = bytes[..20].iter().map(|b| format!("{:02x}", b)).collect();
                    format!("{} ...", prefix.join(" "))
                } else {
                    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
                }
            }
            None => "(not concrete)".to_string(),
        }
    }

    /// Get the value as an unsigned integer (if concrete and <= 16 bytes).
    pub fn value_as_u64(&self) -> Option<u64> {
        let bytes = self.bytes.as_ref()?;
        if bytes.len() > 8 || bytes.is_empty() {
            return None;
        }
        let mut val = 0u64;
        for (i, b) in bytes.iter().enumerate() {
            val |= (*b as u64) << (i * 8);
        }
        Some(val)
    }

    /// Whether the varnode overlaps with another.
    pub fn overlaps(&self, other_offset: u64, other_size: u32) -> bool {
        let self_end = self.offset + self.size as u64;
        let other_end = other_offset + other_size as u64;
        self.offset < other_end && other_offset < self_end
    }
}

/// The model for the unique space table display.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UniqueTableModel {
    /// The unique rows.
    pub rows: Vec<UniqueRow>,
}

impl UniqueTableModel {
    /// Create an empty model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a unique row.
    pub fn add_row(&mut self, row: UniqueRow) {
        self.rows.push(row);
    }

    /// Get all rows.
    pub fn rows(&self) -> &[UniqueRow] {
        &self.rows
    }

    /// The number of rows.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether there are no rows.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Find a row by offset and size.
    pub fn find_by_varnode(&self, offset: u64, size: u32) -> Option<&UniqueRow> {
        self.rows.iter().find(|r| r.offset == offset && r.size == size)
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

    #[test]
    fn test_unique_ref_type() {
        assert_eq!(UniqueRefType::from_rw(true, true), UniqueRefType::ReadWrite);
        assert_eq!(UniqueRefType::from_rw(true, false), UniqueRefType::Read);
        assert_eq!(UniqueRefType::from_rw(false, true), UniqueRefType::Write);
        assert_eq!(UniqueRefType::from_rw(false, false), UniqueRefType::None);
    }

    #[test]
    fn test_unique_row_creation() {
        let row = UniqueRow::new(0x100, 4);
        assert_eq!(row.offset, 0x100);
        assert_eq!(row.size, 4);
        assert_eq!(row.name, "$U100:4");
        assert!(row.bytes.is_none());
        assert_eq!(row.ref_type, UniqueRefType::None);
    }

    #[test]
    fn test_unique_row_bytes_display() {
        let row = UniqueRow::new(0x100, 4).with_bytes(vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(row.bytes_display(), "de ad be ef");
    }

    #[test]
    fn test_unique_row_bytes_display_truncated() {
        let bytes: Vec<u8> = (0..30).collect();
        let row = UniqueRow::new(0x100, 30).with_bytes(bytes);
        let display = row.bytes_display();
        assert!(display.ends_with("..."));
    }

    #[test]
    fn test_unique_row_bytes_display_not_concrete() {
        let row = UniqueRow::new(0x100, 4);
        assert_eq!(row.bytes_display(), "(not concrete)");
    }

    #[test]
    fn test_unique_row_value_as_u64() {
        let row = UniqueRow::new(0x100, 4).with_bytes(vec![0x42, 0x00, 0x00, 0x00]);
        assert_eq!(row.value_as_u64(), Some(0x42));
    }

    #[test]
    fn test_unique_row_value_as_u64_none() {
        let row = UniqueRow::new(0x100, 4); // No bytes
        assert_eq!(row.value_as_u64(), None);
    }

    #[test]
    fn test_unique_row_overlaps() {
        let row = UniqueRow::new(0x100, 4);
        assert!(row.overlaps(0x102, 4)); // Overlapping
        assert!(row.overlaps(0x100, 4)); // Same
        assert!(!row.overlaps(0x200, 4)); // No overlap
        assert!(!row.overlaps(0x104, 4)); // Adjacent, no overlap
    }

    #[test]
    fn test_unique_row_with_ref_type() {
        let row = UniqueRow::new(0x100, 4).with_ref_type(UniqueRefType::Write);
        assert_eq!(row.ref_type, UniqueRefType::Write);
    }

    #[test]
    fn test_unique_row_with_data_type() {
        let row = UniqueRow::new(0x100, 4).with_data_type("uint");
        assert_eq!(row.data_type.as_deref(), Some("uint"));
    }

    #[test]
    fn test_unique_table_model() {
        let mut model = UniqueTableModel::new();
        assert!(model.is_empty());

        model.add_row(UniqueRow::new(0x100, 4));
        model.add_row(UniqueRow::new(0x200, 8));
        assert_eq!(model.len(), 2);
    }

    #[test]
    fn test_unique_table_model_find() {
        let mut model = UniqueTableModel::new();
        model.add_row(UniqueRow::new(0x100, 4));
        model.add_row(UniqueRow::new(0x200, 8));

        assert!(model.find_by_varnode(0x100, 4).is_some());
        assert!(model.find_by_varnode(0x300, 4).is_none());
    }

    #[test]
    fn test_unique_row_serde() {
        let row = UniqueRow::new(0x100, 4)
            .with_bytes(vec![0xaa, 0xbb, 0xcc, 0xdd])
            .with_ref_type(UniqueRefType::Read);
        let json = serde_json::to_string(&row).unwrap();
        let back: UniqueRow = serde_json::from_str(&json).unwrap();
        assert_eq!(back.offset, 0x100);
        assert_eq!(back.size, 4);
        assert_eq!(back.ref_type, UniqueRefType::Read);
    }
}
