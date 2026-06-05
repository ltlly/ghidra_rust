//! Extended pcode row types for the debugger pcode stepper GUI.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.pcode` package.
//! Provides row types for different kinds of pcode operations displayed
//! in the pcode stepper panel.

/// Kind of pcode row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcodeExtendedRowKind {
    /// An operation (arithmetic, logic, etc.).
    Operation,
    /// A branch instruction.
    Branch,
    /// A fallthrough (sequential) instruction.
    Fallthrough,
    /// A unique (temporary) varnode.
    Unique,
    /// An enumerated constant.
    Enum,
}

/// A branch pcode row.
///
/// Corresponds to Java's `BranchPcodeRow`.
#[derive(Debug, Clone)]
pub struct BranchPcodeRow {
    /// The pcode operation mnemonic.
    pub mnemonic: String,
    /// Branch target address.
    pub target: u64,
    /// Whether the branch is conditional.
    pub is_conditional: bool,
    /// Whether the branch was taken.
    pub taken: bool,
    /// The source address.
    pub source_address: u64,
}

impl BranchPcodeRow {
    /// Create a new branch pcode row.
    pub fn new(
        mnemonic: impl Into<String>,
        target: u64,
        is_conditional: bool,
        source_address: u64,
    ) -> Self {
        Self {
            mnemonic: mnemonic.into(),
            target,
            is_conditional,
            taken: false,
            source_address,
        }
    }
}

/// A fallthrough pcode row.
///
/// Corresponds to Java's `FallthroughPcodeRow`.
#[derive(Debug, Clone)]
pub struct FallthroughPcodeRow {
    /// The pcode operation mnemonic.
    pub mnemonic: String,
    /// The source address.
    pub address: u64,
    /// Output varnode, if any.
    pub output: Option<String>,
}

impl FallthroughPcodeRow {
    /// Create a new fallthrough row.
    pub fn new(mnemonic: impl Into<String>, address: u64) -> Self {
        Self {
            mnemonic: mnemonic.into(),
            address,
            output: None,
        }
    }
}

/// A unique varnode pcode row.
///
/// Corresponds to Java's `UniqueRow`.
#[derive(Debug, Clone)]
pub struct UniqueRow {
    /// Unique varnode ID.
    pub unique_id: u64,
    /// Size in bytes.
    pub size: u32,
    /// Current value.
    pub value: Vec<u8>,
    /// The address where this unique varnode was defined.
    pub definition_address: u64,
}

impl UniqueRow {
    /// Create a new unique varnode row.
    pub fn new(unique_id: u64, size: u32, value: Vec<u8>, definition_address: u64) -> Self {
        Self {
            unique_id,
            size,
            value,
            definition_address,
        }
    }

    /// Get the value as a hex string.
    pub fn value_hex(&self) -> String {
        self.value.iter().map(|b| format!("{:02X}", b)).collect()
    }
}

/// An operation pcode row.
///
/// Corresponds to Java's `OpPcodeRow`.
#[derive(Debug, Clone)]
pub struct OpPcodeRow {
    /// The pcode operation mnemonic.
    pub mnemonic: String,
    /// Input varnodes.
    pub inputs: Vec<String>,
    /// Output varnode.
    pub output: Option<String>,
    /// The address.
    pub address: u64,
}

impl OpPcodeRow {
    /// Create a new operation row.
    pub fn new(
        mnemonic: impl Into<String>,
        address: u64,
    ) -> Self {
        Self {
            mnemonic: mnemonic.into(),
            inputs: Vec::new(),
            output: None,
            address,
        }
    }
}

/// An enum constant pcode row.
///
/// Corresponds to Java's `EnumPcodeRow`.
#[derive(Debug, Clone)]
pub struct EnumPcodeRow {
    /// The enum type name.
    pub enum_type: String,
    /// The enum value.
    pub value: u64,
    /// The display name of the value.
    pub display_name: String,
    /// Address where this value was read.
    pub address: u64,
}

impl EnumPcodeRow {
    /// Create a new enum row.
    pub fn new(
        enum_type: impl Into<String>,
        value: u64,
        display_name: impl Into<String>,
        address: u64,
    ) -> Self {
        Self {
            enum_type: enum_type.into(),
            value,
            display_name: display_name.into(),
            address,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_branch_pcode_row() {
        let row = BranchPcodeRow::new("CBRANCH", 0x400100, true, 0x400000);
        assert_eq!(row.mnemonic, "CBRANCH");
        assert_eq!(row.target, 0x400100);
        assert!(row.is_conditional);
        assert!(!row.taken);
    }

    #[test]
    fn test_fallthrough_pcode_row() {
        let row = FallthroughPcodeRow::new("INT_ADD", 0x400010);
        assert_eq!(row.mnemonic, "INT_ADD");
        assert!(row.output.is_none());
    }

    #[test]
    fn test_unique_row() {
        let row = UniqueRow::new(0x1000, 8, vec![0x42; 8], 0x400000);
        assert_eq!(row.value_hex(), "4242424242424242");
        assert_eq!(row.size, 8);
    }

    #[test]
    fn test_op_pcode_row() {
        let mut row = OpPcodeRow::new("STORE", 0x400020);
        row.inputs.push("register".to_string());
        row.inputs.push("0x400100".to_string());
        row.output = Some("ram:0x400100".to_string());
        assert_eq!(row.inputs.len(), 2);
    }

    #[test]
    fn test_enum_pcode_row() {
        let row = EnumPcodeRow::new("SignalType", 9, "SIGKILL", 0x400050);
        assert_eq!(row.enum_type, "SignalType");
        assert_eq!(row.value, 9);
        assert_eq!(row.display_name, "SIGKILL");
    }

    #[test]
    fn test_row_kinds() {
        assert_ne!(PcodeExtendedRowKind::Operation, PcodeExtendedRowKind::Branch);
        assert_ne!(PcodeExtendedRowKind::Unique, PcodeExtendedRowKind::Enum);
    }
}
