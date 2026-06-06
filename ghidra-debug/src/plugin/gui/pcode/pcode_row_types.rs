//! Pcode row data model types for the pcode stepper panel.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.pcode` package.
//! Provides the various row types displayed in the pcode stepper panel,
//! including op rows, branch rows, unique rows, and more.

use serde::{Deserialize, Serialize};

/// The kind of a pcode row in the stepper display.
///
/// Ported from Ghidra's `PcodeRow` type hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PcodeRowKind {
    /// An op pcode row (standard pcode operation).
    Op,
    /// A branch pcode row (conditional or unconditional branch).
    Branch,
    /// A fallthrough pcode row (sequential execution).
    Fallthrough,
    /// A unique space reference row.
    Unique,
    /// An enum (enumerated) pcode row.
    Enum,
}

/// An op pcode row displaying a single pcode operation.
///
/// Ported from Ghidra's `OpPcodeRow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpPcodeRow {
    /// The operation index.
    pub op_index: usize,
    /// The pcode opcode name (e.g., "INT_ADD", "STORE").
    pub opcode: String,
    /// The output varnode (if any).
    pub output: Option<VarnodeDisplay>,
    /// The input varnodes.
    pub inputs: Vec<VarnodeDisplay>,
    /// The display label for this op.
    pub label: String,
}

/// A branch pcode row displaying a branch operation.
///
/// Ported from Ghidra's `BranchPcodeRow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchPcodeRow {
    /// The operation index.
    pub op_index: usize,
    /// The branch target address.
    pub target: u64,
    /// Whether this is a conditional branch.
    pub is_conditional: bool,
    /// The branch condition varnode (if conditional).
    pub condition: Option<VarnodeDisplay>,
    /// The display label.
    pub label: String,
}

/// A fallthrough pcode row.
///
/// Ported from Ghidra's `FallthroughPcodeRow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallthroughPcodeRow {
    /// The operation index.
    pub op_index: usize,
    /// The fallthrough address.
    pub fallthrough_addr: u64,
    /// The display label.
    pub label: String,
}

/// A unique space reference row.
///
/// Ported from Ghidra's `UniqueRow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniqueRowData {
    /// The unique space offset.
    pub offset: u64,
    /// The size of the unique varnode.
    pub size: u16,
    /// The reference type (read, write, both).
    pub ref_type: UniqueRefType,
    /// The value stored in this unique location (if known).
    pub value: Option<u64>,
    /// The display label.
    pub label: String,
}

/// The reference type for a unique space access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UniqueRefType {
    /// Read access.
    Read,
    /// Write access.
    Write,
    /// Both read and write.
    ReadWrite,
}

/// An enum pcode row.
///
/// Ported from Ghidra's `EnumPcodeRow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumPcodeRow {
    /// The operation index.
    pub op_index: usize,
    /// The enum value.
    pub value: u64,
    /// The display label.
    pub label: String,
}

/// Display representation of a varnode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VarnodeDisplay {
    /// The address space name.
    pub space: String,
    /// The offset within the address space.
    pub offset: u64,
    /// The size in bytes.
    pub size: u16,
    /// A display-friendly representation.
    pub display: String,
}

impl VarnodeDisplay {
    /// Create a new varnode display.
    pub fn new(space: impl Into<String>, offset: u64, size: u16) -> Self {
        let s = space.into();
        let display = format!("{}:{:x}:{}", s, offset, size);
        Self {
            space: s,
            offset,
            size,
            display,
        }
    }

    /// Create a register varnode display.
    pub fn register(name: impl Into<String>, offset: u64, size: u16) -> Self {
        let name_str = name.into();
        Self {
            space: "register".into(),
            offset,
            size,
            display: name_str,
        }
    }

    /// Create a constant varnode display.
    pub fn constant(value: u64, size: u16) -> Self {
        Self {
            space: "const".into(),
            offset: value,
            size,
            display: format!("0x{:x}", value),
        }
    }

    /// Create a unique varnode display.
    pub fn unique(offset: u64, size: u16) -> Self {
        Self {
            space: "unique".into(),
            offset,
            size,
            display: format!("unique:{:x}", offset),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varnode_display() {
        let vn = VarnodeDisplay::new("register", 0x20, 8);
        assert_eq!(vn.space, "register");
        assert_eq!(vn.offset, 0x20);
        assert_eq!(vn.size, 8);
    }

    #[test]
    fn test_varnode_register() {
        let vn = VarnodeDisplay::register("RAX", 0, 8);
        assert_eq!(vn.space, "register");
        assert_eq!(vn.display, "RAX");
    }

    #[test]
    fn test_varnode_constant() {
        let vn = VarnodeDisplay::constant(0xDEAD, 4);
        assert_eq!(vn.space, "const");
        assert_eq!(vn.display, "0xdead");
    }

    #[test]
    fn test_varnode_unique() {
        let vn = VarnodeDisplay::unique(0x100, 8);
        assert_eq!(vn.space, "unique");
        assert!(vn.display.starts_with("unique:"));
    }

    #[test]
    fn test_op_pcode_row() {
        let row = OpPcodeRow {
            op_index: 0,
            opcode: "INT_ADD".into(),
            output: Some(VarnodeDisplay::register("RAX", 0, 8)),
            inputs: vec![
                VarnodeDisplay::register("RBX", 8, 8),
                VarnodeDisplay::constant(0x10, 8),
            ],
            label: "RAX = RBX + 0x10".into(),
        };
        assert_eq!(row.opcode, "INT_ADD");
        assert_eq!(row.inputs.len(), 2);
    }

    #[test]
    fn test_branch_pcode_row() {
        let row = BranchPcodeRow {
            op_index: 5,
            target: 0x401000,
            is_conditional: true,
            condition: Some(VarnodeDisplay::register("ZF", 0x38, 1)),
            label: "CBRANCH 0x401000 if ZF".into(),
        };
        assert!(row.is_conditional);
        assert_eq!(row.target, 0x401000);
    }

    #[test]
    fn test_fallthrough_row() {
        let row = FallthroughPcodeRow {
            op_index: 3,
            fallthrough_addr: 0x400010,
            label: "fallthrough".into(),
        };
        assert_eq!(row.fallthrough_addr, 0x400010);
    }

    #[test]
    fn test_unique_row() {
        let row = UniqueRowData {
            offset: 0x100,
            size: 8,
            ref_type: UniqueRefType::ReadWrite,
            value: Some(42),
            label: "unique:100".into(),
        };
        assert_eq!(row.ref_type, UniqueRefType::ReadWrite);
        assert_eq!(row.value, Some(42));
    }

    #[test]
    fn test_unique_ref_types() {
        assert_ne!(UniqueRefType::Read, UniqueRefType::Write);
        assert_ne!(UniqueRefType::Write, UniqueRefType::ReadWrite);
    }

    #[test]
    fn test_enum_row() {
        let row = EnumPcodeRow {
            op_index: 2,
            value: 0xFF,
            label: "ENUM 0xff".into(),
        };
        assert_eq!(row.value, 0xFF);
    }

    #[test]
    fn test_pcode_row_kinds() {
        assert_ne!(PcodeRowKind::Op, PcodeRowKind::Branch);
        assert_ne!(PcodeRowKind::Unique, PcodeRowKind::Enum);
    }

    #[test]
    fn test_serde_roundtrip() {
        let row = OpPcodeRow {
            op_index: 0,
            opcode: "STORE".into(),
            output: None,
            inputs: vec![VarnodeDisplay::constant(0, 8)],
            label: "STORE 0".into(),
        };
        let json = serde_json::to_string(&row).unwrap();
        let back: OpPcodeRow = serde_json::from_str(&json).unwrap();
        assert_eq!(back.opcode, "STORE");
    }
}
