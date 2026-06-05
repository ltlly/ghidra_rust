//! Code unit adapter for trace database listings.
//!
//! Ported from Ghidra's `DBTraceCodeUnitAdapter` and
//! `DBTraceCommentAdapter` in `ghidra.trace.database.listing`.
//! Provides adapters for code units (instructions and data) and
//! comments in the trace listing at a specific snapshot.

use serde::{Deserialize, Serialize};

/// Types of code units in the trace listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodeUnitKind {
    /// An instruction.
    Instruction,
    /// Defined data.
    Data,
    /// Undefined data.
    Undefined,
}

/// A code unit in the trace listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawCodeUnitAdapter {
    /// The address offset.
    pub address: u64,
    /// The address space.
    pub space: String,
    /// The snap.
    pub snap: i64,
    /// The kind of code unit.
    pub kind: CodeUnitKind,
    /// The size in bytes.
    pub size: usize,
    /// The mnemonic (for instructions) or data type name.
    pub mnemonic: String,
    /// The raw bytes.
    pub bytes: Vec<u8>,
}

impl RawCodeUnitAdapter {
    /// Create an instruction code unit.
    pub fn instruction(
        address: u64,
        space: impl Into<String>,
        snap: i64,
        mnemonic: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Self {
        let size = bytes.len();
        Self {
            address,
            space: space.into(),
            snap,
            kind: CodeUnitKind::Instruction,
            size,
            mnemonic: mnemonic.into(),
            bytes,
        }
    }

    /// Create a data code unit.
    pub fn data(
        address: u64,
        space: impl Into<String>,
        snap: i64,
        data_type: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Self {
        let size = bytes.len();
        Self {
            address,
            space: space.into(),
            snap,
            kind: CodeUnitKind::Data,
            size,
            mnemonic: data_type.into(),
            bytes,
        }
    }

    /// Create an undefined code unit.
    pub fn undefined(address: u64, space: impl Into<String>, snap: i64) -> Self {
        Self {
            address,
            space: space.into(),
            snap,
            kind: CodeUnitKind::Undefined,
            size: 1,
            mnemonic: "??".to_string(),
            bytes: Vec::new(),
        }
    }

    /// Get the minimum address.
    pub fn min_address(&self) -> u64 {
        self.address
    }

    /// Get the maximum address.
    pub fn max_address(&self) -> u64 {
        self.address + self.size as u64 - 1
    }

    /// Check if this is an instruction.
    pub fn is_instruction(&self) -> bool {
        self.kind == CodeUnitKind::Instruction
    }

    /// Check if this is data.
    pub fn is_data(&self) -> bool {
        self.kind == CodeUnitKind::Data
    }

    /// Check if this is undefined.
    pub fn is_undefined(&self) -> bool {
        self.kind == CodeUnitKind::Undefined
    }
}

/// Types of comments in the trace listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommentType {
    /// End-of-line comment.
    Eol,
    /// Pre-comment (above).
    Pre,
    /// Post-comment (below).
    Post,
    /// Plate comment (section header).
    Plate,
    /// Repeatable comment.
    Repeatable,
}

/// A comment in the trace listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawCommentAdapter {
    /// The address offset.
    pub address: u64,
    /// The address space.
    pub space: String,
    /// The snap.
    pub snap: i64,
    /// The comment type.
    pub comment_type: CommentType,
    /// The comment text.
    pub text: String,
}

impl RawCommentAdapter {
    /// Create a new comment.
    pub fn new(
        address: u64,
        space: impl Into<String>,
        snap: i64,
        comment_type: CommentType,
        text: impl Into<String>,
    ) -> Self {
        Self {
            address,
            space: space.into(),
            snap,
            comment_type,
            text: text.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_code_unit() {
        let cu = RawCodeUnitAdapter::instruction(0x1000, "ram", 0, "MOV", vec![0x48, 0x89, 0xE5]);
        assert!(cu.is_instruction());
        assert!(!cu.is_data());
        assert_eq!(cu.size, 3);
        assert_eq!(cu.mnemonic, "MOV");
    }

    #[test]
    fn test_data_code_unit() {
        let cu = RawCodeUnitAdapter::data(0x2000, "ram", 0, "dword", vec![1, 2, 3, 4]);
        assert!(cu.is_data());
        assert_eq!(cu.size, 4);
    }

    #[test]
    fn test_undefined_code_unit() {
        let cu = RawCodeUnitAdapter::undefined(0x3000, "ram", 0);
        assert!(cu.is_undefined());
        assert_eq!(cu.mnemonic, "??");
    }

    #[test]
    fn test_code_unit_address_range() {
        let cu = RawCodeUnitAdapter::instruction(0x100, "ram", 0, "NOP", vec![0x90]);
        assert_eq!(cu.min_address(), 0x100);
        assert_eq!(cu.max_address(), 0x100);
    }

    #[test]
    fn test_comment_adapter() {
        let c = RawCommentAdapter::new(0x1000, "ram", 0, CommentType::Plate, "Main function");
        assert_eq!(c.text, "Main function");
        assert_eq!(c.comment_type, CommentType::Plate);
    }

    #[test]
    fn test_comment_types() {
        let c1 = RawCommentAdapter::new(0, "ram", 0, CommentType::Eol, "");
        let c2 = RawCommentAdapter::new(0, "ram", 0, CommentType::Pre, "");
        assert_ne!(c1.comment_type, c2.comment_type);
    }
}
