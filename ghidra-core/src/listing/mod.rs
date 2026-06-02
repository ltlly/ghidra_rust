//! Listing (disassembly) row types for Ghidra Rust.
//!
//! Models the rows shown in a disassembly listing view, including addresses,
//! bytes, mnemonics, operands, and comments.

use crate::addr::Address;
use serde::{Deserialize, Serialize};

/// The mnemonic part of an instruction (e.g., "mov", "call", "push").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionMnemonic {
    /// The raw mnemonic string.
    pub text: String,
}

impl InstructionMnemonic {
    pub fn new(text: impl Into<String>) -> Self {
        Self { text: text.into() }
    }
}

/// A single row in the disassembly listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListingRow {
    /// The address of this instruction.
    pub address: Address,
    /// The raw bytes of the instruction (up to 16 bytes typically).
    pub bytes: Vec<u8>,
    /// Optional label at this address.
    pub label: Option<String>,
    /// The instruction mnemonic.
    pub mnemonic: InstructionMnemonic,
    /// The operand string (e.g., "rax, 0x42").
    pub operands: String,
    /// The full instruction string.
    pub full_instruction: String,
    /// Optional comment on this line.
    pub comment: Option<String>,
}

impl ListingRow {
    pub fn new(
        address: Address,
        bytes: Vec<u8>,
        mnemonic: impl Into<String>,
        operands: impl Into<String>,
    ) -> Self {
        let mnem = mnemonic.into();
        let ops = operands.into();
        let full = if ops.is_empty() {
            mnem.clone()
        } else {
            format!("{} {}", mnem, ops)
        };
        Self {
            address,
            bytes,
            label: None,
            mnemonic: InstructionMnemonic::new(mnem),
            operands: ops,
            full_instruction: full,
            comment: None,
        }
    }
}

/// Which columns to show in the listing view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListingColumns {
    pub show_address: bool,
    pub show_bytes: bool,
    pub show_label: bool,
    pub show_mnemonic: bool,
    pub show_operands: bool,
    pub show_xrefs: bool,
    pub show_comment: bool,
}

impl Default for ListingColumns {
    fn default() -> Self {
        Self {
            show_address: true,
            show_bytes: true,
            show_label: true,
            show_mnemonic: true,
            show_operands: true,
            show_xrefs: true,
            show_comment: true,
        }
    }
}
