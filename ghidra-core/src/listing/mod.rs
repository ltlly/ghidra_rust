//! Listing (disassembly) model types for Ghidra Rust.
//!
//! Models Ghidra's `ghidra.program.model.listing` package, including
//! code unit types, comment types, flow overrides, variables, stack frames,
//! function tags, bookmarks, and the disassembly listing view.

pub mod auto_parameter_type;
pub mod bookmark_manager;
pub mod code_unit;
pub mod code_unit_iterator;
pub mod comment_history;
pub mod comment_type;
pub mod data;
pub mod flow_override;
pub mod function;
pub mod function_manager;
pub mod function_tag;
pub mod group;
pub mod instruction;
pub mod listing;
pub mod parameter;
pub mod program_fragment;
pub mod program_module;
pub mod stack_frame;
pub mod variable;
pub mod variable_filter;

use crate::addr::Address;
use serde::{Deserialize, Serialize};

// Re-export key types
pub use auto_parameter_type::AutoParameterType;
pub use bookmark_manager::{Bookmark, BookmarkManager, BookmarkType};
pub use code_unit::{CodeUnit, CodeUnitData, MNEMONIC};
pub use code_unit_iterator::{AddressCodeUnitIterator, CodeUnitIterator, DataIterator, InstructionIterator, IteratorDirection};
pub use comment_history::CommentHistory;
pub use comment_type::CommentType;
pub use data::Data;
pub use flow_override::FlowOverride;
pub use function::{Function, FunctionApi};
pub use function_manager::FunctionManager;
pub use function_tag::FunctionTag;
pub use group::{Group, GroupData};
pub use instruction::{FlowType, Instruction, Operand};
pub use listing::{CodeUnitComments, InMemoryListing, Listing};
pub use parameter::{FunctionUpdateType, Parameter, ParameterImpl};
pub use program_fragment::ProgramFragment;
pub use program_module::{CircularDependencyException, DuplicateGroupException, ProgramModule, ProgramModuleData};
pub use stack_frame::{StackFrame, StackFrameData, GROWS_NEGATIVE, GROWS_POSITIVE, UNKNOWN_PARAM_OFFSET};
pub use variable::{Variable, VariableData};
pub use variable_filter::{VariableFilter, filters};

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
