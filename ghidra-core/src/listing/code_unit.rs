//! Code unit types and constants for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.listing.CodeUnit`.
//!
//! A code unit is the common interface between instructions and data in a
//! program listing. This module defines the [`CodeUnit`] trait and its
//! associated constants.

use crate::addr::Address;

/// Indicator for a mnemonic (versus an operand).
pub const MNEMONIC: i32 = -1;

// Comment type constants (deprecated in Ghidra 11.4+, use CommentType enum)
/// End-of-line comment type (deprecated, use `CommentType::Eol`).
#[deprecated(since = "11.4", note = "use CommentType::Eol")]
pub const EOL_COMMENT: u32 = 0;
/// Pre-comment type (deprecated, use `CommentType::Pre`).
#[deprecated(since = "11.4", note = "use CommentType::Pre")]
pub const PRE_COMMENT: u32 = 1;
/// Post-comment type (deprecated, use `CommentType::Post`).
#[deprecated(since = "11.4", note = "use CommentType::Post")]
pub const POST_COMMENT: u32 = 2;
/// Plate comment type (deprecated, use `CommentType::Plate`).
#[deprecated(since = "11.4", note = "use CommentType::Plate")]
pub const PLATE_COMMENT: u32 = 3;
/// Repeatable comment type (deprecated, use `CommentType::Repeatable`).
#[deprecated(since = "11.4", note = "use CommentType::Repeatable")]
pub const REPEATABLE_COMMENT: u32 = 4;

// Property name constants
/// Property name for any comment.
pub const COMMENT_PROPERTY: &str = "COMMENT__GHIDRA_";
/// Property name for vertical space formatting.
pub const SPACE_PROPERTY: &str = "Space";
/// Property name for code units that are instructions.
pub const INSTRUCTION_PROPERTY: &str = "INSTRUCTION__GHIDRA_";
/// Property name for code units that are defined data.
pub const DEFINED_DATA_PROPERTY: &str = "DEFINED_DATA__GHIDRA_";

/// The common interface between instructions and data.
///
/// Corresponds to `ghidra.program.model.listing.CodeUnit`. A code unit
/// represents a contiguous range of bytes in a program's memory that is
/// treated as a single logical unit -- either an instruction or a data item.
pub trait CodeUnit {
    /// Get the string representation of the starting address.
    ///
    /// `show_block_name` controls whether the memory block name is included.
    /// `pad` controls whether the address is zero-padded.
    fn get_address_string(&self, show_block_name: bool, pad: bool) -> String;

    /// Returns the label for this code unit.
    fn get_label(&self) -> Option<String>;

    /// Returns the starting (minimum) address for this code unit.
    fn get_min_address(&self) -> &Address;

    /// Returns the ending (maximum) address for this code unit.
    fn get_max_address(&self) -> &Address;

    /// Returns the mnemonic string (e.g., "MOV", "JMP", ".word").
    fn get_mnemonic_string(&self) -> &str;

    /// Returns the length of this code unit in bytes.
    fn get_length(&self) -> usize;

    /// Returns the bytes that make up this code unit.
    fn get_bytes(&self) -> &[u8];

    /// Returns the comment of the given type, or `None` if no comment exists.
    fn get_comment(&self, comment_type: crate::listing::CommentType) -> Option<&str>;

    /// Returns the comment of the given type as an array of lines.
    fn get_comment_as_array(&self, comment_type: crate::listing::CommentType) -> Vec<String>;

    /// Returns `true` if this code unit is an instruction (as opposed to data).
    fn is_instruction(&self) -> bool;

    /// Returns `true` if this code unit is defined data.
    fn is_data(&self) -> bool;

    /// Returns the address set that this code unit occupies.
    fn get_address_set(&self) -> crate::addr::AddressSet {
        let mut set = crate::addr::AddressSet::new();
        set.add_range(*self.get_min_address(), *self.get_max_address());
        set
    }
}

/// Data for a code unit (concrete struct for cases where a trait object is needed).
#[derive(Debug, Clone)]
pub struct CodeUnitData {
    /// The start address.
    pub address: Address,
    /// The bytes of this code unit.
    pub bytes: Vec<u8>,
    /// The mnemonic string.
    pub mnemonic: String,
    /// Optional label.
    pub label: Option<String>,
    /// Whether this is an instruction.
    pub is_instruction: bool,
}

impl CodeUnitData {
    /// Creates a new code unit data.
    pub fn new(
        address: Address,
        bytes: Vec<u8>,
        mnemonic: impl Into<String>,
        is_instruction: bool,
    ) -> Self {
        Self {
            address,
            bytes,
            mnemonic: mnemonic.into(),
            label: None,
            is_instruction,
        }
    }

    /// Sets the label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}
