//! UI actions for assembly patching.
//!
//! Corresponds to Java's `ghidra.app.plugin.core.assembler`.
//!
//! These actions provide the interactive user-facing assembly
//! patching experience.  In the full Ghidra GUI, these are
//! registered as docking actions with keyboard shortcuts (e.g.,
//! Ctrl+Shift+G for instruction patching).
//!
//! Since this Rust port does not include the full GUI framework,
//! the actions are represented as data structures describing
//! their behaviour rather than as interactive Swing components.

use crate::base::analyzer::core::Address;

// ---------------------------------------------------------------------------
// PatchAction
// ---------------------------------------------------------------------------

/// The type of patch operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchActionType {
    /// Patch a single instruction at the current address.
    PatchInstruction,
    /// Patch raw data bytes at the current address.
    PatchData,
}

impl std::fmt::Display for PatchActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PatchInstruction => write!(f, "Patch Instruction"),
            Self::PatchData => write!(f, "Patch Data"),
        }
    }
}

// ---------------------------------------------------------------------------
// PatchRequest
// ---------------------------------------------------------------------------

/// A request to patch bytes at a specific address.
///
/// This represents the result of a user's interaction with the
/// assembly patching UI -- they have selected an address and
/// provided assembly text (or raw data), and the request captures
/// what should be written.
#[derive(Debug, Clone)]
pub struct PatchRequest {
    /// The type of patch.
    pub action_type: PatchActionType,
    /// The address where the patch should be applied.
    pub address: Address,
    /// The original bytes that will be overwritten (for undo).
    pub original_bytes: Vec<u8>,
    /// The new bytes to write.
    pub new_bytes: Vec<u8>,
    /// The assembly text that produced the new bytes (for instruction patches).
    pub assembly_text: Option<String>,
}

impl PatchRequest {
    /// Create a new instruction patch request.
    pub fn instruction(
        address: Address,
        original_bytes: Vec<u8>,
        new_bytes: Vec<u8>,
        assembly_text: impl Into<String>,
    ) -> Self {
        Self {
            action_type: PatchActionType::PatchInstruction,
            address,
            original_bytes,
            new_bytes,
            assembly_text: Some(assembly_text.into()),
        }
    }

    /// Create a new data patch request.
    pub fn data(address: Address, original_bytes: Vec<u8>, new_bytes: Vec<u8>) -> Self {
        Self {
            action_type: PatchActionType::PatchData,
            address,
            original_bytes,
            new_bytes,
            assembly_text: None,
        }
    }

    /// Get the number of bytes being patched.
    pub fn patch_length(&self) -> usize {
        self.new_bytes.len()
    }

    /// Check if the patch changes the number of bytes at the address.
    pub fn changes_size(&self) -> bool {
        self.original_bytes.len() != self.new_bytes.len()
    }
}

// ---------------------------------------------------------------------------
// AssemblyRating
// ---------------------------------------------------------------------------

/// Quality rating for a processor's assembler support.
///
/// Corresponds to Java's `PatchInstructionAction.AssemblyRating`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AssemblyRating {
    /// Not yet tested.
    Unrated,
    /// Known to have poor support.
    Poor,
    /// Functional but with known issues.
    Fair,
    /// Well-tested and reliable.
    Good,
}

impl AssemblyRating {
    /// Get the human-readable description for this rating.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Unrated => {
                "This processor has not been tested with the assembler. \
                 The assembler will probably work on this language."
            }
            Self::Poor => {
                "This processor has known issues with the assembler. \
                 Assembly may produce incorrect results or fail for \
                 some instructions."
            }
            Self::Fair => {
                "This processor has basic assembler support. \
                 Common instructions should work, but complex \
                 instructions may not be supported."
            }
            Self::Good => {
                "This processor has good assembler support. \
                 Most instructions should assemble correctly."
            }
        }
    }
}

impl std::fmt::Display for AssemblyRating {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unrated => write!(f, "Unrated"),
            Self::Poor => write!(f, "Poor"),
            Self::Fair => write!(f, "Fair"),
            Self::Good => write!(f, "Good"),
        }
    }
}

// ---------------------------------------------------------------------------
// DualTextField  (UI placeholder)
// ---------------------------------------------------------------------------

/// A dual text field for assembly input.
///
/// In the full Ghidra GUI, this corresponds to the
/// `AssemblyDualTextField` which shows a mnemonic field and an
/// operands field side by side, with content assist.
///
/// In this port, we represent it as a simple text container.
#[derive(Debug, Clone)]
pub struct AssemblyInput {
    /// The mnemonic part of the assembly instruction.
    pub mnemonic: String,
    /// The operands part.
    pub operands: String,
    /// Whether the input is currently valid.
    pub is_valid: bool,
    /// Validation error message (if any).
    pub error_message: Option<String>,
}

impl AssemblyInput {
    /// Create a new empty input.
    pub fn new() -> Self {
        Self {
            mnemonic: String::new(),
            operands: String::new(),
            is_valid: true,
            error_message: None,
        }
    }

    /// Create from a full assembly line.
    pub fn from_line(line: &str) -> Self {
        let trimmed = line.trim();
        let (mnemonic, operands) = if let Some(pos) = trimmed.find(|c: char| c.is_whitespace()) {
            (
                trimmed[..pos].to_string(),
                trimmed[pos..].trim().to_string(),
            )
        } else {
            (trimmed.to_string(), String::new())
        };
        Self {
            mnemonic,
            operands,
            is_valid: true,
            error_message: None,
        }
    }

    /// Get the full assembly text.
    pub fn full_text(&self) -> String {
        if self.operands.is_empty() {
            self.mnemonic.clone()
        } else {
            format!("{} {}", self.mnemonic, self.operands)
        }
    }

    /// Set an error on this input.
    pub fn set_error(&mut self, message: impl Into<String>) {
        self.is_valid = false;
        self.error_message = Some(message.into());
    }

    /// Clear the error state.
    pub fn clear_error(&mut self) {
        self.is_valid = true;
        self.error_message = None;
    }
}

impl Default for AssemblyInput {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::analyzer::core::Address;

    #[test]
    fn test_patch_request_instruction() {
        let req = PatchRequest::instruction(
            Address::new(0x400000),
            vec![0x00, 0x00],
            vec![0x90, 0x90],
            "NOP; NOP",
        );
        assert_eq!(req.action_type, PatchActionType::PatchInstruction);
        assert_eq!(req.patch_length(), 2);
        assert!(!req.changes_size());
        assert!(req.assembly_text.is_some());
    }

    #[test]
    fn test_patch_request_data() {
        let req = PatchRequest::data(
            Address::new(0x400000),
            vec![0x00],
            vec![0xCC, 0xCC],
        );
        assert_eq!(req.action_type, PatchActionType::PatchData);
        assert!(req.changes_size());
        assert!(req.assembly_text.is_none());
    }

    #[test]
    fn test_assembly_rating() {
        assert_eq!(
            format!("{}", AssemblyRating::Good),
            "Good"
        );
        assert!(!AssemblyRating::Poor.description().is_empty());
    }

    #[test]
    fn test_assembly_input() {
        let input = AssemblyInput::from_line("MOV R0, R1");
        assert_eq!(input.mnemonic, "MOV");
        assert_eq!(input.operands, "R0, R1");
        assert_eq!(input.full_text(), "MOV R0, R1");
        assert!(input.is_valid);
    }

    #[test]
    fn test_assembly_input_no_operands() {
        let input = AssemblyInput::from_line("NOP");
        assert_eq!(input.mnemonic, "NOP");
        assert!(input.operands.is_empty());
        assert_eq!(input.full_text(), "NOP");
    }

    #[test]
    fn test_assembly_input_error() {
        let mut input = AssemblyInput::from_line("FOOBAR R0");
        input.set_error("Unknown mnemonic: FOOBAR");
        assert!(!input.is_valid);
        assert!(input.error_message.is_some());

        input.clear_error();
        assert!(input.is_valid);
    }
}
