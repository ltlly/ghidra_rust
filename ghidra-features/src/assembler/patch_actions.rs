//! Patch actions for the assembler plugin -- ported from
//! `ghidra.app.plugin.core.assembler.PatchInstructionAction` and
//! `PatchDataAction`.
//!
//! Provides the action model for patching instructions and data at
//! addresses in the program listing.

use ghidra_core::Address;

/// Quality rating for assembler support on a given processor.
///
/// Ported from `PatchInstructionAction.AssemblyRating`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AssemblyRating {
    /// The processor has not been tested with the assembler.
    Unrated,
    /// The assembler has poor support for this processor.
    Poor,
    /// The assembler has fair support for this processor.
    Fair,
    /// The assembler has good support for this processor.
    Good,
    /// The assembler has excellent support for this processor.
    Excellent,
}

impl AssemblyRating {
    /// The descriptive message for this rating.
    pub fn message(&self) -> &'static str {
        match self {
            Self::Unrated => "This processor has not been tested with the assembler. \
                The assembler will probably work on this language.",
            Self::Poor => "This processor has poor support with the assembler. \
                The assembler may not produce correct results.",
            Self::Fair => "This processor has fair support with the assembler. \
                Most instructions should assemble correctly.",
            Self::Good => "This processor has good support with the assembler. \
                The assembler should work well for this language.",
            Self::Excellent => "This processor has excellent support with the assembler.",
        }
    }

    /// Whether the assembler should show a warning for this rating.
    pub fn should_warn(&self) -> bool {
        matches!(self, Self::Unrated | Self::Poor)
    }
}

impl Default for AssemblyRating {
    fn default() -> Self {
        Self::Unrated
    }
}

/// The menu group for patch actions.
pub const MENU_GROUP: &str = "Patch";

/// The default key binding for patching instructions.
pub const KEYBIND_PATCH_INSTRUCTION: &str = "ctrl shift G";

/// The default key binding for patching data.
pub const KEYBIND_PATCH_DATA: &str = "ctrl shift D";

/// Result of a patch operation.
#[derive(Debug, Clone)]
pub enum PatchResult {
    /// The patch was applied successfully.
    Success {
        /// The address where the patch was applied.
        address: Address,
        /// The bytes that were written.
        bytes_written: Vec<u8>,
        /// The original bytes that were replaced.
        original_bytes: Vec<u8>,
    },
    /// The patch failed.
    Failure {
        /// The address where the patch was attempted.
        address: Address,
        /// Error message.
        error: String,
    },
    /// The patch was cancelled by the user.
    Cancelled,
}

impl PatchResult {
    /// Whether the patch was successful.
    pub fn is_success(&self) -> bool {
        matches!(self, PatchResult::Success { .. })
    }

    /// Get the error message (if failure).
    pub fn error_message(&self) -> Option<&str> {
        match self {
            PatchResult::Failure { error, .. } => Some(error),
            _ => None,
        }
    }
}

/// A patch instruction action.
///
/// Ported from `ghidra.app.plugin.core.assembler.PatchInstructionAction`.
///
/// Models the UI action for assembling an instruction at the current address.
/// When triggered, it enters an editing mode where the user types an assembly
/// mnemonic. Content-assist provides completions and shows assembled bytes
/// in real time.
#[derive(Debug, Clone)]
pub struct PatchInstructionAction {
    /// The display name.
    pub name: String,
    /// Popup menu path.
    pub popup_menu_path: Vec<String>,
    /// Key binding.
    pub key_binding: String,
    /// Help location.
    pub help_location: String,
    /// Assembly rating for the current processor.
    pub assembly_rating: AssemblyRating,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The current address being patched.
    pub current_address: Option<Address>,
    /// Whether we're currently in patch mode.
    pub in_patch_mode: bool,
    /// The text being edited.
    pub current_text: String,
    /// Assembly completions for the current text.
    pub completions: Vec<AssemblyCompletion>,
}

/// An assembly completion suggestion.
#[derive(Debug, Clone)]
pub struct AssemblyCompletion {
    /// The assembly text for this completion.
    pub text: String,
    /// The assembled bytes (if the instruction is complete).
    pub bytes: Option<Vec<u8>>,
    /// A description/tooltip for this completion.
    pub description: String,
    /// Whether this is a complete instruction (vs. partial mnemonic).
    pub is_complete: bool,
}

impl AssemblyCompletion {
    /// Create a new completion.
    pub fn new(text: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            bytes: None,
            description: description.into(),
            is_complete: false,
        }
    }

    /// Create a completion with assembled bytes.
    pub fn with_bytes(
        text: impl Into<String>,
        bytes: Vec<u8>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            text: text.into(),
            bytes: Some(bytes),
            description: description.into(),
            is_complete: true,
        }
    }
}

impl PatchInstructionAction {
    /// Create a new patch instruction action.
    pub fn new() -> Self {
        Self {
            name: "Patch Instruction".into(),
            popup_menu_path: vec!["Patch Instruction".into()],
            key_binding: KEYBIND_PATCH_INSTRUCTION.into(),
            help_location: "patch_instruction".into(),
            assembly_rating: AssemblyRating::default(),
            enabled: true,
            current_address: None,
            in_patch_mode: false,
            current_text: String::new(),
            completions: Vec::new(),
        }
    }

    /// Start patch mode at the given address.
    pub fn start_patch(&mut self, address: Address) {
        self.current_address = Some(address);
        self.in_patch_mode = true;
        self.current_text = String::new();
        self.completions.clear();
    }

    /// Update the text being edited and refresh completions.
    pub fn update_text(&mut self, text: impl Into<String>) {
        self.current_text = text.into();
        // In a real implementation, this would call the assembler
        // to get completions for the current text.
    }

    /// Apply the current patch text as an instruction.
    pub fn apply_patch(&mut self, bytes: Vec<u8>) -> PatchResult {
        let address = match self.current_address {
            Some(addr) => addr,
            None => return PatchResult::Cancelled,
        };

        if bytes.is_empty() {
            return PatchResult::Failure {
                address,
                error: "No bytes assembled".into(),
            };
        }

        let result = PatchResult::Success {
            address,
            bytes_written: bytes,
            original_bytes: Vec::new(), // would be read from memory in real impl
        };

        // Exit patch mode
        self.in_patch_mode = false;
        self.current_address = None;
        self.current_text.clear();
        self.completions.clear();

        result
    }

    /// Cancel the current patch.
    pub fn cancel_patch(&mut self) {
        self.in_patch_mode = false;
        self.current_address = None;
        self.current_text.clear();
        self.completions.clear();
    }

    /// Set the assembly rating for the current processor.
    pub fn set_assembly_rating(&mut self, rating: AssemblyRating) {
        self.assembly_rating = rating;
    }
}

impl Default for PatchInstructionAction {
    fn default() -> Self {
        Self::new()
    }
}

/// A patch data action.
///
/// Ported from `ghidra.app.plugin.core.assembler.PatchDataAction`.
///
/// Allows the user to "assemble" data at the current address by typing
/// a data representation (e.g., hex bytes, ASCII).
#[derive(Debug, Clone)]
pub struct PatchDataAction {
    /// The display name.
    pub name: String,
    /// Popup menu path.
    pub popup_menu_path: Vec<String>,
    /// Key binding.
    pub key_binding: String,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl PatchDataAction {
    /// Create a new patch data action.
    pub fn new() -> Self {
        Self {
            name: "Patch Data".into(),
            popup_menu_path: vec!["Patch Data".into()],
            key_binding: KEYBIND_PATCH_DATA.into(),
            enabled: true,
        }
    }
}

impl Default for PatchDataAction {
    fn default() -> Self {
        Self::new()
    }
}

/// The assembler plugin model.
///
/// Ported from `ghidra.app.plugin.core.assembler.AssemblerPlugin`.
///
/// Manages the patch instruction and patch data actions, and provides
/// the assembly integration point.
#[derive(Debug)]
pub struct AssemblerPluginModel {
    /// The assembler name.
    pub name: String,
    /// The patch instruction action.
    pub patch_instruction: PatchInstructionAction,
    /// The patch data action.
    pub patch_data: PatchDataAction,
    /// Assembly rating for the current processor.
    pub rating: AssemblyRating,
    /// Patch history (address -> bytes written).
    pub patch_history: Vec<(Address, Vec<u8>)>,
}

impl AssemblerPluginModel {
    /// The standard plugin name.
    pub const ASSEMBLER_NAME: &'static str = "Assembler";

    /// Create a new assembler plugin model.
    pub fn new() -> Self {
        Self {
            name: Self::ASSEMBLER_NAME.into(),
            patch_instruction: PatchInstructionAction::new(),
            patch_data: PatchDataAction::new(),
            rating: AssemblyRating::default(),
            patch_history: Vec::new(),
        }
    }

    /// Record a successful patch in the history.
    pub fn record_patch(&mut self, address: Address, bytes: Vec<u8>) {
        self.patch_history.push((address, bytes));
    }

    /// Undo the last patch.
    pub fn undo_last_patch(&mut self) -> Option<(Address, Vec<u8>)> {
        self.patch_history.pop()
    }

    /// Get the number of patches applied.
    pub fn patch_count(&self) -> usize {
        self.patch_history.len()
    }

    /// Clear the patch history.
    pub fn clear_history(&mut self) {
        self.patch_history.clear();
    }
}

impl Default for AssemblerPluginModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assembly_rating_message() {
        assert!(!AssemblyRating::Unrated.message().is_empty());
        assert!(!AssemblyRating::Good.message().is_empty());
    }

    #[test]
    fn test_assembly_rating_should_warn() {
        assert!(AssemblyRating::Unrated.should_warn());
        assert!(AssemblyRating::Poor.should_warn());
        assert!(!AssemblyRating::Good.should_warn());
        assert!(!AssemblyRating::Excellent.should_warn());
    }

    #[test]
    fn test_assembly_rating_ordering() {
        assert!(AssemblyRating::Unrated < AssemblyRating::Poor);
        assert!(AssemblyRating::Poor < AssemblyRating::Fair);
        assert!(AssemblyRating::Fair < AssemblyRating::Good);
        assert!(AssemblyRating::Good < AssemblyRating::Excellent);
    }

    #[test]
    fn test_patch_result_success() {
        let result = PatchResult::Success {
            address: Address::new(0x1000),
            bytes_written: vec![0x90],
            original_bytes: vec![0xCC],
        };
        assert!(result.is_success());
        assert!(result.error_message().is_none());
    }

    #[test]
    fn test_patch_result_failure() {
        let result = PatchResult::Failure {
            address: Address::new(0x1000),
            error: "Invalid instruction".into(),
        };
        assert!(!result.is_success());
        assert_eq!(result.error_message(), Some("Invalid instruction"));
    }

    #[test]
    fn test_assembly_completion() {
        let c = AssemblyCompletion::new("nop", "No operation");
        assert_eq!(c.text, "nop");
        assert!(!c.is_complete);

        let c = AssemblyCompletion::with_bytes("nop", vec![0x90], "No operation");
        assert!(c.is_complete);
        assert_eq!(c.bytes, Some(vec![0x90]));
    }

    #[test]
    fn test_patch_instruction_action_new() {
        let action = PatchInstructionAction::new();
        assert_eq!(action.name, "Patch Instruction");
        assert_eq!(action.key_binding, KEYBIND_PATCH_INSTRUCTION);
        assert!(action.enabled);
        assert!(!action.in_patch_mode);
    }

    #[test]
    fn test_patch_instruction_start_and_cancel() {
        let mut action = PatchInstructionAction::new();
        action.start_patch(Address::new(0x1000));
        assert!(action.in_patch_mode);
        assert_eq!(action.current_address, Some(Address::new(0x1000)));

        action.cancel_patch();
        assert!(!action.in_patch_mode);
        assert!(action.current_address.is_none());
    }

    #[test]
    fn test_patch_instruction_apply() {
        let mut action = PatchInstructionAction::new();
        action.start_patch(Address::new(0x1000));
        let result = action.apply_patch(vec![0x90]);
        assert!(result.is_success());
        assert!(!action.in_patch_mode);
    }

    #[test]
    fn test_patch_instruction_apply_empty() {
        let mut action = PatchInstructionAction::new();
        action.start_patch(Address::new(0x1000));
        let result = action.apply_patch(vec![]);
        assert!(!result.is_success());
        assert!(result.error_message().is_some());
    }

    #[test]
    fn test_patch_instruction_apply_no_address() {
        let mut action = PatchInstructionAction::new();
        let result = action.apply_patch(vec![0x90]);
        assert!(matches!(result, PatchResult::Cancelled));
    }

    #[test]
    fn test_patch_instruction_update_text() {
        let mut action = PatchInstructionAction::new();
        action.start_patch(Address::new(0x1000));
        action.update_text("mov rax, rbx");
        assert_eq!(action.current_text, "mov rax, rbx");
    }

    #[test]
    fn test_patch_data_action() {
        let action = PatchDataAction::new();
        assert_eq!(action.name, "Patch Data");
        assert_eq!(action.key_binding, KEYBIND_PATCH_DATA);
        assert!(action.enabled);
    }

    #[test]
    fn test_assembler_plugin_model() {
        let mut model = AssemblerPluginModel::new();
        assert_eq!(model.name, AssemblerPluginModel::ASSEMBLER_NAME);
        assert_eq!(model.patch_count(), 0);

        model.record_patch(Address::new(0x1000), vec![0x90]);
        model.record_patch(Address::new(0x1001), vec![0xC3]);
        assert_eq!(model.patch_count(), 2);

        let undone = model.undo_last_patch();
        assert!(undone.is_some());
        assert_eq!(undone.unwrap().0, Address::new(0x1001));
        assert_eq!(model.patch_count(), 1);

        model.clear_history();
        assert_eq!(model.patch_count(), 0);
    }
}
