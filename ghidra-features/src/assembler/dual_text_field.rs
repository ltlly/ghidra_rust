//! Assembly dual text field -- guided assembly input.
//!
//! Ported from `ghidra.app.plugin.core.assembler.AssemblyDualTextField`.
//!
//! Provides a model for guided assembly input: a pair of linked text fields
//! (mnemonic + operands) with autocompletion support. Also includes completion
//! types for suggestions, assembled instructions, and errors.

use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// VisibilityMode -- which text field variant is shown
// ---------------------------------------------------------------------------

/// An enum type to specify which variant of the assembly input is shown.
///
/// Ported from `AssemblyDualTextField.VisibilityMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisibilityMode {
    /// Hide both variants.
    Invisible,
    /// Show the dual-box linked variant (mnemonic + operands).
    DualVisible,
    /// Show the single-box unlinked variant (full assembly text).
    SingleVisible,
}

// ---------------------------------------------------------------------------
// AssemblyCompletion -- generic completion item
// ---------------------------------------------------------------------------

/// A generic class for all items listed by the autocompleter.
///
/// Ported from `AssemblyDualTextField.AssemblyCompletion`.
#[derive(Debug, Clone)]
pub struct AssemblyCompletion {
    /// The text to insert when activated.
    text: String,
    /// The display text (possibly HTML).
    display: String,
    /// Sort order (lower = higher priority).
    order: i32,
    /// Type of completion.
    kind: CompletionKind,
}

/// The kind of assembly completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionKind {
    /// A textual suggestion to continue typing.
    Suggestion,
    /// A fully assembled instruction with bytes.
    Instruction,
    /// An error description.
    Error,
}

impl AssemblyCompletion {
    /// Create a suggestion completion.
    pub fn suggestion(text: impl Into<String>, display: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            display: display.into(),
            order: 1,
            kind: CompletionKind::Suggestion,
        }
    }

    /// Create an instruction completion.
    pub fn instruction(_data: &[u8], display: impl Into<String>, preference: i32) -> Self {
        Self {
            text: String::new(), // Instructions have no insertion text
            display: display.into(),
            order: -preference,
            kind: CompletionKind::Instruction,
        }
    }

    /// Create an error completion.
    pub fn error(text: impl Into<String>, display: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            display: display.into(),
            order: 1,
            kind: CompletionKind::Error,
        }
    }

    /// Get the insertion text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Get the display text.
    pub fn display(&self) -> &str {
        &self.display
    }

    /// Get the kind.
    pub fn kind(&self) -> CompletionKind {
        self.kind
    }

    /// Whether this completion can be auto-activated (on CTRL-SPACE).
    pub fn can_default(&self) -> bool {
        matches!(self.kind, CompletionKind::Suggestion)
    }

    /// Get the sort order.
    pub fn order(&self) -> i32 {
        self.order
    }
}

impl PartialEq for AssemblyCompletion {
    fn eq(&self, other: &Self) -> bool {
        self.display == other.display
    }
}

impl Eq for AssemblyCompletion {}

impl PartialOrd for AssemblyCompletion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AssemblyCompletion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.order
            .cmp(&other.order)
            .then_with(|| self.display.cmp(&other.display))
    }
}

// ---------------------------------------------------------------------------
// AssemblyDualTextField -- the dual text field model
// ---------------------------------------------------------------------------

/// A pair of text fields suitable for guided assembly.
///
/// Ported from `ghidra.app.plugin.core.assembler.AssemblyDualTextField`.
///
/// This model manages the text input state, visibility mode, and
/// completion computation for assembly instructions.
#[derive(Debug)]
pub struct AssemblyDualTextField {
    /// The mnemonic text.
    mnemonic: String,
    /// The operands text.
    operands: String,
    /// The single-line assembly text.
    assembly_text: String,
    /// The current visibility mode.
    visibility: VisibilityMode,
    /// Whether to exhaust undefined bits.
    exhaust_undefined: bool,
    /// The current address for assembly.
    address: u64,
    /// The current architecture identifier.
    architecture: Option<String>,
    /// The existing instruction text (for ordering completions).
    existing_instruction: Option<String>,
    /// Computed completions.
    completions: BTreeSet<AssemblyCompletion>,
}

impl AssemblyDualTextField {
    /// Create a new assembly dual text field.
    pub fn new() -> Self {
        Self {
            mnemonic: String::new(),
            operands: String::new(),
            assembly_text: String::new(),
            visibility: VisibilityMode::DualVisible,
            exhaust_undefined: false,
            address: 0,
            architecture: None,
            existing_instruction: None,
            completions: BTreeSet::new(),
        }
    }

    /// Set the architecture identifier.
    pub fn set_architecture(&mut self, arch: impl Into<String>) {
        self.architecture = Some(arch.into());
    }

    /// Get the architecture.
    pub fn architecture(&self) -> Option<&str> {
        self.architecture.as_deref()
    }

    /// Set the assembly address.
    pub fn set_address(&mut self, address: u64) {
        self.address = address;
        self.existing_instruction = None;
    }

    /// Get the current address.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Set the existing instruction (for ordering completions by similarity).
    pub fn set_existing(&mut self, instruction: impl Into<String>) {
        self.existing_instruction = Some(instruction.into());
    }

    /// Get the mnemonic text.
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    /// Get the operands text.
    pub fn operands(&self) -> &str {
        &self.operands
    }

    /// Set the mnemonic text.
    pub fn set_mnemonic(&mut self, text: impl Into<String>) {
        self.mnemonic = text.into();
    }

    /// Set the operands text.
    pub fn set_operands(&mut self, text: impl Into<String>) {
        self.operands = text.into();
    }

    /// Get the full assembly text (from the visible field).
    pub fn text(&self) -> String {
        match self.visibility {
            VisibilityMode::SingleVisible => self.assembly_text.clone(),
            _ => {
                if self.operands.is_empty() {
                    self.mnemonic.clone()
                } else {
                    format!("{} {}", self.mnemonic, self.operands)
                }
            }
        }
    }

    /// Set the text of the visible field(s).
    pub fn set_text(&mut self, text: impl Into<String>) {
        let text = text.into();
        match self.visibility {
            VisibilityMode::SingleVisible => {
                self.assembly_text = text;
            }
            _ => {
                if let Some(idx) = text.find(char::is_whitespace) {
                    self.mnemonic = text[..idx].to_string();
                    self.operands = text[idx..].trim().to_string();
                } else {
                    self.mnemonic = text;
                    self.operands = String::new();
                }
            }
        }
    }

    /// Set the visibility mode.
    pub fn set_visible(&mut self, mode: VisibilityMode) {
        self.visibility = mode;
    }

    /// Get the visibility mode.
    pub fn visible(&self) -> VisibilityMode {
        self.visibility
    }

    /// Set whether to exhaust undefined bits.
    pub fn set_exhaust_undefined(&mut self, exhaust: bool) {
        self.exhaust_undefined = exhaust;
    }

    /// Whether undefined bits are being exhausted.
    pub fn exhaust_undefined(&self) -> bool {
        self.exhaust_undefined
    }

    /// Get the single-line assembly field text.
    pub fn assembly_text(&self) -> &str {
        &self.assembly_text
    }

    /// Set the single-line assembly field text.
    pub fn set_assembly_text(&mut self, text: impl Into<String>) {
        self.assembly_text = text.into();
    }

    /// Clear all text boxes.
    pub fn clear(&mut self) {
        self.mnemonic.clear();
        self.operands.clear();
        self.assembly_text.clear();
        self.completions.clear();
    }

    /// Set completions.
    pub fn set_completions(&mut self, completions: BTreeSet<AssemblyCompletion>) {
        self.completions = completions;
    }

    /// Get the current completions.
    pub fn completions(&self) -> &BTreeSet<AssemblyCompletion> {
        &self.completions
    }

    /// Get the best completion (highest priority).
    pub fn best_completion(&self) -> Option<&AssemblyCompletion> {
        self.completions.iter().next()
    }

    /// Compute completions for the current text (stub -- real impl delegates to assembler).
    pub fn compute_completions(&mut self, text: &str) {
        self.completions.clear();
        if text.is_empty() {
            return;
        }
        // In the real implementation, this calls the assembler's parseLine
        // and resolveTree methods. For now, produce a placeholder.
        self.completions.insert(AssemblyCompletion::error(
            "",
            format!("No completions available for '{}'", text),
        ));
    }
}

impl Default for AssemblyDualTextField {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_visibility_mode() {
        let mut field = AssemblyDualTextField::new();
        assert_eq!(field.visible(), VisibilityMode::DualVisible);

        field.set_visible(VisibilityMode::SingleVisible);
        assert_eq!(field.visible(), VisibilityMode::SingleVisible);

        field.set_visible(VisibilityMode::Invisible);
        assert_eq!(field.visible(), VisibilityMode::Invisible);
    }

    #[test]
    fn test_dual_field_text() {
        let mut field = AssemblyDualTextField::new();
        field.set_mnemonic("mov");
        field.set_operands("rax, rbx");
        assert_eq!(field.text(), "mov rax, rbx");

        field.set_mnemonic("nop");
        field.set_operands("");
        assert_eq!(field.text(), "nop");
    }

    #[test]
    fn test_set_text_dual_mode() {
        let mut field = AssemblyDualTextField::new();
        field.set_text("mov rax, rbx");
        assert_eq!(field.mnemonic(), "mov");
        assert_eq!(field.operands(), "rax, rbx");

        field.set_text("nop");
        assert_eq!(field.mnemonic(), "nop");
        assert_eq!(field.operands(), "");
    }

    #[test]
    fn test_set_text_single_mode() {
        let mut field = AssemblyDualTextField::new();
        field.set_visible(VisibilityMode::SingleVisible);
        field.set_text("mov rax, rbx");
        assert_eq!(field.assembly_text(), "mov rax, rbx");
        assert_eq!(field.text(), "mov rax, rbx");
    }

    #[test]
    fn test_clear() {
        let mut field = AssemblyDualTextField::new();
        field.set_mnemonic("mov");
        field.set_operands("rax");
        field.set_assembly_text("nop");
        field.clear();

        assert_eq!(field.mnemonic(), "");
        assert_eq!(field.operands(), "");
        assert_eq!(field.assembly_text(), "");
        assert!(field.completions().is_empty());
    }

    #[test]
    fn test_address_lifecycle() {
        let mut field = AssemblyDualTextField::new();
        field.set_address(0x400000);
        assert_eq!(field.address(), 0x400000);

        field.set_existing("mov rax, rbx");
        // Setting a new address should clear existing
        field.set_address(0x400004);
        assert!(field.existing_instruction.is_none());
    }

    #[test]
    fn test_completions() {
        let mut field = AssemblyDualTextField::new();
        assert!(field.completions().is_empty());
        assert!(field.best_completion().is_none());

        let mut completions = BTreeSet::new();
        completions.insert(AssemblyCompletion::suggestion("rax", "Register RAX"));
        completions.insert(AssemblyCompletion::instruction(&[0x90], "90 (nop)", 10000));
        field.set_completions(completions);

        assert_eq!(field.completions().len(), 2);
        // Instruction with high preference has lower order value (better)
        let best = field.best_completion().unwrap();
        assert_eq!(best.kind(), CompletionKind::Instruction);
    }

    #[test]
    fn test_completion_ordering() {
        let s1 = AssemblyCompletion::suggestion("a", "A");
        let s2 = AssemblyCompletion::suggestion("b", "B");
        assert!(s1 < s2); // Same order, alphabetical by display

        let inst = AssemblyCompletion::instruction(&[0x90], "90", 10000);
        let sugg = AssemblyCompletion::suggestion("nop", "nop");
        assert!(inst < sugg); // Instruction with high pref < suggestion
    }

    #[test]
    fn test_completion_properties() {
        let sugg = AssemblyCompletion::suggestion("rbx", "RBX register");
        assert!(sugg.can_default());
        assert_eq!(sugg.text(), "rbx");

        let inst = AssemblyCompletion::instruction(&[0x90], "90", 5000);
        assert!(!inst.can_default());
        assert!(inst.text().is_empty());

        let err = AssemblyCompletion::error("", "Invalid instruction");
        assert!(!err.can_default());
        assert_eq!(err.kind(), CompletionKind::Error);
    }

    #[test]
    fn test_exhaust_undefined() {
        let mut field = AssemblyDualTextField::new();
        assert!(!field.exhaust_undefined());

        field.set_exhaust_undefined(true);
        assert!(field.exhaust_undefined());
    }

    #[test]
    fn test_architecture() {
        let mut field = AssemblyDualTextField::new();
        assert!(field.architecture().is_none());

        field.set_architecture("x86:LE:64:default");
        assert_eq!(field.architecture(), Some("x86:LE:64:default"));
    }

    #[test]
    fn test_compute_completions_empty() {
        let mut field = AssemblyDualTextField::new();
        field.compute_completions("");
        assert!(field.completions().is_empty());
    }

    #[test]
    fn test_compute_completions_stub() {
        let mut field = AssemblyDualTextField::new();
        field.compute_completions("mov");
        assert!(!field.completions().is_empty());
    }
}
