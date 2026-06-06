//! Function signature editing dialogs.
//!
//! Ported from `ghidra.app.plugin.core.function.AbstractEditFunctionSignatureDialog`
//! and `ghidra.app.plugin.core.function.EditFunctionSignatureDialog`.
//!
//! Provides a structured editor for function signatures that allows changing
//! the return type, calling convention, and function attributes (inline, no-return,
//! call-fixup). The dialog validates the signature text and applies changes via
//! a command pattern.

use std::fmt;

// ---------------------------------------------------------------------------
// FunctionSignatureEditResult -- result of applying a signature edit
// ---------------------------------------------------------------------------

/// The result of applying a function signature edit.
///
/// Captures all the changes that should be applied to a function.
#[derive(Debug, Clone)]
pub struct FunctionSignatureEditResult {
    /// The new signature prototype string (e.g., `"int __cdecl main(int argc, char **argv)"`).
    pub prototype_string: String,
    /// The new calling convention name, or `None` to leave unchanged.
    pub calling_convention: Option<String>,
    /// Whether the function should be marked as inline.
    pub is_inline: bool,
    /// Whether the function should be marked as no-return.
    pub is_no_return: bool,
    /// The call-fixup name, or `None` for none.
    pub call_fixup: Option<String>,
    /// The source type for the change.
    pub source_type: SourceType,
}

impl FunctionSignatureEditResult {
    /// Create a new edit result.
    pub fn new(prototype_string: impl Into<String>) -> Self {
        Self {
            prototype_string: prototype_string.into(),
            calling_convention: None,
            is_inline: false,
            is_no_return: false,
            call_fixup: None,
            source_type: SourceType::UserDefined,
        }
    }
}

/// Source type for a function signature change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceType {
    /// User-initiated change.
    UserDefined,
    /// Analysis-detected change.
    Analysis,
    /// Imported from debug info.
    Imported,
    /// Default value.
    Default,
}

impl fmt::Display for SourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserDefined => write!(f, "UserDefined"),
            Self::Analysis => write!(f, "Analysis"),
            Self::Imported => write!(f, "Imported"),
            Self::Default => write!(f, "Default"),
        }
    }
}

// ---------------------------------------------------------------------------
// AbstractEditFunctionSignatureDialog -- base model for signature editing
// ---------------------------------------------------------------------------

/// Abstract model for editing a function signature.
///
/// Provides the state and validation logic for a dialog that allows
/// editing a function's signature, calling convention, and attributes.
///
/// Ported from `AbstractEditFunctionSignatureDialog.java`.
#[derive(Debug, Clone)]
pub struct AbstractEditFunctionSignatureDialog {
    /// Title of the dialog.
    title: String,
    /// The current signature text.
    signature_text: String,
    /// Whether inline editing is allowed.
    allow_inline: bool,
    /// Whether no-return attribute editing is allowed.
    allow_no_return: bool,
    /// Whether call-fixup editing is allowed.
    allow_call_fixup: bool,
    /// Current calling convention name.
    calling_convention: Option<String>,
    /// Available calling conventions.
    calling_conventions: Vec<String>,
    /// Current call-fixup name.
    call_fixup: Option<String>,
    /// Available call-fixup names.
    call_fixups: Vec<String>,
    /// Whether the inline checkbox is checked.
    is_inline: bool,
    /// Whether the no-return checkbox is checked.
    is_no_return: bool,
    /// The error message, if signature is invalid.
    error_message: Option<String>,
    /// Whether the dialog has been initialized with function data.
    initialized: bool,
    /// Whether the dialog was cancelled.
    cancelled: bool,
}

impl AbstractEditFunctionSignatureDialog {
    /// Create a new abstract signature dialog.
    pub fn new(
        title: impl Into<String>,
        allow_inline: bool,
        allow_no_return: bool,
        allow_call_fixup: bool,
    ) -> Self {
        Self {
            title: title.into(),
            signature_text: String::new(),
            allow_inline,
            allow_no_return,
            allow_call_fixup,
            calling_convention: None,
            calling_conventions: vec![
                "default".to_string(),
                "__cdecl".to_string(),
                "__stdcall".to_string(),
                "__fastcall".to_string(),
                "__thiscall".to_string(),
                "vectorcall".to_string(),
            ],
            call_fixup: None,
            call_fixups: Vec::new(),
            is_inline: false,
            is_no_return: false,
            error_message: None,
            initialized: false,
            cancelled: false,
        }
    }

    /// Get the dialog title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Get the current signature text.
    pub fn signature_text(&self) -> &str {
        &self.signature_text
    }

    /// Set the signature text.
    pub fn set_signature_text(&mut self, text: impl Into<String>) {
        self.signature_text = text.into();
        self.validate();
    }

    /// Whether inline editing is allowed.
    pub fn allow_inline(&self) -> bool {
        self.allow_inline
    }

    /// Whether no-return editing is allowed.
    pub fn allow_no_return(&self) -> bool {
        self.allow_no_return
    }

    /// Whether call-fixup editing is allowed.
    pub fn allow_call_fixup(&self) -> bool {
        self.allow_call_fixup
    }

    /// Get the current calling convention.
    pub fn calling_convention(&self) -> Option<&str> {
        self.calling_convention.as_deref()
    }

    /// Set the calling convention.
    pub fn set_calling_convention(&mut self, convention: Option<String>) {
        self.calling_convention = convention;
    }

    /// Get the list of available calling conventions.
    pub fn calling_conventions(&self) -> &[String] {
        &self.calling_conventions
    }

    /// Set the available calling conventions.
    pub fn set_calling_conventions(&mut self, conventions: Vec<String>) {
        self.calling_conventions = conventions;
    }

    /// Get the current call-fixup name.
    pub fn call_fixup(&self) -> Option<&str> {
        self.call_fixup.as_deref()
    }

    /// Set the call-fixup name.
    pub fn set_call_fixup(&mut self, fixup: Option<String>) {
        self.call_fixup = fixup;
    }

    /// Get the list of available call-fixup names.
    pub fn call_fixups(&self) -> &[String] {
        &self.call_fixups
    }

    /// Set the available call-fixup names.
    pub fn set_call_fixups(&mut self, fixups: Vec<String>) {
        self.call_fixups = fixups;
    }

    /// Whether the inline checkbox is checked.
    pub fn is_inline(&self) -> bool {
        self.is_inline
    }

    /// Set the inline checkbox state.
    pub fn set_inline(&mut self, inline: bool) {
        if self.allow_inline {
            self.is_inline = inline;
        }
    }

    /// Whether the no-return checkbox is checked.
    pub fn is_no_return(&self) -> bool {
        self.is_no_return
    }

    /// Set the no-return checkbox state.
    pub fn set_no_return(&mut self, no_return: bool) {
        if self.allow_no_return {
            self.is_no_return = no_return;
        }
    }

    /// Get the current error message, if any.
    pub fn error_message(&self) -> Option<&str> {
        self.error_message.as_deref()
    }

    /// Whether the dialog has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Mark the dialog as initialized.
    pub fn set_initialized(&mut self, initialized: bool) {
        self.initialized = initialized;
    }

    /// Whether the dialog was cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    /// Cancel the dialog.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Whether the signature is currently valid.
    pub fn is_valid(&self) -> bool {
        self.error_message.is_none() && !self.signature_text.is_empty()
    }

    /// Validate the current signature text.
    ///
    /// Sets the error message if the signature is invalid.
    fn validate(&mut self) {
        if self.signature_text.is_empty() {
            self.error_message = Some("Signature cannot be empty".to_string());
        } else if !self.signature_text.contains('(') || !self.signature_text.contains(')') {
            self.error_message = Some("Signature must contain parentheses for parameter list".to_string());
        } else {
            // Check balanced parentheses
            let open_count = self.signature_text.matches('(').count();
            let close_count = self.signature_text.matches(')').count();
            if open_count != close_count {
                self.error_message = Some("Unbalanced parentheses in signature".to_string());
            } else {
                self.error_message = None;
            }
        }
    }

    /// Get the result of the dialog if OK was pressed.
    ///
    /// Returns `None` if the dialog was cancelled or the signature is invalid.
    pub fn get_result(&self) -> Option<FunctionSignatureEditResult> {
        if self.cancelled || !self.is_valid() {
            return None;
        }

        let mut result = FunctionSignatureEditResult::new(&self.signature_text);
        result.calling_convention = self.calling_convention.clone();
        result.is_inline = self.is_inline;
        result.is_no_return = self.is_no_return;
        result.call_fixup = self.call_fixup.clone();
        Some(result)
    }
}

// ---------------------------------------------------------------------------
// EditFunctionSignatureDialog -- concrete dialog for editing a function's signature
// ---------------------------------------------------------------------------

/// Dialog for editing a function's signature.
///
/// Provides a structured editor that allows changing the function's return type,
/// name, parameters, calling convention, and attributes. Supports validation
/// of the signature text and applies changes via the command pattern.
///
/// Ported from `EditFunctionSignatureDialog.java`.
#[derive(Debug, Clone)]
pub struct EditFunctionSignatureDialog {
    /// The base abstract dialog.
    base: AbstractEditFunctionSignatureDialog,
    /// The function name (for display).
    function_name: String,
    /// The original signature prototype string (for comparison/diff).
    old_signature: String,
    /// The address of the function being edited.
    function_address: u64,
    /// The program name.
    program_name: String,
}

impl EditFunctionSignatureDialog {
    /// Create a new edit function signature dialog.
    pub fn new(
        title: impl Into<String>,
        function_name: impl Into<String>,
        function_address: u64,
        program_name: impl Into<String>,
        current_signature: impl Into<String>,
        allow_inline: bool,
        allow_no_return: bool,
        allow_call_fixup: bool,
    ) -> Self {
        let sig = current_signature.into();
        let mut base = AbstractEditFunctionSignatureDialog::new(
            title,
            allow_inline,
            allow_no_return,
            allow_call_fixup,
        );
        base.set_signature_text(sig.clone());
        Self {
            base,
            function_name: function_name.into(),
            old_signature: sig,
            function_address,
            program_name: program_name.into(),
        }
    }

    /// Create a dialog with default settings derived from function properties.
    pub fn for_function(
        function_name: impl Into<String>,
        function_address: u64,
        program_name: impl Into<String>,
        current_signature: impl Into<String>,
    ) -> Self {
        let name = function_name.into();
        let title = format!("Edit Signature: {}", name);
        Self::new(title, name, function_address, program_name, current_signature, true, true, true)
    }

    /// Get a reference to the base abstract dialog.
    pub fn base(&self) -> &AbstractEditFunctionSignatureDialog {
        &self.base
    }

    /// Get a mutable reference to the base abstract dialog.
    pub fn base_mut(&mut self) -> &mut AbstractEditFunctionSignatureDialog {
        &mut self.base
    }

    /// Get the function name.
    pub fn function_name(&self) -> &str {
        &self.function_name
    }

    /// Get the original signature.
    pub fn old_signature(&self) -> &str {
        &self.old_signature
    }

    /// Get the function address.
    pub fn function_address(&self) -> u64 {
        self.function_address
    }

    /// Get the program name.
    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    /// Whether the signature has been modified.
    pub fn is_modified(&self) -> bool {
        self.base.signature_text() != self.old_signature
            || self.base.is_inline()
            || self.base.is_no_return()
            || self.base.call_fixup().is_some()
    }

    /// Get the edit result if OK was pressed and the signature is valid.
    pub fn get_result(&self) -> Option<FunctionSignatureEditResult> {
        self.base.get_result()
    }

    /// Initialize the dialog with function data.
    pub fn initialize(
        &mut self,
        signature_text: impl Into<String>,
        calling_convention: Option<String>,
        calling_conventions: Vec<String>,
        is_inline: bool,
        is_no_return: bool,
    ) {
        self.base.set_signature_text(signature_text);
        self.base.set_calling_convention(calling_convention);
        self.base.set_calling_conventions(calling_conventions);
        self.base.set_inline(is_inline);
        self.base.set_no_return(is_no_return);
        self.base.set_initialized(true);
    }
}

// ---------------------------------------------------------------------------
// Helper: parse a calling convention from a signature string
// ---------------------------------------------------------------------------

/// Extract the calling convention from a prototype string.
///
/// Looks for common calling convention keywords in the signature text.
pub fn extract_calling_convention(prototype: &str) -> Option<&str> {
    if prototype.contains("__cdecl") {
        Some("__cdecl")
    } else if prototype.contains("__stdcall") {
        Some("__stdcall")
    } else if prototype.contains("__fastcall") {
        Some("__fastcall")
    } else if prototype.contains("__thiscall") {
        Some("__thiscall")
    } else if prototype.contains("vectorcall") {
        Some("vectorcall")
    } else {
        None
    }
}

/// Check if a prototype string indicates a void return type.
pub fn is_void_return(prototype: &str) -> bool {
    prototype.trim_start().starts_with("void")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abstract_dialog_new() {
        let dialog = AbstractEditFunctionSignatureDialog::new(
            "Edit Signature",
            true,
            true,
            false,
        );
        assert_eq!(dialog.title(), "Edit Signature");
        assert!(dialog.allow_inline());
        assert!(dialog.allow_no_return());
        assert!(!dialog.allow_call_fixup());
        assert!(!dialog.is_initialized());
    }

    #[test]
    fn test_abstract_dialog_signature_validation() {
        let mut dialog = AbstractEditFunctionSignatureDialog::new(
            "Test", true, true, true,
        );

        // Empty signature is invalid
        dialog.set_signature_text("");
        assert!(!dialog.is_valid());
        assert!(dialog.error_message().is_some());

        // Valid signature
        dialog.set_signature_text("void foo(int x)");
        assert!(dialog.is_valid());
        assert!(dialog.error_message().is_none());
    }

    #[test]
    fn test_abstract_dialog_unbalanced_parens() {
        let mut dialog = AbstractEditFunctionSignatureDialog::new(
            "Test", true, true, true,
        );
        dialog.set_signature_text("int foo(int x");
        assert!(!dialog.is_valid());
        // Has '(' but no ')' so triggers "must contain parentheses" error
        assert!(dialog.error_message().is_some());
    }

    #[test]
    fn test_abstract_dialog_calling_conventions() {
        let mut dialog = AbstractEditFunctionSignatureDialog::new(
            "Test", true, true, true,
        );
        let conventions = dialog.calling_conventions().to_vec();
        assert!(conventions.contains(&"__cdecl".to_string()));
        dialog.set_calling_convention(Some("__stdcall".to_string()));
        assert_eq!(dialog.calling_convention(), Some("__stdcall"));
    }

    #[test]
    fn test_abstract_dialog_attributes() {
        let mut dialog = AbstractEditFunctionSignatureDialog::new(
            "Test", true, true, true,
        );
        dialog.set_inline(true);
        assert!(dialog.is_inline());
        dialog.set_no_return(true);
        assert!(dialog.is_no_return());
        dialog.set_call_fixup(Some("fixup1".to_string()));
        assert_eq!(dialog.call_fixup(), Some("fixup1"));
    }

    #[test]
    fn test_abstract_dialog_get_result() {
        let mut dialog = AbstractEditFunctionSignatureDialog::new(
            "Test", true, true, true,
        );
        dialog.set_signature_text("int foo(int x)");
        dialog.set_calling_convention(Some("__cdecl".to_string()));
        dialog.set_inline(true);

        let result = dialog.get_result().unwrap();
        assert_eq!(result.prototype_string, "int foo(int x)");
        assert_eq!(result.calling_convention, Some("__cdecl".to_string()));
        assert!(result.is_inline);
    }

    #[test]
    fn test_abstract_dialog_get_result_cancelled() {
        let mut dialog = AbstractEditFunctionSignatureDialog::new(
            "Test", true, true, true,
        );
        dialog.set_signature_text("int foo(int x)");
        dialog.cancel();
        assert!(dialog.get_result().is_none());
    }

    #[test]
    fn test_edit_dialog_new() {
        let dialog = EditFunctionSignatureDialog::new(
            "Edit Signature: main",
            "main",
            0x401000,
            "test.exe",
            "int main(int argc, char **argv)",
            true,
            true,
            false,
        );
        assert_eq!(dialog.function_name(), "main");
        assert_eq!(dialog.function_address(), 0x401000);
        assert_eq!(dialog.program_name(), "test.exe");
        assert_eq!(dialog.old_signature(), "int main(int argc, char **argv)");
    }

    #[test]
    fn test_edit_dialog_for_function() {
        let dialog = EditFunctionSignatureDialog::for_function(
            "my_func",
            0x402000,
            "prog.bin",
            "void my_func()",
        );
        assert_eq!(dialog.function_name(), "my_func");
        assert!(dialog.base().title().contains("my_func"));
    }

    #[test]
    fn test_edit_dialog_is_modified() {
        let mut dialog = EditFunctionSignatureDialog::new(
            "Test", "foo", 0x1000, "prog", "void foo()", true, true, true,
        );
        assert!(!dialog.is_modified());

        dialog.base_mut().set_signature_text("int foo(int x)");
        assert!(dialog.is_modified());
    }

    #[test]
    fn test_edit_dialog_initialize() {
        let mut dialog = EditFunctionSignatureDialog::new(
            "Test", "bar", 0x2000, "prog", "int bar(int)", true, true, true,
        );
        dialog.initialize(
            "int bar(int x)",
            Some("__cdecl".to_string()),
            vec!["default".into(), "__cdecl".into()],
            false,
            true,
        );
        assert!(dialog.base().is_initialized());
        assert_eq!(dialog.base().signature_text(), "int bar(int x)");
        assert!(dialog.base().is_no_return());
    }

    #[test]
    fn test_extract_calling_convention() {
        assert_eq!(extract_calling_convention("int __cdecl foo()"), Some("__cdecl"));
        assert_eq!(extract_calling_convention("void __stdcall bar(int)"), Some("__stdcall"));
        assert_eq!(extract_calling_convention("int foo()"), None);
    }

    #[test]
    fn test_is_void_return() {
        assert!(is_void_return("void foo()"));
        assert!(is_void_return("  void bar(int)"));
        assert!(!is_void_return("int foo()"));
    }

    #[test]
    fn test_source_type_display() {
        assert_eq!(SourceType::UserDefined.to_string(), "UserDefined");
        assert_eq!(SourceType::Analysis.to_string(), "Analysis");
    }

    #[test]
    fn test_abstract_dialog_no_return_when_not_allowed() {
        let mut dialog = AbstractEditFunctionSignatureDialog::new(
            "Test", false, false, false,
        );
        // Setting inline/no-return when not allowed should be silently ignored
        dialog.set_inline(true);
        assert!(!dialog.is_inline());
        dialog.set_no_return(true);
        assert!(!dialog.is_no_return());
    }

    #[test]
    fn test_edit_dialog_get_result_with_valid_signature() {
        let mut dialog = EditFunctionSignatureDialog::new(
            "Test", "main", 0x400000, "test.exe",
            "int main(int, char**)", true, true, true,
        );
        dialog.base_mut().set_signature_text("int main(int argc, char **argv)");
        dialog.base_mut().set_calling_convention(Some("__cdecl".to_string()));

        let result = dialog.get_result().unwrap();
        assert_eq!(result.prototype_string, "int main(int argc, char **argv)");
    }
}
