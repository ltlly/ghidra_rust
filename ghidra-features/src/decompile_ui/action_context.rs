//! Decompiler action context -- Rust port of
//! `ghidra.app.plugin.core.decompile.DecompilerActionContext`.
//!
//! Holds the context that is passed to every decompiler action when the
//! user right-clicks or triggers a key-binding inside the decompiler panel.
//! Captures the function entry point, whether a decompile is still in
//! progress, the current line number, and the token under the cursor.

use ghidra_core::addr::Address;

use super::highlight_navigation_actions::{MiddleMouseHighlightSet, TokenRef, TokenStream};
use super::label_actions::{LabelEditRequest, LabelInfo, LabelSource};
use super::secondary_highlight_actions::SecondaryHighlightStore;

// ---------------------------------------------------------------------------
// Token kind discriminant
// ---------------------------------------------------------------------------

/// The kind of Clang token under the cursor.
///
/// In Ghidra this corresponds to the class hierarchy rooted at
/// `ClangToken` (`ClangFuncNameToken`, `ClangLabelToken`,
/// `ClangFieldToken`, `ClangVariableToken`, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClangTokenKind {
    /// A plain syntactic token (keyword, operator, punctuation).
    Syntax,
    /// A function-name token (`ClangFuncNameToken`).
    FunctionName,
    /// A label / symbol token (`ClangLabelToken`).
    Label,
    /// A field-name token inside a struct/union access (`ClangFieldToken`).
    Field,
    /// A variable-name token (`ClangVariableToken`).
    Variable,
    /// A type-name token (`ClangTypeToken`).
    TypeName,
    /// A comment token.
    Comment,
    /// A numeric constant token.
    Constant,
}

impl Default for ClangTokenKind {
    fn default() -> Self {
        Self::Syntax
    }
}

// ---------------------------------------------------------------------------
// Token reference (lightweight placeholder for ClangToken)
// ---------------------------------------------------------------------------

/// A reference to a token in the decompiled C output.
///
/// In Ghidra this is backed by `ClangToken` / `ClangFuncNameToken` in the
/// `ghidra.app.decompiler` package.  Here we store just the information
/// needed by actions.
#[derive(Debug, Clone)]
pub struct ClangTokenRef {
    /// The displayed text of this token.
    pub text: String,
    /// The 1-based line number where this token lives.
    pub line_number: usize,
    /// Column offset within the line.
    pub column: usize,
    /// The discriminant for this token's kind.
    pub kind: ClangTokenKind,
    /// `true` when this token names a function.
    pub is_function_name: bool,
    /// When the token names a function, the entry-point address.
    pub function_entry: Option<Address>,
    /// When the token is a label, the address it refers to.
    pub label_address: Option<Address>,
    /// The raw byte offset into the full decompiled text.
    pub text_offset: usize,
}

impl ClangTokenRef {
    /// Create a new token reference.
    pub fn new(
        text: impl Into<String>,
        line_number: usize,
        column: usize,
        is_function_name: bool,
        function_entry: Option<Address>,
        text_offset: usize,
    ) -> Self {
        Self {
            text: text.into(),
            line_number,
            column,
            kind: if is_function_name {
                ClangTokenKind::FunctionName
            } else {
                ClangTokenKind::Syntax
            },
            is_function_name,
            function_entry,
            label_address: None,
            text_offset,
        }
    }

    /// Create a label token reference.
    pub fn new_label(
        text: impl Into<String>,
        line_number: usize,
        column: usize,
        label_address: Address,
        text_offset: usize,
    ) -> Self {
        Self {
            text: text.into(),
            line_number,
            column,
            kind: ClangTokenKind::Label,
            is_function_name: false,
            function_entry: None,
            label_address: Some(label_address),
            text_offset,
        }
    }

    /// Convenience: returns the 1-based line number.
    pub fn line_parent_line_number(&self) -> usize {
        self.line_number
    }

    /// Returns `true` if this token is a function-name token.
    pub fn is_func_name_token(&self) -> bool {
        self.kind == ClangTokenKind::FunctionName
    }

    /// Returns `true` if this token is a label token.
    pub fn is_label_token(&self) -> bool {
        self.kind == ClangTokenKind::Label
    }
}

// ---------------------------------------------------------------------------
// HighFunctionRef -- lightweight stand-in for HighFunction
// ---------------------------------------------------------------------------

/// A reference to the decompiler's high-level function representation.
///
/// In Ghidra, `HighFunction` holds the decompiler's internal
/// representation of a function (P-code, high-level variables, prototype
/// overrides, etc.).  In Rust we model it as an opaque handle.
#[derive(Debug, Clone)]
pub struct HighFunctionRef {
    /// The function entry-point address.
    pub function_entry: Address,
    /// Whether a prototype override is active.
    pub has_prototype_override: bool,
}

// ---------------------------------------------------------------------------
// CCodeModelRef -- lightweight stand-in for ClangTokenGroup
// ---------------------------------------------------------------------------

/// A reference to the decompiled C code model (the root token group).
///
/// In Ghidra this is a `ClangTokenGroup`; in Rust we model it as an
/// opaque handle carrying the entry-point address so that actions can
/// verify they are working on the expected function.
#[derive(Debug, Clone)]
pub struct CCodeModelRef {
    /// The function entry-point this model belongs to.
    pub function_entry: Address,
}

// ---------------------------------------------------------------------------
// DecompilerActionContext
// ---------------------------------------------------------------------------

/// The context that accompanies every decompiler action.
///
/// Mirrors Ghidra's `DecompilerActionContext`, which extends
/// `NavigatableActionContext` and `RestrictedAddressSetContext`.
#[derive(Debug, Clone)]
pub struct DecompilerActionContext {
    /// The current function's entry-point address (if any).
    pub function_entry_point: Address,
    /// `true` if the decompiler is still working when this context was
    /// created (actions should be disabled in this state).
    pub is_decompiling: bool,
    /// The 0-based line number under the mouse cursor or current token.
    /// A value of `0` means "unknown / not set".
    pub line_number: usize,
    /// The token at the cursor position.  Lazily populated via
    /// [`token_at_cursor`](Self::token_at_cursor).
    token_at_cursor: Option<ClangTokenRef>,
    /// Cached function name (from the decompiled function).
    function_name: Option<String>,
    /// Whether the current function is an "undefined" (placeholder) function.
    is_undefined_function: bool,
    /// The high-level function reference (if available).
    high_function: Option<HighFunctionRef>,
    /// The C code model reference (if available).
    c_code_model: Option<CCodeModelRef>,
    /// Pending label edit request (set by label actions, consumed by the
    /// provider layer).
    pending_label_edit: Option<LabelEditRequest>,
    /// The current text selection (if any).
    text_selection: Option<String>,
    /// Middle-mouse highlight set for the current function.
    middle_mouse_highlights: Option<MiddleMouseHighlightSet>,
    /// The token stream for the current decompiled output.
    token_stream: Option<TokenStream>,
    /// Secondary highlight store reference.
    secondary_highlight_store: SecondaryHighlightStore,
    /// The last status message set via `set_status_message_stored`.
    last_status_message: Option<String>,
}

impl DecompilerActionContext {
    /// Create a context with an explicit line number.
    ///
    /// `line_number` is the 0-based line (typically from a mouse event).
    /// Pass `0` to have it derived from the current token.
    pub fn new(
        function_entry_point: Address,
        is_decompiling: bool,
        line_number: usize,
    ) -> Self {
        Self {
            function_entry_point,
            is_decompiling,
            line_number,
            token_at_cursor: None,
            function_name: None,
            is_undefined_function: false,
            high_function: None,
            c_code_model: None,
            pending_label_edit: None,
            text_selection: None,
            middle_mouse_highlights: None,
            token_stream: None,
            secondary_highlight_store: SecondaryHighlightStore::new(),
            last_status_message: None,
        }
    }

    /// Create a context using the current token's line number.
    pub fn from_token(function_entry_point: Address, is_decompiling: bool) -> Self {
        Self::new(function_entry_point, is_decompiling, 0)
    }

    /// Returns the function entry-point address.
    pub fn get_function_entry_point(&self) -> Address {
        self.function_entry_point
    }

    /// Returns `true` if the decompiler is still working.
    pub fn is_decompiling(&self) -> bool {
        self.is_decompiling
    }

    /// Set the token at the cursor (e.g., populated by the panel).
    pub fn set_token_at_cursor(&mut self, token: ClangTokenRef) {
        self.token_at_cursor = Some(token);
    }

    /// Returns the token at the cursor, if any.
    pub fn token_at_cursor(&self) -> Option<&ClangTokenRef> {
        self.token_at_cursor.as_ref()
    }

    /// Returns a mutable reference to the token at the cursor.
    pub fn token_at_cursor_mut(&mut self) -> Option<&mut ClangTokenRef> {
        self.token_at_cursor.as_mut()
    }

    /// Returns the effective line number.
    ///
    /// If `line_number` was explicitly set (non-zero) it is returned
    /// directly.  Otherwise the token's line number is used.
    pub fn get_line_number(&self) -> usize {
        if self.line_number != 0 {
            return self.line_number;
        }
        self.token_at_cursor
            .as_ref()
            .map(|t| t.line_parent_line_number())
            .unwrap_or(0)
    }

    /// Returns `true` if there is a text selection or range selection.
    pub fn has_selection(&self) -> bool {
        self.text_selection
            .as_ref()
            .map(|s| !s.is_empty())
            .unwrap_or(false)
    }

    /// Set the text selection.
    pub fn set_text_selection(&mut self, selection: Option<String>) {
        self.text_selection = selection;
    }

    /// Get the text selection.
    pub fn get_text_selection(&self) -> Option<&str> {
        self.text_selection.as_deref()
    }

    // -- Function-related methods (from Java's DecompilerActionContext) --

    /// Set the function name for this context.
    pub fn set_function_name(&mut self, name: Option<String>) {
        self.function_name = name;
    }

    /// Get the function name, if known.
    pub fn get_function_name(&self) -> Option<&str> {
        self.function_name.as_deref()
    }

    /// Mark the current function as undefined (placeholder).
    pub fn set_undefined_function(&mut self, undefined: bool) {
        self.is_undefined_function = undefined;
    }

    /// Returns `true` if the current function is a real (non-undefined) function.
    pub fn has_real_function(&self) -> bool {
        !self.is_undefined_function && self.function_name.is_some()
    }

    /// Set the high-level function reference.
    pub fn set_high_function(&mut self, hf: Option<HighFunctionRef>) {
        self.high_function = hf;
    }

    /// Get the high-level function reference.
    pub fn get_high_function(&self) -> Option<&HighFunctionRef> {
        self.high_function.as_ref()
    }

    /// Set the C code model reference.
    pub fn set_c_code_model(&mut self, model: Option<CCodeModelRef>) {
        self.c_code_model = model;
    }

    /// Get the C code model reference.
    pub fn get_c_code_model(&self) -> Option<&CCodeModelRef> {
        self.c_code_model.as_ref()
    }

    /// Set a status message (delegates to the controller).
    pub fn set_status_message(&mut self, _msg: &str) {
        // In the full implementation this delegates to
        // `controller.setStatusMessage(msg)`.
    }

    // -- Label-related methods (used by label_actions) --

    /// Returns `true` if the token at the cursor is a label token.
    pub fn is_label_token_at_cursor(&self) -> bool {
        self.token_at_cursor
            .as_ref()
            .map(|t| t.is_label_token())
            .unwrap_or(false)
    }

    /// Returns label information for the token at the cursor.
    ///
    /// This is `Some(LabelInfo)` when the cursor is on a label token and
    /// the label's address is known.
    pub fn label_info_at_cursor(&self) -> Option<LabelInfo> {
        let token = self.token_at_cursor.as_ref()?;
        if !token.is_label_token() {
            return None;
        }
        let addr = token.label_address?;
        Some(LabelInfo {
            address: addr.offset,
            name: token.text.clone(),
            source: LabelSource::UserDefined,
            is_primary: true,
        })
    }

    /// Request a label edit dialog (consumed by the provider layer).
    pub fn request_label_edit(&mut self, request: LabelEditRequest) {
        self.pending_label_edit = Some(request);
    }

    /// Consume and return any pending label edit request.
    pub fn take_pending_label_edit(&mut self) -> Option<LabelEditRequest> {
        self.pending_label_edit.take()
    }

    /// Returns `true` if a label edit request is pending.
    pub fn has_pending_label_edit(&self) -> bool {
        self.pending_label_edit.is_some()
    }

    // -- Methods needed by highlight navigation actions --

    /// Get the middle-mouse highlight set for the current function.
    pub fn middle_mouse_highlights(&self) -> Option<&MiddleMouseHighlightSet> {
        self.middle_mouse_highlights.as_ref()
    }

    /// Set the middle-mouse highlight set.
    pub fn set_middle_mouse_highlights(&mut self, highlights: Option<MiddleMouseHighlightSet>) {
        self.middle_mouse_highlights = highlights;
    }

    /// Get the token stream for the current decompiled output.
    pub fn token_stream(&self) -> Option<&TokenStream> {
        self.token_stream.as_ref()
    }

    /// Set the token stream.
    pub fn set_token_stream(&mut self, stream: Option<TokenStream>) {
        self.token_stream = stream;
    }

    /// Navigate to a specific token (sets the cursor position).
    pub fn go_to_token(&mut self, token: &TokenRef) {
        let new_token = ClangTokenRef {
            text: token.text.clone(),
            line_number: token.line_index + 1,
            column: token.column_offset,
            kind: ClangTokenKind::Syntax,
            is_function_name: false,
            function_entry: None,
            label_address: None,
            text_offset: 0,
        };
        self.token_at_cursor = Some(new_token);
    }

    // -- Methods needed by secondary highlight actions --

    /// Get the text of the token at the cursor.
    pub fn token_text_at_cursor(&self) -> Option<String> {
        self.token_at_cursor.as_ref().map(|t| t.text.clone())
    }

    /// Get the function entry address as a u64.
    pub fn function_entry(&self) -> u64 {
        self.function_entry_point.offset
    }

    /// Get a reference to the secondary highlight store.
    pub fn secondary_highlight_store(&self) -> &SecondaryHighlightStore {
        &self.secondary_highlight_store
    }

    /// Get a mutable reference to the secondary highlight store.
    pub fn secondary_highlight_store_mut(&mut self) -> &mut SecondaryHighlightStore {
        &mut self.secondary_highlight_store
    }

    // -- Methods needed by convert constant action --

    /// Get the text of the token at the cursor (alias).
    pub fn token_at_cursor_text(&self) -> Option<String> {
        self.token_at_cursor.as_ref().map(|t| t.text.clone())
    }

    /// Check if the token at the cursor is a case keyword.
    pub fn is_case_token_at_cursor(&self) -> bool {
        self.token_at_cursor
            .as_ref()
            .map(|t| t.text == "case" || t.text.starts_with("case "))
            .unwrap_or(false)
    }

    /// Get the varnode at cursor.
    pub fn varnode_at_cursor(&self) -> Option<super::convert_constant_action::VarnodeInfo> {
        let token = self.token_at_cursor.as_ref()?;
        Some(super::convert_constant_action::VarnodeInfo {
            is_constant: token.kind == ClangTokenKind::Constant,
            size: 8,
            offset: token.text.parse::<u64>().unwrap_or(0),
            high_symbol: None,
            data_type: None,
            pcode_op_address: None,
            dynamic_hash: None,
        })
    }

    /// Find a scalar match for the given value.
    pub fn find_scalar_match(
        &self,
        _address: Address,
        _scalar: &super::convert_constant_action::ScalarInfo,
        _window: usize,
    ) -> Option<super::convert_constant_action::ScalarMatch> {
        None
    }

    /// Get the scalar value of a case token at cursor.
    pub fn case_token_scalar_at_cursor(&self) -> Option<super::convert_constant_action::ScalarInfo> {
        if !self.is_case_token_at_cursor() {
            return None;
        }
        self.parse_token_as_number().map(|v| {
            super::convert_constant_action::ScalarInfo::new(64, v, false)
        })
    }

    // ========================================================================
    // Function-for-location (from Java's DecompilerActionContext)
    // ========================================================================

    /// Resolve the function associated with the token at the cursor.
    ///
    /// Mirrors Ghidra's `getFunctionForLocation()`.  If the cursor is on
    /// a function-name token, returns that function's entry point and name.
    /// Otherwise returns `None`.
    pub fn get_function_for_location(&self) -> Option<FunctionRef> {
        let token = self.token_at_cursor.as_ref()?;
        if !token.is_func_name_token() {
            return None;
        }
        let entry = token.function_entry?;
        Some(FunctionRef {
            name: token.text.clone(),
            entry_point: entry,
            is_external: false,
        })
    }

    // ========================================================================
    // Enhanced has_selection (from Java's NavigatableActionContext)
    // ========================================================================

    /// Check whether the context has any kind of selection.
    ///
    /// In Ghidra, `DecompilerActionContext.hasSelection()` checks both
    /// the text selection (from the decompiler panel) AND the program
    /// selection (range selection).  This mirrors that behavior.
    pub fn has_any_selection(&self) -> bool {
        // Check text selection first (same as Java's override).
        if let Some(sel) = &self.text_selection {
            if !sel.is_empty() {
                return true;
            }
        }
        // Also check secondary highlight store (program-level selection).
        self.secondary_highlight_store.has_highlights()
    }

    // ========================================================================
    // Context validity checks (from Java's isEnabledForContext pattern)
    // ========================================================================

    /// Returns `true` if this context is valid for decompiler actions.
    ///
    /// In Ghidra, most actions check `isEnabledForContext()` which
    /// requires: a non-null function, decompile results available,
    /// and the decompiler not currently working.
    pub fn is_valid_for_action(&self) -> bool {
        !self.is_decompiling && self.has_real_function()
    }

    /// Returns `true` if a rename action is valid for this context.
    ///
    /// Combines the validity check with whether the cursor is on a
    /// renameable token.
    pub fn is_rename_action_valid(&self) -> bool {
        self.is_valid_for_action() && self.is_renameable_token()
    }

    /// Returns `true` if a retype action is valid for this context.
    ///
    /// Combines the validity check with whether the cursor is on a
    /// retypeable token.
    pub fn is_retype_action_valid(&self) -> bool {
        self.is_valid_for_action() && self.is_retypeable_token()
    }

    /// Returns `true` if a find-references action is valid.
    ///
    /// Requires a valid context with the cursor on a variable, field,
    /// function-name, or label token.
    pub fn is_find_references_valid(&self) -> bool {
        self.is_valid_for_action()
            && self
                .token_at_cursor
                .as_ref()
                .map(|t| {
                    matches!(
                        t.kind,
                        ClangTokenKind::Variable
                            | ClangTokenKind::Field
                            | ClangTokenKind::FunctionName
                            | ClangTokenKind::Label
                    )
                })
                .unwrap_or(false)
    }

    // ========================================================================
    // Token text helpers (used by convert/equate actions)
    // ========================================================================

    /// Parse the token text as a numeric value.
    ///
    /// Attempts to parse the token at the cursor as either a decimal or
    /// hexadecimal number.  Returns `None` if the token is not numeric.
    pub fn parse_token_as_number(&self) -> Option<u64> {
        let text = self.token_at_cursor.as_ref()?.text.trim();
        if text.starts_with("0x") || text.starts_with("0X") {
            u64::from_str_radix(&text[2..], 16).ok()
        } else {
            text.parse::<u64>().ok().or_else(|| {
                // Try as i64 and convert.
                text.parse::<i64>().ok().map(|v| v as u64)
            })
        }
    }

    /// Get the display text for the current token (for status bar).
    ///
    /// Returns a formatted string suitable for display in the tool's
    /// status bar, including the token kind and text.
    pub fn token_display_info(&self) -> Option<String> {
        let token = self.token_at_cursor.as_ref()?;
        let kind_str = match token.kind {
            ClangTokenKind::Syntax => "token",
            ClangTokenKind::FunctionName => "function",
            ClangTokenKind::Label => "label",
            ClangTokenKind::Field => "field",
            ClangTokenKind::Variable => "variable",
            ClangTokenKind::TypeName => "type",
            ClangTokenKind::Comment => "comment",
            ClangTokenKind::Constant => "constant",
        };
        Some(format!("{}: {}", kind_str, token.text))
    }

    // ========================================================================
    // Status message (delegates to provider/controller)
    // ========================================================================

    /// Set a status message in the tool's status bar.
    ///
    /// In Ghidra this delegates to `controller.setStatusMessage(msg)`.
    /// The message is stored here for test inspection.
    pub fn set_status_message_stored(&mut self, msg: impl Into<String>) {
        self.last_status_message = Some(msg.into());
    }

    /// Get the last status message that was set.
    pub fn last_status_message(&self) -> Option<&str> {
        self.last_status_message.as_deref()
    }

    /// Clear the stored status message.
    pub fn clear_status_message(&mut self) {
        self.last_status_message = None;
    }

    /// Check whether the token at the cursor references a function.
    ///
    /// Returns `true` if the cursor is on a `ClangFuncNameToken`.
    pub fn is_function_token_at_cursor(&self) -> bool {
        self.token_at_cursor
            .as_ref()
            .map(|t| t.is_func_name_token())
            .unwrap_or(false)
    }

    /// Get the variable kind at the cursor (local, global, field, param).
    ///
    /// Mirrors the information used by rename/retype actions to determine
    /// what kind of variable the cursor is on.
    pub fn variable_kind_at_cursor(&self) -> Option<VariableKind> {
        let token = self.token_at_cursor.as_ref()?;
        match token.kind {
            ClangTokenKind::Variable => Some(VariableKind::Local),
            ClangTokenKind::Field => Some(VariableKind::Field),
            _ => None,
        }
    }

    /// Check if the cursor is on a token that can be renamed.
    ///
    /// Returns `true` for variable, field, function-name, and label tokens.
    pub fn is_renameable_token(&self) -> bool {
        let token = match self.token_at_cursor.as_ref() {
            Some(t) => t,
            None => return false,
        };
        matches!(
            token.kind,
            ClangTokenKind::Variable
                | ClangTokenKind::Field
                | ClangTokenKind::FunctionName
                | ClangTokenKind::Label
        )
    }

    /// Check if the cursor is on a token that can be retyped.
    ///
    /// Returns `true` for variable and field tokens.
    pub fn is_retypeable_token(&self) -> bool {
        let token = match self.token_at_cursor.as_ref() {
            Some(t) => t,
            None => return false,
        };
        matches!(
            token.kind,
            ClangTokenKind::Variable | ClangTokenKind::Field
        )
    }
}

// ---------------------------------------------------------------------------
// FunctionRef -- lightweight stand-in for Function
// ---------------------------------------------------------------------------

/// A reference to a function resolved from a token.
///
/// In Ghidra this is a `Function` object obtained via
/// `DecompilerUtils.getFunction(Program, ClangFuncNameToken)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionRef {
    /// The function's name.
    pub name: String,
    /// The function's entry-point address.
    pub entry_point: Address,
    /// Whether this is an external function.
    pub is_external: bool,
}

// ---------------------------------------------------------------------------
// VariableKind -- the kind of variable under the cursor
// ---------------------------------------------------------------------------

/// The kind of variable the cursor is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariableKind {
    /// A local variable.
    Local,
    /// A global variable / symbol.
    Global,
    /// A struct/union field.
    Field,
    /// A function parameter.
    Parameter,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_new() {
        let ctx = DecompilerActionContext::new(Address::new(0x1000), false, 5);
        assert_eq!(ctx.get_function_entry_point(), Address::new(0x1000));
        assert!(!ctx.is_decompiling());
        assert_eq!(ctx.get_line_number(), 5);
    }

    #[test]
    fn test_context_from_token_uses_token_line() {
        let mut ctx = DecompilerActionContext::from_token(Address::new(0x2000), true);
        assert!(ctx.is_decompiling());
        assert_eq!(ctx.get_line_number(), 0); // no token set yet

        ctx.set_token_at_cursor(ClangTokenRef::new("main", 3, 0, true, Some(Address::new(0x2000)), 0));
        assert_eq!(ctx.get_line_number(), 3);
    }

    #[test]
    fn test_context_explicit_line_overrides_token() {
        let mut ctx = DecompilerActionContext::new(Address::new(0x3000), false, 10);
        ctx.set_token_at_cursor(ClangTokenRef::new("x", 42, 0, false, None, 0));
        // Explicit line number wins.
        assert_eq!(ctx.get_line_number(), 10);
    }

    #[test]
    fn test_clang_token_ref() {
        let token = ClangTokenRef::new("foo", 7, 3, false, None, 42);
        assert_eq!(token.text, "foo");
        assert_eq!(token.line_parent_line_number(), 7);
        assert!(!token.is_function_name);
        assert_eq!(token.kind, ClangTokenKind::Syntax);
    }

    #[test]
    fn test_clang_token_ref_label() {
        let token = ClangTokenRef::new_label("LAB_001000", 5, 0, Address::new(0x1000), 100);
        assert!(token.is_label_token());
        assert!(!token.is_func_name_token());
        assert_eq!(token.label_address, Some(Address::new(0x1000)));
    }

    #[test]
    fn test_clang_token_ref_function_name() {
        let token = ClangTokenRef::new("main", 1, 0, true, Some(Address::new(0x4000)), 0);
        assert!(token.is_func_name_token());
        assert!(!token.is_label_token());
        assert_eq!(token.kind, ClangTokenKind::FunctionName);
    }

    #[test]
    fn test_has_selection_empty() {
        let ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        assert!(!ctx.has_selection());
    }

    #[test]
    fn test_has_selection_with_text() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        ctx.set_text_selection(Some("selected text".into()));
        assert!(ctx.has_selection());
    }

    #[test]
    fn test_has_selection_empty_string() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        ctx.set_text_selection(Some(String::new()));
        assert!(!ctx.has_selection());
    }

    #[test]
    fn test_label_token_at_cursor_none() {
        let ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        assert!(!ctx.is_label_token_at_cursor());
        assert!(ctx.label_info_at_cursor().is_none());
    }

    #[test]
    fn test_label_token_at_cursor_non_label() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        ctx.set_token_at_cursor(ClangTokenRef::new("x", 1, 0, false, None, 0));
        assert!(!ctx.is_label_token_at_cursor());
    }

    #[test]
    fn test_label_token_at_cursor_is_label() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        ctx.set_token_at_cursor(
            ClangTokenRef::new_label("LAB_001000", 3, 0, Address::new(0x1000), 0),
        );
        assert!(ctx.is_label_token_at_cursor());

        let info = ctx.label_info_at_cursor().unwrap();
        assert_eq!(info.address, 0x1000);
        assert_eq!(info.name, "LAB_001000");
    }

    #[test]
    fn test_pending_label_edit_request() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        assert!(!ctx.has_pending_label_edit());
        assert!(ctx.take_pending_label_edit().is_none());

        ctx.request_label_edit(LabelEditRequest::add(0x2000));
        assert!(ctx.has_pending_label_edit());

        let req = ctx.take_pending_label_edit().unwrap();
        assert_eq!(req.address, 0x2000);
        assert!(!ctx.has_pending_label_edit());
    }

    #[test]
    fn test_function_name_and_real_function() {
        let mut ctx = DecompilerActionContext::new(Address::new(0x4000), false, 0);
        assert!(!ctx.has_real_function());

        ctx.set_function_name(Some("main".into()));
        assert!(ctx.has_real_function());

        ctx.set_undefined_function(true);
        assert!(!ctx.has_real_function());
    }

    #[test]
    fn test_high_function_ref() {
        let mut ctx = DecompilerActionContext::new(Address::new(0x4000), false, 0);
        assert!(ctx.get_high_function().is_none());

        ctx.set_high_function(Some(HighFunctionRef {
            function_entry: Address::new(0x4000),
            has_prototype_override: false,
        }));
        let hf = ctx.get_high_function().unwrap();
        assert_eq!(hf.function_entry, Address::new(0x4000));
    }

    #[test]
    fn test_c_code_model_ref() {
        let mut ctx = DecompilerActionContext::new(Address::new(0x4000), false, 0);
        assert!(ctx.get_c_code_model().is_none());

        ctx.set_c_code_model(Some(CCodeModelRef {
            function_entry: Address::new(0x4000),
        }));
        let model = ctx.get_c_code_model().unwrap();
        assert_eq!(model.function_entry, Address::new(0x4000));
    }

    #[test]
    fn test_token_kind_default() {
        assert_eq!(ClangTokenKind::default(), ClangTokenKind::Syntax);
    }

    // -- get_function_for_location tests --

    #[test]
    fn test_get_function_for_location_none() {
        let ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        assert!(ctx.get_function_for_location().is_none());
    }

    #[test]
    fn test_get_function_for_location_non_function_token() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        ctx.set_token_at_cursor(ClangTokenRef::new("x", 1, 0, false, None, 0));
        assert!(ctx.get_function_for_location().is_none());
    }

    #[test]
    fn test_get_function_for_location_function_token() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        ctx.set_token_at_cursor(ClangTokenRef::new(
            "main",
            1,
            0,
            true,
            Some(Address::new(0x4000)),
            0,
        ));
        let func = ctx.get_function_for_location().unwrap();
        assert_eq!(func.name, "main");
        assert_eq!(func.entry_point, Address::new(0x4000));
        assert!(!func.is_external);
    }

    #[test]
    fn test_get_function_for_location_no_entry() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        // Function name token but no entry point.
        ctx.set_token_at_cursor(ClangTokenRef::new("unknown", 1, 0, true, None, 0));
        assert!(ctx.get_function_for_location().is_none());
    }

    // -- is_function_token_at_cursor tests --

    #[test]
    fn test_is_function_token_at_cursor_none() {
        let ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        assert!(!ctx.is_function_token_at_cursor());
    }

    #[test]
    fn test_is_function_token_at_cursor_true() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        ctx.set_token_at_cursor(ClangTokenRef::new(
            "printf",
            1,
            0,
            true,
            Some(Address::new(0)),
            0,
        ));
        assert!(ctx.is_function_token_at_cursor());
    }

    #[test]
    fn test_is_function_token_at_cursor_false() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        ctx.set_token_at_cursor(ClangTokenRef::new("x", 1, 0, false, None, 0));
        assert!(!ctx.is_function_token_at_cursor());
    }

    // -- variable_kind_at_cursor tests --

    #[test]
    fn test_variable_kind_at_cursor_none() {
        let ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        assert!(ctx.variable_kind_at_cursor().is_none());
    }

    #[test]
    fn test_variable_kind_at_cursor_variable() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        let mut token = ClangTokenRef::new("localVar", 1, 0, false, None, 0);
        token.kind = ClangTokenKind::Variable;
        ctx.set_token_at_cursor(token);
        assert_eq!(ctx.variable_kind_at_cursor(), Some(VariableKind::Local));
    }

    #[test]
    fn test_variable_kind_at_cursor_field() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        let mut token = ClangTokenRef::new("field", 1, 0, false, None, 0);
        token.kind = ClangTokenKind::Field;
        ctx.set_token_at_cursor(token);
        assert_eq!(ctx.variable_kind_at_cursor(), Some(VariableKind::Field));
    }

    #[test]
    fn test_variable_kind_at_cursor_syntax() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        ctx.set_token_at_cursor(ClangTokenRef::new("return", 1, 0, false, None, 0));
        assert!(ctx.variable_kind_at_cursor().is_none());
    }

    // -- is_renameable_token tests --

    #[test]
    fn test_is_renameable_token_none() {
        let ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        assert!(!ctx.is_renameable_token());
    }

    #[test]
    fn test_is_renameable_token_variable() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        let mut token = ClangTokenRef::new("x", 1, 0, false, None, 0);
        token.kind = ClangTokenKind::Variable;
        ctx.set_token_at_cursor(token);
        assert!(ctx.is_renameable_token());
    }

    #[test]
    fn test_is_renameable_token_function() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        ctx.set_token_at_cursor(ClangTokenRef::new("main", 1, 0, true, Some(Address::new(0)), 0));
        assert!(ctx.is_renameable_token());
    }

    #[test]
    fn test_is_renameable_token_label() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        ctx.set_token_at_cursor(ClangTokenRef::new_label("LAB_001", 1, 0, Address::new(0), 0));
        assert!(ctx.is_renameable_token());
    }

    #[test]
    fn test_is_renameable_token_syntax() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        ctx.set_token_at_cursor(ClangTokenRef::new("return", 1, 0, false, None, 0));
        assert!(!ctx.is_renameable_token());
    }

    // -- is_retypeable_token tests --

    #[test]
    fn test_is_retypeable_token_none() {
        let ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        assert!(!ctx.is_retypeable_token());
    }

    #[test]
    fn test_is_retypeable_token_variable() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        let mut token = ClangTokenRef::new("x", 1, 0, false, None, 0);
        token.kind = ClangTokenKind::Variable;
        ctx.set_token_at_cursor(token);
        assert!(ctx.is_retypeable_token());
    }

    #[test]
    fn test_is_retypeable_token_field() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        let mut token = ClangTokenRef::new("field", 1, 0, false, None, 0);
        token.kind = ClangTokenKind::Field;
        ctx.set_token_at_cursor(token);
        assert!(ctx.is_retypeable_token());
    }

    #[test]
    fn test_is_retypeable_token_function() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        ctx.set_token_at_cursor(ClangTokenRef::new("main", 1, 0, true, Some(Address::new(0)), 0));
        // Function tokens are not retypeable.
        assert!(!ctx.is_retypeable_token());
    }

    // -- FunctionRef tests --

    #[test]
    fn test_function_ref_clone() {
        let func = FunctionRef {
            name: "test".into(),
            entry_point: Address::new(0x1000),
            is_external: false,
        };
        let cloned = func.clone();
        assert_eq!(func, cloned);
    }

    // -- VariableKind tests --

    #[test]
    fn test_variable_kind_clone_copy() {
        let kind = VariableKind::Local;
        let copied = kind;
        assert_eq!(kind, copied);
    }

    // -- has_any_selection tests --

    #[test]
    fn test_has_any_selection_empty() {
        let ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        assert!(!ctx.has_any_selection());
    }

    #[test]
    fn test_has_any_selection_with_text() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        ctx.set_text_selection(Some("selected text".into()));
        assert!(ctx.has_any_selection());
    }

    #[test]
    fn test_has_any_selection_empty_string() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        ctx.set_text_selection(Some(String::new()));
        assert!(!ctx.has_any_selection());
    }

    // -- is_valid_for_action tests --

    #[test]
    fn test_is_valid_for_action_not_decompiling() {
        let mut ctx = DecompilerActionContext::new(Address::new(0x4000), false, 0);
        ctx.set_function_name(Some("main".into()));
        assert!(ctx.is_valid_for_action());
    }

    #[test]
    fn test_is_valid_for_action_decompiling() {
        let mut ctx = DecompilerActionContext::new(Address::new(0x4000), true, 0);
        ctx.set_function_name(Some("main".into()));
        assert!(!ctx.is_valid_for_action());
    }

    #[test]
    fn test_is_valid_for_action_no_function() {
        let ctx = DecompilerActionContext::new(Address::new(0x4000), false, 0);
        assert!(!ctx.is_valid_for_action());
    }

    #[test]
    fn test_is_valid_for_action_undefined_function() {
        let mut ctx = DecompilerActionContext::new(Address::new(0x4000), false, 0);
        ctx.set_function_name(Some("main".into()));
        ctx.set_undefined_function(true);
        assert!(!ctx.is_valid_for_action());
    }

    // -- is_rename_action_valid tests --

    #[test]
    fn test_is_rename_action_valid_variable() {
        let mut ctx = DecompilerActionContext::new(Address::new(0x4000), false, 0);
        ctx.set_function_name(Some("main".into()));
        let mut token = ClangTokenRef::new("x", 1, 0, false, None, 0);
        token.kind = ClangTokenKind::Variable;
        ctx.set_token_at_cursor(token);
        assert!(ctx.is_rename_action_valid());
    }

    #[test]
    fn test_is_rename_action_valid_syntax_token() {
        let mut ctx = DecompilerActionContext::new(Address::new(0x4000), false, 0);
        ctx.set_function_name(Some("main".into()));
        ctx.set_token_at_cursor(ClangTokenRef::new("return", 1, 0, false, None, 0));
        assert!(!ctx.is_rename_action_valid());
    }

    #[test]
    fn test_is_rename_action_valid_decompiling() {
        let mut ctx = DecompilerActionContext::new(Address::new(0x4000), true, 0);
        ctx.set_function_name(Some("main".into()));
        let mut token = ClangTokenRef::new("x", 1, 0, false, None, 0);
        token.kind = ClangTokenKind::Variable;
        ctx.set_token_at_cursor(token);
        assert!(!ctx.is_rename_action_valid());
    }

    // -- is_retype_action_valid tests --

    #[test]
    fn test_is_retype_action_valid_field() {
        let mut ctx = DecompilerActionContext::new(Address::new(0x4000), false, 0);
        ctx.set_function_name(Some("main".into()));
        let mut token = ClangTokenRef::new("field", 1, 0, false, None, 0);
        token.kind = ClangTokenKind::Field;
        ctx.set_token_at_cursor(token);
        assert!(ctx.is_retype_action_valid());
    }

    #[test]
    fn test_is_retype_action_valid_function_token() {
        let mut ctx = DecompilerActionContext::new(Address::new(0x4000), false, 0);
        ctx.set_function_name(Some("main".into()));
        ctx.set_token_at_cursor(ClangTokenRef::new(
            "func",
            1,
            0,
            true,
            Some(Address::new(0x1000)),
            0,
        ));
        assert!(!ctx.is_retype_action_valid());
    }

    // -- is_find_references_valid tests --

    #[test]
    fn test_is_find_references_valid_variable() {
        let mut ctx = DecompilerActionContext::new(Address::new(0x4000), false, 0);
        ctx.set_function_name(Some("main".into()));
        let mut token = ClangTokenRef::new("x", 1, 0, false, None, 0);
        token.kind = ClangTokenKind::Variable;
        ctx.set_token_at_cursor(token);
        assert!(ctx.is_find_references_valid());
    }

    #[test]
    fn test_is_find_references_valid_function_name() {
        let mut ctx = DecompilerActionContext::new(Address::new(0x4000), false, 0);
        ctx.set_function_name(Some("main".into()));
        ctx.set_token_at_cursor(ClangTokenRef::new(
            "printf",
            1,
            0,
            true,
            Some(Address::new(0)),
            0,
        ));
        assert!(ctx.is_find_references_valid());
    }

    #[test]
    fn test_is_find_references_valid_syntax() {
        let mut ctx = DecompilerActionContext::new(Address::new(0x4000), false, 0);
        ctx.set_function_name(Some("main".into()));
        ctx.set_token_at_cursor(ClangTokenRef::new("return", 1, 0, false, None, 0));
        assert!(!ctx.is_find_references_valid());
    }

    #[test]
    fn test_is_find_references_valid_no_token() {
        let mut ctx = DecompilerActionContext::new(Address::new(0x4000), false, 0);
        ctx.set_function_name(Some("main".into()));
        assert!(!ctx.is_find_references_valid());
    }

    // -- parse_token_as_number tests --

    #[test]
    fn test_parse_token_as_number_decimal() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        ctx.set_token_at_cursor(ClangTokenRef::new("42", 1, 0, false, None, 0));
        assert_eq!(ctx.parse_token_as_number(), Some(42));
    }

    #[test]
    fn test_parse_token_as_number_hex() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        ctx.set_token_at_cursor(ClangTokenRef::new("0xFF", 1, 0, false, None, 0));
        assert_eq!(ctx.parse_token_as_number(), Some(0xFF));
    }

    #[test]
    fn test_parse_token_as_number_hex_upper() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        ctx.set_token_at_cursor(ClangTokenRef::new("0X10", 1, 0, false, None, 0));
        assert_eq!(ctx.parse_token_as_number(), Some(0x10));
    }

    #[test]
    fn test_parse_token_as_number_negative() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        ctx.set_token_at_cursor(ClangTokenRef::new("-1", 1, 0, false, None, 0));
        assert_eq!(ctx.parse_token_as_number(), Some((-1i64) as u64));
    }

    #[test]
    fn test_parse_token_as_number_non_numeric() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        ctx.set_token_at_cursor(ClangTokenRef::new("foo", 1, 0, false, None, 0));
        assert_eq!(ctx.parse_token_as_number(), None);
    }

    #[test]
    fn test_parse_token_as_number_none() {
        let ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        assert_eq!(ctx.parse_token_as_number(), None);
    }

    // -- token_display_info tests --

    #[test]
    fn test_token_display_info_none() {
        let ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        assert!(ctx.token_display_info().is_none());
    }

    #[test]
    fn test_token_display_info_variable() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        let mut token = ClangTokenRef::new("myVar", 1, 0, false, None, 0);
        token.kind = ClangTokenKind::Variable;
        ctx.set_token_at_cursor(token);
        let info = ctx.token_display_info().unwrap();
        assert!(info.contains("variable"));
        assert!(info.contains("myVar"));
    }

    #[test]
    fn test_token_display_info_function() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        ctx.set_token_at_cursor(ClangTokenRef::new(
            "printf",
            1,
            0,
            true,
            Some(Address::new(0)),
            0,
        ));
        let info = ctx.token_display_info().unwrap();
        assert!(info.contains("function"));
        assert!(info.contains("printf"));
    }

    #[test]
    fn test_token_display_info_label() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        ctx.set_token_at_cursor(ClangTokenRef::new_label(
            "LAB_001",
            1,
            0,
            Address::new(0x1000),
            0,
        ));
        let info = ctx.token_display_info().unwrap();
        assert!(info.contains("label"));
        assert!(info.contains("LAB_001"));
    }

    #[test]
    fn test_token_display_info_constant() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        let mut token = ClangTokenRef::new("0x42", 1, 0, false, None, 0);
        token.kind = ClangTokenKind::Constant;
        ctx.set_token_at_cursor(token);
        let info = ctx.token_display_info().unwrap();
        assert!(info.contains("constant"));
    }

    // -- status message tests --

    #[test]
    fn test_status_message_stored() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        assert!(ctx.last_status_message().is_none());

        ctx.set_status_message_stored("Decompiling...");
        assert_eq!(ctx.last_status_message(), Some("Decompiling..."));

        ctx.clear_status_message();
        assert!(ctx.last_status_message().is_none());
    }

    // -- edge case: is_rename_action_valid with label --

    #[test]
    fn test_is_rename_action_valid_label() {
        let mut ctx = DecompilerActionContext::new(Address::new(0x4000), false, 0);
        ctx.set_function_name(Some("main".into()));
        ctx.set_token_at_cursor(ClangTokenRef::new_label(
            "LAB_001",
            1,
            0,
            Address::new(0x1000),
            0,
        ));
        assert!(ctx.is_rename_action_valid());
    }

    // -- edge case: is_rename_action_valid no token --

    #[test]
    fn test_is_rename_action_valid_no_token() {
        let mut ctx = DecompilerActionContext::new(Address::new(0x4000), false, 0);
        ctx.set_function_name(Some("main".into()));
        assert!(!ctx.is_rename_action_valid());
    }

    // -- edge case: is_retype_action_valid variable --

    #[test]
    fn test_is_retype_action_valid_variable() {
        let mut ctx = DecompilerActionContext::new(Address::new(0x4000), false, 0);
        ctx.set_function_name(Some("main".into()));
        let mut token = ClangTokenRef::new("localVar", 1, 0, false, None, 0);
        token.kind = ClangTokenKind::Variable;
        ctx.set_token_at_cursor(token);
        assert!(ctx.is_retype_action_valid());
    }

    // -- edge case: is_retype_action_valid label (not retypeable) --

    #[test]
    fn test_is_retype_action_valid_label() {
        let mut ctx = DecompilerActionContext::new(Address::new(0x4000), false, 0);
        ctx.set_function_name(Some("main".into()));
        ctx.set_token_at_cursor(ClangTokenRef::new_label(
            "LAB_001",
            1,
            0,
            Address::new(0x1000),
            0,
        ));
        assert!(!ctx.is_retype_action_valid());
    }

    // -- edge case: is_find_references_valid constant --

    #[test]
    fn test_is_find_references_valid_constant() {
        let mut ctx = DecompilerActionContext::new(Address::new(0x4000), false, 0);
        ctx.set_function_name(Some("main".into()));
        let mut token = ClangTokenRef::new("42", 1, 0, false, None, 0);
        token.kind = ClangTokenKind::Constant;
        ctx.set_token_at_cursor(token);
        assert!(!ctx.is_find_references_valid());
    }
}
