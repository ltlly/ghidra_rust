//! Decompiler action context -- Rust port of
//! `ghidra.app.plugin.core.decompile.DecompilerActionContext`.
//!
//! Holds the context that is passed to every decompiler action when the
//! user right-clicks or triggers a key-binding inside the decompiler panel.
//! Captures the function entry point, whether a decompile is still in
//! progress, the current line number, and the token under the cursor.

use ghidra_core::addr::Address;

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
    /// `true` when this token names a function.
    pub is_function_name: bool,
    /// When the token names a function, the entry-point address.
    pub function_entry: Option<Address>,
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
            is_function_name,
            function_entry,
            text_offset,
        }
    }

    /// Convenience: returns the 1-based line number.
    pub fn line_parent_line_number(&self) -> usize {
        self.line_number
    }
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
        // In a full implementation this would check both the panel's text
        // selection and the range selection.  For now, we only check if a
        // token is present (mimicking the text-blank check in Java).
        self.token_at_cursor.is_some()
    }
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
    }

    #[test]
    fn test_has_selection_empty() {
        let ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        assert!(!ctx.has_selection());
    }

    #[test]
    fn test_has_selection_with_token() {
        let mut ctx = DecompilerActionContext::new(Address::new(0), false, 0);
        ctx.set_token_at_cursor(ClangTokenRef::new("x", 1, 0, false, None, 0));
        assert!(ctx.has_selection());
    }
}
