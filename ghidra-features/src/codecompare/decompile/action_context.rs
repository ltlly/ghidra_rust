//! Action context for the dual decompiler comparison view.
//!
//! Ported from Ghidra's `DualDecompilerActionContext` Java class in
//! `ghidra.features.codecompare.decompile`.
//!
//! In Ghidra, an `ActionContext` carries information about where a user
//! action was triggered. The `DualDecompilerActionContext` extends the
//! base `CodeComparisonActionContext` with decompiler-specific state:
//! which decompiler panel has focus, the current token pair (if any),
//! and the high-level function data.
//!
//! In this Rust port we capture the logical state without the Swing/
//! docking framework dependency.
//!
//! # Key types
//!
//! - [`DecompilerDisplaySide`] -- which decompiler display has focus
//! - [`DualDecompilerActionContext`] -- action context for dual decompiler view
//! - [`DecompilerActionKind`] -- the kind of action being performed

use super::super::panel::action_context::{ActionTrigger, ComparisonActionContext};
use super::super::panel::ProgramInfo;
use super::super::model::ComparisonSide;
use super::token_pair::TokenPair;
use crate::codecompare::graphanalysis::Side;

/// Which decompiler display has focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecompilerDisplaySide {
    /// The left (source) decompiler panel.
    Left,
    /// The right (destination) decompiler panel.
    Right,
}

impl DecompilerDisplaySide {
    /// The opposite display side.
    pub fn opposite(&self) -> Self {
        match self {
            Self::Left => Self::Right,
            Self::Right => Self::Left,
        }
    }

    /// Convert to a `ComparisonSide`.
    pub fn to_comparison_side(&self) -> ComparisonSide {
        match self {
            Self::Left => ComparisonSide::Left,
            Self::Right => ComparisonSide::Right,
        }
    }

    /// Convert to a graphanalysis `Side`.
    pub fn to_side(&self) -> Side {
        match self {
            Self::Left => Side::Left,
            Self::Right => Side::Right,
        }
    }
}

impl From<Side> for DecompilerDisplaySide {
    fn from(side: Side) -> Self {
        match side {
            Side::Left => Self::Left,
            Side::Right => Self::Right,
        }
    }
}

impl From<ComparisonSide> for DecompilerDisplaySide {
    fn from(side: ComparisonSide) -> Self {
        match side {
            ComparisonSide::Left => Self::Left,
            ComparisonSide::Right => Self::Right,
        }
    }
}

/// The kind of action being performed in the dual decompiler view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecompilerActionKind {
    /// Apply a local variable name from the matched token.
    ApplyLocalName,
    /// Apply a global symbol name from the matched token.
    ApplyGlobalName,
    /// Apply a function signature from the matched token.
    ApplyFunctionSignature,
    /// Apply a callee signature with datatypes from the matched tokens.
    ApplyCalleeSignatureWithDatatypes,
    /// Apply an empty callee signature from the matched tokens.
    ApplyCalleeEmptySignature,
    /// Apply a callee function name from the matched tokens.
    ApplyCalleeFunctionName,
    /// Apply a variable type from the matched token.
    ApplyVariableType,
    /// Apply an empty variable type from the matched token.
    ApplyEmptyVariableType,
    /// Compare functions from the matched tokens.
    CompareFunctionsFromTokens,
    /// Generic/other action.
    Other,
}

impl DecompilerActionKind {
    /// A human-readable label for this action kind.
    pub fn label(&self) -> &'static str {
        match self {
            Self::ApplyLocalName => "Apply Local Name From Matched Tokens",
            Self::ApplyGlobalName => "Apply Global Name From Matched Tokens",
            Self::ApplyFunctionSignature => "Apply Function Signature From Matched Tokens",
            Self::ApplyCalleeSignatureWithDatatypes => {
                "Apply Callee Signature With Datatypes From Matched Tokens"
            }
            Self::ApplyCalleeEmptySignature => {
                "Apply Callee Empty Signature From Matched Tokens"
            }
            Self::ApplyCalleeFunctionName => "Apply Callee Function Name From Matched Tokens",
            Self::ApplyVariableType => "Apply Variable Type From Matched Tokens",
            Self::ApplyEmptyVariableType => "Apply Empty Variable Type From Matched Tokens",
            Self::CompareFunctionsFromTokens => "Compare Functions From Matched Tokens",
            Self::Other => "Other Action",
        }
    }

    /// A description of this action kind.
    pub fn description(&self) -> &'static str {
        match self {
            Self::ApplyLocalName => {
                "Copies the local variable name from the source function to the \
                 destination function for the matched token pair."
            }
            Self::ApplyGlobalName => {
                "Copies the global symbol name from the source function to the \
                 destination function for the matched token pair."
            }
            Self::ApplyFunctionSignature => {
                "Copies the function signature from the source function to the \
                 destination function for the matched token pair."
            }
            Self::ApplyCalleeSignatureWithDatatypes => {
                "Applies the callee signature with datatypes from the source \
                 function to the destination function."
            }
            Self::ApplyCalleeEmptySignature => {
                "Applies an empty callee signature from the source function to \
                 the destination function."
            }
            Self::ApplyCalleeFunctionName => {
                "Applies the callee function name from the source function to \
                 the destination function."
            }
            Self::ApplyVariableType => {
                "Copies the variable type from the source function to the \
                 destination function for the matched token pair."
            }
            Self::ApplyEmptyVariableType => {
                "Resets the variable type to empty for the matched token pair."
            }
            Self::CompareFunctionsFromTokens => {
                "Opens a new comparison for the functions referenced by the \
                 matched token pair."
            }
            Self::Other => "A generic action.",
        }
    }

    /// Whether this action requires a matched token pair to be available.
    pub fn requires_token_pair(&self) -> bool {
        !matches!(self, Self::Other)
    }

    /// Whether this action applies to a callee (function call target).
    pub fn is_callee_action(&self) -> bool {
        matches!(
            self,
            Self::ApplyCalleeSignatureWithDatatypes
                | Self::ApplyCalleeEmptySignature
                | Self::ApplyCalleeFunctionName
        )
    }
}

/// Information about a decompiler function for action context purposes.
///
/// Contains the high-level information about a decompiled function that
/// actions may need to access.
#[derive(Debug, Clone)]
pub struct DecompilerFunctionInfo {
    /// The function name.
    pub name: String,
    /// The entry point address.
    pub entry_point: u64,
    /// The program this function belongs to.
    pub program: ProgramInfo,
    /// Whether the program is read-only.
    pub is_read_only: bool,
    /// The number of local variables.
    pub local_variable_count: usize,
    /// The function signature as text.
    pub signature: String,
}

impl DecompilerFunctionInfo {
    /// Create new decompiler function info.
    pub fn new(
        name: impl Into<String>,
        entry_point: u64,
        program: ProgramInfo,
        signature: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            entry_point,
            program,
            is_read_only: false,
            local_variable_count: 0,
            signature: signature.into(),
        }
    }

    /// Get the display name.
    pub fn display_name(&self) -> String {
        format!("{}()", self.name)
    }
}

/// Action context for the dual decompiler comparison view.
///
/// Ported from Ghidra's `DualDecompilerActionContext` Java class.
///
/// This context is created when the user interacts with the dual
/// decompiler view (right-click, keyboard shortcut, etc.). It carries
/// references to the comparison view state, the focused token pair,
/// and the function information for both sides.
///
/// In the original Java, `DualDecompilerActionContext` extends
/// `CodeComparisonActionContext` and implements
/// `RestrictedAddressSetContext`. Here we capture the logical state.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::decompile::action_context::*;
/// use ghidra_features::codecompare::model::ComparisonSide;
/// use ghidra_features::codecompare::panel::action_context::ActionTrigger;
/// use ghidra_features::codecompare::panel::ProgramInfo;
///
/// let left_prog = ProgramInfo::new(1, "/old", "old_binary");
/// let right_prog = ProgramInfo::new(2, "/new", "new_binary");
///
/// let ctx = DualDecompilerActionContext::new(
///     DecompilerDisplaySide::Left,
///     ActionTrigger::Mouse,
///     Some(left_prog),
///     Some(right_prog),
/// );
///
/// assert_eq!(ctx.active_display(), DecompilerDisplaySide::Left);
/// assert!(ctx.token_pair().is_none());
/// ```
pub struct DualDecompilerActionContext {
    /// The base comparison action context.
    base: ComparisonActionContext,
    /// Which decompiler display has focus.
    active_display: DecompilerDisplaySide,
    /// The token pair at the current cursor position, if any.
    token_pair: Option<TokenPair>,
    /// The function info for the left (source) side.
    left_function: Option<DecompilerFunctionInfo>,
    /// The function info for the right (destination) side.
    right_function: Option<DecompilerFunctionInfo>,
    /// Whether the active program is read-only.
    active_program_read_only: bool,
    /// Override for read-only check (used in tests).
    override_read_only: bool,
    /// The address associated with this action.
    address: Option<u64>,
}

impl DualDecompilerActionContext {
    /// Create a new dual decompiler action context.
    pub fn new(
        active_display: DecompilerDisplaySide,
        trigger: ActionTrigger,
        left_program: Option<ProgramInfo>,
        right_program: Option<ProgramInfo>,
    ) -> Self {
        let comparison_side = active_display.to_comparison_side();
        Self {
            base: ComparisonActionContext::new(
                "DecompilerCodeComparisonView",
                comparison_side,
                trigger,
            ),
            active_display,
            token_pair: None,
            left_function: None,
            right_function: None,
            active_program_read_only: false,
            override_read_only: false,
            address: None,
        }
    }

    /// Create a context with a token pair.
    pub fn with_token_pair(
        active_display: DecompilerDisplaySide,
        trigger: ActionTrigger,
        token_pair: TokenPair,
        left_program: Option<ProgramInfo>,
        right_program: Option<ProgramInfo>,
    ) -> Self {
        let comparison_side = active_display.to_comparison_side();
        Self {
            base: ComparisonActionContext::new(
                "DecompilerCodeComparisonView",
                comparison_side,
                trigger,
            ),
            active_display,
            token_pair: Some(token_pair),
            left_function: None,
            right_function: None,
            active_program_read_only: false,
            override_read_only: false,
            address: None,
        }
    }

    /// Get the base action context.
    pub fn base(&self) -> &ComparisonActionContext {
        &self.base
    }

    /// Get a mutable reference to the base action context.
    pub fn base_mut(&mut self) -> &mut ComparisonActionContext {
        &mut self.base
    }

    /// Get the active decompiler display.
    pub fn active_display(&self) -> DecompilerDisplaySide {
        self.active_display
    }

    /// Get the inactive decompiler display.
    pub fn inactive_display(&self) -> DecompilerDisplaySide {
        self.active_display.opposite()
    }

    /// Get the token pair, if any.
    pub fn token_pair(&self) -> Option<&TokenPair> {
        self.token_pair.as_ref()
    }

    /// Set the token pair.
    pub fn set_token_pair(&mut self, pair: Option<TokenPair>) {
        self.token_pair = pair;
    }

    /// Check if a token pair is available.
    pub fn has_token_pair(&self) -> bool {
        self.token_pair.is_some()
    }

    /// Set the function info for the left side.
    pub fn set_left_function(&mut self, func: DecompilerFunctionInfo) {
        self.left_function = Some(func);
    }

    /// Get the function info for the left side.
    pub fn left_function(&self) -> Option<&DecompilerFunctionInfo> {
        self.left_function.as_ref()
    }

    /// Set the function info for the right side.
    pub fn set_right_function(&mut self, func: DecompilerFunctionInfo) {
        self.right_function = Some(func);
    }

    /// Get the function info for the right side.
    pub fn right_function(&self) -> Option<&DecompilerFunctionInfo> {
        self.right_function.as_ref()
    }

    /// Get the function info for the active display.
    pub fn active_function(&self) -> Option<&DecompilerFunctionInfo> {
        match self.active_display {
            DecompilerDisplaySide::Left => self.left_function.as_ref(),
            DecompilerDisplaySide::Right => self.right_function.as_ref(),
        }
    }

    /// Get the function info for the inactive display.
    pub fn inactive_function(&self) -> Option<&DecompilerFunctionInfo> {
        match self.active_display {
            DecompilerDisplaySide::Left => self.right_function.as_ref(),
            DecompilerDisplaySide::Right => self.left_function.as_ref(),
        }
    }

    /// Get the source function (the function providing the data to copy).
    ///
    /// In Ghidra's model, the source is the side the user is copying FROM.
    /// This is typically the inactive side (the one without focus).
    pub fn source_function(&self) -> Option<&DecompilerFunctionInfo> {
        self.inactive_function()
    }

    /// Get the target function (the function receiving the data).
    ///
    /// In Ghidra's model, the target is the side the user is copying TO.
    /// This is typically the active side (the one with focus).
    pub fn target_function(&self) -> Option<&DecompilerFunctionInfo> {
        self.active_function()
    }

    /// Set whether the active program is read-only.
    pub fn set_active_program_read_only(&mut self, read_only: bool) {
        self.active_program_read_only = read_only;
    }

    /// Check if the active program is read-only.
    ///
    /// Returns `false` if the read-only override is set.
    pub fn is_active_program_read_only(&self) -> bool {
        if self.override_read_only {
            return false;
        }
        self.active_program_read_only
    }

    /// Set the read-only override (used in tests).
    pub fn set_override_read_only(&mut self, override_val: bool) {
        self.override_read_only = override_val;
    }

    /// Set the address associated with this action.
    pub fn set_address(&mut self, address: u64) {
        self.address = Some(address);
    }

    /// Get the address associated with this action.
    pub fn address(&self) -> Option<u64> {
        self.address
    }

    /// Check if this context is valid for applying changes.
    ///
    /// A context is valid for applying changes if:
    /// - A token pair is available
    /// - The target program is not read-only
    /// - Both source and target functions are available
    pub fn is_valid_for_apply(&self) -> bool {
        self.has_token_pair()
            && !self.is_active_program_read_only()
            && self.source_function().is_some()
            && self.target_function().is_some()
    }

    /// Check if this context has both function infos.
    pub fn has_both_functions(&self) -> bool {
        self.left_function.is_some() && self.right_function.is_some()
    }
}

impl std::fmt::Debug for DualDecompilerActionContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DualDecompilerActionContext")
            .field("active_display", &self.active_display)
            .field("has_token_pair", &self.has_token_pair())
            .field("has_left_function", &self.left_function.is_some())
            .field("has_right_function", &self.right_function.is_some())
            .field("active_program_read_only", &self.is_active_program_read_only())
            .field("address", &self.address)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codecompare::graphanalysis::{DecompilerToken, TokenKind};

    fn make_program(id: u64, path: &str, name: &str) -> ProgramInfo {
        ProgramInfo::new(id, path, name)
    }

    fn make_decompiler_func(
        name: &str,
        entry: u64,
        program: ProgramInfo,
        signature: &str,
    ) -> DecompilerFunctionInfo {
        DecompilerFunctionInfo::new(name, entry, program, signature)
    }

    fn make_token_pair() -> TokenPair {
        let left = DecompilerToken {
            text: "x".to_string(),
            kind: TokenKind::Variable,
            address: 0x1000,
            side: Side::Left,
        };
        let right = DecompilerToken {
            text: "y".to_string(),
            kind: TokenKind::Variable,
            address: 0x2000,
            side: Side::Right,
        };
        TokenPair::new(left, right)
    }

    // --- DecompilerDisplaySide tests ---

    #[test]
    fn test_display_side_opposite() {
        assert_eq!(
            DecompilerDisplaySide::Left.opposite(),
            DecompilerDisplaySide::Right
        );
        assert_eq!(
            DecompilerDisplaySide::Right.opposite(),
            DecompilerDisplaySide::Left
        );
    }

    #[test]
    fn test_display_side_to_comparison_side() {
        assert_eq!(
            DecompilerDisplaySide::Left.to_comparison_side(),
            ComparisonSide::Left
        );
        assert_eq!(
            DecompilerDisplaySide::Right.to_comparison_side(),
            ComparisonSide::Right
        );
    }

    #[test]
    fn test_display_side_to_side() {
        assert_eq!(DecompilerDisplaySide::Left.to_side(), Side::Left);
        assert_eq!(DecompilerDisplaySide::Right.to_side(), Side::Right);
    }

    #[test]
    fn test_display_side_from_side() {
        assert_eq!(DecompilerDisplaySide::from(Side::Left), DecompilerDisplaySide::Left);
        assert_eq!(DecompilerDisplaySide::from(Side::Right), DecompilerDisplaySide::Right);
    }

    #[test]
    fn test_display_side_from_comparison_side() {
        assert_eq!(
            DecompilerDisplaySide::from(ComparisonSide::Left),
            DecompilerDisplaySide::Left
        );
        assert_eq!(
            DecompilerDisplaySide::from(ComparisonSide::Right),
            DecompilerDisplaySide::Right
        );
    }

    // --- DecompilerActionKind tests ---

    #[test]
    fn test_action_kind_label() {
        assert_eq!(
            DecompilerActionKind::ApplyLocalName.label(),
            "Apply Local Name From Matched Tokens"
        );
        assert_eq!(
            DecompilerActionKind::ApplyGlobalName.label(),
            "Apply Global Name From Matched Tokens"
        );
    }

    #[test]
    fn test_action_kind_description() {
        assert!(!DecompilerActionKind::ApplyLocalName.description().is_empty());
        assert!(!DecompilerActionKind::ApplyVariableType.description().is_empty());
    }

    #[test]
    fn test_action_kind_requires_token_pair() {
        assert!(DecompilerActionKind::ApplyLocalName.requires_token_pair());
        assert!(DecompilerActionKind::ApplyGlobalName.requires_token_pair());
        assert!(!DecompilerActionKind::Other.requires_token_pair());
    }

    #[test]
    fn test_action_kind_is_callee_action() {
        assert!(DecompilerActionKind::ApplyCalleeSignatureWithDatatypes.is_callee_action());
        assert!(DecompilerActionKind::ApplyCalleeEmptySignature.is_callee_action());
        assert!(DecompilerActionKind::ApplyCalleeFunctionName.is_callee_action());
        assert!(!DecompilerActionKind::ApplyLocalName.is_callee_action());
        assert!(!DecompilerActionKind::Other.is_callee_action());
    }

    // --- DecompilerFunctionInfo tests ---

    #[test]
    fn test_decompiler_function_info_new() {
        let prog = make_program(1, "/test", "test");
        let func = make_decompiler_func("main", 0x1000, prog, "int main()");
        assert_eq!(func.name, "main");
        assert_eq!(func.entry_point, 0x1000);
        assert_eq!(func.signature, "int main()");
        assert!(!func.is_read_only);
    }

    #[test]
    fn test_decompiler_function_info_display_name() {
        let prog = make_program(1, "/test", "test");
        let func = make_decompiler_func("main", 0x1000, prog, "int main()");
        assert_eq!(func.display_name(), "main()");
    }

    // --- DualDecompilerActionContext tests ---

    #[test]
    fn test_context_new() {
        let left_prog = make_program(1, "/old", "old");
        let right_prog = make_program(2, "/new", "new");

        let ctx = DualDecompilerActionContext::new(
            DecompilerDisplaySide::Left,
            ActionTrigger::Mouse,
            Some(left_prog),
            Some(right_prog),
        );

        assert_eq!(ctx.active_display(), DecompilerDisplaySide::Left);
        assert_eq!(ctx.inactive_display(), DecompilerDisplaySide::Right);
        assert!(!ctx.has_token_pair());
        assert!(ctx.token_pair().is_none());
        assert!(ctx.left_function().is_none());
        assert!(ctx.right_function().is_none());
        assert!(!ctx.is_active_program_read_only());
    }

    #[test]
    fn test_context_with_token_pair() {
        let left_prog = make_program(1, "/old", "old");
        let right_prog = make_program(2, "/new", "new");
        let pair = make_token_pair();

        let ctx = DualDecompilerActionContext::with_token_pair(
            DecompilerDisplaySide::Right,
            ActionTrigger::Keyboard,
            pair,
            Some(left_prog),
            Some(right_prog),
        );

        assert!(ctx.has_token_pair());
        assert_eq!(ctx.active_display(), DecompilerDisplaySide::Right);
        let tp = ctx.token_pair().unwrap();
        assert_eq!(tp.left_token().text, "x");
        assert_eq!(tp.right_token().text, "y");
    }

    #[test]
    fn test_context_set_token_pair() {
        let ctx_base = DualDecompilerActionContext::new(
            DecompilerDisplaySide::Left,
            ActionTrigger::Mouse,
            None,
            None,
        );
        let mut ctx = ctx_base;
        assert!(!ctx.has_token_pair());

        ctx.set_token_pair(Some(make_token_pair()));
        assert!(ctx.has_token_pair());

        ctx.set_token_pair(None);
        assert!(!ctx.has_token_pair());
    }

    #[test]
    fn test_context_functions() {
        let left_prog = make_program(1, "/old", "old");
        let right_prog = make_program(2, "/new", "new");

        let mut ctx = DualDecompilerActionContext::new(
            DecompilerDisplaySide::Left,
            ActionTrigger::Mouse,
            Some(left_prog.clone()),
            Some(right_prog.clone()),
        );

        let left_func = make_decompiler_func("main_old", 0x1000, left_prog, "int main_old()");
        let right_func = make_decompiler_func("main_new", 0x2000, right_prog, "int main_new()");

        ctx.set_left_function(left_func);
        ctx.set_right_function(right_func);

        assert!(ctx.has_both_functions());
        assert_eq!(ctx.left_function().unwrap().name, "main_old");
        assert_eq!(ctx.right_function().unwrap().name, "main_new");
    }

    #[test]
    fn test_context_active_inactive_functions() {
        let left_prog = make_program(1, "/old", "old");
        let right_prog = make_program(2, "/new", "new");

        let mut ctx = DualDecompilerActionContext::new(
            DecompilerDisplaySide::Left,
            ActionTrigger::Mouse,
            Some(left_prog.clone()),
            Some(right_prog.clone()),
        );

        ctx.set_left_function(make_decompiler_func("left_fn", 0x1000, left_prog, ""));
        ctx.set_right_function(make_decompiler_func("right_fn", 0x2000, right_prog, ""));

        // Active display is Left, so active function is left_fn
        assert_eq!(ctx.active_function().unwrap().name, "left_fn");
        assert_eq!(ctx.inactive_function().unwrap().name, "right_fn");
    }

    #[test]
    fn test_context_source_target_functions() {
        let left_prog = make_program(1, "/old", "old");
        let right_prog = make_program(2, "/new", "new");

        let mut ctx = DualDecompilerActionContext::new(
            DecompilerDisplaySide::Left,
            ActionTrigger::Mouse,
            Some(left_prog.clone()),
            Some(right_prog.clone()),
        );

        ctx.set_left_function(make_decompiler_func("left_fn", 0x1000, left_prog, ""));
        ctx.set_right_function(make_decompiler_func("right_fn", 0x2000, right_prog, ""));

        // Source = inactive side = right
        assert_eq!(ctx.source_function().unwrap().name, "right_fn");
        // Target = active side = left
        assert_eq!(ctx.target_function().unwrap().name, "left_fn");
    }

    #[test]
    fn test_context_read_only() {
        let mut ctx = DualDecompilerActionContext::new(
            DecompilerDisplaySide::Left,
            ActionTrigger::Mouse,
            None,
            None,
        );

        assert!(!ctx.is_active_program_read_only());
        ctx.set_active_program_read_only(true);
        assert!(ctx.is_active_program_read_only());

        // Override should bypass the read-only check
        ctx.set_override_read_only(true);
        assert!(!ctx.is_active_program_read_only());
    }

    #[test]
    fn test_context_address() {
        let mut ctx = DualDecompilerActionContext::new(
            DecompilerDisplaySide::Left,
            ActionTrigger::Mouse,
            None,
            None,
        );

        assert!(ctx.address().is_none());
        ctx.set_address(0x1000);
        assert_eq!(ctx.address(), Some(0x1000));
    }

    #[test]
    fn test_context_is_valid_for_apply() {
        let left_prog = make_program(1, "/old", "old");
        let right_prog = make_program(2, "/new", "new");

        let mut ctx = DualDecompilerActionContext::new(
            DecompilerDisplaySide::Left,
            ActionTrigger::Mouse,
            Some(left_prog.clone()),
            Some(right_prog.clone()),
        );

        // Not valid: no token pair, no functions
        assert!(!ctx.is_valid_for_apply());

        ctx.set_token_pair(Some(make_token_pair()));
        ctx.set_left_function(make_decompiler_func("left_fn", 0x1000, left_prog, ""));
        ctx.set_right_function(make_decompiler_func("right_fn", 0x2000, right_prog, ""));

        // Valid now
        assert!(ctx.is_valid_for_apply());

        // Not valid: read-only
        ctx.set_active_program_read_only(true);
        assert!(!ctx.is_valid_for_apply());
    }

    #[test]
    fn test_context_base() {
        let ctx = DualDecompilerActionContext::new(
            DecompilerDisplaySide::Right,
            ActionTrigger::Keyboard,
            None,
            None,
        );

        assert_eq!(ctx.base().view_name(), "DecompilerCodeComparisonView");
        assert_eq!(ctx.base().active_side(), ComparisonSide::Right);
        assert_eq!(ctx.base().trigger(), ActionTrigger::Keyboard);
    }

    #[test]
    fn test_context_debug() {
        let ctx = DualDecompilerActionContext::new(
            DecompilerDisplaySide::Left,
            ActionTrigger::Mouse,
            None,
            None,
        );

        let debug_str = format!("{:?}", ctx);
        assert!(debug_str.contains("DualDecompilerActionContext"));
        assert!(debug_str.contains("Left"));
    }
}
