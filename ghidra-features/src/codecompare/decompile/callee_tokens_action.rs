//! Callee-specific matched token actions for the dual decompiler view.
//!
//! Ported from Ghidra's `AbstractMatchedCalleeTokensAction` Java class in
//! `ghidra.features.codecompare.decompile`.
//!
//! These actions are a specialization of [`MatchedTokensAction`] (from
//! `matched_tokens_action`) that are only enabled when the matched tokens
//! represent function calls (CALL pcode operations). They extract the callee
//! function from each side of the token pair and delegate to a callee-specific
//! action implementation.
//!
//! # Key types
//!
//! - [`CalleeInfo`] -- information about a callee extracted from a function call token
//! - [`CalleeTokensAction`] -- base struct for callee-specific actions
//! - [`CalleeActionContext`] -- context for evaluating callee actions
//! - [`CalleeActionResult`] -- result of a callee action

use super::super::graphanalysis::Side;

/// Menu group for callee actions.
const CALLEE_MENU_GROUP: &str = "A2_ApplyCallee";

/// The type of pcode operation that represents a function call.
const PCODE_CALL: u32 = 7;

/// Information about a callee function extracted from a function call token.
///
/// When a matched token pair represents function calls on both sides, this
/// struct captures the resolved callee function information.
#[derive(Debug, Clone)]
pub struct CalleeInfo {
    /// The name of the callee function.
    pub name: String,
    /// The entry point address of the callee.
    pub entry_point: u64,
    /// The address of the call site (the CALL instruction).
    pub call_site: u64,
    /// The side this callee belongs to.
    pub side: Side,
    /// Whether this is an external function.
    pub is_external: bool,
    /// Whether this is a thunk function.
    pub is_thunk: bool,
    /// If this is a thunk, the name of the thunked function.
    pub thunked_name: Option<String>,
    /// The program path containing this callee.
    pub program_path: String,
}

impl CalleeInfo {
    /// Create new callee info.
    pub fn new(
        name: impl Into<String>,
        entry_point: u64,
        call_site: u64,
        side: Side,
        program_path: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            entry_point,
            call_site,
            side,
            is_external: false,
            is_thunk: false,
            thunked_name: None,
            program_path: program_path.into(),
        }
    }

    /// Create callee info for an external function.
    pub fn new_external(
        name: impl Into<String>,
        entry_point: u64,
        call_site: u64,
        side: Side,
        program_path: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            entry_point,
            call_site,
            side,
            is_external: true,
            is_thunk: false,
            thunked_name: None,
            program_path: program_path.into(),
        }
    }

    /// Create callee info for a thunk function.
    pub fn new_thunk(
        name: impl Into<String>,
        entry_point: u64,
        call_site: u64,
        side: Side,
        thunked_name: impl Into<String>,
        program_path: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            entry_point,
            call_site,
            side,
            is_external: false,
            is_thunk: true,
            thunked_name: Some(thunked_name.into()),
            program_path: program_path.into(),
        }
    }

    /// Get the effective function name (thunked name if this is a thunk).
    pub fn effective_name(&self) -> &str {
        self.thunked_name.as_deref().unwrap_or(&self.name)
    }

    /// Check if this callee is valid for comparison (not external).
    ///
    /// External functions cannot be compared because they have no
    /// decompilable body.
    pub fn is_comparable(&self) -> bool {
        !self.is_external
    }

    /// Get a display string for this callee.
    pub fn display_string(&self) -> String {
        if self.is_external {
            format!("{} (external)", self.name)
        } else if self.is_thunk {
            format!("{} -> {}", self.name, self.effective_name())
        } else {
            self.name.clone()
        }
    }
}

/// Context for evaluating whether a callee action should be enabled.
///
/// Contains the resolved callee information from both sides of the
/// dual decompiler comparison.
#[derive(Debug, Clone)]
pub struct CalleeActionContext {
    /// The callee on the left side.
    pub left_callee: Option<CalleeInfo>,
    /// The callee on the right side.
    pub right_callee: Option<CalleeInfo>,
    /// The token text on the left side (the function name as displayed).
    pub left_token_text: String,
    /// The token text on the right side.
    pub right_token_text: String,
    /// Whether the left program is read-only.
    pub left_read_only: bool,
    /// Whether the right program is read-only.
    pub right_read_only: bool,
}

impl CalleeActionContext {
    /// Create a new callee action context.
    pub fn new(
        left_callee: Option<CalleeInfo>,
        right_callee: Option<CalleeInfo>,
        left_token_text: impl Into<String>,
        right_token_text: impl Into<String>,
    ) -> Self {
        Self {
            left_callee,
            right_callee,
            left_token_text: left_token_text.into(),
            right_token_text: right_token_text.into(),
            left_read_only: false,
            right_read_only: false,
        }
    }

    /// Check if both sides have valid callee information.
    pub fn has_both_callees(&self) -> bool {
        self.left_callee.is_some() && self.right_callee.is_some()
    }

    /// Check if both callees are comparable (non-external).
    pub fn both_comparable(&self) -> bool {
        match (&self.left_callee, &self.right_callee) {
            (Some(left), Some(right)) => left.is_comparable() && right.is_comparable(),
            _ => false,
        }
    }

    /// Check if the callee names differ between the two sides.
    pub fn names_differ(&self) -> bool {
        let left_name = self.left_callee.as_ref().map(|c| c.effective_name());
        let right_name = self.right_callee.as_ref().map(|c| c.effective_name());
        left_name != right_name
    }

    /// Get a validation error message if the context is invalid for callee actions.
    ///
    /// Returns `None` if the context is valid.
    pub fn validation_error(&self) -> Option<String> {
        if self.left_callee.is_none() && self.right_callee.is_none() {
            return Some("No callee information available on either side".to_string());
        }
        if self.left_callee.is_none() {
            return Some("No callee information on left side".to_string());
        }
        if self.right_callee.is_none() {
            return Some("No callee information on right side".to_string());
        }

        let left = self.left_callee.as_ref().unwrap();
        let right = self.right_callee.as_ref().unwrap();

        if left.is_external {
            return Some(format!(
                "Cannot compare callees - {} is external",
                left.name
            ));
        }
        if right.is_external {
            return Some(format!(
                "Cannot compare callees - {} is external",
                right.name
            ));
        }

        None
    }
}

/// Result of executing a callee action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalleeActionResult {
    /// The action was applied successfully.
    Success {
        /// Description of what was applied.
        description: String,
    },
    /// The action was not applicable (e.g., names already match).
    NotApplicable,
    /// The action failed with an error.
    Failed {
        /// Error message.
        error: String,
    },
    /// The action requires user confirmation.
    NeedsConfirmation {
        /// The confirmation prompt.
        prompt: String,
    },
}

/// Base struct for actions that operate on matched callee tokens in the
/// dual decompiler view.
///
/// Ported from Ghidra's `AbstractMatchedCalleeTokensAction` Java class.
///
/// Subclasses implement [`CalleeAction::do_callee_action`] to define
/// the specific behavior when a callee action is triggered. The base
/// struct handles:
/// - Validating that matched tokens represent function calls
/// - Extracting callee function information from both sides
/// - Checking that callees are non-external
/// - Delegating to the subclass implementation
#[derive(Debug, Clone)]
pub struct CalleeTokensAction {
    /// The action name.
    pub name: String,
    /// The owner.
    pub owner: String,
    /// Whether to disable the action for read-only programs.
    pub disable_on_read_only: bool,
    /// Menu group identifier.
    pub menu_group: String,
}

impl CalleeTokensAction {
    /// Create a new callee tokens action.
    pub fn new(
        name: impl Into<String>,
        owner: impl Into<String>,
        disable_on_read_only: bool,
    ) -> Self {
        Self {
            name: name.into(),
            owner: owner.into(),
            disable_on_read_only,
            menu_group: CALLEE_MENU_GROUP.to_string(),
        }
    }

    /// Check if the given token pair represents function calls on both sides.
    ///
    /// In the Java implementation, this checks that both tokens have a
    /// `PcodeOp` with opcode `CALL` and are `ClangFuncNameToken` instances.
    pub fn is_function_call_token(
        &self,
        left_op_code: Option<u32>,
        right_op_code: Option<u32>,
        left_is_func_name_token: bool,
        right_is_func_name_token: bool,
    ) -> bool {
        match (left_op_code, right_op_code) {
            (Some(left), Some(right)) => {
                left == PCODE_CALL
                    && right == PCODE_CALL
                    && left_is_func_name_token
                    && right_is_func_name_token
            }
            _ => false,
        }
    }

    /// Check if this action is enabled for the given context.
    ///
    /// The action is enabled if both sides have valid callee information
    /// and neither is external.
    pub fn is_enabled(&self, context: &CalleeActionContext) -> bool {
        context.has_both_callees() && context.both_comparable()
    }

    /// Resolve a callee from a call site token.
    ///
    /// In the Java implementation, this looks up the function at the
    /// call target address, handling thunk resolution and external
    /// function rejection.
    pub fn resolve_callee(
        &self,
        func_name: &str,
        call_target: u64,
        side: Side,
        program_path: &str,
        is_external: bool,
        is_thunk: bool,
        thunked_name: Option<&str>,
    ) -> Result<CalleeInfo, String> {
        if is_external {
            return Err(format!(
                "Can't compare callees - {} is external",
                func_name
            ));
        }

        if is_thunk {
            if let Some(thunked) = thunked_name {
                Ok(CalleeInfo::new_thunk(
                    func_name,
                    call_target,
                    0, // call_site set by caller
                    side,
                    thunked,
                    program_path,
                ))
            } else {
                Ok(CalleeInfo::new(
                    func_name,
                    call_target,
                    0,
                    side,
                    program_path,
                ))
            }
        } else {
            Ok(CalleeInfo::new(
                func_name,
                call_target,
                0,
                side,
                program_path,
            ))
        }
    }
}

/// Trait for implementing callee-specific action behavior.
///
/// Implementors define what happens when the user triggers a callee action
/// in the dual decompiler comparison view.
pub trait CalleeAction {
    /// Execute the callee action with the resolved callee functions from both sides.
    ///
    /// # Arguments
    ///
    /// * `left` -- the callee on the left side
    /// * `right` -- the callee on the right side
    ///
    /// # Returns
    ///
    /// The result of the action.
    fn do_callee_action(&self, left: &CalleeInfo, right: &CalleeInfo) -> CalleeActionResult;
}

/// Action that compares two callee functions by opening a new comparison.
///
/// Ported from Ghidra's `CompareFuncsFromMatchedTokensAction` (callee-specific variant).
/// When the user selects matched function call tokens, this action opens a new
/// function comparison between the two called functions.
#[derive(Debug, Clone)]
pub struct CompareCalleesAction {
    /// The base action.
    pub base: CalleeTokensAction,
}

impl CompareCalleesAction {
    /// Create a new compare callees action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            base: CalleeTokensAction::new("Compare Called Functions", owner, false),
        }
    }
}

impl CalleeAction for CompareCalleesAction {
    fn do_callee_action(&self, left: &CalleeInfo, right: &CalleeInfo) -> CalleeActionResult {
        CalleeActionResult::Success {
            description: format!(
                "Opening comparison for function '{}' (called from {} and {})",
                left.effective_name(),
                left.program_path,
                right.program_path
            ),
        }
    }
}

/// Action that applies a callee function name from one side to the other.
///
/// Ported from Ghidra's `ApplyCalleeFunctionNameFromMatchedTokensAction` (callee variant).
#[derive(Debug, Clone)]
pub struct ApplyCalleeNameAction {
    /// The base action.
    pub base: CalleeTokensAction,
}

impl ApplyCalleeNameAction {
    /// Create a new apply callee name action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            base: CalleeTokensAction::new("Apply Callee Function Name", owner, true),
        }
    }
}

impl CalleeAction for ApplyCalleeNameAction {
    fn do_callee_action(&self, left: &CalleeInfo, right: &CalleeInfo) -> CalleeActionResult {
        if left.effective_name() == right.effective_name() {
            return CalleeActionResult::NotApplicable;
        }

        CalleeActionResult::NeedsConfirmation {
            prompt: format!(
                "Rename callee '{}' to '{}' based on match in {}?",
                right.effective_name(),
                left.effective_name(),
                left.program_path
            ),
        }
    }
}

/// Action that applies an empty signature to a callee function.
///
/// Ported from Ghidra's `ApplyCalleeEmptySignatureFromMatchedTokensAction`.
/// This strips the parameter information from the callee, leaving only
/// the function name with an empty parameter list.
#[derive(Debug, Clone)]
pub struct ApplyCalleeEmptySignatureAction {
    /// The base action.
    pub base: CalleeTokensAction,
}

impl ApplyCalleeEmptySignatureAction {
    /// Create a new apply callee empty signature action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            base: CalleeTokensAction::new("Apply Callee Empty Signature", owner, true),
        }
    }
}

impl CalleeAction for ApplyCalleeEmptySignatureAction {
    fn do_callee_action(&self, _left: &CalleeInfo, right: &CalleeInfo) -> CalleeActionResult {
        CalleeActionResult::Success {
            description: format!(
                "Set callee '{}' at 0x{:x} in {} to empty signature",
                right.name, right.entry_point, right.program_path
            ),
        }
    }
}

/// Action that applies a callee signature with full datatypes.
///
/// Ported from Ghidra's `ApplyCalleeSignatureWithDatatypesFromMatchedTokensAction`.
/// This copies the complete function signature including parameter types
/// from one side to the other.
#[derive(Debug, Clone)]
pub struct ApplyCalleeSignatureWithDatatypesAction {
    /// The base action.
    pub base: CalleeTokensAction,
}

impl ApplyCalleeSignatureWithDatatypesAction {
    /// Create a new apply callee signature with datatypes action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            base: CalleeTokensAction::new(
                "Apply Callee Signature With Datatypes",
                owner,
                true,
            ),
        }
    }
}

impl CalleeAction for ApplyCalleeSignatureWithDatatypesAction {
    fn do_callee_action(&self, left: &CalleeInfo, right: &CalleeInfo) -> CalleeActionResult {
        if left.effective_name() == right.effective_name() {
            return CalleeActionResult::NotApplicable;
        }

        CalleeActionResult::NeedsConfirmation {
            prompt: format!(
                "Apply signature from '{}' in {} to callee '{}' in {}?",
                left.effective_name(),
                left.program_path,
                right.effective_name(),
                right.program_path
            ),
        }
    }
}

/// Aggregates all callee-specific actions for the decompiler comparison view.
#[derive(Debug)]
pub struct CalleeActionSet {
    /// Compare called functions.
    pub compare_callees: CompareCalleesAction,
    /// Apply callee function name.
    pub apply_callee_name: ApplyCalleeNameAction,
    /// Apply callee empty signature.
    pub apply_callee_empty_sig: ApplyCalleeEmptySignatureAction,
    /// Apply callee signature with datatypes.
    pub apply_callee_full_sig: ApplyCalleeSignatureWithDatatypesAction,
}

impl CalleeActionSet {
    /// Create a new callee action set with the given owner.
    pub fn new(owner: impl Into<String> + Clone) -> Self {
        Self {
            compare_callees: CompareCalleesAction::new(owner.clone()),
            apply_callee_name: ApplyCalleeNameAction::new(owner.clone()),
            apply_callee_empty_sig: ApplyCalleeEmptySignatureAction::new(owner.clone()),
            apply_callee_full_sig: ApplyCalleeSignatureWithDatatypesAction::new(owner),
        }
    }

    /// Get all action names.
    pub fn action_names(&self) -> Vec<&str> {
        vec![
            &self.compare_callees.base.name,
            &self.apply_callee_name.base.name,
            &self.apply_callee_empty_sig.base.name,
            &self.apply_callee_full_sig.base.name,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_left_callee() -> CalleeInfo {
        CalleeInfo::new("left_func", 0x4000, 0x1000, Side::Left, "/project/left")
    }

    fn make_right_callee() -> CalleeInfo {
        CalleeInfo::new("right_func", 0x8000, 0x2000, Side::Right, "/project/right")
    }

    fn make_context() -> CalleeActionContext {
        CalleeActionContext::new(
            Some(make_left_callee()),
            Some(make_right_callee()),
            "left_func",
            "right_func",
        )
    }

    // --- CalleeInfo tests ---

    #[test]
    fn test_callee_info_new() {
        let info = make_left_callee();
        assert_eq!(info.name, "left_func");
        assert_eq!(info.entry_point, 0x4000);
        assert_eq!(info.call_site, 0x1000);
        assert_eq!(info.side, Side::Left);
        assert!(!info.is_external);
        assert!(!info.is_thunk);
    }

    #[test]
    fn test_callee_info_external() {
        let info = CalleeInfo::new_external("printf", 0, 0x1000, Side::Left, "/project");
        assert!(info.is_external);
        assert!(!info.is_comparable());
        assert_eq!(info.display_string(), "printf (external)");
    }

    #[test]
    fn test_callee_info_thunk() {
        let info = CalleeInfo::new_thunk(
            "thunk_func",
            0x4000,
            0x1000,
            Side::Left,
            "real_func",
            "/project",
        );
        assert!(info.is_thunk);
        assert_eq!(info.effective_name(), "real_func");
        assert!(info.is_comparable());
        assert_eq!(info.display_string(), "thunk_func -> real_func");
    }

    #[test]
    fn test_callee_info_effective_name_no_thunk() {
        let info = make_left_callee();
        assert_eq!(info.effective_name(), "left_func");
    }

    // --- CalleeActionContext tests ---

    #[test]
    fn test_context_has_both_callees() {
        let ctx = make_context();
        assert!(ctx.has_both_callees());
    }

    #[test]
    fn test_context_missing_callee() {
        let ctx = CalleeActionContext::new(
            None,
            Some(make_right_callee()),
            "",
            "right_func",
        );
        assert!(!ctx.has_both_callees());
    }

    #[test]
    fn test_context_both_comparable() {
        let ctx = make_context();
        assert!(ctx.both_comparable());
    }

    #[test]
    fn test_context_external_not_comparable() {
        let ctx = CalleeActionContext::new(
            Some(CalleeInfo::new_external("ext", 0, 0, Side::Left, "/p")),
            Some(make_right_callee()),
            "ext",
            "right_func",
        );
        assert!(!ctx.both_comparable());
    }

    #[test]
    fn test_context_names_differ() {
        let ctx = make_context();
        assert!(ctx.names_differ());
    }

    #[test]
    fn test_context_names_same() {
        let ctx = CalleeActionContext::new(
            Some(make_left_callee()),
            Some(CalleeInfo::new("left_func", 0x8000, 0x2000, Side::Right, "/r")),
            "left_func",
            "left_func",
        );
        assert!(!ctx.names_differ());
    }

    #[test]
    fn test_context_validation_error_external() {
        let ctx = CalleeActionContext::new(
            Some(CalleeInfo::new_external("ext", 0, 0, Side::Left, "/p")),
            Some(make_right_callee()),
            "ext",
            "right_func",
        );
        assert!(ctx.validation_error().is_some());
        assert!(ctx.validation_error().unwrap().contains("external"));
    }

    #[test]
    fn test_context_validation_error_none() {
        let ctx = make_context();
        assert!(ctx.validation_error().is_none());
    }

    // --- CalleeTokensAction tests ---

    #[test]
    fn test_is_function_call_token() {
        let action = CalleeTokensAction::new("test", "owner", true);
        assert!(action.is_function_call_token(Some(PCODE_CALL), Some(PCODE_CALL), true, true));
        assert!(!action.is_function_call_token(Some(PCODE_CALL), Some(PCODE_CALL), false, true));
        assert!(!action.is_function_call_token(Some(5), Some(PCODE_CALL), true, true));
        assert!(!action.is_function_call_token(None, Some(PCODE_CALL), true, true));
    }

    #[test]
    fn test_action_enabled() {
        let action = CalleeTokensAction::new("test", "owner", true);
        let ctx = make_context();
        assert!(action.is_enabled(&ctx));
    }

    #[test]
    fn test_action_disabled_external() {
        let action = CalleeTokensAction::new("test", "owner", true);
        let ctx = CalleeActionContext::new(
            Some(CalleeInfo::new_external("ext", 0, 0, Side::Left, "/p")),
            Some(make_right_callee()),
            "ext",
            "right_func",
        );
        assert!(!action.is_enabled(&ctx));
    }

    #[test]
    fn test_resolve_callee_normal() {
        let action = CalleeTokensAction::new("test", "owner", true);
        let result = action.resolve_callee("func", 0x4000, Side::Left, "/project", false, false, None);
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.name, "func");
        assert!(!info.is_thunk);
    }

    #[test]
    fn test_resolve_callee_external() {
        let action = CalleeTokensAction::new("test", "owner", true);
        let result = action.resolve_callee("ext", 0, Side::Left, "/project", true, false, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("external"));
    }

    #[test]
    fn test_resolve_callee_thunk() {
        let action = CalleeTokensAction::new("test", "owner", true);
        let result = action.resolve_callee(
            "thunk",
            0x4000,
            Side::Left,
            "/project",
            false,
            true,
            Some("real"),
        );
        assert!(result.is_ok());
        let info = result.unwrap();
        assert!(info.is_thunk);
        assert_eq!(info.effective_name(), "real");
    }

    // --- CompareCalleesAction tests ---

    #[test]
    fn test_compare_callees() {
        let action = CompareCalleesAction::new("test");
        let left = make_left_callee();
        let right = make_right_callee();
        match action.do_callee_action(&left, &right) {
            CalleeActionResult::Success { description } => {
                assert!(description.contains("Opening comparison"));
                assert!(description.contains("left_func"));
            }
            _ => panic!("Expected Success"),
        }
    }

    // --- ApplyCalleeNameAction tests ---

    #[test]
    fn test_apply_callee_name_different() {
        let action = ApplyCalleeNameAction::new("test");
        let left = make_left_callee();
        let right = make_right_callee();
        match action.do_callee_action(&left, &right) {
            CalleeActionResult::NeedsConfirmation { prompt } => {
                assert!(prompt.contains("left_func"));
                assert!(prompt.contains("right_func"));
            }
            _ => panic!("Expected NeedsConfirmation"),
        }
    }

    #[test]
    fn test_apply_callee_name_same() {
        let action = ApplyCalleeNameAction::new("test");
        let left = make_left_callee();
        let right = CalleeInfo::new("left_func", 0x8000, 0x2000, Side::Right, "/r");
        assert_eq!(
            action.do_callee_action(&left, &right),
            CalleeActionResult::NotApplicable
        );
    }

    // --- ApplyCalleeEmptySignatureAction tests ---

    #[test]
    fn test_apply_callee_empty_sig() {
        let action = ApplyCalleeEmptySignatureAction::new("test");
        let left = make_left_callee();
        let right = make_right_callee();
        match action.do_callee_action(&left, &right) {
            CalleeActionResult::Success { description } => {
                assert!(description.contains("empty signature"));
                assert!(description.contains("right_func"));
            }
            _ => panic!("Expected Success"),
        }
    }

    // --- ApplyCalleeSignatureWithDatatypesAction tests ---

    #[test]
    fn test_apply_callee_full_sig_different() {
        let action = ApplyCalleeSignatureWithDatatypesAction::new("test");
        let left = make_left_callee();
        let right = make_right_callee();
        match action.do_callee_action(&left, &right) {
            CalleeActionResult::NeedsConfirmation { prompt } => {
                assert!(prompt.contains("signature"));
            }
            _ => panic!("Expected NeedsConfirmation"),
        }
    }

    #[test]
    fn test_apply_callee_full_sig_same() {
        let action = ApplyCalleeSignatureWithDatatypesAction::new("test");
        let left = make_left_callee();
        let right = CalleeInfo::new("left_func", 0x8000, 0x2000, Side::Right, "/r");
        assert_eq!(
            action.do_callee_action(&left, &right),
            CalleeActionResult::NotApplicable
        );
    }

    // --- CalleeActionSet tests ---

    #[test]
    fn test_callee_action_set_names() {
        let set = CalleeActionSet::new("test");
        let names = set.action_names();
        assert_eq!(names.len(), 4);
        assert!(names.contains(&"Compare Called Functions"));
        assert!(names.contains(&"Apply Callee Function Name"));
        assert!(names.contains(&"Apply Callee Empty Signature"));
        assert!(names.contains(&"Apply Callee Signature With Datatypes"));
    }
}
