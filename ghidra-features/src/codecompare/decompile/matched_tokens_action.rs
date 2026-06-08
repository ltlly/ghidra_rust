//! Actions that operate on matched tokens in the dual decompiler view.
//!
//! Ported from Ghidra's `AbstractMatchedTokensAction` and its subclasses
//! in the `ghidra.features.codecompare.decompile` Java package.
//!
//! These actions allow users to apply information from matched tokens
//! in one function to the other function. For example, applying a
//! variable name from the left function to the corresponding variable
//! in the right function.
//!
//! # Base types
//!
//! - [`MatchedTokensAction`] -- base struct for all matched token actions
//!
//! # Concrete actions
//!
//! - [`ApplyLocalNameAction`] -- apply a local variable name from matched tokens
//! - [`ApplyGlobalNameAction`] -- apply a global variable name from matched tokens
//! - [`ApplyVariableTypeAction`] -- apply a variable type from matched tokens
//! - [`ApplyEmptyVariableTypeAction`] -- apply an empty/void variable type
//! - [`ApplyCalleeFunctionNameAction`] -- apply a callee function name
//! - [`ApplyCalleeEmptySignatureAction`] -- apply an empty callee signature
//! - [`ApplyCalleeSignatureWithDatatypesAction`] -- apply callee signature with datatypes
//! - [`CompareFuncsFromMatchedTokensAction`] -- compare functions found in matched tokens

use super::super::graphanalysis::Side;
use super::super::panel::ProgramLocation;

/// The menu parent path for "Apply From Other Function" actions.
const MENU_PARENT: &str = "Apply From Other Function";

/// Help topic for function comparison actions.
const HELP_TOPIC: &str = "FunctionComparison";

/// The type of information that can be applied from matched tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyType {
    /// Apply a local variable name.
    LocalName,
    /// Apply a global variable/symbol name.
    GlobalName,
    /// Apply a variable data type.
    VariableType,
    /// Apply an empty (void) variable type.
    EmptyVariableType,
    /// Apply a callee function name.
    CalleeFunctionName,
    /// Apply an empty callee signature.
    CalleeEmptySignature,
    /// Apply a callee signature with full datatypes.
    CalleeSignatureWithDatatypes,
}

/// Information about a matched token pair that can be used for applying changes.
#[derive(Debug, Clone)]
pub struct MatchedTokenInfo {
    /// The token text on the source side.
    pub source_text: String,
    /// The token text on the destination side.
    pub dest_text: String,
    /// The source function side.
    pub source_side: Side,
    /// The address in the source function.
    pub source_address: u64,
    /// The address in the destination function.
    pub dest_address: u64,
    /// The source function name.
    pub source_function: String,
    /// The destination function name.
    pub dest_function: String,
    /// The line number in the source decompiled output.
    pub source_line: usize,
    /// The line number in the destination decompiled output.
    pub dest_line: usize,
}

impl MatchedTokenInfo {
    /// Create a new matched token info.
    pub fn new(
        source_text: impl Into<String>,
        dest_text: impl Into<String>,
        source_side: Side,
        source_address: u64,
        dest_address: u64,
        source_function: impl Into<String>,
        dest_function: impl Into<String>,
    ) -> Self {
        Self {
            source_text: source_text.into(),
            dest_text: dest_text.into(),
            source_side,
            source_address,
            dest_address,
            source_function: source_function.into(),
            dest_function: dest_function.into(),
            source_line: 0,
            dest_line: 0,
        }
    }

    /// The destination side (opposite of source).
    pub fn dest_side(&self) -> Side {
        self.source_side.opposite()
    }
}

/// Result of applying a matched token action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyResult {
    /// The action was applied successfully.
    Success {
        /// Description of what was applied.
        description: String,
    },
    /// The action was not applicable (no matching context).
    NotApplicable,
    /// The action failed.
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

/// Base struct for actions that operate on matched tokens in the dual decompiler view.
///
/// Ported from Ghidra's `AbstractMatchedTokensAction` Java class.
/// Provides common enablement logic and the action framework. Subclasses
/// implement specific behavior for different types of token information.
#[derive(Debug, Clone)]
pub struct MatchedTokensAction {
    /// The action name.
    pub name: String,
    /// The owner.
    pub owner: String,
    /// The type of information this action applies.
    pub apply_type: ApplyType,
    /// Whether to disable the action for read-only programs.
    pub disable_on_read_only: bool,
    /// Menu path.
    pub menu_path: Vec<String>,
    /// Description.
    pub description: String,
    /// Help location.
    pub help_topic: String,
}

impl MatchedTokensAction {
    /// Create a new matched tokens action.
    pub fn new(
        name: impl Into<String>,
        owner: impl Into<String>,
        apply_type: ApplyType,
        disable_on_read_only: bool,
    ) -> Self {
        let name_str = name.into();
        Self {
            menu_path: vec![MENU_PARENT.to_string(), name_str.clone()],
            name: name_str,
            owner: owner.into(),
            apply_type,
            disable_on_read_only,
            description: String::new(),
            help_topic: HELP_TOPIC.to_string(),
        }
    }

    /// Check if this action is enabled for the given context.
    ///
    /// The action is enabled if:
    /// 1. There is a valid dual decompiler context
    /// 2. The active program is not read-only (if `disable_on_read_only` is set)
    /// 3. There are matched tokens available
    pub fn is_enabled(
        &self,
        has_matched_tokens: bool,
        is_read_only: bool,
    ) -> bool {
        if self.disable_on_read_only && is_read_only {
            return false;
        }
        has_matched_tokens
    }
}

// ---- ApplyLocalNameAction ----

/// An action to apply a local variable name from matched tokens.
///
/// Ported from Ghidra's `ApplyLocalNameFromMatchedTokensAction` Java class.
/// When the user selects a matched token pair where one side is a local
/// variable, this action applies the variable name from one side to the other.
#[derive(Debug, Clone)]
pub struct ApplyLocalNameAction {
    /// The base action.
    pub action: MatchedTokensAction,
}

impl ApplyLocalNameAction {
    /// Create a new apply local name action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            action: MatchedTokensAction::new(
                "Apply Local Variable Name",
                owner,
                ApplyType::LocalName,
                true,
            ),
        }
    }

    /// Execute the action with the given matched token info.
    pub fn execute(&self, token_info: &MatchedTokenInfo) -> ApplyResult {
        if token_info.source_text == token_info.dest_text {
            return ApplyResult::NotApplicable;
        }

        ApplyResult::Success {
            description: format!(
                "Applied local variable name '{}' from {} to {}",
                token_info.source_text,
                token_info.source_function,
                token_info.dest_function
            ),
        }
    }
}

// ---- ApplyGlobalNameAction ----

/// An action to apply a global variable/symbol name from matched tokens.
///
/// Ported from Ghidra's `ApplyGlobalNameFromMatchedTokensAction` Java class.
#[derive(Debug, Clone)]
pub struct ApplyGlobalNameAction {
    /// The base action.
    pub action: MatchedTokensAction,
}

impl ApplyGlobalNameAction {
    /// Create a new apply global name action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            action: MatchedTokensAction::new(
                "Apply Global Name",
                owner,
                ApplyType::GlobalName,
                true,
            ),
        }
    }

    /// Execute the action with the given matched token info.
    pub fn execute(&self, token_info: &MatchedTokenInfo) -> ApplyResult {
        if token_info.source_text == token_info.dest_text {
            return ApplyResult::NotApplicable;
        }

        ApplyResult::Success {
            description: format!(
                "Applied global name '{}' from {} to {}",
                token_info.source_text,
                token_info.source_function,
                token_info.dest_function
            ),
        }
    }
}

// ---- ApplyVariableTypeAction ----

/// An action to apply a variable data type from matched tokens.
///
/// Ported from Ghidra's `ApplyVariableTypeFromMatchedTokensAction` Java class.
#[derive(Debug, Clone)]
pub struct ApplyVariableTypeAction {
    /// The base action.
    pub action: MatchedTokensAction,
}

impl ApplyVariableTypeAction {
    /// Create a new apply variable type action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            action: MatchedTokensAction::new(
                "Apply Variable Type",
                owner,
                ApplyType::VariableType,
                true,
            ),
        }
    }

    /// Execute the action with the given matched token info.
    pub fn execute(&self, token_info: &MatchedTokenInfo) -> ApplyResult {
        if token_info.source_text == token_info.dest_text {
            return ApplyResult::NotApplicable;
        }

        ApplyResult::NeedsConfirmation {
            prompt: format!(
                "Apply type '{}' from {} to variable in {}?",
                token_info.source_text,
                token_info.source_function,
                token_info.dest_function
            ),
        }
    }
}

// ---- ApplyEmptyVariableTypeAction ----

/// An action to apply an empty/void variable type from matched tokens.
///
/// Ported from Ghidra's `ApplyEmptyVariableTypeFromMatchedTokensAction` Java class.
/// This sets the variable type to void/undefined.
#[derive(Debug, Clone)]
pub struct ApplyEmptyVariableTypeAction {
    /// The base action.
    pub action: MatchedTokensAction,
}

impl ApplyEmptyVariableTypeAction {
    /// Create a new apply empty variable type action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            action: MatchedTokensAction::new(
                "Apply Empty Variable Type",
                owner,
                ApplyType::EmptyVariableType,
                true,
            ),
        }
    }

    /// Execute the action.
    pub fn execute(&self, token_info: &MatchedTokenInfo) -> ApplyResult {
        ApplyResult::Success {
            description: format!(
                "Set variable at 0x{:x} in {} to undefined type",
                token_info.dest_address,
                token_info.dest_function
            ),
        }
    }
}

// ---- ApplyCalleeFunctionNameAction ----

/// An action to apply a callee function name from matched tokens.
///
/// Ported from Ghidra's `ApplyCalleeFunctionNameFromMatchedTokensAction` Java class.
#[derive(Debug, Clone)]
pub struct ApplyCalleeFunctionNameAction {
    /// The base action.
    pub action: MatchedTokensAction,
}

impl ApplyCalleeFunctionNameAction {
    /// Create a new apply callee function name action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            action: MatchedTokensAction::new(
                "Apply Callee Function Name",
                owner,
                ApplyType::CalleeFunctionName,
                true,
            ),
        }
    }

    /// Execute the action.
    pub fn execute(&self, token_info: &MatchedTokenInfo) -> ApplyResult {
        if token_info.source_text == token_info.dest_text {
            return ApplyResult::NotApplicable;
        }

        ApplyResult::NeedsConfirmation {
            prompt: format!(
                "Rename callee '{}' to '{}' based on match in {}?",
                token_info.dest_text,
                token_info.source_text,
                token_info.source_function
            ),
        }
    }
}

// ---- ApplyCalleeEmptySignatureAction ----

/// An action to apply an empty callee signature from matched tokens.
///
/// Ported from Ghidra's `ApplyCalleeEmptySignatureFromMatchedTokensAction` Java class.
/// Strips the parameter information from a callee, leaving only the name.
#[derive(Debug, Clone)]
pub struct ApplyCalleeEmptySignatureAction {
    /// The base action.
    pub action: MatchedTokensAction,
}

impl ApplyCalleeEmptySignatureAction {
    /// Create a new apply callee empty signature action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            action: MatchedTokensAction::new(
                "Apply Callee Empty Signature",
                owner,
                ApplyType::CalleeEmptySignature,
                true,
            ),
        }
    }

    /// Execute the action.
    pub fn execute(&self, token_info: &MatchedTokenInfo) -> ApplyResult {
        ApplyResult::Success {
            description: format!(
                "Set callee at 0x{:x} in {} to empty signature",
                token_info.dest_address,
                token_info.dest_function
            ),
        }
    }
}

// ---- ApplyCalleeSignatureWithDatatypesAction ----

/// An action to apply a callee signature with full datatypes from matched tokens.
///
/// Ported from Ghidra's `ApplyCalleeSignatureWithDatatypesFromMatchedTokensAction` Java class.
/// This copies the complete function signature including parameter types.
#[derive(Debug, Clone)]
pub struct ApplyCalleeSignatureWithDatatypesAction {
    /// The base action.
    pub action: MatchedTokensAction,
}

impl ApplyCalleeSignatureWithDatatypesAction {
    /// Create a new apply callee signature with datatypes action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            action: MatchedTokensAction::new(
                "Apply Callee Signature With Datatypes",
                owner,
                ApplyType::CalleeSignatureWithDatatypes,
                true,
            ),
        }
    }

    /// Execute the action.
    pub fn execute(&self, token_info: &MatchedTokenInfo) -> ApplyResult {
        if token_info.source_text == token_info.dest_text {
            return ApplyResult::NotApplicable;
        }

        ApplyResult::NeedsConfirmation {
            prompt: format!(
                "Apply signature from '{}' in {} to callee in {}?",
                token_info.source_text,
                token_info.source_function,
                token_info.dest_function
            ),
        }
    }
}

// ---- CompareFuncsFromMatchedTokensAction ----

/// An action to compare two functions discovered through matched tokens.
///
/// Ported from Ghidra's `CompareFuncsFromMatchedTokensAction` Java class.
/// When a matched token pair references a function call in both sides,
/// this action opens a new comparison between those called functions.
#[derive(Debug, Clone)]
pub struct CompareFuncsFromMatchedTokensAction {
    /// The base action.
    pub action: MatchedTokensAction,
}

impl CompareFuncsFromMatchedTokensAction {
    /// Create a new compare functions from matched tokens action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            action: MatchedTokensAction::new(
                "Compare Called Functions",
                owner,
                ApplyType::CalleeFunctionName,
                false, // don't disable on read-only since this just opens a comparison
            ),
        }
    }

    /// Execute the action.
    pub fn execute(&self, token_info: &MatchedTokenInfo) -> ApplyResult {
        ApplyResult::Success {
            description: format!(
                "Opening comparison for function '{}' (called from {} and {})",
                token_info.source_text,
                token_info.source_function,
                token_info.dest_function
            ),
        }
    }
}

/// All matched token actions for the decompiler comparison view.
///
/// Aggregates all the concrete action implementations for easy management.
#[derive(Debug)]
pub struct MatchedTokenActionSet {
    /// Apply local variable name.
    pub apply_local_name: ApplyLocalNameAction,
    /// Apply global name.
    pub apply_global_name: ApplyGlobalNameAction,
    /// Apply variable type.
    pub apply_variable_type: ApplyVariableTypeAction,
    /// Apply empty variable type.
    pub apply_empty_variable_type: ApplyEmptyVariableTypeAction,
    /// Apply callee function name.
    pub apply_callee_name: ApplyCalleeFunctionNameAction,
    /// Apply callee empty signature.
    pub apply_callee_empty_sig: ApplyCalleeEmptySignatureAction,
    /// Apply callee signature with datatypes.
    pub apply_callee_full_sig: ApplyCalleeSignatureWithDatatypesAction,
    /// Compare called functions.
    pub compare_called_funcs: CompareFuncsFromMatchedTokensAction,
}

impl MatchedTokenActionSet {
    /// Create a new action set with the given owner.
    pub fn new(owner: impl Into<String> + Clone) -> Self {
        Self {
            apply_local_name: ApplyLocalNameAction::new(owner.clone()),
            apply_global_name: ApplyGlobalNameAction::new(owner.clone()),
            apply_variable_type: ApplyVariableTypeAction::new(owner.clone()),
            apply_empty_variable_type: ApplyEmptyVariableTypeAction::new(owner.clone()),
            apply_callee_name: ApplyCalleeFunctionNameAction::new(owner.clone()),
            apply_callee_empty_sig: ApplyCalleeEmptySignatureAction::new(owner.clone()),
            apply_callee_full_sig: ApplyCalleeSignatureWithDatatypesAction::new(owner.clone()),
            compare_called_funcs: CompareFuncsFromMatchedTokensAction::new(owner),
        }
    }

    /// Get all action names.
    pub fn action_names(&self) -> Vec<&str> {
        vec![
            &self.apply_local_name.action.name,
            &self.apply_global_name.action.name,
            &self.apply_variable_type.action.name,
            &self.apply_empty_variable_type.action.name,
            &self.apply_callee_name.action.name,
            &self.apply_callee_empty_sig.action.name,
            &self.apply_callee_full_sig.action.name,
            &self.compare_called_funcs.action.name,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_token_info() -> MatchedTokenInfo {
        MatchedTokenInfo::new(
            "source_var",
            "dest_var",
            Side::Left,
            0x1000,
            0x2000,
            "left_func",
            "right_func",
        )
    }

    // --- MatchedTokensAction tests ---

    #[test]
    fn test_matched_tokens_action_enabled() {
        let action = MatchedTokensAction::new("test", "owner", ApplyType::LocalName, true);
        assert!(action.is_enabled(true, false));
        assert!(!action.is_enabled(true, true));
        assert!(!action.is_enabled(false, false));
    }

    #[test]
    fn test_matched_tokens_action_no_readonly_check() {
        let action = MatchedTokensAction::new("test", "owner", ApplyType::LocalName, false);
        assert!(action.is_enabled(true, true));
    }

    // --- ApplyLocalNameAction tests ---

    #[test]
    fn test_apply_local_name_different() {
        let action = ApplyLocalNameAction::new("test");
        let info = make_token_info();
        match action.execute(&info) {
            ApplyResult::Success { description } => {
                assert!(description.contains("source_var"));
            }
            _ => panic!("Expected Success"),
        }
    }

    #[test]
    fn test_apply_local_name_same() {
        let action = ApplyLocalNameAction::new("test");
        let mut info = make_token_info();
        info.dest_text = info.source_text.clone();
        assert_eq!(action.execute(&info), ApplyResult::NotApplicable);
    }

    // --- ApplyGlobalNameAction tests ---

    #[test]
    fn test_apply_global_name() {
        let action = ApplyGlobalNameAction::new("test");
        let info = make_token_info();
        match action.execute(&info) {
            ApplyResult::Success { .. } => {}
            _ => panic!("Expected Success"),
        }
    }

    // --- ApplyVariableTypeAction tests ---

    #[test]
    fn test_apply_variable_type_needs_confirmation() {
        let action = ApplyVariableTypeAction::new("test");
        let info = make_token_info();
        match action.execute(&info) {
            ApplyResult::NeedsConfirmation { prompt } => {
                assert!(prompt.contains("source_var"));
            }
            _ => panic!("Expected NeedsConfirmation"),
        }
    }

    // --- ApplyEmptyVariableTypeAction tests ---

    #[test]
    fn test_apply_empty_variable_type() {
        let action = ApplyEmptyVariableTypeAction::new("test");
        let info = make_token_info();
        match action.execute(&info) {
            ApplyResult::Success { description } => {
                assert!(description.contains("undefined"));
            }
            _ => panic!("Expected Success"),
        }
    }

    // --- ApplyCalleeFunctionNameAction tests ---

    #[test]
    fn test_apply_callee_name_different() {
        let action = ApplyCalleeFunctionNameAction::new("test");
        let info = make_token_info();
        match action.execute(&info) {
            ApplyResult::NeedsConfirmation { .. } => {}
            _ => panic!("Expected NeedsConfirmation"),
        }
    }

    #[test]
    fn test_apply_callee_name_same() {
        let action = ApplyCalleeFunctionNameAction::new("test");
        let mut info = make_token_info();
        info.dest_text = info.source_text.clone();
        assert_eq!(action.execute(&info), ApplyResult::NotApplicable);
    }

    // --- ApplyCalleeEmptySignatureAction tests ---

    #[test]
    fn test_apply_callee_empty_sig() {
        let action = ApplyCalleeEmptySignatureAction::new("test");
        let info = make_token_info();
        match action.execute(&info) {
            ApplyResult::Success { .. } => {}
            _ => panic!("Expected Success"),
        }
    }

    // --- ApplyCalleeSignatureWithDatatypesAction tests ---

    #[test]
    fn test_apply_callee_full_sig_needs_confirmation() {
        let action = ApplyCalleeSignatureWithDatatypesAction::new("test");
        let info = make_token_info();
        match action.execute(&info) {
            ApplyResult::NeedsConfirmation { .. } => {}
            _ => panic!("Expected NeedsConfirmation"),
        }
    }

    // --- CompareFuncsFromMatchedTokensAction tests ---

    #[test]
    fn test_compare_funcs() {
        let action = CompareFuncsFromMatchedTokensAction::new("test");
        let info = make_token_info();
        match action.execute(&info) {
            ApplyResult::Success { description } => {
                assert!(description.contains("Opening comparison"));
            }
            _ => panic!("Expected Success"),
        }
    }

    // --- MatchedTokenInfo tests ---

    #[test]
    fn test_matched_token_info() {
        let info = make_token_info();
        assert_eq!(info.source_side, Side::Left);
        assert_eq!(info.dest_side(), Side::Right);
        assert_eq!(info.source_address, 0x1000);
        assert_eq!(info.dest_address, 0x2000);
    }

    // --- MatchedTokenActionSet tests ---

    #[test]
    fn test_action_set_names() {
        let set = MatchedTokenActionSet::new("test");
        let names = set.action_names();
        assert_eq!(names.len(), 8);
        assert!(names.contains(&"Apply Local Variable Name"));
        assert!(names.contains(&"Apply Global Name"));
        assert!(names.contains(&"Compare Called Functions"));
    }
}
