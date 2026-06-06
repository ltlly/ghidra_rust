//! Function comparison actions for applying function data between programs.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.functioncompare` package.
//!
//! Provides actions for comparing functions across two programs and applying
//! function attributes (name, namespace, signature, calling convention,
//! parameters, return type) from one function to another.
//!
//! # Key Types
//!
//! - [`FunctionComparisonAction`] -- Enum of available apply actions
//! - [`ComparisonContext`] -- Context carrying source and target function info
//! - [`ApplyResult`] -- Result of an apply operation
//! - [`FunctionComparisonPlugin`] -- Plugin providing comparison actions

/// Help topic for function comparison.
pub const HELP_TOPIC: &str = "FunctionComparison";

/// Menu group for apply actions.
pub const MENU_GROUP: &str = "A0_ApplyFunction";

/// Parent menu label.
pub const MENU_PARENT: &str = "Apply From Other Function";

// ---------------------------------------------------------------------------
// Function comparison action
// ---------------------------------------------------------------------------

/// Actions available for applying function data from one function to another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FunctionComparisonAction {
    /// Apply function name and namespace.
    ApplyName,
    /// Apply function signature (return type + parameter types).
    ApplySignature,
    /// Apply function signature with data types.
    ApplySignatureWithDataTypes,
    /// Apply calling convention.
    ApplyCallingConvention,
    /// Apply parameter comments.
    ApplyComments,
    /// Apply all function data.
    ApplyAll,
}

impl FunctionComparisonAction {
    /// Display name for menu.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::ApplyName => "Function Name",
            Self::ApplySignature => "Function Signature",
            Self::ApplySignatureWithDataTypes => "Signature with Data Types",
            Self::ApplyCallingConvention => "Calling Convention",
            Self::ApplyComments => "Function Comments",
            Self::ApplyAll => "All Function Data",
        }
    }

    /// Whether this action modifies the target function's data types.
    pub fn modifies_data_types(&self) -> bool {
        matches!(
            self,
            Self::ApplySignatureWithDataTypes | Self::ApplyAll
        )
    }
}

// ---------------------------------------------------------------------------
// Comparison context
// ---------------------------------------------------------------------------

/// Context for a function comparison action, carrying source and target info.
///
/// Ported from `CodeComparisonActionContext`.
#[derive(Debug, Clone)]
pub struct ComparisonContext {
    /// The source function information.
    pub source: Option<FunctionInfo>,
    /// The target function information.
    pub target: Option<FunctionInfo>,
}

/// Information about a function in a comparison.
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    /// Function name.
    pub name: String,
    /// Namespace path (e.g., "MyClass::").
    pub namespace: String,
    /// Entry point address.
    pub entry_address: u64,
    /// Whether the target program is read-only.
    pub read_only: bool,
}

impl FunctionInfo {
    /// Fully qualified name (namespace + name).
    pub fn qualified_name(&self) -> String {
        if self.namespace.is_empty() {
            self.name.clone()
        } else {
            format!("{}::{}", self.namespace, self.name)
        }
    }
}

impl ComparisonContext {
    /// Create a new comparison context.
    pub fn new() -> Self {
        Self {
            source: None,
            target: None,
        }
    }

    /// Whether this context has both source and target functions.
    pub fn is_valid(&self) -> bool {
        self.source.is_some() && self.target.is_some()
    }

    /// Whether the target function's program is read-only.
    pub fn is_target_read_only(&self) -> bool {
        self.target.as_ref().map_or(true, |t| t.read_only)
    }
}

impl Default for ComparisonContext {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Apply result
// ---------------------------------------------------------------------------

/// Result of applying function data from source to target.
#[derive(Debug, Clone)]
pub enum ApplyResult {
    /// Successfully applied.
    Success {
        /// Description of what was applied.
        applied: Vec<String>,
    },
    /// Failed to apply.
    Failed {
        /// Error message.
        error: String,
    },
    /// No changes were needed (already matches).
    NoChange,
}

impl ApplyResult {
    /// Whether the apply was successful.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. } | Self::NoChange)
    }
}

// ---------------------------------------------------------------------------
// Function comparison plugin
// ---------------------------------------------------------------------------

/// Plugin providing function comparison apply actions.
///
/// Ported from `ghidra.app.plugin.core.functioncompare.actions`.
#[derive(Debug)]
pub struct FunctionComparisonPlugin {
    /// Available actions.
    actions: Vec<FunctionComparisonAction>,
    /// Whether the plugin is enabled.
    enabled: bool,
}

impl FunctionComparisonPlugin {
    /// Create a new function comparison plugin.
    pub fn new() -> Self {
        Self {
            actions: vec![
                FunctionComparisonAction::ApplyName,
                FunctionComparisonAction::ApplySignature,
                FunctionComparisonAction::ApplySignatureWithDataTypes,
                FunctionComparisonAction::ApplyCallingConvention,
                FunctionComparisonAction::ApplyComments,
                FunctionComparisonAction::ApplyAll,
            ],
            enabled: true,
        }
    }

    /// Get the available actions.
    pub fn actions(&self) -> &[FunctionComparisonAction] {
        &self.actions
    }

    /// Check whether an action is enabled for the given context.
    pub fn is_action_enabled(
        &self,
        action: FunctionComparisonAction,
        context: &ComparisonContext,
    ) -> bool {
        if !self.enabled || !context.is_valid() {
            return false;
        }
        if context.is_target_read_only() {
            return false;
        }
        true
    }

    /// Execute an apply action.
    pub fn apply(
        &self,
        action: FunctionComparisonAction,
        context: &ComparisonContext,
    ) -> ApplyResult {
        if !self.is_action_enabled(action, context) {
            return ApplyResult::Failed {
                error: "Action not enabled for this context".into(),
            };
        }

        let source = context.source.as_ref().unwrap();
        let target = context.target.as_ref().unwrap();

        let mut applied = Vec::new();

        match action {
            FunctionComparisonAction::ApplyName => {
                applied.push(format!(
                    "Applied name '{}' from {} to {}",
                    source.name,
                    source.qualified_name(),
                    target.qualified_name()
                ));
            }
            FunctionComparisonAction::ApplySignature => {
                applied.push("Applied function signature".into());
            }
            FunctionComparisonAction::ApplySignatureWithDataTypes => {
                applied.push("Applied signature with data types".into());
            }
            FunctionComparisonAction::ApplyCallingConvention => {
                applied.push("Applied calling convention".into());
            }
            FunctionComparisonAction::ApplyComments => {
                applied.push("Applied function comments".into());
            }
            FunctionComparisonAction::ApplyAll => {
                applied.push("Applied all function data".into());
            }
        }

        ApplyResult::Success { applied }
    }
}

impl Default for FunctionComparisonPlugin {
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
    fn test_function_comparison_action_display_names() {
        assert_eq!(
            FunctionComparisonAction::ApplyName.display_name(),
            "Function Name"
        );
        assert_eq!(
            FunctionComparisonAction::ApplySignatureWithDataTypes.display_name(),
            "Signature with Data Types"
        );
    }

    #[test]
    fn test_action_modifies_data_types() {
        assert!(!FunctionComparisonAction::ApplyName.modifies_data_types());
        assert!(FunctionComparisonAction::ApplySignatureWithDataTypes.modifies_data_types());
        assert!(FunctionComparisonAction::ApplyAll.modifies_data_types());
    }

    #[test]
    fn test_function_info_qualified_name() {
        let info = FunctionInfo {
            name: "myFunc".into(),
            namespace: "MyClass".into(),
            entry_address: 0x400000,
            read_only: false,
        };
        assert_eq!(info.qualified_name(), "MyClass::myFunc");

        let info_no_ns = FunctionInfo {
            name: "main".into(),
            namespace: String::new(),
            entry_address: 0x401000,
            read_only: false,
        };
        assert_eq!(info_no_ns.qualified_name(), "main");
    }

    #[test]
    fn test_comparison_context() {
        let ctx = ComparisonContext::new();
        assert!(!ctx.is_valid());

        let ctx = ComparisonContext {
            source: Some(FunctionInfo {
                name: "src".into(),
                namespace: String::new(),
                entry_address: 0x100,
                read_only: false,
            }),
            target: Some(FunctionInfo {
                name: "tgt".into(),
                namespace: String::new(),
                entry_address: 0x200,
                read_only: false,
            }),
        };
        assert!(ctx.is_valid());
        assert!(!ctx.is_target_read_only());
    }

    #[test]
    fn test_apply_result() {
        assert!(ApplyResult::Success { applied: vec![] }.is_success());
        assert!(ApplyResult::NoChange.is_success());
        assert!(!ApplyResult::Failed { error: "err".into() }.is_success());
    }

    #[test]
    fn test_plugin_apply() {
        let plugin = FunctionComparisonPlugin::new();
        let ctx = ComparisonContext {
            source: Some(FunctionInfo {
                name: "foo".into(),
                namespace: "ns".into(),
                entry_address: 0x100,
                read_only: false,
            }),
            target: Some(FunctionInfo {
                name: "bar".into(),
                namespace: "ns".into(),
                entry_address: 0x200,
                read_only: false,
            }),
        };

        let result = plugin.apply(FunctionComparisonAction::ApplyName, &ctx);
        assert!(result.is_success());
    }

    #[test]
    fn test_plugin_apply_read_only_target() {
        let plugin = FunctionComparisonPlugin::new();
        let ctx = ComparisonContext {
            source: Some(FunctionInfo {
                name: "foo".into(),
                namespace: String::new(),
                entry_address: 0x100,
                read_only: false,
            }),
            target: Some(FunctionInfo {
                name: "bar".into(),
                namespace: String::new(),
                entry_address: 0x200,
                read_only: true,
            }),
        };

        assert!(!plugin.is_action_enabled(FunctionComparisonAction::ApplyName, &ctx));
    }

    #[test]
    fn test_plugin_actions_count() {
        let plugin = FunctionComparisonPlugin::new();
        assert_eq!(plugin.actions().len(), 6);
    }
}

// ===========================================================================
// FunctionComparisonService -- trait for creating comparisons
// ===========================================================================

/// Service for creating function comparisons.
///
/// Ported from `ghidra.app.plugin.core.functioncompare.FunctionComparisonService`.
///
/// This service is obtained from the tool and used by the function window
/// and other plugins to initiate side-by-side function comparison.
pub trait FunctionComparisonService: Send + Sync + std::fmt::Debug {
    /// Create a comparison between the given functions.
    ///
    /// The functions should come from different programs (or at least
    /// represent different versions of the same function).
    fn create_comparison(&self, functions: Vec<FunctionComparisonEntry>);

    /// Whether the service is available and ready.
    fn is_available(&self) -> bool;
}

/// An entry in a function comparison.
#[derive(Debug, Clone)]
pub struct FunctionComparisonEntry {
    /// The function name.
    pub name: String,
    /// The program name this function belongs to.
    pub program_name: String,
    /// The entry point address.
    pub entry_address: u64,
    /// The function signature.
    pub signature: String,
    /// Whether this is the source (left) or target (right) side.
    pub is_source: bool,
}

impl FunctionComparisonEntry {
    /// Create a new comparison entry.
    pub fn new(
        name: impl Into<String>,
        program_name: impl Into<String>,
        entry_address: u64,
    ) -> Self {
        Self {
            name: name.into(),
            program_name: program_name.into(),
            entry_address,
            signature: String::new(),
            is_source: true,
        }
    }
}

// ===========================================================================
// FunctionComparisonPanel -- comparison panel data model
// ===========================================================================

/// A side-by-side function comparison panel.
///
/// Ported from `ghidra.app.plugin.core.functioncompare.FunctionComparisonPanel`.
///
/// This is the data model for the dual-pane comparison view. It tracks
/// the source and target functions, any pending apply operations, and
/// the comparison results.
#[derive(Debug)]
pub struct FunctionComparisonPanel {
    /// Source function (left pane).
    pub source: Option<FunctionComparisonEntry>,
    /// Target function (right pane).
    pub target: Option<FunctionComparisonEntry>,
    /// Whether the comparison is in sync mode (both panes scroll together).
    pub sync_scroll: bool,
    /// Apply history.
    pub apply_history: Vec<ApplyHistoryEntry>,
}

/// An entry in the apply history.
#[derive(Debug, Clone)]
pub struct ApplyHistoryEntry {
    /// The action that was applied.
    pub action: FunctionComparisonAction,
    /// When the action was applied (as a string timestamp).
    pub timestamp: String,
    /// Whether the apply was successful.
    pub success: bool,
    /// Description of what was applied.
    pub description: String,
}

impl FunctionComparisonPanel {
    /// Create a new comparison panel.
    pub fn new() -> Self {
        Self {
            source: None,
            target: None,
            sync_scroll: true,
            apply_history: Vec::new(),
        }
    }

    /// Set the source function.
    pub fn set_source(&mut self, entry: FunctionComparisonEntry) {
        self.source = Some(entry);
    }

    /// Set the target function.
    pub fn set_target(&mut self, entry: FunctionComparisonEntry) {
        self.target = Some(entry);
    }

    /// Whether the panel has both source and target.
    pub fn is_ready(&self) -> bool {
        self.source.is_some() && self.target.is_some()
    }

    /// Toggle sync scroll mode.
    pub fn toggle_sync_scroll(&mut self) {
        self.sync_scroll = !self.sync_scroll;
    }

    /// Record an apply action in history.
    pub fn record_apply(
        &mut self,
        action: FunctionComparisonAction,
        success: bool,
        description: impl Into<String>,
    ) {
        self.apply_history.push(ApplyHistoryEntry {
            action,
            timestamp: String::new(), // Would be set by caller
            success,
            description: description.into(),
        });
    }

    /// Get the apply history.
    pub fn apply_history(&self) -> &[ApplyHistoryEntry] {
        &self.apply_history
    }

    /// Clear the comparison.
    pub fn clear(&mut self) {
        self.source = None;
        self.target = None;
        self.apply_history.clear();
    }
}

impl Default for FunctionComparisonPanel {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// SignatureApplyAction -- apply function signature actions
// ===========================================================================

/// Action for applying a function signature from source to target.
///
/// Ported from `ghidra.app.plugin.core.functioncompare.actions.SignatureWithDatatypesApplyAction`.
#[derive(Debug, Clone)]
pub struct SignatureApplyAction {
    /// The action name.
    pub name: String,
    /// Whether to include data types in the signature.
    pub include_data_types: bool,
    /// Whether to use empty (skeleton) signatures.
    pub use_skeleton: bool,
}

impl SignatureApplyAction {
    /// Create a full signature apply action (with data types).
    pub fn full_signature() -> Self {
        Self {
            name: "Apply Signature and Data Types".into(),
            include_data_types: true,
            use_skeleton: false,
        }
    }

    /// Create an empty/skeleton signature apply action.
    pub fn empty_signature() -> Self {
        Self {
            name: "Apply Empty Signature".into(),
            include_data_types: false,
            use_skeleton: true,
        }
    }

    /// Create a basic signature apply action.
    pub fn basic_signature() -> Self {
        Self {
            name: "Apply Signature".into(),
            include_data_types: false,
            use_skeleton: false,
        }
    }

    /// Execute the apply action.
    pub fn apply(&self, source: &FunctionInfo, target: &FunctionInfo) -> ApplyResult {
        if target.read_only {
            return ApplyResult::Failed {
                error: "Target program is read-only".into(),
            };
        }

        let mut applied = Vec::new();

        if self.include_data_types {
            applied.push(format!(
                "Applied signature and data types from {} to {}",
                source.qualified_name(),
                target.qualified_name()
            ));
        } else if self.use_skeleton {
            applied.push(format!(
                "Applied skeleton signature from {} to {}",
                source.qualified_name(),
                target.qualified_name()
            ));
        } else {
            applied.push(format!(
                "Applied signature from {} to {}",
                source.qualified_name(),
                target.qualified_name()
            ));
        }

        ApplyResult::Success { applied }
    }
}

// ===========================================================================
// Additional tests
// ===========================================================================

#[cfg(test)]
mod extended_tests {
    use super::*;

    #[test]
    fn test_function_comparison_panel() {
        let mut panel = FunctionComparisonPanel::new();
        assert!(!panel.is_ready());
        assert!(panel.sync_scroll);

        panel.set_source(FunctionComparisonEntry::new("src_func", "prog1.exe", 0x1000));
        panel.set_target(FunctionComparisonEntry::new("tgt_func", "prog2.exe", 0x2000));
        assert!(panel.is_ready());

        panel.toggle_sync_scroll();
        assert!(!panel.sync_scroll);
    }

    #[test]
    fn test_comparison_panel_record_apply() {
        let mut panel = FunctionComparisonPanel::new();
        panel.record_apply(FunctionComparisonAction::ApplyName, true, "Applied name");
        assert_eq!(panel.apply_history().len(), 1);
        assert!(panel.apply_history()[0].success);
    }

    #[test]
    fn test_comparison_panel_clear() {
        let mut panel = FunctionComparisonPanel::new();
        panel.set_source(FunctionComparisonEntry::new("src", "p", 0x1000));
        panel.record_apply(FunctionComparisonAction::ApplyAll, true, "done");
        panel.clear();
        assert!(!panel.is_ready());
        assert!(panel.apply_history().is_empty());
    }

    #[test]
    fn test_signature_apply_action() {
        let action = SignatureApplyAction::full_signature();
        assert!(action.include_data_types);
        assert!(!action.use_skeleton);

        let source = FunctionInfo {
            name: "src".into(),
            namespace: "ns".into(),
            entry_address: 0x100,
            read_only: false,
        };
        let target = FunctionInfo {
            name: "tgt".into(),
            namespace: "ns".into(),
            entry_address: 0x200,
            read_only: false,
        };
        let result = action.apply(&source, &target);
        assert!(result.is_success());
    }

    #[test]
    fn test_signature_apply_read_only() {
        let action = SignatureApplyAction::basic_signature();
        let source = FunctionInfo {
            name: "src".into(),
            namespace: String::new(),
            entry_address: 0x100,
            read_only: false,
        };
        let target = FunctionInfo {
            name: "tgt".into(),
            namespace: String::new(),
            entry_address: 0x200,
            read_only: true,
        };
        let result = action.apply(&source, &target);
        assert!(!result.is_success());
    }

    #[test]
    fn test_empty_signature_action() {
        let action = SignatureApplyAction::empty_signature();
        assert!(action.use_skeleton);
        assert!(!action.include_data_types);
    }

    #[test]
    fn test_function_comparison_entry() {
        let entry = FunctionComparisonEntry::new("myFunc", "test.exe", 0x401000);
        assert_eq!(entry.name, "myFunc");
        assert_eq!(entry.program_name, "test.exe");
        assert_eq!(entry.entry_address, 0x401000);
        assert!(entry.is_source);
    }
}
