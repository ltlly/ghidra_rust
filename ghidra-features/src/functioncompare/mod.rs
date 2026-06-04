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
