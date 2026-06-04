//! Rename plugin -- manages rename operations and action enablement.
//!
//! Ported from Ghidra's rename actions in `ghidra.app.plugin.core`.
//!
//! The `RenamePlugin` provides methods to:
//! - Determine which rename actions are available for a given context
//! - Create rename commands for symbols, functions, and namespaces
//! - Validate rename operations before execution

use super::cmd::{
    validate_symbol_name, is_default_function_name, is_default_label_name, RenameAndMoveCmd,
    RenameFunctionCmd, RenameLabelCmd, RenameNamespaceCmd, SetLabelPrimaryCmd, SetNamespaceCmd,
};
use ghidra_core::addr::Address;
use ghidra_core::symbol::{SourceType, SymbolType};
use serde::{Deserialize, Serialize};

/// The set of rename actions available in the listing.
///
/// Each variant corresponds to a different rename action class in Ghidra.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RenameAction {
    /// Rename a label symbol at the current address.
    RenameLabel,
    /// Rename a function symbol.
    RenameFunction,
    /// Rename a namespace (class, library, generic namespace).
    RenameNamespace,
    /// Move a symbol to a different namespace.
    MoveToNamespace,
    /// Set a label as the primary symbol at its address.
    SetLabelPrimary,
    /// Rename and move a symbol in one operation.
    RenameAndMove,
}

impl RenameAction {
    /// Returns the display name for this action.
    pub fn display_name(self) -> &'static str {
        match self {
            RenameAction::RenameLabel => "Rename Label...",
            RenameAction::RenameFunction => "Rename Function...",
            RenameAction::RenameNamespace => "Rename Namespace...",
            RenameAction::MoveToNamespace => "Move to Namespace...",
            RenameAction::SetLabelPrimary => "Set as Primary Label",
            RenameAction::RenameAndMove => "Rename and Move...",
        }
    }

    /// Returns the key binding for this action, if any.
    pub fn key_binding(self) -> Option<&'static str> {
        match self {
            RenameAction::RenameLabel | RenameAction::RenameFunction => Some("L"),
            _ => None,
        }
    }
}

/// Context for a rename action, carrying information about the current
/// listing position and any symbol present.
///
/// This is the Rust equivalent of the relevant parts of Ghidra's
/// `ListingActionContext` specialized for rename operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameActionContext {
    /// The address at the cursor location.
    pub address: Address,
    /// The symbol type at the cursor (if any).
    pub symbol_type: Option<SymbolType>,
    /// The symbol source (if any).
    pub symbol_source: Option<SourceType>,
    /// Whether the symbol is external.
    pub is_external: bool,
    /// Whether the symbol is dynamic (auto-generated).
    pub is_dynamic: bool,
    /// Whether this is a function entry point.
    pub on_function: bool,
    /// Whether the cursor is on a label field.
    pub on_label_field: bool,
    /// Whether this symbol is pinned.
    pub is_pinned: bool,
}

impl RenameActionContext {
    /// Creates a context for a position with no symbol.
    pub fn empty(address: Address) -> Self {
        Self {
            address,
            symbol_type: None,
            symbol_source: None,
            is_external: false,
            is_dynamic: false,
            on_function: false,
            on_label_field: false,
            is_pinned: false,
        }
    }

    /// Creates a context for a position on a label symbol.
    pub fn on_label(
        address: Address,
        source: SourceType,
        is_external: bool,
        is_dynamic: bool,
    ) -> Self {
        Self {
            address,
            symbol_type: Some(SymbolType::Label),
            symbol_source: Some(source),
            is_external,
            is_dynamic,
            on_function: false,
            on_label_field: true,
            is_pinned: false,
        }
    }

    /// Creates a context for a position on a function symbol.
    pub fn on_function(
        address: Address,
        source: SourceType,
        is_external: bool,
    ) -> Self {
        Self {
            address,
            symbol_type: Some(SymbolType::Function),
            symbol_source: Some(source),
            is_external,
            is_dynamic: false,
            on_function: true,
            on_label_field: true,
            is_pinned: false,
        }
    }

    /// Creates a context for a position on a namespace symbol.
    pub fn on_namespace(address: Address, ns_type: SymbolType) -> Self {
        Self {
            address,
            symbol_type: Some(ns_type),
            symbol_source: Some(SourceType::UserDefined),
            is_external: false,
            is_dynamic: false,
            on_function: false,
            on_label_field: false,
            is_pinned: false,
        }
    }

    /// Returns `true` if a symbol exists at this location.
    pub fn has_symbol(&self) -> bool {
        self.symbol_type.is_some()
    }
}

/// The rename plugin controller.
///
/// Provides methods to determine which rename actions are available
/// and to create appropriate rename commands. This mirrors Ghidra's
/// various rename action classes (`RenameAction`, `RenameFunctionAction`,
/// etc.) consolidated into a single controller.
#[derive(Debug, Clone, Default)]
pub struct RenamePlugin;

impl RenamePlugin {
    /// Creates a new rename plugin.
    pub fn new() -> Self {
        Self
    }

    /// Returns the set of rename actions available for the given context.
    ///
    /// This mirrors the `isEnabledForContext` logic of Ghidra's various
    /// rename action classes.
    pub fn available_actions(&self, ctx: &RenameActionContext) -> Vec<RenameAction> {
        let mut actions = Vec::new();

        if self.is_rename_label_enabled(ctx) {
            actions.push(RenameAction::RenameLabel);
        }
        if self.is_rename_function_enabled(ctx) {
            actions.push(RenameAction::RenameFunction);
        }
        if self.is_rename_namespace_enabled(ctx) {
            actions.push(RenameAction::RenameNamespace);
        }
        if self.is_set_label_primary_enabled(ctx) {
            actions.push(RenameAction::SetLabelPrimary);
        }

        actions
    }

    /// Checks whether the "Rename Label" action should be enabled.
    ///
    /// Mirrors Ghidra's rename label action enablement:
    /// - Not on external addresses
    /// - On a label symbol that is not pinned
    pub fn is_rename_label_enabled(&self, ctx: &RenameActionContext) -> bool {
        if ctx.is_external {
            return false;
        }
        if ctx.is_pinned {
            return false;
        }
        matches!(ctx.symbol_type, Some(SymbolType::Label))
    }

    /// Checks whether the "Rename Function" action should be enabled.
    ///
    /// Mirrors Ghidra's rename function action enablement:
    /// - Not on external addresses
    /// - On a function symbol
    pub fn is_rename_function_enabled(&self, ctx: &RenameActionContext) -> bool {
        if ctx.is_external {
            return false;
        }
        matches!(ctx.symbol_type, Some(SymbolType::Function))
    }

    /// Checks whether the "Rename Namespace" action should be enabled.
    ///
    /// Namespaces (classes, libraries, generic namespaces) can be renamed.
    pub fn is_rename_namespace_enabled(&self, ctx: &RenameActionContext) -> bool {
        matches!(
            ctx.symbol_type,
            Some(SymbolType::Namespace) | Some(SymbolType::Class) | Some(SymbolType::Library)
        )
    }

    /// Checks whether the "Set Label Primary" action should be enabled.
    ///
    /// This is enabled when there are multiple labels at an address and
    /// the selected one is not already primary.
    pub fn is_set_label_primary_enabled(&self, ctx: &RenameActionContext) -> bool {
        // In a full implementation, this checks for multiple symbols at the address
        // and whether the current one is already primary. For now, enable on any label.
        matches!(ctx.symbol_type, Some(SymbolType::Label)) && !ctx.is_external
    }

    /// Creates a rename label command for the given context and new name.
    ///
    /// Returns `None` if rename is not enabled for the context.
    pub fn create_rename_label_cmd(
        &self,
        ctx: &RenameActionContext,
        new_name: &str,
        source: SourceType,
    ) -> Option<RenameLabelCmd> {
        if !self.is_rename_label_enabled(ctx) {
            return None;
        }
        if validate_symbol_name(new_name).is_err() {
            return None;
        }
        Some(RenameLabelCmd::new(ctx.address, new_name, source))
    }

    /// Creates a rename function command for the given context and new name.
    ///
    /// Returns `None` if rename is not enabled for the context.
    pub fn create_rename_function_cmd(
        &self,
        ctx: &RenameActionContext,
        new_name: &str,
        source: SourceType,
    ) -> Option<RenameFunctionCmd> {
        if !self.is_rename_function_enabled(ctx) {
            return None;
        }
        if validate_symbol_name(new_name).is_err() {
            return None;
        }
        Some(RenameFunctionCmd::new(ctx.address, new_name, source))
    }

    /// Creates a rename namespace command.
    pub fn create_rename_namespace_cmd(
        &self,
        namespace_symbol_id: u64,
        new_name: &str,
        source: SourceType,
    ) -> Option<RenameNamespaceCmd> {
        if validate_symbol_name(new_name).is_err() {
            return None;
        }
        Some(RenameNamespaceCmd::new(namespace_symbol_id, new_name, source))
    }

    /// Creates a set-label-primary command for the given context.
    pub fn create_set_primary_cmd(
        &self,
        ctx: &RenameActionContext,
        label_name: &str,
    ) -> Option<SetLabelPrimaryCmd> {
        if !self.is_set_label_primary_enabled(ctx) {
            return None;
        }
        Some(SetLabelPrimaryCmd::new(ctx.address, label_name))
    }

    /// Determines the appropriate source type for a rename based on the
    /// current symbol source and the user's input.
    ///
    /// Ghidra typically uses `UserDefined` for user-initiated renames,
    /// but preserves `Analysis` source for analysis-generated symbols
    /// in certain cases.
    pub fn determine_source_type(
        &self,
        current_source: Option<SourceType>,
        user_initiated: bool,
    ) -> SourceType {
        if user_initiated {
            return SourceType::UserDefined;
        }
        current_source.unwrap_or(SourceType::Default)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rename_label_enabled_on_label() {
        let plugin = RenamePlugin::new();
        let ctx = RenameActionContext::on_label(
            Address::new(0x1000),
            SourceType::Default,
            false,
            false,
        );
        assert!(plugin.is_rename_label_enabled(&ctx));
    }

    #[test]
    fn test_rename_label_disabled_on_external() {
        let plugin = RenamePlugin::new();
        let ctx = RenameActionContext::on_label(
            Address::new(0x1000),
            SourceType::Default,
            true,  // is_external
            false,
        );
        assert!(!plugin.is_rename_label_enabled(&ctx));
    }

    #[test]
    fn test_rename_label_disabled_on_pinned() {
        let plugin = RenamePlugin::new();
        let mut ctx = RenameActionContext::on_label(
            Address::new(0x1000),
            SourceType::UserDefined,
            false,
            false,
        );
        ctx.is_pinned = true;
        assert!(!plugin.is_rename_label_enabled(&ctx));
    }

    #[test]
    fn test_rename_function_enabled() {
        let plugin = RenamePlugin::new();
        let ctx = RenameActionContext::on_function(
            Address::new(0x1000),
            SourceType::Default,
            false,
        );
        assert!(plugin.is_rename_function_enabled(&ctx));
    }

    #[test]
    fn test_rename_function_disabled_on_external() {
        let plugin = RenamePlugin::new();
        let ctx = RenameActionContext::on_function(
            Address::new(0x1000),
            SourceType::Default,
            true,
        );
        assert!(!plugin.is_rename_function_enabled(&ctx));
    }

    #[test]
    fn test_rename_namespace_enabled() {
        let plugin = RenamePlugin::new();
        let ctx = RenameActionContext::on_namespace(
            Address::new(0),
            SymbolType::Namespace,
        );
        assert!(plugin.is_rename_namespace_enabled(&ctx));
    }

    #[test]
    fn test_rename_class_enabled() {
        let plugin = RenamePlugin::new();
        let ctx = RenameActionContext::on_namespace(
            Address::new(0),
            SymbolType::Class,
        );
        assert!(plugin.is_rename_namespace_enabled(&ctx));
    }

    #[test]
    fn test_rename_library_enabled() {
        let plugin = RenamePlugin::new();
        let ctx = RenameActionContext::on_namespace(
            Address::new(0),
            SymbolType::Library,
        );
        assert!(plugin.is_rename_namespace_enabled(&ctx));
    }

    #[test]
    fn test_rename_namespace_disabled_for_label() {
        let plugin = RenamePlugin::new();
        let ctx = RenameActionContext::on_label(
            Address::new(0x1000),
            SourceType::Default,
            false,
            false,
        );
        assert!(!plugin.is_rename_namespace_enabled(&ctx));
    }

    #[test]
    fn test_available_actions_on_label() {
        let plugin = RenamePlugin::new();
        let ctx = RenameActionContext::on_label(
            Address::new(0x1000),
            SourceType::Default,
            false,
            false,
        );
        let actions = plugin.available_actions(&ctx);
        assert!(actions.contains(&RenameAction::RenameLabel));
        assert!(actions.contains(&RenameAction::SetLabelPrimary));
        assert!(!actions.contains(&RenameAction::RenameFunction));
        assert!(!actions.contains(&RenameAction::RenameNamespace));
    }

    #[test]
    fn test_available_actions_on_function() {
        let plugin = RenamePlugin::new();
        let ctx = RenameActionContext::on_function(
            Address::new(0x1000),
            SourceType::Default,
            false,
        );
        let actions = plugin.available_actions(&ctx);
        assert!(actions.contains(&RenameAction::RenameFunction));
        assert!(!actions.contains(&RenameAction::RenameLabel));
    }

    #[test]
    fn test_create_rename_label_cmd() {
        let plugin = RenamePlugin::new();
        let ctx = RenameActionContext::on_label(
            Address::new(0x1000),
            SourceType::Default,
            false,
            false,
        );
        let cmd = plugin.create_rename_label_cmd(&ctx, "new_label", SourceType::UserDefined);
        assert!(cmd.is_some());
        let cmd = cmd.unwrap();
        assert_eq!(cmd.new_name(), "new_label");
        assert_eq!(cmd.address(), Address::new(0x1000));
    }

    #[test]
    fn test_create_rename_label_cmd_invalid_name() {
        let plugin = RenamePlugin::new();
        let ctx = RenameActionContext::on_label(
            Address::new(0x1000),
            SourceType::Default,
            false,
            false,
        );
        assert!(plugin.create_rename_label_cmd(&ctx, "", SourceType::UserDefined).is_none());
    }

    #[test]
    fn test_create_rename_function_cmd() {
        let plugin = RenamePlugin::new();
        let ctx = RenameActionContext::on_function(
            Address::new(0x1000),
            SourceType::Default,
            false,
        );
        let cmd = plugin.create_rename_function_cmd(&ctx, "main", SourceType::UserDefined);
        assert!(cmd.is_some());
    }

    #[test]
    fn test_create_rename_namespace_cmd() {
        let plugin = RenamePlugin::new();
        let cmd = plugin.create_rename_namespace_cmd(42, "MyClass", SourceType::UserDefined);
        assert!(cmd.is_some());
        let cmd = cmd.unwrap();
        assert_eq!(cmd.namespace_symbol_id(), 42);
        assert_eq!(cmd.new_name(), "MyClass");
    }

    #[test]
    fn test_determine_source_type_user_initiated() {
        let plugin = RenamePlugin::new();
        assert_eq!(
            plugin.determine_source_type(Some(SourceType::Analysis), true),
            SourceType::UserDefined
        );
    }

    #[test]
    fn test_determine_source_type_not_user_initiated() {
        let plugin = RenamePlugin::new();
        assert_eq!(
            plugin.determine_source_type(Some(SourceType::Analysis), false),
            SourceType::Analysis
        );
    }

    #[test]
    fn test_determine_source_type_default() {
        let plugin = RenamePlugin::new();
        assert_eq!(
            plugin.determine_source_type(None, false),
            SourceType::Default
        );
    }

    #[test]
    fn test_rename_action_display_names() {
        assert_eq!(RenameAction::RenameLabel.display_name(), "Rename Label...");
        assert_eq!(RenameAction::RenameFunction.display_name(), "Rename Function...");
        assert_eq!(RenameAction::RenameNamespace.display_name(), "Rename Namespace...");
    }

    #[test]
    fn test_rename_action_key_bindings() {
        assert_eq!(RenameAction::RenameLabel.key_binding(), Some("L"));
        assert_eq!(RenameAction::RenameFunction.key_binding(), Some("L"));
        assert!(RenameAction::RenameNamespace.key_binding().is_none());
        assert!(RenameAction::SetLabelPrimary.key_binding().is_none());
    }

    #[test]
    fn test_empty_context_has_no_actions() {
        let plugin = RenamePlugin::new();
        let ctx = RenameActionContext::empty(Address::new(0x1000));
        let actions = plugin.available_actions(&ctx);
        assert!(actions.is_empty());
    }
}
