//! OperandFieldPlugin -- plugin for managing operand field display and actions.
//!
//! Ported from Ghidra's `OperandFieldFactory` and related plugin code in
//! `ghidra.app.util.viewer.field` and `ghidra.app.plugin.core`.
//!
//! This module provides:
//! - [`OperandFieldPlugin`] -- manages operand field display options, action
//!   registration, and operand field location resolution
//! - [`OperandFieldAction`] -- enum of available operand field actions
//! - [`OperandFieldContext`] -- context for determining action enablement

use super::operand_field_helper::{
    OperandFieldDisplayOptions, OperandFieldHelper, OperandKind, OperandLocationInfo,
    UnderlineChoice,
};
use serde::{Deserialize, Serialize};
use std::fmt;

// ============================================================================
// OperandFieldAction
// ============================================================================

/// Actions available in the operand field context menu.
///
/// Each variant corresponds to an action that can be performed when the
/// cursor is on an operand field in the listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperandFieldAction {
    /// Set an equate on the scalar operand.
    SetEquate,
    /// Remove an equate from the scalar operand.
    RemoveEquate,
    /// Set the label at the operand reference target.
    SetOperandLabel,
    /// Edit the operand representation (e.g., rename parameter).
    EditOperand,
    /// Follow the reference (go to target address).
    FollowReference,
    /// Show all references from this operand.
    ShowReferences,
    /// Copy the operand representation to clipboard.
    CopyOperand,
    /// Toggle the underline display for references.
    ToggleUnderline,
}

impl OperandFieldAction {
    /// Returns the display name for this action.
    pub fn display_name(self) -> &'static str {
        match self {
            OperandFieldAction::SetEquate => "Set Equate...",
            OperandFieldAction::RemoveEquate => "Remove Equate",
            OperandFieldAction::SetOperandLabel => "Set Associated Label...",
            OperandFieldAction::EditOperand => "Edit Operand...",
            OperandFieldAction::FollowReference => "Follow Reference",
            OperandFieldAction::ShowReferences => "Show References",
            OperandFieldAction::CopyOperand => "Copy Operand",
            OperandFieldAction::ToggleUnderline => "Toggle Underline",
        }
    }

    /// Returns the key binding for this action, if any.
    pub fn key_binding(self) -> Option<&'static str> {
        match self {
            OperandFieldAction::SetEquate => Some("E"),
            OperandFieldAction::FollowReference => Some("ENTER"),
            OperandFieldAction::CopyOperand => Some("Ctrl+C"),
            _ => None,
        }
    }
}

impl fmt::Display for OperandFieldAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ============================================================================
// OperandFieldContext
// ============================================================================

/// Context for operand field actions.
///
/// Contains all the information needed to determine which actions are
/// available and how to execute them. This mirrors the relevant parts of
/// Ghidra's `ListingActionContext` when the cursor is on an operand field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperandFieldContext {
    /// The address of the code unit.
    pub address: u64,
    /// The operand index.
    pub operand_index: i32,
    /// The sub-operand index.
    pub sub_operand_index: i32,
    /// The character offset in the operand representation.
    pub character_offset: i32,
    /// Whether this is an instruction (vs data).
    pub is_instruction: bool,
    /// Whether the operand has a scalar value.
    pub has_scalar: bool,
    /// The scalar value (if applicable).
    pub scalar_value: Option<i64>,
    /// The scalar bit length.
    pub scalar_bit_length: Option<usize>,
    /// Whether the operand has a reference.
    pub has_reference: bool,
    /// The reference target address.
    pub ref_target: Option<u64>,
    /// Whether there is an equate at this location.
    pub has_equate: bool,
    /// The equate name (if any).
    pub equate_name: Option<String>,
    /// Whether the operand is on a register.
    pub is_register: bool,
    /// Whether the operand is on a variable reference.
    pub is_variable: bool,
    /// The variable name (if applicable).
    pub variable_name: Option<String>,
    /// Whether there is a selection.
    pub has_selection: bool,
    /// Whether this is an error/unsupported operand.
    pub has_error: bool,
}

impl OperandFieldContext {
    /// Create a minimal context at the given address and operand index.
    pub fn new(address: u64, operand_index: i32) -> Self {
        Self {
            address,
            operand_index,
            sub_operand_index: 0,
            character_offset: 0,
            is_instruction: true,
            has_scalar: false,
            scalar_value: None,
            scalar_bit_length: None,
            has_reference: false,
            ref_target: None,
            has_equate: false,
            equate_name: None,
            is_register: false,
            is_variable: false,
            variable_name: None,
            has_selection: false,
            has_error: false,
        }
    }

    /// Create a context for a scalar operand.
    pub fn scalar(address: u64, operand_index: i32, value: i64, bit_length: usize) -> Self {
        Self {
            address,
            operand_index,
            sub_operand_index: 0,
            character_offset: 0,
            is_instruction: true,
            has_scalar: true,
            scalar_value: Some(value),
            scalar_bit_length: Some(bit_length),
            has_reference: false,
            ref_target: None,
            has_equate: false,
            equate_name: None,
            is_register: false,
            is_variable: false,
            variable_name: None,
            has_selection: false,
            has_error: false,
        }
    }

    /// Create a context for a reference operand.
    pub fn reference(address: u64, operand_index: i32, target: u64) -> Self {
        Self {
            address,
            operand_index,
            sub_operand_index: 0,
            character_offset: 0,
            is_instruction: true,
            has_scalar: false,
            scalar_value: None,
            scalar_bit_length: None,
            has_reference: true,
            ref_target: Some(target),
            has_equate: false,
            equate_name: None,
            is_register: false,
            is_variable: false,
            variable_name: None,
            has_selection: false,
            has_error: false,
        }
    }

    /// Create a context for an equate operand.
    pub fn equate(address: u64, operand_index: i32, equate_name: impl Into<String>, value: i64) -> Self {
        Self {
            address,
            operand_index,
            sub_operand_index: 0,
            character_offset: 0,
            is_instruction: true,
            has_scalar: true,
            scalar_value: Some(value),
            scalar_bit_length: None,
            has_reference: false,
            ref_target: None,
            has_equate: true,
            equate_name: Some(equate_name.into()),
            is_register: false,
            is_variable: false,
            variable_name: None,
            has_selection: false,
            has_error: false,
        }
    }

    /// Create a context for a register operand.
    pub fn register(address: u64, operand_index: i32) -> Self {
        Self {
            address,
            operand_index,
            sub_operand_index: 0,
            character_offset: 0,
            is_instruction: true,
            has_scalar: false,
            scalar_value: None,
            scalar_bit_length: None,
            has_reference: false,
            ref_target: None,
            has_equate: false,
            equate_name: None,
            is_register: true,
            is_variable: false,
            variable_name: None,
            has_selection: false,
            has_error: false,
        }
    }

    /// Create an error/unsupported context.
    pub fn error(address: u64, operand_index: i32) -> Self {
        Self {
            address,
            operand_index,
            sub_operand_index: 0,
            character_offset: 0,
            is_instruction: true,
            has_scalar: false,
            scalar_value: None,
            scalar_bit_length: None,
            has_reference: false,
            ref_target: None,
            has_equate: false,
            equate_name: None,
            is_register: false,
            is_variable: false,
            variable_name: None,
            has_selection: false,
            has_error: true,
        }
    }
}

// ============================================================================
// Action enablement functions
// ============================================================================

/// Returns `true` if the "Set Equate" action should be enabled.
///
/// Mirrors the enablement check: must have a scalar value, must not already
/// have an equate.
pub fn is_set_equate_enabled(ctx: &OperandFieldContext) -> bool {
    ctx.has_scalar && ctx.scalar_value.is_some() && !ctx.has_equate && !ctx.has_error
}

/// Returns `true` if the "Remove Equate" action should be enabled.
pub fn is_remove_equate_enabled(ctx: &OperandFieldContext) -> bool {
    ctx.has_equate && ctx.equate_name.is_some()
}

/// Returns `true` if the "Set Operand Label" action should be enabled.
pub fn is_set_operand_label_enabled(ctx: &OperandFieldContext) -> bool {
    ctx.has_reference && ctx.ref_target.is_some() && !ctx.has_error
}

/// Returns `true` if the "Follow Reference" action should be enabled.
pub fn is_follow_reference_enabled(ctx: &OperandFieldContext) -> bool {
    ctx.has_reference && ctx.ref_target.is_some()
}

/// Returns `true` if the "Edit Operand" action should be enabled.
pub fn is_edit_operand_enabled(ctx: &OperandFieldContext) -> bool {
    ctx.is_instruction && !ctx.has_error && (ctx.is_variable || ctx.has_scalar)
}

/// Returns `true` if the "Copy Operand" action should be enabled.
pub fn is_copy_operand_enabled(ctx: &OperandFieldContext) -> bool {
    !ctx.has_error
}

/// Returns the list of enabled actions for the given context.
pub fn get_enabled_actions(ctx: &OperandFieldContext) -> Vec<OperandFieldAction> {
    let mut actions = Vec::new();

    if is_set_equate_enabled(ctx) {
        actions.push(OperandFieldAction::SetEquate);
    }
    if is_remove_equate_enabled(ctx) {
        actions.push(OperandFieldAction::RemoveEquate);
    }
    if is_set_operand_label_enabled(ctx) {
        actions.push(OperandFieldAction::SetOperandLabel);
    }
    if is_follow_reference_enabled(ctx) {
        actions.push(OperandFieldAction::FollowReference);
    }
    if is_edit_operand_enabled(ctx) {
        actions.push(OperandFieldAction::EditOperand);
    }
    if is_copy_operand_enabled(ctx) {
        actions.push(OperandFieldAction::CopyOperand);
    }
    if ctx.has_reference {
        actions.push(OperandFieldAction::ShowReferences);
    }
    actions.push(OperandFieldAction::ToggleUnderline);

    actions
}

// ============================================================================
// OperandFieldPlugin
// ============================================================================

/// The operand field plugin.
///
/// Manages operand field display options, action registration, and operand
/// field location resolution. This is the Rust equivalent of Ghidra's
/// `OperandFieldFactory` plus the plugin-side action management.
///
/// # Architecture
///
/// - `OperandFieldPlugin` owns an `OperandFieldHelper` for display options
/// - `perform_*` methods are the callbacks for each action type
/// - `is_*_enabled` methods delegate to the free functions above
/// - `resolve_location` translates click positions to `OperandLocationInfo`
///
/// # Example
///
/// ```
/// use ghidra_features::base::operandfield::OperandFieldPlugin;
/// use ghidra_features::base::operandfield::OperandFieldContext;
///
/// let mut plugin = OperandFieldPlugin::new("OperandFieldPlugin");
///
/// // Check if set-equate is enabled for a scalar operand
/// let ctx = OperandFieldContext::scalar(0x1000, 0, 0xFF, 8);
/// assert!(plugin.is_set_equate_enabled(&ctx));
/// ```
#[derive(Debug, Clone)]
pub struct OperandFieldPlugin {
    /// The plugin name.
    name: String,
    /// The display helper.
    helper: OperandFieldHelper,
    /// Action history for debugging/testing.
    history: Vec<String>,
    /// Last status message.
    last_status: Option<String>,
}

impl OperandFieldPlugin {
    /// Create a new operand field plugin.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            helper: OperandFieldHelper::new(),
            history: Vec::new(),
            last_status: None,
        }
    }

    /// Create a plugin with custom display options.
    pub fn with_options(name: impl Into<String>, options: OperandFieldDisplayOptions) -> Self {
        Self {
            name: name.into(),
            helper: OperandFieldHelper::with_options(options),
            history: Vec::new(),
            last_status: None,
        }
    }

    /// Returns the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns a reference to the display helper.
    pub fn helper(&self) -> &OperandFieldHelper {
        &self.helper
    }

    /// Returns a mutable reference to the display helper.
    pub fn helper_mut(&mut self) -> &mut OperandFieldHelper {
        &mut self.helper
    }

    /// Returns a reference to the display options.
    pub fn options(&self) -> &OperandFieldDisplayOptions {
        &self.helper.options
    }

    /// Returns a mutable reference to the display options.
    pub fn options_mut(&mut self) -> &mut OperandFieldDisplayOptions {
        &mut self.helper.options
    }

    /// Returns the action history.
    pub fn history(&self) -> &[String] {
        &self.history
    }

    /// Returns the last status message.
    pub fn status(&self) -> Option<&str> {
        self.last_status.as_deref()
    }

    /// Set the status message.
    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.last_status = Some(msg.into());
    }

    /// Clear the status message.
    pub fn clear_status(&mut self) {
        self.last_status = None;
    }

    // -- Action enablement --

    /// Returns `true` if the "Set Equate" action should be enabled.
    pub fn is_set_equate_enabled(&self, ctx: &OperandFieldContext) -> bool {
        is_set_equate_enabled(ctx)
    }

    /// Returns `true` if the "Remove Equate" action should be enabled.
    pub fn is_remove_equate_enabled(&self, ctx: &OperandFieldContext) -> bool {
        is_remove_equate_enabled(ctx)
    }

    /// Returns `true` if the "Set Operand Label" action should be enabled.
    pub fn is_set_operand_label_enabled(&self, ctx: &OperandFieldContext) -> bool {
        is_set_operand_label_enabled(ctx)
    }

    /// Returns `true` if the "Follow Reference" action should be enabled.
    pub fn is_follow_reference_enabled(&self, ctx: &OperandFieldContext) -> bool {
        is_follow_reference_enabled(ctx)
    }

    /// Returns the list of enabled actions for the given context.
    pub fn get_enabled_actions(&self, ctx: &OperandFieldContext) -> Vec<OperandFieldAction> {
        get_enabled_actions(ctx)
    }

    // -- Action callbacks --

    /// Execute the "Set Equate" action.
    ///
    /// Mirrors `EquatePlugin.setEquate()` when triggered from the operand
    /// field context menu.
    pub fn set_equate(
        &mut self,
        ctx: &OperandFieldContext,
        equate_name: &str,
    ) -> Result<(), String> {
        if !is_set_equate_enabled(ctx) {
            return Err("Set Equate not enabled for this context".to_string());
        }
        self.history.push(format!(
            "Set Equate '{}' at 0x{:x}[{}]",
            equate_name, ctx.address, ctx.operand_index
        ));
        Ok(())
    }

    /// Execute the "Remove Equate" action.
    pub fn remove_equate(&mut self, ctx: &OperandFieldContext) -> Result<(), String> {
        if !is_remove_equate_enabled(ctx) {
            return Err("Remove Equate not enabled for this context".to_string());
        }
        self.history.push(format!(
            "Remove Equate at 0x{:x}[{}]",
            ctx.address, ctx.operand_index
        ));
        Ok(())
    }

    /// Execute the "Set Operand Label" action.
    pub fn set_operand_label(
        &mut self,
        ctx: &OperandFieldContext,
        label_name: &str,
    ) -> Result<(), String> {
        if !is_set_operand_label_enabled(ctx) {
            return Err("Set Operand Label not enabled for this context".to_string());
        }
        self.history.push(format!(
            "Set Operand Label '{}' at 0x{:x}[{}] -> 0x{:x}",
            label_name,
            ctx.address,
            ctx.operand_index,
            ctx.ref_target.unwrap_or(0)
        ));
        Ok(())
    }

    /// Execute the "Follow Reference" action.
    ///
    /// Returns the target address to navigate to.
    pub fn follow_reference(&mut self, ctx: &OperandFieldContext) -> Result<u64, String> {
        if !is_follow_reference_enabled(ctx) {
            return Err("Follow Reference not enabled for this context".to_string());
        }
        let target = ctx.ref_target.unwrap();
        self.history.push(format!(
            "Follow Reference at 0x{:x}[{}] -> 0x{:x}",
            ctx.address, ctx.operand_index, target
        ));
        Ok(target)
    }

    /// Execute the "Edit Operand" action.
    pub fn edit_operand(
        &mut self,
        ctx: &OperandFieldContext,
        new_value: &str,
    ) -> Result<(), String> {
        if !is_edit_operand_enabled(ctx) {
            return Err("Edit Operand not enabled for this context".to_string());
        }
        self.history.push(format!(
            "Edit Operand '{}' at 0x{:x}[{}]",
            new_value, ctx.address, ctx.operand_index
        ));
        Ok(())
    }

    /// Execute the "Copy Operand" action.
    ///
    /// Returns the operand representation string to copy.
    pub fn copy_operand(&mut self, ctx: &OperandFieldContext, rep_string: &str) -> Result<String, String> {
        if !is_copy_operand_enabled(ctx) {
            return Err("Copy Operand not enabled for this context".to_string());
        }
        self.history.push(format!(
            "Copy Operand at 0x{:x}[{}]",
            ctx.address, ctx.operand_index
        ));
        Ok(rep_string.to_string())
    }

    /// Toggle the underline display for references.
    pub fn toggle_underline(&mut self) {
        self.helper.options.underline_choice = match self.helper.options.underline_choice {
            UnderlineChoice::Hidden => UnderlineChoice::All,
            UnderlineChoice::All => UnderlineChoice::None,
            UnderlineChoice::None => UnderlineChoice::Hidden,
        };
        self.history.push(format!(
            "Toggle Underline -> {}",
            self.helper.options.underline_choice
        ));
    }

    // -- Location resolution --

    /// Resolve a click position to an `OperandLocationInfo`.
    ///
    /// This mirrors the logic in `OperandFieldHelper.getProgramLocation()`
    /// which translates a (row, col) click in the operand field to a
    /// `ProgramLocation`.
    pub fn resolve_location(
        &self,
        address: u64,
        operand_index: i32,
        sub_operand_index: i32,
        character_offset: i32,
        rep_string: &str,
        ref_address: Option<u64>,
        is_instruction: bool,
    ) -> OperandLocationInfo {
        OperandLocationInfo {
            address,
            operand_index,
            sub_operand_index,
            character_offset,
            ref_address,
            rep_string: rep_string.to_string(),
            equate_name: None,
            equate_value: None,
            is_instruction,
            variable_name: None,
        }
    }

    /// Resolve a location for an equate operand.
    pub fn resolve_equate_location(
        &self,
        address: u64,
        operand_index: i32,
        sub_operand_index: i32,
        character_offset: i32,
        equate_name: &str,
        equate_value: i64,
        ref_address: Option<u64>,
    ) -> OperandLocationInfo {
        OperandLocationInfo {
            address,
            operand_index,
            sub_operand_index,
            character_offset,
            ref_address,
            rep_string: equate_name.to_string(),
            equate_name: Some(equate_name.to_string()),
            equate_value: Some(equate_value),
            is_instruction: false,
            variable_name: None,
        }
    }

    /// Update display options by name.
    pub fn set_option(&mut self, name: &str, value: &str) -> bool {
        self.helper.set_option(name, value)
    }

    /// Update display options from a full options struct.
    pub fn update_options(&mut self, options: OperandFieldDisplayOptions) {
        self.helper.update_options(options);
    }

    /// Returns `true` if the helper is enabled.
    pub fn is_enabled(&self) -> bool {
        self.helper.is_enabled()
    }

    /// Set the helper enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.helper.set_enabled(enabled);
    }

    // -- Operand classification --

    /// Classify an operand element by its kind.
    pub fn classify_operand_element(
        &self,
        element_text: &str,
        is_register: bool,
        is_scalar: bool,
        is_address: bool,
        is_separator: bool,
        is_equate: bool,
        is_variable: bool,
        is_label: bool,
        is_bad_ref: bool,
        is_external: bool,
    ) -> OperandKind {
        self.helper.classify_operand_element(
            element_text,
            is_register,
            is_scalar,
            is_address,
            is_separator,
            is_equate,
            is_variable,
            is_label,
            is_bad_ref,
            is_external,
        )
    }

    /// Format a separator with optional trailing space.
    pub fn format_separator(&self, separator: &str) -> String {
        self.helper.format_separator(separator)
    }

    /// Check if operands should be underlined.
    pub fn is_underlined(
        &self,
        has_references: bool,
        has_non_primary: bool,
        primary_hidden: bool,
    ) -> bool {
        self.helper.is_underlined(has_references, has_non_primary, primary_hidden)
    }

    /// Check if word wrapping should be applied.
    pub fn should_word_wrap(&self, has_error: bool, is_string: bool, is_enum: bool) -> bool {
        self.helper.should_word_wrap(has_error, is_string, is_enum)
    }
}

impl Default for OperandFieldPlugin {
    fn default() -> Self {
        Self::new("OperandFieldPlugin")
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> u64 {
        offset
    }

    // -- OperandFieldAction --

    #[test]
    fn test_action_display_name() {
        assert_eq!(OperandFieldAction::SetEquate.display_name(), "Set Equate...");
        assert_eq!(OperandFieldAction::FollowReference.display_name(), "Follow Reference");
        assert_eq!(OperandFieldAction::CopyOperand.display_name(), "Copy Operand");
    }

    #[test]
    fn test_action_key_binding() {
        assert_eq!(OperandFieldAction::SetEquate.key_binding(), Some("E"));
        assert_eq!(OperandFieldAction::FollowReference.key_binding(), Some("ENTER"));
        assert_eq!(OperandFieldAction::ShowReferences.key_binding(), None);
    }

    #[test]
    fn test_action_display() {
        assert_eq!(format!("{}", OperandFieldAction::SetEquate), "Set Equate...");
    }

    // -- OperandFieldContext --

    #[test]
    fn test_context_new() {
        let ctx = OperandFieldContext::new(addr(0x1000), 0);
        assert_eq!(ctx.address, 0x1000);
        assert_eq!(ctx.operand_index, 0);
        assert!(!ctx.has_scalar);
        assert!(!ctx.has_reference);
        assert!(!ctx.has_equate);
        assert!(!ctx.has_error);
    }

    #[test]
    fn test_context_scalar() {
        let ctx = OperandFieldContext::scalar(addr(0x1000), 0, 0xFF, 8);
        assert!(ctx.has_scalar);
        assert_eq!(ctx.scalar_value, Some(0xFF));
        assert_eq!(ctx.scalar_bit_length, Some(8));
    }

    #[test]
    fn test_context_reference() {
        let ctx = OperandFieldContext::reference(addr(0x1000), 0, addr(0x2000));
        assert!(ctx.has_reference);
        assert_eq!(ctx.ref_target, Some(0x2000));
    }

    #[test]
    fn test_context_equate() {
        let ctx = OperandFieldContext::equate(addr(0x1000), 0, "MY_CONST", 42);
        assert!(ctx.has_equate);
        assert_eq!(ctx.equate_name.as_deref(), Some("MY_CONST"));
        assert_eq!(ctx.scalar_value, Some(42));
    }

    #[test]
    fn test_context_register() {
        let ctx = OperandFieldContext::register(addr(0x1000), 0);
        assert!(ctx.is_register);
        assert!(!ctx.has_scalar);
    }

    #[test]
    fn test_context_error() {
        let ctx = OperandFieldContext::error(addr(0x1000), 0);
        assert!(ctx.has_error);
    }

    // -- Action enablement --

    #[test]
    fn test_set_equate_enabled() {
        let ctx = OperandFieldContext::scalar(addr(0x1000), 0, 0xFF, 8);
        assert!(is_set_equate_enabled(&ctx));
    }

    #[test]
    fn test_set_equate_disabled_no_scalar() {
        let ctx = OperandFieldContext::new(addr(0x1000), 0);
        assert!(!is_set_equate_enabled(&ctx));
    }

    #[test]
    fn test_set_equate_disabled_has_equate() {
        let ctx = OperandFieldContext::equate(addr(0x1000), 0, "X", 42);
        assert!(!is_set_equate_enabled(&ctx));
    }

    #[test]
    fn test_set_equate_disabled_error() {
        let mut ctx = OperandFieldContext::scalar(addr(0x1000), 0, 0xFF, 8);
        ctx.has_error = true;
        assert!(!is_set_equate_enabled(&ctx));
    }

    #[test]
    fn test_remove_equate_enabled() {
        let ctx = OperandFieldContext::equate(addr(0x1000), 0, "X", 42);
        assert!(is_remove_equate_enabled(&ctx));
    }

    #[test]
    fn test_remove_equate_disabled() {
        let ctx = OperandFieldContext::scalar(addr(0x1000), 0, 42, 32);
        assert!(!is_remove_equate_enabled(&ctx));
    }

    #[test]
    fn test_set_operand_label_enabled() {
        let ctx = OperandFieldContext::reference(addr(0x1000), 0, addr(0x2000));
        assert!(is_set_operand_label_enabled(&ctx));
    }

    #[test]
    fn test_set_operand_label_disabled_no_ref() {
        let ctx = OperandFieldContext::new(addr(0x1000), 0);
        assert!(!is_set_operand_label_enabled(&ctx));
    }

    #[test]
    fn test_follow_reference_enabled() {
        let ctx = OperandFieldContext::reference(addr(0x1000), 0, addr(0x2000));
        assert!(is_follow_reference_enabled(&ctx));
    }

    #[test]
    fn test_follow_reference_disabled() {
        let ctx = OperandFieldContext::new(addr(0x1000), 0);
        assert!(!is_follow_reference_enabled(&ctx));
    }

    #[test]
    fn test_edit_operand_enabled_scalar() {
        let ctx = OperandFieldContext::scalar(addr(0x1000), 0, 0xFF, 8);
        assert!(is_edit_operand_enabled(&ctx));
    }

    #[test]
    fn test_edit_operand_enabled_variable() {
        let mut ctx = OperandFieldContext::new(addr(0x1000), 0);
        ctx.is_variable = true;
        assert!(is_edit_operand_enabled(&ctx));
    }

    #[test]
    fn test_edit_operand_disabled_error() {
        let ctx = OperandFieldContext::error(addr(0x1000), 0);
        assert!(!is_edit_operand_enabled(&ctx));
    }

    #[test]
    fn test_copy_operand_enabled() {
        let ctx = OperandFieldContext::new(addr(0x1000), 0);
        assert!(is_copy_operand_enabled(&ctx));
    }

    #[test]
    fn test_copy_operand_disabled_error() {
        let ctx = OperandFieldContext::error(addr(0x1000), 0);
        assert!(!is_copy_operand_enabled(&ctx));
    }

    #[test]
    fn test_get_enabled_actions_scalar() {
        let ctx = OperandFieldContext::scalar(addr(0x1000), 0, 0xFF, 8);
        let actions = get_enabled_actions(&ctx);
        assert!(actions.contains(&OperandFieldAction::SetEquate));
        assert!(actions.contains(&OperandFieldAction::EditOperand));
        assert!(actions.contains(&OperandFieldAction::CopyOperand));
        assert!(actions.contains(&OperandFieldAction::ToggleUnderline));
        assert!(!actions.contains(&OperandFieldAction::RemoveEquate));
    }

    #[test]
    fn test_get_enabled_actions_equate() {
        let ctx = OperandFieldContext::equate(addr(0x1000), 0, "X", 42);
        let actions = get_enabled_actions(&ctx);
        assert!(actions.contains(&OperandFieldAction::RemoveEquate));
        assert!(!actions.contains(&OperandFieldAction::SetEquate));
    }

    #[test]
    fn test_get_enabled_actions_reference() {
        let ctx = OperandFieldContext::reference(addr(0x1000), 0, addr(0x2000));
        let actions = get_enabled_actions(&ctx);
        assert!(actions.contains(&OperandFieldAction::FollowReference));
        assert!(actions.contains(&OperandFieldAction::SetOperandLabel));
        assert!(actions.contains(&OperandFieldAction::ShowReferences));
    }

    #[test]
    fn test_get_enabled_actions_error() {
        let ctx = OperandFieldContext::error(addr(0x1000), 0);
        let actions = get_enabled_actions(&ctx);
        assert!(!actions.contains(&OperandFieldAction::SetEquate));
        assert!(!actions.contains(&OperandFieldAction::FollowReference));
        assert!(!actions.contains(&OperandFieldAction::CopyOperand));
        assert!(actions.contains(&OperandFieldAction::ToggleUnderline));
    }

    // -- OperandFieldPlugin --

    #[test]
    fn test_plugin_new() {
        let plugin = OperandFieldPlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert!(plugin.is_enabled());
        assert!(plugin.history().is_empty());
    }

    #[test]
    fn test_plugin_default() {
        let plugin = OperandFieldPlugin::default();
        assert_eq!(plugin.name(), "OperandFieldPlugin");
    }

    #[test]
    fn test_plugin_with_options() {
        let mut opts = OperandFieldDisplayOptions::default();
        opts.word_wrap = true;
        opts.max_display_lines = 5;
        let plugin = OperandFieldPlugin::with_options("Test", opts);
        assert!(plugin.options().word_wrap);
        assert_eq!(plugin.options().max_display_lines, 5);
    }

    #[test]
    fn test_plugin_set_equate() {
        let mut plugin = OperandFieldPlugin::new("Test");
        let ctx = OperandFieldContext::scalar(addr(0x1000), 0, 0xFF, 8);
        assert!(plugin.set_equate(&ctx, "BYTE_MAX").is_ok());
        assert_eq!(plugin.history().len(), 1);
        assert!(plugin.history()[0].contains("BYTE_MAX"));
    }

    #[test]
    fn test_plugin_set_equate_disabled() {
        let mut plugin = OperandFieldPlugin::new("Test");
        let ctx = OperandFieldContext::new(addr(0x1000), 0);
        assert!(plugin.set_equate(&ctx, "X").is_err());
    }

    #[test]
    fn test_plugin_remove_equate() {
        let mut plugin = OperandFieldPlugin::new("Test");
        let ctx = OperandFieldContext::equate(addr(0x1000), 0, "X", 42);
        assert!(plugin.remove_equate(&ctx).is_ok());
        assert_eq!(plugin.history().len(), 1);
    }

    #[test]
    fn test_plugin_remove_equate_disabled() {
        let mut plugin = OperandFieldPlugin::new("Test");
        let ctx = OperandFieldContext::scalar(addr(0x1000), 0, 42, 32);
        assert!(plugin.remove_equate(&ctx).is_err());
    }

    #[test]
    fn test_plugin_set_operand_label() {
        let mut plugin = OperandFieldPlugin::new("Test");
        let ctx = OperandFieldContext::reference(addr(0x1000), 0, addr(0x2000));
        assert!(plugin.set_operand_label(&ctx, "my_label").is_ok());
        assert!(plugin.history()[0].contains("my_label"));
        assert!(plugin.history()[0].contains("2000"));
    }

    #[test]
    fn test_plugin_follow_reference() {
        let mut plugin = OperandFieldPlugin::new("Test");
        let ctx = OperandFieldContext::reference(addr(0x1000), 0, addr(0x2000));
        let target = plugin.follow_reference(&ctx).unwrap();
        assert_eq!(target, 0x2000);
    }

    #[test]
    fn test_plugin_follow_reference_disabled() {
        let mut plugin = OperandFieldPlugin::new("Test");
        let ctx = OperandFieldContext::new(addr(0x1000), 0);
        assert!(plugin.follow_reference(&ctx).is_err());
    }

    #[test]
    fn test_plugin_edit_operand() {
        let mut plugin = OperandFieldPlugin::new("Test");
        let ctx = OperandFieldContext::scalar(addr(0x1000), 0, 0xFF, 8);
        assert!(plugin.edit_operand(&ctx, "0x42").is_ok());
        assert!(plugin.history()[0].contains("0x42"));
    }

    #[test]
    fn test_plugin_copy_operand() {
        let mut plugin = OperandFieldPlugin::new("Test");
        let ctx = OperandFieldContext::new(addr(0x1000), 0);
        let result = plugin.copy_operand(&ctx, "EAX, EBX").unwrap();
        assert_eq!(result, "EAX, EBX");
    }

    #[test]
    fn test_plugin_toggle_underline() {
        let mut plugin = OperandFieldPlugin::new("Test");
        assert_eq!(plugin.options().underline_choice, UnderlineChoice::Hidden);

        plugin.toggle_underline();
        assert_eq!(plugin.options().underline_choice, UnderlineChoice::All);

        plugin.toggle_underline();
        assert_eq!(plugin.options().underline_choice, UnderlineChoice::None);

        plugin.toggle_underline();
        assert_eq!(plugin.options().underline_choice, UnderlineChoice::Hidden);
    }

    #[test]
    fn test_plugin_resolve_location() {
        let plugin = OperandFieldPlugin::new("Test");
        let loc = plugin.resolve_location(0x1000, 0, 1, 5, "EAX", Some(0x2000), true);
        assert_eq!(loc.address, 0x1000);
        assert_eq!(loc.operand_index, 0);
        assert_eq!(loc.sub_operand_index, 1);
        assert_eq!(loc.character_offset, 5);
        assert_eq!(loc.ref_address, Some(0x2000));
        assert!(loc.is_instruction);
    }

    #[test]
    fn test_plugin_resolve_equate_location() {
        let plugin = OperandFieldPlugin::new("Test");
        let loc = plugin.resolve_equate_location(0x1000, 0, 0, 3, "MY_CONST", 0xFF, None);
        assert_eq!(loc.equate_name.as_deref(), Some("MY_CONST"));
        assert_eq!(loc.equate_value, Some(0xFF));
    }

    #[test]
    fn test_plugin_status() {
        let mut plugin = OperandFieldPlugin::new("Test");
        assert!(plugin.status().is_none());

        plugin.set_status("Test status");
        assert_eq!(plugin.status(), Some("Test status"));

        plugin.clear_status();
        assert!(plugin.status().is_none());
    }

    #[test]
    fn test_plugin_set_option() {
        let mut plugin = OperandFieldPlugin::new("Test");
        assert!(plugin.set_option("word_wrap", "true"));
        assert!(plugin.options().word_wrap);
    }

    #[test]
    fn test_plugin_update_options() {
        let mut plugin = OperandFieldPlugin::new("Test");
        let mut opts = OperandFieldDisplayOptions::default();
        opts.word_wrap = true;
        opts.space_after_separator = true;
        plugin.update_options(opts);
        assert!(plugin.options().word_wrap);
        assert!(plugin.options().space_after_separator);
    }

    #[test]
    fn test_plugin_enabled() {
        let mut plugin = OperandFieldPlugin::new("Test");
        assert!(plugin.is_enabled());
        plugin.set_enabled(false);
        assert!(!plugin.is_enabled());
    }

    #[test]
    fn test_plugin_classify_operand() {
        let plugin = OperandFieldPlugin::new("Test");
        let kind = plugin.classify_operand_element("EAX", true, false, false, false, false, false, false, false, false);
        assert_eq!(kind, OperandKind::Register);
    }

    #[test]
    fn test_plugin_format_separator() {
        let mut plugin = OperandFieldPlugin::new("Test");
        assert_eq!(plugin.format_separator(","), ",");

        plugin.options_mut().space_after_separator = true;
        assert_eq!(plugin.format_separator(","), ", ");
    }

    #[test]
    fn test_plugin_is_underlined() {
        let mut plugin = OperandFieldPlugin::new("Test");
        assert!(!plugin.is_underlined(true, false, false));

        plugin.options_mut().underline_choice = UnderlineChoice::All;
        assert!(plugin.is_underlined(true, false, false));
    }

    #[test]
    fn test_plugin_should_word_wrap() {
        let mut plugin = OperandFieldPlugin::new("Test");
        assert!(!plugin.should_word_wrap(false, true, false));

        plugin.options_mut().word_wrap = true;
        assert!(plugin.should_word_wrap(false, true, false));
    }

    #[test]
    fn test_plugin_full_workflow() {
        let mut plugin = OperandFieldPlugin::new("Test");

        // Create a scalar context
        let ctx = OperandFieldContext::scalar(addr(0x1000), 0, 0xFF, 8);

        // Set equate
        assert!(plugin.set_equate(&ctx, "BYTE_MAX").is_ok());

        // Now the equate is set -- create an equate context
        let ctx = OperandFieldContext::equate(addr(0x1000), 0, "BYTE_MAX", 0xFF);

        // Remove equate
        assert!(plugin.remove_equate(&ctx).is_ok());

        // Check history
        assert_eq!(plugin.history().len(), 2);
        assert!(plugin.history()[0].contains("Set Equate"));
        assert!(plugin.history()[1].contains("Remove Equate"));
    }

    #[test]
    fn test_plugin_reference_workflow() {
        let mut plugin = OperandFieldPlugin::new("Test");

        // Create a reference context
        let ctx = OperandFieldContext::reference(addr(0x1000), 0, addr(0x400000));

        // Set label at target
        assert!(plugin.set_operand_label(&ctx, "main_entry").is_ok());

        // Follow reference
        let target = plugin.follow_reference(&ctx).unwrap();
        assert_eq!(target, 0x400000);

        // Check enabled actions
        let actions = plugin.get_enabled_actions(&ctx);
        assert!(actions.contains(&OperandFieldAction::FollowReference));
        assert!(actions.contains(&OperandFieldAction::SetOperandLabel));
        assert!(actions.contains(&OperandFieldAction::ShowReferences));
    }
}
