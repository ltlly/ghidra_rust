//! Equate listing-context actions -- convert, set, rename, remove equates.
//!
//! Ported from the action classes in `ghidra.app.plugin.core.equate`:
//!
//! - [`ConvertAction`] and [`ConvertActionKind`] -- the 9 `ConvertTo*Action` classes
//!   (unsigned hex, signed hex, unsigned decimal, signed decimal, octal, binary,
//!   char, float, double) unified under a single enum-dispatched struct
//! - [`SetEquateAction`] -- the "Set Equate..." context action from `EquatePlugin`
//! - [`RenameEquateAction`] -- the "Rename Equate..." context action
//! - [`RemoveEquateAction`] -- the "Remove Equate" context action
//! - [`ApplyEnumAction`] -- the "Apply Enum..." context action
//!
//! Each action struct carries a [`ConvertActionKind`] (for convert actions) or
//! configuration data (for set/rename/remove), and exposes:
//! - `name()` -- the action's display name
//! - `is_enabled(context)` -- whether the action is available in a given context
//! - `execute(context)` -- perform the action (returns a boxed [`Command`])

use super::commands::{Command, ConvertCommand, CreateEquateCmd, CreateEnumEquateCommand,
                      RemoveEquateCmd, RenameEquateCmd, RenameEquatesCmd};
use super::format::{format_scalar, menu_label, FormatChoice};
#[cfg(test)]
use super::manager::EquateTable;
use super::Scalar;
use ghidra_core::Address;
use std::collections::HashSet;

// ============================================================================
// Listing action context
// ============================================================================

/// Minimal context for a listing action, analogous to `ListingActionContext` in Java.
///
/// This carries the address, operand/sub-operand indices, whether there is a
/// selection, the scalar at the cursor, and whether the code unit is data.
#[derive(Debug, Clone)]
pub struct ListingActionContext {
    /// Current address.
    pub address: Address,
    /// Operand index at the cursor.
    pub op_index: i32,
    /// Sub-operand index at the cursor.
    pub sub_op_index: i32,
    /// Whether there is an active selection.
    pub has_selection: bool,
    /// Selected address set (start, end) pairs.
    pub selection: Vec<(Address, Address)>,
    /// The scalar at the cursor, if any.
    pub scalar: Option<Scalar>,
    /// Whether the code unit at the cursor is a Data item (vs Instruction).
    pub is_data: bool,
    /// Whether the data is a defined integer data type.
    pub is_defined_integer_data: bool,
    /// Whether the data is within an array or composite (unsupported for equates).
    pub is_in_composite_or_array: bool,
    /// The code unit's byte length (for progress monitoring).
    pub code_unit_length: u32,
    /// Locations to process: (address, op_index, scalar_value) triples.
    /// Pre-populated for selection-based operations.
    pub locations: Vec<(Address, i32, i64)>,
    /// The equate currently at the cursor location, if any.
    pub current_equate_name: Option<String>,
}

impl ListingActionContext {
    /// Create a minimal context for a single address with a scalar.
    pub fn with_scalar(address: Address, op_index: i32, scalar: Scalar) -> Self {
        Self {
            address,
            op_index,
            sub_op_index: 0,
            has_selection: false,
            selection: Vec::new(),
            scalar: Some(scalar),
            is_data: false,
            is_defined_integer_data: false,
            is_in_composite_or_array: false,
            code_unit_length: 1,
            locations: vec![(address, op_index, scalar.value())],
            current_equate_name: None,
        }
    }

    /// The scalar value at the cursor, if present.
    pub fn get_scalar(&self) -> Option<&Scalar> {
        self.scalar.as_ref()
    }

    /// Check whether an equate context action is permitted.
    ///
    /// Matches the Java `EquatePlugin.isEquatePermitted()` logic:
    /// 1. A scalar must be present.
    /// 2. If data, it must be defined integer data (not composite/array).
    /// 3. If an equate exists at this location, its value must differ from the scalar.
    pub fn is_equate_permitted(&self) -> bool {
        let scalar = match &self.scalar {
            Some(s) => s,
            None => return false,
        };

        if self.is_data && !self.is_defined_integer_data {
            return false;
        }

        if self.is_in_composite_or_array {
            return false;
        }

        // If an equate already exists with the same value, it's not "permitted" to set again.
        if self.current_equate_name.is_some()
            && self
                .locations
                .iter()
                .any(|(_, _, v)| *v == scalar.value())
        {
            return false;
        }

        true
    }
}

// ============================================================================
// ConvertActionKind -- the 9 convert-to-* formats
// ============================================================================

/// The kind of convert action, corresponding to the 9 `ConvertTo*Action` classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConvertActionKind {
    /// `ConvertToUnsignedHexAction` -- unsigned hex representation.
    UnsignedHex,
    /// `ConvertToSignedHexAction` -- signed hex representation.
    SignedHex,
    /// `ConvertToUnsignedDecimalAction` -- unsigned decimal.
    UnsignedDecimal,
    /// `ConvertToSignedDecimalAction` -- signed decimal.
    SignedDecimal,
    /// `ConvertToOctalAction` -- unsigned octal.
    Octal,
    /// `ConvertToBinaryAction` -- unsigned binary.
    Binary,
    /// `ConvertToCharAction` -- character representation.
    Char,
    /// `ConvertToFloatAction` -- 32-bit IEEE 754 float (instructions only).
    Float,
    /// `ConvertToDoubleAction` -- 64-bit IEEE 754 double (instructions only).
    Double,
}

impl ConvertActionKind {
    /// All convert action kinds in menu order.
    pub const ALL: [ConvertActionKind; 9] = [
        ConvertActionKind::UnsignedHex,
        ConvertActionKind::SignedHex,
        ConvertActionKind::UnsignedDecimal,
        ConvertActionKind::SignedDecimal,
        ConvertActionKind::Octal,
        ConvertActionKind::Binary,
        ConvertActionKind::Char,
        ConvertActionKind::Float,
        ConvertActionKind::Double,
    ];

    /// The corresponding [`FormatChoice`].
    pub fn format_choice(self) -> FormatChoice {
        match self {
            ConvertActionKind::UnsignedHex => FormatChoice::Hex,
            ConvertActionKind::SignedHex => FormatChoice::SignedHex,
            ConvertActionKind::UnsignedDecimal => FormatChoice::UnsignedDecimal,
            ConvertActionKind::SignedDecimal => FormatChoice::SignedDecimal,
            ConvertActionKind::Octal => FormatChoice::Octal,
            ConvertActionKind::Binary => FormatChoice::Binary,
            ConvertActionKind::Char => FormatChoice::Char,
            ConvertActionKind::Float => FormatChoice::Float,
            ConvertActionKind::Double => FormatChoice::Double,
        }
    }

    /// Whether this action is signed.
    pub fn is_signed(self) -> bool {
        matches!(
            self,
            ConvertActionKind::SignedHex | ConvertActionKind::SignedDecimal
        )
    }

    /// The human-readable action name (matches Java class names).
    pub fn action_name(self) -> &'static str {
        match self {
            ConvertActionKind::UnsignedHex => "Convert To Unsigned Hex",
            ConvertActionKind::SignedHex => "Convert To Signed Hex",
            ConvertActionKind::UnsignedDecimal => "Convert To Unsigned Decimal",
            ConvertActionKind::SignedDecimal => "Convert To Signed Decimal",
            ConvertActionKind::Octal => "Convert To Unsigned Octal",
            ConvertActionKind::Binary => "Convert To Unsigned Binary",
            ConvertActionKind::Char => "Convert To Char",
            ConvertActionKind::Float => "Convert To Float",
            ConvertActionKind::Double => "Convert To Double",
        }
    }

    /// Whether this action is supported on data items.
    pub fn is_supported_on_data(self) -> bool {
        self.format_choice().is_supported_on_data()
    }

    /// The `FormatSettingsDefinition` format id for data items.
    /// Returns `-1` if unsupported for data.
    pub fn format_id(self) -> i32 {
        self.format_choice().format_id()
    }
}

// ============================================================================
// ConvertAction -- unified convert action struct
// ============================================================================

/// A convert action that formats a scalar value at a listing location.
///
/// Corresponds to the `AbstractConvertAction` / `ConvertTo*Action` hierarchy
/// in Java. A single struct is used with a [`ConvertActionKind`] discriminant.
#[derive(Debug, Clone)]
pub struct ConvertAction {
    /// The kind of conversion.
    pub kind: ConvertActionKind,
    /// The menu group name.
    group_name: String,
}

impl ConvertAction {
    /// Create a new convert action.
    pub fn new(kind: ConvertActionKind) -> Self {
        Self {
            kind,
            group_name: "Convert".to_string(),
        }
    }

    /// Create all 9 convert actions in menu order.
    pub fn all() -> Vec<ConvertAction> {
        ConvertActionKind::ALL
            .iter()
            .map(|&kind| ConvertAction::new(kind))
            .collect()
    }

    /// The action name.
    pub fn name(&self) -> &str {
        self.kind.action_name()
    }

    /// The menu group.
    pub fn group(&self) -> &str {
        &self.group_name
    }

    /// The `ConvertActionKind`.
    pub fn kind(&self) -> ConvertActionKind {
        self.kind
    }

    /// The corresponding `FormatChoice`.
    pub fn format_choice(&self) -> FormatChoice {
        self.kind.format_choice()
    }

    /// Whether this action is signed.
    pub fn is_signed(&self) -> bool {
        self.kind.is_signed()
    }

    /// Check whether this action is enabled for the given context.
    ///
    /// Mirrors `AbstractConvertAction.isEnabledForContext()`:
    /// 1. A scalar must be present.
    /// 2. Signed actions are disabled for non-negative scalars.
    /// 3. On data items, the format must be supported on data and the data
    ///    must be defined with an integer data type.
    /// 4. A valid menu name must be produced.
    pub fn is_enabled(&self, ctx: &ListingActionContext) -> bool {
        let scalar = match ctx.get_scalar() {
            Some(s) => s,
            None => return false,
        };

        // Signed actions are disabled for non-negative scalars.
        if self.is_signed() && scalar.signed_value() >= 0 {
            return false;
        }

        // On data items, check data type constraints.
        if ctx.is_data {
            if !self.kind.is_supported_on_data() {
                return false;
            }
            if !ctx.is_defined_integer_data {
                return false;
            }
        }

        // A menu name must be producible.
        self.menu_name(scalar, ctx.is_data).is_some()
    }

    /// Get the menu label for this action in the given context.
    ///
    /// Returns `None` if the action should be disabled.
    pub fn menu_name(&self, scalar: &Scalar, is_data: bool) -> Option<String> {
        menu_label(scalar, self.kind.format_choice(), is_data)
    }

    /// Convert a scalar to a string representation in this action's format.
    ///
    /// Returns `None` when the format is unsupported for the given context.
    pub fn convert_to_string(&self, scalar: &Scalar, is_data: bool) -> Option<String> {
        format_scalar(scalar, self.kind.format_choice(), is_data)
    }

    /// Execute this action, producing a [`ConvertCommand`].
    ///
    /// Returns a boxed command ready for execution against an [`EquateTable`].
    pub fn execute(&self, ctx: &ListingActionContext) -> Box<dyn Command> {
        Box::new(ConvertCommand::new(
            ctx.locations.clone(),
            self.kind.format_choice(),
            self.is_signed(),
            ctx.is_data,
        ))
    }
}

// ============================================================================
// SetEquateAction -- "Set Equate..."
// ============================================================================

/// The "Set Equate..." listing-context action.
///
/// Corresponds to the inline `ListingContextAction("Set Equate", ...)` inside
/// `EquatePlugin.createActions()`. When executed it creates equates on
/// all code units in the specified range whose scalar operand matches
/// the target value.
#[derive(Debug, Clone)]
pub struct SetEquateAction {
    /// The key binding hint (VK_E in Java).
    #[allow(dead_code)]
    key_binding: Option<String>,
}

impl SetEquateAction {
    /// Create the action.
    pub fn new() -> Self {
        Self {
            key_binding: Some("E".to_string()),
        }
    }

    /// Action name.
    pub fn name(&self) -> &str {
        "Set Equate"
    }

    /// Menu path.
    pub fn menu_path(&self) -> &[&str] {
        &["Set Equate..."]
    }

    /// Whether this action is enabled for the given context.
    ///
    /// Delegates to `ListingActionContext::is_equate_permitted()`.
    pub fn is_enabled(&self, ctx: &ListingActionContext) -> bool {
        ctx.is_equate_permitted()
    }

    /// Execute the action: create a [`CreateEquateCmd`].
    ///
    /// # Parameters
    ///
    /// * `ctx` - The action context.
    /// * `equate_name` - The user-chosen equate name.
    /// * `overwrite_existing` - Whether to overwrite existing equates at
    ///   locations that already have a different equate for the same value.
    pub fn execute(
        &self,
        ctx: &ListingActionContext,
        equate_name: impl Into<String>,
        overwrite_existing: bool,
    ) -> Box<dyn Command> {
        let scalar = ctx
            .scalar
            .unwrap_or_else(|| Scalar::unsigned(32, 0));
        Box::new(CreateEquateCmd::new(
            &scalar,
            ctx.locations.clone(),
            equate_name,
            overwrite_existing,
        ))
    }

    /// Execute using an enum UUID for name generation.
    pub fn execute_with_enum(
        &self,
        ctx: &ListingActionContext,
        enum_uuid: impl Into<String>,
        overwrite_existing: bool,
    ) -> Box<dyn Command> {
        let scalar = ctx
            .scalar
            .unwrap_or_else(|| Scalar::unsigned(32, 0));
        Box::new(CreateEquateCmd::with_enum(
            &scalar,
            ctx.locations.clone(),
            enum_uuid,
            overwrite_existing,
        ))
    }
}

impl Default for SetEquateAction {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// RenameEquateAction -- "Rename Equate..."
// ============================================================================

/// The "Rename Equate..." listing-context action.
///
/// Renames the equate at a single (address, op_index) location.
#[derive(Debug, Clone)]
pub struct RenameEquateAction {
    #[allow(dead_code)]
    key_binding: Option<String>,
}

impl RenameEquateAction {
    /// Create the action.
    pub fn new() -> Self {
        Self {
            key_binding: Some("E".to_string()),
        }
    }

    /// Action name.
    pub fn name(&self) -> &str {
        "Rename Equate"
    }

    /// Menu path.
    pub fn menu_path(&self) -> &[&str] {
        &["Rename Equate..."]
    }

    /// Whether the action is enabled.
    ///
    /// Requires a scalar AND an existing equate at the location whose value
    /// matches the scalar.
    pub fn is_enabled(&self, ctx: &ListingActionContext) -> bool {
        let scalar = match ctx.get_scalar() {
            Some(s) => s,
            None => return false,
        };

        // Must have an existing equate whose value matches the scalar.
        ctx.current_equate_name.is_some()
            && ctx
                .locations
                .iter()
                .any(|(_, _, v)| *v == scalar.value() || *v == scalar.unsigned_value() as i64)
    }

    /// Execute the rename, producing a [`RenameEquateCmd`].
    pub fn execute(
        &self,
        old_name: impl Into<String>,
        new_name: impl Into<String>,
        addr: Address,
        op_index: i32,
    ) -> Box<dyn Command> {
        Box::new(RenameEquateCmd::new(old_name, new_name, addr, op_index))
    }

    /// Execute the rename using an enum UUID for name generation.
    pub fn execute_with_enum(
        &self,
        old_name: impl Into<String>,
        enum_uuid: impl Into<String>,
        addr: Address,
        op_index: i32,
    ) -> Box<dyn Command> {
        Box::new(RenameEquateCmd::with_enum(
            old_name,
            enum_uuid,
            addr,
            op_index,
        ))
    }
}

impl Default for RenameEquateAction {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// RemoveEquateAction -- "Remove Equate"
// ============================================================================

/// The "Remove Equate" listing-context action.
///
/// Removes equate(s) at the cursor location or across a selection.
#[derive(Debug, Clone)]
pub struct RemoveEquateAction {
    #[allow(dead_code)]
    key_binding: Option<String>,
}

impl RemoveEquateAction {
    /// Create the action.
    pub fn new() -> Self {
        Self {
            key_binding: Some("Delete".to_string()),
        }
    }

    /// Action name.
    pub fn name(&self) -> &str {
        "Remove Equate"
    }

    /// Menu path.
    pub fn menu_path(&self) -> &[&str] {
        &["Remove Equate"]
    }

    /// Whether the action is enabled.
    ///
    /// Requires an equate at the current location.
    pub fn is_enabled(&self, ctx: &ListingActionContext) -> bool {
        ctx.current_equate_name.is_some()
    }

    /// Execute removal of a single equate.
    pub fn execute(&self, equate_name: impl Into<String>) -> Box<dyn Command> {
        Box::new(RemoveEquateCmd::single(equate_name))
    }

    /// Execute removal of multiple equates.
    pub fn execute_many(&self, names: Vec<impl Into<String>>) -> Box<dyn Command> {
        Box::new(RemoveEquateCmd::new(names))
    }
}

impl Default for RemoveEquateAction {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ApplyEnumAction -- "Apply Enum..."
// ============================================================================

/// The "Apply Enum..." listing-context action.
///
/// Applies an enum's fields as equates to all matching scalars in a
/// selection of addresses.
#[derive(Debug, Clone)]
pub struct ApplyEnumAction;

impl ApplyEnumAction {
    /// Create the action.
    pub fn new() -> Self {
        Self
    }

    /// Action name.
    pub fn name(&self) -> &str {
        "Apply Enum"
    }

    /// Menu path.
    pub fn menu_path(&self) -> &[&str] {
        &["Apply Enum..."]
    }

    /// Whether the action is enabled.
    ///
    /// Requires an active selection.
    pub fn is_enabled(&self, ctx: &ListingActionContext) -> bool {
        ctx.has_selection
    }

    /// Execute: create a [`CreateEnumEquateCommand`].
    ///
    /// # Parameters
    ///
    /// * `ctx` - The action context.
    /// * `enum_uuid` - The UUID of the enum data type.
    /// * `enum_values` - The set of valid values in the enum.
    /// * `should_do_on_sub_ops` - Whether to apply to sub-operands as well.
    pub fn execute(
        &self,
        ctx: &ListingActionContext,
        enum_uuid: impl Into<String>,
        enum_values: HashSet<i64>,
        should_do_on_sub_ops: bool,
    ) -> Box<dyn Command> {
        Box::new(CreateEnumEquateCommand::new(
            ctx.locations.clone(),
            enum_uuid,
            enum_values,
            should_do_on_sub_ops,
        ))
    }
}

impl Default for ApplyEnumAction {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// RenameEquatesAction -- "Rename Equates" (rename all references at once)
// ============================================================================

/// The "Rename Equates" action that renames all references of an equate at once.
///
/// This is used by the Equate Table window, not the listing context menu.
/// Corresponds to `RenameEquatesCmd` in Java.
#[derive(Debug, Clone)]
pub struct RenameEquatesAction;

impl RenameEquatesAction {
    /// Create the action.
    pub fn new() -> Self {
        Self
    }

    /// Action name.
    pub fn name(&self) -> &str {
        "Rename Equates"
    }

    /// Execute: rename all references of an equate.
    pub fn execute(
        &self,
        old_name: impl Into<String>,
        new_name: impl Into<String>,
    ) -> Box<dyn Command> {
        Box::new(RenameEquatesCmd::new(old_name, new_name))
    }
}

impl Default for RenameEquatesAction {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// EquateActionSet -- convenience container for all equate listing actions
// ============================================================================

/// A collection of all equate-related listing context actions.
///
/// This mirrors the action registration in `EquatePlugin.createActions()`.
#[derive(Debug, Clone)]
pub struct EquateActionSet {
    /// The 9 convert actions.
    pub convert_actions: Vec<ConvertAction>,
    /// The "Set Equate" action.
    pub set_action: SetEquateAction,
    /// The "Rename Equate" action.
    pub rename_action: RenameEquateAction,
    /// The "Remove Equate" action.
    pub remove_action: RemoveEquateAction,
    /// The "Apply Enum" action.
    pub apply_enum_action: ApplyEnumAction,
}

impl EquateActionSet {
    /// Create the full set of equate actions.
    pub fn new() -> Self {
        Self {
            convert_actions: ConvertAction::all(),
            set_action: SetEquateAction::new(),
            rename_action: RenameEquateAction::new(),
            remove_action: RemoveEquateAction::new(),
            apply_enum_action: ApplyEnumAction::new(),
        }
    }

    /// Get the set of enabled convert action kinds for a context.
    pub fn enabled_convert_actions(&self, ctx: &ListingActionContext) -> Vec<ConvertActionKind> {
        self.convert_actions
            .iter()
            .filter(|a| a.is_enabled(ctx))
            .map(|a| a.kind())
            .collect()
    }

    /// Get a convert action by kind.
    pub fn get_convert_action(&self, kind: ConvertActionKind) -> Option<&ConvertAction> {
        self.convert_actions.iter().find(|a| a.kind() == kind)
    }
}

impl Default for EquateActionSet {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn unsigned_scalar(val: u64) -> Scalar {
        Scalar::unsigned(32, val)
    }

    fn signed_scalar(val: i64) -> Scalar {
        Scalar::signed(32, val)
    }

    fn ctx_with_scalar(scalar: Scalar, is_data: bool) -> ListingActionContext {
        ListingActionContext {
            address: Address::new(0x1000),
            op_index: 0,
            sub_op_index: 0,
            has_selection: false,
            selection: vec![],
            scalar: Some(scalar),
            is_data,
            is_defined_integer_data: is_data,
            is_in_composite_or_array: false,
            code_unit_length: 4,
            locations: vec![(Address::new(0x1000), 0, 0xFF)],
            current_equate_name: None,
        }
    }

    fn ctx_no_scalar() -> ListingActionContext {
        ListingActionContext {
            address: Address::new(0x1000),
            op_index: 0,
            sub_op_index: 0,
            has_selection: false,
            selection: vec![],
            scalar: None,
            is_data: false,
            is_defined_integer_data: false,
            is_in_composite_or_array: false,
            code_unit_length: 4,
            locations: vec![],
            current_equate_name: None,
        }
    }

    // ---------------------------------------------------------------
    // ConvertActionKind tests
    // ---------------------------------------------------------------

    #[test]
    fn test_convert_action_kind_all_count() {
        assert_eq!(ConvertActionKind::ALL.len(), 9);
    }

    #[test]
    fn test_convert_action_kind_signed() {
        assert!(ConvertActionKind::SignedHex.is_signed());
        assert!(ConvertActionKind::SignedDecimal.is_signed());
        assert!(!ConvertActionKind::UnsignedHex.is_signed());
        assert!(!ConvertActionKind::Binary.is_signed());
    }

    #[test]
    fn test_convert_action_kind_action_name() {
        assert_eq!(
            ConvertActionKind::UnsignedHex.action_name(),
            "Convert To Unsigned Hex"
        );
        assert_eq!(
            ConvertActionKind::Float.action_name(),
            "Convert To Float"
        );
    }

    #[test]
    fn test_convert_action_kind_format_choice() {
        assert_eq!(
            ConvertActionKind::Binary.format_choice(),
            FormatChoice::Binary
        );
        assert_eq!(
            ConvertActionKind::Double.format_choice(),
            FormatChoice::Double
        );
    }

    #[test]
    fn test_convert_action_kind_supported_on_data() {
        assert!(ConvertActionKind::UnsignedHex.is_supported_on_data());
        assert!(ConvertActionKind::Binary.is_supported_on_data());
        assert!(ConvertActionKind::Octal.is_supported_on_data());
        assert!(ConvertActionKind::Char.is_supported_on_data());
        assert!(!ConvertActionKind::Float.is_supported_on_data());
        assert!(!ConvertActionKind::Double.is_supported_on_data());
    }

    #[test]
    fn test_convert_action_kind_format_id() {
        assert_eq!(ConvertActionKind::UnsignedHex.format_id(), 0);
        assert_eq!(ConvertActionKind::UnsignedDecimal.format_id(), 1);
        assert_eq!(ConvertActionKind::Octal.format_id(), 2);
        assert_eq!(ConvertActionKind::Binary.format_id(), 3);
        assert_eq!(ConvertActionKind::Char.format_id(), 4);
        assert_eq!(ConvertActionKind::Float.format_id(), -1);
    }

    // ---------------------------------------------------------------
    // ConvertAction tests
    // ---------------------------------------------------------------

    #[test]
    fn test_convert_action_all_created() {
        let actions = ConvertAction::all();
        assert_eq!(actions.len(), 9);
    }

    #[test]
    fn test_convert_action_name() {
        let action = ConvertAction::new(ConvertActionKind::UnsignedHex);
        assert_eq!(action.name(), "Convert To Unsigned Hex");
    }

    #[test]
    fn test_convert_action_enabled_instruction_positive_unsigned() {
        let action = ConvertAction::new(ConvertActionKind::UnsignedHex);
        let ctx = ctx_with_scalar(unsigned_scalar(0xFF), false);
        assert!(action.is_enabled(&ctx));
    }

    #[test]
    fn test_convert_action_disabled_signed_for_positive() {
        let action = ConvertAction::new(ConvertActionKind::SignedHex);
        let ctx = ctx_with_scalar(unsigned_scalar(42), false);
        assert!(!action.is_enabled(&ctx));
    }

    #[test]
    fn test_convert_action_enabled_signed_for_negative() {
        let action = ConvertAction::new(ConvertActionKind::SignedHex);
        let ctx = ctx_with_scalar(signed_scalar(-1), false);
        assert!(action.is_enabled(&ctx));
    }

    #[test]
    fn test_convert_action_disabled_without_scalar() {
        let action = ConvertAction::new(ConvertActionKind::UnsignedHex);
        let ctx = ctx_no_scalar();
        assert!(!action.is_enabled(&ctx));
    }

    #[test]
    fn test_convert_action_disabled_float_on_data() {
        let action = ConvertAction::new(ConvertActionKind::Float);
        let ctx = ctx_with_scalar(unsigned_scalar(0x3F800000), true);
        assert!(!action.is_enabled(&ctx));
    }

    #[test]
    fn test_convert_action_enabled_hex_on_data() {
        let action = ConvertAction::new(ConvertActionKind::UnsignedHex);
        let ctx = ctx_with_scalar(unsigned_scalar(0xFF), true);
        assert!(action.is_enabled(&ctx));
    }

    #[test]
    fn test_convert_action_convert_to_string_hex() {
        let action = ConvertAction::new(ConvertActionKind::UnsignedHex);
        let scalar = unsigned_scalar(0xDEAD);
        let result = action.convert_to_string(&scalar, false);
        assert_eq!(result.unwrap(), "0xDEAD");
    }

    #[test]
    fn test_convert_action_convert_to_string_hex_data() {
        let action = ConvertAction::new(ConvertActionKind::UnsignedHex);
        let scalar = unsigned_scalar(0xDEAD);
        let result = action.convert_to_string(&scalar, true);
        assert_eq!(result.unwrap(), "DEADh");
    }

    #[test]
    fn test_convert_action_execute_produces_command() {
        let action = ConvertAction::new(ConvertActionKind::UnsignedDecimal);
        let ctx = ctx_with_scalar(unsigned_scalar(255), false);
        let mut cmd = action.execute(&ctx);
        let mut table = EquateTable::new();
        cmd.apply(&mut table).unwrap();
        // Check that the equate was created.
        assert!(table.get_equate("255").is_some());
    }

    // ---------------------------------------------------------------
    // SetEquateAction tests
    // ---------------------------------------------------------------

    #[test]
    fn test_set_equate_action_name() {
        let action = SetEquateAction::new();
        assert_eq!(action.name(), "Set Equate");
    }

    #[test]
    fn test_set_equate_action_menu_path() {
        let action = SetEquateAction::new();
        assert_eq!(action.menu_path(), &["Set Equate..."]);
    }

    #[test]
    fn test_set_equate_action_enabled_with_scalar() {
        let action = SetEquateAction::new();
        let ctx = ctx_with_scalar(unsigned_scalar(0xFF), false);
        // Without an existing equate, should be permitted.
        assert!(action.is_enabled(&ctx));
    }

    #[test]
    fn test_set_equate_action_disabled_without_scalar() {
        let action = SetEquateAction::new();
        let ctx = ctx_no_scalar();
        assert!(!action.is_enabled(&ctx));
    }

    #[test]
    fn test_set_equate_action_execute() {
        let action = SetEquateAction::new();
        let ctx = ctx_with_scalar(unsigned_scalar(0xFF), false);
        let mut cmd = action.execute(&ctx, "MY_CONST", false);
        let mut table = EquateTable::new();
        cmd.apply(&mut table).unwrap();
        let eq = table.get_equate("MY_CONST").unwrap();
        assert_eq!(eq.value, 0xFF);
    }

    #[test]
    fn test_set_equate_action_execute_with_enum() {
        let action = SetEquateAction::new();
        let ctx = ctx_with_scalar(unsigned_scalar(0xFF), false);
        let mut cmd = action.execute_with_enum(&ctx, "test-uuid", false);
        let mut table = EquateTable::new();
        cmd.apply(&mut table).unwrap();
        let expected_name = super::super::manager::EquateManager::format_name_for_equate(
            "test-uuid",
            0xFF,
        );
        assert!(table.get_equate(&expected_name).is_some());
    }

    // ---------------------------------------------------------------
    // RenameEquateAction tests
    // ---------------------------------------------------------------

    #[test]
    fn test_rename_equate_action_name() {
        let action = RenameEquateAction::new();
        assert_eq!(action.name(), "Rename Equate");
    }

    #[test]
    fn test_rename_equate_action_enabled_with_existing_equate() {
        let action = RenameEquateAction::new();
        let mut ctx = ctx_with_scalar(unsigned_scalar(0xFF), false);
        ctx.current_equate_name = Some("OLD_NAME".to_string());
        assert!(action.is_enabled(&ctx));
    }

    #[test]
    fn test_rename_equate_action_disabled_without_equate() {
        let action = RenameEquateAction::new();
        let ctx = ctx_with_scalar(unsigned_scalar(0xFF), false);
        assert!(!action.is_enabled(&ctx));
    }

    #[test]
    fn test_rename_equate_action_execute() {
        let action = RenameEquateAction::new();
        let mut cmd = action.execute("OLD", "NEW", Address::new(0x1000), 0);
        let mut table = EquateTable::new();
        table.create_equate("OLD", 10).unwrap();
        table.add_reference("OLD", Address::new(0x1000), 0);
        cmd.apply(&mut table).unwrap();
        assert!(table.get_equate("OLD").is_none());
        assert!(table.get_equate("NEW").is_some());
    }

    // ---------------------------------------------------------------
    // RemoveEquateAction tests
    // ---------------------------------------------------------------

    #[test]
    fn test_remove_equate_action_name() {
        let action = RemoveEquateAction::new();
        assert_eq!(action.name(), "Remove Equate");
    }

    #[test]
    fn test_remove_equate_action_enabled() {
        let action = RemoveEquateAction::new();
        let mut ctx = ctx_with_scalar(unsigned_scalar(0xFF), false);
        ctx.current_equate_name = Some("MY_CONST".to_string());
        assert!(action.is_enabled(&ctx));
    }

    #[test]
    fn test_remove_equate_action_disabled() {
        let action = RemoveEquateAction::new();
        let ctx = ctx_with_scalar(unsigned_scalar(0xFF), false);
        assert!(!action.is_enabled(&ctx));
    }

    #[test]
    fn test_remove_equate_action_execute() {
        let action = RemoveEquateAction::new();
        let mut cmd = action.execute("MY_CONST");
        let mut table = EquateTable::new();
        table.create_equate("MY_CONST", 42).unwrap();
        cmd.apply(&mut table).unwrap();
        assert!(table.get_equate("MY_CONST").is_none());
    }

    #[test]
    fn test_remove_equate_action_execute_many() {
        let action = RemoveEquateAction::new();
        let mut cmd = action.execute_many(vec!["A", "B"]);
        let mut table = EquateTable::new();
        table.create_equate("A", 1).unwrap();
        table.create_equate("B", 2).unwrap();
        cmd.apply(&mut table).unwrap();
        assert!(table.is_empty());
    }

    // ---------------------------------------------------------------
    // ApplyEnumAction tests
    // ---------------------------------------------------------------

    #[test]
    fn test_apply_enum_action_name() {
        let action = ApplyEnumAction::new();
        assert_eq!(action.name(), "Apply Enum");
    }

    #[test]
    fn test_apply_enum_action_enabled_with_selection() {
        let action = ApplyEnumAction::new();
        let mut ctx = ctx_with_scalar(unsigned_scalar(0xFF), false);
        ctx.has_selection = true;
        assert!(action.is_enabled(&ctx));
    }

    #[test]
    fn test_apply_enum_action_disabled_without_selection() {
        let action = ApplyEnumAction::new();
        let ctx = ctx_with_scalar(unsigned_scalar(0xFF), false);
        assert!(!action.is_enabled(&ctx));
    }

    #[test]
    fn test_apply_enum_action_execute() {
        let action = ApplyEnumAction::new();
        let mut ctx = ctx_with_scalar(unsigned_scalar(1), false);
        // The locations must match enum values; ctx_with_scalar hardcodes 0xFF so override.
        ctx.locations = vec![(Address::new(0x1000), 0, 1)];
        let mut enum_values = HashSet::new();
        enum_values.insert(1);
        enum_values.insert(2);
        enum_values.insert(3);
        let mut cmd = action.execute(&ctx, "enum-uuid", enum_values, false);
        let mut table = EquateTable::new();
        cmd.apply(&mut table).unwrap();
        let expected = super::super::manager::EquateManager::format_name_for_equate("enum-uuid", 1);
        assert!(table.get_equate(&expected).is_some());
    }

    // ---------------------------------------------------------------
    // RenameEquatesAction tests
    // ---------------------------------------------------------------

    #[test]
    fn test_rename_equates_action() {
        let action = RenameEquatesAction::new();
        let mut cmd = action.execute("OLD", "NEW");
        let mut table = EquateTable::new();
        table.create_equate("OLD", 5).unwrap();
        table.add_reference("OLD", Address::new(0x1000), 0);
        table.add_reference("OLD", Address::new(0x2000), 1);
        cmd.apply(&mut table).unwrap();
        assert!(table.get_equate("OLD").is_none());
        let eq = table.get_equate("NEW").unwrap();
        assert_eq!(eq.value, 5);
        assert_eq!(eq.reference_count(), 2);
    }

    // ---------------------------------------------------------------
    // EquateActionSet tests
    // ---------------------------------------------------------------

    #[test]
    fn test_equate_action_set_creation() {
        let set = EquateActionSet::new();
        assert_eq!(set.convert_actions.len(), 9);
    }

    #[test]
    fn test_equate_action_set_enabled_convert_actions() {
        let set = EquateActionSet::new();
        let ctx = ctx_with_scalar(unsigned_scalar(0xFF), false);
        let enabled = set.enabled_convert_actions(&ctx);
        // Signed actions should be disabled for positive values.
        assert!(!enabled.contains(&ConvertActionKind::SignedHex));
        assert!(!enabled.contains(&ConvertActionKind::SignedDecimal));
        // Unsigned actions should be enabled.
        assert!(enabled.contains(&ConvertActionKind::UnsignedHex));
        assert!(enabled.contains(&ConvertActionKind::UnsignedDecimal));
        assert!(enabled.contains(&ConvertActionKind::Binary));
        assert!(enabled.contains(&ConvertActionKind::Octal));
    }

    #[test]
    fn test_equate_action_set_get_convert_action() {
        let set = EquateActionSet::new();
        let action = set.get_convert_action(ConvertActionKind::Binary);
        assert!(action.is_some());
        assert_eq!(action.unwrap().name(), "Convert To Unsigned Binary");
    }

    // ---------------------------------------------------------------
    // ListingActionContext tests
    // ---------------------------------------------------------------

    #[test]
    fn test_listing_action_context_with_scalar() {
        let ctx = ListingActionContext::with_scalar(Address::new(0x4000), 1, unsigned_scalar(42));
        assert_eq!(ctx.address, Address::new(0x4000));
        assert_eq!(ctx.op_index, 1);
        assert!(ctx.get_scalar().is_some());
        assert_eq!(ctx.get_scalar().unwrap().unsigned_value(), 42);
    }

    #[test]
    fn test_listing_action_context_is_equate_permitted_no_scalar() {
        let ctx = ctx_no_scalar();
        assert!(!ctx.is_equate_permitted());
    }

    #[test]
    fn test_listing_action_context_is_equate_permitted_basic() {
        let ctx = ctx_with_scalar(unsigned_scalar(0xFF), false);
        assert!(ctx.is_equate_permitted());
    }

    #[test]
    fn test_listing_action_context_is_equate_permitted_composite_data() {
        let mut ctx = ctx_with_scalar(unsigned_scalar(0xFF), true);
        ctx.is_in_composite_or_array = true;
        assert!(!ctx.is_equate_permitted());
    }

    #[test]
    fn test_listing_action_context_is_equate_permitted_undefined_data() {
        let mut ctx = ctx_with_scalar(unsigned_scalar(0xFF), true);
        ctx.is_defined_integer_data = false;
        assert!(!ctx.is_equate_permitted());
    }
}
