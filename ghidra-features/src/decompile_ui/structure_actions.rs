//! Structure variable actions -- Rust port of the
//! `CreateStructureVariableAction`, `DecompilerStructureVariableAction`,
//! and `ListingStructureVariableAction` classes from
//! `ghidra.app.plugin.core.decompile.actions`.
//!
//! These actions create a new structure data type from a variable that
//! is currently selected in the decompiler panel or in the listing.
//!
//! # Architecture
//!
//! ```text
//! CreateStructureVariableAction (base)
//!   ├── DecompilerStructureVariableAction  (decompiler context)
//!   └── ListingStructureVariableAction     (listing context)
//!
//! Each action:
//!   1. Checks that the selected variable has a data type whose size
//!      is <= the program's default pointer size.
//!   2. Adjusts the menu text to reflect the variable kind
//!      (parameter, local, "this" pointer).
//!   3. Launches a task to create a structure from the variable's
//!      pointer target.
//! ```

// ---------------------------------------------------------------------------
// VariableKind -- classification of the selected variable
// ---------------------------------------------------------------------------

/// The kind of variable that the user selected.
///
/// Used to adjust the menu text shown to the user (e.g., "Create
/// Structure from Parameter" vs. "Create Structure from Local").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariableKind {
    /// A function parameter that is not the implicit `this` pointer.
    Parameter,
    /// The implicit `this` pointer parameter.
    ThisParameter,
    /// A local (stack) variable.
    Local,
    /// A global variable.
    Global,
    /// The function's return value.
    ReturnValue,
    /// A struct/union field.
    Field,
}

impl VariableKind {
    /// Human-readable label for menu text.
    pub fn label(self) -> &'static str {
        match self {
            VariableKind::Parameter => "Parameter",
            VariableKind::ThisParameter => "this Parameter",
            VariableKind::Local => "Local",
            VariableKind::Global => "Global",
            VariableKind::ReturnValue => "Return Value",
            VariableKind::Field => "Field",
        }
    }
}

// ---------------------------------------------------------------------------
// StructureCreationInfo -- gathered data about the target variable
// ---------------------------------------------------------------------------

/// Information about the variable that will be converted to a
/// structure.
///
/// This is gathered by the action's enablement check and then passed
/// to the creation task.
#[derive(Debug, Clone)]
pub struct StructureCreationInfo {
    /// The kind of variable.
    pub kind: VariableKind,
    /// The current data type name.
    pub data_type_name: String,
    /// The byte size of the current data type.
    pub data_type_size: usize,
    /// The maximum pointer size for the program.
    pub max_pointer_size: usize,
    /// Whether the variable's data type is a pointer type.
    pub is_pointer: bool,
}

impl StructureCreationInfo {
    /// Returns `true` if the data type is small enough to be promoted
    /// to a structure (size <= max pointer size).
    pub fn is_eligible(&self) -> bool {
        self.data_type_size > 0 && self.data_type_size <= self.max_pointer_size
    }

    /// Generate the adjusted menu text for the "Create Structure"
    /// action.
    ///
    /// This mirrors `adjustCreateStructureMenuText()` in the Java
    /// code.
    pub fn menu_text(&self) -> String {
        match self.kind {
            VariableKind::ThisParameter => {
                format!(
                    "Create Structure from this {} Pointer",
                    self.data_type_name
                )
            }
            _ => {
                format!(
                    "Create Structure from {} {}",
                    self.data_type_name,
                    self.kind.label()
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CreateStructureVariableAction (base)
// ---------------------------------------------------------------------------

/// Base action for creating a structure from a variable.
///
/// This is the abstract base class in Java; here we model it as a
/// concrete struct with fields common to both the decompiler and
/// listing variants.
#[derive(Debug, Clone)]
pub struct CreateStructureVariableAction {
    /// The action name (used for registration).
    name: String,
    /// The owning plugin name (for action ownership).
    owner: String,
    /// Information about the target variable (set during enablement).
    creation_info: Option<StructureCreationInfo>,
}

impl CreateStructureVariableAction {
    /// Create a new base action.
    pub fn new(name: impl Into<String>, owner: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            owner: owner.into(),
            creation_info: None,
        }
    }

    /// The action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The owning plugin name.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Get the current structure creation info, if set.
    pub fn creation_info(&self) -> Option<&StructureCreationInfo> {
        self.creation_info.as_ref()
    }

    /// Set the structure creation info (called during enablement).
    pub fn set_creation_info(&mut self, info: StructureCreationInfo) {
        self.creation_info = Some(info);
    }

    /// Clear the creation info (called when the action is disabled).
    pub fn clear_creation_info(&mut self) {
        self.creation_info = None;
    }

    /// Adjust the menu text based on the variable kind and data type.
    ///
    /// This mirrors the Java `adjustCreateStructureMenuText()` method.
    pub fn adjust_menu_text(&mut self, kind: VariableKind, data_type_name: &str) {
        let info = StructureCreationInfo {
            kind,
            data_type_name: data_type_name.to_string(),
            data_type_size: 0,
            max_pointer_size: 0,
            is_pointer: false,
        };
        self.creation_info = Some(info);
    }

    /// Check whether the action should be enabled and set up the
    /// creation info accordingly.
    ///
    /// Returns `true` if the variable is eligible for structure
    /// creation.
    pub fn check_enablement(
        &mut self,
        kind: VariableKind,
        data_type_name: &str,
        data_type_size: usize,
        max_pointer_size: usize,
        is_pointer: bool,
    ) -> bool {
        let info = StructureCreationInfo {
            kind,
            data_type_name: data_type_name.to_string(),
            data_type_size,
            max_pointer_size,
            is_pointer,
        };
        let eligible = info.is_eligible();
        if eligible {
            self.creation_info = Some(info);
        } else {
            self.creation_info = None;
        }
        eligible
    }

    /// Execute the structure creation task.
    ///
    /// Returns a description of what the task would do.  In the full
    /// implementation, this launches a background task that creates a
    /// new structure data type in the program's data type manager.
    pub fn execute(&self) -> Option<String> {
        self.creation_info.as_ref().map(|info| {
            format!(
                "Creating structure from {} (size={} bytes, kind={:?})",
                info.data_type_name, info.data_type_size, info.kind,
            )
        })
    }
}

// ---------------------------------------------------------------------------
// DecompilerStructureVariableAction
// ---------------------------------------------------------------------------

/// Action: Create a structure from a variable selected in the
/// decompiler panel.
///
/// Mirrors `DecompilerStructureVariableAction` which extends
/// `CreateStructureVariableAction`.
///
/// Enablement requires:
/// 1. The context is a `DecompilerActionContext`.
/// 2. The current function is not null and not an `UndefinedFunction`.
/// 3. The token at cursor has a `HighVariable` that is not a
///    `HighConstant`.
/// 4. The variable's data type is non-null and its size is <= the
///    program's default pointer size.
#[derive(Debug, Clone)]
pub struct DecompilerStructureVariableAction {
    base: CreateStructureVariableAction,
}

impl DecompilerStructureVariableAction {
    /// Create a new action for the decompiler context.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            base: CreateStructureVariableAction::new(
                "Decompiler Create Structure Variable",
                owner,
            ),
        }
    }

    /// The action name.
    pub fn name(&self) -> &str {
        self.base.name()
    }

    /// Check whether the action is enabled for the given decompiler
    /// context.
    ///
    /// `has_function` -- whether the context has a non-null, non-undefined function.
    /// `token_has_variable` -- whether the token at cursor has a high variable.
    /// `is_high_constant` -- whether the variable is a `HighConstant`.
    /// `is_this_param` -- whether the variable is the implicit `this`.
    /// `data_type_name` -- name of the variable's data type (if any).
    /// `data_type_size` -- byte size of the data type.
    /// `max_pointer_size` -- the program's default pointer size.
    pub fn is_enabled(
        &mut self,
        has_function: bool,
        token_has_variable: bool,
        is_high_constant: bool,
        is_this_param: bool,
        data_type_name: Option<&str>,
        data_type_size: usize,
        max_pointer_size: usize,
    ) -> bool {
        if !has_function {
            self.base.clear_creation_info();
            return false;
        }
        if !token_has_variable || is_high_constant {
            self.base.clear_creation_info();
            return false;
        }
        let dt_name = match data_type_name {
            Some(n) => n,
            None => {
                self.base.clear_creation_info();
                return false;
            }
        };
        let kind = if is_this_param {
            VariableKind::ThisParameter
        } else {
            VariableKind::Parameter
        };
        self.base.check_enablement(kind, dt_name, data_type_size, max_pointer_size, false)
    }

    /// Get the adjusted menu text (call after `is_enabled` returns
    /// `true`).
    pub fn menu_text(&self) -> Option<String> {
        self.base.creation_info().map(|info| info.menu_text())
    }

    /// Execute the action.
    pub fn execute(&self) -> Option<String> {
        self.base.execute()
    }
}

// ---------------------------------------------------------------------------
// ListingStructureVariableAction
// ---------------------------------------------------------------------------

/// The kind of listing location that was selected.
///
/// This determines how the action interprets the program location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListingLocationKind {
    /// A `VariableLocation` -- direct variable reference.
    VariableLocation,
    /// A `FunctionParameterFieldLocation` -- parameter in the function signature.
    FunctionParameterField,
    /// A `FunctionReturnTypeFieldLocation` -- the return type field.
    FunctionReturnTypeField,
    /// Any other location kind (not supported).
    Other,
}

/// Action: Create a structure from a variable selected in the listing.
///
/// Mirrors `ListingStructureVariableAction` which extends
/// `CreateStructureVariableAction`.
///
/// Enablement requires:
/// 1. The context is a `ListingActionContext`.
/// 2. The location is one of the supported kinds
///    (`VariableLocation`, `FunctionParameterFieldLocation`,
///    `FunctionReturnTypeFieldLocation`).
/// 3. The data type is non-null and its size is <= the program's
///    default pointer size.
#[derive(Debug, Clone)]
pub struct ListingStructureVariableAction {
    base: CreateStructureVariableAction,
}

impl ListingStructureVariableAction {
    /// Create a new action for the listing context.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            base: CreateStructureVariableAction::new(
                "Listing Create Structure Variable",
                owner,
            ),
        }
    }

    /// The action name.
    pub fn name(&self) -> &str {
        self.base.name()
    }

    /// Check whether the action is enabled for the given listing
    /// context.
    ///
    /// `location_kind` -- the kind of listing location.
    /// `is_this_param` -- whether the selected variable is the `this`
    ///   parameter.
    /// `data_type_name` -- name of the data type (if any).
    /// `data_type_size` -- byte size of the data type.
    /// `max_pointer_size` -- the program's default pointer size.
    pub fn is_enabled(
        &mut self,
        location_kind: ListingLocationKind,
        is_this_param: bool,
        data_type_name: Option<&str>,
        data_type_size: usize,
        max_pointer_size: usize,
    ) -> bool {
        // Only certain listing locations are supported.
        match location_kind {
            ListingLocationKind::VariableLocation
            | ListingLocationKind::FunctionParameterField
            | ListingLocationKind::FunctionReturnTypeField => {}
            _ => {
                self.base.clear_creation_info();
                return false;
            }
        }
        let dt_name = match data_type_name {
            Some(n) => n,
            None => {
                self.base.clear_creation_info();
                return false;
            }
        };
        let kind = if is_this_param {
            VariableKind::ThisParameter
        } else {
            match location_kind {
                ListingLocationKind::FunctionReturnTypeField => VariableKind::ReturnValue,
                ListingLocationKind::FunctionParameterField => VariableKind::Parameter,
                _ => VariableKind::Local,
            }
        };
        self.base.check_enablement(kind, dt_name, data_type_size, max_pointer_size, false)
    }

    /// Get the adjusted menu text (call after `is_enabled` returns
    /// `true`).
    pub fn menu_text(&self) -> Option<String> {
        self.base.creation_info().map(|info| info.menu_text())
    }

    /// Execute the action.
    pub fn execute(&self) -> Option<String> {
        self.base.execute()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- VariableKind --

    #[test]
    fn test_variable_kind_labels() {
        assert_eq!(VariableKind::Parameter.label(), "Parameter");
        assert_eq!(VariableKind::ThisParameter.label(), "this Parameter");
        assert_eq!(VariableKind::Local.label(), "Local");
        assert_eq!(VariableKind::Global.label(), "Global");
        assert_eq!(VariableKind::ReturnValue.label(), "Return Value");
        assert_eq!(VariableKind::Field.label(), "Field");
    }

    // -- StructureCreationInfo --

    #[test]
    fn test_creation_info_eligible() {
        let info = StructureCreationInfo {
            kind: VariableKind::Parameter,
            data_type_name: "int".into(),
            data_type_size: 4,
            max_pointer_size: 8,
            is_pointer: false,
        };
        assert!(info.is_eligible());
    }

    #[test]
    fn test_creation_info_not_eligible_too_large() {
        let info = StructureCreationInfo {
            kind: VariableKind::Parameter,
            data_type_name: "huge_struct".into(),
            data_type_size: 1024,
            max_pointer_size: 8,
            is_pointer: false,
        };
        assert!(!info.is_eligible());
    }

    #[test]
    fn test_creation_info_not_eligible_zero_size() {
        let info = StructureCreationInfo {
            kind: VariableKind::Parameter,
            data_type_name: "void".into(),
            data_type_size: 0,
            max_pointer_size: 8,
            is_pointer: false,
        };
        assert!(!info.is_eligible());
    }

    #[test]
    fn test_creation_info_menu_text_parameter() {
        let info = StructureCreationInfo {
            kind: VariableKind::Parameter,
            data_type_name: "int*".into(),
            data_type_size: 8,
            max_pointer_size: 8,
            is_pointer: true,
        };
        let text = info.menu_text();
        assert!(text.contains("int*"));
        assert!(text.contains("Parameter"));
        assert!(!text.contains("this"));
    }

    #[test]
    fn test_creation_info_menu_text_this() {
        let info = StructureCreationInfo {
            kind: VariableKind::ThisParameter,
            data_type_name: "MyClass*".into(),
            data_type_size: 8,
            max_pointer_size: 8,
            is_pointer: true,
        };
        let text = info.menu_text();
        assert!(text.contains("MyClass*"));
        assert!(text.contains("Pointer"));
        assert!(text.contains("this"));
    }

    // -- CreateStructureVariableAction (base) --

    #[test]
    fn test_base_action_new() {
        let action = CreateStructureVariableAction::new("TestAction", "TestOwner");
        assert_eq!(action.name(), "TestAction");
        assert_eq!(action.owner(), "TestOwner");
        assert!(action.creation_info().is_none());
    }

    #[test]
    fn test_base_action_check_enablement() {
        let mut action = CreateStructureVariableAction::new("Test", "Owner");
        assert!(action.check_enablement(
            VariableKind::Local,
            "int",
            4,
            8,
            false,
        ));
        assert!(action.creation_info().is_some());
    }

    #[test]
    fn test_base_action_check_enablement_fails() {
        let mut action = CreateStructureVariableAction::new("Test", "Owner");
        assert!(!action.check_enablement(
            VariableKind::Local,
            "big",
            100,
            8,
            false,
        ));
        assert!(action.creation_info().is_none());
    }

    #[test]
    fn test_base_action_execute() {
        let mut action = CreateStructureVariableAction::new("Test", "Owner");
        assert!(action.execute().is_none()); // no creation info yet

        action.check_enablement(VariableKind::Parameter, "int*", 8, 8, true);
        let result = action.execute().unwrap();
        assert!(result.contains("int*"));
        assert!(result.contains("Parameter"));
    }

    #[test]
    fn test_base_action_adjust_menu_text() {
        let mut action = CreateStructureVariableAction::new("Test", "Owner");
        action.adjust_menu_text(VariableKind::Global, "float");
        assert!(action.creation_info().is_some());
    }

    // -- DecompilerStructureVariableAction --

    #[test]
    fn test_decompiler_action_new() {
        let action = DecompilerStructureVariableAction::new("TestPlugin");
        assert!(action.name().contains("Decompiler"));
    }

    #[test]
    fn test_decompiler_action_enabled() {
        let mut action = DecompilerStructureVariableAction::new("Owner");
        assert!(action.is_enabled(
            true,   // has_function
            true,   // token_has_variable
            false,  // is_high_constant
            false,  // is_this_param
            Some("int"),
            4,      // data_type_size
            8,      // max_pointer_size
        ));
        let text = action.menu_text().unwrap();
        assert!(text.contains("int"));
    }

    #[test]
    fn test_decompiler_action_disabled_no_function() {
        let mut action = DecompilerStructureVariableAction::new("Owner");
        assert!(!action.is_enabled(
            false, true, false, false, Some("int"), 4, 8,
        ));
    }

    #[test]
    fn test_decompiler_action_disabled_no_variable() {
        let mut action = DecompilerStructureVariableAction::new("Owner");
        assert!(!action.is_enabled(
            true, false, false, false, Some("int"), 4, 8,
        ));
    }

    #[test]
    fn test_decompiler_action_disabled_high_constant() {
        let mut action = DecompilerStructureVariableAction::new("Owner");
        assert!(!action.is_enabled(
            true, true, true, false, Some("int"), 4, 8,
        ));
    }

    #[test]
    fn test_decompiler_action_disabled_no_data_type() {
        let mut action = DecompilerStructureVariableAction::new("Owner");
        assert!(!action.is_enabled(
            true, true, false, false, None, 4, 8,
        ));
    }

    #[test]
    fn test_decompiler_action_disabled_type_too_large() {
        let mut action = DecompilerStructureVariableAction::new("Owner");
        assert!(!action.is_enabled(
            true, true, false, false, Some("huge"), 1024, 8,
        ));
    }

    #[test]
    fn test_decompiler_action_this_param() {
        let mut action = DecompilerStructureVariableAction::new("Owner");
        assert!(action.is_enabled(
            true, true, false, true, Some("MyClass*"), 8, 8,
        ));
        let text = action.menu_text().unwrap();
        assert!(text.contains("this"));
        assert!(text.contains("Pointer"));
    }

    #[test]
    fn test_decompiler_action_execute() {
        let mut action = DecompilerStructureVariableAction::new("Owner");
        action.is_enabled(true, true, false, false, Some("int*"), 8, 8);
        let result = action.execute().unwrap();
        assert!(result.contains("Creating structure"));
    }

    // -- ListingStructureVariableAction --

    #[test]
    fn test_listing_action_new() {
        let action = ListingStructureVariableAction::new("TestPlugin");
        assert!(action.name().contains("Listing"));
    }

    #[test]
    fn test_listing_action_enabled_variable_location() {
        let mut action = ListingStructureVariableAction::new("Owner");
        assert!(action.is_enabled(
            ListingLocationKind::VariableLocation,
            false,
            Some("int"),
            4,
            8,
        ));
    }

    #[test]
    fn test_listing_action_enabled_param_field() {
        let mut action = ListingStructureVariableAction::new("Owner");
        assert!(action.is_enabled(
            ListingLocationKind::FunctionParameterField,
            false,
            Some("char*"),
            8,
            8,
        ));
        let text = action.menu_text().unwrap();
        assert!(text.contains("char*"));
        assert!(text.contains("Parameter"));
    }

    #[test]
    fn test_listing_action_enabled_return_type() {
        let mut action = ListingStructureVariableAction::new("Owner");
        assert!(action.is_enabled(
            ListingLocationKind::FunctionReturnTypeField,
            false,
            Some("void*"),
            8,
            8,
        ));
        let text = action.menu_text().unwrap();
        assert!(text.contains("Return Value"));
    }

    #[test]
    fn test_listing_action_disabled_other_location() {
        let mut action = ListingStructureVariableAction::new("Owner");
        assert!(!action.is_enabled(
            ListingLocationKind::Other,
            false,
            Some("int"),
            4,
            8,
        ));
    }

    #[test]
    fn test_listing_action_disabled_no_data_type() {
        let mut action = ListingStructureVariableAction::new("Owner");
        assert!(!action.is_enabled(
            ListingLocationKind::VariableLocation,
            false,
            None,
            4,
            8,
        ));
    }

    #[test]
    fn test_listing_action_this_param() {
        let mut action = ListingStructureVariableAction::new("Owner");
        assert!(action.is_enabled(
            ListingLocationKind::VariableLocation,
            true,
            Some("MyClass*"),
            8,
            8,
        ));
        let text = action.menu_text().unwrap();
        assert!(text.contains("this"));
    }

    #[test]
    fn test_listing_action_execute() {
        let mut action = ListingStructureVariableAction::new("Owner");
        action.is_enabled(
            ListingLocationKind::VariableLocation,
            false,
            Some("float"),
            4,
            8,
        );
        let result = action.execute().unwrap();
        assert!(result.contains("Creating structure"));
    }
}
