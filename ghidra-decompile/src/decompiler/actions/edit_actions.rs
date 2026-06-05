//! Specific decompiler edit actions: rename, retype, convert, edit.
//!
//! Port of Ghidra's decompiler action classes:
//! - Rename actions (RenameLocal, RenameGlobal, RenameFunction, RenameField, etc.)
//! - Retype actions (RetypeLocal, RetypeGlobal, RetypeReturn, RetypeField, etc.)
//! - Convert actions (ConvertHex, ConvertDec, ConvertOct, ConvertBinary, ConvertChar, etc.)
//! - Edit actions (EditDataType, EditField, EditProperties, etc.)
//! - Variable actions (IsolateVariable, CommitLocals, CommitParams, etc.)
//! - Structure actions (CreateStructureVariable, ForceUnion, etc.)

use ghidra_core::addr::Address;
use serde::{Deserialize, Serialize};

use super::{ActionCategory, ActionMetadata, ConstantFormat};

// ============================================================================
// Rename actions
// ============================================================================

/// Target of a rename operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RenameTarget {
    /// A local variable.
    LocalVariable,
    /// A global variable or symbol.
    GlobalSymbol,
    /// A function name.
    Function,
    /// A struct field name.
    StructField,
    /// A struct bit field name.
    StructBitField,
    /// A union field name.
    UnionField,
    /// A label name.
    Label,
}

/// Data for a rename operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameAction {
    /// What is being renamed.
    pub target: RenameTarget,
    /// The current name.
    pub old_name: String,
    /// The desired new name.
    pub new_name: String,
    /// The address of the symbol being renamed.
    pub address: Address,
    /// The source variable key (if renaming a local/parameter).
    pub var_key: Option<String>,
}

impl RenameAction {
    /// Create a new rename action.
    pub fn new(
        target: RenameTarget,
        old_name: impl Into<String>,
        new_name: impl Into<String>,
        address: Address,
    ) -> Self {
        Self {
            target,
            old_name: old_name.into(),
            new_name: new_name.into(),
            address,
            var_key: None,
        }
    }

    /// Set the variable key for local/parameter renames.
    pub fn with_var_key(mut self, key: impl Into<String>) -> Self {
        self.var_key = Some(key.into());
        self
    }

    /// Get metadata for this action.
    pub fn metadata(&self) -> ActionMetadata {
        let name = match self.target {
            RenameTarget::LocalVariable => "RenameLocal",
            RenameTarget::GlobalSymbol => "RenameGlobal",
            RenameTarget::Function => "RenameFunction",
            RenameTarget::StructField => "RenameField",
            RenameTarget::StructBitField => "RenameBitField",
            RenameTarget::UnionField => "RenameField",
            RenameTarget::Label => "RenameLabel",
        };
        ActionMetadata::new(name, name, ActionCategory::Editing)
            .with_tooltip(format!("Rename '{}' to '{}'", self.old_name, self.new_name))
    }
}

/// Task for renaming a struct field (spawns async work).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameStructFieldTask {
    /// The new field name.
    pub new_name: String,
    /// The struct data type path.
    pub struct_path: String,
    /// The field ordinal index.
    pub field_ordinal: usize,
    /// The address where the field is accessed.
    pub address: Address,
}

impl RenameStructFieldTask {
    /// Create a new rename struct field task.
    pub fn new(
        new_name: impl Into<String>,
        struct_path: impl Into<String>,
        field_ordinal: usize,
        address: Address,
    ) -> Self {
        Self {
            new_name: new_name.into(),
            struct_path: struct_path.into(),
            field_ordinal,
            address,
        }
    }
}

/// Task for renaming a variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameVariableTask {
    /// The new variable name.
    pub new_name: String,
    /// The variable's high symbol ID.
    pub high_symbol_id: u32,
    /// The function entry point.
    pub function_entry: Address,
}

impl RenameVariableTask {
    /// Create a new rename variable task.
    pub fn new(
        new_name: impl Into<String>,
        high_symbol_id: u32,
        function_entry: Address,
    ) -> Self {
        Self {
            new_name: new_name.into(),
            high_symbol_id,
            function_entry,
        }
    }
}

// ============================================================================
// Retype actions
// ============================================================================

/// Target of a retype operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetypeTarget {
    /// A local variable.
    LocalVariable,
    /// A global symbol.
    GlobalSymbol,
    /// A function return type.
    ReturnType,
    /// A struct field.
    StructField,
    /// A union field.
    UnionField,
}

/// Data for a retype operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetypeAction {
    /// What is being retyped.
    pub target: RetypeTarget,
    /// The new data type path (e.g., "uint32_t", "my_struct *").
    pub new_type_path: String,
    /// The address of the symbol being retyped.
    pub address: Address,
    /// The field ordinal (for struct/union fields).
    pub field_ordinal: Option<usize>,
    /// The variable key (for local variables).
    pub var_key: Option<String>,
}

impl RetypeAction {
    /// Create a new retype action.
    pub fn new(
        target: RetypeTarget,
        new_type_path: impl Into<String>,
        address: Address,
    ) -> Self {
        Self {
            target,
            new_type_path: new_type_path.into(),
            address,
            field_ordinal: None,
            var_key: None,
        }
    }

    /// Set the field ordinal for struct/union field retype.
    pub fn with_field_ordinal(mut self, ordinal: usize) -> Self {
        self.field_ordinal = Some(ordinal);
        self
    }

    /// Set the variable key for local variable retype.
    pub fn with_var_key(mut self, key: impl Into<String>) -> Self {
        self.var_key = Some(key.into());
        self
    }

    /// Get metadata for this action.
    pub fn metadata(&self) -> ActionMetadata {
        let name = match self.target {
            RetypeTarget::LocalVariable => "RetypeLocal",
            RetypeTarget::GlobalSymbol => "RetypeGlobal",
            RetypeTarget::ReturnType => "RetypeReturn",
            RetypeTarget::StructField => "RetypeField",
            RetypeTarget::UnionField => "RetypeField",
        };
        ActionMetadata::new(name, name, ActionCategory::Editing)
    }
}

/// Task for retyping a struct field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetypeStructFieldTask {
    /// The new data type path.
    pub new_type_path: String,
    /// The struct data type path.
    pub struct_path: String,
    /// The field ordinal.
    pub field_ordinal: usize,
    /// The address of access.
    pub address: Address,
}

impl RetypeStructFieldTask {
    /// Create a new retype struct field task.
    pub fn new(
        new_type_path: impl Into<String>,
        struct_path: impl Into<String>,
        field_ordinal: usize,
        address: Address,
    ) -> Self {
        Self {
            new_type_path: new_type_path.into(),
            struct_path: struct_path.into(),
            field_ordinal,
            address,
        }
    }
}

// ============================================================================
// Convert actions
// ============================================================================

/// Data for a constant conversion action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvertConstantAction {
    /// The target format.
    pub format: ConstantFormat,
    /// The address of the constant.
    pub address: Address,
    /// The original value.
    pub original_value: u64,
    /// The size of the constant in bytes.
    pub size: usize,
}

impl ConvertConstantAction {
    /// Create a new convert constant action.
    pub fn new(format: ConstantFormat, address: Address, original_value: u64, size: usize) -> Self {
        Self {
            format,
            address,
            original_value,
            size,
        }
    }

    /// Get the formatted value.
    pub fn formatted_value(&self) -> String {
        self.format.format_value(self.original_value, self.size)
    }

    /// Get metadata for this action.
    pub fn metadata(&self) -> ActionMetadata {
        let name = match self.format {
            ConstantFormat::Hex => "ConvertHex",
            ConstantFormat::Decimal => "ConvertDec",
            ConstantFormat::Octal => "ConvertOct",
            ConstantFormat::Binary => "ConvertBinary",
            ConstantFormat::Char => "ConvertChar",
            ConstantFormat::Float => "ConvertFloat",
            ConstantFormat::Double => "ConvertDouble",
        };
        ActionMetadata::new(name, name, ActionCategory::Editing)
            .with_tooltip(format!("Convert to {}", self.formatted_value()))
    }
}

// ============================================================================
// Edit actions
// ============================================================================

/// Data for editing a data type at the cursor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditDataTypeAction {
    /// The address of the data to edit.
    pub address: Address,
    /// The current data type path.
    pub current_type: String,
    /// The function entry point (for local edits).
    pub function_entry: Option<Address>,
}

impl EditDataTypeAction {
    /// Create a new edit data type action.
    pub fn new(address: Address, current_type: impl Into<String>) -> Self {
        Self {
            address,
            current_type: current_type.into(),
            function_entry: None,
        }
    }

    /// Set the function entry point.
    pub fn with_function(mut self, entry: Address) -> Self {
        self.function_entry = Some(entry);
        self
    }
}

/// Data for editing a field within a composite type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditFieldAction {
    /// The composite type path.
    pub composite_path: String,
    /// The field ordinal.
    pub field_ordinal: usize,
    /// The address of access.
    pub address: Address,
}

impl EditFieldAction {
    /// Create a new edit field action.
    pub fn new(
        composite_path: impl Into<String>,
        field_ordinal: usize,
        address: Address,
    ) -> Self {
        Self {
            composite_path: composite_path.into(),
            field_ordinal,
            address,
        }
    }
}

/// Data for editing properties (e.g., equates, pointer overrides).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditPropertiesAction {
    /// The address to edit properties for.
    pub address: Address,
    /// The function entry point.
    pub function_entry: Option<Address>,
}

impl EditPropertiesAction {
    /// Create a new edit properties action.
    pub fn new(address: Address) -> Self {
        Self {
            address,
            function_entry: None,
        }
    }
}

// ============================================================================
// Variable actions
// ============================================================================

/// Data for isolating a variable (extracting from a composite).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolateVariableAction {
    /// The variable's high symbol ID.
    pub high_symbol_id: u32,
    /// The function entry point.
    pub function_entry: Address,
    /// The new variable name.
    pub new_name: String,
    /// The offset within the original storage.
    pub storage_offset: i64,
    /// The size of the new variable in bytes.
    pub size: usize,
}

impl IsolateVariableAction {
    /// Create a new isolate variable action.
    pub fn new(
        high_symbol_id: u32,
        function_entry: Address,
        new_name: impl Into<String>,
        storage_offset: i64,
        size: usize,
    ) -> Self {
        Self {
            high_symbol_id,
            function_entry,
            new_name: new_name.into(),
            storage_offset,
            size,
        }
    }
}

/// Data for committing local variable changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitLocalsAction {
    /// The function entry point.
    pub function_entry: Address,
    /// Whether to commit name changes.
    pub commit_names: bool,
    /// Whether to commit type changes.
    pub commit_types: bool,
}

impl CommitLocalsAction {
    /// Create a new commit locals action.
    pub fn new(function_entry: Address) -> Self {
        Self {
            function_entry,
            commit_names: true,
            commit_types: true,
        }
    }
}

/// Data for committing parameter changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitParamsAction {
    /// The function entry point.
    pub function_entry: Address,
    /// The new parameter names/types (ordinal -> (name, type_path)).
    pub param_changes: Vec<ParamChange>,
}

impl CommitParamsAction {
    /// Create a new commit params action.
    pub fn new(function_entry: Address) -> Self {
        Self {
            function_entry,
            param_changes: Vec::new(),
        }
    }

    /// Add a parameter change.
    pub fn add_change(&mut self, ordinal: usize, name: String, type_path: Option<String>) {
        self.param_changes.push(ParamChange {
            ordinal,
            name,
            type_path,
        });
    }
}

/// A single parameter change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamChange {
    /// The parameter ordinal (0-based).
    pub ordinal: usize,
    /// The new name.
    pub name: String,
    /// The new type path (None if unchanged).
    pub type_path: Option<String>,
}

// ============================================================================
// Prototype actions
// ============================================================================

/// Action to override the function prototype.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverridePrototypeAction {
    /// The function entry point.
    pub function_entry: Address,
    /// The new calling convention name.
    pub calling_convention: Option<String>,
    /// The new return type path.
    pub return_type: Option<String>,
}

impl OverridePrototypeAction {
    /// Create a new override prototype action.
    pub fn new(function_entry: Address) -> Self {
        Self {
            function_entry,
            calling_convention: None,
            return_type: None,
        }
    }
}

/// Action to specify a C-style prototype.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecifyCPrototypeAction {
    /// The function entry point.
    pub function_entry: Address,
    /// The full C prototype string (e.g., "int foo(int x, char *y)").
    pub prototype_string: String,
}

impl SpecifyCPrototypeAction {
    /// Create a new specify C prototype action.
    pub fn new(function_entry: Address, prototype_string: impl Into<String>) -> Self {
        Self {
            function_entry,
            prototype_string: prototype_string.into(),
        }
    }
}

// ============================================================================
// Structure actions
// ============================================================================

/// Action to create a structure variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateStructureVariableAction {
    /// The variable's high symbol ID.
    pub high_symbol_id: u32,
    /// The function entry point.
    pub function_entry: Address,
    /// The structure data type path.
    pub struct_type_path: String,
}

impl CreateStructureVariableAction {
    /// Create a new create structure variable action.
    pub fn new(
        high_symbol_id: u32,
        function_entry: Address,
        struct_type_path: impl Into<String>,
    ) -> Self {
        Self {
            high_symbol_id,
            function_entry,
            struct_type_path: struct_type_path.into(),
        }
    }
}

/// Action to force a union interpretation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForceUnionAction {
    /// The address of the data.
    pub address: Address,
    /// The union type path.
    pub union_type_path: String,
    /// The selected field ordinal.
    pub field_ordinal: usize,
}

impl ForceUnionAction {
    /// Create a new force union action.
    pub fn new(
        address: Address,
        union_type_path: impl Into<String>,
        field_ordinal: usize,
    ) -> Self {
        Self {
            address,
            union_type_path: union_type_path.into(),
            field_ordinal,
        }
    }
}

/// Action to create a pointer relative to a base.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePointerRelative {
    /// The address of the pointer.
    pub address: Address,
    /// The base address.
    pub base_address: Address,
    /// The function entry point.
    pub function_entry: Address,
}

impl CreatePointerRelative {
    /// Create a new create pointer relative action.
    pub fn new(address: Address, base_address: Address, function_entry: Address) -> Self {
        Self {
            address,
            base_address,
            function_entry,
        }
    }
}

// ============================================================================
// Export action
// ============================================================================

/// Action to export decompiled C code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportToCAction {
    /// The file path to export to.
    pub output_path: String,
    /// Whether to include header comments.
    pub include_header: bool,
    /// Whether to include function signatures only (no bodies).
    pub signatures_only: bool,
}

impl ExportToCAction {
    /// Create a new export to C action.
    pub fn new(output_path: impl Into<String>) -> Self {
        Self {
            output_path: output_path.into(),
            include_header: true,
            signatures_only: false,
        }
    }
}

/// Action to copy the function signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopySignature {
    /// The function entry point.
    pub function_entry: Address,
    /// The function signature string.
    pub signature: String,
}

impl CopySignature {
    /// Create a new copy signature action.
    pub fn new(function_entry: Address, signature: impl Into<String>) -> Self {
        Self {
            function_entry,
            signature: signature.into(),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rename_action_creation() {
        let action = RenameAction::new(
            RenameTarget::LocalVariable,
            "old_name",
            "new_name",
            Address::new(0x1000),
        );
        assert_eq!(action.old_name, "old_name");
        assert_eq!(action.new_name, "new_name");
        assert_eq!(action.target, RenameTarget::LocalVariable);
    }

    #[test]
    fn rename_action_with_var_key() {
        let action = RenameAction::new(
            RenameTarget::LocalVariable,
            "x",
            "y",
            Address::new(0x1000),
        )
        .with_var_key("sym123");
        assert_eq!(action.var_key.as_deref(), Some("sym123"));
    }

    #[test]
    fn rename_action_metadata() {
        let action = RenameAction::new(
            RenameTarget::Function,
            "old_func",
            "new_func",
            Address::new(0x1000),
        );
        let meta = action.metadata();
        assert_eq!(meta.name, "RenameFunction");
        assert_eq!(meta.category, ActionCategory::Editing);
    }

    #[test]
    fn rename_struct_field_task() {
        let task = RenameStructFieldTask::new("new_field", "MyStruct", 2, Address::new(0x2000));
        assert_eq!(task.new_name, "new_field");
        assert_eq!(task.field_ordinal, 2);
    }

    #[test]
    fn rename_variable_task() {
        let task = RenameVariableTask::new("new_var", 42, Address::new(0x1000));
        assert_eq!(task.new_name, "new_var");
        assert_eq!(task.high_symbol_id, 42);
    }

    #[test]
    fn retype_action_creation() {
        let action = RetypeAction::new(
            RetypeTarget::LocalVariable,
            "uint32_t",
            Address::new(0x1000),
        );
        assert_eq!(action.new_type_path, "uint32_t");
    }

    #[test]
    fn retype_action_with_field() {
        let action = RetypeAction::new(
            RetypeTarget::StructField,
            "int",
            Address::new(0x2000),
        )
        .with_field_ordinal(3);
        assert_eq!(action.field_ordinal, Some(3));
    }

    #[test]
    fn retype_struct_field_task() {
        let task = RetypeStructFieldTask::new("int", "MyStruct", 1, Address::new(0x2000));
        assert_eq!(task.new_type_path, "int");
        assert_eq!(task.field_ordinal, 1);
    }

    #[test]
    fn convert_constant_hex() {
        let action = ConvertConstantAction::new(
            ConstantFormat::Hex,
            Address::new(0x1000),
            0xFF,
            4,
        );
        assert_eq!(action.formatted_value(), "0x000000ff");
    }

    #[test]
    fn convert_constant_char() {
        let action = ConvertConstantAction::new(
            ConstantFormat::Char,
            Address::new(0x1000),
            65,
            1,
        );
        assert_eq!(action.formatted_value(), "'A'");
    }

    #[test]
    fn edit_data_type_action() {
        let action = EditDataTypeAction::new(Address::new(0x1000), "int")
            .with_function(Address::new(0x1000));
        assert_eq!(action.current_type, "int");
        assert!(action.function_entry.is_some());
    }

    #[test]
    fn edit_field_action() {
        let action = EditFieldAction::new("MyStruct", 2, Address::new(0x2000));
        assert_eq!(action.field_ordinal, 2);
    }

    #[test]
    fn isolate_variable_action() {
        let action = IsolateVariableAction::new(
            42,
            Address::new(0x1000),
            "new_var",
            4,
            4,
        );
        assert_eq!(action.storage_offset, 4);
        assert_eq!(action.size, 4);
    }

    #[test]
    fn commit_locals_action() {
        let action = CommitLocalsAction::new(Address::new(0x1000));
        assert!(action.commit_names);
        assert!(action.commit_types);
    }

    #[test]
    fn commit_params_action_with_changes() {
        let mut action = CommitParamsAction::new(Address::new(0x1000));
        action.add_change(0, "x".to_string(), Some("int".to_string()));
        action.add_change(1, "y".to_string(), Some("char *".to_string()));
        assert_eq!(action.param_changes.len(), 2);
    }

    #[test]
    fn override_prototype_action() {
        let mut action = OverridePrototypeAction::new(Address::new(0x1000));
        action.calling_convention = Some("__stdcall".to_string());
        action.return_type = Some("int".to_string());
        assert!(action.calling_convention.is_some());
    }

    #[test]
    fn specify_c_prototype_action() {
        let action =
            SpecifyCPrototypeAction::new(Address::new(0x1000), "int foo(int x, char *y)");
        assert!(action.prototype_string.contains("foo"));
    }

    #[test]
    fn create_structure_variable_action() {
        let action = CreateStructureVariableAction::new(
            42,
            Address::new(0x1000),
            "my_struct_t",
        );
        assert_eq!(action.struct_type_path, "my_struct_t");
    }

    #[test]
    fn force_union_action() {
        let action = ForceUnionAction::new(Address::new(0x1000), "my_union_t", 1);
        assert_eq!(action.field_ordinal, 1);
    }

    #[test]
    fn create_pointer_relative() {
        let action = CreatePointerRelative::new(
            Address::new(0x1000),
            Address::new(0x2000),
            Address::new(0x1000),
        );
        assert_eq!(action.base_address, Address::new(0x2000));
    }

    #[test]
    fn export_to_c_action() {
        let action = ExportToCAction::new("/tmp/output.c");
        assert!(action.include_header);
        assert!(!action.signatures_only);
    }

    #[test]
    fn copy_signature() {
        let action = CopySignature::new(Address::new(0x1000), "int foo(int)");
        assert!(action.signature.contains("foo"));
    }

    #[test]
    fn rename_target_variants() {
        assert_ne!(RenameTarget::LocalVariable, RenameTarget::GlobalSymbol);
        assert_eq!(RenameTarget::Function, RenameTarget::Function);
    }

    #[test]
    fn retype_target_variants() {
        assert_ne!(RetypeTarget::LocalVariable, RetypeTarget::ReturnType);
    }
}
