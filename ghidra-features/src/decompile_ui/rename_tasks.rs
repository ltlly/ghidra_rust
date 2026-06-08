//! Rename/retype tasks -- Rust port of the rename and retype task classes
//! from `ghidra.app.plugin.core.decompile.actions`.
//!
//! This module provides the background tasks that perform the actual
//! renaming and retyping of symbols, variables, and fields as requested
//! by the decompiler UI actions.
//!
//! # Architecture
//!
//! ```text
//! RenameTask (abstract base)
//!   ├── RenameVariableTask       -- rename a local/global variable
//!   ├── RenameStructFieldTask    -- rename a field in a struct
//!   ├── RenameUnionFieldTask     -- rename a field in a union
//!   ├── RenameStructBitFieldTask -- rename a bit-field in a struct
//!   └── IsolateVariableTask      -- split a merged variable and rename
//!
//! RetypeFieldTask (abstract base)
//!   ├── RetypeStructFieldTask    -- change the type of a struct field
//!   └── RetypeUnionFieldTask     -- change the type of a union field
//! ```

use ghidra_core::addr::Address;

use super::action_context::ClangTokenRef;

// ---------------------------------------------------------------------------
// SourceType -- where a symbol definition came from
// ---------------------------------------------------------------------------

/// The source of a symbol definition.
///
/// Mirrors `SourceType` from the Ghidra symbol table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceType {
    /// The symbol was created by the default analysis.
    Default,
    /// The symbol was imported from an external source.
    Imported,
    /// The symbol was defined by the user.
    UserDefined,
    /// The symbol was created by an analyzer.
    Analysis,
}

impl Default for SourceType {
    fn default() -> Self {
        SourceType::UserDefined
    }
}

// ---------------------------------------------------------------------------
// DataTypeInfo -- lightweight data type reference
// ---------------------------------------------------------------------------

/// A lightweight reference to a data type.
///
/// In Ghidra this would be a `DataType` object.  Here we store just
/// enough information for the rename/retype tasks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataTypeInfo {
    /// The data type name (e.g., "int", "char *", "my_struct").
    pub name: String,
    /// The size in bytes.
    pub size: usize,
    /// Whether this is a pointer type.
    pub is_pointer: bool,
    /// Whether this is an array type.
    pub is_array: bool,
    /// Whether this is a structure type.
    pub is_struct: bool,
    /// Whether this is a union type.
    pub is_union: bool,
    /// Whether this is an undefined type.
    pub is_undefined: bool,
}

impl DataTypeInfo {
    /// Create a new data type info.
    pub fn new(name: impl Into<String>, size: usize) -> Self {
        Self {
            name: name.into(),
            size,
            is_pointer: false,
            is_array: false,
            is_struct: false,
            is_union: false,
            is_undefined: false,
        }
    }

    /// Create an undefined data type.
    pub fn undefined(size: usize) -> Self {
        Self {
            name: "undefined".into(),
            size,
            is_pointer: false,
            is_array: false,
            is_struct: false,
            is_union: false,
            is_undefined: true,
        }
    }

    /// Create a pointer data type.
    pub fn pointer(target: impl Into<String>, size: usize) -> Self {
        Self {
            name: format!("{}*", target.into()),
            size,
            is_pointer: true,
            is_array: false,
            is_struct: false,
            is_union: false,
            is_undefined: false,
        }
    }
}

// ---------------------------------------------------------------------------
// SymbolInfo -- lightweight symbol reference
// ---------------------------------------------------------------------------

/// A lightweight reference to a symbol in the program.
///
/// In Ghidra this would be a `HighSymbol` / `Symbol` object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolInfo {
    /// The symbol name.
    pub name: String,
    /// The symbol address.
    pub address: Address,
    /// Whether the name is locked (reserved by the system).
    pub name_locked: bool,
    /// The source of this symbol.
    pub source: SourceType,
    /// The data type of the symbol.
    pub data_type: DataTypeInfo,
    /// Whether this is a parameter.
    pub is_parameter: bool,
    /// Whether this is a local variable.
    pub is_local: bool,
}

impl SymbolInfo {
    /// Create a new symbol info.
    pub fn new(
        name: impl Into<String>,
        address: Address,
        data_type: DataTypeInfo,
    ) -> Self {
        Self {
            name: name.into(),
            address,
            name_locked: false,
            source: SourceType::UserDefined,
            data_type,
            is_parameter: false,
            is_local: true,
        }
    }
}

// ---------------------------------------------------------------------------
// FieldInfo -- information about a struct/union field
// ---------------------------------------------------------------------------

/// Information about a field in a composite (struct/union) data type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldInfo {
    /// The field name.
    pub name: String,
    /// The byte offset of the field within the struct.
    pub offset: usize,
    /// The data type of the field.
    pub data_type: DataTypeInfo,
    /// The bit offset within the containing storage unit (for bit-fields).
    pub bit_offset: Option<usize>,
    /// The bit size (for bit-fields).
    pub bit_size: Option<usize>,
    /// The name of the containing struct/union.
    pub parent_name: String,
    /// Whether the parent is a union (vs struct).
    pub parent_is_union: bool,
}

impl FieldInfo {
    /// Create a new field info.
    pub fn new(
        name: impl Into<String>,
        offset: usize,
        data_type: DataTypeInfo,
        parent_name: impl Into<String>,
        parent_is_union: bool,
    ) -> Self {
        Self {
            name: name.into(),
            offset,
            data_type,
            bit_offset: None,
            bit_size: None,
            parent_name: parent_name.into(),
            parent_is_union,
        }
    }

    /// Create a bit-field info.
    pub fn bit_field(
        name: impl Into<String>,
        offset: usize,
        bit_offset: usize,
        bit_size: usize,
        parent_name: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            offset,
            data_type: DataTypeInfo::new("uint", 1),
            bit_offset: Some(bit_offset),
            bit_size: Some(bit_size),
            parent_name: parent_name.into(),
            parent_is_union: false,
        }
    }

    /// Whether this is a bit-field.
    pub fn is_bit_field(&self) -> bool {
        self.bit_offset.is_some() && self.bit_size.is_some()
    }
}

// ---------------------------------------------------------------------------
// TaskResult -- result of a rename/retype task
// ---------------------------------------------------------------------------

/// The result of executing a rename or retype task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskResult {
    /// The task completed successfully.
    Success(String),
    /// The task was cancelled by the user.
    Cancelled,
    /// The task failed with an error.
    Error(String),
    /// The task requires a dialog (input or confirmation).
    NeedsDialog(DialogSpec),
}

/// A dialog specification for user input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialogSpec {
    /// The dialog title.
    pub title: String,
    /// The prompt label.
    pub label: String,
    /// The default (pre-filled) value.
    pub default_value: String,
}

// ---------------------------------------------------------------------------
// RenameTask -- abstract base for rename operations
// ---------------------------------------------------------------------------

/// The base trait for all rename tasks.
///
/// A rename task:
/// 1. Validates the new name (checking for duplicates, reserved names, etc.)
/// 2. Commits the rename to the program database.
/// 3. Notifies the provider that the token was renamed.
///
/// Mirrors the abstract `RenameTask` Java class.
pub trait RenameTask {
    /// The transaction name (e.g., "Rename Local Variable").
    fn transaction_name(&self) -> &str;

    /// The old (current) name.
    fn old_name(&self) -> &str;

    /// Validate a proposed new name.
    ///
    /// Returns `Ok(())` if valid, `Err(message)` if not.
    fn validate(&self, new_name: &str) -> Result<(), String>;

    /// Commit the rename with the given new name.
    ///
    /// Returns `Ok(())` on success.
    fn commit(&mut self, new_name: &str) -> Result<(), String>;

    /// Run the full rename task (validate + commit).
    ///
    /// Returns the task result.
    fn run(&mut self, new_name: &str) -> TaskResult {
        if new_name.is_empty() {
            return TaskResult::Error("Cannot have empty name".into());
        }

        let trimmed = new_name.trim();
        if trimmed == self.old_name() {
            return TaskResult::Cancelled;
        }

        if let Err(msg) = self.validate(trimmed) {
            return TaskResult::Error(msg);
        }

        match self.commit(trimmed) {
            Ok(()) => TaskResult::Success(format!("Renamed '{}' to '{}'", self.old_name(), trimmed)),
            Err(msg) => TaskResult::Error(msg),
        }
    }
}

// ---------------------------------------------------------------------------
// RenameVariableTask -- rename a local or global variable
// ---------------------------------------------------------------------------

/// Task: Rename a local or global variable in the decompiler.
///
/// This handles the common case of renaming a variable that the user
/// clicked on in the decompiler panel.  If the variable is part of a
/// merge group and the user pointed at a specific usage, the task may
/// split the merge group first.
///
/// Mirrors `RenameVariableTask` from the Java source.
#[derive(Debug, Clone)]
pub struct RenameVariableTask {
    /// The symbol being renamed.
    symbol: SymbolInfo,
    /// The token at the cursor.
    token: ClangTokenRef,
    /// The source type for the rename.
    source_type: SourceType,
    /// Whether all parameters must be committed before renaming.
    commit_required: bool,
    /// The function name (for duplicate checking).
    function_name: String,
    /// All existing symbol names in the function (for duplicate checking).
    existing_names: Vec<String>,
}

impl RenameVariableTask {
    /// Create a new rename variable task.
    pub fn new(
        symbol: SymbolInfo,
        token: ClangTokenRef,
        source_type: SourceType,
        function_name: impl Into<String>,
    ) -> Self {
        Self {
            symbol,
            token,
            source_type,
            commit_required: false,
            function_name: function_name.into(),
            existing_names: Vec::new(),
        }
    }

    /// Set the list of existing symbol names in the function.
    pub fn set_existing_names(&mut self, names: Vec<String>) {
        self.existing_names = names;
    }

    /// Set whether parameter commit is required.
    pub fn set_commit_required(&mut self, required: bool) {
        self.commit_required = required;
    }

    /// Get the symbol being renamed.
    pub fn symbol(&self) -> &SymbolInfo {
        &self.symbol
    }

    /// Get the token at the cursor.
    pub fn token(&self) -> &ClangTokenRef {
        &self.token
    }

    /// Check if a name is already used by another symbol in the function.
    fn is_duplicate_name(&self, name: &str) -> bool {
        self.existing_names.iter().any(|n| n == name)
    }
}

impl RenameTask for RenameVariableTask {
    fn transaction_name(&self) -> &str {
        "Rename Local Variable"
    }

    fn old_name(&self) -> &str {
        &self.symbol.name
    }

    fn validate(&self, new_name: &str) -> Result<(), String> {
        if new_name.is_empty() {
            return Err("Cannot have empty name".into());
        }

        if self.is_duplicate_name(new_name) {
            return Err("Duplicate name".into());
        }

        // In the full implementation:
        // 1. Check if the symbol is name-locked
        // 2. If so, check if this instance is directly mapped
        // 3. If not mapped, the rename is not allowed
        // 4. Call AbstractDecompilerAction.checkFullCommit() to see
        //    if parameters need to be committed first

        Ok(())
    }

    fn commit(&mut self, new_name: &str) -> Result<(), String> {
        // In the full implementation:
        // 1. If commit_required, call HighFunctionDBUtil.commitParamsToDatabase()
        // 2. If exact_spot is set and symbol is not name-locked, call
        //    hfunction.splitOutMergeGroup() to isolate the variable
        // 3. Call HighFunctionDBUtil.updateDBVariable(highSymbol, newName, null, srctype)

        self.symbol.name = new_name.to_string();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RenameStructFieldTask -- rename a field in a struct
// ---------------------------------------------------------------------------

/// Task: Rename a field in a structure data type.
///
/// Mirrors `RenameStructFieldTask` from the Java source.
#[derive(Debug, Clone)]
pub struct RenameStructFieldTask {
    /// The field being renamed.
    field: FieldInfo,
    /// The token at the cursor.
    token: ClangTokenRef,
    /// Existing field names in the parent struct (for duplicate checking).
    existing_field_names: Vec<String>,
}

impl RenameStructFieldTask {
    /// Create a new rename struct field task.
    pub fn new(field: FieldInfo, token: ClangTokenRef) -> Self {
        Self {
            field,
            token,
            existing_field_names: Vec::new(),
        }
    }

    /// Set the list of existing field names in the parent struct.
    pub fn set_existing_field_names(&mut self, names: Vec<String>) {
        self.existing_field_names = names;
    }

    /// Get the field being renamed.
    pub fn field(&self) -> &FieldInfo {
        &self.field
    }
}

impl RenameTask for RenameStructFieldTask {
    fn transaction_name(&self) -> &str {
        "Rename Structure Field"
    }

    fn old_name(&self) -> &str {
        &self.field.name
    }

    fn validate(&self, new_name: &str) -> Result<(), String> {
        if new_name.is_empty() {
            return Err("Cannot have empty name".into());
        }

        if self.existing_field_names.iter().any(|n| n == new_name) {
            return Err(format!(
                "Field '{}' already exists in {}",
                new_name, self.field.parent_name
            ));
        }

        Ok(())
    }

    fn commit(&mut self, new_name: &str) -> Result<(), String> {
        // In the full implementation:
        // 1. Get the DataTypeManager from the program
        // 2. Find the structure by name
        // 3. Find the field at the given offset
        // 4. Rename the field
        // 5. Apply the change to the data type manager

        self.field.name = new_name.to_string();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RenameUnionFieldTask -- rename a field in a union
// ---------------------------------------------------------------------------

/// Task: Rename a field in a union data type.
///
/// Mirrors `RenameUnionFieldTask` from the Java source.
#[derive(Debug, Clone)]
pub struct RenameUnionFieldTask {
    /// The field being renamed.
    field: FieldInfo,
    /// The token at the cursor.
    token: ClangTokenRef,
    /// Existing field names in the parent union (for duplicate checking).
    existing_field_names: Vec<String>,
}

impl RenameUnionFieldTask {
    /// Create a new rename union field task.
    pub fn new(field: FieldInfo, token: ClangTokenRef) -> Self {
        Self {
            field,
            token,
            existing_field_names: Vec::new(),
        }
    }

    /// Set the list of existing field names in the parent union.
    pub fn set_existing_field_names(&mut self, names: Vec<String>) {
        self.existing_field_names = names;
    }

    /// Get the field being renamed.
    pub fn field(&self) -> &FieldInfo {
        &self.field
    }
}

impl RenameTask for RenameUnionFieldTask {
    fn transaction_name(&self) -> &str {
        "Rename Union Field"
    }

    fn old_name(&self) -> &str {
        &self.field.name
    }

    fn validate(&self, new_name: &str) -> Result<(), String> {
        if new_name.is_empty() {
            return Err("Cannot have empty name".into());
        }

        if self.existing_field_names.iter().any(|n| n == new_name) {
            return Err(format!(
                "Field '{}' already exists in {}",
                new_name, self.field.parent_name
            ));
        }

        Ok(())
    }

    fn commit(&mut self, new_name: &str) -> Result<(), String> {
        // In the full implementation:
        // 1. Get the DataTypeManager from the program
        // 2. Find the union by name
        // 3. Find the field by name
        // 4. Rename the field
        // 5. Apply the change

        self.field.name = new_name.to_string();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RenameStructBitFieldTask -- rename a bit-field in a struct
// ---------------------------------------------------------------------------

/// Task: Rename a bit-field in a structure data type.
///
/// Mirrors `RenameStructBitFieldTask` from the Java source.
#[derive(Debug, Clone)]
pub struct RenameStructBitFieldTask {
    /// The bit-field being renamed.
    field: FieldInfo,
    /// The token at the cursor.
    token: ClangTokenRef,
    /// Existing field names in the parent struct (for duplicate checking).
    existing_field_names: Vec<String>,
}

impl RenameStructBitFieldTask {
    /// Create a new rename struct bit-field task.
    pub fn new(field: FieldInfo, token: ClangTokenRef) -> Self {
        Self {
            field,
            token,
            existing_field_names: Vec::new(),
        }
    }

    /// Set the list of existing field names in the parent struct.
    pub fn set_existing_field_names(&mut self, names: Vec<String>) {
        self.existing_field_names = names;
    }

    /// Get the bit-field being renamed.
    pub fn field(&self) -> &FieldInfo {
        &self.field
    }
}

impl RenameTask for RenameStructBitFieldTask {
    fn transaction_name(&self) -> &str {
        "Rename Structure Bit Field"
    }

    fn old_name(&self) -> &str {
        &self.field.name
    }

    fn validate(&self, new_name: &str) -> Result<(), String> {
        if new_name.is_empty() {
            return Err("Cannot have empty name".into());
        }

        if self.existing_field_names.iter().any(|n| n == new_name) {
            return Err(format!(
                "Field '{}' already exists in {}",
                new_name, self.field.parent_name
            ));
        }

        Ok(())
    }

    fn commit(&mut self, new_name: &str) -> Result<(), String> {
        // In the full implementation:
        // 1. Get the DataTypeManager
        // 2. Find the structure
        // 3. Find the bit-field at the given offset/bit-offset
        // 4. Rename the bit-field
        // 5. Apply the change

        self.field.name = new_name.to_string();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// IsolateVariableTask -- split a merged variable and rename
// ---------------------------------------------------------------------------

/// Task: Isolate a specific instance of a merged variable and give it
/// a new name.
///
/// In the decompiler, multiple uses of a variable may be merged into a
/// single high-level variable.  This task splits out the specific
/// instance the user clicked on into its own variable, then renames it.
///
/// Mirrors `IsolateVariableTask` from the Java source.
#[derive(Debug, Clone)]
pub struct IsolateVariableTask {
    /// The symbol being isolated and renamed.
    symbol: SymbolInfo,
    /// The token at the cursor.
    token: ClangTokenRef,
    /// The source type for the new symbol.
    source_type: SourceType,
    /// The original name (before isolation).
    original_name: String,
    /// Whether the name is locked (reserved by another instance).
    name_is_reserved: bool,
    /// Whether this instance is directly mapped to the reserved name.
    instance_is_mapped: bool,
    /// Existing symbol names in the function.
    existing_names: Vec<String>,
}

impl IsolateVariableTask {
    /// Create a new isolate variable task.
    pub fn new(
        symbol: SymbolInfo,
        token: ClangTokenRef,
        source_type: SourceType,
    ) -> Self {
        let original_name = symbol.name.clone();
        let name_is_reserved = symbol.name_locked;

        // In the full implementation:
        // instanceIsMapped = (vn.getMergeGroup() == vn.getHigh().getRepresentative().getMergeGroup())
        let instance_is_mapped = false;

        Self {
            symbol,
            token,
            source_type,
            original_name,
            name_is_reserved,
            instance_is_mapped,
            existing_names: Vec::new(),
        }
    }

    /// Set the list of existing symbol names in the function.
    pub fn set_existing_names(&mut self, names: Vec<String>) {
        self.existing_names = names;
    }

    /// Get the symbol being isolated.
    pub fn symbol(&self) -> &SymbolInfo {
        &self.symbol
    }

    /// Whether the original name is reserved by another instance.
    pub fn is_name_reserved(&self) -> bool {
        self.name_is_reserved
    }

    /// Whether this instance is mapped to the reserved name.
    pub fn is_instance_mapped(&self) -> bool {
        self.instance_is_mapped
    }
}

impl RenameTask for IsolateVariableTask {
    fn transaction_name(&self) -> &str {
        "Name New Variable"
    }

    fn old_name(&self) -> &str {
        &self.original_name
    }

    fn validate(&self, new_name: &str) -> Result<(), String> {
        if new_name.is_empty() {
            return Err("Cannot have empty name".into());
        }

        // If the user wants to keep the original name:
        if new_name == self.original_name {
            if self.name_is_reserved && !self.instance_is_mapped {
                return Err(format!(
                    "The name \"{}\" is attached to another instance",
                    self.original_name
                ));
            }
            return Ok(());
        }

        // Check for duplicate names in the function.
        if self.existing_names.iter().any(|n| n == new_name) {
            return Err("Duplicate name".into());
        }

        Ok(())
    }

    fn commit(&mut self, new_name: &str) -> Result<(), String> {
        // In the full implementation:
        // 1. Varnode vn = tokenAtCursor.getVarnode()
        // 2. HighVariable highVariable = highFunction.splitOutMergeGroup(vn.getHigh(), vn)
        // 3. highSymbol = highVariable.getSymbol()
        // 4. DataType dataType = highSymbol.getDataType()
        // 5. If undefined, use unsigned integer of equivalent size
        // 6. HighFunctionDBUtil.updateDBVariable(highSymbol, newName, dataType, srcType)

        self.symbol.name = new_name.to_string();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RetypeFieldTask -- abstract base for retype operations
// ---------------------------------------------------------------------------

/// The base trait for all retype (change data type) tasks.
///
/// A retype task:
/// 1. Validates the new data type.
/// 2. Commits the type change to the program database.
/// 3. Triggers a re-decompile.
pub trait RetypeFieldTask {
    /// The transaction name.
    fn transaction_name(&self) -> &str;

    /// The field being retyped.
    fn field(&self) -> &FieldInfo;

    /// Validate the new data type.
    fn validate(&self, new_type: &DataTypeInfo) -> Result<(), String>;

    /// Commit the type change.
    fn commit(&mut self, new_type: &DataTypeInfo) -> Result<(), String>;

    /// Run the full retype task.
    fn run(&mut self, new_type: &DataTypeInfo) -> TaskResult {
        if let Err(msg) = self.validate(new_type) {
            return TaskResult::Error(msg);
        }

        match self.commit(new_type) {
            Ok(()) => TaskResult::Success(format!(
                "Retyped '{}' to '{}'",
                self.field().name,
                new_type.name
            )),
            Err(msg) => TaskResult::Error(msg),
        }
    }
}

// ---------------------------------------------------------------------------
// RetypeStructFieldTask -- change the type of a struct field
// ---------------------------------------------------------------------------

/// Task: Change the data type of a field in a structure.
///
/// Mirrors `RetypeStructFieldTask` from the Java source.
#[derive(Debug, Clone)]
pub struct RetypeStructFieldTask {
    /// The field being retyped.
    field: FieldInfo,
    /// The token at the cursor.
    token: ClangTokenRef,
}

impl RetypeStructFieldTask {
    /// Create a new retype struct field task.
    pub fn new(field: FieldInfo, token: ClangTokenRef) -> Self {
        Self { field, token }
    }
}

impl RetypeFieldTask for RetypeStructFieldTask {
    fn transaction_name(&self) -> &str {
        "Retype Structure Field"
    }

    fn field(&self) -> &FieldInfo {
        &self.field
    }

    fn validate(&self, new_type: &DataTypeInfo) -> Result<(), String> {
        if new_type.is_undefined {
            return Err("Cannot set field type to undefined".into());
        }
        if new_type.size == 0 {
            return Err("Field type cannot have zero size".into());
        }
        Ok(())
    }

    fn commit(&mut self, new_type: &DataTypeInfo) -> Result<(), String> {
        // In the full implementation:
        // 1. Get the DataTypeManager
        // 2. Find the structure
        // 3. Find the field at the offset
        // 4. Replace the field's data type
        // 5. Apply the change

        self.field.data_type = new_type.clone();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RetypeUnionFieldTask -- change the type of a union field
// ---------------------------------------------------------------------------

/// Task: Change the data type of a field in a union.
///
/// Mirrors `RetypeUnionFieldTask` from the Java source.
#[derive(Debug, Clone)]
pub struct RetypeUnionFieldTask {
    /// The field being retyped.
    field: FieldInfo,
    /// The token at the cursor.
    token: ClangTokenRef,
}

impl RetypeUnionFieldTask {
    /// Create a new retype union field task.
    pub fn new(field: FieldInfo, token: ClangTokenRef) -> Self {
        Self { field, token }
    }
}

impl RetypeFieldTask for RetypeUnionFieldTask {
    fn transaction_name(&self) -> &str {
        "Retype Union Field"
    }

    fn field(&self) -> &FieldInfo {
        &self.field
    }

    fn validate(&self, new_type: &DataTypeInfo) -> Result<(), String> {
        if new_type.is_undefined {
            return Err("Cannot set field type to undefined".into());
        }
        if new_type.size == 0 {
            return Err("Field type cannot have zero size".into());
        }
        Ok(())
    }

    fn commit(&mut self, new_type: &DataTypeInfo) -> Result<(), String> {
        // In the full implementation:
        // 1. Get the DataTypeManager
        // 2. Find the union
        // 3. Find the field by name
        // 4. Replace the field's data type
        // 5. Apply the change

        self.field.data_type = new_type.clone();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helper: check if a symbol name exists in a function
// ---------------------------------------------------------------------------

/// Check if a symbol with the given name exists in the function.
///
/// This is a helper used by multiple rename tasks.  In Ghidra this
/// calls `symbolTable.getSymbols(name, function)`.
pub fn is_symbol_in_function(existing_names: &[String], name: &str) -> bool {
    existing_names.iter().any(|n| n == name)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- SourceType ---

    #[test]
    fn test_source_type_default() {
        assert_eq!(SourceType::default(), SourceType::UserDefined);
    }

    // --- DataTypeInfo ---

    #[test]
    fn test_data_type_info_new() {
        let dt = DataTypeInfo::new("int", 4);
        assert_eq!(dt.name, "int");
        assert_eq!(dt.size, 4);
        assert!(!dt.is_pointer);
        assert!(!dt.is_undefined);
    }

    #[test]
    fn test_data_type_info_undefined() {
        let dt = DataTypeInfo::undefined(8);
        assert!(dt.is_undefined);
        assert_eq!(dt.size, 8);
    }

    #[test]
    fn test_data_type_info_pointer() {
        let dt = DataTypeInfo::pointer("char", 8);
        assert!(dt.is_pointer);
        assert_eq!(dt.name, "char*");
    }

    // --- SymbolInfo ---

    #[test]
    fn test_symbol_info_new() {
        let sym = SymbolInfo::new(
            "myVar",
            Address::new(0x1000),
            DataTypeInfo::new("int", 4),
        );
        assert_eq!(sym.name, "myVar");
        assert_eq!(sym.address, Address::new(0x1000));
        assert!(!sym.name_locked);
        assert!(sym.is_local);
    }

    // --- FieldInfo ---

    #[test]
    fn test_field_info_new() {
        let field = FieldInfo::new(
            "x",
            0,
            DataTypeInfo::new("int", 4),
            "Point",
            false,
        );
        assert_eq!(field.name, "x");
        assert_eq!(field.offset, 0);
        assert_eq!(field.parent_name, "Point");
        assert!(!field.parent_is_union);
        assert!(!field.is_bit_field());
    }

    #[test]
    fn test_field_info_bit_field() {
        let field = FieldInfo::bit_field("flags", 4, 3, 5, "Header");
        assert!(field.is_bit_field());
        assert_eq!(field.bit_offset, Some(3));
        assert_eq!(field.bit_size, Some(5));
    }

    // --- RenameVariableTask ---

    #[test]
    fn test_rename_variable_task_new() {
        let sym = SymbolInfo::new("x", Address::new(0x1000), DataTypeInfo::new("int", 4));
        let token = ClangTokenRef::new("x", 3, 0, false, None, 10);
        let task = RenameVariableTask::new(sym, token, SourceType::UserDefined, "main");
        assert_eq!(task.old_name(), "x");
        assert_eq!(task.transaction_name(), "Rename Local Variable");
    }

    #[test]
    fn test_rename_variable_task_validate_ok() {
        let sym = SymbolInfo::new("x", Address::new(0x1000), DataTypeInfo::new("int", 4));
        let token = ClangTokenRef::new("x", 3, 0, false, None, 10);
        let mut task = RenameVariableTask::new(sym, token, SourceType::UserDefined, "main");
        task.set_existing_names(vec!["y".into(), "z".into()]);
        assert!(task.validate("new_name").is_ok());
    }

    #[test]
    fn test_rename_variable_task_validate_duplicate() {
        let sym = SymbolInfo::new("x", Address::new(0x1000), DataTypeInfo::new("int", 4));
        let token = ClangTokenRef::new("x", 3, 0, false, None, 10);
        let mut task = RenameVariableTask::new(sym, token, SourceType::UserDefined, "main");
        task.set_existing_names(vec!["y".into(), "z".into()]);
        assert!(task.validate("y").is_err());
    }

    #[test]
    fn test_rename_variable_task_run() {
        let sym = SymbolInfo::new("x", Address::new(0x1000), DataTypeInfo::new("int", 4));
        let token = ClangTokenRef::new("x", 3, 0, false, None, 10);
        let mut task = RenameVariableTask::new(sym, token, SourceType::UserDefined, "main");
        let result = task.run("new_var");
        match result {
            TaskResult::Success(msg) => assert!(msg.contains("new_var")),
            _ => panic!("expected Success"),
        }
    }

    #[test]
    fn test_rename_variable_task_run_same_name() {
        let sym = SymbolInfo::new("x", Address::new(0x1000), DataTypeInfo::new("int", 4));
        let token = ClangTokenRef::new("x", 3, 0, false, None, 10);
        let mut task = RenameVariableTask::new(sym, token, SourceType::UserDefined, "main");
        let result = task.run("x");
        assert_eq!(result, TaskResult::Cancelled);
    }

    #[test]
    fn test_rename_variable_task_run_empty() {
        let sym = SymbolInfo::new("x", Address::new(0x1000), DataTypeInfo::new("int", 4));
        let token = ClangTokenRef::new("x", 3, 0, false, None, 10);
        let mut task = RenameVariableTask::new(sym, token, SourceType::UserDefined, "main");
        let result = task.run("");
        assert!(matches!(result, TaskResult::Error(_)));
    }

    // --- RenameStructFieldTask ---

    #[test]
    fn test_rename_struct_field_task_new() {
        let field = FieldInfo::new("x", 0, DataTypeInfo::new("int", 4), "Point", false);
        let token = ClangTokenRef::new("x", 5, 0, false, None, 20);
        let task = RenameStructFieldTask::new(field, token);
        assert_eq!(task.old_name(), "x");
        assert_eq!(task.transaction_name(), "Rename Structure Field");
    }

    #[test]
    fn test_rename_struct_field_task_validate_ok() {
        let field = FieldInfo::new("x", 0, DataTypeInfo::new("int", 4), "Point", false);
        let token = ClangTokenRef::new("x", 5, 0, false, None, 20);
        let mut task = RenameStructFieldTask::new(field, token);
        task.set_existing_field_names(vec!["y".into(), "z".into()]);
        assert!(task.validate("new_x").is_ok());
    }

    #[test]
    fn test_rename_struct_field_task_validate_duplicate() {
        let field = FieldInfo::new("x", 0, DataTypeInfo::new("int", 4), "Point", false);
        let token = ClangTokenRef::new("x", 5, 0, false, None, 20);
        let mut task = RenameStructFieldTask::new(field, token);
        task.set_existing_field_names(vec!["y".into(), "z".into()]);
        assert!(task.validate("y").is_err());
    }

    // --- RenameUnionFieldTask ---

    #[test]
    fn test_rename_union_field_task_new() {
        let field = FieldInfo::new("asInt", 0, DataTypeInfo::new("int", 4), "FloatBits", true);
        let token = ClangTokenRef::new("asInt", 3, 0, false, None, 5);
        let task = RenameUnionFieldTask::new(field, token);
        assert_eq!(task.old_name(), "asInt");
        assert_eq!(task.transaction_name(), "Rename Union Field");
    }

    // --- RenameStructBitFieldTask ---

    #[test]
    fn test_rename_struct_bit_field_task_new() {
        let field = FieldInfo::bit_field("flags", 4, 3, 5, "Header");
        let token = ClangTokenRef::new("flags", 7, 0, false, None, 30);
        let task = RenameStructBitFieldTask::new(field, token);
        assert_eq!(task.old_name(), "flags");
        assert_eq!(task.transaction_name(), "Rename Structure Bit Field");
    }

    // --- IsolateVariableTask ---

    #[test]
    fn test_isolate_variable_task_new() {
        let sym = SymbolInfo {
            name: "x".into(),
            address: Address::new(0x1000),
            name_locked: true,
            source: SourceType::UserDefined,
            data_type: DataTypeInfo::new("int", 4),
            is_parameter: false,
            is_local: true,
        };
        let token = ClangTokenRef::new("x", 3, 0, false, None, 10);
        let task = IsolateVariableTask::new(sym, token, SourceType::UserDefined);
        assert_eq!(task.old_name(), "x");
        assert!(task.is_name_reserved());
        assert!(!task.is_instance_mapped());
    }

    #[test]
    fn test_isolate_variable_task_validate_keep_name_reserved() {
        let sym = SymbolInfo {
            name: "x".into(),
            address: Address::new(0x1000),
            name_locked: true,
            source: SourceType::UserDefined,
            data_type: DataTypeInfo::new("int", 4),
            is_parameter: false,
            is_local: true,
        };
        let token = ClangTokenRef::new("x", 3, 0, false, None, 10);
        let task = IsolateVariableTask::new(sym, token, SourceType::UserDefined);
        // Keeping the original name when reserved and not mapped should fail.
        assert!(task.validate("x").is_err());
    }

    #[test]
    fn test_isolate_variable_task_validate_new_name() {
        let sym = SymbolInfo::new("x", Address::new(0x1000), DataTypeInfo::new("int", 4));
        let token = ClangTokenRef::new("x", 3, 0, false, None, 10);
        let mut task = IsolateVariableTask::new(sym, token, SourceType::UserDefined);
        task.set_existing_names(vec!["y".into()]);
        assert!(task.validate("new_name").is_ok());
    }

    #[test]
    fn test_isolate_variable_task_validate_duplicate() {
        let sym = SymbolInfo::new("x", Address::new(0x1000), DataTypeInfo::new("int", 4));
        let token = ClangTokenRef::new("x", 3, 0, false, None, 10);
        let mut task = IsolateVariableTask::new(sym, token, SourceType::UserDefined);
        task.set_existing_names(vec!["y".into()]);
        assert!(task.validate("y").is_err());
    }

    // --- RetypeStructFieldTask ---

    #[test]
    fn test_retype_struct_field_task_new() {
        let field = FieldInfo::new("x", 0, DataTypeInfo::new("int", 4), "Point", false);
        let token = ClangTokenRef::new("x", 5, 0, false, None, 20);
        let task = RetypeStructFieldTask::new(field, token);
        assert_eq!(task.field().name, "x");
        assert_eq!(task.transaction_name(), "Retype Structure Field");
    }

    #[test]
    fn test_retype_struct_field_task_validate_ok() {
        let field = FieldInfo::new("x", 0, DataTypeInfo::new("int", 4), "Point", false);
        let token = ClangTokenRef::new("x", 5, 0, false, None, 20);
        let task = RetypeStructFieldTask::new(field, token);
        let new_type = DataTypeInfo::new("float", 4);
        assert!(task.validate(&new_type).is_ok());
    }

    #[test]
    fn test_retype_struct_field_task_validate_undefined() {
        let field = FieldInfo::new("x", 0, DataTypeInfo::new("int", 4), "Point", false);
        let token = ClangTokenRef::new("x", 5, 0, false, None, 20);
        let task = RetypeStructFieldTask::new(field, token);
        let new_type = DataTypeInfo::undefined(4);
        assert!(task.validate(&new_type).is_err());
    }

    #[test]
    fn test_retype_struct_field_task_validate_zero_size() {
        let field = FieldInfo::new("x", 0, DataTypeInfo::new("int", 4), "Point", false);
        let token = ClangTokenRef::new("x", 5, 0, false, None, 20);
        let task = RetypeStructFieldTask::new(field, token);
        let new_type = DataTypeInfo::new("void", 0);
        assert!(task.validate(&new_type).is_err());
    }

    #[test]
    fn test_retype_struct_field_task_run() {
        let field = FieldInfo::new("x", 0, DataTypeInfo::new("int", 4), "Point", false);
        let token = ClangTokenRef::new("x", 5, 0, false, None, 20);
        let mut task = RetypeStructFieldTask::new(field, token);
        let new_type = DataTypeInfo::new("float", 4);
        let result = task.run(&new_type);
        match result {
            TaskResult::Success(msg) => {
                assert!(msg.contains("x"));
                assert!(msg.contains("float"));
            }
            _ => panic!("expected Success"),
        }
    }

    // --- RetypeUnionFieldTask ---

    #[test]
    fn test_retype_union_field_task_new() {
        let field = FieldInfo::new("asInt", 0, DataTypeInfo::new("int", 4), "FloatBits", true);
        let token = ClangTokenRef::new("asInt", 3, 0, false, None, 5);
        let task = RetypeUnionFieldTask::new(field, token);
        assert_eq!(task.field().name, "asInt");
        assert_eq!(task.transaction_name(), "Retype Union Field");
    }

    #[test]
    fn test_retype_union_field_task_run() {
        let field = FieldInfo::new("asInt", 0, DataTypeInfo::new("int", 4), "FloatBits", true);
        let token = ClangTokenRef::new("asInt", 3, 0, false, None, 5);
        let mut task = RetypeUnionFieldTask::new(field, token);
        let new_type = DataTypeInfo::new("long", 8);
        let result = task.run(&new_type);
        match result {
            TaskResult::Success(msg) => {
                assert!(msg.contains("asInt"));
                assert!(msg.contains("long"));
            }
            _ => panic!("expected Success"),
        }
    }

    // --- Helper ---

    #[test]
    fn test_is_symbol_in_function() {
        let names = vec!["x".into(), "y".into(), "z".into()];
        assert!(is_symbol_in_function(&names, "x"));
        assert!(!is_symbol_in_function(&names, "w"));
    }
}
