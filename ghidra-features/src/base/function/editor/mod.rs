//! Function editor -- ported from `ghidra.app.plugin.core.function.editor`.
//!
//! Provides the data model for the function signature editor.  The editor
//! allows users to modify a function's name, return type, calling convention,
//! parameters, and inline / no-return flags.
//!
//! # Types ported
//!
//! | Rust struct              | Java class                    |
//! |--------------------------|-------------------------------|
//! | `FunctionEditorModel`    | `FunctionEditorModel`         |
//! | `FunctionData`           | `FunctionData`                |
//! | `FunctionDataView`       | `FunctionDataView`            |
//! | `FunctionVariableData`   | `FunctionVariableData`        |
//! | `ParamInfo`              | `ParamInfo`                   |
//! | `VarnodeType`            | `VarnodeType`                 |
//! | `VarnodeInfo`            | `VarnodeInfo`                 |
//! | `ModelChangeListener`    | `ModelChangeListener`         |
//! | `ParameterTableModel`    | `ParameterTableModel`         |
//! | `StorageAddressModel`    | `StorageAddressModel`         |
//! | `VarnodeTableModel`      | `VarnodeTableModel`           |
//! | `FunctionSignatureTextField` | `FunctionSignatureTextField` |
//! | `RegisterDropDownModel`  | `RegisterDropDownSelectionDataModel` |
//! | `FunctionEditorDialogModel` | `FunctionEditorDialog`     |
//! | `CellEditors`            | Various cell editor models    |

pub mod storage_model;
pub mod varnode_table;
pub mod function_data_view;
pub mod signature_field;
pub mod register_dropdown;
pub mod dialog_model;
pub mod cell_editors;

pub use storage_model::StorageAddressModel;
pub use function_data_view::FunctionDataView;
pub use signature_field::{ColorField, SignatureRegionKind, compute_signature_colors, parse_signature, SignatureParts};
pub use register_dropdown::{RegisterDescriptor, RegisterDropDownModel, SearchMode};
pub use dialog_model::{FunctionEditorDialogModel, FunctionEditorDialogConfig, EditTargetKind, FunctionEditResult};
pub use cell_editors::{ParameterDataTypeCellEditorModel, VarnodeTypeCellEditorModel, VarnodeSizeCellEditorModel, VarnodeLocationRendererModel, VarnodeLocationCellEditorModel};

use std::fmt;


// ---------------------------------------------------------------------------
// VarnodeType
// ---------------------------------------------------------------------------

/// The kind of storage used for a variable.
///
/// Ported from `VarnodeType.java`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VarnodeType {
    /// A register variable.
    Register,
    /// A stack (memory) variable.
    Stack,
    /// A memory variable (absolute address).
    Memory,
}

impl VarnodeType {
    /// Returns `true` if this is a register storage.
    pub fn is_register(&self) -> bool {
        *self == Self::Register
    }

    /// Returns `true` if this is a stack storage.
    pub fn is_stack(&self) -> bool {
        *self == Self::Stack
    }

    /// Returns `true` if this is a memory storage.
    pub fn is_memory(&self) -> bool {
        *self == Self::Memory
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Register => "Register",
            Self::Stack => "Stack",
            Self::Memory => "Memory",
        }
    }
}

impl fmt::Display for VarnodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// VarnodeInfo
// ---------------------------------------------------------------------------

/// Information about a varnode (storage location).
///
/// Ported from `VarnodeInfo.java`.
///
/// # Example
///
/// ```
/// use ghidra_features::base::function::editor::*;
///
/// let vn = VarnodeInfo::register("RAX", 8);
/// assert_eq!(vn.varnode_type(), VarnodeType::Register);
/// assert_eq!(vn.size(), 8);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarnodeInfo {
    /// The kind of storage.
    varnode_type: VarnodeType,
    /// The register name (for register storage) or descriptive name.
    name: String,
    /// The storage size in bytes.
    size: usize,
    /// The offset (for stack: signed offset from frame base;
    /// for memory: absolute address).
    offset: i64,
}

impl VarnodeInfo {
    /// Creates a register varnode.
    pub fn register(name: impl Into<String>, size: usize) -> Self {
        Self {
            varnode_type: VarnodeType::Register,
            name: name.into(),
            size,
            offset: 0,
        }
    }

    /// Creates a stack varnode.
    pub fn stack(offset: i64, size: usize) -> Self {
        Self {
            varnode_type: VarnodeType::Stack,
            name: format!("Stack[{}]", offset),
            size,
            offset,
        }
    }

    /// Creates a memory varnode.
    pub fn memory(address: u64, size: usize) -> Self {
        Self {
            varnode_type: VarnodeType::Memory,
            name: format!("0x{:x}", address),
            size,
            offset: address as i64,
        }
    }

    /// Returns the varnode type.
    pub fn varnode_type(&self) -> VarnodeType {
        self.varnode_type
    }

    /// Returns the name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the size in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns the offset.
    pub fn offset(&self) -> i64 {
        self.offset
    }
}

impl fmt::Display for VarnodeInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} ({} bytes)",
            self.varnode_type.label(),
            self.name,
            self.size
        )
    }
}

// ---------------------------------------------------------------------------
// FunctionVariableData
// ---------------------------------------------------------------------------

/// Data about a function variable (parameter or local).
///
/// Ported from `FunctionVariableData.java`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionVariableData {
    /// The variable name.
    name: Option<String>,
    /// The ordinal (parameter index; -1 for return, >=0 for params).
    ordinal: i32,
    /// The data type name.
    data_type_name: String,
    /// The storage location.
    storage: VarnodeInfo,
    /// Whether this is a custom-storage variable.
    is_custom_storage: bool,
    /// Whether this is an auto-parameter.
    is_auto_parameter: bool,
    /// Whether this is the return value.
    is_return: bool,
}

impl FunctionVariableData {
    /// Creates a new parameter data.
    pub fn parameter(
        name: Option<String>,
        ordinal: i32,
        data_type_name: impl Into<String>,
        storage: VarnodeInfo,
    ) -> Self {
        Self {
            name,
            ordinal,
            data_type_name: data_type_name.into(),
            storage,
            is_custom_storage: false,
            is_auto_parameter: false,
            is_return: false,
        }
    }

    /// Creates a return value data.
    pub fn return_value(
        data_type_name: impl Into<String>,
        storage: VarnodeInfo,
    ) -> Self {
        Self {
            name: None,
            ordinal: -1,
            data_type_name: data_type_name.into(),
            storage,
            is_custom_storage: false,
            is_auto_parameter: false,
            is_return: true,
        }
    }

    /// Creates an auto-parameter data.
    pub fn auto_parameter(
        ordinal: i32,
        data_type_name: impl Into<String>,
        storage: VarnodeInfo,
    ) -> Self {
        Self {
            name: None,
            ordinal,
            data_type_name: data_type_name.into(),
            storage,
            is_custom_storage: false,
            is_auto_parameter: true,
            is_return: false,
        }
    }

    /// Returns the variable name.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns a display name (using default if no name set).
    pub fn display_name(&self) -> String {
        match &self.name {
            Some(n) => n.clone(),
            None => {
                if self.is_return {
                    "return".to_string()
                } else {
                    format!("param_{}", self.ordinal)
                }
            }
        }
    }

    /// Returns the ordinal.
    pub fn ordinal(&self) -> i32 {
        self.ordinal
    }

    /// Returns the data type name.
    pub fn data_type_name(&self) -> &str {
        &self.data_type_name
    }

    /// Returns the storage location.
    pub fn storage(&self) -> &VarnodeInfo {
        &self.storage
    }

    /// Returns whether this is a custom-storage variable.
    pub fn is_custom_storage(&self) -> bool {
        self.is_custom_storage
    }

    /// Returns whether this is an auto-parameter.
    pub fn is_auto_parameter(&self) -> bool {
        self.is_auto_parameter
    }

    /// Returns whether this is the return value.
    pub fn is_return(&self) -> bool {
        self.is_return
    }

    /// Sets the variable name.
    pub fn set_name(&mut self, name: Option<String>) {
        self.name = name;
    }

    /// Sets the data type name.
    pub fn set_data_type(&mut self, data_type_name: impl Into<String>) {
        self.data_type_name = data_type_name.into();
    }

    /// Sets the storage location.
    pub fn set_storage(&mut self, storage: VarnodeInfo) {
        self.storage = storage;
        self.is_custom_storage = true;
    }
}

// ---------------------------------------------------------------------------
// ParamInfo
// ---------------------------------------------------------------------------

/// Extended parameter information for the function editor.
///
/// Ported from `ParamInfo.java`.  This is the editor's model of a
/// function parameter, including support for storage conflicts and
/// forced-indirect parameters.
///
/// # Example
///
/// ```
/// use ghidra_features::base::function::editor::*;
///
/// let param = ParamInfo::new("buf", "void *", VarnodeInfo::register("RDI", 8), 0);
/// assert_eq!(param.name(), "buf");
/// assert_eq!(param.ordinal(), 0);
/// assert!(!param.is_forced_indirect());
/// ```
#[derive(Debug, Clone)]
pub struct ParamInfo {
    /// The parameter name (None if default).
    name: Option<String>,
    /// The formal data type name.
    formal_data_type: String,
    /// The storage location.
    storage: VarnodeInfo,
    /// Whether this uses custom storage.
    is_custom_storage: bool,
    /// The ordinal (parameter index).
    ordinal: i32,
    /// Whether there is a storage conflict.
    has_storage_conflict: bool,
    /// Whether this is forced indirect.
    is_forced_indirect: bool,
}

impl ParamInfo {
    /// Creates a new parameter info.
    pub fn new(
        name: impl Into<String>,
        formal_data_type: impl Into<String>,
        storage: VarnodeInfo,
        ordinal: i32,
    ) -> Self {
        Self {
            name: Some(name.into()),
            formal_data_type: formal_data_type.into(),
            storage,
            is_custom_storage: false,
            ordinal,
            has_storage_conflict: false,
            is_forced_indirect: false,
        }
    }

    /// Creates a parameter info with no name (uses default).
    pub fn with_default_name(
        formal_data_type: impl Into<String>,
        storage: VarnodeInfo,
        ordinal: i32,
    ) -> Self {
        Self {
            name: None,
            formal_data_type: formal_data_type.into(),
            storage,
            is_custom_storage: false,
            ordinal,
            has_storage_conflict: false,
            is_forced_indirect: false,
        }
    }

    /// Returns the parameter name (or default).
    pub fn name(&self) -> String {
        match &self.name {
            Some(n) => n.clone(),
            None => format!("param_{}", self.ordinal),
        }
    }

    /// Returns the raw name (None if default).
    pub fn raw_name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns the formal data type name.
    pub fn formal_data_type(&self) -> &str {
        &self.formal_data_type
    }

    /// Returns the storage location.
    pub fn storage(&self) -> &VarnodeInfo {
        &self.storage
    }

    /// Returns whether this uses custom storage.
    pub fn is_custom_storage(&self) -> bool {
        self.is_custom_storage
    }

    /// Returns the ordinal.
    pub fn ordinal(&self) -> i32 {
        self.ordinal
    }

    /// Returns whether this is the return parameter.
    pub fn is_return_parameter(&self) -> bool {
        self.ordinal == -1
    }

    /// Returns whether this is an auto-parameter.
    pub fn is_auto_parameter(&self) -> bool {
        self.storage.varnode_type() == VarnodeType::Register && self.is_forced_indirect
    }

    /// Returns whether there is a storage conflict.
    pub fn has_storage_conflict(&self) -> bool {
        self.has_storage_conflict
    }

    /// Returns whether this is forced indirect.
    pub fn is_forced_indirect(&self) -> bool {
        self.is_forced_indirect
    }

    /// Sets the parameter name.
    pub fn set_name(&mut self, name: Option<String>) {
        self.name = name;
    }

    /// Sets the formal data type.
    pub fn set_formal_data_type(&mut self, dt: impl Into<String>) {
        self.formal_data_type = dt.into();
    }

    /// Sets the storage location.
    pub fn set_storage(&mut self, storage: VarnodeInfo) {
        self.is_custom_storage = true;
        self.storage = storage;
    }

    /// Sets the storage conflict flag.
    pub fn set_has_storage_conflict(&mut self, conflict: bool) {
        self.has_storage_conflict = conflict;
    }

    /// Sets the forced-indirect flag.
    pub fn set_forced_indirect(&mut self, forced: bool) {
        self.is_forced_indirect = forced;
    }

    /// Sets the ordinal (parameter index).
    pub fn set_ordinal(&mut self, ordinal: i32) {
        self.ordinal = ordinal;
    }

    /// Creates a deep copy of this parameter info.
    pub fn copy(&self) -> Self {
        self.clone()
    }

    /// Returns whether this parameter is the same as another
    /// (ignoring identity).
    pub fn is_same(&self, other: &ParamInfo) -> bool {
        self.name == other.name
            && self.formal_data_type == other.formal_data_type
            && self.is_auto_parameter() == other.is_auto_parameter()
            && (!self.is_custom_storage || self.storage == other.storage)
    }
}

impl PartialEq for ParamInfo {
    fn eq(&self, other: &Self) -> bool {
        self.ordinal == other.ordinal && self.name == other.name
    }
}

impl Eq for ParamInfo {}

impl PartialOrd for ParamInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ParamInfo {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.ordinal
            .cmp(&other.ordinal)
            .then_with(|| self.name().cmp(&other.name()))
    }
}

impl fmt::Display for ParamInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} @ {}",
            self.name(),
            self.formal_data_type,
            self.storage
        )
    }
}

// ---------------------------------------------------------------------------
// FunctionData
// ---------------------------------------------------------------------------

/// Complete data about a function for the editor.
///
/// Ported from `FunctionData.java`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionData {
    /// The function name.
    name: String,
    /// The return data type name.
    return_type: String,
    /// The calling convention name.
    calling_convention: String,
    /// The parameters (including return value).
    parameters: Vec<FunctionVariableData>,
    /// Whether the function uses custom storage.
    is_custom_storage: bool,
    /// Whether the function is marked as inline.
    is_inline: bool,
    /// Whether the function is marked as no-return.
    is_no_return: bool,
    /// The call fixup name, if any.
    call_fixup: Option<String>,
    /// The stack purge size, if known.
    stack_purge_size: Option<i32>,
    /// Whether the function has a varargs parameter.
    has_var_args: bool,
}

impl FunctionData {
    /// Creates function data from basic info.
    pub fn new(
        name: impl Into<String>,
        return_type: impl Into<String>,
        calling_convention: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            return_type: return_type.into(),
            calling_convention: calling_convention.into(),
            parameters: Vec::new(),
            is_custom_storage: false,
            is_inline: false,
            is_no_return: false,
            call_fixup: None,
            stack_purge_size: None,
            has_var_args: false,
        }
    }

    /// Returns the function name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the return type name.
    pub fn return_type(&self) -> &str {
        &self.return_type
    }

    /// Returns the calling convention name.
    pub fn calling_convention(&self) -> &str {
        &self.calling_convention
    }

    /// Returns the parameters.
    pub fn parameters(&self) -> &[FunctionVariableData] {
        &self.parameters
    }

    /// Returns a mutable reference to the parameters.
    pub fn parameters_mut(&mut self) -> &mut Vec<FunctionVariableData> {
        &mut self.parameters
    }

    /// Adds a parameter.
    pub fn add_parameter(&mut self, param: FunctionVariableData) {
        self.parameters.push(param);
    }

    /// Removes a parameter by ordinal.
    pub fn remove_parameter(&mut self, ordinal: i32) -> Option<FunctionVariableData> {
        let pos = self.parameters.iter().position(|p| p.ordinal() == ordinal)?;
        Some(self.parameters.remove(pos))
    }

    /// Returns the number of regular (non-return, non-auto) parameters.
    pub fn regular_parameter_count(&self) -> usize {
        self.parameters
            .iter()
            .filter(|p| !p.is_return() && !p.is_auto_parameter())
            .count()
    }

    /// Returns whether the function uses custom storage.
    pub fn is_custom_storage(&self) -> bool {
        self.is_custom_storage
    }

    /// Returns whether the function is inline.
    pub fn is_inline(&self) -> bool {
        self.is_inline
    }

    /// Returns whether the function is no-return.
    pub fn is_no_return(&self) -> bool {
        self.is_no_return
    }

    /// Returns the call fixup name.
    pub fn call_fixup(&self) -> Option<&str> {
        self.call_fixup.as_deref()
    }

    /// Returns the stack purge size.
    pub fn stack_purge_size(&self) -> Option<i32> {
        self.stack_purge_size
    }

    /// Returns whether the function has varargs.
    pub fn has_var_args(&self) -> bool {
        self.has_var_args
    }

    /// Sets the function name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    /// Sets the return type.
    pub fn set_return_type(&mut self, return_type: impl Into<String>) {
        self.return_type = return_type.into();
    }

    /// Sets the calling convention.
    pub fn set_calling_convention(&mut self, cc: impl Into<String>) {
        self.calling_convention = cc.into();
    }

    /// Sets whether the function uses custom storage.
    pub fn set_custom_storage(&mut self, custom: bool) {
        self.is_custom_storage = custom;
    }

    /// Sets whether the function is inline.
    pub fn set_inline(&mut self, inline: bool) {
        self.is_inline = inline;
    }

    /// Sets whether the function is no-return.
    pub fn set_no_return(&mut self, no_return: bool) {
        self.is_no_return = no_return;
    }

    /// Sets the call fixup.
    pub fn set_call_fixup(&mut self, fixup: Option<String>) {
        self.call_fixup = fixup;
    }

    /// Sets the stack purge size.
    pub fn set_stack_purge_size(&mut self, size: Option<i32>) {
        self.stack_purge_size = size;
    }

    /// Sets whether the function has varargs.
    pub fn set_has_var_args(&mut self, has: bool) {
        self.has_var_args = has;
    }
}

// ---------------------------------------------------------------------------
// ModelChangeListener
// ---------------------------------------------------------------------------

/// Callback trait for when the function editor model changes.
///
/// Ported from `ModelChangeListener.java`.
pub trait ModelChangeListener: fmt::Debug {
    /// Called when the model data has changed.
    fn data_changed(&self);

    /// Called when the model's validity state has changed.
    fn validity_changed(&self, is_valid: bool);

    /// Called when the status text has changed.
    fn status_changed(&self, status: &str);
}

/// A no-op listener used as default.
#[derive(Debug)]
pub struct DummyModelChangeListener;

impl ModelChangeListener for DummyModelChangeListener {
    fn data_changed(&self) {}
    fn validity_changed(&self, _is_valid: bool) {}
    fn status_changed(&self, _status: &str) {}
}

// ---------------------------------------------------------------------------
// FunctionEditorModel
// ---------------------------------------------------------------------------

/// The function editor's data model.
///
/// Ported from `FunctionEditorModel.java`.  This model tracks the
/// function's current state, detects changes, validates input, and
/// notifies listeners of changes.
///
/// # Example
///
/// ```
/// use ghidra_features::base::function::editor::*;
///
/// let mut model = FunctionEditorModel::new(
///     FunctionData::new("main", "int", "__cdecl"),
/// );
/// assert!(!model.has_changes());
/// model.set_name("main2");
/// assert!(model.has_changes());
/// ```
#[derive(Debug)]
pub struct FunctionEditorModel {
    /// The current function data.
    function_data: FunctionData,
    /// A snapshot of the original data for change detection.
    original_data: FunctionData,
    /// The signature field text (for parse-from-text mode).
    signature_text: String,
    /// Whether the model is in parsing mode.
    is_parsing_mode: bool,
    /// Current status text.
    status_text: String,
    /// Whether the model state is valid.
    is_valid: bool,
    /// Whether the signature has been transformed.
    is_signature_transformed: bool,
    /// Whether there are significant parameter changes.
    has_significant_parameter_changes: bool,
    /// The list of calling convention names.
    calling_conventions: Vec<String>,
    /// The list of call fixup names.
    call_fixups: Vec<String>,
}

impl FunctionEditorModel {
    /// Status text shown during parsing mode.
    pub const PARSING_MODE_STATUS: &'static str =
        "<TAB> or <RETURN> to commit edits, <ESC> to abort";

    /// Creates a new function editor model.
    pub fn new(function_data: FunctionData) -> Self {
        let original = function_data.clone();
        let cc = function_data.calling_convention().to_string();
        Self {
            function_data,
            original_data: original,
            signature_text: String::new(),
            is_parsing_mode: false,
            status_text: String::new(),
            is_valid: true,
            is_signature_transformed: false,
            has_significant_parameter_changes: false,
            calling_conventions: vec![
                "unknown".to_string(),
                "default".to_string(),
                cc,
            ],
            call_fixups: Vec::new(),
        }
    }

    /// Returns `true` if the model has unsaved changes.
    pub fn has_changes(&self) -> bool {
        self.function_data.name() != self.original_data.name()
            || self.function_data.return_type() != self.original_data.return_type()
            || self.function_data.calling_convention() != self.original_data.calling_convention()
            || self.function_data.parameters().len() != self.original_data.parameters().len()
            || self.function_data.is_inline() != self.original_data.is_inline()
            || self.function_data.is_no_return() != self.original_data.is_no_return()
            || self.function_data.call_fixup() != self.original_data.call_fixup()
    }

    /// Returns `true` if there are significant parameter changes.
    pub fn has_significant_parameter_changes(&self) -> bool {
        self.has_significant_parameter_changes
    }

    /// Returns the function data.
    pub fn function_data(&self) -> &FunctionData {
        &self.function_data
    }

    /// Returns a mutable reference to the function data.
    pub fn function_data_mut(&mut self) -> &mut FunctionData {
        &mut self.function_data
    }

    /// Returns the function name.
    pub fn name(&self) -> &str {
        self.function_data.name()
    }

    /// Sets the function name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.function_data.set_name(name);
        self.validate();
    }

    /// Returns the return type.
    pub fn return_type(&self) -> &str {
        self.function_data.return_type()
    }

    /// Sets the return type.
    pub fn set_return_type(&mut self, return_type: impl Into<String>) {
        self.function_data.set_return_type(return_type);
        self.has_significant_parameter_changes = true;
        self.validate();
    }

    /// Returns the calling convention.
    pub fn calling_convention(&self) -> &str {
        self.function_data.calling_convention()
    }

    /// Sets the calling convention.
    pub fn set_calling_convention(&mut self, cc: impl Into<String>) {
        self.function_data.set_calling_convention(cc);
        self.validate();
    }

    /// Returns the calling convention names.
    pub fn calling_convention_names(&self) -> &[String] {
        &self.calling_conventions
    }

    /// Sets the calling convention names.
    pub fn set_calling_convention_names(&mut self, names: Vec<String>) {
        self.calling_conventions = names;
    }

    /// Returns the call fixup names.
    pub fn call_fixup_names(&self) -> &[String] {
        &self.call_fixups
    }

    /// Sets the call fixup names.
    pub fn set_call_fixup_names(&mut self, names: Vec<String>) {
        self.call_fixups = names;
    }

    /// Returns the parameters.
    pub fn parameters(&self) -> &[FunctionVariableData] {
        self.function_data.parameters()
    }

    /// Adds a parameter.
    pub fn add_parameter(&mut self, param: FunctionVariableData) {
        self.function_data.add_parameter(param);
        self.has_significant_parameter_changes = true;
        self.validate();
    }

    /// Removes a parameter by ordinal.
    pub fn remove_parameter(&mut self, ordinal: i32) -> Option<FunctionVariableData> {
        let result = self.function_data.remove_parameter(ordinal);
        if result.is_some() {
            self.has_significant_parameter_changes = true;
            self.validate();
        }
        result
    }

    /// Returns the inline flag.
    pub fn is_inline(&self) -> bool {
        self.function_data.is_inline()
    }

    /// Sets the inline flag.
    pub fn set_inline(&mut self, inline: bool) {
        self.function_data.set_inline(inline);
        self.validate();
    }

    /// Returns the no-return flag.
    pub fn is_no_return(&self) -> bool {
        self.function_data.is_no_return()
    }

    /// Sets the no-return flag.
    pub fn set_no_return(&mut self, no_return: bool) {
        self.function_data.set_no_return(no_return);
        self.validate();
    }

    /// Returns the call fixup name.
    pub fn call_fixup(&self) -> Option<&str> {
        self.function_data.call_fixup()
    }

    /// Sets the call fixup.
    pub fn set_call_fixup(&mut self, fixup: Option<String>) {
        self.function_data.set_call_fixup(fixup);
        self.validate();
    }

    /// Returns whether the model is in parsing mode.
    pub fn is_parsing_mode(&self) -> bool {
        self.is_parsing_mode
    }

    /// Sets the parsing mode.
    pub fn set_parsing_mode(&mut self, parsing: bool) {
        self.is_parsing_mode = parsing;
        if parsing {
            self.status_text = Self::PARSING_MODE_STATUS.to_string();
        } else {
            self.status_text.clear();
        }
    }

    /// Returns the status text.
    pub fn status_text(&self) -> &str {
        &self.status_text
    }

    /// Returns whether the model state is valid.
    pub fn is_valid(&self) -> bool {
        self.is_valid
    }

    /// Returns whether the signature has been transformed.
    pub fn is_signature_transformed(&self) -> bool {
        self.is_signature_transformed
    }

    /// Validates the model state.
    fn validate(&mut self) {
        self.is_valid = true;
        self.status_text.clear();

        if self.function_data.name().is_empty() {
            self.is_valid = false;
            self.status_text = "Function name cannot be empty".to_string();
        }
    }

    /// Resets the model to the original state.
    pub fn reset(&mut self) {
        self.function_data = self.original_data.clone();
        self.has_significant_parameter_changes = false;
        self.is_signature_transformed = false;
        self.validate();
    }
}

// ---------------------------------------------------------------------------
// ParameterTableModel
// ---------------------------------------------------------------------------

/// A column identifier for the parameter table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParameterColumn {
    /// Ordinal column.
    Ordinal,
    /// Name column.
    Name,
    /// Data type column.
    DataType,
    /// Storage column.
    Storage,
    /// Whether custom storage is used.
    CustomStorage,
}

impl fmt::Display for ParameterColumn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ordinal => write!(f, "#"),
            Self::Name => write!(f, "Name"),
            Self::DataType => write!(f, "Data Type"),
            Self::Storage => write!(f, "Storage"),
            Self::CustomStorage => write!(f, "Custom"),
        }
    }
}

/// Table model for the function parameters in the editor.
///
/// Ported from `ParameterTableModel.java`.
#[derive(Debug, Clone)]
pub struct ParameterTableModel {
    /// The columns to display.
    columns: Vec<ParameterColumn>,
    /// The parameters.
    parameters: Vec<ParamInfo>,
    /// Whether the model is editable.
    editable: bool,
}

impl ParameterTableModel {
    /// Creates a new parameter table model.
    pub fn new(editable: bool) -> Self {
        Self {
            columns: vec![
                ParameterColumn::Ordinal,
                ParameterColumn::Name,
                ParameterColumn::DataType,
                ParameterColumn::Storage,
            ],
            parameters: Vec::new(),
            editable,
        }
    }

    /// Creates a parameter table model with custom columns.
    pub fn with_columns(columns: Vec<ParameterColumn>, editable: bool) -> Self {
        Self {
            columns,
            parameters: Vec::new(),
            editable,
        }
    }

    /// Returns the columns.
    pub fn columns(&self) -> &[ParameterColumn] {
        &self.columns
    }

    /// Returns the parameters.
    pub fn parameters(&self) -> &[ParamInfo] {
        &self.parameters
    }

    /// Returns a mutable reference to the parameters.
    pub fn parameters_mut(&mut self) -> &mut Vec<ParamInfo> {
        &mut self.parameters
    }

    /// Adds a parameter.
    pub fn add_parameter(&mut self, param: ParamInfo) {
        self.parameters.push(param);
        self.parameters.sort();
    }

    /// Removes a parameter by index.
    pub fn remove_parameter(&mut self, index: usize) -> Option<ParamInfo> {
        if index < self.parameters.len() {
            Some(self.parameters.remove(index))
        } else {
            None
        }
    }

    /// Returns the number of parameters.
    pub fn len(&self) -> usize {
        self.parameters.len()
    }

    /// Returns `true` if there are no parameters.
    pub fn is_empty(&self) -> bool {
        self.parameters.is_empty()
    }

    /// Returns whether the model is editable.
    pub fn is_editable(&self) -> bool {
        self.editable
    }

    /// Sets whether the model is editable.
    pub fn set_editable(&mut self, editable: bool) {
        self.editable = editable;
    }

    /// Returns the column count.
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Gets a cell value by row and column.
    pub fn get_value_at(&self, row: usize, col: usize) -> Option<String> {
        let param = self.parameters.get(row)?;
        let column = self.columns.get(col)?;
        Some(match column {
            ParameterColumn::Ordinal => param.ordinal().to_string(),
            ParameterColumn::Name => param.name(),
            ParameterColumn::DataType => param.formal_data_type().to_string(),
            ParameterColumn::Storage => param.storage().to_string(),
            ParameterColumn::CustomStorage => {
                if param.is_custom_storage() { "Y".to_string() } else { "N".to_string() }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- VarnodeType tests --

    #[test]
    fn test_varnode_type() {
        assert!(VarnodeType::Register.is_register());
        assert!(!VarnodeType::Register.is_stack());
        assert!(VarnodeType::Stack.is_stack());
        assert!(VarnodeType::Memory.is_memory());
    }

    #[test]
    fn test_varnode_type_display() {
        assert_eq!(VarnodeType::Register.to_string(), "Register");
        assert_eq!(VarnodeType::Stack.to_string(), "Stack");
    }

    // -- VarnodeInfo tests --

    #[test]
    fn test_varnode_info_register() {
        let vn = VarnodeInfo::register("RAX", 8);
        assert_eq!(vn.varnode_type(), VarnodeType::Register);
        assert_eq!(vn.name(), "RAX");
        assert_eq!(vn.size(), 8);
    }

    #[test]
    fn test_varnode_info_stack() {
        let vn = VarnodeInfo::stack(-8, 4);
        assert_eq!(vn.varnode_type(), VarnodeType::Stack);
        assert_eq!(vn.offset(), -8);
        assert_eq!(vn.size(), 4);
    }

    #[test]
    fn test_varnode_info_memory() {
        let vn = VarnodeInfo::memory(0x401000, 2);
        assert_eq!(vn.varnode_type(), VarnodeType::Memory);
        assert_eq!(vn.offset(), 0x401000);
    }

    // -- FunctionVariableData tests --

    #[test]
    fn test_function_variable_data_parameter() {
        let var = FunctionVariableData::parameter(
            Some("buf".into()),
            0,
            "void *",
            VarnodeInfo::register("RDI", 8),
        );
        assert_eq!(var.name(), Some("buf"));
        assert_eq!(var.ordinal(), 0);
        assert_eq!(var.data_type_name(), "void *");
        assert!(!var.is_return());
        assert!(!var.is_auto_parameter());
    }

    #[test]
    fn test_function_variable_data_return() {
        let var = FunctionVariableData::return_value(
            "int",
            VarnodeInfo::register("EAX", 4),
        );
        assert!(var.is_return());
        assert_eq!(var.ordinal(), -1);
        assert_eq!(var.display_name(), "return");
    }

    #[test]
    fn test_function_variable_data_default_name() {
        let var = FunctionVariableData::parameter(
            None,
            2,
            "int",
            VarnodeInfo::register("RDX", 4),
        );
        assert_eq!(var.display_name(), "param_2");
    }

    // -- ParamInfo tests --

    #[test]
    fn test_param_info() {
        let param = ParamInfo::new("buf", "void *", VarnodeInfo::register("RDI", 8), 0);
        assert_eq!(param.name(), "buf");
        assert_eq!(param.formal_data_type(), "void *");
        assert_eq!(param.ordinal(), 0);
        assert!(!param.is_return_parameter());
        assert!(!param.is_forced_indirect());
    }

    #[test]
    fn test_param_info_default_name() {
        let param = ParamInfo::with_default_name("int", VarnodeInfo::register("ESI", 4), 1);
        assert_eq!(param.name(), "param_1");
        assert!(param.raw_name().is_none());
    }

    #[test]
    fn test_param_info_return() {
        let param = ParamInfo::new("ret", "int", VarnodeInfo::register("EAX", 4), -1);
        assert!(param.is_return_parameter());
    }

    #[test]
    fn test_param_info_ordering() {
        let mut params = vec![
            ParamInfo::new("b", "int", VarnodeInfo::register("RSI", 4), 1),
            ParamInfo::new("a", "int", VarnodeInfo::register("RDI", 4), 0),
        ];
        params.sort();
        assert_eq!(params[0].name(), "a");
        assert_eq!(params[1].name(), "b");
    }

    #[test]
    fn test_param_info_copy() {
        let param = ParamInfo::new("x", "int", VarnodeInfo::register("RDI", 4), 0);
        let copy = param.copy();
        assert_eq!(copy.name(), "x");
        assert_eq!(copy.formal_data_type(), "int");
    }

    #[test]
    fn test_param_info_is_same() {
        let p1 = ParamInfo::new("x", "int", VarnodeInfo::register("RDI", 4), 0);
        let p2 = ParamInfo::new("x", "int", VarnodeInfo::register("RDI", 4), 0);
        assert!(p1.is_same(&p2));

        let p3 = ParamInfo::new("y", "int", VarnodeInfo::register("RDI", 4), 0);
        assert!(!p1.is_same(&p3));
    }

    // -- FunctionData tests --

    #[test]
    fn test_function_data() {
        let fd = FunctionData::new("main", "int", "__cdecl");
        assert_eq!(fd.name(), "main");
        assert_eq!(fd.return_type(), "int");
        assert_eq!(fd.calling_convention(), "__cdecl");
        assert_eq!(fd.parameters().len(), 0);
        assert!(!fd.is_inline());
        assert!(!fd.is_no_return());
    }

    #[test]
    fn test_function_data_parameters() {
        let mut fd = FunctionData::new("func", "void", "__cdecl");
        fd.add_parameter(FunctionVariableData::parameter(
            Some("x".into()), 0, "int", VarnodeInfo::register("EDI", 4),
        ));
        fd.add_parameter(FunctionVariableData::parameter(
            Some("y".into()), 1, "int", VarnodeInfo::register("ESI", 4),
        ));
        assert_eq!(fd.parameters().len(), 2);
        assert_eq!(fd.regular_parameter_count(), 2);

        fd.remove_parameter(0);
        assert_eq!(fd.parameters().len(), 1);
    }

    #[test]
    fn test_function_data_setters() {
        let mut fd = FunctionData::new("main", "int", "default");
        fd.set_name("main2");
        fd.set_return_type("void");
        fd.set_inline(true);
        fd.set_no_return(true);
        fd.set_call_fixup(Some("fixup".to_string()));

        assert_eq!(fd.name(), "main2");
        assert_eq!(fd.return_type(), "void");
        assert!(fd.is_inline());
        assert!(fd.is_no_return());
        assert_eq!(fd.call_fixup(), Some("fixup"));
    }

    // -- FunctionEditorModel tests --

    #[test]
    fn test_editor_model_no_changes() {
        let fd = FunctionData::new("main", "int", "__cdecl");
        let model = FunctionEditorModel::new(fd);
        assert!(!model.has_changes());
        assert!(model.is_valid());
        assert!(!model.is_parsing_mode());
    }

    #[test]
    fn test_editor_model_name_change() {
        let fd = FunctionData::new("main", "int", "__cdecl");
        let mut model = FunctionEditorModel::new(fd);
        model.set_name("main2");
        assert!(model.has_changes());
    }

    #[test]
    fn test_editor_model_return_type_change() {
        let fd = FunctionData::new("main", "int", "__cdecl");
        let mut model = FunctionEditorModel::new(fd);
        model.set_return_type("void");
        assert!(model.has_changes());
        assert!(model.has_significant_parameter_changes());
    }

    #[test]
    fn test_editor_model_invalid_name() {
        let fd = FunctionData::new("main", "int", "__cdecl");
        let mut model = FunctionEditorModel::new(fd);
        model.set_name("");
        assert!(!model.is_valid());
        assert!(!model.status_text().is_empty());
    }

    #[test]
    fn test_editor_model_parsing_mode() {
        let fd = FunctionData::new("main", "int", "__cdecl");
        let mut model = FunctionEditorModel::new(fd);
        model.set_parsing_mode(true);
        assert!(model.is_parsing_mode());
        assert_eq!(
            model.status_text(),
            FunctionEditorModel::PARSING_MODE_STATUS
        );
    }

    #[test]
    fn test_editor_model_reset() {
        let fd = FunctionData::new("main", "int", "__cdecl");
        let mut model = FunctionEditorModel::new(fd);
        model.set_name("main2");
        model.set_return_type("void");
        assert!(model.has_changes());

        model.reset();
        assert!(!model.has_changes());
        assert_eq!(model.name(), "main");
        assert_eq!(model.return_type(), "int");
    }

    // -- ParameterTableModel tests --

    #[test]
    fn test_parameter_table_model() {
        let mut model = ParameterTableModel::new(true);
        assert!(model.is_empty());
        assert_eq!(model.column_count(), 4);
        assert!(model.is_editable());

        model.add_parameter(ParamInfo::new("buf", "void *", VarnodeInfo::register("RDI", 8), 0));
        model.add_parameter(ParamInfo::new("len", "size_t", VarnodeInfo::register("RSI", 8), 1));
        assert_eq!(model.len(), 2);
    }

    #[test]
    fn test_parameter_table_model_values() {
        let mut model = ParameterTableModel::new(true);
        model.add_parameter(ParamInfo::new("x", "int", VarnodeInfo::register("EDI", 4), 0));

        assert_eq!(model.get_value_at(0, 0), Some("0".into())); // ordinal
        assert_eq!(model.get_value_at(0, 1), Some("x".into())); // name
        assert_eq!(model.get_value_at(0, 2), Some("int".into())); // data type
        assert!(model.get_value_at(0, 3).is_some()); // storage
        assert_eq!(model.get_value_at(1, 0), None); // out of range
    }

    #[test]
    fn test_parameter_table_model_custom_columns() {
        let model = ParameterTableModel::with_columns(
            vec![ParameterColumn::Name, ParameterColumn::DataType],
            false,
        );
        assert_eq!(model.column_count(), 2);
        assert!(!model.is_editable());
    }

    #[test]
    fn test_parameter_table_model_remove() {
        let mut model = ParameterTableModel::new(true);
        model.add_parameter(ParamInfo::new("a", "int", VarnodeInfo::register("EDI", 4), 0));
        model.add_parameter(ParamInfo::new("b", "int", VarnodeInfo::register("ESI", 4), 1));

        let removed = model.remove_parameter(0);
        assert!(removed.is_some());
        assert_eq!(model.len(), 1);
    }

    #[test]
    fn test_parameter_column_display() {
        assert_eq!(ParameterColumn::Ordinal.to_string(), "#");
        assert_eq!(ParameterColumn::Name.to_string(), "Name");
        assert_eq!(ParameterColumn::DataType.to_string(), "Data Type");
    }

    #[test]
    fn test_dummy_model_change_listener() {
        let listener = DummyModelChangeListener;
        listener.data_changed();
        listener.validity_changed(true);
        listener.status_changed("test");
    }
}
