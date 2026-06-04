//! Program listing types — code units, instructions, data items, functions,
//! stack frames, operands, variables, parameters, local variables, bookmarks,
//! program fragments/modules, and the listing trait.
//!
//! All types are converted from `ghidra.program.model.listing` Java interfaces
//! and classes. Key types:
//!
//! - [`Listing`] trait — query and modify code units
//! - [`CodeUnit`] trait — common interface for instructions and data
//! - [`Instruction`] struct — a decoded machine instruction
//! - [`Data`] struct — a typed data item at an address
//! - [`CodeUnitFormat`] struct — formats code units for display
//! - [`Function`] struct — a function with entry point, body, stack frame
//! - [`FunctionManager`] struct — manages functions in a program
//! - [`Variable`] struct — a function variable (parameter or local)
//! - [`Parameter`] struct — a function parameter with ordinal
//! - [`LocalVariable`] struct — a function local variable
//! - [`ProgramModule`] trait — hierarchical module/fragment organization
//! - [`ProgramFragment`] struct — a fragment (group of addresses)
//! - [`StackFrame`] struct — stack frame layout
//! - [`Bookmark`] struct — user-placed bookmarks
//! - [`VariableStorage`] enum — where a variable is stored

// Re-export from the base listing module for backward compatibility.
pub use crate::listing::{InstructionMnemonic, ListingColumns, ListingRow};

use crate::addr::{Address, AddressRange};
use crate::data::DataType;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

// ============================================================================
// CommentType — mirrors ghidra.program.model.listing.CommentType
// ============================================================================

/// The type of a comment attached to a code unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommentType {
    /// End-of-line comment (after the instruction on the same line).
    Eol,
    /// Pre-comment (before the code unit).
    Pre,
    /// Post-comment (after the code unit).
    Post,
    /// Plate comment (multi-line banner before a code unit).
    Plate,
    /// Repeatable comment (shown at all references to this location).
    Repeatable,
}

impl CommentType {
    /// Convert from the legacy integer constants (0=EOL, 1=PRE, 2=POST, 3=PLATE, 4=REPEATABLE).
    pub fn from_ordinal(ord: i32) -> Option<Self> {
        match ord {
            0 => Some(Self::Eol),
            1 => Some(Self::Pre),
            2 => Some(Self::Post),
            3 => Some(Self::Plate),
            4 => Some(Self::Repeatable),
            _ => None,
        }
    }

    /// The ordinal matching the legacy int constants.
    pub fn ordinal(self) -> i32 {
        match self {
            Self::Eol => 0,
            Self::Pre => 1,
            Self::Post => 2,
            Self::Plate => 3,
            Self::Repeatable => 4,
        }
    }
}

impl std::fmt::Display for CommentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Eol => write!(f, "EOL"),
            Self::Pre => write!(f, "PRE"),
            Self::Post => write!(f, "POST"),
            Self::Plate => write!(f, "PLATE"),
            Self::Repeatable => write!(f, "REPEATABLE"),
        }
    }
}

// ============================================================================
// CodeUnitComments — mirrors ghidra.program.model.listing.CodeUnitComments
// ============================================================================

/// All comments at a given address.
#[derive(Debug, Clone, Default)]
pub struct CodeUnitComments {
    /// The address these comments apply to.
    pub address: Address,
    /// End-of-line comment.
    pub eol_comment: Option<String>,
    /// Pre-comment (before the code unit).
    pub pre_comment: Option<String>,
    /// Post-comment (after the code unit).
    pub post_comment: Option<String>,
    /// Plate comment (multi-line banner).
    pub plate_comment: Option<String>,
    /// Repeatable comment.
    pub repeatable_comment: Option<String>,
}

impl CodeUnitComments {
    /// Create a new empty comment set for an address.
    pub fn new(address: Address) -> Self {
        Self {
            address,
            ..Default::default()
        }
    }

    /// Get the comment for a specific type.
    pub fn get_comment(&self, comment_type: CommentType) -> Option<&str> {
        match comment_type {
            CommentType::Eol => self.eol_comment.as_deref(),
            CommentType::Pre => self.pre_comment.as_deref(),
            CommentType::Post => self.post_comment.as_deref(),
            CommentType::Plate => self.plate_comment.as_deref(),
            CommentType::Repeatable => self.repeatable_comment.as_deref(),
        }
    }

    /// Set the comment for a specific type.
    pub fn set_comment(&mut self, comment_type: CommentType, comment: Option<String>) {
        match comment_type {
            CommentType::Eol => self.eol_comment = comment,
            CommentType::Pre => self.pre_comment = comment,
            CommentType::Post => self.post_comment = comment,
            CommentType::Plate => self.plate_comment = comment,
            CommentType::Repeatable => self.repeatable_comment = comment,
        }
    }

    /// Returns true if all comment fields are `None`.
    pub fn is_empty(&self) -> bool {
        self.eol_comment.is_none()
            && self.pre_comment.is_none()
            && self.post_comment.is_none()
            && self.plate_comment.is_none()
            && self.repeatable_comment.is_none()
    }
}

// ============================================================================
// SourceType — function-level source type for listing items
// ============================================================================

/// Indicates the provenance of a function's signature, parameter, or variable.
/// Mirrors ghidra.program.model.symbol.SourceType usage within the listing context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceType {
    /// Default (auto-generated, lowest priority).
    Default,
    /// Produced during analysis.
    Analysis,
    /// Produced during import.
    Imported,
    /// Explicitly set by the user.
    UserDefined,
}

impl Default for SourceType {
    fn default() -> Self {
        SourceType::Default
    }
}

// ============================================================================
// FlowOverride — mirrors ghidra.program.model.listing.FlowOverride
// ============================================================================

/// Override settings for instruction control flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowOverride {
    /// No override; use the instruction's default flow type.
    None,
    /// Override a branch to a call.
    BranchToCall,
    /// Override a call to a branch.
    CallToBranch,
    /// Override to a return.
    Return,
    /// Override to a call and return (call + terminator).
    CallReturn,
    /// Override a call to a computed call.
    CallToComputed,
    /// Clear the flow (no flow at all).
    Clear,
}

impl FlowOverride {
    /// The mnemonic used when displaying flow overrides.
    pub fn mnemonic(self) -> &'static str {
        match self {
            FlowOverride::None => "",
            FlowOverride::BranchToCall => "CALL",
            FlowOverride::CallToBranch => "JMP",
            FlowOverride::Return => "RET",
            FlowOverride::CallReturn => "CALL/RET",
            FlowOverride::CallToComputed => "CALLCOMP",
            FlowOverride::Clear => "CLEAR",
        }
    }
}

impl Default for FlowOverride {
    fn default() -> Self {
        FlowOverride::None
    }
}

// ============================================================================
// VariableStorage — where a variable/parameter is stored
// ============================================================================

/// Describes where a variable or parameter is stored.
/// Mirrors ghidra.program.model.listing.VariableStorage.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VariableStorage {
    /// Stored in a register.
    Register { name: String, size: usize },
    /// Stored on the stack at a given offset (from the frame base).
    Stack { offset: i64, size: usize },
    /// Stored at an absolute memory address.
    Memory { address: Address, size: usize },
    /// Multiple storage locations (compound storage, e.g., split register+stack).
    Compound(Vec<VariableStorage>),
    /// Invalid/unassigned storage.
    Unassigned,
    /// Void/empty storage (for void return values).
    Void,
    /// Bad storage (error state).
    Bad,
}

impl VariableStorage {
    /// Sentinel values matching Ghidra's VariableStorage constants.
    pub const BAD_STORAGE: Self = VariableStorage::Bad;
    pub const UNASSIGNED_STORAGE: Self = VariableStorage::Unassigned;
    pub const VOID_STORAGE: Self = VariableStorage::Void;

    /// Returns true if this is a simple register storage.
    pub fn is_register(&self) -> bool {
        matches!(self, VariableStorage::Register { .. })
    }

    /// Returns true if this is a simple stack storage.
    pub fn is_stack(&self) -> bool {
        matches!(self, VariableStorage::Stack { .. })
    }

    /// Returns true if this is a simple memory storage.
    pub fn is_memory(&self) -> bool {
        matches!(self, VariableStorage::Memory { .. })
    }

    /// Returns true if this is compound storage.
    pub fn is_compound(&self) -> bool {
        matches!(self, VariableStorage::Compound(_))
    }

    /// Returns true if this is valid assigned storage.
    pub fn is_valid(&self) -> bool {
        !matches!(self, VariableStorage::Unassigned | VariableStorage::Bad)
    }

    /// Create a register storage.
    pub fn register(name: impl Into<String>, size: usize) -> Self {
        VariableStorage::Register {
            name: name.into(),
            size,
        }
    }

    /// Create a stack storage.
    pub fn stack(offset: i64, size: usize) -> Self {
        VariableStorage::Stack { offset, size }
    }

    /// Create a memory storage.
    pub fn memory(address: Address, size: usize) -> Self {
        VariableStorage::Memory { address, size }
    }

    /// Get the total size in bytes of this storage.
    pub fn size(&self) -> usize {
        match self {
            VariableStorage::Register { size, .. } => *size,
            VariableStorage::Stack { size, .. } => *size,
            VariableStorage::Memory { size, .. } => *size,
            VariableStorage::Compound(parts) => parts.iter().map(|p| p.size()).sum(),
            _ => 0,
        }
    }
}

impl Default for VariableStorage {
    fn default() -> Self {
        VariableStorage::Unassigned
    }
}

// ============================================================================
// AutoParameterType — mirrors ghidra.program.model.listing.AutoParameterType
// ============================================================================

/// Types of auto-parameters injected by calling conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AutoParameterType {
    /// The `this` pointer for __thiscall.
    This,
    /// The `__return_storage_ptr__` for large return values.
    ReturnStoragePtr,
}

// ============================================================================
// FunctionUpdateType — mirrors Function.FunctionUpdateType
// ============================================================================

/// Describes how a function's signature is being updated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FunctionUpdateType {
    /// All parameters and return already have specific storage assigned.
    CustomStorage,
    /// Formal signature params/return specified without storage; storage computed.
    DynamicStorageFormalParams,
    /// All params and return without storage; storage computed with `this` inference.
    DynamicStorageAllParams,
}

// ============================================================================
// FunctionTag — mirrors ghidra.program.model.listing.FunctionTag
// ============================================================================

/// A tag (label) that can be applied to a function for categorization.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FunctionTag {
    /// The tag name (e.g., "inline", "noreturn", "thunk").
    pub name: String,
    /// Optional comment associated with this tag.
    pub comment: Option<String>,
}

impl FunctionTag {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            comment: None,
        }
    }

    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }
}

// ============================================================================
// FunctionSignature — mirrors ghidra.program.model.listing.FunctionSignature
// ============================================================================

/// A function's signature: return type, calling convention, parameters, varargs.
/// Equivalent to Ghidra's `FunctionSignature` interface.
#[derive(Debug, Clone)]
pub struct FunctionSignature {
    /// The function name (may be empty for anonymous signatures).
    pub name: String,
    /// Return type.
    pub return_type: Option<Arc<dyn DataType>>,
    /// Ordered parameters.
    pub parameters: Vec<Parameter>,
    /// Calling convention name (e.g., "__cdecl", "__stdcall").
    pub calling_convention: String,
    /// Whether the function has variable arguments (e.g., `...`).
    pub has_varargs: bool,
    /// Optional comment.
    pub comment: Option<String>,
}

impl FunctionSignature {
    /// Create a new function signature.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            return_type: None,
            parameters: Vec::new(),
            calling_convention: "__cdecl".to_string(),
            has_varargs: false,
            comment: None,
        }
    }

    /// Set the return type (builder pattern).
    pub fn with_return_type(mut self, dt: Arc<dyn DataType>) -> Self {
        self.return_type = Some(dt);
        self
    }

    /// Add a parameter (builder pattern).
    pub fn with_parameter(mut self, param: Parameter) -> Self {
        self.parameters.push(param);
        self
    }

    /// Set calling convention (builder pattern).
    pub fn with_calling_convention(mut self, cc: impl Into<String>) -> Self {
        self.calling_convention = cc.into();
        self
    }

    /// Set varargs (builder pattern).
    pub fn with_varargs(mut self, v: bool) -> Self {
        self.has_varargs = v;
        self
    }

    /// Render the signature as a C-like prototype string.
    pub fn prototype_string(&self, include_calling_convention: bool) -> String {
        let mut result = String::new();
        if include_calling_convention && !self.calling_convention.is_empty()
            && self.calling_convention != "__cdecl"
        {
            result.push_str(&self.calling_convention);
            result.push(' ');
        }
        if let Some(ref rt) = self.return_type {
            result.push_str(rt.name());
            result.push(' ');
        } else {
            result.push_str("void ");
        }
        result.push_str(&self.name);
        result.push('(');
        let param_strs: Vec<String> = self
            .parameters
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let type_name = p
                    .formal_data_type()
                    .map(|dt| dt.name().to_string())
                    .or_else(|| p.data_type().map(|dt| dt.name().to_string()))
                    .unwrap_or_else(|| "undefined".to_string());
                let name = if p.name().is_empty() {
                    format!("param_{}", i + 1)
                } else {
                    p.name().to_string()
                };
                format!("{} {}", type_name, name)
            })
            .collect();
        result.push_str(&param_strs.join(", "));
        if self.has_varargs {
            if !param_strs.is_empty() {
                result.push_str(", ...");
            } else {
                result.push_str("...");
            }
        }
        result.push(')');
        result
    }
}

impl Default for FunctionSignature {
    fn default() -> Self {
        Self::new("")
    }
}

impl std::fmt::Display for FunctionSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.prototype_string(true))
    }
}

// ============================================================================
// Variable — mirrors ghidra.program.model.listing.Variable
// ============================================================================

/// A variable (parameter or local variable) within a function.
///
/// Mirrors the Java `Variable` interface. Variables have a name, data type,
/// storage location, source, and comment.
#[derive(Debug, Clone)]
pub struct Variable {
    /// The variable name (may be empty or a default name like "param_1").
    pub name: String,
    /// The data type of this variable.
    pub data_type: Option<Arc<dyn DataType>>,
    /// Where this variable is stored (register, stack, memory, compound).
    pub storage: VariableStorage,
    /// The source of this variable (Default, Analysis, Imported, UserDefined).
    pub source: SourceType,
    /// Optional comment.
    pub comment: Option<String>,
    /// The length (size) of the variable in bytes.
    pub length: usize,
    /// The first use offset relative to the function entry point.
    pub first_use_offset: i32,
}

impl Variable {
    /// Create a new variable.
    pub fn new(
        name: impl Into<String>,
        data_type: Option<Arc<dyn DataType>>,
        source: SourceType,
    ) -> Self {
        let length = data_type.as_ref().map(|dt| dt.get_size()).unwrap_or(0);
        Self {
            name: name.into(),
            data_type,
            storage: VariableStorage::Unassigned,
            source,
            comment: None,
            length,
            first_use_offset: 0,
        }
    }

    /// Builder: set storage.
    pub fn with_storage(mut self, storage: VariableStorage) -> Self {
        let size_from_storage = storage.size();
        self.storage = storage;
        if size_from_storage > 0 {
            self.length = size_from_storage;
        }
        self
    }

    /// Builder: set comment.
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Builder: set first use offset.
    pub fn with_first_use_offset(mut self, offset: i32) -> Self {
        self.first_use_offset = offset;
        self
    }

    /// Returns true if this is a simple stack variable.
    pub fn is_stack_variable(&self) -> bool {
        matches!(self.storage, VariableStorage::Stack { .. })
            && !matches!(self.storage, VariableStorage::Compound(_))
    }

    /// Returns true if this is a simple register variable.
    pub fn is_register_variable(&self) -> bool {
        matches!(self.storage, VariableStorage::Register { .. })
            && !matches!(self.storage, VariableStorage::Compound(_))
    }

    /// Returns true if this is a simple memory variable.
    pub fn is_memory_variable(&self) -> bool {
        matches!(self.storage, VariableStorage::Memory { .. })
            && !matches!(self.storage, VariableStorage::Compound(_))
    }

    /// Returns true if this is a compound variable (multiple storage parts).
    pub fn is_compound_variable(&self) -> bool {
        matches!(self.storage, VariableStorage::Compound(_))
    }

    /// Returns true if the variable has assigned (valid) storage.
    pub fn has_assigned_storage(&self) -> bool {
        self.storage.is_valid()
    }

    /// Get the stack offset if this is a simple stack variable.
    pub fn get_stack_offset(&self) -> Option<i64> {
        match &self.storage {
            VariableStorage::Stack { offset, .. } => Some(*offset),
            _ => None,
        }
    }

    /// Get the first storage varnode as an address.
    pub fn get_min_address(&self) -> Option<Address> {
        match &self.storage {
            VariableStorage::Register { name, .. } => {
                // Register name is used; address is synthetic
                None
            }
            VariableStorage::Stack { offset, size } => {
                // Stack offset is relative to frame pointer
                None // Callers need frame base from function
            }
            VariableStorage::Memory { address, .. } => Some(*address),
            VariableStorage::Compound(parts) => parts.iter().find_map(|p| {
                if let VariableStorage::Memory { address, .. } = p {
                    Some(*address)
                } else {
                    None
                }
            }),
            _ => None,
        }
    }
}

impl Default for Variable {
    fn default() -> Self {
        Self {
            name: String::new(),
            data_type: None,
            storage: VariableStorage::Unassigned,
            source: SourceType::Default,
            comment: None,
            length: 0,
            first_use_offset: 0,
        }
    }
}

impl PartialEq for Variable {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.length == other.length
            && self.storage == other.storage
            && self.first_use_offset == other.first_use_offset
    }
}

impl Eq for Variable {}

impl std::hash::Hash for Variable {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.length.hash(state);
        self.storage.hash(state);
        self.first_use_offset.hash(state);
    }
}

// ============================================================================
// Parameter — mirrors ghidra.program.model.listing.Parameter
// ============================================================================

/// A function parameter. Extends Variable with ordinal position and auto-param
/// awareness.
#[derive(Debug, Clone)]
pub struct Parameter {
    /// The underlying variable data (name, type, storage, comment).
    pub variable: Variable,
    /// The ordinal position of this parameter in the function signature
    /// (0 = first parameter, -1 = return).
    pub ordinal: i32,
    /// Whether this parameter was auto-generated by the calling convention
    /// (e.g., `this` pointer, `__return_storage_ptr__`).
    pub auto_parameter: bool,
    /// If auto-parameter, the specific type.
    pub auto_parameter_type: Option<AutoParameterType>,
    /// Whether this parameter was forced to be passed as a pointer (forced indirect).
    pub forced_indirect: bool,
    /// The original formal data type before forced indirect conversion.
    pub formal_data_type: Option<Arc<dyn DataType>>,
}

impl Parameter {
    /// Sentinel ordinal for the return "parameter".
    pub const RETURN_ORDINAL: i32 = -1;
    /// Sentinel ordinal for an unassigned parameter.
    pub const UNASSIGNED_ORDINAL: i32 = -2;
    /// The display name for the return pseudo-parameter.
    pub const RETURN_NAME: &'static str = "<RETURN>";

    /// Create a new parameter.
    pub fn new(
        name: impl Into<String>,
        data_type: Option<Arc<dyn DataType>>,
        ordinal: i32,
        source: SourceType,
    ) -> Self {
        let var = Variable::new(name, data_type.clone(), source);
        Self {
            variable: var,
            ordinal,
            auto_parameter: false,
            auto_parameter_type: None,
            forced_indirect: false,
            formal_data_type: data_type,
        }
    }

    /// Create a return parameter.
    pub fn return_param(data_type: Option<Arc<dyn DataType>>) -> Self {
        Self::new(Self::RETURN_NAME, data_type, Self::RETURN_ORDINAL, SourceType::Default)
    }

    /// Builder: set auto-parameter information.
    pub fn with_auto_param(mut self, auto_type: AutoParameterType) -> Self {
        self.auto_parameter = true;
        self.auto_parameter_type = Some(auto_type);
        self
    }

    /// Builder: set forced indirect.
    pub fn with_forced_indirect(mut self, formal_type: Arc<dyn DataType>) -> Self {
        self.forced_indirect = true;
        self.formal_data_type = Some(formal_type);
        self
    }

    /// Builder: set storage.
    pub fn with_storage(mut self, storage: VariableStorage) -> Self {
        self.variable = self.variable.with_storage(storage);
        self
    }

    /// Builder: set comment.
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.variable = self.variable.with_comment(comment);
        self
    }

    /// The parameter name.
    pub fn name(&self) -> &str {
        &self.variable.name
    }

    /// The data type.
    pub fn data_type(&self) -> Option<&Arc<dyn DataType>> {
        self.variable.data_type.as_ref()
    }

    /// Returns true if this is the return pseudo-parameter.
    pub fn is_return(&self) -> bool {
        self.ordinal == Self::RETURN_ORDINAL
    }

    /// Returns true if this is an auto-parameter.
    pub fn is_auto_parameter(&self) -> bool {
        self.auto_parameter
    }

    /// Returns true if this parameter was forced to indirect (pointer) storage.
    pub fn is_forced_indirect(&self) -> bool {
        self.forced_indirect
    }

    /// The effective data type (the one used for storage, which may be a pointer
    /// if forced indirect).
    pub fn effective_data_type(&self) -> Option<&Arc<dyn DataType>> {
        self.variable.data_type.as_ref()
    }

    /// The formal (original) data type before any forced indirect conversion.
    pub fn formal_data_type(&self) -> Option<&Arc<dyn DataType>> {
        self.formal_data_type.as_ref()
    }
}

impl Default for Parameter {
    fn default() -> Self {
        Self {
            variable: Variable::default(),
            ordinal: Self::UNASSIGNED_ORDINAL,
            auto_parameter: false,
            auto_parameter_type: None,
            forced_indirect: false,
            formal_data_type: None,
        }
    }
}

impl PartialEq for Parameter {
    fn eq(&self, other: &Self) -> bool {
        self.variable == other.variable && self.ordinal == other.ordinal
    }
}

impl Eq for Parameter {}

impl std::hash::Hash for Parameter {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.variable.hash(state);
        self.ordinal.hash(state);
    }
}

/// Concrete implementation of Parameter (for database-backed use).
pub type ParameterImpl = Parameter;

// ============================================================================
// LocalVariable — mirrors ghidra.program.model.listing.LocalVariable
// ============================================================================

/// A local variable within a function.
///
/// Extends Variable with the ability to set the first use offset.
#[derive(Debug, Clone)]
pub struct LocalVariable {
    /// The underlying variable data.
    pub variable: Variable,
}

impl LocalVariable {
    /// Create a new local variable.
    pub fn new(
        name: impl Into<String>,
        data_type: Option<Arc<dyn DataType>>,
        source: SourceType,
    ) -> Self {
        Self {
            variable: Variable::new(name, data_type, source),
        }
    }

    /// Builder: set storage.
    pub fn with_storage(mut self, storage: VariableStorage) -> Self {
        self.variable = self.variable.with_storage(storage);
        self
    }

    /// Builder: set comment.
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.variable = self.variable.with_comment(comment);
        self
    }

    /// Set the first use offset. Returns true if the offset was set.
    /// Corresponds to `LocalVariable.setFirstUseOffset(int)` in Java.
    pub fn set_first_use_offset(&mut self, first_use_offset: i32) -> bool {
        self.variable.first_use_offset = first_use_offset;
        true
    }

    /// Get the first use offset.
    pub fn first_use_offset(&self) -> i32 {
        self.variable.first_use_offset
    }

    /// The variable name.
    pub fn name(&self) -> &str {
        &self.variable.name
    }

    /// The data type.
    pub fn data_type(&self) -> Option<&Arc<dyn DataType>> {
        self.variable.data_type.as_ref()
    }

    /// Returns true if this is a stack variable.
    pub fn is_stack_variable(&self) -> bool {
        self.variable.is_stack_variable()
    }

    /// Returns true if this is a register variable.
    pub fn is_register_variable(&self) -> bool {
        self.variable.is_register_variable()
    }
}

impl Default for LocalVariable {
    fn default() -> Self {
        Self {
            variable: Variable::default(),
        }
    }
}

impl PartialEq for LocalVariable {
    fn eq(&self, other: &Self) -> bool {
        self.variable == other.variable
    }
}

impl Eq for LocalVariable {}

/// Concrete implementation of LocalVariable (for database-backed use).
pub type LocalVariableImpl = LocalVariable;

// ============================================================================
// BookmarkType — mirrors ghidra.program.model.listing.BookmarkType
// ============================================================================

/// A category/type of bookmark.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BookmarkType {
    /// The unique type name (e.g., "Analysis", "Info", "Warning", "Error").
    pub type_name: String,
    /// A marker symbol (single character for display).
    pub marker: Option<String>,
    /// Whether this bookmark type has an associated keyboard shortcut.
    pub has_shortcut: bool,
}

impl BookmarkType {
    pub fn new(type_name: impl Into<String>) -> Self {
        Self {
            type_name: type_name.into(),
            marker: None,
            has_shortcut: false,
        }
    }

    pub fn with_marker(mut self, marker: impl Into<String>) -> Self {
        self.marker = Some(marker.into());
        self
    }
}

// ============================================================================
// Bookmark — mirrors ghidra.program.model.listing.Bookmark
// ============================================================================

/// A user-placed bookmark at a specific address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bookmark {
    /// The bookmark ID (unique within the program).
    pub id: u64,
    /// The address where this bookmark is placed.
    pub address: Address,
    /// The bookmark type string (e.g., "Analysis", "Info").
    pub bookmark_type: String,
    /// The category string (sub-type grouping).
    pub category: String,
    /// The comment/description text.
    pub comment: String,
}

impl Bookmark {
    pub fn new(
        id: u64,
        address: Address,
        bookmark_type: impl Into<String>,
        category: impl Into<String>,
        comment: impl Into<String>,
    ) -> Self {
        Self {
            id,
            address,
            bookmark_type: bookmark_type.into(),
            category: category.into(),
            comment: comment.into(),
        }
    }
}

// ============================================================================
// BookmarkManager — mirrors ghidra.program.model.listing.BookmarkManager
// ============================================================================

/// Manages bookmarks in a program.
#[derive(Debug, Clone, Default)]
pub struct BookmarkManager {
    /// Bookmarks keyed by address.
    bookmarks: HashMap<Address, Vec<Bookmark>>,
    /// All defined bookmark types.
    bookmark_types: HashMap<String, BookmarkType>,
    /// All categories.
    categories: HashSet<String>,
    /// Next bookmark ID.
    next_id: u64,
}

impl BookmarkManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a bookmark at an address. Overwrites any existing bookmark of the same type+category.
    pub fn set_bookmark(
        &mut self,
        addr: Address,
        bookmark_type: impl Into<String>,
        category: impl Into<String>,
        comment: impl Into<String>,
    ) -> Bookmark {
        let bm_type: String = bookmark_type.into();
        let cat: String = category.into();
        let comment: String = comment.into();

        if !self.bookmark_types.contains_key(&bm_type) {
            self.bookmark_types
                .insert(bm_type.clone(), BookmarkType::new(&bm_type));
        }
        self.categories.insert(cat.clone());

        let id = self.next_id;
        self.next_id += 1;
        let bm = Bookmark {
            id,
            address: addr,
            bookmark_type: bm_type,
            category: cat,
            comment,
        };
        self.bookmarks.entry(addr).or_default().push(bm.clone());
        bm
    }

    /// Remove all bookmarks at an address.
    pub fn remove_bookmarks(&mut self, addr: &Address) -> Vec<Bookmark> {
        self.bookmarks.remove(addr).unwrap_or_default()
    }

    /// Get all bookmarks at an address.
    pub fn get_bookmarks(&self, addr: &Address) -> Vec<&Bookmark> {
        self.bookmarks
            .get(addr)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Get all bookmarks of a given type.
    pub fn get_bookmarks_by_type(&self, bookmark_type: &str) -> Vec<&Bookmark> {
        self.bookmarks
            .values()
            .flatten()
            .filter(|bm| bm.bookmark_type == bookmark_type)
            .collect()
    }

    /// Get all defined bookmark types.
    pub fn get_bookmark_types(&self) -> Vec<&BookmarkType> {
        self.bookmark_types.values().collect()
    }

    /// Get all categories.
    pub fn get_categories(&self) -> Vec<&String> {
        self.categories.iter().collect()
    }

    /// Total number of bookmarks.
    pub fn num_bookmarks(&self) -> usize {
        self.bookmarks.values().map(|v| v.len()).sum()
    }

    /// Returns all addresses that currently have one or more bookmarks.
    pub fn get_bookmark_addresses(&self) -> Vec<Address> {
        self.bookmarks.keys().copied().collect()
    }
}

// ============================================================================
// CodeUnit trait — mirrors ghidra.program.model.listing.CodeUnit
// ============================================================================

/// Common interface for both instructions and data items at a specific address.
///
/// Provides query methods for length, bytes, labels, symbols, comments,
/// references, and operands. This trait is the Rust equivalent of Ghidra's
/// `CodeUnit` Java interface.
pub trait CodeUnit: Send + Sync {
    /// The start address of this code unit.
    fn get_min_address(&self) -> Address;

    /// The end address (inclusive) of this code unit.
    fn get_max_address(&self) -> Address {
        self.get_min_address().add((self.get_length() as u64).saturating_sub(1))
    }

    /// The length of this code unit in bytes.
    fn get_length(&self) -> usize;

    /// The raw bytes of this code unit.
    fn get_bytes(&self) -> Vec<u8>;

    /// The mnemonic string (e.g., "mov", "db", "dw").
    fn get_mnemonic_string(&self) -> String;

    /// The label at this code unit's address, if any.
    fn get_label(&self) -> Option<String>;

    /// Get a comment of the specified type.
    fn get_comment(&self, comment_type: CommentType) -> Option<String>;

    /// Set a comment of the specified type.
    fn set_comment(&mut self, comment_type: CommentType, comment: Option<String>);

    /// The number of operands (0 for data items, 0..N for instructions).
    fn get_num_operands(&self) -> usize;

    /// Returns true if this address is within this code unit's range.
    fn contains(&self, addr: &Address) -> bool {
        let min = self.get_min_address();
        let max = self.get_max_address();
        addr.offset >= min.offset && addr.offset <= max.offset
    }

    /// Returns true if this code unit is an instruction.
    fn is_instruction(&self) -> bool;

    /// Returns true if this code unit is a data item.
    fn is_data(&self) -> bool;
}

// ============================================================================
// Group trait — mirrors ghidra.program.model.listing.Group
// ============================================================================

/// Base trait for program tree nodes (fragments and modules).
/// Corresponds to Ghidra's `Group` interface.
pub trait Group: Send + Sync {
    /// The name of this group.
    fn get_name(&self) -> &str;

    /// Set the name.
    fn set_name(&mut self, name: String);

    /// The comment/description.
    fn get_comment(&self) -> Option<&str>;

    /// Set the comment.
    fn set_comment(&mut self, comment: Option<String>);

    /// Get the alias (alternate name).
    fn get_alias(&self) -> Option<&str>;

    /// Set the alias.
    fn set_alias(&mut self, alias: Option<String>);

    /// Returns true if this group is empty (no addresses).
    fn is_empty(&self) -> bool;

    /// The minimum address covered by this group.
    fn get_min_address(&self) -> Option<Address>;

    /// The maximum address covered by this group.
    fn get_max_address(&self) -> Option<Address>;

    /// A unique name for this group.
    fn get_unique_name(&self) -> String;
}

// ============================================================================
// ProgramFragment — mirrors ghidra.program.model.listing.ProgramFragment
// ============================================================================

/// A fragment is a leaf node in the program tree. It holds a set of addresses
/// and cannot contain children.
#[derive(Debug, Clone)]
pub struct ProgramFragment {
    /// The fragment name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional alias.
    pub alias: Option<String>,
    /// The set of addresses in this fragment.
    pub addresses: HashSet<Address>,
}

impl ProgramFragment {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            comment: None,
            alias: None,
            addresses: HashSet::new(),
        }
    }

    /// Add an address to this fragment.
    pub fn add_address(&mut self, addr: Address) {
        self.addresses.insert(addr);
    }

    /// Remove an address from this fragment.
    pub fn remove_address(&mut self, addr: &Address) -> bool {
        self.addresses.remove(addr)
    }

    /// Move all addresses in the given range to a new base.
    pub fn move_addresses(&mut self, min_addr: Address, max_addr: Address, new_base: Address) {
        let delta = new_base.offset as i64 - min_addr.offset as i64;
        let to_move: Vec<Address> = self
            .addresses
            .iter()
            .filter(|a| a.offset >= min_addr.offset && a.offset <= max_addr.offset)
            .copied()
            .collect();
        for addr in to_move {
            self.addresses.remove(&addr);
            let new_addr = if delta >= 0 {
                addr.add(delta as u64)
            } else {
                addr.sub((-delta) as u64)
            };
            self.addresses.insert(new_addr);
        }
    }
}

impl Group for ProgramFragment {
    fn get_name(&self) -> &str {
        &self.name
    }

    fn set_name(&mut self, name: String) {
        self.name = name;
    }

    fn get_comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    fn set_comment(&mut self, comment: Option<String>) {
        self.comment = comment;
    }

    fn get_alias(&self) -> Option<&str> {
        self.alias.as_deref()
    }

    fn set_alias(&mut self, alias: Option<String>) {
        self.alias = alias;
    }

    fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    fn get_min_address(&self) -> Option<Address> {
        self.addresses.iter().min_by_key(|a| a.offset).copied()
    }

    fn get_max_address(&self) -> Option<Address> {
        self.addresses.iter().max_by_key(|a| a.offset).copied()
    }

    fn get_unique_name(&self) -> String {
        self.name.clone()
    }
}

// ============================================================================
// ProgramModule trait — mirrors ghidra.program.model.listing.ProgramModule
// ============================================================================

/// A module is an internal node in the program tree. It can contain children
/// which are either other modules or fragments.
///
/// Corresponds to Ghidra's `ProgramModule` interface.
pub trait ProgramModule: Group {
    /// Returns true if this module directly contains the given fragment.
    fn contains_fragment(&self, fragment: &ProgramFragment) -> bool;

    /// Returns true if this module directly contains the given module.
    fn contains_module(&self, module: &dyn ProgramModule) -> bool;

    /// The number of direct children.
    fn get_num_children(&self) -> usize;

    /// Get all direct children (modules and fragments mixed).
    fn get_children(&self) -> Vec<&dyn Group>;

    /// Get the index of the child with the given name, or -1 if not found.
    fn get_index(&self, name: &str) -> Option<usize>;

    /// Add a module as a child.
    fn add_module(
        &mut self,
        module: &dyn ProgramModule,
    ) -> Result<(), String>; // CircularDependencyException, DuplicateGroupException

    /// Add a fragment as a child.
    fn add_fragment(&mut self, fragment: &ProgramFragment) -> Result<(), String>;

    /// Create a new child module with the given name.
    fn create_module(&mut self, module_name: &str) -> Result<Box<dyn ProgramModule>, String>;

    /// Create a new child fragment with the given name.
    fn create_fragment(&mut self, fragment_name: &str) -> Result<ProgramFragment, String>;

    /// Reparent a child from another module to this one.
    fn reparent(
        &mut self,
        name: &str,
        old_parent: &dyn ProgramModule,
    ) -> Result<(), String>;

    /// Move a child to a new index position.
    fn move_child(&mut self, name: &str, index: usize) -> Result<(), String>;

    /// Remove a child by name. Returns true if removed.
    fn remove_child(&mut self, name: &str) -> Result<bool, String>;

    /// Returns true if the given module is a descendant of this module.
    fn is_descendant_of_module(&self, module: &dyn ProgramModule) -> bool;

    /// Returns true if the given fragment is a descendant of this module.
    fn is_descendant_of_fragment(&self, fragment: &ProgramFragment) -> bool;

    /// The first address (by user ordering of children).
    fn get_first_address(&self) -> Option<Address>;

    /// The last address (by user ordering of children).
    fn get_last_address(&self) -> Option<Address>;

    /// The address set covering all descendant fragments.
    fn get_address_set(&self) -> Vec<AddressRange>;

    /// A version tag for detecting undo/redo changes.
    fn get_version_tag(&self) -> u64;

    /// The current modification number of this module tree.
    fn get_modification_number(&self) -> u64;

    /// The tree ID this module belongs to.
    fn get_tree_id(&self) -> u64;
}

// ============================================================================
// CodeUnitFormat — mirrors ghidra.program.model.listing.CodeUnitFormat
// ============================================================================

/// Options controlling how CodeUnitFormat renders code units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeUnitFormatOptions {
    /// Show block name in address display.
    pub show_block_name: bool,
    /// Pad address with leading zeros for fixed-width columns.
    pub pad_address: bool,
    /// Show the mnemonic column.
    pub show_mnemonic: bool,
    /// Show the operand column.
    pub show_operands: bool,
    /// Show the bytes column.
    pub show_bytes: bool,
    /// Show the comment column.
    pub show_comments: bool,
    /// Maximum number of spaces between columns.
    pub column_spacing: usize,
}

impl Default for CodeUnitFormatOptions {
    fn default() -> Self {
        Self {
            show_block_name: false,
            pad_address: true,
            show_mnemonic: true,
            show_operands: true,
            show_bytes: true,
            show_comments: true,
            column_spacing: 2,
        }
    }
}

/// Formats code units (instructions and data items) for display in a listing view.
///
/// Equivalent to Ghidra's `CodeUnitFormat` class. Produces formatted strings
/// suitable for display in a terminal or GUI listing window.
#[derive(Debug, Clone)]
pub struct CodeUnitFormat {
    /// Display options.
    pub options: CodeUnitFormatOptions,
}

impl CodeUnitFormat {
    /// Create a new formatter with default options.
    pub fn new() -> Self {
        Self {
            options: CodeUnitFormatOptions::default(),
        }
    }

    /// Create a formatter with specific options.
    pub fn with_options(options: CodeUnitFormatOptions) -> Self {
        Self { options }
    }

    /// Format the address portion of a code unit display.
    pub fn format_address(&self, addr: &Address) -> String {
        if self.options.pad_address {
            format!("{:08x}", addr.offset)
        } else {
            format!("{:x}", addr.offset)
        }
    }

    /// Format the bytes portion of a code unit display.
    pub fn format_bytes(&self, bytes: &[u8]) -> String {
        let hex_parts: Vec<String> = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        hex_parts.join(" ")
    }

    /// Format an instruction for display.
    pub fn format_instruction(&self, ins: &Instruction) -> String {
        let mut parts = Vec::new();

        if self.options.show_bytes {
            parts.push(self.format_bytes(&ins.bytes));
        }

        if let Some(ref label) = ins.label {
            parts.push(format!("{}:", label));
        }

        if self.options.show_mnemonic {
            parts.push(ins.mnemonic.clone());
        }

        if self.options.show_operands {
            let op_strs: Vec<String> = ins.operands.iter().map(|o| o.to_string()).collect();
            parts.push(op_strs.join(", "));
        }

        if self.options.show_comments {
            if let Some(ref comment) = ins.comment {
                parts.push(format!("; {}", comment));
            }
        }

        parts.join(
            &" ".repeat(self.options.column_spacing),
        )
    }

    /// Format a data item for display.
    pub fn format_data(&self, data: &Data) -> String {
        let mut parts = Vec::new();

        if self.options.show_bytes {
            // Data does not directly hold raw bytes — use type name as surrogate
            parts.push(data.data_type_name.clone());
        }

        if let Some(ref label) = data.label {
            parts.push(format!("{}:", label));
        }

        parts.push(data.data_type_name.clone());

        if let Some(ref value) = data.value {
            parts.push(value.clone());
        }

        if self.options.show_comments {
            if let Some(ref comment) = data.comment {
                parts.push(format!("; {}", comment));
            }
        }

        parts.join(
            &" ".repeat(self.options.column_spacing),
        )
    }
}

impl Default for CodeUnitFormat {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// CodeUnitComment — convenience type for comment rendering
// ============================================================================

/// A comment attached to a code unit with its type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeUnitComment {
    /// The type of comment.
    pub comment_type: CommentType,
    /// The comment text.
    pub text: String,
}

impl CodeUnitComment {
    pub fn new(comment_type: CommentType, text: impl Into<String>) -> Self {
        Self {
            comment_type,
            text: text.into(),
        }
    }
}

// ============================================================================
// CodeUnit (concrete struct) — for storage/iteration
// ============================================================================
// Note: The `CodeUnit` trait is defined above. This is a simple concrete
// struct used for storage in collections and returned by iterators.
// It is NOT the same as the trait above; the existing alias in mod.rs
// re-exports the struct under the same name for backward compatibility.
// For new code, prefer the `CodeUnit` trait.

/// A concrete code unit used for storage in collections.
/// This is a simple data holder, distinct from the `CodeUnit` trait defined above.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeUnitData {
    /// The start address of this code unit.
    pub address: Address,
    /// How many bytes this code unit occupies.
    pub length: usize,
    /// The raw bytes in this code unit.
    pub bytes: Vec<u8>,
    /// An optional comment attached to this code unit.
    pub comment: Option<String>,
    /// Arbitrary key-value properties.
    pub properties: BTreeMap<String, String>,
}

impl CodeUnitData {
    pub fn new(address: Address, length: usize, bytes: Vec<u8>) -> Self {
        Self {
            address,
            length,
            bytes,
            comment: None,
            properties: BTreeMap::new(),
        }
    }

    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    pub fn with_property(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.properties.insert(key.into(), value.into());
        self
    }

    pub fn next_address(&self) -> Address {
        self.address.add(self.length as u64)
    }

    pub fn contains(&self, addr: &Address) -> bool {
        addr.offset >= self.address.offset
            && addr.offset < self.address.offset + self.length as u64
    }

    pub fn get_property(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(|s| s.as_str())
    }

    pub fn is_instruction(&self) -> bool {
        self.properties.contains_key("INSTRUCTION")
    }

    pub fn is_data(&self) -> bool {
        self.properties.contains_key("DATA_TYPE")
    }
}

// ============================================================================
// Instruction — mirrors ghidra.program.model.listing.Instruction
// ============================================================================

/// A decoded instruction within the listing.
///
/// Corresponds to Ghidra's `Instruction` interface. Includes the mnemonic,
/// operand list, flow type, fall-through address, delay slot metadata,
/// p-code micro-operations, length override support, and label/comment.
#[derive(Debug, Clone)]
pub struct Instruction {
    /// The address of this instruction.
    pub address: Address,
    /// The effective length (may differ from parsed length if length-overridden).
    pub length: usize,
    /// The raw opcode bytes (effective length).
    pub bytes: Vec<u8>,
    /// The mnemonic string (e.g., "mov", "call", "jmp").
    pub mnemonic: String,
    /// The operand representation.
    pub operands: Vec<Operand>,
    /// The P-code micro-operation sequences.
    pub pcode_sequences: Vec<Vec<String>>,
    /// The default fall-through address (from the prototype).
    pub default_fallthrough: Option<Address>,
    /// The effective fall-through address (default or overridden).
    pub fallthrough_address: Option<Address>,
    /// The address that falls through to this instruction.
    pub fall_from: Option<Address>,
    /// The control-flow type.
    pub flow_type: FlowType,
    /// Flow override (if any).
    pub flow_override: FlowOverride,
    /// Delay slot depth (0 = no delay slots).
    pub delay_slot_depth: usize,
    /// Whether this instruction is itself in a delay slot.
    pub is_in_delay_slot: bool,
    /// Whether the length has been overridden.
    pub length_overridden: bool,
    /// The actual parsed length (before any length override).
    pub parsed_length: usize,
    /// Whether the fall-through has been overridden.
    pub fallthrough_overridden: bool,
    /// Optional label at this address.
    pub label: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Cross-reference targets.
    pub xref_targets: Vec<Address>,
}

impl Instruction {
    /// Maximum length override value.
    pub const MAX_LENGTH_OVERRIDE: usize = 7;
    /// Invalid depth change constant.
    pub const INVALID_DEPTH_CHANGE: i32 = 0x0100_0000;

    /// Create a new instruction.
    pub fn new(
        address: Address,
        length: usize,
        bytes: Vec<u8>,
        mnemonic: impl Into<String>,
    ) -> Self {
        Self {
            address,
            length,
            bytes,
            mnemonic: mnemonic.into(),
            operands: Vec::new(),
            pcode_sequences: Vec::new(),
            default_fallthrough: None,
            fallthrough_address: None,
            fall_from: None,
            flow_type: FlowType::Normal,
            flow_override: FlowOverride::None,
            delay_slot_depth: 0,
            is_in_delay_slot: false,
            length_overridden: false,
            parsed_length: length,
            fallthrough_overridden: false,
            label: None,
            comment: None,
            xref_targets: Vec::new(),
        }
    }

    /// Builder: add an operand.
    pub fn with_operand(mut self, op: Operand) -> Self {
        self.operands.push(op);
        self
    }

    /// Builder: set all operands.
    pub fn with_operands(mut self, ops: Vec<Operand>) -> Self {
        self.operands = ops;
        self
    }

    /// Builder: set the flow type.
    pub fn with_flow_type(mut self, flow: FlowType) -> Self {
        self.flow_type = flow;
        self
    }

    /// Builder: set the fall-through address.
    pub fn with_fallthrough(mut self, addr: Address) -> Self {
        self.default_fallthrough = Some(addr);
        self.fallthrough_address = Some(addr);
        self
    }

    /// Builder: set delay slot metadata.
    pub fn with_delay_slot(mut self, depth: usize, is_in_slot: bool) -> Self {
        self.delay_slot_depth = depth;
        self.is_in_delay_slot = is_in_slot;
        self
    }

    /// Builder: set a label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Builder: set a comment.
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Set the flow override.
    pub fn set_flow_override(&mut self, flow_override: FlowOverride) {
        self.flow_override = flow_override;
    }

    /// Override the fall-through address.
    pub fn set_fall_through(&mut self, addr: Option<Address>) {
        self.fallthrough_address = addr;
        self.fallthrough_overridden = true;
    }

    /// Clear the fall-through override, restoring the default.
    pub fn clear_fall_through_override(&mut self) {
        self.fallthrough_address = self.default_fallthrough;
        self.fallthrough_overridden = false;
    }

    /// Returns true if the fall-through has been overridden.
    pub fn is_fall_through_overridden(&self) -> bool {
        self.fallthrough_overridden
    }

    /// Set a length override.
    pub fn set_length_override(&mut self, length: usize) -> Result<(), String> {
        if length > Self::MAX_LENGTH_OVERRIDE {
            return Err(format!(
                "Length override {} exceeds maximum {}",
                length,
                Self::MAX_LENGTH_OVERRIDE
            ));
        }
        if length == 0 {
            self.length = self.parsed_length;
            self.length_overridden = false;
        } else {
            self.length = length;
            self.length_overridden = true;
        }
        Ok(())
    }

    /// Get the parsed (original) bytes.
    pub fn get_parsed_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Add a p-code micro-op sequence.
    pub fn add_pcode(&mut self, pcode: Vec<String>) {
        self.pcode_sequences.push(pcode);
    }

    /// Returns true if this is a branch instruction (jump or call).
    pub fn is_branch(&self) -> bool {
        self.flow_type.is_branch()
    }

    /// Returns true if this is a call instruction.
    pub fn is_call(&self) -> bool {
        self.flow_type.is_call()
    }

    /// Returns true if this is a return instruction.
    pub fn is_return(&self) -> bool {
        self.flow_type == FlowType::Return
    }

    /// Returns true if execution falls through to the next instruction.
    pub fn has_fallthrough(&self) -> bool {
        self.fallthrough_address.is_some() && self.flow_type != FlowType::Terminator
    }

    /// Returns true if this is a simple fall-through (no branch flow).
    pub fn is_fallthrough(&self) -> bool {
        self.flow_type == FlowType::Normal && self.flow_override == FlowOverride::None
    }

    /// The address immediately following this instruction.
    pub fn next_address(&self) -> Address {
        self.address.add(self.length as u64)
    }

    /// Get the effective fall-through address.
    pub fn get_fall_through(&self) -> Option<Address> {
        self.fallthrough_address
    }

    /// Get the default fall-through from the prototype.
    pub fn get_default_fall_through(&self) -> Option<Address> {
        self.default_fallthrough
    }

    /// Render the full instruction string for display.
    pub fn full_instruction(&self) -> String {
        if self.operands.is_empty() {
            self.mnemonic.clone()
        } else {
            let ops: Vec<String> = self.operands.iter().map(|o| o.to_string()).collect();
            format!("{} {}", self.mnemonic, ops.join(", "))
        }
    }
}

// ============================================================================
// Data — mirrors ghidra.program.model.listing.Data
// ============================================================================

/// A data item within the listing — a typed value applied at an address.
///
/// Corresponds to Ghidra's `Data` interface. Supports structures, unions,
/// arrays, pointers, typedefs, and component hierarchies.
#[derive(Debug, Clone)]
pub struct Data {
    /// The address of this data item.
    pub address: Address,
    /// The size of this data item in bytes.
    pub size: usize,
    /// The data type applied at this location.
    pub data_type: Option<Arc<dyn DataType>>,
    /// The name of the data type (for display).
    pub data_type_name: String,
    /// An optional interpreted value string (e.g., "42", "\"hello\"").
    pub value: Option<String>,
    /// Whether this data type has been defined (not an undefined placeholder).
    pub is_defined: bool,
    /// Whether this data is a pointer.
    pub is_pointer: bool,
    /// Whether this data is a union.
    pub is_union: bool,
    /// Whether this data is a structure.
    pub is_structure: bool,
    /// Whether this data is an array.
    pub is_array: bool,
    /// Whether this data is dynamic (size determined at runtime).
    pub is_dynamic: bool,
    /// Whether this data is constant (not writable).
    pub is_constant: bool,
    /// The field name if this is a component of a composite type.
    pub field_name: Option<String>,
    /// The component path (indices into parent composites).
    pub component_path: Vec<usize>,
    /// Sub-components (for composite types).
    pub components: Vec<Data>,
    /// The parent data item, if this is a component.
    pub parent: Option<Box<Data>>,
    /// Offset from the parent data item start.
    pub parent_offset: usize,
    /// Offset from the root data item start.
    pub root_offset: usize,
    /// Optional label at this address.
    pub label: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
}

impl Data {
    /// Create a new data item.
    pub fn new(
        address: Address,
        size: usize,
        data_type: Option<Arc<dyn DataType>>,
    ) -> Self {
        let name = data_type
            .as_ref()
            .map(|dt| dt.name().to_string())
            .unwrap_or_else(|| "undefined".to_string());
        let is_defined = data_type.as_ref().map(|dt| dt.is_defined()).unwrap_or(false);
        let is_pointer = data_type.as_ref().map(|dt| dt.is_pointer()).unwrap_or(false);
        Self {
            address,
            size,
            data_type,
            data_type_name: name,
            value: None,
            is_defined,
            is_pointer,
            is_union: false,
            is_structure: false,
            is_array: false,
            is_dynamic: false,
            is_constant: false,
            field_name: None,
            component_path: Vec::new(),
            components: Vec::new(),
            parent: None,
            parent_offset: 0,
            root_offset: 0,
            label: None,
            comment: None,
        }
    }

    /// Builder: set a display value.
    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.value = Some(value.into());
        self
    }

    /// Builder: set a label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Builder: set a comment.
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Builder: set as structure.
    pub fn with_structure(mut self) -> Self {
        self.is_structure = true;
        self
    }

    /// Builder: set as union.
    pub fn with_union(mut self) -> Self {
        self.is_union = true;
        self
    }

    /// Builder: set as array.
    pub fn with_array(mut self) -> Self {
        self.is_array = true;
        self
    }

    /// Get a component by index.
    pub fn get_component(&self, index: usize) -> Option<&Data> {
        self.components.get(index)
    }

    /// Get a component by its component path.
    pub fn get_component_by_path(&self, path: &[usize]) -> Option<&Data> {
        let mut current = self;
        for &idx in path {
            current = current.components.get(idx)?;
        }
        Some(current)
    }

    /// Number of immediate child components.
    pub fn get_num_components(&self) -> usize {
        self.components.len()
    }

    /// The component level (0 = top-level, 1 = direct child, etc.).
    pub fn get_component_level(&self) -> usize {
        self.component_path.len()
    }

    /// Returns true if this data item has any child components.
    pub fn has_components(&self) -> bool {
        !self.components.is_empty()
    }

    /// Returns true if this data item is the top-level/root data object.
    pub fn is_root(&self) -> bool {
        self.parent.is_none() && self.component_path.is_empty()
    }

    /// Returns true if this has a string value (the data type produces a String).
    pub fn has_string_value(&self) -> bool {
        self.data_type_name.contains("string")
            || self.data_type_name.contains("String")
    }

    /// The default value representation string.
    pub fn get_default_value_representation(&self) -> String {
        self.value.clone().unwrap_or_else(|| "??".to_string())
    }

    /// The full path name (dot notation) for this field.
    pub fn get_path_name(&self) -> String {
        if let Some(ref field) = self.field_name {
            if let Some(ref parent) = self.parent {
                format!("{}.{}", parent.get_path_name(), field)
            } else {
                field.clone()
            }
        } else {
            self.data_type_name.clone()
        }
    }

    /// The component path name (dot notation) for this field.
    pub fn get_component_path_name(&self) -> String {
        self.get_path_name()
    }

    /// Get the root data item (top-level parent).
    pub fn get_root(&self) -> &Data {
        let mut current = self;
        while let Some(ref parent) = current.parent {
            current = parent;
        }
        current
    }
}

// ============================================================================
// Listing trait — mirrors ghidra.program.model.listing.Listing
// ============================================================================

/// The abstract interface for interacting with the program listing.
///
/// A [`Listing`] provides query and modification methods for code units,
/// instructions, data items, comments, and functions. This trait corresponds
/// to Ghidra's `Listing` Java interface.
pub trait Listing: Send + Sync {
    /// Default tree name constant.
    const DEFAULT_TREE_NAME: &'static str = "Program Tree";

    // ---- Code Unit queries ----

    /// Get the code unit that starts at the given address.
    fn get_code_unit_at(&self, addr: &Address) -> Option<CodeUnitData>;

    /// Get the code unit that contains the given address.
    fn get_code_unit_containing(&self, addr: &Address) -> Option<CodeUnitData>;

    /// Get the next code unit after the given address.
    fn get_code_unit_after(&self, addr: &Address) -> Option<CodeUnitData>;

    /// Get the code unit before the given address.
    fn get_code_unit_before(&self, addr: &Address) -> Option<CodeUnitData>;

    // ---- Instruction queries ----

    /// Get the instruction at the given address.
    fn get_instruction_at(&self, addr: &Address) -> Option<Instruction>;

    /// Get the instruction containing the given address.
    fn get_instruction_containing(&self, addr: &Address) -> Option<Instruction>;

    /// Get the instruction after the given address.
    fn get_instruction_after(&self, addr: &Address) -> Option<Instruction>;

    /// Get the instruction before the given address.
    fn get_instruction_before(&self, addr: &Address) -> Option<Instruction>;

    // ---- Data queries ----

    /// Get the data item (defined or undefined) at the given address.
    fn get_data_at(&self, addr: &Address) -> Option<Data>;

    /// Get the data item containing the given address.
    fn get_data_containing(&self, addr: &Address) -> Option<Data>;

    /// Get the data item after the given address.
    fn get_data_after(&self, addr: &Address) -> Option<Data>;

    /// Get the data item before the given address.
    fn get_data_before(&self, addr: &Address) -> Option<Data>;

    /// Get the defined data item at the given address.
    fn get_defined_data_at(&self, addr: &Address) -> Option<Data>;

    /// Get the undefined data item at the given address.
    fn get_undefined_data_at(&self, addr: &Address) -> Option<Data>;

    // ---- Comments ----

    /// Get a comment of a specific type at an address.
    fn get_comment(&self, comment_type: CommentType, address: &Address) -> Option<String>;

    /// Get all comments at an address.
    fn get_all_comments(&self, address: &Address) -> CodeUnitComments;

    /// Set a comment of a specific type at an address.
    fn set_comment(
        &mut self,
        address: Address,
        comment_type: CommentType,
        comment: Option<String>,
    );

    // ---- Iteration ----

    /// Get code units in the given range (forward).
    fn get_code_units(&self, range: &AddressRange) -> Vec<CodeUnitData>;

    /// Get instructions in the given range.
    fn get_instructions(&self, range: &AddressRange) -> Vec<Instruction>;

    /// Get data items in the given range.
    fn get_data(&self, range: &AddressRange) -> Vec<Data>;

    // ---- Modification ----

    /// Create a code unit at the given address.
    fn create_code_unit(
        &mut self,
        addr: Address,
        length: usize,
        bytes: Vec<u8>,
    ) -> Result<(), String>;

    /// Remove a code unit at the given address.
    fn remove_code_unit(&mut self, addr: &Address) -> Result<(), String>;

    /// Clear all code units in the given range.
    fn clear_code_units(&mut self, range: &AddressRange) -> Result<(), String>;

    /// Clear comments in the given range.
    fn clear_comments(&mut self, start_addr: Address, end_addr: Address);

    /// Returns true if the given range is entirely undefined.
    fn is_undefined(&self, start: Address, end: Address) -> bool;

    // ---- Program tree ----

    /// Get the names of all program trees.
    fn get_tree_names(&self) -> Vec<String>;

    /// Get the root module for a tree.
    fn get_root_module(&self, tree_name: &str) -> Option<Box<dyn ProgramModule>>;

    /// Create a root module (new tree).
    fn create_root_module(
        &mut self,
        tree_name: &str,
    ) -> Result<Box<dyn ProgramModule>, String>;

    /// Remove a tree.
    fn remove_tree(&mut self, tree_name: &str) -> bool;

    // ---- Statistics ----

    /// Total number of code units.
    fn get_num_code_units(&self) -> usize;

    /// Total number of defined data items.
    fn get_num_defined_data(&self) -> usize;

    /// Total number of instructions.
    fn get_num_instructions(&self) -> usize;

    // ---- Bounds ----

    /// Minimum address that has a code unit.
    fn get_min_address(&self) -> Option<Address>;

    /// Maximum address that has a code unit.
    fn get_max_address(&self) -> Option<Address>;

    /// Raw bytes at an address.
    fn get_bytes(&self, addr: Address, length: usize) -> Vec<u8>;
}

// ============================================================================
// InMemoryListing — a concrete, in-memory implementation of Listing
// ============================================================================

/// A simple in-memory implementation of [`Listing`] backed by `BTreeMap`s.
#[derive(Debug, Clone, Default)]
pub struct InMemoryListing {
    /// Code units indexed by address.
    code_units: BTreeMap<Address, CodeUnitData>,
    /// Instructions indexed by address.
    instructions: BTreeMap<Address, Instruction>,
    /// Data items indexed by address.
    data_items: BTreeMap<Address, Data>,
    /// Comments indexed by address.
    comments: HashMap<Address, CodeUnitComments>,
    /// Raw bytes storage.
    raw_bytes: HashMap<Address, Vec<u8>>,
    /// Compatibility: listing rows indexed by address (used by ghidra-app).
    pub rows: HashMap<Address, crate::listing::ListingRow>,
}

impl InMemoryListing {
    /// Create a new empty listing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a listing row at the given address (compatibility).
    pub fn add(&mut self, addr: Address, row: crate::listing::ListingRow) {
        self.rows.insert(addr, row);
    }

    /// Get a listing row at the given address (compatibility).
    pub fn get(&self, addr: &Address) -> Option<&crate::listing::ListingRow> {
        self.rows.get(addr)
    }

    /// Get all code unit addresses in order as listing rows.
    pub fn get_all_rows(&self) -> Vec<crate::listing::ListingRow> {
        self.code_units
            .iter()
            .map(|(addr, cu)| {
                let bytes = self.raw_bytes.get(addr).cloned().unwrap_or_else(|| cu.bytes.clone());
                crate::listing::ListingRow {
                    address: *addr,
                    bytes,
                    label: None,
                    mnemonic: crate::listing::InstructionMnemonic::new(
                        self.instructions.get(addr).map(|i| i.mnemonic.as_str()).unwrap_or("db")
                    ),
                    operands: self.instructions.get(addr).map(|i| {
                        i.operands.iter().map(|o| format!("{}", o)).collect::<Vec<_>>().join(", ")
                    }).unwrap_or_default(),
                    full_instruction: self.instructions.get(addr).map(|i| {
                        let ops = i.operands.iter().map(|o| format!("{}", o)).collect::<Vec<_>>().join(", ");
                        if ops.is_empty() { i.mnemonic.clone() } else { format!("{} {}", i.mnemonic, ops) }
                    }).unwrap_or_else(|| "db".to_string()),
                    comment: self.comments.get(addr).and_then(|c| c.eol_comment.clone()),
                }
            })
            .collect()
    }

    /// Number of stored code units.
    pub fn code_unit_count(&self) -> usize { self.code_units.len() }

    /// Number of stored instructions.
    pub fn instruction_count(&self) -> usize { self.instructions.len() }

    /// Number of stored data items.
    pub fn data_count(&self) -> usize { self.data_items.len() }

    /// Returns true if a code unit starts at the given address.
    pub fn has_code_unit_at(&self, addr: &Address) -> bool { self.code_units.contains_key(addr) }

    /// Returns true if an instruction starts at the given address.
    pub fn has_instruction_at(&self, addr: &Address) -> bool { self.instructions.contains_key(addr) }

    /// Returns true if a data item starts at the given address.
    pub fn has_data_at(&self, addr: &Address) -> bool { self.data_items.contains_key(addr) }

    /// Number of addresses with at least one stored comment.
    pub fn comment_address_count(&self) -> usize { self.comments.len() }
}

impl Listing for InMemoryListing {
    fn get_code_unit_at(&self, addr: &Address) -> Option<CodeUnitData> {
        self.code_units.get(addr).cloned()
    }

    fn get_code_unit_containing(&self, addr: &Address) -> Option<CodeUnitData> {
        self.code_units
            .values()
            .find(|cu| cu.contains(addr))
            .cloned()
    }

    fn get_code_unit_after(&self, addr: &Address) -> Option<CodeUnitData> {
        self.code_units
            .range((std::ops::Bound::Excluded(addr), std::ops::Bound::Unbounded))
            .next()
            .map(|(_, cu)| cu.clone())
    }

    fn get_code_unit_before(&self, addr: &Address) -> Option<CodeUnitData> {
        self.code_units
            .range((std::ops::Bound::Unbounded, std::ops::Bound::Excluded(addr)))
            .next_back()
            .map(|(_, cu)| cu.clone())
    }

    fn get_instruction_at(&self, addr: &Address) -> Option<Instruction> {
        self.instructions.get(addr).cloned()
    }

    fn get_instruction_containing(&self, addr: &Address) -> Option<Instruction> {
        self.instructions
            .values()
            .find(|ins| {
                addr.offset >= ins.address.offset
                    && addr.offset < ins.address.offset + ins.length as u64
            })
            .cloned()
    }

    fn get_instruction_after(&self, addr: &Address) -> Option<Instruction> {
        self.instructions
            .range((std::ops::Bound::Excluded(addr), std::ops::Bound::Unbounded))
            .next()
            .map(|(_, ins)| ins.clone())
    }

    fn get_instruction_before(&self, addr: &Address) -> Option<Instruction> {
        self.instructions
            .range((std::ops::Bound::Unbounded, std::ops::Bound::Excluded(addr)))
            .next_back()
            .map(|(_, ins)| ins.clone())
    }

    fn get_data_at(&self, addr: &Address) -> Option<Data> {
        self.data_items.get(addr).cloned()
    }

    fn get_data_containing(&self, addr: &Address) -> Option<Data> {
        self.data_items
            .values()
            .find(|d| {
                addr.offset >= d.address.offset
                    && addr.offset < d.address.offset + d.size as u64
            })
            .cloned()
    }

    fn get_data_after(&self, addr: &Address) -> Option<Data> {
        self.data_items
            .range((std::ops::Bound::Excluded(addr), std::ops::Bound::Unbounded))
            .next()
            .map(|(_, d)| d.clone())
    }

    fn get_data_before(&self, addr: &Address) -> Option<Data> {
        self.data_items
            .range((std::ops::Bound::Unbounded, std::ops::Bound::Excluded(addr)))
            .next_back()
            .map(|(_, d)| d.clone())
    }

    fn get_defined_data_at(&self, addr: &Address) -> Option<Data> {
        self.data_items.get(addr).filter(|d| d.is_defined).cloned()
    }

    fn get_undefined_data_at(&self, addr: &Address) -> Option<Data> {
        self.data_items.get(addr).filter(|d| !d.is_defined).cloned()
    }

    fn get_comment(&self, comment_type: CommentType, address: &Address) -> Option<String> {
        self.comments
            .get(address)
            .and_then(|c| c.get_comment(comment_type))
            .map(|s| s.to_string())
    }

    fn get_all_comments(&self, address: &Address) -> CodeUnitComments {
        self.comments
            .get(address)
            .cloned()
            .unwrap_or_else(|| CodeUnitComments::new(*address))
    }

    fn set_comment(
        &mut self,
        address: Address,
        comment_type: CommentType,
        comment: Option<String>,
    ) {
        self.comments
            .entry(address)
            .or_insert_with(|| CodeUnitComments::new(address))
            .set_comment(comment_type, comment);
    }

    fn get_code_units(&self, range: &AddressRange) -> Vec<CodeUnitData> {
        self.code_units
            .range(range.start..=range.end)
            .map(|(_, cu)| cu.clone())
            .collect()
    }

    fn get_instructions(&self, range: &AddressRange) -> Vec<Instruction> {
        self.instructions
            .range(range.start..=range.end)
            .map(|(_, ins)| ins.clone())
            .collect()
    }

    fn get_data(&self, range: &AddressRange) -> Vec<Data> {
        self.data_items
            .range(range.start..=range.end)
            .map(|(_, d)| d.clone())
            .collect()
    }

    fn create_code_unit(
        &mut self,
        addr: Address,
        length: usize,
        bytes: Vec<u8>,
    ) -> Result<(), String> {
        let cu = CodeUnitData::new(addr, length, bytes.clone());
        self.code_units.insert(addr, cu);
        self.raw_bytes.insert(addr, bytes);
        Ok(())
    }

    fn remove_code_unit(&mut self, addr: &Address) -> Result<(), String> {
        self.code_units.remove(addr);
        self.instructions.remove(addr);
        self.data_items.remove(addr);
        self.raw_bytes.remove(addr);
        Ok(())
    }

    fn clear_code_units(&mut self, range: &AddressRange) -> Result<(), String> {
        let addrs: Vec<Address> = self
            .code_units
            .range(range.start..=range.end)
            .map(|(a, _)| *a)
            .collect();
        for addr in addrs {
            self.code_units.remove(&addr);
            self.instructions.remove(&addr);
            self.data_items.remove(&addr);
            self.raw_bytes.remove(&addr);
            self.comments.remove(&addr);
        }
        Ok(())
    }

    fn clear_comments(&mut self, start_addr: Address, end_addr: Address) {
        let to_remove: Vec<Address> = self
            .comments
            .keys()
            .filter(|a| a.offset >= start_addr.offset && a.offset <= end_addr.offset)
            .copied()
            .collect();
        for addr in to_remove {
            self.comments.remove(&addr);
        }
    }

    fn is_undefined(&self, start: Address, end: Address) -> bool {
        for offset in start.offset..=end.offset {
            let addr = Address::new(offset);
            if self.code_units.contains_key(&addr)
                || self.instructions.contains_key(&addr)
                || self.data_items.contains_key(&addr)
            {
                return false;
            }
        }
        true
    }

    fn get_tree_names(&self) -> Vec<String> {
        vec![Self::DEFAULT_TREE_NAME.to_string()]
    }

    fn get_root_module(&self, _tree_name: &str) -> Option<Box<dyn ProgramModule>> {
        None
    }

    fn create_root_module(
        &mut self,
        _tree_name: &str,
    ) -> Result<Box<dyn ProgramModule>, String> {
        Err("ProgramModule not implemented in InMemoryListing".to_string())
    }

    fn remove_tree(&mut self, _tree_name: &str) -> bool {
        false
    }

    fn get_num_code_units(&self) -> usize {
        self.code_units.len()
    }

    fn get_num_defined_data(&self) -> usize {
        self.data_items.values().filter(|d| d.is_defined).count()
    }

    fn get_num_instructions(&self) -> usize {
        self.instructions.len()
    }

    fn get_min_address(&self) -> Option<Address> {
        self.code_units.keys().next().copied()
    }

    fn get_max_address(&self) -> Option<Address> {
        self.code_units.keys().next_back().copied()
    }

    fn get_bytes(&self, addr: Address, length: usize) -> Vec<u8> {
        if let Some(data) = self.raw_bytes.get(&addr) {
            let take = length.min(data.len());
            data[..take].to_vec()
        } else {
            Vec::new()
        }
    }
}

// ============================================================================
// Function — mirrors ghidra.program.model.listing.Function
// ============================================================================

/// A function in the program. Functions have an entry point, a body, a stack
/// frame, parameters, local variables, return type, calling convention, and
/// tags. Thunk functions reference another function.
#[derive(Debug, Clone)]
pub struct Function {
    /// The function name.
    pub name: String,
    /// The entry-point address.
    pub entry_point: Address,
    /// The body range (all addresses covered by the function).
    pub body: AddressRange,
    /// The return type, if known.
    pub return_type: Option<Arc<dyn DataType>>,
    /// The return parameter (ordinal = -1).
    pub return_param: Parameter,
    /// The function parameters (ordered).
    pub parameters: Vec<Parameter>,
    /// Local variables.
    pub local_variables: Vec<LocalVariable>,
    /// The calling convention name.
    pub calling_convention: String,
    /// Stack frame layout.
    pub stack_frame: StackFrame,
    /// Stack purge size (bytes popped by callee on x86 stdcall).
    pub stack_purge_size: i32,
    /// Whether the stack purge size has been determined/valid.
    pub stack_purge_size_valid: bool,
    /// Overall signature source.
    pub signature_source: SourceType,
    /// Whether this function has custom variable storage.
    pub custom_storage: bool,
    /// Whether this function is a thunk (wrapper/forwarder).
    pub is_thunk: bool,
    /// If this is a thunk, the address of the thunked function.
    pub thunked_function: Option<Address>,
    /// Whether this function has a variable argument list.
    pub has_varargs: bool,
    /// Whether this function is marked as inline.
    pub inline: bool,
    /// Whether this function is marked as noreturn.
    pub no_return: bool,
    /// Call-fixup name (compiler-spec specific).
    pub call_fixup: Option<String>,
    /// Function comment.
    pub comment: Option<String>,
    /// Repeatable comment (shown at call sites).
    pub repeatable_comment: Option<String>,
    /// Tags applied to this function.
    pub tags: HashSet<FunctionTag>,
    /// Whether this function is external (EXTERNAL address space).
    pub is_external: bool,
    /// Whether this function has been deleted.
    pub deleted: bool,
}

impl Function {
    /// Default parameter prefix.
    pub const DEFAULT_PARAM_PREFIX: &'static str = "param_";
    /// Default local variable prefix.
    pub const DEFAULT_LOCAL_PREFIX: &'static str = "local_";
    /// Default local temp prefix.
    pub const DEFAULT_LOCAL_TEMP_PREFIX: &'static str = "temp_";
    /// Reserved local prefix.
    pub const DEFAULT_LOCAL_RESERVED_PREFIX: &'static str = "local_res";
    /// The `this` parameter name for __thiscall.
    pub const THIS_PARAM_NAME: &'static str = "this";
    /// The return storage pointer parameter name.
    pub const RETURN_PTR_PARAM_NAME: &'static str = "__return_storage_ptr__";
    /// Unknown calling convention string.
    pub const UNKNOWN_CALLING_CONVENTION: &'static str = "unknown";
    /// Default calling convention string.
    pub const DEFAULT_CALLING_CONVENTION: &'static str = "default";
    /// Unknown stack depth constant.
    pub const UNKNOWN_STACK_DEPTH_CHANGE: i32 = i32::MAX;
    /// Invalid stack depth constant.
    pub const INVALID_STACK_DEPTH_CHANGE: i32 = i32::MAX - 1;
    /// Inline tag name.
    pub const INLINE_TAG: &'static str = "inline";
    /// Noreturn tag name.
    pub const NORETURN_TAG: &'static str = "noreturn";
    /// Thunk tag name.
    pub const THUNK_TAG: &'static str = "thunk";

    /// Create a new function.
    pub fn new(name: impl Into<String>, entry_point: Address, body: AddressRange) -> Self {
        Self {
            name: name.into(),
            entry_point,
            body,
            return_type: None,
            return_param: Parameter::return_param(None),
            parameters: Vec::new(),
            local_variables: Vec::new(),
            calling_convention: Self::DEFAULT_CALLING_CONVENTION.to_string(),
            stack_frame: StackFrame::new(),
            stack_purge_size: 0,
            stack_purge_size_valid: false,
            signature_source: SourceType::Default,
            custom_storage: false,
            is_thunk: false,
            thunked_function: None,
            has_varargs: false,
            inline: false,
            no_return: false,
            call_fixup: None,
            comment: None,
            repeatable_comment: None,
            tags: HashSet::new(),
            is_external: false,
            deleted: false,
        }
    }

    /// Builder: set return type.
    pub fn with_return_type(mut self, dt: Arc<dyn DataType>) -> Self {
        self.return_param = Parameter::return_param(Some(dt.clone()));
        self.return_type = Some(dt);
        self
    }

    /// Builder: add a parameter.
    pub fn with_parameter(mut self, param: Parameter) -> Self {
        self.parameters.push(param);
        self
    }

    /// Builder: add a local variable.
    pub fn with_local(mut self, var: LocalVariable) -> Self {
        self.local_variables.push(var);
        self
    }

    /// Builder: set calling convention.
    pub fn with_calling_convention(mut self, cc: impl Into<String>) -> Self {
        self.calling_convention = cc.into();
        self
    }

    /// Builder: set as thunk.
    pub fn with_thunk(mut self, target: Address) -> Self {
        self.is_thunk = true;
        self.thunked_function = Some(target);
        self.tags.insert(FunctionTag::new(Self::THUNK_TAG));
        self
    }

    /// Builder: set as inline.
    pub fn with_inline(mut self) -> Self {
        self.inline = true;
        self.tags.insert(FunctionTag::new(Self::INLINE_TAG));
        self
    }

    /// Builder: set as no-return.
    pub fn with_noreturn(mut self) -> Self {
        self.no_return = true;
        self.tags.insert(FunctionTag::new(Self::NORETURN_TAG));
        self
    }

    /// Builder: set varargs.
    pub fn with_varargs(mut self) -> Self {
        self.has_varargs = true;
        self
    }

    /// Builder: set comment.
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Builder: set repeatable comment.
    pub fn with_repeatable_comment(mut self, comment: impl Into<String>) -> Self {
        self.repeatable_comment = Some(comment.into());
        self
    }

    /// Builder: add a tag.
    pub fn with_tag(mut self, tag: FunctionTag) -> Self {
        self.tags.insert(tag);
        self
    }

    /// Get a parameter by ordinal.
    pub fn get_parameter(&self, ordinal: i32) -> Option<&Parameter> {
        if ordinal == Parameter::RETURN_ORDINAL {
            Some(&self.return_param)
        } else {
            self.parameters.get(ordinal as usize)
        }
    }

    /// Number of parameters (excluding return).
    pub fn get_parameter_count(&self) -> usize {
        self.parameters.len()
    }

    /// Auto-parameter count (parameters injected by calling convention).
    pub fn get_auto_parameter_count(&self) -> usize {
        self.parameters
            .iter()
            .filter(|p| p.auto_parameter)
            .count()
    }

    /// Find a parameter by name.
    pub fn get_parameter_by_name(&self, name: &str) -> Option<&Parameter> {
        self.parameters.iter().find(|param| param.name() == name)
    }

    /// Find a local variable by name.
    pub fn get_local_variable_by_name(&self, name: &str) -> Option<&LocalVariable> {
        self.local_variables.iter().find(|local| local.name() == name)
    }

    /// Number of local variables.
    pub fn get_local_variable_count(&self) -> usize {
        self.local_variables.len()
    }

    /// Returns true if the given tag name is applied to the function.
    pub fn has_tag_named(&self, tag_name: &str) -> bool {
        self.tags.iter().any(|tag| tag.name == tag_name)
    }

    /// End address of the function body.
    pub fn get_body_end(&self) -> Address {
        self.body.end
    }

    /// Returns true if the given address is contained in this function's body.
    pub fn contains_address(&self, addr: &Address) -> bool {
        self.body.contains(addr)
    }

    /// Returns true if this function has a valid stack purge size.
    pub fn is_stack_purge_size_valid(&self) -> bool {
        self.stack_purge_size_valid
    }

    /// Get the effective calling convention name.
    pub fn get_calling_convention_name(&self) -> String {
        if self.calling_convention.is_empty() {
            Self::UNKNOWN_CALLING_CONVENTION.to_string()
        } else {
            self.calling_convention.clone()
        }
    }

    /// Check if the calling convention is unknown.
    pub fn has_unknown_calling_convention_name(&self) -> bool {
        self.calling_convention.is_empty()
            || self.calling_convention == Self::UNKNOWN_CALLING_CONVENTION
    }

    /// Get the signature string for display.
    pub fn signature_string(&self) -> String {
        let mut result = String::new();
        if let Some(ref rt) = self.return_type {
            result.push_str(rt.name());
        } else {
            result.push_str("void");
        }
        result.push(' ');
        result.push_str(&self.name);
        result.push('(');
        let param_strs: Vec<String> = self
            .parameters
            .iter()
            .map(|p| {
                let type_name = p
                    .variable
                    .data_type
                    .as_ref()
                    .map(|dt| dt.name().to_string())
                    .unwrap_or_else(|| "undefined".to_string());
                let name = if p.variable.name.is_empty() {
                    format!("{}", p.ordinal)
                } else {
                    p.variable.name.clone()
                };
                format!("{} {}", type_name, name)
            })
            .collect();
        result.push_str(&param_strs.join(", "));
        if self.has_varargs {
            if param_strs.is_empty() {
                result.push_str("...");
            } else {
                result.push_str(", ...");
            }
        }
        result.push(')');
        result
    }

    /// Get the prototype string (optionally including calling convention).
    pub fn prototype_string(&self, include_calling_convention: bool) -> String {
        let mut result = String::new();
        if include_calling_convention
            && !self.calling_convention.is_empty()
            && self.calling_convention != Self::DEFAULT_CALLING_CONVENTION
        {
            result.push_str(&self.calling_convention);
            result.push(' ');
        }
        result.push_str(&self.signature_string());
        result
    }
}

impl PartialEq for Function {
    fn eq(&self, other: &Self) -> bool {
        self.entry_point == other.entry_point && self.name == other.name
    }
}

impl Eq for Function {}

// ============================================================================
// FunctionData — lightweight function data (for backward compatibility)
// ============================================================================

/// Lightweight function data compatible with older code.
/// Prefer using the full `Function` struct for new code.
#[derive(Debug, Clone)]
pub struct FunctionData {
    pub name: String,
    pub entry_point: Address,
    pub body: AddressRange,
    pub return_type: Option<Arc<dyn DataType>>,
    pub parameters: Vec<FunctionParameter>,
    pub local_variables: Vec<FunctionVariable>,
    pub called_functions: Vec<Address>,
    pub calling_convention: String,
    pub is_thunk: bool,
    pub thunked_function: Option<Address>,
    pub stack_frame: StackFrame,
    pub has_varargs: bool,
    pub inline: bool,
    pub no_return: bool,
    pub signature: Option<String>,
}

impl FunctionData {
    pub fn new(name: impl Into<String>, entry_point: Address, body: AddressRange) -> Self {
        Self {
            name: name.into(),
            entry_point,
            body,
            return_type: None,
            parameters: Vec::new(),
            local_variables: Vec::new(),
            called_functions: Vec::new(),
            calling_convention: "cdecl".to_string(),
            is_thunk: false,
            thunked_function: None,
            stack_frame: StackFrame::new(),
            has_varargs: false,
            inline: false,
            no_return: false,
            signature: None,
        }
    }

    pub fn with_signature(mut self, sig: impl Into<String>) -> Self {
        self.signature = Some(sig.into());
        self
    }

    pub fn with_return_type(mut self, dt: Arc<dyn DataType>) -> Self {
        self.return_type = Some(dt);
        self
    }

    pub fn with_parameter(mut self, p: FunctionParameter) -> Self {
        self.parameters.push(p);
        self
    }

    pub fn with_local(mut self, v: FunctionVariable) -> Self {
        self.local_variables.push(v);
        self
    }

    pub fn with_calling_convention(mut self, cc: impl Into<String>) -> Self {
        self.calling_convention = cc.into();
        self
    }

    pub fn with_thunk(mut self, target: Address) -> Self {
        self.is_thunk = true;
        self.thunked_function = Some(target);
        self
    }

    pub fn add_called_function(&mut self, addr: Address) {
        if !self.called_functions.contains(&addr) {
            self.called_functions.push(addr);
        }
    }
}

// ============================================================================
// FunctionParameter (for the FunctionData type)
// ============================================================================

/// A function parameter used in FunctionData.
#[derive(Debug, Clone)]
pub struct FunctionParameter {
    pub name: String,
    pub data_type: Arc<dyn DataType>,
    pub ordinal: usize,
    pub storage: VariableStorage,
    pub comment: Option<String>,
}

impl FunctionParameter {
    pub fn new(
        name: impl Into<String>,
        data_type: Arc<dyn DataType>,
        ordinal: usize,
    ) -> Self {
        Self {
            name: name.into(),
            data_type,
            ordinal,
            storage: VariableStorage::Unassigned,
            comment: None,
        }
    }

    pub fn with_storage(mut self, storage: VariableStorage) -> Self {
        self.storage = storage;
        self
    }
}

// ============================================================================
// FunctionVariable (local variable for FunctionData)
// ============================================================================

/// A local variable within a FunctionData.
#[derive(Debug, Clone)]
pub struct FunctionVariable {
    pub name: String,
    pub data_type: Arc<dyn DataType>,
    pub storage: VariableStorage,
    pub comment: Option<String>,
    pub first_use: Option<Address>,
}

impl FunctionVariable {
    pub fn new(name: impl Into<String>, data_type: Arc<dyn DataType>) -> Self {
        Self {
            name: name.into(),
            data_type,
            storage: VariableStorage::Unassigned,
            comment: None,
            first_use: None,
        }
    }

    pub fn with_storage(mut self, storage: VariableStorage) -> Self {
        self.storage = storage;
        self
    }
}

// ============================================================================
// FunctionManager — mirrors ghidra.program.model.listing.FunctionManager
// ============================================================================

/// Manages functions in a program. Provides methods to query, create, remove,
/// and iterate over functions, and build call trees.
///
/// Corresponds to Ghidra's `FunctionManager` interface.
#[derive(Debug, Clone, Default)]
pub struct FunctionManager {
    /// Functions indexed by entry point.
    functions: HashMap<Address, Function>,
    /// Functions indexed by name.
    by_name: HashMap<String, Vec<Address>>,
    /// Known calling convention names.
    calling_convention_names: Vec<String>,
    /// Function tag manager.
    tags: HashMap<String, FunctionTag>,
}

impl FunctionManager {
    /// Create a new empty function manager.
    pub fn new() -> Self {
        Self::default()
    }

    // ---- Function CRUD ----

    /// Create a new function.
    pub fn create_function(
        &mut self,
        name: Option<&str>,
        entry_point: Address,
        body: AddressRange,
        source: SourceType,
    ) -> Result<&Function, String> {
        let func_name = name.unwrap_or("").to_string();
        if self.functions.contains_key(&entry_point) {
            return Err(format!("Function already exists at {}", entry_point));
        }
        let func = Function::new(func_name.clone(), entry_point, body);
        self.functions.insert(entry_point, func);
        self.by_name
            .entry(func_name)
            .or_default()
            .push(entry_point);
        Ok(self.functions.get(&entry_point).unwrap())
    }

    /// Remove a function by entry point.
    pub fn remove_function(&mut self, entry_point: &Address) -> bool {
        if let Some(func) = self.functions.remove(entry_point) {
            if let Some(addrs) = self.by_name.get_mut(&func.name) {
                addrs.retain(|a| a != entry_point);
                if addrs.is_empty() {
                    self.by_name.remove(&func.name);
                }
            }
            true
        } else {
            false
        }
    }

    /// Get a function by entry point.
    pub fn get_function_at(&self, entry_point: &Address) -> Option<&Function> {
        self.functions.get(entry_point)
    }

    /// Get a mutable reference to a function by entry point.
    pub fn get_function_at_mut(&mut self, entry_point: &Address) -> Option<&mut Function> {
        self.functions.get_mut(entry_point)
    }

    /// Get a function containing an address.
    pub fn get_function_containing(&self, addr: &Address) -> Option<&Function> {
        self.functions
            .values()
            .find(|f| f.contains_address(addr))
    }

    /// Get functions by name.
    pub fn get_functions_by_name(&self, name: &str) -> Vec<&Function> {
        if let Some(addrs) = self.by_name.get(name) {
            addrs
                .iter()
                .filter_map(|a| self.functions.get(a))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get all functions.
    pub fn get_functions(&self) -> Vec<&Function> {
        self.functions.values().collect()
    }

    /// Returns true if the manager currently contains no functions.
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }

    /// Get the first function by entry-point order.
    pub fn get_first_function(&self) -> Option<&Function> {
        self.functions
            .keys()
            .min()
            .and_then(|entry| self.functions.get(entry))
    }

    /// Get the next function after the given entry point.
    pub fn get_function_after(&self, entry_point: &Address) -> Option<&Function> {
        self.functions
            .iter()
            .filter(|(entry, _)| *entry > entry_point)
            .min_by_key(|(entry, _)| *entry)
            .map(|(_, func)| func)
    }

    /// Get all function entry points.
    pub fn get_function_entry_points(&self) -> Vec<Address> {
        self.functions.keys().copied().collect()
    }

    /// Total number of functions.
    pub fn get_function_count(&self) -> usize {
        self.functions.len()
    }

    /// Returns true if a function exists at the entry point.
    pub fn has_function(&self, entry_point: &Address) -> bool {
        self.functions.contains_key(entry_point)
    }

    /// Returns true if the given address is in any function.
    pub fn is_in_function(&self, addr: &Address) -> bool {
        self.functions
            .values()
            .any(|f| f.contains_address(addr))
    }

    // ---- Signature management ----

    /// Get all calling convention names.
    pub fn get_calling_convention_names(&self) -> Vec<&str> {
        self.calling_convention_names
            .iter()
            .map(|s| s.as_str())
            .collect()
    }

    /// Set the calling convention names.
    pub fn set_calling_convention_names(&mut self, names: Vec<String>) {
        self.calling_convention_names = names;
    }

    // ---- Tag management ----

    /// Add a function tag.
    pub fn add_tag(&mut self, tag: FunctionTag) {
        self.tags.insert(tag.name.clone(), tag);
    }

    /// Get a function tag by name.
    pub fn get_tag(&self, name: &str) -> Option<&FunctionTag> {
        self.tags.get(name)
    }

    /// Get all tags.
    pub fn get_all_tags(&self) -> Vec<&FunctionTag> {
        self.tags.values().collect()
    }

    // ---- Call tree ----

    /// Get functions called by the function at entry_point.
    /// (Requires reference/flow data to be populated externally.)
    pub fn get_called_functions(&self, _entry_point: &Address) -> Vec<Address> {
        // In a full implementation this would query references.
        Vec::new()
    }

    /// Get functions that call the function at entry_point.
    pub fn get_calling_functions(&self, _target: &Address) -> Vec<Address> {
        // In a full implementation this would query references.
        Vec::new()
    }

    /// Build the call tree rooted at the given entry point.
    pub fn get_call_tree(&self, root: &Address) -> Vec<(Address, Address)> {
        let mut result = Vec::new();
        let mut visited = HashSet::new();
        self.build_call_tree_recursive(root, &mut result, &mut visited);
        result
    }

    fn build_call_tree_recursive(
        &self,
        current: &Address,
        result: &mut Vec<(Address, Address)>,
        visited: &mut HashSet<Address>,
    ) {
        if !visited.insert(*current) {
            return;
        }
        for callee in self.get_called_functions(current) {
            result.push((*current, callee));
            self.build_call_tree_recursive(&callee, result, visited);
        }
    }
}

// ============================================================================
// InMemoryFunctionManager — concrete FunctionManager impl (compat alias)
// ============================================================================

/// Alias for backward compatibility. Prefer using `FunctionManager` directly.
pub type InMemoryFunctionManager = FunctionManager;

// ============================================================================
// StackFrame — stack frame layout
// ============================================================================

/// The stack frame layout of a function.
///
/// Describes how the function uses the stack: local variable area, parameter
/// area, saved registers, the return address, and the total frame size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackFrame {
    /// Size (positive) of the local variable area.
    pub local_size: i64,
    /// Offset of the first stack parameter from the frame base.
    pub parameter_offset: i64,
    /// Offset of the return address from the frame base.
    pub return_address_offset: i64,
    /// Offset of saved registers from the frame base.
    pub saved_register_offset: i64,
    /// Total frame size in bytes.
    pub frame_size: i64,
    /// Whether the stack grows downward (negative direction).
    pub grows_negative: bool,
}

impl StackFrame {
    pub fn new() -> Self {
        Self {
            local_size: 0,
            parameter_offset: 8,
            return_address_offset: 8,
            saved_register_offset: 0,
            frame_size: 0,
            grows_negative: true,
        }
    }

    pub fn with_local_size(mut self, size: i64) -> Self {
        self.local_size = size;
        self.frame_size = self.compute_frame_size();
        self
    }

    pub fn with_parameter_offset(mut self, offset: i64) -> Self {
        self.parameter_offset = offset;
        self
    }

    pub fn with_return_address_offset(mut self, offset: i64) -> Self {
        self.return_address_offset = offset;
        self
    }

    pub fn with_saved_register_offset(mut self, offset: i64) -> Self {
        self.saved_register_offset = offset;
        self
    }

    pub fn compute_frame_size(&self) -> i64 {
        let local = self.local_size.abs();
        let ra = (self.return_address_offset - self.saved_register_offset).abs();
        local + ra
    }

    pub fn is_auto_computed(&self) -> bool {
        self.local_size == 0 && self.frame_size == 0
    }
}

impl Default for StackFrame {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Operand enum
// ============================================================================

/// An instruction operand.
#[derive(Debug, Clone)]
pub enum Operand {
    /// A register operand.
    Register(String),
    /// A scalar/immediate value.
    Scalar(i64),
    /// An absolute address reference.
    Address(Address),
    /// A complex expression (e.g., "[rbp-0x8]").
    Expression(String),
    /// A floating-point immediate.
    Float(f64),
    /// No operand.
    None,
}

impl PartialEq for Operand {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Operand::Register(a), Operand::Register(b)) => a == b,
            (Operand::Scalar(a), Operand::Scalar(b)) => a == b,
            (Operand::Address(a), Operand::Address(b)) => a == b,
            (Operand::Expression(a), Operand::Expression(b)) => a == b,
            (Operand::Float(a), Operand::Float(b)) => a.to_bits() == b.to_bits(),
            (Operand::None, Operand::None) => true,
            _ => false,
        }
    }
}

impl Eq for Operand {}

impl std::hash::Hash for Operand {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            Operand::Register(s) => s.hash(state),
            Operand::Scalar(v) => v.hash(state),
            Operand::Address(a) => a.hash(state),
            Operand::Expression(e) => e.hash(state),
            Operand::Float(v) => v.to_bits().hash(state),
            Operand::None => {}
        }
    }
}

impl Operand {
    pub fn register(name: impl Into<String>) -> Self {
        Operand::Register(name.into())
    }

    pub fn scalar(value: i64) -> Self {
        Operand::Scalar(value)
    }

    pub fn address(addr: Address) -> Self {
        Operand::Address(addr)
    }

    pub fn expression(e: impl Into<String>) -> Self {
        Operand::Expression(e.into())
    }

    pub fn is_register(&self) -> bool {
        matches!(self, Operand::Register(_))
    }

    pub fn is_scalar(&self) -> bool {
        matches!(self, Operand::Scalar(_))
    }

    pub fn is_address(&self) -> bool {
        matches!(self, Operand::Address(_))
    }

    pub fn is_expression(&self) -> bool {
        matches!(self, Operand::Expression(_))
    }
}

impl std::fmt::Display for Operand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operand::Register(name) => write!(f, "{}", name),
            Operand::Scalar(v) => write!(f, "0x{:x}", v),
            Operand::Address(addr) => write!(f, "{}", addr),
            Operand::Expression(e) => write!(f, "{}", e),
            Operand::Float(v) => write!(f, "{}", v),
            Operand::None => write!(f, ""),
        }
    }
}

// ============================================================================
// FlowType enum
// ============================================================================

/// The control-flow type of an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowType {
    Normal,
    Jump,
    ConditionalJump,
    Call,
    ConditionalCall,
    Return,
    Terminator,
    SystemCall,
}

impl FlowType {
    pub fn is_branch(&self) -> bool {
        matches!(self, FlowType::Jump | FlowType::ConditionalJump)
    }

    pub fn is_call(&self) -> bool {
        matches!(self, FlowType::Call | FlowType::ConditionalCall)
    }

    pub fn has_fallthrough(&self) -> bool {
        matches!(
            self,
            FlowType::Normal
                | FlowType::ConditionalJump
                | FlowType::ConditionalCall
                | FlowType::Call
                | FlowType::SystemCall
        )
    }

    pub fn is_terminator(&self) -> bool {
        matches!(self, FlowType::Jump | FlowType::Return | FlowType::Terminator)
    }

    pub fn name(&self) -> &'static str {
        match self {
            FlowType::Normal => "NORMAL",
            FlowType::Jump => "JUMP",
            FlowType::ConditionalJump => "CONDITIONAL_JUMP",
            FlowType::Call => "CALL",
            FlowType::ConditionalCall => "CONDITIONAL_CALL",
            FlowType::Return => "RETURN",
            FlowType::Terminator => "TERMINATOR",
            FlowType::SystemCall => "SYSTEM_CALL",
        }
    }
}

impl Default for FlowType {
    fn default() -> Self {
        FlowType::Normal
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::types::{
        BuiltInDataType, BuiltInDataTypeWrapper, PointerDataType, StructureDataType,
    };

    fn make_int_type() -> Arc<dyn DataType> {
        Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Int))
    }

    fn make_char_type() -> Arc<dyn DataType> {
        Arc::new(BuiltInDataTypeWrapper::new(BuiltInDataType::Char))
    }

    // ---- CodeUnitData tests ----

    #[test]
    fn test_code_unit_new() {
        let cu = CodeUnitData::new(Address::new(0x1000), 3, vec![0x90; 3]);
        assert_eq!(cu.address, Address::new(0x1000));
        assert_eq!(cu.length, 3);
        assert_eq!(cu.bytes.len(), 3);
    }

    #[test]
    fn test_code_unit_contains() {
        let cu = CodeUnitData::new(Address::new(0x1000), 4, vec![0x00; 4]);
        assert!(cu.contains(&Address::new(0x1000)));
        assert!(cu.contains(&Address::new(0x1003)));
        assert!(!cu.contains(&Address::new(0x1004)));
    }

    // ---- Instruction tests ----

    #[test]
    fn test_instruction_new() {
        let ins = Instruction::new(Address::new(0x1000), 3, vec![0x48, 0x89, 0xe5], "mov");
        assert_eq!(ins.mnemonic, "mov");
        assert_eq!(ins.length, 3);
    }

    #[test]
    fn test_instruction_full_output() {
        let ins = Instruction::new(
            Address::new(0x1000),
            5,
            vec![0xb8, 0x2a, 0x00, 0x00, 0x00],
            "mov",
        )
        .with_operand(Operand::register("eax"))
        .with_operand(Operand::scalar(0x2a));
        let full = ins.full_instruction();
        assert!(full.contains("mov"));
        assert!(full.contains("eax"));
    }

    #[test]
    fn test_instruction_set_length_override() {
        let mut ins = Instruction::new(Address::new(0x1000), 5, vec![0x90; 5], "nop");
        ins.set_length_override(3).unwrap();
        assert_eq!(ins.length, 3);
        assert!(ins.length_overridden);
        ins.set_length_override(0).unwrap();
        assert!(!ins.length_overridden);
        assert_eq!(ins.length, 5);
    }

    // ---- Data tests ----

    #[test]
    fn test_data_new() {
        let dt = make_int_type();
        let data = Data::new(Address::new(0x2000), 4, Some(dt))
            .with_value("42")
            .with_label("my_int");
        assert_eq!(data.address, Address::new(0x2000));
        assert_eq!(data.value, Some("42".to_string()));
    }

    #[test]
    fn test_data_pointer_check() {
        let void_type: Arc<dyn DataType> = Arc::new(BuiltInDataTypeWrapper::new(
            BuiltInDataType::Void,
        ));
        let ptr_type: Arc<dyn DataType> = Arc::new(PointerDataType::new(void_type));
        let data = Data::new(Address::new(0x3000), 8, Some(ptr_type));
        assert!(data.is_pointer);
    }

    // ---- Variable tests ----

    #[test]
    fn test_variable_creation() {
        let dt = make_int_type();
        let var = Variable::new("counter", Some(dt), SourceType::UserDefined)
            .with_storage(VariableStorage::stack(-4, 4));
        assert_eq!(var.name, "counter");
        assert!(var.is_stack_variable());
        assert_eq!(var.length, 4);
    }

    #[test]
    fn test_variable_register() {
        let dt = make_int_type();
        let var = Variable::new("flags", Some(dt), SourceType::Analysis)
            .with_storage(VariableStorage::register("eax", 4));
        assert!(var.is_register_variable());
        assert_eq!(var.length, 4);
    }

    // ---- Parameter tests ----

    #[test]
    fn test_parameter_creation() {
        let dt = make_int_type();
        let param = Parameter::new("argc", Some(dt), 0, SourceType::UserDefined)
            .with_storage(VariableStorage::register("rdi", 8));
        assert_eq!(param.name(), "argc");
        assert_eq!(param.ordinal, 0);
        assert!(!param.is_return());
    }

    #[test]
    fn test_return_parameter() {
        let dt = make_int_type();
        let ret = Parameter::return_param(Some(dt));
        assert!(ret.is_return());
        assert_eq!(ret.name(), "<RETURN>");
        assert_eq!(ret.ordinal, Parameter::RETURN_ORDINAL);
    }

    // ---- LocalVariable tests ----

    #[test]
    fn test_local_variable() {
        let dt = make_int_type();
        let mut local = LocalVariable::new("tmp", Some(dt), SourceType::Analysis)
            .with_storage(VariableStorage::stack(-8, 4));
        assert!(local.set_first_use_offset(0x10));
        assert_eq!(local.first_use_offset(), 0x10);
        assert!(local.is_stack_variable());
    }

    // ---- Function tests ----

    #[test]
    fn test_function_creation() {
        let body = AddressRange::new(Address::new(0x1000), Address::new(0x1021));
        let func = Function::new("main", Address::new(0x1000), body);
        assert_eq!(func.name, "main");
        assert_eq!(func.entry_point, Address::new(0x1000));
        assert!(!func.is_thunk);
        assert!(func.contains_address(&Address::new(0x1010)));
    }

    #[test]
    fn test_function_signature() {
        let body = AddressRange::new(Address::new(0x1000), Address::new(0x1021));
        let int_type = make_int_type();
        let char_type = make_char_type();

        let param1 = Parameter::new("argc", Some(int_type.clone()), 0, SourceType::UserDefined);
        let param2 = Parameter::new("argv", Some(Arc::new(PointerDataType::new(char_type))), 1, SourceType::UserDefined);

        let func = Function::new("main", Address::new(0x1000), body)
            .with_return_type(int_type)
            .with_parameter(param1)
            .with_parameter(param2);

        let sig = func.signature_string();
        assert!(sig.contains("main"));
        assert!(sig.contains("argc"));
        assert!(sig.contains("argv"));
    }

    // ---- FunctionManager tests ----

    #[test]
    fn test_fm_create_and_remove() {
        let mut mgr = FunctionManager::new();
        let body = AddressRange::new(Address::new(0x1000), Address::new(0x1021));
        mgr.create_function(Some("main"), Address::new(0x1000), body, SourceType::UserDefined)
            .unwrap();
        assert_eq!(mgr.get_function_count(), 1);
        assert!(mgr.remove_function(&Address::new(0x1000)));
        assert_eq!(mgr.get_function_count(), 0);
    }

    #[test]
    fn test_fm_get_containing() {
        let mut mgr = FunctionManager::new();
        let body = AddressRange::new(Address::new(0x1000), Address::new(0x1021));
        mgr.create_function(Some("main"), Address::new(0x1000), body, SourceType::UserDefined)
            .unwrap();
        let func = mgr.get_function_containing(&Address::new(0x1010));
        assert!(func.is_some());
        assert_eq!(func.unwrap().name, "main");
    }

    #[test]
    fn test_function_convenience_helpers() {
        let body = AddressRange::new(Address::new(0x1000), Address::new(0x1021));
        let int_type = make_int_type();
        let local = LocalVariable::new("tmp", Some(int_type.clone()), SourceType::Analysis);
        let func = Function::new("main", Address::new(0x1000), body)
            .with_parameter(Parameter::new("argc", Some(int_type.clone()), 0, SourceType::UserDefined))
            .with_local(local)
            .with_tag(FunctionTag::new("entry"));

        assert_eq!(func.get_parameter_by_name("argc").map(|p| p.ordinal), Some(0));
        assert_eq!(func.get_local_variable_by_name("tmp").map(|v| v.name()), Some("tmp"));
        assert_eq!(func.get_local_variable_count(), 1);
        assert!(func.has_tag_named("entry"));
        assert_eq!(func.get_body_end(), Address::new(0x1021));
    }

    #[test]
    fn test_listing_collection_helpers() {
        let addr = Address::new(0x1000);
        let mut listing = InMemoryListing::new();
        listing.create_code_unit(addr, 1, vec![0x90]).unwrap();
        listing.instructions.insert(addr, Instruction::new(addr, 1, vec![0x90], "nop"));
        listing.data_items.insert(addr, Data::new(addr, 1, None));
        listing.set_comment(addr, CommentType::Eol, Some("note".to_string()));

        assert_eq!(listing.code_unit_count(), 1);
        assert_eq!(listing.instruction_count(), 1);
        assert_eq!(listing.data_count(), 1);
        assert!(listing.has_code_unit_at(&addr));
        assert!(listing.has_instruction_at(&addr));
        assert!(listing.has_data_at(&addr));
        assert_eq!(listing.comment_address_count(), 1);
    }

    #[test]
    fn test_data_convenience_helpers() {
        let child = Data::new(Address::new(0x1001), 1, Some(make_char_type()));
        let mut root = Data::new(Address::new(0x1000), 2, Some(make_int_type()));
        root.components.push(child);

        assert!(root.has_components());
        assert!(root.is_root());
        assert!(!root.get_component(0).unwrap().has_components());
    }

    #[test]
    fn test_function_manager_navigation_helpers() {
        let mut mgr = FunctionManager::new();
        let body1 = AddressRange::new(Address::new(0x1000), Address::new(0x1005));
        let body2 = AddressRange::new(Address::new(0x2000), Address::new(0x2005));
        assert!(mgr.is_empty());
        mgr.create_function(Some("first"), Address::new(0x1000), body1, SourceType::UserDefined)
            .unwrap();
        mgr.create_function(Some("second"), Address::new(0x2000), body2, SourceType::UserDefined)
            .unwrap();

        assert_eq!(mgr.get_first_function().map(|f| f.name.as_str()), Some("first"));
        assert_eq!(mgr.get_function_after(&Address::new(0x1000)).map(|f| f.name.as_str()), Some("second"));
    }

    // ---- StackFrame tests ----

    #[test]
    fn test_stack_frame_default() {
        let sf = StackFrame::new();
        assert_eq!(sf.local_size, 0);
        assert_eq!(sf.parameter_offset, 8);
        assert!(sf.grows_negative);
    }

    // ---- CommentType tests ----

    #[test]
    fn test_comment_type_ordinal() {
        assert_eq!(CommentType::Eol.ordinal(), 0);
        assert_eq!(CommentType::Pre.ordinal(), 1);
        assert_eq!(CommentType::Post.ordinal(), 2);
        assert_eq!(CommentType::Plate.ordinal(), 3);
        assert_eq!(CommentType::Repeatable.ordinal(), 4);
        assert_eq!(
            CommentType::from_ordinal(0),
            Some(CommentType::Eol)
        );
    }

    // ---- CodeUnitComments tests ----

    #[test]
    fn test_code_unit_comments() {
        let mut comments = CodeUnitComments::new(Address::new(0x1000));
        assert!(comments.is_empty());
        comments.set_comment(CommentType::Eol, Some("end of line".to_string()));
        assert_eq!(
            comments.get_comment(CommentType::Eol),
            Some("end of line")
        );
        assert!(!comments.is_empty());
    }

    // ---- CodeUnitFormat tests ----

    #[test]
    fn test_code_unit_format_address() {
        let fmt = CodeUnitFormat::new();
        let addr = Address::new(0x1000);
        assert_eq!(fmt.format_address(&addr), "00001000");
    }

    #[test]
    fn test_code_unit_format_bytes() {
        let fmt = CodeUnitFormat::new();
        assert_eq!(fmt.format_bytes(&[0x90, 0x90, 0xc3]), "90 90 c3");
    }

    #[test]
    fn test_code_unit_format_instruction() {
        let fmt = CodeUnitFormat::new();
        let ins = Instruction::new(Address::new(0x1000), 3, vec![0x48, 0x89, 0xe5], "mov")
            .with_operand(Operand::register("rbp"))
            .with_operand(Operand::register("rsp"));
        let formatted = fmt.format_instruction(&ins);
        assert!(formatted.contains("mov"));
        assert!(formatted.contains("rbp"));
    }

    // ---- Bookmark tests ----

    #[test]
    fn test_bookmark_manager() {
        let mut mgr = BookmarkManager::new();
        let bm = mgr.set_bookmark(
            Address::new(0x1000),
            "Analysis",
            "Entry Point",
            "Program entry",
        );
        assert_eq!(bm.address, Address::new(0x1000));
        assert_eq!(mgr.num_bookmarks(), 1);
        let found = mgr.get_bookmarks(&Address::new(0x1000));
        assert_eq!(found.len(), 1);
    }

    // ---- FunctionSignature tests ----

    #[test]
    fn test_function_signature_display() {
        let int_type = make_int_type();
        let sig = FunctionSignature::new("do_thing")
            .with_return_type(int_type.clone())
            .with_parameter(Parameter::new("x", Some(int_type), 0, SourceType::UserDefined))
            .with_calling_convention("__cdecl");
        let display = sig.prototype_string(false);
        assert!(display.contains("do_thing"));
        assert!(display.contains("int x"));
    }

    // ---- ProgramFragment tests ----

    #[test]
    fn test_program_fragment() {
        let mut frag = ProgramFragment::new(".text");
        frag.add_address(Address::new(0x1000));
        frag.add_address(Address::new(0x1001));
        assert_eq!(frag.get_name(), ".text");
        assert!(!frag.is_empty());
        assert_eq!(
            frag.get_min_address(),
            Some(Address::new(0x1000))
        );
    }
}


// ============================================================================
// Additional listing types (port of Java Ghidra listing/lang model)
// ============================================================================

/// An equate (named constant) at a specific operand position.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[allow(dead_code)]
pub struct Equate { pub name: String, pub value: i64, pub references: Vec<(Address, i32)> }
#[allow(dead_code)]
impl Equate {
    pub fn new(name: impl Into<String>, value: i64) -> Self { Self { name: name.into(), value, references: Vec::new() } }
    pub fn add_reference(&mut self, addr: Address, op_index: i32) { self.references.push((addr, op_index)); }
    pub fn remove_reference(&mut self, addr: &Address, op_index: i32) -> bool {
        let b = self.references.len(); self.references.retain(|(a,o)| a!=addr||*o!=op_index); self.references.len()<b }
    pub fn get_reference_addresses(&self) -> Vec<Address> { self.references.iter().map(|(a,_)| *a).collect() }
    pub fn reference_count(&self) -> usize { self.references.len() }
}

/// Manages equates (named constants).
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct EquateTable { equates: HashMap<String, Equate> }
#[allow(dead_code)]
impl EquateTable {
    pub fn new() -> Self { Self::default() }
    pub fn create_equate(&mut self, name: impl Into<String>, value: i64) -> Result<&Equate, String> {
        let n=name.into(); if self.equates.contains_key(&n){return Err(format!("exists: {}",n));}
        self.equates.insert(n.clone(), Equate::new(&n,value)); Ok(self.equates.get(&n).unwrap()) }
    pub fn remove_equate(&mut self, name: &str) -> bool { self.equates.remove(name).is_some() }
    pub fn get_equate(&self, name: &str) -> Option<&Equate> { self.equates.get(name) }
    pub fn num_equates(&self) -> usize { self.equates.len() }
    pub fn is_empty(&self) -> bool { self.equates.is_empty() }
}

/// An external library referenced by the program.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ExternalLibrary { pub name: String, pub path: Option<String>, pub resolved: bool }

/// An external symbol from an external library.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ExternalSymbol { pub name: String, pub library_name: String, pub external_address: Option<Address>,
    pub label: Option<String>, pub is_function: bool, pub data_type: Option<Arc<dyn DataType>> }

/// Manages external symbols (functions/data from external libraries).
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct ExternalManager { libraries: HashMap<String, ExternalLibrary>, symbols: HashMap<(String,String), ExternalSymbol>, locations: HashMap<Address,(String,String)> }
#[allow(dead_code)]
impl ExternalManager {
    pub fn new() -> Self { Self::default() }
    pub fn add_external_library(&mut self, name: impl Into<String>, path: Option<String>) {
        let n=name.into(); self.libraries.entry(n.clone()).or_insert_with(|| ExternalLibrary{name:n,path,resolved:false}); }
    pub fn add_external_function(&mut self, sn: impl Into<String>, ln: impl Into<String>, addr: Option<Address>) {
        let s=sn.into(); let l=ln.into();
        self.symbols.insert((l.clone(),s.clone()), ExternalSymbol{name:s,library_name:l,external_address:addr,label:None,is_function:true,data_type:None}); }
    pub fn get_external_library_names(&self) -> Vec<&str> { self.libraries.keys().map(|s|s.as_str()).collect() }
    pub fn get_external_symbols(&self) -> Vec<&ExternalSymbol> { self.symbols.values().collect() }
    pub fn get_external_functions(&self) -> Vec<&ExternalSymbol> { self.symbols.values().filter(|s|s.is_function).collect() }
    pub fn library_count(&self) -> usize { self.libraries.len() }
    pub fn symbol_count(&self) -> usize { self.symbols.len() }
    pub fn is_empty(&self) -> bool { self.symbols.is_empty() && self.libraries.is_empty() }
}

/// A prototype model describes how parameters are passed for a calling convention.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PrototypeModel { pub name: String, pub description: String,
    pub integer_param_registers: Vec<String>, pub float_param_registers: Vec<String>,
    pub integer_return_register: Option<String>, pub float_return_register: Option<String>,
    pub stack_pointer: Option<String>, pub stack_grows_negative: bool, pub stack_alignment: u32,
    pub shadow_space: u32, pub caller_cleanup: bool, pub max_register_bytes: usize,
    pub is_unknown: bool, pub is_default: bool, pub affected_registers: Vec<String> }
#[allow(dead_code)]
impl PrototypeModel {
    pub fn new(name: impl Into<String>) -> Self { Self {
        name:name.into(), description:String::new(), integer_param_registers:Vec::new(),
        float_param_registers:Vec::new(), integer_return_register:None, float_return_register:None,
        stack_pointer:None, stack_grows_negative:true, stack_alignment:16, shadow_space:0,
        caller_cleanup:true, max_register_bytes:0, is_unknown:false, is_default:false,
        affected_registers:Vec::new() } }
    pub fn with_description(mut self, d: impl Into<String>) -> Self { self.description=d.into(); self }
    pub fn with_integer_params(mut self, r: Vec<impl Into<String>>) -> Self { self.integer_param_registers=r.into_iter().map(|x|x.into()).collect(); self }
    pub fn with_integer_return(mut self, r: impl Into<String>) -> Self { self.integer_return_register=Some(r.into()); self }
    pub fn with_float_return(mut self, r: impl Into<String>) -> Self { self.float_return_register=Some(r.into()); self }
    pub fn with_stack_pointer(mut self, r: impl Into<String>) -> Self { self.stack_pointer=Some(r.into()); self }
    pub fn with_stack_alignment(mut self, a: u32) -> Self { self.stack_alignment=a; self }
    pub fn with_shadow_space(mut self, s: u32) -> Self { self.shadow_space=s; self }
    pub fn with_caller_cleanup(mut self) -> Self { self.caller_cleanup=true; self }
    pub fn with_callee_cleanup(mut self) -> Self { self.caller_cleanup=false; self }
    pub fn with_default(mut self) -> Self { self.is_default=true; self }
    pub fn with_unknown(mut self) -> Self { self.is_unknown=true; self }
    pub fn total_register_params(&self) -> usize { self.integer_param_registers.len()+self.float_param_registers.len() }
    pub fn sysv_amd64() -> Self { Self::new("__sysv64").with_description("System V AMD64 ABI")
        .with_integer_params(vec!["RDI","RSI","RDX","RCX","R8","R9"])
        .with_integer_return("RAX").with_float_return("XMM0").with_stack_pointer("RSP")
        .with_stack_alignment(16).with_caller_cleanup().with_default() }
    pub fn win64() -> Self { Self::new("__win64").with_description("Microsoft x64 ABI")
        .with_integer_params(vec!["RCX","RDX","R8","R9"])
        .with_integer_return("RAX").with_float_return("XMM0").with_stack_pointer("RSP")
        .with_stack_alignment(16).with_shadow_space(32).with_caller_cleanup() }
    pub fn cdecl() -> Self { Self::new("__cdecl").with_integer_return("EAX").with_stack_alignment(4).with_caller_cleanup().with_default() }
    pub fn stdcall() -> Self { Self::new("__stdcall").with_integer_return("EAX").with_stack_alignment(4).with_callee_cleanup() }
    pub fn unknown() -> Self { Self::new("unknown").with_unknown() }
}
impl fmt::Display for PrototypeModel { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f,"PrototypeModel({})",self.name) } }

/// Manages function tags.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct FunctionTagManager { tags: HashMap<String, FunctionTag> }
#[allow(dead_code)]
impl FunctionTagManager {
    pub fn new() -> Self { Self::default() }
    pub fn create_tag(&mut self, name: impl Into<String>, comment: Option<String>) -> Result<&FunctionTag, String> {
        let n=name.into(); if self.tags.contains_key(&n){return Err(format!("exists: {}",n));}
        self.tags.insert(n.clone(), FunctionTag{name:n.clone(),comment}); Ok(self.tags.get(&n).unwrap()) }
    pub fn get_tag(&self, name: &str) -> Option<&FunctionTag> { self.tags.get(name) }
    pub fn get_all_tags(&self) -> Vec<&FunctionTag> { self.tags.values().collect() }
    pub fn remove_tag(&mut self, name: &str) -> bool { self.tags.remove(name).is_some() }
    pub fn tag_count(&self) -> usize { self.tags.len() }
}

/// Tracks register values at specific addresses (for disassembler context).
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct ProgramContext { defaults: HashMap<String, Vec<u8>>, values: HashMap<Address, HashMap<String, Vec<u8>>>, flow_overrides: HashMap<Address, FlowOverride> }
#[allow(dead_code)]
impl ProgramContext {
    pub fn new() -> Self { Self::default() }
    pub fn set_default(&mut self, r: impl Into<String>, v: Vec<u8>) { self.defaults.insert(r.into(),v); }
    pub fn get_default(&self, r: &str) -> Option<&Vec<u8>> { self.defaults.get(r) }
    pub fn get_defaults(&self) -> &HashMap<String, Vec<u8>> { &self.defaults }
    pub fn set_value(&mut self, a: Address, r: impl Into<String>, v: Vec<u8>) { self.values.entry(a).or_default().insert(r.into(),v); }
    pub fn get_value(&self, a: &Address, r: &str) -> Option<&Vec<u8>> { self.values.get(a).and_then(|m| m.get(r)) }
    pub fn get_values_at(&self, a: &Address) -> Option<&HashMap<String, Vec<u8>>> { self.values.get(a) }
    pub fn set_flow_override(&mut self, a: Address, f: FlowOverride) { self.flow_overrides.insert(a,f); }
    pub fn get_flow_override(&self, a: &Address) -> Option<FlowOverride> { self.flow_overrides.get(a).copied() }
    pub fn get_flow_override_addresses(&self) -> Vec<Address> { self.flow_overrides.keys().copied().collect() }
    pub fn has_defaults(&self) -> bool { !self.defaults.is_empty() }
    pub fn has_values(&self) -> bool { !self.values.is_empty() }
}
