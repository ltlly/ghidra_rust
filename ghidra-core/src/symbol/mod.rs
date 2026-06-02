//! Symbol table types for Ghidra Rust.
//!
//! Models Ghidra's symbol table including:
//! - [`Symbol`] trait and its concrete implementations ([`LabelSymbol`],
//!   [`FunctionSymbol`], [`GlobalSymbol`])
//! - [`SymbolTable`] trait for managing symbols
//! - [`Namespace`] trait for hierarchical scoping
//! - [`Reference`] and [`ReferenceManager`] for cross-references
//! - [`RefType`], [`FlowType`], and [`DataRefType`] for classifying references
//! - [`SymbolType`] and [`SourceType`] enums
//!
//! This module is a direct translation of Ghidra's
//! `ghidra.program.model.symbol` package.

use crate::addr::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during symbol operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum SymbolError {
    /// A symbol with the same name already exists in the namespace.
    #[error("duplicate name: {0}")]
    DuplicateName(String),

    /// The provided input is invalid (e.g., empty name, whitespace, null).
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// Attempted to create a circular namespace dependency.
    #[error("circular dependency: {0}")]
    CircularDependency(String),

    /// The symbol has been deleted.
    #[error("symbol has been deleted")]
    SymbolDeleted,

    /// The operation is not supported for this symbol type.
    #[error("unsupported operation: {0}")]
    UnsupportedOperation(String),

    /// Invalid argument provided.
    #[error("illegal argument: {0}")]
    IllegalArgument(String),

    /// Symbol was not found.
    #[error("symbol not found: {0}")]
    SymbolNotFound(String),

    /// Reference was not found.
    #[error("reference not found")]
    ReferenceNotFound,

    /// General I/O or persistence error.
    #[error("symbol error: {0}")]
    Other(String),
}

/// Result type alias for symbol operations.
pub type SymbolResult<T> = Result<T, SymbolError>;

// ---------------------------------------------------------------------------
// SymbolType
// ---------------------------------------------------------------------------

/// The type of a symbol, corresponding to Ghidra's `SymbolType` abstract class
/// and its static instances.
///
/// Each variant has an associated storage ID and namespace flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolType {
    /// A label at a memory or external address. Allows duplicate names.
    Label,
    /// An external library. Must be in the global namespace.
    Library,
    /// A generic namespace. Uses NO_ADDRESS.
    Namespace,
    /// A class namespace. Uses NO_ADDRESS, cannot be inside a function.
    Class,
    /// A function entry point. Allows duplicate names.
    Function,
    /// A function parameter.
    Parameter,
    /// A function local variable.
    LocalVar,
    /// A global register variable.
    GlobalVar,
    /// An imported symbol (external library function).
    Import,
    /// An exported symbol (function or data exported by the binary).
    Export,
    /// An unknown / unclassified symbol type.
    Unknown,
    /// The global namespace root (not persisted in the database).
    Global,
}

impl SymbolType {
    /// The number of persisted symbol types (excluding Global).
    const PERSISTED_COUNT: usize = 8;

    /// All persisted symbol types indexed by storage ID (0..=7).
    const PERSISTED: [Option<SymbolType>; Self::PERSISTED_COUNT] = [
        Some(SymbolType::Label),        // 0
        Some(SymbolType::Library),      // 1
        None,                           // 2 (was deprecated slot)
        Some(SymbolType::Namespace),    // 3
        Some(SymbolType::Class),        // 4
        Some(SymbolType::Function),     // 5
        Some(SymbolType::Parameter),    // 6
        Some(SymbolType::LocalVar),     // 7
    ];

    /// Returns the storage ID used for persistent serialization.
    /// Returns -1 for the Global type.
    pub fn get_id(self) -> i8 {
        match self {
            SymbolType::Label => 0,
            SymbolType::Library => 1,
            SymbolType::Namespace => 3,
            SymbolType::Class => 4,
            SymbolType::Function => 5,
            SymbolType::Parameter => 6,
            SymbolType::LocalVar => 7,
            SymbolType::GlobalVar => 8,
            SymbolType::Import => 9,
            SymbolType::Export => 10,
            SymbolType::Global => -1,
            _ => -2,
            SymbolType::Unknown => -2,
        }
    }

    /// Returns the `SymbolType` for the given storage ID, or `None`.
    pub fn from_id(id: i8) -> Option<SymbolType> {
        if id == -1 {
            return Some(SymbolType::Global);
        }
        if id == 8 {
            return Some(SymbolType::GlobalVar);
        }
        if id < 0 || id as usize >= Self::PERSISTED_COUNT {
            return None;
        }
        Self::PERSISTED[id as usize]
    }

    /// Returns `true` if this symbol type represents a namespace-containing
    /// symbol.
    pub fn is_namespace(self) -> bool {
        matches!(
            self,
            SymbolType::Library
                | SymbolType::Namespace
                | SymbolType::Class
                | SymbolType::Function
                | SymbolType::Global
        )
    }

    /// Returns `true` if this symbol type allows duplicate names within the
    /// same namespace.
    pub fn allows_duplicates(self) -> bool {
        matches!(self, SymbolType::Label | SymbolType::Function)
    }

    /// Returns `true` if `source` is a valid source for this symbol type,
    /// given an optional address.
    pub fn is_valid_source(self, source: SourceType, addr: Option<&Address>) -> bool {
        match self {
            SymbolType::Label => {
                if source != SourceType::Default {
                    return true;
                }
                addr.map(|a| a.is_external_address()).unwrap_or(false)
            }
            SymbolType::Library
            | SymbolType::Namespace
            | SymbolType::Class
            | SymbolType::GlobalVar
            | SymbolType::Global => source != SourceType::Default,
            SymbolType::Function | SymbolType::Parameter | SymbolType::LocalVar => true,
            SymbolType::Import | SymbolType::Export | SymbolType::Unknown => true,
        }
    }

    /// Returns `true` if `addr` is a valid address for this symbol type.
    pub fn is_valid_address(self, addr: &Address) -> bool {
        match self {
            SymbolType::Label | SymbolType::Function | SymbolType::Import | SymbolType::Export => {
                addr.is_memory_address() || addr.is_external_address()
            }
            SymbolType::Library | SymbolType::Namespace | SymbolType::Class => addr.is_no_address(),
            SymbolType::Parameter | SymbolType::LocalVar | SymbolType::GlobalVar => {
                addr.is_variable_address()
            }
            SymbolType::Unknown => true,
            SymbolType::Global => false,
        }
    }
}

impl fmt::Display for SymbolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SymbolType::Label => write!(f, "Label"),
            SymbolType::Library => write!(f, "Library"),
            SymbolType::Namespace => write!(f, "Namespace"),
            SymbolType::Class => write!(f, "Class"),
            SymbolType::Function => write!(f, "Function"),
            SymbolType::Parameter => write!(f, "Parameter"),
            SymbolType::LocalVar => write!(f, "Local Var"),
            SymbolType::GlobalVar => write!(f, "Global Register Var"),
            SymbolType::Import => write!(f, "Import"),
            SymbolType::Export => write!(f, "Export"),
            SymbolType::Unknown => write!(f, "Unknown"),
            SymbolType::Global => write!(f, "Global"),
        }
    }
}

// ---------------------------------------------------------------------------
// SourceType
// ---------------------------------------------------------------------------

/// Indicates the general source/origin of a markup made to a program.
///
/// The priority order (highest to lowest) is:
/// 1. [`UserDefined`](SourceType::UserDefined)
/// 2. [`Imported`](SourceType::Imported)
/// 3. [`Analysis`](SourceType::Analysis) / [`AI`](SourceType::AI) (equal)
/// 4. [`Default`](SourceType::Default) (lowest)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceType {
    /// Dynamically produced content (lowest priority). Storage ID 1.
    Default,
    /// Content produced by an analyzer. Storage ID 2.
    Analysis,
    /// Content produced through AI assistance. Storage ID 2 (same level as Analysis).
    AI,
    /// Content produced during import of reliable data. Storage ID 3.
    Imported,
    /// Content produced by the user (highest priority). Storage ID 4.
    UserDefined,
}

impl SourceType {
    /// Source types indexed by storage ID.
    const BY_STORAGE_ID: [Option<SourceType>; 5] = [
        Some(SourceType::Analysis),    // 0
        Some(SourceType::UserDefined), // 1
        Some(SourceType::Default),     // 2
        Some(SourceType::Imported),    // 3
        Some(SourceType::AI),          // 4
    ];

    /// Returns the numeric priority. Higher numbers mean higher priority.
    pub fn priority(self) -> u8 {
        match self {
            SourceType::Default => 2,
            SourceType::Analysis => 0,
            SourceType::AI => 4,
            SourceType::Imported => 3,
            SourceType::UserDefined => 1,
        }
    }

    /// Returns the storage ID for persistent serialization.
    pub fn storage_id(self) -> u8 {
        match self {
            SourceType::Default => 2,
            SourceType::Analysis => 0,
            SourceType::AI => 4,
            SourceType::Imported => 3,
            SourceType::UserDefined => 1,
        }
    }

    /// Returns the `SourceType` for the given storage ID.
    pub fn from_storage_id(id: u8) -> Option<SourceType> {
        Self::BY_STORAGE_ID.get(id as usize).copied().flatten()
    }

    /// Returns `true` if this source type has higher priority than `other`.
    pub fn is_higher_priority_than(self, other: SourceType) -> bool {
        self.priority() > other.priority()
    }

    /// Returns `true` if this source type has higher or equal priority.
    pub fn is_higher_or_equal_priority_than(self, other: SourceType) -> bool {
        self.priority() >= other.priority()
    }

    /// Returns `true` if this source type has lower priority than `other`.
    pub fn is_lower_priority_than(self, other: SourceType) -> bool {
        self.priority() < other.priority()
    }

    /// Returns `true` if this source type has lower or equal priority.
    pub fn is_lower_or_equal_priority_than(self, other: SourceType) -> bool {
        self.priority() <= other.priority()
    }

    /// Returns a user-friendly display string.
    pub fn display_string(self) -> &'static str {
        match self {
            SourceType::Default => "Default",
            SourceType::Analysis => "Analysis",
            SourceType::AI => "AI",
            SourceType::Imported => "Imported",
            SourceType::UserDefined => "User Defined",
        }
    }
}

impl fmt::Display for SourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_string())
    }
}

// ---------------------------------------------------------------------------
// FlowType
// ---------------------------------------------------------------------------

/// Flow types for instructions, describing how execution flows from one
/// instruction to the next. Corresponds to Ghidra's `FlowType` constants
/// defined within `RefType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FlowType {
    /// Unknown flow type (error state).
    Invalid,
    /// Complex or generic flow.
    Flow,
    /// Fall-through override.
    FallThrough,
    /// Unconditional jump/branch.
    UnconditionalJump,
    /// Conditional jump/branch with fall-through.
    ConditionalJump,
    /// Unconditional call with fall-through.
    UnconditionalCall,
    /// Conditional call with fall-through.
    ConditionalCall,
    /// Terminal (e.g., return from function).
    Terminator,
    /// Computed jump/branch.
    ComputedJump,
    /// Conditional terminal (e.g., conditional return).
    ConditionalTerminator,
    /// Computed call with fall-through.
    ComputedCall,
    /// Unconditional call followed by terminal without fall-through.
    CallTerminator,
    /// Computed call followed by terminal without fall-through.
    ComputedCallTerminator,
    /// Conditional call followed by terminal without fall-through.
    ConditionalCallTerminator,
    /// Conditional computed call with fall-through.
    ConditionalComputedCall,
    /// Conditional computed jump with fall-through.
    ConditionalComputedJump,
    /// Conditional jump followed by terminal without fall-through.
    JumpTerminator,
    /// Reference placed on a pointer used indirectly by computed flow.
    Indirection,
    /// Override: change CALL/CALLIND to CALL with new target.
    CallOverrideUnconditional,
    /// Override: change BRANCH/CBRANCH to BRANCH with new target.
    JumpOverrideUnconditional,
    /// Override: change CALLOTHER to CALL.
    CallOtherOverrideCall,
    /// Override: change CALLOTHER to BRANCH.
    CallOtherOverrideJump,
}

impl FlowType {
    /// Returns the byte value used for persistent storage.
    pub fn value(self) -> i8 {
        match self {
            FlowType::Invalid => -2,
            FlowType::Flow => -1,
            FlowType::FallThrough => 0,
            FlowType::UnconditionalJump => 1,
            FlowType::ConditionalJump => 2,
            FlowType::UnconditionalCall => 3,
            FlowType::ConditionalCall => 4,
            FlowType::Terminator => 5,
            FlowType::ComputedJump => 6,
            FlowType::ConditionalTerminator => 7,
            FlowType::ComputedCall => 8,
            FlowType::Indirection => 9,
            FlowType::CallTerminator => 10,
            FlowType::JumpTerminator => 11,
            FlowType::ConditionalComputedJump => 12,
            FlowType::ConditionalComputedCall => 13,
            FlowType::ConditionalCallTerminator => 14,
            FlowType::ComputedCallTerminator => 15,
            FlowType::CallOverrideUnconditional => 16,
            FlowType::JumpOverrideUnconditional => 17,
            FlowType::CallOtherOverrideCall => 18,
            FlowType::CallOtherOverrideJump => 19,
        }
    }

    /// Returns `true` if this is a flow reference type.
    pub fn is_flow(self) -> bool {
        true
    }

    /// Returns `true` if execution can fall through past this instruction.
    pub fn has_fallthrough(self) -> bool {
        matches!(
            self,
            FlowType::Invalid
                | FlowType::Flow
                | FlowType::FallThrough
                | FlowType::ConditionalJump
                | FlowType::UnconditionalCall
                | FlowType::ConditionalCall
                | FlowType::ConditionalTerminator
                | FlowType::ComputedCall
                | FlowType::ConditionalComputedCall
                | FlowType::ConditionalComputedJump
                | FlowType::CallOverrideUnconditional
                | FlowType::CallOtherOverrideCall
        )
    }

    /// Returns `true` if this is a fallthrough type.
    pub fn is_fallthrough(self) -> bool {
        self == FlowType::FallThrough
    }

    /// Returns `true` if this is a call flow.
    pub fn is_call(self) -> bool {
        matches!(
            self,
            FlowType::UnconditionalCall
                | FlowType::ConditionalCall
                | FlowType::ComputedCall
                | FlowType::CallTerminator
                | FlowType::ComputedCallTerminator
                | FlowType::ConditionalCallTerminator
                | FlowType::ConditionalComputedCall
                | FlowType::CallOverrideUnconditional
                | FlowType::CallOtherOverrideCall
        )
    }

    /// Returns `true` if this is a jump/branch flow.
    pub fn is_jump(self) -> bool {
        matches!(
            self,
            FlowType::UnconditionalJump
                | FlowType::ConditionalJump
                | FlowType::ComputedJump
                | FlowType::ConditionalComputedJump
                | FlowType::JumpTerminator
                | FlowType::JumpOverrideUnconditional
                | FlowType::CallOtherOverrideJump
        )
    }

    /// Returns `true` if this is a terminal instruction.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            FlowType::Terminator
                | FlowType::ConditionalTerminator
                | FlowType::CallTerminator
                | FlowType::ComputedCallTerminator
                | FlowType::ConditionalCallTerminator
                | FlowType::JumpTerminator
        )
    }

    /// Returns `true` if this is a conditional flow.
    pub fn is_conditional(self) -> bool {
        matches!(
            self,
            FlowType::ConditionalJump
                | FlowType::ConditionalCall
                | FlowType::ConditionalTerminator
                | FlowType::ConditionalComputedCall
                | FlowType::ConditionalComputedJump
                | FlowType::ConditionalCallTerminator
        )
    }

    /// Returns `true` if this is an unconditional flow.
    pub fn is_unconditional(self) -> bool {
        !self.is_conditional()
    }

    /// Returns `true` if the destination is computed (not directly referenced).
    pub fn is_computed(self) -> bool {
        matches!(
            self,
            FlowType::ComputedJump
                | FlowType::ComputedCall
                | FlowType::ComputedCallTerminator
                | FlowType::ConditionalComputedCall
                | FlowType::ConditionalComputedJump
        )
    }

    /// Returns `true` if this is an override reference.
    pub fn is_override(self) -> bool {
        matches!(
            self,
            FlowType::CallOverrideUnconditional
                | FlowType::JumpOverrideUnconditional
                | FlowType::CallOtherOverrideCall
                | FlowType::CallOtherOverrideJump
        )
    }

    /// Returns the flow type name.
    pub fn name(self) -> &'static str {
        match self {
            FlowType::Invalid => "INVALID",
            FlowType::Flow => "FLOW",
            FlowType::FallThrough => "FALL_THROUGH",
            FlowType::UnconditionalJump => "UNCONDITIONAL_JUMP",
            FlowType::ConditionalJump => "CONDITIONAL_JUMP",
            FlowType::UnconditionalCall => "UNCONDITIONAL_CALL",
            FlowType::ConditionalCall => "CONDITIONAL_CALL",
            FlowType::Terminator => "TERMINATOR",
            FlowType::ComputedJump => "COMPUTED_JUMP",
            FlowType::ConditionalTerminator => "CONDITIONAL_TERMINATOR",
            FlowType::ComputedCall => "COMPUTED_CALL",
            FlowType::CallTerminator => "CALL_TERMINATOR",
            FlowType::ComputedCallTerminator => "COMPUTED_CALL_TERMINATOR",
            FlowType::ConditionalCallTerminator => "CONDITIONAL_CALL_TERMINATOR",
            FlowType::ConditionalComputedCall => "CONDITIONAL_COMPUTED_CALL",
            FlowType::ConditionalComputedJump => "CONDITIONAL_COMPUTED_JUMP",
            FlowType::JumpTerminator => "JUMP_TERMINATOR",
            FlowType::Indirection => "INDIRECTION",
            FlowType::CallOverrideUnconditional => "CALL_OVERRIDE_UNCONDITIONAL",
            FlowType::JumpOverrideUnconditional => "JUMP_OVERRIDE_UNCONDITIONAL",
            FlowType::CallOtherOverrideCall => "CALLOTHER_OVERRIDE_CALL",
            FlowType::CallOtherOverrideJump => "CALLOTHER_OVERRIDE_JUMP",
        }
    }
}

impl fmt::Display for FlowType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ---------------------------------------------------------------------------
// DataRefType
// ---------------------------------------------------------------------------

/// Data reference types, corresponding to Ghidra's `DataRefType`.
/// Uses bitmask access flags: READ=1, WRITE=2, IND=4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataRefType {
    /// Thunk relationship (does not rely on a stored reference).
    Thunk,
    /// Generic data reference (read/write unknown).
    Data,
    /// Data passed to a function.
    Param,
    /// Indirect data reference via pointer.
    DataInd,
    /// Direct read.
    Read,
    /// Direct write.
    Write,
    /// Direct read and write.
    ReadWrite,
    /// Indirect read via pointer.
    ReadInd,
    /// Indirect write via pointer.
    WriteInd,
    /// Indirect read and write via pointer.
    ReadWriteInd,
    /// External entry point location reference.
    ExternalRef,
}

impl DataRefType {
    /// Internal access flags.
    const READ: u8 = 1;
    const WRITE: u8 = 2;
    const IND: u8 = 4;

    /// Returns the access flags bitmask for this data reference type.
    fn access_flags(self) -> u8 {
        match self {
            DataRefType::Thunk | DataRefType::Data | DataRefType::Param | DataRefType::ExternalRef => {
                0
            }
            DataRefType::Read => Self::READ,
            DataRefType::Write => Self::WRITE,
            DataRefType::ReadWrite => Self::READ | Self::WRITE,
            DataRefType::DataInd => Self::IND,
            DataRefType::ReadInd => Self::READ | Self::IND,
            DataRefType::WriteInd => Self::WRITE | Self::IND,
            DataRefType::ReadWriteInd => Self::READ | Self::WRITE | Self::IND,
        }
    }

    /// Returns the byte value used for persistent storage.
    pub fn value(self) -> i8 {
        match self {
            DataRefType::Data => 100,
            DataRefType::Read => 101,
            DataRefType::Write => 102,
            DataRefType::ReadWrite => 103,
            DataRefType::ReadInd => 104,
            DataRefType::WriteInd => 105,
            DataRefType::ReadWriteInd => 106,
            DataRefType::Param => 107,
            DataRefType::ExternalRef => 113,
            DataRefType::DataInd => 114,
            DataRefType::Thunk => 127,
        }
    }

    /// Returns `true` if this is a data reference.
    pub fn is_data(self) -> bool {
        true
    }

    /// Returns `true` if this reference is a read.
    pub fn is_read(self) -> bool {
        (self.access_flags() & Self::READ) != 0
    }

    /// Returns `true` if this reference is a write.
    pub fn is_write(self) -> bool {
        (self.access_flags() & Self::WRITE) != 0
    }

    /// Returns `true` if this reference is indirect.
    pub fn is_indirect(self) -> bool {
        (self.access_flags() & Self::IND) != 0
    }

    /// Returns the ref type name.
    pub fn name(self) -> &'static str {
        match self {
            DataRefType::Thunk => "THUNK",
            DataRefType::Data => "DATA",
            DataRefType::Param => "PARAM",
            DataRefType::DataInd => "DATA_IND",
            DataRefType::Read => "READ",
            DataRefType::Write => "WRITE",
            DataRefType::ReadWrite => "READ_WRITE",
            DataRefType::ReadInd => "READ_IND",
            DataRefType::WriteInd => "WRITE_IND",
            DataRefType::ReadWriteInd => "READ_WRITE_IND",
            DataRefType::ExternalRef => "EXTERNAL",
        }
    }
}

impl fmt::Display for DataRefType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ---------------------------------------------------------------------------
// RefType
// ---------------------------------------------------------------------------

/// Unified reference type, encompassing both flow and data reference types.
/// Corresponds to Ghidra's `RefType` abstract class and its static constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RefType {
    /// A flow (instruction) reference.
    Flow(FlowType),
    /// A data reference.
    Data(DataRefType),
}

impl RefType {
    /// Returns the byte storage value.
    pub fn value(self) -> i8 {
        match self {
            RefType::Flow(ft) => ft.value(),
            RefType::Data(dt) => dt.value(),
        }
    }

    /// Returns `true` if this is a flow reference.
    pub fn is_flow(self) -> bool {
        matches!(self, RefType::Flow(_))
    }

    /// Returns `true` if this is a data reference.
    pub fn is_data(self) -> bool {
        matches!(self, RefType::Data(_))
    }

    /// Returns `true` if this reference is a read.
    pub fn is_read(self) -> bool {
        match self {
            RefType::Data(dt) => dt.is_read(),
            _ => false,
        }
    }

    /// Returns `true` if this reference is a write.
    pub fn is_write(self) -> bool {
        match self {
            RefType::Data(dt) => dt.is_write(),
            _ => false,
        }
    }

    /// Returns `true` if this reference is indirect.
    pub fn is_indirect(self) -> bool {
        match self {
            RefType::Flow(FlowType::Indirection) => true,
            RefType::Data(dt) => dt.is_indirect(),
            _ => false,
        }
    }

    /// Returns `true` if this is a fallthrough type.
    pub fn is_fallthrough(self) -> bool {
        self == RefType::Flow(FlowType::FallThrough)
    }

    /// Returns `true` if this flow type can fall through.
    pub fn has_fallthrough(self) -> bool {
        match self {
            RefType::Flow(ft) => ft.has_fallthrough(),
            _ => false,
        }
    }

    /// Returns `true` if this is a call reference.
    pub fn is_call(self) -> bool {
        match self {
            RefType::Flow(ft) => ft.is_call(),
            _ => false,
        }
    }

    /// Returns `true` if this is a jump reference.
    pub fn is_jump(self) -> bool {
        match self {
            RefType::Flow(ft) => ft.is_jump(),
            _ => false,
        }
    }

    /// Returns `true` if this is an unconditional call or jump.
    pub fn is_unconditional(self) -> bool {
        match self {
            RefType::Flow(ft) => ft.is_unconditional(),
            _ => false,
        }
    }

    /// Returns `true` if this is a conditional call or jump.
    pub fn is_conditional(self) -> bool {
        match self {
            RefType::Flow(ft) => ft.is_conditional(),
            _ => false,
        }
    }

    /// Returns `true` if this is a computed flow.
    pub fn is_computed(self) -> bool {
        match self {
            RefType::Flow(ft) => ft.is_computed(),
            _ => false,
        }
    }

    /// Returns `true` if this is a terminal instruction.
    pub fn is_terminal(self) -> bool {
        match self {
            RefType::Flow(ft) => ft.is_terminal(),
            _ => false,
        }
    }

    /// Returns `true` if this is an override reference.
    pub fn is_override(self) -> bool {
        match self {
            RefType::Flow(ft) => ft.is_override(),
            _ => false,
        }
    }

    /// Returns the display name.
    pub fn name(self) -> &'static str {
        match self {
            RefType::Flow(ft) => ft.name(),
            RefType::Data(dt) => dt.name(),
        }
    }

    /// Returns a user-friendly display string.
    pub fn display_string(self) -> &'static str {
        match self {
            RefType::Data(DataRefType::Thunk) => "Thunk",
            RefType::Flow(FlowType::FallThrough) => "FallThrough",
            _ => {
                if self.is_read() && self.is_write() {
                    "RW"
                } else if self.is_read() {
                    "Read"
                } else if self.is_write() {
                    "Write"
                } else if self.is_data() {
                    "Data"
                } else if self.is_call() {
                    "Call"
                } else if self.is_jump() {
                    if self.is_conditional() {
                        "Branch"
                    } else {
                        "Jump"
                    }
                } else {
                    "Unknown"
                }
            }
        }
    }

    // -- Static convenience constructors for commonly used constants --

    pub const INVALID: RefType = RefType::Flow(FlowType::Invalid);
    pub const FLOW: RefType = RefType::Flow(FlowType::Flow);
    pub const FALL_THROUGH: RefType = RefType::Flow(FlowType::FallThrough);
    pub const UNCONDITIONAL_JUMP: RefType = RefType::Flow(FlowType::UnconditionalJump);
    pub const CONDITIONAL_JUMP: RefType = RefType::Flow(FlowType::ConditionalJump);
    pub const UNCONDITIONAL_CALL: RefType = RefType::Flow(FlowType::UnconditionalCall);
    pub const CONDITIONAL_CALL: RefType = RefType::Flow(FlowType::ConditionalCall);
    pub const TERMINATOR: RefType = RefType::Flow(FlowType::Terminator);
    pub const COMPUTED_JUMP: RefType = RefType::Flow(FlowType::ComputedJump);
    pub const CONDITIONAL_TERMINATOR: RefType = RefType::Flow(FlowType::ConditionalTerminator);
    pub const COMPUTED_CALL: RefType = RefType::Flow(FlowType::ComputedCall);
    pub const CALL_TERMINATOR: RefType = RefType::Flow(FlowType::CallTerminator);
    pub const COMPUTED_CALL_TERMINATOR: RefType = RefType::Flow(FlowType::ComputedCallTerminator);
    pub const CONDITIONAL_CALL_TERMINATOR: RefType =
        RefType::Flow(FlowType::ConditionalCallTerminator);
    pub const CONDITIONAL_COMPUTED_CALL: RefType =
        RefType::Flow(FlowType::ConditionalComputedCall);
    pub const CONDITIONAL_COMPUTED_JUMP: RefType =
        RefType::Flow(FlowType::ConditionalComputedJump);
    pub const JUMP_TERMINATOR: RefType = RefType::Flow(FlowType::JumpTerminator);
    pub const INDIRECTION: RefType = RefType::Flow(FlowType::Indirection);
    pub const CALL_OVERRIDE_UNCONDITIONAL: RefType =
        RefType::Flow(FlowType::CallOverrideUnconditional);
    pub const JUMP_OVERRIDE_UNCONDITIONAL: RefType =
        RefType::Flow(FlowType::JumpOverrideUnconditional);
    pub const CALLOTHER_OVERRIDE_CALL: RefType =
        RefType::Flow(FlowType::CallOtherOverrideCall);
    pub const CALLOTHER_OVERRIDE_JUMP: RefType =
        RefType::Flow(FlowType::CallOtherOverrideJump);
    pub const THUNK: RefType = RefType::Data(DataRefType::Thunk);
    pub const DATA: RefType = RefType::Data(DataRefType::Data);
    pub const PARAM: RefType = RefType::Data(DataRefType::Param);
    pub const DATA_IND: RefType = RefType::Data(DataRefType::DataInd);
    pub const READ: RefType = RefType::Data(DataRefType::Read);
    pub const WRITE: RefType = RefType::Data(DataRefType::Write);
    pub const READ_WRITE: RefType = RefType::Data(DataRefType::ReadWrite);
    pub const READ_IND: RefType = RefType::Data(DataRefType::ReadInd);
    pub const WRITE_IND: RefType = RefType::Data(DataRefType::WriteInd);
    pub const READ_WRITE_IND: RefType = RefType::Data(DataRefType::ReadWriteInd);
    pub const EXTERNAL_REF: RefType = RefType::Data(DataRefType::ExternalRef);
}

impl fmt::Display for RefType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ---------------------------------------------------------------------------
// LabelHistory
// ---------------------------------------------------------------------------

/// Records a change made to labels at a given address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelHistory {
    /// The address where the label change occurred.
    pub address: Address,
    /// The label name that was set.
    pub label: String,
    /// The source of the change.
    pub source: SourceType,
    /// When the change was made (as a timestamp string).
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// Namespace trait
// ---------------------------------------------------------------------------

/// The Namespace interface, corresponding to Ghidra's `Namespace`.
///
/// A namespace provides hierarchical scoping for symbols. The global namespace
/// (ID=0) is the root. Function, Library, Class, and generic Namespace types
/// all implement this trait.
pub trait Namespace: fmt::Debug + Send + Sync {
    /// Returns the symbol for this namespace.
    fn get_symbol(&self) -> &dyn SymbolApi;

    /// Returns the type of namespace (e.g., Function, Library, Class).
    fn get_type(&self) -> SymbolType {
        SymbolType::Namespace
    }

    /// Returns `true` if this namespace is external (associated with a Library).
    fn is_external(&self) -> bool;

    /// Returns the simple namespace name (without parent path).
    fn get_name(&self) -> String;

    /// Returns the namespace name, optionally prepended with the full parent path.
    fn get_name_full(&self, include_namespace_path: bool) -> String;

    /// Returns the namespace ID.
    fn get_id(&self) -> u64;

    /// Returns the parent namespace, or `None` for the global namespace.
    fn get_parent_namespace(&self) -> Option<&dyn Namespace>;

    /// Returns the address set for this namespace.
    fn get_body(&self) -> Vec<Address>;

    /// Sets the parent namespace.
    fn set_parent_namespace(
        &mut self,
        parent: &dyn Namespace,
    ) -> SymbolResult<()>;

    /// Returns `true` if this is the global namespace (ID 0).
    fn is_global(&self) -> bool {
        self.get_id() == 0
    }

    /// Returns `true` if this is a library namespace.
    fn is_library(&self) -> bool {
        let s = self.get_symbol();
        s.get_symbol_type() == SymbolType::Library
    }

    /// Returns the namespace path as a list of namespace names.
    fn get_path_list(&self, omit_library: bool) -> Vec<String>
    where
        Self: Sized,
    {
        if self.is_global() {
            return Vec::new();
        }
        let mut list = Vec::new();
        let mut current: &dyn Namespace = self;
        loop {
            if current.is_global() || (omit_library && current.is_library()) {
                break;
            }
            list.push(current.get_name());
            match current.get_parent_namespace() {
                Some(parent) => current = parent,
                None => break,
            }
        }
        list.reverse();
        list
    }

    /// Namespace delimiter ("::").
    fn delimiter() -> &'static str
    where
        Self: Sized,
    {
        "::"
    }

    /// Global namespace ID.
    fn global_namespace_id() -> u64
    where
        Self: Sized,
    {
        0
    }
}

// ---------------------------------------------------------------------------
// Symbol trait
// ---------------------------------------------------------------------------

/// The SymbolApi trait, corresponding to Ghidra's `Symbol` interface.
///
/// A symbol associates a string name with an address. Symbols exist within a
/// namespace hierarchy and may have references pointing to or from them.
///
/// This trait is named `SymbolApi` to avoid collision with the concrete
/// [`Symbol`] enum that wraps the implementing types. All concrete symbol
/// types ([`LabelSymbol`], [`FunctionSymbol`], [`GlobalSymbol`], and the
/// [`Symbol`] enum) implement this trait.
pub trait SymbolApi: fmt::Debug + Send + Sync {
    /// Returns the address of this symbol.
    fn get_address(&self) -> &Address;

    /// Returns the name of this symbol.
    fn get_name(&self) -> String;

    /// Returns the full path name as an array of strings, ending with the
    /// symbol name.
    fn get_path(&self) -> Vec<String>;

    /// Returns the symbol name, optionally prepended with the namespace path.
    fn get_name_qualified(&self, include_namespace: bool) -> String;

    /// Returns the parent namespace for this symbol.
    fn get_parent_namespace(&self) -> Option<&dyn Namespace>;

    /// Returns the parent namespace symbol.
    fn get_parent_symbol(&self) -> Option<&dyn SymbolApi>;

    /// Returns `true` if the given namespace is a descendant of this symbol.
    fn is_descendant(&self, namespace: &dyn Namespace) -> bool;

    /// Returns `true` if the given parent is valid for this symbol.
    fn is_valid_parent(&self, parent: &dyn Namespace) -> bool;

    /// Returns this symbol's type.
    fn get_symbol_type(&self) -> SymbolType;

    /// Returns the number of references to this symbol or its address.
    fn get_reference_count(&self) -> usize {
        0
    }

    /// Returns `true` if this symbol has at least one reference to it.
    fn has_references(&self) -> bool {
        false
    }

    /// Returns all memory references to the address of this symbol.
    fn get_references(&self) -> &[Reference] {
        &[]
    }

    /// Returns the symbol's unique ID.
    fn get_id(&self) -> u64;

    /// Returns the object associated with this symbol, or `None` if deleted.
    fn get_object(&self) -> Option<&dyn std::any::Any> {
        None
    }

    /// Returns `true` if this symbol is in the global namespace.
    fn is_global(&self) -> bool;

    /// Returns `true` if this is an external symbol.
    fn is_external(&self) -> bool;

    /// Returns `true` if this symbol is primary at its address.
    fn is_primary(&self) -> bool {
        false
    }

    /// Sets this symbol as primary at its address.
    fn set_primary(&mut self) -> bool {
        false
    }

    /// Returns `true` if the symbol is at an external entry point address.
    fn is_external_entry_point(&self) -> bool {
        false
    }

    /// Returns `true` if this symbol is pinned to its address.
    fn is_pinned(&self) -> bool {
        false
    }

    /// Sets whether this symbol is pinned to its address.
    fn set_pinned(&mut self, _pinned: bool) -> SymbolResult<()> {
        Err(SymbolError::UnsupportedOperation(
            "Only Code and Function Symbols may be pinned.".to_string(),
        ))
    }

    /// Returns `true` if this symbol is dynamic (not stored in the database).
    fn is_dynamic(&self) -> bool;

    /// Returns the source of this symbol.
    fn get_source(&self) -> SourceType;

    /// Sets the source of this symbol.
    fn set_source(&mut self, source: SourceType);

    /// Returns `true` if this symbol has been deleted.
    fn is_deleted(&self) -> bool;

    /// Sets the name of this symbol.
    fn set_name(&mut self, new_name: &str, source: SourceType) -> SymbolResult<()>;

    /// Sets the parent namespace of this symbol.
    fn set_namespace(&mut self, new_namespace: &dyn Namespace) -> SymbolResult<()>;

    /// Sets both the name and namespace atomically.
    fn set_name_and_namespace(
        &mut self,
        new_name: &str,
        new_namespace: &dyn Namespace,
        source: SourceType,
    ) -> SymbolResult<()>;

    /// Deletes this symbol and its associated resources.
    fn delete(&mut self) -> bool;
}

// ---------------------------------------------------------------------------
// GlobalSymbol
// ---------------------------------------------------------------------------

/// The global namespace symbol. There is exactly one of these per program.
/// It is the root of the namespace hierarchy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalSymbol {
    /// The global namespace name.
    name: String,
}

impl GlobalSymbol {
    /// Creates a new GlobalSymbol with the default name.
    pub fn new() -> Self {
        Self {
            name: "Global".to_string(),
        }
    }

    /// Creates a new GlobalSymbol with a custom name.
    pub fn with_name(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

impl Default for GlobalSymbol {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolApi for GlobalSymbol {
    fn get_address(&self) -> &Address {
        &Address::NULL
    }

    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_path(&self) -> Vec<String> {
        vec![self.name.clone()]
    }

    fn get_name_qualified(&self, include_namespace: bool) -> String {
        if include_namespace {
            self.name.clone()
        } else {
            self.name.clone()
        }
    }

    fn get_parent_namespace(&self) -> Option<&dyn Namespace> {
        None
    }

    fn get_parent_symbol(&self) -> Option<&dyn SymbolApi> {
        None
    }

    fn is_descendant(&self, _namespace: &dyn Namespace) -> bool {
        true
    }

    fn is_valid_parent(&self, _parent: &dyn Namespace) -> bool {
        false
    }

    fn get_symbol_type(&self) -> SymbolType {
        SymbolType::Global
    }

    fn get_id(&self) -> u64 {
        0
    }

    fn is_global(&self) -> bool {
        true
    }

    fn is_external(&self) -> bool {
        false
    }

    fn is_primary(&self) -> bool {
        true
    }

    fn is_dynamic(&self) -> bool {
        false
    }

    fn get_source(&self) -> SourceType {
        SourceType::UserDefined
    }

    fn set_source(&mut self, _source: SourceType) {
        // Global symbol source cannot be changed.
    }

    fn is_deleted(&self) -> bool {
        false
    }

    fn set_name(&mut self, _new_name: &str, _source: SourceType) -> SymbolResult<()> {
        Err(SymbolError::UnsupportedOperation(
            "Cannot rename global symbol".to_string(),
        ))
    }

    fn set_namespace(&mut self, _new_namespace: &dyn Namespace) -> SymbolResult<()> {
        Err(SymbolError::UnsupportedOperation(
            "Cannot move global symbol".to_string(),
        ))
    }

    fn set_name_and_namespace(
        &mut self,
        _new_name: &str,
        _new_namespace: &dyn Namespace,
        _source: SourceType,
    ) -> SymbolResult<()> {
        Err(SymbolError::UnsupportedOperation(
            "Cannot rename or move global symbol".to_string(),
        ))
    }

    fn delete(&mut self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// LabelSymbol
// ---------------------------------------------------------------------------

/// A label symbol at a memory or external address. Corresponds to
/// `SymbolType::Label`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelSymbol {
    /// The symbol ID.
    id: u64,
    /// The label name.
    name: String,
    /// The address this label is at.
    address: Address,
    /// The parent namespace ID. 0 means global namespace.
    namespace_id: u64,
    /// The source of this label.
    source: SourceType,
    /// Whether this is the primary symbol at this address.
    primary: bool,
    /// Whether this is a dynamic (auto-generated) symbol.
    dynamic: bool,
    /// Whether this symbol is pinned to its address.
    pinned: bool,
    /// Whether this symbol has been deleted.
    deleted: bool,
    /// References to this symbol.
    references: Vec<Reference>,
}

impl LabelSymbol {
    /// Creates a new label symbol.
    pub fn new(id: u64, name: impl Into<String>, address: Address) -> Self {
        Self {
            id,
            name: name.into(),
            address,
            namespace_id: 0,
            source: SourceType::UserDefined,
            primary: false,
            dynamic: false,
            pinned: false,
            deleted: false,
            references: Vec::new(),
        }
    }

    /// Creates a new label symbol with full configuration.
    pub fn with_options(
        id: u64,
        name: impl Into<String>,
        address: Address,
        namespace_id: u64,
        source: SourceType,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            address,
            namespace_id,
            source,
            primary: false,
            dynamic: false,
            pinned: false,
            deleted: false,
            references: Vec::new(),
        }
    }

    /// Creates a dynamic label symbol.
    pub fn dynamic(id: u64, address: Address, namespace_id: u64) -> Self {
        Self {
            id,
            name: format!("{}_{:08X}", "LAB", address.offset),
            address,
            namespace_id,
            source: SourceType::Default,
            primary: false,
            dynamic: true,
            pinned: false,
            deleted: false,
            references: Vec::new(),
        }
    }
}

impl SymbolApi for LabelSymbol {
    fn get_address(&self) -> &Address {
        &self.address
    }

    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_path(&self) -> Vec<String> {
        vec![self.name.clone()]
    }

    fn get_name_qualified(&self, include_namespace: bool) -> String {
        if include_namespace {
            format!("{}::{}", "Global", self.name)
        } else {
            self.name.clone()
        }
    }

    fn get_parent_namespace(&self) -> Option<&dyn Namespace> {
        // Returns None because we can't return a reference to a trait from a
        // field directly. Callers should use the namespace_id to look up the
        // namespace from the symbol table.
        None
    }

    fn get_parent_symbol(&self) -> Option<&dyn SymbolApi> {
        None
    }

    fn is_descendant(&self, namespace: &dyn Namespace) -> bool {
        self.namespace_id == namespace.get_id()
    }

    fn is_valid_parent(&self, parent: &dyn Namespace) -> bool {
        // A label may have any namespace as parent except a function in external space.
        let is_external = self.address.is_external_address();
        if is_external != parent.is_external() {
            return false;
        }
        if parent.get_id() != 0
            && parent.get_type() == SymbolType::Function
            && is_external
        {
            return false;
        }
        true
    }

    fn get_symbol_type(&self) -> SymbolType {
        SymbolType::Label
    }

    fn get_reference_count(&self) -> usize {
        self.references.len()
    }

    fn has_references(&self) -> bool {
        !self.references.is_empty()
    }

    fn get_references(&self) -> &[Reference] {
        &self.references
    }

    fn get_id(&self) -> u64 {
        self.id
    }

    fn is_global(&self) -> bool {
        self.namespace_id == 0
    }

    fn is_external(&self) -> bool {
        self.address.is_external_address()
    }

    fn is_primary(&self) -> bool {
        self.primary
    }

    fn set_primary(&mut self) -> bool {
        if self.primary {
            false
        } else {
            self.primary = true;
            true
        }
    }

    fn is_external_entry_point(&self) -> bool {
        false
    }

    fn is_pinned(&self) -> bool {
        self.pinned
    }

    fn set_pinned(&mut self, pinned: bool) -> SymbolResult<()> {
        self.pinned = pinned;
        Ok(())
    }

    fn is_dynamic(&self) -> bool {
        self.dynamic
    }

    fn get_source(&self) -> SourceType {
        self.source
    }

    fn set_source(&mut self, source: SourceType) {
        if SymbolType::Label.is_valid_source(source, Some(&self.address)) {
            self.source = source;
            if source != SourceType::Default {
                self.dynamic = false;
            }
        }
    }

    fn is_deleted(&self) -> bool {
        self.deleted
    }

    fn set_name(&mut self, new_name: &str, source: SourceType) -> SymbolResult<()> {
        validate_symbol_name(new_name)?;
        self.name = new_name.to_string();
        self.set_source(source);
        Ok(())
    }

    fn set_namespace(&mut self, new_namespace: &dyn Namespace) -> SymbolResult<()> {
        if !self.is_valid_parent(new_namespace) {
            return Err(SymbolError::InvalidInput(format!(
                "invalid parent namespace for label symbol"
            )));
        }
        self.namespace_id = new_namespace.get_id();
        Ok(())
    }

    fn set_name_and_namespace(
        &mut self,
        new_name: &str,
        new_namespace: &dyn Namespace,
        source: SourceType,
    ) -> SymbolResult<()> {
        self.set_name(new_name, source)?;
        self.set_namespace(new_namespace)?;
        Ok(())
    }

    fn delete(&mut self) -> bool {
        if self.deleted {
            return false;
        }
        self.deleted = true;
        self.references.clear();
        true
    }
}

// ---------------------------------------------------------------------------
// FunctionSymbol
// ---------------------------------------------------------------------------

/// A function entry point symbol. Corresponds to `SymbolType::Function`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSymbol {
    /// The symbol ID.
    id: u64,
    /// The function name.
    name: String,
    /// The entry point address.
    address: Address,
    /// The parent namespace ID.
    namespace_id: u64,
    /// The source of this function symbol.
    source: SourceType,
    /// Whether this is the primary symbol at this address.
    primary: bool,
    /// Whether this is a default (auto-named) function.
    default: bool,
    /// Whether this function is a thunk.
    thunk: bool,
    /// Whether this symbol is pinned.
    pinned: bool,
    /// Whether this symbol has been deleted.
    deleted: bool,
}

impl FunctionSymbol {
    /// Creates a new function symbol.
    pub fn new(id: u64, name: impl Into<String>, address: Address) -> Self {
        Self {
            id,
            name: name.into(),
            address,
            namespace_id: 0,
            source: SourceType::UserDefined,
            primary: true,
            default: false,
            thunk: false,
            pinned: false,
            deleted: false,
        }
    }

    /// Creates a default function symbol (e.g., FUN_00401000).
    pub fn default_symbol(id: u64, address: Address) -> Self {
        let name = format!("FUN_{:08X}", address.offset);
        Self {
            id,
            name,
            address,
            namespace_id: 0,
            source: SourceType::Default,
            primary: true,
            default: true,
            thunk: false,
            pinned: false,
            deleted: false,
        }
    }

    /// Creates a thunk function symbol.
    pub fn thunk(id: u64, name: impl Into<String>, address: Address) -> Self {
        Self {
            id,
            name: name.into(),
            address,
            namespace_id: 0,
            source: SourceType::Default,
            primary: false,
            default: false,
            thunk: true,
            pinned: false,
            deleted: false,
        }
    }

    /// Returns `true` if this function has the default name.
    pub fn is_default(&self) -> bool {
        self.default
    }

    /// Returns `true` if this function is a thunk.
    pub fn is_thunk(&self) -> bool {
        self.thunk
    }
}

impl SymbolApi for FunctionSymbol {
    fn get_address(&self) -> &Address {
        &self.address
    }

    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_path(&self) -> Vec<String> {
        vec![self.name.clone()]
    }

    fn get_name_qualified(&self, include_namespace: bool) -> String {
        if include_namespace {
            format!("Global::{}", self.name)
        } else {
            self.name.clone()
        }
    }

    fn get_parent_namespace(&self) -> Option<&dyn Namespace> {
        None
    }

    fn get_parent_symbol(&self) -> Option<&dyn SymbolApi> {
        None
    }

    fn is_descendant(&self, namespace: &dyn Namespace) -> bool {
        self.namespace_id == namespace.get_id()
    }

    fn is_valid_parent(&self, parent: &dyn Namespace) -> bool {
        let is_external = self.address.is_external_address();
        if is_external != parent.is_external() {
            return false;
        }
        if parent.get_id() != 0 {
            // A function cannot be inside another function.
            let mut p = Some(parent);
            while let Some(current) = p {
                if current.get_id() == 0 {
                    break;
                }
                if current.get_type() == SymbolType::Function {
                    return false;
                }
                p = current.get_parent_namespace();
            }
        }
        true
    }

    fn get_symbol_type(&self) -> SymbolType {
        SymbolType::Function
    }

    fn get_id(&self) -> u64 {
        self.id
    }

    fn is_global(&self) -> bool {
        self.namespace_id == 0
    }

    fn is_external(&self) -> bool {
        self.address.is_external_address()
    }

    fn is_primary(&self) -> bool {
        self.primary
    }

    fn set_primary(&mut self) -> bool {
        if self.primary {
            false
        } else {
            self.primary = true;
            true
        }
    }

    fn is_pinned(&self) -> bool {
        self.pinned
    }

    fn set_pinned(&mut self, pinned: bool) -> SymbolResult<()> {
        self.pinned = pinned;
        Ok(())
    }

    fn is_dynamic(&self) -> bool {
        false
    }

    fn get_source(&self) -> SourceType {
        self.source
    }

    fn set_source(&mut self, source: SourceType) {
        self.source = source;
        if source != SourceType::Default {
            self.default = false;
        }
    }

    fn is_deleted(&self) -> bool {
        self.deleted
    }

    fn set_name(&mut self, new_name: &str, source: SourceType) -> SymbolResult<()> {
        validate_symbol_name(new_name)?;
        self.name = new_name.to_string();
        self.set_source(source);
        self.default = false;
        Ok(())
    }

    fn set_namespace(&mut self, new_namespace: &dyn Namespace) -> SymbolResult<()> {
        if !self.is_valid_parent(new_namespace) {
            return Err(SymbolError::InvalidInput(format!(
                "invalid parent namespace for function symbol"
            )));
        }
        self.namespace_id = new_namespace.get_id();
        Ok(())
    }

    fn set_name_and_namespace(
        &mut self,
        new_name: &str,
        new_namespace: &dyn Namespace,
        source: SourceType,
    ) -> SymbolResult<()> {
        self.set_name(new_name, source)?;
        self.set_namespace(new_namespace)?;
        Ok(())
    }

    fn delete(&mut self) -> bool {
        if self.deleted {
            return false;
        }
        // Default function symbols cannot be deleted; they revert to the default name.
        if self.default {
            return false;
        }
        self.deleted = true;
        true
    }
}

// ---------------------------------------------------------------------------
// Reference
// ---------------------------------------------------------------------------

/// A reference from one address to another.
///
/// Corresponds to Ghidra's `Reference` interface. A reference has a source
/// address ("from"), a destination address ("to"), a reference type, and
/// an operand index identifying where in the instruction the reference is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reference {
    /// The address of the code unit making the reference.
    from_address: Address,
    /// The address being referenced.
    to_address: Address,
    /// The type of reference.
    ref_type: RefType,
    /// The operand index. `MNEMONIC` (-1) means the mnemonic, other values are
    /// operand indices.
    op_index: i32,
    /// The ID of the symbol this reference is associated with, or -1 if none.
    symbol_id: i64,
    /// Whether this is the primary reference at this operand.
    primary: bool,
    /// The source of this reference.
    source: SourceType,
    /// Whether this reference has been deleted.
    deleted: bool,
}

/// Operand index for the instruction/data mnemonic.
pub const MNEMONIC: i32 = -1;

/// Special operand index used when not applicable (e.g., thunk references).
pub const OTHER_OP_INDEX: i32 = -2;

impl Reference {
    /// Creates a new memory reference.
    pub fn new(from_address: Address, to_address: Address, ref_type: RefType, op_index: i32) -> Self {
        Self {
            from_address,
            to_address,
            ref_type,
            op_index,
            symbol_id: -1,
            primary: false,
            source: SourceType::Default,
            deleted: false,
        }
    }

    /// Creates a new reference with full options.
    pub fn with_options(
        from_address: Address,
        to_address: Address,
        ref_type: RefType,
        op_index: i32,
        source: SourceType,
        primary: bool,
    ) -> Self {
        Self {
            from_address,
            to_address,
            ref_type,
            op_index,
            symbol_id: -1,
            primary,
            source,
            deleted: false,
        }
    }

    /// Creates a mnemonic reference.
    pub fn mnemonic(from_address: Address, to_address: Address, ref_type: RefType) -> Self {
        Self::new(from_address, to_address, ref_type, MNEMONIC)
    }

    /// Returns the "from" address.
    pub fn get_from_address(&self) -> &Address {
        &self.from_address
    }

    /// Returns the "to" address.
    pub fn get_to_address(&self) -> &Address {
        &self.to_address
    }

    /// Returns the reference type.
    pub fn get_reference_type(&self) -> RefType {
        self.ref_type
    }

    /// Sets the reference type.
    pub fn set_reference_type(&mut self, ref_type: RefType) {
        self.ref_type = ref_type;
    }

    /// Returns the operand index.
    pub fn get_operand_index(&self) -> i32 {
        self.op_index
    }

    /// Returns `true` if this is a mnemonic reference.
    pub fn is_mnemonic_reference(&self) -> bool {
        self.op_index == MNEMONIC
    }

    /// Returns `true` if this is an operand reference.
    pub fn is_operand_reference(&self) -> bool {
        self.op_index != MNEMONIC && self.op_index != OTHER_OP_INDEX
    }

    /// Returns `true` if this is the primary reference.
    pub fn is_primary(&self) -> bool {
        self.primary
    }

    /// Sets whether this is the primary reference.
    pub fn set_primary(&mut self, primary: bool) {
        self.primary = primary;
    }

    /// Returns the associated symbol ID, or -1 if none.
    pub fn get_symbol_id(&self) -> i64 {
        self.symbol_id
    }

    /// Sets the associated symbol ID.
    pub fn set_symbol_id(&mut self, symbol_id: i64) {
        self.symbol_id = symbol_id;
    }

    /// Returns the source type.
    pub fn get_source(&self) -> SourceType {
        self.source
    }

    /// Sets the source type.
    pub fn set_source(&mut self, source: SourceType) {
        self.source = source;
    }

    /// Returns `true` if this reference is to a memory address.
    pub fn is_memory_reference(&self) -> bool {
        self.to_address.is_memory_address()
            || self.to_address.is_external_address()
            || self.is_offset_reference()
            || self.is_shifted_reference()
    }

    /// Returns `true` if this reference is to a register.
    pub fn is_register_reference(&self) -> bool {
        self.to_address.is_register_address()
    }

    /// Returns `true` if this reference is to a stack location.
    pub fn is_stack_reference(&self) -> bool {
        self.to_address.is_stack_address()
    }

    /// Returns `true` if this is an external reference.
    pub fn is_external_reference(&self) -> bool {
        self.to_address.is_external_address()
    }

    /// Returns `true` if this is an entry point reference.
    pub fn is_entry_point_reference(&self) -> bool {
        false
    }

    /// Returns `true` if this is an offset reference.
    pub fn is_offset_reference(&self) -> bool {
        false
    }

    /// Returns `true` if this is a shifted reference.
    pub fn is_shifted_reference(&self) -> bool {
        false
    }

    /// Marks this reference as deleted.
    pub fn delete(&mut self) {
        self.deleted = true;
    }

    /// Returns `true` if this reference has been deleted.
    pub fn is_deleted(&self) -> bool {
        self.deleted
    }
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} -> {} ({})",
            self.from_address, self.to_address, self.ref_type
        )
    }
}

impl std::cmp::Ord for Reference {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.from_address
            .cmp(&other.from_address)
            .then_with(|| self.op_index.cmp(&other.op_index))
            .then_with(|| self.to_address.cmp(&other.to_address))
    }
}

impl std::cmp::PartialOrd for Reference {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// ---------------------------------------------------------------------------
// ReferenceIterator - a simple wrapper for iterating over references
// ---------------------------------------------------------------------------

/// An iterator over references. Corresponds to Ghidra's `ReferenceIterator`
/// interface.
pub struct ReferenceIterator {
    references: Vec<Reference>,
    index: usize,
}

impl ReferenceIterator {
    /// Creates a new reference iterator from a vector of references.
    pub fn new(references: Vec<Reference>) -> Self {
        Self {
            references,
            index: 0,
        }
    }

    /// Returns `true` if there are more references.
    pub fn has_next(&self) -> bool {
        self.index < self.references.len()
    }

    /// Returns the next reference, if any.
    pub fn next(&mut self) -> Option<&Reference> {
        if self.index < self.references.len() {
            let r = &self.references[self.index];
            self.index += 1;
            Some(r)
        } else {
            None
        }
    }

    /// Returns the total number of references.
    pub fn len(&self) -> usize {
        self.references.len()
    }

    /// Returns `true` if there are no references.
    pub fn is_empty(&self) -> bool {
        self.references.is_empty()
    }

    /// Reset the iterator to the beginning.
    pub fn reset(&mut self) {
        self.index = 0;
    }
}

impl Iterator for ReferenceIterator {
    type Item = Reference;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.references.len() {
            let r = self.references[self.index].clone();
            self.index += 1;
            Some(r)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// ReferenceManager
// ---------------------------------------------------------------------------

/// Manages references in a program. Corresponds to Ghidra's `ReferenceManager`
/// interface.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReferenceManager {
    /// All references managed by this manager.
    references: Vec<Reference>,
    /// Set of addresses that are external entry points.
    external_entry_points: HashSet<Address>,
    /// Next available reference ID (for internal tracking).
    next_id: u64,
}

impl ReferenceManager {
    /// Creates a new empty reference manager.
    pub fn new() -> Self {
        Self {
            references: Vec::new(),
            external_entry_points: HashSet::new(),
            next_id: 0,
        }
    }

    /// Adds a reference to the manager.
    pub fn add_reference(&mut self, reference: Reference) -> SymbolResult<&Reference> {
        self.references.push(reference);
        Ok(self.references.last().unwrap())
    }

    /// Adds a memory reference.
    pub fn add_memory_reference(
        &mut self,
        from_addr: Address,
        to_addr: Address,
        ref_type: RefType,
        source: SourceType,
        op_index: i32,
    ) -> SymbolResult<&Reference> {
        // Replace any existing references at the same from+op_index
        self.remove_references_at(from_addr, op_index);
        let r = Reference::with_options(from_addr, to_addr, ref_type, op_index, source, true);
        self.add_reference(r)
    }

    /// Adds a stack reference.
    pub fn add_stack_reference(
        &mut self,
        from_addr: Address,
        op_index: i32,
        _stack_offset: i32,
        ref_type: RefType,
        source: SourceType,
    ) -> SymbolResult<&Reference> {
        self.remove_references_at(from_addr, op_index);
        // Stack references use a special stack address.
        let to_addr = Address::new(0); // placeholder; real impl would use stack offset
        let r = Reference::with_options(from_addr, to_addr, ref_type, op_index, source, true);
        self.add_reference(r)
    }

    /// Adds a register reference.
    pub fn add_register_reference(
        &mut self,
        from_addr: Address,
        op_index: i32,
        _register_addr: Address,
        ref_type: RefType,
        source: SourceType,
    ) -> SymbolResult<&Reference> {
        self.remove_references_at(from_addr, op_index);
        let r = Reference::with_options(from_addr, _register_addr, ref_type, op_index, source, true);
        self.add_reference(r)
    }

    /// Adds an external reference.
    pub fn add_external_reference(
        &mut self,
        from_addr: Address,
        ext_label: &str,
        ext_addr: Option<Address>,
        source: SourceType,
        op_index: i32,
        ref_type: RefType,
    ) -> SymbolResult<&Reference> {
        self.remove_references_at(from_addr, op_index);
        let to_addr = ext_addr.unwrap_or_else(|| {
            // External address: use a special encoding.
            Address::new(0) // placeholder; real impl uses external space addressing
        });
        let r = Reference::with_options(from_addr, to_addr, ref_type, op_index, source, true);
        self.add_reference(r)
    }

    /// Adds an offset memory reference.
    pub fn add_offset_mem_reference(
        &mut self,
        from_addr: Address,
        to_addr: Address,
        _to_addr_is_base: bool,
        _offset: i64,
        ref_type: RefType,
        source: SourceType,
        op_index: i32,
    ) -> SymbolResult<&Reference> {
        self.remove_references_at(from_addr, op_index);
        let r = Reference::with_options(from_addr, to_addr, ref_type, op_index, source, true);
        self.add_reference(r)
    }

    /// Adds a shifted memory reference.
    pub fn add_shifted_mem_reference(
        &mut self,
        from_addr: Address,
        to_addr: Address,
        _shift_value: i32,
        ref_type: RefType,
        source: SourceType,
        op_index: i32,
    ) -> SymbolResult<&Reference> {
        self.remove_references_at(from_addr, op_index);
        let r = Reference::with_options(from_addr, to_addr, ref_type, op_index, source, true);
        self.add_reference(r)
    }

    /// Removes all references from the given address range.
    pub fn remove_all_references_from_range(
        &mut self,
        begin_addr: Address,
        end_addr: Address,
    ) {
        self.references.retain(|r| {
            r.from_address < begin_addr || r.from_address > end_addr
        });
    }

    /// Removes all references from the given address.
    pub fn remove_all_references_from(&mut self, from_addr: Address) {
        self.references.retain(|r| r.from_address != from_addr);
    }

    /// Removes all references to the given address.
    pub fn remove_all_references_to(&mut self, to_addr: Address) {
        self.references.retain(|r| r.to_address != to_addr);
    }

    /// Removes references at a specific from address and operand index.
    fn remove_references_at(&mut self, from_addr: Address, op_index: i32) {
        self.references
            .retain(|r| !(r.from_address == from_addr && r.op_index == op_index));
    }

    /// Sets the primary flag on a reference.
    pub fn set_primary(&mut self, ref_to_set: &Reference, is_primary: bool) {
        if let Some(r) = self
            .references
            .iter_mut()
            .find(|r| r.from_address == ref_to_set.from_address
                && r.to_address == ref_to_set.to_address
                && r.op_index == ref_to_set.op_index)
        {
            r.primary = is_primary;
        }
    }

    /// Returns all references from the given address.
    pub fn get_references_from(&self, from_addr: Address) -> Vec<&Reference> {
        self.references
            .iter()
            .filter(|r| r.from_address == from_addr)
            .collect()
    }

    /// Returns all references from the given address and operand index.
    pub fn get_references_from_op(
        &self,
        from_addr: Address,
        op_index: i32,
    ) -> Vec<&Reference> {
        self.references
            .iter()
            .filter(|r| r.from_address == from_addr && r.op_index == op_index)
            .collect()
    }

    /// Returns all references to the given address.
    pub fn get_references_to(&self, to_addr: Address) -> ReferenceIterator {
        let refs: Vec<Reference> = self
            .references
            .iter()
            .filter(|r| r.to_address == to_addr)
            .cloned()
            .collect();
        ReferenceIterator::new(refs)
    }

    /// Returns the number of references to the given address.
    pub fn get_reference_count_to(&self, to_addr: Address) -> usize {
        self.references
            .iter()
            .filter(|r| r.to_address == to_addr)
            .count()
    }

    /// Returns the number of references from the given address.
    pub fn get_reference_count_from(&self, from_addr: Address) -> usize {
        self.references
            .iter()
            .filter(|r| r.from_address == from_addr)
            .count()
    }

    /// Returns the total number of "from" addresses that have references.
    pub fn get_reference_source_count(&self) -> usize {
        let unique_from: HashSet<Address> =
            self.references.iter().map(|r| r.from_address).collect();
        unique_from.len()
    }

    /// Returns the total number of "to" addresses that are referenced.
    pub fn get_reference_destination_count(&self) -> usize {
        let unique_to: HashSet<Address> =
            self.references.iter().map(|r| r.to_address).collect();
        unique_to.len()
    }

    /// Returns `true` if there are references from the given address.
    pub fn has_references_from(&self, from_addr: Address) -> bool {
        self.references
            .iter()
            .any(|r| r.from_address == from_addr)
    }

    /// Returns `true` if there are references from the given address and operand.
    pub fn has_references_from_op(&self, from_addr: Address, op_index: i32) -> bool {
        self.references
            .iter()
            .any(|r| r.from_address == from_addr && r.op_index == op_index)
    }

    /// Returns `true` if there are references to the given address.
    pub fn has_references_to(&self, to_addr: Address) -> bool {
        self.references.iter().any(|r| r.to_address == to_addr)
    }

    /// Returns `true` if the given address has flow references from it.
    pub fn has_flow_references_from(&self, addr: Address) -> bool {
        self.references
            .iter()
            .any(|r| r.from_address == addr && r.ref_type.is_flow())
    }

    /// Returns all flow references from the given address.
    pub fn get_flow_references_from(&self, addr: Address) -> Vec<&Reference> {
        self.references
            .iter()
            .filter(|r| r.from_address == addr && r.ref_type.is_flow())
            .collect()
    }

    /// Returns the primary reference from the given address and operand.
    pub fn get_primary_reference_from(
        &self,
        addr: Address,
        op_index: i32,
    ) -> Option<&Reference> {
        self.references
            .iter()
            .find(|r| r.from_address == addr && r.op_index == op_index && r.primary)
    }

    /// Returns a reference matching the exact from, to, and operand.
    pub fn get_reference(
        &self,
        from_addr: Address,
        to_addr: Address,
        op_index: i32,
    ) -> Option<&Reference> {
        self.references.iter().find(|r| {
            r.from_address == from_addr
                && r.to_address == to_addr
                && r.op_index == op_index
        })
    }

    /// Returns an iterator over all external space references.
    pub fn get_external_references(&self) -> ReferenceIterator {
        let refs: Vec<Reference> = self
            .references
            .iter()
            .filter(|r| r.to_address.is_external_address())
            .cloned()
            .collect();
        ReferenceIterator::new(refs)
    }

    /// Returns an iterator over references starting from the given address.
    pub fn get_reference_iterator(&self, start_addr: Address) -> ReferenceIterator {
        let mut refs: Vec<Reference> = self
            .references
            .iter()
            .filter(|r| r.from_address >= start_addr)
            .cloned()
            .collect();
        refs.sort_by_key(|r| r.from_address);
        ReferenceIterator::new(refs)
    }

    /// Returns an iterator over "from" addresses.
    pub fn get_reference_source_iterator(
        &self,
        start_addr: Address,
        forward: bool,
    ) -> Vec<Address> {
        let mut from_addrs: Vec<Address> = self
            .references
            .iter()
            .map(|r| r.from_address)
            .filter(|a| if forward { *a >= start_addr } else { *a <= start_addr })
            .collect();
        from_addrs.sort();
        from_addrs.dedup();
        if !forward {
            from_addrs.reverse();
        }
        from_addrs
    }

    /// Returns an iterator over "to" addresses.
    pub fn get_reference_destination_iterator(
        &self,
        start_addr: Address,
        forward: bool,
    ) -> Vec<Address> {
        let mut to_addrs: Vec<Address> = self
            .references
            .iter()
            .map(|r| r.to_address)
            .filter(|a| if forward { *a >= start_addr } else { *a <= start_addr })
            .collect();
        to_addrs.sort();
        to_addrs.dedup();
        if !forward {
            to_addrs.reverse();
        }
        to_addrs
    }

    /// Updates the reference type on a reference.
    pub fn update_ref_type(&mut self, existing_ref: &Reference, new_type: RefType) -> Option<&Reference> {
        if let Some(r) = self.references.iter_mut().find(|r| {
            r.from_address == existing_ref.from_address
                && r.to_address == existing_ref.to_address
                && r.op_index == existing_ref.op_index
        }) {
            r.ref_type = new_type;
            Some(r)
        } else {
            None
        }
    }

    /// Associates a reference with a symbol.
    pub fn set_association(&mut self, symbol_id: u64, ref_to_assoc: &Reference) -> SymbolResult<()> {
        if let Some(r) = self.references.iter_mut().find(|r| {
            r.from_address == ref_to_assoc.from_address
                && r.to_address == ref_to_assoc.to_address
                && r.op_index == ref_to_assoc.op_index
        }) {
            r.symbol_id = symbol_id as i64;
            Ok(())
        } else {
            Err(SymbolError::ReferenceNotFound)
        }
    }

    /// Removes any symbol association from a reference.
    pub fn remove_association(&mut self, ref_to_clear: &Reference) -> SymbolResult<()> {
        if let Some(r) = self.references.iter_mut().find(|r| {
            r.from_address == ref_to_clear.from_address
                && r.to_address == ref_to_clear.to_address
                && r.op_index == ref_to_clear.op_index
        }) {
            r.symbol_id = -1;
            Ok(())
        } else {
            Err(SymbolError::ReferenceNotFound)
        }
    }

    /// Deletes a reference.
    pub fn delete(&mut self, ref_to_delete: &Reference) -> SymbolResult<()> {
        let len_before = self.references.len();
        self.references.retain(|r| {
            !(r.from_address == ref_to_delete.from_address
                && r.to_address == ref_to_delete.to_address
                && r.op_index == ref_to_delete.op_index)
        });
        if self.references.len() < len_before {
            Ok(())
        } else {
            Err(SymbolError::ReferenceNotFound)
        }
    }

    /// Returns the reference level for references to the given address.
    pub fn get_reference_level(&self, _to_addr: Address) -> u8 {
        // Placeholder: returns highest reference level for the address.
        0
    }

    // -- External entry point management --

    /// Adds an address as an external entry point.
    pub fn add_external_entry_point(&mut self, addr: Address) {
        self.external_entry_points.insert(addr);
    }

    /// Removes an address from the external entry points.
    pub fn remove_external_entry_point(&mut self, addr: Address) {
        self.external_entry_points.remove(&addr);
    }

    /// Returns `true` if the given address is an external entry point.
    pub fn is_external_entry_point(&self, addr: Address) -> bool {
        self.external_entry_points.contains(&addr)
    }

    /// Returns the external entry points.
    pub fn get_external_entry_points(&self) -> &HashSet<Address> {
        &self.external_entry_points
    }
}

// ---------------------------------------------------------------------------
// SymbolTable trait
// ---------------------------------------------------------------------------

/// The SymbolTable trait, corresponding to Ghidra's `SymbolTable` interface.
///
/// Manages the symbols defined in a program: creation, lookup, iteration,
/// and namespacing.
pub trait SymbolTable: fmt::Debug + Send + Sync {
    /// Creates a label symbol with the given name in the global namespace.
    fn create_label(
        &mut self,
        addr: Address,
        name: &str,
        source: SourceType,
    ) -> SymbolResult<&dyn SymbolApi>;

    /// Creates a label symbol with the given name and namespace.
    fn create_label_in_namespace(
        &mut self,
        addr: Address,
        name: &str,
        namespace: &dyn Namespace,
        source: SourceType,
    ) -> SymbolResult<&dyn SymbolApi>;

    /// Removes a symbol with special behavior for function symbols.
    fn remove_symbol_special(&mut self, sym: &dyn SymbolApi) -> bool;

    /// Returns the symbol for the given ID.
    fn get_symbol(&self, symbol_id: u64) -> Option<&dyn SymbolApi>;

    /// Returns a symbol matching the given name, address, and namespace.
    fn get_symbol_by_name_addr_namespace(
        &self,
        name: &str,
        addr: Address,
        namespace: &dyn Namespace,
    ) -> Option<&dyn SymbolApi>;

    /// Returns the global symbol with the given name and address.
    fn get_global_symbol(&self, name: &str, addr: Address) -> Option<&dyn SymbolApi>;

    /// Returns all global symbols with the given name.
    fn get_global_symbols(&self, name: &str) -> Vec<&dyn SymbolApi>;

    /// Returns all label or function symbols with the given name in the given namespace.
    fn get_label_or_function_symbols(
        &self,
        name: &str,
        namespace: &dyn Namespace,
    ) -> Vec<&dyn SymbolApi>;

    /// Returns a namespace symbol with the given name in the given namespace.
    fn get_namespace_symbol(
        &self,
        name: &str,
        namespace: &dyn Namespace,
    ) -> Option<&dyn SymbolApi>;

    /// Returns the library symbol with the given name.
    fn get_library_symbol(&self, name: &str) -> Option<&dyn SymbolApi>;

    /// Returns the class symbol with the given name in the given namespace.
    fn get_class_symbol(
        &self,
        name: &str,
        namespace: &dyn Namespace,
    ) -> Option<&dyn SymbolApi>;

    /// Returns all symbols with the given name in the given namespace.
    fn get_symbols_by_name_and_namespace(
        &self,
        name: &str,
        namespace: &dyn Namespace,
    ) -> Vec<&dyn SymbolApi>;

    /// Returns all symbols with the given name.
    fn get_symbols_by_name(&self, name: &str) -> Vec<&dyn SymbolApi>;

    /// Returns all symbols, optionally including dynamic ones.
    fn get_all_symbols(&self, include_dynamic: bool) -> Vec<&dyn SymbolApi>;

    /// Returns the primary symbol at the given address.
    fn get_primary_symbol(&self, addr: Address) -> Option<&dyn SymbolApi>;

    /// Returns all symbols at the given address.
    fn get_symbols_at(&self, addr: Address) -> Vec<&dyn SymbolApi>;

    /// Returns all user-defined (non-dynamic) symbols at the given address.
    fn get_user_symbols(&self, addr: Address) -> Vec<&dyn SymbolApi>;

    /// Returns `true` if any symbol exists at the given address.
    fn has_symbol(&self, addr: Address) -> bool;

    /// Returns the namespace with the given name in the given parent.
    fn get_namespace(
        &self,
        name: &str,
        namespace: &dyn Namespace,
    ) -> Option<&dyn Namespace>;

    /// Returns the deepest namespace containing the given address.
    fn get_namespace_for_address(&self, addr: Address) -> Option<&dyn Namespace>;

    /// Returns the total number of symbols.
    fn get_num_symbols(&self) -> usize;

    /// Returns label history for the given address.
    fn get_label_history(&self, addr: Address) -> Vec<LabelHistory>;

    /// Returns `true` if there is label history for the given address.
    fn has_label_history(&self, addr: Address) -> bool;

    /// Adds an address to the external entry points.
    fn add_external_entry_point(&mut self, addr: Address);

    /// Removes an address from the external entry points.
    fn remove_external_entry_point(&mut self, addr: Address);

    /// Returns `true` if the address is an external entry point.
    fn is_external_entry_point(&self, addr: Address) -> bool;

    /// Creates a class namespace.
    fn create_class(
        &mut self,
        parent: &dyn Namespace,
        name: &str,
        source: SourceType,
    ) -> SymbolResult<Box<dyn Namespace>>;

    /// Creates a library namespace.
    fn create_external_library(
        &mut self,
        name: &str,
        source: SourceType,
    ) -> SymbolResult<Box<dyn Namespace>>;

    /// Creates a generic namespace.
    fn create_namespace(
        &mut self,
        parent: &dyn Namespace,
        name: &str,
        source: SourceType,
    ) -> SymbolResult<Box<dyn Namespace>>;
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Validates a symbol name. Returns an error if the name is empty, contains
/// whitespace, or is otherwise invalid.
pub fn validate_symbol_name(name: &str) -> SymbolResult<()> {
    if name.is_empty() {
        return Err(SymbolError::InvalidInput(
            "symbol name must not be empty".to_string(),
        ));
    }
    if name.contains(char::is_whitespace) {
        return Err(SymbolError::InvalidInput(format!(
            "symbol name '{}' contains whitespace",
            name
        )));
    }
    if name.contains("::") {
        return Err(SymbolError::InvalidInput(format!(
            "symbol name '{}' contains namespace delimiter",
            name
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SymbolPath - kept for backward compatibility
// ---------------------------------------------------------------------------

/// A path through the symbol tree (hierarchical namespace).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SymbolPath {
    /// Path segments from root to leaf.
    pub segments: Vec<String>,
}

impl SymbolPath {
    pub fn root() -> Self {
        Self {
            segments: vec!["Global".to_string()],
        }
    }

    pub fn from_segments(segments: Vec<String>) -> Self {
        Self { segments }
    }

    pub fn parent(&self) -> Option<SymbolPath> {
        if self.segments.len() <= 1 {
            None
        } else {
            Some(SymbolPath {
                segments: self.segments[..self.segments.len() - 1].to_vec(),
            })
        }
    }

    pub fn display_name(&self) -> String {
        self.segments.join("::")
    }

    pub fn is_root(&self) -> bool {
        self.segments.len() == 1
    }
}

impl fmt::Display for SymbolPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ---------------------------------------------------------------------------
// SymbolTreeNode - kept for backward compatibility
// ---------------------------------------------------------------------------

/// A node in the symbol tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolTreeNode {
    /// Display name of this node.
    pub name: String,
    /// Full path to this node.
    pub path: SymbolPath,
    /// The symbol data, if this is a leaf node.
    pub symbol: Option<Symbol>,
    /// Child nodes (sub-namespaces or sibling symbols).
    pub children: Vec<SymbolTreeNode>,
}

impl SymbolTreeNode {
    pub fn new(name: impl Into<String>, path: SymbolPath) -> Self {
        Self {
            name: name.into(),
            path,
            symbol: None,
            children: Vec::new(),
        }
    }

    pub fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }

    pub fn root() -> Self {
        Self::new("Global", SymbolPath::root())
    }

    pub fn add_child(&mut self, child: SymbolTreeNode) {
        self.children.push(child);
    }

    pub fn category(
        name: impl Into<String>,
        path: SymbolPath,
        children: Vec<SymbolTreeNode>,
    ) -> Self {
        Self {
            name: name.into(),
            path,
            symbol: None,
            children,
        }
    }

    pub fn leaf(
        name: impl Into<String>,
        path: SymbolPath,
        symbol: Symbol,
    ) -> Self {
        Self {
            name: name.into(),
            path,
            symbol: Some(symbol),
            children: Vec::new(),
        }
    }
}

impl Default for SymbolTreeNode {
    fn default() -> Self {
        Self::root()
    }
}

// ---------------------------------------------------------------------------
// Concrete Symbol wrapper enum - for storing symbols in collections
// ---------------------------------------------------------------------------

/// A concrete wrapper enum over the various symbol implementations.
///
/// This allows storing heterogeneous symbol types in collections while
/// still using the [`Symbol`] trait for dispatch. It replaces the old flat
/// `Symbol` struct and serves as the primary concrete symbol type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Symbol {
    /// A label symbol.
    Label(LabelSymbol),
    /// A function symbol.
    Function(FunctionSymbol),
    /// The global root symbol.
    Global(GlobalSymbol),
}

impl Symbol {
    /// Create a new symbol of the given kind (backward compatibility).
    pub fn new(name: impl Into<String>, address: Address, kind: SymbolType) -> Self {
        match kind {
            SymbolType::Function => {
                let mut fs = FunctionSymbol::new(0, name, address);
                fs.primary = true;
                Symbol::Function(fs)
            }
            _ => {
                let mut ls =
                    LabelSymbol::with_options(0, name, address, 0, SourceType::UserDefined);
                ls.primary = true;
                Symbol::Label(ls)
            }
        }
    }

    /// Create a function symbol (backward-compatible).
    pub fn function(name: impl Into<String>, address: Address) -> Self {
        let mut fs = FunctionSymbol::new(0, name, address);
        fs.primary = true;
        Symbol::Function(fs)
    }

    /// Create a label symbol (backward-compatible).
    pub fn label(name: impl Into<String>, address: Address) -> Self {
        let mut ls =
            LabelSymbol::with_options(0, name, address, 0, SourceType::UserDefined);
        ls.primary = true;
        Symbol::Label(ls)
    }

    /// Create an import symbol (backward-compatible).
    pub fn import(name: impl Into<String>, address: Address) -> Self {
        let mut ls =
            LabelSymbol::with_options(0, name, address, 0, SourceType::Imported);
        ls.primary = false;
        Symbol::Label(ls)
    }

    /// Returns the symbol name. Delegates to the inner type's `SymbolApi::get_name`.
    pub fn name(&self) -> String {
        <Self as SymbolApi>::get_name(self)
    }

    /// Returns the symbol address.
    pub fn address(&self) -> &Address {
        <Self as SymbolApi>::get_address(self)
    }

    /// Returns the symbol type.
    pub fn kind(&self) -> SymbolType {
        <Self as SymbolApi>::get_symbol_type(self)
    }

    /// Returns the symbol source.
    pub fn source(&self) -> SourceType {
        <Self as SymbolApi>::get_source(self)
    }

    /// Returns `true` if this is the primary symbol at its address.
    pub fn is_primary(&self) -> bool {
        <Self as SymbolApi>::is_primary(self)
    }
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", <Self as SymbolApi>::get_name(self))
    }
}

impl SymbolApi for Symbol {
    fn get_address(&self) -> &Address {
        match self {
            Symbol::Label(s) => SymbolApi::get_address(s),
            Symbol::Function(s) => SymbolApi::get_address(s),
            Symbol::Global(s) => SymbolApi::get_address(s),
        }
    }
    fn get_name(&self) -> String {
        match self {
            Symbol::Label(s) => SymbolApi::get_name(s),
            Symbol::Function(s) => SymbolApi::get_name(s),
            Symbol::Global(s) => SymbolApi::get_name(s),
        }
    }
    fn get_path(&self) -> Vec<String> {
        match self {
            Symbol::Label(s) => SymbolApi::get_path(s),
            Symbol::Function(s) => SymbolApi::get_path(s),
            Symbol::Global(s) => SymbolApi::get_path(s),
        }
    }
    fn get_name_qualified(&self, include_namespace: bool) -> String {
        match self {
            Symbol::Label(s) => SymbolApi::get_name_qualified(s, include_namespace),
            Symbol::Function(s) => SymbolApi::get_name_qualified(s, include_namespace),
            Symbol::Global(s) => SymbolApi::get_name_qualified(s, include_namespace),
        }
    }
    fn get_parent_namespace(&self) -> Option<&dyn Namespace> {
        None
    }
    fn get_parent_symbol(&self) -> Option<&dyn SymbolApi> {
        None
    }
    fn is_descendant(&self, namespace: &dyn Namespace) -> bool {
        match self {
            Symbol::Label(s) => SymbolApi::is_descendant(s, namespace),
            Symbol::Function(s) => SymbolApi::is_descendant(s, namespace),
            Symbol::Global(s) => SymbolApi::is_descendant(s, namespace),
        }
    }
    fn is_valid_parent(&self, parent: &dyn Namespace) -> bool {
        match self {
            Symbol::Label(s) => SymbolApi::is_valid_parent(s, parent),
            Symbol::Function(s) => SymbolApi::is_valid_parent(s, parent),
            Symbol::Global(s) => SymbolApi::is_valid_parent(s, parent),
        }
    }
    fn get_symbol_type(&self) -> SymbolType {
        match self {
            Symbol::Label(s) => SymbolApi::get_symbol_type(s),
            Symbol::Function(s) => SymbolApi::get_symbol_type(s),
            Symbol::Global(s) => SymbolApi::get_symbol_type(s),
        }
    }
    fn get_id(&self) -> u64 {
        match self {
            Symbol::Label(s) => SymbolApi::get_id(s),
            Symbol::Function(s) => SymbolApi::get_id(s),
            Symbol::Global(s) => SymbolApi::get_id(s),
        }
    }
    fn is_global(&self) -> bool {
        match self {
            Symbol::Label(s) => SymbolApi::is_global(s),
            Symbol::Function(s) => SymbolApi::is_global(s),
            Symbol::Global(s) => SymbolApi::is_global(s),
        }
    }
    fn is_external(&self) -> bool {
        match self {
            Symbol::Label(s) => SymbolApi::is_external(s),
            Symbol::Function(s) => SymbolApi::is_external(s),
            Symbol::Global(s) => SymbolApi::is_external(s),
        }
    }
    fn is_primary(&self) -> bool {
        match self {
            Symbol::Label(s) => SymbolApi::is_primary(s),
            Symbol::Function(s) => SymbolApi::is_primary(s),
            Symbol::Global(s) => SymbolApi::is_primary(s),
        }
    }
    fn set_primary(&mut self) -> bool {
        match self {
            Symbol::Label(s) => s.set_primary(),
            Symbol::Function(s) => s.set_primary(),
            Symbol::Global(_) => false,
        }
    }
    fn is_pinned(&self) -> bool {
        match self {
            Symbol::Label(s) => SymbolApi::is_pinned(s),
            Symbol::Function(s) => SymbolApi::is_pinned(s),
            Symbol::Global(s) => SymbolApi::is_pinned(s),
        }
    }
    fn set_pinned(&mut self, pinned: bool) -> SymbolResult<()> {
        match self {
            Symbol::Label(s) => s.set_pinned(pinned),
            Symbol::Function(s) => s.set_pinned(pinned),
            Symbol::Global(_) => Err(SymbolError::UnsupportedOperation(
                "Only Code and Function Symbols may be pinned.".to_string(),
            )),
        }
    }
    fn is_dynamic(&self) -> bool {
        match self {
            Symbol::Label(s) => SymbolApi::is_dynamic(s),
            Symbol::Function(s) => SymbolApi::is_dynamic(s),
            Symbol::Global(s) => SymbolApi::is_dynamic(s),
        }
    }
    fn get_source(&self) -> SourceType {
        match self {
            Symbol::Label(s) => SymbolApi::get_source(s),
            Symbol::Function(s) => SymbolApi::get_source(s),
            Symbol::Global(s) => SymbolApi::get_source(s),
        }
    }
    fn set_source(&mut self, source: SourceType) {
        match self {
            Symbol::Label(s) => s.set_source(source),
            Symbol::Function(s) => s.set_source(source),
            Symbol::Global(_) => {}
        }
    }
    fn is_deleted(&self) -> bool {
        match self {
            Symbol::Label(s) => SymbolApi::is_deleted(s),
            Symbol::Function(s) => SymbolApi::is_deleted(s),
            Symbol::Global(s) => SymbolApi::is_deleted(s),
        }
    }
    fn set_name(&mut self, new_name: &str, source: SourceType) -> SymbolResult<()> {
        match self {
            Symbol::Label(s) => s.set_name(new_name, source),
            Symbol::Function(s) => s.set_name(new_name, source),
            Symbol::Global(_) => Err(SymbolError::UnsupportedOperation(
                "Cannot rename global symbol".to_string(),
            )),
        }
    }
    fn set_namespace(&mut self, new_namespace: &dyn Namespace) -> SymbolResult<()> {
        match self {
            Symbol::Label(s) => s.set_namespace(new_namespace),
            Symbol::Function(s) => s.set_namespace(new_namespace),
            Symbol::Global(_) => Err(SymbolError::UnsupportedOperation(
                "Cannot move global symbol".to_string(),
            )),
        }
    }
    fn set_name_and_namespace(
        &mut self,
        new_name: &str,
        new_namespace: &dyn Namespace,
        source: SourceType,
    ) -> SymbolResult<()> {
        match self {
            Symbol::Label(s) => {
                s.set_name_and_namespace(new_name, new_namespace, source)
            }
            Symbol::Function(s) => {
                s.set_name_and_namespace(new_name, new_namespace, source)
            }
            Symbol::Global(_) => Err(SymbolError::UnsupportedOperation(
                "Cannot rename or move global symbol".to_string(),
            )),
        }
    }
    fn delete(&mut self) -> bool {
        match self {
            Symbol::Label(s) => s.delete(),
            Symbol::Function(s) => s.delete(),
            Symbol::Global(_) => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Backward-compatible aliases from the original simplified module
// ---------------------------------------------------------------------------

/// Kept for backward compatibility. Equivalent to `SourceType`.
#[deprecated(note = "use `SourceType` instead")]
pub type SymbolSource = SourceType;

/// Kept for backward compatibility. Equivalent to `SymbolType`.
#[deprecated(note = "use `SymbolType` instead")]
pub type SymbolKind = SymbolType;

/// Build a default symbol tree for testing/demo purposes.
pub fn demo_symbol_tree() -> SymbolTreeNode {
    let mut root = SymbolTreeNode::root();

    // Functions
    let mut functions = SymbolTreeNode::new(
        "Functions",
        SymbolPath::from_segments(vec!["Global".into(), "Functions".into()]),
    );
    functions.add_child(SymbolTreeNode::leaf(
        "main",
        SymbolPath::from_segments(vec![
            "Global".into(),
            "Functions".into(),
            "main".into(),
        ]),
        Symbol::Label(LabelSymbol::new(1, "main", Address::new(0x1000)))
    ));
    functions.add_child(SymbolTreeNode::leaf(
        "printf",
        SymbolPath::from_segments(vec![
            "Global".into(),
            "Functions".into(),
            "printf".into(),
        ]),
        Symbol::Label(LabelSymbol::new(2, "printf", Address::new(0x2000)))
    ));
    root.add_child(functions);

    // Labels
    let mut labels = SymbolTreeNode::new(
        "Labels",
        SymbolPath::from_segments(vec!["Global".into(), "Labels".into()]),
    );
    labels.add_child(SymbolTreeNode::leaf(
        "DAT_00101000",
        SymbolPath::from_segments(vec![
            "Global".into(),
            "Labels".into(),
            "DAT_00101000".into(),
        ]),
        Symbol::Label(LabelSymbol::new(3, "DAT_00101000", Address::new(0x1001000)))
    ));
    root.add_child(labels);

    // Imports
    let mut imports = SymbolTreeNode::new(
        "Imports",
        SymbolPath::from_segments(vec!["Global".into(), "Imports".into()]),
    );
    imports.add_child(SymbolTreeNode::leaf(
        "puts",
        SymbolPath::from_segments(vec![
            "Global".into(),
            "Imports".into(),
            "puts".into(),
        ]),
        Symbol::Label(LabelSymbol::new(4, "puts", Address::new(0x3000)))
    ));
    imports.add_child(SymbolTreeNode::leaf(
        "malloc",
        SymbolPath::from_segments(vec![
            "Global".into(),
            "Imports".into(),
            "malloc".into(),
        ]),
        Symbol::Label(LabelSymbol::new(5, "malloc", Address::new(0x3010)))
    ));
    root.add_child(imports);

    // Exports
    let mut exports = SymbolTreeNode::new(
        "Exports",
        SymbolPath::from_segments(vec!["Global".into(), "Exports".into()]),
    );
    exports.add_child(SymbolTreeNode::leaf(
        "global_counter",
        SymbolPath::from_segments(vec![
            "Global".into(),
            "Exports".into(),
            "global_counter".into(),
        ]),
        Symbol::Label(LabelSymbol::new(6, "global_counter", Address::new(0x2001000)))
    ));
    root.add_child(exports);

    root
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_type_ids() {
        assert_eq!(SymbolType::Label.get_id(), 0);
        assert_eq!(SymbolType::Library.get_id(), 1);
        assert_eq!(SymbolType::Function.get_id(), 5);
        assert_eq!(SymbolType::Global.get_id(), -1);
        assert_eq!(SymbolType::from_id(0), Some(SymbolType::Label));
        assert_eq!(SymbolType::from_id(-1), Some(SymbolType::Global));
        assert_eq!(SymbolType::from_id(99), None);
    }

    #[test]
    fn test_symbol_type_is_namespace() {
        assert!(SymbolType::Global.is_namespace());
        assert!(SymbolType::Namespace.is_namespace());
        assert!(SymbolType::Class.is_namespace());
        assert!(SymbolType::Library.is_namespace());
        assert!(SymbolType::Function.is_namespace());
        assert!(!SymbolType::Label.is_namespace());
        assert!(!SymbolType::Parameter.is_namespace());
        assert!(!SymbolType::LocalVar.is_namespace());
    }

    #[test]
    fn test_symbol_type_allows_duplicates() {
        assert!(SymbolType::Label.allows_duplicates());
        assert!(SymbolType::Function.allows_duplicates());
        assert!(!SymbolType::Namespace.allows_duplicates());
        assert!(!SymbolType::Class.allows_duplicates());
    }

    #[test]
    fn test_source_type_priority() {
        assert!(SourceType::UserDefined.is_higher_priority_than(SourceType::Default));
        assert!(SourceType::Imported.is_higher_priority_than(SourceType::Analysis));
        assert!(SourceType::Analysis.is_lower_priority_than(SourceType::Imported));
        assert!(SourceType::Default.is_lower_priority_than(SourceType::Analysis));

        // Analysis and AI are at same priority: none is higher than the other.
        assert!(!SourceType::Analysis.is_higher_priority_than(SourceType::AI));
        assert!(!SourceType::AI.is_higher_priority_than(SourceType::Analysis));
        assert!(SourceType::Analysis.is_higher_or_equal_priority_than(SourceType::AI));
        assert!(SourceType::AI.is_higher_or_equal_priority_than(SourceType::Analysis));
    }

    #[test]
    fn test_source_type_storage_id() {
        assert_eq!(SourceType::from_storage_id(0), Some(SourceType::Analysis));
        assert_eq!(SourceType::from_storage_id(1), Some(SourceType::UserDefined));
        assert_eq!(SourceType::from_storage_id(2), Some(SourceType::Default));
        assert_eq!(SourceType::from_storage_id(3), Some(SourceType::Imported));
        assert_eq!(SourceType::from_storage_id(4), Some(SourceType::AI));
        assert_eq!(SourceType::from_storage_id(99), None);
    }

    #[test]
    fn test_flow_type_properties() {
        assert!(FlowType::Invalid.has_fallthrough());
        assert!(!FlowType::Terminator.has_fallthrough());
        assert!(FlowType::UnconditionalJump.is_jump());
        assert!(FlowType::UnconditionalJump.is_unconditional());
        assert!(FlowType::ConditionalJump.is_conditional());
        assert!(FlowType::UnconditionalCall.is_call());
        assert!(FlowType::ComputedJump.is_computed());
        assert!(FlowType::Terminator.is_terminal());
        assert!(FlowType::JumpOverrideUnconditional.is_override());
    }

    #[test]
    fn test_data_ref_type_properties() {
        assert!(DataRefType::Data.is_data());
        assert!(DataRefType::Read.is_read());
        assert!(DataRefType::Write.is_write());
        assert!(!DataRefType::Read.is_write());
        assert!(DataRefType::ReadWrite.is_read());
        assert!(DataRefType::ReadWrite.is_write());
        assert!(DataRefType::ReadInd.is_indirect());
        assert!(!DataRefType::Read.is_indirect());
    }

    #[test]
    fn test_ref_type_display_string() {
        assert_eq!(RefType::DATA.display_string(), "Data");
        assert_eq!(RefType::READ.display_string(), "Read");
        assert_eq!(RefType::WRITE.display_string(), "Write");
        assert_eq!(RefType::READ_WRITE.display_string(), "RW");
    }

    #[test]
    fn test_label_symbol_basics() {
        let addr = Address::new(0x401000);
        let label = LabelSymbol::new(100, "my_label", addr);
        assert_eq!(label.get_name(), "my_label");
        assert_eq!(label.get_address(), &addr);
        assert_eq!(label.get_symbol_type(), SymbolType::Label);
        assert_eq!(label.get_id(), 100);
        assert!(!label.is_primary());
        assert!(!label.is_dynamic());
    }

    #[test]
    fn test_dynamic_label() {
        let addr = Address::new(0x401000);
        let label = LabelSymbol::dynamic(200, addr, 0);
        assert!(label.is_dynamic());
        assert_eq!(label.get_source(), SourceType::Default);
    }

    #[test]
    fn test_function_symbol_basics() {
        let addr = Address::new(0x401000);
        let func = FunctionSymbol::new(300, "main", addr);
        assert_eq!(func.get_name(), "main");
        assert_eq!(func.get_symbol_type(), SymbolType::Function);
        assert!(func.is_primary());
        assert!(!func.is_default());
    }

    #[test]
    fn test_default_function() {
        let addr = Address::new(0x401000);
        let func = FunctionSymbol::default_symbol(400, addr);
        assert!(func.is_default());
        assert_eq!(func.get_name(), "FUN_00401000");
        assert_eq!(func.get_source(), SourceType::Default);
    }

    #[test]
    fn test_global_symbol() {
        let gs = GlobalSymbol::new();
        assert_eq!(gs.get_name(), "Global");
        assert_eq!(gs.get_symbol_type(), SymbolType::Global);
        assert!(gs.is_global());
        assert_eq!(gs.get_id(), 0);
    }

    #[test]
    fn test_validate_symbol_name() {
        assert!(validate_symbol_name("valid_name").is_ok());
        assert!(validate_symbol_name("").is_err());
        assert!(validate_symbol_name("name with spaces").is_err());
        assert!(validate_symbol_name("name::delim").is_err());
    }

    #[test]
    fn test_reference_creation() {
        let from = Address::new(0x401000);
        let to = Address::new(0x500000);
        let r = Reference::mnemonic(from, to, RefType::UNCONDITIONAL_CALL);
        assert_eq!(r.get_from_address(), &from);
        assert_eq!(r.get_to_address(), &to);
        assert_eq!(r.get_operand_index(), MNEMONIC);
        assert!(r.is_mnemonic_reference());
        assert!(r.get_reference_type().is_call());
    }

    #[test]
    fn test_reference_ordering() {
        let r1 = Reference::new(Address::new(0x100), Address::new(0x200), RefType::DATA, 0);
        let r2 = Reference::new(Address::new(0x200), Address::new(0x300), RefType::DATA, 0);
        assert!(r1 < r2);
    }

    #[test]
    fn test_reference_manager_basics() {
        let mut mgr = ReferenceManager::new();

        let from = Address::new(0x401000);
        let to = Address::new(0x500000);

        mgr.add_memory_reference(from, to, RefType::UNCONDITIONAL_CALL, SourceType::UserDefined, 0)
            .unwrap();

        assert_eq!(mgr.get_reference_count_to(to), 1);
        assert_eq!(mgr.get_reference_count_from(from), 1);
        assert!(mgr.has_references_from(from));
        assert!(mgr.has_references_to(to));

        let refs = mgr.get_references_from(from);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].get_from_address(), &from);
        assert_eq!(refs[0].get_to_address(), &to);
    }

    #[test]
    fn test_reference_manager_delete() {
        let mut mgr = ReferenceManager::new();
        let from = Address::new(0x401000);
        let to = Address::new(0x500000);

        let r = Reference::new(from, to, RefType::DATA, 0);
        mgr.add_reference(r.clone()).unwrap();

        assert!(mgr.has_references_from(from));
        mgr.remove_all_references_from(from);
        assert!(!mgr.has_references_from(from));
    }

    #[test]
    fn test_reference_manager_external_entry_points() {
        let mut mgr = ReferenceManager::new();
        let addr = Address::new(0x401000);

        assert!(!mgr.is_external_entry_point(addr));
        mgr.add_external_entry_point(addr);
        assert!(mgr.is_external_entry_point(addr));
        mgr.remove_external_entry_point(addr);
        assert!(!mgr.is_external_entry_point(addr));
    }

    #[test]
    fn test_label_set_name() {
        let mut label = LabelSymbol::new(1, "old_name", Address::new(0x1000));
        assert_eq!(label.get_name(), "old_name");

        label.set_name("new_name", SourceType::UserDefined).unwrap();
        assert_eq!(label.get_name(), "new_name");

        // Whitespace should be rejected
        assert!(label.set_name("bad name", SourceType::UserDefined).is_err());
        // Empty name should be rejected
        assert!(label.set_name("", SourceType::UserDefined).is_err());
    }

    #[test]
    fn test_function_set_name_removes_default() {
        let mut func = FunctionSymbol::default_symbol(1, Address::new(0x401000));
        assert!(func.is_default());

        func.set_name("main", SourceType::UserDefined).unwrap();
        assert_eq!(func.get_name(), "main");
        assert!(!func.is_default());
        assert_eq!(func.get_source(), SourceType::UserDefined);
    }

    #[test]
    fn test_function_symbol_delete_default() {
        let mut func = FunctionSymbol::default_symbol(1, Address::new(0x401000));
        assert!(!func.delete()); // Default functions cannot be deleted.
    }

    #[test]
    fn test_function_symbol_delete_named() {
        let mut func = FunctionSymbol::new(1, "my_func", Address::new(0x401000));
        assert!(func.delete());
        assert!(func.is_deleted());
        assert!(!func.delete()); // Already deleted.
    }
}
