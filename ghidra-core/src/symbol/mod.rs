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

pub mod utilities;

use crate::addr::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
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
            SourceType::Default => 1,
            SourceType::Analysis => 2,
            SourceType::AI => 2,
            SourceType::Imported => 3,
            SourceType::UserDefined => 4,
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

// ---------------------------------------------------------------------------
// NamespaceSymbol
// ---------------------------------------------------------------------------

/// A generic namespace symbol. Corresponds to `SymbolType::Namespace`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceSymbol {
    /// The symbol ID.
    id: u64,
    /// The namespace name.
    name: String,
    /// The parent namespace ID (0 = global).
    parent_namespace_id: u64,
    /// The source of this namespace symbol.
    source: SourceType,
    /// Whether this symbol has been deleted.
    deleted: bool,
}

impl NamespaceSymbol {
    /// Creates a new namespace symbol.
    pub fn new(id: u64, name: impl Into<String>, parent_namespace_id: u64, source: SourceType) -> Self {
        Self {
            id,
            name: name.into(),
            parent_namespace_id,
            source,
            deleted: false,
        }
    }

    /// Returns the parent namespace ID.
    pub fn parent_namespace_id(&self) -> u64 {
        self.parent_namespace_id
    }
}

impl SymbolApi for NamespaceSymbol {
    fn get_address(&self) -> &Address {
        &Address::NULL
    }
    fn get_name(&self) -> String { self.name.clone() }
    fn get_path(&self) -> Vec<String> { vec![self.name.clone()] }
    fn get_name_qualified(&self, include_namespace: bool) -> String {
        if include_namespace { format!("Global::{}", self.name) } else { self.name.clone() }
    }
    fn get_parent_namespace(&self) -> Option<&dyn Namespace> { None }
    fn get_parent_symbol(&self) -> Option<&dyn SymbolApi> { None }
    fn is_descendant(&self, namespace: &dyn Namespace) -> bool {
        self.parent_namespace_id == namespace.get_id()
    }
    fn is_valid_parent(&self, parent: &dyn Namespace) -> bool {
        !parent.get_type().is_namespace() || parent.get_id() != self.id
    }
    fn get_symbol_type(&self) -> SymbolType { SymbolType::Namespace }
    fn get_id(&self) -> u64 { self.id }
    fn is_global(&self) -> bool { self.parent_namespace_id == 0 }
    fn is_external(&self) -> bool { false }
    fn is_primary(&self) -> bool { false }
    fn is_dynamic(&self) -> bool { false }
    fn get_source(&self) -> SourceType { self.source }
    fn set_source(&mut self, source: SourceType) { self.source = source; }
    fn is_deleted(&self) -> bool { self.deleted }
    fn set_name(&mut self, new_name: &str, source: SourceType) -> SymbolResult<()> {
        validate_symbol_name(new_name)?;
        self.name = new_name.to_string();
        self.source = source;
        Ok(())
    }
    fn set_namespace(&mut self, new_namespace: &dyn Namespace) -> SymbolResult<()> {
        if new_namespace.get_id() == self.id {
            return Err(SymbolError::CircularDependency("cannot move namespace into itself".into()));
        }
        self.parent_namespace_id = new_namespace.get_id();
        Ok(())
    }
    fn set_name_and_namespace(&mut self, new_name: &str, new_namespace: &dyn Namespace, source: SourceType) -> SymbolResult<()> {
        self.set_name(new_name, source)?;
        self.set_namespace(new_namespace)
    }
    fn delete(&mut self) -> bool {
        if self.deleted { return false; }
        self.deleted = true;
        true
    }
}

impl Namespace for NamespaceSymbol {
    fn get_symbol(&self) -> &dyn SymbolApi { self }
    fn get_type(&self) -> SymbolType { SymbolType::Namespace }
    fn is_external(&self) -> bool { false }
    fn get_name(&self) -> String { self.name.clone() }
    fn get_name_full(&self, include_namespace_path: bool) -> String {
        if include_namespace_path { format!("Global::{}", self.name) } else { self.name.clone() }
    }
    fn get_id(&self) -> u64 { self.id }
    fn get_parent_namespace(&self) -> Option<&dyn Namespace> { None }
    fn get_body(&self) -> Vec<Address> { Vec::new() }
    fn set_parent_namespace(&mut self, parent: &dyn Namespace) -> SymbolResult<()> {
        self.set_namespace(parent)
    }
}

// ---------------------------------------------------------------------------
// ClassSymbol
// ---------------------------------------------------------------------------

/// A class namespace symbol. Corresponds to `SymbolType::Class`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassSymbol {
    /// The symbol ID.
    id: u64,
    /// The class name.
    name: String,
    /// The parent namespace ID (0 = global).
    parent_namespace_id: u64,
    /// The source of this class symbol.
    source: SourceType,
    /// Whether this symbol has been deleted.
    deleted: bool,
}

impl ClassSymbol {
    /// Creates a new class symbol.
    pub fn new(id: u64, name: impl Into<String>, parent_namespace_id: u64, source: SourceType) -> Self {
        Self {
            id,
            name: name.into(),
            parent_namespace_id,
            source,
            deleted: false,
        }
    }

    /// Returns the parent namespace ID.
    pub fn parent_namespace_id(&self) -> u64 {
        self.parent_namespace_id
    }
}

impl SymbolApi for ClassSymbol {
    fn get_address(&self) -> &Address { &Address::NULL }
    fn get_name(&self) -> String { self.name.clone() }
    fn get_path(&self) -> Vec<String> { vec![self.name.clone()] }
    fn get_name_qualified(&self, include_namespace: bool) -> String {
        if include_namespace { format!("Global::{}", self.name) } else { self.name.clone() }
    }
    fn get_parent_namespace(&self) -> Option<&dyn Namespace> { None }
    fn get_parent_symbol(&self) -> Option<&dyn SymbolApi> { None }
    fn is_descendant(&self, namespace: &dyn Namespace) -> bool {
        self.parent_namespace_id == namespace.get_id()
    }
    fn is_valid_parent(&self, parent: &dyn Namespace) -> bool {
        // Class cannot be inside a function.
        parent.get_type() != SymbolType::Function
    }
    fn get_symbol_type(&self) -> SymbolType { SymbolType::Class }
    fn get_id(&self) -> u64 { self.id }
    fn is_global(&self) -> bool { self.parent_namespace_id == 0 }
    fn is_external(&self) -> bool { false }
    fn is_primary(&self) -> bool { false }
    fn is_dynamic(&self) -> bool { false }
    fn get_source(&self) -> SourceType { self.source }
    fn set_source(&mut self, source: SourceType) { self.source = source; }
    fn is_deleted(&self) -> bool { self.deleted }
    fn set_name(&mut self, new_name: &str, source: SourceType) -> SymbolResult<()> {
        validate_symbol_name(new_name)?;
        self.name = new_name.to_string();
        self.source = source;
        Ok(())
    }
    fn set_namespace(&mut self, new_namespace: &dyn Namespace) -> SymbolResult<()> {
        if !self.is_valid_parent(new_namespace) {
            return Err(SymbolError::InvalidInput("invalid parent namespace for class symbol".into()));
        }
        self.parent_namespace_id = new_namespace.get_id();
        Ok(())
    }
    fn set_name_and_namespace(&mut self, new_name: &str, new_namespace: &dyn Namespace, source: SourceType) -> SymbolResult<()> {
        self.set_name(new_name, source)?;
        self.set_namespace(new_namespace)
    }
    fn delete(&mut self) -> bool {
        if self.deleted { return false; }
        self.deleted = true;
        true
    }
}

impl Namespace for ClassSymbol {
    fn get_symbol(&self) -> &dyn SymbolApi { self }
    fn get_type(&self) -> SymbolType { SymbolType::Class }
    fn is_external(&self) -> bool { false }
    fn get_name(&self) -> String { self.name.clone() }
    fn get_name_full(&self, include_namespace_path: bool) -> String {
        if include_namespace_path { format!("Global::{}", self.name) } else { self.name.clone() }
    }
    fn get_id(&self) -> u64 { self.id }
    fn get_parent_namespace(&self) -> Option<&dyn Namespace> { None }
    fn get_body(&self) -> Vec<Address> { Vec::new() }
    fn set_parent_namespace(&mut self, parent: &dyn Namespace) -> SymbolResult<()> {
        self.set_namespace(parent)
    }
}

// ---------------------------------------------------------------------------
// LibrarySymbol
// ---------------------------------------------------------------------------

/// An external library symbol. Corresponds to `SymbolType::Library`.
/// Always resides in the global namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LibrarySymbol {
    /// The symbol ID.
    id: u64,
    /// The library name (e.g., "libc.so.6").
    name: String,
    /// The source of this library symbol.
    source: SourceType,
    /// Whether this symbol has been deleted.
    deleted: bool,
}

impl LibrarySymbol {
    /// Creates a new library symbol.
    pub fn new(id: u64, name: impl Into<String>, source: SourceType) -> Self {
        Self {
            id,
            name: name.into(),
            source,
            deleted: false,
        }
    }
}

impl SymbolApi for LibrarySymbol {
    fn get_address(&self) -> &Address { &Address::NULL }
    fn get_name(&self) -> String { self.name.clone() }
    fn get_path(&self) -> Vec<String> { vec![self.name.clone()] }
    fn get_name_qualified(&self, _include_namespace: bool) -> String { self.name.clone() }
    fn get_parent_namespace(&self) -> Option<&dyn Namespace> { None }
    fn get_parent_symbol(&self) -> Option<&dyn SymbolApi> { None }
    fn is_descendant(&self, _namespace: &dyn Namespace) -> bool { true }
    fn is_valid_parent(&self, parent: &dyn Namespace) -> bool {
        // Libraries must be in the global namespace.
        parent.get_id() == 0
    }
    fn get_symbol_type(&self) -> SymbolType { SymbolType::Library }
    fn get_id(&self) -> u64 { self.id }
    fn is_global(&self) -> bool { true }
    fn is_external(&self) -> bool { true }
    fn is_primary(&self) -> bool { false }
    fn is_dynamic(&self) -> bool { false }
    fn get_source(&self) -> SourceType { self.source }
    fn set_source(&mut self, source: SourceType) { self.source = source; }
    fn is_deleted(&self) -> bool { self.deleted }
    fn set_name(&mut self, new_name: &str, source: SourceType) -> SymbolResult<()> {
        validate_symbol_name(new_name)?;
        self.name = new_name.to_string();
        self.source = source;
        Ok(())
    }
    fn set_namespace(&mut self, new_namespace: &dyn Namespace) -> SymbolResult<()> {
        if !self.is_valid_parent(new_namespace) {
            return Err(SymbolError::InvalidInput("library must be in global namespace".into()));
        }
        Ok(()) // no-op; library is always global
    }
    fn set_name_and_namespace(&mut self, new_name: &str, new_namespace: &dyn Namespace, source: SourceType) -> SymbolResult<()> {
        self.set_name(new_name, source)?;
        self.set_namespace(new_namespace)
    }
    fn delete(&mut self) -> bool {
        if self.deleted { return false; }
        self.deleted = true;
        true
    }
}

impl Namespace for LibrarySymbol {
    fn get_symbol(&self) -> &dyn SymbolApi { self }
    fn get_type(&self) -> SymbolType { SymbolType::Library }
    fn is_external(&self) -> bool { true }
    fn get_name(&self) -> String { self.name.clone() }
    fn get_name_full(&self, _include_namespace_path: bool) -> String { self.name.clone() }
    fn get_id(&self) -> u64 { self.id }
    fn get_parent_namespace(&self) -> Option<&dyn Namespace> { None }
    fn get_body(&self) -> Vec<Address> { Vec::new() }
    fn set_parent_namespace(&mut self, _parent: &dyn Namespace) -> SymbolResult<()> {
        Err(SymbolError::UnsupportedOperation("cannot change parent of library namespace".into()))
    }
}

// ---------------------------------------------------------------------------
// ImportSymbol
// ---------------------------------------------------------------------------

/// An imported symbol (external library function/data). Corresponds to
/// `SymbolType::Import`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportSymbol {
    /// The symbol ID.
    id: u64,
    /// The imported name.
    name: String,
    /// The external address (or entry point address).
    address: Address,
    /// The parent namespace ID (usually a Library namespace).
    namespace_id: u64,
    /// The source of this import symbol.
    source: SourceType,
    /// Whether this is the primary symbol at this address.
    primary: bool,
    /// Whether this symbol has been deleted.
    deleted: bool,
}

impl ImportSymbol {
    /// Creates a new import symbol.
    pub fn new(id: u64, name: impl Into<String>, address: Address, namespace_id: u64, source: SourceType) -> Self {
        Self { id, name: name.into(), address, namespace_id, source, primary: true, deleted: false }
    }

    /// Returns the parent namespace ID.
    pub fn namespace_id(&self) -> u64 { self.namespace_id }
}

impl SymbolApi for ImportSymbol {
    fn get_address(&self) -> &Address { &self.address }
    fn get_name(&self) -> String { self.name.clone() }
    fn get_path(&self) -> Vec<String> { vec![self.name.clone()] }
    fn get_name_qualified(&self, include_namespace: bool) -> String {
        if include_namespace { format!("Global::{}", self.name) } else { self.name.clone() }
    }
    fn get_parent_namespace(&self) -> Option<&dyn Namespace> { None }
    fn get_parent_symbol(&self) -> Option<&dyn SymbolApi> { None }
    fn is_descendant(&self, namespace: &dyn Namespace) -> bool { self.namespace_id == namespace.get_id() }
    fn is_valid_parent(&self, _parent: &dyn Namespace) -> bool { true }
    fn get_symbol_type(&self) -> SymbolType { SymbolType::Import }
    fn get_id(&self) -> u64 { self.id }
    fn is_global(&self) -> bool { self.namespace_id == 0 }
    fn is_external(&self) -> bool { self.address.is_external_address() }
    fn is_primary(&self) -> bool { self.primary }
    fn set_primary(&mut self) -> bool { if self.primary { false } else { self.primary = true; true } }
    fn is_dynamic(&self) -> bool { false }
    fn get_source(&self) -> SourceType { self.source }
    fn set_source(&mut self, source: SourceType) { self.source = source; }
    fn is_deleted(&self) -> bool { self.deleted }
    fn set_name(&mut self, new_name: &str, source: SourceType) -> SymbolResult<()> {
        validate_symbol_name(new_name)?;
        self.name = new_name.to_string();
        self.source = source;
        Ok(())
    }
    fn set_namespace(&mut self, new_namespace: &dyn Namespace) -> SymbolResult<()> {
        self.namespace_id = new_namespace.get_id();
        Ok(())
    }
    fn set_name_and_namespace(&mut self, new_name: &str, new_namespace: &dyn Namespace, source: SourceType) -> SymbolResult<()> {
        self.set_name(new_name, source)?;
        self.set_namespace(new_namespace)
    }
    fn delete(&mut self) -> bool {
        if self.deleted { return false; }
        self.deleted = true;
        true
    }
}

// ---------------------------------------------------------------------------
// ExportSymbol
// ---------------------------------------------------------------------------

/// An exported symbol (function or data exported by the binary). Corresponds to
/// `SymbolType::Export`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportSymbol {
    /// The symbol ID.
    id: u64,
    /// The exported name.
    name: String,
    /// The export address.
    address: Address,
    /// The parent namespace ID (0 = global).
    namespace_id: u64,
    /// The source of this export symbol.
    source: SourceType,
    /// Whether this is the primary symbol at this address.
    primary: bool,
    /// Whether this symbol has been deleted.
    deleted: bool,
}

impl ExportSymbol {
    /// Creates a new export symbol.
    pub fn new(id: u64, name: impl Into<String>, address: Address, namespace_id: u64, source: SourceType) -> Self {
        Self { id, name: name.into(), address, namespace_id, source, primary: true, deleted: false }
    }

    /// Returns the parent namespace ID.
    pub fn namespace_id(&self) -> u64 { self.namespace_id }
}

impl SymbolApi for ExportSymbol {
    fn get_address(&self) -> &Address { &self.address }
    fn get_name(&self) -> String { self.name.clone() }
    fn get_path(&self) -> Vec<String> { vec![self.name.clone()] }
    fn get_name_qualified(&self, include_namespace: bool) -> String {
        if include_namespace { format!("Global::{}", self.name) } else { self.name.clone() }
    }
    fn get_parent_namespace(&self) -> Option<&dyn Namespace> { None }
    fn get_parent_symbol(&self) -> Option<&dyn SymbolApi> { None }
    fn is_descendant(&self, namespace: &dyn Namespace) -> bool { self.namespace_id == namespace.get_id() }
    fn is_valid_parent(&self, _parent: &dyn Namespace) -> bool { true }
    fn get_symbol_type(&self) -> SymbolType { SymbolType::Export }
    fn get_id(&self) -> u64 { self.id }
    fn is_global(&self) -> bool { self.namespace_id == 0 }
    fn is_external(&self) -> bool { self.address.is_external_address() }
    fn is_primary(&self) -> bool { self.primary }
    fn set_primary(&mut self) -> bool { if self.primary { false } else { self.primary = true; true } }
    fn is_dynamic(&self) -> bool { false }
    fn get_source(&self) -> SourceType { self.source }
    fn set_source(&mut self, source: SourceType) { self.source = source; }
    fn is_deleted(&self) -> bool { self.deleted }
    fn set_name(&mut self, new_name: &str, source: SourceType) -> SymbolResult<()> {
        validate_symbol_name(new_name)?;
        self.name = new_name.to_string();
        self.source = source;
        Ok(())
    }
    fn set_namespace(&mut self, new_namespace: &dyn Namespace) -> SymbolResult<()> {
        self.namespace_id = new_namespace.get_id();
        Ok(())
    }
    fn set_name_and_namespace(&mut self, new_name: &str, new_namespace: &dyn Namespace, source: SourceType) -> SymbolResult<()> {
        self.set_name(new_name, source)?;
        self.set_namespace(new_namespace)
    }
    fn delete(&mut self) -> bool {
        if self.deleted { return false; }
        self.deleted = true;
        true
    }
}

// ---------------------------------------------------------------------------
// ParameterSymbol
// ---------------------------------------------------------------------------

/// A function parameter symbol. Corresponds to `SymbolType::Parameter`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParameterSymbol {
    /// The symbol ID.
    id: u64,
    /// The parameter name.
    name: String,
    /// The address (variable address space).
    address: Address,
    /// The owning function symbol ID.
    function_id: u64,
    /// Ordinal position of the parameter (0-based).
    ordinal: u32,
    /// The source of this parameter.
    source: SourceType,
    /// Whether this symbol has been deleted.
    deleted: bool,
}

impl ParameterSymbol {
    /// Creates a new parameter symbol.
    pub fn new(id: u64, name: impl Into<String>, address: Address, function_id: u64, ordinal: u32, source: SourceType) -> Self {
        Self { id, name: name.into(), address, function_id, ordinal, source, deleted: false }
    }

    /// Returns the owning function ID.
    pub fn function_id(&self) -> u64 { self.function_id }

    /// Returns the parameter ordinal.
    pub fn ordinal(&self) -> u32 { self.ordinal }
}

impl SymbolApi for ParameterSymbol {
    fn get_address(&self) -> &Address { &self.address }
    fn get_name(&self) -> String { self.name.clone() }
    fn get_path(&self) -> Vec<String> { vec![self.name.clone()] }
    fn get_name_qualified(&self, _include_namespace: bool) -> String { self.name.clone() }
    fn get_parent_namespace(&self) -> Option<&dyn Namespace> { None }
    fn get_parent_symbol(&self) -> Option<&dyn SymbolApi> { None }
    fn is_descendant(&self, _namespace: &dyn Namespace) -> bool { false }
    fn is_valid_parent(&self, _parent: &dyn Namespace) -> bool { true }
    fn get_symbol_type(&self) -> SymbolType { SymbolType::Parameter }
    fn get_id(&self) -> u64 { self.id }
    fn is_global(&self) -> bool { false }
    fn is_external(&self) -> bool { false }
    fn is_primary(&self) -> bool { false }
    fn is_dynamic(&self) -> bool { false }
    fn get_source(&self) -> SourceType { self.source }
    fn set_source(&mut self, source: SourceType) { self.source = source; }
    fn is_deleted(&self) -> bool { self.deleted }
    fn set_name(&mut self, new_name: &str, source: SourceType) -> SymbolResult<()> {
        validate_symbol_name(new_name)?;
        self.name = new_name.to_string();
        self.source = source;
        Ok(())
    }
    fn set_namespace(&mut self, _new_namespace: &dyn Namespace) -> SymbolResult<()> {
        Err(SymbolError::UnsupportedOperation("cannot move parameter symbol to a different namespace".into()))
    }
    fn set_name_and_namespace(&mut self, new_name: &str, _new_namespace: &dyn Namespace, source: SourceType) -> SymbolResult<()> {
        self.set_name(new_name, source)
    }
    fn delete(&mut self) -> bool {
        if self.deleted { return false; }
        self.deleted = true;
        true
    }
}

// ---------------------------------------------------------------------------
// LocalVarSymbol
// ---------------------------------------------------------------------------

/// A function local variable symbol. Corresponds to `SymbolType::LocalVar`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalVarSymbol {
    /// The symbol ID.
    id: u64,
    /// The variable name.
    name: String,
    /// The address (variable address space).
    address: Address,
    /// The owning function symbol ID.
    function_id: u64,
    /// The source of this local variable.
    source: SourceType,
    /// Whether this symbol has been deleted.
    deleted: bool,
}

impl LocalVarSymbol {
    /// Creates a new local variable symbol.
    pub fn new(id: u64, name: impl Into<String>, address: Address, function_id: u64, source: SourceType) -> Self {
        Self { id, name: name.into(), address, function_id, source, deleted: false }
    }

    /// Returns the owning function ID.
    pub fn function_id(&self) -> u64 { self.function_id }
}

impl SymbolApi for LocalVarSymbol {
    fn get_address(&self) -> &Address { &self.address }
    fn get_name(&self) -> String { self.name.clone() }
    fn get_path(&self) -> Vec<String> { vec![self.name.clone()] }
    fn get_name_qualified(&self, _include_namespace: bool) -> String { self.name.clone() }
    fn get_parent_namespace(&self) -> Option<&dyn Namespace> { None }
    fn get_parent_symbol(&self) -> Option<&dyn SymbolApi> { None }
    fn is_descendant(&self, _namespace: &dyn Namespace) -> bool { false }
    fn is_valid_parent(&self, _parent: &dyn Namespace) -> bool { true }
    fn get_symbol_type(&self) -> SymbolType { SymbolType::LocalVar }
    fn get_id(&self) -> u64 { self.id }
    fn is_global(&self) -> bool { false }
    fn is_external(&self) -> bool { false }
    fn is_primary(&self) -> bool { false }
    fn is_dynamic(&self) -> bool { false }
    fn get_source(&self) -> SourceType { self.source }
    fn set_source(&mut self, source: SourceType) { self.source = source; }
    fn is_deleted(&self) -> bool { self.deleted }
    fn set_name(&mut self, new_name: &str, source: SourceType) -> SymbolResult<()> {
        validate_symbol_name(new_name)?;
        self.name = new_name.to_string();
        self.source = source;
        Ok(())
    }
    fn set_namespace(&mut self, _new_namespace: &dyn Namespace) -> SymbolResult<()> {
        Err(SymbolError::UnsupportedOperation("cannot move local variable to a different namespace".into()))
    }
    fn set_name_and_namespace(&mut self, new_name: &str, _new_namespace: &dyn Namespace, source: SourceType) -> SymbolResult<()> {
        self.set_name(new_name, source)
    }
    fn delete(&mut self) -> bool {
        if self.deleted { return false; }
        self.deleted = true;
        true
    }
}

// ---------------------------------------------------------------------------
// GlobalVarSymbol
// ---------------------------------------------------------------------------

/// A global register variable symbol. Corresponds to `SymbolType::GlobalVar`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalVarSymbol {
    /// The symbol ID.
    id: u64,
    /// The variable name.
    name: String,
    /// The address (variable/register address space).
    address: Address,
    /// The parent namespace ID (0 = global).
    namespace_id: u64,
    /// The source of this global variable.
    source: SourceType,
    /// Whether this symbol has been deleted.
    deleted: bool,
}

impl GlobalVarSymbol {
    /// Creates a new global register variable symbol.
    pub fn new(id: u64, name: impl Into<String>, address: Address, namespace_id: u64, source: SourceType) -> Self {
        Self { id, name: name.into(), address, namespace_id, source, deleted: false }
    }

    /// Returns the parent namespace ID.
    pub fn namespace_id(&self) -> u64 { self.namespace_id }
}

impl SymbolApi for GlobalVarSymbol {
    fn get_address(&self) -> &Address { &self.address }
    fn get_name(&self) -> String { self.name.clone() }
    fn get_path(&self) -> Vec<String> { vec![self.name.clone()] }
    fn get_name_qualified(&self, include_namespace: bool) -> String {
        if include_namespace { format!("Global::{}", self.name) } else { self.name.clone() }
    }
    fn get_parent_namespace(&self) -> Option<&dyn Namespace> { None }
    fn get_parent_symbol(&self) -> Option<&dyn SymbolApi> { None }
    fn is_descendant(&self, namespace: &dyn Namespace) -> bool { self.namespace_id == namespace.get_id() }
    fn is_valid_parent(&self, _parent: &dyn Namespace) -> bool { true }
    fn get_symbol_type(&self) -> SymbolType { SymbolType::GlobalVar }
    fn get_id(&self) -> u64 { self.id }
    fn is_global(&self) -> bool { self.namespace_id == 0 }
    fn is_external(&self) -> bool { false }
    fn is_primary(&self) -> bool { false }
    fn is_dynamic(&self) -> bool { false }
    fn get_source(&self) -> SourceType { self.source }
    fn set_source(&mut self, source: SourceType) { self.source = source; }
    fn is_deleted(&self) -> bool { self.deleted }
    fn set_name(&mut self, new_name: &str, source: SourceType) -> SymbolResult<()> {
        validate_symbol_name(new_name)?;
        self.name = new_name.to_string();
        self.source = source;
        Ok(())
    }
    fn set_namespace(&mut self, new_namespace: &dyn Namespace) -> SymbolResult<()> {
        self.namespace_id = new_namespace.get_id();
        Ok(())
    }
    fn set_name_and_namespace(&mut self, new_name: &str, new_namespace: &dyn Namespace, source: SourceType) -> SymbolResult<()> {
        self.set_name(new_name, source)?;
        self.set_namespace(new_namespace)
    }
    fn delete(&mut self) -> bool {
        if self.deleted { return false; }
        self.deleted = true;
        true
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
// ReferenceDestinationRangeIter -- iterates over "to" addresses in a range
// ---------------------------------------------------------------------------

/// Iterates over unique "to" addresses within a given address range.
///
/// This is used by cross-reference utilities to find all addresses referenced
/// within a specific code unit range (for offcut xref detection).
pub struct ReferenceDestinationRangeIter<'a> {
    mgr: &'a ReferenceManager,
    start: Address,
    end: Address,
    index: usize,
    seen: HashSet<Address>,
}

impl<'a> Iterator for ReferenceDestinationRangeIter<'a> {
    type Item = Address;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.mgr.references.len() {
            let r = &self.mgr.references[self.index];
            self.index += 1;
            let addr = r.to_address;
            if addr >= self.start && addr <= self.end && self.seen.insert(addr) {
                return Some(addr);
            }
        }
        None
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
    ///
    /// Stack references are used to reference stack variables. The stack offset
    /// is encoded into the "to" address using the stack address space. In this
    /// simplified implementation, the offset is stored as the address offset.
    pub fn add_stack_reference(
        &mut self,
        from_addr: Address,
        op_index: i32,
        stack_offset: i32,
        ref_type: RefType,
        source: SourceType,
    ) -> SymbolResult<&Reference> {
        self.remove_references_at(from_addr, op_index);
        // Stack references encode the stack offset into the address.
        // The stack address space uses a high bit to distinguish from memory addresses.
        let to_addr = Address::new(stack_offset as u64);
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
    ///
    /// External references point to symbols in external libraries. If no external
    /// address is provided, a special external-space address is synthesized from
    /// the label name hash.
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
            // Synthesize an external address from the label name hash.
            // External addresses use a high range to distinguish from memory addresses.
            let hash = ext_label.bytes().fold(0u64, |acc, b| {
                acc.wrapping_mul(31).wrapping_add(b as u64)
            });
            Address::new(0xFFFF_FFFF_FFFF_0000u64.wrapping_add(hash & 0xFFFF))
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
    pub fn remove_references_at(&mut self, from_addr: Address, op_index: i32) {
        self.references
            .retain(|r| !(r.from_address == from_addr && r.op_index == op_index));
    }

    /// Returns the total number of references.
    pub fn num_references(&self) -> usize {
        self.references.len()
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

    /// Returns an iterator over "to" addresses within the given range (inclusive).
    pub fn get_reference_destination_iterator_range(
        &self,
        start_addr: &Address,
        end_addr: &Address,
    ) -> ReferenceDestinationRangeIter<'_> {
        ReferenceDestinationRangeIter {
            mgr: self,
            start: *start_addr,
            end: *end_addr,
            index: 0,
            seen: HashSet::new(),
        }
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

    pub fn from_delimited(path: &str) -> Self {
        let mut segments: Vec<String> = path
            .split("::")
            .map(str::trim)
            .filter(|segment| !segment.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if segments.is_empty() {
            return Self::root();
        }
        if segments.first().map(String::as_str) != Some("Global") {
            segments.insert(0, "Global".to_string());
        }
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

    pub fn name(&self) -> &str {
        self.segments
            .last()
            .map(String::as_str)
            .unwrap_or("Global")
    }

    pub fn leaf_name(&self) -> Option<&str> {
        self.segments.last().map(String::as_str)
    }

    pub fn as_slice(&self) -> &[String] {
        &self.segments
    }

    pub fn len(&self) -> usize {
        self.segments.len()
    }

    pub fn depth(&self) -> usize {
        self.segments.len().saturating_sub(1)
    }

    pub fn child(&self, name: impl Into<String>) -> Self {
        let mut segments = self.segments.clone();
        segments.push(name.into());
        Self { segments }
    }

    pub fn starts_with(&self, other: &SymbolPath) -> bool {
        self.segments.starts_with(&other.segments)
    }
}

impl From<&str> for SymbolPath {
    fn from(path: &str) -> Self {
        Self::from_delimited(path)
    }
}

impl From<String> for SymbolPath {
    fn from(path: String) -> Self {
        Self::from_delimited(&path)
    }
}

impl From<Vec<String>> for SymbolPath {
    fn from(segments: Vec<String>) -> Self {
        Self::from_segments(segments)
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

    pub fn child_count(&self) -> usize {
        self.children.len()
    }

    pub fn has_symbol(&self) -> bool {
        self.symbol.is_some()
    }

    pub fn symbol(&self) -> Option<&Symbol> {
        self.symbol.as_ref()
    }

    pub fn children(&self) -> &[SymbolTreeNode] {
        &self.children
    }

    pub fn find_child(&self, name: &str) -> Option<&SymbolTreeNode> {
        self.children.iter().find(|child| child.name == name)
    }

    pub fn get_child(&self, index: usize) -> Option<&SymbolTreeNode> {
        self.children.get(index)
    }

    pub fn has_children(&self) -> bool {
        !self.children.is_empty()
    }

    pub fn find_path<'a>(&'a self, path: &SymbolPath) -> Option<&'a SymbolTreeNode> {
        let self_segments = self.path.as_slice();
        let target_segments = path.as_slice();
        if target_segments.len() < self_segments.len() || !target_segments.starts_with(self_segments) {
            return None;
        }
        if target_segments.len() == self_segments.len() {
            return Some(self);
        }
        let next = &target_segments[self_segments.len()];
        self.find_child(next)?.find_path(path)
    }
}

impl<'a> IntoIterator for &'a SymbolTreeNode {
    type Item = &'a SymbolTreeNode;
    type IntoIter = std::slice::Iter<'a, SymbolTreeNode>;

    fn into_iter(self) -> Self::IntoIter {
        self.children.iter()
    }
}

impl std::str::FromStr for SymbolPath {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(SymbolPath::from_delimited(s))
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
    /// A generic namespace symbol.
    Namespace(NamespaceSymbol),
    /// A class namespace symbol.
    Class(ClassSymbol),
    /// An external library symbol.
    Library(LibrarySymbol),
    /// An imported symbol (external library function/data).
    Import(ImportSymbol),
    /// An exported symbol (function or data exported by the binary).
    Export(ExportSymbol),
    /// A function parameter symbol.
    Parameter(ParameterSymbol),
    /// A function local variable symbol.
    LocalVar(LocalVarSymbol),
    /// A global register variable symbol.
    GlobalVar(GlobalVarSymbol),
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
            SymbolType::Namespace => {
                Symbol::Namespace(NamespaceSymbol::new(0, name, 0, SourceType::UserDefined))
            }
            SymbolType::Class => {
                Symbol::Class(ClassSymbol::new(0, name, 0, SourceType::UserDefined))
            }
            SymbolType::Library => {
                Symbol::Library(LibrarySymbol::new(0, name, SourceType::UserDefined))
            }
            SymbolType::Import => {
                Symbol::Import(ImportSymbol::new(0, name, address, 0, SourceType::Imported))
            }
            SymbolType::Export => {
                Symbol::Export(ExportSymbol::new(0, name, address, 0, SourceType::UserDefined))
            }
            SymbolType::GlobalVar => {
                Symbol::GlobalVar(GlobalVarSymbol::new(0, name, address, 0, SourceType::UserDefined))
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
        Symbol::Import(ImportSymbol::new(0, name, address, 0, SourceType::Imported))
    }

    /// Create an export symbol (backward-compatible).
    pub fn export(name: impl Into<String>, address: Address) -> Self {
        Symbol::Export(ExportSymbol::new(0, name, address, 0, SourceType::UserDefined))
    }

    /// Create a library symbol.
    pub fn library(name: impl Into<String>) -> Self {
        Symbol::Library(LibrarySymbol::new(0, name, SourceType::UserDefined))
    }

    /// Create a namespace symbol.
    pub fn namespace(name: impl Into<String>, parent_id: u64) -> Self {
        Symbol::Namespace(NamespaceSymbol::new(0, name, parent_id, SourceType::UserDefined))
    }

    /// Create a class symbol.
    pub fn class(name: impl Into<String>, parent_id: u64) -> Self {
        Symbol::Class(ClassSymbol::new(0, name, parent_id, SourceType::UserDefined))
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

    /// Returns the symbol identifier.
    pub fn id(&self) -> u64 {
        <Self as SymbolApi>::get_id(self)
    }

    /// Returns the fully-qualified path for this symbol.
    pub fn path(&self) -> SymbolPath {
        SymbolPath::from_segments(<Self as SymbolApi>::get_path(self))
    }

    /// Returns the fully-qualified symbol name.
    pub fn qualified_name(&self) -> String {
        <Self as SymbolApi>::get_name_qualified(self, true)
    }

    /// Returns true if this symbol belongs to the global namespace.
    pub fn is_global_namespace_member(&self) -> bool {
        <Self as SymbolApi>::is_global(self)
    }

    /// Returns true if this symbol represents an external symbol.
    pub fn is_external_symbol(&self) -> bool {
        <Self as SymbolApi>::is_external(self)
    }

    /// Returns true if this symbol is dynamic.
    pub fn is_dynamic_symbol(&self) -> bool {
        <Self as SymbolApi>::is_dynamic(self)
    }

    /// Returns the symbol namespace identifier when available.
    pub fn namespace_id(&self) -> Option<u64> {
        match self {
            Symbol::Label(s) => Some(s.namespace_id),
            Symbol::Function(s) => Some(s.namespace_id),
            Symbol::Namespace(s) => Some(s.parent_namespace_id()),
            Symbol::Class(s) => Some(s.parent_namespace_id()),
            Symbol::Import(s) => Some(s.namespace_id()),
            Symbol::Export(s) => Some(s.namespace_id()),
            Symbol::GlobalVar(s) => Some(s.namespace_id()),
            Symbol::Library(_) => Some(0), // libraries are always in global
            Symbol::Global(_) => None,
            Symbol::Parameter(s) => Some(s.function_id()),
            Symbol::LocalVar(s) => Some(s.function_id()),
        }
    }

    /// Returns true if this symbol's namespace id matches the given value.
    pub fn is_in_namespace(&self, namespace_id: u64) -> bool {
        self.namespace_id() == Some(namespace_id)
    }

    /// Returns the label variant if this symbol is a label.
    pub fn as_label(&self) -> Option<&LabelSymbol> {
        match self {
            Symbol::Label(label) => Some(label),
            _ => None,
        }
    }

    /// Returns the function variant if this symbol is a function.
    pub fn as_function(&self) -> Option<&FunctionSymbol> {
        match self {
            Symbol::Function(function) => Some(function),
            _ => None,
        }
    }

    /// Returns the global variant if this symbol is the global symbol.
    pub fn as_global(&self) -> Option<&GlobalSymbol> {
        match self {
            Symbol::Global(global) => Some(global),
            _ => None,
        }
    }

    /// Returns the namespace variant if this symbol is a namespace symbol.
    pub fn as_namespace_symbol(&self) -> Option<&NamespaceSymbol> {
        match self {
            Symbol::Namespace(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the class variant if this symbol is a class symbol.
    pub fn as_class(&self) -> Option<&ClassSymbol> {
        match self {
            Symbol::Class(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the library variant if this symbol is a library symbol.
    pub fn as_library(&self) -> Option<&LibrarySymbol> {
        match self {
            Symbol::Library(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the import variant if this symbol is an import symbol.
    pub fn as_import(&self) -> Option<&ImportSymbol> {
        match self {
            Symbol::Import(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the export variant if this symbol is an export symbol.
    pub fn as_export(&self) -> Option<&ExportSymbol> {
        match self {
            Symbol::Export(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the parameter variant if this symbol is a parameter symbol.
    pub fn as_parameter(&self) -> Option<&ParameterSymbol> {
        match self {
            Symbol::Parameter(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the local var variant if this symbol is a local variable symbol.
    pub fn as_local_var(&self) -> Option<&LocalVarSymbol> {
        match self {
            Symbol::LocalVar(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the global var variant if this symbol is a global register variable.
    pub fn as_global_var(&self) -> Option<&GlobalVarSymbol> {
        match self {
            Symbol::GlobalVar(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the symbol variant as a namespace when applicable.
    pub fn as_namespace(&self) -> Option<&dyn Namespace> {
        match self {
            Symbol::Function(function) => Some(function),
            Symbol::Global(global) => Some(global),
            Symbol::Namespace(s) => Some(s),
            Symbol::Class(s) => Some(s),
            Symbol::Library(s) => Some(s),
            _ => None,
        }
    }

    /// Returns true if this symbol can serve as a namespace.
    pub fn is_namespace_symbol(&self) -> bool {
        self.as_namespace().is_some()
    }

    /// Returns true if this symbol has been deleted.
    pub fn is_deleted_symbol(&self) -> bool {
        <Self as SymbolApi>::is_deleted(self)
    }

    /// Returns true if this symbol has references attached.
    pub fn has_attached_references(&self) -> bool {
        <Self as SymbolApi>::has_references(self)
    }

    /// Returns the attached reference slice.
    pub fn references(&self) -> &[Reference] {
        <Self as SymbolApi>::get_references(self)
    }

    /// Returns the symbol source.
    pub fn source_type(&self) -> SourceType {
        self.source()
    }

    /// Returns true if this symbol is a function symbol.
    pub fn is_function_symbol(&self) -> bool {
        matches!(self, Symbol::Function(_))
    }

    /// Returns true if this symbol is a label symbol.
    pub fn is_label_symbol(&self) -> bool {
        matches!(self, Symbol::Label(_))
    }

    /// Returns true if this symbol is a namespace symbol.
    pub fn is_namespace_type(&self) -> bool {
        matches!(self, Symbol::Namespace(_))
    }

    /// Returns true if this symbol is a class symbol.
    pub fn is_class_symbol(&self) -> bool {
        matches!(self, Symbol::Class(_))
    }

    /// Returns true if this symbol is a library symbol.
    pub fn is_library_symbol(&self) -> bool {
        matches!(self, Symbol::Library(_))
    }

    /// Returns true if this symbol is an import symbol.
    pub fn is_import_symbol(&self) -> bool {
        matches!(self, Symbol::Import(_))
    }

    /// Returns true if this symbol is an export symbol.
    pub fn is_export_symbol(&self) -> bool {
        matches!(self, Symbol::Export(_))
    }

    /// Returns true if this symbol is a parameter symbol.
    pub fn is_parameter_symbol(&self) -> bool {
        matches!(self, Symbol::Parameter(_))
    }

    /// Returns true if this symbol is a local variable symbol.
    pub fn is_local_var_symbol(&self) -> bool {
        matches!(self, Symbol::LocalVar(_))
    }

    /// Returns true if this symbol is a global variable symbol.
    pub fn is_global_var_symbol(&self) -> bool {
        matches!(self, Symbol::GlobalVar(_))
    }
}

impl From<LabelSymbol> for Symbol {
    fn from(symbol: LabelSymbol) -> Self {
        Symbol::Label(symbol)
    }
}

impl From<FunctionSymbol> for Symbol {
    fn from(symbol: FunctionSymbol) -> Self {
        Symbol::Function(symbol)
    }
}

impl From<GlobalSymbol> for Symbol {
    fn from(symbol: GlobalSymbol) -> Self {
        Symbol::Global(symbol)
    }
}

impl From<NamespaceSymbol> for Symbol {
    fn from(symbol: NamespaceSymbol) -> Self {
        Symbol::Namespace(symbol)
    }
}

impl From<ClassSymbol> for Symbol {
    fn from(symbol: ClassSymbol) -> Self {
        Symbol::Class(symbol)
    }
}

impl From<LibrarySymbol> for Symbol {
    fn from(symbol: LibrarySymbol) -> Self {
        Symbol::Library(symbol)
    }
}

impl From<ImportSymbol> for Symbol {
    fn from(symbol: ImportSymbol) -> Self {
        Symbol::Import(symbol)
    }
}

impl From<ExportSymbol> for Symbol {
    fn from(symbol: ExportSymbol) -> Self {
        Symbol::Export(symbol)
    }
}

impl From<ParameterSymbol> for Symbol {
    fn from(symbol: ParameterSymbol) -> Self {
        Symbol::Parameter(symbol)
    }
}

impl From<LocalVarSymbol> for Symbol {
    fn from(symbol: LocalVarSymbol) -> Self {
        Symbol::LocalVar(symbol)
    }
}

impl From<GlobalVarSymbol> for Symbol {
    fn from(symbol: GlobalVarSymbol) -> Self {
        Symbol::GlobalVar(symbol)
    }
}

impl AsRef<dyn SymbolApi> for Symbol {
    fn as_ref(&self) -> &(dyn SymbolApi + 'static) {
        self
    }
}

impl LabelSymbol {
    /// Returns the namespace id for this label.
    pub fn namespace_id(&self) -> u64 {
        self.namespace_id
    }

    /// Returns true if this label is dynamic.
    pub fn is_dynamic_label(&self) -> bool {
        self.dynamic
    }

    /// Returns the attached references for this label.
    pub fn references(&self) -> &[Reference] {
        &self.references
    }
}

impl FunctionSymbol {
    /// Returns the namespace id for this function symbol.
    pub fn namespace_id(&self) -> u64 {
        self.namespace_id
    }
}

impl Namespace for GlobalSymbol {
    fn get_symbol(&self) -> &dyn SymbolApi {
        self
    }

    fn get_type(&self) -> SymbolType {
        SymbolType::Global
    }

    fn is_external(&self) -> bool {
        false
    }

    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_name_full(&self, _include_namespace_path: bool) -> String {
        self.name.clone()
    }

    fn get_id(&self) -> u64 {
        0
    }

    fn get_parent_namespace(&self) -> Option<&dyn Namespace> {
        None
    }

    fn get_body(&self) -> Vec<Address> {
        Vec::new()
    }

    fn set_parent_namespace(
        &mut self,
        _parent: &dyn Namespace,
    ) -> SymbolResult<()> {
        Err(SymbolError::UnsupportedOperation(
            "Cannot change parent of global namespace".to_string(),
        ))
    }
}

impl Namespace for FunctionSymbol {
    fn get_symbol(&self) -> &dyn SymbolApi {
        self
    }

    fn get_type(&self) -> SymbolType {
        SymbolType::Function
    }

    fn is_external(&self) -> bool {
        self.address.is_external_address()
    }

    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_name_full(&self, include_namespace_path: bool) -> String {
        if include_namespace_path {
            format!("Global::{}", self.name)
        } else {
            self.name.clone()
        }
    }

    fn get_id(&self) -> u64 {
        self.id
    }

    fn get_parent_namespace(&self) -> Option<&dyn Namespace> {
        None
    }

    fn get_body(&self) -> Vec<Address> {
        vec![self.address]
    }

    fn set_parent_namespace(
        &mut self,
        parent: &dyn Namespace,
    ) -> SymbolResult<()> {
        self.set_namespace(parent)
    }
}

impl Reference {
    /// Returns true if the reference is a call flow.
    pub fn is_call(&self) -> bool {
        self.ref_type.is_call()
    }

    /// Returns true if the reference is any jump/branch flow.
    pub fn is_jump(&self) -> bool {
        self.ref_type.is_jump()
    }

    /// Returns true if the reference is fallthrough.
    pub fn is_fallthrough(&self) -> bool {
        self.ref_type.is_fallthrough()
    }

    /// Returns true if the reference is data-only.
    pub fn is_data(&self) -> bool {
        self.ref_type.is_data()
    }

    /// Returns true if the reference is a flow reference.
    pub fn is_flow(&self) -> bool {
        self.ref_type.is_flow()
    }
}

impl ReferenceManager {
    /// Returns an iterator over all references.
    pub fn iter(&self) -> impl Iterator<Item = &Reference> {
        self.references.iter()
    }

    /// Returns all references as a slice.
    pub fn as_slice(&self) -> &[Reference] {
        &self.references
    }

    /// Returns true if there are no references.
    pub fn is_empty(&self) -> bool {
        self.references.is_empty()
    }

    /// Returns the total number of stored references.
    pub fn len(&self) -> usize {
        self.references.len()
    }

    /// Returns the next internal reference id value.
    pub fn next_id(&self) -> u64 {
        self.next_id
    }
}

impl<'a> IntoIterator for &'a ReferenceManager {
    type Item = &'a Reference;
    type IntoIter = std::slice::Iter<'a, Reference>;

    fn into_iter(self) -> Self::IntoIter {
        self.references.iter()
    }
}

impl<'a> IntoIterator for &'a SymbolPath {
    type Item = &'a String;
    type IntoIter = std::slice::Iter<'a, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.segments.iter()
    }
}

impl ExactSizeIterator for ReferenceIterator {}

impl std::iter::FusedIterator for ReferenceIterator {}

impl SymbolTable for Vec<Symbol> {
    fn create_label(
        &mut self,
        addr: Address,
        name: &str,
        source: SourceType,
    ) -> SymbolResult<&dyn SymbolApi> {
        validate_symbol_name(name)?;
        self.push(Symbol::Label(LabelSymbol::with_options(0, name, addr, 0, source)));
        Ok(self.last().unwrap())
    }

    fn create_label_in_namespace(
        &mut self,
        addr: Address,
        name: &str,
        namespace: &dyn Namespace,
        source: SourceType,
    ) -> SymbolResult<&dyn SymbolApi> {
        validate_symbol_name(name)?;
        self.push(Symbol::Label(LabelSymbol::with_options(
            0,
            name,
            addr,
            namespace.get_id(),
            source,
        )));
        Ok(self.last().unwrap())
    }

    fn remove_symbol_special(&mut self, sym: &dyn SymbolApi) -> bool {
        if let Some(index) = self.iter().position(|candidate| candidate.get_id() == sym.get_id()) {
            let mut removed = self.remove(index);
            removed.delete()
        } else {
            false
        }
    }

    fn get_symbol(&self, symbol_id: u64) -> Option<&dyn SymbolApi> {
        self.iter()
            .find(|symbol| symbol.get_id() == symbol_id)
            .map(|symbol| symbol as &dyn SymbolApi)
    }

    fn get_symbol_by_name_addr_namespace(
        &self,
        name: &str,
        addr: Address,
        namespace: &dyn Namespace,
    ) -> Option<&dyn SymbolApi> {
        self.iter()
            .find(|symbol| {
                symbol.get_name() == name
                    && *symbol.get_address() == addr
                    && symbol
                        .get_parent_namespace()
                        .map(|parent| parent.get_id())
                        .unwrap_or(0)
                        == namespace.get_id()
            })
            .map(|symbol| symbol as &dyn SymbolApi)
    }

    fn get_global_symbol(&self, name: &str, addr: Address) -> Option<&dyn SymbolApi> {
        self.iter()
            .find(|symbol| symbol.get_name() == name && *symbol.get_address() == addr && symbol.is_global())
            .map(|symbol| symbol as &dyn SymbolApi)
    }

    fn get_global_symbols(&self, name: &str) -> Vec<&dyn SymbolApi> {
        self.iter()
            .filter(|symbol| symbol.get_name() == name && symbol.is_global())
            .map(|symbol| symbol as &dyn SymbolApi)
            .collect()
    }

    fn get_label_or_function_symbols(
        &self,
        name: &str,
        namespace: &dyn Namespace,
    ) -> Vec<&dyn SymbolApi> {
        self.iter()
            .filter(|symbol| {
                symbol.get_name() == name
                    && matches!(symbol.get_symbol_type(), SymbolType::Label | SymbolType::Function)
                    && symbol.namespace_id() == Some(namespace.get_id())
            })
            .map(|symbol| symbol as &dyn SymbolApi)
            .collect()
    }

    fn get_namespace_symbol(
        &self,
        name: &str,
        namespace: &dyn Namespace,
    ) -> Option<&dyn SymbolApi> {
        self.iter()
            .find(|symbol| {
                symbol.get_name() == name
                    && symbol.kind().is_namespace()
                    && symbol.namespace_id() == Some(namespace.get_id())
            })
            .map(|symbol| symbol as &dyn SymbolApi)
    }

    fn get_library_symbol(&self, name: &str) -> Option<&dyn SymbolApi> {
        self.iter()
            .find(|symbol| symbol.get_name() == name && symbol.get_symbol_type() == SymbolType::Library)
            .map(|symbol| symbol as &dyn SymbolApi)
    }

    fn get_class_symbol(
        &self,
        name: &str,
        namespace: &dyn Namespace,
    ) -> Option<&dyn SymbolApi> {
        self.iter()
            .find(|symbol| {
                symbol.get_name() == name
                    && symbol.get_symbol_type() == SymbolType::Class
                    && symbol.namespace_id() == Some(namespace.get_id())
            })
            .map(|symbol| symbol as &dyn SymbolApi)
    }

    fn get_symbols_by_name_and_namespace(
        &self,
        name: &str,
        namespace: &dyn Namespace,
    ) -> Vec<&dyn SymbolApi> {
        self.iter()
            .filter(|symbol| symbol.get_name() == name && symbol.namespace_id() == Some(namespace.get_id()))
            .map(|symbol| symbol as &dyn SymbolApi)
            .collect()
    }

    fn get_symbols_by_name(&self, name: &str) -> Vec<&dyn SymbolApi> {
        self.iter()
            .filter(|symbol| symbol.get_name() == name)
            .map(|symbol| symbol as &dyn SymbolApi)
            .collect()
    }

    fn get_all_symbols(&self, include_dynamic: bool) -> Vec<&dyn SymbolApi> {
        self.iter()
            .filter(|symbol| include_dynamic || !symbol.is_dynamic())
            .map(|symbol| symbol as &dyn SymbolApi)
            .collect()
    }

    fn get_primary_symbol(&self, addr: Address) -> Option<&dyn SymbolApi> {
        self.iter()
            .find(|symbol| *symbol.get_address() == addr && symbol.is_primary())
            .map(|symbol| symbol as &dyn SymbolApi)
    }

    fn get_symbols_at(&self, addr: Address) -> Vec<&dyn SymbolApi> {
        self.iter()
            .filter(|symbol| *symbol.get_address() == addr)
            .map(|symbol| symbol as &dyn SymbolApi)
            .collect()
    }

    fn get_user_symbols(&self, addr: Address) -> Vec<&dyn SymbolApi> {
        self.iter()
            .filter(|symbol| *symbol.get_address() == addr && !symbol.is_dynamic())
            .map(|symbol| symbol as &dyn SymbolApi)
            .collect()
    }

    fn has_symbol(&self, addr: Address) -> bool {
        self.iter().any(|symbol| *symbol.get_address() == addr)
    }

    fn get_namespace(
        &self,
        name: &str,
        namespace: &dyn Namespace,
    ) -> Option<&dyn Namespace> {
        self.iter()
            .find(|symbol| {
                symbol.get_name() == name
                    && symbol.kind().is_namespace()
                    && symbol.namespace_id() == Some(namespace.get_id())
            })
            .and_then(|symbol| symbol.as_namespace())
    }

    fn get_namespace_for_address(&self, _addr: Address) -> Option<&dyn Namespace> {
        None
    }

    fn get_num_symbols(&self) -> usize {
        self.len()
    }

    fn get_label_history(&self, _addr: Address) -> Vec<LabelHistory> {
        Vec::new()
    }

    fn has_label_history(&self, _addr: Address) -> bool {
        false
    }

    fn add_external_entry_point(&mut self, _addr: Address) {}

    fn remove_external_entry_point(&mut self, _addr: Address) {}

    fn is_external_entry_point(&self, _addr: Address) -> bool {
        false
    }

    fn create_class(
        &mut self,
        parent: &dyn Namespace,
        name: &str,
        source: SourceType,
    ) -> SymbolResult<Box<dyn Namespace>> {
        validate_symbol_name(name)?;
        let sym = ClassSymbol::new(0, name, parent.get_id(), source);
        self.push(Symbol::Class(sym.clone()));
        Ok(Box::new(sym))
    }

    fn create_external_library(
        &mut self,
        name: &str,
        source: SourceType,
    ) -> SymbolResult<Box<dyn Namespace>> {
        validate_symbol_name(name)?;
        let sym = LibrarySymbol::new(0, name, source);
        self.push(Symbol::Library(sym.clone()));
        Ok(Box::new(sym))
    }

    fn create_namespace(
        &mut self,
        parent: &dyn Namespace,
        name: &str,
        source: SourceType,
    ) -> SymbolResult<Box<dyn Namespace>> {
        validate_symbol_name(name)?;
        let sym = NamespaceSymbol::new(0, name, parent.get_id(), source);
        self.push(Symbol::Namespace(sym.clone()));
        Ok(Box::new(sym))
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
            Symbol::Namespace(s) => SymbolApi::get_address(s),
            Symbol::Class(s) => SymbolApi::get_address(s),
            Symbol::Library(s) => SymbolApi::get_address(s),
            Symbol::Import(s) => SymbolApi::get_address(s),
            Symbol::Export(s) => SymbolApi::get_address(s),
            Symbol::Parameter(s) => SymbolApi::get_address(s),
            Symbol::LocalVar(s) => SymbolApi::get_address(s),
            Symbol::GlobalVar(s) => SymbolApi::get_address(s),
        }
    }
    fn get_name(&self) -> String {
        match self {
            Symbol::Label(s) => SymbolApi::get_name(s),
            Symbol::Function(s) => SymbolApi::get_name(s),
            Symbol::Global(s) => SymbolApi::get_name(s),
            Symbol::Namespace(s) => SymbolApi::get_name(s),
            Symbol::Class(s) => SymbolApi::get_name(s),
            Symbol::Library(s) => SymbolApi::get_name(s),
            Symbol::Import(s) => SymbolApi::get_name(s),
            Symbol::Export(s) => SymbolApi::get_name(s),
            Symbol::Parameter(s) => SymbolApi::get_name(s),
            Symbol::LocalVar(s) => SymbolApi::get_name(s),
            Symbol::GlobalVar(s) => SymbolApi::get_name(s),
        }
    }
    fn get_path(&self) -> Vec<String> {
        match self {
            Symbol::Label(s) => SymbolApi::get_path(s),
            Symbol::Function(s) => SymbolApi::get_path(s),
            Symbol::Global(s) => SymbolApi::get_path(s),
            Symbol::Namespace(s) => SymbolApi::get_path(s),
            Symbol::Class(s) => SymbolApi::get_path(s),
            Symbol::Library(s) => SymbolApi::get_path(s),
            Symbol::Import(s) => SymbolApi::get_path(s),
            Symbol::Export(s) => SymbolApi::get_path(s),
            Symbol::Parameter(s) => SymbolApi::get_path(s),
            Symbol::LocalVar(s) => SymbolApi::get_path(s),
            Symbol::GlobalVar(s) => SymbolApi::get_path(s),
        }
    }
    fn get_name_qualified(&self, include_namespace: bool) -> String {
        match self {
            Symbol::Label(s) => SymbolApi::get_name_qualified(s, include_namespace),
            Symbol::Function(s) => SymbolApi::get_name_qualified(s, include_namespace),
            Symbol::Global(s) => SymbolApi::get_name_qualified(s, include_namespace),
            Symbol::Namespace(s) => SymbolApi::get_name_qualified(s, include_namespace),
            Symbol::Class(s) => SymbolApi::get_name_qualified(s, include_namespace),
            Symbol::Library(s) => SymbolApi::get_name_qualified(s, include_namespace),
            Symbol::Import(s) => SymbolApi::get_name_qualified(s, include_namespace),
            Symbol::Export(s) => SymbolApi::get_name_qualified(s, include_namespace),
            Symbol::Parameter(s) => SymbolApi::get_name_qualified(s, include_namespace),
            Symbol::LocalVar(s) => SymbolApi::get_name_qualified(s, include_namespace),
            Symbol::GlobalVar(s) => SymbolApi::get_name_qualified(s, include_namespace),
        }
    }
    fn get_parent_namespace(&self) -> Option<&dyn Namespace> { None }
    fn get_parent_symbol(&self) -> Option<&dyn SymbolApi> { None }
    fn is_descendant(&self, namespace: &dyn Namespace) -> bool {
        match self {
            Symbol::Label(s) => SymbolApi::is_descendant(s, namespace),
            Symbol::Function(s) => SymbolApi::is_descendant(s, namespace),
            Symbol::Global(s) => SymbolApi::is_descendant(s, namespace),
            Symbol::Namespace(s) => SymbolApi::is_descendant(s, namespace),
            Symbol::Class(s) => SymbolApi::is_descendant(s, namespace),
            Symbol::Library(s) => SymbolApi::is_descendant(s, namespace),
            Symbol::Import(s) => SymbolApi::is_descendant(s, namespace),
            Symbol::Export(s) => SymbolApi::is_descendant(s, namespace),
            Symbol::Parameter(s) => SymbolApi::is_descendant(s, namespace),
            Symbol::LocalVar(s) => SymbolApi::is_descendant(s, namespace),
            Symbol::GlobalVar(s) => SymbolApi::is_descendant(s, namespace),
        }
    }
    fn is_valid_parent(&self, parent: &dyn Namespace) -> bool {
        match self {
            Symbol::Label(s) => SymbolApi::is_valid_parent(s, parent),
            Symbol::Function(s) => SymbolApi::is_valid_parent(s, parent),
            Symbol::Global(s) => SymbolApi::is_valid_parent(s, parent),
            Symbol::Namespace(s) => SymbolApi::is_valid_parent(s, parent),
            Symbol::Class(s) => SymbolApi::is_valid_parent(s, parent),
            Symbol::Library(s) => SymbolApi::is_valid_parent(s, parent),
            Symbol::Import(s) => SymbolApi::is_valid_parent(s, parent),
            Symbol::Export(s) => SymbolApi::is_valid_parent(s, parent),
            Symbol::Parameter(s) => SymbolApi::is_valid_parent(s, parent),
            Symbol::LocalVar(s) => SymbolApi::is_valid_parent(s, parent),
            Symbol::GlobalVar(s) => SymbolApi::is_valid_parent(s, parent),
        }
    }
    fn get_symbol_type(&self) -> SymbolType {
        match self {
            Symbol::Label(s) => SymbolApi::get_symbol_type(s),
            Symbol::Function(s) => SymbolApi::get_symbol_type(s),
            Symbol::Global(s) => SymbolApi::get_symbol_type(s),
            Symbol::Namespace(s) => SymbolApi::get_symbol_type(s),
            Symbol::Class(s) => SymbolApi::get_symbol_type(s),
            Symbol::Library(s) => SymbolApi::get_symbol_type(s),
            Symbol::Import(s) => SymbolApi::get_symbol_type(s),
            Symbol::Export(s) => SymbolApi::get_symbol_type(s),
            Symbol::Parameter(s) => SymbolApi::get_symbol_type(s),
            Symbol::LocalVar(s) => SymbolApi::get_symbol_type(s),
            Symbol::GlobalVar(s) => SymbolApi::get_symbol_type(s),
        }
    }
    fn get_id(&self) -> u64 {
        match self {
            Symbol::Label(s) => SymbolApi::get_id(s),
            Symbol::Function(s) => SymbolApi::get_id(s),
            Symbol::Global(s) => SymbolApi::get_id(s),
            Symbol::Namespace(s) => SymbolApi::get_id(s),
            Symbol::Class(s) => SymbolApi::get_id(s),
            Symbol::Library(s) => SymbolApi::get_id(s),
            Symbol::Import(s) => SymbolApi::get_id(s),
            Symbol::Export(s) => SymbolApi::get_id(s),
            Symbol::Parameter(s) => SymbolApi::get_id(s),
            Symbol::LocalVar(s) => SymbolApi::get_id(s),
            Symbol::GlobalVar(s) => SymbolApi::get_id(s),
        }
    }
    fn is_global(&self) -> bool {
        match self {
            Symbol::Label(s) => SymbolApi::is_global(s),
            Symbol::Function(s) => SymbolApi::is_global(s),
            Symbol::Global(s) => SymbolApi::is_global(s),
            Symbol::Namespace(s) => SymbolApi::is_global(s),
            Symbol::Class(s) => SymbolApi::is_global(s),
            Symbol::Library(s) => SymbolApi::is_global(s),
            Symbol::Import(s) => SymbolApi::is_global(s),
            Symbol::Export(s) => SymbolApi::is_global(s),
            Symbol::Parameter(s) => SymbolApi::is_global(s),
            Symbol::LocalVar(s) => SymbolApi::is_global(s),
            Symbol::GlobalVar(s) => SymbolApi::is_global(s),
        }
    }
    fn is_external(&self) -> bool {
        match self {
            Symbol::Label(s) => SymbolApi::is_external(s),
            Symbol::Function(s) => SymbolApi::is_external(s),
            Symbol::Global(s) => SymbolApi::is_external(s),
            Symbol::Namespace(s) => SymbolApi::is_external(s),
            Symbol::Class(s) => SymbolApi::is_external(s),
            Symbol::Library(s) => SymbolApi::is_external(s),
            Symbol::Import(s) => SymbolApi::is_external(s),
            Symbol::Export(s) => SymbolApi::is_external(s),
            Symbol::Parameter(s) => SymbolApi::is_external(s),
            Symbol::LocalVar(s) => SymbolApi::is_external(s),
            Symbol::GlobalVar(s) => SymbolApi::is_external(s),
        }
    }
    fn is_primary(&self) -> bool {
        match self {
            Symbol::Label(s) => SymbolApi::is_primary(s),
            Symbol::Function(s) => SymbolApi::is_primary(s),
            Symbol::Global(s) => SymbolApi::is_primary(s),
            Symbol::Import(s) => SymbolApi::is_primary(s),
            Symbol::Export(s) => SymbolApi::is_primary(s),
            _ => false,
        }
    }
    fn set_primary(&mut self) -> bool {
        match self {
            Symbol::Label(s) => s.set_primary(),
            Symbol::Function(s) => s.set_primary(),
            Symbol::Import(s) => s.set_primary(),
            Symbol::Export(s) => s.set_primary(),
            _ => false,
        }
    }
    fn is_pinned(&self) -> bool {
        match self {
            Symbol::Label(s) => SymbolApi::is_pinned(s),
            Symbol::Function(s) => SymbolApi::is_pinned(s),
            _ => false,
        }
    }
    fn set_pinned(&mut self, pinned: bool) -> SymbolResult<()> {
        match self {
            Symbol::Label(s) => s.set_pinned(pinned),
            Symbol::Function(s) => s.set_pinned(pinned),
            _ => Err(SymbolError::UnsupportedOperation(
                "Only Code and Function Symbols may be pinned.".to_string(),
            )),
        }
    }
    fn is_dynamic(&self) -> bool {
        match self {
            Symbol::Label(s) => SymbolApi::is_dynamic(s),
            Symbol::Function(s) => SymbolApi::is_dynamic(s),
            _ => false,
        }
    }
    fn get_source(&self) -> SourceType {
        match self {
            Symbol::Label(s) => SymbolApi::get_source(s),
            Symbol::Function(s) => SymbolApi::get_source(s),
            Symbol::Global(s) => SymbolApi::get_source(s),
            Symbol::Namespace(s) => SymbolApi::get_source(s),
            Symbol::Class(s) => SymbolApi::get_source(s),
            Symbol::Library(s) => SymbolApi::get_source(s),
            Symbol::Import(s) => SymbolApi::get_source(s),
            Symbol::Export(s) => SymbolApi::get_source(s),
            Symbol::Parameter(s) => SymbolApi::get_source(s),
            Symbol::LocalVar(s) => SymbolApi::get_source(s),
            Symbol::GlobalVar(s) => SymbolApi::get_source(s),
        }
    }
    fn set_source(&mut self, source: SourceType) {
        match self {
            Symbol::Label(s) => s.set_source(source),
            Symbol::Function(s) => s.set_source(source),
            Symbol::Namespace(s) => s.set_source(source),
            Symbol::Class(s) => s.set_source(source),
            Symbol::Library(s) => s.set_source(source),
            Symbol::Import(s) => s.set_source(source),
            Symbol::Export(s) => s.set_source(source),
            Symbol::Parameter(s) => s.set_source(source),
            Symbol::LocalVar(s) => s.set_source(source),
            Symbol::GlobalVar(s) => s.set_source(source),
            Symbol::Global(_) => {}
        }
    }
    fn is_deleted(&self) -> bool {
        match self {
            Symbol::Label(s) => SymbolApi::is_deleted(s),
            Symbol::Function(s) => SymbolApi::is_deleted(s),
            Symbol::Global(s) => SymbolApi::is_deleted(s),
            Symbol::Namespace(s) => SymbolApi::is_deleted(s),
            Symbol::Class(s) => SymbolApi::is_deleted(s),
            Symbol::Library(s) => SymbolApi::is_deleted(s),
            Symbol::Import(s) => SymbolApi::is_deleted(s),
            Symbol::Export(s) => SymbolApi::is_deleted(s),
            Symbol::Parameter(s) => SymbolApi::is_deleted(s),
            Symbol::LocalVar(s) => SymbolApi::is_deleted(s),
            Symbol::GlobalVar(s) => SymbolApi::is_deleted(s),
        }
    }
    fn set_name(&mut self, new_name: &str, source: SourceType) -> SymbolResult<()> {
        match self {
            Symbol::Label(s) => s.set_name(new_name, source),
            Symbol::Function(s) => s.set_name(new_name, source),
            Symbol::Namespace(s) => s.set_name(new_name, source),
            Symbol::Class(s) => s.set_name(new_name, source),
            Symbol::Library(s) => s.set_name(new_name, source),
            Symbol::Import(s) => s.set_name(new_name, source),
            Symbol::Export(s) => s.set_name(new_name, source),
            Symbol::Parameter(s) => s.set_name(new_name, source),
            Symbol::LocalVar(s) => s.set_name(new_name, source),
            Symbol::GlobalVar(s) => s.set_name(new_name, source),
            Symbol::Global(_) => Err(SymbolError::UnsupportedOperation(
                "Cannot rename global symbol".to_string(),
            )),
        }
    }
    fn set_namespace(&mut self, new_namespace: &dyn Namespace) -> SymbolResult<()> {
        match self {
            Symbol::Label(s) => s.set_namespace(new_namespace),
            Symbol::Function(s) => s.set_namespace(new_namespace),
            Symbol::Namespace(s) => s.set_namespace(new_namespace),
            Symbol::Class(s) => s.set_namespace(new_namespace),
            Symbol::Library(s) => s.set_namespace(new_namespace),
            Symbol::Import(s) => s.set_namespace(new_namespace),
            Symbol::Export(s) => s.set_namespace(new_namespace),
            Symbol::GlobalVar(s) => s.set_namespace(new_namespace),
            Symbol::Global(_) => Err(SymbolError::UnsupportedOperation(
                "Cannot move global symbol".to_string(),
            )),
            Symbol::Parameter(_) => Err(SymbolError::UnsupportedOperation(
                "Cannot move parameter symbol".to_string(),
            )),
            Symbol::LocalVar(_) => Err(SymbolError::UnsupportedOperation(
                "Cannot move local variable symbol".to_string(),
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
            Symbol::Label(s) => s.set_name_and_namespace(new_name, new_namespace, source),
            Symbol::Function(s) => s.set_name_and_namespace(new_name, new_namespace, source),
            Symbol::Namespace(s) => s.set_name_and_namespace(new_name, new_namespace, source),
            Symbol::Class(s) => s.set_name_and_namespace(new_name, new_namespace, source),
            Symbol::Library(s) => s.set_name_and_namespace(new_name, new_namespace, source),
            Symbol::Import(s) => s.set_name_and_namespace(new_name, new_namespace, source),
            Symbol::Export(s) => s.set_name_and_namespace(new_name, new_namespace, source),
            Symbol::GlobalVar(s) => s.set_name_and_namespace(new_name, new_namespace, source),
            Symbol::Global(_) => Err(SymbolError::UnsupportedOperation(
                "Cannot rename or move global symbol".to_string(),
            )),
            Symbol::Parameter(s) => s.set_name_and_namespace(new_name, new_namespace, source),
            Symbol::LocalVar(s) => s.set_name_and_namespace(new_name, new_namespace, source),
        }
    }
    fn delete(&mut self) -> bool {
        match self {
            Symbol::Label(s) => s.delete(),
            Symbol::Function(s) => s.delete(),
            Symbol::Namespace(s) => s.delete(),
            Symbol::Class(s) => s.delete(),
            Symbol::Library(s) => s.delete(),
            Symbol::Import(s) => s.delete(),
            Symbol::Export(s) => s.delete(),
            Symbol::Parameter(s) => s.delete(),
            Symbol::LocalVar(s) => s.delete(),
            Symbol::GlobalVar(s) => s.delete(),
            Symbol::Global(_) => false,
        }
    }
}

// ---------------------------------------------------------------------------
// AddressLabelPair  (AddressLabelPair.java)
// ---------------------------------------------------------------------------

/// Container for holding an address and label.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AddressLabelPair {
    addr: Address,
    label: String,
}

impl AddressLabelPair {
    pub fn new(addr: Address, label: impl Into<String>) -> Self {
        Self { addr, label: label.into() }
    }
    pub fn get_address(&self) -> &Address { &self.addr }
    pub fn get_label(&self) -> &str { &self.label }
}

impl fmt::Display for AddressLabelPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.addr, self.label)
    }
}

// ---------------------------------------------------------------------------
// DynamicReference  (DynamicReference.java)
// ---------------------------------------------------------------------------

/// Marker trait for dynamically determined references which may not be
/// explicitly added, deleted or modified.
pub trait DynamicReference {
    /// Returns the from address.
    fn get_from_address(&self) -> &Address;
    /// Returns the to address.
    fn get_to_address(&self) -> &Address;
    /// Returns the reference type.
    fn get_reference_type(&self) -> RefType;
    /// Returns the operand index.
    fn get_operand_index(&self) -> i32;
    /// Returns the symbol ID.
    fn get_symbol_id(&self) -> i64;
    /// Returns `true` if primary.
    fn is_primary(&self) -> bool;
    /// Returns the source.
    fn get_source(&self) -> SourceType;
    /// Returns `true` if this is a memory reference.
    fn is_memory_reference(&self) -> bool;
    /// Returns `true` if this is a register reference.
    fn is_register_reference(&self) -> bool;
    /// Returns `true` if this is a stack reference.
    fn is_stack_reference(&self) -> bool;
    /// Returns `true` if this is an external reference.
    fn is_external_reference(&self) -> bool;
    /// Returns `true` if this is an entry point reference.
    fn is_entry_point_reference(&self) -> bool;
    /// Returns `true` if this is an offset reference.
    fn is_offset_reference(&self) -> bool;
    /// Returns `true` if this is a shifted reference.
    fn is_shifted_reference(&self) -> bool;
}

// ---------------------------------------------------------------------------
// EntryPointReference  (EntryPointReference.java)
// ---------------------------------------------------------------------------

/// Reference object for entry points. Extends the base reference concept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryPointReference {
    from_address: Address,
    to_address: Address,
    ref_type: RefType,
    op_index: i32,
    source: SourceType,
    primary: bool,
}

impl EntryPointReference {
    pub fn new(from_address: Address, to_address: Address, ref_type: RefType, op_index: i32) -> Self {
        Self { from_address, to_address, ref_type, op_index, source: SourceType::Default, primary: false }
    }
    pub fn get_from_address(&self) -> &Address { &self.from_address }
    pub fn get_to_address(&self) -> &Address { &self.to_address }
    pub fn get_reference_type(&self) -> RefType { self.ref_type }
    pub fn get_operand_index(&self) -> i32 { self.op_index }
    pub fn get_source(&self) -> SourceType { self.source }
    pub fn is_primary(&self) -> bool { self.primary }
    pub fn is_entry_point_reference(&self) -> bool { true }
    pub fn is_memory_reference(&self) -> bool { true }
    pub fn is_register_reference(&self) -> bool { false }
    pub fn is_stack_reference(&self) -> bool { false }
    pub fn is_external_reference(&self) -> bool { false }
}

// ---------------------------------------------------------------------------
// EquateReference  (EquateReference.java)
// ---------------------------------------------------------------------------

/// An equate reference consists of an address and an operand index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquateReference {
    address: Address,
    op_index: i16,
    dynamic_hash_value: u64,
}

impl EquateReference {
    pub fn new(address: Address, op_index: i16) -> Self {
        Self { address, op_index, dynamic_hash_value: 0 }
    }
    pub fn with_dynamic_hash(address: Address, op_index: i16, dynamic_hash_value: u64) -> Self {
        Self { address, op_index, dynamic_hash_value }
    }
    pub fn get_address(&self) -> &Address { &self.address }
    pub fn get_op_index(&self) -> i16 { self.op_index }
    pub fn get_dynamic_hash_value(&self) -> u64 { self.dynamic_hash_value }
}

// ---------------------------------------------------------------------------
// Equate  (Equate.java)
// ---------------------------------------------------------------------------

/// An equate defines a relationship between a scalar value and a string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Equate {
    /// The equate name.
    name: String,
    /// The numeric value.
    value: i64,
    /// References where this equate is used.
    references: Vec<EquateReference>,
}

impl Equate {
    pub fn new(name: impl Into<String>, value: i64) -> Self {
        Self { name: name.into(), value, references: Vec::new() }
    }
    pub fn get_name(&self) -> &str { &self.name }
    pub fn get_display_name(&self) -> String { self.name.clone() }
    pub fn get_value(&self) -> i64 { self.value }
    pub fn set_value(&mut self, value: i64) { self.value = value; }
    pub fn get_references(&self) -> &[EquateReference] { &self.references }
    pub fn get_reference_count(&self) -> usize { self.references.len() }
    pub fn add_reference(&mut self, er: EquateReference) { self.references.push(er); }
    pub fn remove_reference(&mut self, address: &Address, op_index: i16) -> bool {
        let len_before = self.references.len();
        self.references.retain(|r| !(r.address == *address && r.op_index == op_index));
        self.references.len() < len_before
    }
    /// Returns the equate name for a given value, or the value as hex string.
    pub fn get_equated_string_masked(value: i64, mask: i64, prefix: &str) -> String {
        let masked = value & mask;
        format!("{}{:X}", prefix, masked)
    }
}

impl fmt::Display for Equate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = 0x{:X}", self.name, self.value)
    }
}

// ---------------------------------------------------------------------------
// EquateTable  (EquateTable.java)
// ---------------------------------------------------------------------------

/// Manages all equates for a program. An equate defines a relationship between
/// a scalar value and a string whereby the scalar may be represented by the string.
pub trait EquateTable: fmt::Debug + Send + Sync {
    /// Creates a new equate.
    fn create_equate(&mut self, name: &str, value: i64) -> SymbolResult<Box<dyn EquateApi>>;
    /// Returns the equate with the given name.
    fn get_equate(&self, name: &str) -> Option<&dyn EquateApi>;
    /// Returns all equates with the given value.
    fn get_equates(&self, value: i64) -> Vec<&dyn EquateApi>;
    /// Returns all equates.
    fn get_all_equates(&self) -> Vec<&dyn EquateApi>;
    /// Removes the equate with the given name.
    fn remove_equate(&mut self, name: &str) -> SymbolResult<()>;
    /// Returns the equate at the given address and operand index.
    fn get_equate_at(&self, address: &Address, op_index: i16) -> Option<&dyn EquateApi>;
    /// Returns all equate references at the given address.
    fn get_equate_references(&self, address: &Address) -> Vec<&dyn EquateApi>;
}

/// Trait object interface for equates (used by EquateTable).
pub trait EquateApi: fmt::Debug + Send + Sync {
    fn get_name(&self) -> String;
    fn get_display_name(&self) -> String;
    fn get_value(&self) -> i64;
    fn set_value(&mut self, value: i64);
    fn get_references(&self) -> &[EquateReference];
    fn get_reference_count(&self) -> usize;
    fn add_reference(&mut self, er: EquateReference);
    fn remove_reference(&mut self, address: &Address, op_index: i16) -> bool;
}

impl EquateApi for Equate {
    fn get_name(&self) -> String { self.name.clone() }
    fn get_display_name(&self) -> String { self.name.clone() }
    fn get_value(&self) -> i64 { self.value }
    fn set_value(&mut self, value: i64) { self.value = value; }
    fn get_references(&self) -> &[EquateReference] { &self.references }
    fn get_reference_count(&self) -> usize { self.references.len() }
    fn add_reference(&mut self, er: EquateReference) { self.references.push(er); }
    fn remove_reference(&mut self, address: &Address, op_index: i16) -> bool {
        let len_before = self.references.len();
        self.references.retain(|r| !(r.address == *address && r.op_index == op_index));
        self.references.len() < len_before
    }
}

// ---------------------------------------------------------------------------
// ExternalPath  (ExternalPath.java)
// ---------------------------------------------------------------------------

/// Represents the path to an external library or namespace.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExternalPath {
    /// Path components (library name, namespace, ...).
    pub segments: Vec<String>,
}

impl ExternalPath {
    const DELIMITER: &'static str = "::";

    /// Creates a new external path from segments. At least 2 segments required.
    pub fn new(segments: Vec<String>) -> SymbolResult<Self> {
        if segments.len() < 2 {
            return Err(SymbolError::InvalidInput(
                "An external path must contain at least 2 segments.".to_string(),
            ));
        }
        for s in &segments {
            if s.is_empty() {
                return Err(SymbolError::InvalidInput(
                    "An external path cannot contain an empty string.".to_string(),
                ));
            }
        }
        Ok(Self { segments })
    }

    /// Creates an external path from library name and label.
    pub fn from_library_and_label(library: impl Into<String>, label: impl Into<String>) -> Self {
        Self { segments: vec![library.into(), label.into()] }
    }

    /// Returns the library name (first segment).
    pub fn get_library_name(&self) -> &str {
        &self.segments[0]
    }

    /// Returns the label (last segment).
    pub fn get_label(&self) -> &str {
        self.segments.last().map(String::as_str).unwrap_or("")
    }

    /// Returns the parent path (all segments except the last).
    pub fn get_parent_path(&self) -> Option<ExternalPath> {
        if self.segments.len() <= 2 {
            None
        } else {
            Some(ExternalPath {
                segments: self.segments[..self.segments.len() - 1].to_vec(),
            })
        }
    }

    /// Returns the full delimited path.
    pub fn to_delimited_string(&self) -> String {
        self.segments.join(Self::DELIMITER)
    }
}

impl fmt::Display for ExternalPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_delimited_string())
    }
}

// ---------------------------------------------------------------------------
// ExternalLocation  (ExternalLocation.java)
// ---------------------------------------------------------------------------

/// Defines a location within an external program (i.e., library).
pub trait ExternalLocation: fmt::Debug + Send + Sync {
    /// Returns the symbol associated with this external location or None.
    fn get_symbol(&self) -> Option<&dyn SymbolApi>;
    /// Returns the name of the external program containing this location.
    fn get_library_name(&self) -> &str;
    /// Returns the external label.
    fn get_label(&self) -> Option<&str>;
    /// Returns the external path.
    fn get_external_path(&self) -> &ExternalPath;
    /// Returns the external address, or None if label-only.
    fn get_address(&self) -> Option<Address>;
    /// Returns the source of this external location.
    fn get_source(&self) -> SourceType;
    /// Returns `true` if this location has an associated function.
    fn is_function(&self) -> bool;
    /// Returns `true` if this location has a data type.
    fn is_data(&self) -> bool;
    /// Sets the label and optionally address.
    fn set(&mut self, label: &str, addr: Option<Address>, source: SourceType) -> SymbolResult<()>;
}

// ---------------------------------------------------------------------------
// ExternalLocationIterator  (ExternalLocationIterator.java)
// ---------------------------------------------------------------------------

/// Iterator over external locations.
pub struct ExternalLocationIterator {
    locations: Vec<ExternalLocationImpl>,
    index: usize,
}

impl ExternalLocationIterator {
    pub fn new(locations: Vec<ExternalLocationImpl>) -> Self {
        Self { locations, index: 0 }
    }
    pub fn has_next(&self) -> bool { self.index < self.locations.len() }
    pub fn peek(&self) -> Option<&ExternalLocationImpl> {
        self.locations.get(self.index)
    }
    pub fn len(&self) -> usize { self.locations.len() }
    pub fn is_empty(&self) -> bool { self.locations.is_empty() }
}

impl Iterator for ExternalLocationIterator {
    type Item = ExternalLocationImpl;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.locations.len() {
            let loc = self.locations[self.index].clone();
            self.index += 1;
            Some(loc)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// ExternalLocationAdapter  (ExternalLocationAdapter.java)
// ---------------------------------------------------------------------------

/// Adapter that wraps any `Iterator` of boxed `ExternalLocation` trait objects
/// into an `ExternalLocationIterator`-compatible interface.
///
/// Corresponds to Ghidra's `ExternalLocationAdapter` which adapts a generic
/// `Iterator<ExternalLocation>` to the `ExternalLocationIterator` interface.
pub struct ExternalLocationAdapter {
    locations: Vec<Box<dyn ExternalLocation>>,
    index: usize,
}

impl ExternalLocationAdapter {
    /// Creates a new adapter from a vector of boxed external locations.
    pub fn new(locations: Vec<Box<dyn ExternalLocation>>) -> Self {
        Self { locations, index: 0 }
    }

    /// Creates an empty adapter.
    pub fn empty() -> Self {
        Self { locations: Vec::new(), index: 0 }
    }

    /// Returns `true` if there are more external locations.
    pub fn has_next(&self) -> bool {
        self.index < self.locations.len()
    }

    /// Returns the number of remaining locations.
    pub fn remaining(&self) -> usize {
        self.locations.len().saturating_sub(self.index)
    }

    /// Returns the total number of locations.
    pub fn len(&self) -> usize {
        self.locations.len()
    }

    /// Returns `true` if there are no locations.
    pub fn is_empty(&self) -> bool {
        self.locations.is_empty()
    }

    /// Resets the iterator to the beginning.
    pub fn reset(&mut self) {
        self.index = 0;
    }

    /// Returns a reference to the next location without advancing.
    pub fn peek(&self) -> Option<&dyn ExternalLocation> {
        self.locations.get(self.index).map(|b| b.as_ref())
    }
}

impl Iterator for ExternalLocationAdapter {
    type Item = Box<dyn ExternalLocation>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.locations.len() {
            let loc = self.locations.remove(self.index);
            // Don't increment index since we removed the element
            Some(loc)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// ExternalLocationImpl  (ExternalLocationAdapter.java / concrete impl)
// ---------------------------------------------------------------------------

/// Concrete implementation of ExternalLocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalLocationImpl {
    external_path: ExternalPath,
    label: Option<String>,
    address: Option<Address>,
    source: SourceType,
    is_function: bool,
    symbol_id: Option<u64>,
}

impl ExternalLocationImpl {
    pub fn new(
        external_path: ExternalPath,
        label: Option<String>,
        address: Option<Address>,
        source: SourceType,
        is_function: bool,
    ) -> Self {
        Self { external_path, label, address, source, is_function, symbol_id: None }
    }

    pub fn get_library_name_str(&self) -> &str {
        self.external_path.get_library_name()
    }
    pub fn get_label_str(&self) -> Option<&str> {
        self.label.as_deref()
    }
    pub fn get_address_opt(&self) -> Option<Address> {
        self.address
    }
    pub fn get_source_type(&self) -> SourceType { self.source }
    pub fn is_function_loc(&self) -> bool { self.is_function }
    pub fn set_symbol_id(&mut self, id: u64) { self.symbol_id = Some(id); }
    pub fn get_symbol_id(&self) -> Option<u64> { self.symbol_id }
}

impl ExternalLocation for ExternalLocationImpl {
    fn get_symbol(&self) -> Option<&dyn SymbolApi> { None }
    fn get_library_name(&self) -> &str { self.external_path.get_library_name() }
    fn get_label(&self) -> Option<&str> { self.label.as_deref() }
    fn get_external_path(&self) -> &ExternalPath { &self.external_path }
    fn get_address(&self) -> Option<Address> { self.address }
    fn get_source(&self) -> SourceType { self.source }
    fn is_function(&self) -> bool { self.is_function }
    fn is_data(&self) -> bool { !self.is_function }
    fn set(&mut self, label: &str, addr: Option<Address>, source: SourceType) -> SymbolResult<()> {
        self.label = Some(label.to_string());
        self.address = addr;
        self.source = source;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ExternalManager  (ExternalManager.java)
// ---------------------------------------------------------------------------

/// Manages external programs and locations within those programs.
pub trait ExternalManager: fmt::Debug + Send + Sync {
    /// Returns all external library names sorted by preferred search order.
    fn get_external_library_names(&self) -> Vec<String>;
    /// Returns the external library with the given name.
    fn get_external_library(&self, name: &str) -> Option<&dyn ExternalLocation>;
    /// Returns the external location for the given address.
    fn get_external_location(&self, addr: Address) -> Option<&dyn ExternalLocation>;
    /// Returns all external locations.
    fn get_external_locations(&self) -> Vec<&dyn ExternalLocation>;
    /// Adds an external library name.
    fn add_external_library_name(&mut self, name: &str, source: SourceType) -> SymbolResult<()>;
    /// Removes an external library name.
    fn remove_external_library_name(&mut self, name: &str) -> SymbolResult<()>;
    /// Returns the external location for the given symbol.
    fn get_location(&self, symbol: &dyn SymbolApi) -> Option<&dyn ExternalLocation>;
    /// Gets the default external location for the given label.
    fn get_default_external_location(&self, label: &str) -> Option<&dyn ExternalLocation>;
    /// Gets all external locations with the given label across all libraries.
    fn get_external_locations_by_label(&self, label: &str) -> Vec<&dyn ExternalLocation>;
}

// ---------------------------------------------------------------------------
// ExternalReference  (ExternalReference.java)
// ---------------------------------------------------------------------------

/// A reference to an external location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalReference {
    from_address: Address,
    to_address: Address,
    ref_type: RefType,
    op_index: i32,
    source: SourceType,
    primary: bool,
    library_name: String,
    label: Option<String>,
    external_path: ExternalPath,
}

impl ExternalReference {
    pub fn new(
        from_address: Address,
        to_address: Address,
        ref_type: RefType,
        op_index: i32,
        library_name: impl Into<String>,
        label: Option<String>,
    ) -> Self {
        let lib = library_name.into();
        let lbl = label.clone().unwrap_or_default();
        Self {
            from_address,
            to_address,
            ref_type,
            op_index,
            source: SourceType::Default,
            primary: false,
            library_name: lib.clone(),
            label,
            external_path: ExternalPath::from_library_and_label(lib, lbl),
        }
    }

    pub fn get_from_address(&self) -> &Address { &self.from_address }
    pub fn get_to_address(&self) -> &Address { &self.to_address }
    pub fn get_reference_type(&self) -> RefType { self.ref_type }
    pub fn get_operand_index(&self) -> i32 { self.op_index }
    pub fn get_source(&self) -> SourceType { self.source }
    pub fn is_primary(&self) -> bool { self.primary }
    pub fn is_memory_reference(&self) -> bool { true }
    pub fn is_register_reference(&self) -> bool { false }
    pub fn is_stack_reference(&self) -> bool { false }
    pub fn is_external_reference(&self) -> bool { true }
    pub fn is_entry_point_reference(&self) -> bool { false }
    pub fn is_offset_reference(&self) -> bool { false }
    pub fn is_shifted_reference(&self) -> bool { false }
    pub fn get_library_name(&self) -> &str { &self.library_name }
    pub fn get_label(&self) -> Option<&str> { self.label.as_deref() }
    pub fn get_external_location_ref(&self) -> &ExternalPath { &self.external_path }
}

// ---------------------------------------------------------------------------
// NameTransformer  (NameTransformer.java)
// ---------------------------------------------------------------------------

/// Interface to transform (shorten, simplify) names for display.
pub trait NameTransformer {
    /// Return a transformed version of the given input. If no change is made,
    /// returns the input unchanged.
    fn simplify(&self, input: &str) -> String;
}

// ---------------------------------------------------------------------------
// IdentityNameTransformer  (IdentityNameTransformer.java)
// ---------------------------------------------------------------------------

/// A name transformer that returns the input unchanged.
#[derive(Debug, Clone, Copy, Default)]
pub struct IdentityNameTransformer;

impl NameTransformer for IdentityNameTransformer {
    fn simplify(&self, input: &str) -> String {
        input.to_string()
    }
}

// ---------------------------------------------------------------------------
// IllegalCharCppTransformer  (IllegalCharCppTransformer.java)
// ---------------------------------------------------------------------------

/// A name transformer that replaces illegal C++ identifier characters with '_'.
///
/// Treats the name as a C++ symbol. Letters and digits are generally legal.
/// '~' is allowed at the start. Template parameters allow additional special
/// characters. Certain special characters are allowed after "operator".
#[derive(Debug, Clone)]
pub struct IllegalCharCppTransformer {
    legal_chars: [u8; 128],
}

const AFTER_FIRST_CHAR: u8 = 1;
const TEMPLATE: u8 = 2;
const OPERATOR: u8 = 4;
const FIRST_CHAR_FLAG: u8 = 8;

impl IllegalCharCppTransformer {
    pub fn new() -> Self {
        let mut legal_chars = [0u8; 128];
        legal_chars[b'_' as usize] = AFTER_FIRST_CHAR | TEMPLATE | OPERATOR | FIRST_CHAR_FLAG;
        legal_chars[b'0' as usize] = AFTER_FIRST_CHAR | TEMPLATE | OPERATOR;
        legal_chars[b'1' as usize] = AFTER_FIRST_CHAR | TEMPLATE | OPERATOR;
        legal_chars[b'2' as usize] = AFTER_FIRST_CHAR | TEMPLATE | OPERATOR;
        legal_chars[b'3' as usize] = AFTER_FIRST_CHAR | TEMPLATE | OPERATOR;
        legal_chars[b'4' as usize] = AFTER_FIRST_CHAR | TEMPLATE | OPERATOR;
        legal_chars[b'5' as usize] = AFTER_FIRST_CHAR | TEMPLATE | OPERATOR;
        legal_chars[b'6' as usize] = AFTER_FIRST_CHAR | TEMPLATE | OPERATOR;
        legal_chars[b'7' as usize] = AFTER_FIRST_CHAR | TEMPLATE | OPERATOR;
        legal_chars[b'8' as usize] = AFTER_FIRST_CHAR | TEMPLATE | OPERATOR;
        legal_chars[b'9' as usize] = AFTER_FIRST_CHAR | TEMPLATE | OPERATOR;
        legal_chars[b'~' as usize] = FIRST_CHAR_FLAG;
        legal_chars[b'(' as usize] = OPERATOR;
        legal_chars[b')' as usize] = OPERATOR;
        legal_chars[b'+' as usize] = OPERATOR;
        legal_chars[b'-' as usize] = OPERATOR;
        legal_chars[b'*' as usize] = OPERATOR;
        legal_chars[b'/' as usize] = OPERATOR;
        legal_chars[b'%' as usize] = OPERATOR;
        legal_chars[b'^' as usize] = OPERATOR;
        legal_chars[b'&' as usize] = OPERATOR;
        legal_chars[b'|' as usize] = OPERATOR;
        legal_chars[b'!' as usize] = OPERATOR;
        legal_chars[b'=' as usize] = OPERATOR;
        legal_chars[b'<' as usize] = OPERATOR;
        legal_chars[b'>' as usize] = OPERATOR;
        legal_chars[b'[' as usize] = OPERATOR;
        legal_chars[b']' as usize] = OPERATOR;
        legal_chars[b' ' as usize] = OPERATOR;
        legal_chars[b',' as usize] = TEMPLATE;
        Self { legal_chars }
    }
}

impl Default for IllegalCharCppTransformer {
    fn default() -> Self { Self::new() }
}

impl NameTransformer for IllegalCharCppTransformer {
    fn simplify(&self, input: &str) -> String {
        let chars: Vec<char> = input.chars().collect();
        let mut template_depth: i32 = 0;
        let mut transform: Option<Vec<char>> = None;

        for (i, &c) in chars.iter().enumerate() {
            if c.is_alphabetic() {
                continue;
            }
            if c == '<' {
                template_depth += 1;
                continue;
            }
            if c == '>' {
                template_depth -= 1;
                if template_depth < 0 { template_depth = 0; }
                continue;
            }
            if (c as u32) < 128 {
                let val = self.legal_chars[c as usize];
                if val != 0 {
                    if (val & AFTER_FIRST_CHAR) != 0 && i > 0 { continue; }
                    if (val & FIRST_CHAR_FLAG) != 0 && i == 0 { continue; }
                    if (val & TEMPLATE) != 0 && template_depth > 0 { continue; }
                    if (val & OPERATOR) != 0 && i >= 8 && i <= 10 {
                        if input.starts_with("operator") { continue; }
                    }
                }
            }
            // Illegal character found
            if transform.is_none() {
                transform = Some(chars.clone());
            }
            if let Some(ref mut t) = transform {
                t[i] = '_';
            }
        }
        match transform {
            Some(t) => t.into_iter().collect(),
            None => input.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// MemReferenceImpl  (MemReferenceImpl.java)
// ---------------------------------------------------------------------------

/// Implementation for a reference not associated with a program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemReferenceImpl {
    from_address: Address,
    to_address: Address,
    ref_type: RefType,
    op_index: i32,
    source_type: SourceType,
    symbol_id: i64,
    is_primary: bool,
}

impl MemReferenceImpl {
    pub fn new(
        from_address: Address,
        to_address: Address,
        ref_type: RefType,
        source_type: SourceType,
        op_index: i32,
        is_primary: bool,
    ) -> Self {
        Self {
            from_address,
            to_address,
            ref_type,
            op_index,
            source_type,
            symbol_id: -1,
            is_primary,
        }
    }

    pub fn get_from_address(&self) -> &Address { &self.from_address }
    pub fn get_to_address(&self) -> &Address { &self.to_address }
    pub fn get_reference_type(&self) -> RefType { self.ref_type }
    pub fn set_reference_type(&mut self, ref_type: RefType) { self.ref_type = ref_type; }
    pub fn get_operand_index(&self) -> i32 { self.op_index }
    pub fn get_symbol_id(&self) -> i64 { self.symbol_id }
    pub fn set_symbol_id(&mut self, id: i64) { self.symbol_id = id; }
    pub fn is_primary(&self) -> bool { self.is_primary }
    pub fn set_primary(&mut self, primary: bool) { self.is_primary = primary; }
    pub fn get_source(&self) -> SourceType { self.source_type }
    pub fn set_source(&mut self, source: SourceType) { self.source_type = source; }
    pub fn is_mnemonic_reference(&self) -> bool { self.op_index == MNEMONIC }
    pub fn is_operand_reference(&self) -> bool { self.op_index != MNEMONIC && self.op_index != OTHER_OP_INDEX }
    pub fn is_memory_reference(&self) -> bool { true }
    pub fn is_register_reference(&self) -> bool { false }
    pub fn is_stack_reference(&self) -> bool { false }
    pub fn is_external_reference(&self) -> bool { false }
    pub fn is_entry_point_reference(&self) -> bool { false }
    pub fn is_offset_reference(&self) -> bool { false }
    pub fn is_shifted_reference(&self) -> bool { false }
}

impl PartialOrd for MemReferenceImpl {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MemReferenceImpl {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.from_address
            .cmp(&other.from_address)
            .then_with(|| self.op_index.cmp(&other.op_index))
            .then_with(|| self.to_address.cmp(&other.to_address))
    }
}

// ---------------------------------------------------------------------------
// OffsetReference  (OffsetReference.java)
// ---------------------------------------------------------------------------

/// A memory reference whose "to" address is computed from a base address plus an offset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffsetReference {
    from_address: Address,
    to_address: Address,
    base_address: Address,
    offset: i64,
    ref_type: RefType,
    op_index: i32,
    source: SourceType,
    primary: bool,
}

impl OffsetReference {
    pub fn new(
        from_address: Address,
        to_address: Address,
        base_address: Address,
        offset: i64,
        ref_type: RefType,
        op_index: i32,
    ) -> Self {
        Self {
            from_address,
            to_address,
            base_address,
            offset,
            ref_type,
            op_index,
            source: SourceType::Default,
            primary: false,
        }
    }

    pub fn get_from_address(&self) -> &Address { &self.from_address }
    pub fn get_to_address(&self) -> &Address { &self.to_address }
    pub fn get_base_address(&self) -> &Address { &self.base_address }
    pub fn get_offset(&self) -> i64 { self.offset }
    pub fn get_reference_type(&self) -> RefType { self.ref_type }
    pub fn get_operand_index(&self) -> i32 { self.op_index }
    pub fn get_source(&self) -> SourceType { self.source }
    pub fn is_primary(&self) -> bool { self.primary }
    pub fn is_memory_reference(&self) -> bool { true }
    pub fn is_register_reference(&self) -> bool { false }
    pub fn is_stack_reference(&self) -> bool { false }
    pub fn is_external_reference(&self) -> bool { false }
    pub fn is_entry_point_reference(&self) -> bool { false }
    pub fn is_offset_reference(&self) -> bool { true }
    pub fn is_shifted_reference(&self) -> bool { false }
}

// ---------------------------------------------------------------------------
// ShiftedReference  (ShiftedReference.java)
// ---------------------------------------------------------------------------

/// A memory reference whose "to" address is computed by shifting the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShiftedReference {
    from_address: Address,
    to_address: Address,
    shift_value: i32,
    ref_type: RefType,
    op_index: i32,
    source: SourceType,
    primary: bool,
}

impl ShiftedReference {
    pub fn new(
        from_address: Address,
        to_address: Address,
        shift_value: i32,
        ref_type: RefType,
        op_index: i32,
    ) -> Self {
        Self {
            from_address,
            to_address,
            shift_value,
            ref_type,
            op_index,
            source: SourceType::Default,
            primary: false,
        }
    }

    pub fn get_from_address(&self) -> &Address { &self.from_address }
    pub fn get_to_address(&self) -> &Address { &self.to_address }
    pub fn get_shift_value(&self) -> i32 { self.shift_value }
    pub fn get_reference_type(&self) -> RefType { self.ref_type }
    pub fn get_operand_index(&self) -> i32 { self.op_index }
    pub fn get_source(&self) -> SourceType { self.source }
    pub fn is_primary(&self) -> bool { self.primary }
    pub fn is_memory_reference(&self) -> bool { true }
    pub fn is_register_reference(&self) -> bool { false }
    pub fn is_stack_reference(&self) -> bool { false }
    pub fn is_external_reference(&self) -> bool { false }
    pub fn is_entry_point_reference(&self) -> bool { false }
    pub fn is_offset_reference(&self) -> bool { false }
    pub fn is_shifted_reference(&self) -> bool { true }
}

// ---------------------------------------------------------------------------
// StackReference  (StackReference.java)
// ---------------------------------------------------------------------------

/// A reference to a stack location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackReference {
    from_address: Address,
    to_address: Address,
    stack_offset: i32,
    ref_type: RefType,
    op_index: i32,
    source: SourceType,
    primary: bool,
}

impl StackReference {
    pub fn new(
        from_address: Address,
        stack_offset: i32,
        ref_type: RefType,
        op_index: i32,
    ) -> Self {
        Self {
            from_address,
            to_address: Address::new(stack_offset as u64),
            stack_offset,
            ref_type,
            op_index,
            source: SourceType::Default,
            primary: false,
        }
    }

    pub fn get_from_address(&self) -> &Address { &self.from_address }
    pub fn get_to_address(&self) -> &Address { &self.to_address }
    pub fn get_stack_offset(&self) -> i32 { self.stack_offset }
    pub fn get_reference_type(&self) -> RefType { self.ref_type }
    pub fn get_operand_index(&self) -> i32 { self.op_index }
    pub fn get_source(&self) -> SourceType { self.source }
    pub fn is_primary(&self) -> bool { self.primary }
    pub fn is_memory_reference(&self) -> bool { false }
    pub fn is_register_reference(&self) -> bool { false }
    pub fn is_stack_reference(&self) -> bool { true }
    pub fn is_external_reference(&self) -> bool { false }
    pub fn is_entry_point_reference(&self) -> bool { false }
    pub fn is_offset_reference(&self) -> bool { false }
    pub fn is_shifted_reference(&self) -> bool { false }
}

// ---------------------------------------------------------------------------
// ThunkReference  (ThunkReference.java)
// ---------------------------------------------------------------------------

/// Implementation for a thunk function reference. These references are dynamic
/// in nature and may not be explicitly added, removed or altered. Their presence
/// is inferred by the existence of a thunk function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThunkReference {
    from_address: Address,
    to_address: Address,
}

impl ThunkReference {
    pub fn new(thunk_addr: Address, thunked_addr: Address) -> Self {
        Self { from_address: thunk_addr, to_address: thunked_addr }
    }

    pub fn get_from_address(&self) -> &Address { &self.from_address }
    pub fn get_to_address(&self) -> &Address { &self.to_address }
    pub fn get_reference_type(&self) -> RefType { RefType::THUNK }
    pub fn get_operand_index(&self) -> i32 { OTHER_OP_INDEX }
    pub fn get_symbol_id(&self) -> i64 { -1 }
    pub fn is_primary(&self) -> bool { false }
    pub fn get_source(&self) -> SourceType { SourceType::Default }
    pub fn is_memory_reference(&self) -> bool { false }
    pub fn is_register_reference(&self) -> bool { false }
    pub fn is_stack_reference(&self) -> bool { false }
    pub fn is_external_reference(&self) -> bool { false }
    pub fn is_entry_point_reference(&self) -> bool { false }
    pub fn is_offset_reference(&self) -> bool { false }
    pub fn is_shifted_reference(&self) -> bool { false }
}

impl DynamicReference for ThunkReference {
    fn get_from_address(&self) -> &Address { &self.from_address }
    fn get_to_address(&self) -> &Address { &self.to_address }
    fn get_reference_type(&self) -> RefType { RefType::THUNK }
    fn get_operand_index(&self) -> i32 { OTHER_OP_INDEX }
    fn get_symbol_id(&self) -> i64 { -1 }
    fn is_primary(&self) -> bool { false }
    fn get_source(&self) -> SourceType { SourceType::Default }
    fn is_memory_reference(&self) -> bool { false }
    fn is_register_reference(&self) -> bool { false }
    fn is_stack_reference(&self) -> bool { false }
    fn is_external_reference(&self) -> bool { false }
    fn is_entry_point_reference(&self) -> bool { false }
    fn is_offset_reference(&self) -> bool { false }
    fn is_shifted_reference(&self) -> bool { false }
}

// ---------------------------------------------------------------------------
// RefTypeFactory  (RefTypeFactory.java)
// ---------------------------------------------------------------------------

/// Factory for creating and looking up RefType instances.
pub struct RefTypeFactory;

impl RefTypeFactory {
    /// All valid memory reference types.
    const MEMORY_REF_TYPES: [RefType; 22] = [
        RefType::DATA, RefType::PARAM, RefType::READ, RefType::WRITE,
        RefType::READ_WRITE, RefType::READ_IND, RefType::WRITE_IND,
        RefType::READ_WRITE_IND, RefType::DATA_IND, RefType::EXTERNAL_REF,
        RefType::FALL_THROUGH, RefType::UNCONDITIONAL_JUMP, RefType::CONDITIONAL_JUMP,
        RefType::UNCONDITIONAL_CALL, RefType::CONDITIONAL_CALL,
        RefType::COMPUTED_JUMP, RefType::COMPUTED_CALL,
        RefType::CONDITIONAL_COMPUTED_CALL, RefType::CONDITIONAL_COMPUTED_JUMP,
        RefType::CALL_OVERRIDE_UNCONDITIONAL, RefType::JUMP_OVERRIDE_UNCONDITIONAL,
        RefType::INDIRECTION,
    ];

    /// Valid stack reference types.
    const STACK_REF_TYPES: [RefType; 4] = [
        RefType::DATA, RefType::READ, RefType::WRITE, RefType::READ_WRITE,
    ];

    /// Valid data reference types.
    const DATA_REF_TYPES: [RefType; 5] = [
        RefType::DATA, RefType::PARAM, RefType::READ, RefType::WRITE, RefType::READ_WRITE,
    ];

    /// Valid external reference types.
    const EXTERNAL_REF_TYPES: [RefType; 19] = [
        RefType::COMPUTED_CALL, RefType::COMPUTED_JUMP,
        RefType::CONDITIONAL_CALL, RefType::CONDITIONAL_JUMP,
        RefType::UNCONDITIONAL_CALL, RefType::UNCONDITIONAL_JUMP,
        RefType::CONDITIONAL_COMPUTED_CALL, RefType::CONDITIONAL_COMPUTED_JUMP,
        RefType::DATA, RefType::DATA_IND,
        RefType::READ, RefType::READ_IND,
        RefType::WRITE, RefType::WRITE_IND,
        RefType::READ_WRITE, RefType::READ_WRITE_IND,
        RefType::CALL_OVERRIDE_UNCONDITIONAL,
        RefType::CALLOTHER_OVERRIDE_CALL,
        RefType::CALLOTHER_OVERRIDE_JUMP,
    ];

    /// Returns all valid memory reference types.
    pub fn get_memory_ref_types() -> &'static [RefType] { &Self::MEMORY_REF_TYPES }

    /// Returns all valid stack reference types.
    pub fn get_stack_ref_types() -> &'static [RefType] { &Self::STACK_REF_TYPES }

    /// Returns all valid data reference types.
    pub fn get_data_ref_types() -> &'static [RefType] { &Self::DATA_REF_TYPES }

    /// Returns all valid external reference types.
    pub fn get_external_ref_types() -> &'static [RefType] { &Self::EXTERNAL_REF_TYPES }

    /// Looks up a RefType by its numeric value.
    pub fn get(value: i8) -> Option<RefType> {
        // Check flow types first
        for ft in &[
            FlowType::Invalid, FlowType::Flow, FlowType::FallThrough,
            FlowType::UnconditionalJump, FlowType::ConditionalJump,
            FlowType::UnconditionalCall, FlowType::ConditionalCall,
            FlowType::Terminator, FlowType::ComputedJump,
            FlowType::ConditionalTerminator, FlowType::ComputedCall,
            FlowType::Indirection, FlowType::CallTerminator,
            FlowType::JumpTerminator, FlowType::ConditionalComputedJump,
            FlowType::ConditionalComputedCall, FlowType::ConditionalCallTerminator,
            FlowType::ComputedCallTerminator, FlowType::CallOverrideUnconditional,
            FlowType::JumpOverrideUnconditional, FlowType::CallOtherOverrideCall,
            FlowType::CallOtherOverrideJump,
        ] {
            if ft.value() == value {
                return Some(RefType::Flow(*ft));
            }
        }
        // Check data types
        for dt in &[
            DataRefType::Data, DataRefType::Read, DataRefType::Write,
            DataRefType::ReadWrite, DataRefType::ReadInd, DataRefType::WriteInd,
            DataRefType::ReadWriteInd, DataRefType::Param, DataRefType::ExternalRef,
            DataRefType::DataInd, DataRefType::Thunk,
        ] {
            if dt.value() == value {
                return Some(RefType::Data(*dt));
            }
        }
        None
    }

    /// Returns `true` if the given RefType is a valid memory reference type.
    pub fn is_memory_ref_type(ref_type: RefType) -> bool {
        Self::MEMORY_REF_TYPES.contains(&ref_type)
    }
}

// ---------------------------------------------------------------------------
// ReferenceIteratorAdapter  (ReferenceIteratorAdapter.java)
// ---------------------------------------------------------------------------

/// Wraps a `Vec<Reference>` to provide a Java-style iterator with `has_next()`
/// and `next()` methods, alongside the standard Rust `Iterator` trait.
pub struct ReferenceIteratorAdapter {
    references: Vec<Reference>,
    index: usize,
}

impl ReferenceIteratorAdapter {
    pub fn new(references: Vec<Reference>) -> Self {
        Self { references, index: 0 }
    }
    pub fn has_next(&self) -> bool { self.index < self.references.len() }
    pub fn peek(&self) -> Option<&Reference> { self.references.get(self.index) }
    pub fn len(&self) -> usize { self.references.len() }
    pub fn is_empty(&self) -> bool { self.references.is_empty() }
    pub fn reset(&mut self) { self.index = 0; }
}

impl Iterator for ReferenceIteratorAdapter {
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

impl ExactSizeIterator for ReferenceIteratorAdapter {}
impl std::iter::FusedIterator for ReferenceIteratorAdapter {}

// ---------------------------------------------------------------------------
// ReferenceListener  (ReferenceListener.java)
// ---------------------------------------------------------------------------

/// Callback interface for reference change notifications.
pub trait ReferenceListener {
    /// Notification that the given memory reference has been added.
    fn mem_reference_added(&self, ref_obj: &Reference);
    /// Notification that the given memory reference has been removed.
    fn mem_reference_removed(&self, ref_obj: &Reference);
    /// Notification that the given stack reference has been added.
    fn stack_reference_added(&self, ref_obj: &Reference);
    /// Notification that the given stack reference has been removed.
    fn stack_reference_removed(&self, ref_obj: &Reference);
    /// Notification that the given register reference has been added.
    fn register_reference_added(&self, ref_obj: &Reference);
    /// Notification that the given register reference has been removed.
    fn register_reference_removed(&self, ref_obj: &Reference);
    /// Notification that the given external reference has been added.
    fn external_reference_added(&self, ref_obj: &Reference);
    /// Notification that the given external reference has been removed.
    fn external_reference_removed(&self, ref_obj: &Reference);
    /// Notification that a reference was overridden.
    fn reference_overridden(&self, ref_obj: &Reference);
    /// Notification that a reference override was removed.
    fn reference_override_removed(&self, ref_obj: &Reference);
}

// ---------------------------------------------------------------------------
// SymbolIterator  (SymbolIterator.java)
// ---------------------------------------------------------------------------

/// Iterator over symbols.
pub struct SymbolIteratorStruct {
    symbols: Vec<Symbol>,
    index: usize,
}

impl SymbolIteratorStruct {
    pub fn new(symbols: Vec<Symbol>) -> Self {
        Self { symbols, index: 0 }
    }

    /// Returns an empty symbol iterator.
    pub fn empty() -> Self {
        Self { symbols: Vec::new(), index: 0 }
    }

    pub fn has_next(&self) -> bool { self.index < self.symbols.len() }
    pub fn len(&self) -> usize { self.symbols.len() }
    pub fn is_empty(&self) -> bool { self.symbols.is_empty() }
    pub fn reset(&mut self) { self.index = 0; }
}

impl Iterator for SymbolIteratorStruct {
    type Item = Symbol;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.symbols.len() {
            let s = self.symbols[self.index].clone();
            self.index += 1;
            Some(s)
        } else {
            None
        }
    }
}

impl ExactSizeIterator for SymbolIteratorStruct {}
impl std::iter::FusedIterator for SymbolIteratorStruct {}

// ---------------------------------------------------------------------------
// SymbolIteratorAdapter  (SymbolIteratorAdapter.java)
// ---------------------------------------------------------------------------

/// Wraps a `Vec<Symbol>` to provide Java-style iteration.
pub struct SymbolIteratorAdapter {
    symbols: Vec<Symbol>,
    index: usize,
}

impl SymbolIteratorAdapter {
    pub fn new(symbols: Vec<Symbol>) -> Self {
        Self { symbols, index: 0 }
    }
    pub fn has_next(&self) -> bool { self.index < self.symbols.len() }
    pub fn len(&self) -> usize { self.symbols.len() }
    pub fn is_empty(&self) -> bool { self.symbols.is_empty() }
    pub fn reset(&mut self) { self.index = 0; }
    pub fn to_vec(&self) -> &[Symbol] { &self.symbols }
}

impl Iterator for SymbolIteratorAdapter {
    type Item = Symbol;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.symbols.len() {
            let s = self.symbols[self.index].clone();
            self.index += 1;
            Some(s)
        } else {
            None
        }
    }
}

impl ExactSizeIterator for SymbolIteratorAdapter {}
impl std::iter::FusedIterator for SymbolIteratorAdapter {}

// ---------------------------------------------------------------------------
// SymbolTableListener  (SymbolTableListener.java)
// ---------------------------------------------------------------------------

/// Callback interface for symbol table change notifications.
pub trait SymbolTableListener {
    /// Notification that the given symbol has been added.
    fn symbol_added(&self, symbol: &dyn SymbolApi);
    /// Notification that a symbol was removed.
    fn symbol_removed(&self, addr: Address, name: &str, is_local: bool);
    /// Notification that the given symbol was renamed.
    fn symbol_renamed(&self, symbol: &dyn SymbolApi, old_name: &str);
    /// Notification that the given symbol was set as the primary symbol.
    fn primary_symbol_set(&self, symbol: &dyn SymbolApi);
    /// Notification that the scope on a symbol changed.
    fn symbol_scope_changed(&self, symbol: &dyn SymbolApi);
    /// Notification that an external entry point was added at the given address.
    fn external_entry_point_added(&self, addr: Address);
    /// Notification that an external entry point was removed from the given address.
    fn external_entry_point_removed(&self, addr: Address);
    /// Notification that the association between a reference and a specific symbol has changed.
    fn association_added(&self, symbol: &dyn SymbolApi, reference: &Reference);
    /// Notification that the association between the given reference and any symbol was removed.
    fn association_removed(&self, reference: &Reference);
}

// ---------------------------------------------------------------------------
// SymbolUtilities  (SymbolUtilities.java)
// ---------------------------------------------------------------------------

/// Utility methods for working with symbol strings and default naming conventions.
pub struct SymbolUtilities;

/// Maximum allowed symbol name length.
pub const MAX_SYMBOL_NAME_LENGTH: usize = 2000;

/// Default prefix for a subroutine.
pub const DEFAULT_SUBROUTINE_PREFIX: &str = "SUB_";
/// Default prefix for a reference that has flow but is not a call.
pub const DEFAULT_SYMBOL_PREFIX: &str = "LAB_";
/// Default prefix for a data reference.
pub const DEFAULT_DATA_PREFIX: &str = "DAT_";
/// Default prefix for a reference that is unknown.
pub const DEFAULT_UNKNOWN_PREFIX: &str = "UNK_";
/// Default prefix for an entry point.
pub const DEFAULT_EXTERNAL_ENTRY_PREFIX: &str = "EXT_ENTRY_";
/// Default prefix for a function.
pub const DEFAULT_FUNCTION_PREFIX: &str = "FUN_";
/// Default prefix for internal references.
pub const DEFAULT_INTERNAL_REF_PREFIX: &str = "REF_";
/// Default prefix for local reserved names.
pub const DEFAULT_LOCAL_RESERVED_PREFIX: &str = "var_";
/// Default prefix for local variables.
pub const DEFAULT_LOCAL_PREFIX: &str = "local_";
/// Ordinal prefix.
pub const ORDINAL_PREFIX: &str = "ordinal_";
/// Minimum number of hex digits in default label addresses.
pub const MIN_LABEL_ADDRESS_DIGITS: usize = 8;
/// Underscore separator for label construction.
pub const UNDERSCORE: &str = "_";

/// Reference level constants.
pub const UNK_LEVEL: u8 = 0;
pub const DAT_LEVEL: u8 = 1;
pub const LAB_LEVEL: u8 = 2;
pub const SUB_LEVEL: u8 = 3;
pub const FUN_LEVEL: u8 = 4;
pub const EXT_LEVEL: u8 = 5;

impl SymbolUtilities {
    /// Returns `true` if the name appears to be an auto-generated default symbol name.
    pub fn is_default_label_name(name: &str) -> bool {
        if name.len() < 4 { return false; }
        name.starts_with(DEFAULT_SUBROUTINE_PREFIX)
            || name.starts_with(DEFAULT_SYMBOL_PREFIX)
            || name.starts_with(DEFAULT_DATA_PREFIX)
            || name.starts_with(DEFAULT_UNKNOWN_PREFIX)
            || name.starts_with(DEFAULT_EXTERNAL_ENTRY_PREFIX)
    }

    /// Returns `true` if the name appears to be an auto-generated default function name.
    pub fn is_default_function_name(name: &str) -> bool {
        name.starts_with(DEFAULT_FUNCTION_PREFIX)
    }

    /// Returns `true` if the name appears to be a default label prefix.
    pub fn is_default_label_prefix(prefix: &str) -> bool {
        prefix == DEFAULT_SUBROUTINE_PREFIX
            || prefix == DEFAULT_SYMBOL_PREFIX
            || prefix == DEFAULT_DATA_PREFIX
            || prefix == DEFAULT_UNKNOWN_PREFIX
    }

    /// Creates a default function name from an address, e.g., "FUN_00401000".
    pub fn default_function_name(addr: &Address) -> String {
        format!("{}{:0width$X}", DEFAULT_FUNCTION_PREFIX, addr.offset, width = MIN_LABEL_ADDRESS_DIGITS)
    }

    /// Creates a default label name from an address, e.g., "LAB_00401000".
    pub fn default_label_name(addr: &Address) -> String {
        format!("{}{:0width$X}", DEFAULT_SYMBOL_PREFIX, addr.offset, width = MIN_LABEL_ADDRESS_DIGITS)
    }

    /// Creates a default data label name from an address, e.g., "DAT_00401000".
    pub fn default_data_name(addr: &Address) -> String {
        format!("{}{:0width$X}", DEFAULT_DATA_PREFIX, addr.offset, width = MIN_LABEL_ADDRESS_DIGITS)
    }

    /// Creates a default external entry name from an address.
    pub fn default_external_entry_name(addr: &Address) -> String {
        format!("{}{:0width$X}", DEFAULT_EXTERNAL_ENTRY_PREFIX, addr.offset, width = MIN_LABEL_ADDRESS_DIGITS)
    }

    /// Returns `true` if the given name is a valid symbol name (non-empty,
    /// no whitespace, no namespace delimiter).
    pub fn is_valid_symbol_name(name: &str) -> bool {
        validate_symbol_name(name).is_ok()
    }

    /// Returns a case-insensitive comparison of two symbol names.
    pub fn compare_symbol_names(a: &str, b: &str) -> std::cmp::Ordering {
        a.to_lowercase().cmp(&b.to_lowercase())
    }

    /// Returns `true` if the name starts with a known dynamic data type prefix.
    pub fn is_dynamic_data_type_prefix(name: &str) -> bool {
        let lower = name.to_lowercase();
        // Check common built-in data type prefixes
        const PREFIXES: &[&str] = &[
            "byte_", "word_", "dword_", "qword_", "oword_", "char_",
            "short_", "int_", "long_", "float_", "double_", "bool_",
            "string_", "unicode_", "pointer_", "struct_", "array_",
            "undefined_", "undefined1_", "undefined2_", "undefined4_", "undefined8_",
        ];
        PREFIXES.iter().any(|p| lower.starts_with(p))
    }

    /// Strips the namespace path from a qualified name, returning just the leaf name.
    pub fn get_name_without_namespace(qualified_name: &str) -> &str {
        qualified_name.rsplit("::").next().unwrap_or(qualified_name)
    }

    /// Returns the namespace path from a qualified name, or None if no delimiter.
    pub fn get_namespace_path(qualified_name: &str) -> Option<&str> {
        qualified_name.rfind("::").map(|pos| &qualified_name[..pos])
    }

    /// Parses a possibly-qualified symbol name into its path components.
    pub fn parse_qualified_name(qualified_name: &str) -> Vec<&str> {
        qualified_name.split("::").collect()
    }

    /// Returns the default prefix for the given symbol type.
    pub fn get_default_prefix(symbol_type: SymbolType) -> &'static str {
        match symbol_type {
            SymbolType::Function => DEFAULT_FUNCTION_PREFIX,
            SymbolType::Label => DEFAULT_SYMBOL_PREFIX,
            _ => DEFAULT_UNKNOWN_PREFIX,
        }
    }

    /// Returns `true` if the given symbol has a non-default name.
    pub fn has_non_default_name(symbol: &dyn SymbolApi) -> bool {
        !Self::is_default_label_name(&symbol.get_name())
            && !Self::is_default_function_name(&symbol.get_name())
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
        assert_eq!(SymbolApi::get_name(&func), "main");
        assert_eq!(SymbolApi::get_symbol_type(&func), SymbolType::Function);
        assert!(SymbolApi::is_primary(&func));
        assert!(!func.is_default());
    }

    #[test]
    fn test_default_function() {
        let addr = Address::new(0x401000);
        let func = FunctionSymbol::default_symbol(400, addr);
        assert!(func.is_default());
        assert_eq!(SymbolApi::get_name(&func), "FUN_00401000");
        assert_eq!(SymbolApi::get_source(&func), SourceType::Default);
    }

    #[test]
    fn test_global_symbol() {
        let gs = GlobalSymbol::new();
        assert_eq!(SymbolApi::get_name(&gs), "Global");
        assert_eq!(SymbolApi::get_symbol_type(&gs), SymbolType::Global);
        assert!(SymbolApi::is_global(&gs));
        assert_eq!(SymbolApi::get_id(&gs), 0);
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
    fn test_symbol_path_helpers() {
        let path = SymbolPath::from_delimited("Functions::main");
        assert_eq!(path.name(), "main");
        assert_eq!(path.leaf_name(), Some("main"));
        assert_eq!(path.depth(), 2);
        assert!(path.starts_with(&SymbolPath::root()));
        assert_eq!(path.parent().map(|parent| parent.display_name()), Some("Global::Functions".to_string()));
    }

    #[test]
    fn test_symbol_tree_node_helpers() {
        let leaf = SymbolTreeNode::leaf(
            "main",
            SymbolPath::from_delimited("Global::Functions::main"),
            Symbol::function("main", Address::new(0x401000)),
        );
        let root = SymbolTreeNode::category(
            "Global",
            SymbolPath::root(),
            vec![leaf.clone()],
        );
        assert!(root.has_children());
        assert_eq!(root.child_count(), 1);
        assert_eq!(root.get_child(0).map(|child| child.name.as_str()), Some("main"));
        assert!(leaf.has_symbol());
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

        SymbolApi::set_name(&mut func, "main", SourceType::UserDefined).unwrap();
        assert_eq!(<FunctionSymbol as SymbolApi>::get_name(&func), "main");
        assert!(!func.is_default());
        assert_eq!(<FunctionSymbol as SymbolApi>::get_source(&func), SourceType::UserDefined);
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

    // -----------------------------------------------------------------------
    // Tests for AddressLabelPair
    // -----------------------------------------------------------------------

    #[test]
    fn test_address_label_pair() {
        let pair = AddressLabelPair::new(Address::new(0x401000), "main");
        assert_eq!(*pair.get_address(), Address::new(0x401000));
        assert_eq!(pair.get_label(), "main");
        assert_eq!(pair.to_string(), format!("{}: main", Address::new(0x401000)));
    }

    #[test]
    fn test_address_label_pair_equality() {
        let p1 = AddressLabelPair::new(Address::new(0x1000), "foo");
        let p2 = AddressLabelPair::new(Address::new(0x1000), "foo");
        let p3 = AddressLabelPair::new(Address::new(0x2000), "bar");
        assert_eq!(p1, p2);
        assert_ne!(p1, p3);
    }

    // -----------------------------------------------------------------------
    // Tests for Equate
    // -----------------------------------------------------------------------

    #[test]
    fn test_equate_basics() {
        let mut eq = Equate::new("MY_CONSTANT", 42);
        assert_eq!(eq.get_name(), "MY_CONSTANT");
        assert_eq!(eq.get_value(), 42);
        eq.set_value(100);
        assert_eq!(eq.get_value(), 100);
    }

    #[test]
    fn test_equate_references() {
        let mut eq = Equate::new("FOO", 10);
        let er = EquateReference::new(Address::new(0x1000), 0);
        eq.add_reference(er);
        assert_eq!(eq.get_reference_count(), 1);
        assert!(eq.remove_reference(&Address::new(0x1000), 0));
        assert_eq!(eq.get_reference_count(), 0);
        assert!(!eq.remove_reference(&Address::new(0x9999), 0));
    }

    #[test]
    fn test_equate_display() {
        let eq = Equate::new("FLAG", 0xFF);
        assert_eq!(eq.to_string(), "FLAG = 0xFF");
    }

    #[test]
    fn test_equate_equated_string_masked() {
        let s = Equate::get_equated_string_masked(0x1234, 0xFF, "0x");
        assert_eq!(s, "0x34");
    }

    // -----------------------------------------------------------------------
    // Tests for EquateReference
    // -----------------------------------------------------------------------

    #[test]
    fn test_equate_reference() {
        let er = EquateReference::with_dynamic_hash(Address::new(0x1000), 1, 12345);
        assert_eq!(*er.get_address(), Address::new(0x1000));
        assert_eq!(er.get_op_index(), 1);
        assert_eq!(er.get_dynamic_hash_value(), 12345);
    }

    // -----------------------------------------------------------------------
    // Tests for EquateApi trait (on Equate)
    // -----------------------------------------------------------------------

    #[test]
    fn test_equate_api_trait() {
        let eq: Box<dyn EquateApi> = Box::new(Equate::new("X", 5));
        assert_eq!(eq.get_name(), "X");
        assert_eq!(eq.get_value(), 5);
    }

    // -----------------------------------------------------------------------
    // Tests for ExternalPath
    // -----------------------------------------------------------------------

    #[test]
    fn test_external_path_basic() {
        let path = ExternalPath::from_library_and_label("libc.so.6", "printf");
        assert_eq!(path.get_library_name(), "libc.so.6");
        assert_eq!(path.get_label(), "printf");
        assert_eq!(path.to_delimited_string(), "libc.so.6::printf");
        assert_eq!(path.to_string(), "libc.so.6::printf");
    }

    #[test]
    fn test_external_path_new_valid() {
        let path = ExternalPath::new(vec!["lib.so".into(), "ns".into(), "func".into()]);
        assert!(path.is_ok());
        let path = path.unwrap();
        assert_eq!(path.get_library_name(), "lib.so");
        assert_eq!(path.get_label(), "func");
        assert_eq!(path.segments.len(), 3);
    }

    #[test]
    fn test_external_path_new_too_few() {
        let path = ExternalPath::new(vec!["lib.so".into()]);
        assert!(path.is_err());
    }

    #[test]
    fn test_external_path_empty_segment() {
        let path = ExternalPath::new(vec!["lib.so".into(), "".into()]);
        assert!(path.is_err());
    }

    #[test]
    fn test_external_path_parent() {
        let path = ExternalPath::new(vec!["lib.so".into(), "ns".into(), "func".into()]).unwrap();
        let parent = path.get_parent_path();
        assert!(parent.is_some());
        let parent = parent.unwrap();
        assert_eq!(parent.segments, vec!["lib.so".to_string(), "ns".to_string()]);
    }

    #[test]
    fn test_external_path_parent_none_for_two_segments() {
        let path = ExternalPath::from_library_and_label("lib.so", "func");
        assert!(path.get_parent_path().is_none());
    }

    // -----------------------------------------------------------------------
    // Tests for ExternalLocationImpl
    // -----------------------------------------------------------------------

    #[test]
    fn test_external_location_impl() {
        let path = ExternalPath::from_library_and_label("libc.so.6", "printf");
        let mut loc = ExternalLocationImpl::new(
            path, Some("printf".to_string()), None, SourceType::Imported, true,
        );
        assert_eq!(loc.get_library_name(), "libc.so.6");
        assert_eq!(loc.get_label(), Some("printf"));
        assert!(loc.get_address().is_none());
        assert!(loc.is_function());
        assert!(!loc.is_data());
        assert_eq!(loc.get_source(), SourceType::Imported);

        loc.set("puts", Some(Address::new(0x1000)), SourceType::UserDefined).unwrap();
        assert_eq!(loc.get_label(), Some("puts"));
        assert_eq!(loc.get_address(), Some(Address::new(0x1000)));
    }

    #[test]
    fn test_external_location_iterator() {
        let path1 = ExternalPath::from_library_and_label("lib.so", "a");
        let path2 = ExternalPath::from_library_and_label("lib.so", "b");
        let locs = vec![
            ExternalLocationImpl::new(path1, Some("a".into()), None, SourceType::Imported, false),
            ExternalLocationImpl::new(path2, Some("b".into()), None, SourceType::Imported, true),
        ];
        let mut iter = ExternalLocationIterator::new(locs);
        assert!(iter.has_next());
        assert_eq!(iter.len(), 2);
        let first = iter.next().unwrap();
        assert_eq!(first.get_label(), Some("a"));
        let second = iter.next().unwrap();
        assert_eq!(second.get_label(), Some("b"));
        assert!(!iter.has_next());
    }

    // -----------------------------------------------------------------------
    // Tests for ExternalReference
    // -----------------------------------------------------------------------

    #[test]
    fn test_external_reference() {
        let er = ExternalReference::new(
            Address::new(0x401000),
            Address::new(0x500000),
            RefType::UNCONDITIONAL_CALL,
            0,
            "libc.so.6",
            Some("printf".to_string()),
        );
        assert_eq!(*er.get_from_address(), Address::new(0x401000));
        assert_eq!(*er.get_to_address(), Address::new(0x500000));
        assert!(er.is_external_reference());
        assert!(er.is_memory_reference());
        assert!(!er.is_stack_reference());
        assert!(!er.is_offset_reference());
        assert!(!er.is_shifted_reference());
        assert_eq!(er.get_library_name(), "libc.so.6");
        assert_eq!(er.get_label(), Some("printf"));
    }

    // -----------------------------------------------------------------------
    // Tests for NameTransformer
    // -----------------------------------------------------------------------

    #[test]
    fn test_identity_name_transformer() {
        let t = IdentityNameTransformer;
        assert_eq!(t.simplify("hello"), "hello");
        assert_eq!(t.simplify(""), "");
        assert_eq!(t.simplify("std::vector<int>"), "std::vector<int>");
    }

    #[test]
    fn test_illegal_char_cpp_transformer() {
        let t = IllegalCharCppTransformer::new();
        // Valid identifier: no change
        assert_eq!(t.simplify("my_func"), "my_func");
        // Digit after first char: ok
        assert_eq!(t.simplify("func2"), "func2");
        // Template: ok
        assert_eq!(t.simplify("vector<int>"), "vector<int>");
        // Space: illegal
        assert_eq!(t.simplify("my func"), "my_func");
        // Dollar sign: illegal
        assert_eq!(t.simplify("$var"), "_var");
        // Operator special chars: ok after "operator"
        assert_eq!(t.simplify("operator+"), "operator+");
        assert_eq!(t.simplify("operator[]"), "operator[]");
        // Tilde at start: ok
        assert_eq!(t.simplify("~MyClass"), "~MyClass");
    }

    // -----------------------------------------------------------------------
    // Tests for MemReferenceImpl
    // -----------------------------------------------------------------------

    #[test]
    fn test_mem_reference_impl() {
        let r = MemReferenceImpl::new(
            Address::new(0x401000),
            Address::new(0x500000),
            RefType::UNCONDITIONAL_CALL,
            SourceType::UserDefined,
            0,
            true,
        );
        assert_eq!(*r.get_from_address(), Address::new(0x401000));
        assert_eq!(*r.get_to_address(), Address::new(0x500000));
        assert!(r.is_primary());
        assert!(r.is_memory_reference());
        assert!(!r.is_register_reference());
        assert!(!r.is_stack_reference());
        assert!(!r.is_external_reference());
        assert!(!r.is_offset_reference());
        assert!(!r.is_shifted_reference());
        assert_eq!(r.get_symbol_id(), -1);
        assert!(!r.is_mnemonic_reference());
    }

    #[test]
    fn test_mem_reference_impl_ordering() {
        let r1 = MemReferenceImpl::new(
            Address::new(0x1000), Address::new(0x2000),
            RefType::DATA, SourceType::Default, 0, false,
        );
        let r2 = MemReferenceImpl::new(
            Address::new(0x2000), Address::new(0x3000),
            RefType::DATA, SourceType::Default, 0, false,
        );
        assert!(r1 < r2);
    }

    // -----------------------------------------------------------------------
    // Tests for OffsetReference
    // -----------------------------------------------------------------------

    #[test]
    fn test_offset_reference() {
        let r = OffsetReference::new(
            Address::new(0x401000),
            Address::new(0x500100),
            Address::new(0x500000),
            0x100,
            RefType::READ,
            0,
        );
        assert_eq!(*r.get_base_address(), Address::new(0x500000));
        assert_eq!(r.get_offset(), 0x100);
        assert!(r.is_offset_reference());
        assert!(r.is_memory_reference());
        assert!(!r.is_shifted_reference());
        assert!(!r.is_stack_reference());
    }

    // -----------------------------------------------------------------------
    // Tests for ShiftedReference
    // -----------------------------------------------------------------------

    #[test]
    fn test_shifted_reference() {
        let r = ShiftedReference::new(
            Address::new(0x401000),
            Address::new(0x500002),
            2,
            RefType::READ,
            0,
        );
        assert_eq!(r.get_shift_value(), 2);
        assert!(r.is_shifted_reference());
        assert!(r.is_memory_reference());
        assert!(!r.is_offset_reference());
    }

    // -----------------------------------------------------------------------
    // Tests for StackReference
    // -----------------------------------------------------------------------

    #[test]
    fn test_stack_reference() {
        let r = StackReference::new(
            Address::new(0x401000),
            -8,
            RefType::READ,
            0,
        );
        assert_eq!(r.get_stack_offset(), -8);
        assert!(r.is_stack_reference());
        assert!(!r.is_memory_reference());
        assert!(!r.is_register_reference());
    }

    // -----------------------------------------------------------------------
    // Tests for ThunkReference
    // -----------------------------------------------------------------------

    #[test]
    fn test_thunk_reference() {
        let r = ThunkReference::new(Address::new(0x401000), Address::new(0x500000));
        assert_eq!(*r.get_from_address(), Address::new(0x401000));
        assert_eq!(*r.get_to_address(), Address::new(0x500000));
        assert_eq!(r.get_reference_type(), RefType::THUNK);
        assert_eq!(r.get_operand_index(), OTHER_OP_INDEX);
        assert!(!r.is_memory_reference());
        assert!(!r.is_register_reference());
        assert!(!r.is_stack_reference());
        assert_eq!(r.get_source(), SourceType::Default);
    }

    #[test]
    fn test_thunk_reference_dynamic_ref_trait() {
        let r = ThunkReference::new(Address::new(0x1000), Address::new(0x2000));
        let dr: &dyn DynamicReference = &r;
        assert_eq!(*dr.get_from_address(), Address::new(0x1000));
        assert_eq!(dr.get_reference_type(), RefType::THUNK);
    }

    // -----------------------------------------------------------------------
    // Tests for EntryPointReference
    // -----------------------------------------------------------------------

    #[test]
    fn test_entry_point_reference() {
        let r = EntryPointReference::new(
            Address::new(0x401000),
            Address::new(0x500000),
            RefType::UNCONDITIONAL_JUMP,
            MNEMONIC,
        );
        assert!(r.is_entry_point_reference());
        assert!(r.is_memory_reference());
        assert!(!r.is_register_reference());
        assert!(!r.is_stack_reference());
    }

    // -----------------------------------------------------------------------
    // Tests for RefTypeFactory
    // -----------------------------------------------------------------------

    #[test]
    fn test_ref_type_factory_get() {
        assert_eq!(RefTypeFactory::get(0), Some(RefType::Flow(FlowType::FallThrough)));
        assert_eq!(RefTypeFactory::get(1), Some(RefType::Flow(FlowType::UnconditionalJump)));
        assert_eq!(RefTypeFactory::get(100), Some(RefType::Data(DataRefType::Data)));
        assert_eq!(RefTypeFactory::get(101), Some(RefType::Data(DataRefType::Read)));
        assert!(RefTypeFactory::get(99).is_none());
    }

    #[test]
    fn test_ref_type_factory_arrays() {
        assert!(!RefTypeFactory::get_memory_ref_types().is_empty());
        assert!(!RefTypeFactory::get_stack_ref_types().is_empty());
        assert!(!RefTypeFactory::get_data_ref_types().is_empty());
        assert!(!RefTypeFactory::get_external_ref_types().is_empty());
    }

    #[test]
    fn test_ref_type_factory_is_memory_ref_type() {
        assert!(RefTypeFactory::is_memory_ref_type(RefType::DATA));
        assert!(RefTypeFactory::is_memory_ref_type(RefType::READ));
        assert!(RefTypeFactory::is_memory_ref_type(RefType::UNCONDITIONAL_CALL));
    }

    // -----------------------------------------------------------------------
    // Tests for ReferenceIteratorAdapter
    // -----------------------------------------------------------------------

    #[test]
    fn test_reference_iterator_adapter() {
        let refs = vec![
            Reference::new(Address::new(0x100), Address::new(0x200), RefType::DATA, 0),
            Reference::new(Address::new(0x300), Address::new(0x400), RefType::READ, 1),
        ];
        let mut adapter = ReferenceIteratorAdapter::new(refs);
        assert!(adapter.has_next());
        assert_eq!(adapter.len(), 2);
        let first = adapter.next().unwrap();
        assert_eq!(*first.get_from_address(), Address::new(0x100));
        let _second = adapter.next().unwrap();
        assert!(!adapter.has_next());

        adapter.reset();
        assert!(adapter.has_next());
    }

    // -----------------------------------------------------------------------
    // Tests for SymbolIteratorStruct
    // -----------------------------------------------------------------------

    #[test]
    fn test_symbol_iterator_struct() {
        let symbols = vec![
            Symbol::label("foo", Address::new(0x1000)),
            Symbol::label("bar", Address::new(0x2000)),
        ];
        let mut iter = SymbolIteratorStruct::new(symbols);
        assert!(iter.has_next());
        assert_eq!(iter.len(), 2);
        let first = iter.next().unwrap();
        assert_eq!(first.name(), "foo");
        let second = iter.next().unwrap();
        assert_eq!(second.name(), "bar");
        assert!(!iter.has_next());
    }

    #[test]
    fn test_symbol_iterator_empty() {
        let mut iter = SymbolIteratorStruct::empty();
        assert!(!iter.has_next());
        assert!(iter.is_empty());
        assert!(iter.next().is_none());
    }

    // -----------------------------------------------------------------------
    // Tests for SymbolIteratorAdapter
    // -----------------------------------------------------------------------

    #[test]
    fn test_symbol_iterator_adapter() {
        let symbols = vec![
            Symbol::function("main", Address::new(0x401000)),
        ];
        let mut adapter = SymbolIteratorAdapter::new(symbols);
        assert!(adapter.has_next());
        let sym = adapter.next().unwrap();
        assert_eq!(sym.name(), "main");
        assert!(!adapter.has_next());
    }

    // -----------------------------------------------------------------------
    // Tests for SymbolUtilities
    // -----------------------------------------------------------------------

    #[test]
    fn test_symbol_utilities_is_default_label_name() {
        assert!(SymbolUtilities::is_default_label_name("LAB_00401000"));
        assert!(SymbolUtilities::is_default_label_name("SUB_00401000"));
        assert!(SymbolUtilities::is_default_label_name("DAT_00401000"));
        assert!(SymbolUtilities::is_default_label_name("UNK_00401000"));
        assert!(!SymbolUtilities::is_default_label_name("main"));
        assert!(!SymbolUtilities::is_default_label_name("ab"));
    }

    #[test]
    fn test_symbol_utilities_is_default_function_name() {
        assert!(SymbolUtilities::is_default_function_name("FUN_00401000"));
        assert!(!SymbolUtilities::is_default_function_name("main"));
    }

    #[test]
    fn test_symbol_utilities_default_names() {
        let addr = Address::new(0x401000);
        assert_eq!(SymbolUtilities::default_function_name(&addr), "FUN_00401000");
        assert_eq!(SymbolUtilities::default_label_name(&addr), "LAB_00401000");
        assert_eq!(SymbolUtilities::default_data_name(&addr), "DAT_00401000");
    }

    #[test]
    fn test_symbol_utilities_parse_qualified_name() {
        let parts = SymbolUtilities::parse_qualified_name("Global::my_ns::func");
        assert_eq!(parts, vec!["Global", "my_ns", "func"]);
    }

    #[test]
    fn test_symbol_utilities_get_name_without_namespace() {
        assert_eq!(SymbolUtilities::get_name_without_namespace("Global::ns::func"), "func");
        assert_eq!(SymbolUtilities::get_name_without_namespace("simple"), "simple");
    }

    #[test]
    fn test_symbol_utilities_get_namespace_path() {
        assert_eq!(SymbolUtilities::get_namespace_path("Global::ns::func"), Some("Global::ns"));
        assert_eq!(SymbolUtilities::get_namespace_path("simple"), None);
    }

    #[test]
    fn test_symbol_utilities_is_dynamic_data_type_prefix() {
        assert!(SymbolUtilities::is_dynamic_data_type_prefix("dword_00401000"));
        assert!(SymbolUtilities::is_dynamic_data_type_prefix("byte_1234"));
        assert!(!SymbolUtilities::is_dynamic_data_type_prefix("my_variable"));
    }

    #[test]
    fn test_symbol_utilities_compare_names() {
        use std::cmp::Ordering;
        assert_eq!(SymbolUtilities::compare_symbol_names("abc", "ABC"), Ordering::Equal);
        assert_eq!(SymbolUtilities::compare_symbol_names("abc", "def"), Ordering::Less);
        assert_eq!(SymbolUtilities::compare_symbol_names("DEF", "abc"), Ordering::Greater);
    }

    #[test]
    fn test_symbol_utilities_get_default_prefix() {
        assert_eq!(SymbolUtilities::get_default_prefix(SymbolType::Function), DEFAULT_FUNCTION_PREFIX);
        assert_eq!(SymbolUtilities::get_default_prefix(SymbolType::Label), DEFAULT_SYMBOL_PREFIX);
    }

    #[test]
    fn test_symbol_utilities_has_non_default_name() {
        let label = LabelSymbol::new(1, "main", Address::new(0x1000));
        assert!(SymbolUtilities::has_non_default_name(&label));

        let default_label = LabelSymbol::new(2, "LAB_00001000", Address::new(0x1000));
        assert!(!SymbolUtilities::has_non_default_name(&default_label));
    }

    #[test]
    fn test_symbol_utilities_is_valid() {
        assert!(SymbolUtilities::is_valid_symbol_name("valid_name"));
        assert!(!SymbolUtilities::is_valid_symbol_name(""));
        assert!(!SymbolUtilities::is_valid_symbol_name("bad name"));
    }

    // -----------------------------------------------------------------------
    // Tests for constants
    // -----------------------------------------------------------------------

    #[test]
    fn test_symbol_utility_constants() {
        assert_eq!(MAX_SYMBOL_NAME_LENGTH, 2000);
        assert_eq!(DEFAULT_SUBROUTINE_PREFIX, "SUB_");
        assert_eq!(DEFAULT_SYMBOL_PREFIX, "LAB_");
        assert_eq!(DEFAULT_DATA_PREFIX, "DAT_");
        assert_eq!(DEFAULT_UNKNOWN_PREFIX, "UNK_");
        assert_eq!(DEFAULT_FUNCTION_PREFIX, "FUN_");
        assert_eq!(MIN_LABEL_ADDRESS_DIGITS, 8);
        assert_eq!(UNK_LEVEL, 0);
        assert_eq!(FUN_LEVEL, 4);
        assert_eq!(EXT_LEVEL, 5);
    }

    // -----------------------------------------------------------------------
    // Tests for ExternalLocation trait on ExternalLocationImpl
    // -----------------------------------------------------------------------

    #[test]
    fn test_external_location_trait() {
        let path = ExternalPath::from_library_and_label("libc.so.6", "malloc");
        let loc: Box<dyn ExternalLocation> = Box::new(ExternalLocationImpl::new(
            path, Some("malloc".into()), Some(Address::new(0x1000)),
            SourceType::Imported, true,
        ));
        assert_eq!(loc.get_library_name(), "libc.so.6");
        assert_eq!(loc.get_label(), Some("malloc"));
        assert_eq!(loc.get_address(), Some(Address::new(0x1000)));
        assert!(loc.is_function());
    }

    // -----------------------------------------------------------------------
    // Tests for Symbol variants' namespace_id and type checks
    // -----------------------------------------------------------------------

    #[test]
    fn test_symbol_namespace_id() {
        let label = Symbol::Label(LabelSymbol::with_options(1, "foo", Address::new(0x1000), 5, SourceType::UserDefined));
        assert_eq!(label.namespace_id(), Some(5));
        assert!(label.is_in_namespace(5));
        assert!(!label.is_in_namespace(0));

        let lib = Symbol::library("libc.so.6");
        assert_eq!(lib.namespace_id(), Some(0));
    }

    #[test]
    fn test_symbol_type_checks() {
        let func = Symbol::function("main", Address::new(0x1000));
        assert!(func.is_function_symbol());
        assert!(!func.is_label_symbol());

        let label = Symbol::label("lab", Address::new(0x2000));
        assert!(label.is_label_symbol());
        assert!(!label.is_function_symbol());

        let lib = Symbol::library("libc.so.6");
        assert!(lib.is_library_symbol());
        assert!(lib.is_namespace_symbol());

        let ns = Symbol::namespace("my_ns", 0);
        assert!(ns.is_namespace_type());

        let cls = Symbol::class("MyClass", 0);
        assert!(cls.is_class_symbol());
    }

    // -----------------------------------------------------------------------
    // Tests for DynamicReference trait
    // -----------------------------------------------------------------------

    #[test]
    fn test_dynamic_reference_methods() {
        let tr = ThunkReference::new(Address::new(0x1000), Address::new(0x2000));
        assert_eq!(*tr.get_from_address(), Address::new(0x1000));
        assert_eq!(*tr.get_to_address(), Address::new(0x2000));
        assert!(!tr.is_memory_reference());
        assert!(!tr.is_register_reference());
        assert!(!tr.is_stack_reference());
        assert!(!tr.is_external_reference());
        assert!(!tr.is_entry_point_reference());
        assert!(!tr.is_offset_reference());
        assert!(!tr.is_shifted_reference());
    }
}
