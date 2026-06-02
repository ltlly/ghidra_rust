//! Program model — listing types.
//!
//! This module provides the core listing types converted from
//! `ghidra.program.model.listing`:
//!
//! | Java type           | Rust type                          |
//! |---------------------|------------------------------------|
//! | `Listing.java`      | [`Listing`] trait                  |
//! | `Program.java`      | [`Program`] struct (in program.rs) |
//! | `ProgramModule.java`| [`ProgramModule`] trait            |
//! | `CodeUnit.java`     | [`CodeUnit`] trait                 |
//! | `Instruction.java`  | [`Instruction`] struct             |
//! | `Data.java`         | [`Data`] struct                    |
//! | `CodeUnitFormat.java`| [`CodeUnitFormat`] struct         |
//! | `Function.java`     | [`Function`] struct                |
//! | `FunctionManager.java`| [`FunctionManager`] struct       |
//! | `Variable.java`     | [`Variable`] struct                |
//! | `Parameter.java`    | [`Parameter`] struct               |
//! | `LocalVariable.java`| [`LocalVariable`] struct           |
//!
//! All traits and structs are designed to be thread-safe (`Send + Sync`)
//! and use `Arc` for shared ownership of data types.

pub mod program;
pub mod listing;
pub mod lang;

// ============================================================================
// Re-exports from program.rs
// ============================================================================
pub use program::{
    Comment, CommentKind, DomainFile, DomainObject, DomainObjectChangeEvent,
    DomainObjectChangeType, DomainObjectListener,
    InMemoryDBHandle, ListingData, MemoryBlock, MemoryPermissions,
    Program, ProgramChangeRecord, ProgramChangeRecordSet, ProgramChangeSet,
    ProgramDB, SimpleDataType, SymbolTable,
};

// ============================================================================
// Re-exports from listing.rs
// ============================================================================
pub use listing::{
    AutoParameterType, Bookmark, BookmarkManager, BookmarkType,
    CodeUnitComments, CodeUnitData as CodeUnitStorage, CodeUnitFormat,
    CodeUnitFormatOptions, CommentType, Data, FlowOverride, FlowType,
    Function, FunctionData, FunctionManager, FunctionParameter,
    FunctionSignature, FunctionTag, FunctionUpdateType, FunctionVariable,
    Group, InMemoryFunctionManager, InMemoryListing, Instruction, Listing,
    LocalVariable, LocalVariableImpl, Operand, Parameter, ParameterImpl,
    ProgramFragment, ProgramModule, SourceType as ListingSourceType,
    StackFrame, Variable, VariableStorage,
};

// ============================================================================
// Re-exports from lang.rs
// ============================================================================
pub use lang::{
    CallingConvention, CompilerSpec, CompilerSpecID, Language, LanguageID,
    Processor, Register, RegisterManager,
};
