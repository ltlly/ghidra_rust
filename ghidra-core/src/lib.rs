//! Ghidra Rust - Core framework.
//!
//! Provides the foundational types for program representation, addressing,
//! data types, symbols, and database management.

pub mod addr;
pub mod data;
pub mod database;
pub mod error;
pub mod filesystem;
pub mod generic;
pub mod graph;
pub mod listing;
pub mod macro_;
pub mod mem;
pub mod program;
pub mod project;
pub mod symbol;
pub mod util;
pub mod utility;

// Re-exports for key types used across the workspace.
pub use addr::{Address, AddressRange, AddressSpace};
pub use data::{DataType, DataTypePath, DataTypeTreeNode};
pub use symbol::{
    FlowType, FunctionSymbol, GlobalSymbol, LabelHistory, LabelSymbol, Namespace, RefType,
    Reference, ReferenceManager, SourceType, Symbol, SymbolApi, SymbolKind, SymbolPath,
    SymbolSource, SymbolTable as SymbolTableTrait, SymbolTreeNode, SymbolType,
};
pub use listing::{InstructionMnemonic, ListingRow};
pub use program::program::{
    Comment, CommentKind, DomainFile, DomainObject, DomainObjectChangeEvent,
    DomainObjectChangeType, DomainObjectListener, InMemoryDBHandle,
    ListingData, MemoryBlock, MemoryPermissions, Program, ProgramChangeRecord,
    ProgramChangeRecordSet, ProgramChangeSet, ProgramDB, SimpleDataType, SymbolTable,
};
pub use program::listing::{
    Bookmark, BookmarkManager, BookmarkType, CodeUnitComments, CodeUnitData,
    CodeUnitFormat, CodeUnitFormatOptions, CommentType, Data, FlowOverride,
    Function, FunctionData, FunctionManager, FunctionParameter,
    FunctionSignature, FunctionTag, FunctionUpdateType, FunctionVariable,
    Group, InMemoryFunctionManager, InMemoryListing, Instruction, Listing,
    LocalVariable, LocalVariableImpl, Operand, Parameter, ParameterImpl,
    ProgramFragment, ProgramModule, SourceType as ListingSourceType,
    StackFrame, Variable, VariableStorage,
};
pub use project::{
    DomainFolder, Project, ProjectData, ProjectError, ProjectFile, ProjectLocator,
    ProjectManager, ProjectResult, PROJECT_DIR_SUFFIX, PROJECT_FILE_SUFFIX,
};
