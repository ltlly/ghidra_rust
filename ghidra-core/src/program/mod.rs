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
pub mod dynamic_var;

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
    AddressChangeSet as AddressChangeSetTrait, AutoParameterType,
    Bookmark, BookmarkComparator, BookmarkManager, BookmarkType, BookmarkTypeComparator,
    CircularDependencyException, CodeUnitComments, CodeUnitData as CodeUnitStorage,
    CodeUnitFormat, CodeUnitFormatOptions, CodeUnitIteratorImpl,
    CommentHistory, CommentType,
    CompoundStackVariableFilter, ContextChangeException,
    Data, DataBuffer, DataIteratorImpl, DataStub, DataTypeArchiveInfo,
    DefaultProgramContext as DefaultProgramContextTrait,
    DomainObjectChangeSet as DomainObjectChangeSetTrait,
    DuplicateGroupException,
    Equate, EquateTable,
    ExternalLibrary, ExternalManager, ExternalSymbol,
    FlowOverride, FlowType,
    Function, FunctionData, FunctionIteratorImpl, FunctionManager,
    FunctionOverlapException, FunctionParameter,
    FunctionSignature, FunctionTag, FunctionTagChangeSet as FunctionTagChangeSetTrait,
    FunctionTagManager, FunctionUpdateType, FunctionVariable,
    GhidraClass,
    Group, IncompatibleLanguageException,
    InMemoryFunctionManager, InMemoryListing, Instruction, InstructionIteratorImpl,
    InstructionPcodeOverride, InstructionStub,
    LabelString, LabelType, Library, Listing,
    LocalVariable, LocalVariableImpl, LocalVariableFilter, MemoryVariableFilter,
    Operand, OperandElement, OperandRepresentationList,
    Parameter, ParameterFilter, ParameterImpl,
    ProgramChangeSetTrait, ProgramContext, ProgramFragment, ProgramModule,
    ProgramTreeChangeSet as ProgramTreeChangeSetTrait, ProgramUserData,
    PrototypeModel,
    RegisterChangeSet as RegisterChangeSetTrait,
    RepeatableComment,
    SourceType as ListingSourceType, StackFrame, StackVariableFilter,
    StackVariableComparator, StubListing,
    SymbolChangeSet as SymbolChangeSetTrait,
    ThunkFunction, UniqueVariableFilter,
    Variable, VariableFilter, VariableOffset, VariableSizeException, VariableStorage,
    VariableUtilities,
};

// ============================================================================
// Re-exports from lang.rs
// ============================================================================
pub use lang::{
    AddressLabelInfo,
    BasicCompilerSpecDescription,
    BasicLanguageDescription,
    CallingConvention,
    CompilerSpec,
    CompilerSpecDescription,
    CompilerSpecID,
    ConstantPoolRecord,
    ContextSetting,
    DecompilerLanguage,
    Endian,
    ExternalLanguageCompilerSpecQuery,
    GhidraLanguagePropertyKeys,
    InjectPayload,
    InjectPayloadType,
    InputListType,
    InstructionPrototype,
    INVALID_DEPTH_CHANGE,
    Language,
    LanguageCompilerSpecPair,
    LanguageCompilerSpecQuery,
    LanguageDescription,
    LanguageID,
    LangError,
    MaskImpl,
    OperandType,
    PcodeInjectLibrary,
    ParamEntry,
    ParameterPieces,
    Processor,
    ProcessorContext,
    ProcessorContextView,
    ProgramArchitecture,
    PrototypePieces,
    Register,
    RegisterBuilder,
    RegisterManager,
    RegisterTree,
    RegisterTypeFlags,
    RegisterValue,
    SpaceNames,
    StorageClass,
    UnknownRegister,
};

// Re-export lang::FlowType and lang::PrototypeModel with qualified names
// to avoid collision with listing module types of the same name.
pub use lang::{
    FlowType as LangFlowType,
    PrototypeModel as LangPrototypeModel,
};

// Additional lang types not yet in the main re-export list.
pub use lang::{
    InstructionBlock, InstructionBlockFlow, InstructionError, InstructionErrorCode,
    InstructionSet, LanguageNotFoundException, ParamList, ParamListRegisterOut,
    ParamPassingConvention, PrototypeModelError, RegisterTranslator,
};

// ============================================================================
// Re-exports from dynamic_var.rs
// ============================================================================
pub use dynamic_var::{DynamicStorageKind, DynamicVariableStorage, VarnodeStorage};
