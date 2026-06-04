//! Ghidra Rust - Core framework.
//!
//! Provides the foundational types for program representation, addressing,
//! data types, symbols, and database management.

pub mod addr;
pub mod data;
pub mod pty;
pub mod database;
pub mod error;
pub mod filesystem;
pub mod generic;
pub mod graph;
pub mod help;
pub mod listing;
pub mod macro_;
pub mod mem;
pub mod program;
pub mod project;
pub mod symbol;
pub mod util;
pub mod utility;

// Re-exports for key types used across the workspace.
pub use addr::{AddrSpaceType, Address, AddressFactory, AddressRange, AddressSet, AddressSpace};
pub use data::{DataType, DataTypePath, DataTypeTreeNode};
pub use symbol::{
    AddressLabelPair, ClassSymbol, DataRefType, EntryPointReference, EquateApi,
    EquateReference, ExportSymbol, ExternalLocation, ExternalLocationImpl,
    ExternalLocationIterator, ExternalPath, ExternalReference, FlowType,
    FunctionSymbol, GlobalSymbol, GlobalVarSymbol, IdentityNameTransformer,
    IllegalCharCppTransformer, ImportSymbol, LabelHistory, LabelSymbol,
    LibrarySymbol, LocalVarSymbol, MemReferenceImpl, NameTransformer,
    Namespace, NamespaceSymbol, OffsetReference, ParameterSymbol, RefType,
    RefTypeFactory, Reference, ReferenceIteratorAdapter, ReferenceListener,
    ReferenceManager, ShiftedReference, SourceType, StackReference, Symbol,
    SymbolApi, SymbolIteratorAdapter, SymbolIteratorStruct, SymbolKind,
    SymbolPath, SymbolSource, SymbolTable as SymbolTableTrait,
    SymbolTableListener, SymbolTreeNode, SymbolType, SymbolUtilities,
    ThunkReference, MAX_SYMBOL_NAME_LENGTH, MIN_LABEL_ADDRESS_DIGITS,
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
    CodeUnitFormat, CodeUnitFormatOptions, CommentType, Data, Equate, EquateTable,
    ExternalLibrary, ExternalManager, ExternalSymbol, FlowOverride,
    Function, FunctionData, FunctionManager, FunctionParameter,
    FunctionSignature, FunctionTag, FunctionTagManager, FunctionUpdateType,
    FunctionVariable,
    Group, InMemoryFunctionManager, InMemoryListing, Instruction, Listing,
    LocalVariable, LocalVariableImpl, Operand, Parameter, ParameterImpl,
    ProgramContext, ProgramFragment, ProgramModule, PrototypeModel,
    SourceType as ListingSourceType,
    StackFrame, Variable, VariableStorage,
};
pub use project::{
    DomainFolder, Project, ProjectData, ProjectError, ProjectFile, ProjectLocator,
    ProjectManager, ProjectResult, PROJECT_DIR_SUFFIX, PROJECT_FILE_SUFFIX,
};
pub use project::model::{
    AbortedTransactionListener as ProjectAbortedTransactionListener,
    ChangeSet as ProjectChangeSet, CheckinHandler as ProjectCheckinHandler,
    DomainFolderChangeListener, DomainObject2, DomainObjectChangeRecord,
    DomainObjectChangedEvent, DomainObjectClosedListener, DomainObjectEvent,
    DomainObjectListener as ProjectDomainObjectListener, DomainFile2,
    DomainFolder2, DynamicEventType, EventQueueID, EventType as ProjectEventType,
    ItemCheckoutStatus, LinkFileInfo, LinkStatus, LinkedDomainFile, LinkedDomainFolder,
    ProjectData2, SimpleCheckinHandler, SimpleTransactionInfo, ToolAssociationInfo,
    TransactionInfo as ProjectTransactionInfo, TransactionListener,
    TransactionStatus, Version as ProjectVersion,
};
pub use project::data::{
    ContentHandler, DefaultCheckinHandler, DefaultProjectData, DomainFileIndex,
    DomainFolderChangeListenerList, DomainObjectChangeSupport, DomainObjectDBChangeSet,
    LinkHandler, MetadataManager, MISSING_CONTENT, OpenMode, OptionValue, OptionsDB,
    PluginConfig, PROGRAM_CONTENT, ToolState, ToolStateFactory, TransientDataManager,
    UNKNOWN_CONTENT,
};
pub use project::cmd::{
    BackgroundCommand, BackgroundCommandMonitor, Command, CommandManager, CommandResult,
    CompoundBackgroundCommand, CompoundCmd, MergeableBackgroundCommand,
};
pub use project::plugintool::{
    Plugin, PluginDescription, PluginEvent, PluginLifecycle, PluginManager as ProjectPluginManager,
    PluginToolInterface, ServiceInfo, ServiceManager,
};
pub use project::task::{
    GhidraTask, GTask, ScheduledTask, TaskDialogResult, TaskError, TaskMonitor,
    TaskScheduler, TaskState,
};
pub use project::protocol::{
    GhidraUrl, GhidraUrlError, GhidraUrlHandler, UrlResource, parse_ghidra_url,
};
pub use project::manager::{
    ProjectHandle, ProjectManager as ProjectManagerTrait, RepositoryAdapter,
    RepositoryServerAdapter, SaveState, ServerInfo, SimpleProjectManager, ToolChest,
    ToolManager, ToolServices, ToolTemplate, ProjectViewListener,
};
