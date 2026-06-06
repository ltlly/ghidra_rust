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
pub mod pcode;
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
pub use pcode::{
    AttributeId, BlockCondition, BlockCopy, BlockDoWhile, BlockEdge, BlockGoto,
    BlockGraph, BlockIfElse, BlockIfGoto, BlockInfLoop, BlockList, BlockMap,
    BlockMultiGoto, BlockProperIf, BlockSwitch, BlockType, BlockWhileDo,
    Decoder, DecoderException, DynamicHash, ElementId, Encoder,
    EquateSymbol as PcodeEquateSymbol, DataTypeSymbol as PcodeDataTypeSymbol,
    FunctionPrototype, GlobalSymbolMap, HighCodeSymbol, HighConstant,
    HighExternalSymbol, HighFunction, HighFunctionSymbol, HighFunctionShellSymbol,
    HighGlobal, HighLabelSymbol, HighLocal, HighOther, HighParam,
    HighSymbol as PcodeHighSymbol, HighVariable, HighVariableClass,
    JumpTable as PcodeJumpTable, LocalSymbolMap, OpCode, PcodeBlock, PcodeBlockBasic,
    PcodeDataTypeManager,
    PcodeOp, PcodeOpAST, SequenceNumber, SymbolEntry as PcodeSymbolEntry,
    Varnode, VarnodeAST,
};
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

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use error::GhidraError;

    // ---- Address types ----

    #[test]
    fn test_address_creation_and_null() {
        let addr = Address::new(0x401000);
        assert_eq!(addr.offset, 0x401000);
        assert!(!addr.is_null());
        assert!(Address::NULL.is_null());
    }

    #[test]
    fn test_address_arithmetic() {
        let a = Address::new(0x1000);
        let b = a.add(0x100);
        assert_eq!(b.offset, 0x1100);
        let c = b.sub(0x50);
        assert_eq!(c.offset, 0x10B0);
        assert_eq!(b.subtract(&a), 0x100);
    }

    #[test]
    fn test_address_next_prev() {
        let a = Address::new(100);
        assert_eq!(a.next().offset, 101);
        assert_eq!(a.prev().offset, 99);
    }

    #[test]
    fn test_address_successor_predecessor() {
        let a = Address::new(5);
        let b = Address::new(6);
        assert!(a.is_successor(&b));
        assert!(b.is_predecessor(&a));
        assert!(!a.is_predecessor(&b));
    }

    #[test]
    fn test_address_display() {
        let a = Address::new(0xDEAD);
        assert_eq!(format!("{}", a), "0000dead");
        assert_eq!(format!("{:x}", a), "0000dead");
    }

    #[test]
    fn test_address_from_str() {
        let a: Address = "0x401000".parse().unwrap();
        assert_eq!(a.offset, 0x401000);
        let b: Address = "DEAD".parse().unwrap();
        assert_eq!(b.offset, 0xDEAD);
    }

    #[test]
    fn test_address_conversions() {
        let a = Address::new(42);
        let u: u64 = a.into();
        assert_eq!(u, 42);
        let a2: Address = 100u64.into();
        assert_eq!(a2.offset, 100);
        let s: usize = Address::new(256).into();
        assert_eq!(s, 256);
    }

    #[test]
    fn test_address_operators() {
        let a = Address::new(100);
        let b = a + 50u64;
        assert_eq!(b.offset, 150);
        let c = b - 30u64;
        assert_eq!(c.offset, 120);
        let diff: i64 = b - a;
        assert_eq!(diff, 50);
        assert_eq!(a, 100u64);
    }

    // ---- AddressSpace ----

    #[test]
    fn test_address_space_construction() {
        let ram = AddressSpace::ram();
        assert_eq!(ram.get_name(), "ram");
        assert_eq!(ram.get_pointer_size(), 8);
        assert!(!ram.is_big_endian());
        assert_eq!(ram.get_type(), AddrSpaceType::Ram);
        assert!(ram.is_memory_space());
    }

    #[test]
    fn test_address_space_type_checks() {
        let reg = AddressSpace::register();
        assert!(reg.is_register_space());
        assert!(!reg.is_memory_space());

        let cst = AddressSpace::constant();
        assert!(cst.is_constant_space());

        let stk = AddressSpace::stack();
        assert!(stk.is_stack_space());

        let ext = AddressSpace::external();
        assert!(ext.is_external_space());
    }

    #[test]
    fn test_address_space_overlay() {
        let base = AddressSpace::ram();
        let overlay = AddressSpace::new_overlay("ov_ram", &base);
        assert!(overlay.is_overlay_space());
        assert_eq!(overlay.get_pointer_size(), base.get_pointer_size());
    }

    #[test]
    fn test_address_space_parse() {
        let ram = AddressSpace::ram();
        let addr = ram.get_address("0x401000").unwrap();
        assert_eq!(addr.offset, 0x401000);
        let addr2 = ram.get_address("DEADBEEF").unwrap();
        assert_eq!(addr2.offset, 0xDEADBEEF);
        assert!(ram.get_address("not_a_number").is_none());
    }

    #[test]
    fn test_address_space_max_address() {
        let ram = AddressSpace::ram();
        assert_eq!(ram.get_max_address().offset, u64::MAX);
    }

    #[test]
    fn test_address_space_valid_name() {
        assert!(AddressSpace::is_valid_name("ram"));
        assert!(!AddressSpace::is_valid_name(""));
        assert!(!AddressSpace::is_valid_name("bad:name"));
    }

    // ---- AddressRange ----

    #[test]
    fn test_address_range_basics() {
        let r = AddressRange::new(Address::new(0x1000), Address::new(0x1FFF));
        assert_eq!(r.len(), 0x1000);
        assert!(!r.is_empty());
        assert!(r.contains(&Address::new(0x1500)));
        assert!(!r.contains(&Address::new(0x2000)));
    }

    #[test]
    fn test_address_range_singleton() {
        let r = AddressRange::new(Address::new(0x100), Address::new(0x100));
        assert!(r.is_singleton());
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn test_address_range_intersection() {
        let a = AddressRange::new(Address::new(0x100), Address::new(0x200));
        let b = AddressRange::new(Address::new(0x180), Address::new(0x280));
        let i = a.intersection(&b).unwrap();
        assert_eq!(i.start.offset, 0x180);
        assert_eq!(i.end.offset, 0x200);

        let c = AddressRange::new(Address::new(0x300), Address::new(0x400));
        assert!(a.intersection(&c).is_none());
    }

    #[test]
    fn test_address_range_contains_range() {
        let outer = AddressRange::new(Address::new(0x0), Address::new(0xFFFF));
        let inner = AddressRange::new(Address::new(0x100), Address::new(0x200));
        assert!(outer.contains_range(&inner));
        assert!(!inner.contains_range(&outer));
    }

    #[test]
    fn test_address_range_iterator() {
        let r = AddressRange::new(Address::new(10), Address::new(14));
        let addrs: Vec<u64> = r.iter().map(|a| a.offset).collect();
        assert_eq!(addrs, vec![10, 11, 12, 13, 14]);
        assert_eq!(r.iter().len(), 5);
    }

    // ---- AddressFactory ----

    #[test]
    fn test_address_factory_basic() {
        let factory = AddressFactory::new();
        assert!(factory.get_space("ram").is_some());
        assert_eq!(factory.num_address_spaces(), 1);
        assert_eq!(factory.default_space().get_name(), "ram");
    }

    #[test]
    fn test_address_factory_multiple_spaces() {
        let factory = AddressFactory::with_spaces(
            vec![AddressSpace::ram(), AddressSpace::register()],
            "ram",
        );
        assert_eq!(factory.num_address_spaces(), 2);
        assert!(factory.get_space("register").is_some());
        assert!(factory.get_register_space().is_some());
    }

    #[test]
    fn test_address_factory_parse() {
        let factory = AddressFactory::new();
        let addr = factory.get_address_from_string("0x401000").unwrap();
        assert_eq!(addr.offset, 0x401000);
    }

    // ---- AddressSet ----

    #[test]
    fn test_address_set_add_range() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        assert_eq!(set.num_address_ranges(), 1);
        assert_eq!(set.num_addresses(), 0x101);
        assert!(set.contains(&Address::new(0x150)));
    }

    #[test]
    fn test_address_set_merge_adjacent() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        set.add_range(Address::new(0x201), Address::new(0x300));
        // Adjacent ranges may or may not merge depending on implementation;
        // verify all addresses are present
        assert!(set.contains(&Address::new(0x100)));
        assert!(set.contains(&Address::new(0x200)));
        assert!(set.contains(&Address::new(0x201)));
        assert!(set.contains(&Address::new(0x300)));
    }

    #[test]
    fn test_address_set_delete() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x300));
        set.delete_range(Address::new(0x500), Address::new(0x600));
        // After deleting [0x500, 0x600] from [0x100, 0x300], nothing changes
        assert!(set.contains(&Address::new(0x100)));
        assert!(set.contains(&Address::new(0x300)));
        assert!(!set.contains(&Address::new(0x500)));
    }

    #[test]
    fn test_address_set_intersection() {
        let mut a = AddressSet::new();
        a.add_range(Address::new(0x100), Address::new(0x200));
        let mut b = AddressSet::new();
        b.add_range(Address::new(0x180), Address::new(0x280));
        let inter = a.intersect(&b);
        assert_eq!(inter.num_addresses(), 0x81); // 0x180..0x200
    }

    #[test]
    fn test_address_set_union() {
        let mut a = AddressSet::new();
        a.add_range(Address::new(0x100), Address::new(0x150));
        let mut b = AddressSet::new();
        b.add_range(Address::new(0x200), Address::new(0x250));
        let union_set = a.union(&b);
        assert_eq!(union_set.num_address_ranges(), 2);
        assert_eq!(union_set.num_addresses(), 0x51 * 2);
    }

    #[test]
    fn test_address_set_difference() {
        let mut a = AddressSet::new();
        a.add_range(Address::new(0x100), Address::new(0x300));
        let mut b = AddressSet::new();
        b.add_range(Address::new(0x500), Address::new(0x600));
        let diff = a.difference(&b);
        // Removing non-overlapping range [0x500, 0x600] from [0x100, 0x300] leaves [0x100, 0x300]
        assert!(diff.contains(&Address::new(0x100)));
        assert!(diff.contains(&Address::new(0x300)));
        assert!(!diff.contains(&Address::new(0x500)));
    }

    #[test]
    fn test_address_set_boundaries() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x200));
        assert_eq!(set.get_min_address().unwrap().offset, 0x100);
        assert_eq!(set.get_max_address().unwrap().offset, 0x200);
    }

    #[test]
    fn test_address_set_contains_set() {
        let mut outer = AddressSet::new();
        outer.add_range(Address::new(0x0), Address::new(0xFFFF));
        let mut inner = AddressSet::new();
        inner.add_range(Address::new(0x100), Address::new(0x200));
        assert!(outer.contains_set(&inner));
        assert!(!inner.contains_set(&outer));
    }

    #[test]
    fn test_address_set_iterator() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0x100), Address::new(0x102));
        let ranges: Vec<_> = set.iter().collect();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start.offset, 0x100);
        assert_eq!(ranges[0].end.offset, 0x102);
    }

    // ---- Error types ----

    #[test]
    fn test_ghidra_error_display() {
        let err = GhidraError::NotFound("symbol".into());
        assert!(format!("{}", err).contains("Not found"));
        let err2 = GhidraError::MemoryError("segfault".into());
        assert!(format!("{}", err2).contains("Memory error"));
    }

    #[test]
    fn test_ghidra_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err: GhidraError = io_err.into();
        assert!(matches!(err, GhidraError::IoError(_)));
    }

    // ---- GenericAddress ----

    #[test]
    fn test_generic_address_from_address() {
        let ga = addr::GenericAddress::from_address(Address::new(0x1000));
        assert_eq!(ga.get_offset(), 0x1000);
        assert!(ga.is_memory_address());
    }

    #[test]
    fn test_generic_address_arithmetic() {
        let ga = addr::GenericAddress::from_address(Address::new(0x1000));
        let ga2 = ga.add_wrap(0x100);
        assert_eq!(ga2.get_offset(), 0x1100);
        let ga3 = ga2.subtract_wrap(0x50);
        assert_eq!(ga3.get_offset(), 0x10B0);
    }

    #[test]
    fn test_generic_address_next_previous() {
        let ga = addr::GenericAddress::from_address(Address::new(100));
        let next = ga.next().unwrap();
        assert_eq!(next.get_offset(), 101);
        let prev = next.previous().unwrap();
        assert_eq!(prev.get_offset(), 100);
    }

    #[test]
    fn test_generic_address_stack_display() {
        let space = Arc::new(AddressSpace::stack());
        let ga = addr::GenericAddress::new(space, 0x10);
        assert!(ga.is_stack_address());
        let s = ga.to_string_with_space(false);
        assert!(s.contains("Stack["));
    }

    // ---- SegmentedAddress ----

    #[test]
    fn test_segmented_address_real_mode() {
        let space = Arc::new(AddressSpace::new("seg16", 4, false, AddrSpaceType::Segmented, 10));
        let seg_space = addr::SegmentedAddressSpace::new_real_mode(space);
        let seg_addr = addr::SegmentedAddress::from_segment_offset(&seg_space, 0x1234, 0x5678);
        assert_eq!(seg_addr.get_segment(), 0x1234);
        assert_eq!(seg_addr.get_segment_offset(), 0x5678);
        let expected_flat = (0x1234u64 << 4) + 0x5678;
        assert_eq!(seg_addr.get_flat_offset(), expected_flat);
    }

    #[test]
    fn test_segmented_address_display() {
        let space = Arc::new(AddressSpace::new("seg16", 4, false, AddrSpaceType::Segmented, 10));
        let seg_space = addr::SegmentedAddressSpace::new_real_mode(space);
        let seg_addr = addr::SegmentedAddress::from_segment_offset(&seg_space, 0xABCD, 0x1234);
        assert_eq!(seg_addr.to_segment_string(), "abcd:1234");
    }

    // ---- OverlayAddressSpace ----

    #[test]
    fn test_overlay_address_space() {
        let base = Arc::new(AddressSpace::ram());
        let mut ov = addr::OverlayAddressSpace::new("my_overlay", base.clone(), 100, "my_overlay");
        assert!(ov.own_space().is_overlay_space());
        assert_eq!(ov.get_overlayed_space().get_name(), "ram");

        ov.add_overlay_region(Address::new(0x1000), Address::new(0x2000));
        assert!(ov.contains_offset(0x1500));
        assert!(!ov.contains_offset(0x3000));
    }

    #[test]
    fn test_overlay_address_translation() {
        let base = Arc::new(AddressSpace::ram());
        let mut ov = addr::OverlayAddressSpace::new("ov", base.clone(), 100, "ov");
        ov.add_overlay_region(Address::new(0x1000), Address::new(0x2000));

        let overlay_addr = ov.get_address(0x1500);
        assert_eq!(overlay_addr.get_address_space().get_name(), "ov");

        let base_addr = ov.get_address(0x5000);
        assert_eq!(base_addr.get_address_space().get_name(), "ram");
    }

    // ---- DataType ----

    #[test]
    fn test_data_type_basic() {
        use data::types::StructureDataType;
        let dt = StructureDataType::new("uint32");
        assert_eq!(dt.name, "uint32");
    }

    // ---- Symbol types ----

    #[test]
    fn test_source_type_values() {
        use symbol::SourceType;
        assert_ne!(SourceType::Default, SourceType::Imported);
        assert_ne!(SourceType::Imported, SourceType::Analysis);
        assert_eq!(SourceType::Default, SourceType::Default);
    }

    // ---- Program ----

    #[test]
    fn test_program_demo() {
        let prog = program::program::Program::demo();
        assert!(!prog.name.is_empty());
    }
}
