//! Database-backed trace storage.
//!
//! Provides a SQLite-backed implementation of the trace model, ported from
//! Ghidra's `DBTrace` and associated managers.
//!
//! Sub-modules:
//! - `trace_db`: Main trace database.
//! - `trace_db_manager`: Trait for database managers.
//! - `trace_db_bookmark`: Bookmark manager.
//! - `trace_db_breakpoint`: Breakpoint location/specification manager.
//! - `trace_db_context`: Register context manager.
//! - `trace_db_data`: Data type manager.
//! - `trace_db_guest`: Guest platform manager.
//! - `trace_db_listing`: Code listing manager.
//! - `trace_db_map`: Address mapping manager.
//! - `trace_db_memory`: Memory state manager.
//! - `trace_db_module`: Module/section manager.
//! - `trace_db_program`: Program view manager.
//! - `trace_db_property`: Property map manager.
//! - `trace_db_space`: Address space manager.
//! - `trace_db_stack`: Stack frame manager.
//! - `trace_db_symbol`: Symbol/reference manager.
//! - `trace_db_target`: Target object manager.
//! - `trace_db_thread`: Thread/process manager.
//! - `trace_db_time`: Time/snap manager.
//! - `trace_db_time_viewport`: Time viewport for viewing.

pub mod listing;
pub mod target_impl;
pub mod trace_db;
pub mod trace_db_address;
pub mod trace_db_listing_deep;
pub mod trace_db_register_context_deep;
pub mod trace_db_cache;
pub mod trace_db_addr_property;
pub mod trace_db_bookmark;
pub mod trace_db_breakpoint;
pub mod trace_db_cache_containing;
pub mod trace_db_class_symbol;
pub mod trace_db_cache_sequence;
pub mod trace_db_changeset;
pub mod trace_db_content;
pub mod trace_db_content_handler;
pub mod trace_db_context;
pub mod trace_db_data;
pub mod trace_db_data_settings;
pub mod trace_db_data_type_mgr;
pub mod trace_db_direct_listener;
pub mod trace_db_equate;
pub mod trace_db_equate_space;
pub mod trace_db_event_scope;
pub mod trace_db_fragment;
pub mod trace_db_guest;
pub mod trace_db_method;
pub mod trace_db_instruction;
pub mod trace_db_label;
pub mod trace_db_link_content;
pub mod trace_db_listing;
pub mod trace_db_manager;
pub mod trace_db_map;
pub mod trace_db_mem_buffer;
pub mod trace_db_memory;
pub mod trace_db_module;
pub mod trace_db_obj_internals;
pub mod trace_db_overlay;
pub mod trace_db_program;
pub mod trace_db_program_view;
pub mod trace_db_property;
pub mod trace_db_snapshot;
pub mod trace_db_space;
pub mod trace_db_spatial;
pub mod trace_db_stack;
pub mod trace_db_symbol;
pub mod trace_db_target;
pub mod trace_db_target_iface;
pub mod trace_db_thread;
pub mod trace_db_time;
pub mod trace_db_time_viewport;
pub mod trace_db_user_data;
pub mod trace_db_util;
pub mod trace_db_utils;
pub mod trace_db_value_storage;
pub mod trace_db_visitor_ext;
pub mod trace_db_extras;
pub mod trace_db_map_impl;
pub mod trace_db_memory_impl;
pub mod trace_db_ref_impl;
pub mod trace_db_symbol_impl;
pub mod trace_db_value_spatial;
pub mod trace_db_visitors;
pub mod trace_db_database;
pub mod trace_db_object_cache;
pub mod trace_db_object_value_data;
pub mod trace_db_object_value_behind;
pub mod trace_db_object_value_query;
pub mod trace_db_symbol_manager;
pub mod trace_db_label_symbol;
pub mod trace_db_namespace_symbol;
pub mod trace_db_reference_manager;
pub mod trace_db_reference_space;
pub mod trace_db_memory_space_impl;
pub mod trace_db_memory_buffer;
pub mod trace_db_memory_block;
pub mod trace_db_object_process;
pub mod trace_db_object_register;
pub mod trace_db_object_memory;
pub mod trace_db_program_view_impl;
pub mod trace_db_program_view_listing;
pub mod trace_db_program_view_memory;

// New modules from Debugger / Framework-TraceModeling port
pub mod trace_db_bookmark_type;
pub mod trace_db_guest_ext;
pub mod trace_db_listing_views_ext;
pub mod trace_db_map_occlusion;
pub mod trace_db_program_view_ext;
pub mod trace_db_symbol_views_ext;
pub mod trace_db_target_iface_ext;
pub mod trace_db_target_storage_ext;

// Additional modules from remaining Debug module ports
pub mod trace_db_value_box;
pub mod trace_db_value_query;
pub mod trace_db_object_aggregate;
pub mod trace_db_field_codec;
pub mod trace_db_spatial_tree;

pub use trace_db::TraceDatabase;
pub use trace_db_database::{
    DBTrace, DBTraceChangeSet as TraceDatabaseChangeSet, TraceDatabaseConfig,
    TraceDirectChangeListener as TraceDatabaseDirectListener,
};
pub use trace_db_data_settings::{DataSettingsAdapter, DataSettingsOperations, SettingsValue};
pub use trace_db_data_type_mgr::{DataTypeConflictHandler, DataTypeEntry, TraceDataTypeManager};
pub use trace_db_address::{
    AddressSpaceManager, AddressSpaceType, OverlaySpaceInfo, TraceAddressSpace,
};
pub use trace_db_breakpoint::{
    DbTraceBreakpointLocation, DbTraceBreakpointManager, DbTraceBreakpointSpec,
};
pub use trace_db_guest::{
    DbTraceGuestLanguage, DbTraceGuestPlatform, DbTraceHostPlatform, DbTracePlatformManager,
};
pub use trace_db_manager::{DbTraceManager, TraceDbError, TraceDbResult};
pub use trace_db_target_iface::{
    DbObjectActivatable, DbObjectAggregate, DbObjectEnvironment, DbObjectExecutionStateful,
    DbObjectFocusScope, DbObjectTogglable, DbTargetInterfaceRegistry,
};
pub use trace_db_changeset::{ChangeOperation, ChangeRecord, DbTraceChangeSet};
pub use trace_db_direct_listener::{
    DirectChangeKind, DirectChangeEvent, DirectChangeListener, DirectChangeListenerSet,
};
pub use trace_db_time_viewport::{SingleSnapViewport, TraceTimeViewport};
pub use trace_db_user_data::{DbTraceUserData, UserDataEntry};
pub use trace_db_utils::{TraceDatabaseInfo, TraceDbUtils};
pub use trace_db_addr_property::{
    AddressPropertyEntry, DBTraceAddressPropertyApiView, DBTraceAddressPropertyManager,
};
pub use trace_db_equate_space::DBTraceEquateSpace;
pub use trace_db_program_view::{
    ProgramViewBookmark, ProgramViewBookmarkManager, ProgramViewChangeSet, ProgramViewEquate,
    ProgramViewEquateTable, ProgramViewFragment, ProgramViewFunction, ProgramViewFunctionManager,
    ProgramViewSnapshot,
};
pub use trace_db_value_storage::{
    ImmutableValueBox, ImmutableValueShape, ValueBox, ValueShape, ValueSpace, ValueTriple,
};
pub use trace_db_event_scope::{DbEventScopeManager, DbObjectEventScope};
pub use trace_db_method::{DbMethodManager, DbObjectMethod, MethodParameter};
pub use trace_db_snapshot::{DbTraceSnapshot, DbTraceTimeManager};
pub use trace_db_value_spatial::{
    ImmutableValueShape as SpatialImmutableValueShape, RecAddress, ValueBox as SpatialValueBox,
    ValueShape as SpatialValueShape, ValueSpace as SpatialValueSpace,
    ValueTriple as SpatialValueTriple,
};
pub use trace_db_visitors::{
    AllPathsVisitor, AncestorsRelativeVisitor, AncestorsRootVisitor,
    CanonicalSuccessorsRelativeVisitor, OrderedSuccessorsVisitor, SuccessorsRelativeVisitor,
    TraceObjectVisitor, TraversalDirection, TreeTraversal, VisitorAction,
};

// New modules from Framework-TraceModeling port
pub use trace_db_object_cache::{CachePerDbTraceObject, Cached, CachedLifespanValues, SnapKey};
pub use trace_db_object_value_data::{
    DbTraceObjectValueData, PrimitiveValue, ValueKind,
};
pub use trace_db_object_value_behind::{BehindValue, DbTraceObjectValueBehind};
pub use trace_db_object_value_query::{
    HyperDirection, QueryBound, TraceObjectValueQuery,
};
pub use trace_db_symbol_manager::{
    SourceType, SymbolId, SymbolType, TraceDbSymbolManager, TraceSymbolEntry,
};
pub use trace_db_label_symbol::DbTraceLabelSymbol;
pub use trace_db_namespace_symbol::{DbTraceNamespaceSymbol, DbTraceNamespaceSymbolView};
pub use trace_db_reference_manager::{
    DBTraceOffsetReference, DBTraceShiftedReference, DBTraceStackReference,
    TraceDbReferenceManager, TraceReferenceEntry, TraceReferenceKind,
};
pub use trace_db_reference_space::{
    DbTraceReferenceSpace, DbTraceSnapSelectedReferenceSpace, SpaceReference,
};
pub use trace_db_memory_space_impl::{
    DbTraceMemoryBlockEntry, DbTraceMemoryBufferEntry, DbTraceMemoryRegion,
    DbTraceMemorySpaceImpl, DbTraceMemoryStateEntry, BLOCK_SHIFT, BLOCK_MASK, BLOCK_SIZE,
};
pub use trace_db_memory_buffer::{DbTraceEmptyMemBuffer, DbTraceMemBuffer, MemoryStateQueryResult};
pub use trace_db_memory_block::CompressedMemoryBlock;
pub use trace_db_object_process::DbTraceObjectProcess;
pub use trace_db_object_register::{DbTraceObjectRegister, DbTraceObjectRegisterContainer};
pub use trace_db_object_memory::DbTraceObjectMemory;
pub use trace_db_program_view_impl::{
    DbTraceProgramViewImpl, DbTraceVariableSnapProgramView,
    ProgramViewBookmark as ImplProgramViewBookmark,
    ProgramViewChangeSet as ImplProgramViewChangeSet,
    ProgramViewSnapshot as ImplProgramViewSnapshot,
};
pub use trace_db_program_view_listing::{
    DbTraceProgramViewListing, ProgramViewCodeUnitType,
    ProgramViewEquate as ListingProgramViewEquate,
    ProgramViewEquateTable as ListingProgramViewEquateTable,
    ProgramViewFragment as ListingProgramViewFragment,
    ProgramViewListingEntry,
};
pub use trace_db_program_view_memory::{
    DbTraceProgramViewMemory, ProgramViewBookmarkEntry,
    ProgramViewBookmarkManager as MemProgramViewBookmarkManager,
    ProgramViewMemoryBlock, ProgramViewProgramContext, ProgramViewPropertyMap,
    ProgramViewPropertyMapManager, ProgramViewReference, ProgramViewReferenceManager,
    ProgramViewRegisterValue, ProgramViewSymbol, ProgramViewSymbolTable,
};

// Re-exports from new modules
pub use trace_db_bookmark_type::DbTraceBookmarkType;
pub use trace_db_guest_ext::{
    GuestPlatformMappedMemory, InternalTracePlatform, ObjectRegisterSupport,
};
pub use trace_db_listing_views_ext::{
    CodeUnitViewEntry, CodeUnitsMemoryView, ComposedCodeUnitsView,
};
pub use trace_db_map_occlusion::{
    OcclusionDirection, OcclusionEntry, OcclusionIntoFutureIterator, OcclusionIntoPastIterator,
};
pub use trace_db_program_view_ext::{
    ProgramRegisterValue, ProgramViewProgramContext as ProgramViewProgramContextExt,
    ProgramViewReference as ProgramViewReferenceEntry,
    ProgramViewReferenceManager as ProgramViewReferenceManagerExt,
    ProgramViewReferenceType,
};
pub use trace_db_symbol_views_ext::{
    SnapSelectedReferenceSpace, SymbolMultipleTypesNoDuplicatesView,
    SymbolMultipleTypesView, SymbolMultipleTypesWithAddressNoDuplicatesView,
    SymbolMultipleTypesWithLocationView,
};
pub use trace_db_target_iface_ext::{
    DbObjectExecutionStateful as ExtendedExecutionStateful,
    DbObjectFocusScope as ExtendedFocusScope,
    DbObjectTogglable as ExtendedTogglable,
};
pub use trace_db_target_storage_ext::{
    AddressRange, CachedValueEntry, ObjectValueMapAddressSetView,
    ObjectValueWriteBehindCache, TraceObjectValueStorage,
};

// Additional modules from remaining Debug module ports
pub mod trace_db_listing_extras;
pub mod trace_db_target_extras;
pub mod trace_db_symbol_extras;

// New modules ported from Framework-TraceModeling and Debugger
pub mod trace_db_space_based;
pub mod trace_db_property_impl;
pub mod trace_db_addr_snap_map;
pub mod trace_db_static_mapping;
pub mod trace_db_content_handler_impl;
pub mod trace_db_module_impl;
pub mod trace_db_abstract_views;

pub use trace_db_field_codec::{
    DBTraceFieldCodec, EncodedField, FieldDataType, FieldValue, TraceObjectFieldCodecSet,
};
pub use trace_db_spatial_tree::{RStarEntry, RStarTree, SpatialRect};

// Re-exports from listing extras
pub use trace_db_listing_extras::{
    CodeUnitProperties, CodeUnitViewEntry as ListingCodeUnitEntry,
    CodeUnitsMemoryView as ListingCodeUnitsView, DBTraceCodeUnitAdapter,
    DBTraceCommentAdapter, DBTraceDataAdapter, DataComponent, FlowOverride,
    TraceCodeComment, TraceCommentType,
};

// Re-exports from target extras
pub use trace_db_target_extras::{
    CacheKey as TargetCacheKey, DBTraceObject as TraceDbObject,
    DBTraceObjectFieldCodec, DBTraceObjectManager as TraceDbObjectMgr,
    DBTraceObjectValueAddressSetView, DBTraceObjectValueWriteBehindCache,
    ObjectValue as TraceObjectValue, ObjectValueType,
};

// Re-exports from symbol extras
pub use trace_db_symbol_extras::{
    DBTraceClassSymbolView, DBTraceEquate, DBTraceLabelSymbolView,
    MultiTypeSymbolView, SourceType as SymSourceType, SymbolType as SymType,
    TraceDbSymbolManager as SymManager, TraceSymbolEntry as SymEntry,
};

// Re-exports from new Framework-TraceModeling modules
pub use trace_db_space_based::{
    DbTraceSpaceBased, DbTraceSpaceEntry, DelegatingManager, RegisterContainerBinding,
    SpaceBasedManager, TraceDbAddressSpace,
};
pub use trace_db_property_impl::{
    known_properties, DbTraceAddressPropertyManager, PropertyMapEntry, PropertyMapValue,
    TracePropertyMap,
};
pub use trace_db_addr_snap_map::{
    AddressSnapPropertyEntry, AddressSnapPropertyMap, AddressSnapRange as AddrSnapPropertyRange,
    PointQuery, RangeQuery,
};
pub use trace_db_static_mapping::{
    DbTraceStaticMappingManager, StaticMapping,
};
pub use trace_db_content_handler_impl::{
    LinkContentHandler, TraceContentHandler, TraceContentMetadata, TraceContentType,
};
pub use trace_db_module_impl::{
    DbTraceModuleManager, TraceModuleEntry, TraceSectionEntry,
};

// Additional modules from remaining Debug module ports
pub mod trace_db_transaction;
pub use trace_db_transaction::{TraceTransaction, TraceTransactionManager};

// Internal listing/symbol view abstractions ported from Framework-TraceModeling
pub mod trace_db_listing_internals;
pub mod trace_db_symbol_internals;
pub use trace_db_listing_internals::{
    AbstractBaseDBTraceDefinedUnitsView, AbstractDBTraceDataComponent,
    AbstractSingleDBTraceCodeUnitsView, AbstractWithUndefinedDBTraceCodeUnitsMemoryView,
    InternalCodeUnitKind, InternalTraceBaseDefinedUnitsView, InternalTraceDefinedDataView,
    ListingClearOp,
};
pub use trace_db_symbol_internals::{
    AbstractDBTraceSymbolSingleTypeView, AbstractDBTraceSymbolSingleTypeWithAddressView,
    AbstractDBTraceSymbolSingleTypeWithLocationView, SymbolQueryFilter,
};

// New modules from remaining Debug port (Framework-TraceModeling / Debugger)
pub mod trace_db_address_encode;
pub mod trace_db_property_api_view;
pub mod trace_db_program_byte_cache;
pub mod trace_db_program_mem_blocks;
pub mod trace_db_program_context_view;
pub mod trace_db_program_property_maps;
pub mod trace_db_program_root_module;
pub mod trace_db_program_symbol_table;
pub mod trace_db_program_func_manager;
pub mod trace_db_program_ref_manager_view;
pub mod trace_db_raw_data_adapter;
pub mod trace_db_raw_code_unit_adapter;
