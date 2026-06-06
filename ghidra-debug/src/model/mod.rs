//! Core trace model types ported from Ghidra's Framework-TraceModeling.
//!
//! This module provides the fundamental types for representing a debug trace:
//! time (Lifespan, TraceSnapshot), space (AddressSnap), threads, modules,
//! breakpoints, memory state, execution state, bookmarks, code listing,
//! symbols, stacks, register context, and guest platforms.

pub mod address_snap;
pub mod bookmark;
pub mod bookmark_ops;
pub mod breakpoint;
pub mod breakpoint_spec;
pub mod changeset;
pub mod code_ops;
pub mod context;
pub mod data;
pub mod data_type;
pub mod domain_object_listener;
pub mod duplicate_key;
pub mod equate_ops;
pub mod execution_state;
pub mod guest;
pub mod lifespan;
pub mod listing;
pub mod listing_views;
pub mod map;
pub mod mem_buffer;
pub mod memory;
pub mod memory_ext;
pub mod memory_flag;
pub mod module;
pub mod module_ops;
pub mod options;
pub mod program;
pub mod property;
pub mod reference_ext;
pub mod reference_ops;
pub mod register;
pub mod register_context;
pub mod register_context_ops;
pub mod register_value;
pub mod stack;
pub mod symbol;
pub mod symbol_types;
pub mod symbol_views;
pub mod symbol_views_extra;
pub mod target_iface;
pub mod target_info;
pub mod target_path;
pub mod target_manager;
pub mod target_object;
pub mod target_schema;
pub mod target_schema_ext;
pub mod target_value;
pub mod thread;
pub mod step_trait;
pub mod time;
pub mod time_schedule;
pub mod schedule;
pub mod trace;
pub mod trace_data_ops;
pub mod trace_data_viewport;
pub mod trace_emulation;
pub mod trace_event;
pub mod trace_location;
pub mod trace_method;
pub mod trace_object_value;
pub mod trace_span;

// Extended modules ported from remaining Java packages
pub mod target_info_ext;
pub mod target_schema_xml;

pub mod address_translator;
pub mod experiment;
pub mod location_tracking;
pub mod map_proposal;

pub use address_snap::{AddressSnap, TraceAddressSnapRange};
pub use address_translator::{
    AddressTranslator, MappingChangeEvent, MappingChangeKind, TranslatedAddress, TranslationEntry,
};
pub use bookmark::{TraceBookmark, TraceBookmarkManager, TraceBookmarkType};
pub use breakpoint::{BreakpointKindSet, TraceBreakpointKind};
pub use breakpoint_spec::{
    TraceBreakpointCommon, TraceBreakpointLocation, TraceBreakpointSpec,
};
pub use changeset::{ChangeType, TraceChangeRecord, TraceChangeSet};
pub use context::{ContextAddressRange, ContextRegisterValue, LanguageId, RegisterId, TraceRegisterContextOperations};
pub use data_type::{DataTypeConflictHandler, TraceBasedDataTypeManager, TraceDataType};
pub use domain_object_listener::{
    DomainObjectChangeRecord, DomainObjectChangedEvent, DomainObjectEvent, TraceDomainObjectListener,
};
pub use duplicate_key::DuplicateKeyException;
pub use execution_state::TraceExecutionState;
pub use guest::{TraceGuestPlatformMappedRange, TracePlatform, TracePlatformManager};
pub use lifespan::{is_scratch, Lifespan};
pub use listing::{CodeUnitType, TraceCodeManager, TraceCodeUnit, TraceCodeIndex};
pub use listing_views::{
    TraceCodeUnitsView, TraceDataView, TraceDefinedDataView, TraceDefinedUnitsView,
    TraceInstructionsView, TraceUndefinedDataView,
};
pub use map::TraceAddressSnapRangePropertyMap;
pub use memory::{TraceMemoryRegion, TraceMemoryState};
pub use memory_ext::{MemoryRegionBuilder, TraceMemorySpaceInputStream, TraceOverlappedRegionException};
pub use memory_flag::{MemoryFlagSet, RegisterValueConverter, RegisterValueError, TraceMemoryFlag};
pub use module::{TraceModule, TraceSection, TraceStaticMapping};
pub use options::{CompilerSpecId, TraceLanguageId, TraceOptionsManagerExt};
pub use program::{TickSpecificTraceView, TraceProgramView, TraceProgramViewMemory, TraceVariableSnapProgramView};
pub use property::{TracePropertyMap, TraceBoolPropertyMap, TraceIntPropertyMap, TraceStringPropertyMap};
pub use register::{TraceRegister, TraceRegisterContainer, TraceRegisterGroup};
pub use register_context::{RegisterDefinedState, TraceRegisterContextManager, TraceRegisterValue};
pub use register_value::{RegisterSizeConverter, RegisterValueException};
pub use reference_ext::{TraceOffsetReference, TraceReferenceVariant, TraceShiftedReference, TraceStackReference};
pub use stack::{TraceStack, TraceStackFrame, TraceStackManager};
pub use symbol::{
    TraceEquate, TraceEquateReference, TraceReference, TraceReferenceKind,
    TraceSymbol, TraceSymbolKind, TraceSymbolManager,
};
pub use symbol_views::{
    TraceClassSymbolView, TraceEquateView, TraceLabelSymbolView, TraceNamespaceSymbolView,
    TraceReferenceView, TraceSymbolNoDuplicatesView, TraceSymbolView,
};
pub use symbol_views_extra::{
    TraceSymbolWithAddressNoDuplicatesView, TraceSymbolWithAddressView,
    TraceSymbolWithLocationView,
};
pub use target_iface::{
    ExecutionState, TraceActivatable, TraceAggregate, TraceEnvironment, TraceEventScope,
    TraceExecutionStateful, TraceFocusScope, TraceMethod, TraceObjectInterface, TraceRegion,
    TraceTargetEvent, TraceTargetProcess, TraceTargetRegisterContainer, TraceTargetRegisterValue,
    TraceTargetSection, TraceTargetStack, TraceTargetStackFrame, TraceTogglable,
};
pub use target_info::{builtin as target_builtin, TraceObjectInfo, TraceObjectInterfaceFactory, TraceObjectInterfaceRegistry};
pub use target_manager::{TargetObjectError, TraceObjectManager};
pub use target_object::{ConflictResolution, TraceObject};
pub use target_schema::{AttributeSchema, MinimalSchemaContext, PrimitiveTraceObjectSchema, SchemaBuilder, SchemaContext, SchemaName, TraceObjectSchemaDef};
pub use target_value::{PrimitiveValue, TraceObjectValPath, TraceObjectValue, TruncateResult};
pub use thread::{TraceProcess, TraceThread};
pub use time::{TraceSchedule, TraceSnapshot, TraceTimeManager};
pub use step_trait::{PatchStep as StepPatchStep, SkipStep, StepKind as StepKindTrait, StepType, TickStep as StepTickStep};
pub use time_schedule::{CompareResult, PatchStep, ScheduleSequence, ScheduleStep, Scheduler, StepKind, TickStep};
pub use trace::{Trace, TraceOptionsManager, TraceTimeViewport, TraceUserData};
pub use trace_data_ops::{
    CommentType, DataSettingsAdapter, DataTypeConflictHandler as DataOpConflictHandler,
    ReferenceInfo, ReferenceType, SettingsValue, TraceDataSettings, TraceDataSettingsOperations,
    TraceDataTypeEntry as DataOpDataTypeEntry,
};
pub use trace_emulation::{
    EmulationMode, EmulationStateSnapshot, EmulationStatus, TraceEmulationIntegration,
    UnknownStatePcodeExecutionException,
};
pub use trace_location::{TraceClosedException, TraceLocation, TraceUniqueObject, UniqueObjectBase};
pub use trace_method::{
    ArgValue, MethodArguments, MethodParameter, MethodResult, MethodValue, TraceMethodDescriptor,
};
pub mod defaults;
pub mod operations_ext;
pub mod register_value_convert;
pub mod trace_address_snap_range;
pub mod trace_conflicted_mapping;
pub mod trace_data_type;
pub mod trace_data_type_manager;
pub mod trace_event_listener;
pub mod trace_memory_manager;
pub mod trace_module_manager;
pub mod trace_overlay;
pub mod trace_register;
pub mod trace_stack_manager;
pub mod trace_thread_manager;
pub mod trace_model_extras;

pub use trace_data_viewport::TraceDataViewport;
pub use trace_span::TraceSpan;

pub use bookmark_ops::{TraceBookmarkOperations, TraceBookmarkSpace, TraceBookmarkSpaceManager};
pub use code_ops::{TraceCodeOperations, TraceCodeSpace, TraceCodeSpaceManager};
pub use equate_ops::{EquateSpaceBuilder, TraceEquateOperations, TraceEquateSpace};
pub use module_ops::{
    ModuleSpaceBuilder, TraceConflictedMappingException, TraceModuleOperations, TraceModuleSpace,
};
pub use reference_ops::{ReferenceOrder, TraceReferenceOperations, TraceReferenceSpace};
pub use register_context_ops::{
    ContextMaskedRange, MaskedContextValue, TraceRegisterContextSpace, TraceRegisterContextSpaceOps,
};
pub use symbol_types::{
    TraceClassSymbol, TraceLabelSymbol, TraceNamespaceSymbol, TraceSymbolWithLifespan,
};
pub use trace_event::{
    LogLevel, TraceEvent, TraceEventManager, TraceEventType, TraceLogEntry, TraceLogManager,
};
pub use trace_object_value::{
    ChangeCollector, TargetTreeSnapshot, TraceObjectChangeListener, ValueChangeEvent, ValueChangeKind,
};
pub use location_tracking::{
    AutoMapMatchStrategy, AutoMapSpec, AutoReadMemorySpec, GoToInput, LocationTrackingSpec,
    TrackingEvent,
};
pub use map_proposal::{
    MapProposal, MapProposalSet, MapProposalSource, ModuleMapProposal, ProposedMapping,
    RegionMapProposal, RegionPermissions, SectionMapProposal, SectionMapping,
};

pub mod trace_address_snap_space;
pub mod trace_code_manager_impl;
pub mod trace_memory_space;
pub use trace_address_snap_space::{
    AddressSnapRange, TraceAddressSnapSpace, for_address_space,
};

pub mod trace_memory_ops;
pub use trace_memory_ops::{
    InMemoryTraceMemory, MemoryRegionInfo, TraceMemoryOperations,
    find_first_non_matching, is_state_entirely as memory_is_state_entirely,
};

pub use experiment::{
    DebugExperiment, DiagnosticBoundingBox, RStarTreeDiagnostics, TracePerformanceMetrics,
};

pub use trace_data_type::{DataTypeKind, TraceDataType as TraceDataTypeExt};
pub use trace_data_type::TraceDataTypeManager as TraceDataTypeMgrExt;
pub use trace_data_type_manager::TraceDataTypeManager as TraceDataTypeRegistry;
pub use trace_event_listener::{
    CompositeTraceListener, TraceDomainChangeRecord, TraceDomainObjectEventListener, TraceEventKind,
};
pub use trace_memory_manager::TraceMemoryRegionFull;
pub use trace_memory_manager::TraceMemoryManager as TraceMemoryManagerExt;
pub use trace_memory_manager::TraceMemorySpace as TraceMemorySpaceExt;
pub use trace_module_manager::TraceModuleManager as TraceModuleManagerExt;
pub use trace_overlay::{TraceOverlayManager, TraceOverlaySpace};
pub use trace_register::TraceRegister as TraceRegisterDef;
pub use trace_register::TraceRegisterContainer as TraceRegisterContainerExt;
pub use trace_register::TraceRegisterGroup as TraceRegisterGroupExt;
pub use trace_stack_manager::TraceStack as TraceCallStack;
pub use trace_stack_manager::TraceStackFrame as TraceCallStackFrame;
pub use trace_stack_manager::TraceStackManager as TraceStackManagerExt;
pub use trace_thread_manager::TraceThreadManager as TraceThreadManagerExt;

pub use trace_model_extras::{
    TraceAddressPropertyManager as TraceAddrPropMgr, TraceDataUnit, TraceMemoryObject as TraceMemObj,
    TraceMemoryRegionEntry as TraceMemRegionEntry, TracePropertyMapOperations, TracePropertyMapSpace,
    TraceReferenceEntry as TraceRefEntry, TraceReferenceManagerOps as TraceRefMgrOps,
    TraceReferenceType as TraceRefType,
};

pub mod trace_emulation_state;
pub use trace_emulation_state::{
    TraceByteState, TraceMemoryStateArithmetic, TraceMemoryStatePiece,
};

// New model modules from remaining Debug port
pub mod trace_property_map_ops;
pub mod trace_program_view_ext;
pub mod trace_memory_space_input_stream;
pub mod trace_data_type_ops;
pub mod memory_stream;

// Symbol view modules (ported from trace/model/symbol)
pub mod trace_label_symbol_view;
pub mod trace_namespace_symbol_view;
pub mod trace_class_symbol_view;
pub mod trace_symbol_view;
pub mod trace_symbol_no_duplicates_view;
pub mod trace_equate_reference;
pub mod trace_equate_operations;
pub mod trace_reference_operations;
pub mod trace_symbol_with_lifespan;

// Listing view modules (ported from trace/model/listing)
pub mod trace_code_space;
pub mod trace_code_operations;
pub mod trace_data_view;

// Memory modules (ported from trace/model/memory)
pub mod trace_memory_operations;

// Core model modules (ported from trace/model)
pub mod trace_change_set;
pub mod trace_user_data;
pub mod trace_time_viewport;
pub mod trace_closed_exception;
pub mod default_trace_location;
pub mod trace_unique_object;

// Extended trace options and user preferences
pub mod trace_options_ext;
pub use trace_options_ext::{TraceOptionValue, TraceOptionsStore, TraceUserPreferences};
pub mod default_address_snap;
pub mod default_trace_span;
