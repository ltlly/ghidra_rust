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
pub mod trace_db_fragment;
pub mod trace_db_guest;
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
pub mod trace_db_property;
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
pub mod trace_db_visitor_ext;

pub use trace_db::TraceDatabase;
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
