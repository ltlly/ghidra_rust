//! Address factory and overlay space management ported from
//! ghidra.trace.database.address.

pub mod address_db_field_codec;
pub mod db_trace_overlay_space_adapter;
pub mod overlay_space_entry;
pub mod trace_address_factory;

pub use db_trace_overlay_space_adapter::DBTraceOverlaySpaceAdapter;
pub use trace_address_factory::{AddressSpaceDesc, AddressSpaceType, TraceAddressFactory};
