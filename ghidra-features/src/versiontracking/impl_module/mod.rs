//! Implementation details for Version Tracking.
//!
//! Contains the event system, change management, change records,
//! program correlator info, and markup item management.

pub mod events;
pub mod change_record;
pub mod program_correlator_info;
pub mod markup_item_impl;
pub mod markup_item_manager;
pub mod related_match;

pub use events::VTEvent;
pub use change_record::VersionTrackingChangeRecord;
pub use program_correlator_info::ProgramCorrelatorInfoImpl;
pub use markup_item_impl::MarkupItemImpl;
pub use markup_item_manager::MarkupItemManagerImpl;
pub use related_match::VTRelatedMatchImpl;
