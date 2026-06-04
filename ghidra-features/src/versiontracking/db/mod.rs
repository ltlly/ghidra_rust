//! Database persistence layer for Version Tracking.
//!
//! Uses rusqlite to persist VT sessions, match sets, matches,
//! associations, tags, and markup items.

pub mod session_db;
pub mod table;
pub mod match_set_db;
pub mod match_db;
pub mod association_db;
pub mod tag_db;
pub mod markup_item_db;
pub mod address_correlator_db;

pub use session_db::VtSessionDB;
pub use table::{TableColumn, TableDescriptor, FieldType};
pub use match_set_db::VtMatchSetDB;
pub use match_db::VtMatchDB;
pub use association_db::VtAssociationDB;
pub use tag_db::VtMatchTagDB;
pub use markup_item_db::MarkupItemStorageDB;
pub use address_correlator_db::AddressCorrelatorDB;
