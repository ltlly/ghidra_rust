//! External Program Management -- ported from Ghidra's
//! `ghidra.program.database.external` Java package.
//!
//! This module provides the database-backed implementations for
//! managing external programs (libraries) and their external location
//! references.  It provides:
//!
//! - [`ExternalLocationDB`] -- a database-backed external location
//! - [`ExternalManagerDB`] -- the manager for all external references
//! - [`ExternalManager`] trait re-export for use by the rest of the crate
//!
//! External locations represent symbols (functions or data) imported from
//! external libraries.

pub mod external_location_db;
pub mod external_manager_db;

pub use external_location_db::ExternalLocationDB;
pub use external_manager_db::ExternalManagerDB;

// Re-export the ExternalManager trait from ghidra-core
pub use ghidra_core::symbol::ExternalManager;
