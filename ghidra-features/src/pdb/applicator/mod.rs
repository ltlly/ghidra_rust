//! PDB Applicator -- applies parsed PDB types and symbols to a program.
//!
//! Ports Ghidra's `ghidra.app.util.pdb.pdbapplicator` package.
//!
//! This module contains the core machinery for taking parsed PDB data
//! (types from TPI/IPI, symbols from DBI module streams, and debug info
//! from the DBI header) and applying it to a Ghidra [`Program`] by creating
//! data types, function signatures, labels, and other analysis artifacts.
//!
//! # Architecture
//!
//! The application pipeline is structured around three main components:
//!
//! - [`DefaultPdbApplicator`] -- The main orchestrator that drives the
//!   full application lifecycle: parsing, type application, symbol
//!   application, and debug info application.
//!
//! - [`TypeApplierFactory`] -- Dispatches type records to specialized
//!   appliers (composite, enum, pointer, array, procedure, etc.).
//!
//! - [`SymbolApplierFactory`] -- Dispatches symbol records to specialized
//!   appliers (data, procedure, public, label, UDT, thunk, etc.).
//!
//! # Usage
//!
//! ```rust,no_run
//! use ghidra_features::pdb::applicator::DefaultPdbApplicator;
//!
//! let mut applicator = DefaultPdbApplicator::new();
//! # fn get_pdb_bytes() -> &'static [u8] { &[] }
//! applicator.apply_bytes(get_pdb_bytes()).expect("apply failed");
//!
//! let metrics = applicator.metrics();
//! println!("Types applied: {}", metrics.types_applied());
//! println!("Symbols applied: {}", metrics.symbols_applied());
//! ```

pub mod default_pdb_applicator;
pub mod symbol_applier_factory;
pub mod type_applier_factory;

// Re-export the main public types for convenience.
pub use default_pdb_applicator::{DefaultPdbApplicator, DefaultPdbApplicatorError, ApplicatorPhase};
pub use symbol_applier_factory::{
    SymbolApplierFactory, SymbolApplyError, SymbolApplicationResult,
};
pub use type_applier_factory::{
    TypeApplierFactory, TypeApplyError, AppliedType, CompositeKind,
};
