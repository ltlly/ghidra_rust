//! Subroutine block model and analysis -- ported from Ghidra's
//! `SubroutineBlockModel.java`, `SubroutineDestReferenceIterator.java`,
//! `SubroutineSourceReferenceIterator.java`, `SubroutineMatch.java`,
//! `SubroutineMatchSet.java`, and `SubroutineModelCmd.java`.
//!
//! This module provides:
//!
//! - [`SubroutineBlockModel`] -- trait for models that partition code into subroutines
//! - [`CodeBlock`] / [`CodeBlockReference`] -- control-flow block abstractions
//! - [`SubroutineDestReferenceIterator`] -- iterates over destination references leaving a subroutine
//! - [`SubroutineSourceReferenceIterator`] -- iterates over source references entering a subroutine
//! - [`SubroutineMatch`] -- match info container for cross-program comparison
//! - [`SubroutineMatchSet`] -- a collection of subroutine matches between two programs
//! - [`SubroutineModelCmd`] -- command to organize a program tree by subroutine model

mod block_model;
mod dest_iter;
mod source_iter;
mod match_types;
mod model_cmd;

pub use block_model::*;
pub use dest_iter::*;
pub use source_iter::*;
pub use match_types::*;
pub use model_cmd::*;
