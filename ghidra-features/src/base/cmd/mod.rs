//! Command pattern implementations for undoable program modifications.
//!
//! Ported from Ghidra's `ghidra.app.cmd` Java package. Each command
//! encapsulates a single mutation to a program for undo/redo support.
//! Commands are organized into sub-packages by domain:
//!
//! - [`comments`] -- set, append, paste comments
//! - [`data`] -- create arrays, structures, strings
//! - [`disassemble`] -- disassembly commands
//! - [`equate`] -- set/clear equates
//! - [`formats`] -- binary format analysis commands
//! - [`function`] -- create/delete/edit functions and variables
//! - [`label`] -- add/delete/rename labels
//! - [`memory`] -- add/delete/move memory blocks
//! - [`module`] -- program tree modularization
//! - [`refs`] -- add/remove/edit references
//! - [`register`] -- set register values

pub mod analysis;
pub mod comments;
pub mod data;
pub mod disassemble;
pub mod equate;
pub mod formats;
pub mod function;
pub mod label;
pub mod memory;
pub mod module;
pub mod refs;
pub mod register;
