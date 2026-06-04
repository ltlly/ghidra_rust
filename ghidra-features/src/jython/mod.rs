//! Jython -- Python scripting integration for Ghidra.
//!
//! This module ports the Jython extension from Ghidra's Java source.
//! It provides a Python interpreter integration that allows Ghidra
//! to execute Python (Jython) scripts for automation and analysis.
//!
//! # Architecture
//!
//! - [`GhidraJythonInterpreter`] -- The Python interpreter that
//!   provides script execution capabilities.
//!
//! - [`JythonScript`] -- Represents a Python script that can be
//!   executed within Ghidra.
//!
//! - [`JythonScriptProvider`] -- Manages script discovery and loading.
//!
//! - [`JythonPlugin`] -- The Ghidra plugin that provides the
//!   Python scripting console.
//!
//! - [`JythonUtils`] -- Utility functions for Jython integration.

mod interpreter;
mod script;
mod plugin;
mod utils;

pub use interpreter::GhidraJythonInterpreter;
pub use script::{JythonScript, JythonScriptProvider};
pub use plugin::JythonPlugin;
pub use utils::JythonUtils;
