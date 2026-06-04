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

pub mod code_completion;
mod interpreter;
mod plugin;
pub mod pydev_utils;
mod script;
mod utils;

pub use code_completion::JythonCodeCompletionFactory;
pub use interpreter::GhidraJythonInterpreter;
pub use plugin::JythonPlugin;
pub use pydev_utils::PyDevUtils;
pub use script::{JythonScript, JythonScriptProvider};
pub use utils::JythonUtils;
