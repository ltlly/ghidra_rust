//! Debug API model types for action contexts.
//!
//! Ported from Ghidra's `ghidra.debug.api.model` package.

pub mod debugger_object_action_context;
pub mod debugger_single_object_path_action_context;

pub use debugger_object_action_context::DebuggerObjectActionContext;
pub use debugger_single_object_path_action_context::DebuggerSingleObjectPathActionContext;
