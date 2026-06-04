//! Function plugin -- ported from `ghidra.app.plugin.core.function`.
//!
//! Provides the [`FunctionPlugin`] and all associated actions for
//! creating, editing, deleting, and managing functions and their
//! variables.
//!
//! # Modules
//!
//! | Rust module | Java class(es)                                    |
//! |-------------|---------------------------------------------------|
//! | `plugin`    | `FunctionPlugin`                                  |
//! | `actions`   | All `*Action` classes (create, delete, edit, etc.) |
//! | `variable`  | Variable-related actions and helpers               |
//! | `thunk`     | Thunk function actions                             |
//! | `stack`     | Stack analysis and purge actions                   |

pub mod plugin;
pub mod actions;
pub mod variable;
pub mod thunk;
pub mod stack;

pub use plugin::*;
pub use actions::*;
pub use variable::*;
pub use thunk::*;
pub use stack::*;
