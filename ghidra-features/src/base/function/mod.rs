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
pub mod tags;
pub mod variable;
pub mod variable_comment;
pub mod thunk;
pub mod stack;
pub mod stack_depth;
pub mod editor;
pub mod analyzers;
pub mod data_actions;
pub mod extra_analyzers;
pub mod editor_ui;
pub mod tags_ui;
pub mod table_model;
pub mod cycle_group;
pub mod function_data_view;
pub mod storage_editor;
pub mod extra_actions;

/// Function creation, deletion, and editing actions (CreateFunctionAction,
/// DeleteFunctionAction, EditFunctionAction, etc.).
///
/// Ported from `ghidra.app.plugin.core.function` individual action classes.
pub mod action_creators;

/// Extended function analyzers (CreateThunkAnalyzer, SharedReturnAnalyzer,
/// StackVariableAnalyzer, X86FunctionPurgeAnalyzer, ExternalEntryFunctionAnalyzer).
///
/// Ported from `ghidra.app.plugin.core.function` analyzer classes.
pub mod analyzers_ext;

pub use plugin::*;
pub use actions::*;
pub use tags::*;
pub use variable::*;
pub use variable_comment::*;
pub use thunk::*;
pub use stack::*;
pub use stack_depth::*;
pub use editor::*;
pub use analyzers::*;
pub use data_actions::*;
pub use extra_analyzers::*;
pub use editor_ui::*;
pub use tags_ui::*;
pub use table_model::*;
pub use cycle_group::*;
pub use function_data_view::*;
pub use storage_editor::*;
