//! Structure Editor -- Rust port of Ghidra's
//! `ghidra.app.plugin.core.compositeeditor` package.
//!
//! Provides the model, panel, and provider for editing composite data
//! types (structures and unions).  The editor allows users to add,
//! remove, rearrange, retype, and rename fields in a tabular view.
//!
//! # Architecture
//!
//! ```text
//! CompositeEditorProvider
//!   ├── CompositeEditorModel (abstract base)
//!   │     ├── StructureEditorModel (for structures)
//!   │     └── UnionEditorModel    (for unions)
//!   └── CompositeEditorPanel
//!         ├── StructureEditorPanel
//!         └── UnionEditorPanel
//! ```

pub mod actions;
pub mod composite_model;
pub mod model;
pub mod provider;
pub mod selection;

// Re-export the most important public types.
pub use actions::{
    ApplyResult, ClearResult, CompositeEditorAction, DeleteResult, DuplicateResult,
    MoveDirection, MoveResult, UnpackageResult,
};
pub use composite_model::{CompositeEditorModel, EditorColumn};
pub use model::StructureEditorModel;
pub use provider::{CompositeEditorProvider, EditorState, StructureEditorProvider};
pub use selection::EditorSelection;
