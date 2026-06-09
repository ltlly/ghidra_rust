//! Property change management and property set editing.
//!
//! Ports Ghidra's Features/PropertyChange Java classes to Rust:
//!
//! - [`property_change_manager`] -- manages property change listeners,
//!   dispatches events, and supports scoped event groups.
//! - [`property_set_editor_dialog`] -- data model for a property set editor
//!   dialog with undo/redo and commit-to-manager support.
//!
//! These modules complement the existing [`super::property`] module which
//! provides the underlying `PropertyMap`, `PropertyMapManager`, and
//! `PropertyDeleteCmd` types.

pub mod property_change_manager;
pub mod property_set_editor_dialog;

// Re-export key types for convenience.
pub use property_change_manager::{
    ListenerId, PropertyChangeManager, PropertyChangeEvent, PropertyChangeListener, PropertyValue,
    ScopedPropertyChanges,
};
pub use property_set_editor_dialog::{
    EditAction, PropertyEntry, PropertySetEditorModel,
};
