//! Function plugin -- actions for creating, editing, deleting, and managing
//! functions and their variables, tags, thunk detection, and stack analysis.
//!
//! Ported from `ghidra.app.plugin.core.function` in Ghidra's Features/Base.
//!
//! This module re-exports the core function types from [`crate::base::function`]
//! and adds feature-level convenience types for function management,
//! variable storage, and the function editor dialog model.
//!
//! # Architecture
//!
//! - [`FunctionPlugin`] -- top-level plugin orchestrating all function actions
//! - [`FunctionEditorModel`] -- model for the function signature editor dialog
//! - [`ParamInfo`] -- parameter metadata (name, type, storage, ordinal)
//! - [`VarnodeType`] -- storage kind (Register, Stack, Memory)
//! - [`FunctionTag`] / [`FunctionTagManager`] -- tag CRUD on functions
//! - [`CycleGroupAction`] -- data-type cycling on operands
//! - [`StorageAddressModel`] -- storage validation for function parameters
//!
//! # Example
//!
//! ```
//! use ghidra_features::function::*;
//!
//! let tag = FunctionTag::new("important".to_string(), "Marks critical functions".to_string());
//! assert_eq!(tag.name(), "important");
//! assert!(!tag.is_auto_created());
//!
//! let param = ParamInfoBuilder::new(0, "buffer")
//!     .data_type_name("void *")
//!     .build();
//! assert_eq!(param.ordinal(), 0);
//! assert_eq!(param.name(), "buffer");
//! ```

// Re-export all core function types from base module.
pub use crate::base::function::*;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// FunctionTag -- lightweight tag model (supplements base::function::tags)
// ---------------------------------------------------------------------------

/// A tag that can be associated with functions for categorization.
///
/// Ported from `FunctionTag` / `InMemoryFunctionTag` in
/// `ghidra.app.plugin.core.function.tags`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionTag {
    /// Unique identifier for this tag.
    pub id: u64,
    /// Display name of the tag.
    name: String,
    /// Optional description text.
    description: String,
    /// Whether this tag was created automatically by an analyzer.
    auto_created: bool,
}

impl FunctionTag {
    /// Create a new function tag.
    pub fn new(name: String, description: String) -> Self {
        Self {
            id: 0,
            name,
            description,
            auto_created: false,
        }
    }

    /// Create a new in-memory tag (not yet persisted).
    pub fn in_memory(name: String) -> Self {
        Self {
            id: 0,
            name,
            description: String::new(),
            auto_created: false,
        }
    }

    /// Get the tag name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the tag description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Returns `true` if this tag was auto-created by an analyzer.
    pub fn is_auto_created(&self) -> bool {
        self.auto_created
    }

    /// Mark this tag as auto-created.
    pub fn set_auto_created(&mut self, auto: bool) {
        self.auto_created = auto;
    }

    /// Set the tag name.
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// Set the description.
    pub fn set_description(&mut self, desc: String) {
        self.description = desc;
    }
}

// ---------------------------------------------------------------------------
// FunctionTagRowObject -- row object for the tag table display
// ---------------------------------------------------------------------------

/// Row object for displaying a function tag in a table.
///
/// Ported from `FunctionTagRowObject.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionTagRowObject {
    /// The tag data.
    pub tag: FunctionTag,
    /// Number of functions using this tag.
    pub function_count: usize,
}

impl FunctionTagRowObject {
    /// Create a new row object.
    pub fn new(tag: FunctionTag, function_count: usize) -> Self {
        Self {
            tag,
            function_count,
        }
    }

    /// Get the tag name.
    pub fn name(&self) -> &str {
        self.tag.name()
    }

    /// Get the usage count.
    pub fn function_count(&self) -> usize {
        self.function_count
    }
}

// ---------------------------------------------------------------------------
// ParamInfoBuilder -- builder pattern for constructing ParamInfo
// ---------------------------------------------------------------------------

/// Builder for constructing [`ParamInfo`] instances.
///
/// Ported from the constructor patterns in `ParamInfo.java`.
#[derive(Debug, Clone)]
pub struct ParamInfoBuilder {
    ordinal: usize,
    name: String,
    data_type_name: String,
    is_auto_parameter: bool,
    is_custom_storage: bool,
}

impl ParamInfoBuilder {
    /// Create a new builder for a parameter with the given ordinal and name.
    pub fn new(ordinal: usize, name: impl Into<String>) -> Self {
        Self {
            ordinal,
            name: name.into(),
            data_type_name: "undefined".to_string(),
            is_auto_parameter: false,
            is_custom_storage: false,
        }
    }

    /// Set the data type name.
    pub fn data_type_name(mut self, name: impl Into<String>) -> Self {
        self.data_type_name = name.into();
        self
    }

    /// Mark this as an auto-parameter.
    pub fn auto_parameter(mut self) -> Self {
        self.is_auto_parameter = true;
        self
    }

    /// Mark this as using custom storage.
    pub fn custom_storage(mut self) -> Self {
        self.is_custom_storage = true;
        self
    }

    /// Build the [`ParamInfo`].
    pub fn build(self) -> BuiltParamInfo {
        BuiltParamInfo {
            ordinal: self.ordinal,
            name: self.name,
            data_type_name: self.data_type_name,
            is_auto_parameter: self.is_auto_parameter,
            is_custom_storage: self.is_custom_storage,
        }
    }
}

/// A built parameter info record.
///
/// This is the feature-level wrapper around parameter metadata.
/// The full `ParamInfo` with runtime storage binding lives in
/// `base::function::editor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuiltParamInfo {
    ordinal: usize,
    name: String,
    data_type_name: String,
    is_auto_parameter: bool,
    is_custom_storage: bool,
}

impl BuiltParamInfo {
    /// Get the parameter ordinal.
    pub fn ordinal(&self) -> usize {
        self.ordinal
    }

    /// Get the parameter name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the data type name.
    pub fn data_type_name(&self) -> &str {
        &self.data_type_name
    }

    /// Returns `true` if this is an auto-parameter.
    pub fn is_auto_parameter(&self) -> bool {
        self.is_auto_parameter
    }

    /// Returns `true` if this uses custom storage.
    pub fn is_custom_storage(&self) -> bool {
        self.is_custom_storage
    }
}

// ---------------------------------------------------------------------------
// FunctionEditorState -- serializable state for the function editor dialog
// ---------------------------------------------------------------------------

/// Serializable state for the function editor dialog.
///
/// Ported from the save/restore logic in `FunctionEditorDialog.java`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionEditorState {
    /// Whether the inline checkbox is checked.
    pub is_inline: bool,
    /// Whether the no-return checkbox is checked.
    pub is_no_return: bool,
    /// Whether the varargs checkbox is checked.
    pub is_varargs: bool,
    /// The selected calling convention name.
    pub calling_convention: Option<String>,
    /// The selected call-fixup name.
    pub call_fixup: Option<String>,
    /// Whether the commit-signature checkbox is checked.
    pub commit_signature: bool,
}

// ---------------------------------------------------------------------------
// StackDepthChangeEvent -- event fired when stack depth changes
// ---------------------------------------------------------------------------

/// Event fired when the stack depth at an address changes.
///
/// Ported from `StackDepthChangeEvent.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackDepthChangeEvent {
    /// The address where the stack depth changed.
    pub address: u64,
    /// The new stack depth value.
    pub new_depth: i32,
    /// The previous stack depth value (if known).
    pub old_depth: Option<i32>,
}

impl StackDepthChangeEvent {
    /// Create a new stack depth change event.
    pub fn new(address: u64, new_depth: i32, old_depth: Option<i32>) -> Self {
        Self {
            address,
            new_depth,
            old_depth,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_tag_creation() {
        let tag = FunctionTag::new("critical".to_string(), "High priority".to_string());
        assert_eq!(tag.name(), "critical");
        assert_eq!(tag.description(), "High priority");
        assert!(!tag.is_auto_created());
    }

    #[test]
    fn test_function_tag_in_memory() {
        let tag = FunctionTag::in_memory("temp".to_string());
        assert_eq!(tag.name(), "temp");
        assert!(tag.description().is_empty());
    }

    #[test]
    fn test_function_tag_setters() {
        let mut tag = FunctionTag::new("old".to_string(), "desc".to_string());
        tag.set_name("new".to_string());
        tag.set_description("new desc".to_string());
        tag.set_auto_created(true);
        assert_eq!(tag.name(), "new");
        assert_eq!(tag.description(), "new desc");
        assert!(tag.is_auto_created());
    }

    #[test]
    fn test_function_tag_row_object() {
        let tag = FunctionTag::new("tag1".to_string(), "".to_string());
        let row = FunctionTagRowObject::new(tag, 42);
        assert_eq!(row.name(), "tag1");
        assert_eq!(row.function_count(), 42);
    }

    #[test]
    fn test_param_info_builder() {
        let param = ParamInfoBuilder::new(0, "buf")
            .data_type_name("char *")
            .build();
        assert_eq!(param.ordinal(), 0);
        assert_eq!(param.name(), "buf");
        assert_eq!(param.data_type_name(), "char *");
        assert!(!param.is_auto_parameter());
        assert!(!param.is_custom_storage());
    }

    #[test]
    fn test_param_info_builder_auto() {
        let param = ParamInfoBuilder::new(1, "return_addr")
            .auto_parameter()
            .custom_storage()
            .build();
        assert!(param.is_auto_parameter());
        assert!(param.is_custom_storage());
    }

    #[test]
    fn test_function_editor_state() {
        let state = FunctionEditorState {
            is_inline: true,
            is_no_return: false,
            is_varargs: false,
            calling_convention: Some("thiscall".to_string()),
            call_fixup: None,
            commit_signature: true,
        };
        assert!(state.is_inline);
        assert_eq!(state.calling_convention.as_deref(), Some("thiscall"));
    }

    #[test]
    fn test_stack_depth_change_event() {
        let event = StackDepthChangeEvent::new(0x400000, -8, Some(0));
        assert_eq!(event.address, 0x400000);
        assert_eq!(event.new_depth, -8);
        assert_eq!(event.old_depth, Some(0));
    }

    #[test]
    fn test_function_editor_state_default() {
        let state = FunctionEditorState::default();
        assert!(!state.is_inline);
        assert!(!state.is_no_return);
        assert!(!state.is_varargs);
        assert!(state.calling_convention.is_none());
        assert!(!state.commit_signature);
    }
}
