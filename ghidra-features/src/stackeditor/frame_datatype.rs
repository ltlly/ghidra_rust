//! Stack frame data type -- ported from
//! `ghidra.app.plugin.core.stackeditor.StackFrameDataType`.
//!
//! Provides a `Structure`-like representation of a function's stack frame
//! for use by the Stack Frame Editor. This datatype wraps a real structure
//! and provides stack-offset-to-structure-offset translation.

use std::collections::BTreeMap;

/// A stack component wrapper that translates between stack offsets and
/// structure offsets.
///
/// Ported from `StackFrameDataType.StackComponentWrapper`.
#[derive(Debug, Clone)]
pub struct StackComponentWrapper {
    /// The field name (e.g. "local_8h", "param_0h").
    pub field_name: String,
    /// The data type name.
    pub data_type_name: String,
    /// The size in bytes.
    pub length: usize,
    /// The offset within the stack frame (can be negative).
    pub stack_offset: i32,
    /// The offset within the wrapped structure (always non-negative).
    pub struct_offset: i32,
    /// An optional comment.
    pub comment: Option<String>,
    /// Whether this component is undefined (gap/padding).
    pub is_undefined: bool,
}

impl StackComponentWrapper {
    /// Create a new stack component wrapper.
    pub fn new(
        field_name: impl Into<String>,
        data_type_name: impl Into<String>,
        length: usize,
        stack_offset: i32,
        struct_offset: i32,
    ) -> Self {
        Self {
            field_name: field_name.into(),
            data_type_name: data_type_name.into(),
            length,
            stack_offset,
            struct_offset,
            comment: None,
            is_undefined: false,
        }
    }

    /// Create an undefined (gap) component.
    pub fn undefined(struct_offset: i32, length: usize) -> Self {
        Self {
            field_name: String::new(),
            data_type_name: "undefined".into(),
            length,
            stack_offset: struct_offset, // same for undefined
            struct_offset,
            comment: None,
            is_undefined: true,
        }
    }

    /// The end offset (exclusive) in the structure.
    pub fn end_offset(&self) -> i32 {
        self.struct_offset + self.length as i32
    }
}

/// Stack grow direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackGrowDirection {
    /// Stack grows toward lower addresses (most common: x86, ARM, etc.).
    Negative,
    /// Stack grows toward higher addresses.
    Positive,
}

impl StackGrowDirection {
    /// Whether the stack grows negative.
    pub fn grows_negative(&self) -> bool {
        matches!(self, Self::Negative)
    }
}

/// Represents a stack frame data type for the editor.
///
/// Ported from `ghidra.app.plugin.core.stackeditor.StackFrameDataType`.
///
/// This is the model for editing a function's stack frame. It wraps
/// a structure that represents the stack layout, and provides methods
/// for resizing locals and parameters, managing components, and
/// computing stack-offset to structure-offset translations.
#[derive(Debug)]
pub struct StackFrameDataType {
    /// The wrapped structure name.
    structure_name: String,
    /// Components in the stack frame, keyed by structure offset.
    components: BTreeMap<i32, StackComponentWrapper>,
    /// Whether the stack grows negative (toward lower addresses).
    grows_negative: bool,
    /// The return address offset.
    return_address_offset: i32,
    /// The parameter offset (split point between negative and positive regions).
    parameter_offset: i32,
    /// Size of the negative region (locals or params, depending on direction).
    negative_length: usize,
    /// Size of the positive region.
    positive_length: usize,
}

impl StackFrameDataType {
    /// The structure name used internally.
    pub const STACK_STRUCTURE_NAME: &'static str = "{{STACK_FRAME}}";

    /// Create a new stack frame data type.
    pub fn new(
        grows_negative: bool,
        return_address_offset: i32,
        parameter_offset: i32,
        local_size: usize,
        param_size: usize,
    ) -> Self {
        let (negative_length, positive_length) = if grows_negative {
            (local_size, param_size)
        } else {
            (param_size, local_size)
        };

        Self {
            structure_name: Self::STACK_STRUCTURE_NAME.into(),
            components: BTreeMap::new(),
            grows_negative,
            return_address_offset,
            parameter_offset,
            negative_length,
            positive_length,
        }
    }

    /// Whether the stack grows negative.
    pub fn grows_negative(&self) -> bool {
        self.grows_negative
    }

    /// Get the return address offset.
    pub fn return_address_offset(&self) -> i32 {
        self.return_address_offset
    }

    /// Get the parameter offset (the split point).
    pub fn parameter_offset(&self) -> i32 {
        self.parameter_offset
    }

    /// Get the total frame size.
    pub fn frame_size(&self) -> usize {
        self.negative_length + self.positive_length
    }

    /// Get the local size.
    pub fn local_size(&self) -> usize {
        if self.grows_negative {
            self.negative_length
        } else {
            self.positive_length
        }
    }

    /// Get the parameter size.
    pub fn parameter_size(&self) -> usize {
        if self.grows_negative {
            self.positive_length
        } else {
            self.negative_length
        }
    }

    /// Set the local size.
    pub fn set_local_size(&mut self, size: usize) -> bool {
        self.adjust_frame_size(size, self.local_size(), self.grows_negative)
    }

    /// Set the parameter size.
    pub fn set_parameter_size(&mut self, size: usize) -> bool {
        self.adjust_frame_size(size, self.parameter_size(), !self.grows_negative)
    }

    /// Adjust the frame size for either locals or parameters.
    ///
    /// Returns `true` if the adjustment was successful.
    fn adjust_frame_size(&mut self, new_size: usize, current_size: usize, is_negative: bool) -> bool {
        if new_size == current_size {
            return true;
        }

        let delta = if new_size > current_size {
            new_size - current_size
        } else {
            current_size - new_size
        };

        if new_size < current_size {
            // Shrink: delete components in the removed range
            let (min_offset, max_offset) = if is_negative {
                let old_min = self.parameter_offset - self.negative_length as i32;
                let new_min = old_min + delta as i32;
                (old_min, new_min - 1)
            } else {
                let old_max = self.parameter_offset + self.positive_length as i32 - 1;
                let new_max = old_max - delta as i32;
                (new_max + 1, old_max)
            };
            self.delete_range(min_offset, max_offset);
        }

        if is_negative {
            self.negative_length = new_size;
        } else {
            self.positive_length = new_size;
        }

        true
    }

    /// Delete components whose stack offsets fall within the given range.
    fn delete_range(&mut self, min_offset: i32, max_offset: i32) {
        let offsets_to_remove: Vec<i32> = self
            .components
            .values()
            .filter(|c| c.stack_offset >= min_offset && c.stack_offset <= max_offset)
            .map(|c| c.struct_offset)
            .collect();
        for offset in offsets_to_remove {
            self.components.remove(&offset);
        }
    }

    /// Add a component at a stack offset.
    pub fn add_component(&mut self, component: StackComponentWrapper) {
        self.components.insert(component.struct_offset, component);
    }

    /// Remove a component at a stack offset.
    pub fn remove_component(&mut self, struct_offset: i32) -> Option<StackComponentWrapper> {
        self.components.remove(&struct_offset)
    }

    /// Get a component at a stack offset.
    pub fn get_component(&self, struct_offset: i32) -> Option<&StackComponentWrapper> {
        self.components.get(&struct_offset)
    }

    /// Get the component containing the given stack offset.
    pub fn get_component_containing(&self, stack_offset: i32) -> Option<&StackComponentWrapper> {
        self.components.values().find(|c| {
            stack_offset >= c.struct_offset && stack_offset < c.end_offset()
        })
    }

    /// Get all defined (non-undefined) components.
    pub fn get_defined_components(&self) -> Vec<&StackComponentWrapper> {
        self.components
            .values()
            .filter(|c| !c.is_undefined)
            .collect()
    }

    /// Get all components in order.
    pub fn get_all_components(&self) -> Vec<&StackComponentWrapper> {
        self.components.values().collect()
    }

    /// The number of defined components.
    pub fn component_count(&self) -> usize {
        self.components.values().filter(|c| !c.is_undefined).count()
    }

    /// The minimum stack offset.
    pub fn min_offset(&self) -> i32 {
        self.parameter_offset - self.negative_length as i32
    }

    /// The maximum stack offset.
    pub fn max_offset(&self) -> i32 {
        self.parameter_offset + self.positive_length as i32 - 1
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_frame_new() {
        let frame = StackFrameDataType::new(true, 4, 0, 16, 8);
        assert!(frame.grows_negative());
        assert_eq!(frame.return_address_offset(), 4);
        assert_eq!(frame.parameter_offset(), 0);
        assert_eq!(frame.frame_size(), 24);
        assert_eq!(frame.local_size(), 16);
        assert_eq!(frame.parameter_size(), 8);
    }

    #[test]
    fn test_stack_frame_positive_grows() {
        // grows_negative=false: params come first (negative region), locals second (positive region)
        let frame = StackFrameDataType::new(false, 4, 0, 16, 8);
        assert!(!frame.grows_negative());
        // negative_length = param_size = 8, positive_length = local_size = 16
        // local_size() returns positive_length when grows_negative is false
        assert_eq!(frame.local_size(), 16);
        assert_eq!(frame.parameter_size(), 8);
    }

    #[test]
    fn test_add_and_get_component() {
        let mut frame = StackFrameDataType::new(true, 4, 0, 16, 8);
        let comp = StackComponentWrapper::new("local_8h", "int", 4, -8, 8);
        frame.add_component(comp);
        assert_eq!(frame.component_count(), 1);
        let retrieved = frame.get_component(8).unwrap();
        assert_eq!(retrieved.field_name, "local_8h");
    }

    #[test]
    fn test_remove_component() {
        let mut frame = StackFrameDataType::new(true, 4, 0, 16, 8);
        frame.add_component(StackComponentWrapper::new("local_8h", "int", 4, -8, 8));
        let removed = frame.remove_component(8);
        assert!(removed.is_some());
        assert_eq!(frame.component_count(), 0);
    }

    #[test]
    fn test_get_component_containing() {
        let mut frame = StackFrameDataType::new(true, 4, 0, 16, 8);
        frame.add_component(StackComponentWrapper::new("local_8h", "int", 4, -8, 8));
        // Struct offset 8..11 should be found
        let comp = frame.get_component_containing(8);
        assert!(comp.is_some());
        assert_eq!(comp.unwrap().field_name, "local_8h");
        // Offset 12 should NOT be found
        assert!(frame.get_component_containing(12).is_none());
    }

    #[test]
    fn test_set_local_size() {
        let mut frame = StackFrameDataType::new(true, 4, 0, 16, 8);
        assert!(frame.set_local_size(32));
        assert_eq!(frame.local_size(), 32);
        assert_eq!(frame.frame_size(), 40);
    }

    #[test]
    fn test_set_parameter_size() {
        let mut frame = StackFrameDataType::new(true, 4, 0, 16, 8);
        assert!(frame.set_parameter_size(16));
        assert_eq!(frame.parameter_size(), 16);
        assert_eq!(frame.frame_size(), 32);
    }

    #[test]
    fn test_shrink_removes_components() {
        let mut frame = StackFrameDataType::new(true, 4, 0, 16, 8);
        frame.add_component(StackComponentWrapper::new("local_16h", "int", 4, -16, 0));
        frame.add_component(StackComponentWrapper::new("local_8h", "int", 4, -8, 8));
        // Shrink locals from 16 to 8 -> removes component at struct offset 0
        frame.set_local_size(8);
        assert_eq!(frame.component_count(), 1);
        assert!(frame.get_component(0).is_none());
        assert!(frame.get_component(8).is_some());
    }

    #[test]
    fn test_offsets() {
        let frame = StackFrameDataType::new(true, 4, 0, 16, 8);
        assert_eq!(frame.min_offset(), -16);
        assert_eq!(frame.max_offset(), 7);
    }

    #[test]
    fn test_stack_component_wrapper() {
        let comp = StackComponentWrapper::new("x", "int", 4, -8, 8);
        assert_eq!(comp.end_offset(), 12);
        assert!(!comp.is_undefined);

        let undef = StackComponentWrapper::undefined(4, 4);
        assert!(undef.is_undefined);
        assert_eq!(undef.data_type_name, "undefined");
    }

    #[test]
    fn test_grow_direction() {
        assert!(StackGrowDirection::Negative.grows_negative());
        assert!(!StackGrowDirection::Positive.grows_negative());
    }

    #[test]
    fn test_structure_name() {
        assert_eq!(
            StackFrameDataType::STACK_STRUCTURE_NAME,
            "{{STACK_FRAME}}"
        );
    }
}
