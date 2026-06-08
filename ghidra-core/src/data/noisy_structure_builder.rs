//! Builder for constructing structures with noisy/partial information.
//!
//! Port of Ghidra's `NoisyStructureBuilder.java`.
//!
//! Used during auto-analysis to build structure definitions from incomplete
//! information, adding padding and unknown fields as needed.

use std::sync::Arc;

use super::types::{DataType, StructureDataType};

// ============================================================================
// NoisyStructureBuilder
// ============================================================================

/// A builder for constructing structures from partially known information.
///
/// Port of Ghidra's `NoisyStructureBuilder.java`. This builder helps
/// auto-analysis routines create structure definitions by allowing fields
/// to be added at specific offsets, automatically inserting padding for
/// gaps.
#[derive(Debug, Clone)]
pub struct NoisyStructureBuilder {
    /// The structure being built.
    structure: StructureDataType,
    /// Tracks which offsets have been assigned.
    assigned_offsets: Vec<bool>,
}

impl NoisyStructureBuilder {
    /// Create a new builder for a structure with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            structure: StructureDataType::new(name),
            assigned_offsets: Vec::new(),
        }
    }

    /// Create a new builder with a specified initial size.
    pub fn with_size(name: impl Into<String>, size: usize) -> Self {
        let mut builder = Self::new(name);
        builder.assigned_offsets.resize(size, false);
        builder
    }

    /// Get a reference to the structure being built.
    pub fn structure(&self) -> &StructureDataType {
        &self.structure
    }

    /// Get a mutable reference to the structure being built.
    pub fn structure_mut(&mut self) -> &mut StructureDataType {
        &mut self.structure
    }

    /// Consume the builder and return the structure.
    pub fn build(self) -> StructureDataType {
        self.structure
    }

    /// Add a field at a specific byte offset.
    ///
    /// If the offset is beyond the current structure size, padding will be
    /// inserted. Returns `true` if the field was successfully added.
    pub fn add_field_at_offset(
        &mut self,
        offset: usize,
        field_name: impl Into<String>,
        data_type: Arc<dyn DataType>,
    ) -> bool {
        let field_size = data_type.get_size();
        if field_size == 0 {
            return false;
        }

        // Extend tracking vector if needed
        let end = offset + field_size;
        if end > self.assigned_offsets.len() {
            self.assigned_offsets.resize(end, false);
        }

        // Check if this range overlaps with already-assigned fields
        for i in offset..end {
            if self.assigned_offsets[i] {
                return false; // Overlap
            }
        }

        // Insert padding if needed
        if offset > self.structure.size {
            let pad_size = offset - self.structure.size;
            self.structure.add_padding(pad_size);
        }

        // Add the field
        self.structure.add_field(field_name, data_type);

        // Mark offsets as assigned
        for i in offset..end {
            self.assigned_offsets[i] = true;
        }

        true
    }

    /// Add a pointer field at a specific offset.
    pub fn add_pointer_at_offset(
        &mut self,
        offset: usize,
        field_name: impl Into<String>,
        pointed_to: Arc<dyn DataType>,
        pointer_size: usize,
    ) -> bool {
        use super::types::PointerDataType;
        let ptr = Arc::new(PointerDataType::with_size(pointed_to, pointer_size));
        self.add_field_at_offset(offset, field_name, ptr)
    }

    /// Add an array field at a specific offset.
    pub fn add_array_at_offset(
        &mut self,
        offset: usize,
        field_name: impl Into<String>,
        element_type: Arc<dyn DataType>,
        count: usize,
    ) -> bool {
        use super::types::ArrayDataType;
        let array = Arc::new(ArrayDataType::new(element_type, count));
        self.add_field_at_offset(offset, field_name, array)
    }

    /// Fill remaining unassigned space with undefined bytes.
    pub fn fill_gaps(&mut self) {
        let size = self.assigned_offsets.len();
        if size == 0 {
            return;
        }

        let mut gap_start: Option<usize> = None;
        for i in 0..size {
            if !self.assigned_offsets[i] {
                if gap_start.is_none() {
                    gap_start = Some(i);
                }
            } else if let Some(start) = gap_start.take() {
                let gap_size = i - start;
                // Add padding bytes for this gap
                // We need to add at the correct position
                let current_size = self.structure.size;
                if start >= current_size {
                    self.structure.add_padding(gap_size);
                }
                // Mark as assigned
                for j in start..i {
                    self.assigned_offsets[j] = true;
                }
            }
        }

        // Handle trailing gap
        if let Some(start) = gap_start {
            let gap_size = size - start;
            self.structure.add_padding(gap_size);
            for j in start..size {
                self.assigned_offsets[j] = true;
            }
        }
    }

    /// Get the number of bytes that have been assigned.
    pub fn assigned_bytes(&self) -> usize {
        self.assigned_offsets.iter().filter(|&&b| b).count()
    }

    /// Get the total size of the structure so far.
    pub fn current_size(&self) -> usize {
        self.structure.size
    }

    /// Get the number of defined (non-padding) components.
    pub fn defined_component_count(&self) -> usize {
        self.structure.get_num_defined_components()
    }

    /// Returns true if all bytes up to the current size are assigned.
    pub fn is_fully_assigned(&self) -> bool {
        self.assigned_offsets.iter().all(|&b| b)
    }
}

impl std::fmt::Display for NoisyStructureBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "NoisyStructureBuilder('{}', {} bytes, {}/{} assigned)",
            self.structure.name,
            self.structure.size,
            self.assigned_bytes(),
            self.current_size()
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::builtin_types::*;

    #[test]
    fn test_builder_basic() {
        let builder = NoisyStructureBuilder::new("test");
        assert_eq!(builder.current_size(), 0);
        assert_eq!(builder.defined_component_count(), 0);
    }

    #[test]
    fn test_add_field_at_offset_0() {
        let mut builder = NoisyStructureBuilder::new("test");
        let int_dt: Arc<dyn DataType> = Arc::new(IntegerDataType::new());
        assert!(builder.add_field_at_offset(0, "field0", int_dt));
        assert_eq!(builder.current_size(), 4);
        assert_eq!(builder.defined_component_count(), 1);
        assert_eq!(builder.assigned_bytes(), 4);
    }

    #[test]
    fn test_add_field_with_gap() {
        let mut builder = NoisyStructureBuilder::new("test");
        let byte_dt: Arc<dyn DataType> = Arc::new(ByteDataType::new());
        let int_dt: Arc<dyn DataType> = Arc::new(IntegerDataType::new());

        builder.add_field_at_offset(0, "b", byte_dt);
        assert!(builder.add_field_at_offset(4, "i", int_dt));
        // Gap at offset 1-3 should have padding
        assert_eq!(builder.current_size(), 8);
        assert_eq!(builder.structure.get_num_components(), 3); // b, padding, i
    }

    #[test]
    fn test_add_field_overlap_rejected() {
        let mut builder = NoisyStructureBuilder::new("test");
        let int_dt: Arc<dyn DataType> = Arc::new(IntegerDataType::new());
        let byte_dt: Arc<dyn DataType> = Arc::new(ByteDataType::new());

        builder.add_field_at_offset(0, "i", int_dt);
        // Overlapping field should be rejected
        assert!(!builder.add_field_at_offset(2, "b", byte_dt));
    }

    #[test]
    fn test_add_pointer_at_offset() {
        let mut builder = NoisyStructureBuilder::new("test");
        let int_dt: Arc<dyn DataType> = Arc::new(IntegerDataType::new());
        assert!(builder.add_pointer_at_offset(0, "ptr", int_dt, 8));
        assert_eq!(builder.current_size(), 8);
    }

    #[test]
    fn test_add_array_at_offset() {
        let mut builder = NoisyStructureBuilder::new("test");
        let byte_dt: Arc<dyn DataType> = Arc::new(ByteDataType::new());
        assert!(builder.add_array_at_offset(0, "arr", byte_dt, 10));
        assert_eq!(builder.current_size(), 10);
    }

    #[test]
    fn test_build() {
        let mut builder = NoisyStructureBuilder::new("test");
        let int_dt: Arc<dyn DataType> = Arc::new(IntegerDataType::new());
        builder.add_field_at_offset(0, "x", int_dt);
        let s = builder.build();
        assert_eq!(s.name, "test");
        assert_eq!(s.size, 4);
    }

    #[test]
    fn test_display() {
        let builder = NoisyStructureBuilder::new("my_struct");
        let s = format!("{}", builder);
        assert!(s.contains("my_struct"));
    }
}
