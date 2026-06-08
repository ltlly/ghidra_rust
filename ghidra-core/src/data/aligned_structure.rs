//! Aligned structure packing and inspection.
//!
//! Port of Ghidra's `AlignedStructurePacker.java`, `AlignedStructureInspector.java`,
//! and `AlignedComponentPacker.java`.
//!
//! These utilities handle the placement and alignment of components within
//! a structure, respecting packing rules and data organization constraints.

use super::types::{DataType, StructureDataType};
use super::{align_up, DataOrganization};

// ============================================================================
// AlignedComponentPacker
// ============================================================================

/// Handles the placement of individual components within a structure.
///
/// Port of Ghidra's `AlignedComponentPacker.java`.
#[derive(Debug, Clone)]
pub struct AlignedComponentPacker {
    /// The packing value (0 = default, non-zero = explicit pack).
    packing: u8,
    /// Whether packing is enabled.
    packing_enabled: bool,
    /// The data organization for computing alignments.
    alignment_type: AlignmentMode,
}

/// How component alignment is determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlignmentMode {
    /// Use each component's natural alignment.
    Natural,
    /// Use the machine alignment from data organization.
    Machine,
    /// Use a specific explicit alignment value.
    Explicit(usize),
}

impl AlignedComponentPacker {
    /// Create a packer with default (natural) alignment.
    pub fn new() -> Self {
        Self {
            packing: 0,
            packing_enabled: true,
            alignment_type: AlignmentMode::Natural,
        }
    }

    /// Create a packer with an explicit pack value.
    pub fn with_packing(packing: u8) -> Self {
        Self {
            packing,
            packing_enabled: true,
            alignment_type: AlignmentMode::Natural,
        }
    }

    /// Set the alignment mode.
    pub fn with_alignment_mode(mut self, mode: AlignmentMode) -> Self {
        self.alignment_type = mode;
        self
    }

    /// Enable or disable packing.
    pub fn with_packing_enabled(mut self, enabled: bool) -> Self {
        self.packing_enabled = enabled;
        self
    }

    /// Compute the effective alignment for a component given the current packing rules.
    pub fn compute_alignment(
        &self,
        component_type: &dyn DataType,
        org: &DataOrganization,
    ) -> usize {
        let natural_align = component_type.get_alignment();

        if !self.packing_enabled {
            return 1; // No packing: alignment is 1
        }

        let base_align = match self.alignment_type {
            AlignmentMode::Natural => natural_align,
            AlignmentMode::Machine => org.get_machine_alignment(),
            AlignmentMode::Explicit(explicit) => explicit,
        };

        if self.packing > 0 {
            base_align.min(self.packing as usize).max(1)
        } else {
            base_align.max(1)
        }
    }

    /// Compute the offset for a component at the given current offset.
    pub fn compute_offset(
        &self,
        current_offset: usize,
        component_type: &dyn DataType,
        org: &DataOrganization,
    ) -> usize {
        let alignment = self.compute_alignment(component_type, org);
        align_up(current_offset, alignment)
    }
}

impl Default for AlignedComponentPacker {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// AlignedStructureInspector
// ============================================================================

/// Inspects and analyzes the alignment and layout of a structure.
///
/// Port of Ghidra's `AlignedStructureInspector.java`.
#[derive(Debug)]
pub struct AlignedStructureInspector;

impl AlignedStructureInspector {
    /// Analyze the alignment of a structure and return the layout information.
    pub fn inspect(structure: &StructureDataType) -> StructureLayout {
        let mut max_alignment: usize = 1;
        let mut gaps: Vec<GapInfo> = Vec::new();
        let mut last_end: usize = 0;

        for comp in structure.get_components() {
            if comp.is_padding() {
                continue;
            }

            let offset = comp.get_offset();
            let size = comp.get_size();
            let alignment = comp.get_alignment();

            // Detect gap
            if offset > last_end {
                gaps.push(GapInfo {
                    offset: last_end,
                    size: offset - last_end,
                });
            }

            max_alignment = max_alignment.max(alignment);
            last_end = offset + size;
        }

        // Trailing padding
        let total_size = structure.size;
        if total_size > last_end {
            gaps.push(GapInfo {
                offset: last_end,
                size: total_size - last_end,
            });
        }

        StructureLayout {
            total_size,
            max_alignment,
            component_count: structure.get_num_defined_components(),
            padding_count: structure.get_num_components() - structure.get_num_defined_components(),
            gaps,
        }
    }

    /// Check if a structure's layout is valid (no overlapping components).
    pub fn is_valid_layout(structure: &StructureDataType) -> bool {
        let components = structure.get_components();
        for i in 0..components.len() {
            for j in (i + 1)..components.len() {
                let a = &components[i];
                let b = &components[j];
                // Skip padding
                if a.is_padding() || b.is_padding() {
                    continue;
                }
                // Skip bitfields (they can overlap at byte level)
                if a.is_bitfield() || b.is_bitfield() {
                    continue;
                }
                // Check overlap
                let a_end = a.offset + a.get_size();
                let b_end = b.offset + b.get_size();
                if a.offset < b_end && b.offset < a_end {
                    return false;
                }
            }
        }
        true
    }

    /// Compute the effective packing value for a structure.
    pub fn compute_packing(structure: &StructureDataType, _org: &DataOrganization) -> u8 {
        if structure.packing > 0 {
            return structure.packing;
        }
        // Analyze components to determine if packing is implied
        let mut min_alignment = usize::MAX;
        for comp in structure.get_components() {
            if !comp.is_padding() {
                let natural = comp.get_alignment();
                min_alignment = min_alignment.min(natural);
            }
        }
        if min_alignment == usize::MAX {
            0
        } else {
            0 // No explicit packing detected
        }
    }
}

// ============================================================================
// AlignedStructurePacker
// ============================================================================

/// Packs a structure by placing components according to alignment rules.
///
/// Port of Ghidra's `AlignedStructurePacker.java`.
#[derive(Debug)]
pub struct AlignedStructurePacker;

impl AlignedStructurePacker {
    /// Pack all components of a structure according to the given organization.
    ///
    /// Returns a new structure with components placed at their aligned offsets.
    pub fn pack(
        structure: &StructureDataType,
        org: &DataOrganization,
    ) -> StructureDataType {
        let packer = AlignedComponentPacker::new()
            .with_packing_enabled(structure.packing > 0 || true)
            .with_alignment_mode(if structure.packing > 0 {
                AlignmentMode::Natural
            } else {
                AlignmentMode::Natural
            });

        let mut result = StructureDataType::new(&structure.name);
        result.packing = structure.packing;
        result.description = structure.description.clone();
        result.category_path = structure.category_path.clone();

        let mut current_offset: usize = 0;
        let mut max_alignment: usize = 1;

        for comp in structure.get_components() {
            if comp.is_padding() {
                result.add_padding(comp.get_size());
                current_offset += comp.get_size();
                continue;
            }

            let effective_align = packer.compute_alignment(comp.data_type.as_ref(), org);
            let aligned_offset = align_up(current_offset, effective_align);

            // Add padding if needed
            if aligned_offset > current_offset {
                result.add_padding(aligned_offset - current_offset);
            }

            // Add the component
            let comp_type = comp.data_type.clone();
            result.add_field(comp.field_name.clone(), comp_type);

            max_alignment = max_alignment.max(effective_align);
            current_offset = aligned_offset + comp.get_size();
        }

        result.alignment = max_alignment;
        result.size = align_up(current_offset, max_alignment);
        result
    }
}

// ============================================================================
// StructureLayout
// ============================================================================

/// Layout information about a structure.
#[derive(Debug, Clone)]
pub struct StructureLayout {
    /// Total size in bytes.
    pub total_size: usize,
    /// Maximum alignment requirement.
    pub max_alignment: usize,
    /// Number of defined (non-padding) components.
    pub component_count: usize,
    /// Number of padding components.
    pub padding_count: usize,
    /// Information about gaps in the layout.
    pub gaps: Vec<GapInfo>,
}

impl StructureLayout {
    /// Returns `true` if there are no gaps in the structure.
    pub fn is_compact(&self) -> bool {
        self.gaps.is_empty()
    }

    /// The total bytes of padding/gaps.
    pub fn total_padding_bytes(&self) -> usize {
        self.gaps.iter().map(|g| g.size).sum()
    }

    /// The ratio of useful bytes to total bytes.
    pub fn utilization(&self) -> f64 {
        if self.total_size == 0 {
            return 1.0;
        }
        let useful = self.total_size - self.total_padding_bytes();
        useful as f64 / self.total_size as f64
    }
}

/// Information about a gap (unused bytes) in a structure layout.
#[derive(Debug, Clone)]
pub struct GapInfo {
    /// The offset where the gap starts.
    pub offset: usize,
    /// The size of the gap in bytes.
    pub size: usize,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::builtin_types::*;
    use crate::data::types::StructureDataType;
    use std::sync::Arc;

    #[test]
    fn test_component_packer_natural() {
        let packer = AlignedComponentPacker::new();
        let org = DataOrganization::default_organization();
        let dt: Arc<dyn DataType> = Arc::new(IntegerDataType::default());
        assert_eq!(packer.compute_alignment(dt.as_ref(), &org), 4);
    }

    #[test]
    fn test_component_packer_with_packing() {
        let packer = AlignedComponentPacker::with_packing(2);
        let org = DataOrganization::default_organization();
        let dt: Arc<dyn DataType> = Arc::new(IntegerDataType::default());
        assert_eq!(packer.compute_alignment(dt.as_ref(), &org), 2);
    }

    #[test]
    fn test_component_packer_disabled() {
        let packer = AlignedComponentPacker::new().with_packing_enabled(false);
        let org = DataOrganization::default_organization();
        let dt: Arc<dyn DataType> = Arc::new(IntegerDataType::default());
        assert_eq!(packer.compute_alignment(dt.as_ref(), &org), 1);
    }

    #[test]
    fn test_compute_offset() {
        let packer = AlignedComponentPacker::new();
        let org = DataOrganization::default_organization();
        let dt: Arc<dyn DataType> = Arc::new(IntegerDataType::default());
        assert_eq!(packer.compute_offset(0, dt.as_ref(), &org), 0);
        assert_eq!(packer.compute_offset(1, dt.as_ref(), &org), 4);
        assert_eq!(packer.compute_offset(3, dt.as_ref(), &org), 4);
        assert_eq!(packer.compute_offset(4, dt.as_ref(), &org), 4);
    }

    #[test]
    fn test_structure_inspector_valid() {
        let mut s = StructureDataType::new("test");
        s.add_field("a", Arc::new(ByteDataType::default()));
        s.add_field("b", Arc::new(IntegerDataType::default()));
        assert!(AlignedStructureInspector::is_valid_layout(&s));
    }

    #[test]
    fn test_structure_inspector_layout() {
        let mut s = StructureDataType::new("test");
        s.add_field("a", Arc::new(ByteDataType::default()));
        s.add_field("b", Arc::new(IntegerDataType::default()));
        let layout = AlignedStructureInspector::inspect(&s);
        assert_eq!(layout.component_count, 2);
        assert!(layout.total_size > 0);
    }

    #[test]
    fn test_structure_packer() {
        let org = DataOrganization::default_organization();
        let mut s = StructureDataType::new("test");
        s.add_field("a", Arc::new(ByteDataType::default()));
        s.add_field("b", Arc::new(IntegerDataType::default()));

        let packed = AlignedStructurePacker::pack(&s, &org);
        assert!(packed.size >= 5);
        assert!(packed.alignment >= 4);
    }

    #[test]
    fn test_structure_layout_utilization() {
        let layout = StructureLayout {
            total_size: 8,
            max_alignment: 4,
            component_count: 1,
            padding_count: 0,
            gaps: vec![],
        };
        assert_eq!(layout.utilization(), 1.0);
        assert!(layout.is_compact());

        let layout_with_gap = StructureLayout {
            total_size: 8,
            max_alignment: 4,
            component_count: 1,
            padding_count: 1,
            gaps: vec![GapInfo { offset: 1, size: 3 }],
        };
        assert!(layout_with_gap.utilization() < 1.0);
        assert!(!layout_with_gap.is_compact());
    }

    #[test]
    fn test_alignment_mode() {
        assert_eq!(AlignmentMode::Natural, AlignmentMode::Natural);
        assert_ne!(AlignmentMode::Natural, AlignmentMode::Machine);
    }
}
