//! Structure-specific editor panel.
//!
//! Ported from `ghidra.app.plugin.core.compositeeditor.StructureEditorPanel`.
//!
//! Extends the base composite editor panel with structure-specific features
//! including offset/alignment management, bit-field editing integration,
//! gap/undefined-byte display, and hex offset formatting.

use super::{
    ComponentRow, DataTypePath,
    composite_editor_panel::{CompositeEditorPanel, InfoLevel},
};

// ---------------------------------------------------------------------------
// Alignment mode
// ---------------------------------------------------------------------------

/// How component alignment is handled in the structure editor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlignmentMode {
    /// No explicit alignment (components are packed).
    None,
    /// Align components to their natural alignment.
    Natural,
    /// Align components to a specific byte boundary.
    Packed(u32),
}

impl AlignmentMode {
    /// Get the alignment in bytes for a given component size.
    pub fn alignment_for(&self, component_size: u32) -> u32 {
        match self {
            Self::None => 1,
            Self::Natural => {
                // Natural alignment: align to the component size, capped at 8
                component_size.next_power_of_two().min(8)
            }
            Self::Packed(n) => (*n).max(1),
        }
    }
}

// ---------------------------------------------------------------------------
// Bit-field info
// ---------------------------------------------------------------------------

/// Information about a bit-field component within a structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitFieldInfo {
    /// The ordinal of the containing component.
    pub component_ordinal: usize,
    /// The bit offset within the storage unit.
    pub bit_offset: u32,
    /// The bit size of the bit-field.
    pub bit_size: u32,
    /// The base type mnemonic (e.g., "uint", "int").
    pub base_type: String,
    /// Whether the declaration is valid.
    pub valid: bool,
}

impl BitFieldInfo {
    /// Create a new bit-field info.
    pub fn new(
        component_ordinal: usize,
        bit_offset: u32,
        bit_size: u32,
        base_type: impl Into<String>,
    ) -> Self {
        Self {
            component_ordinal,
            bit_offset,
            bit_size,
            base_type: base_type.into(),
            valid: bit_size > 0 && bit_size <= 64 && bit_offset + bit_size <= 64,
        }
    }

    /// The end bit position (exclusive).
    pub fn end_bit(&self) -> u32 {
        self.bit_offset + self.bit_size
    }
}

// ---------------------------------------------------------------------------
// Structure editor panel
// ---------------------------------------------------------------------------

/// Structure-specific editor panel extending the base composite editor panel.
///
/// Adds structure-specific features:
/// - Offset management and recomputation on edits
/// - Alignment mode configuration
/// - Bit-field editing integration
/// - Undefined byte (gap) display between components
/// - Hex offset formatting
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.StructureEditorPanel`.
#[derive(Debug)]
pub struct StructureEditorPanel {
    /// The base composite editor panel.
    pub base: CompositeEditorPanel,
    /// The alignment mode.
    pub alignment_mode: AlignmentMode,
    /// Whether to show undefined bytes (gaps) as rows.
    pub show_undefined_bytes: bool,
    /// Whether to display offsets in hex.
    pub show_hex_offsets: bool,
    /// Bit-field components, keyed by containing component ordinal.
    bit_fields: Vec<BitFieldInfo>,
    /// The total declared structure size (may differ from component-derived size).
    declared_size: Option<u64>,
}

impl StructureEditorPanel {
    /// Create a new structure editor panel.
    pub fn new(dt_path: DataTypePath) -> Self {
        Self {
            base: CompositeEditorPanel::new(dt_path, true),
            alignment_mode: AlignmentMode::Natural,
            show_undefined_bytes: true,
            show_hex_offsets: true,
            bit_fields: Vec::new(),
            declared_size: None,
        }
    }

    /// Set the components and recompute offsets.
    pub fn set_components(&mut self, components: Vec<ComponentRow>) {
        self.base.set_components(components);
        self.recompute_offsets();
    }

    /// Get the total size of the structure.
    pub fn total_size(&self) -> u64 {
        self.declared_size.unwrap_or_else(|| {
            self.base
                .components()
                .last()
                .map_or(0, |c| c.end_offset())
        })
    }

    /// Set the declared structure size.
    pub fn set_declared_size(&mut self, size: u64) {
        self.declared_size = Some(size);
    }

    /// Clear the declared size (use component-derived size).
    pub fn clear_declared_size(&mut self) {
        self.declared_size = None;
    }

    /// Add a bit-field to the structure.
    pub fn add_bit_field(&mut self, info: BitFieldInfo) {
        if !info.valid {
            self.base.add_message(
                format!(
                    "Invalid bit-field at component {}: offset={}, size={}",
                    info.component_ordinal, info.bit_offset, info.bit_size
                ),
                InfoLevel::Error,
            );
        }
        self.bit_fields.push(info);
    }

    /// Get the bit-field info for a component.
    pub fn bit_field_for(&self, ordinal: usize) -> Option<&BitFieldInfo> {
        self.bit_fields.iter().find(|bf| bf.component_ordinal == ordinal)
    }

    /// Remove bit-field info for a component.
    pub fn remove_bit_field(&mut self, ordinal: usize) {
        self.bit_fields.retain(|bf| bf.component_ordinal != ordinal);
    }

    /// Get all bit-field infos.
    pub fn bit_fields(&self) -> &[BitFieldInfo] {
        &self.bit_fields
    }

    /// Recompute component offsets based on alignment mode.
    pub fn recompute_offsets(&mut self) {
        let components = self.base.components().to_vec();
        if components.is_empty() {
            return;
        }
        let mut offset = 0u64;
        let mut new_components = Vec::with_capacity(components.len());
        for comp in &components {
            let alignment = self.alignment_mode.alignment_for(comp.length) as u64;
            let aligned_offset = (offset + alignment - 1) & !(alignment - 1);
            let mut new_comp = comp.clone();
            new_comp.offset = aligned_offset;
            new_components.push(new_comp);
            offset = aligned_offset + comp.length as u64;
        }
        self.base.set_components(new_components);
    }

    /// Format an offset value according to display settings.
    pub fn format_offset(&self, offset: u64) -> String {
        if self.show_hex_offsets {
            format!("0x{:X}", offset)
        } else {
            offset.to_string()
        }
    }

    /// Get undefined byte ranges (gaps between components).
    pub fn undefined_ranges(&self) -> Vec<(u64, u64)> {
        let components = self.base.components();
        if components.is_empty() {
            return Vec::new();
        }
        let mut ranges = Vec::new();
        let mut expected = 0u64;
        for comp in components {
            if comp.offset > expected {
                ranges.push((expected, comp.offset));
            }
            expected = comp.end_offset();
        }
        let total = self.total_size();
        if expected < total {
            ranges.push((expected, total));
        }
        ranges
    }

    /// The number of undefined bytes.
    pub fn undefined_byte_count(&self) -> u64 {
        self.undefined_ranges().iter().map(|(a, b)| b - a).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_path(name: &str) -> DataTypePath {
        DataTypePath::new("/", name)
    }

    #[test]
    fn test_alignment_mode_none() {
        assert_eq!(AlignmentMode::None.alignment_for(4), 1);
    }

    #[test]
    fn test_alignment_mode_natural() {
        assert_eq!(AlignmentMode::Natural.alignment_for(1), 1);
        assert_eq!(AlignmentMode::Natural.alignment_for(2), 2);
        assert_eq!(AlignmentMode::Natural.alignment_for(4), 4);
        assert_eq!(AlignmentMode::Natural.alignment_for(8), 8);
        assert_eq!(AlignmentMode::Natural.alignment_for(16), 8); // capped at 8
    }

    #[test]
    fn test_alignment_mode_packed() {
        assert_eq!(AlignmentMode::Packed(2).alignment_for(8), 2);
        assert_eq!(AlignmentMode::Packed(1).alignment_for(4), 1);
        assert_eq!(AlignmentMode::Packed(0).alignment_for(4), 1); // min 1
    }

    #[test]
    fn test_bit_field_info() {
        let bf = BitFieldInfo::new(0, 4, 3, "uint");
        assert_eq!(bf.end_bit(), 7);
        assert!(bf.valid);
    }

    #[test]
    fn test_bit_field_info_invalid() {
        let bf = BitFieldInfo::new(0, 60, 8, "uint"); // would exceed 64 bits
        assert!(!bf.valid);
    }

    #[test]
    fn test_structure_editor_panel_creation() {
        let panel = StructureEditorPanel::new(root_path("S"));
        assert!(panel.show_undefined_bytes);
        assert!(panel.show_hex_offsets);
        assert_eq!(panel.total_size(), 0);
    }

    #[test]
    fn test_structure_editor_panel_set_components() {
        let mut panel = StructureEditorPanel::new(root_path("S"));
        panel.set_components(vec![
            ComponentRow::new(0, "int", "x", 0, 4),
            ComponentRow::new(1, "char", "c", 4, 1),
        ]);
        assert_eq!(panel.base.component_count(), 2);
        assert_eq!(panel.total_size(), 5);
    }

    #[test]
    fn test_structure_editor_panel_format_offset() {
        let panel = StructureEditorPanel::new(root_path("S"));
        assert_eq!(panel.format_offset(255), "0xFF");

        let mut panel2 = StructureEditorPanel::new(root_path("S"));
        panel2.show_hex_offsets = false;
        assert_eq!(panel2.format_offset(255), "255");
    }

    #[test]
    fn test_structure_editor_panel_declared_size() {
        let mut panel = StructureEditorPanel::new(root_path("S"));
        assert!(panel.declared_size.is_none());

        panel.set_declared_size(16);
        assert_eq!(panel.total_size(), 16);

        panel.clear_declared_size();
        assert_eq!(panel.total_size(), 0);
    }

    #[test]
    fn test_structure_editor_panel_bit_fields() {
        let mut panel = StructureEditorPanel::new(root_path("S"));
        let bf = BitFieldInfo::new(0, 0, 3, "uint");
        panel.add_bit_field(bf);

        assert!(panel.bit_field_for(0).is_some());
        assert!(panel.bit_field_for(1).is_none());

        panel.remove_bit_field(0);
        assert!(panel.bit_field_for(0).is_none());
    }

    #[test]
    fn test_structure_editor_panel_undefined_ranges_empty() {
        let panel = StructureEditorPanel::new(root_path("S"));
        assert!(panel.undefined_ranges().is_empty());
        assert_eq!(panel.undefined_byte_count(), 0);
    }

    #[test]
    fn test_structure_editor_panel_undefined_ranges_gap() {
        let mut panel = StructureEditorPanel::new(root_path("S"));
        // Place a component with a gap
        let mut comp0 = ComponentRow::new(0, "int", "x", 0, 4);
        comp0.length = 4;
        let mut comp1 = ComponentRow::new(1, "char", "c", 8, 1);
        comp1.length = 1;
        comp1.offset = 8; // gap at 4..8

        panel.base.set_components(vec![comp0, comp1]);
        panel.set_declared_size(9);

        let ranges = panel.undefined_ranges();
        // Gap between end of comp0 (4) and start of comp1 (8)
        assert!(!ranges.is_empty());
        assert_eq!(panel.undefined_byte_count(), 4); // 4 bytes gap
    }

    #[test]
    fn test_structure_editor_panel_recompute_offsets_no_alignment() {
        let mut panel = StructureEditorPanel::new(root_path("S"));
        panel.alignment_mode = AlignmentMode::None;
        panel.set_components(vec![
            ComponentRow::new(0, "char", "a", 0, 1),
            ComponentRow::new(1, "int", "b", 0, 4),
            ComponentRow::new(2, "short", "c", 0, 2),
        ]);
        // With no alignment, offsets should be sequential
        assert_eq!(panel.base.components()[0].offset, 0);
        assert_eq!(panel.base.components()[1].offset, 1);
        assert_eq!(panel.base.components()[2].offset, 5);
    }
}
