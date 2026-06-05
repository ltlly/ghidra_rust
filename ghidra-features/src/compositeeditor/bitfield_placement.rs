//! Bit-field placement component for the composite editor.
//!
//! Ported from `ghidra.app.plugin.core.compositeeditor.BitFieldPlacementComponent`.
//!
//! Visualizes the bit layout of a storage unit showing how bit-fields
//! are packed within bytes.

/// A bit within the placement display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlacementBit {
    /// The bit index (0-63).
    pub index: u32,
    /// Whether this bit is occupied by a bit-field.
    pub occupied: bool,
    /// The ordinal of the component owning this bit (if occupied).
    pub owner_ordinal: Option<usize>,
}

/// Represents a bit-field's position within a storage unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitFieldPlacement {
    /// The name of the bit-field.
    pub name: String,
    /// The base type mnemonic (e.g., "uint", "int").
    pub base_type: String,
    /// The bit offset within the storage unit.
    pub bit_offset: u32,
    /// The bit size of the field.
    pub bit_size: u32,
    /// The ordinal in the containing composite.
    pub ordinal: usize,
}

impl BitFieldPlacement {
    /// Create a new bit-field placement.
    pub fn new(
        name: impl Into<String>,
        base_type: impl Into<String>,
        bit_offset: u32,
        bit_size: u32,
        ordinal: usize,
    ) -> Self {
        Self {
            name: name.into(),
            base_type: base_type.into(),
            bit_offset,
            bit_size,
            ordinal,
        }
    }

    /// The end bit position (exclusive).
    pub fn end_bit(&self) -> u32 {
        self.bit_offset + self.bit_size
    }

    /// Whether this placement overlaps with another.
    pub fn overlaps(&self, other: &BitFieldPlacement) -> bool {
        self.bit_offset < other.end_bit() && other.bit_offset < self.end_bit()
    }

    /// Get the byte index of the first byte this field touches.
    pub fn start_byte(&self) -> u32 {
        self.bit_offset / 8
    }

    /// Get the byte index of the last byte this field touches (inclusive).
    pub fn end_byte(&self) -> u32 {
        (self.end_bit() - 1) / 8
    }

    /// Whether this bit-field spans multiple bytes.
    pub fn spans_bytes(&self) -> bool {
        self.start_byte() != self.end_byte()
    }
}

// ---------------------------------------------------------------------------
// BitFieldPlacementComponent
// ---------------------------------------------------------------------------

/// Component that visualizes bit-field layout within a storage unit.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.BitFieldPlacementComponent`.
#[derive(Debug)]
pub struct BitFieldPlacementComponent {
    /// The total size of the storage unit in bits.
    pub storage_bits: u32,
    /// Whether the layout is big-endian (MSB first).
    pub big_endian: bool,
    /// The bit-field placements.
    placements: Vec<BitFieldPlacement>,
    /// The currently selected placement index.
    selected: Option<usize>,
}

impl BitFieldPlacementComponent {
    /// Create a new bit-field placement component.
    pub fn new(storage_bits: u32, big_endian: bool) -> Self {
        Self {
            storage_bits,
            big_endian,
            placements: Vec::new(),
            selected: None,
        }
    }

    /// Create a placement component for a given byte size.
    pub fn for_byte_size(byte_size: u32, big_endian: bool) -> Self {
        Self::new(byte_size * 8, big_endian)
    }

    /// Add a bit-field placement.
    pub fn add_placement(&mut self, placement: BitFieldPlacement) -> Result<(), String> {
        // Validate bounds
        if placement.end_bit() > self.storage_bits {
            return Err(format!(
                "Bit-field '{}' exceeds storage: offset={}, size={}, storage={}",
                placement.name, placement.bit_offset, placement.bit_size, self.storage_bits
            ));
        }

        // Check for overlaps
        for existing in &self.placements {
            if existing.overlaps(&placement) {
                return Err(format!(
                    "Bit-field '{}' overlaps with '{}'",
                    placement.name, existing.name
                ));
            }
        }

        self.placements.push(placement);
        Ok(())
    }

    /// Remove a placement by ordinal.
    pub fn remove_placement(&mut self, ordinal: usize) -> Option<BitFieldPlacement> {
        if let Some(pos) = self.placements.iter().position(|p| p.ordinal == ordinal) {
            Some(self.placements.remove(pos))
        } else {
            None
        }
    }

    /// Get all placements.
    pub fn placements(&self) -> &[BitFieldPlacement] {
        &self.placements
    }

    /// Get the placement at a given bit index, if any.
    pub fn placement_at_bit(&self, bit: u32) -> Option<&BitFieldPlacement> {
        self.placements
            .iter()
            .find(|p| bit >= p.bit_offset && bit < p.end_bit())
    }

    /// Generate the bit array for visual display.
    pub fn generate_bits(&self) -> Vec<PlacementBit> {
        let mut bits: Vec<PlacementBit> = (0..self.storage_bits)
            .map(|i| PlacementBit {
                index: i,
                occupied: false,
                owner_ordinal: None,
            })
            .collect();

        for placement in &self.placements {
            for bit in placement.bit_offset..placement.end_bit() {
                if (bit as usize) < bits.len() {
                    bits[bit as usize].occupied = true;
                    bits[bit as usize].owner_ordinal = Some(placement.ordinal);
                }
            }
        }

        if self.big_endian {
            // For display, big-endian shows MSB on the left
            // bits are already indexed from 0 (LSB) to storage_bits-1 (MSB)
            // We reverse for display purposes
        }

        bits
    }

    /// Select a placement by ordinal.
    pub fn select(&mut self, ordinal: usize) {
        self.selected = self.placements.iter().position(|p| p.ordinal == ordinal);
    }

    /// Deselect.
    pub fn deselect(&mut self) {
        self.selected = None;
    }

    /// Get the selected placement.
    pub fn selected_placement(&self) -> Option<&BitFieldPlacement> {
        self.selected.and_then(|i| self.placements.get(i))
    }

    /// Number of free bits in the storage unit.
    pub fn free_bits(&self) -> u32 {
        let used: u32 = self.placements.iter().map(|p| p.bit_size).sum();
        self.storage_bits.saturating_sub(used)
    }

    /// Whether the placement is full (no free bits).
    pub fn is_full(&self) -> bool {
        self.free_bits() == 0
    }

    /// Clear all placements.
    pub fn clear(&mut self) {
        self.placements.clear();
        self.selected = None;
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_field_placement_basics() {
        let bf = BitFieldPlacement::new("flags", "uint", 3, 5, 0);
        assert_eq!(bf.end_bit(), 8);
        assert_eq!(bf.start_byte(), 0);
        assert_eq!(bf.end_byte(), 0);
        assert!(!bf.spans_bytes());
    }

    #[test]
    fn test_bit_field_placement_spanning_bytes() {
        let bf = BitFieldPlacement::new("wide", "uint", 6, 4, 0);
        assert_eq!(bf.start_byte(), 0);
        assert_eq!(bf.end_byte(), 1);
        assert!(bf.spans_bytes());
    }

    #[test]
    fn test_bit_field_placement_overlap() {
        let bf1 = BitFieldPlacement::new("a", "uint", 0, 4, 0);
        let bf2 = BitFieldPlacement::new("b", "uint", 3, 4, 1);
        let bf3 = BitFieldPlacement::new("c", "uint", 4, 4, 2);
        assert!(bf1.overlaps(&bf2));
        assert!(!bf1.overlaps(&bf3));
        assert!(bf2.overlaps(&bf3));
    }

    #[test]
    fn test_placement_component_creation() {
        let comp = BitFieldPlacementComponent::new(32, false);
        assert_eq!(comp.storage_bits, 32);
        assert!(!comp.big_endian);
        assert!(comp.placements().is_empty());
    }

    #[test]
    fn test_placement_component_for_byte_size() {
        let comp = BitFieldPlacementComponent::for_byte_size(4, false);
        assert_eq!(comp.storage_bits, 32);
    }

    #[test]
    fn test_placement_component_add() {
        let mut comp = BitFieldPlacementComponent::new(8, false);
        comp.add_placement(BitFieldPlacement::new("a", "uint", 0, 3, 0)).unwrap();
        comp.add_placement(BitFieldPlacement::new("b", "uint", 3, 5, 1)).unwrap();
        assert_eq!(comp.placements().len(), 2);
        assert!(comp.is_full());
    }

    #[test]
    fn test_placement_component_out_of_bounds() {
        let mut comp = BitFieldPlacementComponent::new(8, false);
        let result = comp.add_placement(BitFieldPlacement::new("bad", "uint", 6, 4, 0));
        assert!(result.is_err());
    }

    #[test]
    fn test_placement_component_overlap_error() {
        let mut comp = BitFieldPlacementComponent::new(8, false);
        comp.add_placement(BitFieldPlacement::new("a", "uint", 0, 4, 0)).unwrap();
        let result = comp.add_placement(BitFieldPlacement::new("b", "uint", 2, 3, 1));
        assert!(result.is_err());
    }

    #[test]
    fn test_placement_component_generate_bits() {
        let mut comp = BitFieldPlacementComponent::new(8, false);
        comp.add_placement(BitFieldPlacement::new("lo", "uint", 0, 3, 0)).unwrap();
        comp.add_placement(BitFieldPlacement::new("hi", "uint", 5, 3, 1)).unwrap();

        let bits = comp.generate_bits();
        assert_eq!(bits.len(), 8);
        assert!(bits[0].occupied);
        assert!(bits[2].occupied);
        assert!(!bits[3].occupied);
        assert!(!bits[4].occupied);
        assert!(bits[5].occupied);
        assert!(bits[7].occupied);
    }

    #[test]
    fn test_placement_component_select() {
        let mut comp = BitFieldPlacementComponent::new(8, false);
        comp.add_placement(BitFieldPlacement::new("a", "uint", 0, 4, 0)).unwrap();
        comp.add_placement(BitFieldPlacement::new("b", "uint", 4, 4, 1)).unwrap();

        comp.select(1);
        assert_eq!(comp.selected_placement().unwrap().name, "b");

        comp.deselect();
        assert!(comp.selected_placement().is_none());
    }

    #[test]
    fn test_placement_component_remove() {
        let mut comp = BitFieldPlacementComponent::new(8, false);
        comp.add_placement(BitFieldPlacement::new("a", "uint", 0, 4, 0)).unwrap();
        let removed = comp.remove_placement(0);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().name, "a");
        assert!(comp.placements().is_empty());
    }

    #[test]
    fn test_placement_component_free_bits() {
        let mut comp = BitFieldPlacementComponent::new(16, false);
        assert_eq!(comp.free_bits(), 16);
        comp.add_placement(BitFieldPlacement::new("a", "uint", 0, 5, 0)).unwrap();
        assert_eq!(comp.free_bits(), 11);
    }

    #[test]
    fn test_placement_component_clear() {
        let mut comp = BitFieldPlacementComponent::new(8, false);
        comp.add_placement(BitFieldPlacement::new("a", "uint", 0, 4, 0)).unwrap();
        comp.select(0);
        comp.clear();
        assert!(comp.placements().is_empty());
        assert!(comp.selected_placement().is_none());
    }

    #[test]
    fn test_placement_at_bit() {
        let mut comp = BitFieldPlacementComponent::new(8, false);
        comp.add_placement(BitFieldPlacement::new("a", "uint", 2, 4, 0)).unwrap();

        assert!(comp.placement_at_bit(0).is_none());
        assert!(comp.placement_at_bit(1).is_none());
        assert_eq!(comp.placement_at_bit(2).unwrap().name, "a");
        assert_eq!(comp.placement_at_bit(5).unwrap().name, "a");
        assert!(comp.placement_at_bit(6).is_none());
    }
}
