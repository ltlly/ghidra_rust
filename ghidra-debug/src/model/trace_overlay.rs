//! Overlay address space support for traces.
//!
//! Ported from Ghidra's `DBTraceOverlaySpaceAdapter`.

use serde::{Deserialize, Serialize};

/// An overlay address space in a trace.
///
/// Overlay spaces map over existing address spaces, providing alternative
/// names and potentially different interpretations for the same memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceOverlaySpace {
    /// Name of the overlay space.
    pub name: String,
    /// The underlying (base) space name.
    pub base_space_name: String,
    /// The overlay start address in the base space.
    pub base_offset: u64,
    /// The overlay length in bytes.
    pub length: u64,
}

impl TraceOverlaySpace {
    /// Create a new overlay space.
    pub fn new(
        name: impl Into<String>,
        base_space_name: impl Into<String>,
        base_offset: u64,
        length: u64,
    ) -> Self {
        Self {
            name: name.into(),
            base_space_name: base_space_name.into(),
            base_offset,
            length,
        }
    }

    /// Whether the given offset falls within this overlay.
    pub fn contains(&self, offset: u64) -> bool {
        offset >= self.base_offset && offset < self.base_offset + self.length
    }

    /// Translate an overlay offset to a base offset.
    pub fn to_base_offset(&self, overlay_offset: u64) -> u64 {
        overlay_offset - self.base_offset
    }

    /// Translate a base offset to an overlay offset.
    pub fn from_base_offset(&self, base_offset: u64) -> u64 {
        base_offset + self.base_offset
    }
}

/// Manages overlay spaces in a trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceOverlayManager {
    /// Registered overlay spaces.
    overlays: Vec<TraceOverlaySpace>,
}

impl TraceOverlayManager {
    /// Create a new overlay manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an overlay space.
    pub fn add_overlay(&mut self, overlay: TraceOverlaySpace) {
        self.overlays.push(overlay);
    }

    /// Find an overlay by name.
    pub fn find_by_name(&self, name: &str) -> Option<&TraceOverlaySpace> {
        self.overlays.iter().find(|o| o.name == name)
    }

    /// Find overlays that cover the given base address.
    pub fn find_overlays_at(&self, base_space: &str, offset: u64) -> Vec<&TraceOverlaySpace> {
        self.overlays
            .iter()
            .filter(|o| o.base_space_name == base_space && o.contains(offset))
            .collect()
    }

    /// Number of registered overlays.
    pub fn count(&self) -> usize {
        self.overlays.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overlay_contains() {
        let o = TraceOverlaySpace::new("MY_CODE", "ram", 0x400000, 0x10000);
        assert!(o.contains(0x401000));
        assert!(!o.contains(0x500000));
    }

    #[test]
    fn test_overlay_translate() {
        let o = TraceOverlaySpace::new("MY_CODE", "ram", 0x400000, 0x10000);
        assert_eq!(o.to_base_offset(0x400100), 0x100);
        assert_eq!(o.from_base_offset(0x100), 0x400100);
    }

    #[test]
    fn test_overlay_manager() {
        let mut mgr = TraceOverlayManager::new();
        mgr.add_overlay(TraceOverlaySpace::new("OVL1", "ram", 0x400000, 0x1000));
        mgr.add_overlay(TraceOverlaySpace::new("OVL2", "ram", 0x500000, 0x1000));
        assert_eq!(mgr.count(), 2);
        assert!(mgr.find_by_name("OVL1").is_some());
        let at = mgr.find_overlays_at("ram", 0x400500);
        assert_eq!(at.len(), 1);
    }
}
