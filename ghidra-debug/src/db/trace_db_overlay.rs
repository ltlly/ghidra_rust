//! Overlay space adapter for trace databases.
//!
//! Ported from Ghidra's `DBTraceOverlaySpaceAdapter`.
//!
//! Provides an adapter for managing overlay address spaces in the trace
//! database. Overlay spaces allow multiple data regions to map to the
//! same underlying address space, used for things like ROM overlays
//! or address space rebasing.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Information about an overlay address space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlaySpaceInfo {
    /// The name of the overlay space.
    pub name: String,
    /// The ID of the underlying (base) address space.
    pub base_space_id: u32,
    /// The unique ID of this overlay space.
    pub overlay_space_id: u32,
    /// The start offset of the overlay.
    pub start_offset: u64,
    /// The end offset of the overlay.
    pub end_offset: u64,
    /// Whether this overlay is currently active.
    pub active: bool,
}

impl OverlaySpaceInfo {
    /// Create a new overlay space info.
    pub fn new(
        name: impl Into<String>,
        base_space_id: u32,
        overlay_space_id: u32,
        start_offset: u64,
        end_offset: u64,
    ) -> Self {
        Self {
            name: name.into(),
            base_space_id,
            overlay_space_id,
            start_offset,
            end_offset,
            active: true,
        }
    }

    /// Check if an offset falls within this overlay's range.
    pub fn contains_offset(&self, offset: u64) -> bool {
        offset >= self.start_offset && offset <= self.end_offset
    }

    /// Get the size of this overlay's range.
    pub fn size(&self) -> u64 {
        self.end_offset.saturating_sub(self.start_offset)
    }
}

/// Adapter for managing overlay spaces in the trace database.
#[derive(Debug)]
pub struct DBTraceOverlaySpaceAdapter {
    /// Registered overlay spaces.
    overlays: HashMap<u32, OverlaySpaceInfo>,
    /// Next available overlay space ID.
    next_id: u32,
}

impl DBTraceOverlaySpaceAdapter {
    /// Create a new overlay space adapter.
    pub fn new() -> Self {
        Self {
            overlays: HashMap::new(),
            next_id: 0x8000_0000, // Start overlay IDs in upper range
        }
    }

    /// Create a new overlay space.
    pub fn create_overlay(
        &mut self,
        name: impl Into<String>,
        base_space_id: u32,
        start_offset: u64,
        end_offset: u64,
    ) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        let info = OverlaySpaceInfo::new(name, base_space_id, id, start_offset, end_offset);
        self.overlays.insert(id, info);
        id
    }

    /// Remove an overlay space by ID.
    pub fn remove_overlay(&mut self, overlay_id: u32) -> Option<OverlaySpaceInfo> {
        self.overlays.remove(&overlay_id)
    }

    /// Get information about an overlay space.
    pub fn get_overlay(&self, overlay_id: u32) -> Option<&OverlaySpaceInfo> {
        self.overlays.get(&overlay_id)
    }

    /// Get all overlays for a given base space.
    pub fn overlays_for_base(&self, base_space_id: u32) -> Vec<&OverlaySpaceInfo> {
        self.overlays
            .values()
            .filter(|info| info.base_space_id == base_space_id)
            .collect()
    }

    /// Translate an overlay address to a base address.
    pub fn overlay_to_base(&self, overlay_id: u32, offset: u64) -> Option<(u32, u64)> {
        let info = self.overlays.get(&overlay_id)?;
        if info.contains_offset(offset) {
            Some((info.base_space_id, offset))
        } else {
            None
        }
    }

    /// Translate a base address to an overlay address, if it falls within an overlay.
    pub fn base_to_overlay(&self, base_space_id: u32, offset: u64) -> Option<(u32, u64)> {
        for info in self.overlays.values() {
            if info.base_space_id == base_space_id
                && info.active
                && info.contains_offset(offset)
            {
                return Some((info.overlay_space_id, offset));
            }
        }
        None
    }

    /// Get all registered overlay spaces.
    pub fn all_overlays(&self) -> Vec<&OverlaySpaceInfo> {
        self.overlays.values().collect()
    }

    /// Get the number of overlay spaces.
    pub fn overlay_count(&self) -> usize {
        self.overlays.len()
    }
}

impl Default for DBTraceOverlaySpaceAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overlay_space_info() {
        let info = OverlaySpaceInfo::new("ROM_OVERLAY", 1, 0x80000000, 0, 0xFFFF);
        assert_eq!(info.name, "ROM_OVERLAY");
        assert_eq!(info.base_space_id, 1);
        assert!(info.contains_offset(0));
        assert!(info.contains_offset(0xFFFF));
        assert!(!info.contains_offset(0x10000));
        assert_eq!(info.size(), 0xFFFF);
    }

    #[test]
    fn test_overlay_adapter_create() {
        let mut adapter = DBTraceOverlaySpaceAdapter::new();
        let id = adapter.create_overlay("my_overlay", 1, 0, 0xFFFF);
        assert!(id >= 0x8000_0000);
        assert_eq!(adapter.overlay_count(), 1);

        let info = adapter.get_overlay(id).unwrap();
        assert_eq!(info.name, "my_overlay");
        assert_eq!(info.base_space_id, 1);
    }

    #[test]
    fn test_overlay_adapter_remove() {
        let mut adapter = DBTraceOverlaySpaceAdapter::new();
        let id = adapter.create_overlay("test", 1, 0, 100);
        assert_eq!(adapter.overlay_count(), 1);

        let removed = adapter.remove_overlay(id);
        assert!(removed.is_some());
        assert_eq!(adapter.overlay_count(), 0);
        assert!(adapter.get_overlay(id).is_none());
    }

    #[test]
    fn test_overlay_adapter_overlays_for_base() {
        let mut adapter = DBTraceOverlaySpaceAdapter::new();
        adapter.create_overlay("ov1", 1, 0, 0xFFFF);
        adapter.create_overlay("ov2", 1, 0x10000, 0x1FFFF);
        adapter.create_overlay("ov3", 2, 0, 0xFFFF);

        let base1_overlays = adapter.overlays_for_base(1);
        assert_eq!(base1_overlays.len(), 2);

        let base2_overlays = adapter.overlays_for_base(2);
        assert_eq!(base2_overlays.len(), 1);
    }

    #[test]
    fn test_overlay_adapter_translate() {
        let mut adapter = DBTraceOverlaySpaceAdapter::new();
        let id = adapter.create_overlay("ov", 1, 0, 0xFFFF);

        // Overlay to base
        let result = adapter.overlay_to_base(id, 0x100);
        assert_eq!(result, Some((1, 0x100)));

        // Out of range
        let result = adapter.overlay_to_base(id, 0x20000);
        assert_eq!(result, None);
    }

    #[test]
    fn test_overlay_adapter_base_to_overlay() {
        let mut adapter = DBTraceOverlaySpaceAdapter::new();
        let id = adapter.create_overlay("ov", 1, 0, 0xFFFF);

        let result = adapter.base_to_overlay(1, 0x100);
        assert_eq!(result, Some((id, 0x100)));

        let result = adapter.base_to_overlay(1, 0x20000);
        assert_eq!(result, None);

        let result = adapter.base_to_overlay(99, 0x100);
        assert_eq!(result, None);
    }
}
