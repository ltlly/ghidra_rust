//! Program address factory ported from Java's `ProgramAddressFactory`.
//!
//! Extends the base address factory with program-specific capabilities
//! such as overlay address spaces and stack space management.

use crate::addr::{Address, AddressFactory, AddressSpace, AddrSpaceType};
use std::collections::HashMap;
use std::fmt;

// ============================================================================
// OverlaySpaceInfo
// ============================================================================

/// Information about a program-specific overlay address space.
#[derive(Debug, Clone)]
pub struct OverlaySpaceInfo {
    /// Name of the overlay space.
    pub name: String,
    /// Unique ID of the overlay space.
    pub space_id: u32,
    /// The underlying (parent) space ID that this overlay maps over.
    pub parent_space_type: AddrSpaceType,
    /// Base address of the overlay region in the parent space.
    pub parent_base_offset: u64,
    /// Size of the overlay region.
    pub size: u64,
}

// ============================================================================
// ProgramAddressFactory (port of Java ProgramAddressFactory)
// ============================================================================

/// Program-specific address factory.
///
/// Port of Java `ghidra.program.database.ProgramAddressFactory`.
///
/// Extends the base [`AddressFactory`] with overlay space management,
/// stack space tracking, and stale overlay detection.
#[derive(Debug)]
pub struct ProgramAddressFactory {
    /// The base address factory from the language.
    base_factory: AddressFactory,
    /// Overlay spaces added by the program.
    overlays: HashMap<String, OverlaySpaceInfo>,
    /// Stack space (if defined by the language).
    stack_space: Option<AddressSpace>,
    /// Whether there are stale (unresolved) overlays.
    has_stale_overlays: bool,
    /// Next temporary overlay ID.
    next_tmp_id: u32,
}

impl ProgramAddressFactory {
    /// Create a new program address factory from a base factory.
    pub fn new(base_factory: AddressFactory) -> Self {
        Self {
            base_factory,
            overlays: HashMap::new(),
            stack_space: None,
            has_stale_overlays: false,
            next_tmp_id: 1,
        }
    }

    /// Get the base (language-provided) address factory.
    pub fn base_factory(&self) -> &AddressFactory {
        &self.base_factory
    }

    /// Get the stack space, if defined.
    pub fn stack_space(&self) -> Option<&AddressSpace> {
        self.stack_space.as_ref()
    }

    /// Set the stack space.
    pub fn set_stack_space(&mut self, space: AddressSpace) {
        self.stack_space = Some(space);
    }

    // ---- Overlay management ----

    /// Add an overlay address space to the program.
    ///
    /// Port of Java `ProgramAddressFactory.addOverlayAddressSpace(...)`.
    pub fn add_overlay(
        &mut self,
        name: &str,
        parent_space_type: AddrSpaceType,
        parent_base_offset: u64,
        size: u64,
    ) -> OverlaySpaceInfo {
        let space_id = self.next_tmp_id;
        self.next_tmp_id += 1;
        let info = OverlaySpaceInfo {
            name: name.to_string(),
            space_id,
            parent_space_type,
            parent_base_offset,
            size,
        };
        self.overlays.insert(name.to_string(), info.clone());
        info
    }

    /// Remove an overlay address space.
    pub fn remove_overlay(&mut self, name: &str) -> Option<OverlaySpaceInfo> {
        self.overlays.remove(name)
    }

    /// Get info about an overlay space by name.
    pub fn get_overlay(&self, name: &str) -> Option<&OverlaySpaceInfo> {
        self.overlays.get(name)
    }

    /// Get all overlay spaces.
    pub fn overlays(&self) -> &HashMap<String, OverlaySpaceInfo> {
        &self.overlays
    }

    /// Return the number of overlay spaces.
    pub fn overlay_count(&self) -> usize {
        self.overlays.len()
    }

    /// Whether there are stale overlays that need resolution.
    pub fn has_stale_overlays(&self) -> bool {
        self.has_stale_overlays
    }

    /// Mark overlays as stale.
    pub fn set_stale_overlays(&mut self, stale: bool) {
        self.has_stale_overlays = stale;
    }

    // ---- Address space queries ----

    /// Check if a space type is a memory address space.
    pub fn is_memory_space(&self, space_type: AddrSpaceType) -> bool {
        space_type.is_memory()
    }

    /// Check if a space type is an overlay.
    pub fn is_overlay_space(&self, name: &str) -> bool {
        self.overlays.contains_key(name)
    }

    /// Translate an address from the original factory to the program factory,
    /// accounting for any image base changes.
    pub fn translate_address(&self, addr: &Address) -> Address {
        // For now, addresses pass through unchanged.
        *addr
    }
}

impl fmt::Display for ProgramAddressFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProgramAddressFactory(overlays={}, stack={})",
            self.overlays.len(),
            self.stack_space.is_some(),
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_address_factory_basics() {
        let base = AddressFactory::new();
        let paf = ProgramAddressFactory::new(base);
        assert_eq!(paf.overlay_count(), 0);
        assert!(!paf.has_stale_overlays());
        assert!(paf.stack_space().is_none());
    }

    #[test]
    fn test_overlay_add_remove() {
        let base = AddressFactory::new();
        let mut paf = ProgramAddressFactory::new(base);

        let overlay = paf.add_overlay("OVR1", AddrSpaceType::Ram, 0x10000, 0x1000);
        assert_eq!(overlay.name, "OVR1");
        assert_eq!(paf.overlay_count(), 1);
        assert!(paf.is_overlay_space("OVR1"));
        assert!(!paf.is_overlay_space("NOPE"));

        paf.remove_overlay("OVR1");
        assert_eq!(paf.overlay_count(), 0);
    }

    #[test]
    fn test_stale_overlays() {
        let base = AddressFactory::new();
        let mut paf = ProgramAddressFactory::new(base);
        assert!(!paf.has_stale_overlays());
        paf.set_stale_overlays(true);
        assert!(paf.has_stale_overlays());
    }

    #[test]
    fn test_stack_space() {
        let base = AddressFactory::new();
        let mut paf = ProgramAddressFactory::new(base);
        assert!(paf.stack_space().is_none());
        paf.set_stack_space(AddressSpace::new("stack", 8, false, AddrSpaceType::Stack, 5));
        assert!(paf.stack_space().is_some());
    }
}
