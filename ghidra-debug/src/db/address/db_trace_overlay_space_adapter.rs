//! DBTraceOverlaySpaceAdapter ported from DBTraceOverlaySpaceAdapter.java.
//!
//! Manages overlay address spaces persisted in the database.

use std::collections::HashMap;
use super::trace_address_factory::{AddressSpaceDesc, TraceAddressFactory};

/// An entry representing a persisted overlay space.
#[derive(Debug, Clone)]
pub struct OverlaySpaceEntry {
    /// Overlay space name.
    pub name: String,
    /// Base space name.
    pub base_space: String,
}

/// Adapter managing overlay address spaces backed by a database.
#[derive(Debug)]
pub struct DBTraceOverlaySpaceAdapter {
    overlays: Vec<OverlaySpaceEntry>,
    by_name: HashMap<String, usize>,
}

impl DBTraceOverlaySpaceAdapter {
    /// Create a new adapter.
    pub fn new() -> Self {
        Self {
            overlays: Vec::new(),
            by_name: HashMap::new(),
        }
    }

    /// Initialize from existing entries.
    pub fn from_entries(entries: Vec<OverlaySpaceEntry>) -> Self {
        let mut by_name = HashMap::new();
        for (i, e) in entries.iter().enumerate() {
            by_name.insert(e.name.clone(), i);
        }
        Self {
            overlays: entries,
            by_name,
        }
    }

    /// Resync overlay spaces into the address factory.
    pub fn resync_address_factory(&self, factory: &mut TraceAddressFactory) {
        for entry in &self.overlays {
            if factory.get_space(&entry.name).is_none() {
                // Attempt to create overlay if base exists
                if factory.is_valid_overlay_base_space(&entry.base_space) {
                    let _ = factory.add_overlay_space(0, &entry.name, &entry.base_space);
                }
            }
        }
    }

    /// Create a new overlay address space.
    pub fn create_overlay(
        &mut self,
        factory: &mut TraceAddressFactory,
        name: &str,
        base: &str,
    ) -> Result<(), String> {
        if self.by_name.contains_key(name) {
            return Err(format!("Overlay {} already exists.", name));
        }
        if factory.get_space(name).is_some() {
            return Err(format!("Address space {} already exists.", name));
        }
        let entry = OverlaySpaceEntry {
            name: name.to_string(),
            base_space: base.to_string(),
        };
        let idx = self.overlays.len();
        self.overlays.push(entry);
        self.by_name.insert(name.to_string(), idx);
        factory.add_overlay_space(0, name, base)?;
        Ok(())
    }

    /// Delete an overlay address space.
    pub fn delete_overlay(
        &mut self,
        factory: &mut TraceAddressFactory,
        name: &str,
    ) -> Result<(), String> {
        let idx = self.by_name.remove(name)
            .ok_or_else(|| format!("Overlay not found: {}", name))?;
        self.overlays.remove(idx);
        // Rebuild indices
        self.by_name.clear();
        for (i, e) in self.overlays.iter().enumerate() {
            self.by_name.insert(e.name.clone(), i);
        }
        factory.remove_overlay_space(name);
        Ok(())
    }

    /// Get all overlay entries.
    pub fn overlays(&self) -> &[OverlaySpaceEntry] {
        &self.overlays
    }

    /// Check if an overlay exists.
    pub fn has_overlay(&self, name: &str) -> bool {
        self.by_name.contains_key(name)
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
    use crate::db::address::trace_address_factory::AddressSpaceType;

    #[test]
    fn test_create_and_delete_overlay() {
        let mut factory = TraceAddressFactory::new();
        factory.add_space("ram", AddressSpaceType::Physical);

        let mut adapter = DBTraceOverlaySpaceAdapter::new();
        adapter.create_overlay(&mut factory, "ov_ram", "ram").unwrap();
        assert!(adapter.has_overlay("ov_ram"));
        assert!(factory.get_space("ov_ram").is_some());

        adapter.delete_overlay(&mut factory, "ov_ram").unwrap();
        assert!(!adapter.has_overlay("ov_ram"));
        assert!(factory.get_space("ov_ram").is_none());
    }

    #[test]
    fn test_duplicate_overlay_fails() {
        let mut factory = TraceAddressFactory::new();
        factory.add_space("ram", AddressSpaceType::Physical);

        let mut adapter = DBTraceOverlaySpaceAdapter::new();
        adapter.create_overlay(&mut factory, "ov", "ram").unwrap();
        assert!(adapter.create_overlay(&mut factory, "ov", "ram").is_err());
    }

    #[test]
    fn test_resync() {
        let entries = vec![
            OverlaySpaceEntry { name: "ov1".to_string(), base_space: "ram".to_string() },
        ];
        let adapter = DBTraceOverlaySpaceAdapter::from_entries(entries);

        let mut factory = TraceAddressFactory::new();
        factory.add_space("ram", AddressSpaceType::Physical);

        adapter.resync_address_factory(&mut factory);
        assert!(factory.get_space("ov1").is_some());
    }
}
