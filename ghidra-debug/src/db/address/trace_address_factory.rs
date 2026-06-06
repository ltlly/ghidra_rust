//! TraceAddressFactory ported from TraceAddressFactory.java.
//!
//! Extends the address factory to support register-type overlay base spaces.

use std::collections::HashMap;

/// Address space type constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressSpaceType {
    /// Physical memory.
    Physical,
    /// Register space.
    Register,
    /// Overlay space.
    Overlay,
}

/// A simple address space descriptor.
#[derive(Debug, Clone)]
pub struct AddressSpaceDesc {
    /// Unique space ID.
    pub id: u16,
    /// Space name.
    pub name: String,
    /// Space type.
    pub space_type: AddressSpaceType,
    /// Size in bytes (0 = 64-bit default).
    pub size: u64,
    /// Whether this is an overlay.
    pub is_overlay: bool,
    /// Base space name (for overlays).
    pub base_space: Option<String>,
}

/// Trace address factory that supports register overlay base spaces.
#[derive(Debug)]
pub struct TraceAddressFactory {
    spaces: HashMap<u16, AddressSpaceDesc>,
    by_name: HashMap<String, u16>,
    next_id: u16,
}

impl TraceAddressFactory {
    /// Create a new TraceAddressFactory.
    pub fn new() -> Self {
        Self {
            spaces: HashMap::new(),
            by_name: HashMap::new(),
            next_id: 0,
        }
    }

    /// Register a new address space.
    pub fn add_space(&mut self, name: &str, space_type: AddressSpaceType) -> u16 {
        let id = self.next_id;
        self.next_id += 1;
        let desc = AddressSpaceDesc {
            id,
            name: name.to_string(),
            space_type,
            size: 0,
            is_overlay: false,
            base_space: None,
        };
        self.spaces.insert(id, desc);
        self.by_name.insert(name.to_string(), id);
        id
    }

    /// Check if a base space is valid for overlay creation.
    pub fn is_valid_overlay_base_space(&self, base_name: &str) -> bool {
        if let Some(&id) = self.by_name.get(base_name) {
            if let Some(space) = self.spaces.get(&id) {
                return matches!(space.space_type,
                    AddressSpaceType::Physical | AddressSpaceType::Register);
            }
        }
        false
    }

    /// Add an overlay space.
    pub fn add_overlay_space(&mut self, key: u64, name: &str, base_name: &str) -> Result<u16, String> {
        if self.by_name.contains_key(name) {
            return Err(format!("Address space {} already exists.", name));
        }
        if !self.is_valid_overlay_base_space(base_name) {
            return Err(format!("Invalid address space for overlay: {}", base_name));
        }
        let id = self.next_id;
        self.next_id += 1;
        let desc = AddressSpaceDesc {
            id,
            name: name.to_string(),
            space_type: AddressSpaceType::Overlay,
            size: 0,
            is_overlay: true,
            base_space: Some(base_name.to_string()),
        };
        self.spaces.insert(id, desc);
        self.by_name.insert(name.to_string(), id);
        Ok(id)
    }

    /// Remove an overlay space by name.
    pub fn remove_overlay_space(&mut self, name: &str) -> bool {
        if let Some(&id) = self.by_name.get(name) {
            self.spaces.remove(&id);
            self.by_name.remove(name);
            true
        } else {
            false
        }
    }

    /// Get a space by name.
    pub fn get_space(&self, name: &str) -> Option<&AddressSpaceDesc> {
        self.by_name.get(name).and_then(|id| self.spaces.get(id))
    }

    /// Get a space by ID.
    pub fn get_space_by_id(&self, id: u16) -> Option<&AddressSpaceDesc> {
        self.spaces.get(&id)
    }

    /// Get all registered spaces.
    pub fn all_spaces(&self) -> impl Iterator<Item = &AddressSpaceDesc> {
        self.spaces.values()
    }
}

impl Default for TraceAddressFactory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_space() {
        let mut factory = TraceAddressFactory::new();
        let id = factory.add_space("ram", AddressSpaceType::Physical);
        assert!(factory.get_space("ram").is_some());
        assert_eq!(factory.get_space_by_id(id).unwrap().name, "ram");
    }

    #[test]
    fn test_overlay_on_physical() {
        let mut factory = TraceAddressFactory::new();
        factory.add_space("ram", AddressSpaceType::Physical);
        assert!(factory.is_valid_overlay_base_space("ram"));
        let ov_id = factory.add_overlay_space(1, "ov_ram", "ram");
        assert!(ov_id.is_ok());
    }

    #[test]
    fn test_overlay_on_register() {
        let mut factory = TraceAddressFactory::new();
        factory.add_space("reg", AddressSpaceType::Register);
        assert!(factory.is_valid_overlay_base_space("reg"));
    }

    #[test]
    fn test_cannot_overlay_nonexistent() {
        let factory = TraceAddressFactory::new();
        assert!(!factory.is_valid_overlay_base_space("missing"));
    }

    #[test]
    fn test_duplicate_overlay_fails() {
        let mut factory = TraceAddressFactory::new();
        factory.add_space("ram", AddressSpaceType::Physical);
        factory.add_overlay_space(1, "ov", "ram").unwrap();
        assert!(factory.add_overlay_space(2, "ov", "ram").is_err());
    }

    #[test]
    fn test_remove_overlay() {
        let mut factory = TraceAddressFactory::new();
        factory.add_space("ram", AddressSpaceType::Physical);
        factory.add_overlay_space(1, "ov", "ram").unwrap();
        assert!(factory.remove_overlay_space("ov"));
        assert!(factory.get_space("ov").is_none());
    }
}
