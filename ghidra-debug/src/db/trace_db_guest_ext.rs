//! Extended guest platform types for database-backed traces.
//!
//! Ported from Ghidra's `ghidra.trace.database.guest` package.
//! Provides guest platform mapped memory, register support,
//! and the internal trace platform interface.

use std::collections::BTreeMap;


/// A memory mapping for a guest platform in the trace.
///
/// Corresponds to Java's `DBTraceGuestPlatformMappedMemory`. Represents
/// a region of memory mapped into a guest platform's address space.
#[derive(Debug, Clone)]
pub struct GuestPlatformMappedMemory {
    /// The platform identifier.
    pub platform_id: u64,
    /// The mapped address range start (offset in the guest space).
    pub range_start: u64,
    /// The mapped address range end.
    pub range_end: u64,
    /// The host address this maps to.
    pub host_offset: u64,
    /// The address space name in the guest platform.
    pub space_name: String,
    /// Whether this mapping is big-endian.
    pub is_big_endian: bool,
    /// Size of the mapped memory in bytes.
    pub size: u64,
}

impl GuestPlatformMappedMemory {
    /// Create a new guest platform mapped memory.
    pub fn new(
        platform_id: u64,
        range_start: u64,
        range_end: u64,
        host_offset: u64,
        space_name: impl Into<String>,
        is_big_endian: bool,
    ) -> Self {
        let size = range_end - range_start + 1;
        Self {
            platform_id,
            range_start,
            range_end,
            host_offset,
            space_name: space_name.into(),
            is_big_endian,
            size,
        }
    }

    /// Check if an address falls within this mapping.
    pub fn contains(&self, offset: u64) -> bool {
        offset >= self.range_start && offset <= self.range_end
    }

    /// Translate a guest address to a host address.
    pub fn guest_to_host(&self, guest_offset: u64) -> Option<u64> {
        if self.contains(guest_offset) {
            Some(self.host_offset + (guest_offset - self.range_start))
        } else {
            None
        }
    }

    /// Translate a host address to a guest address.
    pub fn host_to_guest(&self, host_offset: u64) -> Option<u64> {
        let guest_offset = host_offset.checked_sub(self.host_offset)?;
        let abs = self.range_start.checked_add(guest_offset)?;
        if abs <= self.range_end {
            Some(abs)
        } else {
            None
        }
    }

    /// Get the size of this mapping.
    pub fn size(&self) -> u64 {
        self.size
    }
}

/// Register support for tracking register value transfers.
///
/// Corresponds to Java's `DBTraceObjectRegisterSupport`. Handles the logic
/// of transferring register values between trace objects, labels, and
/// memory-mapped regions.
#[derive(Debug)]
pub struct ObjectRegisterSupport {
    /// Map of register name to (value, snap) entries.
    register_values: BTreeMap<String, Vec<(i64, Vec<u8>)>>,
    /// Big-endian flag for this platform.
    is_big_endian: bool,
}

impl ObjectRegisterSupport {
    /// Create a new register support handler.
    pub fn new(is_big_endian: bool) -> Self {
        Self {
            register_values: BTreeMap::new(),
            is_big_endian,
        }
    }

    /// Record a register value at a given snap.
    pub fn set_register_value(
        &mut self,
        register: impl Into<String>,
        snap: i64,
        value: Vec<u8>,
    ) {
        let entries = self.register_values.entry(register.into()).or_default();
        // Remove any existing entry for this snap
        entries.retain(|(s, _)| *s != snap);
        entries.push((snap, value));
        entries.sort_by_key(|(s, _)| *s);
    }

    /// Get a register value at or before a given snap.
    pub fn get_register_value(&self, register: &str, snap: i64) -> Option<&Vec<u8>> {
        let entries = self.register_values.get(register)?;
        entries
            .iter()
            .rev()
            .find(|(s, _)| *s <= snap)
            .map(|(_, v)| v)
    }

    /// Check if a register has any values recorded.
    pub fn has_register(&self, register: &str) -> bool {
        self.register_values
            .get(register)
            .map_or(false, |v| !v.is_empty())
    }

    /// Get all register names.
    pub fn register_names(&self) -> Vec<&str> {
        self.register_values.keys().map(|s| s.as_str()).collect()
    }

    /// Whether the register support is configured for big-endian.
    pub fn is_big_endian(&self) -> bool {
        self.is_big_endian
    }

    /// Clear all register values.
    pub fn clear(&mut self) {
        self.register_values.clear();
    }

    /// Get the number of registers tracked.
    pub fn register_count(&self) -> usize {
        self.register_values.len()
    }

    /// Remove all values for a specific register.
    pub fn remove_register(&mut self, register: &str) {
        self.register_values.remove(register);
    }
}

/// Internal interface for a trace platform.
///
/// Corresponds to Java's `InternalTracePlatform`. Extends the trace
/// platform with direct access to architecture details.
#[derive(Debug, Clone)]
pub struct InternalTracePlatform {
    /// Platform identifier.
    pub platform_id: u64,
    /// Language ID (processor architecture identifier).
    pub language_id: String,
    /// Compiler specification ID.
    pub compiler_spec_id: String,
    /// Endianness.
    pub is_big_endian: bool,
    /// Register definitions (name -> size in bytes).
    pub register_defs: BTreeMap<String, u32>,
    /// Address space names.
    pub address_spaces: Vec<String>,
}

impl InternalTracePlatform {
    /// Create a new internal trace platform.
    pub fn new(
        platform_id: u64,
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
        is_big_endian: bool,
    ) -> Self {
        Self {
            platform_id,
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
            is_big_endian,
            register_defs: BTreeMap::new(),
            address_spaces: Vec::new(),
        }
    }

    /// Add a register definition.
    pub fn add_register(&mut self, name: impl Into<String>, size_bytes: u32) {
        self.register_defs.insert(name.into(), size_bytes);
    }

    /// Add an address space.
    pub fn add_address_space(&mut self, name: impl Into<String>) {
        let n = name.into();
        if !self.address_spaces.contains(&n) {
            self.address_spaces.push(n);
        }
    }

    /// Get the register size in bytes, if defined.
    pub fn register_size(&self, name: &str) -> Option<u32> {
        self.register_defs.get(name).copied()
    }

    /// Check if a register exists.
    pub fn has_register(&self, name: &str) -> bool {
        self.register_defs.contains_key(name)
    }

    /// Get the language ID.
    pub fn language_id(&self) -> &str {
        &self.language_id
    }

    /// Get the compiler spec ID.
    pub fn compiler_spec_id(&self) -> &str {
        &self.compiler_spec_id
    }

    /// Whether the platform is big-endian.
    pub fn is_big_endian(&self) -> bool {
        self.is_big_endian
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guest_mapped_memory_containment() {
        let mem = GuestPlatformMappedMemory::new(1, 0x1000, 0x1FFF, 0x400000, "ram", false);
        assert!(mem.contains(0x1500));
        assert!(!mem.contains(0x2000));
        assert_eq!(mem.size(), 0x1000);
    }

    #[test]
    fn test_guest_mapped_memory_translation() {
        let mem = GuestPlatformMappedMemory::new(1, 0x1000, 0x1FFF, 0x400000, "ram", false);
        assert_eq!(mem.guest_to_host(0x1000), Some(0x400000));
        assert_eq!(mem.guest_to_host(0x1004), Some(0x400004));
        assert_eq!(mem.guest_to_host(0x2000), None);

        assert_eq!(mem.host_to_guest(0x400000), Some(0x1000));
        assert_eq!(mem.host_to_guest(0x400004), Some(0x1004));
        assert_eq!(mem.host_to_guest(0x3FFFFF), None);
    }

    #[test]
    fn test_object_register_support() {
        let mut rs = ObjectRegisterSupport::new(false);
        assert!(!rs.has_register("RAX"));

        rs.set_register_value("RAX", 0, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        rs.set_register_value("RAX", 10, vec![9, 8, 7, 6, 5, 4, 3, 2]);
        rs.set_register_value("RBX", 0, vec![0; 8]);

        assert!(rs.has_register("RAX"));
        assert_eq!(rs.register_count(), 2);
        assert_eq!(rs.register_names(), vec!["RAX", "RBX"]);

        assert_eq!(
            rs.get_register_value("RAX", 5),
            Some(&vec![1, 2, 3, 4, 5, 6, 7, 8])
        );
        assert_eq!(
            rs.get_register_value("RAX", 15),
            Some(&vec![9, 8, 7, 6, 5, 4, 3, 2])
        );
        assert!(rs.get_register_value("RAX", -1).is_none());
    }

    #[test]
    fn test_object_register_support_remove() {
        let mut rs = ObjectRegisterSupport::new(true);
        rs.set_register_value("RAX", 0, vec![1, 2, 3]);
        rs.remove_register("RAX");
        assert!(!rs.has_register("RAX"));
        assert_eq!(rs.register_count(), 0);
    }

    #[test]
    fn test_internal_trace_platform() {
        let mut p = InternalTracePlatform::new(1, "x86:LE:64:default", "default", false);
        p.add_register("RAX", 8);
        p.add_register("RBX", 8);
        p.add_register("EAX", 4);
        p.add_address_space("register");
        p.add_address_space("ram");

        assert!(p.has_register("RAX"));
        assert!(!p.has_register("RCX"));
        assert_eq!(p.register_size("RAX"), Some(8));
        assert_eq!(p.register_size("EAX"), Some(4));
        assert_eq!(p.address_spaces.len(), 2);
        assert_eq!(p.language_id(), "x86:LE:64:default");
        assert!(!p.is_big_endian());
    }

    #[test]
    fn test_internal_trace_platform_no_duplicate_spaces() {
        let mut p = InternalTracePlatform::new(1, "test", "default", true);
        p.add_address_space("ram");
        p.add_address_space("ram");
        assert_eq!(p.address_spaces.len(), 1);
    }
}
