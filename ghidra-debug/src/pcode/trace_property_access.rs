//! P-code trace property access implementations.
//!
//! Ported from Ghidra's Framework-TraceModeling:
//! - `DefaultPcodeTracePropertyAccess`
//! - `InternalPcodeTraceDataAccess`
//!
//! Provides property-map-based access for the p-code trace emulation
//! system. Properties are address-snap-keyed values stored alongside
//! the trace memory and register state.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A property value stored in the trace property map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PropertyValue {
    /// A boolean value.
    Bool(bool),
    /// An integer value.
    Int(i64),
    /// A string value.
    String(String),
    /// A byte array value.
    Bytes(Vec<u8>),
    /// A void/null value.
    Void,
}

impl PropertyValue {
    /// Try to get a bool value.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            PropertyValue::Bool(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get an integer value.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            PropertyValue::Int(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get a string value.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            PropertyValue::String(v) => Some(v.as_str()),
            _ => None,
        }
    }

    /// Try to get a byte array value.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            PropertyValue::Bytes(v) => Some(v.as_slice()),
            _ => None,
        }
    }

    /// Whether this is a void/null value.
    pub fn is_void(&self) -> bool {
        matches!(self, PropertyValue::Void)
    }
}

/// A property entry in the trace property map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyEntry {
    /// The address.
    pub address: u64,
    /// The address space name.
    pub space: String,
    /// The snap range.
    pub lifespan: Lifespan,
    /// The property name.
    pub name: String,
    /// The property value.
    pub value: PropertyValue,
}

/// Access interface for trace property maps.
///
/// Ported from Ghidra's `DefaultPcodeTracePropertyAccess`.
#[derive(Debug, Clone, Default)]
pub struct TracePropertyAccess {
    /// Properties indexed by (space, address, name).
    entries: BTreeMap<(String, u64, String), Vec<PropertyEntry>>,
}

impl TracePropertyAccess {
    /// Create a new property access.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a property value at an address for a snap range.
    pub fn set(
        &mut self,
        space: &str,
        address: u64,
        name: &str,
        value: PropertyValue,
        lifespan: Lifespan,
    ) {
        let key = (space.to_string(), address, name.to_string());
        let entry = PropertyEntry {
            address,
            space: space.to_string(),
            lifespan,
            name: name.to_string(),
            value,
        };
        self.entries.entry(key).or_default().push(entry);
    }

    /// Get the property value at an address and snap.
    pub fn get(&self, space: &str, address: u64, name: &str, snap: i64) -> Option<&PropertyValue> {
        let key = (space.to_string(), address, name.to_string());
        self.entries.get(&key).and_then(|entries| {
            entries
                .iter()
                .find(|e| e.lifespan.contains(snap))
                .map(|e| &e.value)
        })
    }

    /// Remove all property entries at an address and name.
    pub fn remove(&mut self, space: &str, address: u64, name: &str) {
        let key = (space.to_string(), address, name.to_string());
        self.entries.remove(&key);
    }

    /// Get all property entries for a space.
    pub fn entries_for_space(&self, space: &str) -> Vec<&PropertyEntry> {
        self.entries
            .iter()
            .filter(|((s, _, _), _)| s == space)
            .flat_map(|(_, entries)| entries.iter())
            .collect()
    }

    /// Get all unique property names for a space.
    pub fn property_names(&self, space: &str) -> Vec<&str> {
        let mut names = std::collections::BTreeSet::new();
        for ((s, _, name), _) in &self.entries {
            if s == space {
                names.insert(name.as_str());
            }
        }
        names.into_iter().collect()
    }

    /// Get the total number of property entries.
    pub fn len(&self) -> usize {
        self.entries.values().map(|v| v.len()).sum()
    }

    /// Whether the property map is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Internal access layer for p-code trace data operations.
///
/// Ported from Ghidra's `InternalPcodeTraceDataAccess`.
#[derive(Debug, Clone, Default)]
pub struct InternalPcodeTraceDataAccess {
    /// Property maps indexed by map name.
    property_maps: BTreeMap<String, TracePropertyAccess>,
    /// Internal state: which memory regions have been written.
    written_regions: BTreeMap<String, Vec<(u64, u64)>>,
    /// Internal state: which registers have been written.
    written_registers: BTreeMap<String, Vec<(String, i64)>>,
}

impl InternalPcodeTraceDataAccess {
    /// Create a new internal data access layer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create a property map by name.
    pub fn property_map(&mut self, name: &str) -> &mut TracePropertyAccess {
        self.property_maps
            .entry(name.to_string())
            .or_insert_with(TracePropertyAccess::new)
    }

    /// Get a property map by name (immutable).
    pub fn get_property_map(&self, name: &str) -> Option<&TracePropertyAccess> {
        self.property_maps.get(name)
    }

    /// Record that a memory region was written.
    pub fn record_memory_write(&mut self, space: &str, start: u64, end: u64) {
        self.written_regions
            .entry(space.to_string())
            .or_default()
            .push((start, end));
    }

    /// Get all written memory regions for a space.
    pub fn written_memory_regions(&self, space: &str) -> &[(u64, u64)] {
        self.written_regions
            .get(space)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Record that a register was written.
    pub fn record_register_write(&mut self, space: &str, register: &str, snap: i64) {
        self.written_registers
            .entry(space.to_string())
            .or_default()
            .push((register.to_string(), snap));
    }

    /// Get all written registers for a space.
    pub fn written_registers(&self, space: &str) -> &[(String, i64)] {
        self.written_registers
            .get(space)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Clear all recorded writes.
    pub fn clear_write_records(&mut self) {
        self.written_regions.clear();
        self.written_registers.clear();
    }

    /// Get the number of property maps.
    pub fn property_map_count(&self) -> usize {
        self.property_maps.len()
    }

    /// Get all property map names.
    pub fn property_map_names(&self) -> Vec<&str> {
        self.property_maps.keys().map(|s| s.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_property_value_types() {
        let b = PropertyValue::Bool(true);
        assert_eq!(b.as_bool(), Some(true));
        assert!(b.as_int().is_none());

        let i = PropertyValue::Int(42);
        assert_eq!(i.as_int(), Some(42));

        let s = PropertyValue::String("hello".into());
        assert_eq!(s.as_str(), Some("hello"));

        let bytes = PropertyValue::Bytes(vec![0x01, 0x02]);
        assert_eq!(bytes.as_bytes(), Some(&[0x01, 0x02][..]));

        let v = PropertyValue::Void;
        assert!(v.is_void());
    }

    #[test]
    fn test_property_access_set_get() {
        let mut access = TracePropertyAccess::new();
        let lifespan = Lifespan::span(0, 100);

        access.set(
            "ram",
            0x1000,
            "color",
            PropertyValue::Int(0xFF0000),
            lifespan,
        );

        let value = access.get("ram", 0x1000, "color", 50);
        assert!(value.is_some());
        assert_eq!(value.unwrap().as_int(), Some(0xFF0000));

        // Outside lifespan
        let value = access.get("ram", 0x1000, "color", 150);
        assert!(value.is_none());

        // Wrong space
        let value = access.get("register", 0x1000, "color", 50);
        assert!(value.is_none());
    }

    #[test]
    fn test_property_access_remove() {
        let mut access = TracePropertyAccess::new();
        let lifespan = Lifespan::span(0, 100);

        access.set("ram", 0x1000, "color", PropertyValue::Int(1), lifespan);
        assert!(!access.is_empty());

        access.remove("ram", 0x1000, "color");
        assert!(access.is_empty());
    }

    #[test]
    fn test_property_access_entries_for_space() {
        let mut access = TracePropertyAccess::new();
        let lifespan = Lifespan::span(0, 100);

        access.set("ram", 0x1000, "a", PropertyValue::Bool(true), lifespan.clone());
        access.set("ram", 0x2000, "b", PropertyValue::Int(2), lifespan.clone());
        access.set("register", 0, "c", PropertyValue::String("x".into()), lifespan);

        let ram_entries = access.entries_for_space("ram");
        assert_eq!(ram_entries.len(), 2);

        let reg_entries = access.entries_for_space("register");
        assert_eq!(reg_entries.len(), 1);
    }

    #[test]
    fn test_internal_pcode_trace_data_access() {
        let mut data = InternalPcodeTraceDataAccess::new();

        data.property_map("color").set(
            "ram",
            0x1000,
            "bg",
            PropertyValue::Int(0xFFFFFF),
            Lifespan::span(0, 10),
        );

        assert_eq!(data.property_map_count(), 1);
        assert_eq!(data.property_map_names(), vec!["color"]);

        let color_map = data.get_property_map("color").unwrap();
        assert_eq!(color_map.len(), 1);
    }

    #[test]
    fn test_internal_data_access_write_records() {
        let mut data = InternalPcodeTraceDataAccess::new();

        data.record_memory_write("ram", 0x1000, 0x1100);
        data.record_memory_write("ram", 0x2000, 0x2100);
        data.record_register_write("register", "EAX", 0);

        assert_eq!(data.written_memory_regions("ram").len(), 2);
        assert_eq!(data.written_registers("register").len(), 1);
        assert!(data.written_memory_regions("stack").is_empty());

        data.clear_write_records();
        assert!(data.written_memory_regions("ram").is_empty());
    }
}
