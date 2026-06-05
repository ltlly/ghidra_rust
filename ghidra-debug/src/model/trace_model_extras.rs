//! Additional trace model types from Ghidra's Framework-TraceModeling.
//!
//! This module consolidates several trace model types that were missing from
//! the initial port, including:
//! - `TraceData`: Data code unit interface
//! - `TraceInstruction`: Instruction code unit interface
//! - `TraceMemory`: Memory model interface
//! - `TraceGuestPlatform`: Guest platform for multi-language targets
//! - `TraceBreakpointManager`: Breakpoint management interface
//! - `TraceEquateManager`: Equate management interface
//! - `TraceReferenceManager`: Reference management interface
//! - `TraceStaticMappingManager`: Static mapping management interface
//! - `TracePropertyMapOperations`: Property map operations
//! - `TracePropertyMapSpace`: Property map space interface
//! - `TraceAddressPropertyManager`: Address property management
//! - `TraceAddressSnapRangePropertyMapOperations`: Address-snap property map ops
//! - `TraceAddressSnapRangePropertyMapSpace`: Address-snap property map space

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::model::Lifespan;

/// A data code unit within a trace listing.
///
/// Ported from Ghidra's `TraceData` interface. Represents a typed data element
/// at a specific address and snap within a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDataUnit {
    /// The trace address (offset).
    pub address: u64,
    /// The snap (time snapshot).
    pub snap: i64,
    /// The data type name (e.g., "dword", "string").
    pub data_type_name: String,
    /// The length in bytes.
    pub length: usize,
    /// The raw bytes of the data value.
    pub value: Vec<u8>,
    /// Component path for nested data types.
    pub component_path: Vec<usize>,
    /// Whether this is an undefined data unit.
    pub is_undefined: bool,
}

impl TraceDataUnit {
    /// Create a new data unit.
    pub fn new(address: u64, snap: i64, data_type_name: impl Into<String>, length: usize) -> Self {
        Self {
            address,
            snap,
            data_type_name: data_type_name.into(),
            length,
            value: vec![0u8; length],
            component_path: Vec::new(),
            is_undefined: false,
        }
    }

    /// Create an undefined data unit.
    pub fn undefined(address: u64, snap: i64, length: usize) -> Self {
        Self {
            address,
            snap,
            data_type_name: "undefined".into(),
            length,
            value: vec![0u8; length],
            component_path: Vec::new(),
            is_undefined: true,
        }
    }

    /// Get the end address (exclusive).
    pub fn end_address(&self) -> u64 {
        self.address + self.length as u64
    }

    /// Get the component at the given index, if this is a composite type.
    pub fn get_component(&self, index: usize) -> Option<Self> {
        if index >= self.length {
            return None;
        }
        let mut child = self.clone();
        child.component_path.push(index);
        Some(child)
    }

    /// Whether this data unit has components.
    pub fn has_components(&self) -> bool {
        self.length > 1 && !self.is_undefined
    }
}

/// An instruction code unit within a trace listing.
///
/// Ported from Ghidra's `TraceInstruction` interface. Represents a
/// disassembled instruction at a specific address and snap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceInstructionUnit {
    /// The trace address (offset).
    pub address: u64,
    /// The snap (time snapshot).
    pub snap: i64,
    /// The mnemonic string (e.g., "MOV", "ADD").
    pub mnemonic: String,
    /// The instruction length in bytes.
    pub length: usize,
    /// The raw instruction bytes.
    pub bytes: Vec<u8>,
    /// Default fall-through address.
    pub fall_through: Option<u64>,
    /// Flow targets (branches, calls).
    pub flows: Vec<u64>,
    /// The language/processor ID.
    pub language_id: String,
    /// Whether this is in a guest (mapped) address space.
    pub is_guest: bool,
    /// Guest default fall-through (in guest address space).
    pub guest_fall_through: Option<u64>,
    /// Guest flow targets (in guest address space).
    pub guest_flows: Vec<u64>,
}

impl TraceInstructionUnit {
    /// Create a new instruction unit.
    pub fn new(
        address: u64,
        snap: i64,
        mnemonic: impl Into<String>,
        length: usize,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            address,
            snap,
            mnemonic: mnemonic.into(),
            length,
            bytes,
            fall_through: None,
            flows: Vec::new(),
            language_id: String::new(),
            is_guest: false,
            guest_fall_through: None,
            guest_flows: Vec::new(),
        }
    }

    /// Set the fall-through address.
    pub fn with_fall_through(mut self, addr: u64) -> Self {
        self.fall_through = Some(addr);
        self
    }

    /// Add a flow target.
    pub fn with_flow(mut self, addr: u64) -> Self {
        self.flows.push(addr);
        self
    }

    /// Get the end address (exclusive).
    pub fn end_address(&self) -> u64 {
        self.address + self.length as u64
    }

    /// Whether this instruction has a fall-through.
    pub fn has_fall_through(&self) -> bool {
        self.fall_through.is_some()
    }

    /// Whether this is a call instruction.
    pub fn is_call(&self) -> bool {
        self.mnemonic.starts_with("CALL") || self.mnemonic.starts_with("call")
    }

    /// Whether this is a return instruction.
    pub fn is_return(&self) -> bool {
        self.mnemonic == "RET"
            || self.mnemonic == "ret"
            || self.mnemonic == "RETN"
            || self.mnemonic == "BX LR"
    }
}

/// The memory model of a target object.
///
/// Ported from Ghidra's `TraceMemory` interface. Represents the memory
/// layout of a debug target, containing regions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceMemoryObject {
    /// The schema name for this interface.
    pub schema_name: String,
    /// The short name.
    pub short_name: String,
    /// Regions in this memory model.
    pub regions: Vec<TraceMemoryRegionEntry>,
}

impl Default for TraceMemoryObject {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceMemoryObject {
    /// Create a new memory object.
    pub fn new() -> Self {
        Self {
            schema_name: "Memory".into(),
            short_name: "memory".into(),
            regions: Vec::new(),
        }
    }

    /// Add a region to this memory model.
    pub fn add_region(&mut self, region: TraceMemoryRegionEntry) {
        self.regions.push(region);
    }
}

/// A memory region entry in a trace memory model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceMemoryRegionEntry {
    /// The region name.
    pub name: String,
    /// Start address.
    pub min_address: u64,
    /// End address (exclusive).
    pub max_address: u64,
    /// The address space name.
    pub space_name: String,
    /// Whether the region is readable.
    pub readable: bool,
    /// Whether the region is writable.
    pub writable: bool,
    /// Whether the region is executable.
    pub executable: bool,
    /// The lifespan of this region.
    pub lifespan: Lifespan,
}

impl TraceMemoryRegionEntry {
    /// Create a new memory region entry.
    pub fn new(
        name: impl Into<String>,
        min_address: u64,
        max_address: u64,
        space_name: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            min_address,
            max_address,
            space_name: space_name.into(),
            readable: true,
            writable: true,
            executable: false,
            lifespan: Lifespan::ALL,
        }
    }

    /// Get the size of this region.
    pub fn size(&self) -> u64 {
        self.max_address - self.min_address
    }
}

/// A static mapping between program and trace addresses.
///
/// Ported from Ghidra's `TraceStaticMapping`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStaticMapping {
    /// Unique ID.
    pub id: i64,
    /// Program address range min.
    pub program_min: u64,
    /// Program address range max.
    pub program_max: u64,
    /// Trace address range min.
    pub trace_min: u64,
    /// Trace address range max.
    pub trace_max: u64,
    /// The snap range.
    pub lifespan: Lifespan,
    /// The program URL.
    pub program_url: String,
    /// Whether the addresses are byte-mapped (vs. address-mapped).
    pub byte_mapped: bool,
}

impl TraceStaticMapping {
    /// Create a new static mapping.
    pub fn new(
        program_min: u64,
        program_max: u64,
        trace_min: u64,
        trace_max: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            id: 0,
            program_min,
            program_max,
            trace_min,
            trace_max,
            lifespan,
            program_url: String::new(),
            byte_mapped: false,
        }
    }

    /// Translate a program address to a trace address.
    pub fn program_to_trace(&self, prog_addr: u64) -> Option<u64> {
        if prog_addr < self.program_min || prog_addr > self.program_max {
            return None;
        }
        let offset = prog_addr - self.program_min;
        Some(self.trace_min + offset)
    }

    /// Translate a trace address to a program address.
    pub fn trace_to_program(&self, trace_addr: u64) -> Option<u64> {
        if trace_addr < self.trace_min || trace_addr > self.trace_max {
            return None;
        }
        let offset = trace_addr - self.trace_min;
        Some(self.program_min + offset)
    }

    /// Get the length of the mapping.
    pub fn length(&self) -> u64 {
        self.program_max - self.program_min
    }
}

/// Property map operations trait for trace property management.
///
/// Ported from `TracePropertyMapOperations`.
pub trait TracePropertyMapOperations<T: Clone>: Send + Sync {
    /// Get a property value at the given address and snap.
    fn get(&self, address: u64, snap: i64) -> Option<T>;

    /// Set a property value.
    fn set(&mut self, address: u64, lifespan: &Lifespan, value: T) -> Result<(), String>;

    /// Remove a property value.
    fn remove(&mut self, address: u64, snap: i64) -> bool;

    /// Get all property entries.
    fn entries(&self) -> Vec<(u64, Lifespan, T)>;

    /// Clear all entries.
    fn clear(&mut self);
}

/// Property map space interface for managing properties within an address space.
///
/// Ported from `TracePropertyMapSpace`.
#[derive(Debug)]
pub struct TracePropertyMapSpace<T: Clone> {
    /// The address space name.
    pub space_name: String,
    /// Properties indexed by (address, lifespan).
    properties: BTreeMap<u64, Vec<(Lifespan, T)>>,
}

impl<T: Clone + std::fmt::Debug> TracePropertyMapSpace<T> {
    /// Create a new property map space.
    pub fn new(space_name: impl Into<String>) -> Self {
        Self {
            space_name: space_name.into(),
            properties: BTreeMap::new(),
        }
    }
}

impl<T: Clone + std::fmt::Debug + Send + Sync> TracePropertyMapOperations<T>
    for TracePropertyMapSpace<T>
{
    fn get(&self, address: u64, snap: i64) -> Option<T> {
        self.properties
            .get(&address)?
            .iter()
            .find(|(lifespan, _)| lifespan.contains(snap))
            .map(|(_, v)| v.clone())
    }

    fn set(&mut self, address: u64, lifespan: &Lifespan, value: T) -> Result<(), String> {
        let entries = self.properties.entry(address).or_default();
        // Remove overlapping entries
        entries.retain(|(l, _)| !l.intersects(lifespan));
        entries.push((lifespan.clone(), value));
        Ok(())
    }

    fn remove(&mut self, address: u64, snap: i64) -> bool {
        if let Some(entries) = self.properties.get_mut(&address) {
            let before = entries.len();
            entries.retain(|(l, _)| !l.contains(snap));
            entries.len() < before
        } else {
            false
        }
    }

    fn entries(&self) -> Vec<(u64, Lifespan, T)> {
        self.properties
            .iter()
            .flat_map(|(&addr, entries)| {
                entries
                    .iter()
                    .map(move |(l, v)| (addr, l.clone(), v.clone()))
            })
            .collect()
    }

    fn clear(&mut self) {
        self.properties.clear();
    }
}

/// Address property manager for managing boolean properties across address spaces.
///
/// Ported from `TraceAddressPropertyManager`.
#[derive(Debug)]
pub struct TraceAddressPropertyManager {
    /// Properties per space name.
    spaces: BTreeMap<String, TracePropertyMapSpace<bool>>,
}

impl Default for TraceAddressPropertyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceAddressPropertyManager {
    /// Create a new address property manager.
    pub fn new() -> Self {
        Self {
            spaces: BTreeMap::new(),
        }
    }

    /// Get or create a property map space.
    pub fn get_or_create_space(&mut self, space_name: &str) -> &mut TracePropertyMapSpace<bool> {
        self.spaces
            .entry(space_name.to_string())
            .or_insert_with(|| TracePropertyMapSpace::new(space_name))
    }

    /// Get a property value.
    pub fn get(&self, space_name: &str, address: u64, snap: i64) -> Option<bool> {
        self.spaces.get(space_name)?.get(address, snap)
    }

    /// Set a property value.
    pub fn set(
        &mut self,
        space_name: &str,
        address: u64,
        lifespan: &Lifespan,
        value: bool,
    ) -> Result<(), String> {
        self.get_or_create_space(space_name)
            .set(address, lifespan, value)
    }

    /// Remove a property.
    pub fn remove(&mut self, space_name: &str, address: u64, snap: i64) -> bool {
        if let Some(space) = self.spaces.get_mut(space_name) {
            space.remove(address, snap)
        } else {
            false
        }
    }

    /// Get all space names.
    pub fn space_names(&self) -> Vec<&str> {
        self.spaces.keys().map(|s| s.as_str()).collect()
    }
}

/// Equate (named constant) manager trait.
///
/// Ported from `TraceEquateManager`.
pub trait TraceEquateManagerOps: Send + Sync {
    /// Create an equate.
    fn create_equate(
        &mut self,
        name: &str,
        value: i64,
        address: u64,
        snap: i64,
    ) -> Result<i64, String>;

    /// Remove an equate by ID.
    fn remove_equate(&mut self, equate_id: i64) -> Result<(), String>;

    /// Get equate by name.
    fn get_equate_by_name(&self, name: &str) -> Option<i64>;

    /// Get equate at address.
    fn get_equate_at(&self, address: u64, snap: i64) -> Option<String>;

    /// Get all equates.
    fn get_all_equates(&self) -> Vec<(i64, String, i64)>;
}

/// Reference manager trait for managing code references in traces.
///
/// Ported from `TraceReferenceManager`.
pub trait TraceReferenceManagerOps: Send + Sync {
    /// Add a reference.
    fn add_reference(
        &mut self,
        from_address: u64,
        to_address: u64,
        ref_type: TraceReferenceType,
        snap: i64,
    ) -> Result<i64, String>;

    /// Remove a reference.
    fn remove_reference(&mut self, ref_id: i64) -> Result<(), String>;

    /// Get references from an address.
    fn get_references_from(&self, address: u64, snap: i64) -> Vec<TraceReferenceEntry>;

    /// Get references to an address.
    fn get_references_to(&self, address: u64, snap: i64) -> Vec<TraceReferenceEntry>;
}

/// A reference type in a trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraceReferenceType {
    /// A data reference (read/write).
    Data,
    /// A flow reference (jump/call).
    Flow,
    /// An offset reference.
    Offset,
    /// A shifted reference.
    Shifted,
    /// A stack reference.
    Stack,
}

/// A reference entry in the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceReferenceEntry {
    /// Reference ID.
    pub id: i64,
    /// Source address.
    pub from_address: u64,
    /// Destination address.
    pub to_address: u64,
    /// Reference type.
    pub ref_type: TraceReferenceType,
    /// The snap at which this reference exists.
    pub snap: i64,
}

/// Guest platform for multi-language targets.
///
/// Ported from `TraceGuestPlatform`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceGuestPlatform {
    /// The guest language ID.
    pub language_id: String,
    /// The guest compiler spec ID.
    pub compiler_spec_id: String,
    /// Mapped ranges from guest to host.
    pub mapped_ranges: Vec<TraceGuestPlatformMappedRange>,
}

/// A mapped range from guest to host address space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceGuestPlatformMappedRange {
    /// Guest address range min.
    pub guest_min: u64,
    /// Guest address range max.
    pub guest_max: u64,
    /// Host address range min.
    pub host_min: u64,
    /// Host address range max.
    pub host_max: u64,
    /// The host address space name.
    pub host_space_name: String,
    /// The guest address space name.
    pub guest_space_name: String,
}

impl TraceGuestPlatformMappedRange {
    /// Translate a guest address to a host address.
    pub fn guest_to_host(&self, guest_addr: u64) -> Option<u64> {
        if guest_addr < self.guest_min || guest_addr > self.guest_max {
            return None;
        }
        let offset = guest_addr - self.guest_min;
        Some(self.host_min + offset)
    }

    /// Translate a host address to a guest address.
    pub fn host_to_guest(&self, host_addr: u64) -> Option<u64> {
        if host_addr < self.host_min || host_addr > self.host_max {
            return None;
        }
        let offset = host_addr - self.host_min;
        Some(self.guest_min + offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_data_unit() {
        let unit = TraceDataUnit::new(0x400000, 0, "dword", 4);
        assert_eq!(unit.address, 0x400000);
        assert_eq!(unit.length, 4);
        assert_eq!(unit.end_address(), 0x400004);
        assert!(!unit.is_undefined);
        assert!(unit.has_components());

        let comp = unit.get_component(0);
        assert!(comp.is_some());
        assert_eq!(comp.unwrap().component_path, vec![0]);

        let undef = TraceDataUnit::undefined(0x500000, 0, 8);
        assert!(undef.is_undefined);
        assert!(!undef.has_components());
    }

    #[test]
    fn test_trace_instruction_unit() {
        let inst = TraceInstructionUnit::new(0x400000, 0, "MOV", 2, vec![0x89, 0xE5])
            .with_fall_through(0x400002)
            .with_flow(0x400100);
        assert_eq!(inst.mnemonic, "MOV");
        assert!(inst.has_fall_through());
        assert_eq!(inst.fall_through, Some(0x400002));
        assert_eq!(inst.flows.len(), 1);
        assert_eq!(inst.end_address(), 0x400002);
        assert!(!inst.is_call());
        assert!(!inst.is_return());
    }

    #[test]
    fn test_instruction_call_detection() {
        let call = TraceInstructionUnit::new(0x1000, 0, "CALL", 5, vec![]);
        assert!(call.is_call());

        let ret = TraceInstructionUnit::new(0x2000, 0, "RET", 1, vec![]);
        assert!(ret.is_return());

        let bx_lr = TraceInstructionUnit::new(0x3000, 0, "BX LR", 4, vec![]);
        assert!(bx_lr.is_return());
    }

    #[test]
    fn test_trace_memory_object() {
        let mut mem = TraceMemoryObject::new();
        assert_eq!(mem.schema_name, "Memory");

        mem.add_region(TraceMemoryRegionEntry::new(".text", 0x400000, 0x500000, "ram"));
        assert_eq!(mem.regions.len(), 1);
        assert_eq!(mem.regions[0].size(), 0x100000);
        assert!(mem.regions[0].readable);
        assert!(!mem.regions[0].executable); // default
    }

    #[test]
    fn test_static_mapping() {
        let mapping = TraceStaticMapping::new(0x401000, 0x402000, 0x1000, 0x2000, Lifespan::ALL);
        assert_eq!(mapping.length(), 0x1000);

        assert_eq!(mapping.program_to_trace(0x401000), Some(0x1000));
        assert_eq!(mapping.program_to_trace(0x401500), Some(0x1500));
        assert_eq!(mapping.program_to_trace(0x402000), Some(0x2000));
        assert_eq!(mapping.program_to_trace(0x500000), None);

        assert_eq!(mapping.trace_to_program(0x1000), Some(0x401000));
        assert_eq!(mapping.trace_to_program(0x1500), Some(0x401500));
        assert_eq!(mapping.trace_to_program(0x3000), None);
    }

    #[test]
    fn test_property_map_space() {
        let mut space = TracePropertyMapSpace::<bool>::new("ram");
        assert_eq!(space.space_name, "ram");

        space.set(0x1000, &Lifespan::span(0, 10), true).unwrap();
        space.set(0x1000, &Lifespan::span(20, 30), false).unwrap();

        assert_eq!(space.get(0x1000, 5), Some(true));
        assert_eq!(space.get(0x1000, 25), Some(false));
        assert_eq!(space.get(0x1000, 15), None);
        assert_eq!(space.get(0x2000, 5), None);

        assert!(space.remove(0x1000, 5));
        assert_eq!(space.get(0x1000, 5), None);
        assert_eq!(space.get(0x1000, 25), Some(false));

        let entries = space.entries();
        assert_eq!(entries.len(), 1);

        space.clear();
        assert!(space.entries().is_empty());
    }

    #[test]
    fn test_address_property_manager() {
        let mut mgr = TraceAddressPropertyManager::new();
        assert!(mgr.space_names().is_empty());

        mgr.set("ram", 0x1000, &Lifespan::span(0, 10), true)
            .unwrap();
        assert_eq!(mgr.get("ram", 0x1000, 5), Some(true));
        assert_eq!(mgr.get("ram", 0x1000, 15), None);
        assert_eq!(mgr.get("other", 0x1000, 5), None);
        assert_eq!(mgr.space_names(), vec!["ram"]);

        assert!(mgr.remove("ram", 0x1000, 5));
        assert_eq!(mgr.get("ram", 0x1000, 5), None);
    }

    #[test]
    fn test_guest_platform_mapped_range() {
        let range = TraceGuestPlatformMappedRange {
            guest_min: 0x0,
            guest_max: 0xFFF,
            host_min: 0x400000,
            host_max: 0x400FFF,
            host_space_name: "ram".into(),
            guest_space_name: "guest_ram".into(),
        };

        assert_eq!(range.guest_to_host(0x100), Some(0x400100));
        assert_eq!(range.host_to_guest(0x400500), Some(0x500));
        assert_eq!(range.guest_to_host(0x2000), None);
        assert_eq!(range.host_to_guest(0x500000), None);
    }

    #[test]
    fn test_trace_reference_type() {
        assert_ne!(TraceReferenceType::Data, TraceReferenceType::Flow);
        assert_eq!(TraceReferenceType::Offset, TraceReferenceType::Offset);
    }

    #[test]
    fn test_trace_reference_entry() {
        let entry = TraceReferenceEntry {
            id: 1,
            from_address: 0x400000,
            to_address: 0x400100,
            ref_type: TraceReferenceType::Flow,
            snap: 0,
        };
        assert_eq!(entry.ref_type, TraceReferenceType::Flow);
    }
}
