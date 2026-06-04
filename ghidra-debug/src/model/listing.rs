//! Trace code listing - instructions, data, and code units in a trace.
//!
//! Ported from Ghidra's `ghidra.trace.model.listing` package.
//! Provides the trace-equivalent of Ghidra's Program Listing, supporting
//! instructions and data units across snaps and address spaces.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::Lifespan;

/// A code unit type in the trace listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CodeUnitType {
    /// An instruction.
    Instruction,
    /// Defined data.
    Data,
    /// Undefined data.
    Undefined,
}

/// A code unit in the trace listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCodeUnit {
    /// Unique key.
    pub key: i64,
    /// The address offset.
    pub address: u64,
    /// The address space name (e.g., "ram", "register").
    pub space: String,
    /// The lifespan of this code unit.
    pub lifespan: Lifespan,
    /// The type of this code unit.
    pub unit_type: CodeUnitType,
    /// Length in bytes.
    pub length: u32,
    /// The mnemonic string (for instructions) or type name (for data).
    pub mnemonic: String,
    /// The raw bytes of the code unit.
    pub bytes: Vec<u8>,
    /// For instructions: the prototype ID (instruction encoding).
    pub prototype_id: Option<u32>,
    /// Thread key if this is in a register space.
    pub thread_key: Option<i64>,
    /// Frame level if this is in a register space.
    pub frame_level: Option<i32>,
}

impl TraceCodeUnit {
    /// Create an instruction code unit.
    pub fn instruction(
        key: i64,
        address: u64,
        space: impl Into<String>,
        lifespan: Lifespan,
        length: u32,
        mnemonic: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            key,
            address,
            space: space.into(),
            lifespan,
            unit_type: CodeUnitType::Instruction,
            length,
            mnemonic: mnemonic.into(),
            bytes,
            prototype_id: None,
            thread_key: None,
            frame_level: None,
        }
    }

    /// Create a data code unit.
    pub fn data(
        key: i64,
        address: u64,
        space: impl Into<String>,
        lifespan: Lifespan,
        length: u32,
        mnemonic: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            key,
            address,
            space: space.into(),
            lifespan,
            unit_type: CodeUnitType::Data,
            length,
            mnemonic: mnemonic.into(),
            bytes,
            prototype_id: None,
            thread_key: None,
            frame_level: None,
        }
    }

    /// Create an undefined data code unit.
    pub fn undefined(
        key: i64,
        address: u64,
        space: impl Into<String>,
        lifespan: Lifespan,
        length: u32,
    ) -> Self {
        Self {
            key,
            address,
            space: space.into(),
            lifespan,
            unit_type: CodeUnitType::Undefined,
            length,
            mnemonic: String::new(),
            bytes: Vec::new(),
            prototype_id: None,
            thread_key: None,
            frame_level: None,
        }
    }

    /// Set the prototype ID for an instruction.
    pub fn with_prototype(mut self, proto_id: u32) -> Self {
        self.prototype_id = Some(proto_id);
        self
    }

    /// Set the thread and frame for register-space code units.
    pub fn with_register_context(mut self, thread_key: i64, frame_level: i32) -> Self {
        self.thread_key = Some(thread_key);
        self.frame_level = Some(frame_level);
        self
    }

    /// The end address (exclusive).
    pub fn max_address(&self) -> u64 {
        self.address + self.length as u64 - 1
    }

    /// Whether this code unit contains the given address.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.address && address <= self.max_address()
    }

    /// Whether this is an instruction.
    pub fn is_instruction(&self) -> bool {
        self.unit_type == CodeUnitType::Instruction
    }

    /// Whether this is defined data.
    pub fn is_data(&self) -> bool {
        self.unit_type == CodeUnitType::Data
    }
}

/// Manages the code listing for a trace (instructions, data, undefined regions).
///
/// Supports a "fluent" interface similar to Ghidra's `TraceCodeManager`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceCodeManager {
    next_key: i64,
    units: Vec<TraceCodeUnit>,
}

impl TraceCodeManager {
    /// Create a new code manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an instruction to the listing.
    pub fn add_instruction(
        &mut self,
        address: u64,
        space: impl Into<String>,
        lifespan: Lifespan,
        length: u32,
        mnemonic: impl Into<String>,
        bytes: Vec<u8>,
    ) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        self.units.push(TraceCodeUnit::instruction(
            key, address, space, lifespan, length, mnemonic, bytes,
        ));
        key
    }

    /// Add a data unit to the listing.
    pub fn add_data(
        &mut self,
        address: u64,
        space: impl Into<String>,
        lifespan: Lifespan,
        length: u32,
        mnemonic: impl Into<String>,
        bytes: Vec<u8>,
    ) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        self.units.push(TraceCodeUnit::data(
            key, address, space, lifespan, length, mnemonic, bytes,
        ));
        key
    }

    /// Delete a code unit by key.
    pub fn delete_unit(&mut self, key: i64) -> bool {
        let before = self.units.len();
        self.units.retain(|u| u.key != key);
        self.units.len() < before
    }

    /// Get all code units.
    pub fn all_units(&self) -> &[TraceCodeUnit] {
        &self.units
    }

    /// Get instructions only.
    pub fn instructions(&self) -> Vec<&TraceCodeUnit> {
        self.units
            .iter()
            .filter(|u| u.is_instruction())
            .collect()
    }

    /// Get data units only.
    pub fn data_units(&self) -> Vec<&TraceCodeUnit> {
        self.units.iter().filter(|u| u.is_data()).collect()
    }

    /// Get the instruction at the given address at the given snap.
    pub fn get_instruction_at(&self, snap: i64, address: u64, space: &str) -> Option<&TraceCodeUnit> {
        self.units.iter().find(|u| {
            u.is_instruction()
                && u.space == space
                && u.address == address
                && u.lifespan.contains(snap)
        })
    }

    /// Get the code unit containing the given address at the given snap.
    pub fn get_containing(&self, snap: i64, address: u64, space: &str) -> Option<&TraceCodeUnit> {
        self.units.iter().find(|u| {
            u.space == space
                && u.contains(address)
                && u.lifespan.contains(snap)
        })
    }

    /// Get all code units in the given space at the given snap.
    pub fn units_in_space(&self, snap: i64, space: &str) -> Vec<&TraceCodeUnit> {
        self.units
            .iter()
            .filter(|u| u.space == space && u.lifespan.contains(snap))
            .collect()
    }

    /// Get all instructions in a given address range.
    pub fn instructions_in_range(
        &self,
        snap: i64,
        space: &str,
        min_addr: u64,
        max_addr: u64,
    ) -> Vec<&TraceCodeUnit> {
        self.units
            .iter()
            .filter(|u| {
                u.is_instruction()
                    && u.space == space
                    && u.lifespan.contains(snap)
                    && u.address >= min_addr
                    && u.address <= max_addr
            })
            .collect()
    }

    /// Number of code units.
    pub fn len(&self) -> usize {
        self.units.len()
    }

    /// Whether there are no code units.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    /// Get a code unit by key.
    pub fn get(&self, key: i64) -> Option<&TraceCodeUnit> {
        self.units.iter().find(|u| u.key == key)
    }
}

/// A map from (space, address, snap) to code unit key, for fast lookups.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceCodeIndex {
    /// Index by (space, address) for instruction lookups.
    by_address: BTreeMap<(String, u64), Vec<i64>>,
}

impl TraceCodeIndex {
    /// Create a new index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Index a code unit.
    pub fn insert(&mut self, space: &str, address: u64, key: i64) {
        self.by_address
            .entry((space.to_string(), address))
            .or_default()
            .push(key);
    }

    /// Remove a code unit from the index.
    pub fn remove(&mut self, space: &str, address: u64, key: i64) {
        if let Some(keys) = self.by_address.get_mut(&(space.to_string(), address)) {
            keys.retain(|k| *k != key);
            if keys.is_empty() {
                self.by_address.remove(&(space.to_string(), address));
            }
        }
    }

    /// Look up code unit keys at a given address.
    pub fn get(&self, space: &str, address: u64) -> Option<&Vec<i64>> {
        self.by_address.get(&(space.to_string(), address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_unit_instruction() {
        let cu = TraceCodeUnit::instruction(
            1, 0x400000, "ram", Lifespan::at(0), 3, "MOV", vec![0x89, 0xe5, 0x90],
        );
        assert!(cu.is_instruction());
        assert!(!cu.is_data());
        assert_eq!(cu.max_address(), 0x400002);
        assert!(cu.contains(0x400001));
        assert!(!cu.contains(0x400003));
    }

    #[test]
    fn test_code_unit_data() {
        let cu = TraceCodeUnit::data(
            2, 0x1000, "ram", Lifespan::at(0), 4, "DWORD", vec![0x01, 0x00, 0x00, 0x00],
        );
        assert!(cu.is_data());
        assert_eq!(cu.length, 4);
    }

    #[test]
    fn test_code_unit_register_context() {
        let cu = TraceCodeUnit::instruction(
            1, 0, "register", Lifespan::at(0), 8, "RAX", vec![0; 8],
        )
        .with_register_context(100, 0);
        assert_eq!(cu.thread_key, Some(100));
        assert_eq!(cu.frame_level, Some(0));
    }

    #[test]
    fn test_code_manager_add_and_query() {
        let mut mgr = TraceCodeManager::new();
        mgr.add_instruction(0x400000, "ram", Lifespan::at(0), 3, "NOP", vec![0x90, 0x90, 0x90]);
        mgr.add_instruction(0x400003, "ram", Lifespan::at(0), 5, "MOV", vec![0xb8, 0x01, 0x00, 0x00, 0x00]);
        mgr.add_data(0x500000, "ram", Lifespan::at(0), 4, "DWORD", vec![0x01, 0x00, 0x00, 0x00]);

        assert_eq!(mgr.len(), 3);
        assert_eq!(mgr.instructions().len(), 2);
        assert_eq!(mgr.data_units().len(), 1);
    }

    #[test]
    fn test_code_manager_get_instruction_at() {
        let mut mgr = TraceCodeManager::new();
        mgr.add_instruction(0x400000, "ram", Lifespan::at(0), 3, "NOP", vec![0x90; 3]);

        let inst = mgr.get_instruction_at(0, 0x400000, "ram");
        assert!(inst.is_some());
        assert_eq!(inst.unwrap().mnemonic, "NOP");

        assert!(mgr.get_instruction_at(0, 0x500000, "ram").is_none());
        assert!(mgr.get_instruction_at(1, 0x400000, "ram").is_none());
    }

    #[test]
    fn test_code_manager_get_containing() {
        let mut mgr = TraceCodeManager::new();
        mgr.add_instruction(0x400000, "ram", Lifespan::at(0), 5, "CALL", vec![0xe8; 5]);

        let cu = mgr.get_containing(0, 0x400002, "ram");
        assert!(cu.is_some());
        assert_eq!(cu.unwrap().mnemonic, "CALL");
    }

    #[test]
    fn test_code_manager_instructions_in_range() {
        let mut mgr = TraceCodeManager::new();
        mgr.add_instruction(0x400000, "ram", Lifespan::at(0), 1, "NOP", vec![0x90]);
        mgr.add_instruction(0x400001, "ram", Lifespan::at(0), 1, "NOP", vec![0x90]);
        mgr.add_instruction(0x400002, "ram", Lifespan::at(0), 1, "NOP", vec![0x90]);
        mgr.add_instruction(0x400010, "ram", Lifespan::at(0), 1, "NOP", vec![0x90]);

        let in_range = mgr.instructions_in_range(0, "ram", 0x400000, 0x400001);
        assert_eq!(in_range.len(), 2);
    }

    #[test]
    fn test_code_manager_delete() {
        let mut mgr = TraceCodeManager::new();
        let key = mgr.add_instruction(0x400000, "ram", Lifespan::at(0), 1, "NOP", vec![0x90]);
        assert_eq!(mgr.len(), 1);
        assert!(mgr.delete_unit(key));
        assert!(mgr.is_empty());
    }

    #[test]
    fn test_code_index() {
        let mut idx = TraceCodeIndex::new();
        idx.insert("ram", 0x400000, 1);
        idx.insert("ram", 0x400000, 2);
        idx.insert("ram", 0x400003, 3);

        assert_eq!(idx.get("ram", 0x400000).unwrap().len(), 2);
        assert_eq!(idx.get("ram", 0x400003).unwrap().len(), 1);
        assert!(idx.get("ram", 0x500000).is_none());

        idx.remove("ram", 0x400000, 1);
        assert_eq!(idx.get("ram", 0x400000).unwrap().len(), 1);
    }

    #[test]
    fn test_code_unit_serde() {
        let cu = TraceCodeUnit::instruction(
            1, 0x400, "ram", Lifespan::at(0), 3, "NOP", vec![0x90; 3],
        );
        let json = serde_json::to_string(&cu).unwrap();
        let back: TraceCodeUnit = serde_json::from_str(&json).unwrap();
        assert_eq!(back.key, 1);
        assert_eq!(back.address, 0x400);
    }
}
