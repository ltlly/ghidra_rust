//! Data adapters for reading memory and data from traces.
//!
//! Ported from Ghidra's `ghidra.trace.util.DataAdapter*` and
//! `ghidra.trace.util.MemoryAdapter` classes. These adapters provide
//! a uniform interface for reading bytes, instructions, code units,
//! and data elements from trace memory at specific snapshots.

use serde::{Deserialize, Serialize};

/// A simplified representation of a memory read result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryReadResult {
    /// The start address.
    pub address: u64,
    /// The bytes read.
    pub data: Vec<u8>,
    /// The memory state for each byte (e.g., known, unknown, error).
    pub states: Vec<MemoryByteState>,
}

/// The state of a single byte in trace memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryByteState {
    /// The byte value is known.
    Known,
    /// The byte value is unknown (not yet captured).
    Unknown,
    /// The byte value is in error (unreadable).
    Error,
}

/// An adapter for reading raw bytes from trace memory.
#[derive(Debug, Clone)]
pub struct MemoryAdapter {
    trace_id: String,
    snap: i64,
    space_name: String,
}

impl MemoryAdapter {
    /// Create a new memory adapter.
    pub fn new(trace_id: impl Into<String>, snap: i64, space_name: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            snap,
            space_name: space_name.into(),
        }
    }

    /// Get the trace ID.
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    /// Get the snap.
    pub fn snap(&self) -> i64 {
        self.snap
    }

    /// Get the address space name.
    pub fn space_name(&self) -> &str {
        &self.space_name
    }
}

/// A minimal data adapter for reading typed values from memory.
#[derive(Debug, Clone)]
pub struct DataAdapterMinimal {
    memory: MemoryAdapter,
}

impl DataAdapterMinimal {
    /// Create a new minimal data adapter.
    pub fn new(memory: MemoryAdapter) -> Self {
        Self { memory }
    }

    /// Get a reference to the underlying memory adapter.
    pub fn memory(&self) -> &MemoryAdapter {
        &self.memory
    }
}

/// An adapter for reading data values with type information.
#[derive(Debug, Clone)]
pub struct DataAdapterFromDataType {
    minimal: DataAdapterMinimal,
    /// The data type name.
    pub type_name: String,
    /// The data type size in bytes.
    pub type_size: u32,
}

impl DataAdapterFromDataType {
    /// Create a new typed data adapter.
    pub fn new(minimal: DataAdapterMinimal, type_name: impl Into<String>, type_size: u32) -> Self {
        Self {
            minimal,
            type_name: type_name.into(),
            type_size,
        }
    }

    /// Get a reference to the minimal adapter.
    pub fn minimal(&self) -> &DataAdapterMinimal {
        &self.minimal
    }
}

/// An adapter for reading data with display settings.
#[derive(Debug, Clone)]
pub struct DataAdapterFromSettings {
    minimal: DataAdapterMinimal,
    /// Display format settings.
    pub settings: DataDisplaySettings,
}

/// Display settings for data adapters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataDisplaySettings {
    /// The number base for displaying numbers.
    pub radix: u32,
    /// Whether to show the address.
    pub show_address: bool,
    /// Whether to show bytes.
    pub show_bytes: bool,
}

impl Default for DataDisplaySettings {
    fn default() -> Self {
        Self {
            radix: 16,
            show_address: true,
            show_bytes: true,
        }
    }
}

/// An adapter for reading instruction data from a prototype description.
///
/// Ported from Ghidra's `ghidra.trace.util.InstructionAdapterFromPrototype`.
/// Used when disassembling to provide instruction bytes and mnemonic from
/// a prototype instruction, rather than reading from memory directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionAdapterFromPrototype {
    /// The address of the instruction.
    pub address: u64,
    /// The mnemonic (e.g., "MOV", "ADD", "JMP").
    pub mnemonic: String,
    /// The raw instruction bytes.
    pub bytes: Vec<u8>,
    /// The length override, if any.
    pub length_override: Option<u32>,
    /// Whether this instruction has fall-through.
    pub has_fall_through: bool,
}

impl InstructionAdapterFromPrototype {
    /// Create a new instruction adapter from a prototype.
    pub fn new(
        address: u64,
        mnemonic: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Self {
        let len = bytes.len() as u32;
        Self {
            address,
            mnemonic: mnemonic.into(),
            bytes,
            length_override: None,
            has_fall_through: true,
        }
    }

    /// Get the instruction length in bytes.
    pub fn length(&self) -> u32 {
        self.length_override.unwrap_or(self.bytes.len() as u32)
    }

    /// Set a length override.
    pub fn with_length_override(mut self, length: u32) -> Self {
        self.length_override = Some(length);
        self
    }

    /// Set whether this instruction has fall-through.
    pub fn with_fall_through(mut self, has_fall_through: bool) -> Self {
        self.has_fall_through = has_fall_through;
        self
    }

    /// Get the end address of this instruction (exclusive).
    pub fn end_address(&self) -> u64 {
        self.address + self.length() as u64
    }
}

/// Utility functions for byte array manipulation.
pub mod byte_utils {
    /// XOR two byte slices.
    pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
        a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
    }

    /// Check if all bytes in a slice are zero.
    pub fn is_all_zeros(data: &[u8]) -> bool {
        data.iter().all(|&b| b == 0)
    }

    /// Convert bytes to a hex string.
    pub fn to_hex(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Parse a hex string to bytes.
    pub fn from_hex(s: &str) -> Option<Vec<u8>> {
        if s.len() % 2 != 0 {
            return None;
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
            .collect()
    }

    /// Fill a byte slice with a value.
    pub fn fill(data: &mut [u8], value: u8) {
        data.fill(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::byte_utils;

    #[test]
    fn test_memory_adapter_creation() {
        let adapter = MemoryAdapter::new("trace1", 5, "ram");
        assert_eq!(adapter.trace_id(), "trace1");
        assert_eq!(adapter.snap(), 5);
        assert_eq!(adapter.space_name(), "ram");
    }

    #[test]
    fn test_byte_state() {
        assert_ne!(MemoryByteState::Known, MemoryByteState::Unknown);
        assert_ne!(MemoryByteState::Unknown, MemoryByteState::Error);
    }

    #[test]
    fn test_byte_utils_xor() {
        let a = vec![0xFF, 0x00, 0xAA];
        let b = vec![0xFF, 0xFF, 0x55];
        assert_eq!(byte_utils::xor(&a, &b), vec![0x00, 0xFF, 0xFF]);
    }

    #[test]
    fn test_byte_utils_all_zeros() {
        assert!(byte_utils::is_all_zeros(&[0, 0, 0]));
        assert!(!byte_utils::is_all_zeros(&[0, 1, 0]));
    }

    #[test]
    fn test_byte_utils_hex_roundtrip() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let hex = byte_utils::to_hex(&data);
        assert_eq!(hex, "deadbeef");
        let parsed = byte_utils::from_hex(&hex).unwrap();
        assert_eq!(parsed, data);
    }

    #[test]
    fn test_byte_utils_hex_invalid() {
        assert!(byte_utils::from_hex("xyz").is_none());
        assert!(byte_utils::from_hex("abc").is_none()); // odd length
    }

    #[test]
    fn test_data_display_settings_default() {
        let settings = DataDisplaySettings::default();
        assert_eq!(settings.radix, 16);
        assert!(settings.show_address);
        assert!(settings.show_bytes);
    }

    #[test]
    fn test_memory_read_result() {
        let result = MemoryReadResult {
            address: 0x1000,
            data: vec![0x90, 0xCC],
            states: vec![MemoryByteState::Known, MemoryByteState::Known],
        };
        assert_eq!(result.data.len(), 2);
        assert_eq!(result.states.len(), 2);
    }

    #[test]
    fn test_data_adapter_hierarchy() {
        let mem = MemoryAdapter::new("t", 0, "ram");
        let minimal = DataAdapterMinimal::new(mem);
        let typed = DataAdapterFromDataType::new(minimal, "uint32", 4);
        assert_eq!(typed.type_name, "uint32");
        assert_eq!(typed.type_size, 4);
    }

    #[test]
    fn test_instruction_adapter_basic() {
        let adapter = InstructionAdapterFromPrototype::new(0x1000, "NOP", vec![0x90]);
        assert_eq!(adapter.address, 0x1000);
        assert_eq!(adapter.mnemonic, "NOP");
        assert_eq!(adapter.length(), 1);
        assert_eq!(adapter.end_address(), 0x1001);
        assert!(adapter.has_fall_through);
    }

    #[test]
    fn test_instruction_adapter_multi_byte() {
        let adapter = InstructionAdapterFromPrototype::new(
            0x2000, "MOV EAX, 0x42", vec![0xB8, 0x42, 0x00, 0x00, 0x00],
        );
        assert_eq!(adapter.length(), 5);
        assert_eq!(adapter.end_address(), 0x2005);
    }

    #[test]
    fn test_instruction_adapter_length_override() {
        let adapter = InstructionAdapterFromPrototype::new(0, "TEST", vec![0x01])
            .with_length_override(4);
        assert_eq!(adapter.length(), 4);
        assert_eq!(adapter.end_address(), 4);
    }

    #[test]
    fn test_instruction_adapter_no_fall_through() {
        let adapter = InstructionAdapterFromPrototype::new(0, "JMP", vec![0xE9, 0x00, 0x00, 0x00, 0x00])
            .with_fall_through(false);
        assert!(!adapter.has_fall_through);
    }
}
