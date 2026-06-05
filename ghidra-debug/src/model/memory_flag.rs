//! Memory flag types for trace memory state.
//!
//! Ported from Ghidra's `TraceMemoryFlag`. These flags indicate the
//! state and permissions of memory regions in a trace.

use serde::{Deserialize, Serialize};

/// Flags for memory regions in a trace.
///
/// Ported from Ghidra's `TraceMemoryFlag`. These flags describe the
/// accessibility and state of a memory region in a debug trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TraceMemoryFlag {
    /// Memory is readable.
    Read,
    /// Memory is writable.
    Write,
    /// Memory is executable.
    Execute,
    /// Memory has been modified in the trace.
    Modified,
    /// Memory state is known (has been read from target).
    Known,
    /// Memory state is unknown (has not been read).
    Unknown,
    /// Memory is volatile (may change between reads).
    Volatile,
    /// Memory is in a register space.
    Register,
}

impl TraceMemoryFlag {
    /// Whether this flag indicates readability.
    pub fn is_readable(&self) -> bool {
        matches!(self, Self::Read | Self::Write | Self::Execute)
    }

    /// Whether this flag indicates writability.
    pub fn is_writable(&self) -> bool {
        matches!(self, Self::Write)
    }

    /// Whether this flag indicates executability.
    pub fn is_executable(&self) -> bool {
        matches!(self, Self::Execute)
    }

    /// Whether this flag indicates known state.
    pub fn is_known(&self) -> bool {
        matches!(self, Self::Known | Self::Modified)
    }

    /// Whether this flag indicates unknown state.
    pub fn is_unknown(&self) -> bool {
        *self == Self::Unknown
    }

    /// Get all flags as a static slice.
    pub fn all() -> &'static [TraceMemoryFlag] {
        &[
            Self::Read,
            Self::Write,
            Self::Execute,
            Self::Modified,
            Self::Known,
            Self::Unknown,
            Self::Volatile,
            Self::Register,
        ]
    }
}

/// A set of memory flags for a memory region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryFlagSet {
    /// The flags.
    flags: Vec<TraceMemoryFlag>,
}

impl MemoryFlagSet {
    /// Create a new empty flag set.
    pub fn new() -> Self {
        Self { flags: Vec::new() }
    }

    /// Create a flag set from a vector of flags.
    pub fn from_flags(flags: Vec<TraceMemoryFlag>) -> Self {
        Self { flags }
    }

    /// Add a flag.
    pub fn add(&mut self, flag: TraceMemoryFlag) {
        if !self.flags.contains(&flag) {
            self.flags.push(flag);
        }
    }

    /// Remove a flag.
    pub fn remove(&mut self, flag: TraceMemoryFlag) {
        self.flags.retain(|f| *f != flag);
    }

    /// Check if a flag is present.
    pub fn has(&self, flag: TraceMemoryFlag) -> bool {
        self.flags.contains(&flag)
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.flags.is_empty()
    }

    /// Get all flags in the set.
    pub fn flags(&self) -> &[TraceMemoryFlag] {
        &self.flags
    }

    /// Whether this set includes read access.
    pub fn is_readable(&self) -> bool {
        self.has(TraceMemoryFlag::Read) || self.has(TraceMemoryFlag::Write)
    }

    /// Whether this set includes write access.
    pub fn is_writable(&self) -> bool {
        self.has(TraceMemoryFlag::Write)
    }

    /// Whether this set includes execute access.
    pub fn is_executable(&self) -> bool {
        self.has(TraceMemoryFlag::Execute)
    }

    /// Whether this set includes known state.
    pub fn is_known(&self) -> bool {
        self.has(TraceMemoryFlag::Known) || self.has(TraceMemoryFlag::Modified)
    }
}

impl Default for MemoryFlagSet {
    fn default() -> Self {
        Self::new()
    }
}

/// A register value stored in the trace.
///
/// Ported from Ghidra's `RegisterValue` used in the trace model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceRegisterValue {
    /// The register name.
    pub register_name: String,
    /// The register address in the register space.
    pub register_address: u64,
    /// The size of the register in bytes.
    pub size: usize,
    /// The value bytes (may be shorter than `size` if only some bytes are known).
    pub value: Vec<u8>,
    /// A mask indicating which bytes of the value are known.
    pub mask: Vec<u8>,
}

impl TraceRegisterValue {
    /// Create a new register value with all bytes known.
    pub fn new(
        register_name: impl Into<String>,
        register_address: u64,
        value: Vec<u8>,
    ) -> Self {
        let size = value.len();
        let mask = vec![0xff; size];
        Self {
            register_name: register_name.into(),
            register_address,
            size,
            value,
            mask,
        }
    }

    /// Create a register value with a mask.
    pub fn with_mask(
        register_name: impl Into<String>,
        register_address: u64,
        value: Vec<u8>,
        mask: Vec<u8>,
    ) -> Self {
        let size = value.len();
        Self {
            register_name: register_name.into(),
            register_address,
            size,
            value,
            mask,
        }
    }

    /// Whether all bytes of the value are known.
    pub fn is_fully_known(&self) -> bool {
        self.mask.iter().all(|&b| b == 0xff)
    }

    /// Whether no bytes of the value are known.
    pub fn is_fully_unknown(&self) -> bool {
        self.mask.iter().all(|&b| b == 0x00)
    }

    /// Get the value as a u64 (interpreting bytes in little-endian order).
    ///
    /// Returns `None` if the value is not fully known or is larger than 8 bytes.
    pub fn as_u64_le(&self) -> Option<u64> {
        if !self.is_fully_known() || self.value.len() > 8 {
            return None;
        }
        let mut bytes = [0u8; 8];
        bytes[..self.value.len()].copy_from_slice(&self.value);
        Some(u64::from_le_bytes(bytes))
    }

    /// Get the value as a u64 (interpreting bytes in big-endian order).
    ///
    /// Returns `None` if the value is not fully known or is larger than 8 bytes.
    pub fn as_u64_be(&self) -> Option<u64> {
        if !self.is_fully_known() || self.value.len() > 8 {
            return None;
        }
        let mut bytes = [0u8; 8];
        bytes[8 - self.value.len()..].copy_from_slice(&self.value);
        Some(u64::from_be_bytes(bytes))
    }
}

/// A register value converter for converting between register value formats.
///
/// Ported from Ghidra's `RegisterValueConverter`.
#[derive(Debug)]
pub struct RegisterValueConverter {
    /// The source register size.
    pub source_size: usize,
    /// The target register size.
    pub target_size: usize,
}

impl RegisterValueConverter {
    /// Create a new converter.
    pub fn new(source_size: usize, target_size: usize) -> Self {
        Self {
            source_size,
            target_size,
        }
    }

    /// Convert a register value to a different size.
    ///
    /// If the target is larger, pads with zeros. If smaller, truncates.
    pub fn convert(&self, value: &TraceRegisterValue) -> TraceRegisterValue {
        let mut new_value = vec![0u8; self.target_size];
        let mut new_mask = vec![0u8; self.target_size];

        let copy_len = value.value.len().min(self.target_size);
        new_value[..copy_len].copy_from_slice(&value.value[..copy_len]);
        new_mask[..copy_len].copy_from_slice(&value.mask[..copy_len]);

        TraceRegisterValue {
            register_name: value.register_name.clone(),
            register_address: value.register_address,
            size: self.target_size,
            value: new_value,
            mask: new_mask,
        }
    }
}

/// Exception for register value errors.
///
/// Ported from Ghidra's `RegisterValueException`.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RegisterValueError {
    /// The register value has an invalid size.
    #[error("Invalid register value size: expected {expected}, got {actual}")]
    InvalidSize {
        /// Expected size.
        expected: usize,
        /// Actual size.
        actual: usize,
    },

    /// The register value is unknown.
    #[error("Register value is unknown")]
    UnknownValue,

    /// The register value overlaps with another.
    #[error("Register value overlaps: {0}")]
    Overlap(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_flag_properties() {
        assert!(TraceMemoryFlag::Read.is_readable());
        assert!(TraceMemoryFlag::Write.is_readable());
        assert!(TraceMemoryFlag::Write.is_writable());
        assert!(TraceMemoryFlag::Execute.is_executable());
        assert!(TraceMemoryFlag::Known.is_known());
        assert!(TraceMemoryFlag::Modified.is_known());
        assert!(TraceMemoryFlag::Unknown.is_unknown());
        assert!(!TraceMemoryFlag::Read.is_writable());
        assert!(!TraceMemoryFlag::Read.is_executable());
    }

    #[test]
    fn test_memory_flag_set() {
        let mut set = MemoryFlagSet::new();
        assert!(set.is_empty());

        set.add(TraceMemoryFlag::Read);
        set.add(TraceMemoryFlag::Write);
        set.add(TraceMemoryFlag::Execute);

        assert!(set.is_readable());
        assert!(set.is_writable());
        assert!(set.is_executable());

        set.remove(TraceMemoryFlag::Write);
        assert!(!set.is_writable());
        assert!(set.is_readable()); // Read is still present
    }

    #[test]
    fn test_register_value_new() {
        let rv = TraceRegisterValue::new("RIP", 0x10, vec![0x00, 0x10, 0x40, 0x00]);
        assert_eq!(rv.register_name, "RIP");
        assert_eq!(rv.size, 4);
        assert!(rv.is_fully_known());
        assert!(!rv.is_fully_unknown());
    }

    #[test]
    fn test_register_value_with_mask() {
        let rv = TraceRegisterValue::with_mask(
            "RIP",
            0x10,
            vec![0x00, 0x10, 0x40, 0x00],
            vec![0xff, 0xff, 0x00, 0x00],
        );
        assert!(!rv.is_fully_known());
        assert!(!rv.is_fully_unknown());
    }

    #[test]
    fn test_register_value_as_u64() {
        let rv = TraceRegisterValue::new("RIP", 0x10, vec![0x00, 0x10, 0x40, 0x00]);
        assert_eq!(rv.as_u64_le(), Some(0x00401000));
        assert_eq!(rv.as_u64_be(), Some(0x00104000));
    }

    #[test]
    fn test_register_value_as_u64_unknown() {
        let rv = TraceRegisterValue::with_mask(
            "RIP",
            0x10,
            vec![0x00, 0x10, 0x40, 0x00],
            vec![0xff, 0xff, 0x00, 0x00],
        );
        assert!(rv.as_u64_le().is_none());
    }

    #[test]
    fn test_register_value_converter() {
        let converter = RegisterValueConverter::new(4, 8);
        let rv = TraceRegisterValue::new("RIP", 0x10, vec![0x00, 0x10, 0x40, 0x00]);
        let converted = converter.convert(&rv);
        assert_eq!(converted.size, 8);
        assert_eq!(converted.value, vec![0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_register_value_converter_truncate() {
        let converter = RegisterValueConverter::new(8, 4);
        let rv = TraceRegisterValue::new("RIP", 0x10, vec![0x00, 0x10, 0x40, 0x00, 0x01, 0x02, 0x03, 0x04]);
        let converted = converter.convert(&rv);
        assert_eq!(converted.size, 4);
        assert_eq!(converted.value, vec![0x00, 0x10, 0x40, 0x00]);
    }

    #[test]
    fn test_memory_flag_all() {
        let all = TraceMemoryFlag::all();
        assert_eq!(all.len(), 8);
    }

    #[test]
    fn test_register_value_error_display() {
        let err = RegisterValueError::InvalidSize {
            expected: 4,
            actual: 8,
        };
        assert!(err.to_string().contains("expected 4"));
        assert!(err.to_string().contains("got 8"));

        let err = RegisterValueError::UnknownValue;
        assert!(err.to_string().contains("unknown"));
    }
}
