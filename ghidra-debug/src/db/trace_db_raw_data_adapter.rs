//! Raw data adapter for trace database listings.
//!
//! Ported from Ghidra's `DBTraceDataAdapter` and `DBTraceDefinedDataAdapter`
//! in `ghidra.trace.database.listing`. Provides adapters for accessing
//! data elements (bytes, words, etc.) from the trace listing at a specific
//! snapshot.

use serde::{Deserialize, Serialize};


/// A raw data element in the trace listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawDataAdapter {
    /// The address offset of this data element.
    pub address: u64,
    /// The address space.
    pub space: String,
    /// The snap at which this data was observed.
    pub snap: i64,
    /// The data type name (e.g., "byte", "word", "dword", "qword").
    pub data_type: String,
    /// The size in bytes.
    pub size: usize,
    /// The raw bytes.
    pub bytes: Vec<u8>,
    /// Whether this is an undefined data element.
    pub is_undefined: bool,
}

impl RawDataAdapter {
    /// Create a new raw data adapter.
    pub fn new(
        address: u64,
        space: impl Into<String>,
        snap: i64,
        data_type: impl Into<String>,
        size: usize,
    ) -> Self {
        Self {
            address,
            space: space.into(),
            snap,
            data_type: data_type.into(),
            size,
            bytes: Vec::new(),
            is_undefined: false,
        }
    }

    /// Create an undefined data adapter.
    pub fn undefined(address: u64, space: impl Into<String>, snap: i64) -> Self {
        Self {
            address,
            space: space.into(),
            snap,
            data_type: "undefined".to_string(),
            size: 1,
            bytes: Vec::new(),
            is_undefined: true,
        }
    }

    /// Set the raw bytes.
    pub fn with_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.bytes = bytes;
        self
    }

    /// Get the minimum address (same as address for non-composite types).
    pub fn min_address(&self) -> u64 {
        self.address
    }

    /// Get the maximum address.
    pub fn max_address(&self) -> u64 {
        self.address + self.size as u64 - 1
    }

    /// Get the length in bytes.
    pub fn length(&self) -> usize {
        self.size
    }

    /// Get the byte value at the given offset within this data element.
    pub fn byte_at(&self, offset: usize) -> Option<u8> {
        self.bytes.get(offset).copied()
    }

    /// Get the value as a u8.
    pub fn as_u8(&self) -> Option<u8> {
        if self.bytes.len() >= 1 {
            Some(self.bytes[0])
        } else {
            None
        }
    }

    /// Get the value as a u16 (little-endian).
    pub fn as_u16(&self) -> Option<u16> {
        if self.bytes.len() >= 2 {
            Some(u16::from_le_bytes([self.bytes[0], self.bytes[1]]))
        } else {
            None
        }
    }

    /// Get the value as a u32 (little-endian).
    pub fn as_u32(&self) -> Option<u32> {
        if self.bytes.len() >= 4 {
            Some(u32::from_le_bytes([
                self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3],
            ]))
        } else {
            None
        }
    }

    /// Get the value as a u64 (little-endian).
    pub fn as_u64(&self) -> Option<u64> {
        if self.bytes.len() >= 8 {
            Some(u64::from_le_bytes([
                self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3],
                self.bytes[4], self.bytes[5], self.bytes[6], self.bytes[7],
            ]))
        } else {
            None
        }
    }
}

/// A defined data adapter with additional metadata.
///
/// Ported from Ghidra's `DBTraceDefinedDataAdapter`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawDefinedDataAdapter {
    /// The base data adapter.
    pub base: RawDataAdapter,
    /// Whether this has a user-defined name/label.
    pub has_label: bool,
    /// The label text.
    pub label: String,
    /// Flow override (NONE, CALL_RETURN, CALL_OTHER, JUMP_RETURN).
    pub flow_override: FlowOverride,
    /// Comment at this address.
    pub comment: Option<String>,
    /// Repeatable comment.
    pub repeatable_comment: Option<String>,
}

/// Flow override types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowOverride {
    /// No override.
    None,
    /// Override as call-return.
    CallReturn,
    /// Override as call-other.
    CallOther,
    /// Override as jump-return.
    JumpReturn,
}

impl Default for FlowOverride {
    fn default() -> Self {
        Self::None
    }
}

impl RawDefinedDataAdapter {
    /// Create a new defined data adapter.
    pub fn new(base: RawDataAdapter) -> Self {
        Self {
            base,
            has_label: false,
            label: String::new(),
            flow_override: FlowOverride::None,
            comment: None,
            repeatable_comment: None,
        }
    }

    /// Set the label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.has_label = true;
        self.label = label.into();
        self
    }

    /// Set the comment.
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Set the flow override.
    pub fn with_flow_override(mut self, flow: FlowOverride) -> Self {
        self.flow_override = flow;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_adapter_new() {
        let data = RawDataAdapter::new(0x1000, "ram", 0, "byte", 1)
            .with_bytes(vec![0x42]);
        assert_eq!(data.as_u8(), Some(0x42));
        assert_eq!(data.min_address(), 0x1000);
        assert_eq!(data.max_address(), 0x1000);
    }

    #[test]
    fn test_raw_adapter_u16() {
        let data = RawDataAdapter::new(0x100, "ram", 0, "word", 2)
            .with_bytes(vec![0x34, 0x12]);
        assert_eq!(data.as_u16(), Some(0x1234));
    }

    #[test]
    fn test_raw_adapter_u32() {
        let data = RawDataAdapter::new(0x100, "ram", 0, "dword", 4)
            .with_bytes(vec![0x78, 0x56, 0x34, 0x12]);
        assert_eq!(data.as_u32(), Some(0x12345678));
    }

    #[test]
    fn test_raw_adapter_u64() {
        let data = RawDataAdapter::new(0x100, "ram", 0, "qword", 8)
            .with_bytes(vec![0, 0, 0, 0, 0x78, 0x56, 0x34, 0x12]);
        assert_eq!(data.as_u64(), Some(0x1234567800000000));
    }

    #[test]
    fn test_raw_adapter_undefined() {
        let data = RawDataAdapter::undefined(0x100, "ram", 0);
        assert!(data.is_undefined);
        assert_eq!(data.data_type, "undefined");
    }

    #[test]
    fn test_raw_adapter_empty_bytes() {
        let data = RawDataAdapter::new(0, "ram", 0, "byte", 0);
        assert!(data.as_u8().is_none());
    }

    #[test]
    fn test_defined_adapter_new() {
        let base = RawDataAdapter::new(0x1000, "ram", 0, "dword", 4)
            .with_bytes(vec![1, 2, 3, 4]);
        let defined = RawDefinedDataAdapter::new(base).with_label("counter");
        assert!(defined.has_label);
        assert_eq!(defined.label, "counter");
        assert_eq!(defined.flow_override, FlowOverride::None);
    }

    #[test]
    fn test_defined_adapter_comment() {
        let base = RawDataAdapter::new(0x100, "ram", 0, "byte", 1);
        let defined = RawDefinedDataAdapter::new(base).with_comment("a comment");
        assert_eq!(defined.comment, Some("a comment".to_string()));
    }

    #[test]
    fn test_flow_override_default() {
        assert_eq!(FlowOverride::default(), FlowOverride::None);
    }

    #[test]
    fn test_raw_adapter_byte_at() {
        let data = RawDataAdapter::new(0, "ram", 0, "bytes", 3)
            .with_bytes(vec![10, 20, 30]);
        assert_eq!(data.byte_at(0), Some(10));
        assert_eq!(data.byte_at(1), Some(20));
        assert_eq!(data.byte_at(2), Some(30));
        assert_eq!(data.byte_at(3), None);
    }
}
