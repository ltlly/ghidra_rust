//! Undefined data code unit type.
//!
//! Ported from Ghidra's `UndefinedDBTraceData`.

use crate::db::listing::code_unit::{AbstractCodeUnit, CodeUnitKind};
use crate::model::CodeUnitType;

/// An undefined data region in the trace listing.
///
/// Undefined regions represent areas of memory that have not been
/// explicitly defined as instructions or data.
#[derive(Debug, Clone)]
pub struct UndefinedDbTraceData {
    /// The base code unit properties.
    pub base: AbstractCodeUnit,
    /// Whether the bytes in this region are known (from memory state).
    pub bytes_known: bool,
    /// The raw bytes, if known.
    pub bytes: Option<Vec<u8>>,
}

impl UndefinedDbTraceData {
    /// Create a new undefined data region.
    pub fn new(offset: u64, length: u32, snap: i64) -> Self {
        Self {
            base: AbstractCodeUnit {
                offset,
                length,
                snap,
                thread_id: 0,
                kind: CodeUnitKind::Undefined,
                unit_type: CodeUnitType::Undefined,
                is_overlay: false,
                space_name: "ram".into(),
            },
            bytes_known: false,
            bytes: None,
        }
    }

    /// Create an undefined region with known bytes.
    pub fn with_bytes(offset: u64, snap: i64, bytes: Vec<u8>) -> Self {
        let length = bytes.len() as u32;
        Self {
            base: AbstractCodeUnit {
                offset,
                length,
                snap,
                thread_id: 0,
                kind: CodeUnitKind::Undefined,
                unit_type: CodeUnitType::Undefined,
                is_overlay: false,
                space_name: "ram".into(),
            },
            bytes_known: true,
            bytes: Some(bytes),
        }
    }

    /// Check if the bytes are known for this undefined region.
    pub fn are_bytes_known(&self) -> bool {
        self.bytes_known
    }

    /// Get the bytes if known.
    pub fn get_bytes(&self) -> Option<&[u8]> {
        self.bytes.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_undefined_basic() {
        let undef = UndefinedDbTraceData::new(0x3000, 16, 0);
        assert_eq!(undef.base.offset, 0x3000);
        assert_eq!(undef.base.length, 16);
        assert!(!undef.are_bytes_known());
        assert!(undef.get_bytes().is_none());
    }

    #[test]
    fn test_undefined_with_bytes() {
        let undef = UndefinedDbTraceData::with_bytes(0x4000, 0, vec![0xCC; 4]);
        assert!(undef.are_bytes_known());
        assert_eq!(undef.get_bytes(), Some([0xCC, 0xCC, 0xCC, 0xCC].as_slice()));
    }
}
