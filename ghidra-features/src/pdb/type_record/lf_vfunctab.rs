//! LF_VFUNCTAB -- concrete Virtual Function Table Pointer type record.
//!
//! Ports Ghidra's `VirtualFunctionTablePointerMsType` (PDB_ID = 0x1409)
//! Java class.
//!
//! Represents a virtual function table (vftable) pointer within a composite
//! type (struct/class/union) in the PDB type stream. This is a leaf record
//! that appears inside an `LF_FIELDLIST`. It indicates that the composite
//! contains a vftable pointer at the specified location.
//!
//! # Binary Layout (LF_VFUNCTAB / 0x1409)
//!
//! ```text
//! +0  u16   padding           2 bytes of documented padding
//! +2  u32   vftableType       Type index of the vftable type
//! ```

use std::fmt;

use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::RecordNumber;

/// Concrete PDB virtual function table pointer type record (`LF_VFUNCTAB`).
///
/// This is the Rust equivalent of Ghidra's `VirtualFunctionTablePointerMsType`.
/// It stores the record number of the vftable type. The vftable type itself
/// is represented by `LF_VTSHAPE` records.
///
/// Note: Despite the name `LF_VFUNCTAB`, this record does not contain the
/// actual virtual function table. It represents a *pointer* to a vftable
/// that is embedded within the object layout. The actual vftable entries
/// are described by the referenced type record.
///
/// Corresponds to the Java `VirtualFunctionTablePointerMsType` class and
/// its parent `AbstractVirtualFunctionTablePointerMsType`.
#[derive(Debug, Clone)]
pub struct LfVfunctab {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// Record number of the vftable pointer type.
    pub vftable_type_record_number: RecordNumber,
}

impl LfVfunctab {
    /// Create a new vftable pointer type record.
    pub fn new(vftable_type_record_number: RecordNumber) -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            vftable_type_record_number,
        }
    }

    /// Create from a raw type index.
    pub fn from_parsed(vftable_type_index: u32) -> Self {
        Self::new(RecordNumber::type_record(vftable_type_index))
    }

    /// Get the record number of the vftable pointer type.
    ///
    /// Mirrors Java `AbstractVirtualFunctionTablePointerMsType.getPointerTypeRecordNumber()`.
    pub fn pointer_type_record_number(&self) -> RecordNumber {
        self.vftable_type_record_number
    }
}

impl AbstractMsType for LfVfunctab {
    fn name(&self) -> &str {
        ""
    }

    fn pdb_id(&self) -> u32 {
        0x1409 // LF_VFUNCTAB
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, _bind: Bind) -> String {
        // Mirrors Java:
        //   builder.append("VFTablePtr: ");
        //   builder.append(pdb.getTypeRecord(pointerTypeRecordNumber));
        let mut result = String::new();
        result.push_str("VFTablePtr: ");
        result.push_str(&self.vftable_type_record_number.to_string());
        result
    }
}

impl fmt::Display for LfVfunctab {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_vfunctab() -> LfVfunctab {
        LfVfunctab::new(RecordNumber::type_record(0x3001))
    }

    #[test]
    fn test_vfunctab_basic() {
        let vt = make_test_vfunctab();
        assert_eq!(vt.pdb_id(), 0x1409);
        assert_eq!(
            vt.vftable_type_record_number,
            RecordNumber::type_record(0x3001)
        );
    }

    #[test]
    fn test_vfunctab_from_parsed() {
        let vt = LfVfunctab::from_parsed(0x4001);
        assert_eq!(
            vt.vftable_type_record_number,
            RecordNumber::type_record(0x4001)
        );
    }

    #[test]
    fn test_vfunctab_emit() {
        let vt = make_test_vfunctab();
        let emitted = vt.emit(Bind::NONE);
        assert!(emitted.contains("VFTablePtr:"));
        assert!(emitted.contains("0x3001"));
    }

    #[test]
    fn test_vfunctab_emit_format() {
        let vt = LfVfunctab::from_parsed(0x4001);
        let emitted = vt.emit(Bind::NONE);
        assert!(emitted.starts_with("VFTablePtr: "));
        assert!(emitted.contains("0x4001"));
    }

    #[test]
    fn test_vfunctab_record_number() {
        let mut vt = make_test_vfunctab();
        assert!(vt.record_number().is_no_type());
        vt.set_record_number(RecordNumber::type_record(0x5000));
        assert_eq!(vt.record_number().index(), 0x5000);
    }

    #[test]
    fn test_vfunctab_display() {
        let vt = make_test_vfunctab();
        let display = format!("{}", vt);
        assert!(display.contains("VFTablePtr"));
        assert!(display.contains("0x3001"));
    }

    #[test]
    fn test_vfunctab_name_is_empty() {
        let vt = make_test_vfunctab();
        assert_eq!(vt.name(), "");
    }

    #[test]
    fn test_vfunctab_pointer_type_record_number() {
        let vt = LfVfunctab::new(RecordNumber::type_record(0x6000));
        assert_eq!(
            vt.pointer_type_record_number(),
            RecordNumber::type_record(0x6000)
        );
    }

    #[test]
    fn test_vfunctab_from_parsed_zero() {
        let vt = LfVfunctab::from_parsed(0);
        assert_eq!(
            vt.vftable_type_record_number,
            RecordNumber::type_record(0)
        );
    }
}
