//! LF_VTSHAPE -- concrete VT Shape type record.
//!
//! Ports Ghidra's `VtShapeMsType` (PDB_ID = 0x000A) Java class.
//!
//! Represents the shape of a virtual function table (vftable) in the PDB type
//! stream. The shape encodes the kind of each vftable entry (near, far, thin,
//! outer, etc.) using a list of descriptors packed as nibbles.
//!
//! # Binary Layout (LF_VTSHAPE / 0x000A)
//!
//! ```text
//! +0  u16   count           Number of vftable entries
//! +2  nib[] descriptors     Packed nibble descriptors (2 per byte, upper first)
//!     ...  padding          Align to 4-byte boundary
//! ```

use std::fmt;

use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::RecordNumber;

// =============================================================================
// VtShapeDescriptor -- kind of a single vftable slot
// =============================================================================

/// Descriptor for a single vftable entry shape.
///
/// Corresponds to the Java `VtShapeDescriptorMsProperty` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum VtShapeDescriptor {
    /// Near pointer (16-bit).
    Near = 0,
    /// Far pointer (16:16).
    Far = 1,
    /// Thin pointer (no displacement).
    Thin = 2,
    /// Outer pointer (with displacement).
    Outer = 3,
    /// Meta pointer (managed code).
    Meta = 4,
    /// Near32 pointer.
    Near32 = 5,
    /// Far32 pointer (16:32).
    Far32 = 6,
    /// Unused / unknown descriptor value.
    Unused = 7,
}

impl VtShapeDescriptor {
    /// Label string used in emit output.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Near => "near",
            Self::Far => "far",
            Self::Thin => "thin",
            Self::Outer => "outer",
            Self::Meta => "meta",
            Self::Near32 => "near32",
            Self::Far32 => "far32",
            Self::Unused => "unused",
        }
    }

    /// Parse from a 4-bit nibble value.
    pub fn from_value(val: u8) -> Self {
        match val {
            0 => Self::Near,
            1 => Self::Far,
            2 => Self::Thin,
            3 => Self::Outer,
            4 => Self::Meta,
            5 => Self::Near32,
            6 => Self::Far32,
            _ => Self::Unused,
        }
    }
}

impl fmt::Display for VtShapeDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// =============================================================================
// LfVtshape -- the concrete VT shape type record
// =============================================================================

/// Concrete PDB VT Shape type record (`LF_VTSHAPE`).
///
/// This is the Rust equivalent of Ghidra's `VtShapeMsType`. It stores a list
/// of descriptors that describe the pointer properties of each vftable entry.
#[derive(Debug, Clone)]
pub struct LfVtshape {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// Number of vftable entries.
    count: u16,
    /// Descriptors for each vftable entry.
    descriptors: Vec<VtShapeDescriptor>,
}

impl LfVtshape {
    /// Create a new VT shape type record.
    pub fn new(descriptors: Vec<VtShapeDescriptor>) -> Self {
        let count = descriptors.len() as u16;
        Self {
            record_number: RecordNumber::NO_TYPE,
            count,
            descriptors,
        }
    }

    /// Create from raw parsed field values (packed nibble bytes).
    ///
    /// `count` is the number of descriptors, `packed_bytes` contains the
    /// nibble-packed descriptor data (upper nibble first, then lower nibble).
    pub fn from_packed(count: u16, packed_bytes: &[u8]) -> Self {
        let mut descriptors = Vec::with_capacity(count as usize);
        let count_usize = count as usize;

        for i in 0..count_usize / 2 {
            if let Some(&byte) = packed_bytes.get(i) {
                descriptors.push(VtShapeDescriptor::from_value(byte >> 4));
                descriptors.push(VtShapeDescriptor::from_value(byte & 0x0F));
            }
        }
        if count_usize % 2 == 1 {
            if let Some(&byte) = packed_bytes.get(count_usize / 2) {
                descriptors.push(VtShapeDescriptor::from_value(byte >> 4));
            }
        }

        Self {
            record_number: RecordNumber::NO_TYPE,
            count,
            descriptors,
        }
    }

    /// Get the number of vftable entries.
    pub fn count(&self) -> u16 {
        self.count
    }

    /// Get the slice of descriptors.
    pub fn descriptors(&self) -> &[VtShapeDescriptor] {
        &self.descriptors
    }

    /// Whether the shape contains a specific descriptor kind.
    pub fn has_descriptor(&self, descriptor: VtShapeDescriptor) -> bool {
        self.descriptors.contains(&descriptor)
    }
}

impl AbstractMsType for LfVtshape {
    fn pdb_id(&self) -> u32 {
        0x000A // LF_VTSHAPE
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, _bind: Bind) -> String {
        // Mirrors Java:
        //   DelimiterState ds = new DelimiterState("", ",");
        //   builder.append("vtshape: {");
        //   for (descriptor : descriptorList) { builder.append(ds.out(true, descriptor)); }
        //   builder.append("}");
        let mut result = String::new();
        result.push_str("vtshape: {");
        for (i, desc) in self.descriptors.iter().enumerate() {
            if i > 0 {
                result.push(',');
            }
            result.push_str(desc.label());
        }
        result.push('}');
        result
    }
}

impl fmt::Display for LfVtshape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vtshape_descriptor_from_value() {
        assert_eq!(VtShapeDescriptor::from_value(0), VtShapeDescriptor::Near);
        assert_eq!(VtShapeDescriptor::from_value(5), VtShapeDescriptor::Near32);
        assert_eq!(VtShapeDescriptor::from_value(7), VtShapeDescriptor::Unused);
        assert_eq!(VtShapeDescriptor::from_value(8), VtShapeDescriptor::Unused);
    }

    #[test]
    fn test_vtshape_descriptor_label() {
        assert_eq!(VtShapeDescriptor::Near.label(), "near");
        assert_eq!(VtShapeDescriptor::Far.label(), "far");
        assert_eq!(VtShapeDescriptor::Thin.label(), "thin");
        assert_eq!(VtShapeDescriptor::Outer.label(), "outer");
        assert_eq!(VtShapeDescriptor::Meta.label(), "meta");
        assert_eq!(VtShapeDescriptor::Near32.label(), "near32");
        assert_eq!(VtShapeDescriptor::Far32.label(), "far32");
        assert_eq!(VtShapeDescriptor::Unused.label(), "unused");
    }

    #[test]
    fn test_vtshape_descriptor_display() {
        assert_eq!(format!("{}", VtShapeDescriptor::Near32), "near32");
        assert_eq!(format!("{}", VtShapeDescriptor::Thin), "thin");
    }

    #[test]
    fn test_vtshape_new() {
        let vs = LfVtshape::new(vec![
            VtShapeDescriptor::Near32,
            VtShapeDescriptor::Near32,
            VtShapeDescriptor::Near32,
        ]);
        assert_eq!(vs.pdb_id(), 0x000A);
        assert_eq!(vs.count(), 3);
        assert_eq!(vs.descriptors().len(), 3);
    }

    #[test]
    fn test_vtshape_from_packed_even() {
        // 4 descriptors: 2 bytes. Byte 0: upper=5(near32), lower=5(near32).
        //                Byte 1: upper=5(near32), lower=5(near32).
        let vs = LfVtshape::from_packed(4, &[0x55, 0x55]);
        assert_eq!(vs.count(), 4);
        assert!(vs.descriptors().iter().all(|d| *d == VtShapeDescriptor::Near32));
    }

    #[test]
    fn test_vtshape_from_packed_odd() {
        // 3 descriptors: Byte 0 upper=5(near32), lower=5(near32).
        //                Byte 1 upper=1(far).
        let vs = LfVtshape::from_packed(3, &[0x55, 0x10]);
        assert_eq!(vs.count(), 3);
        assert_eq!(vs.descriptors()[0], VtShapeDescriptor::Near32);
        assert_eq!(vs.descriptors()[1], VtShapeDescriptor::Near32);
        assert_eq!(vs.descriptors()[2], VtShapeDescriptor::Far);
    }

    #[test]
    fn test_vtshape_from_packed_empty() {
        let vs = LfVtshape::from_packed(0, &[]);
        assert_eq!(vs.count(), 0);
        assert!(vs.descriptors().is_empty());
    }

    #[test]
    fn test_vtshape_has_descriptor() {
        let vs = LfVtshape::new(vec![
            VtShapeDescriptor::Near32,
            VtShapeDescriptor::Far,
        ]);
        assert!(vs.has_descriptor(VtShapeDescriptor::Near32));
        assert!(vs.has_descriptor(VtShapeDescriptor::Far));
        assert!(!vs.has_descriptor(VtShapeDescriptor::Thin));
    }

    #[test]
    fn test_vtshape_emit() {
        let vs = LfVtshape::new(vec![
            VtShapeDescriptor::Near32,
            VtShapeDescriptor::Near32,
        ]);
        let emitted = vs.emit(Bind::NONE);
        assert_eq!(emitted, "vtshape: {near32,near32}");
    }

    #[test]
    fn test_vtshape_emit_empty() {
        let vs = LfVtshape::new(vec![]);
        let emitted = vs.emit(Bind::NONE);
        assert_eq!(emitted, "vtshape: {}");
    }

    #[test]
    fn test_vtshape_emit_mixed() {
        let vs = LfVtshape::new(vec![
            VtShapeDescriptor::Near,
            VtShapeDescriptor::Far,
            VtShapeDescriptor::Thin,
        ]);
        let emitted = vs.emit(Bind::NONE);
        assert_eq!(emitted, "vtshape: {near,far,thin}");
    }

    #[test]
    fn test_vtshape_record_number() {
        let mut vs = LfVtshape::new(vec![VtShapeDescriptor::Near32]);
        assert!(vs.record_number().is_no_type());
        vs.set_record_number(RecordNumber::type_record(0x2000));
        assert_eq!(vs.record_number().index(), 0x2000);
    }

    #[test]
    fn test_vtshape_display() {
        let vs = LfVtshape::new(vec![VtShapeDescriptor::Near32]);
        let display = format!("{}", vs);
        assert!(display.contains("vtshape"));
        assert!(display.contains("near32"));
    }
}
