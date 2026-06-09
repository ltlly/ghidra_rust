//! AbstractMsType -- base trait for all PDB MS type records.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType`
//! and the `MsType` interface.

use std::fmt;

use super::bind::Bind;
use super::RecordNumber;

/// Base trait for all PDB MS (Microsoft) type records.
///
/// Every CodeView `LF_*` type record in a PDB implements this trait.
/// It provides the common interface for obtaining the type's numeric
/// kind identifier (`pdb_id`), its human-readable name, and its
/// record number within the TPI/IPI stream.
///
/// # Hierarchy Notes
///
/// In Ghidra's Java implementation, `AbstractMsType` is the abstract base
/// class for the full type hierarchy. Sub-variants end in:
///
/// - `16MsType` -- 16-bit type indices, ST-format strings.
/// - `StMsType` -- 32-bit type indices, ST-format strings.
/// - `MsType`   -- 32-bit type indices, NT-format strings.
///
/// This Rust port represents all variants through a single trait with
/// concrete struct implementations rather than an inheritance hierarchy.
pub trait AbstractMsType: fmt::Debug {
    /// The human-readable name of this type, or an empty string if unnamed.
    ///
    /// The default returns `""`. Types that carry a name (structs, classes,
    /// enums, etc.) override this.
    fn name(&self) -> &str {
        ""
    }

    /// A numeric identifier for this type record kind.
    ///
    /// Used primarily for debug/diagnostic output. Corresponds to the
    /// `getPdbId()` method in the Java implementation. Returns the `LF_*`
    /// constant (e.g., `0x0004` for `LF_CLASS`).
    fn pdb_id(&self) -> u32;

    /// The TPI/IPI record number for this type, if one has been assigned.
    fn record_number(&self) -> RecordNumber {
        RecordNumber::NO_TYPE
    }

    /// Set the TPI/IPI record number for this type.
    fn set_record_number(&mut self, _record_number: RecordNumber) {}

    /// Emit a textual representation of this type.
    ///
    /// The `bind` parameter controls parenthesization: types that need
    /// parentheses when nested inside a lower-precedence context will add
    /// them based on `bind`.
    ///
    /// The default implementation produces `IncompleteImpl(TypeName)`.
    fn emit(&self, bind: Bind) -> String {
        format!("IncompleteImpl({:?})", self)
    }

    /// Convenience: emit with `Bind::NONE`.
    fn to_type_string(&self) -> String {
        self.emit(Bind::NONE)
    }
}

/// A minimal concrete implementation of [`AbstractMsType`] for types
/// whose kind is known but whose fields have not been fully parsed.
///
/// This is used as a placeholder when a type record is encountered with
/// a recognized kind but the full parsing is deferred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownMsType {
    /// The raw type kind (LF_* value).
    pub kind: u32,
    /// The raw payload bytes.
    pub raw_data: Vec<u8>,
    /// The record number within the type stream, if known.
    pub record: RecordNumber,
}

impl UnknownMsType {
    /// Create a new unknown type from a leaf id and raw bytes.
    pub fn new(kind: u32, raw_data: Vec<u8>) -> Self {
        UnknownMsType {
            kind,
            raw_data,
            record: RecordNumber::NO_TYPE,
        }
    }

    /// Create a new unknown type with an associated record number.
    pub fn with_record_number(kind: u32, raw_data: Vec<u8>, record: RecordNumber) -> Self {
        UnknownMsType {
            kind,
            raw_data,
            record,
        }
    }
}

impl AbstractMsType for UnknownMsType {
    fn pdb_id(&self) -> u32 {
        self.kind
    }

    fn record_number(&self) -> RecordNumber {
        self.record
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record = record_number;
    }
}

impl fmt::Display for UnknownMsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UnknownMsType(kind=0x{:04X})", self.kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestType {
        id: u32,
        type_name: String,
    }

    impl AbstractMsType for TestType {
        fn pdb_id(&self) -> u32 {
            self.id
        }
        fn name(&self) -> &str {
            &self.type_name
        }
    }

    #[test]
    fn test_pdb_id() {
        let t = TestType {
            id: 0x0004,
            type_name: "MyClass".to_string(),
        };
        assert_eq!(t.pdb_id(), 0x0004);
    }

    #[test]
    fn test_name() {
        let t = TestType {
            id: 0x0004,
            type_name: "MyClass".to_string(),
        };
        assert_eq!(t.name(), "MyClass");
    }

    #[test]
    fn test_default_name() {
        let t = UnknownMsType::new(0xFFFF, vec![0x01, 0x02]);
        assert_eq!(t.name(), "");
    }

    #[test]
    fn test_unknown_ms_type() {
        let t = UnknownMsType::new(0x0015, vec![0xAA, 0xBB]);
        assert_eq!(t.pdb_id(), 0x0015);
        assert_eq!(t.name(), "");
        assert!(t.record_number().is_no_type());
        assert_eq!(format!("{}", t), "UnknownMsType(kind=0x0015)");
    }

    #[test]
    fn test_unknown_with_record() {
        let rn = RecordNumber::type_record(42);
        let t = UnknownMsType::with_record_number(0x0004, vec![0x01], rn);
        assert_eq!(t.record_number().index(), 42);
        assert!(!t.record_number().is_no_type());
    }

    #[test]
    fn test_set_record_number() {
        let mut t = UnknownMsType::new(0x0004, vec![]);
        assert!(t.record_number().is_no_type());
        t.set_record_number(RecordNumber::type_record(0x3000));
        assert_eq!(t.record_number().index(), 0x3000);
    }

    #[test]
    fn test_emit_default() {
        let t = UnknownMsType::new(0x0015, vec![0x01]);
        let emitted = t.emit(Bind::NONE);
        assert!(emitted.contains("IncompleteImpl"));
    }

    #[test]
    fn test_to_type_string() {
        let t = UnknownMsType::new(0x0015, vec![]);
        let s = t.to_type_string();
        assert!(s.contains("IncompleteImpl"));
    }
}
