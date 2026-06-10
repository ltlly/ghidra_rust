//! S_SKIP -- Skip symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.SkipMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;

/// A skip symbol (`S_SKIP`).
///
/// This symbol is used to skip over a range of symbol records. When a
/// debugger encounters an `S_SKIP` record, it should advance past the
/// specified number of bytes worth of symbol data without interpreting
/// them. This is used as a forward-reference patching mechanism when the
/// compiler needs to reserve space for a symbol record whose final size
/// is not yet known.
///
/// The `record_length` field stores the remaining length of the skip
/// region (the number of bytes from the end of this record to the end
/// of the skipped region). In Ghidra's Java implementation this is
/// computed as `reader.getLimit() - reader.getIndex()` -- the number
/// of unconsumed bytes in the record's payload.
///
/// This corresponds to `S_SKIP` (0x0007) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SSkip {
    /// The length of the record data following this symbol header.
    pub record_length: u32,
}

impl SSkip {
    /// Create a new skip symbol.
    pub fn new(record_length: u32) -> Self {
        Self { record_length }
    }

    /// Parse an S_SKIP symbol from a byte slice.
    ///
    /// The S_SKIP symbol's payload length is determined by the outer record
    /// framing. The `data` parameter represents the payload bytes after the
    /// symbol header. The length of `data` is stored as the `record_length`.
    ///
    /// This mirrors the Java implementation where `recordLength = reader.getLimit() - reader.getIndex()`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        Some(Self {
            record_length: data.len() as u32,
        })
    }

    /// Return the skip length in bytes.
    pub fn length(&self) -> u32 {
        self.record_length
    }

    /// Return whether this skip symbol covers zero bytes (no-op skip).
    pub fn is_empty(&self) -> bool {
        self.record_length == 0
    }
}

impl Default for SSkip {
    fn default() -> Self {
        Self::new(0)
    }
}

impl AbstractMsSymbol for SSkip {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_SKIP
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_SKIP"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Skip Record, Length = 0x{:X}", self.record_length)
    }
}

impl fmt::Display for SSkip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty() {
        let data = [];
        let sym = SSkip::parse(&data).unwrap();
        assert_eq!(sym.record_length, 0);
    }

    #[test]
    fn test_parse_with_data() {
        let data = [0x00; 64];
        let sym = SSkip::parse(&data).unwrap();
        assert_eq!(sym.record_length, 64);
    }

    #[test]
    fn test_new() {
        let sym = SSkip::new(128);
        assert_eq!(sym.record_length, 128);
    }

    #[test]
    fn test_trait_impls() {
        let sym = SSkip::new(32);
        assert_eq!(sym.pdb_id(), 0x0007);
        assert_eq!(sym.symbol_type_name(), "S_SKIP");
    }

    #[test]
    fn test_display() {
        let sym = SSkip::new(0x40);
        let s = format!("{}", sym);
        assert!(s.contains("Skip Record"));
        assert!(s.contains("0x40"));
    }

    #[test]
    fn test_display_zero_length() {
        let sym = SSkip::new(0);
        let s = format!("{}", sym);
        assert!(s.contains("0x0"));
    }

    #[test]
    fn test_clone_eq() {
        let a = SSkip::new(100);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_parse_preserves_length() {
        // Verify parse captures the data slice length
        let data = vec![0xAA; 256];
        let sym = SSkip::parse(&data).unwrap();
        assert_eq!(sym.record_length, 256);
    }

    #[test]
    fn test_length_accessor() {
        let sym = SSkip::new(42);
        assert_eq!(sym.length(), 42);
    }

    #[test]
    fn test_is_empty_true() {
        let sym = SSkip::new(0);
        assert!(sym.is_empty());
    }

    #[test]
    fn test_is_empty_false() {
        let sym = SSkip::new(10);
        assert!(!sym.is_empty());
    }

    #[test]
    fn test_default() {
        let sym = SSkip::default();
        assert_eq!(sym.record_length, 0);
        assert_eq!(sym, SSkip::new(0));
    }
}
