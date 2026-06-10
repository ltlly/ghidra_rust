//! S_ANNOTATION -- Annotation symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AnnotationMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::address_ms_symbol::AddressMsSymbol;

/// An annotation symbol (`S_ANNOTATION`).
///
/// This symbol carries user-defined annotations (source-level comments or
/// markers) at a specific segment:offset address. Each annotation contains
/// one or more length-prefixed UTF-8 strings.
///
/// # PDB Binary Layout
///
/// ```text
/// offset       : u32
/// segment      : u16
/// strings[]    : (u16 length, u8 data[length])*  -- zero or more
/// ```
///
/// Each string in the `strings` array is preceded by a 16-bit little-endian
/// length field giving the number of bytes in the string (not including the
/// length field itself). Parsing stops when the length is zero or the
/// remaining data is exhausted.
///
/// This corresponds to `S_ANNOTATION` (0x1019) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SAnnotation {
    /// Offset of the annotation within the segment.
    pub offset: u64,

    /// The PE section/segment containing this annotation.
    pub segment: u16,

    /// The annotation strings (one or more length-prefixed UTF-8 strings).
    pub strings: Vec<String>,
}

impl SAnnotation {
    /// Create a new annotation symbol.
    pub fn new(offset: u64, segment: u16, strings: Vec<String>) -> Self {
        Self {
            offset,
            segment,
            strings,
        }
    }

    /// Parse an S_ANNOTATION symbol from a byte slice.
    ///
    /// Expects the layout: `offset(u32) + segment(u16) + strings[(u16 len, u8 data[len])*]`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 6 {
            return None;
        }
        let offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64;
        let segment = u16::from_le_bytes([data[4], data[5]]);

        let mut strings = Vec::new();
        let mut pos = 6;

        while pos + 2 <= data.len() {
            let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            if len == 0 || pos + len > data.len() {
                break;
            }
            let s = String::from_utf8_lossy(&data[pos..pos + len]).to_string();
            strings.push(s);
            pos += len;
        }

        Some(Self {
            offset,
            segment,
            strings,
        })
    }
}

impl AbstractMsSymbol for SAnnotation {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_ANNOTATION
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_ANNOTATION"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Annotation: [{:04X}:{:08X}], Strings: [",
            self.segment, self.offset,
        )?;
        for (i, s) in self.strings.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "\"{}\"", s)?;
        }
        write!(f, "]")
    }
}

impl AddressMsSymbol for SAnnotation {
    fn offset(&self) -> u64 {
        self.offset
    }

    fn segment(&self) -> u16 {
        self.segment
    }
}

impl fmt::Display for SAnnotation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_annotation_bytes(
        offset: u32,
        segment: u16,
        strings: &[&[u8]],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&offset.to_le_bytes());
        data.extend_from_slice(&segment.to_le_bytes());
        for s in strings {
            data.extend_from_slice(&(s.len() as u16).to_le_bytes());
            data.extend_from_slice(s);
        }
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_annotation_bytes(0x1000, 1, &[b"hello", b"world"]);
        let sym = SAnnotation::parse(&data).unwrap();
        assert_eq!(sym.offset, 0x1000);
        assert_eq!(sym.segment, 1);
        assert_eq!(sym.strings.len(), 2);
        assert_eq!(sym.strings[0], "hello");
        assert_eq!(sym.strings[1], "world");
    }

    #[test]
    fn test_parse_single_string() {
        let data = make_annotation_bytes(0x2000, 2, &[b"note"]);
        let sym = SAnnotation::parse(&data).unwrap();
        assert_eq!(sym.strings, vec!["note"]);
    }

    #[test]
    fn test_parse_no_strings() {
        let data = make_annotation_bytes(0x3000, 1, &[]);
        let sym = SAnnotation::parse(&data).unwrap();
        assert!(sym.strings.is_empty());
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01]; // too short
        assert!(SAnnotation::parse(&data).is_none());
    }

    #[test]
    fn test_trait_impls() {
        let sym = SAnnotation::new(
            0x5000,
            3,
            vec!["annotation1".to_string(), "annotation2".to_string()],
        );
        assert_eq!(sym.pdb_id(), 0x1019);
        assert_eq!(sym.symbol_type_name(), "S_ANNOTATION");
        assert_eq!(sym.offset(), 0x5000);
        assert_eq!(sym.segment(), 3);
    }

    #[test]
    fn test_display() {
        let sym = SAnnotation::new(
            0x1000,
            1,
            vec!["test".to_string()],
        );
        let s = format!("{}", sym);
        assert!(s.contains("Annotation"));
        assert!(s.contains("1000"));
        assert!(s.contains("test"));
    }

    #[test]
    fn test_address_trait() {
        let sym = SAnnotation::new(0x4000, 2, vec![]);
        assert_eq!(sym.flat_address(), (2u64 << 32) | 0x4000);
    }

    #[test]
    fn test_clone_eq() {
        let a = SAnnotation::new(0x1000, 1, vec!["x".to_string()]);
        let b = a.clone();
        assert_eq!(a, b);
    }
}
