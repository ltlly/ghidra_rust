//! S_ANNOTATION -- Annotation symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AnnotationMsSymbol`
//! and `AnnotationReferenceMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::address_ms_symbol::AddressMsSymbol;
use super::name_ms_symbol::NameMsSymbol;

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
/// count        : u16   (number of strings)
/// strings[]    : (u16 length, u8 data[length])*  -- exactly `count` entries
/// align(4)     : padding to 4-byte boundary
/// ```
///
/// Each string in the `strings` array is preceded by a 16-bit little-endian
/// length field giving the number of bytes in the string (not including the
/// length field itself).
///
/// This corresponds to `S_ANNOTATION` (0x1019) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SAnnotation {
    /// Offset of the annotation within the segment.
    pub offset: u64,

    /// The PE section/segment containing this annotation.
    pub segment: u16,

    /// The number of annotation strings declared in the record.
    pub count: u16,

    /// The annotation strings (one or more length-prefixed UTF-8 strings).
    pub strings: Vec<String>,
}

impl SAnnotation {
    /// Create a new annotation symbol.
    pub fn new(offset: u64, segment: u16, strings: Vec<String>) -> Self {
        let count = strings.len() as u16;
        Self {
            offset,
            segment,
            count,
            strings,
        }
    }

    /// Create a new annotation symbol with an explicit count.
    ///
    /// Use this when the count is known from the binary record and may differ
    /// from the number of successfully parsed strings.
    pub fn new_with_count(
        offset: u64,
        segment: u16,
        count: u16,
        strings: Vec<String>,
    ) -> Self {
        Self {
            offset,
            segment,
            count,
            strings,
        }
    }

    /// Parse an S_ANNOTATION symbol from a byte slice.
    ///
    /// Expects the layout:
    /// `offset(u32) + segment(u16) + count(u16) + strings[(u16 len, u8 data[len])*] + align(4)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64;
        let segment = u16::from_le_bytes([data[4], data[5]]);
        let count = u16::from_le_bytes([data[6], data[7]]);

        let mut strings = Vec::new();
        let mut pos = 8;

        for _ in 0..count {
            if pos + 2 > data.len() {
                break;
            }
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
            count,
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
            "Annotation: [{:04X}:{:08X}]",
            self.segment, self.offset,
        )?;
        for (i, s) in self.strings.iter().enumerate() {
            write!(f, "\n{:5}: {}", i, s)?;
        }
        Ok(())
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

/// An annotation reference symbol (`S_ANNOTATIONREF`).
///
/// This symbol provides a cross-module reference to an annotation definition.
/// It follows the same V2 reference layout as `S_PROCREF` and `S_DATAREF`.
///
/// Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AnnotationReferenceMsSymbol`.
///
/// # PDB Binary Layout (V2 / MsSymbol format)
///
/// ```text
/// sum_name       : u32     (checksum of the name)
/// sym_offset     : u32     (actual offset in $$SYMBOL table)
/// module_index   : u16
/// name           : NT string (UTF-8)
/// ```
///
/// This corresponds to `S_ANNOTATIONREF` (0x1128) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SAnnotationRef {
    /// The name of the referenced annotation.
    pub name: String,

    /// Index of the module (object file) that defines this annotation.
    pub module_index: u16,

    /// Checksum of the name (sum/suc field from the PDB).
    pub sum_name: u32,

    /// Actual offset of the symbol in the $$SYMBOL table.
    pub offset_actual_symbol: u32,
}

impl SAnnotationRef {
    /// Create a new annotation reference symbol.
    pub fn new(name: String, module_index: u16) -> Self {
        Self {
            name,
            module_index,
            sum_name: 0,
            offset_actual_symbol: 0,
        }
    }

    /// Create a new annotation reference symbol with full reference internals.
    pub fn new_with_internals(
        name: String,
        module_index: u16,
        sum_name: u32,
        offset_actual_symbol: u32,
    ) -> Self {
        Self {
            name,
            module_index,
            sum_name,
            offset_actual_symbol,
        }
    }

    /// Parse an S_ANNOTATIONREF symbol from a byte slice (V2 format).
    ///
    /// Expects the layout:
    /// `sum_name(u32) + sym_offset(u32) + module_index(u16) + name(NT, aligned to 4)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }
        let sum_name = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let offset_actual_symbol = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let module_index = u16::from_le_bytes([data[8], data[9]]);

        let name_start = 10;
        if name_start >= data.len() {
            return Some(Self {
                name: String::new(),
                module_index,
                sum_name,
                offset_actual_symbol,
            });
        }

        let end = data[name_start..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(data[name_start..].len());
        let name = String::from_utf8_lossy(&data[name_start..name_start + end]).to_string();

        Some(Self {
            name,
            module_index,
            sum_name,
            offset_actual_symbol,
        })
    }
}

impl AbstractMsSymbol for SAnnotationRef {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_ANNOTATIONREF
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_ANNOTATIONREF"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {:08X}: ({:4}, {:08X}) {}",
            self.symbol_type_name(),
            self.sum_name,
            self.module_index,
            self.offset_actual_symbol,
            self.name,
        )
    }
}

impl NameMsSymbol for SAnnotationRef {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SAnnotationRef {
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
        data.extend_from_slice(&(strings.len() as u16).to_le_bytes());
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
        assert_eq!(sym.count, 2);
        assert_eq!(sym.strings.len(), 2);
        assert_eq!(sym.strings[0], "hello");
        assert_eq!(sym.strings[1], "world");
    }

    #[test]
    fn test_parse_single_string() {
        let data = make_annotation_bytes(0x2000, 2, &[b"note"]);
        let sym = SAnnotation::parse(&data).unwrap();
        assert_eq!(sym.count, 1);
        assert_eq!(sym.strings, vec!["note"]);
    }

    #[test]
    fn test_parse_no_strings() {
        let data = make_annotation_bytes(0x3000, 1, &[]);
        let sym = SAnnotation::parse(&data).unwrap();
        assert_eq!(sym.count, 0);
        assert!(sym.strings.is_empty());
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01]; // too short
        assert!(SAnnotation::parse(&data).is_none());
    }

    #[test]
    fn test_parse_count_mismatch() {
        // Declare count=3 but only provide 2 strings
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&3u16.to_le_bytes()); // count=3
        data.extend_from_slice(&5u16.to_le_bytes());
        data.extend_from_slice(b"hello");
        data.extend_from_slice(&5u16.to_le_bytes());
        data.extend_from_slice(b"world");
        // Third string missing -- parser should stop
        let sym = SAnnotation::parse(&data).unwrap();
        assert_eq!(sym.count, 3);
        assert_eq!(sym.strings.len(), 2);
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
        assert_eq!(sym.count, 2);
    }

    #[test]
    fn test_new_with_count() {
        let sym = SAnnotation::new_with_count(
            0x6000,
            1,
            5,
            vec!["a".to_string()],
        );
        assert_eq!(sym.count, 5);
        assert_eq!(sym.strings.len(), 1);
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
    fn test_display_multiline() {
        let sym = SAnnotation::new(
            0x1000,
            1,
            vec!["first".to_string(), "second".to_string()],
        );
        let s = format!("{}", sym);
        assert!(s.contains("first"));
        assert!(s.contains("second"));
        // Java format: one string per line with index
        assert!(s.contains("\n"));
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

    // SAnnotationRef tests

    fn make_annotationref_bytes(
        name: &[u8],
        module_index: u16,
        sum_name: u32,
        sym_offset: u32,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&sum_name.to_le_bytes());
        data.extend_from_slice(&sym_offset.to_le_bytes());
        data.extend_from_slice(&module_index.to_le_bytes());
        data.extend_from_slice(name);
        data.push(0); // null terminator
        data
    }

    #[test]
    fn test_annotationref_parse_basic() {
        let data = make_annotationref_bytes(b"my_note", 3, 0x1234, 0x5678);
        let sym = SAnnotationRef::parse(&data).unwrap();
        assert_eq!(sym.name, "my_note");
        assert_eq!(sym.module_index, 3);
        assert_eq!(sym.sum_name, 0x1234);
        assert_eq!(sym.offset_actual_symbol, 0x5678);
    }

    #[test]
    fn test_annotationref_parse_truncated() {
        let data = [0x00; 5];
        assert!(SAnnotationRef::parse(&data).is_none());
    }

    #[test]
    fn test_annotationref_parse_empty_name() {
        let data = make_annotationref_bytes(b"", 2, 0, 0);
        let sym = SAnnotationRef::parse(&data).unwrap();
        assert_eq!(sym.name, "");
        assert_eq!(sym.module_index, 2);
    }

    #[test]
    fn test_annotationref_trait_impls() {
        let sym = SAnnotationRef::new("note".to_string(), 5);
        assert_eq!(sym.pdb_id(), 0x1128);
        assert_eq!(sym.symbol_type_name(), "S_ANNOTATIONREF");
        assert_eq!(sym.name(), "note");
        assert_eq!(sym.module_index, 5);
    }

    #[test]
    fn test_annotationref_new_with_internals() {
        let sym = SAnnotationRef::new_with_internals(
            "annotation".to_string(),
            1,
            0xABCD,
            0x1234,
        );
        assert_eq!(sym.sum_name, 0xABCD);
        assert_eq!(sym.offset_actual_symbol, 0x1234);
    }

    #[test]
    fn test_annotationref_display() {
        let sym = SAnnotationRef::new("my_note".to_string(), 2);
        let s = format!("{}", sym);
        assert!(s.contains("S_ANNOTATIONREF"));
        assert!(s.contains("my_note"));
        assert!(s.contains("2"));
    }

    #[test]
    fn test_annotationref_clone_eq() {
        let a = SAnnotationRef::new("x".to_string(), 1);
        let b = a.clone();
        assert_eq!(a, b);
    }
}
