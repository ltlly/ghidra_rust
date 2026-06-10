//! S_INLINESITE -- Inline site symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.InlineSiteMsSymbol`.
//!
//! # Binary Format
//!
//! ```text
//! parent_offset  : u32       (linked-list offset to parent scope)
//! end_offset     : u32       (offset to S_INLINESITE_END)
//! inlinee        : u32       (IPI item index referencing S_BUILDINFO)
//! annotations    : variable  (BinaryAnnotation records)
//! ```
//!
//! # Annotations
//!
//! The `annotations` field contains zero or more `BinaryAnnotation` records
//! that describe how the inlined code maps back to the original source.
//! Each record is encoded as a sequence of unsigned integers. The first
//! integer is the opcode; subsequent integers are operands whose count
//! depends on the opcode.
//!
//! Known opcodes (from LLVM/MS PDB):
//! - 0: Invalid (should not appear)
//! - 1: Code offset (1 operand: offset)
//! - 2: Adjust the code offset by a signed delta (1 operand: delta)
//! - 3: Column start/end (2 operands: start_col, end_col)
//! - 4: Add the given number of lines to the source line (1 operand: count)
//! - 5: Set the source line to the given value (1 operand: line)
//! - 6: Set the source file to the given value (1 operand: file_id)
//! - 7: Set the discriminator (1 operand: discriminator)
//! - 8: Mark the end of the annotations (0 operands)

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::record_number::{RecordCategory, RecordNumber};

/// An inline site symbol (`S_INLINESITE`).
///
/// This symbol marks the beginning of an inlined function's scope within
/// its caller. It is paired with [`super::s_end::SEnd`] (specifically
/// `S_INLINESITE_END`) to delimit the range of code that was inlined.
///
/// The `inlinee` field references an item record in the IPI stream that
/// contains the inlinee's function information (via `S_BUILDINFO`).
///
/// # PDB Binary Layout
///
/// ```text
/// parent_offset  : u32
/// end_offset     : u32
/// inlinee        : u32  (IPI item index)
/// annotations    : variable-length binary data
/// ```
///
/// The `parent_offset` and `end_offset` fields form a linked-list structure
/// among nested scopes. The `annotations` field contains BinaryAnnotation
/// records that describe the inlined code's mapping back to the original
/// source.
///
/// This corresponds to `S_INLINESITE` (0x103E) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SInlineSite {
    /// Offset to the parent scope record (for nesting).
    pub parent_offset: u32,

    /// Offset to the end (S_INLINESITE_END) record.
    pub end_offset: u32,

    /// The inlinee's item record number (IPI index referencing S_BUILDINFO).
    pub inlinee: RecordNumber,

    /// Raw binary annotation data following the fixed fields.
    pub annotations: Vec<u8>,
}

impl SInlineSite {
    /// Create a new inline site symbol.
    pub fn new(
        parent_offset: u32,
        end_offset: u32,
        inlinee: RecordNumber,
        annotations: Vec<u8>,
    ) -> Self {
        Self {
            parent_offset,
            end_offset,
            inlinee,
            annotations,
        }
    }

    /// Parse an S_INLINESITE symbol from a byte slice.
    ///
    /// Expects the layout:
    /// `parent_offset(u32) + end_offset(u32) + inlinee(u32) + annotations(variable)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        let parent_offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let end_offset = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let (inlinee, _) = RecordNumber::parse(data, 8, RecordCategory::Item, 32);
        let annotations = if data.len() > 12 {
            data[12..].to_vec()
        } else {
            Vec::new()
        };
        Some(Self {
            parent_offset,
            end_offset,
            inlinee,
            annotations,
        })
    }

    /// Return `true` if this inline site has annotation data.
    pub fn has_annotations(&self) -> bool {
        !self.annotations.is_empty()
    }

    /// Return the number of raw annotation bytes.
    pub fn annotation_byte_count(&self) -> usize {
        self.annotations.len()
    }

    /// Parse the raw annotation bytes into a sequence of [`BinaryAnnotation`]
    /// records.
    ///
    /// Returns an empty vector if there are no annotations or if parsing
    /// fails (e.g., malformed data). Parsing is best-effort -- any record
    /// that cannot be decoded terminates the sequence.
    pub fn parse_annotations(&self) -> Vec<BinaryAnnotation> {
        parse_binary_annotations(&self.annotations)
    }
}

/// A decoded binary annotation record from an inline site.
///
/// Binary annotations are encoded as a variable-length sequence of unsigned
/// 16-bit integers. The first integer is the opcode; the remaining integers
/// are operands whose count depends on the opcode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryAnnotation {
    /// The annotation opcode.
    pub opcode: BinaryAnnotationOpcode,
    /// Operand values (count depends on the opcode).
    pub operands: Vec<u16>,
}

/// Opcodes for binary annotations in inline site records.
///
/// These values come from the LLVM PDB documentation and Microsoft's
/// CodeView specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum BinaryAnnotationOpcode {
    /// Invalid / unknown opcode.
    Invalid = 0,
    /// Code offset: set the current code offset (1 operand).
    CodeOffset = 1,
    /// Adjust code offset by a signed delta (1 operand).
    AdjustCodeOffset = 2,
    /// Column range: start and end columns (2 operands).
    Column = 3,
    /// Add lines to the current source line (1 operand).
    AddLine = 4,
    /// Set the source line to an absolute value (1 operand).
    SetLine = 5,
    /// Set the source file index (1 operand).
    SetFile = 6,
    /// Set the discriminator value (1 operand).
    SetDiscriminator = 7,
    /// End of annotations (0 operands).
    End = 8,
}

impl BinaryAnnotationOpcode {
    /// Convert a raw u16 value to an opcode.
    pub fn from_u16(val: u16) -> Self {
        match val {
            1 => Self::CodeOffset,
            2 => Self::AdjustCodeOffset,
            3 => Self::Column,
            4 => Self::AddLine,
            5 => Self::SetLine,
            6 => Self::SetFile,
            7 => Self::SetDiscriminator,
            8 => Self::End,
            _ => Self::Invalid,
        }
    }

    /// Return the expected number of operands for this opcode.
    pub fn operand_count(&self) -> usize {
        match self {
            Self::Invalid | Self::End => 0,
            Self::CodeOffset | Self::AdjustCodeOffset | Self::AddLine
            | Self::SetLine | Self::SetFile | Self::SetDiscriminator => 1,
            Self::Column => 2,
        }
    }
}

/// Parse binary annotations from raw bytes.
///
/// The annotation data is a sequence of little-endian `u16` values.
/// Returns a vector of decoded [`BinaryAnnotation`] records. Parsing stops
/// at the first `End` opcode or when the data is exhausted.
pub fn parse_binary_annotations(data: &[u8]) -> Vec<BinaryAnnotation> {
    let mut annotations = Vec::new();
    let mut pos = 0;

    while pos + 2 <= data.len() {
        let opcode_val = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        let opcode = BinaryAnnotationOpcode::from_u16(opcode_val);
        let expected = opcode.operand_count();

        let mut operands = Vec::with_capacity(expected);
        for _ in 0..expected {
            if pos + 2 > data.len() {
                break;
            }
            operands.push(u16::from_le_bytes([data[pos], data[pos + 1]]));
            pos += 2;
        }

        let is_end = opcode == BinaryAnnotationOpcode::End;
        annotations.push(BinaryAnnotation { opcode, operands });

        if is_end {
            break;
        }
    }

    annotations
}

impl AbstractMsSymbol for SInlineSite {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_INLINESITE
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_INLINESITE"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "InlineSite: Parent: {:#X}, End: {:#X}, Inlinee: {}, Annotations: {} bytes",
            self.parent_offset,
            self.end_offset,
            self.inlinee,
            self.annotations.len(),
        )
    }
}

impl fmt::Display for SInlineSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::record_number::RecordNumber;

    fn make_inlinesite_bytes(
        parent_offset: u32,
        end_offset: u32,
        inlinee: u32,
        annotations: &[u8],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&parent_offset.to_le_bytes());
        data.extend_from_slice(&end_offset.to_le_bytes());
        data.extend_from_slice(&inlinee.to_le_bytes());
        data.extend_from_slice(annotations);
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_inlinesite_bytes(0, 0x40, 0x1234, &[]);
        let sym = SInlineSite::parse(&data).unwrap();
        assert_eq!(sym.parent_offset, 0);
        assert_eq!(sym.end_offset, 0x40);
        assert_eq!(sym.inlinee.number(), 0x1234);
        assert!(sym.annotations.is_empty());
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SInlineSite::parse(&data).is_none());
    }

    #[test]
    fn test_parse_exact_minimum() {
        let data = make_inlinesite_bytes(0, 0, 0, &[]);
        assert_eq!(data.len(), 12);
        let sym = SInlineSite::parse(&data).unwrap();
        assert_eq!(sym.parent_offset, 0);
        assert_eq!(sym.end_offset, 0);
        assert_eq!(sym.inlinee.number(), 0);
    }

    #[test]
    fn test_parse_with_annotations() {
        let annotations = [0x01, 0x02, 0x03, 0x04];
        let data = make_inlinesite_bytes(0x10, 0x80, 0x5678, &annotations);
        let sym = SInlineSite::parse(&data).unwrap();
        assert_eq!(sym.parent_offset, 0x10);
        assert_eq!(sym.end_offset, 0x80);
        assert_eq!(sym.inlinee.number(), 0x5678);
        assert_eq!(sym.annotations, vec![0x01, 0x02, 0x03, 0x04]);
        assert!(sym.has_annotations());
    }

    #[test]
    fn test_has_annotations() {
        let sym_no = SInlineSite::new(0, 0, RecordNumber::item_record_number(1), vec![]);
        assert!(!sym_no.has_annotations());

        let sym_yes = SInlineSite::new(0, 0, RecordNumber::item_record_number(1), vec![0xAA]);
        assert!(sym_yes.has_annotations());
    }

    #[test]
    fn test_annotation_byte_count() {
        let sym = SInlineSite::new(
            0,
            0,
            RecordNumber::item_record_number(1),
            vec![0x01, 0x02, 0x03],
        );
        assert_eq!(sym.annotation_byte_count(), 3);
    }

    #[test]
    fn test_trait_impls() {
        let sym = SInlineSite::new(
            0x10,
            0x80,
            RecordNumber::item_record_number(0x1234),
            vec![],
        );
        assert_eq!(sym.pdb_id(), 0x103E);
        assert_eq!(sym.symbol_type_name(), "S_INLINESITE");
        assert_eq!(sym.parent_offset, 0x10);
        assert_eq!(sym.end_offset, 0x80);
    }

    #[test]
    fn test_display() {
        let sym = SInlineSite::new(
            0,
            0x40,
            RecordNumber::item_record_number(0x1000),
            vec![0x01, 0x02],
        );
        let s = format!("{}", sym);
        assert!(s.contains("InlineSite"));
        assert!(s.contains("40"));
        assert!(s.contains("2 bytes"));
    }

    #[test]
    fn test_display_no_annotations() {
        let sym = SInlineSite::new(
            0,
            0x40,
            RecordNumber::item_record_number(0x1000),
            vec![],
        );
        let s = format!("{}", sym);
        assert!(s.contains("0 bytes"));
    }

    #[test]
    fn test_inlinee_is_item_category() {
        let sym = SInlineSite::new(
            0,
            0,
            RecordNumber::item_record_number(0x100),
            vec![],
        );
        assert_eq!(sym.inlinee.category(), super::super::record_number::RecordCategory::Item);
    }

    #[test]
    fn test_clone_eq() {
        let a = SInlineSite::new(
            0x10,
            0x80,
            RecordNumber::item_record_number(0x1234),
            vec![0x01, 0x02],
        );
        let b = a.clone();
        assert_eq!(a, b);
    }

    // BinaryAnnotation parsing tests

    fn make_annotation(opcode: u16, operands: &[u16]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&opcode.to_le_bytes());
        for op in operands {
            data.extend_from_slice(&op.to_le_bytes());
        }
        data
    }

    #[test]
    fn test_parse_annotations_empty() {
        let sym = SInlineSite::new(
            0,
            0,
            RecordNumber::item_record_number(1),
            vec![],
        );
        let anns = sym.parse_annotations();
        assert!(anns.is_empty());
    }

    #[test]
    fn test_parse_annotations_end_only() {
        let data = make_annotation(8, &[]); // End opcode
        let sym = SInlineSite::new(
            0,
            0,
            RecordNumber::item_record_number(1),
            data,
        );
        let anns = sym.parse_annotations();
        assert_eq!(anns.len(), 1);
        assert_eq!(anns[0].opcode, BinaryAnnotationOpcode::End);
        assert!(anns[0].operands.is_empty());
    }

    #[test]
    fn test_parse_annotations_code_offset() {
        let mut data = Vec::new();
        data.extend_from_slice(&make_annotation(1, &[0x10])); // CodeOffset(0x10)
        data.extend_from_slice(&make_annotation(5, &[42]));   // SetLine(42)
        data.extend_from_slice(&make_annotation(8, &[]));     // End

        let sym = SInlineSite::new(
            0,
            0,
            RecordNumber::item_record_number(1),
            data,
        );
        let anns = sym.parse_annotations();
        assert_eq!(anns.len(), 3);
        assert_eq!(anns[0].opcode, BinaryAnnotationOpcode::CodeOffset);
        assert_eq!(anns[0].operands, vec![0x10]);
        assert_eq!(anns[1].opcode, BinaryAnnotationOpcode::SetLine);
        assert_eq!(anns[1].operands, vec![42]);
        assert_eq!(anns[2].opcode, BinaryAnnotationOpcode::End);
    }

    #[test]
    fn test_parse_annotations_column() {
        let mut data = Vec::new();
        data.extend_from_slice(&make_annotation(3, &[5, 20])); // Column(5, 20)
        data.extend_from_slice(&make_annotation(8, &[]));      // End

        let sym = SInlineSite::new(
            0,
            0,
            RecordNumber::item_record_number(1),
            data,
        );
        let anns = sym.parse_annotations();
        assert_eq!(anns.len(), 2);
        assert_eq!(anns[0].opcode, BinaryAnnotationOpcode::Column);
        assert_eq!(anns[0].operands, vec![5, 20]);
    }

    #[test]
    fn test_parse_annotations_truncated() {
        // Opcode says 1 operand but data is too short
        let data = make_annotation(1, &[]); // CodeOffset with no operand bytes
        let sym = SInlineSite::new(
            0,
            0,
            RecordNumber::item_record_number(1),
            data,
        );
        let anns = sym.parse_annotations();
        assert_eq!(anns.len(), 1);
        assert_eq!(anns[0].opcode, BinaryAnnotationOpcode::CodeOffset);
        assert!(anns[0].operands.is_empty());
    }

    #[test]
    fn test_parse_annotations_unknown_opcode() {
        // Unknown opcode (99) has 0 expected operands, so the remaining
        // bytes after it are parsed as additional records.
        let mut data = Vec::new();
        data.extend_from_slice(&make_annotation(99, &[])); // unknown, 0 operands
        data.extend_from_slice(&make_annotation(8, &[]));   // End

        let sym = SInlineSite::new(
            0,
            0,
            RecordNumber::item_record_number(1),
            data,
        );
        let anns = sym.parse_annotations();
        assert_eq!(anns.len(), 2);
        assert_eq!(anns[0].opcode, BinaryAnnotationOpcode::Invalid);
        assert!(anns[0].operands.is_empty());
        assert_eq!(anns[1].opcode, BinaryAnnotationOpcode::End);
    }

    #[test]
    fn test_binary_annotation_opcode_operand_count() {
        assert_eq!(BinaryAnnotationOpcode::End.operand_count(), 0);
        assert_eq!(BinaryAnnotationOpcode::CodeOffset.operand_count(), 1);
        assert_eq!(BinaryAnnotationOpcode::Column.operand_count(), 2);
        assert_eq!(BinaryAnnotationOpcode::Invalid.operand_count(), 0);
    }

    #[test]
    fn test_binary_annotation_opcode_from_u16() {
        assert_eq!(BinaryAnnotationOpcode::from_u16(0), BinaryAnnotationOpcode::Invalid);
        assert_eq!(BinaryAnnotationOpcode::from_u16(1), BinaryAnnotationOpcode::CodeOffset);
        assert_eq!(BinaryAnnotationOpcode::from_u16(8), BinaryAnnotationOpcode::End);
        assert_eq!(BinaryAnnotationOpcode::from_u16(255), BinaryAnnotationOpcode::Invalid);
    }
}
