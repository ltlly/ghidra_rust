//! NE Segment and SegmentTable ported from Ghidra's
//! `ghidra.app.util.bin.format.ne.Segment` and related classes.
//!
//! Provides types for NE segment descriptors and relocations:
//! - [`Segment`] -- a single segment descriptor with flags and relocations
//! - [`SegmentRelocation`] -- a segment relocation entry
//! - [`SegmentTable`] -- collection of all segments in the NE file

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;

// ---------------------------------------------------------------------------
// Segment flags
// ---------------------------------------------------------------------------

/// Data segment type.
const FLAG_DATA: u16 = 0x0001;
/// Loaded / has allocated memory.
const FLAG_ALLOC: u16 = 0x0002;
/// Segment is loaded.
const FLAG_LOADED: u16 = 0x0004;
/// Segment not fixed (moveable).
const FLAG_MOVEABLE: u16 = 0x0010;
/// Pure (shareable) or impure (unshareable).
const FLAG_PURE: u16 = 0x0020;
/// Preload or load-on-call.
const FLAG_PRELOAD: u16 = 0x0040;
/// If code, segment is execute-only; if data, read-only.
const FLAG_EXE_ONLY: u16 = 0x0080;
/// Segment has relocation records.
const FLAG_RELOC_INFO: u16 = 0x0100;
/// Segment is discardable.
const FLAG_DISCARD: u16 = 0x1000;
/// Segment is 32-bit.
const FLAG_32BIT: u16 = 0x2000;

// ---------------------------------------------------------------------------
// SegmentRelocation
// ---------------------------------------------------------------------------

/// Relocation types (low nibble of type byte)
pub const TYPE_LO_BYTE: u8 = 0x00;
pub const TYPE_SEGMENT: u8 = 0x02;
pub const TYPE_FAR_ADDR: u8 = 0x03;
pub const TYPE_OFFSET: u8 = 0x05;
pub const TYPE_FAR_ADDR_48: u8 = 0x0C;
pub const TYPE_OFFSET_32: u8 = 0x0D;

/// Type string names indexed by type value.
pub const TYPE_STRINGS: [&str; 14] = [
    "Low Byte",
    "???1",
    "16-bit Segment Selector",
    "32-bit Pointer",
    "???4",
    "16-bit Pointer",
    "???6",
    "???7",
    "???8",
    "???9",
    "???10",
    "48-bit Pointer",
    "???12",
    "32-bit Offset",
];

/// Byte lengths for each relocation type.
pub const TYPE_LENGTHS: [usize; 14] = [
    1, // TYPE_LO_BYTE
    0, 2, // TYPE_SEGMENT
    4, // TYPE_FAR_ADDR
    0, 2, // TYPE_OFFSET
    0, 0, 0, 0, 0, 0, 6, // TYPE_FAR_ADDR_48
    4, // TYPE_OFFSET_32
];

// Relocation target flags (low 2 bits of flag byte)
/// Internal reference relocation.
pub const FLAG_INTERNAL_REF: u8 = 0x00;
/// Import ordinal relocation.
pub const FLAG_IMPORT_ORDINAL: u8 = 0x01;
/// Import name relocation.
pub const FLAG_IMPORT_NAME: u8 = 0x02;
/// Operating system fixup relocation.
pub const FLAG_OS_FIXUP: u8 = 0x03;
/// Additive relocation flag.
pub const FLAG_ADDITIVE: u8 = 0x04;

/// Mask for target type in flag byte.
const FLAG_TARGET_MASK: u8 = 0x03;

/// Moveable segment marker.
pub const SEGMENT_MOVEABLE: u16 = 0xFF;

/// A segment relocation entry in a New Executable.
///
/// Ported from `ghidra.app.util.bin.format.ne.SegmentRelocation`.
/// Each relocation describes a fixup that must be applied when the
/// segment is loaded into memory.
#[derive(Debug, Clone)]
pub struct SegmentRelocation {
    /// The segment this relocation belongs to.
    segment: u32,
    /// The relocation type (low nibble).
    relocation_type: u8,
    /// The flag byte (target type + additive flag).
    flagbyte: u8,
    /// Offset within the segment where the fixup applies.
    offset: u16,
    /// Target segment number.
    target_segment: u16,
    /// Target offset within the target segment.
    target_offset: u16,
}

impl SegmentRelocation {
    /// Number of values required to reconstruct this relocation.
    pub const VALUES_SIZE: usize = 5;

    /// Parse a segment relocation from the reader.
    pub fn parse(reader: &mut BinaryReader, segment: u32) -> io::Result<Self> {
        let relocation_type = reader.read_next_u8()?;
        let flagbyte = reader.read_next_u8()?;
        let offset = reader.read_next_u16()?;
        let target_segment = reader.read_next_u16()?;
        let target_offset = reader.read_next_u16()?;

        Ok(Self {
            segment,
            relocation_type,
            flagbyte,
            offset,
            target_segment,
            target_offset,
        })
    }

    /// Construct from raw values.
    pub fn from_values(relocation_type: u8, values: &[i64]) -> Self {
        assert!(
            values.len() == Self::VALUES_SIZE,
            "Expected {} values",
            Self::VALUES_SIZE
        );
        Self {
            segment: values[0] as u32,
            relocation_type,
            flagbyte: values[1] as u8,
            offset: values[2] as u16,
            target_segment: values[3] as u16,
            target_offset: values[4] as u16,
        }
    }

    /// Returns the segment this relocation belongs to.
    pub fn segment(&self) -> u32 {
        self.segment
    }

    /// Returns true if this relocation is an internal reference.
    pub fn is_internal_ref(&self) -> bool {
        self.flagbyte & FLAG_TARGET_MASK == FLAG_INTERNAL_REF
    }

    /// Returns true if this relocation is an import by ordinal.
    pub fn is_import_ordinal(&self) -> bool {
        self.flagbyte & FLAG_TARGET_MASK == FLAG_IMPORT_ORDINAL
    }

    /// Returns true if this relocation is an import by name.
    pub fn is_import_name(&self) -> bool {
        self.flagbyte & FLAG_TARGET_MASK == FLAG_IMPORT_NAME
    }

    /// Returns true if this relocation is an operating system fixup.
    pub fn is_op_sys_fixup(&self) -> bool {
        self.flagbyte & FLAG_TARGET_MASK == FLAG_OS_FIXUP
    }

    /// Returns true if this relocation is additive.
    ///
    /// If additive, the relocation value is added to the existing value.
    /// Otherwise, the existing value is overwritten.
    pub fn is_additive(&self) -> bool {
        self.flagbyte & FLAG_ADDITIVE != 0
    }

    /// Returns the relocation type.
    pub fn relocation_type(&self) -> u8 {
        self.relocation_type
    }

    /// Returns the flag byte.
    pub fn flag_byte(&self) -> u8 {
        self.flagbyte
    }

    /// Returns the relocation offset within the segment.
    pub fn offset(&self) -> u16 {
        self.offset
    }

    /// Returns the target segment number.
    pub fn target_segment(&self) -> u16 {
        self.target_segment
    }

    /// Returns the target offset.
    pub fn target_offset(&self) -> u16 {
        self.target_offset
    }

    /// Returns values required to reconstruct this object.
    pub fn values(&self) -> [i64; 5] {
        [
            self.segment as i64,
            self.flagbyte as i64,
            self.offset as i64,
            self.target_segment as i64,
            self.target_offset as i64,
        ]
    }

    /// Returns a human-readable name for this relocation type.
    pub fn type_name(&self) -> &str {
        let idx = (self.relocation_type & 0x0F) as usize;
        if idx < TYPE_STRINGS.len() {
            TYPE_STRINGS[idx]
        } else {
            "Unknown"
        }
    }
}

impl fmt::Display for SegmentRelocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SegmentRelocation {{ type={}, offset=0x{:04X}, target=0x{:04X}:0x{:04X} }}",
            self.type_name(),
            self.offset,
            self.target_segment,
            self.target_offset
        )
    }
}

// ---------------------------------------------------------------------------
// Segment
// ---------------------------------------------------------------------------

/// A single segment descriptor in a New Executable.
///
/// Ported from `ghidra.app.util.bin.format.ne.Segment`.
/// Each segment has an offset in the file, a length, flags, and
/// optional relocation records.
#[derive(Debug)]
pub struct Segment {
    /// The segment index (1-based).
    segment_id: u32,
    /// Byte offset to content, relative to BOF (zero means no file data).
    offset: u16,
    /// Length of segment in file (zero means 64K).
    length: u16,
    /// Segment flags.
    flagword: u16,
    /// Minimum size in memory to allocate (zero means 64K).
    min_alloc_size: u16,
    /// The aligned offset value (offset * alignment).
    offset_align: u32,
    /// Number of relocations.
    n_relocations: u16,
    /// Relocation records for this segment.
    relocations: Vec<SegmentRelocation>,
}

impl Segment {
    /// Parse a segment from the reader.
    pub fn parse(
        reader: &mut BinaryReader,
        segment_alignment: u16,
        segment_id: u32,
    ) -> io::Result<Self> {
        let offset = reader.read_next_u16()?;
        let length = reader.read_next_u16()?;
        let flagword = reader.read_next_u16()?;
        let min_alloc_size = reader.read_next_u16()?;

        let offset_align = (offset as u32) * (segment_alignment as u32);

        let mut relocations = Vec::new();
        let mut n_relocations = 0u16;

        if flagword & FLAG_RELOC_INFO != 0 {
            let reloc_pos = offset_align + (length as u32);
            let old_index = reader.cursor();
            reader.set_cursor(reloc_pos as u64);

            n_relocations = reader.read_next_u16()?;
            for _ in 0..n_relocations {
                relocations.push(SegmentRelocation::parse(reader, segment_id)?);
            }
            reader.set_cursor(old_index);
        }

        Ok(Self {
            segment_id,
            offset,
            length,
            flagword,
            min_alloc_size,
            offset_align,
            n_relocations,
            relocations,
        })
    }

    /// Returns the segment ID.
    pub fn segment_id(&self) -> u32 {
        self.segment_id
    }

    /// Returns true if the segment should operate in 32-bit mode.
    pub fn is_32bit(&self) -> bool {
        self.flagword & FLAG_32BIT != 0
    }

    /// Returns true if this is a code segment.
    pub fn is_code(&self) -> bool {
        !self.is_data()
    }

    /// Returns true if this is a data segment.
    pub fn is_data(&self) -> bool {
        self.flagword & FLAG_DATA != 0
    }

    /// Returns true if this segment has relocations.
    pub fn has_relocation(&self) -> bool {
        self.flagword & FLAG_RELOC_INFO != 0
    }

    /// Returns true if this segment is loader allocated.
    pub fn is_loader_allocated(&self) -> bool {
        self.flagword & FLAG_ALLOC != 0
    }

    /// Returns true if this segment is loaded.
    pub fn is_loaded(&self) -> bool {
        self.flagword & FLAG_LOADED != 0
    }

    /// Returns true if this segment is moveable.
    pub fn is_moveable(&self) -> bool {
        self.flagword & FLAG_MOVEABLE != 0
    }

    /// Returns true if this segment is preloaded.
    pub fn is_preload(&self) -> bool {
        self.flagword & FLAG_PRELOAD != 0
    }

    /// Returns true if this segment is pure (shareable).
    pub fn is_pure(&self) -> bool {
        self.flagword & FLAG_PURE != 0
    }

    /// Returns true if this segment is read-only (data segments only).
    pub fn is_read_only(&self) -> bool {
        self.is_data() && (self.flagword & FLAG_EXE_ONLY != 0)
    }

    /// Returns true if this segment is execute-only (code segments only).
    pub fn is_execute_only(&self) -> bool {
        self.is_code() && (self.flagword & FLAG_EXE_ONLY != 0)
    }

    /// Returns true if this segment is discardable.
    pub fn is_discardable(&self) -> bool {
        self.flagword & FLAG_DISCARD != 0
    }

    /// Returns the raw flag word.
    pub fn flagword(&self) -> u16 {
        self.flagword
    }

    /// Returns the length of this segment in the file.
    pub fn length(&self) -> u16 {
        self.length
    }

    /// Returns the minimum allocation size (zero means 64K).
    pub fn min_alloc_size(&self) -> u16 {
        self.min_alloc_size
    }

    /// Returns the raw (unshifted) offset.
    pub fn offset(&self) -> u16 {
        self.offset
    }

    /// Returns the actual (shift-aligned) offset to the contents.
    pub fn offset_shift_aligned(&self) -> u32 {
        self.offset_align
    }

    /// Returns the relocations defined for this segment.
    pub fn relocations(&self) -> &[SegmentRelocation] {
        &self.relocations
    }

    /// Returns the number of relocations.
    pub fn relocation_count(&self) -> u16 {
        self.n_relocations
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Segment {{ id={}, offset=0x{:04X}, length={}, flags=0x{:04X}, relocs={} }}",
            self.segment_id, self.offset_align, self.length, self.flagword, self.n_relocations
        )
    }
}

// ---------------------------------------------------------------------------
// SegmentTable
// ---------------------------------------------------------------------------

/// The segment table in a New Executable.
///
/// Ported from `ghidra.app.util.bin.format.ne.SegmentTable`.
/// Contains all segment descriptors for the executable.
#[derive(Debug)]
pub struct SegmentTable {
    segments: Vec<Segment>,
}

impl SegmentTable {
    /// Parse a segment table from the reader.
    ///
    /// `base_segment` is the starting segment number (for address computation).
    pub fn parse(
        reader: &mut BinaryReader,
        index: u64,
        segment_count: u16,
        shift_align_count: u16,
        base_segment: u32,
    ) -> io::Result<Self> {
        let old_index = reader.cursor();
        reader.set_cursor(index);

        // The alignment value is 1 << shift_count
        let alignment = 1u16 << shift_align_count;
        let count = segment_count as usize;

        let mut segments = Vec::with_capacity(count);
        let mut cur_segment = base_segment;

        for _ in 0..count {
            let seg = Segment::parse(reader, alignment, cur_segment)?;
            let size = seg.min_alloc_size() as u32;
            let effective_size = if size == 0 { 0x10000 } else { size };
            cur_segment += effective_size;
            segments.push(seg);
        }

        reader.set_cursor(old_index);
        Ok(Self { segments })
    }

    /// Returns the array of segments.
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Returns the number of segments.
    pub fn len(&self) -> usize {
        self.segments.len()
    }

    /// Returns true if the segment table is empty.
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_segment_bytes(flags: u16, include_reloc: bool) -> Vec<u8> {
        let mut data = Vec::new();

        // Segment entry: offset(2) + length(2) + flags(2) + minAllocSize(2) = 8 bytes
        data.extend_from_slice(&0x0100u16.to_le_bytes()); // offset = 0x0100
        data.extend_from_slice(&0x0080u16.to_le_bytes()); // length = 128
        data.extend_from_slice(&flags.to_le_bytes()); // flags
        data.extend_from_slice(&0x0100u16.to_le_bytes()); // minAllocSize = 256

        if include_reloc {
            // Pad to offset_align position (offset * alignment)
            // alignment=1, so offset_align = 0x0100 * 1 = 0x0100
            // We need data from 0 to 0x0100+0x80 = 0x0180, then relocations
            while data.len() < 0x0182 {
                data.push(0);
            }
            // nRelocations = 1
            data[0x0180] = 1;
            data[0x0181] = 0;

            // Relocation entry: type(1) + flags(1) + offset(2) + targetSeg(2) + targetOff(2) = 8
            data.push(TYPE_SEGMENT); // type
            data.push(FLAG_INTERNAL_REF); // flags
            data.extend_from_slice(&0x0010u16.to_le_bytes()); // offset
            data.extend_from_slice(&0x0002u16.to_le_bytes()); // target segment
            data.extend_from_slice(&0x0000u16.to_le_bytes()); // target offset
        }

        data
    }

    #[test]
    fn test_parse_segment_basic() {
        let data = make_segment_bytes(FLAG_DATA | FLAG_ALLOC, false);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let seg = Segment::parse(&mut reader, 1, 1).unwrap();

        assert_eq!(seg.segment_id(), 1);
        assert!(seg.is_data());
        assert!(!seg.is_code());
        assert!(seg.is_loader_allocated());
        assert!(!seg.has_relocation());
        assert_eq!(seg.length(), 0x80);
        assert_eq!(seg.min_alloc_size(), 0x0100);
    }

    #[test]
    fn test_parse_segment_code() {
        let data = make_segment_bytes(FLAG_ALLOC | FLAG_LOADED, false);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let seg = Segment::parse(&mut reader, 1, 1).unwrap();

        assert!(seg.is_code());
        assert!(!seg.is_data());
        assert!(seg.is_loaded());
    }

    #[test]
    fn test_segment_flags() {
        let data = make_segment_bytes(FLAG_MOVEABLE | FLAG_PURE | FLAG_PRELOAD, false);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let seg = Segment::parse(&mut reader, 1, 1).unwrap();

        assert!(seg.is_moveable());
        assert!(seg.is_pure());
        assert!(seg.is_preload());
        assert!(!seg.is_discardable());
    }

    #[test]
    fn test_segment_discardable() {
        let data = make_segment_bytes(FLAG_DISCARD, false);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let seg = Segment::parse(&mut reader, 1, 1).unwrap();

        assert!(seg.is_discardable());
    }

    #[test]
    fn test_segment_with_relocation() {
        let data = make_segment_bytes(FLAG_DATA | FLAG_RELOC_INFO, true);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let seg = Segment::parse(&mut reader, 1, 5).unwrap();

        assert!(seg.has_relocation());
        assert_eq!(seg.relocation_count(), 1);
        assert_eq!(seg.relocations().len(), 1);

        let reloc = &seg.relocations()[0];
        assert!(reloc.is_internal_ref());
        assert!(!reloc.is_import_ordinal());
        assert_eq!(reloc.relocation_type(), TYPE_SEGMENT);
        assert_eq!(reloc.offset(), 0x0010);
        assert_eq!(reloc.target_segment(), 2);
    }

    #[test]
    fn test_segment_relocation_types() {
        let mut data = Vec::new();
        // Segment with relocation
        data.extend_from_slice(&0x0000u16.to_le_bytes()); // offset
        data.extend_from_slice(&0x0004u16.to_le_bytes()); // length
        data.extend_from_slice(&(FLAG_DATA | FLAG_RELOC_INFO).to_le_bytes());
        data.extend_from_slice(&0x0100u16.to_le_bytes()); // minAllocSize

        // Padding to reloc position (offset*1 + length = 4)
        // relocations start at offset_align + length = 0 + 4 = 4
        // but we already have 8 bytes, so we need to pad to position 4+2=6 for nRelocations
        // Actually, offset_align = offset * alignment = 0 * 1 = 0
        // reloc_pos = 0 + 4 = 4
        // nRelocations is at file position 4
        // But we wrote 8 bytes for the segment header...
        // This test constructs relocations at different types

        // Simpler: create data where we directly test the relocation parser
        let reloc_data = vec![
            TYPE_LO_BYTE,
            FLAG_IMPORT_NAME,
            0x10,
            0x00, // offset
            0x01,
            0x00, // module ordinal
            0x05,
            0x00, // function ordinal
        ];
        let mut reader = BinaryReader::from_bytes(&reloc_data, true);
        let reloc = SegmentRelocation::parse(&mut reader, 0).unwrap();

        assert!(reloc.is_import_name());
        assert!(!reloc.is_additive());
        assert_eq!(reloc.relocation_type(), TYPE_LO_BYTE);
        assert_eq!(reloc.type_name(), "Low Byte");
    }

    #[test]
    fn test_relocation_values_roundtrip() {
        let data = vec![
            TYPE_FAR_ADDR,
            FLAG_INTERNAL_REF | FLAG_ADDITIVE,
            0x20,
            0x00,
            0x03,
            0x00,
            0x40,
            0x00,
        ];
        let mut reader = BinaryReader::from_bytes(&data, true);
        let reloc = SegmentRelocation::parse(&mut reader, 7).unwrap();

        assert!(reloc.is_additive());
        assert_eq!(reloc.segment(), 7);
        assert_eq!(reloc.relocation_type(), TYPE_FAR_ADDR);

        let vals = reloc.values();
        assert_eq!(vals[0], 7); // segment
        assert_eq!(vals[1], (FLAG_INTERNAL_REF | FLAG_ADDITIVE) as i64); // flags
        assert_eq!(vals[2], 0x20); // offset
        assert_eq!(vals[3], 3); // target segment
        assert_eq!(vals[4], 0x40); // target offset
    }

    #[test]
    fn test_relocation_display() {
        let data = vec![TYPE_SEGMENT, FLAG_INTERNAL_REF, 0x00, 0x10, 0x02, 0x00, 0x00, 0x00];
        let mut reader = BinaryReader::from_bytes(&data, true);
        let reloc = SegmentRelocation::parse(&mut reader, 1).unwrap();

        let s = format!("{}", reloc);
        assert!(s.contains("16-bit Segment Selector"));
        assert!(s.contains("0x1000"));
    }

    #[test]
    fn test_segment_display() {
        let data = make_segment_bytes(FLAG_DATA | FLAG_ALLOC, false);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let seg = Segment::parse(&mut reader, 1, 3).unwrap();

        let s = format!("{}", seg);
        assert!(s.contains("id=3"));
        assert!(s.contains("flags=0x0003"));
    }

    #[test]
    fn test_segment_table_parse() {
        // Create 2 segments, no relocations
        let mut data = Vec::new();
        // Segment 1: code, loaded
        data.extend_from_slice(&0x0010u16.to_le_bytes()); // offset
        data.extend_from_slice(&0x0040u16.to_le_bytes()); // length
        data.extend_from_slice(&(FLAG_LOADED).to_le_bytes()); // flags (code)
        data.extend_from_slice(&0x0080u16.to_le_bytes()); // minAllocSize
        // Segment 2: data, alloc
        data.extend_from_slice(&0x0050u16.to_le_bytes()); // offset
        data.extend_from_slice(&0x0020u16.to_le_bytes()); // length
        data.extend_from_slice(&(FLAG_DATA | FLAG_ALLOC).to_le_bytes()); // flags
        data.extend_from_slice(&0x0040u16.to_le_bytes()); // minAllocSize

        let mut reader = BinaryReader::from_bytes(&data, true);
        let table = SegmentTable::parse(&mut reader, 0, 2, 0, 1).unwrap();

        assert_eq!(table.len(), 2);
        assert!(!table.is_empty());
        assert!(table.segments()[0].is_code());
        assert!(table.segments()[1].is_data());
    }
}
