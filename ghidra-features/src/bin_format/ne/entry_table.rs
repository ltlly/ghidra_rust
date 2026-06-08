//! NE Entry Table ported from Ghidra's
//! `ghidra.app.util.bin.format.ne.EntryTable` and related classes.
//!
//! Provides types for NE entry point definitions:
//! - [`EntryTable`] -- collection of entry table bundles
//! - [`EntryTableBundle`] -- a group of entry points with the same type
//! - [`EntryPoint`] -- a single entry point within a bundle

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;

// ---------------------------------------------------------------------------
// EntryTableBundle
// ---------------------------------------------------------------------------

/// Marker denoting an unused entry table bundle.
pub const BUNDLE_UNUSED: u8 = 0x00;
/// Marker for moveable segments.
pub const BUNDLE_MOVEABLE: u8 = 0xFF;
/// Marker for constants defined in module.
pub const BUNDLE_CONSTANT: u8 = 0xFE;

/// A bundle of entry points in the NE entry table.
///
/// Ported from `ghidra.app.util.bin.format.ne.EntryTableBundle`.
/// Each bundle groups multiple entry points that share the same segment
/// and type (fixed segment, moveable, or constant).
#[derive(Debug)]
pub struct EntryTableBundle {
    /// Number of entries in this bundle.
    count: u8,
    /// Bundle type: segment number, MOVEABLE, or CONSTANT.
    bundle_type: u8,
    /// The entry points in this bundle.
    entry_points: Vec<EntryPoint>,
}

impl EntryTableBundle {
    /// Parse an entry table bundle from the reader.
    pub fn parse(reader: &mut BinaryReader) -> io::Result<Self> {
        let count = reader.read_next_u8()?;
        if count == 0 {
            return Ok(Self {
                count: 0,
                bundle_type: 0,
                entry_points: Vec::new(),
            });
        }

        let bundle_type = reader.read_next_u8()?;
        if bundle_type == BUNDLE_UNUSED {
            return Ok(Self {
                count,
                bundle_type: 0,
                entry_points: Vec::new(),
            });
        }

        let count_usize = count as usize;
        let mut entry_points = Vec::with_capacity(count_usize);
        for _ in 0..count_usize {
            entry_points.push(EntryPoint::parse(reader, bundle_type)?);
        }

        Ok(Self {
            count,
            bundle_type,
            entry_points,
        })
    }

    /// Returns true if this bundle is moveable.
    pub fn is_moveable(&self) -> bool {
        self.bundle_type == BUNDLE_MOVEABLE
    }

    /// Returns true if this bundle is a constant.
    pub fn is_constant(&self) -> bool {
        self.bundle_type == BUNDLE_CONSTANT
    }

    /// Returns the number of entries in the bundle.
    pub fn count(&self) -> u8 {
        self.count
    }

    /// Returns the bundle type (segment number, MOVEABLE, or CONSTANT).
    pub fn bundle_type(&self) -> u8 {
        self.bundle_type
    }

    /// Returns the entry points in this bundle.
    pub fn entry_points(&self) -> &[EntryPoint] {
        &self.entry_points
    }
}

impl fmt::Display for EntryTableBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let type_str = if self.is_moveable() {
            "MOVEABLE"
        } else if self.is_constant() {
            "CONSTANT"
        } else {
            "FIXED"
        };
        write!(
            f,
            "EntryTableBundle {{ type={}, count={}, entries={} }}",
            type_str,
            self.count,
            self.entry_points.len()
        )
    }
}

// ---------------------------------------------------------------------------
// EntryPoint
// ---------------------------------------------------------------------------

/// Entry point flags
pub const ENTRY_EXPORTED: u8 = 0x01;
pub const ENTRY_GLOBAL: u8 = 0x02;

/// A single entry point within an entry table bundle.
///
/// Ported from `ghidra.app.util.bin.format.ne.EntryPoint`.
/// For moveable segments, the entry point includes a 3-byte segment:offset
/// specification. For fixed segments, it includes a 2-byte offset.
#[derive(Debug, Clone)]
pub struct EntryPoint {
    /// Entry point flags (exported, global).
    flagword: u8,
    /// For moveable entries: the int 0x3F instruction.
    instruction: u16,
    /// For moveable entries: the segment number.
    segment: u8,
    /// Offset within the segment to the entry point.
    offset: u16,
    /// Whether this entry belongs to a moveable bundle.
    is_moveable: bool,
}

impl EntryPoint {
    /// Parse an entry point from the reader.
    pub fn parse(reader: &mut BinaryReader, bundle_type: u8) -> io::Result<Self> {
        let is_moveable = bundle_type == BUNDLE_MOVEABLE;

        let flagword = reader.read_next_u8()?;

        let (instruction, segment) = if is_moveable {
            let inst = reader.read_next_u16()?;
            let seg = reader.read_next_u8()?;
            (inst, seg)
        } else {
            (0, 0)
        };

        let offset = reader.read_next_u16()?;

        Ok(Self {
            flagword,
            instruction,
            segment,
            offset,
            is_moveable,
        })
    }

    /// Returns the flag word.
    pub fn flagword(&self) -> u8 {
        self.flagword
    }

    /// Returns the instruction (only valid for moveable entries).
    pub fn instruction(&self) -> u16 {
        self.instruction
    }

    /// Returns the segment number (only valid for moveable entries).
    pub fn segment(&self) -> u8 {
        self.segment
    }

    /// Returns the offset within the segment.
    pub fn offset(&self) -> u16 {
        self.offset
    }

    /// Returns true if this entry is exported.
    pub fn is_exported(&self) -> bool {
        self.flagword & ENTRY_EXPORTED != 0
    }

    /// Returns true if this entry is global.
    pub fn is_global(&self) -> bool {
        self.flagword & ENTRY_GLOBAL != 0
    }

    /// Returns true if this entry belongs to a moveable bundle.
    pub fn is_moveable(&self) -> bool {
        self.is_moveable
    }
}

impl fmt::Display for EntryPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_moveable {
            write!(
                f,
                "EntryPoint {{ seg=0x{:02X}, off=0x{:04X}, inst=0x{:04X}, exported={} }}",
                self.segment,
                self.offset,
                self.instruction,
                self.is_exported()
            )
        } else {
            write!(
                f,
                "EntryPoint {{ off=0x{:04X}, exported={} }}",
                self.offset,
                self.is_exported()
            )
        }
    }
}

// ---------------------------------------------------------------------------
// EntryTable
// ---------------------------------------------------------------------------

/// The entry table in a New Executable.
///
/// Ported from `ghidra.app.util.bin.format.ne.EntryTable`.
/// Contains bundles of entry points that define the exported
/// and internal entry points of the executable.
#[derive(Debug)]
pub struct EntryTable {
    bundles: Vec<EntryTableBundle>,
}

impl EntryTable {
    /// Parse an entry table from the reader.
    pub fn parse(
        reader: &mut BinaryReader,
        index: u64,
        _byte_count: u16,
    ) -> io::Result<Self> {
        let old_index = reader.cursor();
        reader.set_cursor(index);

        let mut bundles = Vec::new();
        loop {
            let etb = EntryTableBundle::parse(reader)?;
            if etb.count() == 0 {
                break;
            }
            bundles.push(etb);
        }

        reader.set_cursor(old_index);
        Ok(Self { bundles })
    }

    /// Returns the entry table bundles.
    pub fn bundles(&self) -> &[EntryTableBundle] {
        &self.bundles
    }

    /// Returns the total number of entry points across all bundles.
    pub fn total_entry_count(&self) -> usize {
        self.bundles.iter().map(|b| b.entry_points().len()).sum()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_point_fixed() {
        // Fixed segment bundle: segment 2
        let mut data = Vec::new();
        // Bundle: count=1, type=2 (fixed segment 2)
        data.push(1);
        data.push(2);
        // Entry point: flagword=0x01 (exported), offset=0x0100
        data.push(ENTRY_EXPORTED);
        data.extend_from_slice(&0x0100u16.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(&data, true);
        let bundle = EntryTableBundle::parse(&mut reader).unwrap();

        assert_eq!(bundle.count(), 1);
        assert!(!bundle.is_moveable());
        assert!(!bundle.is_constant());
        assert_eq!(bundle.bundle_type(), 2);
        assert_eq!(bundle.entry_points().len(), 1);

        let ep = &bundle.entry_points()[0];
        assert!(ep.is_exported());
        assert!(!ep.is_global());
        assert_eq!(ep.offset(), 0x0100);
        assert!(!ep.is_moveable());
    }

    #[test]
    fn test_entry_point_moveable() {
        let mut data = Vec::new();
        // Bundle: count=1, type=0xFF (moveable)
        data.push(1);
        data.push(BUNDLE_MOVEABLE);
        // Entry point: flagword=0x03 (exported+global), instruction=0x3FCD, segment=1, offset=0x0200
        data.push(ENTRY_EXPORTED | ENTRY_GLOBAL);
        data.extend_from_slice(&0x3FCDu16.to_le_bytes()); // instruction
        data.push(0x01); // segment
        data.extend_from_slice(&0x0200u16.to_le_bytes()); // offset

        let mut reader = BinaryReader::from_bytes(&data, true);
        let bundle = EntryTableBundle::parse(&mut reader).unwrap();

        assert!(bundle.is_moveable());
        assert_eq!(bundle.entry_points().len(), 1);

        let ep = &bundle.entry_points()[0];
        assert!(ep.is_moveable());
        assert!(ep.is_exported());
        assert!(ep.is_global());
        assert_eq!(ep.instruction(), 0x3FCD);
        assert_eq!(ep.segment(), 1);
        assert_eq!(ep.offset(), 0x0200);
    }

    #[test]
    fn test_entry_point_constant() {
        let mut data = Vec::new();
        data.push(1);
        data.push(BUNDLE_CONSTANT);
        data.push(0); // flags
        data.extend_from_slice(&0x0050u16.to_le_bytes()); // offset

        let mut reader = BinaryReader::from_bytes(&data, true);
        let bundle = EntryTableBundle::parse(&mut reader).unwrap();

        assert!(bundle.is_constant());
    }

    #[test]
    fn test_empty_bundle() {
        let data = vec![0u8]; // count=0
        let mut reader = BinaryReader::from_bytes(&data, true);
        let bundle = EntryTableBundle::parse(&mut reader).unwrap();

        assert_eq!(bundle.count(), 0);
        assert!(bundle.entry_points().is_empty());
    }

    #[test]
    fn test_unused_bundle() {
        let data = vec![1, 0]; // count=1, type=0 (unused)
        let mut reader = BinaryReader::from_bytes(&data, true);
        let bundle = EntryTableBundle::parse(&mut reader).unwrap();

        assert_eq!(bundle.count(), 1);
        // Type 0 is unused, so no entry points should be parsed
        assert!(bundle.entry_points().is_empty());
    }

    #[test]
    fn test_entry_table() {
        let mut data = Vec::new();

        // Bundle 1: 2 fixed entries in segment 1
        data.push(2); // count
        data.push(1); // type = segment 1
        data.push(ENTRY_EXPORTED);
        data.extend_from_slice(&0x0100u16.to_le_bytes());
        data.push(0x00);
        data.extend_from_slice(&0x0200u16.to_le_bytes());

        // Bundle 2: 1 moveable entry
        data.push(1);
        data.push(BUNDLE_MOVEABLE);
        data.push(ENTRY_EXPORTED);
        data.extend_from_slice(&0x3FCDu16.to_le_bytes());
        data.push(2);
        data.extend_from_slice(&0x0300u16.to_le_bytes());

        // Terminator
        data.push(0);

        let mut reader = BinaryReader::from_bytes(&data, true);
        let table = EntryTable::parse(&mut reader, 0, 0).unwrap();

        assert_eq!(table.bundles().len(), 2);
        assert_eq!(table.total_entry_count(), 3);
    }

    #[test]
    fn test_entry_table_empty() {
        let data = vec![0u8]; // immediate terminator
        let mut reader = BinaryReader::from_bytes(&data, true);
        let table = EntryTable::parse(&mut reader, 0, 0).unwrap();

        assert!(table.bundles().is_empty());
        assert_eq!(table.total_entry_count(), 0);
    }

    #[test]
    fn test_entry_point_display() {
        let mut data = Vec::new();
        data.push(1);
        data.push(3); // fixed segment 3
        data.push(ENTRY_EXPORTED | ENTRY_GLOBAL);
        data.extend_from_slice(&0x0100u16.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(&data, true);
        let bundle = EntryTableBundle::parse(&mut reader).unwrap();
        let ep = &bundle.entry_points()[0];

        let s = format!("{}", ep);
        assert!(s.contains("0x0100"));
        assert!(s.contains("exported=true"));
    }

    #[test]
    fn test_bundle_display() {
        let data = vec![0u8];
        let mut reader = BinaryReader::from_bytes(&data, true);
        let bundle = EntryTableBundle::parse(&mut reader).unwrap();

        let s = format!("{}", bundle);
        assert!(s.contains("count=0"));
    }
}
