//! PEF relocation base type ported from Ghidra's `Relocation.java`.
//!
//! Abstract base for PEF relocation instructions. Each relocation opcode
//! occupies a 16-bit chunk; the high 7 bits encode the opcode and the low
//! 9 bits are operand data.

use std::fmt;

/// Relocation high-order opcode values (7-bit, shifted left by 9).
///
/// Binary values indicated by "x" are don't-care operands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RelocOpcode {
    /// RelocBySectDWithSkip -- 00xxxxx
    BySectDWithSkip = 0,
    /// RelocByIndexGroup -- 0100000
    ByIndexGroup = 1,
    /// RelocIncrPosition -- 100000x
    IncrPosition = 2,
    /// RelocSmRepeat -- 1010000
    SmRepeat = 3,
    /// RelocSetPosition -- 1100000
    SetPosition = 4,
    /// RelocLgRepeat -- 1100001
    LgRepeat = 5,
    /// RelocLgSetOrBySection -- 1100010
    LgSetOrBySection = 6,
    /// RelocLgByImport -- 1100100
    LgByImport = 7,
    /// RelocValueGroup -- 1110000
    ValueGroup = 8,
    /// Undefined/unsupported opcode
    Undefined = 0xff,
}

impl RelocOpcode {
    /// Returns the numeric opcode value (0-7, or 0xff for undefined).
    pub fn value(self) -> u8 {
        self as u8
    }

    /// Decode an opcode from the high 7 bits of a 16-bit relocation chunk.
    pub fn from_chunk(chunk: u16) -> Self {
        let high7 = (chunk >> 9) as u8;
        // Match based on the high 7 bits
        if high7 & 0b1000000 == 0 {
            // 0xxxxxxx -> RelocBySectDWithSkip
            RelocOpcode::BySectDWithSkip
        } else if high7 == 0b0100000 {
            RelocOpcode::ByIndexGroup
        } else if high7 & 0b1110000 == 0b1000000 {
            RelocOpcode::IncrPosition
        } else if high7 == 0b1010000 {
            RelocOpcode::SmRepeat
        } else if high7 == 0b1100000 {
            RelocOpcode::SetPosition
        } else if high7 == 0b1100001 {
            RelocOpcode::LgRepeat
        } else if high7 == 0b1100010 {
            RelocOpcode::LgSetOrBySection
        } else if high7 == 0b1100100 {
            RelocOpcode::LgByImport
        } else if high7 == 0b1110000 {
            RelocOpcode::ValueGroup
        } else {
            RelocOpcode::Undefined
        }
    }

    /// Returns a human-readable name for this opcode.
    pub fn name(self) -> &'static str {
        match self {
            RelocOpcode::BySectDWithSkip => "RelocBySectDWithSkip",
            RelocOpcode::ByIndexGroup => "RelocByIndexGroup",
            RelocOpcode::IncrPosition => "RelocIncrPosition",
            RelocOpcode::SmRepeat => "RelocSmRepeat",
            RelocOpcode::SetPosition => "RelocSetPosition",
            RelocOpcode::LgRepeat => "RelocLgRepeat",
            RelocOpcode::LgSetOrBySection => "RelocLgSetOrBySection",
            RelocOpcode::LgByImport => "RelocLgByImport",
            RelocOpcode::ValueGroup => "RelocValueGroup",
            RelocOpcode::Undefined => "RelocUndefined",
        }
    }
}

impl fmt::Display for RelocOpcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// A parsed PEF relocation instruction.
///
/// Relocation instructions are stored in 16-bit chunks. Most instructions
/// take up one chunk combining an opcode and related operands.
#[derive(Debug, Clone)]
pub struct Relocation {
    /// The decoded opcode.
    opcode: RelocOpcode,
    /// The raw 16-bit chunk value.
    chunk: u16,
    /// Size in bytes (always 2 for base relocations; some are multi-chunk).
    size_in_bytes: u32,
    /// Repeat count for repeat-based opcodes.
    repeat_count: u32,
    /// Number of additional chunks consumed.
    repeat_chunks: u32,
}

impl Relocation {
    /// Parse a relocation from the next 2 bytes of the reader.
    ///
    /// The chunk is read in big-endian (PEF is always big-endian).
    pub fn parse(chunk: u16) -> Self {
        let opcode = RelocOpcode::from_chunk(chunk);
        let low9 = chunk & 0x01ff;

        let (repeat_count, repeat_chunks) = match opcode {
            RelocOpcode::BySectDWithSkip => {
                // skipCount is bits 8..5 (4 bits), relocCount is bits 4..0 (5 bits)
                // Both are metadata; no extra chunks consumed here.
                (0, 0)
            }
            RelocOpcode::ByIndexGroup => {
                // The low 9 bits give the count of indices minus 1
                (0, 0)
            }
            RelocOpcode::IncrPosition => {
                // skipCount in low 9 bits
                (0, 0)
            }
            RelocOpcode::SmRepeat => {
                // repeatCount in bits 8..5 (4 bits), chunkCount in bits 4..0 (5 bits)
                let repeat = ((low9 >> 5) & 0x0f) as u32;
                let chunks = (low9 & 0x1f) as u32;
                (repeat, chunks)
            }
            RelocOpcode::SetPosition => {
                // offset in low 9 bits
                (0, 0)
            }
            RelocOpcode::LgRepeat => {
                // Additional chunks follow for repeatCount and chunkCount
                (0, 2) // Two additional 16-bit values follow
            }
            RelocOpcode::LgSetOrBySection => {
                // Additional chunk follows for section index or offset
                (0, 1)
            }
            RelocOpcode::LgByImport => {
                // Additional chunk follows for import index
                (0, 1)
            }
            RelocOpcode::ValueGroup => {
                // The low 9 bits give the count minus 1
                (0, 0)
            }
            RelocOpcode::Undefined => (0, 0),
        };

        Self {
            opcode,
            chunk,
            size_in_bytes: 2,
            repeat_count,
            repeat_chunks,
        }
    }

    /// Returns the opcode for this relocation.
    pub fn opcode(&self) -> RelocOpcode {
        self.opcode
    }

    /// Returns the raw 16-bit chunk.
    pub fn chunk(&self) -> u16 {
        self.chunk
    }

    /// Returns the low 9 bits of the chunk (operand data).
    pub fn operand(&self) -> u16 {
        self.chunk & 0x01ff
    }

    /// Returns the size of this relocation instruction in bytes.
    pub fn size_in_bytes(&self) -> u32 {
        self.size_in_bytes + self.repeat_chunks * 2
    }

    /// Returns the repeat count for repeat-based opcodes.
    pub fn repeat_count(&self) -> u32 {
        self.repeat_count
    }

    /// Returns the number of additional 16-bit chunks consumed.
    pub fn repeat_chunks(&self) -> u32 {
        self.repeat_chunks
    }

    /// Returns true if the opcode is recognized (not undefined).
    pub fn is_valid(&self) -> bool {
        self.opcode != RelocOpcode::Undefined
    }

    /// Returns the skip count for RelocBySectDWithSkip.
    ///
    /// The skip count occupies bits 8..5 of the chunk (4 bits).
    pub fn skip_count(&self) -> u16 {
        (self.chunk >> 5) & 0x0f
    }

    /// Returns the reloc count for RelocBySectDWithSkip.
    ///
    /// The reloc count occupies bits 4..0 of the chunk (5 bits).
    pub fn reloc_count(&self) -> u16 {
        self.chunk & 0x1f
    }
}

impl fmt::Display for Relocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Relocation({} chunk=0x{:04x})",
            self.opcode, self.chunk
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reloc_opcode_from_chunk_sect_d_with_skip() {
        // High 7 bits: 00xxxxx (any value < 0x80 in the high byte)
        // Chunk 0x0000 -> high7 = 0x00 -> BySectDWithSkip
        assert_eq!(
            RelocOpcode::from_chunk(0x0000),
            RelocOpcode::BySectDWithSkip
        );
        // Chunk 0x00FF -> high7 = 0x00 -> BySectDWithSkip
        assert_eq!(
            RelocOpcode::from_chunk(0x00FF),
            RelocOpcode::BySectDWithSkip
        );
    }

    #[test]
    fn test_reloc_opcode_from_chunk_by_index_group() {
        // 0100000 in high 7 bits = 0x40 in bits 15..9
        // chunk = 0b0100000_xxxxxxxxx = 0x4000
        assert_eq!(
            RelocOpcode::from_chunk(0x4000),
            RelocOpcode::ByIndexGroup
        );
    }

    #[test]
    fn test_reloc_opcode_from_chunk_incr_position() {
        // 100000x -> high 7 bits start with 10, but not SmRepeat(1010000)
        // 0b1000000_xxxxxxxxx = 0x8000
        assert_eq!(
            RelocOpcode::from_chunk(0x8000),
            RelocOpcode::IncrPosition
        );
    }

    #[test]
    fn test_reloc_opcode_from_chunk_sm_repeat() {
        // 1010000 -> 0xA000
        assert_eq!(
            RelocOpcode::from_chunk(0xA000),
            RelocOpcode::SmRepeat
        );
    }

    #[test]
    fn test_reloc_opcode_from_chunk_set_position() {
        // 1100000 -> 0xC000
        assert_eq!(
            RelocOpcode::from_chunk(0xC000),
            RelocOpcode::SetPosition
        );
    }

    #[test]
    fn test_reloc_opcode_from_chunk_lg_repeat() {
        // 1100001 -> 0xC200
        assert_eq!(
            RelocOpcode::from_chunk(0xC200),
            RelocOpcode::LgRepeat
        );
    }

    #[test]
    fn test_reloc_opcode_from_chunk_lg_set_or_by_section() {
        // 1100010 -> 0xC400
        assert_eq!(
            RelocOpcode::from_chunk(0xC400),
            RelocOpcode::LgSetOrBySection
        );
    }

    #[test]
    fn test_reloc_opcode_from_chunk_lg_by_import() {
        // 1100100 -> 0xC800
        assert_eq!(
            RelocOpcode::from_chunk(0xC800),
            RelocOpcode::LgByImport
        );
    }

    #[test]
    fn test_reloc_opcode_from_chunk_value_group() {
        // 1110000 -> 0xE000
        assert_eq!(
            RelocOpcode::from_chunk(0xE000),
            RelocOpcode::ValueGroup
        );
    }

    #[test]
    fn test_relocation_parse_basic() {
        // A BySectDWithSkip with skipCount=3, relocCount=5
        // skipCount in bits 8..5 = 3 << 5 = 0x60
        // relocCount in bits 4..0 = 5
        // chunk = 0x0065
        let reloc = Relocation::parse(0x0065);
        assert_eq!(reloc.opcode(), RelocOpcode::BySectDWithSkip);
        assert_eq!(reloc.skip_count(), 3);
        assert_eq!(reloc.reloc_count(), 5);
        assert_eq!(reloc.operand(), 0x0065);
        assert!(reloc.is_valid());
    }

    #[test]
    fn test_relocation_sm_repeat() {
        // SmRepeat: high 7 = 1010000 = 0xA0
        // repeatCount in bits 8..5, chunkCount in bits 4..0
        // chunk = 0xA000 | (3 << 5) | 7 = 0xA000 | 0x60 | 0x07 = 0xA067
        let reloc = Relocation::parse(0xA067);
        assert_eq!(reloc.opcode(), RelocOpcode::SmRepeat);
        assert_eq!(reloc.repeat_count(), 3);
        assert_eq!(reloc.repeat_chunks(), 7);
    }

    #[test]
    fn test_relocation_display() {
        let reloc = Relocation::parse(0x0000);
        let s = format!("{}", reloc);
        assert!(s.contains("RelocBySectDWithSkip"));
        assert!(s.contains("0x0000"));
    }

    #[test]
    fn test_reloc_opcode_display() {
        assert_eq!(
            format!("{}", RelocOpcode::BySectDWithSkip),
            "RelocBySectDWithSkip"
        );
        assert_eq!(format!("{}", RelocOpcode::ValueGroup), "RelocValueGroup");
    }
}
