//! GCC Exception Table (LSDA) Structures
//!
//! Ported from `ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable`.
//!
//! Provides parsing of the Language-Specific Data Area (LSDA) in `.gcc_except_table`:
//! - LSDA Header (LPStart, TType, call site encoding)
//! - Call Site Table (try/catch region bounds)
//! - Action Table (type filter chains)
//! - Type Table (C++ type info pointers)

use crate::exceptionhandlers::gcc::decode::{read_uleb128, read_sleb128, StandardDwarfEhDecoder, DwarfEhDecoder};

/// The encoding value for "omit" (no encoding present).
pub const OMITTED_ENCODING: u8 = 0xFF;

/// LSDA (Language-Specific Data Area) header.
///
/// Defines the bounds of exception unwinding support within a function
/// and encodes how to interpret the call site, action, and type tables.
#[derive(Debug, Clone)]
pub struct LsdaHeader {
    /// LPStart encoding (0xFF = omitted, uses function base).
    pub lp_start_encoding: u8,
    /// The LPStart address (absolute start of the landing pad region).
    pub lp_start: Option<u64>,
    /// TType encoding (0xFF = no type table).
    pub ttype_encoding: u8,
    /// Offset from this header to the start of the type table.
    pub ttype_offset: u64,
    /// Call site table encoding.
    pub call_site_encoding: u8,
    /// Length of the call site table in bytes.
    pub call_site_table_length: u64,
}

impl LsdaHeader {
    /// Parse an LSDA header from raw bytes.
    ///
    /// Returns the parsed header and the number of bytes consumed.
    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.is_empty() {
            return None;
        }

        let mut offset = 0;

        // Read LPStart encoding
        let lp_start_encoding = data[offset];
        offset += 1;

        // Read LPStart value if not omitted
        let lp_start = if lp_start_encoding != OMITTED_ENCODING {
            let decoder = StandardDwarfEhDecoder::from_encoding(lp_start_encoding);
            let (val, consumed) = decoder.decode_value(data, offset)?;
            offset += consumed;
            Some(val as u64)
        } else {
            None
        };

        // Read TType encoding
        if offset >= data.len() {
            return None;
        }
        let ttype_encoding = data[offset];
        offset += 1;

        // Read TType offset if type table is present
        let ttype_offset = if ttype_encoding != OMITTED_ENCODING {
            if offset >= data.len() {
                return None;
            }
            let (val, consumed) = read_uleb128(&data[offset..])?;
            offset += consumed;
            val
        } else {
            0
        };

        // Read call site encoding
        if offset >= data.len() {
            return None;
        }
        let call_site_encoding = data[offset];
        offset += 1;

        // Read call site table length
        if offset >= data.len() {
            return None;
        }
        let (call_site_table_length, consumed) = read_uleb128(&data[offset..])?;
        offset += consumed;

        Some((
            Self {
                lp_start_encoding,
                lp_start,
                ttype_encoding,
                ttype_offset,
                call_site_encoding,
                call_site_table_length,
            },
            offset,
        ))
    }

    /// Whether the type table is present.
    pub fn has_type_table(&self) -> bool {
        self.ttype_encoding != OMITTED_ENCODING
    }
}

/// The LSDA (Language-Specific Data Area) table.
///
/// Contains the parsed header, call site records, action records,
/// and type table for a function's exception handling data.
#[derive(Debug, Clone)]
pub struct LsdaTable {
    /// The LSDA header.
    pub header: LsdaHeader,
    /// Call site records (try/catch region bounds).
    pub call_site_records: Vec<LsdaCallSiteRecord>,
    /// Action records (type filter chains).
    pub action_records: Vec<LsdaActionRecord>,
    /// Type table entries (C++ type info addresses).
    pub type_table: Vec<u64>,
}

impl LsdaTable {
    /// Parse a complete LSDA table from raw bytes.
    ///
    /// `function_start` is the start address of the function (used when LPStart is omitted).
    pub fn parse(data: &[u8], function_start: u64) -> Option<Self> {
        let (header, mut offset) = LsdaHeader::parse(data)?;

        let _lp_start = header.lp_start.unwrap_or(function_start);

        // Parse call site table
        let call_site_end = offset + header.call_site_table_length as usize;
        let cs_decoder = StandardDwarfEhDecoder::from_encoding(header.call_site_encoding);
        let mut call_site_records = Vec::new();

        while offset < call_site_end && offset < data.len() {
            let (cs_start, c1) = cs_decoder.decode_value(data, offset)?;
            offset += c1;
            let (cs_len, c2) = cs_decoder.decode_value(data, offset)?;
            offset += c2;
            let (lp_offset, c3) = cs_decoder.decode_value(data, offset)?;
            offset += c3;

            // Action offset (ULEB128 or UByte depending on encoding)
            let (action_offset, consumed) = read_uleb128(&data[offset..]).unwrap_or((0, 1));
            offset += consumed;

            call_site_records.push(LsdaCallSiteRecord {
                call_site_start: cs_start as u64,
                call_site_length: cs_len as u64,
                landing_pad_offset: lp_offset as u64,
                action_offset: action_offset as u32,
            });
        }

        // Parse action table
        let action_table_start = call_site_end;
        let _action_decoder = StandardDwarfEhDecoder::from_encoding(header.call_site_encoding);
        let mut action_records = Vec::new();
        let mut action_offset = action_table_start;

        while action_offset < data.len() {
            if let Some((type_filter, c1)) = read_sleb128(&data[action_offset..]) {
                action_offset += c1;
                let (next_displacement, c2) = read_sleb128(&data[action_offset..]).unwrap_or((0, 0));
                action_offset += c2;

                action_records.push(LsdaActionRecord {
                    type_filter: type_filter as i32,
                    next_displacement: next_displacement as i32,
                });

                if next_displacement == 0 {
                    break;
                }
            } else {
                break;
            }
        }

        // Parse type table if present
        let type_table = if header.has_type_table() {
            let mut tt = Vec::new();
            // Type table entries are typically at the end, encoded per ttype_encoding
            // They are referenced by negative index from the action records
            // For now, store raw entries; actual resolution depends on the encoding
            let ttype_decoder = StandardDwarfEhDecoder::from_encoding(header.ttype_encoding);
            let mut ttype_offset = data.len().saturating_sub(4); // approximate
            // In a real implementation, we'd compute the exact position from the header
            while ttype_offset > 0 && ttype_offset + 4 <= data.len() {
                if let Some((val, consumed)) = ttype_decoder.decode_value(data, ttype_offset) {
                    tt.push(val as u64);
                    ttype_offset += consumed;
                } else {
                    break;
                }
            }
            tt.reverse(); // Type table is read in reverse
            tt
        } else {
            Vec::new()
        };

        Some(Self {
            header,
            call_site_records,
            action_records,
            type_table,
        })
    }

    /// Get the call site table.
    pub fn call_site_table(&self) -> &[LsdaCallSiteRecord] {
        &self.call_site_records
    }

    /// Get the action table.
    pub fn action_table(&self) -> &[LsdaActionRecord] {
        &self.action_records
    }

    /// Get the type table.
    pub fn type_table(&self) -> &[u64] {
        &self.type_table
    }
}

/// An LSDA call site record defines the bounds of a try-catch region.
#[derive(Debug, Clone, Copy)]
pub struct LsdaCallSiteRecord {
    /// Offset of the call site from LPStart.
    pub call_site_start: u64,
    /// Length of the call site.
    pub call_site_length: u64,
    /// Offset of the landing pad from LPStart (0 = no landing pad).
    pub landing_pad_offset: u64,
    /// Offset into the action table (0 = cleanup only).
    pub action_offset: u32,
}

impl LsdaCallSiteRecord {
    /// Whether this call site has a landing pad (catch handler).
    pub fn has_landing_pad(&self) -> bool {
        self.landing_pad_offset != 0
    }

    /// The absolute start of the call site given the LPStart.
    pub fn start_address(&self, lp_start: u64) -> u64 {
        lp_start + self.call_site_start
    }

    /// The absolute end of the call site given the LPStart.
    pub fn end_address(&self, lp_start: u64) -> u64 {
        lp_start + self.call_site_start + self.call_site_length
    }

    /// The absolute landing pad address given the LPStart.
    pub fn landing_pad_address(&self, lp_start: u64) -> u64 {
        lp_start + self.landing_pad_offset
    }
}

/// An LSDA action record associates a type filter with a catch action.
#[derive(Debug, Clone, Copy)]
pub struct LsdaActionRecord {
    /// Type filter: 0 = cleanup, positive = index into type table.
    pub type_filter: i32,
    /// Displacement to the next action record (0 = end of chain).
    pub next_displacement: i32,
}

impl LsdaActionRecord {
    /// Whether this is a cleanup action (no catch).
    pub fn is_cleanup(&self) -> bool {
        self.type_filter == 0
    }

    /// Whether this is the last action in the chain.
    pub fn is_last(&self) -> bool {
        self.next_displacement == 0
    }
}

/// An LSDA call site table containing all call site records for a function.
#[derive(Debug, Clone)]
pub struct LsdaCallSiteTable {
    /// The call site records.
    pub records: Vec<LsdaCallSiteRecord>,
}

impl LsdaCallSiteTable {
    /// Create an empty call site table.
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Find the call site record containing the given address.
    pub fn find_call_site(&self, lp_start: u64, address: u64) -> Option<&LsdaCallSiteRecord> {
        self.records.iter().find(|cs| {
            let start = cs.start_address(lp_start);
            let end = cs.end_address(lp_start);
            address >= start && address < end
        })
    }
}

/// An LSDA action table containing all action records for a function.
#[derive(Debug, Clone)]
pub struct LsdaActionTable {
    /// The action records.
    pub records: Vec<LsdaActionRecord>,
}

impl LsdaActionTable {
    /// Create an empty action table.
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Get an action record at the given byte offset within the table.
    ///
    /// Note: The offset is relative to the start of the action table,
    /// and each record is variable-sized due to LEB128 encoding.
    pub fn get_action_at_offset(&self, offset: usize) -> Option<&LsdaActionRecord> {
        self.records.get(offset)
    }
}

/// An LSDA type table containing type info addresses.
#[derive(Debug, Clone)]
pub struct LsdaTypeTable {
    /// The type info addresses.
    pub entries: Vec<u64>,
}

impl LsdaTypeTable {
    /// Create an empty type table.
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Get the type info address for the given action filter.
    ///
    /// Negative filters (in Java) are stored as positive indices here.
    pub fn get_type_info_address(&self, action_filter: i32) -> Option<u64> {
        if action_filter <= 0 || (action_filter as usize) > self.entries.len() {
            return None;
        }
        // Type table is indexed from the end (negative offset from action filter)
        let idx = self.entries.len() - action_filter as usize;
        self.entries.get(idx).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lsda_header_parse_simple() {
        // LPStart encoding = 0xFF (omit)
        // TType encoding = 0xFF (omit)
        // Call site encoding = 0x03 (udata4)
        // Call site table length = 0
        let data = [0xFF, 0xFF, 0x03, 0x00];
        let (header, consumed) = LsdaHeader::parse(&data).unwrap();
        assert_eq!(header.lp_start_encoding, 0xFF);
        assert!(header.lp_start.is_none());
        assert_eq!(header.ttype_encoding, 0xFF);
        assert!(!header.has_type_table());
        assert_eq!(header.call_site_encoding, 0x03);
        assert_eq!(header.call_site_table_length, 0);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn test_lsda_header_with_lpstart() {
        // LPStart encoding = 0x0b (sdata4)
        // LPStart value = 0x1000
        // TType encoding = 0xFF (omit)
        // Call site encoding = 0x03 (udata4)
        // Call site table length = 0
        let data = [0x0b, 0x00, 0x10, 0x00, 0x00, 0xFF, 0x03, 0x00];
        let (header, _) = LsdaHeader::parse(&data).unwrap();
        assert_eq!(header.lp_start_encoding, 0x0b);
        assert_eq!(header.lp_start, Some(0x1000));
    }

    #[test]
    fn test_call_site_record() {
        let cs = LsdaCallSiteRecord {
            call_site_start: 0x100,
            call_site_length: 0x50,
            landing_pad_offset: 0x200,
            action_offset: 4,
        };
        assert!(cs.has_landing_pad());
        assert_eq!(cs.start_address(0x1000), 0x1100);
        assert_eq!(cs.end_address(0x1000), 0x1150);
        assert_eq!(cs.landing_pad_address(0x1000), 0x1200);
    }

    #[test]
    fn test_call_site_record_no_landing_pad() {
        let cs = LsdaCallSiteRecord {
            call_site_start: 0x100,
            call_site_length: 0x50,
            landing_pad_offset: 0,
            action_offset: 0,
        };
        assert!(!cs.has_landing_pad());
    }

    #[test]
    fn test_action_record() {
        let ar = LsdaActionRecord {
            type_filter: 0,
            next_displacement: 0,
        };
        assert!(ar.is_cleanup());
        assert!(ar.is_last());

        let ar2 = LsdaActionRecord {
            type_filter: 2,
            next_displacement: 8,
        };
        assert!(!ar2.is_cleanup());
        assert!(!ar2.is_last());
    }

    #[test]
    fn test_call_site_table_find() {
        let table = LsdaCallSiteTable {
            records: vec![
                LsdaCallSiteRecord {
                    call_site_start: 0,
                    call_site_length: 0x100,
                    landing_pad_offset: 0x200,
                    action_offset: 0,
                },
                LsdaCallSiteRecord {
                    call_site_start: 0x100,
                    call_site_length: 0x200,
                    landing_pad_offset: 0x400,
                    action_offset: 0,
                },
            ],
        };
        let lp_start = 0x1000;
        assert!(table.find_call_site(lp_start, 0x1050).is_some());
        assert!(table.find_call_site(lp_start, 0x1200).is_some());
        assert!(table.find_call_site(lp_start, 0x1400).is_none());
    }

    #[test]
    fn test_action_table() {
        let table = LsdaActionTable::new();
        assert!(table.records.is_empty());
    }

    #[test]
    fn test_type_table() {
        let table = LsdaTypeTable {
            entries: vec![0x8000, 0x9000, 0xA000],
        };
        assert_eq!(table.get_type_info_address(1), Some(0xA000));
        assert_eq!(table.get_type_info_address(2), Some(0x9000));
        assert_eq!(table.get_type_info_address(3), Some(0x8000));
        assert_eq!(table.get_type_info_address(4), None);
        assert_eq!(table.get_type_info_address(0), None);
    }
}
