//! Intel HEX format parser and writer.
//!
//! Ported from Ghidra's `ghidra.app.util.opinion.IntelHexRecord`,
//! `IntelHexRecordReader`, `IntelHexRecordWriter`, and `IntelHexMemImage`.
//!
//! The Intel HEX format is a text-based file format for conveying binary
//! program data to be burned into ROM/flash memory. Each line is an ASCII
//! text record beginning with a colon (`:`) and containing hex-encoded bytes.
//!
//! References:
//! - Intel HEX format specification (Wikipedia)
//! - <https://en.wikipedia.org/wiki/Intel_HEX>

use std::collections::BTreeMap;
use std::fmt;

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// Maximum data bytes per record (255).
pub const MAX_RECORD_LENGTH: usize = 255;

/// Data record: contains data bytes and their 16-bit address.
pub const DATA_RECORD_TYPE: u8 = 0x00;
/// End-of-file record: marks the end of the hex file.
pub const END_OF_FILE_RECORD_TYPE: u8 = 0x01;
/// Extended segment address record: sets the upper 16 bits of the segment address.
pub const EXTENDED_SEGMENT_ADDRESS_RECORD_TYPE: u8 = 0x02;
/// Start segment address record: sets the CS:IP register pair.
pub const START_SEGMENT_ADDRESS_RECORD_TYPE: u8 = 0x03;
/// Extended linear address record: sets the upper 16 bits of a 32-bit address.
pub const EXTENDED_LINEAR_ADDRESS_RECORD_TYPE: u8 = 0x04;
/// Start linear address record: sets the EIP register (32-bit entry point).
pub const START_LINEAR_ADDRESS_RECORD_TYPE: u8 = 0x05;

// ═══════════════════════════════════════════════════════════════════════════════════
// Error Types
// ═══════════════════════════════════════════════════════════════════════════════════

/// Errors encountered while parsing Intel HEX records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntelHexError {
    /// Line is too short to contain a valid record.
    LineTooShort,
    /// Line does not start with the record mark (`:`).
    MissingRecordMark,
    /// Error parsing the record length field.
    InvalidRecordLength(String),
    /// Error parsing the load offset field.
    InvalidLoadOffset(String),
    /// Error parsing the record type field.
    InvalidRecordType(String),
    /// Error parsing the data bytes.
    InvalidDataByte(String),
    /// Error parsing the checksum field.
    InvalidChecksum(String),
    /// Line length is inconsistent with the declared record length.
    InconsistentLineLength {
        expected: usize,
        actual: usize,
    },
    /// Record length exceeds the maximum allowed.
    RecordTooLong(usize),
    /// Record length does not match the data array length.
    LengthMismatch {
        declared: usize,
        actual: usize,
    },
    /// Load offset is out of range (must be 0..=0xFFFF).
    LoadOffsetOutOfRange(u32),
    /// Invalid record type value.
    UnknownRecordType(u8),
    /// Validation error for a specific record type.
    ValidationError(String),
    /// Checksum mismatch.
    ChecksumMismatch {
        reported: u8,
        actual: u8,
    },
    /// Hex parsing error.
    ParseHexError(String),
}

impl fmt::Display for IntelHexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LineTooShort => write!(f, "line too short to contain record"),
            Self::MissingRecordMark => write!(f, "line does not start with record mark (:)"),
            Self::InvalidRecordLength(s) => write!(f, "error parsing record length: {s}"),
            Self::InvalidLoadOffset(s) => write!(f, "error parsing load offset: {s}"),
            Self::InvalidRecordType(s) => write!(f, "error parsing record type: {s}"),
            Self::InvalidDataByte(s) => write!(f, "error parsing data byte: {s}"),
            Self::InvalidChecksum(s) => write!(f, "error parsing checksum: {s}"),
            Self::InconsistentLineLength { expected, actual } => {
                write!(
                    f,
                    "line invalid length to contain record with record length {expected} (got {actual})"
                )
            }
            Self::RecordTooLong(len) => write!(f, "recordLength > {MAX_RECORD_LENGTH} (got {len})"),
            Self::LengthMismatch { declared, actual } => {
                write!(f, "recordLength ({declared}) != data.length ({actual})")
            }
            Self::LoadOffsetOutOfRange(off) => write!(f, "loadOffset out of range: 0x{off:04X}"),
            Self::UnknownRecordType(t) => write!(f, "illegal record type: 0x{t:02X}"),
            Self::ValidationError(s) => write!(f, "{s}"),
            Self::ChecksumMismatch { reported, actual } => {
                write!(
                    f,
                    "checksum mismatch: reported 0x{reported:02X}, actual 0x{actual:02X}"
                )
            }
            Self::ParseHexError(s) => write!(f, "hex parse error: {s}"),
        }
    }
}

impl std::error::Error for IntelHexError {}

// ═══════════════════════════════════════════════════════════════════════════════════
// IntelHexRecord
// ═══════════════════════════════════════════════════════════════════════════════════

/// A single Intel HEX record (one line of an `.hex` file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntelHexRecord {
    /// Number of data bytes in this record.
    pub record_length: u8,
    /// Load offset (16-bit address for data records).
    pub load_offset: u16,
    /// Record type (0x00..=0x05).
    pub record_type: u8,
    /// Data bytes.
    pub data: Vec<u8>,
    /// Checksum as reported in the file.
    pub checksum: u8,
    /// Checksum computed from the record fields.
    pub actual_checksum: u8,
}

impl IntelHexRecord {
    /// Create a new record (for writing). Computes the checksum automatically.
    pub fn new(record_length: u8, load_offset: u16, record_type: u8, data: Vec<u8>) -> Self {
        let actual_checksum = Self::compute_checksum(record_length, load_offset, record_type, &data);
        Self {
            record_length,
            load_offset,
            record_type,
            data,
            checksum: actual_checksum,
            actual_checksum,
        }
    }

    /// Create a record from parsed fields (for reading). Validates the record.
    pub fn from_fields(
        record_length: u8,
        load_offset: u16,
        record_type: u8,
        data: Vec<u8>,
        checksum: u8,
    ) -> Result<Self, IntelHexError> {
        let actual_checksum =
            Self::compute_checksum(record_length, load_offset, record_type, &data);
        let record = Self {
            record_length,
            load_offset,
            record_type,
            data,
            checksum,
            actual_checksum,
        };
        record.validate()?;
        Ok(record)
    }

    /// Compute the two's complement checksum for the given fields.
    fn compute_checksum(record_length: u8, load_offset: u16, record_type: u8, data: &[u8]) -> u8 {
        let mut accum: u32 = 0;
        accum += record_length as u32;
        accum += (load_offset & 0xFF) as u32;
        accum += ((load_offset >> 8) & 0xFF) as u32;
        accum += record_type as u32;
        for &b in data {
            accum += b as u32;
        }
        let lowest = (accum & 0xFF) as u8;
        (0u8.wrapping_sub(lowest))
    }

    /// Validate the record fields against the specification.
    fn validate(&self) -> Result<(), IntelHexError> {
        // Check record length matches data
        if self.record_length as usize != self.data.len() {
            return Err(IntelHexError::LengthMismatch {
                declared: self.record_length as usize,
                actual: self.data.len(),
            });
        }
        if self.record_length as usize > MAX_RECORD_LENGTH {
            return Err(IntelHexError::RecordTooLong(self.record_length as usize));
        }
        // Check load offset range
        if self.load_offset > 0xFFFF {
            return Err(IntelHexError::LoadOffsetOutOfRange(self.load_offset as u32));
        }
        // Check record type specific constraints
        match self.record_type {
            DATA_RECORD_TYPE => {} // no special constraints
            END_OF_FILE_RECORD_TYPE => {
                if self.record_length != 0 {
                    return Err(IntelHexError::ValidationError(format!(
                        "bad length ({}) for End Of File Record",
                        self.record_length
                    )));
                }
                if self.load_offset != 0 {
                    return Err(IntelHexError::ValidationError(format!(
                        "bad load offset (0x{:04X}) for End Of File Record",
                        self.load_offset
                    )));
                }
            }
            EXTENDED_SEGMENT_ADDRESS_RECORD_TYPE => {
                if self.record_length != 2 {
                    return Err(IntelHexError::ValidationError(format!(
                        "bad length ({}) for Extended Segment Address Record",
                        self.record_length
                    )));
                }
                if self.load_offset != 0 {
                    return Err(IntelHexError::ValidationError(format!(
                        "bad load offset (0x{:04X}) for Extended Segment Address Record",
                        self.load_offset
                    )));
                }
            }
            START_SEGMENT_ADDRESS_RECORD_TYPE => {
                if self.record_length != 4 {
                    return Err(IntelHexError::ValidationError(format!(
                        "bad length ({}) for Start Segment Address Record",
                        self.record_length
                    )));
                }
                if self.load_offset != 0 {
                    return Err(IntelHexError::ValidationError(format!(
                        "bad load offset (0x{:04X}) for Start Segment Address Record",
                        self.load_offset
                    )));
                }
            }
            EXTENDED_LINEAR_ADDRESS_RECORD_TYPE => {
                if self.record_length != 2 {
                    return Err(IntelHexError::ValidationError(format!(
                        "bad length ({}) for Extended Linear Address Record",
                        self.record_length
                    )));
                }
                if self.load_offset != 0 {
                    return Err(IntelHexError::ValidationError(format!(
                        "bad load offset (0x{:04X}) for Extended Linear Address Record",
                        self.load_offset
                    )));
                }
            }
            START_LINEAR_ADDRESS_RECORD_TYPE => {
                if self.record_length != 4 {
                    return Err(IntelHexError::ValidationError(format!(
                        "bad length ({}) for Start Linear Address Record",
                        self.record_length
                    )));
                }
                if self.load_offset != 0 {
                    return Err(IntelHexError::ValidationError(format!(
                        "bad load offset (0x{:04X}) for Start Linear Address Record",
                        self.load_offset
                    )));
                }
            }
            other => return Err(IntelHexError::UnknownRecordType(other)),
        }
        Ok(())
    }

    /// Whether the reported checksum matches the actual checksum.
    pub fn is_checksum_correct(&self) -> bool {
        self.checksum == self.actual_checksum
    }

    /// Format the record as an Intel HEX text line (e.g., `:0300300002337A1E`).
    pub fn format(&self) -> String {
        let mut s = format!(
            ":{:02X}{:04X}{:02X}",
            self.record_length, self.load_offset, self.record_type
        );
        for &b in &self.data {
            s.push_str(&format!("{b:02X}"));
        }
        s.push_str(&format!("{:02X}", self.actual_checksum));
        s
    }

    /// Return the data bytes as a hex string.
    pub fn data_hex_string(&self) -> String {
        self.data.iter().map(|b| format!("{b:02X}")).collect()
    }

    /// Return the record type name.
    pub fn type_name(&self) -> &'static str {
        match self.record_type {
            DATA_RECORD_TYPE => "Data",
            END_OF_FILE_RECORD_TYPE => "EndOfFile",
            EXTENDED_SEGMENT_ADDRESS_RECORD_TYPE => "ExtendedSegmentAddress",
            START_SEGMENT_ADDRESS_RECORD_TYPE => "StartSegmentAddress",
            EXTENDED_LINEAR_ADDRESS_RECORD_TYPE => "ExtendedLinearAddress",
            START_LINEAR_ADDRESS_RECORD_TYPE => "StartLinearAddress",
            _ => "Unknown",
        }
    }
}

impl fmt::Display for IntelHexRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// IntelHexRecordReader
// ═══════════════════════════════════════════════════════════════════════════════════

/// Parse a single Intel HEX record from a text line.
///
/// The line must start with `:` and contain hex-encoded bytes.
pub fn parse_record(line: &str) -> Result<IntelHexRecord, IntelHexError> {
    let line = line.trim();
    if line.len() < 11 {
        // minimum: `:00000001FF` (11 chars)
        return Err(IntelHexError::LineTooShort);
    }
    if !line.starts_with(':') {
        return Err(IntelHexError::MissingRecordMark);
    }

    let hex = &line[1..]; // skip the ':'

    let record_length = parse_hex_byte(hex, 0, 2)
        .map_err(|e| IntelHexError::InvalidRecordLength(e.to_string()))? as usize;
    let load_offset = parse_hex_u16(hex, 2, 6)
        .map_err(|e| IntelHexError::InvalidLoadOffset(e.to_string()))?;
    let record_type = parse_hex_byte(hex, 6, 8)
        .map_err(|e| IntelHexError::InvalidRecordType(e.to_string()))?;

    let data_start = 8;
    let data_end = data_start + record_length * 2;
    let checksum_start = data_end;
    let checksum_end = checksum_start + 2;

    if hex.len() != checksum_end {
        return Err(IntelHexError::InconsistentLineLength {
            expected: checksum_end,
            actual: hex.len(),
        });
    }

    let data = parse_hex_bytes(&hex[data_start..data_end])
        .map_err(|e| IntelHexError::InvalidDataByte(e.to_string()))?;
    let checksum = parse_hex_byte(hex, checksum_start, checksum_end)
        .map_err(|e| IntelHexError::InvalidChecksum(e.to_string()))?;

    IntelHexRecord::from_fields(record_length as u8, load_offset, record_type, data, checksum)
}

/// Parse all records from a multi-line Intel HEX file.
pub fn parse_records(text: &str) -> Vec<Result<IntelHexRecord, IntelHexError>> {
    text.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(parse_record)
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════════════
// IntelHexRecordWriter
// ═══════════════════════════════════════════════════════════════════════════════════

/// Writer for Intel HEX records.
///
/// Accumulates bytes at sequential addresses and emits records when the
/// segment changes or the line buffer is full.
pub struct IntelHexRecordWriter {
    max_bytes_per_line: usize,
    drop_extra_bytes: bool,
    /// Current base address for extended address records.
    current_base: u32,
    /// Whether we have emitted an extended address record.
    base_set: bool,
    /// Buffered bytes for the current data record.
    buffer: Vec<u8>,
    /// Load offset of the first byte in the buffer.
    buffer_offset: u16,
    /// All emitted records.
    records: Vec<IntelHexRecord>,
    /// Whether finish() has been called.
    done: bool,
}

impl IntelHexRecordWriter {
    /// Create a new writer.
    ///
    /// `max_bytes_per_line` must be <= 255. If `drop_extra_bytes` is true,
    /// trailing bytes that don't fill a complete line are discarded.
    pub fn new(max_bytes_per_line: usize, drop_extra_bytes: bool) -> Self {
        assert!(
            max_bytes_per_line <= MAX_RECORD_LENGTH,
            "max_bytes_per_line must be <= {MAX_RECORD_LENGTH}"
        );
        Self {
            max_bytes_per_line,
            drop_extra_bytes,
            current_base: 0,
            base_set: false,
            buffer: Vec::new(),
            buffer_offset: 0,
            records: Vec::new(),
            done: false,
        }
    }

    /// Add a single byte at the given absolute address.
    pub fn add_byte(&mut self, address: u32, byte: u8) {
        assert!(!self.done, "cannot add_byte() after finish()");

        let offset = address & 0x0000_FFFF;
        let segment = address & 0xFFFF_0000;

        // Emit extended address record if the segment changed.
        if !self.base_set || segment != self.current_base {
            self.flush_buffer();
            let data = [(segment >> 24) as u8, (segment >> 16) as u8];
            self.records.push(IntelHexRecord::new(
                2,
                0,
                EXTENDED_LINEAR_ADDRESS_RECORD_TYPE,
                data.to_vec(),
            ));
            self.current_base = segment;
            self.base_set = true;
        }

        if self.buffer.is_empty() {
            self.buffer_offset = offset as u16;
        }

        self.buffer.push(byte);

        if self.buffer.len() >= self.max_bytes_per_line {
            self.flush_buffer();
        }
    }

    /// Add multiple bytes starting at the given address.
    pub fn add_bytes(&mut self, address: u32, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            self.add_byte(address + i as u32, b);
        }
    }

    /// Flush the current buffer to a data record.
    fn flush_buffer(&mut self) {
        if !self.buffer.is_empty() {
            let data = self.buffer.clone();
            self.records.push(IntelHexRecord::new(
                data.len() as u8,
                self.buffer_offset,
                DATA_RECORD_TYPE,
                data,
            ));
            self.buffer.clear();
        }
    }

    /// Finalize the hex file with an optional entry point address.
    ///
    /// Returns all emitted records including the end-of-file record.
    pub fn finish(&mut self, entry_point: Option<u32>) -> &[IntelHexRecord] {
        if !self.done {
            // Flush remaining bytes
            if !self.buffer.is_empty() && !self.drop_extra_bytes {
                self.flush_buffer();
            }

            // Emit start address record if entry point is provided
            if let Some(ep) = entry_point {
                let data = [
                    (ep >> 24) as u8,
                    (ep >> 16) as u8,
                    (ep >> 8) as u8,
                    (ep & 0xFF) as u8,
                ];
                self.records.push(IntelHexRecord::new(
                    4,
                    0,
                    START_LINEAR_ADDRESS_RECORD_TYPE,
                    data.to_vec(),
                ));
            }

            // End-of-file record
            self.records.push(IntelHexRecord::new(
                0,
                0,
                END_OF_FILE_RECORD_TYPE,
                Vec::new(),
            ));

            self.done = true;
        }
        &self.records
    }

    /// Format all records as a complete Intel HEX file string.
    pub fn to_hex_string(&mut self, entry_point: Option<u32>) -> String {
        let records = self.finish(entry_point);
        records
            .iter()
            .map(|r| r.format())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// IntelHexMemImage
// ═══════════════════════════════════════════════════════════════════════════════════

/// Memory image built from parsing Intel HEX records.
///
/// Accumulates data bytes from records into contiguous memory blocks,
/// handling extended address records and segment address records.
#[derive(Debug, Clone)]
pub struct IntelHexMemImage {
    /// Base address (updated by extended address records).
    base: u64,
    /// Memory blocks: sorted map from start address to data bytes.
    blocks: BTreeMap<u64, Vec<u8>>,
    /// Entry point EIP (from start linear address record).
    start_eip: Option<u64>,
    /// Entry point CS (from start segment address record).
    start_cs: Option<u16>,
    /// Entry point IP (from start segment address record).
    start_ip: Option<u16>,
    /// Warnings accumulated during parsing.
    warnings: Vec<String>,
}

impl IntelHexMemImage {
    /// Create a new empty memory image.
    pub fn new() -> Self {
        Self {
            base: 0,
            blocks: BTreeMap::new(),
            start_eip: None,
            start_cs: None,
            start_ip: None,
            warnings: Vec::new(),
        }
    }

    /// Parse a single record and update the memory image.
    pub fn add_record(&mut self, record: &IntelHexRecord) {
        if !record.is_checksum_correct() {
            self.warnings.push(format!(
                "checksum mismatch: reported 0x{:02X}, actual 0x{:02X}",
                record.checksum, record.actual_checksum
            ));
        }

        let load_offset = record.load_offset as u64;

        match record.record_type {
            DATA_RECORD_TYPE => {
                let addr = self.base + load_offset;
                self.blocks
                    .entry(addr)
                    .or_default()
                    .extend_from_slice(&record.data);
            }
            END_OF_FILE_RECORD_TYPE => {
                // Nothing to do
            }
            EXTENDED_SEGMENT_ADDRESS_RECORD_TYPE => {
                if record.data.len() >= 2 {
                    let seg = ((record.data[0] as u64) << 8) | (record.data[1] as u64);
                    self.base = seg << 4;
                }
            }
            EXTENDED_LINEAR_ADDRESS_RECORD_TYPE => {
                if record.data.len() >= 2 {
                    let high = ((record.data[0] as u64) << 24) | ((record.data[1] as u64) << 16);
                    self.base = high;
                }
            }
            START_SEGMENT_ADDRESS_RECORD_TYPE => {
                if record.data.len() >= 4 {
                    self.start_cs = Some(((record.data[0] as u16) << 8) | (record.data[1] as u16));
                    self.start_ip = Some(((record.data[2] as u16) << 8) | (record.data[3] as u16));
                }
            }
            START_LINEAR_ADDRESS_RECORD_TYPE => {
                if record.data.len() >= 4 {
                    self.start_eip = Some(
                        ((record.data[0] as u64) << 24)
                            | ((record.data[1] as u64) << 16)
                            | ((record.data[2] as u64) << 8)
                            | (record.data[3] as u64),
                    );
                }
            }
            _ => {}
        }
    }

    /// Parse all records from a hex file text.
    pub fn parse(&mut self, text: &str) {
        for result in parse_records(text) {
            match result {
                Ok(record) => self.add_record(&record),
                Err(e) => self.warnings.push(format!("parse error: {e}")),
            }
        }
    }

    /// Return the entry point EIP (from start linear address record).
    pub fn start_eip(&self) -> Option<u64> {
        self.start_eip
    }

    /// Return the entry point CS:IP (from start segment address record).
    pub fn start_cs_ip(&self) -> Option<(u16, u16)> {
        match (self.start_cs, self.start_ip) {
            (Some(cs), Some(ip)) => Some((cs, ip)),
            _ => None,
        }
    }

    /// Return accumulated warnings.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Return the memory blocks as a sorted map of address -> data.
    pub fn blocks(&self) -> &BTreeMap<u64, Vec<u8>> {
        &self.blocks
    }

    /// Merge overlapping or contiguous blocks into the minimal set.
    pub fn merge_blocks(&self) -> BTreeMap<u64, Vec<u8>> {
        let mut merged: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        for (&addr, data) in &self.blocks {
            if let Some((&prev_addr, prev_data)) = merged.last_key_value() {
                let prev_end = prev_addr + prev_data.len() as u64;
                if addr <= prev_end {
                    // Merge into previous block
                    let entry = merged.get_mut(&prev_addr).unwrap();
                    if addr + data.len() as u64 > prev_end {
                        let overlap = (addr - prev_addr) as usize;
                        entry.extend_from_slice(&data[prev_end.saturating_sub(addr) as usize..]);
                        // Actually we need to handle overlapping properly
                        let needed = (addr + data.len() as u64 - prev_addr) as usize;
                        if needed > entry.len() {
                            entry.resize(needed, 0);
                        }
                        let offset = (addr - prev_addr) as usize;
                        for (i, &b) in data.iter().enumerate() {
                            if offset + i < entry.len() {
                                entry[offset + i] = b;
                            }
                        }
                    }
                    continue;
                }
            }
            merged.insert(addr, data.clone());
        }
        merged
    }

    /// Return the total number of data bytes across all blocks.
    pub fn total_bytes(&self) -> usize {
        self.blocks.values().map(|v| v.len()).sum()
    }
}

impl Default for IntelHexMemImage {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Utility: hex parsing helpers
// ═══════════════════════════════════════════════════════════════════════════════════

fn parse_hex_byte(s: &str, start: usize, end: usize) -> Result<u8, String> {
    u8::from_str_radix(&s[start..end], 16).map_err(|e| e.to_string())
}

fn parse_hex_u16(s: &str, start: usize, end: usize) -> Result<u16, String> {
    u16::from_str_radix(&s[start..end], 16).map_err(|e| e.to_string())
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("data string of odd length".to_string());
    }
    let mut result = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let b = u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string())?;
        result.push(b);
    }
    Ok(result)
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_data_record() {
        // :0300300002337A1E
        // length=3, offset=0x0030, type=0x00 (data), data=02 33 7A, checksum=1E
        let record = parse_record(":0300300002337A1E").unwrap();
        assert_eq!(record.record_length, 3);
        assert_eq!(record.load_offset, 0x0030);
        assert_eq!(record.record_type, DATA_RECORD_TYPE);
        assert_eq!(record.data, vec![0x02, 0x33, 0x7A]);
        assert!(record.is_checksum_correct());
    }

    #[test]
    fn test_parse_eof_record() {
        // :00000001FF
        let record = parse_record(":00000001FF").unwrap();
        assert_eq!(record.record_length, 0);
        assert_eq!(record.load_offset, 0);
        assert_eq!(record.record_type, END_OF_FILE_RECORD_TYPE);
        assert!(record.data.is_empty());
        assert!(record.is_checksum_correct());
    }

    #[test]
    fn test_parse_extended_linear_address() {
        // :020000040800F2
        // length=2, offset=0, type=04, data=08 00, checksum=F2
        let record = parse_record(":020000040800F2").unwrap();
        assert_eq!(record.record_type, EXTENDED_LINEAR_ADDRESS_RECORD_TYPE);
        assert_eq!(record.data, vec![0x08, 0x00]);
        assert!(record.is_checksum_correct());
    }

    #[test]
    fn test_parse_start_linear_address() {
        // :04000005000000CD2A
        let record = parse_record(":04000005000000CD2A").unwrap();
        assert_eq!(record.record_type, START_LINEAR_ADDRESS_RECORD_TYPE);
        assert_eq!(record.record_length, 4);
        assert!(record.is_checksum_correct());
    }

    #[test]
    fn test_parse_extended_segment_address() {
        // :0200000212FEEC
        let record = parse_record(":0200000212FEEC").unwrap();
        assert_eq!(record.record_type, EXTENDED_SEGMENT_ADDRESS_RECORD_TYPE);
        assert_eq!(record.data, vec![0x12, 0xFE]);
        assert!(record.is_checksum_correct());
    }

    #[test]
    fn test_format_record() {
        let record = IntelHexRecord::new(3, 0x0030, DATA_RECORD_TYPE, vec![0x02, 0x33, 0x7A]);
        assert_eq!(record.format(), ":0300300002337A1E");
    }

    #[test]
    fn test_format_eof() {
        let record = IntelHexRecord::new(0, 0, END_OF_FILE_RECORD_TYPE, Vec::new());
        assert_eq!(record.format(), ":00000001FF");
    }

    #[test]
    fn test_checksum_mismatch() {
        // Corrupt the checksum
        let result = parse_record(":0300300002337A1F"); // 1F instead of 1E
        // The record should still parse but the checksum won't match
        match result {
            Ok(record) => assert!(!record.is_checksum_correct()),
            Err(_) => {} // Also acceptable if validation catches it
        }
    }

    #[test]
    fn test_invalid_record_mark() {
        let result = parse_record("0300300002337A1E");
        assert_eq!(result, Err(IntelHexError::MissingRecordMark));
    }

    #[test]
    fn test_line_too_short() {
        let result = parse_record(":00");
        assert_eq!(result, Err(IntelHexError::LineTooShort));
    }

    #[test]
    fn test_parse_multiple_records() {
        let hex = ":0300300002337A1E\n:00000001FF\n";
        let records = parse_records(hex);
        assert_eq!(records.len(), 2);
        assert!(records[0].as_ref().unwrap().is_checksum_correct());
        assert!(records[1].as_ref().unwrap().is_checksum_correct());
    }

    #[test]
    fn test_record_display() {
        let record = IntelHexRecord::new(3, 0x0030, DATA_RECORD_TYPE, vec![0x02, 0x33, 0x7A]);
        assert_eq!(record.to_string(), ":0300300002337A1E");
    }

    #[test]
    fn test_record_type_name() {
        let r1 = IntelHexRecord::new(0, 0, END_OF_FILE_RECORD_TYPE, vec![]);
        assert_eq!(r1.type_name(), "EndOfFile");

        let r2 = IntelHexRecord::new(2, 0, EXTENDED_LINEAR_ADDRESS_RECORD_TYPE, vec![0, 0]);
        assert_eq!(r2.type_name(), "ExtendedLinearAddress");
    }

    #[test]
    fn test_data_hex_string() {
        let record = IntelHexRecord::new(3, 0x0030, DATA_RECORD_TYPE, vec![0x02, 0x33, 0x7A]);
        assert_eq!(record.data_hex_string(), "02337A");
    }

    #[test]
    fn test_writer_basic() {
        let mut writer = IntelHexRecordWriter::new(16, false);
        writer.add_bytes(0x0000_0000, &[0x01, 0x02, 0x03]);
        let hex = writer.to_hex_string(Some(0x0000_0000));
        // Should contain a data record, a start linear address record, and an EOF
        assert!(hex.contains(":03000000010203")); // data record
        assert!(hex.contains(":00000001FF")); // EOF
        assert!(hex.contains(":04000005")); // start linear address
    }

    #[test]
    fn test_writer_extended_address() {
        let mut writer = IntelHexRecordWriter::new(16, false);
        // Write at address 0x0800_0000 (will need extended linear address record)
        writer.add_byte(0x0800_0000, 0xAA);
        let records = writer.finish(None);
        // Should have: extended linear address, data, EOF
        assert!(records.len() >= 3);
        assert_eq!(records[0].record_type, EXTENDED_LINEAR_ADDRESS_RECORD_TYPE);
        assert_eq!(records[0].data, vec![0x08, 0x00]);
    }

    #[test]
    fn test_mem_image_parse() {
        let hex = "\
:020000040800F2
:03000000010203F6
:00000001FF
";
        let mut img = IntelHexMemImage::new();
        img.parse(hex);
        assert_eq!(img.total_bytes(), 3);
        assert!(img.start_eip().is_none());
    }

    #[test]
    fn test_mem_image_start_eip() {
        let hex = "\
:0400000500001000E7
:00000001FF
";
        let mut img = IntelHexMemImage::new();
        img.parse(hex);
        assert_eq!(img.start_eip(), Some(0x0000_1000));
    }

    #[test]
    fn test_mem_image_extended_segment() {
        let hex = "\
:0200000212FEA2
:03000000010203F6
:00000001FF
";
        let mut img = IntelHexMemImage::new();
        img.parse(hex);
        // base = 0x12FE << 4 = 0x12FE0
        // data at 0x12FE0 + 0 = 0x12FE0
        assert_eq!(img.total_bytes(), 3);
        assert!(img.blocks().contains_key(&0x12FE0));
    }

    #[test]
    fn test_mem_image_start_cs_ip() {
        let hex = "\
:04000003004000505A
:00000001FF
";
        let mut img = IntelHexMemImage::new();
        img.parse(hex);
        assert_eq!(img.start_cs_ip(), Some((0x0040, 0x0050)));
    }

    #[test]
    fn test_unknown_record_type() {
        let result = parse_record(":00000006FA");
        assert!(matches!(result, Err(IntelHexError::UnknownRecordType(6))));
    }

    #[test]
    fn test_roundtrip() {
        let original = ":0300300002337A1E\n:00000001FF\n";
        let records = parse_records(original);
        let formatted: Vec<String> = records
            .iter()
            .map(|r| r.as_ref().unwrap().format())
            .collect();
        assert_eq!(formatted.join("\n") + "\n", original);
    }

    #[test]
    fn test_merge_blocks() {
        let mut img = IntelHexMemImage::new();
        img.blocks.insert(0x100, vec![1, 2, 3]);
        img.blocks.insert(0x103, vec![4, 5, 6]);
        let merged = img.merge_blocks();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[&0x100], vec![1, 2, 3, 4, 5, 6]);
    }
}
