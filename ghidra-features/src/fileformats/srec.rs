//! Motorola S-Record format parser.
//!
//! Ported from Ghidra's `ghidra.app.util.opinion.MotorolaHexLoader`.
//!
//! The Motorola S-Record (SREC) format is a text-based file format for
//! conveying binary data. Each line begins with `S` followed by a record
//! type digit (0-9), byte count, address, data, and checksum.
//!
//! Record types:
//! - S0: Header record (metadata)
//! - S1: Data with 16-bit address
//! - S2: Data with 24-bit address
//! - S3: Data with 32-bit address
//! - S5/S6: Count of preceding S1/S2/S3 records
//! - S7: End record for S3 (32-bit start address)
//! - S8: End record for S2 (24-bit start address)
//! - S9: End record for S1 (16-bit start address)
//!
//! References:
//! - Motorola S-Record format (Wikipedia)
//! - <https://en.wikipedia.org/wiki/SREC_(file_format)>

use std::collections::BTreeMap;
use std::fmt;

// ═══════════════════════════════════════════════════════════════════════════════════
// Error Types
// ═══════════════════════════════════════════════════════════════════════════════════

/// Errors encountered while parsing S-Record files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrecError {
    /// Line is too short.
    LineTooShort,
    /// Line does not start with 'S'.
    MissingStartCode,
    /// Invalid record type character.
    InvalidRecordType(char),
    /// Error parsing the byte count.
    InvalidByteCount(String),
    /// Error parsing the address.
    InvalidAddress(String),
    /// Error parsing a data byte.
    InvalidDataByte(String),
    /// Error parsing the checksum.
    InvalidChecksum(String),
    /// Byte count is inconsistent with line length.
    InconsistentLength {
        expected: usize,
        actual: usize,
    },
    /// Checksum mismatch.
    ChecksumMismatch {
        reported: u8,
        computed: u8,
        line: usize,
    },
}

impl fmt::Display for SrecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LineTooShort => write!(f, "line too short"),
            Self::MissingStartCode => write!(f, "line does not start with 'S'"),
            Self::InvalidRecordType(c) => write!(f, "invalid record type character: '{c}'"),
            Self::InvalidByteCount(s) => write!(f, "error parsing byte count: {s}"),
            Self::InvalidAddress(s) => write!(f, "error parsing address: {s}"),
            Self::InvalidDataByte(s) => write!(f, "error parsing data byte: {s}"),
            Self::InvalidChecksum(s) => write!(f, "error parsing checksum: {s}"),
            Self::InconsistentLength { expected, actual } => {
                write!(
                    f,
                    "line length inconsistent: expected {expected} hex chars, got {actual}"
                )
            }
            Self::ChecksumMismatch {
                reported,
                computed,
                line,
            } => {
                write!(
                    f,
                    "checksum mismatch on line {line}: reported 0x{reported:02X}, computed 0x{computed:02X}"
                )
            }
        }
    }
}

impl std::error::Error for SrecError {}

// ═══════════════════════════════════════════════════════════════════════════════════
// SrecRecord
// ═══════════════════════════════════════════════════════════════════════════════════

/// The type of an S-Record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrecRecordType {
    /// S0: Header record.
    Header,
    /// S1: Data with 16-bit address.
    Data16,
    /// S2: Data with 24-bit address.
    Data24,
    /// S3: Data with 32-bit address.
    Data32,
    /// S5: Count of S1/S2/S3 records (16-bit count).
    Count16,
    /// S6: Count of S1/S2/S3 records (24-bit count).
    Count24,
    /// S7: End record with 32-bit start address.
    Start32,
    /// S8: End record with 24-bit start address.
    Start24,
    /// S9: End record with 16-bit start address.
    Start16,
}

impl SrecRecordType {
    /// Return the address length in bytes for this record type.
    pub fn address_len(&self) -> usize {
        match self {
            Self::Header | Self::Data16 | Self::Count16 | Self::Start16 => 2,
            Self::Data24 | Self::Count24 | Self::Start24 => 3,
            Self::Data32 | Self::Start32 => 4,
        }
    }

    /// Return the character digit (0-9) for this record type.
    pub fn digit(&self) -> char {
        match self {
            Self::Header => '0',
            Self::Data16 => '1',
            Self::Data24 => '2',
            Self::Data32 => '3',
            Self::Count16 => '5',
            Self::Count24 => '6',
            Self::Start32 => '7',
            Self::Start24 => '8',
            Self::Start16 => '9',
        }
    }

    /// Whether this is a data record (S1, S2, S3).
    pub fn is_data(&self) -> bool {
        matches!(self, Self::Data16 | Self::Data24 | Self::Data32)
    }

    /// Whether this is an end/start record (S7, S8, S9).
    pub fn is_end(&self) -> bool {
        matches!(self, Self::Start16 | Self::Start24 | Self::Start32)
    }

    /// Parse from a character digit.
    pub fn from_char(c: char) -> Result<Self, SrecError> {
        match c {
            '0' => Ok(Self::Header),
            '1' => Ok(Self::Data16),
            '2' => Ok(Self::Data24),
            '3' => Ok(Self::Data32),
            '5' => Ok(Self::Count16),
            '6' => Ok(Self::Count24),
            '7' => Ok(Self::Start32),
            '8' => Ok(Self::Start24),
            '9' => Ok(Self::Start16),
            other => Err(SrecError::InvalidRecordType(other)),
        }
    }
}

impl fmt::Display for SrecRecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "S{}", self.digit())
    }
}

/// A single S-Record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrecRecord {
    /// Record type.
    pub record_type: SrecRecordType,
    /// Byte count (includes address + data + checksum bytes).
    pub byte_count: u8,
    /// Address field.
    pub address: u32,
    /// Data bytes.
    pub data: Vec<u8>,
    /// Checksum byte.
    pub checksum: u8,
    /// Computed checksum.
    pub computed_checksum: u8,
}

impl SrecRecord {
    /// Whether the checksum is correct.
    pub fn is_checksum_valid(&self) -> bool {
        self.checksum == self.computed_checksum
    }

    /// Format the record as an S-Record text line.
    pub fn format(&self) -> String {
        let addr_bytes = self.record_type.address_len();
        let mut s = format!("S{}{:02X}", self.record_type.digit(), self.byte_count);

        // Address (big-endian, variable width)
        for i in (0..addr_bytes).rev() {
            s.push_str(&format!("{:02X}", (self.address >> (i * 8)) & 0xFF));
        }

        // Data
        for &b in &self.data {
            s.push_str(&format!("{b:02X}"));
        }

        // Checksum
        s.push_str(&format!("{:02X}", self.computed_checksum));
        s
    }
}

impl fmt::Display for SrecRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Parser
// ═══════════════════════════════════════════════════════════════════════════════════

/// Compute the S-Record checksum (one's complement of the sum of byte_count, address, and data bytes).
fn compute_srec_checksum(byte_count: u8, address: u32, addr_len: usize, data: &[u8]) -> u8 {
    let mut sum: u32 = byte_count as u32;
    for i in (0..addr_len).rev() {
        sum += ((address >> (i * 8)) & 0xFF) as u32;
    }
    for &b in data {
        sum += b as u32;
    }
    (!sum & 0xFF) as u8
}

/// Parse a hex byte pair at position `pos` in the line.
fn parse_hex_pair(line: &str, pos: usize) -> Result<u8, SrecError> {
    if pos + 2 > line.len() {
        return Err(SrecError::LineTooShort);
    }
    u8::from_str_radix(&line[pos..pos + 2], 16)
        .map_err(|e| SrecError::InvalidDataByte(e.to_string()))
}

/// Parse a single S-Record line.
pub fn parse_record(line: &str) -> Result<SrecRecord, SrecError> {
    let line = line.trim();
    if line.len() < 10 {
        return Err(SrecError::LineTooShort);
    }
    if !line.starts_with('S') && !line.starts_with('s') {
        return Err(SrecError::MissingStartCode);
    }

    let record_type = SrecRecordType::from_char(line.as_bytes()[1] as char)?;
    let addr_len = record_type.address_len();

    // Byte count
    let byte_count = parse_hex_pair(line, 2)?;
    let byte_count_usize = byte_count as usize;

    // Verify line length: "S" + type digit + 2 (count) + 2*byte_count hex chars + checksum(2)
    // = 1 + 1 + 2 + 2*byte_count = 4 + 2*byte_count... but checksum is part of byte_count
    // Total hex chars after "S1": 2 (count) + 2*byte_count = 2 + 2*byte_count
    let expected_hex_len = 2 + 2 * byte_count_usize;
    let actual_hex_len = line.len() - 2; // subtract "S1"
    if actual_hex_len < expected_hex_len {
        return Err(SrecError::InconsistentLength {
            expected: expected_hex_len + 2,
            actual: line.len(),
        });
    }

    // Address
    let mut address: u32 = 0;
    let addr_start = 4;
    for i in 0..addr_len {
        let b = parse_hex_pair(line, addr_start + i * 2)?;
        address = (address << 8) | (b as u32);
    }

    // Data (byte_count includes address bytes + data bytes + 1 checksum byte)
    let data_len = byte_count_usize.saturating_sub(addr_len).saturating_sub(1);
    let data_start = addr_start + addr_len * 2;
    let mut data = Vec::with_capacity(data_len);
    for i in 0..data_len {
        let b = parse_hex_pair(line, data_start + i * 2)?;
        data.push(b);
    }

    // Checksum
    let checksum_pos = data_start + data_len * 2;
    let checksum = parse_hex_pair(line, checksum_pos)?;
    let computed = compute_srec_checksum(byte_count, address, addr_len, &data);

    Ok(SrecRecord {
        record_type,
        byte_count,
        address,
        data,
        checksum,
        computed_checksum: computed,
    })
}

/// Parse all records from an S-Record file.
pub fn parse_records(text: &str) -> Vec<Result<SrecRecord, SrecError>> {
    text.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .enumerate()
        .map(|(i, line)| {
            parse_record(line)
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════════════
// SrecMemImage
// ═══════════════════════════════════════════════════════════════════════════════════

/// Memory image built from parsing S-Record files.
#[derive(Debug, Clone)]
pub struct SrecMemImage {
    /// Memory blocks: sorted map from start address to data bytes.
    blocks: BTreeMap<u64, Vec<u8>>,
    /// Start address from end record (S7/S8/S9).
    start_address: Option<u64>,
    /// Header text from S0 record.
    header: Option<String>,
    /// Warnings accumulated during parsing.
    warnings: Vec<String>,
    /// Total number of data records parsed.
    data_record_count: usize,
}

impl SrecMemImage {
    /// Create a new empty memory image.
    pub fn new() -> Self {
        Self {
            blocks: BTreeMap::new(),
            start_address: None,
            header: None,
            warnings: Vec::new(),
            data_record_count: 0,
        }
    }

    /// Add a parsed record to the memory image.
    pub fn add_record(&mut self, record: &SrecRecord) {
        if !record.is_checksum_valid() {
            self.warnings.push(format!(
                "S{} at address 0x{:X}: checksum mismatch (reported 0x{:02X}, computed 0x{:02X})",
                record.record_type.digit(),
                record.address,
                record.checksum,
                record.computed_checksum,
            ));
        }

        match record.record_type {
            SrecRecordType::Header => {
                self.header = Some(
                    String::from_utf8_lossy(&record.data)
                        .trim_end_matches('\0')
                        .to_string(),
                );
            }
            SrecRecordType::Data16 | SrecRecordType::Data24 | SrecRecordType::Data32 => {
                let addr = record.address as u64;
                self.blocks
                    .entry(addr)
                    .or_default()
                    .extend_from_slice(&record.data);
                self.data_record_count += 1;
            }
            SrecRecordType::Start16 | SrecRecordType::Start24 | SrecRecordType::Start32 => {
                self.start_address = Some(record.address as u64);
            }
            SrecRecordType::Count16 | SrecRecordType::Count24 => {
                // Record count validation could be done here
            }
        }
    }

    /// Parse all records from an S-Record file text.
    pub fn parse(&mut self, text: &str) {
        for result in parse_records(text) {
            match result {
                Ok(record) => self.add_record(&record),
                Err(e) => self.warnings.push(format!("parse error: {e}")),
            }
        }
    }

    /// Return the start address from the end record.
    pub fn start_address(&self) -> Option<u64> {
        self.start_address
    }

    /// Return the header text.
    pub fn header(&self) -> Option<&str> {
        self.header.as_deref()
    }

    /// Return the memory blocks.
    pub fn blocks(&self) -> &BTreeMap<u64, Vec<u8>> {
        &self.blocks
    }

    /// Return warnings.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Return the total number of data bytes.
    pub fn total_bytes(&self) -> usize {
        self.blocks.values().map(|v| v.len()).sum()
    }

    /// Return the number of data records parsed.
    pub fn data_record_count(&self) -> usize {
        self.data_record_count
    }
}

impl Default for SrecMemImage {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Utility
// ═══════════════════════════════════════════════════════════════════════════════════

/// Check if a byte slice looks like it could be an S-Record file.
pub fn is_srec_file(data: &[u8]) -> bool {
    // Look for a line starting with 'S' followed by a digit
    for line in data.split(|&b| b == b'\n') {
        let line = if let Some(pos) = line.iter().position(|&b| b == b'\r') {
            &line[..pos]
        } else {
            line
        };
        let trimmed: Vec<u8> = line
            .iter()
            .copied()
            .skip_while(|b| *b == b' ' || *b == b'\t')
            .collect();
        if trimmed.len() >= 2 && (trimmed[0] == b'S' || trimmed[0] == b's') {
            if trimmed[1].is_ascii_digit() {
                return true;
            }
        }
    }
    false
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_s0_header() {
        // S00F000068656C6C6F202020202000003C
        let record = parse_record("S00F000068656C6C6F202020202000003C").unwrap();
        assert_eq!(record.record_type, SrecRecordType::Header);
        assert_eq!(record.byte_count, 0x0F);
        assert_eq!(record.address, 0);
        assert!(record.is_checksum_valid());
    }

    #[test]
    fn test_parse_s1_data() {
        // S1130000285F245F2212226A000424290008237C2A
        let record = parse_record("S1130000285F245F2212226A000424290008237C2A").unwrap();
        assert_eq!(record.record_type, SrecRecordType::Data16);
        assert_eq!(record.byte_count, 0x13);
        assert_eq!(record.address, 0x0000);
        assert!(record.is_checksum_valid());
    }

    #[test]
    fn test_parse_s2_data() {
        // S214000000285F245F2212226A000424290008237C29
        let record = parse_record("S214000000285F245F2212226A000424290008237C29").unwrap();
        assert_eq!(record.record_type, SrecRecordType::Data24);
        assert_eq!(record.address, 0x000000);
        assert!(record.is_checksum_valid());
    }

    #[test]
    fn test_parse_s3_data() {
        // S31500000000285F245F2212226A000424290008237C28
        let record = parse_record("S31500000000285F245F2212226A000424290008237C28").unwrap();
        assert_eq!(record.record_type, SrecRecordType::Data32);
        assert_eq!(record.address, 0x00000000);
        assert!(record.is_checksum_valid());
    }

    #[test]
    fn test_parse_s7_end() {
        // S70500000000FA
        let record = parse_record("S70500000000FA").unwrap();
        assert_eq!(record.record_type, SrecRecordType::Start32);
        assert_eq!(record.address, 0);
        assert!(record.is_checksum_valid());
    }

    #[test]
    fn test_parse_s8_end() {
        // S804000000FB
        let record = parse_record("S804000000FB").unwrap();
        assert_eq!(record.record_type, SrecRecordType::Start24);
        assert!(record.is_checksum_valid());
    }

    #[test]
    fn test_parse_s9_end() {
        // S9030000FC
        let record = parse_record("S9030000FC").unwrap();
        assert_eq!(record.record_type, SrecRecordType::Start16);
        assert!(record.is_checksum_valid());
    }

    #[test]
    fn test_format_record() {
        let record = SrecRecord {
            record_type: SrecRecordType::Data16,
            byte_count: 0x13,
            address: 0x0000,
            data: vec![
                0x28, 0x5F, 0x24, 0x5F, 0x22, 0x12, 0x22, 0x6A, 0x00, 0x04, 0x24, 0x29, 0x00,
                0x08, 0x23, 0x7C,
            ],
            checksum: 0x2A,
            computed_checksum: 0x2A,
        };
        assert_eq!(record.format(), "S1130000285F245F2212226A000424290008237C2A");
    }

    #[test]
    fn test_checksum_mismatch() {
        // Corrupt the checksum
        let record = parse_record("S1130000285F245F2212226A000424290008237C2B").unwrap();
        assert!(!record.is_checksum_valid());
    }

    #[test]
    fn test_missing_start_code() {
        let result = parse_record("X1130000285F245F2212226A000424290008237C2A");
        assert_eq!(result, Err(SrecError::MissingStartCode));
    }

    #[test]
    fn test_line_too_short() {
        let result = parse_record("S1");
        assert_eq!(result, Err(SrecError::LineTooShort));
    }

    #[test]
    fn test_parse_multiple_records() {
        let srec = "\
S00F000068656C6C6F202020202000003C
S1130000285F245F2212226A000424290008237C2A
S9030000FC
";
        let records = parse_records(srec);
        assert_eq!(records.len(), 3);
        assert!(records.iter().all(|r| r.as_ref().unwrap().is_checksum_valid()));
    }

    #[test]
    fn test_is_srec_file() {
        let srec = b"S1130000285F245F2212226A000424290008237C2A\nS9030000FC\n";
        assert!(is_srec_file(srec));
        assert!(!is_srec_file(b"not an srec file"));
        assert!(!is_srec_file(b""));
    }

    #[test]
    fn test_mem_image_parse() {
        let srec = "\
S1130000285F245F2212226A000424290008237C2A
S9030000FC
";
        let mut img = SrecMemImage::new();
        img.parse(srec);
        assert_eq!(img.total_bytes(), 16);
        assert_eq!(img.data_record_count(), 1);
        assert_eq!(img.start_address(), Some(0));
    }

    #[test]
    fn test_mem_image_header() {
        let srec = "\
S00F000068656C6C6F202020202000003C
S9030000FC
";
        let mut img = SrecMemImage::new();
        img.parse(srec);
        assert!(img.header().is_some());
    }

    #[test]
    fn test_record_type_display() {
        assert_eq!(SrecRecordType::Data16.to_string(), "S1");
        assert_eq!(SrecRecordType::Data24.to_string(), "S2");
        assert_eq!(SrecRecordType::Data32.to_string(), "S3");
        assert_eq!(SrecRecordType::Start16.to_string(), "S9");
    }

    #[test]
    fn test_record_type_is_data() {
        assert!(SrecRecordType::Data16.is_data());
        assert!(SrecRecordType::Data24.is_data());
        assert!(SrecRecordType::Data32.is_data());
        assert!(!SrecRecordType::Header.is_data());
        assert!(!SrecRecordType::Start16.is_data());
    }

    #[test]
    fn test_record_type_is_end() {
        assert!(SrecRecordType::Start16.is_end());
        assert!(SrecRecordType::Start24.is_end());
        assert!(SrecRecordType::Start32.is_end());
        assert!(!SrecRecordType::Data16.is_end());
        assert!(!SrecRecordType::Header.is_end());
    }

    #[test]
    fn test_roundtrip() {
        let original = "S1130000285F245F2212226A000424290008237C2A";
        let record = parse_record(original).unwrap();
        assert_eq!(record.format(), original);
    }

    #[test]
    fn test_record_display() {
        let record = parse_record("S9030000FC").unwrap();
        assert_eq!(record.to_string(), "S9030000FC");
    }

    #[test]
    fn test_invalid_record_type() {
        let result = parse_record("S4130000...");
        assert!(matches!(result, Err(SrecError::InvalidRecordType('4'))));
    }

    #[test]
    fn test_high_address_s2() {
        // S2 with address 0x100000
        // S214100000285F245F2212226A000424290008237C19
        let record = parse_record("S214100000285F245F2212226A000424290008237C19").unwrap();
        assert_eq!(record.record_type, SrecRecordType::Data24);
        assert_eq!(record.address, 0x100000);
        assert!(record.is_checksum_valid());
    }

    #[test]
    fn test_mem_image_start_address_s7() {
        let srec = "\
S31500000000285F245F2212226A000424290008237C28
S70500001000EA
";
        let mut img = SrecMemImage::new();
        img.parse(srec);
        assert_eq!(img.start_address(), Some(0x1000));
    }
}
