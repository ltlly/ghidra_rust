//! IntelHexExporter — exports program bytes in Intel HEX format.
//!
//! Ported from Ghidra's `IntelHexExporter.java`.
//!
//! The Intel HEX format is a text-based file format that conveys binary
//! information in hexadecimal form. Each line (record) has the format:
//!
//! ```text
//! :LLAAAATT[DD...]CC
//! ```
//!
//! where `LL` = byte count, `AAAA` = address, `TT` = record type,
//! `DD` = data bytes, `CC` = checksum.

use super::traits::{Exporter, ExporterException, ExporterOption};
use ghidra_core::program::Program;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

const DEFAULT_RECORD_SIZE: usize = 0x10;

/// Intel HEX record types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IntelHexRecordType {
    /// Data record.
    Data = 0x00,
    /// End of file.
    EndOfFile = 0x01,
    /// Extended segment address.
    ExtendedSegmentAddress = 0x02,
    /// Start segment address.
    StartSegmentAddress = 0x03,
    /// Extended linear address.
    ExtendedLinearAddress = 0x04,
    /// Start linear address.
    StartLinearAddress = 0x05,
}

/// A single Intel HEX record.
#[derive(Debug, Clone)]
pub struct IntelHexRecord {
    /// Byte count (number of data bytes, max 255).
    pub byte_count: u8,
    /// Address field.
    pub address: u16,
    /// Record type.
    pub record_type: IntelHexRecordType,
    /// Data bytes.
    pub data: Vec<u8>,
}

impl IntelHexRecord {
    /// Format this record as an Intel HEX line.
    pub fn format(&self) -> String {
        let mut line = String::new();
        line.push(':');

        // Byte count
        line.push_str(&format!("{:02X}", self.byte_count));

        // Address
        line.push_str(&format!("{:04X}", self.address));

        // Record type
        line.push_str(&format!("{:02X}", self.record_type as u8));

        // Data
        let mut checksum = self.byte_count as u16;
        checksum = checksum.wrapping_add(((self.address >> 8) & 0xff) as u8 as u16);
        checksum = checksum.wrapping_add((self.address & 0xff) as u8 as u16);
        checksum = checksum.wrapping_add(self.record_type as u8 as u16);

        for &b in &self.data {
            line.push_str(&format!("{:02X}", b));
            checksum = checksum.wrapping_add(b as u16);
        }

        // Checksum (two's complement of the sum of all bytes)
        let checksum_byte = (!(checksum as u8)).wrapping_add(1);
        line.push_str(&format!("{:02X}", checksum_byte));

        line
    }
}

/// Helper for building Intel HEX records from a byte stream.
pub struct IntelHexRecordWriter {
    record_size: usize,
    drop_extra_bytes: bool,
    current_address: u64,
    current_buffer: Vec<u8>,
    records: Vec<IntelHexRecord>,
    high_address: u32,
}

impl IntelHexRecordWriter {
    /// Create a new writer with the given record size.
    ///
    /// * `record_size` — maximum bytes per record (1-255)
    /// * `drop_extra_bytes` — if true, trailing bytes that don't fill a full
    ///   record are omitted
    pub fn new(record_size: usize, drop_extra_bytes: bool) -> Self {
        Self {
            record_size: record_size.min(0xff),
            drop_extra_bytes,
            current_address: 0,
            current_buffer: Vec::new(),
            records: Vec::new(),
            high_address: 0,
        }
    }

    /// Add a byte at the given address.
    pub fn add_byte(&mut self, address: u64, byte: u8) {
        // If there's a gap or the buffer is full, flush
        if (!self.current_buffer.is_empty() && address != self.current_address)
            || self.current_buffer.len() >= self.record_size
        {
            self.flush_buffer();
        }

        if self.current_buffer.is_empty() {
            self.current_address = address;
        }
        self.current_buffer.push(byte);
        self.current_address = address + 1;
    }

    fn flush_buffer(&mut self) {
        if self.current_buffer.is_empty() {
            return;
        }

        let addr = self.current_address - self.current_buffer.len() as u64;

        // Check if we need an extended linear address record
        let high = ((addr >> 16) & 0xffff) as u32;
        if high != self.high_address {
            self.high_address = high;
            self.records.push(IntelHexRecord {
                byte_count: 2,
                address: 0,
                record_type: IntelHexRecordType::ExtendedLinearAddress,
                data: vec![(high >> 8) as u8, (high & 0xff) as u8],
            });
        }

        let low_addr = (addr & 0xffff) as u16;
        let byte_count = self.current_buffer.len() as u8;

        self.records.push(IntelHexRecord {
            byte_count,
            address: low_addr,
            record_type: IntelHexRecordType::Data,
            data: self.current_buffer.clone(),
        });

        self.current_buffer.clear();
    }

    /// Finalize the writer and return all records.
    ///
    /// * `entry_point` — optional entry point address for the start record
    pub fn finish(mut self, entry_point: Option<u64>) -> Vec<IntelHexRecord> {
        // Flush any remaining bytes
        if !self.drop_extra_bytes || self.current_buffer.len() == self.record_size {
            self.flush_buffer();
        }

        // End of file record
        self.records.push(IntelHexRecord {
            byte_count: 0,
            address: 0,
            record_type: IntelHexRecordType::EndOfFile,
            data: Vec::new(),
        });

        // Start linear address record (if entry point provided)
        if let Some(entry) = entry_point {
            self.records.push(IntelHexRecord {
                byte_count: 4,
                address: 0,
                record_type: IntelHexRecordType::StartLinearAddress,
                data: vec![
                    ((entry >> 24) & 0xff) as u8,
                    ((entry >> 16) & 0xff) as u8,
                    ((entry >> 8) & 0xff) as u8,
                    (entry & 0xff) as u8,
                ],
            });
        }

        self.records
    }
}

/// An exporter that writes program bytes in Intel HEX format.
///
/// Exports initialized memory blocks as Intel HEX records. The default record
/// size is 16 bytes per line, but this is configurable.
#[derive(Debug)]
pub struct IntelHexExporter {
    /// Number of bytes per record line.
    pub record_size: usize,
    /// If true, trailing bytes that don't fill a full record are omitted.
    pub drop_extra_bytes: bool,
}

impl IntelHexExporter {
    /// Create a new Intel HEX exporter with default settings.
    pub fn new() -> Self {
        Self {
            record_size: DEFAULT_RECORD_SIZE,
            drop_extra_bytes: false,
        }
    }

    /// Create a new Intel HEX exporter with custom record size.
    pub fn with_record_size(record_size: usize, drop_extra_bytes: bool) -> Self {
        Self {
            record_size,
            drop_extra_bytes,
        }
    }
}

impl Default for IntelHexExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Exporter for IntelHexExporter {
    fn name(&self) -> &str {
        "Intel Hex"
    }

    fn file_extension(&self) -> &str {
        "hex"
    }

    fn help_topic(&self) -> Option<&str> {
        Some("intel_hex")
    }

    fn get_options(&self) -> Vec<ExporterOption> {
        vec![
            ExporterOption::integer("Record Size", self.record_size as i64)
                .with_group("Intel Hex"),
            ExporterOption::boolean("Drop Extra Bytes", self.drop_extra_bytes)
                .with_group("Intel Hex"),
        ]
    }

    fn set_options(&mut self, options: &[ExporterOption]) -> Result<(), ExporterException> {
        for opt in options {
            if let ExporterOption::Integer { name, value, .. } = opt {
                if name == "Record Size" {
                    let v = *value;
                    if v < 1 || v > 255 {
                        return Err(ExporterException::Message(
                            "Record size must be between 1 and 255".to_string(),
                        ));
                    }
                    self.record_size = v as usize;
                }
            }
            if let ExporterOption::Boolean { name, value, .. } = opt {
                if name == "Drop Extra Bytes" {
                    self.drop_extra_bytes = *value;
                }
            }
        }
        Ok(())
    }

    fn export(
        &self,
        file: &Path,
        program: &Program,
        start_addr: Option<u64>,
        end_addr: Option<u64>,
    ) -> Result<bool, ExporterException> {
        let mut writer =
            IntelHexRecordWriter::new(self.record_size, self.drop_extra_bytes);

        // Collect initialized blocks, sorted by address
        let mut blocks: Vec<_> = program
            .memory_blocks
            .values()
            .filter(|b| b.initialized)
            .collect();
        blocks.sort_by_key(|b| b.range.start.offset);

        for block in &blocks {
            if !block.initialized || block.data.is_empty() {
                continue;
            }

            let block_start = block.range.start.offset;
            for (i, &byte) in block.data.iter().enumerate() {
                let addr = block_start + i as u64;
                if let Some(start) = start_addr {
                    if addr < start {
                        continue;
                    }
                }
                if let Some(end) = end_addr {
                    if addr > end {
                        continue;
                    }
                }
                writer.add_byte(addr, byte);
            }
        }

        // Find entry point from external entry point symbols
        let entry_point = program
            .symbol_table
            .symbols
            .values()
            .find(|s| s.kind() == ghidra_core::symbol::SymbolType::Function)
            .map(|s| s.address().offset);

        let records = writer.finish(entry_point);

        // Write records to file
        let mut file_writer =
            io::BufWriter::new(fs::File::create(file).map_err(ExporterException::Io)?);
        for record in &records {
            writeln!(file_writer, "{}", record.format()).map_err(ExporterException::Io)?;
        }
        file_writer.flush().map_err(ExporterException::Io)?;

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::{Address, AddressRange};
    use ghidra_core::program::{MemoryBlock, MemoryPermissions, Program};
    use std::fs;

    fn make_program() -> Program {
        let mut prog = Program::new("hex_test", Address::new(0x1000));
        prog.memory_blocks.insert(
            ".text".to_string(),
            MemoryBlock {
                name: ".text".to_string(),
                range: AddressRange::new(Address::new(0x1000), Address::new(0x100f)),
                permissions: MemoryPermissions::RX,
                initialized: true,
                data: vec![
                    0x55, 0x48, 0x89, 0xe5, 0xb8, 0x00, 0x00, 0x00, 0x5d, 0xc3, 0x90, 0x90,
                    0x90, 0x90, 0x90, 0x90,
                ],
            },
        );
        prog
    }

    #[test]
    fn test_intel_hex_record_format() {
        let record = IntelHexRecord {
            byte_count: 2,
            address: 0x0000,
            record_type: IntelHexRecordType::Data,
            data: vec![0x55, 0x48],
        };
        let formatted = record.format();
        assert!(formatted.starts_with(':'));
        assert_eq!(formatted, ":02000000554861");
    }

    #[test]
    fn test_intel_hex_record_eof() {
        let record = IntelHexRecord {
            byte_count: 0,
            address: 0,
            record_type: IntelHexRecordType::EndOfFile,
            data: Vec::new(),
        };
        assert_eq!(record.format(), ":00000001FF");
    }

    #[test]
    fn test_intel_hex_record_writer() {
        let mut writer = IntelHexRecordWriter::new(4, false);
        writer.add_byte(0x1000, 0x55);
        writer.add_byte(0x1001, 0x48);
        writer.add_byte(0x1002, 0x89);
        writer.add_byte(0x1003, 0xe5);
        writer.add_byte(0x1004, 0xc3);
        let records = writer.finish(None);

        // Should have: data(4 bytes), data(1 byte), EOF
        assert!(records.len() >= 3);
        assert_eq!(records[0].record_type, IntelHexRecordType::Data);
        assert_eq!(records[0].byte_count, 4);
        assert_eq!(records[1].record_type, IntelHexRecordType::Data);
        assert_eq!(records[1].byte_count, 1);
        assert_eq!(records.last().unwrap().record_type, IntelHexRecordType::EndOfFile);
    }

    #[test]
    fn test_intel_hex_exporter_properties() {
        let e = IntelHexExporter::new();
        assert_eq!(e.name(), "Intel Hex");
        assert_eq!(e.file_extension(), "hex");
    }

    #[test]
    fn test_intel_hex_exporter_export() {
        let prog = make_program();
        let e = IntelHexExporter::new();
        let tmp = std::env::temp_dir().join("intel_hex_exporter_test.hex");
        let result = e.export(&tmp, &prog, None, None).unwrap();
        assert!(result);

        let content = fs::read_to_string(&tmp).unwrap();
        assert!(content.starts_with(':'));
        assert!(content.contains("\n"));
        // Should contain the EOF record
        assert!(content.contains(":00000001FF"));

        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_intel_hex_exporter_custom_record_size() {
        let e = IntelHexExporter::with_record_size(8, true);
        assert_eq!(e.record_size, 8);
        assert!(e.drop_extra_bytes);
    }

    #[test]
    fn test_intel_hex_exporter_options() {
        let mut e = IntelHexExporter::new();
        let opts = e.get_options();
        assert_eq!(opts.len(), 2);

        let new_opts = vec![
            ExporterOption::integer("Record Size", 32).with_group("Intel Hex"),
            ExporterOption::boolean("Drop Extra Bytes", true).with_group("Intel Hex"),
        ];
        e.set_options(&new_opts).unwrap();
        assert_eq!(e.record_size, 32);
        assert!(e.drop_extra_bytes);
    }

    #[test]
    fn test_intel_hex_exporter_bad_record_size() {
        let mut e = IntelHexExporter::new();
        let opts = vec![ExporterOption::integer("Record Size", 300).with_group("Intel Hex")];
        assert!(e.set_options(&opts).is_err());
    }

    #[test]
    fn test_extended_linear_address_record() {
        let mut writer = IntelHexRecordWriter::new(16, false);
        // Write a byte at a high address to trigger an extended linear address record
        writer.add_byte(0x1_0000, 0xAA);
        let records = writer.finish(None);

        // Should have: extended linear address, data, EOF
        assert!(records.len() >= 3);
        assert_eq!(records[0].record_type, IntelHexRecordType::ExtendedLinearAddress);
        assert_eq!(records[0].data, vec![0x00, 0x01]);
    }
}
