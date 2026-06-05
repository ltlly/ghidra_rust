//! Background export command for trace data.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.export` package:
//! - `ExportTraceBackgroundCmd`: Background command that exports trace data
//!   in various formats (ASCII, binary, HTML, Intel HEX, XML).

use serde::{Deserialize, Serialize};

/// Export format for trace data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraceExportFormat {
    /// ASCII hex dump.
    AsciiHex,
    /// Raw binary.
    Binary,
    /// HTML formatted dump.
    Html,
    /// Intel HEX format.
    IntelHex,
    /// XML formatted dump.
    Xml,
    /// S-Record format.
    SRecord,
}

impl TraceExportFormat {
    /// Get the default file extension for this format.
    pub fn file_extension(&self) -> &'static str {
        match self {
            Self::AsciiHex => ".txt",
            Self::Binary => ".bin",
            Self::Html => ".html",
            Self::IntelHex => ".hex",
            Self::Xml => ".xml",
            Self::SRecord => ".srec",
        }
    }

    /// Get a human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::AsciiHex => "ASCII Hex Dump",
            Self::Binary => "Raw Binary",
            Self::Html => "HTML Formatted Dump",
            Self::IntelHex => "Intel HEX Format",
            Self::Xml => "XML Formatted Dump",
            Self::SRecord => "Motorola S-Record",
        }
    }
}

/// A background command for exporting trace data.
///
/// Ported from Ghidra's `ExportTraceBackgroundCmd`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportTraceBackgroundCmd {
    /// The export format.
    pub format: TraceExportFormat,
    /// The output file path.
    pub output_path: String,
    /// The start address of the export range.
    pub start_address: u64,
    /// The end address of the export range (inclusive).
    pub end_address: u64,
    /// The snap to export from.
    pub snap: i64,
    /// Whether to include addresses in the output.
    pub include_addresses: bool,
    /// Bytes per line for text formats.
    pub bytes_per_line: u16,
}

impl ExportTraceBackgroundCmd {
    /// Create a new export command.
    pub fn new(
        format: TraceExportFormat,
        output_path: impl Into<String>,
        start_address: u64,
        end_address: u64,
        snap: i64,
    ) -> Self {
        Self {
            format,
            output_path: output_path.into(),
            start_address,
            end_address,
            snap,
            include_addresses: true,
            bytes_per_line: 16,
        }
    }

    /// Set bytes per line for text formats.
    pub fn with_bytes_per_line(mut self, bpl: u16) -> Self {
        self.bytes_per_line = bpl;
        self
    }

    /// Set whether to include addresses.
    pub fn with_addresses(mut self, include: bool) -> Self {
        self.include_addresses = include;
        self
    }

    /// Get the number of bytes to export.
    pub fn export_size(&self) -> u64 {
        if self.end_address >= self.start_address {
            self.end_address - self.start_address + 1
        } else {
            0
        }
    }

    /// Format a single line of hex dump (for ASCII/HTML).
    pub fn format_hex_line(&self, address: u64, bytes: &[u8]) -> String {
        let mut result = String::new();
        if self.include_addresses {
            result.push_str(&format!("{:08x}: ", address));
        }
        for (i, b) in bytes.iter().enumerate() {
            if i > 0 && i % 4 == 0 {
                result.push(' ');
            }
            result.push_str(&format!("{:02x} ", b));
        }
        result
    }

    /// Format an Intel HEX record.
    pub fn format_intel_hex_record(address: u16, data: &[u8]) -> String {
        let len = data.len() as u8;
        let mut checksum = len.wrapping_add((address >> 8) as u8).wrapping_add((address & 0xff) as u8);
        let mut record = format!(":{:02X}{:04X}00", len, address);
        for b in data {
            record.push_str(&format!("{:02X}", b));
            checksum = checksum.wrapping_add(*b);
        }
        checksum = (!checksum).wrapping_add(1);
        record.push_str(&format!("{:02X}", checksum));
        record
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_format_properties() {
        assert_eq!(TraceExportFormat::Binary.file_extension(), ".bin");
        assert_eq!(TraceExportFormat::IntelHex.file_extension(), ".hex");
        assert!(!TraceExportFormat::Html.description().is_empty());
    }

    #[test]
    fn test_export_background_cmd() {
        let cmd = ExportTraceBackgroundCmd::new(
            TraceExportFormat::AsciiHex,
            "/tmp/output.txt",
            0x1000,
            0x1fff,
            5,
        )
        .with_bytes_per_line(32)
        .with_addresses(true);

        assert_eq!(cmd.format, TraceExportFormat::AsciiHex);
        assert_eq!(cmd.export_size(), 0x1000);
        assert_eq!(cmd.bytes_per_line, 32);
    }

    #[test]
    fn test_format_hex_line() {
        let cmd = ExportTraceBackgroundCmd::new(
            TraceExportFormat::AsciiHex,
            "/tmp/out",
            0,
            0xff,
            0,
        );
        let line = cmd.format_hex_line(0x1000, &[0x48, 0x65, 0x6c, 0x6c, 0x6f]);
        assert!(line.starts_with("00001000:"));
        assert!(line.contains("48"));
        assert!(line.contains("65"));
    }

    #[test]
    fn test_format_intel_hex_record() {
        let record = ExportTraceBackgroundCmd::format_intel_hex_record(0x1000, &[0xAA, 0xBB, 0xCC]);
        assert!(record.starts_with(":"));
        assert_eq!(&record[1..3], "03"); // length = 3
        assert_eq!(&record[3..7], "1000"); // address
        assert_eq!(&record[7..9], "00"); // type = data
        assert_eq!(&record[9..11], "AA"); // data[0]
    }

    #[test]
    fn test_export_size_zero_range() {
        let cmd = ExportTraceBackgroundCmd::new(
            TraceExportFormat::Binary,
            "/tmp/out",
            0x2000,
            0x1000,
            0,
        );
        assert_eq!(cmd.export_size(), 0);
    }

    #[test]
    fn test_export_format_serde() {
        let format = TraceExportFormat::IntelHex;
        let json = serde_json::to_string(&format).unwrap();
        let back: TraceExportFormat = serde_json::from_str(&json).unwrap();
        assert_eq!(back, TraceExportFormat::IntelHex);
    }

    #[test]
    fn test_format_hex_line_without_addresses() {
        let cmd = ExportTraceBackgroundCmd::new(
            TraceExportFormat::AsciiHex,
            "/tmp/out",
            0,
            0xff,
            0,
        ).with_addresses(false);
        let line = cmd.format_hex_line(0x1000, &[0xAA]);
        assert!(!line.contains("1000"));
        assert!(line.contains("aa"));
    }
}
