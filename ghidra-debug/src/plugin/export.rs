//! Trace view exporters.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.export` package.
//! Provides exporters for trace data in various formats (ASCII, binary,
//! HTML, Intel HEX, XML).

use serde::{Deserialize, Serialize};


/// Supported export formats for trace data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExportFormat {
    /// Plain text (ASCII).
    Ascii,
    /// Raw binary.
    Binary,
    /// HTML formatted output.
    Html,
    /// Intel HEX format.
    IntelHex,
    /// XML formatted output.
    Xml,
}

impl std::fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ascii => write!(f, "ASCII"),
            Self::Binary => write!(f, "Binary"),
            Self::Html => write!(f, "HTML"),
            Self::IntelHex => write!(f, "Intel HEX"),
            Self::Xml => write!(f, "XML"),
        }
    }
}

/// Configuration for a trace export operation.
///
/// Ported from Ghidra's various `TraceView*Exporter` classes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceExportConfig {
    /// The export format.
    pub format: ExportFormat,
    /// The address range start.
    pub start_address: u64,
    /// The address range end (inclusive).
    pub end_address: u64,
    /// The snap to export.
    pub snap: i64,
    /// Whether to include address headers.
    pub include_headers: bool,
    /// The column width for hex output.
    pub column_width: usize,
    /// Whether to include ASCII representation alongside hex.
    pub include_ascii: bool,
}

impl TraceExportConfig {
    /// Create a new export config.
    pub fn new(format: ExportFormat, start: u64, end: u64, snap: i64) -> Self {
        Self {
            format,
            start_address: start,
            end_address: end,
            snap,
            include_headers: true,
            column_width: 16,
            include_ascii: true,
        }
    }

    /// Create an ASCII export config.
    pub fn ascii(start: u64, end: u64, snap: i64) -> Self {
        Self::new(ExportFormat::Ascii, start, end, snap)
    }

    /// Create a binary export config.
    pub fn binary(start: u64, end: u64, snap: i64) -> Self {
        Self::new(ExportFormat::Binary, start, end, snap)
    }

    /// Create an HTML export config.
    pub fn html(start: u64, end: u64, snap: i64) -> Self {
        Self::new(ExportFormat::Html, start, end, snap)
    }

    /// Create an Intel HEX export config.
    pub fn intel_hex(start: u64, end: u64, snap: i64) -> Self {
        Self::new(ExportFormat::IntelHex, start, end, snap)
    }

    /// Create an XML export config.
    pub fn xml(start: u64, end: u64, snap: i64) -> Self {
        Self::new(ExportFormat::Xml, start, end, snap)
    }

    /// The size of the export range.
    pub fn range_size(&self) -> u64 {
        self.end_address - self.start_address + 1
    }
}

/// Format a byte slice as an Intel HEX record.
///
/// Each record has the format: `:LLAAAATT[DD...]CC`
/// - LL: byte count
/// - AAAA: address
/// - TT: record type (00=data, 01=EOF)
/// - DD: data bytes
/// - CC: checksum
pub fn format_intel_hex(address: u16, data: &[u8], record_type: u8) -> String {
    let len = data.len().min(255) as u8;
    let mut line = format!(":{:02X}{:04X}{:02X}", len, address, record_type);
    let mut checksum: u8 = len.wrapping_add((address >> 8) as u8).wrapping_add((address & 0xff) as u8).wrapping_add(record_type);
    for &b in &data[..len as usize] {
        line.push_str(&format!("{:02X}", b));
        checksum = checksum.wrapping_add(b);
    }
    let checksum = (!checksum).wrapping_add(1);
    line.push_str(&format!("{:02X}", checksum));
    line
}

/// Format data as an Intel HEX stream.
pub fn format_intel_hex_stream(start_address: u64, data: &[u8], bytes_per_line: usize) -> String {
    let mut output = String::new();
    let mut offset = 0u64;
    for chunk in data.chunks(bytes_per_line) {
        let addr = (start_address + offset) as u16;
        output.push_str(&format_intel_hex(addr, chunk, 0x00));
        output.push('\n');
        offset += chunk.len() as u64;
    }
    // EOF record
    output.push_str(&format_intel_hex(0, &[], 0x01));
    output.push('\n');
    output
}

/// Format a byte slice as a hex dump with ASCII representation.
pub fn format_hex_dump(start_address: u64, data: &[u8], column_width: usize) -> String {
    let mut output = String::new();
    for (i, chunk) in data.chunks(column_width).enumerate() {
        let addr = start_address + (i * column_width) as u64;
        output.push_str(&format!("{:08x}  ", addr));

        for (j, &byte) in chunk.iter().enumerate() {
            output.push_str(&format!("{:02x} ", byte));
            if j == column_width / 2 - 1 {
                output.push(' ');
            }
        }
        // Padding
        if chunk.len() < column_width {
            for j in chunk.len()..column_width {
                output.push_str("   ");
                if j == column_width / 2 - 1 {
                    output.push(' ');
                }
            }
        }

        output.push_str(" |");
        for &byte in chunk {
            if byte >= 0x20 && byte <= 0x7e {
                output.push(byte as char);
            } else {
                output.push('.');
            }
        }
        output.push_str("|\n");
    }
    output
}

/// Format data as XML.
pub fn format_trace_xml(start_address: u64, data: &[u8]) -> String {
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str(&format!(
        "<trace-dump start=\"0x{:x}\" length=\"{}\">\n",
        start_address,
        data.len()
    ));
    for (i, chunk) in data.chunks(16).enumerate() {
        let addr = start_address + (i * 16) as u64;
        xml.push_str(&format!("  <bytes address=\"0x{:x}\">", addr));
        for &b in chunk {
            xml.push_str(&format!("{:02x}", b));
        }
        xml.push_str("</bytes>\n");
    }
    xml.push_str("</trace-dump>\n");
    xml
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_format_display() {
        assert_eq!(ExportFormat::Ascii.to_string(), "ASCII");
        assert_eq!(ExportFormat::IntelHex.to_string(), "Intel HEX");
    }

    #[test]
    fn test_export_config() {
        let config = TraceExportConfig::ascii(0x400000, 0x4000ff, 0);
        assert_eq!(config.format, ExportFormat::Ascii);
        assert_eq!(config.range_size(), 0x100);
    }

    #[test]
    fn test_intel_hex_record() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let record = format_intel_hex(0x1000, &data, 0x00);
        assert!(record.starts_with(':'));
        assert_eq!(&record[1..3], "04"); // length
        assert_eq!(&record[3..7], "1000"); // address
        assert_eq!(&record[7..9], "00"); // type
    }

    #[test]
    fn test_intel_hex_eof() {
        let record = format_intel_hex(0, &[], 0x01);
        assert_eq!(record, ":00000001FF");
    }

    #[test]
    fn test_intel_hex_stream() {
        let data = vec![0xAA; 32];
        let output = format_intel_hex_stream(0x400000, &data, 16);
        let lines: Vec<&str> = output.trim().lines().collect();
        assert_eq!(lines.len(), 3); // 2 data + 1 EOF
        assert!(lines[2].contains("01")); // EOF record type
    }

    #[test]
    fn test_hex_dump() {
        let data = vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]; // "Hello"
        let dump = format_hex_dump(0x1000, &data, 16);
        assert!(dump.contains("1000"));
        assert!(dump.contains("48"));
        assert!(dump.contains("Hello"));
    }

    #[test]
    fn test_hex_dump_non_printable() {
        let data = vec![0x00, 0x01, 0x7f];
        let dump = format_hex_dump(0x0, &data, 16);
        assert!(dump.contains("...")); // dots for non-printable
    }

    #[test]
    fn test_trace_xml() {
        let data = vec![0xCA, 0xFE];
        let xml = format_trace_xml(0x400000, &data);
        assert!(xml.contains("<?xml"));
        assert!(xml.contains("trace-dump"));
        assert!(xml.contains("cafe"));
    }

    #[test]
    fn test_export_config_range_size() {
        let config = TraceExportConfig::binary(0, 0xff, 0);
        assert_eq!(config.range_size(), 256);
    }

    #[test]
    fn test_export_configs() {
        let c = TraceExportConfig::html(0x1000, 0x2000, 5);
        assert_eq!(c.format, ExportFormat::Html);
        assert_eq!(c.snap, 5);

        let c = TraceExportConfig::intel_hex(0, 0xff, 0);
        assert_eq!(c.format, ExportFormat::IntelHex);

        let c = TraceExportConfig::xml(0, 0xff, 0);
        assert_eq!(c.format, ExportFormat::Xml);
    }
}
