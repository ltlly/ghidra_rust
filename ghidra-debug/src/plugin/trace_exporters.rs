//! Trace view exporters.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.export` package.
//! Provides exporters for trace data in various formats: ASCII, HTML,
//! XML, binary, and Intel HEX.

use serde::{Deserialize, Serialize};
use std::fmt;

/// The output format for trace export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraceExportFormat {
    /// Plain ASCII text representation.
    Ascii,
    /// HTML formatted output.
    Html,
    /// XML formatted output.
    Xml,
    /// Raw binary dump.
    Binary,
    /// Intel HEX format.
    IntelHex,
}

impl fmt::Display for TraceExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ascii => write!(f, "ASCII"),
            Self::Html => write!(f, "HTML"),
            Self::Xml => write!(f, "XML"),
            Self::Binary => write!(f, "Binary"),
            Self::IntelHex => write!(f, "Intel HEX"),
        }
    }
}

/// Configuration for exporting trace data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceExportConfig {
    /// The export format.
    pub format: TraceExportFormat,
    /// The trace key to export from.
    pub trace_key: i64,
    /// The snapshot to export (None for latest).
    pub snapshot: Option<i64>,
    /// Start address for the export range.
    pub start_address: u64,
    /// End address for the export range.
    pub end_address: u64,
    /// Whether to include comments in the output.
    pub include_comments: bool,
    /// Whether to include data type annotations.
    pub include_data_types: bool,
}

impl TraceExportConfig {
    /// Create a new export config.
    pub fn new(format: TraceExportFormat, trace_key: i64, start: u64, end: u64) -> Self {
        Self {
            format,
            trace_key,
            snapshot: None,
            start_address: start,
            end_address: end,
            include_comments: true,
            include_data_types: false,
        }
    }

    /// Set the snapshot.
    pub fn with_snapshot(mut self, snap: i64) -> Self {
        self.snapshot = Some(snap);
        self
    }

    /// Set whether to include comments.
    pub fn with_comments(mut self, include: bool) -> Self {
        self.include_comments = include;
        self
    }

    /// Set whether to include data types.
    pub fn with_data_types(mut self, include: bool) -> Self {
        self.include_data_types = include;
        self
    }

    /// Get the number of bytes in the export range.
    pub fn range_size(&self) -> u64 {
        self.end_address.saturating_sub(self.start_address)
    }
}

/// Result of a trace export operation.
#[derive(Debug, Clone)]
pub struct TraceExportResult {
    /// The export format used.
    pub format: TraceExportFormat,
    /// The exported data.
    pub data: Vec<u8>,
    /// The number of bytes exported.
    pub byte_count: usize,
    /// Any warnings generated during export.
    pub warnings: Vec<String>,
}

impl TraceExportResult {
    /// Create a new export result.
    pub fn new(format: TraceExportFormat, data: Vec<u8>) -> Self {
        let byte_count = data.len();
        Self {
            format,
            data,
            byte_count,
            warnings: Vec::new(),
        }
    }

    /// Add a warning to this result.
    pub fn with_warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }

    /// Get the data as a UTF-8 string (for text formats).
    pub fn as_text(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.data)
    }
}

/// An ASCII exporter for trace data.
///
/// Produces a plain-text representation of disassembly, data, and comments
/// within the specified address range.
#[derive(Debug, Default)]
pub struct TraceViewAsciiExporter;

impl TraceViewAsciiExporter {
    /// Export the given memory bytes as an ASCII hex dump.
    pub fn export_hex_dump(start_address: u64, data: &[u8]) -> String {
        let mut output = String::new();
        for (i, chunk) in data.chunks(16).enumerate() {
            let addr = start_address + (i as u64) * 16;
            output.push_str(&format!("{:08x}  ", addr));
            for (j, byte) in chunk.iter().enumerate() {
                if j == 8 {
                    output.push(' ');
                }
                output.push_str(&format!("{:02x} ", byte));
            }
            // Pad if less than 16 bytes
            for j in chunk.len()..16 {
                if j == 8 {
                    output.push(' ');
                }
                output.push_str("   ");
            }
            output.push_str(" |");
            for byte in chunk {
                if byte.is_ascii_graphic() || *byte == b' ' {
                    output.push(*byte as char);
                } else {
                    output.push('.');
                }
            }
            output.push('|');
            output.push('\n');
        }
        output
    }
}

/// An Intel HEX exporter for trace data.
///
/// Produces output in the Intel HEX record format, suitable for use with
/// programming tools and embedded systems.
#[derive(Debug, Default)]
pub struct TraceViewIntelHexExporter;

impl TraceViewIntelHexExporter {
    /// Export data as Intel HEX format.
    pub fn export(start_address: u64, data: &[u8]) -> String {
        let mut output = String::new();
        let mut addr = start_address as u16;

        for chunk in data.chunks(16) {
            let byte_count = chunk.len() as u8;
            let record_type = 0x00u8; // Data record
            let mut checksum = byte_count.wrapping_add((addr >> 8) as u8).wrapping_add((addr & 0xFF) as u8).wrapping_add(record_type);

            let mut line = format!(":{:02X}{:04X}{:02X}", byte_count, addr, record_type);
            for &byte in chunk {
                line.push_str(&format!("{:02X}", byte));
                checksum = checksum.wrapping_add(byte);
            }
            checksum = (!checksum).wrapping_add(1);
            line.push_str(&format!("{:02X}", checksum));
            output.push_str(&line);
            output.push('\n');

            addr = addr.wrapping_add(chunk.len() as u16);
        }

        // End of file record
        output.push_str(":00000001FF\n");
        output
    }

    /// Parse an Intel HEX record from a line.
    pub fn parse_record(line: &str) -> Result<IntelHexRecord, String> {
        let line = line.trim();
        if !line.starts_with(':') {
            return Err("Record must start with ':'".into());
        }
        let hex = &line[1..];
        if hex.len() < 10 {
            return Err("Record too short".into());
        }

        let byte_count = u8::from_str_radix(&hex[0..2], 16)
            .map_err(|_| "Invalid byte count")?;
        let address = u16::from_str_radix(&hex[2..6], 16)
            .map_err(|_| "Invalid address")?;
        let record_type = u8::from_str_radix(&hex[6..8], 16)
            .map_err(|_| "Invalid record type")?;

        let data_end = 8 + (byte_count as usize) * 2;
        if hex.len() < data_end + 2 {
            return Err("Record data too short".into());
        }

        let mut data = Vec::with_capacity(byte_count as usize);
        for i in (8..data_end).step_by(2) {
            let byte = u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| "Invalid data byte")?;
            data.push(byte);
        }

        let checksum = u8::from_str_radix(&hex[data_end..data_end + 2], 16)
            .map_err(|_| "Invalid checksum")?;

        Ok(IntelHexRecord {
            byte_count,
            address,
            record_type,
            data,
            checksum,
        })
    }
}

/// A parsed Intel HEX record.
#[derive(Debug, Clone, PartialEq)]
pub struct IntelHexRecord {
    /// Number of data bytes.
    pub byte_count: u8,
    /// The address field.
    pub address: u16,
    /// The record type (0x00=data, 0x01=EOF, etc.).
    pub record_type: u8,
    /// The data bytes.
    pub data: Vec<u8>,
    /// The checksum byte.
    pub checksum: u8,
}

impl IntelHexRecord {
    /// Whether this is an end-of-file record.
    pub fn is_eof(&self) -> bool {
        self.record_type == 0x01
    }

    /// Whether this is a data record.
    pub fn is_data(&self) -> bool {
        self.record_type == 0x00
    }

    /// Verify the checksum.
    pub fn verify_checksum(&self) -> bool {
        let mut sum = self.byte_count;
        sum = sum.wrapping_add((self.address >> 8) as u8);
        sum = sum.wrapping_add((self.address & 0xFF) as u8);
        sum = sum.wrapping_add(self.record_type);
        for &b in &self.data {
            sum = sum.wrapping_add(b);
        }
        sum = sum.wrapping_add(self.checksum);
        sum == 0
    }
}

/// An HTML exporter for trace data.
#[derive(Debug, Default)]
pub struct TraceViewHtmlExporter;

impl TraceViewHtmlExporter {
    /// Export a simple HTML table of address/bytes/mnemonic.
    pub fn export_rows(rows: &[(u64, &[u8], &str)]) -> String {
        let mut html = String::from("<table border=\"1\">\n");
        html.push_str("<tr><th>Address</th><th>Bytes</th><th>Mnemonic</th></tr>\n");
        for (addr, bytes, mnemonic) in rows {
            let hex_bytes: Vec<String> = bytes.iter().map(|b| format!("{:02x}", b)).collect();
            html.push_str(&format!(
                "<tr><td>{:08x}</td><td>{}</td><td>{}</td></tr>\n",
                addr,
                hex_bytes.join(" "),
                html_escape(mnemonic),
            ));
        }
        html.push_str("</table>\n");
        html
    }
}

/// An XML exporter for trace data.
#[derive(Debug, Default)]
pub struct TraceViewXmlExporter;

impl TraceViewXmlExporter {
    /// Export address/byte pairs as XML.
    pub fn export_bytes(start_address: u64, data: &[u8]) -> String {
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<trace-dump>\n");
        for (i, &byte) in data.iter().enumerate() {
            let addr = start_address + i as u64;
            xml.push_str(&format!("  <byte address=\"{:#x}\" value=\"{:#04x}\"/>\n", addr, byte));
        }
        xml.push_str("</trace-dump>\n");
        xml
    }
}

/// A binary exporter (raw byte dump).
#[derive(Debug, Default)]
pub struct TraceViewBinaryExporter;

impl TraceViewBinaryExporter {
    /// Export raw bytes (identity transformation).
    pub fn export(data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
}

/// A trait for trace view exporters that can handle domain objects.
///
/// Ported from Ghidra's exporter pattern where each exporter overrides
/// `canExportDomainObject` to indicate compatibility.
pub trait TraceViewExporter: std::fmt::Debug {
    /// Whether this exporter can export the given domain object type.
    fn can_export_domain_object(&self, domain_type: &str) -> bool;

    /// Get the supported export format.
    fn format(&self) -> TraceExportFormat;

    /// Get configurable options for this exporter.
    fn options(&self) -> Vec<ExportOption> {
        Vec::new()
    }
}

/// A configurable export option.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportOption {
    /// Option name.
    pub name: String,
    /// Option description.
    pub description: String,
    /// Default value.
    pub default_value: ExportOptionValue,
    /// Current value.
    pub value: ExportOptionValue,
}

/// The value type for an export option.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportOptionValue {
    /// Boolean option.
    Bool(bool),
    /// Integer option.
    Int(i64),
    /// String option.
    String(String),
}

/// A registry of trace view exporters.
#[derive(Debug, Default)]
pub struct TraceExporterRegistry {
    exporters: Vec<Box<dyn TraceViewExporter>>,
}

impl TraceExporterRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            exporters: Vec::new(),
        }
    }

    /// Register an exporter.
    pub fn register(&mut self, exporter: Box<dyn TraceViewExporter>) {
        self.exporters.push(exporter);
    }

    /// Find all exporters that can handle the given domain type.
    pub fn find_exporters(&self, domain_type: &str) -> Vec<TraceExportFormat> {
        self.exporters
            .iter()
            .filter(|e| e.can_export_domain_object(domain_type))
            .map(|e| e.format())
            .collect()
    }

    /// Get the number of registered exporters.
    pub fn len(&self) -> usize {
        self.exporters.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.exporters.is_empty()
    }
}

/// Escape HTML special characters.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_format_display() {
        assert_eq!(format!("{}", TraceExportFormat::Ascii), "ASCII");
        assert_eq!(format!("{}", TraceExportFormat::Html), "HTML");
        assert_eq!(format!("{}", TraceExportFormat::IntelHex), "Intel HEX");
    }

    #[test]
    fn test_export_config() {
        let config = TraceExportConfig::new(TraceExportFormat::Ascii, 1, 0, 0x1000)
            .with_snapshot(5)
            .with_comments(true);
        assert_eq!(config.range_size(), 0x1000);
        assert_eq!(config.snapshot, Some(5));
    }

    #[test]
    fn test_ascii_hex_dump() {
        let data = vec![0x48, 0x65, 0x6C, 0x6C, 0x6F];
        let dump = TraceViewAsciiExporter::export_hex_dump(0, &data);
        assert!(dump.contains("00000000"));
        assert!(dump.contains("48 65 6c 6c 6f"));
        assert!(dump.contains("|Hello|"));
    }

    #[test]
    fn test_intel_hex_export() {
        let data = vec![0x02, 0x00, 0x00, 0x02, 0x00, 0x30];
        let hex = TraceViewIntelHexExporter::export(0x0000, &data);
        assert!(hex.starts_with(':'));
        assert!(hex.contains(":00000001FF")); // EOF record
    }

    #[test]
    fn test_intel_hex_round_trip() {
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let hex = TraceViewIntelHexExporter::export(0x1000, &data);
        for line in hex.lines() {
            if line.starts_with(':') && line.len() > 10 {
                let record = TraceViewIntelHexExporter::parse_record(line).unwrap();
                assert!(record.verify_checksum());
            }
        }
    }

    #[test]
    fn test_intel_hex_record_types() {
        let data_record = IntelHexRecord {
            byte_count: 2,
            address: 0,
            record_type: 0x00,
            data: vec![0x12, 0x34],
            checksum: 0xCA,
        };
        assert!(data_record.is_data());
        assert!(!data_record.is_eof());

        let eof_record = IntelHexRecord {
            byte_count: 0,
            address: 0,
            record_type: 0x01,
            data: vec![],
            checksum: 0xFF,
        };
        assert!(eof_record.is_eof());
    }

    #[test]
    fn test_html_export() {
        let rows: Vec<(u64, Vec<u8>, String)> = vec![
            (0x400000, vec![0x90], "NOP".into()),
            (0x400001, vec![0xCC], "INT3".into()),
        ];
        let row_refs: Vec<(u64, &[u8], &str)> = rows
            .iter()
            .map(|(a, b, m)| (*a, b.as_slice(), m.as_str()))
            .collect();
        let html = TraceViewHtmlExporter::export_rows(&row_refs);
        assert!(html.contains("<table"));
        assert!(html.contains("400000"));
        assert!(html.contains("NOP"));
    }

    #[test]
    fn test_xml_export() {
        let data = vec![0x90, 0xCC];
        let xml = TraceViewXmlExporter::export_bytes(0x400000, &data);
        assert!(xml.contains("<?xml"));
        assert!(xml.contains("trace-dump"));
        assert!(xml.contains("400000"));
    }

    #[test]
    fn test_binary_export() {
        let data = vec![1, 2, 3, 4];
        let exported = TraceViewBinaryExporter::export(&data);
        assert_eq!(exported, data);
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("a<b>c"), "a&lt;b&gt;c");
        assert_eq!(html_escape("a&b"), "a&amp;b");
    }

    #[test]
    fn test_export_result() {
        let result = TraceExportResult::new(TraceExportFormat::Ascii, vec![65, 66, 67])
            .with_warning("Truncated");
        assert_eq!(result.byte_count, 3);
        assert_eq!(result.as_text().unwrap(), "ABC");
        assert_eq!(result.warnings.len(), 1);
    }
}
