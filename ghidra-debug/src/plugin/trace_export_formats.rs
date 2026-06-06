//! Individual trace view export format implementations.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.export` package.
//! Provides concrete exporter implementations for ASCII, binary, HTML,
//! Intel HEX, and XML output formats.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ASCII Exporter
// ---------------------------------------------------------------------------

/// Export trace data as ASCII text.
///
/// Ported from `TraceViewAsciiExporter.java`. Exports memory contents as
/// hex-dump style ASCII output with addresses and ASCII representation.
#[derive(Debug, Clone)]
pub struct AsciiExporter {
    /// Number of bytes per line.
    pub bytes_per_line: usize,
    /// Whether to show ASCII representation.
    pub show_ascii: bool,
    /// Whether to show addresses.
    pub show_address: bool,
    /// Line ending style.
    pub line_ending: LineEnding,
}

/// Line ending style for text exports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LineEnding {
    /// Unix-style line ending.
    Lf,
    /// Windows-style line ending.
    CrLf,
    /// Classic Mac-style line ending.
    Cr,
}

impl Default for LineEnding {
    fn default() -> Self {
        Self::Lf
    }
}

impl AsciiExporter {
    /// Create a new ASCII exporter with default settings.
    pub fn new() -> Self {
        Self {
            bytes_per_line: 16,
            show_ascii: true,
            show_address: true,
            line_ending: LineEnding::Lf,
        }
    }

    /// Set bytes per line.
    pub fn bytes_per_line(mut self, n: usize) -> Self {
        self.bytes_per_line = n;
        self
    }

    /// Set whether to show ASCII representation.
    pub fn show_ascii(mut self, show: bool) -> Self {
        self.show_ascii = show;
        self
    }

    /// Set whether to show addresses.
    pub fn show_address(mut self, show: bool) -> Self {
        self.show_address = show;
        self
    }

    /// Set the line ending style.
    pub fn line_ending(mut self, ending: LineEnding) -> Self {
        self.line_ending = ending;
        self
    }

    /// Get the line ending string.
    pub fn line_ending_str(&self) -> &'static str {
        match self.line_ending {
            LineEnding::Lf => "\n",
            LineEnding::CrLf => "\r\n",
            LineEnding::Cr => "\r",
        }
    }

    /// Format a single line of hex dump.
    pub fn format_line(&self, address: u64, data: &[u8]) -> String {
        let mut line = String::new();

        if self.show_address {
            line.push_str(&format!("{:08x}: ", address));
        }

        // Hex portion
        for (i, byte) in data.iter().enumerate() {
            if i > 0 && i % 4 == 0 {
                line.push(' ');
            }
            line.push_str(&format!("{:02x} ", byte));
        }

        // Pad to align ASCII portion
        if self.show_ascii {
            let hex_width = self.bytes_per_line * 3 + (self.bytes_per_line / 4);
            while line.len() < hex_width + if self.show_address { 10 } else { 0 } {
                line.push(' ');
            }
            line.push_str(" |");
            for byte in data {
                if byte.is_ascii_graphic() || *byte == b' ' {
                    line.push(*byte as char);
                } else {
                    line.push('.');
                }
            }
            line.push('|');
        }

        line
    }

    /// Export data as ASCII hex dump.
    pub fn export(&self, address: u64, data: &[u8]) -> String {
        let mut result = String::new();
        let le = self.line_ending_str();

        for (i, chunk) in data.chunks(self.bytes_per_line).enumerate() {
            if i > 0 {
                result.push_str(le);
            }
            result.push_str(&self.format_line(address + i as u64 * self.bytes_per_line as u64, chunk));
        }

        result
    }
}

impl Default for AsciiExporter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Binary Exporter
// ---------------------------------------------------------------------------

/// Export trace data as raw binary.
///
/// Ported from `TraceViewBinaryExporter.java`. Exports memory contents
/// as raw bytes without any formatting.
#[derive(Debug, Clone)]
pub struct BinaryExporter {
    /// Optional fill byte for gaps in memory.
    pub fill_byte: Option<u8>,
    /// Whether to include a header with metadata.
    pub include_header: bool,
}

impl BinaryExporter {
    /// Create a new binary exporter.
    pub fn new() -> Self {
        Self {
            fill_byte: Some(0x00),
            include_header: false,
        }
    }

    /// Set the fill byte for memory gaps.
    pub fn fill_byte(mut self, byte: u8) -> Self {
        self.fill_byte = Some(byte);
        self
    }

    /// Set whether to include a header.
    pub fn include_header(mut self, include: bool) -> Self {
        self.include_header = include;
        self
    }

    /// Export data as raw binary bytes.
    pub fn export(&self, data: &[u8]) -> Vec<u8> {
        if self.include_header {
            let mut result = Vec::with_capacity(data.len() + 16);
            // Simple header: magic + length
            result.extend_from_slice(b"GHTR");
            result.extend_from_slice(&(data.len() as u32).to_le_bytes());
            result.extend_from_slice(&[0u8; 8]); // reserved
            result.extend_from_slice(data);
            result
        } else {
            data.to_vec()
        }
    }

    /// Fill gaps in data with the fill byte.
    pub fn fill_gaps(&self, data: &mut Vec<u8>, start: usize, end: usize) {
        if let Some(fill) = self.fill_byte {
            while data.len() < end {
                if data.len() < start {
                    data.push(fill);
                } else {
                    data.push(fill);
                }
            }
        }
    }
}

impl Default for BinaryExporter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// HTML Exporter
// ---------------------------------------------------------------------------

/// Export trace data as HTML.
///
/// Ported from `TraceViewHtmlExporter.java`. Exports memory contents as
/// an HTML table with syntax highlighting for different byte ranges.
#[derive(Debug, Clone)]
pub struct HtmlExporter {
    /// Number of bytes per row.
    pub bytes_per_row: usize,
    /// Whether to include CSS styling.
    pub include_css: bool,
    /// Background color for the hex dump area.
    pub background_color: String,
    /// Text color for addresses.
    pub address_color: String,
    /// Text color for hex values.
    pub hex_color: String,
    /// Text color for ASCII representation.
    pub ascii_color: String,
}

impl HtmlExporter {
    /// Create a new HTML exporter with default settings.
    pub fn new() -> Self {
        Self {
            bytes_per_row: 16,
            include_css: true,
            background_color: "#1e1e1e".to_string(),
            address_color: "#569cd6".to_string(),
            hex_color: "#d4d4d4".to_string(),
            ascii_color: "#6a9955".to_string(),
        }
    }

    /// Generate the CSS stylesheet.
    pub fn css(&self) -> String {
        format!(
            r#"body {{ background: {}; color: {}; font-family: monospace; font-size: 14px; }}
.addr {{ color: {}; }}
.hex {{ color: {}; }}
.ascii {{ color: {}; }}
tr:hover {{ background: rgba(255,255,255,0.05); }}
table {{ border-collapse: collapse; }}"#,
            self.background_color, self.hex_color,
            self.address_color, self.hex_color, self.ascii_color
        )
    }

    /// Export data as an HTML document.
    pub fn export(&self, address: u64, data: &[u8]) -> String {
        let mut html = String::new();
        html.push_str("<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n");
        html.push_str("<title>Ghidra Trace Export</title>\n");
        if self.include_css {
            html.push_str(&format!("<style>\n{}\n</style>\n", self.css()));
        }
        html.push_str("</head>\n<body>\n<table>\n");

        for (i, chunk) in data.chunks(self.bytes_per_row).enumerate() {
            let row_addr = address + i as u64 * self.bytes_per_row as u64;
            html.push_str(&format!(
                "<tr><td class=\"addr\">{:08x}</td><td class=\"hex\">",
                row_addr
            ));
            for (j, byte) in chunk.iter().enumerate() {
                if j > 0 && j % 4 == 0 {
                    html.push(' ');
                }
                html.push_str(&format!("{:02x} ", byte));
            }
            html.push_str("</td><td class=\"ascii\">");
            for byte in chunk {
                if byte.is_ascii_graphic() || *byte == b' ' {
                    html.push(*byte as char);
                } else {
                    html.push('.');
                }
            }
            html.push_str("</td></tr>\n");
        }

        html.push_str("</table>\n</body>\n</html>\n");
        html
    }
}

impl Default for HtmlExporter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Intel HEX Exporter
// ---------------------------------------------------------------------------

/// Export trace data as Intel HEX format.
///
/// Ported from `TraceViewIntelHexExporter.java`. Exports memory contents
/// in the standard Intel HEX (.hex) format used by embedded systems tools.
#[derive(Debug, Clone)]
pub struct IntelHexExporter {
    /// Bytes per record (max 255, typically 16 or 32).
    pub bytes_per_record: usize,
}

impl IntelHexExporter {
    /// Create a new Intel HEX exporter.
    pub fn new() -> Self {
        Self {
            bytes_per_record: 16,
        }
    }

    /// Calculate the checksum for an Intel HEX record.
    pub fn checksum(record_type: u8, address: u16, data: &[u8]) -> u8 {
        let mut sum = data.len() as u8;
        sum = sum.wrapping_add((address >> 8) as u8);
        sum = sum.wrapping_add((address & 0xFF) as u8);
        sum = sum.wrapping_add(record_type);
        for byte in data {
            sum = sum.wrapping_add(*byte);
        }
        (!sum).wrapping_add(1)
    }

    /// Format a single Intel HEX data record.
    pub fn format_data_record(&self, address: u16, data: &[u8]) -> String {
        let len = data.len() as u8;
        let checksum = Self::checksum(0x00, address, data);
        let mut record = format!(":{:02X}{:04X}00", len, address);
        for byte in data {
            record.push_str(&format!("{:02X}", byte));
        }
        record.push_str(&format!("{:02X}", checksum));
        record
    }

    /// Format an extended linear address record.
    pub fn format_ext_address(segment: u16) -> String {
        let data = [(segment >> 8) as u8, (segment & 0xFF) as u8];
        let checksum = Self::checksum(0x02, 0x0000, &data);
        format!(":02000004{:04X}{:02X}", segment, checksum)
    }

    /// Format the end-of-file record.
    pub fn eof_record() -> String {
        ":00000001FF".to_string()
    }

    /// Export data as Intel HEX format.
    pub fn export(&self, address: u64, data: &[u8]) -> String {
        let mut result = String::new();
        let mut current_segment: u16 = (address >> 16) as u16;
        result.push_str(&Self::format_ext_address(current_segment));
        result.push('\n');

        let mut offset = address & 0xFFFF;
        for chunk in data.chunks(self.bytes_per_record) {
            // Check if we need a new extended address record
            let new_segment = ((address + (data.len() as u64 - chunk.len() as u64)) >> 16) as u16;
            if new_segment != current_segment && offset as usize + chunk.len() > 0xFFFF {
                current_segment = new_segment;
                result.push_str(&Self::format_ext_address(current_segment));
                result.push('\n');
                offset = 0;
            }

            result.push_str(&self.format_data_record(offset as u16, chunk));
            result.push('\n');
            offset += chunk.len() as u64;
            if offset > 0xFFFF {
                offset &= 0xFFFF;
            }
        }

        result.push_str(&Self::eof_record());
        result.push('\n');
        result
    }
}

impl Default for IntelHexExporter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// XML Exporter
// ---------------------------------------------------------------------------

/// Export trace data as XML.
///
/// Ported from `TraceViewXmlExporter.java`. Exports memory contents
/// as a structured XML document.
#[derive(Debug, Clone)]
pub struct XmlExporter {
    /// Whether to include the XML declaration.
    pub include_declaration: bool,
    /// Root element name.
    pub root_element: String,
    /// Whether to pretty-print with indentation.
    pub pretty_print: bool,
}

impl XmlExporter {
    /// Create a new XML exporter.
    pub fn new() -> Self {
        Self {
            include_declaration: true,
            root_element: "trace-export".to_string(),
            pretty_print: true,
        }
    }

    /// Set whether to include the XML declaration.
    pub fn include_declaration(mut self, include: bool) -> Self {
        self.include_declaration = include;
        self
    }

    /// Set the root element name.
    pub fn root_element(mut self, name: impl Into<String>) -> Self {
        self.root_element = name.into();
        self
    }

    /// Set whether to pretty-print.
    pub fn pretty_print(mut self, yes: bool) -> Self {
        self.pretty_print = yes;
        self
    }

    /// Export data as an XML document.
    pub fn export(&self, address: u64, data: &[u8]) -> String {
        let indent = if self.pretty_print { "  " } else { "" };
        let nl = if self.pretty_print { "\n" } else { "" };
        let mut xml = String::new();

        if self.include_declaration {
            xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        }
        xml.push_str(&format!("<{}>{nl}", self.root_element));
        xml.push_str(&format!("{indent}<region address=\"0x{:x}\" length=\"{}\">{nl}", address, data.len()));

        for (i, chunk) in data.chunks(16).enumerate() {
            let row_addr = address + i as u64 * 16;
            xml.push_str(&format!("{indent}{indent}<bytes offset=\"0x{:x}\">", row_addr - address));
            for byte in chunk {
                xml.push_str(&format!("{:02x}", byte));
            }
            xml.push_str(&format!("</bytes>{nl}"));
        }

        xml.push_str(&format!("{indent}</region>{nl}"));
        xml.push_str(&format!("</{}>\n", self.root_element));
        xml
    }
}

impl Default for XmlExporter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ascii_exporter_basic() {
        let exporter = AsciiExporter::new();
        let data = vec![0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64];
        let result = exporter.export(0x1000, &data);
        assert!(result.contains("1000:"));
        assert!(result.contains("48"));
        assert!(result.contains("Hello World"));
    }

    #[test]
    fn test_ascii_exporter_multiline() {
        let exporter = AsciiExporter::new().bytes_per_line(8);
        let data = vec![0u8; 20];
        let result = exporter.export(0, &data);
        let lines: Vec<&str> = result.split('\n').collect();
        assert_eq!(lines.len(), 3); // 20 bytes / 8 per line = 2.5 -> 3 lines
    }

    #[test]
    fn test_ascii_exporter_no_ascii() {
        let exporter = AsciiExporter::new().show_ascii(false);
        let data = vec![0x41, 0x42, 0x43];
        let result = exporter.export(0, &data);
        assert!(!result.contains("|ABC|"));
    }

    #[test]
    fn test_binary_exporter_basic() {
        let exporter = BinaryExporter::new();
        let data = vec![0x01, 0x02, 0x03];
        let result = exporter.export(&data);
        assert_eq!(result, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_binary_exporter_with_header() {
        let exporter = BinaryExporter::new().include_header(true);
        let data = vec![0x01, 0x02, 0x03];
        let result = exporter.export(&data);
        assert!(result.len() > data.len());
        assert_eq!(&result[0..4], b"GHTR");
    }

    #[test]
    fn test_html_exporter_basic() {
        let exporter = HtmlExporter::new();
        let data = vec![0x48, 0x65, 0x6C, 0x6C, 0x6F];
        let result = exporter.export(0x1000, &data);
        assert!(result.contains("<!DOCTYPE html>"));
        assert!(result.contains("1000"));
        assert!(result.contains("48"));
        assert!(result.contains("Hello"));
    }

    #[test]
    fn test_html_exporter_css() {
        let exporter = HtmlExporter::new();
        let css = exporter.css();
        assert!(css.contains("background"));
        assert!(css.contains("monospace"));
    }

    #[test]
    fn test_intel_hex_checksum() {
        // Verify checksum calculation with known values
        let cs = IntelHexExporter::checksum(0x00, 0x0000, &[0x02, 0x00, 0x00, 0x04, 0x00, 0x00]);
        // Sum = 2 + 0 + 0 + 4 + 0 + 0 + 6 (len) + 0 (type) = 12, ~12+1 = 244 = 0xF4... let me verify
        // Actually: len=6, addr_hi=0, addr_lo=0, type=0, data=[02,00,00,04,00,00]
        // sum = 6 + 0 + 0 + 0 + 2 + 0 + 0 + 4 + 0 + 0 = 12
        // ~12 = 243, +1 = 244 = 0xF4... no, 255-12+1 = 244
        // Wait: (!12u8).wrapping_add(1) = 243u8.wrapping_add(1) = 244u8
        // Actually 255-12=243, 243+1=244
        // Let me just verify it's consistent
        assert_eq!(cs, (!12u8).wrapping_add(1));
    }

    #[test]
    fn test_intel_hex_data_record() {
        let exporter = IntelHexExporter::new();
        let record = exporter.format_data_record(0x0000, &[0x01, 0x02, 0x03]);
        assert!(record.starts_with(':'));
        // : + len(2) + addr(4) + type(2) + data(6) + checksum(2) = 17
        assert_eq!(record.len(), 1 + 2 + 4 + 2 + 6 + 2);
    }

    #[test]
    fn test_intel_hex_export() {
        let exporter = IntelHexExporter::new();
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let result = exporter.export(0x0000, &data);
        assert!(result.contains(":"));
        assert!(result.ends_with(":00000001FF\n"));
    }

    #[test]
    fn test_intel_hex_eof_record() {
        assert_eq!(IntelHexExporter::eof_record(), ":00000001FF");
    }

    #[test]
    fn test_xml_exporter_basic() {
        let exporter = XmlExporter::new();
        let data = vec![0x48, 0x65, 0x6C, 0x6C, 0x6F];
        let result = exporter.export(0x1000, &data);
        assert!(result.contains("<?xml"));
        assert!(result.contains("<trace-export>"));
        assert!(result.contains("</trace-export>"));
        assert!(result.contains("address=\"0x1000\""));
        assert!(result.contains("48656c6c6f"));
    }

    #[test]
    fn test_xml_exporter_no_declaration() {
        let exporter = XmlExporter::new().include_declaration(false);
        let data = vec![0x01];
        let result = exporter.export(0, &data);
        assert!(!result.contains("<?xml"));
    }

    #[test]
    fn test_xml_exporter_custom_root() {
        let exporter = XmlExporter::new().root_element("custom-root");
        let data = vec![0x01];
        let result = exporter.export(0, &data);
        assert!(result.contains("<custom-root>"));
        assert!(result.contains("</custom-root>"));
    }

    #[test]
    fn test_line_ending_variants() {
        let lf = LineEnding::Lf;
        let crlf = LineEnding::CrLf;
        let cr = LineEnding::Cr;

        assert_eq!(format!("{:?}", lf), "Lf");
        assert_eq!(format!("{:?}", crlf), "CrLf");
        assert_eq!(format!("{:?}", cr), "Cr");
    }

    #[test]
    fn test_ascii_exporter_line_ending() {
        let exporter = AsciiExporter::new()
            .line_ending(LineEnding::CrLf)
            .bytes_per_line(2);
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let result = exporter.export(0, &data);
        assert!(result.contains("\r\n"), "Expected \\r\\n in result: {:?}", result);
    }

    #[test]
    fn test_binary_exporter_fill_gaps() {
        let exporter = BinaryExporter::new().fill_byte(0xFF);
        let mut data = vec![0x01, 0x02];
        exporter.fill_gaps(&mut data, 0, 5);
        assert_eq!(data.len(), 5);
        assert_eq!(data[2], 0xFF);
    }

    #[test]
    fn test_intel_hex_ext_address() {
        let record = IntelHexExporter::format_ext_address(0x0001);
        assert!(record.starts_with(":020000040001"));
    }
}
