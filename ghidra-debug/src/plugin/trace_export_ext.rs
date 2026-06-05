//! Extended trace export types ported from Java.
//!
//! Ported from the Debugger module's `export` package. Provides
//! export formats for trace views: ASCII, binary, HTML, Intel HEX, and XML.

/// Supported export formats for trace data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TraceExportFormat {
    /// Plain ASCII text export.
    Ascii,
    /// Raw binary export.
    Binary,
    /// HTML formatted export.
    Html,
    /// Intel HEX format export.
    IntelHex,
    /// XML formatted export.
    Xml,
}

impl TraceExportFormat {
    /// Get the file extension for this format.
    pub fn file_extension(&self) -> &'static str {
        match self {
            Self::Ascii => "txt",
            Self::Binary => "bin",
            Self::Html => "html",
            Self::IntelHex => "hex",
            Self::Xml => "xml",
        }
    }

    /// Get the MIME type for this format.
    pub fn mime_type(&self) -> &'static str {
        match self {
            Self::Ascii => "text/plain",
            Self::Binary => "application/octet-stream",
            Self::Html => "text/html",
            Self::IntelHex => "text/plain",
            Self::Xml => "application/xml",
        }
    }

    /// Get a human-readable name for this format.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Ascii => "ASCII Text",
            Self::Binary => "Raw Binary",
            Self::Html => "HTML Document",
            Self::IntelHex => "Intel HEX",
            Self::Xml => "XML Document",
        }
    }

    /// Get all available formats.
    pub fn all() -> &'static [TraceExportFormat] {
        &[
            Self::Ascii,
            Self::Binary,
            Self::Html,
            Self::IntelHex,
            Self::Xml,
        ]
    }
}

/// Configuration for exporting trace data.
#[derive(Debug, Clone)]
pub struct TraceExportConfig {
    /// The export format.
    pub format: TraceExportFormat,
    /// Start address of the export range.
    pub start_address: u64,
    /// End address of the export range.
    pub end_address: u64,
    /// The snap (time point) to export from.
    pub snap: i64,
    /// Whether to include addresses in the output.
    pub include_addresses: bool,
    /// Whether to include comments in the output.
    pub include_comments: bool,
    /// Output file path (if writing to file).
    pub output_path: Option<String>,
}

impl TraceExportConfig {
    /// Create a new export config.
    pub fn new(format: TraceExportFormat, start_address: u64, end_address: u64, snap: i64) -> Self {
        Self {
            format,
            start_address,
            end_address,
            snap,
            include_addresses: true,
            include_comments: false,
            output_path: None,
        }
    }

    /// Get the size of the export range in bytes.
    pub fn range_size(&self) -> u64 {
        self.end_address.saturating_sub(self.start_address)
    }

    /// Set the output file path.
    pub fn with_output(mut self, path: impl Into<String>) -> Self {
        self.output_path = Some(path.into());
        self
    }
}

/// Trait for trace view exporters.
pub trait TraceViewExporter: Send + Sync {
    /// Whether this exporter can handle the given domain object class.
    fn can_export(&self, domain_type: &str) -> bool;

    /// Get the supported format.
    fn format(&self) -> TraceExportFormat;

    /// Export trace data to the given output.
    fn export(&self, config: &TraceExportConfig, data: &[u8]) -> Result<Vec<u8>, String>;
}

/// ASCII trace view exporter.
pub struct AsciiTraceExporter;

impl TraceViewExporter for AsciiTraceExporter {
    fn can_export(&self, domain_type: &str) -> bool {
        domain_type == "Trace" || domain_type == "Program"
    }

    fn format(&self) -> TraceExportFormat {
        TraceExportFormat::Ascii
    }

    fn export(&self, config: &TraceExportConfig, data: &[u8]) -> Result<Vec<u8>, String> {
        let mut output = Vec::new();
        for (i, &byte) in data.iter().enumerate() {
            let addr = config.start_address + i as u64;
            if config.include_addresses {
                output.extend_from_slice(format!("{:08x}: ", addr).as_bytes());
            }
            output.extend_from_slice(format!("{:02x}\n", byte).as_bytes());
        }
        Ok(output)
    }
}

/// Binary trace view exporter.
pub struct BinaryTraceExporter;

impl TraceViewExporter for BinaryTraceExporter {
    fn can_export(&self, domain_type: &str) -> bool {
        domain_type == "Trace"
    }

    fn format(&self) -> TraceExportFormat {
        TraceExportFormat::Binary
    }

    fn export(&self, _config: &TraceExportConfig, data: &[u8]) -> Result<Vec<u8>, String> {
        Ok(data.to_vec())
    }
}

/// HTML trace view exporter.
pub struct HtmlTraceExporter;

impl TraceViewExporter for HtmlTraceExporter {
    fn can_export(&self, domain_type: &str) -> bool {
        domain_type == "Trace"
    }

    fn format(&self) -> TraceExportFormat {
        TraceExportFormat::Html
    }

    fn export(&self, config: &TraceExportConfig, data: &[u8]) -> Result<Vec<u8>, String> {
        let mut html = String::from("<html><body><pre>\n");
        for (i, &byte) in data.iter().enumerate() {
            let addr = config.start_address + i as u64;
            html.push_str(&format!("{:08x}: {:02x}\n", addr, byte));
        }
        html.push_str("</pre></body></html>");
        Ok(html.into_bytes())
    }
}

/// Intel HEX trace view exporter.
pub struct IntelHexTraceExporter;

impl TraceViewExporter for IntelHexTraceExporter {
    fn can_export(&self, domain_type: &str) -> bool {
        domain_type == "Trace"
    }

    fn format(&self) -> TraceExportFormat {
        TraceExportFormat::IntelHex
    }

    fn export(&self, config: &TraceExportConfig, data: &[u8]) -> Result<Vec<u8>, String> {
        let mut output = String::new();
        let mut addr = config.start_address;
        for chunk in data.chunks(16) {
            let byte_count = chunk.len() as u8;
            let addr16 = (addr & 0xFFFF) as u16;
            let mut record = format!(
                "{:02X}{:04X}00",
                byte_count, addr16
            );
            for &b in chunk {
                record.push_str(&format!("{:02X}", b));
            }
            // Simple checksum
            let checksum = byte_count
                .wrapping_add((addr16 >> 8) as u8)
                .wrapping_add((addr16 & 0xFF) as u8)
                .wrapping_add(
                    chunk.iter().fold(0u8, |acc, &b| acc.wrapping_add(b)),
                )
                .wrapping_neg();
            record.push_str(&format!("{:02X}", checksum));
            output.push_str(&format!(":{}\n", record));
            addr += chunk.len() as u64;
        }
        output.push_str(":00000001FF\n"); // EOF record
        Ok(output.into_bytes())
    }
}

/// XML trace view exporter.
pub struct XmlTraceExporter;

impl TraceViewExporter for XmlTraceExporter {
    fn can_export(&self, domain_type: &str) -> bool {
        domain_type == "Trace"
    }

    fn format(&self) -> TraceExportFormat {
        TraceExportFormat::Xml
    }

    fn export(&self, config: &TraceExportConfig, data: &[u8]) -> Result<Vec<u8>, String> {
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<trace-dump>\n");
        for (i, &byte) in data.iter().enumerate() {
            let addr = config.start_address + i as u64;
            xml.push_str(&format!("  <byte address=\"{:#x}\" value=\"{:#04x}\"/>\n", addr, byte));
        }
        xml.push_str("</trace-dump>");
        Ok(xml.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_format_properties() {
        assert_eq!(TraceExportFormat::Ascii.file_extension(), "txt");
        assert_eq!(TraceExportFormat::Html.mime_type(), "text/html");
        assert_eq!(TraceExportFormat::IntelHex.display_name(), "Intel HEX");
        assert_eq!(TraceExportFormat::all().len(), 5);
    }

    #[test]
    fn test_export_config() {
        let config = TraceExportConfig::new(TraceExportFormat::Ascii, 0x400000, 0x400100, 0);
        assert_eq!(config.range_size(), 0x100);
    }

    #[test]
    fn test_ascii_export() {
        let exporter = AsciiTraceExporter;
        assert!(exporter.can_export("Trace"));
        assert!(!exporter.can_export("Unknown"));

        let config = TraceExportConfig::new(TraceExportFormat::Ascii, 0x400000, 0x400004, 0);
        let data = vec![0x55, 0xAA, 0x00, 0xFF];
        let result = exporter.export(&config, &data).unwrap();
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("400000: 55"));
        assert!(text.contains("400003: ff"));
    }

    #[test]
    fn test_binary_export() {
        let exporter = BinaryTraceExporter;
        let config = TraceExportConfig::new(TraceExportFormat::Binary, 0, 4, 0);
        let data = vec![1, 2, 3, 4];
        let result = exporter.export(&config, &data).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_html_export() {
        let exporter = HtmlTraceExporter;
        let config = TraceExportConfig::new(TraceExportFormat::Html, 0x100, 0x102, 0);
        let data = vec![0xAB, 0xCD];
        let result = exporter.export(&config, &data).unwrap();
        let html = String::from_utf8(result).unwrap();
        assert!(html.contains("<html>"));
        assert!(html.contains("00000100: ab"));
    }

    #[test]
    fn test_intel_hex_export() {
        let exporter = IntelHexTraceExporter;
        let config = TraceExportConfig::new(TraceExportFormat::IntelHex, 0, 4, 0);
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let result = exporter.export(&config, &data).unwrap();
        let hex = String::from_utf8(result).unwrap();
        // Check the record starts with :0400000001020304 (length, addr, type, data)
        assert!(hex.contains(":0400000001020304"));
        assert!(hex.contains(":00000001FF"));
        // Verify it's valid hex (each line starts with ':')
        for line in hex.lines() {
            assert!(line.starts_with(':'));
        }
    }

    #[test]
    fn test_xml_export() {
        let exporter = XmlTraceExporter;
        let config = TraceExportConfig::new(TraceExportFormat::Xml, 0, 2, 0);
        let data = vec![0xAA, 0xBB];
        let result = exporter.export(&config, &data).unwrap();
        let xml = String::from_utf8(result).unwrap();
        assert!(xml.contains("<?xml"));
        assert!(xml.contains("trace-dump"));
        assert!(xml.contains("0xaa"));
    }
}
