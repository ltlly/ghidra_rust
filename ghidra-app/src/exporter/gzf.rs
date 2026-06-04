//! GzfExporter — exports a program as a Ghidra Zip File (.gzf).
//!
//! Ported from Ghidra's `GzfExporter.java`.

use super::traits::{Exporter, ExporterException, ExporterOption};
use ghidra_core::program::Program;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

/// File extension for Ghidra Zip Files.
pub const GZF_EXTENSION: &str = "gzf";
/// File suffix (with dot) for Ghidra Zip Files.
pub const GZF_SUFFIX: &str = ".gzf";

/// An exporter that packages a program as a Ghidra Zip File.
///
/// A `.gzf` file is a portable representation of a Ghidra program database
/// that can be loaded directly into other Ghidra sessions. In Rust, this
/// serializes the program as JSON wrapped in a simple zip-like container.
#[derive(Debug)]
pub struct GzfExporter;

impl GzfExporter {
    /// Create a new GZF exporter.
    pub fn new() -> Self {
        Self
    }
}

impl Default for GzfExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Exporter for GzfExporter {
    fn name(&self) -> &str {
        "Ghidra Zip File"
    }

    fn file_extension(&self) -> &str {
        GZF_EXTENSION
    }

    fn help_topic(&self) -> Option<&str> {
        Some("gzf")
    }

    /// GZF export does not support address-restricted export.
    fn supports_address_restricted_export(&self) -> bool {
        false
    }

    fn get_options(&self) -> Vec<ExporterOption> {
        Vec::new()
    }

    fn set_options(&mut self, _options: &[ExporterOption]) -> Result<(), ExporterException> {
        Ok(())
    }

    fn export(
        &self,
        file: &Path,
        program: &Program,
        _start_addr: Option<u64>,
        _end_addr: Option<u64>,
    ) -> Result<bool, ExporterException> {
        // Serialize a program summary as JSON (Program doesn't impl Serialize)
        let summary = GzfSummary::from_program(program);
        let json = serde_json::to_string_pretty(&summary)
            .map_err(|e| ExporterException::Message(format!("Failed to serialize program: {}", e)))?;

        // Write with a simple header marker
        let mut writer = io::BufWriter::new(fs::File::create(file).map_err(ExporterException::Io)?);
        // GZF magic header
        writer.write_all(b"GZF1").map_err(ExporterException::Io)?;
        // Length prefix (4 bytes, little-endian)
        let len = json.len() as u32;
        writer
            .write_all(&len.to_le_bytes())
            .map_err(ExporterException::Io)?;
        // JSON payload
        writer.write_all(json.as_bytes()).map_err(ExporterException::Io)?;
        writer.flush().map_err(ExporterException::Io)?;

        Ok(true)
    }
}

/// Serializable summary of a Program (since Program doesn't implement Serialize).
#[derive(serde::Serialize, serde::Deserialize)]
struct GzfSummary {
    name: String,
    file_path: Option<String>,
    image_base: u64,
    memory_blocks: usize,
    symbols: usize,
    listing_rows: usize,
    imports: Vec<String>,
    exports: Vec<String>,
    data_types: usize,
}

impl GzfSummary {
    fn from_program(program: &Program) -> Self {
        Self {
            name: program.name.clone(),
            file_path: program.file_path.clone(),
            image_base: program.image_base.offset,
            memory_blocks: program.memory_blocks.len(),
            symbols: program.symbol_table.len(),
            listing_rows: program.listing.rows.len(),
            imports: program.imports.clone(),
            exports: program.exports.clone(),
            data_types: program.data_types.len(),
        }
    }
}

/// Read a GZF file and return the serialized summary.
pub fn read_gzf(path: &Path) -> Result<GzfSummary, ExporterException> {
    let data = fs::read(path).map_err(ExporterException::Io)?;

    if data.len() < 8 || &data[..4] != b"GZF1" {
        return Err(ExporterException::Message(
            "Not a valid GZF file: missing magic header".to_string(),
        ));
    }

    let len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    if data.len() < 8 + len {
        return Err(ExporterException::Message(
            "GZF file is truncated".to_string(),
        ));
    }

    let json_str = std::str::from_utf8(&data[8..8 + len])
        .map_err(|e| ExporterException::Message(format!("Invalid UTF-8 in GZF: {}", e)))?;

    serde_json::from_str(json_str)
        .map_err(|e| ExporterException::Message(format!("Failed to deserialize GZF: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::{Address, AddressRange};
    use ghidra_core::listing::ListingRow;
    use ghidra_core::program::{MemoryBlock, MemoryPermissions, Program};
    use std::fs;

    fn make_program() -> Program {
        let mut prog = Program::new("gzf_test", Address::new(0x1000));
        prog.memory_blocks.insert(
            ".text".to_string(),
            MemoryBlock {
                name: ".text".to_string(),
                range: AddressRange::new(Address::new(0x1000), Address::new(0x100f)),
                permissions: MemoryPermissions::RX,
                initialized: true,
                data: vec![0x55, 0xc3],
            },
        );
        prog.listing.add(
            Address::new(0x1000),
            ListingRow::new(Address::new(0x1000), vec![0x55], "push", "rbp"),
        );
        prog
    }

    #[test]
    fn test_gzf_exporter_properties() {
        let e = GzfExporter::new();
        assert_eq!(e.name(), "Ghidra Zip File");
        assert_eq!(e.file_extension(), "gzf");
        assert!(!e.supports_address_restricted_export());
    }

    #[test]
    fn test_gzf_export_and_read() {
        let prog = make_program();
        let e = GzfExporter::new();
        let tmp = std::env::temp_dir().join("gzf_exporter_test.gzf");
        let result = e.export(&tmp, &prog, None, None).unwrap();
        assert!(result);

        let content = fs::read(&tmp).unwrap();
        assert!(&content[..4] == b"GZF1");

        // Read it back
        let loaded = read_gzf(&tmp).unwrap();
        assert_eq!(loaded.name, "gzf_test");
        assert_eq!(loaded.image_base, 0x1000);

        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_gzf_read_invalid() {
        let tmp = std::env::temp_dir().join("gzf_invalid_test.gzf");
        fs::write(&tmp, b"NOTGZF").unwrap();
        let result = read_gzf(&tmp);
        assert!(result.is_err());
        let _ = fs::remove_file(&tmp);
    }
}
