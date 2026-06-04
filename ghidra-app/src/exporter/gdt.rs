//! GdtExporter — exports data type archives as Ghidra Data Type files.
//!
//! Ported from Ghidra's `GdtExporter.java`.

use super::traits::{Exporter, ExporterException, ExporterOption};
use ghidra_core::program::Program;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

/// File extension for Ghidra Data Type archive files.
pub const GDT_EXTENSION: &str = "gdt";
/// File suffix (with dot) for Ghidra Data Type archive files.
pub const GDT_SUFFIX: &str = ".gdt";

/// An exporter that packages program data types as a Ghidra Data Type Archive.
///
/// A `.gdt` file contains data type definitions that can be imported into
/// other Ghidra programs. In Rust, this serializes the program's data types
/// as a structured JSON file.
#[derive(Debug)]
pub struct GdtExporter;

impl GdtExporter {
    /// Create a new GDT exporter.
    pub fn new() -> Self {
        Self
    }
}

impl Default for GdtExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Exporter for GdtExporter {
    fn name(&self) -> &str {
        "Ghidra Data Type Archive File"
    }

    fn file_extension(&self) -> &str {
        GDT_EXTENSION
    }

    fn help_topic(&self) -> Option<&str> {
        Some("gdt")
    }

    /// GDT export does not support address-restricted export.
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
        // Collect data types into a serializable structure
        let types: Vec<GdtEntry> = program
            .data_types
            .iter()
            .map(|(addr, dt)| GdtEntry {
                address: format!("0x{:x}", addr.offset),
                name: dt.name.clone(),
                size: dt.size,
                kind: format!("{:?}", dt.kind),
                description: dt.description.clone(),
            })
            .collect();

        let gdt = GdtFile {
            version: 1,
            program_name: program.name.clone(),
            image_base: format!("0x{:x}", program.image_base.offset),
            data_types: types,
        };

        let json = serde_json::to_string_pretty(&gdt)
            .map_err(|e| ExporterException::Message(format!("Failed to serialize GDT: {}", e)))?;

        let mut writer =
            io::BufWriter::new(fs::File::create(file).map_err(ExporterException::Io)?);
        // GDT magic header
        writer.write_all(b"GDT1").map_err(ExporterException::Io)?;
        let len = json.len() as u32;
        writer
            .write_all(&len.to_le_bytes())
            .map_err(ExporterException::Io)?;
        writer.write_all(json.as_bytes()).map_err(ExporterException::Io)?;
        writer.flush().map_err(ExporterException::Io)?;

        Ok(true)
    }
}

/// Internal serializable structure for a GDT file.
#[derive(serde::Serialize, serde::Deserialize)]
struct GdtFile {
    version: u32,
    program_name: String,
    image_base: String,
    data_types: Vec<GdtEntry>,
}

/// A single data type entry in a GDT file.
#[derive(serde::Serialize, serde::Deserialize)]
struct GdtEntry {
    address: String,
    name: String,
    size: usize,
    kind: String,
    description: String,
}

/// Read a GDT file and return the entries.
pub fn read_gdt(path: &Path) -> Result<GdtFile, ExporterException> {
    let data = fs::read(path).map_err(ExporterException::Io)?;

    if data.len() < 8 || &data[..4] != b"GDT1" {
        return Err(ExporterException::Message(
            "Not a valid GDT file: missing magic header".to_string(),
        ));
    }

    let len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    if data.len() < 8 + len {
        return Err(ExporterException::Message(
            "GDT file is truncated".to_string(),
        ));
    }

    let json_str = std::str::from_utf8(&data[8..8 + len])
        .map_err(|e| ExporterException::Message(format!("Invalid UTF-8 in GDT: {}", e)))?;

    serde_json::from_str(json_str)
        .map_err(|e| ExporterException::Message(format!("Failed to deserialize GDT: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::{Address, AddressRange};
    use ghidra_core::program::{MemoryBlock, MemoryPermissions, Program, SimpleDataType};
    use std::fs;

    fn make_program() -> Program {
        let mut prog = Program::new("gdt_test", Address::new(0x1000));
        prog.memory_blocks.insert(
            ".text".to_string(),
            MemoryBlock {
                name: ".text".to_string(),
                range: AddressRange::new(Address::new(0x1000), Address::new(0x1fff)),
                permissions: MemoryPermissions::RX,
                initialized: true,
                data: Vec::new(),
            },
        );
        prog.data_types
            .insert(Address::new(0x1000), SimpleDataType::i32());
        prog.data_types.insert(
            Address::new(0x1004),
            SimpleDataType::new("u64", 8, ghidra_core::data::DataTypeKind::Primitive),
        );
        prog
    }

    #[test]
    fn test_gdt_exporter_properties() {
        let e = GdtExporter::new();
        assert_eq!(e.name(), "Ghidra Data Type Archive File");
        assert_eq!(e.file_extension(), "gdt");
        assert!(!e.supports_address_restricted_export());
    }

    #[test]
    fn test_gdt_export_and_read() {
        let prog = make_program();
        let e = GdtExporter::new();
        let tmp = std::env::temp_dir().join("gdt_exporter_test.gdt");
        let result = e.export(&tmp, &prog, None, None).unwrap();
        assert!(result);

        let content = fs::read(&tmp).unwrap();
        assert!(&content[..4] == b"GDT1");

        let gdt = read_gdt(&tmp).unwrap();
        assert_eq!(gdt.version, 1);
        assert_eq!(gdt.program_name, "gdt_test");
        assert_eq!(gdt.data_types.len(), 2);

        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_gdt_read_invalid() {
        let tmp = std::env::temp_dir().join("gdt_invalid_test.gdt");
        fs::write(&tmp, b"NOTGDT").unwrap();
        let result = read_gdt(&tmp);
        assert!(result.is_err());
        let _ = fs::remove_file(&tmp);
    }
}
