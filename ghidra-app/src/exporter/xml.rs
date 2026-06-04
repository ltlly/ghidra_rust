//! XmlExporter — exports a program listing as XML.
//!
//! Ported from Ghidra's `XmlExporter.java`.

use super::traits::{Exporter, ExporterException, ExporterOption};
use ghidra_core::program::{MemoryPermissions, Program};
use std::fs;
use std::io::{self, Write};
use std::path::Path;

/// An exporter that creates an XML representation of a program.
///
/// The output XML includes program metadata, the memory map, symbol table,
/// listing (instructions/data), data types, and cross-references.
#[derive(Debug)]
pub struct XmlExporter {
    /// Whether to include listing data in the XML.
    pub include_listing: bool,
    /// Whether to include symbols.
    pub include_symbols: bool,
    /// Whether to include memory blocks.
    pub include_memory: bool,
    /// Whether to include data types.
    pub include_types: bool,
}

impl XmlExporter {
    /// Create a new XML exporter with all sections enabled.
    pub fn new() -> Self {
        Self {
            include_listing: true,
            include_symbols: true,
            include_memory: true,
            include_types: true,
        }
    }
}

impl Default for XmlExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Exporter for XmlExporter {
    fn name(&self) -> &str {
        "XML"
    }

    fn file_extension(&self) -> &str {
        "xml"
    }

    fn help_topic(&self) -> Option<&str> {
        Some("xml")
    }

    fn get_options(&self) -> Vec<ExporterOption> {
        vec![
            ExporterOption::boolean("Include Listing", self.include_listing)
                .with_group("XML Sections"),
            ExporterOption::boolean("Include Symbols", self.include_symbols)
                .with_group("XML Sections"),
            ExporterOption::boolean("Include Memory", self.include_memory)
                .with_group("XML Sections"),
            ExporterOption::boolean("Include Types", self.include_types)
                .with_group("XML Sections"),
        ]
    }

    fn set_options(&mut self, options: &[ExporterOption]) -> Result<(), ExporterException> {
        for opt in options {
            if let ExporterOption::Boolean { name, value, .. } = opt {
                match name.as_str() {
                    "Include Listing" => self.include_listing = *value,
                    "Include Symbols" => self.include_symbols = *value,
                    "Include Memory" => self.include_memory = *value,
                    "Include Types" => self.include_types = *value,
                    _ => {
                        return Err(ExporterException::Message(format!(
                            "Unknown XML option: {}",
                            name
                        )))
                    }
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
            io::BufWriter::new(fs::File::create(file).map_err(ExporterException::Io)?);

        writeln!(writer, r#"<?xml version="1.0" encoding="UTF-8"?>"#).map_err(ExporterException::Io)?;
        writeln!(writer, r#"<PROGRAM NAME="{}" IMAGE_BASE="0x{:x}">"#, program.name, program.image_base.offset)
            .map_err(ExporterException::Io)?;

        // Memory blocks section
        if self.include_memory {
            writeln!(writer, "  <MEMORY_MAP>").map_err(ExporterException::Io)?;
            let mut blocks: Vec<_> = program.memory_blocks.values().collect();
            blocks.sort_by_key(|b| b.range.start.offset);
            for block in &blocks {
                let perms = match block.permissions {
                    MemoryPermissions::R => "r--",
                    MemoryPermissions::RX => "r-x",
                    MemoryPermissions::RW => "rw-",
                    MemoryPermissions::RWX => "rwx",
                };
                writeln!(
                    writer,
                    r#"    <MEMORY_BLOCK NAME="{}" START="0x{:x}" END="0x{:x}" LENGTH="{}" PERMISSIONS="{}" INITIALIZED="{}" />"#,
                    block.name,
                    block.range.start.offset,
                    block.range.end.offset,
                    block.range.len(),
                    perms,
                    if block.initialized { "true" } else { "false" }
                )
                .map_err(ExporterException::Io)?;
            }
            writeln!(writer, "  </MEMORY_MAP>").map_err(ExporterException::Io)?;
        }

        // Symbols section
        if self.include_symbols {
            writeln!(writer, "  <SYMBOL_TABLE>").map_err(ExporterException::Io)?;
            let mut syms: Vec<_> = program.symbol_table.iter().collect();
            syms.sort_by_key(|s| s.address().offset);
            for sym in &syms {
                writeln!(
                    writer,
                    r#"    <SYMBOL NAME="{}" ADDRESS="0x{:x}" KIND="{:?}" />"#,
                    sym.name(),
                    sym.address().offset,
                    sym.kind()
                )
                .map_err(ExporterException::Io)?;
            }
            writeln!(writer, "  </SYMBOL_TABLE>").map_err(ExporterException::Io)?;
        }

        // Listing section
        if self.include_listing {
            writeln!(writer, "  <LISTING>").map_err(ExporterException::Io)?;
            let mut rows: Vec<_> = program.listing.rows.values().collect();
            rows.sort_by_key(|r| r.address);
            for row in &rows {
                let addr = row.address.offset;
                // Filter by range
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

                let bytes_hex: String = row
                    .bytes
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join("");
                let label_attr = row
                    .label
                    .as_ref()
                    .map(|l| format!(r#" LABEL="{}""#, l))
                    .unwrap_or_default();
                let comment_attr = row
                    .comment
                    .as_ref()
                    .map(|c| format!(r#" COMMENT="{}""#, c))
                    .unwrap_or_default();

                writeln!(
                    writer,
                    r#"    <CODE_UNIT ADDRESS="0x{:x}" BYTES="{}" MNEMONIC="{}" OPERANDS="{}"{}{} />"#,
                    addr, bytes_hex, row.mnemonic.text, row.operands, label_attr, comment_attr,
                )
                .map_err(ExporterException::Io)?;
            }
            writeln!(writer, "  </LISTING>").map_err(ExporterException::Io)?;
        }

        // Data types section
        if self.include_types {
            writeln!(writer, "  <DATA_TYPES>").map_err(ExporterException::Io)?;
            let mut types: Vec<_> = program.data_types.iter().collect();
            types.sort_by_key(|(addr, _)| addr.offset);
            for (addr, dt) in &types {
                writeln!(
                    writer,
                    r#"    <DATA_TYPE ADDRESS="0x{:x}" NAME="{}" SIZE="{}" KIND="{:?}" />"#,
                    addr.offset, dt.name, dt.size, dt.kind,
                )
                .map_err(ExporterException::Io)?;
            }
            writeln!(writer, "  </DATA_TYPES>").map_err(ExporterException::Io)?;
        }

        writeln!(writer, "</PROGRAM>").map_err(ExporterException::Io)?;
        writer.flush().map_err(ExporterException::Io)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::{Address, AddressRange};
    use ghidra_core::listing::ListingRow;
    use ghidra_core::program::{MemoryBlock, Program};
    use ghidra_core::symbol::Symbol;
    use std::fs;

    fn make_program() -> Program {
        let mut prog = Program::new("xml_test", Address::new(0x400000));
        prog.memory_blocks.insert(
            ".text".to_string(),
            MemoryBlock {
                name: ".text".to_string(),
                range: AddressRange::new(Address::new(0x400000), Address::new(0x4000ff)),
                permissions: MemoryPermissions::RX,
                initialized: true,
                data: Vec::new(),
            },
        );
        prog.listing.add(
            Address::new(0x400000),
            ListingRow::new(Address::new(0x400000), vec![0x55], "push", "rbp"),
        );
        prog.symbol_table
            .add(Symbol::function("main", Address::new(0x400000)));
        prog
    }

    #[test]
    fn test_xml_exporter_properties() {
        let e = XmlExporter::new();
        assert_eq!(e.name(), "XML");
        assert_eq!(e.file_extension(), "xml");
    }

    #[test]
    fn test_xml_exporter_export() {
        let prog = make_program();
        let e = XmlExporter::new();
        let tmp = std::env::temp_dir().join("xml_exporter_test.xml");
        let result = e.export(&tmp, &prog, None, None).unwrap();
        assert!(result);

        let content = fs::read_to_string(&tmp).unwrap();
        assert!(content.contains(r#"<?xml version="1.0""#));
        assert!(content.contains("<PROGRAM"));
        assert!(content.contains("MEMORY_BLOCK"));
        assert!(content.contains("SYMBOL"));
        assert!(content.contains("CODE_UNIT"));
        assert!(content.contains("push"));

        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_xml_exporter_selective_sections() {
        let prog = make_program();
        let mut e = XmlExporter::new();
        e.include_listing = false;
        e.include_types = false;

        let tmp = std::env::temp_dir().join("xml_exporter_selective.xml");
        e.export(&tmp, &prog, None, None).unwrap();

        let content = fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("MEMORY_BLOCK"));
        assert!(content.contains("SYMBOL"));
        assert!(!content.contains("CODE_UNIT"));

        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_xml_exporter_set_options() {
        let mut e = XmlExporter::new();
        let opts = vec![
            ExporterOption::boolean("Include Listing", false).with_group("XML Sections"),
        ];
        e.set_options(&opts).unwrap();
        assert!(!e.include_listing);
    }
}
