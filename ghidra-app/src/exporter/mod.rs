//! Export functionality for Ghidra Rust.
//!
//! This module provides two export systems:
//!
//! 1. **`ExportManager`** (from `legacy`) — a central export manager providing
//!    C, C header, JSON, HTML report, CSV, SQLite, Ghidra project, IDA Python,
//!    and binary patch exports.
//!
//! 2. **Trait-based exporters** — Ghidra-compatible exporter pattern with a
//!    [`trait@Exporter`] trait, [`ExporterRegistry`], and format-specific
//!    exporters: [`AsciiExporter`], [`BinaryExporter`], [`HtmlExporter`],
//!    [`XmlExporter`], [`IntelHexExporter`], [`GzfExporter`], [`GdtExporter`],
//!    and [`OriginalFileExporter`].
//!
//! # Trait-based exporter example
//!
//! ```ignore
//! use ghidra_app::exporter::{ExporterRegistry, ascii::AsciiExporter};
//!
//! let mut registry = ExporterRegistry::with_defaults();
//! registry.export_by_name("Ascii", &output_path, &program, None, None)?;
//! ```

// Legacy ExportManager and related types
pub mod legacy;

// New trait-based exporter modules
pub mod traits;
pub mod options;
pub mod line_dispenser;
pub mod program_text_writer;

pub mod ascii;
pub mod binary;
pub mod html_export;
pub mod xml;
pub mod intel_hex;
pub mod gzf;
pub mod gdt;
pub mod original_file;

// Re-export the legacy ExportManager and its types at the module root
pub use legacy::{
    BinaryPatch, CsvRow, ExportMetadata, ExportManager, JsonDataType, JsonExport, JsonFunction,
    JsonMemoryBlock, JsonStringRef, JsonSymbol,
};

// Re-export the trait-based exporter types
pub use traits::{Exporter, ExporterException, ExporterOption, ExporterRegistry};
pub use options::ProgramTextOptions;
pub use ascii::AsciiExporter;
pub use binary::BinaryExporter as RawBinaryExporter;
pub use html_export::HtmlExporter;
pub use xml::XmlExporter;
pub use intel_hex::{IntelHexExporter, IntelHexRecord, IntelHexRecordWriter, IntelHexRecordType};
pub use gzf::GzfExporter;
pub use gdt::GdtExporter;
pub use original_file::OriginalFileExporter;

// Re-export utility functions
pub use line_dispenser::{clip, get_fill};

#[cfg(test)]
mod integration_tests {
    use super::*;
    use ghidra_core::addr::{Address, AddressRange};
    use ghidra_core::listing::ListingRow;
    use ghidra_core::program::{MemoryBlock, MemoryPermissions, Program, SimpleDataType};
    use ghidra_core::symbol::Symbol;
    use std::fs;

    fn make_full_program() -> Program {
        let mut prog = Program::new("integration_test", Address::new(0x400000));
        prog.file_path = Some("/tmp/test.bin".to_string());

        // Memory blocks
        prog.memory_blocks.insert(
            ".text".to_string(),
            MemoryBlock {
                name: ".text".to_string(),
                range: AddressRange::new(Address::new(0x400000), Address::new(0x40000f)),
                permissions: MemoryPermissions::RX,
                initialized: true,
                data: vec![
                    0x55, 0x48, 0x89, 0xe5, 0xb8, 0x00, 0x00, 0x00, 0x5d, 0xc3,
                    0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                ],
            },
        );
        prog.memory_blocks.insert(
            ".data".to_string(),
            MemoryBlock {
                name: ".data".to_string(),
                range: AddressRange::new(Address::new(0x600000), Address::new(0x60000f)),
                permissions: MemoryPermissions::RW,
                initialized: true,
                data: vec![0; 16],
            },
        );

        // Listing rows
        prog.listing.add(
            Address::new(0x400000),
            ListingRow::new(Address::new(0x400000), vec![0x55], "push", "rbp"),
        );
        prog.listing.add(
            Address::new(0x400001),
            ListingRow::new(
                Address::new(0x400001),
                vec![0x48, 0x89, 0xe5],
                "mov",
                "rbp, rsp",
            ),
        );
        prog.listing.add(
            Address::new(0x400004),
            ListingRow::new(
                Address::new(0x400004),
                vec![0xb8, 0x00, 0x00, 0x00, 0x00],
                "mov",
                "eax, 0x0",
            ),
        );

        // Symbols
        prog.symbol_table
            .add(Symbol::function("main", Address::new(0x400000)));
        prog.symbol_table
            .add(Symbol::label("data_start", Address::new(0x600000)));

        // Data types
        prog.data_types
            .insert(Address::new(0x400000), SimpleDataType::i32());
        prog.data_types
            .insert(
                Address::new(0x400004),
                SimpleDataType::new("u64", 8, ghidra_core::data::DataTypeKind::Primitive),
            );

        // Imports/exports
        prog.imports.push("puts".to_string());
        prog.exports.push("main".to_string());

        prog
    }

    // -- Legacy ExportManager tests --

    #[test]
    fn test_legacy_export_json() {
        let prog = make_full_program();
        let mgr = ExportManager::new();
        let export = mgr.build_json_export(&prog);
        assert_eq!(export.metadata.name, "integration_test");
        assert_eq!(export.functions.len(), 1);
        assert_eq!(export.symbols.len(), 2);
    }

    #[test]
    fn test_legacy_export_csv() {
        let prog = make_full_program();
        let mgr = ExportManager::new();
        let tmp = std::env::temp_dir().join("integration_test.csv");
        mgr.export_csv(&prog, &tmp).unwrap();
        let content = fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("address,bytes,label,mnemonic,operands,comment"));
        assert!(content.contains("push"));
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_legacy_export_c() {
        let prog = make_full_program();
        let mgr = ExportManager::new();
        let tmp = std::env::temp_dir().join("integration_test.c");
        mgr.export_c(&prog, &tmp).unwrap();
        let content = fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("int main(void)"));
        let _ = fs::remove_file(&tmp);
    }

    // -- Trait-based exporter tests --

    #[test]
    fn test_ascii_export_via_registry() {
        let prog = make_full_program();
        let registry = ExporterRegistry::with_defaults();
        let tmp = std::env::temp_dir().join("integration_ascii.txt");
        let result = registry
            .export_by_name("Ascii", &tmp, &prog, None, None)
            .unwrap();
        assert!(result);
        let content = fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("push"));
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_binary_export_via_registry() {
        let prog = make_full_program();
        let registry = ExporterRegistry::with_defaults();
        let tmp = std::env::temp_dir().join("integration_binary.bin");
        let result = registry
            .export_by_name("Raw Bytes", &tmp, &prog, None, None)
            .unwrap();
        assert!(result);
        let bytes = fs::read(&tmp).unwrap();
        assert_eq!(bytes.len(), 32); // 16 (.text) + 16 (.data)
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_xml_export_via_registry() {
        let prog = make_full_program();
        let registry = ExporterRegistry::with_defaults();
        let tmp = std::env::temp_dir().join("integration_xml.xml");
        let result = registry
            .export_by_name("XML", &tmp, &prog, None, None)
            .unwrap();
        assert!(result);
        let content = fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("CODE_UNIT"));
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_html_export_via_registry() {
        let prog = make_full_program();
        let registry = ExporterRegistry::with_defaults();
        let tmp = std::env::temp_dir().join("integration_html.html");
        let result = registry
            .export_by_name("HTML", &tmp, &prog, None, None)
            .unwrap();
        assert!(result);
        let content = fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("<html>"));
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_intel_hex_export_via_registry() {
        let prog = make_full_program();
        let registry = ExporterRegistry::with_defaults();
        let tmp = std::env::temp_dir().join("integration_hex.hex");
        let result = registry
            .export_by_name("Intel Hex", &tmp, &prog, None, None)
            .unwrap();
        assert!(result);
        let content = fs::read_to_string(&tmp).unwrap();
        assert!(content.starts_with(':'));
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_gzf_export_via_registry() {
        let prog = make_full_program();
        let registry = ExporterRegistry::with_defaults();
        let tmp = std::env::temp_dir().join("integration_gzf.gzf");
        let result = registry
            .export_by_name("Ghidra Zip File", &tmp, &prog, None, None)
            .unwrap();
        assert!(result);
        let bytes = fs::read(&tmp).unwrap();
        assert!(&bytes[..4] == b"GZF1");
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_gdt_export_via_registry() {
        let prog = make_full_program();
        let registry = ExporterRegistry::with_defaults();
        let tmp = std::env::temp_dir().join("integration_gdt.gdt");
        let result = registry
            .export_by_name("Ghidra Data Type Archive File", &tmp, &prog, None, None)
            .unwrap();
        assert!(result);
        let bytes = fs::read(&tmp).unwrap();
        assert!(&bytes[..4] == b"GDT1");
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_original_file_export_via_registry() {
        let prog = make_full_program();
        let registry = ExporterRegistry::with_defaults();
        let tmp = std::env::temp_dir().join("integration_orig.bin");
        let result = registry
            .export_by_name("Original File", &tmp, &prog, None, None)
            .unwrap();
        assert!(result);
        let bytes = fs::read(&tmp).unwrap();
        assert!(!bytes.is_empty());
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_registry_lists_all_exporters() {
        let registry = ExporterRegistry::with_defaults();
        let names = registry.names();
        assert!(names.contains(&"Ascii"));
        assert!(names.contains(&"Raw Bytes"));
        assert!(names.contains(&"HTML"));
        assert!(names.contains(&"XML"));
        assert!(names.contains(&"Intel Hex"));
        assert!(names.contains(&"Ghidra Zip File"));
        assert!(names.contains(&"Ghidra Data Type Archive File"));
        assert!(names.contains(&"Original File"));
        assert_eq!(names.len(), 8);
    }

    #[test]
    fn test_registry_unknown_exporter() {
        let prog = make_full_program();
        let registry = ExporterRegistry::with_defaults();
        let tmp = std::env::temp_dir().join("integration_unknown.txt");
        let result = registry.export_by_name("NoSuchExporter", &tmp, &prog, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_program_text_options_roundtrip() {
        let opts = ProgramTextOptions::plaintext();
        let exported = opts.to_options();
        let mut opts2 = ProgramTextOptions::default();
        opts2.apply_options(&exported).unwrap();
        assert_eq!(opts.addr_width, opts2.addr_width);
        assert_eq!(opts.label_width, opts2.label_width);
        assert_eq!(opts.show_comments, opts2.show_comments);
    }

    #[test]
    fn test_clip_utility() {
        assert_eq!(clip("abc", 5, true, true), "abc  ");
        assert_eq!(clip("abcdef", 5, true, true), "ab...");
        assert_eq!(get_fill(3), "   ");
    }

    #[test]
    fn test_exporter_exception_from_string() {
        let e = ExporterException::from("test error");
        assert_eq!(format!("{}", e), "test error");
    }
}
