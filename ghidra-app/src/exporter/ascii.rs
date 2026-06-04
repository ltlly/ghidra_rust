//! AsciiExporter — exports a program listing as plain ASCII text.
//!
//! Ported from Ghidra's `AsciiExporter.java`.

use super::options::ProgramTextOptions;
use super::program_text_writer::ProgramTextWriter;
use super::traits::{Exporter, ExporterException, ExporterOption};
use ghidra_core::program::Program;
use std::path::Path;

/// An exporter that creates an ASCII representation of a program listing.
///
/// Writes a formatted text file with addresses, bytes, labels, mnemonics,
/// operands, and comments — one line per code unit.
#[derive(Debug)]
pub struct AsciiExporter {
    options: ProgramTextOptions,
}

impl AsciiExporter {
    /// Create a new ASCII exporter with default options.
    pub fn new() -> Self {
        Self {
            options: ProgramTextOptions::plaintext(),
        }
    }
}

impl Default for AsciiExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Exporter for AsciiExporter {
    fn name(&self) -> &str {
        "Ascii"
    }

    fn file_extension(&self) -> &str {
        "txt"
    }

    fn help_topic(&self) -> Option<&str> {
        Some("ascii")
    }

    fn get_options(&self) -> Vec<ExporterOption> {
        self.options.to_options()
    }

    fn set_options(&mut self, options: &[ExporterOption]) -> Result<(), ExporterException> {
        self.options.apply_options(options)
    }

    fn export(
        &self,
        file: &Path,
        program: &Program,
        start_addr: Option<u64>,
        end_addr: Option<u64>,
    ) -> Result<bool, ExporterException> {
        let writer = ProgramTextWriter::new(self.options.clone());
        writer
            .write(file, program, start_addr, end_addr)
            .map_err(ExporterException::Io)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::{Address, AddressRange};
    use ghidra_core::listing::ListingRow;
    use ghidra_core::program::{MemoryBlock, MemoryPermissions, Program};
    use std::fs;

    fn make_program() -> Program {
        let mut prog = Program::new("ascii_test", Address::new(0x1000));
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
        prog.listing.add(
            Address::new(0x1000),
            ListingRow::new(Address::new(0x1000), vec![0xcc], "int3", ""),
        );
        prog.listing.add(
            Address::new(0x1001),
            ListingRow::new(Address::new(0x1001), vec![0x90], "nop", ""),
        );
        prog
    }

    #[test]
    fn test_ascii_exporter_properties() {
        let e = AsciiExporter::new();
        assert_eq!(e.name(), "Ascii");
        assert_eq!(e.file_extension(), "txt");
        assert_eq!(e.default_suffix(), ".txt");
        assert!(e.help_topic().is_some());
    }

    #[test]
    fn test_ascii_exporter_export() {
        let prog = make_program();
        let e = AsciiExporter::new();
        let tmp = std::env::temp_dir().join("ascii_exporter_test.txt");
        let result = e.export(&tmp, &prog, None, None).unwrap();
        assert!(result);

        let content = fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("int3"));
        assert!(content.contains("nop"));

        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_ascii_exporter_options() {
        let e = AsciiExporter::new();
        let opts = e.get_options();
        assert!(!opts.is_empty());
    }

    #[test]
    fn test_ascii_exporter_set_options() {
        let mut e = AsciiExporter::new();
        let opts = vec![ExporterOption::integer(" Address ", 8).with_group("Field Widths")];
        e.set_options(&opts).unwrap();
    }
}
