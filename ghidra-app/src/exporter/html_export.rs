//! HtmlExporter — exports a program listing as HTML.
//!
//! Ported from Ghidra's `HtmlExporter.java`. This is the program-text-listing
//! HTML exporter (different from the interactive HTML report in `legacy.rs`).

use super::options::ProgramTextOptions;
use super::program_text_writer::ProgramTextWriter;
use super::traits::{Exporter, ExporterException, ExporterOption};
use ghidra_core::program::Program;
use std::path::Path;

/// An exporter that creates an HTML representation of a program listing.
///
/// The output is an HTML page with formatted disassembly listing including
/// hyperlinked addresses, syntax-highlighted code, and comment annotations.
#[derive(Debug)]
pub struct HtmlExporter {
    options: ProgramTextOptions,
}

impl HtmlExporter {
    /// Create a new HTML exporter with default options.
    pub fn new() -> Self {
        Self {
            options: ProgramTextOptions::html(),
        }
    }
}

impl Default for HtmlExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Exporter for HtmlExporter {
    fn name(&self) -> &str {
        "HTML"
    }

    fn file_extension(&self) -> &str {
        "html"
    }

    fn help_topic(&self) -> Option<&str> {
        Some("html")
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
        let mut prog = Program::new("html_test", Address::new(0x1000));
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
            ListingRow::new(Address::new(0x1000), vec![0x55], "push", "rbp"),
        );
        prog
    }

    #[test]
    fn test_html_exporter_properties() {
        let e = HtmlExporter::new();
        assert_eq!(e.name(), "HTML");
        assert_eq!(e.file_extension(), "html");
        assert!(e.options.is_html);
    }

    #[test]
    fn test_html_exporter_export() {
        let prog = make_program();
        let e = HtmlExporter::new();
        let tmp = std::env::temp_dir().join("html_exporter_test.html");
        let result = e.export(&tmp, &prog, None, None).unwrap();
        assert!(result);

        let content = fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("<html>"));
        assert!(content.contains("push"));
        assert!(content.contains("</html>"));

        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_html_exporter_options() {
        let e = HtmlExporter::new();
        let opts = e.get_options();
        assert!(!opts.is_empty());
    }
}
