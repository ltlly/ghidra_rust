//! BinaryExporter — exports initialized memory blocks as raw bytes.
//!
//! Ported from Ghidra's `BinaryExporter.java`.

use super::traits::{Exporter, ExporterException, ExporterOption};
use ghidra_core::program::Program;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

/// An exporter that writes initialized memory blocks as raw binary bytes.
///
/// Only initialized, readable memory blocks are exported. The output is a
/// flat binary file suitable for loading into other tools.
#[derive(Debug)]
pub struct BinaryExporter;

impl BinaryExporter {
    /// Create a new binary exporter.
    pub fn new() -> Self {
        Self
    }
}

impl Default for BinaryExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Exporter for BinaryExporter {
    fn name(&self) -> &str {
        "Raw Bytes"
    }

    fn file_extension(&self) -> &str {
        "bin"
    }

    fn help_topic(&self) -> Option<&str> {
        Some("binary")
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
        start_addr: Option<u64>,
        end_addr: Option<u64>,
    ) -> Result<bool, ExporterException> {
        let mut writer = io::BufWriter::new(fs::File::create(file).map_err(ExporterException::Io)?);

        // Collect initialized, readable blocks and emit their data
        let mut blocks: Vec<_> = program
            .memory_blocks
            .values()
            .filter(|b| b.initialized)
            .collect();
        blocks.sort_by_key(|b| b.range.start.offset);

        for block in &blocks {
            let block_start = block.range.start.offset;
            let block_end = block.range.end.offset;

            // Apply address range filter
            let effective_start = start_addr.map_or(block_start, |s| s.max(block_start));
            let effective_end = end_addr.map_or(block_end, |e| e.min(block_end));

            if effective_start > effective_end {
                continue;
            }

            // Write the data bytes from the block
            if !block.data.is_empty() {
                let data_start = (effective_start - block_start) as usize;
                let data_end = ((effective_end - block_start + 1) as usize).min(block.data.len());
                if data_start < data_end {
                    writer
                        .write_all(&block.data[data_start..data_end])
                        .map_err(ExporterException::Io)?;
                }
            }
        }

        writer.flush().map_err(ExporterException::Io)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::{Address, AddressRange};
    use ghidra_core::program::{MemoryBlock, MemoryPermissions, Program};
    use std::fs;

    fn make_program() -> Program {
        let mut prog = Program::new("bin_test", Address::new(0x1000));
        prog.memory_blocks.insert(
            ".text".to_string(),
            MemoryBlock {
                name: ".text".to_string(),
                range: AddressRange::new(Address::new(0x1000), Address::new(0x1007)),
                permissions: MemoryPermissions::RX,
                initialized: true,
                data: vec![0x55, 0x48, 0x89, 0xe5, 0xb8, 0x00, 0x00, 0x00],
            },
        );
        prog.memory_blocks.insert(
            ".bss".to_string(),
            MemoryBlock {
                name: ".bss".to_string(),
                range: AddressRange::new(Address::new(0x2000), Address::new(0x200f)),
                permissions: MemoryPermissions::RW,
                initialized: false,
                data: Vec::new(),
            },
        );
        prog
    }

    #[test]
    fn test_binary_exporter_properties() {
        let e = BinaryExporter::new();
        assert_eq!(e.name(), "Raw Bytes");
        assert_eq!(e.file_extension(), "bin");
    }

    #[test]
    fn test_binary_exporter_export() {
        let prog = make_program();
        let e = BinaryExporter::new();
        let tmp = std::env::temp_dir().join("binary_exporter_test.bin");
        let result = e.export(&tmp, &prog, None, None).unwrap();
        assert!(result);

        let bytes = fs::read(&tmp).unwrap();
        // Only the .text block (initialized) should be exported
        assert_eq!(bytes, vec![0x55, 0x48, 0x89, 0xe5, 0xb8, 0x00, 0x00, 0x00]);

        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_binary_exporter_address_restricted() {
        let prog = make_program();
        let e = BinaryExporter::new();
        let tmp = std::env::temp_dir().join("binary_exporter_restricted.bin");
        let result = e.export(&tmp, &prog, Some(0x1000), Some(0x1003)).unwrap();
        assert!(result);

        let bytes = fs::read(&tmp).unwrap();
        assert_eq!(bytes, vec![0x55, 0x48, 0x89, 0xe5]);

        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_binary_exporter_no_options() {
        let e = BinaryExporter::new();
        assert!(e.get_options().is_empty());
    }
}
