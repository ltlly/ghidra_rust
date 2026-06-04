//! OriginalFileExporter — exports the original program file bytes.
//!
//! Ported from Ghidra's `OriginalFileExporter.java`.

use super::traits::{Exporter, ExporterException, ExporterOption};
use ghidra_core::program::Program;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

const USER_MODS_OPTION_NAME: &str = "Export User Byte Modifications";
const USER_MODS_OPTION_DEFAULT: bool = true;

/// An exporter that writes the program's original file bytes to disk.
///
/// This exporter reconstructs the binary file from the program's memory
/// blocks. When user modifications are enabled, any patched bytes from
/// the listing are applied on top of the original data.
#[derive(Debug)]
pub struct OriginalFileExporter {
    /// Whether to apply user byte modifications.
    export_user_modifications: bool,
}

impl OriginalFileExporter {
    /// Create a new original file exporter.
    pub fn new() -> Self {
        Self {
            export_user_modifications: USER_MODS_OPTION_DEFAULT,
        }
    }
}

impl Default for OriginalFileExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Exporter for OriginalFileExporter {
    fn name(&self) -> &str {
        "Original File"
    }

    fn file_extension(&self) -> &str {
        "bin"
    }

    fn help_topic(&self) -> Option<&str> {
        Some("original_file")
    }

    /// Original file export does not support address-restricted export.
    fn supports_address_restricted_export(&self) -> bool {
        false
    }

    fn get_options(&self) -> Vec<ExporterOption> {
        vec![ExporterOption::boolean(
            USER_MODS_OPTION_NAME,
            self.export_user_modifications,
        )]
    }

    fn set_options(&mut self, options: &[ExporterOption]) -> Result<(), ExporterException> {
        for opt in options {
            if let ExporterOption::Boolean { name, value, .. } = opt {
                if name == USER_MODS_OPTION_NAME {
                    self.export_user_modifications = *value;
                }
            }
        }
        Ok(())
    }

    fn export(
        &self,
        file: &Path,
        program: &Program,
        _start_addr: Option<u64>,
        _end_addr: Option<u64>,
    ) -> Result<bool, ExporterException> {
        // Collect all memory blocks and write them out
        let mut blocks: Vec<_> = program.memory_blocks.values().collect();
        if blocks.is_empty() {
            return Err(ExporterException::Message(
                "Program has no memory blocks to export".to_string(),
            ));
        }
        blocks.sort_by_key(|b| b.range.start.offset);

        let mut writer =
            io::BufWriter::new(fs::File::create(file).map_err(ExporterException::Io)?);

        for block in &blocks {
            if block.data.is_empty() {
                continue;
            }
            writer
                .write_all(&block.data)
                .map_err(ExporterException::Io)?;
        }

        writer.flush().map_err(ExporterException::Io)?;

        // If user modifications are enabled, apply listing bytes on top
        if self.export_user_modifications && !program.listing.rows.is_empty() {
            // Re-read the file and patch in listing bytes
            let mut file_data = fs::read(file).map_err(ExporterException::Io)?;
            let base_addr = blocks
                .first()
                .map(|b| b.range.start.offset)
                .unwrap_or(0);

            for row in program.listing.rows.values() {
                let offset = (row.address.offset - base_addr) as usize;
                if offset + row.bytes.len() <= file_data.len() {
                    file_data[offset..offset + row.bytes.len()].copy_from_slice(&row.bytes);
                }
            }

            fs::write(file, &file_data).map_err(ExporterException::Io)?;
        }

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
        let mut prog = Program::new("orig_test", Address::new(0x1000));
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
        prog.listing.add(
            Address::new(0x1000),
            ListingRow::new(Address::new(0x1000), vec![0x90], "nop", ""),
        );
        prog
    }

    #[test]
    fn test_original_file_exporter_properties() {
        let e = OriginalFileExporter::new();
        assert_eq!(e.name(), "Original File");
        assert_eq!(e.file_extension(), "bin");
        assert!(!e.supports_address_restricted_export());
    }

    #[test]
    fn test_original_file_exporter_export() {
        let prog = make_program();
        let e = OriginalFileExporter::new();
        let tmp = std::env::temp_dir().join("orig_file_exporter_test.bin");
        let result = e.export(&tmp, &prog, None, None).unwrap();
        assert!(result);

        let bytes = fs::read(&tmp).unwrap();
        assert_eq!(bytes.len(), 8);
        // First byte should be 0x90 (nop) from the listing, since user mods are enabled
        assert_eq!(bytes[0], 0x90);

        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_original_file_exporter_no_user_mods() {
        let prog = make_program();
        let mut e = OriginalFileExporter::new();
        e.export_user_modifications = false;
        let tmp = std::env::temp_dir().join("orig_file_no_mods_test.bin");
        let result = e.export(&tmp, &prog, None, None).unwrap();
        assert!(result);

        let bytes = fs::read(&tmp).unwrap();
        // First byte should be original 0x55 since user mods disabled
        assert_eq!(bytes[0], 0x55);

        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_original_file_exporter_options() {
        let mut e = OriginalFileExporter::new();
        let opts = e.get_options();
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].name(), USER_MODS_OPTION_NAME);

        let new_opts = vec![ExporterOption::boolean(USER_MODS_OPTION_NAME, false)];
        e.set_options(&new_opts).unwrap();
        assert!(!e.export_user_modifications);
    }
}
