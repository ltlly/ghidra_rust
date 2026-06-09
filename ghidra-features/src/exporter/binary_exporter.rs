//! Binary exporter implementation.
//!
//! Exports memory blocks as raw bytes.
//!
//! Ported from `ghidra.app.util.exporter.BinaryExporter`.

use std::io::Write;

use crate::base::analyzer::{AddressSet, Program};
use crate::loader::framework::MessageLog as LoaderMessageLog;

use super::{Exporter, ExporterError, MemoryModel};

/// Exports memory blocks as raw bytes.
///
/// Ported from `ghidra.app.util.exporter.BinaryExporter`.
pub struct BinaryExporter;

impl BinaryExporter {
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

    fn default_extension(&self) -> &str {
        "bin"
    }

    fn export(
        &self,
        program: &Program,
        addr_set: Option<&AddressSet>,
        memory: Option<&MemoryModel>,
        writer: &mut dyn Write,
        log: &mut LoaderMessageLog,
    ) -> Result<bool, ExporterError> {
        let set = match addr_set {
            Some(s) => s.clone(),
            None => program.memory.clone(),
        };

        let mem = memory.ok_or_else(|| {
            ExporterError::MemoryAccess("No memory model provided for binary export".into())
        })?;

        let mut total = 0u64;
        for range in set.iter() {
            let mut addr = range.start;
            while addr.offset <= range.end.offset {
                if let Some(byte) = mem.get_byte(&addr) {
                    writer.write_all(&[byte])?;
                    total += 1;
                }
                addr = addr.add(1);
            }
        }

        log.append_msg(format!("Exported {} bytes to binary", total));
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::analyzer::{Address, AddressRange, Language};

    fn make_test_program() -> Program {
        let lang = Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let mut prog = Program::new("test_binary", lang);
        prog.image_base = 0x400000;
        prog.memory
            .add_range(AddressRange::new(Address::new(0x400000), Address::new(0x40001F)));
        prog.symbols.insert(Address::new(0x400000), "_start".into());
        prog.symbols.insert(Address::new(0x400010), "main".into());
        prog
    }

    fn make_test_memory() -> MemoryModel {
        let mut mem = MemoryModel::new();
        for i in 0u8..32 {
            mem.set_byte(&Address::new(0x400000 + i as u64), i);
        }
        mem
    }

    #[test]
    fn test_binary_exporter() {
        let prog = make_test_program();
        let mem = make_test_memory();
        let exporter = BinaryExporter::new();
        assert_eq!(exporter.name(), "Raw Bytes");
        assert_eq!(exporter.default_extension(), "bin");

        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        let result = exporter.export(&prog, None, Some(&mem), &mut output, &mut log);
        assert!(result.is_ok());
        assert_eq!(output.len(), 32);
        assert_eq!(output[0], 0);
        assert_eq!(output[31], 31);
    }

    #[test]
    fn test_binary_exporter_no_memory() {
        let prog = make_test_program();
        let exporter = BinaryExporter::new();
        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        let result = exporter.export(&prog, None, None, &mut output, &mut log);
        assert!(result.is_err());
    }

    #[test]
    fn test_binary_exporter_restricted() {
        let prog = make_test_program();
        let mem = make_test_memory();
        let exporter = BinaryExporter::new();

        let mut set = AddressSet::new();
        set.add_range(AddressRange::new(Address::new(0x400000), Address::new(0x400003)));

        let mut output = Vec::new();
        let mut log = LoaderMessageLog::new();
        let result = exporter.export(&prog, Some(&set), Some(&mem), &mut output, &mut log);
        assert!(result.is_ok());
        assert_eq!(output.len(), 4);
    }
}
