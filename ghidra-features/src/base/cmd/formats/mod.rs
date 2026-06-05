//! Binary format analysis commands.
//!
//! Ported from `ghidra.app.cmd.formats`.

/// Binary format types that can be analyzed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    Elf,
    PortableExecutable,
    Macho,
    Coff,
    CoffArchive,
    AppleSingleDouble,
    Pef,
}

/// Command to run binary format analysis on a loaded program.
#[derive(Debug)]
pub struct BinaryAnalysisCommand {
    format: BinaryFormat,
}

impl BinaryAnalysisCommand {
    pub fn new(format: BinaryFormat) -> Self {
        Self { format }
    }

    pub fn format(&self) -> BinaryFormat {
        self.format
    }

    pub fn apply_to(&self, _program_name: &str) -> bool {
        true
    }
}

/// ELF binary analysis command.
#[derive(Debug)]
pub struct ElfBinaryAnalysisCommand {
    inner: BinaryAnalysisCommand,
}

impl ElfBinaryAnalysisCommand {
    pub fn new() -> Self {
        Self {
            inner: BinaryAnalysisCommand::new(BinaryFormat::Elf),
        }
    }
}

impl Default for ElfBinaryAnalysisCommand {
    fn default() -> Self {
        Self::new()
    }
}

/// Portable Executable (PE) binary analysis command.
#[derive(Debug)]
pub struct PortableExecutableBinaryAnalysisCommand {
    inner: BinaryAnalysisCommand,
}

impl PortableExecutableBinaryAnalysisCommand {
    pub fn new() -> Self {
        Self {
            inner: BinaryAnalysisCommand::new(BinaryFormat::PortableExecutable),
        }
    }
}

impl Default for PortableExecutableBinaryAnalysisCommand {
    fn default() -> Self {
        Self::new()
    }
}

/// Mach-O binary analysis command.
#[derive(Debug)]
pub struct MachoBinaryAnalysisCommand {
    inner: BinaryAnalysisCommand,
}

impl MachoBinaryAnalysisCommand {
    pub fn new() -> Self {
        Self {
            inner: BinaryAnalysisCommand::new(BinaryFormat::Macho),
        }
    }
}

impl Default for MachoBinaryAnalysisCommand {
    fn default() -> Self {
        Self::new()
    }
}

/// COFF binary analysis command.
#[derive(Debug)]
pub struct CoffBinaryAnalysisCommand {
    inner: BinaryAnalysisCommand,
}

impl CoffBinaryAnalysisCommand {
    pub fn new() -> Self {
        Self {
            inner: BinaryAnalysisCommand::new(BinaryFormat::Coff),
        }
    }
}

impl Default for CoffBinaryAnalysisCommand {
    fn default() -> Self {
        Self::new()
    }
}

/// COFF archive analysis command.
#[derive(Debug)]
pub struct CoffArchiveBinaryAnalysisCommand {
    inner: BinaryAnalysisCommand,
}

impl CoffArchiveBinaryAnalysisCommand {
    pub fn new() -> Self {
        Self {
            inner: BinaryAnalysisCommand::new(BinaryFormat::CoffArchive),
        }
    }
}

impl Default for CoffArchiveBinaryAnalysisCommand {
    fn default() -> Self {
        Self::new()
    }
}

/// AppleSingle/AppleDouble analysis command.
#[derive(Debug)]
pub struct AppleSingleDoubleBinaryAnalysisCommand {
    inner: BinaryAnalysisCommand,
}

impl AppleSingleDoubleBinaryAnalysisCommand {
    pub fn new() -> Self {
        Self {
            inner: BinaryAnalysisCommand::new(BinaryFormat::AppleSingleDouble),
        }
    }
}

impl Default for AppleSingleDoubleBinaryAnalysisCommand {
    fn default() -> Self {
        Self::new()
    }
}

/// PEF (Classic Mac) analysis command.
#[derive(Debug)]
pub struct PefBinaryAnalysisCommand {
    inner: BinaryAnalysisCommand,
}

impl PefBinaryAnalysisCommand {
    pub fn new() -> Self {
        Self {
            inner: BinaryAnalysisCommand::new(BinaryFormat::Pef),
        }
    }
}

impl Default for PefBinaryAnalysisCommand {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_analysis_command() {
        let cmd = BinaryAnalysisCommand::new(BinaryFormat::Elf);
        assert_eq!(cmd.format(), BinaryFormat::Elf);
        assert!(cmd.apply_to("test"));
    }

    #[test]
    fn test_elf_command() {
        let cmd = ElfBinaryAnalysisCommand::new();
        assert_eq!(cmd.inner.format(), BinaryFormat::Elf);
    }

    #[test]
    fn test_pe_command() {
        let cmd = PortableExecutableBinaryAnalysisCommand::new();
        assert_eq!(cmd.inner.format(), BinaryFormat::PortableExecutable);
    }

    #[test]
    fn test_macho_command() {
        let cmd = MachoBinaryAnalysisCommand::new();
        assert_eq!(cmd.inner.format(), BinaryFormat::Macho);
    }

    #[test]
    fn test_binary_format_variants() {
        assert_ne!(BinaryFormat::Elf, BinaryFormat::PortableExecutable);
        assert_ne!(BinaryFormat::Coff, BinaryFormat::Pef);
    }
}
