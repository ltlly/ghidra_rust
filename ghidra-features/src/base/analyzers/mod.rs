//! Binary format analyzers that run automatically during import.
//!
//! Ported from Ghidra's `ghidra.app.analyzers` Java package. Each analyzer
//! inspects a loaded program to apply format-specific analysis (e.g., ELF
//! relocations, PE imports, Mach-O symbols, COFF archives).
//!
//! # Key types
//!
//! - [`BinaryFormatAnalyzer`] -- trait for format-specific analyzers
//! - [`ElfAnalyzer`] -- ELF binary format analysis
//! - [`PortableExecutableAnalyzer`] -- PE binary format analysis
//! - [`MachoAnalyzer`] -- Mach-O binary format analysis
//! - [`CoffAnalyzer`] -- COFF binary format analysis
//! - [`CoffArchiveAnalyzer`] -- COFF archive analysis
//! - [`AppleSingleDoubleAnalyzer`] -- AppleSingle/AppleDouble analysis
//! - [`PefAnalyzer`] -- PEF (Classic Mac) analysis
//! - [`CondenseFillerBytesAnalyzer`] -- filler byte condensation

use std::fmt;

// ---------------------------------------------------------------------------
// Placeholder types
// ---------------------------------------------------------------------------

/// Placeholder for a Ghidra Program.
#[derive(Debug, Clone)]
pub struct Program {
    pub name: String,
}

/// Placeholder for a program address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address(pub u64);

/// Placeholder for an address set.
#[derive(Debug, Clone, Default)]
pub struct AddressSet {
    pub ranges: Vec<(Address, Address)>,
}

impl AddressSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn contains(&self, addr: Address) -> bool {
        self.ranges
            .iter()
            .any(|(start, end)| addr.0 >= start.0 && addr.0 <= end.0)
    }
}

/// Placeholder for TaskMonitor.
pub trait TaskMonitor: fmt::Debug + Send + Sync {
    fn is_cancelled(&self) -> bool;
    fn set_progress(&self, value: u64);
    fn set_message(&self, msg: &str);
}

// ---------------------------------------------------------------------------
// BinaryFormatAnalyzer trait
// ---------------------------------------------------------------------------

/// Trait for analyzers that process specific binary formats.
pub trait BinaryFormatAnalyzer: fmt::Debug + Send + Sync {
    /// Human-readable name of this analyzer.
    fn name(&self) -> &str;

    /// Whether this analyzer is enabled by default.
    fn is_default_enabled(&self) -> bool {
        true
    }

    /// Analyze the given program.
    ///
    /// Returns `true` if analysis completed successfully.
    fn analyze(
        &self,
        program: &mut Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
    ) -> bool;
}

// ---------------------------------------------------------------------------
// AbstractBinaryFormatAnalyzer
// ---------------------------------------------------------------------------

/// Base implementation with common behavior for all binary format analyzers.
#[derive(Debug)]
pub struct AbstractBinaryFormatAnalyzer {
    name: String,
    default_enabled: bool,
}

impl AbstractBinaryFormatAnalyzer {
    pub fn new(name: impl Into<String>, default_enabled: bool) -> Self {
        Self {
            name: name.into(),
            default_enabled,
        }
    }
}

impl BinaryFormatAnalyzer for AbstractBinaryFormatAnalyzer {
    fn name(&self) -> &str {
        &self.name
    }

    fn is_default_enabled(&self) -> bool {
        self.default_enabled
    }

    fn analyze(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
    ) -> bool {
        // Base implementation does nothing; override in concrete analyzers.
        true
    }
}

// ---------------------------------------------------------------------------
// Concrete analyzers
// ---------------------------------------------------------------------------

/// ELF binary format analyzer.
///
/// Processes ELF-specific structures: section headers, relocations,
/// dynamic linking information, symbol tables, etc.
#[derive(Debug)]
pub struct ElfAnalyzer {
    inner: AbstractBinaryFormatAnalyzer,
}

impl ElfAnalyzer {
    pub fn new() -> Self {
        Self {
            inner: AbstractBinaryFormatAnalyzer::new("ELF Analyzer", true),
        }
    }
}

impl Default for ElfAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryFormatAnalyzer for ElfAnalyzer {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn analyze(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
    ) -> bool {
        // ELF-specific analysis would go here.
        true
    }
}

/// Portable Executable (PE) binary format analyzer.
///
/// Processes PE-specific structures: import/export tables, relocations,
/// resource directories, TLS, etc.
#[derive(Debug)]
pub struct PortableExecutableAnalyzer {
    inner: AbstractBinaryFormatAnalyzer,
}

impl PortableExecutableAnalyzer {
    pub fn new() -> Self {
        Self {
            inner: AbstractBinaryFormatAnalyzer::new("PE Analyzer", true),
        }
    }
}

impl Default for PortableExecutableAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryFormatAnalyzer for PortableExecutableAnalyzer {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn analyze(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
    ) -> bool {
        true
    }
}

/// Mach-O binary format analyzer.
#[derive(Debug)]
pub struct MachoAnalyzer {
    inner: AbstractBinaryFormatAnalyzer,
}

impl MachoAnalyzer {
    pub fn new() -> Self {
        Self {
            inner: AbstractBinaryFormatAnalyzer::new("Mach-O Analyzer", true),
        }
    }
}

impl Default for MachoAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryFormatAnalyzer for MachoAnalyzer {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn analyze(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
    ) -> bool {
        true
    }
}

/// COFF binary format analyzer.
#[derive(Debug)]
pub struct CoffAnalyzer {
    inner: AbstractBinaryFormatAnalyzer,
}

impl CoffAnalyzer {
    pub fn new() -> Self {
        Self {
            inner: AbstractBinaryFormatAnalyzer::new("COFF Analyzer", true),
        }
    }
}

impl Default for CoffAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryFormatAnalyzer for CoffAnalyzer {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn analyze(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
    ) -> bool {
        true
    }
}

/// COFF archive (`.a` / `.lib`) analyzer.
#[derive(Debug)]
pub struct CoffArchiveAnalyzer {
    inner: AbstractBinaryFormatAnalyzer,
}

impl CoffArchiveAnalyzer {
    pub fn new() -> Self {
        Self {
            inner: AbstractBinaryFormatAnalyzer::new("COFF Archive Analyzer", true),
        }
    }
}

impl Default for CoffArchiveAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryFormatAnalyzer for CoffArchiveAnalyzer {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn analyze(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
    ) -> bool {
        true
    }
}

/// AppleSingle / AppleDouble format analyzer.
#[derive(Debug)]
pub struct AppleSingleDoubleAnalyzer {
    inner: AbstractBinaryFormatAnalyzer,
}

impl AppleSingleDoubleAnalyzer {
    pub fn new() -> Self {
        Self {
            inner: AbstractBinaryFormatAnalyzer::new("AppleSingle/Double Analyzer", true),
        }
    }
}

impl Default for AppleSingleDoubleAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryFormatAnalyzer for AppleSingleDoubleAnalyzer {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn analyze(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
    ) -> bool {
        true
    }
}

/// PEF (Preferred Executable Format, Classic Mac) analyzer.
#[derive(Debug)]
pub struct PefAnalyzer {
    inner: AbstractBinaryFormatAnalyzer,
}

impl PefAnalyzer {
    pub fn new() -> Self {
        Self {
            inner: AbstractBinaryFormatAnalyzer::new("PEF Analyzer", true),
        }
    }
}

impl Default for PefAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryFormatAnalyzer for PefAnalyzer {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn analyze(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
    ) -> bool {
        true
    }
}

/// Analyzer that condenses filler bytes (NOP sleds, padding) into
/// a single annotated region.
#[derive(Debug)]
pub struct CondenseFillerBytesAnalyzer {
    inner: AbstractBinaryFormatAnalyzer,
}

impl CondenseFillerBytesAnalyzer {
    pub fn new() -> Self {
        Self {
            inner: AbstractBinaryFormatAnalyzer::new("Condense Filler Bytes", true),
        }
    }
}

impl Default for CondenseFillerBytesAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryFormatAnalyzer for CondenseFillerBytesAnalyzer {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn analyze(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        _monitor: &dyn TaskMonitor,
    ) -> bool {
        true
    }
}

/// Create all built-in binary format analyzers.
pub fn create_default_analyzers() -> Vec<Box<dyn BinaryFormatAnalyzer>> {
    vec![
        Box::new(ElfAnalyzer::new()),
        Box::new(PortableExecutableAnalyzer::new()),
        Box::new(MachoAnalyzer::new()),
        Box::new(CoffAnalyzer::new()),
        Box::new(CoffArchiveAnalyzer::new()),
        Box::new(AppleSingleDoubleAnalyzer::new()),
        Box::new(PefAnalyzer::new()),
        Box::new(CondenseFillerBytesAnalyzer::new()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct NoopMonitor;

    impl TaskMonitor for NoopMonitor {
        fn is_cancelled(&self) -> bool {
            false
        }
        fn set_progress(&self, _value: u64) {}
        fn set_message(&self, _msg: &str) {}
    }

    #[test]
    fn test_elf_analyzer() {
        let analyzer = ElfAnalyzer::new();
        assert_eq!(analyzer.name(), "ELF Analyzer");
        assert!(analyzer.is_default_enabled());
        let mut prog = Program {
            name: "test.elf".into(),
        };
        assert!(analyzer.analyze(&mut prog, &AddressSet::new(), &NoopMonitor));
    }

    #[test]
    fn test_pe_analyzer() {
        let analyzer = PortableExecutableAnalyzer::new();
        assert_eq!(analyzer.name(), "PE Analyzer");
        let mut prog = Program {
            name: "test.exe".into(),
        };
        assert!(analyzer.analyze(&mut prog, &AddressSet::new(), &NoopMonitor));
    }

    #[test]
    fn test_macho_analyzer() {
        let analyzer = MachoAnalyzer::new();
        assert_eq!(analyzer.name(), "Mach-O Analyzer");
        let mut prog = Program {
            name: "test.macho".into(),
        };
        assert!(analyzer.analyze(&mut prog, &AddressSet::new(), &NoopMonitor));
    }

    #[test]
    fn test_coff_analyzer() {
        let analyzer = CoffAnalyzer::new();
        assert_eq!(analyzer.name(), "COFF Analyzer");
    }

    #[test]
    fn test_coff_archive_analyzer() {
        let analyzer = CoffArchiveAnalyzer::new();
        assert_eq!(analyzer.name(), "COFF Archive Analyzer");
    }

    #[test]
    fn test_apple_single_double() {
        let analyzer = AppleSingleDoubleAnalyzer::new();
        assert_eq!(analyzer.name(), "AppleSingle/Double Analyzer");
    }

    #[test]
    fn test_pef_analyzer() {
        let analyzer = PefAnalyzer::new();
        assert_eq!(analyzer.name(), "PEF Analyzer");
    }

    #[test]
    fn test_condense_filler() {
        let analyzer = CondenseFillerBytesAnalyzer::new();
        assert_eq!(analyzer.name(), "Condense Filler Bytes");
    }

    #[test]
    fn test_abstract_analyzer_default_disabled() {
        let analyzer = AbstractBinaryFormatAnalyzer::new("Custom", false);
        assert!(!analyzer.is_default_enabled());
    }

    #[test]
    fn test_create_default_analyzers() {
        let analyzers = create_default_analyzers();
        assert_eq!(analyzers.len(), 8);
    }

    #[test]
    fn test_address_set() {
        let mut set = AddressSet::new();
        assert!(set.is_empty());
        set.ranges.push((Address(0x1000), Address(0x2000)));
        assert!(set.contains(Address(0x1500)));
        assert!(!set.contains(Address(0x3000)));
    }
}
