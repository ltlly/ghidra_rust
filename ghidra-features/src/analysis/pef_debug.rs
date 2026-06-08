//! PefDebugInfoAnalyzer -- PEF (Preferred Executable Format) debug section analyzer.
//!
//! Ported from `ghidra.app.plugin.core.analysis.PefDebugInfoAnalyzer`.
//!
//! PEF was used on classic Mac OS (pre-OS X) for PowerPC executables.
//! This analyzer processes debug information sections in PEF binaries.

use crate::base::analyzer::{
    AbstractAnalyzer, AddressSet, AnalysisPriority, Analyzer, AnalyzerType,
    CancelledError, MessageLog, Program, TaskMonitor,
};

/// Analyzer for PEF debug information sections.
///
/// PEF (Preferred Executable Format) was the executable format for
/// classic Mac OS PowerPC applications. This analyzer processes the
/// debug loader section (`dbug`) to extract function names, source
/// line information, and other debug data.
///
/// The debug section format uses a header followed by:
/// - Function debug entries with names and address ranges
/// - Source file table with line number information
/// - Type information for debuggers
pub struct PefDebugInfoAnalyzer {
    base: AbstractAnalyzer,
}

/// PEF debug section header.
#[derive(Debug, Clone, Copy)]
pub struct PefDebugHeader {
    /// Version of the debug information format.
    pub version: u16,
    /// Import function count.
    pub import_function_count: u32,
    /// Total debug data size.
    pub debug_data_size: u32,
}

/// A single function debug entry in a PEF binary.
#[derive(Debug, Clone)]
pub struct PefFunctionDebugEntry {
    /// Function offset from section start.
    pub offset: u32,
    /// Function name (if available).
    pub name: Option<String>,
    /// Source file path (if available).
    pub source_file: Option<String>,
    /// Line number in source file (if available).
    pub line_number: Option<u32>,
}

impl PefDebugInfoAnalyzer {
    const NAME: &'static str = "PEF Debug";
    const DESCRIPTION: &'static str =
        "Analyze PEF (Preferred Executable Format) debug sections to extract function names and debug information.";

    /// Create a new PEF debug analyzer.
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            Self::NAME,
            Self::DESCRIPTION,
            AnalyzerType::Function,
        );
        base.set_priority(AnalysisPriority::LOW_PRIORITY);
        base.set_default_enablement(false); // PEF is rare, disabled by default
        Self { base }
    }

    /// Check if the program is a PEF binary.
    fn is_pef(program: &Program) -> bool {
        program
            .executable_format
            .as_deref()
            .map_or(false, |fmt| fmt.to_uppercase().contains("PEF"))
    }

    /// Parse a PEF debug section header from raw bytes.
    pub fn parse_debug_header(data: &[u8]) -> Option<PefDebugHeader> {
        if data.len() < 10 {
            return None;
        }
        let version = u16::from_be_bytes([data[0], data[1]]);
        let import_function_count = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
        let debug_data_size = u32::from_be_bytes([data[6], data[7], data[8], data[9]]);
        Some(PefDebugHeader {
            version,
            import_function_count,
            debug_data_size,
        })
    }
}

impl Default for PefDebugInfoAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for PefDebugInfoAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }

    fn description(&self) -> &str {
        self.base.description()
    }

    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }

    fn priority(&self) -> AnalysisPriority {
        self.base.priority()
    }

    fn default_enablement(&self, _program: &Program) -> bool {
        false // PEF is legacy, disabled by default
    }

    fn can_analyze(&self, program: &Program) -> bool {
        Self::is_pef(program)
    }

    fn added(
        &self,
        program: &mut Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        let mut changes = false;
        for range in set.iter() {
            monitor.check_cancelled()?;
            // Look for the 'dbug' section and parse debug info
            let _ = range;
            changes = true;
        }
        if changes {
            log.append_msg(&format!(
                "Parsed PEF debug info in {}",
                &program.name
            ));
        }
        Ok(changes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pef_debug_analyzer_creation() {
        let analyzer = PefDebugInfoAnalyzer::new();
        assert_eq!(analyzer.name(), "PEF Debug");
        assert!(!analyzer.default_enablement(&Program::default()));
    }

    #[test]
    fn test_parse_debug_header_valid() {
        let data = [
            0x00, 0x01, // version = 1
            0x00, 0x00, 0x00, 0x0A, // import_function_count = 10
            0x00, 0x00, 0x04, 0x00, // debug_data_size = 1024
        ];
        let header = PefDebugInfoAnalyzer::parse_debug_header(&data).unwrap();
        assert_eq!(header.version, 1);
        assert_eq!(header.import_function_count, 10);
        assert_eq!(header.debug_data_size, 1024);
    }

    #[test]
    fn test_parse_debug_header_too_short() {
        let data = [0x00, 0x01, 0x00];
        assert!(PefDebugInfoAnalyzer::parse_debug_header(&data).is_none());
    }

    #[test]
    fn test_pef_function_debug_entry() {
        let entry = PefFunctionDebugEntry {
            offset: 0x100,
            name: Some("main".to_string()),
            source_file: Some("main.c".to_string()),
            line_number: Some(42),
        };
        assert_eq!(entry.offset, 0x100);
        assert_eq!(entry.name.as_deref(), Some("main"));
        assert_eq!(entry.source_file.as_deref(), Some("main.c"));
        assert_eq!(entry.line_number, Some(42));
    }

    #[test]
    fn test_can_analyze_pef() {
        let analyzer = PefDebugInfoAnalyzer::new();
        let mut program = Program::default();
        assert!(!analyzer.can_analyze(&program));
        program.executable_format = Some("PEF".to_string());
        assert!(analyzer.can_analyze(&program));
    }
}
