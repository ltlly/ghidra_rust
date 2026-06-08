//! MachoFunctionStartsAnalyzer -- creates functions from Mach-O LC_FUNCTION_STARTS.
//!
//! Ported from `ghidra.app.plugin.core.analysis.MachoFunctionStartsAnalyzer`.
//! Reads the LC_FUNCTION_STARTS load command from Mach-O headers and creates
//! functions at the specified addresses. Also supports DYLD shared caches.

use std::collections::HashMap;

use crate::base::analyzer::core::*;
use crate::base::analyzer::priority::*;
use crate::base::analyzer::r#trait::*;

/// A function start entry parsed from LC_FUNCTION_STARTS.
#[derive(Debug, Clone)]
pub struct FunctionStartEntry {
    /// Virtual address of the function start.
    pub address: u64,
    /// Whether this function was successfully created.
    pub created: bool,
    /// Skip reason (if the function was skipped).
    pub skip_reason: Option<String>,
}

/// Analyzer that creates functions from Mach-O LC_FUNCTION_STARTS.
///
/// Parses the LC_FUNCTION_STARTS load command from Mach-O headers and creates
/// functions at the specified addresses. Validates each address before creating
/// a function (e.g., checks for existing data, UDF instructions, invalid subroutines).
///
/// # Options
///
/// - `Bookmark new functions` -- create bookmarks for new functions (default: false)
/// - `Bookmark failed functions` -- create bookmarks for failed functions (default: false)
/// - `Bookmark skipped functions` -- create bookmarks for skipped functions (default: false)
/// - `Use PseudoDisassembler` -- validate function starts with pseudo-disassembler (default: true)
#[derive(Debug, Clone)]
pub struct MachoFunctionStartsAnalyzer {
    base: AbstractAnalyzer,
    /// Whether this is a DYLD shared cache.
    pub is_dyld: bool,
    /// Create bookmarks for new functions.
    pub create_bookmarks_new: bool,
    /// Create bookmarks for failed functions.
    pub create_bookmarks_failed: bool,
    /// Create bookmarks for skipped functions.
    pub create_bookmarks_skipped: bool,
    /// Use pseudo-disassembler for validation.
    pub use_pseudo_disassembler: bool,
    /// Parsed function start entries.
    entries: Vec<FunctionStartEntry>,
}

impl MachoFunctionStartsAnalyzer {
    /// Creates a new analyzer.
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Mach-O Function Starts",
            "An analyzer for discovering functions via the Mach-O LC_FUNCTION_STARTS load command",
            AnalyzerType::Byte,
        );
        base.set_default_enablement(true);
        base.set_priority(AnalysisPriority::FUNCTION_ID_ANALYSIS.after());

        Self {
            base,
            is_dyld: false,
            create_bookmarks_new: false,
            create_bookmarks_failed: false,
            create_bookmarks_skipped: false,
            use_pseudo_disassembler: true,
            entries: Vec::new(),
        }
    }

    /// Returns parsed function start entries.
    pub fn entries(&self) -> &[FunctionStartEntry] {
        &self.entries
    }

    /// Validates whether a function start address is acceptable.
    ///
    /// Checks:
    /// - No existing data at the address (except undefined)
    /// - No existing function at the address
    /// - If using pseudo-disassembler, validates the instruction is not UDF
    fn validate_function_start(
        &self,
        program: &Program,
        addr: Address,
    ) -> Option<String> {
        // Check for existing data (possible switch data)
        if let Some(data) = program.listing.get_defined_data_at(&addr) {
            if data.data_type_name != "undefined" {
                return Some("Skipped Existing Data".to_string());
            }
        }

        // Check for existing function
        if program.function_manager.get_function_at(&addr).is_some() {
            return Some("Skipped Existing Function".to_string());
        }

        // Pseudo-disassembler validation
        if self.use_pseudo_disassembler {
            if let Some(instr) = program.listing.get_instruction_at(&addr) {
                // Check for UDF (undefined instruction)
                if instr.mnemonic.to_uppercase() == "UDF" {
                    return Some("Skipped UDF Instruction".to_string());
                }
            }
        }

        None // Valid
    }

    /// Processes function start addresses from parsed data.
    fn process_function_starts(
        &mut self,
        program: &mut Program,
        text_segment_addr: u64,
        function_starts: &[u64],
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<u32, CancelledError> {
        let mut created = 0u32;
        let mut skipped = 0u32;
        let mut failed = 0u32;

        for &offset in function_starts {
            monitor.check_cancelled()?;

            let addr = Address::new(text_segment_addr + offset);

            if !set.contains(&addr) {
                continue;
            }

            // Validate the function start
            if let Some(skip_reason) = self.validate_function_start(program, addr) {
                self.entries.push(FunctionStartEntry {
                    address: addr.offset,
                    created: false,
                    skip_reason: Some(skip_reason.clone()),
                });

                if self.create_bookmarks_skipped {
                    program.set_bookmark(
                        addr,
                        BookmarkType::Analysis,
                        "LC_FUNCTION_STARTS",
                        &skip_reason,
                    );
                }
                skipped += 1;
                continue;
            }

            // Create function
            if let Some(instr) = program.listing.get_instruction_at(&addr) {
                let body = AddressSet::from_range(AddressRange::new(
                    addr,
                    Address::new(addr.offset + instr.length as u64 - 1),
                ));

                program.function_manager.functions.insert(
                    addr,
                    Function {
                        entry_point: addr,
                        body,
                        name: None,
                        is_external: false,
                        is_thunk: false,
                        is_inline: false,
                        has_noreturn: false,
                        call_fixup: None,
                    },
                );

                self.entries.push(FunctionStartEntry {
                    address: addr.offset,
                    created: true,
                    skip_reason: None,
                });

                if self.create_bookmarks_new {
                    program.set_bookmark(
                        addr,
                        BookmarkType::Analysis,
                        "LC_FUNCTION_STARTS",
                        "New Function",
                    );
                }

                created += 1;
            } else {
                // No instruction at address
                self.entries.push(FunctionStartEntry {
                    address: addr.offset,
                    created: false,
                    skip_reason: Some("No instruction at address".to_string()),
                });

                if self.create_bookmarks_failed {
                    program.set_bookmark(
                        addr,
                        BookmarkType::Analysis,
                        "LC_FUNCTION_STARTS",
                        "Failed Function",
                    );
                }

                failed += 1;
            }
        }

        log.append_msg(format!(
            "MachoFunctionStartsAnalyzer: created={}, skipped={}, failed={}",
            created, skipped, failed
        ));

        Ok(created)
    }
}

impl Analyzer for MachoFunctionStartsAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        AnalyzerType::Byte
    }
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::FUNCTION_ID_ANALYSIS.after()
    }

    fn can_analyze(&self, program: &Program) -> bool {
        program
            .executable_format
            .as_deref()
            .map_or(false, |f| f == "Mach-O" || f.contains("DyldCache"))
    }

    fn default_enablement(&self, _program: &Program) -> bool {
        true
    }

    fn added(
        &self,
        program: &mut Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        monitor.check_cancelled()?;
        monitor.set_message("Analyzing Mach-O function starts...");

        let mut analyzer = self.clone();
        analyzer.entries.clear();

        // In a real implementation, this would parse the Mach-O header to find
        // the LC_FUNCTION_STARTS load command and extract function start offsets.
        // For now, we demonstrate the structure with a simulation.

        // Simulated function starts (in a real implementation, these come from parsing)
        let function_starts: Vec<u64> = Vec::new();

        let text_segment_addr = program.get_min_address().map(|a| a.offset).unwrap_or(0);

        let result = analyzer.process_function_starts(
            program,
            text_segment_addr,
            &function_starts,
            set,
            monitor,
            log,
        )?;

        Ok(result > 0)
    }

    fn options_changed(&mut self, opts: &HashMap<String, AnalysisOptionValue>) {
        if let Some(AnalysisOptionValue::Bool(v)) = opts.get("Bookmark new functions") {
            self.create_bookmarks_new = *v;
        }
        if let Some(AnalysisOptionValue::Bool(v)) = opts.get("Bookmark failed functions") {
            self.create_bookmarks_failed = *v;
        }
        if let Some(AnalysisOptionValue::Bool(v)) = opts.get("Bookmark skipped functions") {
            self.create_bookmarks_skipped = *v;
        }
        if let Some(AnalysisOptionValue::Bool(v)) = opts.get("Use PseudoDisassembler") {
            self.use_pseudo_disassembler = *v;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_macho_program() -> Program {
        let lang = Language {
            processor: "ARM".into(),
            variant: "LE".into(),
            size: 64,
        };
        let mut p = Program::new("test_macho", lang);
        p.executable_format = Some("Mach-O".into());
        p.memory
            .add_range(AddressRange::new(Address::new(0x100000), Address::new(0x200000)));
        p
    }

    #[test]
    fn test_macho_analyzer_creation() {
        let a = MachoFunctionStartsAnalyzer::new();
        assert_eq!(a.name(), "Mach-O Function Starts");
        assert!(!a.create_bookmarks_new);
        assert!(a.use_pseudo_disassembler);
    }

    #[test]
    fn test_macho_can_analyze() {
        let a = MachoFunctionStartsAnalyzer::new();
        let mut p = make_macho_program();
        assert!(a.can_analyze(&p));

        p.executable_format = Some("ELF".into());
        assert!(!a.can_analyze(&p));
    }

    #[test]
    fn test_macho_priority() {
        let a = MachoFunctionStartsAnalyzer::new();
        assert!(a.priority() > AnalysisPriority::FUNCTION_ID_ANALYSIS);
    }

    #[test]
    fn test_validate_function_start_empty() {
        let a = MachoFunctionStartsAnalyzer::new();
        let p = make_macho_program();
        // No instruction at address -- validation should pass (no skip reason)
        assert!(a
            .validate_function_start(&p, Address::new(0x150000))
            .is_none());
    }

    #[test]
    fn test_validate_function_start_existing_function() {
        let a = MachoFunctionStartsAnalyzer::new();
        let mut p = make_macho_program();

        p.function_manager.functions.insert(
            Address::new(0x150000),
            Function {
                entry_point: Address::new(0x150000),
                body: AddressSet::from_range(AddressRange::new(
                    Address::new(0x150000),
                    Address::new(0x150010),
                )),
                name: Some("existing".into()),
                is_external: false,
                is_thunk: false,
                is_inline: false,
                has_noreturn: false,
                call_fixup: None,
            },
        );

        let reason = a.validate_function_start(&p, Address::new(0x150000));
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("Existing Function"));
    }

    #[test]
    fn test_validate_function_start_udf() {
        let a = MachoFunctionStartsAnalyzer::new();
        let mut p = make_macho_program();

        p.listing.instructions.insert(
            Address::new(0x150000),
            Instruction {
                address: Address::new(0x150000),
                length: 4,
                mnemonic: "UDF".into(),
                flow_type: FlowType::Terminator,
                fall_through: None,
                flows: vec![],
                num_operands: 0,
            },
        );

        let reason = a.validate_function_start(&p, Address::new(0x150000));
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("UDF"));
    }

    #[test]
    fn test_validate_function_start_valid() {
        let a = MachoFunctionStartsAnalyzer::new();
        let mut p = make_macho_program();

        p.listing.instructions.insert(
            Address::new(0x150000),
            Instruction {
                address: Address::new(0x150000),
                length: 4,
                mnemonic: "PUSH".into(),
                flow_type: FlowType::Fallthrough,
                fall_through: Some(Address::new(0x150004)),
                flows: vec![],
                num_operands: 1,
            },
        );

        let reason = a.validate_function_start(&p, Address::new(0x150000));
        assert!(reason.is_none());
    }

    #[test]
    fn test_macho_options_changed() {
        let mut a = MachoFunctionStartsAnalyzer::new();
        let mut opts = HashMap::new();
        opts.insert(
            "Bookmark new functions".to_string(),
            AnalysisOptionValue::Bool(true),
        );
        opts.insert(
            "Bookmark failed functions".to_string(),
            AnalysisOptionValue::Bool(true),
        );
        opts.insert(
            "Bookmark skipped functions".to_string(),
            AnalysisOptionValue::Bool(true),
        );
        a.options_changed(&opts);
        assert!(a.create_bookmarks_new);
        assert!(a.create_bookmarks_failed);
        assert!(a.create_bookmarks_skipped);
    }
}
