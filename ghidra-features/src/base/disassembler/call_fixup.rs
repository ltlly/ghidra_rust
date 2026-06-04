//! Call fixup analyzer -- ported from Ghidra's `CallFixupAnalyzer.java`.
//!
//! Installs call-fixups defined by the compiler specification and fixes
//! functions that call non-returning or call-fixup functions.

use std::collections::HashMap;

use crate::base::analyzer::core::*;
use crate::base::analyzer::priority::*;
use crate::base::analyzer::r#trait::*;

// ---------------------------------------------------------------------------
// CallFixupAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer that installs call-fixups from compiler specs.
///
/// A call-fixup is a piece of P-code that replaces the semantics of a call
/// instruction. When a function is known to have a call-fixup, this analyzer
/// installs it and repairs any code flow issues caused by non-returning
/// functions.
///
/// # Example
///
/// ```ignore
/// use ghidra_features::base::disassembler::CallFixupAnalyzer;
///
/// let analyzer = CallFixupAnalyzer::new();
/// ```
#[derive(Debug, Clone)]
pub struct CallFixupAnalyzer {
    base: AbstractAnalyzer,
    /// Cached target-fixup map from the compiler spec.
    cached_fixup_map: HashMap<String, String>,
}

impl CallFixupAnalyzer {
    /// Create a new call fixup analyzer.
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Call-Fixup Installer",
            "Installs Call-Fixups defined by the compiler specification and fixes \
             any functions calling Non-Returning or CallFixup Functions.",
            AnalyzerType::Function,
        );
        base.set_priority(AnalysisPriority::DISASSEMBLY.after());
        base.set_default_enablement(true);
        base.set_supports_one_time_analysis(true);

        Self {
            base,
            cached_fixup_map: HashMap::new(),
        }
    }

    /// Get the call-fixup name for a given function, if any.
    ///
    /// This looks up the function name in the compiler spec's target-fixup map.
    pub fn get_call_fixup_for_function(&self, function_name: &str) -> Option<&str> {
        self.cached_fixup_map.get(function_name).map(|s| s.as_str())
    }

    /// Set the target-fixup map (from compiler spec).
    pub fn set_target_fixup_map(&mut self, map: HashMap<String, String>) {
        self.cached_fixup_map = map;
    }

    /// Process a function for call-fixup installation.
    ///
    /// Returns `true` if the function was modified.
    pub fn process_function(&self, function: &mut Function) -> bool {
        let mut modified = false;

        // Check if there's a fixup name for this function
        let func_name = function.name.as_deref().unwrap_or("");
        if let Some(fixup_name) = self.get_call_fixup_for_function(func_name) {
            if function.call_fixup.is_none() {
                function.call_fixup = Some(fixup_name.to_string());
                modified = true;
            }
        }

        modified
    }

    /// Check if a function needs flow repair due to no-return or call-fixup.
    pub fn function_needs_repair(function: &Function) -> bool {
        function.has_noreturn
            || (function.call_fixup.is_some()
                && !function.call_fixup.as_deref().unwrap_or("").is_empty())
    }
}

impl Default for CallFixupAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for CallFixupAnalyzer {
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
        self.base.default_enablement(_program)
    }

    fn can_analyze(&self, _program: &Program) -> bool {
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
        monitor.set_message("Installing call-fixups...");

        let mut modified_count = 0;
        let mut needs_repair_count = 0;

        // Iterate over functions in the given address set
        let entries: Vec<(Address, Function)> = program
            .function_manager
            .functions
            .iter()
            .filter(|(addr, _)| set.contains(addr))
            .map(|(addr, func)| (*addr, func.clone()))
            .collect();

        for (addr, mut function) in entries {
            monitor.check_cancelled()?;

            if self.process_function(&mut function) {
                modified_count += 1;
                program.function_manager.functions.insert(addr, function.clone());
            }

            if Self::function_needs_repair(&function) {
                needs_repair_count += 1;
                // In a full implementation, this would repair the code flow
                // by clearing bad instruction sequences after no-return calls.
            }
        }

        log.append_msg(format!(
            "Installed {} call-fixups, {} functions need flow repair",
            modified_count, needs_repair_count
        ));

        Ok(modified_count > 0 || needs_repair_count > 0)
    }

    fn supports_one_time_analysis(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// CallFixupChangeAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer variant that responds to function modifier changes.
///
/// This is a specialization of [`CallFixupAnalyzer`] that is triggered
/// when a function's modifiers change (e.g., no-return flag is set).
#[derive(Debug, Clone)]
pub struct CallFixupChangeAnalyzer {
    base: CallFixupAnalyzer,
}

impl CallFixupChangeAnalyzer {
    /// Create a new call fixup change analyzer.
    pub fn new() -> Self {
        let mut base = CallFixupAnalyzer::new();
        base.base = AbstractAnalyzer::new(
            "Call-Fixup Modifier",
            "Re-evaluates functions when their modifiers change for call-fixup effects.",
            AnalyzerType::FunctionModifiers,
        );
        base.base.set_priority(AnalysisPriority::DISASSEMBLY.after());
        base.base.set_default_enablement(true);

        Self { base }
    }
}

impl Default for CallFixupChangeAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for CallFixupChangeAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }

    fn description(&self) -> &str {
        self.base.description()
    }

    fn analysis_type(&self) -> AnalyzerType {
        AnalyzerType::FunctionModifiers
    }

    fn priority(&self) -> AnalysisPriority {
        self.base.priority()
    }

    fn default_enablement(&self, _program: &Program) -> bool {
        true
    }

    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }

    fn added(
        &self,
        program: &mut Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        self.base.added(program, set, monitor, log)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_fixup_analyzer_creation() {
        let analyzer = CallFixupAnalyzer::new();
        assert_eq!(analyzer.name(), "Call-Fixup Installer");
        assert_eq!(analyzer.analysis_type(), AnalyzerType::Function);
        assert!(analyzer.default_enablement(&Program::new("test", Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        })));
    }

    #[test]
    fn test_function_needs_repair() {
        let mut func = Function {
            entry_point: Address::new(0x1000),
            body: AddressSet::new(),
            name: Some("test".to_string()),
            is_external: false,
            is_thunk: false,
            is_inline: false,
            has_noreturn: false,
            call_fixup: None,
        };
        assert!(!CallFixupAnalyzer::function_needs_repair(&func));

        func.has_noreturn = true;
        assert!(CallFixupAnalyzer::function_needs_repair(&func));

        func.has_noreturn = false;
        func.call_fixup = Some("my_fixup".to_string());
        assert!(CallFixupAnalyzer::function_needs_repair(&func));
    }

    #[test]
    fn test_get_call_fixup_for_function() {
        let mut analyzer = CallFixupAnalyzer::new();
        let mut map = HashMap::new();
        map.insert("memset".to_string(), "memset_fixup".to_string());
        analyzer.set_target_fixup_map(map);

        assert_eq!(
            analyzer.get_call_fixup_for_function("memset"),
            Some("memset_fixup")
        );
        assert_eq!(
            analyzer.get_call_fixup_for_function("printf"),
            None
        );
    }

    #[test]
    fn test_process_function() {
        let mut analyzer = CallFixupAnalyzer::new();
        let mut map = HashMap::new();
        map.insert("memcpy".to_string(), "memcpy_fixup".to_string());
        analyzer.set_target_fixup_map(map);

        let mut func = Function {
            entry_point: Address::new(0x1000),
            body: AddressSet::new(),
            name: Some("memcpy".to_string()),
            is_external: false,
            is_thunk: false,
            is_inline: false,
            has_noreturn: false,
            call_fixup: None,
        };

        assert!(analyzer.process_function(&mut func));
        assert_eq!(func.call_fixup.as_deref(), Some("memcpy_fixup"));

        // Second call should not modify (already has fixup)
        assert!(!analyzer.process_function(&mut func));
    }

    #[test]
    fn test_call_fixup_change_analyzer() {
        let analyzer = CallFixupChangeAnalyzer::new();
        assert_eq!(analyzer.name(), "Call-Fixup Modifier");
        assert_eq!(analyzer.analysis_type(), AnalyzerType::FunctionModifiers);
    }

    #[test]
    fn test_can_analyze() {
        let analyzer = CallFixupAnalyzer::new();
        let prog = Program::new("test", Language {
            processor: "ARM".into(),
            variant: "LE".into(),
            size: 32,
        });
        assert!(analyzer.can_analyze(&prog));
    }
}
