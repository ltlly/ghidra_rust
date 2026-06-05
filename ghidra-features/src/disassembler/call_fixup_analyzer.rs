//! Call-Fixup Analyzer -- ported from
//! `ghidra.app.plugin.core.disassembler.CallFixupAnalyzer`.
//!
//! Installs call-fixups defined by the compiler specification and
//! fixes any functions calling non-returning or call-fixup functions.

use ghidra_core::Address;
use std::collections::{HashMap, HashSet};

use super::entry_point_analyzer::{AnalysisPriority, AnalyzerType};

/// A call-fixup definition from the compiler specification.
///
/// Ported from `ghidra.program.model.lang.CallFixup`.
#[derive(Debug, Clone)]
pub struct CallFixupDefinition {
    /// The name of the call fixup (e.g. "memcpy", "memset").
    pub name: String,
    /// The p-code snippet to inline at call sites.
    pub pcode_snippet: String,
    /// The target fixup name (what it replaces).
    pub target_name: String,
    /// Whether this is a callee fixup (vs. caller fixup).
    pub is_callee_fixup: bool,
}

impl CallFixupDefinition {
    /// Create a new call fixup definition.
    pub fn new(
        name: impl Into<String>,
        pcode_snippet: impl Into<String>,
        target_name: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            pcode_snippet: pcode_snippet.into(),
            target_name: target_name.into(),
            is_callee_fixup: true,
        }
    }
}

/// Information about a call site that needs fixing.
#[derive(Debug, Clone)]
pub struct CallFixupLocation {
    /// Address of the call instruction.
    pub call_address: Address,
    /// Address of the called function.
    pub callee_address: Address,
    /// The fixup name to apply (if any).
    pub fixup_name: Option<String>,
    /// Whether the callee is non-returning.
    pub is_non_returning: bool,
}

/// Result of a repair operation.
#[derive(Debug, Clone, Default)]
pub struct RepairResult {
    /// Functions that were repaired.
    pub repaired_functions: Vec<Address>,
    /// Call sites that were modified.
    pub modified_call_sites: Vec<Address>,
    /// Functions that were flagged as non-fixed.
    pub non_fixed_functions: Vec<Address>,
}

impl RepairResult {
    /// Whether any repairs were made.
    pub fn has_repairs(&self) -> bool {
        !self.repaired_functions.is_empty() || !self.modified_call_sites.is_empty()
    }
}

/// Call-Fixup Analyzer for installing call-fixups and fixing non-returning function calls.
///
/// Ported from `ghidra.app.plugin.core.disassembler.CallFixupAnalyzer`.
///
/// This analyzer:
/// 1. Loads call-fixup definitions from the compiler specification.
/// 2. Scans functions for calls to non-returning or call-fixup functions.
/// 3. Clears and repairs disassembly at affected call sites.
/// 4. Updates function bodies after repairs.
#[derive(Debug)]
pub struct CallFixupAnalyzer {
    /// The analyzer name.
    pub name: String,
    /// Description.
    pub description: String,
    /// The analyzer type.
    pub analyzer_type: AnalyzerType,
    /// Analysis priority.
    pub priority: AnalysisPriority,
    /// Whether enabled by default.
    pub default_enabled: bool,
    /// Whether supports one-time analysis.
    pub supports_one_time_analysis: bool,
    /// Cached call-fixup definitions (name -> definition).
    fixup_definitions: HashMap<String, CallFixupDefinition>,
    /// Cached target fixup map (callee name -> fixup name).
    target_fixup_map: HashMap<String, String>,
    /// Functions that need fixup processing.
    pending_functions: HashSet<u64>,
    /// Protected locations that should not be cleared.
    protected_locations: HashSet<u64>,
}

impl CallFixupAnalyzer {
    /// The standard analyzer name.
    pub const NAME: &'static str = "Call-Fixup Installer";

    /// Create a new call-fixup analyzer.
    pub fn new() -> Self {
        Self {
            name: Self::NAME.into(),
            description: "Installs Call-Fixups defined by the compiler specification \
                         and fixes any functions calling Non-Returning or CallFixup Functions"
                .into(),
            analyzer_type: AnalyzerType::FunctionAnalyzer,
            priority: AnalysisPriority::Disassembly.after(),
            default_enabled: true,
            supports_one_time_analysis: true,
            fixup_definitions: HashMap::new(),
            target_fixup_map: HashMap::new(),
            pending_functions: HashSet::new(),
            protected_locations: HashSet::new(),
        }
    }

    /// Register a call-fixup definition.
    pub fn register_fixup(&mut self, fixup: CallFixupDefinition) {
        self.target_fixup_map
            .insert(fixup.target_name.clone(), fixup.name.clone());
        self.fixup_definitions
            .insert(fixup.name.clone(), fixup);
    }

    /// Look up the fixup name for a callee function name.
    pub fn get_fixup_for_callee(&self, callee_name: &str) -> Option<&str> {
        self.target_fixup_map
            .get(callee_name)
            .map(|s| s.as_str())
    }

    /// Get a fixup definition by name.
    pub fn get_fixup_definition(&self, name: &str) -> Option<&CallFixupDefinition> {
        self.fixup_definitions.get(name)
    }

    /// Add a function to the pending processing set.
    pub fn add_pending_function(&mut self, address: Address) {
        self.pending_functions.insert(address.offset);
    }

    /// Add a protected location.
    pub fn add_protected_location(&mut self, address: Address) {
        self.protected_locations.insert(address.offset);
    }

    /// Add multiple protected locations.
    pub fn add_protected_locations(&mut self, addresses: &[Address]) {
        for addr in addresses {
            self.protected_locations.insert(addr.offset);
        }
    }

    /// Whether a location is protected from clearing.
    pub fn is_protected(&self, address: Address) -> bool {
        self.protected_locations.contains(&address.offset)
    }

    /// Get pending functions.
    pub fn pending_functions(&self) -> &HashSet<u64> {
        &self.pending_functions
    }

    /// Identify call-fixup locations for a set of functions.
    ///
    /// This models the core analysis logic: for each pending function,
    /// check its call targets and determine which need fixups.
    pub fn identify_fixup_locations(
        &self,
        call_targets: &[(Address, String)], // (call_site, callee_name)
    ) -> Vec<CallFixupLocation> {
        let mut locations = Vec::new();
        for &(call_site, ref callee_name) in call_targets {
            let fixup_name = self.get_fixup_for_callee(callee_name).map(|s| s.to_string());
            let is_non_returning = self.is_non_returning_function(callee_name);
            if fixup_name.is_some() || is_non_returning {
                locations.push(CallFixupLocation {
                    call_address: call_site,
                    callee_address: Address::new(0), // would be resolved in real impl
                    fixup_name,
                    is_non_returning,
                });
            }
        }
        locations
    }

    /// Check if a function name is non-returning.
    ///
    /// In a full implementation, this checks the compiler spec's
    /// non-returning function list.
    pub fn is_non_returning_function(&self, name: &str) -> bool {
        // Common non-returning functions
        matches!(
            name,
            "exit" | "abort" | "_exit" | "__stack_chk_fail" | "longjmp" | "_Unwind_Resume"
        )
    }

    /// Perform repair on identified locations.
    ///
    /// Returns a `RepairResult` summarizing what was changed.
    pub fn repair_damage(
        &mut self,
        locations: &[CallFixupLocation],
    ) -> RepairResult {
        let mut result = RepairResult::default();
        for loc in locations {
            if !self.is_protected(loc.call_address) {
                result.modified_call_sites.push(loc.call_address);
            }
            if loc.is_non_returning {
                result
                    .repaired_functions
                    .push(loc.callee_address);
            }
        }
        self.pending_functions.clear();
        result
    }

    /// Get the number of registered fixup definitions.
    pub fn fixup_count(&self) -> usize {
        self.fixup_definitions.len()
    }

    /// Clear all state.
    pub fn clear(&mut self) {
        self.pending_functions.clear();
        self.protected_locations.clear();
    }
}

impl Default for CallFixupAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_fixup_analyzer_new() {
        let analyzer = CallFixupAnalyzer::new();
        assert_eq!(analyzer.name, CallFixupAnalyzer::NAME);
        assert_eq!(analyzer.analyzer_type, AnalyzerType::FunctionAnalyzer);
        assert!(analyzer.default_enabled);
        assert!(analyzer.supports_one_time_analysis);
    }

    #[test]
    fn test_register_fixup() {
        let mut analyzer = CallFixupAnalyzer::new();
        analyzer.register_fixup(CallFixupDefinition::new(
            "memcpy_fixup",
            "pcode...",
            "memcpy",
        ));
        assert_eq!(analyzer.fixup_count(), 1);
        assert_eq!(analyzer.get_fixup_for_callee("memcpy"), Some("memcpy_fixup"));
        assert!(analyzer.get_fixup_for_callee("malloc").is_none());
    }

    #[test]
    fn test_get_fixup_definition() {
        let mut analyzer = CallFixupAnalyzer::new();
        analyzer.register_fixup(CallFixupDefinition::new(
            "memset_fixup",
            "pcode...",
            "memset",
        ));
        let def = analyzer.get_fixup_definition("memset_fixup").unwrap();
        assert_eq!(def.target_name, "memset");
        assert!(def.is_callee_fixup);
    }

    #[test]
    fn test_non_returning_functions() {
        let analyzer = CallFixupAnalyzer::new();
        assert!(analyzer.is_non_returning_function("exit"));
        assert!(analyzer.is_non_returning_function("abort"));
        assert!(!analyzer.is_non_returning_function("printf"));
    }

    #[test]
    fn test_identify_fixup_locations() {
        let mut analyzer = CallFixupAnalyzer::new();
        analyzer.register_fixup(CallFixupDefinition::new(
            "memcpy_fixup",
            "pcode...",
            "memcpy",
        ));

        let call_targets = vec![
            (Address::new(0x1000), "memcpy".into()),
            (Address::new(0x2000), "printf".into()),
            (Address::new(0x3000), "exit".into()),
        ];

        let locations = analyzer.identify_fixup_locations(&call_targets);
        assert_eq!(locations.len(), 2); // memcpy + exit
        assert!(locations[0].fixup_name.is_some());
        assert!(locations[1].is_non_returning);
    }

    #[test]
    fn test_protected_locations() {
        let mut analyzer = CallFixupAnalyzer::new();
        analyzer.add_protected_location(Address::new(0x1000));
        assert!(analyzer.is_protected(Address::new(0x1000)));
        assert!(!analyzer.is_protected(Address::new(0x2000)));
    }

    #[test]
    fn test_repair_damage() {
        let mut analyzer = CallFixupAnalyzer::new();
        analyzer.add_protected_location(Address::new(0x1000));
        let locations = vec![
            CallFixupLocation {
                call_address: Address::new(0x1000),
                callee_address: Address::new(0x5000),
                fixup_name: Some("memcpy_fixup".into()),
                is_non_returning: false,
            },
            CallFixupLocation {
                call_address: Address::new(0x2000),
                callee_address: Address::new(0x6000),
                fixup_name: None,
                is_non_returning: true,
            },
        ];
        let result = analyzer.repair_damage(&locations);
        assert!(result.has_repairs());
        // 0x1000 is protected, so NOT in modified_call_sites; 0x2000 is not protected
        assert_eq!(result.modified_call_sites.len(), 1);
        assert_eq!(result.modified_call_sites[0], Address::new(0x2000));
        assert_eq!(result.repaired_functions.len(), 1);
    }

    #[test]
    fn test_pending_functions() {
        let mut analyzer = CallFixupAnalyzer::new();
        analyzer.add_pending_function(Address::new(0x1000));
        analyzer.add_pending_function(Address::new(0x2000));
        assert_eq!(analyzer.pending_functions().len(), 2);
        analyzer.clear();
        assert!(analyzer.pending_functions().is_empty());
    }

    #[test]
    fn test_call_fixup_definition() {
        let fixup = CallFixupDefinition::new("test_fixup", "pcode...", "target");
        assert_eq!(fixup.name, "test_fixup");
        assert_eq!(fixup.pcode_snippet, "pcode...");
        assert_eq!(fixup.target_name, "target");
        assert!(fixup.is_callee_fixup);
    }
}
