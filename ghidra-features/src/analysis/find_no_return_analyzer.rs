//! Find No-Return Functions Analyzer -- evidence-based non-return detection.
//!
//! Ported from Ghidra's
//! `ghidra.app.plugin.core.analysis.FindNoReturnFunctionsAnalyzer` (923 lines).
//!
//! Unlike [`super::symbol_analyzers::NoReturnFunctionAnalyzer`] which uses
//! naming conventions, this analyzer examines control flow to discover
//! functions that do not return. It collects "evidence" -- references to
//! a function where the call site has no fall-through -- and when a
//! threshold is crossed, marks the function as non-returning.
//!
//! # Key Types
//!
//! - [`FindNoReturnFunctionsAnalyzer`] -- The analyzer plugin
//! - [`NoReturnEvidence`] -- A single piece of evidence
//! - [`EvidenceCollector`] -- Collects and thresholds evidence
//! - [`FlowRepairAction`] -- Repairs flow after a non-returning call

use std::collections::{HashMap, HashSet};

use ghidra_core::Address;

/// Default evidence threshold before marking a function as non-returning.
pub const DEFAULT_EVIDENCE_THRESHOLD: usize = 3;

/// Name of this analyzer.
pub const ANALYZER_NAME: &str = "Non-Returning Functions - Discovered";

/// Description of this analyzer.
pub const ANALYZER_DESCRIPTION: &str =
    "As code is disassembled, discovers indications that functions do not return. \
     When a threshold of evidence is crossed, functions are marked non-returning.";

// ---------------------------------------------------------------------------
// NoReturnEvidence -- a single piece of evidence
// ---------------------------------------------------------------------------

/// A single piece of evidence that a function does not return.
///
/// Ported from the `NoReturnLocations` inner class and evidence
/// collection logic in `FindNoReturnFunctionsAnalyzer`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NoReturnEvidence {
    /// Address of the call/jump to the suspect function.
    pub call_site: Address,
    /// Address of the suspect function (entry point).
    pub target_function: Address,
    /// The type of evidence.
    pub evidence_type: EvidenceType,
}

/// The type of evidence suggesting a function does not return.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceType {
    /// A call instruction where the fall-through is not reachable.
    CallNoFallThrough,
    /// A jump to a non-returning function.
    JumpToNonReturning,
    /// The function body ends with an unconditional branch.
    UnconditionalBranch,
    /// A CALL-RETURN pattern was detected.
    CallReturnPattern,
    /// The function was explicitly marked non-returning by name (e.g., `exit`).
    NameBased,
}

impl EvidenceType {
    /// Human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::CallNoFallThrough => "Call site has no fall-through path",
            Self::JumpToNonReturning => "Jump to known non-returning function",
            Self::UnconditionalBranch => "Function ends with unconditional branch",
            Self::CallReturnPattern => "CALL_RETURN pattern detected",
            Self::NameBased => "Function name matches non-returning pattern",
        }
    }

    /// Weight of this evidence type (higher = more convincing).
    pub fn weight(&self) -> usize {
        match self {
            Self::CallNoFallThrough => 2,
            Self::JumpToNonReturning => 3,
            Self::UnconditionalBranch => 1,
            Self::CallReturnPattern => 2,
            Self::NameBased => 3,
        }
    }
}

// ---------------------------------------------------------------------------
// EvidenceCollector -- tracks evidence per function
// ---------------------------------------------------------------------------

/// Collects evidence for non-returning functions and determines when
/// the evidence threshold is crossed.
///
/// Ported from the evidence accumulation logic in
/// `FindNoReturnFunctionsAnalyzer`.
#[derive(Debug)]
pub struct EvidenceCollector {
    /// Evidence per function address.
    evidence: HashMap<u64, Vec<NoReturnEvidence>>,
    /// Functions already confirmed as non-returning.
    confirmed: HashSet<u64>,
    /// Evidence threshold.
    threshold: usize,
    /// Whether to use weighted evidence.
    use_weighted: bool,
}

impl EvidenceCollector {
    /// Create a new evidence collector with the default threshold.
    pub fn new() -> Self {
        Self {
            evidence: HashMap::new(),
            confirmed: HashSet::new(),
            threshold: DEFAULT_EVIDENCE_THRESHOLD,
            use_weighted: false,
        }
    }

    /// Create with a custom threshold.
    pub fn with_threshold(threshold: usize) -> Self {
        Self {
            threshold,
            ..Self::new()
        }
    }

    /// Enable weighted evidence scoring.
    pub fn with_weighted(mut self) -> Self {
        self.use_weighted = true;
        self
    }

    /// Add a piece of evidence.
    ///
    /// Returns `true` if the function is newly confirmed as non-returning.
    pub fn add_evidence(&mut self, evidence: NoReturnEvidence) -> bool {
        let func_addr = evidence.target_function.offset;

        // Skip if already confirmed
        if self.confirmed.contains(&func_addr) {
            return false;
        }

        let was_below = self.score(func_addr) < self.threshold;

        self.evidence
            .entry(func_addr)
            .or_default()
            .push(evidence);

        let now_above = self.score(func_addr) >= self.threshold;

        if was_below && now_above {
            self.confirmed.insert(func_addr);
            true
        } else {
            false
        }
    }

    /// Get the evidence score for a function.
    pub fn score(&self, func_addr: u64) -> usize {
        match self.evidence.get(&func_addr) {
            Some(items) => {
                if self.use_weighted {
                    items.iter().map(|e| e.evidence_type.weight()).sum()
                } else {
                    items.len()
                }
            }
            None => 0,
        }
    }

    /// Check if a function is confirmed non-returning.
    pub fn is_confirmed(&self, func_addr: u64) -> bool {
        self.confirmed.contains(&func_addr)
    }

    /// Get all evidence for a function.
    pub fn get_evidence(&self, func_addr: u64) -> Option<&Vec<NoReturnEvidence>> {
        self.evidence.get(&func_addr)
    }

    /// Get all confirmed non-returning functions.
    pub fn confirmed_functions(&self) -> &HashSet<u64> {
        &self.confirmed
    }

    /// Get the total number of evidence items across all functions.
    pub fn total_evidence_count(&self) -> usize {
        self.evidence.values().map(|v| v.len()).sum()
    }

    /// Get the number of confirmed non-returning functions.
    pub fn confirmed_count(&self) -> usize {
        self.confirmed.len()
    }

    /// Reset all evidence.
    pub fn clear(&mut self) {
        self.evidence.clear();
        self.confirmed.clear();
    }

    /// Get the threshold.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Set the threshold.
    pub fn set_threshold(&mut self, threshold: usize) {
        self.threshold = threshold;
    }
}

impl Default for EvidenceCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FindNoReturnFunctionsAnalyzer -- the analyzer itself
// ---------------------------------------------------------------------------

/// Evidence-based non-returning function analyzer.
///
/// Ported from `ghidra.app.plugin.core.analysis.FindNoReturnFunctionsAnalyzer`.
///
/// Examines control flow at call sites to discover functions that never
/// return. When evidence accumulates above a threshold, functions are
/// marked as non-returning and the flow after the call is repaired.
#[derive(Debug)]
pub struct FindNoReturnFunctionsAnalyzer {
    /// Evidence collector.
    collector: EvidenceCollector,
    /// Whether to repair flow after non-returning calls.
    repair_damage: bool,
    /// Whether to create bookmarks.
    create_bookmarks: bool,
    /// Whether the analyzer is enabled.
    enabled: bool,
    /// Known non-returning function names.
    known_non_returning: HashSet<String>,
    /// Bookmarks created during analysis.
    bookmarks: Vec<Bookmark>,
}

/// A bookmark created by the analyzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bookmark {
    /// The address of the bookmark.
    pub address: Address,
    /// The bookmark text.
    pub text: String,
    /// The category.
    pub category: String,
}

impl FindNoReturnFunctionsAnalyzer {
    /// Create a new analyzer with default settings.
    pub fn new() -> Self {
        let mut known = HashSet::new();
        // Standard non-returning function names (C/C++/POSIX)
        for name in &[
            "exit", "_exit", "abort", "__assert_fail", "__stack_chk_fail",
            "ExitProcess", "ExitThread", "TerminateProcess", "TerminateThread",
            "longjmp", "_longjmp", "siglongjmp", "pthread_exit",
            "die", "panic", "unreachable",
        ] {
            known.insert(name.to_string());
        }

        Self {
            collector: EvidenceCollector::new(),
            repair_damage: true,
            create_bookmarks: true,
            enabled: true,
            known_non_returning: known,
            bookmarks: Vec::new(),
        }
    }

    /// Set the evidence threshold.
    pub fn set_threshold(&mut self, threshold: usize) {
        self.collector.set_threshold(threshold);
    }

    /// Get the evidence threshold.
    pub fn threshold(&self) -> usize {
        self.collector.threshold()
    }

    /// Enable or disable flow repair.
    pub fn set_repair_damage(&mut self, enabled: bool) {
        self.repair_damage = enabled;
    }

    /// Whether flow repair is enabled.
    pub fn is_repair_damage_enabled(&self) -> bool {
        self.repair_damage
    }

    /// Enable or disable bookmark creation.
    pub fn set_create_bookmarks(&mut self, enabled: bool) {
        self.create_bookmarks = enabled;
    }

    /// Whether bookmark creation is enabled.
    pub fn is_create_bookmarks_enabled(&self) -> bool {
        self.create_bookmarks
    }

    /// Enable or disable the analyzer.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether the analyzer is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Add a known non-returning function name.
    pub fn add_known_non_returning(&mut self, name: impl Into<String>) {
        self.known_non_returning.insert(name.into());
    }

    /// Check if a function name is a known non-returning function.
    pub fn is_known_non_returning(&self, name: &str) -> bool {
        self.known_non_returning.contains(name)
    }

    /// Get the evidence collector.
    pub fn collector(&self) -> &EvidenceCollector {
        &self.collector
    }

    /// Get a mutable reference to the evidence collector.
    pub fn collector_mut(&mut self) -> &mut EvidenceCollector {
        &mut self.collector
    }

    /// Process a call site and collect evidence if the call
    /// appears to be non-returning.
    ///
    /// Returns `true` if the target function was newly confirmed.
    pub fn process_call_site(
        &mut self,
        call_site: Address,
        target_function: Address,
        has_fall_through: bool,
    ) -> bool {
        if !self.enabled {
            return false;
        }

        let evidence = if !has_fall_through {
            NoReturnEvidence {
                call_site,
                target_function,
                evidence_type: EvidenceType::CallNoFallThrough,
            }
        } else {
            return false;
        };

        let newly_confirmed = self.collector.add_evidence(evidence);

        if newly_confirmed && self.create_bookmarks {
            self.bookmarks.push(Bookmark {
                address: target_function,
                text: format!(
                    "Non-returning function discovered (threshold: {})",
                    self.collector.threshold()
                ),
                category: "Analysis".into(),
            });
        }

        newly_confirmed
    }

    /// Process a function name and add name-based evidence.
    pub fn process_function_name(
        &mut self,
        func_name: &str,
        func_address: Address,
    ) -> bool {
        if !self.enabled {
            return false;
        }

        if !self.is_known_non_returning(func_name) {
            return false;
        }

        let evidence = NoReturnEvidence {
            call_site: func_address,
            target_function: func_address,
            evidence_type: EvidenceType::NameBased,
        };

        let newly_confirmed = self.collector.add_evidence(evidence);

        if newly_confirmed && self.create_bookmarks {
            self.bookmarks.push(Bookmark {
                address: func_address,
                text: format!("Non-returning function: {}", func_name),
                category: "Analysis".into(),
            });
        }

        newly_confirmed
    }

    /// Get bookmarks created during analysis.
    pub fn bookmarks(&self) -> &[Bookmark] {
        &self.bookmarks
    }

    /// Clear all collected data.
    pub fn reset(&mut self) {
        self.collector.clear();
        self.bookmarks.clear();
    }

    /// Get the list of all known non-returning function names.
    pub fn known_non_returning_names(&self) -> &HashSet<String> {
        &self.known_non_returning
    }
}

impl Default for FindNoReturnFunctionsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FlowRepairAction -- repairs flow after a non-returning call
// ---------------------------------------------------------------------------

/// Represents the repair action needed after a non-returning function
/// is discovered.
///
/// Ported from `ClearFlowAndRepairCmd` usage in `FindNoReturnFunctionsAnalyzer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRepairAction {
    /// The address of the call instruction.
    pub call_site: Address,
    /// The fall-through address to clear.
    pub fall_through: Address,
    /// Whether to remove the fall-through code.
    pub remove_fall_through: bool,
}

impl FlowRepairAction {
    /// Create a new flow repair action.
    pub fn new(call_site: Address, fall_through: Address) -> Self {
        Self {
            call_site,
            fall_through,
            remove_fall_through: true,
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_type_weight() {
        assert_eq!(EvidenceType::CallNoFallThrough.weight(), 2);
        assert_eq!(EvidenceType::JumpToNonReturning.weight(), 3);
        assert_eq!(EvidenceType::UnconditionalBranch.weight(), 1);
        assert_eq!(EvidenceType::NameBased.weight(), 3);
    }

    #[test]
    fn test_evidence_collector_basic() {
        let mut collector = EvidenceCollector::new();
        let addr = Address::new(0x401000);

        // Below threshold
        collector.add_evidence(NoReturnEvidence {
            call_site: Address::new(0x1000),
            target_function: addr,
            evidence_type: EvidenceType::CallNoFallThrough,
        });
        assert!(!collector.is_confirmed(addr.offset));
        assert_eq!(collector.score(addr.offset), 1);

        // Still below
        collector.add_evidence(NoReturnEvidence {
            call_site: Address::new(0x2000),
            target_function: addr,
            evidence_type: EvidenceType::CallNoFallThrough,
        });
        assert!(!collector.is_confirmed(addr.offset));
        assert_eq!(collector.score(addr.offset), 2);

        // At threshold
        collector.add_evidence(NoReturnEvidence {
            call_site: Address::new(0x3000),
            target_function: addr,
            evidence_type: EvidenceType::CallNoFallThrough,
        });
        assert!(collector.is_confirmed(addr.offset));
        assert_eq!(collector.score(addr.offset), 3);
        assert_eq!(collector.confirmed_count(), 1);
    }

    #[test]
    fn test_evidence_collector_weighted() {
        let mut collector = EvidenceCollector::with_threshold(6).with_weighted();
        let addr = Address::new(0x401000);

        // Add one JumpToNonReturning (weight=3) and one CallNoFallThrough (weight=2)
        collector.add_evidence(NoReturnEvidence {
            call_site: Address::new(0x1000),
            target_function: addr,
            evidence_type: EvidenceType::JumpToNonReturning,
        });
        assert!(!collector.is_confirmed(addr.offset));

        collector.add_evidence(NoReturnEvidence {
            call_site: Address::new(0x2000),
            target_function: addr,
            evidence_type: EvidenceType::CallNoFallThrough,
        });
        assert!(!collector.is_confirmed(addr.offset)); // score=5 < 6

        collector.add_evidence(NoReturnEvidence {
            call_site: Address::new(0x3000),
            target_function: addr,
            evidence_type: EvidenceType::UnconditionalBranch,
        });
        assert!(collector.is_confirmed(addr.offset)); // score=6 >= 6
    }

    #[test]
    fn test_evidence_collector_custom_threshold() {
        let mut collector = EvidenceCollector::with_threshold(1);
        let addr = Address::new(0x401000);

        let newly_confirmed = collector.add_evidence(NoReturnEvidence {
            call_site: Address::new(0x1000),
            target_function: addr,
            evidence_type: EvidenceType::NameBased,
        });
        assert!(newly_confirmed);
        assert!(collector.is_confirmed(addr.offset));

        // Adding more evidence should not report newly confirmed again
        let again = collector.add_evidence(NoReturnEvidence {
            call_site: Address::new(0x2000),
            target_function: addr,
            evidence_type: EvidenceType::CallNoFallThrough,
        });
        assert!(!again);
    }

    #[test]
    fn test_evidence_collector_get_evidence() {
        let mut collector = EvidenceCollector::new();
        let addr = Address::new(0x401000);

        assert!(collector.get_evidence(addr.offset).is_none());

        collector.add_evidence(NoReturnEvidence {
            call_site: Address::new(0x1000),
            target_function: addr,
            evidence_type: EvidenceType::CallNoFallThrough,
        });

        let ev = collector.get_evidence(addr.offset);
        assert!(ev.is_some());
        assert_eq!(ev.unwrap().len(), 1);
    }

    #[test]
    fn test_evidence_collector_total_count() {
        let mut collector = EvidenceCollector::new();
        collector.add_evidence(NoReturnEvidence {
            call_site: Address::new(0x1000),
            target_function: Address::new(0x401000),
            evidence_type: EvidenceType::CallNoFallThrough,
        });
        collector.add_evidence(NoReturnEvidence {
            call_site: Address::new(0x2000),
            target_function: Address::new(0x402000),
            evidence_type: EvidenceType::CallNoFallThrough,
        });
        assert_eq!(collector.total_evidence_count(), 2);
    }

    #[test]
    fn test_analyzer_new() {
        let analyzer = FindNoReturnFunctionsAnalyzer::new();
        assert_eq!(analyzer.threshold(), DEFAULT_EVIDENCE_THRESHOLD);
        assert!(analyzer.is_repair_damage_enabled());
        assert!(analyzer.is_create_bookmarks_enabled());
        assert!(analyzer.is_enabled());
    }

    #[test]
    fn test_analyzer_process_call_site() {
        let mut analyzer = FindNoReturnFunctionsAnalyzer::new();
        analyzer.set_threshold(2);
        let target = Address::new(0x401000);

        // First call: not confirmed
        let r1 = analyzer.process_call_site(Address::new(0x1000), target, false);
        assert!(!r1);

        // Second call: confirmed
        let r2 = analyzer.process_call_site(Address::new(0x2000), target, false);
        assert!(r2);

        // Should have created a bookmark
        assert_eq!(analyzer.bookmarks().len(), 1);
        assert!(analyzer.bookmarks()[0].text.contains("Non-returning"));
    }

    #[test]
    fn test_analyzer_process_call_with_fall_through() {
        let mut analyzer = FindNoReturnFunctionsAnalyzer::new();
        // Calls with fall-through should not produce evidence
        let r = analyzer.process_call_site(
            Address::new(0x1000),
            Address::new(0x401000),
            true, // has fall-through
        );
        assert!(!r);
        assert_eq!(analyzer.collector().total_evidence_count(), 0);
    }

    #[test]
    fn test_analyzer_known_non_returning() {
        let analyzer = FindNoReturnFunctionsAnalyzer::new();
        assert!(analyzer.is_known_non_returning("exit"));
        assert!(analyzer.is_known_non_returning("abort"));
        assert!(analyzer.is_known_non_returning("panic"));
        assert!(!analyzer.is_known_non_returning("printf"));
    }

    #[test]
    fn test_analyzer_process_function_name() {
        let mut analyzer = FindNoReturnFunctionsAnalyzer::new();
        analyzer.set_threshold(1);
        let addr = Address::new(0x401000);

        let r = analyzer.process_function_name("exit", addr);
        assert!(r);
        assert!(analyzer.collector().is_confirmed(addr.offset));
        assert_eq!(analyzer.bookmarks().len(), 1);
    }

    #[test]
    fn test_analyzer_process_unknown_function_name() {
        let mut analyzer = FindNoReturnFunctionsAnalyzer::new();
        let r = analyzer.process_function_name("printf", Address::new(0x401000));
        assert!(!r);
    }

    #[test]
    fn test_analyzer_disabled() {
        let mut analyzer = FindNoReturnFunctionsAnalyzer::new();
        analyzer.set_enabled(false);

        let r = analyzer.process_call_site(
            Address::new(0x1000),
            Address::new(0x401000),
            false,
        );
        assert!(!r);

        let r = analyzer.process_function_name("exit", Address::new(0x401000));
        assert!(!r);
    }

    #[test]
    fn test_analyzer_no_bookmarks() {
        let mut analyzer = FindNoReturnFunctionsAnalyzer::new();
        analyzer.set_create_bookmarks(false);
        analyzer.set_threshold(1);

        analyzer.process_call_site(Address::new(0x1000), Address::new(0x401000), false);
        assert!(analyzer.bookmarks().is_empty());
    }

    #[test]
    fn test_analyzer_reset() {
        let mut analyzer = FindNoReturnFunctionsAnalyzer::new();
        analyzer.set_threshold(1);
        analyzer.process_call_site(Address::new(0x1000), Address::new(0x401000), false);
        assert_eq!(analyzer.bookmarks().len(), 1);
        assert_eq!(analyzer.collector().confirmed_count(), 1);

        analyzer.reset();
        assert!(analyzer.bookmarks().is_empty());
        assert_eq!(analyzer.collector().confirmed_count(), 0);
    }

    #[test]
    fn test_analyzer_add_custom_known_non_returning() {
        let mut analyzer = FindNoReturnFunctionsAnalyzer::new();
        assert!(!analyzer.is_known_non_returning("my_die"));
        analyzer.add_known_non_returning("my_die");
        assert!(analyzer.is_known_non_returning("my_die"));
    }

    #[test]
    fn test_flow_repair_action() {
        let action = FlowRepairAction::new(Address::new(0x1000), Address::new(0x1005));
        assert_eq!(action.call_site, Address::new(0x1000));
        assert_eq!(action.fall_through, Address::new(0x1005));
        assert!(action.remove_fall_through);
    }

    #[test]
    fn test_analyzer_multiple_functions() {
        let mut analyzer = FindNoReturnFunctionsAnalyzer::new();
        analyzer.set_threshold(2);

        let func_a = Address::new(0x401000);
        let func_b = Address::new(0x402000);

        // Function A: 2 evidence items -> confirmed
        analyzer.process_call_site(Address::new(0x1000), func_a, false);
        analyzer.process_call_site(Address::new(0x2000), func_a, false);

        // Function B: 1 evidence item -> not confirmed
        analyzer.process_call_site(Address::new(0x3000), func_b, false);

        assert!(analyzer.collector().is_confirmed(func_a.offset));
        assert!(!analyzer.collector().is_confirmed(func_b.offset));
        assert_eq!(analyzer.collector().confirmed_count(), 1);
    }

    #[test]
    fn test_analyzer_confirmed_functions_set() {
        let mut analyzer = FindNoReturnFunctionsAnalyzer::new();
        analyzer.set_threshold(1);
        analyzer.process_call_site(Address::new(0x1000), Address::new(0x401000), false);

        let confirmed = analyzer.collector().confirmed_functions();
        assert!(confirmed.contains(&0x401000));
    }

    #[test]
    fn test_evidence_type_description() {
        assert!(!EvidenceType::CallNoFallThrough.description().is_empty());
        assert!(!EvidenceType::JumpToNonReturning.description().is_empty());
        assert!(!EvidenceType::UnconditionalBranch.description().is_empty());
        assert!(!EvidenceType::NameBased.description().is_empty());
    }
}
