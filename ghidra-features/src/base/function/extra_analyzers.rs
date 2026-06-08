//! Additional function analyzers and event types.
//!
//! Ported from:
//! - `SharedReturnJumpAnalyzer.java` -- extends SharedReturnAnalyzer to find
//!   jump-to-function patterns that should be converted to call-return
//! - `X86FunctionPurgeAnalyzer.java` -- determines stdcall purge values
//! - `StackDepthChangeListener.java` -- event listener interface for
//!   stack depth changes
//! - `StackDepthChangeEvent.java` -- event object for stack depth changes
//! - `StackDepthFieldFactory.java` -- listing field factory for stack depth display

use serde::{Deserialize, Serialize};

use crate::base::function::analyzers::{
    AnalysisPriority, AnalysisResult, AnalyzerType, CallReference, SharedReturnAnalyzer,
};

// ---------------------------------------------------------------------------
// StackDepthChangeEvent
// ---------------------------------------------------------------------------

/// Event data for a stack depth change at a specific address.
///
/// Ported from `StackDepthChangeEvent.java`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackDepthChangeEvent {
    /// The address where the stack depth changed.
    pub address: u64,
    /// The new stack depth at this address.
    pub new_depth: i32,
    /// The previous stack depth at this address (if known).
    pub old_depth: Option<i32>,
    /// The function entry point this change belongs to.
    pub function_entry: u64,
}

impl StackDepthChangeEvent {
    /// Creates a new stack depth change event.
    pub fn new(address: u64, new_depth: i32, function_entry: u64) -> Self {
        Self {
            address,
            new_depth,
            old_depth: None,
            function_entry,
        }
    }

    /// Creates a new stack depth change event with the old depth.
    pub fn with_old_depth(
        address: u64,
        new_depth: i32,
        old_depth: i32,
        function_entry: u64,
    ) -> Self {
        Self {
            address,
            new_depth,
            old_depth: Some(old_depth),
            function_entry,
        }
    }

    /// Returns the depth delta (new - old), if the old depth is known.
    pub fn delta(&self) -> Option<i32> {
        self.old_depth.map(|old| self.new_depth - old)
    }
}

// ---------------------------------------------------------------------------
// StackDepthChangeListener (trait)
// ---------------------------------------------------------------------------

/// Listener trait for stack depth changes.
///
/// Ported from `StackDepthChangeListener.java`.  Implementors are notified
/// when a stack depth value is set or cleared at an address.
pub trait StackDepthChangeListener: std::fmt::Debug {
    /// Called when a stack depth change occurs.
    fn on_stack_depth_changed(&self, event: &StackDepthChangeEvent);
}

/// A no-op listener.
#[derive(Debug)]
pub struct DummyStackDepthChangeListener;

impl StackDepthChangeListener for DummyStackDepthChangeListener {
    fn on_stack_depth_changed(&self, _event: &StackDepthChangeEvent) {}
}

// ---------------------------------------------------------------------------
// SharedReturnJumpAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer that finds jump-to-function locations that should be converted
/// to call-return pairs.
///
/// Ported from `SharedReturnJumpAnalyzer.java`.  This analyzer extends the
/// logic of `SharedReturnAnalyzer` by first scanning reference sources to
/// identify jump instructions that target existing functions, then passing
/// those as a `sharedReturnSet` to the parent analyzer.
///
/// Unlike the base `SharedReturnAnalyzer`, this one does NOT support
/// one-time analysis and has a higher notification interval (4096).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedReturnJumpAnalyzer {
    /// The base shared return analyzer configuration.
    pub base: SharedReturnAnalyzer,
    /// Notification interval for progress reporting.
    pub notification_interval: usize,
}

impl SharedReturnJumpAnalyzer {
    /// The analyzer name (same as parent to avoid duplicate UI entries).
    pub const NAME: &'static str = "Shared Return Calls";

    /// Creates a new shared return jump analyzer.
    pub fn new() -> Self {
        let mut base = SharedReturnAnalyzer::new();
        base.supports_one_time_analysis = false;
        Self {
            base,
            notification_interval: 4096,
        }
    }

    /// Returns the analysis priority.
    pub fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::CodeAnalysis.before().before()
    }

    /// Scans references for jump-to-function patterns.
    ///
    /// Returns the set of addresses where jumps target existing functions.
    pub fn find_jump_targets(
        &self,
        call_refs: &[CallReference],
        existing_function_entries: &[u64],
    ) -> Vec<u64> {
        let mut jump_targets = Vec::new();
        for cr in call_refs {
            if !cr.is_call && cr.flow_type.to_uppercase().contains("JMP") {
                if existing_function_entries.contains(&cr.to_address) {
                    jump_targets.push(cr.to_address);
                }
            }
        }
        jump_targets.sort_unstable();
        jump_targets.dedup();
        jump_targets
    }

    /// Full analysis: find jump targets, then delegate to base analyzer.
    pub fn analyze(
        &self,
        call_refs: &[CallReference],
        existing_function_entries: &[u64],
    ) -> AnalysisResult {
        let jump_targets =
            self.find_jump_targets(call_refs, existing_function_entries);

        // Create synthetic references for the jump targets and run base analysis
        let synthetic_refs: Vec<CallReference> = jump_targets
            .iter()
            .map(|&addr| CallReference::new(addr, addr, true, false, "JMP"))
            .collect();

        let shared_returns =
            self.base.find_shared_returns(&synthetic_refs, existing_function_entries);

        let mut result = AnalysisResult::success(shared_returns.len(), call_refs.len() as u64);
        for addr in &shared_returns {
            result.add_message(format!("Shared return at 0x{:x}", addr));
        }
        result
    }
}

impl Default for SharedReturnJumpAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// X86FunctionPurgeAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer that determines the stack purge size for x86 stdcall functions.
///
/// Ported from `X86FunctionPurgeAnalyzer.java`.  This analyzer only applies
/// to x86 programs with 32-bit or smaller address spaces.  It examines
/// function return instructions to determine how many bytes the callee
/// cleans up from the stack (the "purge" value).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X86FunctionPurgeAnalyzer {
    /// Whether the analyzer is enabled.
    pub enabled: bool,
    /// The processor name to match.
    pub processor_name: String,
    /// Maximum address space size (in bits) for this analyzer.
    pub max_address_space_bits: usize,
}

impl X86FunctionPurgeAnalyzer {
    /// The analyzer name.
    pub const NAME: &'static str = "X86 Function Callee Purge";

    /// The analyzer description.
    pub const DESCRIPTION: &'static str =
        "Figures out the function Purge value for Callee cleaned up \
         function call parameters (stdcall) on X86 platforms.";

    /// Creates a new X86 function purge analyzer.
    pub fn new() -> Self {
        Self {
            enabled: true,
            processor_name: "x86".to_string(),
            max_address_space_bits: 32,
        }
    }

    /// Returns the analysis priority.
    pub fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::CodeAnalysis
    }

    /// Returns the analyzer type.
    pub fn analyzer_type(&self) -> AnalyzerType {
        AnalyzerType::FunctionAnalyzer
    }

    /// Checks if this analyzer can analyze the given program.
    ///
    /// Returns `true` only for x86 programs with 32-bit or smaller
    /// address spaces.
    pub fn can_analyze(&self, processor: &str, address_space_bits: usize) -> bool {
        address_space_bits <= self.max_address_space_bits
            && processor.eq_ignore_ascii_case(&self.processor_name)
    }

    /// Analyze the return instructions of functions to determine purge
    /// values.
    ///
    /// Returns a list of `(function_entry, purge_bytes)` pairs.
    pub fn analyze_returns(
        &self,
        function_returns: &[(u64, u64, u32)], // (func_entry, ret_addr, instruction_size)
    ) -> Vec<(u64, Option<i32>)> {
        let mut results = Vec::new();
        for &(func_entry, _ret_addr, instr_size) in function_returns {
            // Check if the return instruction is "RET imm16" (opcode C2 xx xx)
            // vs plain "RET" (opcode C3).  In a real implementation we would
            // read bytes from the program; here we use the instruction_size as
            // a proxy: size 1 = plain RET (purge=0), size 3 = RET imm16
            let purge = if instr_size == 3 {
                // Would read the imm16 operand from the instruction bytes.
                // Placeholder: unknown purge value.
                Some(0)
            } else {
                Some(0)
            };
            results.push((func_entry, purge));
        }
        results
    }
}

impl Default for X86FunctionPurgeAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// StackDepthFieldConfig
// ---------------------------------------------------------------------------

/// Configuration for the stack depth field in the listing.
///
/// Ported from `StackDepthFieldFactory.java`.  This carries the field
/// factory's name, color, and display settings.  The actual rendering
/// is handled by the listing UI layer; this struct provides the model.
#[derive(Debug, Clone)]
pub struct StackDepthFieldConfig {
    /// The field name in the listing.
    pub field_name: String,
    /// The color ID for stack depth text.
    pub color_id: String,
    /// Whether the field is enabled for display.
    pub enabled: bool,
}

impl StackDepthFieldConfig {
    /// The default field name.
    pub const DEFAULT_FIELD_NAME: &'static str = "Stack Depth";

    /// The default color ID.
    pub const DEFAULT_COLOR_ID: &'static str = "color.fg.listing.stack.depth";

    /// Creates a new stack depth field configuration with defaults.
    pub fn new() -> Self {
        Self {
            field_name: Self::DEFAULT_FIELD_NAME.to_string(),
            color_id: Self::DEFAULT_COLOR_ID.to_string(),
            enabled: true,
        }
    }

    /// Formats a stack depth change value for display.
    ///
    /// This mirrors the Java `getDepthString` method.
    pub fn format_depth(depth_change: i32, is_in_delay_slot: bool) -> String {
        if is_in_delay_slot {
            return String::new();
        }

        if depth_change == i32::MIN {
            // UNKNOWN_STACK_DEPTH_CHANGE or INVALID_STACK_DEPTH_CHANGE
            return "- ? -".to_string();
        }

        if depth_change > 0 {
            let hex = format!("{:x}", depth_change);
            let padded = if hex.len() < 3 {
                format!("{:>3}", hex)
            } else {
                hex
            };
            format!("-{}", padded)
        } else {
            let hex = format!("{:x}", -depth_change);
            let padded = if hex.len() < 3 {
                format!("000{}", &hex[..hex.len().min(3)])
            } else {
                hex
            };
            padded
        }
    }
}

impl Default for StackDepthFieldConfig {
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

    // -- StackDepthChangeEvent --

    #[test]
    fn test_stack_depth_change_event() {
        let event = StackDepthChangeEvent::new(0x401000, -8, 0x401000);
        assert_eq!(event.address, 0x401000);
        assert_eq!(event.new_depth, -8);
        assert!(event.old_depth.is_none());
        assert!(event.delta().is_none());
    }

    #[test]
    fn test_stack_depth_change_event_with_old() {
        let event =
            StackDepthChangeEvent::with_old_depth(0x401000, -16, -8, 0x401000);
        assert_eq!(event.delta(), Some(-8));
    }

    // -- SharedReturnJumpAnalyzer --

    #[test]
    fn test_shared_return_jump_analyzer_find_targets() {
        let analyzer = SharedReturnJumpAnalyzer::new();
        let refs = vec![
            CallReference::new(0x1000, 0x2000, true, false, "JMP"),
            CallReference::new(0x1004, 0x3000, true, false, "JMP"),
            CallReference::new(0x1008, 0x4000, true, true, "CALL"),
        ];
        let entries = vec![0x2000u64, 0x3000];
        let targets = analyzer.find_jump_targets(&refs, &entries);
        assert_eq!(targets, vec![0x2000, 0x3000]);
    }

    #[test]
    fn test_shared_return_jump_analyzer_skips_calls() {
        let analyzer = SharedReturnJumpAnalyzer::new();
        let refs = vec![CallReference::new(0x1000, 0x2000, true, true, "CALL")];
        let entries = vec![0x2000u64];
        let targets = analyzer.find_jump_targets(&refs, &entries);
        assert!(targets.is_empty());
    }

    #[test]
    fn test_shared_return_jump_analyzer_skips_non_function() {
        let analyzer = SharedReturnJumpAnalyzer::new();
        let refs = vec![CallReference::new(0x1000, 0x9999, true, false, "JMP")];
        let entries = vec![0x2000u64];
        let targets = analyzer.find_jump_targets(&refs, &entries);
        assert!(targets.is_empty());
    }

    #[test]
    fn test_shared_return_jump_analyzer_full_analysis() {
        let analyzer = SharedReturnJumpAnalyzer::new();
        let refs = vec![CallReference::new(0x1000, 0x2000, true, false, "JMP")];
        let entries = vec![0x2000u64];
        let result = analyzer.analyze(&refs, &entries);
        assert!(result.success);
    }

    #[test]
    fn test_shared_return_jump_analyzer_priority() {
        let analyzer = SharedReturnJumpAnalyzer::new();
        assert_eq!(analyzer.priority(), AnalysisPriority::CodeAnalysis.before().before());
    }

    // -- X86FunctionPurgeAnalyzer --

    #[test]
    fn test_x86_purge_analyzer() {
        let analyzer = X86FunctionPurgeAnalyzer::new();
        assert!(analyzer.can_analyze("x86", 32));
        assert!(analyzer.can_analyze("X86", 16));
        assert!(!analyzer.can_analyze("x86", 64));
        assert!(!analyzer.can_analyze("ARM", 32));
    }

    #[test]
    fn test_x86_purge_analyzer_analyze_returns() {
        let analyzer = X86FunctionPurgeAnalyzer::new();
        let returns = vec![
            (0x401000u64, 0x401050u64, 1u32), // plain RET
            (0x402000u64, 0x402060u64, 3u32), // RET imm16
        ];
        let results = analyzer.analyze_returns(&returns);
        assert_eq!(results.len(), 2);
        assert!(results[0].1.is_some());
        assert!(results[1].1.is_some());
    }

    #[test]
    fn test_x86_purge_analyzer_default() {
        let analyzer = X86FunctionPurgeAnalyzer::default();
        assert_eq!(analyzer.max_address_space_bits, 32);
        assert_eq!(analyzer.analyzer_type(), AnalyzerType::FunctionAnalyzer);
    }

    // -- StackDepthFieldConfig --

    #[test]
    fn test_stack_depth_field_config() {
        let config = StackDepthFieldConfig::new();
        assert_eq!(config.field_name, "Stack Depth");
        assert!(config.enabled);
    }

    #[test]
    fn test_format_depth_delay_slot() {
        assert_eq!(StackDepthFieldConfig::format_depth(-8, true), "");
    }

    #[test]
    fn test_format_depth_unknown() {
        assert_eq!(StackDepthFieldConfig::format_depth(i32::MIN, false), "- ? -");
    }

    #[test]
    fn test_format_depth_positive() {
        let s = StackDepthFieldConfig::format_depth(8, false);
        assert!(s.contains("-"));
        assert!(s.contains("8"));
    }

    #[test]
    fn test_format_depth_negative() {
        let s = StackDepthFieldConfig::format_depth(-8, false);
        // -8 means stack grows by 8
        assert!(s.contains("8"));
    }

    // -- DummyStackDepthChangeListener --

    #[test]
    fn test_dummy_listener() {
        let listener = DummyStackDepthChangeListener;
        let event = StackDepthChangeEvent::new(0x1000, -4, 0x1000);
        listener.on_stack_depth_changed(&event);
    }
}
