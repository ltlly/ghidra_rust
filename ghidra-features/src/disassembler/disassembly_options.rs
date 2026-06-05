//! Disassembly options and configuration.
//!
//! Ported from disassembly-related configuration classes in
//! `ghidra.app.plugin.core.disassembler`.
//!
//! Provides options for controlling how disassembly is performed,
//! including flow control, depth limits, and override settings.

use serde::{Deserialize, Serialize};

/// Flow override settings for disassembly.
///
/// Ported from `ghidra.app.plugin.core.disassembler.FlowOverride`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FlowOverride {
    /// No override -- use the processor's default flow behavior.
    None,
    /// Override to call (the instruction should be treated as a call).
    Call,
    /// Override to call-return (call and return).
    CallReturn,
    /// Override to jump (the instruction should be treated as a jump).
    Jump,
    /// Override to return (the instruction should be treated as a return).
    Return,
}

impl FlowOverride {
    /// Get the display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::None => "No Override",
            Self::Call => "Call",
            Self::CallReturn => "Call/Return",
            Self::Jump => "Jump",
            Self::Return => "Return",
        }
    }

    /// Whether this override changes control flow.
    pub fn changes_flow(&self) -> bool {
        *self != Self::None
    }
}

/// Disassembly options for controlling behavior.
///
/// Ported from the disassembly dialog options in Ghidra's disassembler plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyOptions {
    /// Whether to follow flow during disassembly.
    pub follow_flow: bool,
    /// Whether to disassemble into existing code.
    pub disassemble_into_existing: bool,
    /// Whether to disassemble dead code (unreachable).
    pub allow_dead_code: bool,
    /// Whether to treat unknown bytes as data (vs skipping).
    pub treat_unknown_as_data: bool,
    /// Maximum depth for following call targets.
    pub max_call_depth: u32,
    /// Maximum number of instructions to disassemble.
    pub max_instructions: usize,
    /// Flow override to apply.
    pub flow_override: FlowOverride,
    /// Whether to apply the override to the entry point.
    pub apply_override_at_entry: bool,
    /// Processor-specific options.
    pub processor_options: std::collections::HashMap<String, String>,
}

impl DisassemblyOptions {
    /// Create default disassembly options.
    pub fn new() -> Self {
        Self {
            follow_flow: true,
            disassemble_into_existing: false,
            allow_dead_code: false,
            treat_unknown_as_data: false,
            max_call_depth: 10,
            max_instructions: 100000,
            flow_override: FlowOverride::None,
            apply_override_at_entry: false,
            processor_options: std::collections::HashMap::new(),
        }
    }

    /// Set a processor-specific option.
    pub fn set_processor_option(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.processor_options.insert(key.into(), value.into());
    }

    /// Get a processor-specific option.
    pub fn get_processor_option(&self, key: &str) -> Option<&str> {
        self.processor_options.get(key).map(|s| s.as_str())
    }

    /// Create options for ARM Thumb mode.
    pub fn arm_thumb() -> Self {
        let mut opts = Self::new();
        opts.set_processor_option("mode", "thumb");
        opts
    }

    /// Create options for minimal disassembly (no follow).
    pub fn minimal() -> Self {
        Self {
            follow_flow: false,
            disassemble_into_existing: false,
            allow_dead_code: false,
            treat_unknown_as_data: false,
            max_call_depth: 0,
            max_instructions: 1,
            flow_override: FlowOverride::None,
            apply_override_at_entry: false,
            processor_options: std::collections::HashMap::new(),
        }
    }
}

impl Default for DisassemblyOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Context for a disassembly operation.
///
/// Contains all the information needed for a single disassembly request.
#[derive(Debug, Clone)]
pub struct DisassemblyContext {
    /// The starting address.
    pub start_address: u64,
    /// The address space name.
    pub space: String,
    /// Disassembly options.
    pub options: DisassemblyOptions,
    /// The program name.
    pub program_name: String,
    /// Whether this is a re-disassembly of existing code.
    pub is_re_disassembly: bool,
    /// Address ranges to restrict disassembly to.
    pub restricted_ranges: Vec<(u64, u64)>,
}

impl DisassemblyContext {
    /// Create a new disassembly context.
    pub fn new(start_address: u64, space: impl Into<String>) -> Self {
        Self {
            start_address,
            space: space.into(),
            options: DisassemblyOptions::default(),
            program_name: String::new(),
            is_re_disassembly: false,
            restricted_ranges: Vec::new(),
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
    fn test_flow_override_display() {
        assert_eq!(FlowOverride::None.display_name(), "No Override");
        assert_eq!(FlowOverride::Call.display_name(), "Call");
        assert_eq!(FlowOverride::Jump.display_name(), "Jump");
        assert_eq!(FlowOverride::Return.display_name(), "Return");
    }

    #[test]
    fn test_flow_override_changes_flow() {
        assert!(!FlowOverride::None.changes_flow());
        assert!(FlowOverride::Call.changes_flow());
        assert!(FlowOverride::Jump.changes_flow());
        assert!(FlowOverride::Return.changes_flow());
    }

    #[test]
    fn test_disassembly_options_default() {
        let opts = DisassemblyOptions::new();
        assert!(opts.follow_flow);
        assert!(!opts.disassemble_into_existing);
        assert_eq!(opts.max_call_depth, 10);
        assert_eq!(opts.max_instructions, 100000);
        assert_eq!(opts.flow_override, FlowOverride::None);
    }

    #[test]
    fn test_disassembly_options_minimal() {
        let opts = DisassemblyOptions::minimal();
        assert!(!opts.follow_flow);
        assert_eq!(opts.max_call_depth, 0);
        assert_eq!(opts.max_instructions, 1);
    }

    #[test]
    fn test_disassembly_options_arm_thumb() {
        let opts = DisassemblyOptions::arm_thumb();
        assert_eq!(opts.get_processor_option("mode"), Some("thumb"));
    }

    #[test]
    fn test_disassembly_options_processor_options() {
        let mut opts = DisassemblyOptions::new();
        assert!(opts.get_processor_option("mode").is_none());

        opts.set_processor_option("mode", "arm");
        assert_eq!(opts.get_processor_option("mode"), Some("arm"));
    }

    #[test]
    fn test_disassembly_context() {
        let ctx = DisassemblyContext::new(0x401000, "ram");
        assert_eq!(ctx.start_address, 0x401000);
        assert_eq!(ctx.space, "ram");
        assert!(!ctx.is_re_disassembly);
        assert!(ctx.restricted_ranges.is_empty());
    }
}
