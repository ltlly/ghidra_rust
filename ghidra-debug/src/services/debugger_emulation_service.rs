//! DebuggerEmulationService - service for emulation control.
//!
//! Ported from Ghidra's `ghidra.app.services.DebuggerEmulationService`.

use serde::{Deserialize, Serialize};

/// Emulation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmulationMode {
    /// Native execution.
    Native,
    /// P-code emulation.
    Pcode,
    /// Trace-based replay.
    TraceReplay,
}

/// Result of an emulation step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulationStepResult {
    /// The new program counter after stepping.
    pub new_pc: u64,
    /// The number of instructions executed.
    pub instructions_executed: u64,
    /// Whether the emulation hit a breakpoint.
    pub hit_breakpoint: bool,
    /// Whether the emulation completed (process exited or hit an error).
    pub completed: bool,
    /// Error message, if any.
    pub error: Option<String>,
}

/// Service interface for debugger emulation.
pub trait DebuggerEmulationServiceExt {
    /// Start emulation from the current state.
    fn start_emulation(&mut self, trace_key: i64, mode: EmulationMode) -> Result<(), String>;

    /// Stop emulation.
    fn stop_emulation(&mut self, trace_key: i64) -> Result<(), String>;

    /// Step emulation by one instruction.
    fn step_instruction(&mut self, trace_key: i64) -> Result<EmulationStepResult, String>;

    /// Step emulation by one pcode operation.
    fn step_pcode(&mut self, trace_key: i64) -> Result<EmulationStepResult, String>;

    /// Step over (execute until the next instruction at this level).
    fn step_over(&mut self, trace_key: i64) -> Result<EmulationStepResult, String>;

    /// Step out (execute until the current function returns).
    fn step_out(&mut self, trace_key: i64) -> Result<EmulationStepResult, String>;

    /// Run emulation until a breakpoint or completion.
    fn run(&mut self, trace_key: i64) -> Result<EmulationStepResult, String>;

    /// Whether emulation is active for the given trace.
    fn is_emulating(&self, trace_key: i64) -> bool;

    /// Get the current emulation mode.
    fn emulation_mode(&self, trace_key: i64) -> Option<EmulationMode>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emulation_modes() {
        assert_ne!(EmulationMode::Native, EmulationMode::Pcode);
        assert_ne!(EmulationMode::TraceReplay, EmulationMode::Native);
    }

    #[test]
    fn test_step_result() {
        let result = EmulationStepResult {
            new_pc: 0x400004,
            instructions_executed: 1,
            hit_breakpoint: false,
            completed: false,
            error: None,
        };
        assert_eq!(result.new_pc, 0x400004);
        assert!(!result.hit_breakpoint);
    }
}
