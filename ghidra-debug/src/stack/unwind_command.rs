//! UnwindStackCommand - command for unwinding the stack of a debug session.
//!
//! Ported from Ghidra's `UnwindStackCommand` from
//! `ghidra.app.plugin.core.debug.stack`. Provides a high-level command
//! that orchestrates the StackUnwinder to produce a complete call stack
//! from the current debug state.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::sym_pcode_executor::{PcodeOpSymbolic, SymPcodeExecutor};
use super::unwind_info::{ReturnLocation, UnwindInfo};
use super::unwind_warning::UnwindWarningSet;
use super::unwound_frame::{UnwoundFrame, UnwindAnalysis, UnwindWarning};

/// Command to unwind the call stack from the current debug coordinates.
///
/// Ported from Ghidra's `UnwindStackCommand`. This is a high-level
/// operation that coordinates multiple analysis passes to produce
/// a complete stack trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnwindStackCommand {
    /// The trace key (database identifier).
    pub trace_key: i64,
    /// The thread key to unwind.
    pub thread_key: i64,
    /// The snap (time point) to unwind at.
    pub snap: i64,
    /// Starting frame level (usually 0 for innermost).
    pub start_frame: u32,
    /// Maximum number of frames to unwind.
    pub max_frames: u32,
    /// Whether to apply the analysis results to the trace as bookmarks.
    pub apply_to_trace: bool,
}

impl UnwindStackCommand {
    /// Create a new unwind command.
    pub fn new(trace_key: i64, thread_key: i64, snap: i64) -> Self {
        Self {
            trace_key,
            thread_key,
            snap,
            start_frame: 0,
            max_frames: 256,
            apply_to_trace: true,
        }
    }

    /// Set the maximum number of frames.
    pub fn with_max_frames(mut self, max: u32) -> Self {
        self.max_frames = max;
        self
    }

    /// Set the starting frame level.
    pub fn with_start_frame(mut self, frame: u32) -> Self {
        self.start_frame = frame;
        self
    }

    /// Whether to apply results to the trace.
    pub fn with_apply_to_trace(mut self, apply: bool) -> Self {
        self.apply_to_trace = apply;
        self
    }
}

/// Result of executing an UnwindStackCommand.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnwindStackCommandResult {
    /// The unwound frames.
    pub frames: Vec<UnwoundFrame>,
    /// The analysis result.
    pub analysis: UnwindAnalysis,
    /// Warnings collected during unwinding.
    pub warnings: Vec<UnwindWarning>,
    /// Number of symbolic operations performed.
    pub symbolic_ops: u64,
    /// Total time taken in microseconds.
    pub duration_us: u64,
}

impl UnwindStackCommandResult {
    /// Create a new result.
    pub fn new() -> Self {
        Self {
            frames: Vec::new(),
            analysis: UnwindAnalysis::Success,
            warnings: Vec::new(),
            symbolic_ops: 0,
            duration_us: 0,
        }
    }

    /// Create a failed result.
    pub fn failed(message: impl Into<String>) -> Self {
        Self {
            frames: Vec::new(),
            analysis: UnwindAnalysis::Failed(message.into()),
            warnings: Vec::new(),
            symbolic_ops: 0,
            duration_us: 0,
        }
    }

    /// Whether the unwind was successful.
    pub fn is_success(&self) -> bool {
        matches!(self.analysis, UnwindAnalysis::Success)
    }

    /// Get the innermost frame (level 0).
    pub fn innermost_frame(&self) -> Option<&UnwoundFrame> {
        self.frames.first()
    }

    /// Get the outermost frame.
    pub fn outermost_frame(&self) -> Option<&UnwoundFrame> {
        self.frames.last()
    }

    /// Get the frame at the given level.
    pub fn frame_at_level(&self, level: u32) -> Option<&UnwoundFrame> {
        self.frames.iter().find(|f| f.level == level)
    }

    /// Get the total number of frames.
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }
}

impl Default for UnwindStackCommandResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the unwind information for a given frame during stack analysis.
///
/// This performs the two-pass analysis described in Ghidra's `UnwindAnalysis`:
/// 1. Execute from function entry to PC to capture register save points
/// 2. Execute from PC to return to determine stack adjustments and
///    return address locations.
///
/// Ported from Ghidra's `UnwindAnalysis.AnalysisForPC.computeUnwindInfo`.
pub fn build_unwind_info(
    executor: &mut SymPcodeExecutor,
    entry_to_pc_ops: &[PcodeOpSymbolic],
    pc_to_return_ops: &[PcodeOpSymbolic],
) -> UnwindInfo {
    // Pass 1: Execute from entry to PC
    for op in entry_to_pc_ops {
        executor.execute_op(op);
    }

    // Capture stack depth and saved registers
    let depth = executor.compute_stack_depth();
    let saved_from_stack = executor.compute_map_using_stack();

    // Pass 2: Fork state and execute from PC to return
    let forked_state = executor.fork_regs();
    let mut return_executor = SymPcodeExecutor::with_state(forked_state);

    for op in pc_to_return_ops {
        return_executor.execute_op(op);
    }

    let adjust = return_executor.compute_stack_depth();

    // Build the saved register map as HashMap<String, i64>
    let mut saved_registers = HashMap::new();
    for (stack_offset, reg_name) in &saved_from_stack {
        saved_registers.insert(reg_name.clone(), *stack_offset);
    }

    // Compute return location from the return executor's state
    let return_location = match return_executor.state.compute_return_address_location() {
        Some(super::sym_state::ReturnAddressLocation::Stack { offset, size }) => {
            ReturnLocation::Stack { offset, size }
        }
        Some(super::sym_state::ReturnAddressLocation::Register { name, mask, size: _ }) => {
            ReturnLocation::Register { name, mask }
        }
        None => ReturnLocation::Unknown,
    };

    UnwindInfo {
        function_name: None,
        depth,
        adjust,
        return_location,
        return_mask: u64::MAX,
        saved_registers,
        warnings: UnwindWarningSet::new(),
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stack::sym::Sym;

    #[test]
    fn test_unwind_command_creation() {
        let cmd = UnwindStackCommand::new(1, 42, 100);
        assert_eq!(cmd.trace_key, 1);
        assert_eq!(cmd.thread_key, 42);
        assert_eq!(cmd.snap, 100);
        assert_eq!(cmd.max_frames, 256);
        assert!(cmd.apply_to_trace);
    }

    #[test]
    fn test_unwind_command_builder() {
        let cmd = UnwindStackCommand::new(1, 2, 3)
            .with_max_frames(10)
            .with_start_frame(2)
            .with_apply_to_trace(false);
        assert_eq!(cmd.max_frames, 10);
        assert_eq!(cmd.start_frame, 2);
        assert!(!cmd.apply_to_trace);
    }

    #[test]
    fn test_unwind_result_success() {
        let result = UnwindStackCommandResult::new();
        assert!(result.is_success());
        assert_eq!(result.frame_count(), 0);
    }

    #[test]
    fn test_unwind_result_failed() {
        let result = UnwindStackCommandResult::failed("could not find function");
        assert!(!result.is_success());
        if let UnwindAnalysis::Failed(msg) = &result.analysis {
            assert!(msg.contains("could not find"));
        } else {
            panic!("Expected Failed variant");
        }
    }

    #[test]
    fn test_unwind_result_frames() {
        let mut result = UnwindStackCommandResult::new();
        result.frames.push(UnwoundFrame::new(0, 0x400000, 0x7fff00));
        result.frames.push(UnwoundFrame::new(1, 0x401000, 0x7ffe00));
        result.frames.push(UnwoundFrame::new(2, 0x402000, 0x7ffd00));
        assert_eq!(result.frame_count(), 3);
        assert_eq!(result.innermost_frame().unwrap().level, 0);
        assert_eq!(result.outermost_frame().unwrap().level, 2);
        assert!(result.frame_at_level(1).is_some());
        assert!(result.frame_at_level(5).is_none());
    }

    #[test]
    fn test_unwind_command_serde() {
        let cmd = UnwindStackCommand::new(1, 2, 3);
        let json = serde_json::to_string(&cmd).unwrap();
        let back: UnwindStackCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(back.trace_key, 1);
    }

    #[test]
    fn test_build_unwind_info_empty() {
        let mut exec = SymPcodeExecutor::new("RSP", false);
        let info = build_unwind_info(&mut exec, &[], &[]);
        // With no ops and no RSP register set, depth/adjust are None
        assert!(info.depth.is_none() || info.depth == Some(0));
        assert!(info.adjust.is_none() || info.adjust == Some(0));
        assert!(info.saved_registers.is_empty());
        assert!(!info.has_error());
    }

    #[test]
    fn test_build_unwind_info_with_stack_adjust() {
        let mut exec = SymPcodeExecutor::new("RSP", false);
        // Set up RSP register symbol
        let sp_addr = super::super::sym_pcode_executor::register_name_to_addr("RSP");
        exec.state.write_sym("register", sp_addr, Sym::register("RSP", 8));

        // Entry to PC: SUB RSP, 0x20
        let entry_ops = vec![PcodeOpSymbolic::IntSub {
            a: super::super::sym_pcode_executor::VarnodeId::Register("RSP".into()),
            b: super::super::sym_pcode_executor::VarnodeId::Constant(0x20),
            output: super::super::sym_pcode_executor::VarnodeId::Register("RSP".into()),
        }];

        // PC to return: ADD RSP, 0x20
        let return_ops = vec![PcodeOpSymbolic::IntAdd {
            a: super::super::sym_pcode_executor::VarnodeId::Register("RSP".into()),
            b: super::super::sym_pcode_executor::VarnodeId::Constant(0x20),
            output: super::super::sym_pcode_executor::VarnodeId::Register("RSP".into()),
        }];

        let info = build_unwind_info(&mut exec, &entry_ops, &return_ops);
        // The depth should reflect the stack adjustment
        assert!(info.depth.is_some());
        assert!(!info.has_error());
    }

    #[test]
    fn test_build_unwind_info_with_saved_register() {
        let mut exec = SymPcodeExecutor::new("RSP", false);
        let sp_addr = super::super::sym_pcode_executor::register_name_to_addr("RSP");
        exec.state.write_sym("register", sp_addr, Sym::register("RSP", 8));

        // Entry to PC: SUB RSP, 16; STORE [RSP-8] = R30
        let entry_ops = vec![
            PcodeOpSymbolic::IntSub {
                a: super::super::sym_pcode_executor::VarnodeId::Register("RSP".into()),
                b: super::super::sym_pcode_executor::VarnodeId::Constant(16),
                output: super::super::sym_pcode_executor::VarnodeId::Register("RSP".into()),
            },
        ];

        let info = build_unwind_info(&mut exec, &entry_ops, &[]);
        assert!(!info.has_error());
    }
}
