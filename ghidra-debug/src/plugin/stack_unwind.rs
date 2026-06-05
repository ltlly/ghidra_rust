//! Stack unwinding for the debugger plugin.
//!
//! Ported from `ghidra/app/plugin/core/debug/stack/` package.
//! Provides stack unwinding through debug frames:
//! - `UnwindStackCommand`: main entry point for unwinding
//! - `AbstractUnwoundFrame`, `ListingUnwoundFrame`, etc.
//! - `EvaluationException` for unwinding errors

use serde::{Deserialize, Serialize};
use thiserror::Error;
use std::collections::BTreeMap;

/// Errors during stack unwinding.
#[derive(Debug, Error)]
pub enum UnwindError {
    /// Failed to evaluate an expression.
    #[error("Evaluation error: {0}")]
    EvaluationError(String),

    /// Failed to read register state.
    #[error("Register read error: register {register}")]
    RegisterReadError {
        /// The register that could not be read.
        register: String,
    },

    /// Failed to read memory for return address.
    #[error("Memory read error at {offset:#x}: {reason}")]
    MemoryReadError {
        /// The offset that failed.
        offset: u64,
        /// Why it failed.
        reason: String,
    },

    /// Frame count limit exceeded.
    #[error("Maximum frame count ({0}) exceeded")]
    MaxFramesExceeded(usize),

    /// Dynamic mapping error.
    #[error("Dynamic mapping error: {0}")]
    DynamicMappingError(String),

    /// A generic unwinding error.
    #[error("Unwind error: {0}")]
    Other(String),
}

/// An exception during evaluation.
///
/// Ported from `EvaluationException.java`.
#[derive(Debug, Error)]
#[error("Evaluation exception: {message}")]
pub struct EvaluationException {
    /// The error message.
    pub message: String,
    /// Program counter at the point of error.
    pub pc: u64,
}

impl EvaluationException {
    /// Create a new evaluation exception.
    pub fn new(message: String, pc: u64) -> Self {
        Self { message, pc }
    }
}

/// An exception caused by dynamic mapping issues.
///
/// Ported from `DynamicMappingException.java`.
#[derive(Debug, Error)]
#[error("Dynamic mapping exception: {message}")]
pub struct DynamicMappingException {
    /// The error message.
    pub message: String,
}

/// A register value in the unwound frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterValue {
    /// Register name.
    pub name: String,
    /// Register value bytes (big-endian).
    pub value: Vec<u8>,
}

/// An unwound stack frame.
///
/// Ported from `AbstractUnwoundFrame.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnwoundFrame {
    /// Frame number (0 = innermost).
    pub frame_number: u32,
    /// Program counter for this frame.
    pub pc: u64,
    /// Stack pointer for this frame.
    pub sp: u64,
    /// Frame pointer for this frame.
    pub fp: u64,
    /// Return address.
    pub return_address: u64,
    /// Register values for this frame.
    pub registers: BTreeMap<String, Vec<u8>>,
    /// The function name, if known.
    pub function_name: Option<String>,
    /// The source file and line, if known.
    pub source_location: Option<String>,
}

impl UnwoundFrame {
    /// Create a new unwound frame.
    pub fn new(frame_number: u32, pc: u64) -> Self {
        Self {
            frame_number,
            pc,
            sp: 0,
            fp: 0,
            return_address: 0,
            registers: BTreeMap::new(),
            function_name: None,
            source_location: None,
        }
    }

    /// Set the stack pointer.
    pub fn with_sp(mut self, sp: u64) -> Self {
        self.sp = sp;
        self
    }

    /// Set the frame pointer.
    pub fn with_fp(mut self, fp: u64) -> Self {
        self.fp = fp;
        self
    }

    /// Set the return address.
    pub fn with_return_address(mut self, ra: u64) -> Self {
        self.return_address = ra;
        self
    }

    /// Set the function name.
    pub fn with_function_name(mut self, name: String) -> Self {
        self.function_name = Some(name);
        self
    }

    /// Add a register value.
    pub fn with_register(mut self, name: String, value: Vec<u8>) -> Self {
        self.registers.insert(name, value);
        self
    }

    /// Get a register value.
    pub fn get_register(&self, name: &str) -> Option<&[u8]> {
        self.registers.get(name).map(|v| v.as_slice())
    }
}

/// A frame obtained from the listing (analysis).
///
/// Ported from `ListingUnwoundFrame.java`.
#[derive(Debug, Clone)]
pub struct ListingUnwoundFrame {
    /// The base unwound frame.
    pub frame: UnwoundFrame,
    /// The function containing this frame.
    pub function_offset: u64,
    /// Stack depth at this frame.
    pub stack_depth: u64,
}

/// A frame obtained from analysis.
///
/// Ported from `AnalysisUnwoundFrame.java`.
#[derive(Debug, Clone)]
pub struct AnalysisUnwoundFrame {
    /// The base unwound frame.
    pub frame: UnwoundFrame,
    /// Confidence level (0.0 - 1.0).
    pub confidence: f64,
}

/// A fake/synthetic frame for testing or display.
///
/// Ported from `FakeUnwoundFrame.java`.
#[derive(Debug, Clone)]
pub struct FakeUnwoundFrame {
    /// The base unwound frame.
    pub frame: UnwoundFrame,
}

/// A command that performs stack unwinding.
///
/// Ported from `UnwindStackCommand.java`.
#[derive(Debug)]
pub struct UnwindStackCommand {
    /// Trace key.
    pub trace_key: i64,
    /// Thread key.
    pub thread_key: i64,
    /// Starting snap.
    pub snap: i64,
    /// Maximum number of frames to unwind.
    pub max_frames: usize,
    /// The resulting frames.
    frames: Vec<UnwoundFrame>,
}

impl UnwindStackCommand {
    /// Create a new unwind command.
    pub fn new(trace_key: i64, thread_key: i64, snap: i64) -> Self {
        Self {
            trace_key,
            thread_key,
            snap,
            max_frames: 100,
            frames: Vec::new(),
        }
    }

    /// Set the maximum frame count.
    pub fn with_max_frames(mut self, max: usize) -> Self {
        self.max_frames = max;
        self
    }

    /// Execute the unwinding.
    pub fn execute(&mut self) -> Result<&[UnwoundFrame], UnwindError> {
        // In full implementation:
        // 1. Read initial register state from trace
        // 2. Follow frame pointers / return addresses
        // 3. For each frame, look up function name
        // 4. Stop when frame pointer is 0 or max frames reached
        self.frames.clear();

        // Stub: create a single frame with the starting state
        self.frames.push(
            UnwoundFrame::new(0, 0)
                .with_sp(0)
                .with_fp(0),
        );

        Ok(&self.frames)
    }

    /// Get the unwound frames.
    pub fn frames(&self) -> &[UnwoundFrame] {
        &self.frames
    }
}

/// Builder for constructing unwind commands with common patterns.
pub struct UnwindCommandBuilder {
    trace_key: i64,
    thread_key: i64,
    snap: i64,
    max_frames: usize,
}

impl UnwindCommandBuilder {
    /// Create a new builder.
    pub fn new(trace_key: i64, thread_key: i64, snap: i64) -> Self {
        Self {
            trace_key,
            thread_key,
            snap,
            max_frames: 100,
        }
    }

    /// Set max frames.
    pub fn max_frames(mut self, max: usize) -> Self {
        self.max_frames = max;
        self
    }

    /// Build the command.
    pub fn build(self) -> UnwindStackCommand {
        UnwindStackCommand::new(self.trace_key, self.thread_key, self.snap)
            .with_max_frames(self.max_frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unwound_frame() {
        let frame = UnwoundFrame::new(0, 0x400000)
            .with_sp(0x7FFF00)
            .with_fp(0x7FFF80)
            .with_return_address(0x400100)
            .with_function_name("main".into())
            .with_register("RAX".into(), vec![0x42; 8]);

        assert_eq!(frame.frame_number, 0);
        assert_eq!(frame.pc, 0x400000);
        assert_eq!(frame.sp, 0x7FFF00);
        assert_eq!(frame.fp, 0x7FFF80);
        assert_eq!(frame.function_name, Some("main".into()));
        assert_eq!(frame.get_register("RAX"), Some(&[0x42; 8][..]));
    }

    #[test]
    fn test_unwind_stack_command() {
        let mut cmd = UnwindStackCommand::new(1, 1, 0);
        let frames = cmd.execute().unwrap();
        assert!(!frames.is_empty());
    }

    #[test]
    fn test_unwind_command_builder() {
        let cmd = UnwindCommandBuilder::new(1, 1, 0)
            .max_frames(50)
            .build();
        assert_eq!(cmd.max_frames, 50);
    }

    #[test]
    fn test_evaluation_exception() {
        let ex = EvaluationException::new("test".into(), 0x400000);
        assert_eq!(ex.pc, 0x400000);
    }

    #[test]
    fn test_listing_unwound_frame() {
        let frame = ListingUnwoundFrame {
            frame: UnwoundFrame::new(0, 0x400000),
            function_offset: 0x400000,
            stack_depth: 16,
        };
        assert_eq!(frame.function_offset, 0x400000);
    }
}
