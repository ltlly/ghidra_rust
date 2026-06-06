//! Stack unwinding analysis and frame recovery.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.stack` package.
//! Provides symbolic analysis of stack frames, register save/restore
//! tracking, and call-stack unwinding for debug traces.
//!
//! Key types:
//! - `Sym`: Symbolic values used during stack analysis (constants, registers,
//!   stack offsets, stack dereferences, opaque).
//! - `SymArithmetic`: Arithmetic over symbolic values for p-code interpretation.
//! - `SymState`: Symbolic p-code executor state tracking stack, register, and
//!   unique spaces.
//! - `UnwindInfo`: Information about a single frame needed to unwind.
//! - `StackUnwinder`: Orchestrates multi-frame unwinding.
//! - `SavedRegisterMap`: Maps register ranges to stack addresses for saved
//!   register redirection.
//! - `UnwindWarning`: Warnings generated during analysis.

pub mod frame_structure_builder;
pub mod saved_register_map;
pub mod stack_unwinder;
pub mod sym;
pub mod sym_arithmetic;
pub mod sym_pcode_executor;
pub mod sym_state;
pub mod unwind_analysis;
pub mod unwind_info;
pub mod unwind_warning;
pub mod unwind_command;
pub mod unwound_frame;
pub mod stack_frames;

pub use saved_register_map::SavedRegisterMap;
pub use stack_unwinder::StackUnwinder;
pub use sym::{ConstSym, OpaqueSym, RegisterSym, StackDerefSym, StackOffsetSym, Sym};
pub use sym_arithmetic::SymArithmetic;
pub use sym_pcode_executor::{PcodeOpSymbolic, SymPcodeExecutor, VarnodeId};
pub use sym_state::SymState;
pub use unwind_analysis::{AnalysisForPC, BlockEdge, BlockVertex, UnwindAnalysis};
pub use unwind_info::UnwindInfo;
pub use unwind_warning::{UnwindWarning, UnwindWarningKind, UnwindWarningSet};
pub use unwind_command::{UnwindStackCommand, UnwindStackCommandResult};

// ---------------------------------------------------------------------------
// Exception types
// ---------------------------------------------------------------------------

/// Exception indicating a failure during symbolic evaluation of a variable.
///
/// Ported from Ghidra's `EvaluationException`.
#[derive(Debug, Clone)]
pub struct EvaluationException {
    message: String,
}

impl EvaluationException {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for EvaluationException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EvaluationException: {}", self.message)
    }
}

impl std::error::Error for EvaluationException {}

/// Exception indicating failed or incomplete stack unwinding.
///
/// Ported from Ghidra's `UnwindException`.
#[derive(Debug, Clone)]
pub struct UnwindException {
    message: String,
    cause: Option<String>,
}

impl UnwindException {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            cause: None,
        }
    }

    pub fn with_cause(message: impl Into<String>, cause: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            cause: Some(cause.into()),
        }
    }
}

impl std::fmt::Display for UnwindException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.cause {
            Some(c) => write!(f, "UnwindException: {} (caused by: {})", self.message, c),
            None => write!(f, "UnwindException: {}", self.message),
        }
    }
}

impl std::error::Error for UnwindException {}
