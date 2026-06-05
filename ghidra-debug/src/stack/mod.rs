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
pub mod unwind_info;
pub mod unwind_warning;
pub mod unwind_command;
pub mod unwound_frame;

pub use saved_register_map::SavedRegisterMap;
pub use stack_unwinder::StackUnwinder;
pub use sym::{ConstSym, OpaqueSym, RegisterSym, StackDerefSym, StackOffsetSym, Sym};
pub use sym_arithmetic::SymArithmetic;
pub use sym_pcode_executor::{PcodeOpSymbolic, SymPcodeExecutor, VarnodeId};
pub use sym_state::SymState;
pub use unwind_info::UnwindInfo;
pub use unwind_warning::{UnwindWarning, UnwindWarningKind, UnwindWarningSet};
pub use unwind_command::{UnwindStackCommand, UnwindStackCommandResult};
