//! P-code intermediate representation module.
//!
//! Models Ghidra's P-code: the register-transfer language used as an
//! intermediate representation between SLEIGH processor specifications
//! and the decompiler's analysis and C-output stages.
//!
//! # Organization
//!
//! - [`opcodes`] -- all 70 P-code operation codes with classification
//!   helpers, display, and parsing via [`OpCode`].
//! - [`operation`] -- [`Varnode`] (a triple of address-space, offset, size)
//!   and [`PcodeOperation`] (opcode + inputs + optional output).
//! - [`sequence`] -- [`PcodeSequence`] (operations for one instruction) and
//!   [`SequenceBuilder`] for incremental construction.
//! - [`semantics`] -- [`ConstructSem`] trait for semantic actions during
//!   disassembly, and [`PcodeEmitter`] for outputting P-code.
//! - [`analysis`] -- control-flow graphs, dominators, loops, SSA, constant
//!   propagation, dead-code elimination, expression simplification.
//! - [`c_output`] -- structured C token output, control-flow structuring,
//!   formatting, and the `format_function` entry point.

pub mod analysis;
pub mod c_output;
pub mod opcodes;
pub mod operation;
pub mod semantics;
pub mod sequence;

// Re-export the most commonly used types at the module root so that
// `use super::{OpCode, PcodeOperation, PcodeSequence, Varnode}` continues
// to work from sibling modules.
pub use opcodes::{OpCode, OpCodeIter, ParseOpCodeError};
pub use operation::{PcodeOperation, Varnode};
pub use semantics::{ConstructSem, PcodeEmitter};
pub use sequence::{PcodeSequence, SequenceBuilder};
