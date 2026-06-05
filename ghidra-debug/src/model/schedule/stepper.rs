//! Stepper trait for pcode machine stepping.
//!
//! Ported from Ghidra's `Stepper` interface and `StepKind` enum.

use serde::{Deserialize, Serialize};

/// The kind of a step and how to execute it.
///
/// Ported from Ghidra's `StepKind` enum which implements `Stepper`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StepKind {
    /// Step one instruction (full decode + execute).
    Instruction,
    /// Step one pcode operation.
    PcodeOp,
}

impl StepKind {
    /// Get a human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Instruction => "instruction",
            Self::PcodeOp => "pcode",
        }
    }
}

impl std::fmt::Display for StepKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// A trait that defines how to step a pcode thread.
///
/// Ported from Ghidra's `Stepper` interface. Two methods are needed:
/// `tick` (advance one full step) and `skip` (skip one step without executing).
///
/// In the Rust port, this trait provides the semantics without requiring
/// an actual pcode machine to be present. Actual execution is handled
/// by the emulation framework.
pub trait Stepper: Send + Sync {
    /// Execute one full step on the given thread.
    fn tick(&self, thread_id: i64);

    /// Skip one step on the given thread (advance without executing).
    fn skip(&self, thread_id: i64);

    /// Get the kind of this stepper.
    fn kind(&self) -> StepKind;
}

/// A stepper that performs instruction-level stepping.
#[derive(Debug, Clone, Copy, Default)]
pub struct InstructionStepper;

impl Stepper for InstructionStepper {
    fn tick(&self, _thread_id: i64) {
        // In real implementation, this would call pcodeThread.stepInstruction()
    }

    fn skip(&self, _thread_id: i64) {
        // In real implementation, this would call pcodeThread.skipInstruction()
    }

    fn kind(&self) -> StepKind {
        StepKind::Instruction
    }
}

/// A stepper that performs pcode-op-level stepping.
#[derive(Debug, Clone, Copy, Default)]
pub struct PcodeStepper;

impl Stepper for PcodeStepper {
    fn tick(&self, _thread_id: i64) {
        // In real implementation, this would call pcodeThread.stepPcodeOp()
    }

    fn skip(&self, _thread_id: i64) {
        // In real implementation, this would call pcodeThread.skipPcodeOp()
    }

    fn kind(&self) -> StepKind {
        StepKind::PcodeOp
    }
}

/// Get the instruction-level stepper.
pub fn instruction_stepper() -> &'static dyn Stepper {
    &InstructionStepper
}

/// Get the pcode-op-level stepper.
pub fn pcode_stepper() -> &'static dyn Stepper {
    &PcodeStepper
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_step_kind_display() {
        assert_eq!(StepKind::Instruction.to_string(), "instruction");
        assert_eq!(StepKind::PcodeOp.to_string(), "pcode");
    }

    #[test]
    fn test_instruction_stepper() {
        let s = InstructionStepper;
        assert_eq!(s.kind(), StepKind::Instruction);
        s.tick(0);
        s.skip(0);
    }

    #[test]
    fn test_pcode_stepper() {
        let s = PcodeStepper;
        assert_eq!(s.kind(), StepKind::PcodeOp);
        s.tick(0);
        s.skip(0);
    }

    #[test]
    fn test_stepper_functions() {
        assert_eq!(instruction_stepper().kind(), StepKind::Instruction);
        assert_eq!(pcode_stepper().kind(), StepKind::PcodeOp);
    }
}
