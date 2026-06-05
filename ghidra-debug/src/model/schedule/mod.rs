//! Full emulation time scheduling model.
//!
//! Ported from Ghidra's `ghidra.trace.model.time.schedule` package.
//!
//! This module provides the complete scheduling model for stepping through
//! emulated code, including:
//! - **Step types**: `TickStep`, `SkipStep`, `PatchStep` for instruction,
//!   skip, and patch operations.
//! - **`Sequence`**: An ordered list of steps with normalization, comparison,
//!   and relativization.
//! - **`TraceSchedule`**: A full schedule consisting of a snap, instruction
//!   step sequence, and pcode step sequence.
//! - **`Stepper`**: Trait for defining how steps execute on a pcode machine.
//! - **`CompareResult`**: Rich comparison semantics for schedules.
//! - **`Scheduler`**: Iterator-based scheduler for running machines.

pub mod compare_result;
pub mod patch_step;
pub mod scheduler;
pub mod sequence;
pub mod skip_step;
pub mod stepper;
pub mod tick_step;
pub mod trace_schedule_full;

pub use compare_result::CompareResult;
pub use patch_step::PatchStep;
pub use scheduler::{OneThreadScheduler, RoundRobinScheduler, RunResult, Scheduler, TraceScheduler};
pub use sequence::Sequence;
pub use skip_step::SkipStep;
pub use stepper::{Stepper, StepKind};
pub use tick_step::TickStep;
pub use trace_schedule_full::{ScheduleForm, ScheduleSource, TimeRadix, TraceSchedule};
