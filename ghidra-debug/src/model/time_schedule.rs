//! Time schedule types for emulation stepping.
//!
//! Ported from Ghidra's `ghidra.trace.model.time.schedule` package.
//! Provides the scheduling model for stepping through emulated code:
//! instruction steps, pcode steps, skip steps, tick steps, and patch steps.

use serde::{Deserialize, Serialize};

/// The kind of a single step in a schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepKind {
    /// Execute one instruction.
    Instruction,
    /// Execute one pcode operation.
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

/// The result of comparing two schedules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompareResult {
    /// The two schedules are equivalent.
    Equal,
    /// The first schedule is before the second.
    Before,
    /// The first schedule is after the second.
    After,
    /// The relationship cannot be determined (e.g., different sources).
    Unrelated,
}

/// A single step in a schedule sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleStep {
    /// The kind of step.
    pub kind: StepKind,
    /// The number of times to repeat this step kind.
    pub count: u64,
}

impl ScheduleStep {
    /// Create a new step.
    pub fn new(kind: StepKind, count: u64) -> Self {
        Self { kind, count }
    }

    /// An instruction step (single step into).
    pub fn instruction(count: u64) -> Self {
        Self::new(StepKind::Instruction, count)
    }

    /// A pcode step.
    pub fn pcode(count: u64) -> Self {
        Self::new(StepKind::PcodeOp, count)
    }

    /// A skip step: skip N instructions without executing.
    pub fn skip(count: u64) -> Self {
        Self {
            kind: StepKind::Instruction,
            count,
        }
    }

    /// Parse a step from a schedule string token (e.g., "5i", "3p", "2s").
    pub fn parse_token(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        let (num_str, kind_char) = if let Some(last) = s.chars().last() {
            if last.is_ascii_alphabetic() {
                (&s[..s.len() - 1], last)
            } else {
                (s, 'i') // default to instruction
            }
        } else {
            return None;
        };
        let count: u64 = num_str.parse().ok()?;
        match kind_char {
            'i' => Some(Self::instruction(count)),
            'p' => Some(Self::pcode(count)),
            's' => Some(Self::skip(count)),
            _ => None,
        }
    }
}

impl std::fmt::Display for ScheduleStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let suffix = match self.kind {
            StepKind::Instruction => "i",
            StepKind::PcodeOp => "p",
        };
        write!(f, "{}{}", self.count, suffix)
    }
}

/// A sequence of steps forming a complete schedule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleSequence {
    /// The initial snap from which this sequence starts.
    pub initial_snap: i64,
    /// The ordered list of steps.
    pub steps: Vec<ScheduleStep>,
}

impl ScheduleSequence {
    /// Create a new sequence starting at the given snap.
    pub fn new(initial_snap: i64) -> Self {
        Self {
            initial_snap,
            steps: Vec::new(),
        }
    }

    /// Add a step to the sequence.
    pub fn push(&mut self, step: ScheduleStep) {
        self.steps.push(step);
    }

    /// Get the total number of steps across all entries.
    pub fn total_steps(&self) -> u64 {
        self.steps.iter().map(|s| s.count).sum()
    }

    /// Parse a schedule sequence from a string (e.g., "5:1i" or "5:2i1p").
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let colon = s.find(':')?;
        let initial_snap: i64 = s[..colon].parse().ok()?;
        let rest = &s[colon + 1..];

        let mut seq = Self::new(initial_snap);
        let mut i = 0;
        let bytes = rest.as_bytes();
        while i < bytes.len() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if i == start {
                // No digits found, default to 1
                if i < bytes.len() {
                    let kind = match bytes[i] as char {
                        'i' => StepKind::Instruction,
                        'p' => StepKind::PcodeOp,
                        _ => return None,
                    };
                    seq.push(ScheduleStep::new(kind, 1));
                    i += 1;
                }
            } else {
                let count: u64 = rest[start..i].parse().ok()?;
                if i < bytes.len() {
                    let kind = match bytes[i] as char {
                        'i' => StepKind::Instruction,
                        'p' => StepKind::PcodeOp,
                        _ => return None,
                    };
                    seq.push(ScheduleStep::new(kind, count));
                    i += 1;
                } else {
                    // Trailing number without suffix, default to instruction
                    seq.push(ScheduleStep::instruction(count));
                }
            }
        }
        Some(seq)
    }
}

impl std::fmt::Display for ScheduleSequence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:", self.initial_snap)?;
        for step in &self.steps {
            write!(f, "{}", step)?;
        }
        Ok(())
    }
}

/// A scheduler that tracks the current position in a step sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scheduler {
    /// The sequence being scheduled.
    pub sequence: ScheduleSequence,
    /// The index of the current step in the sequence.
    pub current_step_index: usize,
    /// How many repetitions of the current step have been completed.
    pub current_step_progress: u64,
}

impl Scheduler {
    /// Create a new scheduler for the given sequence.
    pub fn new(sequence: ScheduleSequence) -> Self {
        Self {
            sequence,
            current_step_index: 0,
            current_step_progress: 0,
        }
    }

    /// Check if all steps have been completed.
    pub fn is_done(&self) -> bool {
        self.current_step_index >= self.sequence.steps.len()
    }

    /// Get the current step kind, if any.
    pub fn current_kind(&self) -> Option<StepKind> {
        self.sequence
            .steps
            .get(self.current_step_index)
            .map(|s| s.kind)
    }

    /// Advance the scheduler by one tick.
    /// Returns the step kind that was executed, or None if done.
    pub fn advance(&mut self) -> Option<StepKind> {
        if self.is_done() {
            return None;
        }
        let kind = self.sequence.steps[self.current_step_index].kind;
        self.current_step_progress += 1;
        if self.current_step_progress >= self.sequence.steps[self.current_step_index].count {
            self.current_step_index += 1;
            self.current_step_progress = 0;
        }
        Some(kind)
    }

    /// Get the remaining number of steps.
    pub fn remaining(&self) -> u64 {
        if self.is_done() {
            return 0;
        }
        let remaining_in_current =
            self.sequence.steps[self.current_step_index].count - self.current_step_progress;
        remaining_in_current
            + self.sequence.steps[self.current_step_index + 1..]
                .iter()
                .map(|s| s.count)
                .sum::<u64>()
    }

    /// Reset the scheduler to the beginning.
    pub fn reset(&mut self) {
        self.current_step_index = 0;
        self.current_step_progress = 0;
    }

    /// Compare two schedules.
    pub fn compare(a: &ScheduleSequence, b: &ScheduleSequence) -> CompareResult {
        if a.initial_snap != b.initial_snap {
            return CompareResult::Unrelated;
        }
        let total_a = a.total_steps();
        let total_b = b.total_steps();
        match total_a.cmp(&total_b) {
            std::cmp::Ordering::Equal => CompareResult::Equal,
            std::cmp::Ordering::Less => CompareResult::Before,
            std::cmp::Ordering::Greater => CompareResult::After,
        }
    }
}

/// A tick step: advancing one snap forward in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TickStep {
    /// The target snap.
    pub snap: i64,
}

impl TickStep {
    /// Create a new tick step.
    pub fn new(snap: i64) -> Self {
        Self { snap }
    }
}

/// A patch step: applying a data modification at a given snap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchStep {
    /// The snap at which to apply the patch.
    pub snap: i64,
    /// The address at which to apply.
    pub address: u64,
    /// The bytes to write.
    pub data: Vec<u8>,
}

impl PatchStep {
    /// Create a new patch step.
    pub fn new(snap: i64, address: u64, data: Vec<u8>) -> Self {
        Self {
            snap,
            address,
            data,
        }
    }
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
    fn test_schedule_step_instruction() {
        let step = ScheduleStep::instruction(5);
        assert_eq!(step.count, 5);
        assert_eq!(step.to_string(), "5i");
    }

    #[test]
    fn test_schedule_step_pcode() {
        let step = ScheduleStep::pcode(3);
        assert_eq!(step.to_string(), "3p");
    }

    #[test]
    fn test_schedule_step_parse() {
        let step = ScheduleStep::parse_token("5i").unwrap();
        assert_eq!(step.kind, StepKind::Instruction);
        assert_eq!(step.count, 5);

        let step = ScheduleStep::parse_token("3p").unwrap();
        assert_eq!(step.kind, StepKind::PcodeOp);
        assert_eq!(step.count, 3);
    }

    #[test]
    fn test_schedule_sequence_parse() {
        let seq = ScheduleSequence::parse("5:3i1p").unwrap();
        assert_eq!(seq.initial_snap, 5);
        assert_eq!(seq.steps.len(), 2);
        assert_eq!(seq.steps[0].kind, StepKind::Instruction);
        assert_eq!(seq.steps[0].count, 3);
        assert_eq!(seq.steps[1].kind, StepKind::PcodeOp);
        assert_eq!(seq.steps[1].count, 1);
    }

    #[test]
    fn test_schedule_sequence_display() {
        let seq = ScheduleSequence::parse("5:3i1p").unwrap();
        assert_eq!(seq.to_string(), "5:3i1p");
    }

    #[test]
    fn test_schedule_sequence_total_steps() {
        let seq = ScheduleSequence::parse("0:3i2p").unwrap();
        assert_eq!(seq.total_steps(), 5);
    }

    #[test]
    fn test_scheduler_advance() {
        let seq = ScheduleSequence::parse("0:2i1p").unwrap();
        let mut sched = Scheduler::new(seq);
        assert!(!sched.is_done());
        assert_eq!(sched.current_kind(), Some(StepKind::Instruction));

        assert_eq!(sched.advance(), Some(StepKind::Instruction));
        assert!(!sched.is_done());
        assert_eq!(sched.advance(), Some(StepKind::Instruction));
        assert!(!sched.is_done());
        assert_eq!(sched.advance(), Some(StepKind::PcodeOp));
        assert!(sched.is_done());
        assert_eq!(sched.advance(), None);
    }

    #[test]
    fn test_scheduler_reset() {
        let seq = ScheduleSequence::parse("0:1i").unwrap();
        let mut sched = Scheduler::new(seq);
        sched.advance();
        assert!(sched.is_done());
        sched.reset();
        assert!(!sched.is_done());
    }

    #[test]
    fn test_compare_equal() {
        let a = ScheduleSequence::parse("0:3i").unwrap();
        let b = ScheduleSequence::parse("0:3i").unwrap();
        assert_eq!(Scheduler::compare(&a, &b), CompareResult::Equal);
    }

    #[test]
    fn test_compare_before_after() {
        let a = ScheduleSequence::parse("0:2i").unwrap();
        let b = ScheduleSequence::parse("0:3i").unwrap();
        assert_eq!(Scheduler::compare(&a, &b), CompareResult::Before);
        assert_eq!(Scheduler::compare(&b, &a), CompareResult::After);
    }

    #[test]
    fn test_compare_unrelated() {
        let a = ScheduleSequence::parse("0:3i").unwrap();
        let b = ScheduleSequence::parse("1:3i").unwrap();
        assert_eq!(Scheduler::compare(&a, &b), CompareResult::Unrelated);
    }

    #[test]
    fn test_tick_step() {
        let ts = TickStep::new(5);
        assert_eq!(ts.snap, 5);
    }

    #[test]
    fn test_patch_step() {
        let ps = PatchStep::new(1, 0x400000, vec![0x90, 0x90]);
        assert_eq!(ps.snap, 1);
        assert_eq!(ps.address, 0x400000);
        assert_eq!(ps.data, vec![0x90, 0x90]);
    }
}
