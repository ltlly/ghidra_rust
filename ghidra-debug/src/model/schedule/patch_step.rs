//! PatchStep - a step that applies a sleigh patch to machine state.
//!
//! Ported from Ghidra's `PatchStep` class.

use serde::{Deserialize, Serialize};

use super::compare_result::CompareResult;
use super::tick_step::StepType;
use super::trace_schedule_full::TimeRadix;

/// A step that applies a Sleigh code patch to machine state.
///
/// Ported from Ghidra's `PatchStep`. Unlike tick and skip steps,
/// a patch step modifies register or memory state using a line of
/// Sleigh code, e.g., `{r0=0x1234}` or `{*0x400000:4=0xdeadbeef}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PatchStep {
    /// The key of the thread in the trace, or -1 for the "last thread".
    pub thread_key: i64,
    /// The Sleigh expression to execute (without braces).
    pub sleigh: String,
}

impl PatchStep {
    /// Create a new patch step.
    pub fn new(thread_key: i64, sleigh: impl Into<String>) -> Self {
        Self {
            thread_key,
            sleigh: sleigh.into(),
        }
    }

    /// Parse a patch step from a string specification.
    ///
    /// The spec must be brace-enclosed: `{sleigh_code}`.
    pub fn parse(thread_key: i64, spec: &str) -> Result<Self, String> {
        if !spec.starts_with('{') || !spec.ends_with('}') {
            return Err(format!("Cannot parse patch step: '{}'", spec));
        }
        Ok(Self::new(thread_key, &spec[1..spec.len() - 1]))
    }

    /// The step type.
    pub fn step_type(&self) -> StepType {
        StepType::Patch
    }

    /// Whether this is a no-op.
    pub fn is_nop(&self) -> bool {
        self.sleigh.is_empty()
    }

    /// Get the thread key.
    pub fn thread_key(&self) -> i64 {
        self.thread_key
    }

    /// Whether this step applies to the event thread.
    pub fn is_event_thread(&self) -> bool {
        self.thread_key == -1
    }

    /// Get the tick count (always 0 for patch steps, philosophically).
    pub fn tick_count(&self) -> u64 {
        0
    }

    /// Get the skip count (always 0 for patch steps).
    pub fn skip_count(&self) -> u64 {
        0
    }

    /// Get the patch count (always 1 for patch steps).
    pub fn patch_count(&self) -> u64 {
        1
    }

    /// Patch steps are never compatible (never combined).
    pub fn is_compatible(&self, _other: &PatchStep) -> bool {
        false
    }

    /// Rewind by the given count. Each patch step counts as 1.
    pub fn rewind(&mut self, count: u64) -> i64 {
        count as i64 - 1
    }

    /// Generate a Sleigh line for setting a register value.
    ///
    /// Format: `register=0xvalue`
    pub fn generate_register_sleigh(register: &str, value: &[u8], big_endian: bool) -> String {
        let hex_value = if big_endian {
            bytes_to_hex(value)
        } else {
            let mut reversed = value.to_vec();
            reversed.reverse();
            bytes_to_hex(&reversed)
        };
        format!("{}=0x{}", register, hex_value)
    }

    /// Generate a Sleigh line for writing to memory.
    ///
    /// Format: `*0xaddress:length=0xvalue`
    pub fn generate_memory_sleigh(address: u64, length: usize, value: &[u8], big_endian: bool) -> String {
        let hex_value = if big_endian {
            bytes_to_hex(value)
        } else {
            let mut reversed = value.to_vec();
            reversed.reverse();
            bytes_to_hex(&reversed)
        };
        format!("*0x{:x}:{}=0x{}", address, length, hex_value)
    }

    /// Generate a Sleigh goto statement.
    pub fn generate_goto_sleigh(address: u64) -> String {
        format!("goto 0x{:x}", address)
    }

    /// Format the step with optional thread prefix.
    pub fn to_string_with_radix(&self, _radix: &TimeRadix) -> String {
        if self.thread_key == -1 {
            format!("{{{}}}", self.sleigh)
        } else {
            format!("t{}-{{{}}}", self.thread_key, self.sleigh)
        }
    }

    /// Richly compare this patch step to another.
    pub fn compare_step(&self, other: &PatchStep) -> CompareResult {
        let type_cmp = self.step_type().cmp(&other.step_type());
        if type_cmp != std::cmp::Ordering::Equal {
            return CompareResult::unrelated(type_cmp);
        }
        let thread_cmp = self.thread_key.cmp(&other.thread_key);
        if thread_cmp != std::cmp::Ordering::Equal {
            return CompareResult::unrelated(thread_cmp);
        }
        CompareResult::unrelated(self.sleigh.cmp(&other.sleigh))
    }
}

impl std::fmt::Display for PatchStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string_with_radix(&TimeRadix::default()))
    }
}

fn bytes_to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_patch_step_new() {
        let step = PatchStep::new(1, "r0=0x1234");
        assert_eq!(step.thread_key, 1);
        assert_eq!(step.sleigh, "r0=0x1234");
        assert!(!step.is_nop());
    }

    #[test]
    fn test_patch_step_parse() {
        let step = PatchStep::parse(1, "{r0=0x1234}").unwrap();
        assert_eq!(step.thread_key, 1);
        assert_eq!(step.sleigh, "r0=0x1234");

        assert!(PatchStep::parse(1, "r0=0x1234").is_err());
    }

    #[test]
    fn test_patch_step_nop() {
        let step = PatchStep::new(1, "");
        assert!(step.is_nop());
    }

    #[test]
    fn test_patch_step_display() {
        let step = PatchStep::new(1, "r0=0x1234");
        assert_eq!(step.to_string(), "t1-{r0=0x1234}");

        let step = PatchStep::new(-1, "r0=0x1234");
        assert_eq!(step.to_string(), "{r0=0x1234}");
    }

    #[test]
    fn test_patch_step_counts() {
        let step = PatchStep::new(1, "r0=0x1234");
        assert_eq!(step.tick_count(), 0);
        assert_eq!(step.skip_count(), 0);
        assert_eq!(step.patch_count(), 1);
    }

    #[test]
    fn test_patch_step_not_compatible() {
        let a = PatchStep::new(1, "r0=0x1");
        let b = PatchStep::new(1, "r0=0x2");
        assert!(!a.is_compatible(&b));
    }

    #[test]
    fn test_patch_step_rewind() {
        let mut step = PatchStep::new(1, "r0=0x1");
        let excess = step.rewind(1);
        assert_eq!(excess, 0);

        let excess = step.rewind(3);
        assert_eq!(excess, 2);
    }

    #[test]
    fn test_generate_register_sleigh() {
        let s = PatchStep::generate_register_sleigh("r0", &[0x12, 0x34], true);
        assert_eq!(s, "r0=0x1234");
    }

    #[test]
    fn test_generate_memory_sleigh() {
        let s = PatchStep::generate_memory_sleigh(0x400000, 4, &[0xde, 0xad, 0xbe, 0xef], true);
        assert_eq!(s, "*0x400000:4=0xdeadbeef");
    }

    #[test]
    fn test_generate_goto_sleigh() {
        let s = PatchStep::generate_goto_sleigh(0x401000);
        assert_eq!(s, "goto 0x401000");
    }

    #[test]
    fn test_patch_step_compare() {
        let a = PatchStep::new(1, "r0=0x1");
        let b = PatchStep::new(1, "r0=0x2");
        let c = PatchStep::new(2, "r0=0x1");

        // Same thread, different sleigh
        let cmp = a.compare_step(&b);
        assert!(!cmp.related);

        // Different thread
        let cmp = a.compare_step(&c);
        assert!(!cmp.related);
    }
}
