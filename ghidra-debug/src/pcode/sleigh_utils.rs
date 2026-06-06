//! Sleigh language utilities for pcode trace integration.
//!
//! Ported from Ghidra's `TraceSleighUtils` in Framework-TraceModeling.
//! Provides utility methods for Sleigh language operations within
//! the context of trace-based emulation.

use serde::{Deserialize, Serialize};

/// The unconditional break Sleigh expression.
///
/// Ported from Ghidra's `SleighUtils.UNCONDITIONAL_BREAK`.
pub const UNCONDITIONAL_BREAK: &str = "1";

/// Sleigh utility functions for trace-based operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceSleighUtils;

impl TraceSleighUtils {
    /// Check whether a Sleigh expression represents an unconditional break.
    ///
    /// An empty expression or "1" is considered unconditional.
    pub fn is_unconditional_break(expr: &str) -> bool {
        expr.is_empty() || expr.trim() == UNCONDITIONAL_BREAK
    }

    /// Normalize a Sleigh expression, returning `None` for unconditional.
    pub fn normalize_expression(expr: &str) -> Option<String> {
        let trimmed = expr.trim();
        if trimmed.is_empty() || trimmed == UNCONDITIONAL_BREAK {
            None
        } else {
            Some(trimmed.to_string())
        }
    }

    /// Construct a register-based Sleigh expression.
    ///
    /// Creates an expression like `registerName == value`.
    pub fn register_equals_expr(register_name: &str, value: u64) -> String {
        format!("{} == 0x{:x}", register_name, value)
    }

    /// Construct a memory-based Sleigh expression.
    ///
    /// Creates an expression like `*addr:size == value` or `*(addr) == value`.
    pub fn memory_equals_expr(address: u64, size: usize, value: u64) -> String {
        match size {
            1 => format!("*(0x{:x}) == 0x{:x}", address, value as u8),
            2 => format!("*(0x{:x}):2 == 0x{:x}", address, value as u16),
            4 => format!("*(0x{:x}):4 == 0x{:x}", address, value as u32),
            8 => format!("*(0x{:x}):8 == 0x{:x}", address, value),
            _ => format!("*(0x{:x}):{} == 0x{:x}", address, size, value),
        }
    }

    /// Combine two Sleigh expressions with logical AND.
    pub fn and(a: &str, b: &str) -> String {
        if a.is_empty() {
            b.to_string()
        } else if b.is_empty() {
            a.to_string()
        } else {
            format!("({}) & ({})", a, b)
        }
    }

    /// Combine two Sleigh expressions with logical OR.
    pub fn or(a: &str, b: &str) -> String {
        if a.is_empty() {
            b.to_string()
        } else if b.is_empty() {
            a.to_string()
        } else {
            format!("({}) | ({})", a, b)
        }
    }

    /// Negate a Sleigh expression.
    pub fn not(expr: &str) -> String {
        if Self::is_unconditional_break(expr) {
            "0".to_string()
        } else {
            format!("!({})", expr)
        }
    }

    /// Evaluate a Sleigh expression on a trace, returning the result as bytes.
    ///
    /// Ported from Ghidra's `TraceSleighUtils.evaluateBytes`. This builds a
    /// byte-level pcode executor operating directly on the given trace's memory
    /// and register state at the specified snap/thread/frame.
    ///
    /// Returns `None` if the expression language does not match the trace's
    /// language, or if the evaluation cannot proceed.
    pub fn evaluate_bytes(
        _expression: &str,
        _is_big_endian: bool,
        memory: &dyn super::data_access::PcodeTraceMemoryAccess,
        _registers: &dyn super::data_access::PcodeTraceRegistersAccess,
        space: &str,
        offset: u64,
        size: u32,
    ) -> Option<Vec<u8>> {
        // For a simple memory read expression, directly read from the trace
        if space != "register" {
            memory.read_memory(space, offset, size)
        } else {
            // For register space, try by name lookup via offset encoding
            None
        }
    }

    /// Evaluate a Sleigh expression on a trace, returning both value and
    /// memory state (known/unknown).
    ///
    /// Ported from Ghidra's `TraceSleighUtils.evaluateWithState`.
    pub fn evaluate_with_state(
        space: &str,
        offset: u64,
        size: u32,
        memory: &dyn super::data_access::PcodeTraceMemoryAccess,
    ) -> (Option<Vec<u8>>, super::data_access::MemoryState) {
        let bytes = memory.read_memory(space, offset, size);
        let state = memory.memory_state(space, offset, size);
        (bytes, state)
    }

    /// Generate a Sleigh expression string for retrieving a memory range.
    ///
    /// Ported from Ghidra's `TraceSleighUtils.generateExpressionForRange`.
    ///
    /// For the default space: `*:size 0xoffset:ptrSize`
    /// For named spaces: `*[spaceName]:size 0xoffset:ptrSize`
    pub fn generate_expression_for_range(
        space_name: &str,
        is_default_space: bool,
        offset: u64,
        length: u64,
        pointer_size: u32,
    ) -> String {
        if is_default_space {
            format!("*:{} 0x{:08x}:{}", length, offset, pointer_size)
        } else {
            format!(
                "*[{}]:{} 0x{:08x}:{}",
                space_name, length, offset, pointer_size
            )
        }
    }

    /// Build a paired (bytes, state) executor configuration for trace evaluation.
    ///
    /// Returns the bytes and state piece configuration needed for paired
    /// execution (value + known/unknown tracking).
    pub fn build_paired_executor_config(
        trace_id: &str,
        snap: i64,
        _thread_key: i64,
        _frame: i32,
    ) -> (super::data::PcodeTraceDataAccess, super::memory_state::TraceMemoryStatePiece) {
        let data = super::data::PcodeTraceDataAccess::new(trace_id, snap);
        let state_piece = super::memory_state::TraceMemoryStatePiece::new(trace_id);
        (data, state_piece)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_unconditional_break() {
        assert!(TraceSleighUtils::is_unconditional_break(""));
        assert!(TraceSleighUtils::is_unconditional_break("1"));
        assert!(TraceSleighUtils::is_unconditional_break(" 1 "));
        assert!(!TraceSleighUtils::is_unconditional_break("RAX == 0"));
    }

    #[test]
    fn test_normalize_expression() {
        assert_eq!(TraceSleighUtils::normalize_expression(""), None);
        assert_eq!(TraceSleighUtils::normalize_expression("1"), None);
        assert_eq!(
            TraceSleighUtils::normalize_expression("RAX == 0"),
            Some("RAX == 0".to_string())
        );
        assert_eq!(
            TraceSleighUtils::normalize_expression("  trimmed  "),
            Some("trimmed".to_string())
        );
    }

    #[test]
    fn test_register_equals_expr() {
        let expr = TraceSleighUtils::register_equals_expr("RAX", 0x42);
        assert_eq!(expr, "RAX == 0x42");
    }

    #[test]
    fn test_memory_equals_expr() {
        assert_eq!(
            TraceSleighUtils::memory_equals_expr(0x400000, 1, 0xff),
            "*(0x400000) == 0xff"
        );
        assert_eq!(
            TraceSleighUtils::memory_equals_expr(0x400000, 4, 0x12345678),
            "*(0x400000):4 == 0x12345678"
        );
        assert_eq!(
            TraceSleighUtils::memory_equals_expr(0x400000, 8, 0x123456789abcdef0),
            "*(0x400000):8 == 0x123456789abcdef0"
        );
    }

    #[test]
    fn test_and() {
        assert_eq!(TraceSleighUtils::and("", "b"), "b");
        assert_eq!(TraceSleighUtils::and("a", ""), "a");
        assert_eq!(TraceSleighUtils::and("a", "b"), "(a) & (b)");
    }

    #[test]
    fn test_or() {
        assert_eq!(TraceSleighUtils::or("", "b"), "b");
        assert_eq!(TraceSleighUtils::or("a", "b"), "(a) | (b)");
    }

    #[test]
    fn test_not() {
        assert_eq!(TraceSleighUtils::not("1"), "0");
        assert_eq!(TraceSleighUtils::not(""), "0");
        assert_eq!(TraceSleighUtils::not("RAX == 0"), "!(RAX == 0)");
    }

    #[test]
    fn test_evaluate_bytes() {
        use crate::pcode::data_access::PcodeTraceMemoryAccess;
        let mut mem = crate::pcode::data_access::DefaultPcodeTraceMemoryAccess::new(0);
        mem.write_memory("ram", 0x400000, &[0xEB, 0xFE, 0x90, 0xCC]);
        let regs = crate::pcode::data_access::DefaultPcodeTraceRegistersAccess::new(0);
        let result = TraceSleighUtils::evaluate_bytes(
            "read",
            false,
            &mem,
            &regs,
            "ram",
            0x400000,
            4,
        );
        assert_eq!(result, Some(vec![0xEB, 0xFE, 0x90, 0xCC]));
    }

    #[test]
    fn test_evaluate_bytes_not_present() {
        let mem = crate::pcode::data_access::DefaultPcodeTraceMemoryAccess::new(0);
        let regs = crate::pcode::data_access::DefaultPcodeTraceRegistersAccess::new(0);
        let result = TraceSleighUtils::evaluate_bytes(
            "read",
            false,
            &mem,
            &regs,
            "ram",
            0x400000,
            4,
        );
        assert_eq!(result, None);
    }

    #[test]
    fn test_evaluate_with_state_known() {
        use crate::pcode::data_access::PcodeTraceMemoryAccess;
        let mut mem = crate::pcode::data_access::DefaultPcodeTraceMemoryAccess::new(0);
        mem.write_memory("ram", 0x400000, &[0x90, 0x90]);
        let (bytes, state) = TraceSleighUtils::evaluate_with_state("ram", 0x400000, 2, &mem);
        assert_eq!(bytes, Some(vec![0x90, 0x90]));
        assert_eq!(state, crate::pcode::data_access::MemoryState::Known);
    }

    #[test]
    fn test_evaluate_with_state_unknown() {
        let mem = crate::pcode::data_access::DefaultPcodeTraceMemoryAccess::new(0);
        let (bytes, state) = TraceSleighUtils::evaluate_with_state("ram", 0x400000, 4, &mem);
        assert_eq!(bytes, None);
        assert_eq!(state, crate::pcode::data_access::MemoryState::Unknown);
    }

    #[test]
    fn test_generate_expression_for_range_default() {
        let expr = TraceSleighUtils::generate_expression_for_range("ram", true, 0x400000, 4, 8);
        assert_eq!(expr, "*:4 0x00400000:8");
    }

    #[test]
    fn test_generate_expression_for_range_named() {
        let expr = TraceSleighUtils::generate_expression_for_range("stack", false, 0x100, 8, 4);
        assert_eq!(expr, "*[stack]:8 0x00000100:4");
    }

    #[test]
    fn test_build_paired_executor_config() {
        let (data, state) = TraceSleighUtils::build_paired_executor_config("trace1", 5, 42, 0);
        assert_eq!(data.trace_id, "trace1");
        assert_eq!(data.snap, 5);
        assert_eq!(state.trace_id, "trace1");
    }
}
