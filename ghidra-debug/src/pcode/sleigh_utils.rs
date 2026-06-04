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
}
