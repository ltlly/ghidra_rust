//! ClangBreak -- a line break in decompiler output.
//!
//! Port of Ghidra's `ghidra.app.decompiler.ClangBreak`.
//!
//! In Ghidra's Java code, `ClangBreak` is a subclass of `ClangToken` that
//! represents a line break plus indentation for the next line.  In Rust,
//! `ClangBreak` is already represented as a `ClangNodeKind::Break(ClangBreakData)`
//! variant in the arena.
//!
//! This module provides the `ClangBreakData` struct and additional
//! convenience methods.

use super::clang_node::ClangBreakData;

impl ClangBreakData {
    /// Create a new line break with the given indent level.
    pub fn new(indent: i32) -> Self {
        Self { indent }
    }

    /// Create a line break with zero indent.
    pub fn zero_indent() -> Self {
        Self { indent: 0 }
    }

    /// Get the indentation level (number of indent units after this break).
    pub fn get_indent(&self) -> i32 {
        self.indent
    }

    /// Set the indentation level.
    pub fn set_indent(&mut self, indent: i32) {
        self.indent = indent;
    }

    /// Get the indentation string for this break (4 spaces per indent level).
    pub fn indent_string(&self) -> String {
        let level = self.indent.max(0) as usize;
        "    ".repeat(level)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clang_break_new() {
        let b = ClangBreakData::new(3);
        assert_eq!(b.get_indent(), 3);
        assert_eq!(b.indent_string(), "            "); // 3*4 spaces
    }

    #[test]
    fn test_clang_break_zero_indent() {
        let b = ClangBreakData::zero_indent();
        assert_eq!(b.get_indent(), 0);
        assert_eq!(b.indent_string(), "");
    }

    #[test]
    fn test_clang_break_set_indent() {
        let mut b = ClangBreakData::new(0);
        b.set_indent(2);
        assert_eq!(b.get_indent(), 2);
        assert_eq!(b.indent_string(), "        "); // 2*4 spaces
    }

    #[test]
    fn test_clang_break_negative_indent_clamped() {
        let b = ClangBreakData::new(-1);
        assert_eq!(b.indent_string(), ""); // negative clamped to 0
    }
}
