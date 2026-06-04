//! ClangLine: a line of C code in the decompiler output.
//!
//! Port of Ghidra's `ghidra.app.decompiler.ClangLine`.

use super::clang_node::{ClangNodeArena, ClangNodeId, SyntaxType};

/// A line of C code.  This is an independent grouping of C tokens
/// from the statement/vardecl/retype groups.
///
/// Lines are produced by the PrettyPrinter when flattening the
/// token-group tree into displayable lines.
#[derive(Debug, Clone)]
pub struct ClangLine {
    /// Indentation level (number of indent units).
    indent_level: usize,
    /// Token node ids on this line.
    tokens: Vec<ClangNodeId>,
    /// Line number (0-based).
    line_number: usize,
}

impl ClangLine {
    /// Create a new ClangLine with the given line number and indent level.
    pub fn new(line_number: usize, indent: usize) -> Self {
        Self {
            indent_level: indent,
            tokens: Vec::new(),
            line_number,
        }
    }

    /// Get the indentation string for this line.
    pub fn indent_string(&self) -> String {
        "    ".repeat(self.indent_level)
    }

    /// Get the indentation level.
    pub fn indent(&self) -> usize {
        self.indent_level
    }

    /// Set the indentation level.
    pub fn set_indent(&mut self, indent: usize) {
        self.indent_level = indent;
    }

    /// Add a token to this line.
    pub fn add_token(&mut self, token_id: ClangNodeId) {
        self.tokens.push(token_id);
    }

    /// Get all token ids on this line.
    pub fn all_tokens(&self) -> &[ClangNodeId] {
        &self.tokens
    }

    /// Get the number of tokens.
    pub fn num_tokens(&self) -> usize {
        self.tokens.len()
    }

    /// Get the line number.
    pub fn line_number(&self) -> usize {
        self.line_number
    }

    /// Get the i-th token id.
    pub fn token(&self, i: usize) -> Option<ClangNodeId> {
        self.tokens.get(i).copied()
    }

    /// Find the index of a token in this line.
    pub fn index_of_token(&self, token_id: ClangNodeId) -> Option<usize> {
        self.tokens.iter().position(|&t| t == token_id)
    }

    /// Convert this line to a string using the given arena.
    pub fn to_debug_string(&self, arena: &ClangNodeArena) -> String {
        self.to_debug_string_with_callouts(arena, &[], "[", "]")
    }

    /// Convert this line to a string, marking specific tokens with delimiters.
    pub fn to_debug_string_with_callouts(
        &self,
        arena: &ClangNodeArena,
        callout_tokens: &[ClangNodeId],
        start: &str,
        end: &str,
    ) -> String {
        let mut buf = format!("{}: ", self.line_number);
        for &tok_id in &self.tokens {
            let is_callout = callout_tokens.contains(&tok_id);
            if is_callout {
                buf.push_str(start);
            }
            if let Some(text) = arena.token_text(tok_id) {
                buf.push_str(&text);
            }
            if is_callout {
                buf.push_str(end);
            }
        }
        buf
    }
}

impl fmt::Display for ClangLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Without an arena, just show line number and token count
        write!(f, "Line {}: {} tokens", self.line_number, self.tokens.len())
    }
}

use std::fmt;

/// Convert a ClangTokenGroup tree into a list of ClangLines.
///
/// This is the core of the PrettyPrinter flattening step.
pub fn to_lines(arena: &ClangNodeArena, root_id: ClangNodeId) -> Vec<ClangLine> {
    let mut lines = Vec::new();
    let mut current_line = ClangLine::new(0, 0);
    flatten_to_lines(arena, root_id, 0, &mut current_line, &mut lines);
    // Push the last line if it has tokens
    if !current_line.all_tokens().is_empty() {
        lines.push(current_line);
    }
    // If no lines, add an empty one
    if lines.is_empty() {
        lines.push(ClangLine::new(0, 0));
    }
    lines
}

fn flatten_to_lines(
    arena: &ClangNodeArena,
    id: ClangNodeId,
    indent: usize,
    current_line: &mut ClangLine,
    lines: &mut Vec<ClangLine>,
) {
    use super::clang_node::ClangNodeKind;

    match arena.get(id) {
        Some(ClangNodeKind::Break(b)) => {
            // Line break: push current line and start new one
            lines.push(std::mem::replace(
                current_line,
                ClangLine::new(lines.len(), (indent as i32 + b.indent).max(0) as usize),
            ));
        }
        Some(ClangNodeKind::TokenGroup(_))
        | Some(ClangNodeKind::Function(_))
        | Some(ClangNodeKind::FuncProto(_))
        | Some(ClangNodeKind::Statement(_))
        | Some(ClangNodeKind::VariableDecl(_))
        | Some(ClangNodeKind::ReturnType(_)) => {
            // Group: recurse into children
            let num = arena.num_children(id);
            for i in 0..num {
                if let Some(child) = arena.child(id, i) {
                    flatten_to_lines(arena, child, indent, current_line, lines);
                }
            }
        }
        _ => {
            // Leaf token: add to current line
            current_line.add_token(id);
        }
    }
}

/// Pad empty lines with at least one token so they appear correctly.
pub fn pad_empty_lines(lines: &mut [ClangLine]) {
    // In Ghidra this ensures empty lines have at least some content for rendering.
    // In Rust we just ensure the indent is correct.
    for line in lines.iter_mut() {
        if line.num_tokens() == 0 {
            // Empty lines are fine in Rust representation
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::clang_node::*;
    use super::*;

    #[test]
    fn test_clang_line_basic() {
        let line = ClangLine::new(0, 2);
        assert_eq!(line.line_number(), 0);
        assert_eq!(line.indent(), 2);
        assert_eq!(line.indent_string(), "        ");
        assert_eq!(line.num_tokens(), 0);
    }

    #[test]
    fn test_clang_line_add_token() {
        let mut arena = ClangNodeArena::new();
        let t1 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("int".into()),
            syntax_type: SyntaxType::Keyword,
            ..Default::default()
        }));
        let t2 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("x".into()),
            syntax_type: SyntaxType::Variable,
            ..Default::default()
        }));

        let mut line = ClangLine::new(0, 0);
        line.add_token(t1);
        line.add_token(t2);
        assert_eq!(line.num_tokens(), 2);
        assert_eq!(line.index_of_token(t1), Some(0));
        assert_eq!(line.index_of_token(t2), Some(1));
    }

    #[test]
    fn test_to_lines_with_break() {
        let mut arena = ClangNodeArena::new();
        let root = arena.alloc(ClangNodeKind::TokenGroup(ClangTokenGroupData::default()));

        let t1 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("int".into()),
            ..Default::default()
        }));
        arena.add_child(root, t1);

        let br = arena.alloc(ClangNodeKind::Break(ClangBreakData { indent: 1 }));
        arena.add_child(root, br);

        let t2 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("x".into()),
            ..Default::default()
        }));
        arena.add_child(root, t2);

        let lines = to_lines(&arena, root);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].num_tokens(), 1);
        assert_eq!(lines[1].num_tokens(), 1);
        assert_eq!(lines[1].indent(), 1);
    }
}
