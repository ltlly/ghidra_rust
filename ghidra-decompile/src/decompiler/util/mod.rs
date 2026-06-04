//! Decompiler utilities.
//!
//! Port of Ghidra's `ghidra.app.decompiler.util` package.

use super::clang_node::{ClangNodeArena, ClangNodeId};
use super::clang_line::ClangLine;

/// Convert a ClangNode tree into a list of ClangLines.
///
/// This is a convenience wrapper around `clang_line::to_lines`.
pub fn to_lines(arena: &ClangNodeArena, root_id: ClangNodeId) -> Vec<ClangLine> {
    super::clang_line::to_lines(arena, root_id)
}

/// Extract the plain text from a ClangNode tree.
pub fn to_plain_text(arena: &ClangNodeArena, root_id: ClangNodeId) -> String {
    let lines = to_lines(arena, root_id);
    let mut buf = String::new();
    for line in &lines {
        buf.push_str(&line.indent_string());
        for &tok_id in line.all_tokens() {
            if let Some(text) = arena.token_text(tok_id) {
                buf.push_str(&text);
            }
        }
        buf.push('\n');
    }
    buf
}

/// Find the ClangNodeId of the token at the given line and column.
pub fn find_token_at(
    arena: &ClangNodeArena,
    root_id: ClangNodeId,
    target_line: usize,
    target_column: usize,
) -> Option<ClangNodeId> {
    let lines = to_lines(arena, root_id);
    let line = lines.get(target_line)?;
    let mut column = 0usize;
    for &tok_id in line.all_tokens() {
        let text = arena.token_text(tok_id).unwrap_or_default();
        let end_column = column + text.len();
        if target_column >= column && target_column < end_column {
            return Some(tok_id);
        }
        column = end_column;
    }
    None
}

/// Calculate the display width of a line.
pub fn line_display_width(arena: &ClangNodeArena, line: &ClangLine) -> usize {
    let indent_width = line.indent();
    let text_width: usize = line
        .all_tokens()
        .iter()
        .map(|&tok_id| arena.token_text(tok_id).map_or(0, |t| t.len()))
        .sum();
    indent_width + text_width
}

#[cfg(test)]
mod tests {
    use super::super::clang_node::*;
    use super::*;

    fn make_arena() -> (ClangNodeArena, ClangNodeId) {
        let mut arena = ClangNodeArena::new();
        let root = arena.alloc(ClangNodeKind::TokenGroup(ClangTokenGroupData::default()));

        let t1 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("int".into()),
            ..Default::default()
        }));
        arena.add_child(root, t1);

        let t2 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some(" ".into()),
            ..Default::default()
        }));
        arena.add_child(root, t2);

        let t3 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("x".into()),
            ..Default::default()
        }));
        arena.add_child(root, t3);

        let t4 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some(";".into()),
            ..Default::default()
        }));
        arena.add_child(root, t4);

        (arena, root)
    }

    #[test]
    fn test_to_lines() {
        let (arena, root) = make_arena();
        let lines = to_lines(&arena, root);
        assert!(!lines.is_empty());
    }

    #[test]
    fn test_to_plain_text() {
        let (arena, root) = make_arena();
        let text = to_plain_text(&arena, root);
        assert!(text.contains("int"));
        assert!(text.contains("x"));
    }

    #[test]
    fn test_find_token_at() {
        let (arena, root) = make_arena();
        // "int x;" -> column 0-2 is "int", column 3 is " ", column 4 is "x", column 5 is ";"
        let tok = find_token_at(&arena, root, 0, 4);
        assert!(tok.is_some());
    }
}
