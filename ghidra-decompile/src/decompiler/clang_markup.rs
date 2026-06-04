//! Clang markup builder -- port of Ghidra's `ghidra.app.decompiler.ClangMarkup`.
//!
//! Provides the `build_clang_tree` entry point that parses a serialized
//! Clang AST into an arena-based node tree.

use super::clang_node::{ClangNodeArena, ClangNodeKind, ClangTokenGroupData, ClangFunctionData};

/// Build a Clang AST tree from a serialized representation.
///
/// Port of Ghidra's `ClangMarkup.buildClangTree()`.  In Ghidra this reads
/// from a `Decoder`; here we accept pre-parsed node kinds.
///
/// Returns the root node id and the arena holding all nodes.
pub fn build_clang_tree(
    nodes: Vec<ClangNodeKind>,
    is_function: bool,
) -> (usize, ClangNodeArena) {
    let mut arena = ClangNodeArena::new();

    let root = if is_function {
        arena.alloc(ClangNodeKind::Function(ClangFunctionData::default()))
    } else {
        arena.alloc(ClangNodeKind::TokenGroup(ClangTokenGroupData::default()))
    };

    for node in nodes {
        let child_id = arena.alloc(node);
        arena.add_child(root, child_id);
    }

    (root, arena)
}

/// Parse a flat list of text tokens into a Clang tree.
///
/// This is a convenience function for building a simple Clang tree from
/// plain text tokens without going through the full decoder.
pub fn build_clang_tree_from_tokens(tokens: &[&str]) -> (usize, ClangNodeArena) {
    use super::clang_node::{ClangTokenData, SyntaxType};

    let mut arena = ClangNodeArena::new();
    let root = arena.alloc(ClangNodeKind::TokenGroup(ClangTokenGroupData::default()));

    for token_text in tokens {
        let syntax = if is_keyword(token_text) {
            SyntaxType::Keyword
        } else if is_type_name(token_text) {
            SyntaxType::Type
        } else {
            SyntaxType::Default
        };

        let node = ClangNodeKind::Token(ClangTokenData {
            text: Some(token_text.to_string()),
            syntax_type: syntax,
            ..Default::default()
        });
        let child_id = arena.alloc(node);
        arena.add_child(root, child_id);
    }

    (root, arena)
}

/// Simple keyword detection.
fn is_keyword(s: &str) -> bool {
    matches!(
        s,
        "if" | "else"
            | "while"
            | "for"
            | "do"
            | "switch"
            | "case"
            | "break"
            | "continue"
            | "return"
            | "goto"
            | "default"
            | "sizeof"
            | "typedef"
            | "struct"
            | "union"
            | "enum"
            | "const"
            | "volatile"
            | "static"
            | "extern"
            | "register"
            | "auto"
            | "void"
            | "unsigned"
            | "signed"
            | "long"
            | "short"
    )
}

/// Simple type-name detection.
fn is_type_name(s: &str) -> bool {
    matches!(
        s,
        "int" | "char" | "float" | "double" | "bool" | "uint" | "uchar" | "ulong"
    ) || (s.chars().next().map(|c| c.is_uppercase()).unwrap_or(false)
        && s.len() > 1
        && !s.contains(' '))
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::clang_node::{ClangBreakData, ClangTokenData, SyntaxType};

    #[test]
    fn test_build_clang_tree_empty() {
        let (root, arena) = build_clang_tree(vec![], false);
        assert_eq!(arena.num_children(root), 0);
    }

    #[test]
    fn test_build_clang_tree_as_function() {
        let nodes = vec![
            ClangNodeKind::Token(ClangTokenData {
                text: Some("int".into()),
                syntax_type: SyntaxType::Keyword,
                ..Default::default()
            }),
        ];
        let (root, arena) = build_clang_tree(nodes, true);
        assert!(matches!(arena.get(root), Some(ClangNodeKind::Function(_))));
        assert_eq!(arena.num_children(root), 1);
    }

    #[test]
    fn test_build_clang_tree_as_group() {
        let nodes = vec![
            ClangNodeKind::Token(ClangTokenData {
                text: Some("x".into()),
                ..Default::default()
            }),
        ];
        let (root, arena) = build_clang_tree(nodes, false);
        assert!(matches!(
            arena.get(root),
            Some(ClangNodeKind::TokenGroup(_))
        ));
    }

    #[test]
    fn test_build_clang_tree_from_tokens() {
        let tokens = vec!["int", "main", "(", ")", "{", "return", "0", ";", "}"];
        let (root, arena) = build_clang_tree_from_tokens(&tokens);
        assert_eq!(arena.num_children(root), 9);
    }

    #[test]
    fn test_is_keyword() {
        assert!(is_keyword("if"));
        assert!(is_keyword("return"));
        assert!(!is_keyword("myvar"));
        assert!(!is_keyword("printf"));
    }

    #[test]
    fn test_is_type_name() {
        assert!(is_type_name("int"));
        assert!(is_type_name("char"));
        assert!(is_type_name("MyStruct"));
        assert!(!is_type_name("myvar"));
        assert!(!is_type_name("x"));
    }

    #[test]
    fn test_build_tree_with_break_and_tokens() {
        let nodes = vec![
            ClangNodeKind::Token(ClangTokenData {
                text: Some("int".into()),
                syntax_type: SyntaxType::Keyword,
                ..Default::default()
            }),
            ClangNodeKind::Break(ClangBreakData { indent: 1 }),
            ClangNodeKind::Token(ClangTokenData {
                text: Some("x".into()),
                syntax_type: SyntaxType::Variable,
                ..Default::default()
            }),
        ];
        let (root, arena) = build_clang_tree(nodes, false);
        assert_eq!(arena.num_children(root), 3);
    }
}
