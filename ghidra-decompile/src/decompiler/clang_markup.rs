#![allow(dead_code)]
//! Clang markup builder -- port of Ghidra's `ghidra.app.decompiler.ClangMarkup`.
//!
//! Provides the `build_clang_tree` entry point that parses a serialized
//! Clang AST into an arena-based node tree.
//!
//! Also provides a lightweight XML-tag parser (`MarkupParser`) that converts
//! decompiler output markup into a ClangNodeArena.

use super::clang_node::{ClangNodeArena, ClangNodeKind, ClangTokenGroupData, ClangFunctionData};

// ============================================================================
// MarkupParser — XML-like tag parser for decompiler output
// ============================================================================

/// Errors during markup parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarkupError {
    /// Unexpected end of input.
    UnexpectedEof,
    /// Malformed tag.
    MalformedTag(String),
    /// Unknown tag name.
    UnknownTag(String),
}

impl std::fmt::Display for MarkupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MarkupError::UnexpectedEof => write!(f, "unexpected end of markup"),
            MarkupError::MalformedTag(s) => write!(f, "malformed tag: {}", s),
            MarkupError::UnknownTag(s) => write!(f, "unknown tag: {}", s),
        }
    }
}

impl std::error::Error for MarkupError {}

/// A lightweight XML-like markup parser for decompiler output.
///
/// Parses tags like `<funcname>`, `<variable>`, `<syntax>`, etc. and builds
/// a ClangNodeArena tree.
pub struct MarkupParser;

impl MarkupParser {
    /// Parse markup text into a ClangNodeArena.
    pub fn parse(markup: &str) -> Result<(ClangNodeArena, usize), MarkupError> {
        let mut arena = ClangNodeArena::new();
        if markup.is_empty() {
            let root = arena.alloc(ClangNodeKind::TokenGroup(ClangTokenGroupData::default()));
            return Ok((arena, root));
        }
        let elements = Self::parse_tags(markup)?;
        let root = Self::build_arena(&mut arena, &elements)?;
        Ok((arena, root))
    }

    fn parse_tags(input: &str) -> Result<Vec<ParsedTag>, MarkupError> {
        let mut tags = Vec::new();
        let mut pos = 0;
        let bytes = input.as_bytes();

        while pos < bytes.len() {
            if bytes[pos] == b'<' {
                // Find closing >
                let close = input[pos..].find('>').ok_or_else(|| {
                    MarkupError::MalformedTag("unclosed <".into())
                })?;
                let tag_content = &input[pos + 1..pos + close];
                let full_end = pos + close + 1;

                // Self-closing
                if tag_content.ends_with('/') {
                    let name = tag_content[..tag_content.len() - 1].trim();
                    tags.push(ParsedTag::SelfClosing(name.to_string()));
                    pos = full_end;
                    continue;
                }

                // Closing tag
                if tag_content.starts_with('/') {
                    tags.push(ParsedTag::Close(tag_content[1..].trim().to_string()));
                    pos = full_end;
                    continue;
                }

                // Opening tag — find the matching close
                let name = tag_content.split_whitespace().next().unwrap_or(tag_content);
                let close_tag = format!("</{}>", name);
                let content_start = full_end;
                let content_end = input[content_start..]
                    .find(&close_tag)
                    .map(|p| content_start + p)
                    .unwrap_or(input.len());
                let content = &input[content_start..content_end];
                let children = Self::parse_tags(content)?;
                tags.push(ParsedTag::Open {
                    name: name.to_string(),
                    children,
                });
                pos = content_end + close_tag.len();
            } else {
                // Plain text
                let end = input[pos..].find('<').unwrap_or(input.len() - pos);
                let text = &input[pos..pos + end];
                if !text.is_empty() {
                    tags.push(ParsedTag::Text(text.to_string()));
                }
                pos += end;
            }
        }
        Ok(tags)
    }

    fn build_arena(
        arena: &mut ClangNodeArena,
        elements: &[ParsedTag],
    ) -> Result<usize, MarkupError> {
        if elements.len() == 1 {
            return Self::build_element(arena, &elements[0]);
        }
        let group = arena.alloc(ClangNodeKind::TokenGroup(ClangTokenGroupData::default()));
        for elem in elements {
            let child = Self::build_element(arena, elem)?;
            arena.add_child(group, child);
        }
        Ok(group)
    }

    fn build_element(
        arena: &mut ClangNodeArena,
        elem: &ParsedTag,
    ) -> Result<usize, MarkupError> {
        use super::clang_node::*;
        match elem {
            ParsedTag::Text(s) => Ok(arena.alloc(ClangNodeKind::Token(ClangTokenData {
                text: Some(s.clone()),
                syntax_type: SyntaxType::Default,
                ..Default::default()
            }))),
            ParsedTag::SelfClosing(name) => match name.as_str() {
                "break" => Ok(arena.alloc(ClangNodeKind::Break(ClangBreakData { indent: 0 }))),
                _ => Err(MarkupError::UnknownTag(name.clone())),
            },
            ParsedTag::Open { name, children } => {
                let text = Self::extract_text(children);
                let id = match name.as_str() {
                    "function" => {
                        let id = arena.alloc(ClangNodeKind::Function(ClangFunctionData::default()));
                        for child in children {
                            let cid = Self::build_element(arena, child)?;
                            arena.add_child(id, cid);
                        }
                        return Ok(id);
                    }
                    "funcproto" => {
                        let id = arena.alloc(ClangNodeKind::FuncProto(ClangFuncProtoData::default()));
                        for child in children {
                            let cid = Self::build_element(arena, child)?;
                            arena.add_child(id, cid);
                        }
                        return Ok(id);
                    }
                    "statement" => {
                        let id = arena.alloc(ClangNodeKind::Statement(ClangStatementData::default()));
                        for child in children {
                            let cid = Self::build_element(arena, child)?;
                            arena.add_child(id, cid);
                        }
                        return Ok(id);
                    }
                    "vardecl" => {
                        let id = arena.alloc(ClangNodeKind::VariableDecl(ClangVariableDeclData::default()));
                        for child in children {
                            let cid = Self::build_element(arena, child)?;
                            arena.add_child(id, cid);
                        }
                        return Ok(id);
                    }
                    "return_type" => {
                        let id = arena.alloc(ClangNodeKind::ReturnType(ClangReturnTypeData::default()));
                        for child in children {
                            let cid = Self::build_element(arena, child)?;
                            arena.add_child(id, cid);
                        }
                        return Ok(id);
                    }
                    "syntax" => ClangNodeKind::SyntaxToken(ClangSyntaxTokenData {
                        token: ClangTokenData { text: Some(text), syntax_type: SyntaxType::Default, ..Default::default() },
                        open: -1, close: -1, is_variable_ref: false,
                    }),
                    "variable" => ClangNodeKind::VariableToken(ClangVariableTokenData {
                        token: ClangTokenData { text: Some(text), syntax_type: SyntaxType::Variable, ..Default::default() },
                        ..Default::default()
                    }),
                    "funcname" => ClangNodeKind::FuncNameToken(ClangFuncNameTokenData {
                        token: ClangTokenData { text: Some(text), syntax_type: SyntaxType::Function, ..Default::default() },
                        ..Default::default()
                    }),
                    "field" => ClangNodeKind::FieldToken(ClangFieldTokenData {
                        token: ClangTokenData { text: Some(text), syntax_type: SyntaxType::Field, ..Default::default() },
                        ..Default::default()
                    }),
                    "type" => ClangNodeKind::TypeToken(ClangTypeTokenData {
                        token: ClangTokenData { text: Some(text), syntax_type: SyntaxType::Type, ..Default::default() },
                    }),
                    "comment" => ClangNodeKind::CommentToken(ClangCommentTokenData {
                        token: ClangTokenData { text: Some(text), syntax_type: SyntaxType::Comment, ..Default::default() },
                        source_address: None,
                    }),
                    "label" => ClangNodeKind::LabelToken(ClangLabelTokenData {
                        token: ClangTokenData { text: Some(text.clone()), syntax_type: SyntaxType::Default, ..Default::default() },
                        block_address: ghidra_core::addr::Address::NULL,
                    }),
                    "case" => {
                        let val = text.parse::<i64>().unwrap_or(0);
                        ClangNodeKind::CaseToken(ClangCaseTokenData {
                            token: ClangTokenData { text: Some(text), syntax_type: SyntaxType::Keyword, ..Default::default() },
                            value: val, ..Default::default()
                        })
                    }
                    other => return Err(MarkupError::UnknownTag(other.to_string())),
                };
                Ok(arena.alloc(id))
            }
            ParsedTag::Close(_) => Ok(0), // handled during Open parsing
        }
    }

    fn extract_text(elements: &[ParsedTag]) -> String {
        let mut result = String::new();
        for elem in elements {
            match elem {
                ParsedTag::Text(s) => result.push_str(s),
                ParsedTag::Open { children, .. } => result.push_str(&Self::extract_text(children)),
                _ => {}
            }
        }
        result
    }
}

#[derive(Debug)]
enum ParsedTag {
    Text(String),
    Open { name: String, children: Vec<ParsedTag> },
    Close(#[allow(dead_code)] String),
    SelfClosing(String),
}

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

    // -- MarkupParser tests --

    #[test]
    fn markup_parser_empty() {
        let (arena, root) = MarkupParser::parse("").unwrap();
        assert_eq!(arena.num_children(root), 0);
    }

    #[test]
    fn markup_parser_plain_text() {
        let (arena, root) = MarkupParser::parse("hello world").unwrap();
        let text = arena.token_text(root);
        assert_eq!(text.as_deref(), Some("hello world"));
    }

    #[test]
    fn markup_parser_syntax_token() {
        let (arena, root) = MarkupParser::parse("<syntax>return</syntax>").unwrap();
        assert_eq!(arena.token_text(root).as_deref(), Some("return"));
    }

    #[test]
    fn markup_parser_variable_token() {
        let (arena, root) = MarkupParser::parse("<variable>x</variable>").unwrap();
        assert_eq!(arena.token_text(root).as_deref(), Some("x"));
        assert_eq!(arena.syntax_type(root), Some(SyntaxType::Variable));
    }

    #[test]
    fn markup_parser_funcname_token() {
        let (arena, root) = MarkupParser::parse("<funcname>main</funcname>").unwrap();
        assert_eq!(arena.token_text(root).as_deref(), Some("main"));
        assert_eq!(arena.syntax_type(root), Some(SyntaxType::Function));
    }

    #[test]
    fn markup_parser_type_token() {
        let (arena, root) = MarkupParser::parse("<type>int</type>").unwrap();
        assert_eq!(arena.token_text(root).as_deref(), Some("int"));
        assert_eq!(arena.syntax_type(root), Some(SyntaxType::Type));
    }

    #[test]
    fn markup_parser_comment_token() {
        let (arena, root) = MarkupParser::parse("<comment>/* hello */</comment>").unwrap();
        assert_eq!(arena.token_text(root).as_deref(), Some("/* hello */"));
        assert_eq!(arena.syntax_type(root), Some(SyntaxType::Comment));
    }

    #[test]
    fn markup_parser_field_token() {
        let (arena, root) = MarkupParser::parse("<field>length</field>").unwrap();
        assert_eq!(arena.token_text(root).as_deref(), Some("length"));
        assert_eq!(arena.syntax_type(root), Some(SyntaxType::Field));
    }

    #[test]
    fn markup_parser_function_group() {
        let markup = "<function><syntax>int</syntax> <funcname>main</funcname>()</function>";
        let (arena, root) = MarkupParser::parse(markup).unwrap();
        assert_eq!(arena.num_children(root), 4);
        let text = arena.to_string(root);
        assert!(text.contains("int"));
        assert!(text.contains("main"));
    }

    #[test]
    fn markup_parser_statement_group() {
        let markup = "<statement><variable>x</variable> <syntax>=</syntax> <syntax>5</syntax>;</statement>";
        let (arena, root) = MarkupParser::parse(markup).unwrap();
        assert!(arena.num_children(root) > 0);
    }

    #[test]
    fn markup_parser_unknown_tag_errors() {
        assert!(MarkupParser::parse("<bogus>text</bogus>").is_err());
    }

    #[test]
    fn markup_parser_mixed_tokens() {
        let markup = concat!(
            "<syntax>int</syntax> ",
            "<funcname>foo</funcname>(",
            "<type>char</type> ",
            "<variable>s</variable>",
            ")"
        );
        let (arena, root) = MarkupParser::parse(markup).unwrap();
        let text = arena.to_string(root);
        assert!(text.contains("int"));
        assert!(text.contains("foo"));
        assert!(text.contains("char"));
        assert!(text.contains("s"));
    }

    #[test]
    fn markup_parser_label_token() {
        let (arena, root) = MarkupParser::parse("<label>LABEL_1000</label>").unwrap();
        assert_eq!(arena.token_text(root).as_deref(), Some("LABEL_1000"));
    }

    #[test]
    fn markup_parser_case_token() {
        let (arena, root) = MarkupParser::parse("<case>42</case>").unwrap();
        assert_eq!(arena.token_text(root).as_deref(), Some("42"));
        assert_eq!(arena.syntax_type(root), Some(SyntaxType::Keyword));
    }

    #[test]
    fn markup_parser_nested_groups() {
        let markup = "<function><funcproto><type>void</type> <funcname>bar</funcname>()</funcproto></function>";
        let (arena, root) = MarkupParser::parse(markup).unwrap();
        let proto = arena.child(root, 0).unwrap();
        let text = arena.to_string(proto);
        assert!(text.contains("void"));
        assert!(text.contains("bar"));
    }
}
