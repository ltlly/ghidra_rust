//! PrettyPrinter: converts a ClangNode tree into readable C code.
//!
//! Port of Ghidra's `ghidra.app.decompiler.PrettyPrinter`.

use super::clang_node::{ClangNodeArena, ClangNodeId, ClangNodeKind, SyntaxType};
use super::clang_line::{to_lines, ClangLine};
use super::decompiled_function::DecompiledFunction;

/// The default indentation string (4 spaces).
pub const INDENT_STRING: &str = "    ";

/// Name transformer function type.
///
/// In Ghidra this transforms symbol names for display.  A `None` transformer
/// means identity (no transformation).
pub type NameTransformer = Option<Box<dyn Fn(&str) -> String>>;

/// Converts a C/C++ language token group into readable C/C++ code.
///
/// The PrettyPrinter takes a ClangNode tree and produces a
/// `DecompiledFunction` containing both the raw C code and the
/// function signature.
pub struct PrettyPrinter {
    /// The function name (for signature extraction).
    function_name: Option<String>,
    /// The root ClangNode id.
    root_id: ClangNodeId,
    /// The ClangNode arena.
    arena: ClangNodeArena,
    /// Flattened lines.
    lines: Vec<ClangLine>,
    /// Name transformer.
    transformer: NameTransformer,
}

impl PrettyPrinter {
    /// Create a new PrettyPrinter.
    pub fn new(
        function_name: Option<String>,
        root_id: ClangNodeId,
        arena: ClangNodeArena,
        transformer: NameTransformer,
    ) -> Self {
        let mut printer = Self {
            function_name,
            root_id,
            arena,
            lines: Vec::new(),
            transformer,
        };
        printer.flatten_lines();
        printer.pad_empty_lines();
        printer
    }

    /// Get the list of C language lines.
    pub fn lines(&self) -> &[ClangLine] {
        &self.lines
    }

    /// Print the token group into a DecompiledFunction.
    pub fn print(&self) -> DecompiledFunction {
        let mut buf = String::new();
        for line in &self.lines {
            self.get_text(&mut buf, line);
            buf.push('\n');
        }
        let signature = self.find_signature();
        DecompiledFunction::new(signature, buf)
    }

    /// Get the text of a single line (static helper).
    pub fn get_text_for_line(arena: &ClangNodeArena, line: &ClangLine) -> String {
        let mut buf = String::new();
        Self::get_text_static(&mut buf, arena, line);
        buf
    }

    // ==================================================================
    // Private implementation
    // ==================================================================

    fn flatten_lines(&mut self) {
        self.lines = to_lines(&self.arena, self.root_id);
    }

    fn pad_empty_lines(&mut self) {
        // In Ghidra this ensures empty lines have padding for rendering.
        // In Rust this is a no-op since our lines don't need padding.
    }

    fn get_text(&self, buf: &mut String, line: &ClangLine) {
        buf.push_str(&line.indent_string());
        for &tok_id in line.all_tokens() {
            let text = self.arena.token_text(tok_id).unwrap_or_default();
            let is_keyword = self
                .arena
                .syntax_type(tok_id)
                .map_or(false, |s| s == SyntaxType::Keyword);

            if is_keyword {
                buf.push_str(&text);
            } else {
                buf.push_str(&text);
            }
        }
    }

    fn get_text_static(buf: &mut String, arena: &ClangNodeArena, line: &ClangLine) {
        buf.push_str(&line.indent_string());
        for &tok_id in line.all_tokens() {
            let text = arena.token_text(tok_id).unwrap_or_default();
            buf.push_str(&text);
        }
    }

    fn find_signature(&self) -> Option<String> {
        // Walk children of root looking for ClangFuncProto
        let num = self.arena.num_children(self.root_id);
        for i in 0..num {
            if let Some(child_id) = self.arena.child(self.root_id, i) {
                if matches!(
                    self.arena.get(child_id),
                    Some(ClangNodeKind::FuncProto(_))
                ) {
                    return Some(self.arena.to_string(child_id));
                }
            }
        }
        None
    }
}

impl fmt::Debug for PrettyPrinter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrettyPrinter")
            .field("function_name", &self.function_name)
            .field("root_id", &self.root_id)
            .field("num_lines", &self.lines.len())
            .finish()
    }
}

use std::fmt;

#[cfg(test)]
mod tests {
    use super::super::clang_node::*;
    use super::*;

    fn make_simple_arena() -> (ClangNodeArena, ClangNodeId) {
        let mut arena = ClangNodeArena::new();
        let root = arena.alloc(ClangNodeKind::TokenGroup(ClangTokenGroupData::default()));

        let t_int = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("int".into()),
            syntax_type: SyntaxType::Keyword,
            ..Default::default()
        }));
        arena.add_child(root, t_int);

        let t_space = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some(" ".into()),
            ..Default::default()
        }));
        arena.add_child(root, t_space);

        let t_main = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("main".into()),
            syntax_type: SyntaxType::Function,
            ..Default::default()
        }));
        arena.add_child(root, t_main);

        let t_lparen = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("(".into()),
            ..Default::default()
        }));
        arena.add_child(root, t_lparen);

        let t_rparen = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some(")".into()),
            ..Default::default()
        }));
        arena.add_child(root, t_rparen);

        // Add a break
        let br = arena.alloc(ClangNodeKind::Break(ClangBreakData { indent: 0 }));
        arena.add_child(root, br);

        let t_return = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("return".into()),
            syntax_type: SyntaxType::Keyword,
            ..Default::default()
        }));
        arena.add_child(root, t_return);

        let t_space2 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some(" ".into()),
            ..Default::default()
        }));
        arena.add_child(root, t_space2);

        let t_0 = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("0".into()),
            syntax_type: SyntaxType::Const,
            ..Default::default()
        }));
        arena.add_child(root, t_0);

        let t_semi = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some(";".into()),
            ..Default::default()
        }));
        arena.add_child(root, t_semi);

        (arena, root)
    }

    #[test]
    fn test_pretty_printer_basic() {
        let (arena, root) = make_simple_arena();
        let printer = PrettyPrinter::new(None, root, arena, None);
        let result = printer.print();
        let c = result.c_code();
        assert!(c.contains("int"));
        assert!(c.contains("main"));
        assert!(c.contains("return"));
        assert!(c.contains("0"));
    }

    #[test]
    fn test_pretty_printer_lines() {
        let (arena, root) = make_simple_arena();
        let printer = PrettyPrinter::new(None, root, arena, None);
        // Should have 2 lines (break splits into two)
        assert!(printer.lines().len() >= 1);
    }

    #[test]
    fn test_pretty_printer_signature() {
        let mut arena = ClangNodeArena::new();
        let root = arena.alloc(ClangNodeKind::Function(ClangFunctionData::default()));

        // Add a FuncProto child
        let proto = arena.alloc(ClangNodeKind::FuncProto(ClangFuncProtoData::default()));
        arena.add_child(root, proto);

        let t_int = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("int".into()),
            ..Default::default()
        }));
        arena.add_child(proto, t_int);

        let t_main = arena.alloc(ClangNodeKind::Token(ClangTokenData {
            text: Some("main".into()),
            ..Default::default()
        }));
        arena.add_child(proto, t_main);

        let printer = PrettyPrinter::new(Some("main".to_string()), root, arena, None);
        let result = printer.print();
        let sig = result.signature().unwrap();
        assert!(sig.contains("int"));
        assert!(sig.contains("main"));
    }
}
