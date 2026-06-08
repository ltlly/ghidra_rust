//! Decompiler panel -- Rust port of the rendering component of
//! `ghidra.app.plugin.core.decompile.DecompilerPanel`.
//!
//! Models the line/token representation of decompiled C output.
//! The panel displays a list of [`DecompiledLine`]s, each containing
//! a sequence of [`DecompiledToken`]s. It supports navigation,
//! cursor positioning, and highlighting.
//!
//! This module does not perform actual decompilation -- it models the
//! data structure that the decompiler panel uses to render output.

use ghidra_core::addr::Address;

// ---------------------------------------------------------------------------
// DecompiledToken
// ---------------------------------------------------------------------------

/// A single token in the decompiled output.
///
/// Tokens are the smallest displayable units: keywords, variable names,
/// operators, literals, etc.
#[derive(Debug, Clone)]
pub struct DecompiledToken {
    /// The displayed text.
    pub text: String,
    /// The token type (determines coloring).
    pub token_type: DecompiledTokenType,
    /// The source address this token refers to (if any).
    pub address: Option<Address>,
    /// The variable/symbol this token names (if applicable).
    pub symbol_id: Option<u64>,
    /// Byte offset of this token within the full decompiled text.
    pub text_offset: usize,
    /// Column position within the line.
    pub col: usize,
    /// Whether this token is currently highlighted.
    pub highlighted: bool,
    /// Whether this token is currently selected.
    pub selected: bool,
}

/// The type of a decompiled token, used for syntax coloring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecompiledTokenType {
    /// A keyword (if, while, return, etc.).
    Keyword,
    /// A type name (int, char, struct, etc.).
    TypeName,
    /// A function name.
    FunctionName,
    /// A variable name.
    Variable,
    /// A field name (struct/union member).
    FieldName,
    /// A label (goto target).
    Label,
    /// An operator (+, -, *, etc.).
    Operator,
    /// A literal value (number, string, char).
    Literal,
    /// A comment.
    Comment,
    /// A separator (parentheses, braces, semicolons).
    Separator,
    /// A space or whitespace.
    Whitespace,
    /// A bit field token.
    BitField,
    /// A syntax token (generic).
    Syntax,
}

impl DecompiledToken {
    /// Create a new token.
    pub fn new(
        text: impl Into<String>,
        token_type: DecompiledTokenType,
        col: usize,
        text_offset: usize,
    ) -> Self {
        Self {
            text: text.into(),
            token_type,
            address: None,
            symbol_id: None,
            text_offset,
            col,
            highlighted: false,
            selected: false,
        }
    }

    /// Set the source address for this token.
    pub fn with_address(mut self, addr: Address) -> Self {
        self.address = Some(addr);
        self
    }

    /// Set the symbol ID for this token.
    pub fn with_symbol_id(mut self, id: u64) -> Self {
        self.symbol_id = Some(id);
        self
    }

    /// Check if this token is a variable.
    pub fn is_variable(&self) -> bool {
        self.token_type == DecompiledTokenType::Variable
    }

    /// Check if this token is a function name.
    pub fn is_function_name(&self) -> bool {
        self.token_type == DecompiledTokenType::FunctionName
    }

    /// Get the display length of the token text.
    pub fn display_len(&self) -> usize {
        self.text.len()
    }
}

// ---------------------------------------------------------------------------
// DecompiledLine
// ---------------------------------------------------------------------------

/// A single line of decompiled output.
///
/// Each line has a line number, indentation level, address information,
/// and a sequence of tokens.
#[derive(Debug, Clone)]
pub struct DecompiledLine {
    /// The 1-based line number.
    pub line_number: usize,
    /// The indentation level (number of 4-space indents).
    pub indent_level: usize,
    /// The primary source address for this line.
    pub address: Option<Address>,
    /// The function entry point this line belongs to.
    pub function_entry: Option<Address>,
    /// Tokens on this line.
    pub tokens: Vec<DecompiledToken>,
    /// Whether this line contains a breakpoint.
    pub has_breakpoint: bool,
    /// Whether this line is currently visible in the panel.
    pub visible: bool,
}

impl DecompiledLine {
    /// Create a new line with the given number and indentation.
    pub fn new(line_number: usize, indent_level: usize) -> Self {
        Self {
            line_number,
            indent_level,
            address: None,
            function_entry: None,
            tokens: Vec::new(),
            has_breakpoint: false,
            visible: true,
        }
    }

    /// Add a token to this line.
    pub fn add_token(&mut self, token: DecompiledToken) {
        self.tokens.push(token);
    }

    /// Get the full text of this line (concatenated tokens).
    pub fn full_text(&self) -> String {
        let indent = "    ".repeat(self.indent_level);
        let mut text = indent;
        for token in &self.tokens {
            text.push_str(&token.text);
        }
        text
    }

    /// Get the token at the given column position.
    pub fn token_at_col(&self, col: usize) -> Option<&DecompiledToken> {
        // Search from the end (most tokens have increasing col values)
        for token in self.tokens.iter().rev() {
            if col >= token.col && col < token.col + token.display_len() {
                return Some(token);
            }
        }
        None
    }

    /// Get the number of tokens on this line.
    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }

    /// Set the source address for this line.
    pub fn set_address(&mut self, addr: Address) {
        self.address = Some(addr);
    }
}

impl Default for DecompiledLine {
    fn default() -> Self {
        Self {
            line_number: 0,
            indent_level: 0,
            address: None,
            function_entry: None,
            tokens: Vec::new(),
            has_breakpoint: false,
            visible: true,
        }
    }
}

// ---------------------------------------------------------------------------
// DecompiledFunction
// ---------------------------------------------------------------------------

/// A complete decompiled function.
///
/// Contains the function metadata and all its decompiled lines.
#[derive(Debug, Clone)]
pub struct DecompiledFunction {
    /// The function's entry point.
    pub entry_point: Address,
    /// The function name.
    pub name: String,
    /// The return type.
    pub return_type: String,
    /// The function signature as a string.
    pub signature: String,
    /// All lines of the decompiled output.
    pub lines: Vec<DecompiledLine>,
    /// Whether the function has been fully decompiled.
    pub is_complete: bool,
}

impl DecompiledFunction {
    /// Create a new decompiled function.
    pub fn new(entry_point: Address, name: impl Into<String>) -> Self {
        Self {
            entry_point,
            name: name.into(),
            return_type: "undefined".into(),
            signature: String::new(),
            lines: Vec::new(),
            is_complete: false,
        }
    }

    /// Get the total number of lines.
    pub fn line_count(&self) -> usize {
        self.lines.len()
    }

    /// Get a line by number (1-based).
    pub fn get_line(&self, line_number: usize) -> Option<&DecompiledLine> {
        self.lines.iter().find(|l| l.line_number == line_number)
    }

    /// Find the line containing a token at the given address.
    pub fn find_line_for_address(&self, addr: &Address) -> Option<&DecompiledLine> {
        self.lines.iter().find(|l| l.address.as_ref() == Some(addr))
    }

    /// Get the full decompiled text as a string.
    pub fn full_text(&self) -> String {
        self.lines
            .iter()
            .map(|l| l.full_text())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ---------------------------------------------------------------------------
// DecompilerPanel
// ---------------------------------------------------------------------------

/// The decompiler panel that manages the display of decompiled functions.
///
/// This models the non-GUI aspects of the decompiler panel, including
/// the current function, cursor position, selection, and navigation.
#[derive(Debug)]
pub struct DecompilerPanel {
    /// The currently displayed function.
    pub current_function: Option<DecompiledFunction>,
    /// The cursor line number (1-based).
    cursor_line: usize,
    /// The cursor column within the line.
    cursor_col: usize,
    /// The selection start line.
    selection_start: Option<(usize, usize)>,
    /// The selection end line.
    selection_end: Option<(usize, usize)>,
    /// The total number of lines in the current display.
    total_lines: usize,
}

impl DecompilerPanel {
    /// Create a new decompiler panel.
    pub fn new() -> Self {
        Self {
            current_function: None,
            cursor_line: 0,
            cursor_col: 0,
            selection_start: None,
            selection_end: None,
            total_lines: 0,
        }
    }

    /// Set the displayed function.
    pub fn set_function(&mut self, func: DecompiledFunction) {
        self.total_lines = func.line_count();
        self.cursor_line = 1;
        self.cursor_col = 0;
        self.selection_start = None;
        self.selection_end = None;
        self.current_function = Some(func);
    }

    /// Clear the panel.
    pub fn clear(&mut self) {
        self.current_function = None;
        self.cursor_line = 0;
        self.cursor_col = 0;
        self.total_lines = 0;
    }

    /// Get the current cursor position.
    pub fn cursor_position(&self) -> (usize, usize) {
        (self.cursor_line, self.cursor_col)
    }

    /// Set the cursor position.
    pub fn set_cursor(&mut self, line: usize, col: usize) {
        self.cursor_line = line;
        self.cursor_col = col;
    }

    /// Navigate to a specific address in the decompiled output.
    ///
    /// Returns the line number if the address was found.
    pub fn go_to_address(&mut self, addr: &Address) -> Option<usize> {
        if let Some(ref func) = self.current_function {
            if let Some(line) = func.find_line_for_address(addr) {
                self.cursor_line = line.line_number;
                self.cursor_col = 0;
                return Some(line.line_number);
            }
        }
        None
    }

    /// Get the token at the cursor.
    pub fn token_at_cursor(&self) -> Option<&DecompiledToken> {
        let func = self.current_function.as_ref()?;
        let line = func.get_line(self.cursor_line)?;
        line.token_at_col(self.cursor_col)
    }

    /// Get the line at the cursor.
    pub fn line_at_cursor(&self) -> Option<&DecompiledLine> {
        let func = self.current_function.as_ref()?;
        func.get_line(self.cursor_line)
    }

    /// Set the selection range.
    pub fn set_selection(&mut self, start: (usize, usize), end: (usize, usize)) {
        self.selection_start = Some(start);
        self.selection_end = Some(end);
    }

    /// Clear the selection.
    pub fn clear_selection(&mut self) {
        self.selection_start = None;
        self.selection_end = None;
    }

    /// Whether there is an active selection.
    pub fn has_selection(&self) -> bool {
        self.selection_start.is_some() && self.selection_end.is_some()
    }

    /// Get the total number of lines.
    pub fn total_lines(&self) -> usize {
        self.total_lines
    }

    /// Get the function name.
    pub fn function_name(&self) -> Option<&str> {
        self.current_function.as_ref().map(|f| f.name.as_str())
    }
}

impl Default for DecompilerPanel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_creation() {
        let token = DecompiledToken::new("int", DecompiledTokenType::TypeName, 0, 0);
        assert_eq!(token.text, "int");
        assert_eq!(token.token_type, DecompiledTokenType::TypeName);
        assert!(!token.highlighted);
    }

    #[test]
    fn test_token_with_address() {
        let token = DecompiledToken::new("main", DecompiledTokenType::FunctionName, 0, 0)
            .with_address(Address::new(0x401000));
        assert_eq!(token.address, Some(Address::new(0x401000)));
        assert!(token.is_function_name());
    }

    #[test]
    fn test_token_with_symbol_id() {
        let token = DecompiledToken::new("x", DecompiledTokenType::Variable, 4, 10)
            .with_symbol_id(42);
        assert_eq!(token.symbol_id, Some(42));
        assert!(token.is_variable());
    }

    #[test]
    fn test_line_creation() {
        let line = DecompiledLine::new(1, 0);
        assert_eq!(line.line_number, 1);
        assert_eq!(line.indent_level, 0);
        assert!(line.tokens.is_empty());
    }

    #[test]
    fn test_line_add_token() {
        let mut line = DecompiledLine::new(1, 1);
        line.add_token(DecompiledToken::new("return", DecompiledTokenType::Keyword, 4, 0));
        line.add_token(DecompiledToken::new(" ", DecompiledTokenType::Whitespace, 10, 6));
        line.add_token(DecompiledToken::new("0", DecompiledTokenType::Literal, 11, 7));
        assert_eq!(line.token_count(), 3);
    }

    #[test]
    fn test_line_full_text() {
        let mut line = DecompiledLine::new(1, 2);
        line.add_token(DecompiledToken::new("return", DecompiledTokenType::Keyword, 8, 0));
        line.add_token(DecompiledToken::new(" 0;", DecompiledTokenType::Syntax, 14, 6));
        assert_eq!(line.full_text(), "        return 0;");
    }

    #[test]
    fn test_line_token_at_col() {
        let mut line = DecompiledLine::new(1, 0);
        line.add_token(DecompiledToken::new("int", DecompiledTokenType::TypeName, 0, 0));
        line.add_token(DecompiledToken::new(" x", DecompiledTokenType::Variable, 4, 3));
        assert!(line.token_at_col(0).is_some());
        assert_eq!(line.token_at_col(0).unwrap().text, "int");
        assert_eq!(line.token_at_col(1).unwrap().text, "int");
        assert!(line.token_at_col(4).is_some());
        assert_eq!(line.token_at_col(4).unwrap().text, " x");
    }

    #[test]
    fn test_function_creation() {
        let func = DecompiledFunction::new(Address::new(0x1000), "main");
        assert_eq!(func.entry_point, Address::new(0x1000));
        assert_eq!(func.name, "main");
        assert_eq!(func.line_count(), 0);
    }

    #[test]
    fn test_function_full_text() {
        let mut func = DecompiledFunction::new(Address::new(0x1000), "main");
        let mut line1 = DecompiledLine::new(1, 0);
        line1.add_token(DecompiledToken::new("void main() {", DecompiledTokenType::Syntax, 0, 0));
        let mut line2 = DecompiledLine::new(2, 1);
        line2.add_token(DecompiledToken::new("return;", DecompiledTokenType::Keyword, 4, 14));
        let mut line3 = DecompiledLine::new(3, 0);
        line3.add_token(DecompiledToken::new("}", DecompiledTokenType::Syntax, 0, 22));
        func.lines = vec![line1, line2, line3];
        func.is_complete = true;

        let text = func.full_text();
        assert!(text.contains("void main()"));
        assert!(text.contains("return;"));
    }

    #[test]
    fn test_function_find_line_for_address() {
        let mut func = DecompiledFunction::new(Address::new(0x1000), "test");
        let mut line = DecompiledLine::new(1, 0);
        line.set_address(Address::new(0x1004));
        func.lines.push(line);
        assert!(func.find_line_for_address(&Address::new(0x1004)).is_some());
        assert!(func.find_line_for_address(&Address::new(0x9999)).is_none());
    }

    #[test]
    fn test_panel_new() {
        let panel = DecompilerPanel::new();
        assert!(panel.current_function.is_none());
        assert_eq!(panel.cursor_position(), (0, 0));
        assert_eq!(panel.total_lines(), 0);
    }

    #[test]
    fn test_panel_set_function() {
        let mut panel = DecompilerPanel::new();
        let func = DecompiledFunction::new(Address::new(0x1000), "main");
        panel.set_function(func);
        assert!(panel.current_function.is_some());
        assert_eq!(panel.cursor_position(), (1, 0));
        assert_eq!(panel.function_name(), Some("main"));
    }

    #[test]
    fn test_panel_go_to_address() {
        let mut panel = DecompilerPanel::new();
        let mut func = DecompiledFunction::new(Address::new(0x1000), "test");
        let mut line = DecompiledLine::new(5, 0);
        line.set_address(Address::new(0x1008));
        func.lines.push(line);
        panel.set_function(func);

        let result = panel.go_to_address(&Address::new(0x1008));
        assert_eq!(result, Some(5));
        assert_eq!(panel.cursor_position().0, 5);
    }

    #[test]
    fn test_panel_selection() {
        let mut panel = DecompilerPanel::new();
        assert!(!panel.has_selection());
        panel.set_selection((1, 0), (5, 10));
        assert!(panel.has_selection());
        panel.clear_selection();
        assert!(!panel.has_selection());
    }

    #[test]
    fn test_panel_token_at_cursor() {
        let mut panel = DecompilerPanel::new();
        let mut func = DecompiledFunction::new(Address::new(0x1000), "test");
        let mut line = DecompiledLine::new(1, 0);
        line.add_token(DecompiledToken::new("x", DecompiledTokenType::Variable, 0, 0));
        func.lines.push(line);
        panel.set_function(func);
        panel.set_cursor(1, 0);

        let token = panel.token_at_cursor();
        assert!(token.is_some());
        assert_eq!(token.unwrap().text, "x");
    }

    #[test]
    fn test_panel_clear() {
        let mut panel = DecompilerPanel::new();
        let func = DecompiledFunction::new(Address::new(0x1000), "test");
        panel.set_function(func);
        panel.clear();
        assert!(panel.current_function.is_none());
        assert_eq!(panel.total_lines(), 0);
    }

    #[test]
    fn test_token_type_equality() {
        assert_eq!(DecompiledTokenType::Keyword, DecompiledTokenType::Keyword);
        assert_ne!(DecompiledTokenType::Keyword, DecompiledTokenType::Variable);
    }

    #[test]
    fn test_line_set_address() {
        let mut line = DecompiledLine::new(1, 0);
        assert!(line.address.is_none());
        line.set_address(Address::new(0x2000));
        assert_eq!(line.address, Some(Address::new(0x2000)));
    }
}
