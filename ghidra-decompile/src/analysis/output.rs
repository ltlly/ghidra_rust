//! C code output generation from structured decompiler IR.
//!
//! This module provides the final stage of the decompiler pipeline: converting
//! the structured control-flow graph (produced by `control_flow_struct`) into
//! syntactically valid C source code.
//!
//! # Components
//!
//! - [`CToken`] -- a lexical token in the C output, with semantic categories
//!   for syntax highlighting and IDE navigation.
//! - [`CFormatter`] -- generates formatted C source text with configurable
//!   brace style, indentation, and address annotation.
//! - [`PrettyPrinter`] -- higher-level printer that manages indentation state
//!   and produces a token stream suitable for GUI rendering or direct text
//!   output.
//!
//! # Example
//!
//! ```ignore
//! use ghidra_decompile::analysis::output::{CFormatter, OutputConfig};
//!
//! let cfg = OutputConfig::default();
//! let fmt = CFormatter::new(cfg);
//! let c_source = fmt.format_function(&function_metadata, &structured_body);
//! ```

use std::fmt::Write;

use ghidra_core::addr::Address;

use super::control_flow_struct::{
    BinaryOperator, BlockData, Expression, StructuredNode, SwitchCase, UnaryOperator,
};

// ============================================================================
// CToken
// ============================================================================

/// A single token in the C output stream.
///
/// Each token carries its semantic category for use by GUI renderers
/// (syntax highlighting, hyperlinks, address-tooltip popups) and its
/// text content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CToken {
    /// C keyword: `if`, `while`, `return`, `struct`, `switch`, `for`, etc.
    Keyword(String),

    /// Type name: `int`, `uint32_t`, `void*`, `char`, etc.
    Type(String),

    /// An identifier (variable, function, label name), optionally linked
    /// to its definition address.
    Identifier {
        name: String,
        /// Navigation address, if known.
        address: Option<Address>,
    },

    /// A numeric literal.
    Number {
        text: String,
        /// The raw value as an integer (for tooltips).
        value: Option<u64>,
    },

    /// A string literal (double-quoted).
    StringLiteral(String),

    /// A character literal (single-quoted).
    CharLiteral(String),

    /// A comment (line or block).
    Comment(String),

    /// An operator: `+`, `<<`, `&&`, `=`, `+=`, etc.
    Operator(String),

    /// Punctuation: `(`, `)`, `{`, `}`, `;`, `,`, `:`.
    Punctuation(char),

    /// Whitespace between tokens (spaces, tabs).
    Whitespace(String),

    /// Newline (formatting boundary).
    Newline,

    /// An address reference (for clickable navigation in a GUI).
    Address(Address),

    /// Cross-reference: an identifier that links to a different address.
    Reference {
        name: String,
        target: Address,
    },
}

impl CToken {
    /// Create a keyword token.
    pub fn keyword(kw: impl Into<String>) -> Self {
        CToken::Keyword(kw.into())
    }

    /// Create a type token.
    pub fn type_name(ty: impl Into<String>) -> Self {
        CToken::Type(ty.into())
    }

    /// Create an identifier token without navigation.
    pub fn ident(name: impl Into<String>) -> Self {
        CToken::Identifier {
            name: name.into(),
            address: None,
        }
    }

    /// Create an identifier token with a navigation address.
    pub fn ident_at(name: impl Into<String>, addr: Address) -> Self {
        CToken::Identifier {
            name: name.into(),
            address: Some(addr),
        }
    }

    /// Create a number token.
    pub fn number(text: impl Into<String>, value: Option<u64>) -> Self {
        CToken::Number {
            text: text.into(),
            value,
        }
    }

    /// Create an operator token.
    pub fn op(op: impl Into<String>) -> Self {
        CToken::Operator(op.into())
    }

    /// Create a punctuation token.
    pub fn punct(c: char) -> Self {
        CToken::Punctuation(c)
    }

    /// Returns true if this token is whitespace or a newline.
    pub fn is_whitespace(&self) -> bool {
        matches!(self, CToken::Whitespace(_) | CToken::Newline)
    }

    /// Returns the plain-text content of this token.
    pub fn text(&self) -> String {
        match self {
            CToken::Keyword(s) => s.clone(),
            CToken::Type(s) => s.clone(),
            CToken::Identifier { name, .. } => name.clone(),
            CToken::Number { text, .. } => text.clone(),
            CToken::StringLiteral(s) => format!("\"{}\"", s),
            CToken::CharLiteral(c) => format!("'{}'", c),
            CToken::Comment(c) => c.clone(),
            CToken::Operator(op) => op.clone(),
            CToken::Punctuation(p) => p.to_string(),
            CToken::Whitespace(w) => w.clone(),
            CToken::Newline => "\n".to_string(),
            CToken::Address(a) => format!("{:#x}", a.offset),
            CToken::Reference { name, .. } => name.clone(),
        }
    }
}

// ============================================================================
// OutputConfig
// ============================================================================

/// Configuration for the C formatter.
#[derive(Debug, Clone)]
pub struct OutputConfig {
    /// Number of spaces per indentation level.
    pub indent_size: usize,
    /// Maximum desired line length.
    pub max_line_length: usize,
    /// Where to place opening braces.
    pub brace_style: BraceStyle,
    /// Emit original address comments.
    pub show_addresses: bool,
    /// Emit explicit type casts.
    pub show_type_casts: bool,
    /// Rename internal temporaries to `var_XX`.
    pub rename_temporaries: bool,
    /// Emit local-variable declarations at function top.
    pub emit_var_declarations: bool,
    /// Use hex for numeric literals above this value.
    pub hex_threshold: u64,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            indent_size: 4,
            max_line_length: 120,
            brace_style: BraceStyle::KAndR,
            show_addresses: false,
            show_type_casts: true,
            rename_temporaries: true,
            emit_var_declarations: true,
            hex_threshold: 9,
        }
    }
}

/// Brace-placement styles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BraceStyle {
    /// Opening brace on the same line: `if (cond) {`
    KAndR,
    /// Opening brace on its own line: `if (cond)\n{`
    Allman,
    /// GNU style: brace indented half-indent on next line.
    GNU,
    /// Whitesmiths: body and braces indented together.
    Whitesmiths,
}

// ============================================================================
// FunctionMetadata
// ============================================================================

/// Metadata for the function being decompiled (needed for C output).
#[derive(Debug, Clone)]
pub struct FunctionMetadata {
    /// Function name.
    pub name: String,
    /// Return type as a C type string (e.g., "void", "int", "uint32_t").
    pub return_type: String,
    /// Parameter names and types.
    pub parameters: Vec<(String, String)>, // (type, name)
    /// True if variadic (has "...")
    pub is_variadic: bool,
    /// True if static.
    pub is_static: bool,
    /// True if inline.
    pub is_inline: bool,
    /// Function entry address.
    pub entry_point: Address,
    /// Comment to emit before the function signature.
    pub signature_comment: Option<String>,
}

impl FunctionMetadata {
    /// Create function metadata with a name and entry point.
    pub fn new(name: impl Into<String>, entry_point: Address) -> Self {
        Self {
            name: name.into(),
            return_type: "void".to_string(),
            parameters: Vec::new(),
            is_variadic: false,
            is_static: false,
            is_inline: false,
            entry_point,
            signature_comment: None,
        }
    }
}

// ============================================================================
// CFormatter
// ============================================================================

/// Generates formatted C source code from structured nodes.
///
/// Supports multiple brace styles, configurable indentation, address
/// annotations, and a token-stream mode for GUI renderers.
pub struct CFormatter {
    /// Configuration.
    pub config: OutputConfig,
    /// Accumulated output text.
    output: String,
    /// Accumulated tokens (when token mode is enabled).
    tokens: Vec<CToken>,
    /// Whether to collect tokens in addition to text.
    token_mode: bool,
}

impl CFormatter {
    /// Create a new formatter with the given configuration.
    pub fn new(config: OutputConfig) -> Self {
        Self {
            config,
            output: String::new(),
            tokens: Vec::new(),
            token_mode: false,
        }
    }

    /// Enable token-collection mode. Tokens are accumulated in `self.tokens`
    /// as they are emitted.
    pub fn enable_token_mode(&mut self, enabled: bool) -> &mut Self {
        self.token_mode = enabled;
        self
    }

    /// Returns the accumulated tokens (if token mode is enabled).
    pub fn tokens(&self) -> &[CToken] {
        &self.tokens
    }

    // ------------------------------------------------------------------
    // Top-level formatting
    // ------------------------------------------------------------------

    /// Format a complete function as C source code.
    ///
    /// Emits the function signature followed by the body, with optional
    /// variable declarations and address comments.
    pub fn format_function(
        &mut self,
        func: &FunctionMetadata,
        body: &StructuredNode,
    ) -> String {
        self.output.clear();
        self.tokens.clear();

        // Address header comment.
        if self.config.show_addresses {
            self.emit_comment(&format!(" function at {}", func.entry_point));
        }

        // Signature comment.
        if let Some(ref comment) = func.signature_comment {
            self.emit_comment(comment);
        }

        // Function signature.
        self.emit_signature(func);

        // Opening brace.
        self.emit_opening_brace(0);

        // Function body.
        let body_text = self.format_node(body, 1);
        self.output.push_str(&body_text);

        // Closing brace.
        self.emit_line(0, "}");
        self.emit_newline();

        // Return a copy of the output for chaining, but keep the formatter
        // state for further queries.
        self.output.clone()
    }

    /// Format a structured node (and its subtree) as C text.
    pub fn format_node(&mut self, node: &StructuredNode, indent: usize) -> String {
        match node {
            StructuredNode::Block(block) => self.format_block(block, indent),
            StructuredNode::IfElse {
                condition,
                then_branch,
                else_branch,
            } => self.format_if_else(condition, then_branch, else_branch.as_deref(), indent),
            StructuredNode::While { condition, body } => {
                self.format_while(condition, body, indent)
            }
            StructuredNode::DoWhile { condition, body } => {
                self.format_do_while(condition, body, indent)
            }
            StructuredNode::For {
                init,
                condition,
                step,
                body,
            } => self.format_for(
                init.as_deref(),
                condition.as_deref(),
                step.as_deref(),
                body,
                indent,
            ),
            StructuredNode::Switch {
                expression,
                cases,
                default,
            } => self.format_switch(expression, cases, default.as_deref(), indent),
            StructuredNode::Goto { label, target: _ } => {
                format!("{}goto {};\n", self.indent_str(indent), label)
            }
            StructuredNode::Label { name, node } => self.format_label(name, node, indent),
            StructuredNode::Break => format!("{}break;\n", self.indent_str(indent)),
            StructuredNode::Continue => format!("{}continue;\n", self.indent_str(indent)),
            StructuredNode::Return(expr) => {
                self.format_return(expr.as_deref(), indent)
            }
            StructuredNode::InfiniteLoop { body } => {
                self.format_infinite_loop(body, indent)
            }
            StructuredNode::Sequence(nodes) => self.format_sequence(nodes, indent),
        }
    }

    /// Format an expression as a C expression string.
    pub fn format_expression(&self, expr: &Expression) -> String {
        expr_to_c(expr, 0, self.config.show_type_casts)
    }

    // ------------------------------------------------------------------
    // Block formatting
    // ------------------------------------------------------------------

    fn format_block(&self, block: &BlockData, indent: usize) -> String {
        let mut out = String::new();
        let prefix = self.indent_str(indent);

        for expr in &block.operations {
            if self.config.show_addresses && !block.address.is_null() {
                let _ = writeln!(out, "{}// {:#x}", prefix, block.address.offset);
            }
            let expr_str = expr_to_c(expr, 0, self.config.show_type_casts);
            let _ = writeln!(out, "{}{};", prefix, expr_str);
        }

        out
    }

    // ------------------------------------------------------------------
    // Control-flow formatting
    // ------------------------------------------------------------------

    fn format_if_else(
        &self,
        condition: &Expression,
        then_branch: &StructuredNode,
        else_branch: Option<&StructuredNode>,
        indent: usize,
    ) -> String {
        let mut out = String::new();
        let cond_str = expr_to_c(condition, 0, true);
        let prefix = self.indent_str(indent);
        let if_line = format!("{}if ({})", prefix, cond_str);

        self.write_control_open(&mut out, &if_line, indent);
        let then_body = self.format_node_owned(then_branch, indent + 1);
        out.push_str(&then_body);

        if let Some(else_node) = else_branch {
            // Chain `else if` if applicable.
            if matches!(else_node, StructuredNode::IfElse { .. }) {
                let close_prefix = self.indent_str(indent);
                let else_body = self.format_node_owned(else_node, indent);
                let _ = write!(out, "{}else {}", close_prefix, else_body.trim_start());
            } else {
                let _ = writeln!(out, "{}else", self.indent_str(indent));
                self.write_open_brace(&mut out, indent);
                let else_body = self.format_node_owned(else_node, indent + 1);
                out.push_str(&else_body);
                let _ = writeln!(out, "{}}}", self.indent_str(indent));
            }
        } else {
            let _ = writeln!(out, "{}}}", self.indent_str(indent));
        }

        out
    }

    fn format_while(
        &self,
        condition: &Expression,
        body: &StructuredNode,
        indent: usize,
    ) -> String {
        let mut out = String::new();
        let cond_str = expr_to_c(condition, 0, true);
        let line = format!("{}while ({})", self.indent_str(indent), cond_str);

        self.write_control_open(&mut out, &line, indent);
        let body_str = self.format_node_owned(body, indent + 1);
        out.push_str(&body_str);
        let _ = writeln!(out, "{}}}", self.indent_str(indent));
        out
    }

    fn format_do_while(
        &self,
        condition: &Expression,
        body: &StructuredNode,
        indent: usize,
    ) -> String {
        let mut out = String::new();
        let prefix = self.indent_str(indent);

        let _ = writeln!(out, "{}do", prefix);
        self.write_open_brace(&mut out, indent);

        let body_str = self.format_node_owned(body, indent + 1);
        out.push_str(&body_str);

        let cond_str = expr_to_c(condition, 0, true);
        let _ = writeln!(out, "{}}} while ({});", prefix, cond_str);
        out
    }

    fn format_for(
        &self,
        init: Option<&Expression>,
        condition: Option<&Expression>,
        step: Option<&Expression>,
        body: &StructuredNode,
        indent: usize,
    ) -> String {
        let mut out = String::new();
        let init_str = init.map(|e| expr_to_c(e, 0, true)).unwrap_or_default();
        let cond_str = condition.map(|e| expr_to_c(e, 0, true)).unwrap_or_default();
        let step_str = step.map(|e| expr_to_c(e, 0, true)).unwrap_or_default();

        let line = format!(
            "{}for ({}; {}; {})",
            self.indent_str(indent),
            init_str,
            cond_str,
            step_str
        );

        self.write_control_open(&mut out, &line, indent);
        let body_str = self.format_node_owned(body, indent + 1);
        out.push_str(&body_str);
        let _ = writeln!(out, "{}}}", self.indent_str(indent));
        out
    }

    fn format_switch(
        &self,
        expression: &Expression,
        cases: &[SwitchCase],
        default: Option<&StructuredNode>,
        indent: usize,
    ) -> String {
        let mut out = String::new();
        let prefix = self.indent_str(indent);
        let expr_str = expr_to_c(expression, 0, true);
        let switch_line = format!("{}switch ({})", prefix, expr_str);

        self.write_control_open(&mut out, &switch_line, indent);
        let inner_indent = indent + 1;

        for case in cases {
            for val in &case.values {
                let _ = writeln!(out, "{}case {}:", self.indent_str(inner_indent), val);
            }
            let case_body = self.format_node_owned(&case.body, inner_indent + 1);
            out.push_str(&case_body);
            if !case.is_fallthrough {
                let _ = writeln!(
                    out,
                    "{}break;",
                    self.indent_str(inner_indent + 1)
                );
            }
        }

        if let Some(default_node) = default {
            let _ = writeln!(out, "{}default:", self.indent_str(inner_indent));
            let default_body = self.format_node_owned(default_node, inner_indent + 1);
            out.push_str(&default_body);
            let _ = writeln!(
                out,
                "{}break;",
                self.indent_str(inner_indent + 1)
            );
        }

        let _ = writeln!(out, "{}}}", prefix);
        out
    }

    fn format_infinite_loop(&self, body: &StructuredNode, indent: usize) -> String {
        let mut out = String::new();
        let line = format!("{}for (;;)", self.indent_str(indent));

        self.write_control_open(&mut out, &line, indent);
        let body_str = self.format_node_owned(body, indent + 1);
        out.push_str(&body_str);
        let _ = writeln!(out, "{}}}", self.indent_str(indent));
        out
    }

    fn format_label(&self, name: &str, node: &StructuredNode, indent: usize) -> String {
        let mut out = String::new();
        let label_indent = if indent > 0 { indent - 1 } else { 0 };
        let _ = writeln!(out, "{}{} :", self.indent_str(label_indent), name);
        let body = self.format_node_owned(node, indent);
        out.push_str(&body);
        out
    }

    fn format_return(&self, expr: Option<&Expression>, indent: usize) -> String {
        match expr {
            Some(e) => format!(
                "{}return {};\n",
                self.indent_str(indent),
                expr_to_c(e, 0, true)
            ),
            None => format!("{}return;\n", self.indent_str(indent)),
        }
    }

    fn format_sequence(&self, nodes: &[StructuredNode], indent: usize) -> String {
        let mut out = String::new();
        for node in nodes {
            out.push_str(&self.format_node_owned(node, indent));
        }
        out
    }

    // Owned version of format_node (non-mut, to avoid borrow conflicts
    // in recursive calls).
    fn format_node_owned(&self, node: &StructuredNode, indent: usize) -> String {
        match node {
            StructuredNode::Block(block) => self.format_block(block, indent),
            StructuredNode::IfElse {
                condition,
                then_branch,
                else_branch,
            } => self.format_if_else(condition, then_branch, else_branch.as_deref(), indent),
            StructuredNode::While { condition, body } => {
                self.format_while(condition, body, indent)
            }
            StructuredNode::DoWhile { condition, body } => {
                self.format_do_while(condition, body, indent)
            }
            StructuredNode::For {
                init,
                condition,
                step,
                body,
            } => self.format_for(
                init.as_deref(),
                condition.as_deref(),
                step.as_deref(),
                body,
                indent,
            ),
            StructuredNode::Switch {
                expression,
                cases,
                default,
            } => self.format_switch(expression, cases, default.as_deref(), indent),
            StructuredNode::Goto { label, target: _ } => {
                format!("{}goto {};\n", self.indent_str(indent), label)
            }
            StructuredNode::Label { name, node } => self.format_label(name, node, indent),
            StructuredNode::Break => format!("{}break;\n", self.indent_str(indent)),
            StructuredNode::Continue => format!("{}continue;\n", self.indent_str(indent)),
            StructuredNode::Return(expr) => {
                self.format_return(expr.as_deref(), indent)
            }
            StructuredNode::InfiniteLoop { body } => {
                self.format_infinite_loop(body, indent)
            }
            StructuredNode::Sequence(nodes) => self.format_sequence(nodes, indent),
        }
    }

    // ------------------------------------------------------------------
    // Emit helpers (for the top-level `format_function` call)
    // ------------------------------------------------------------------

    fn emit_signature(&mut self, func: &FunctionMetadata) {
        let mut sig = String::new();

        if func.is_static {
            sig.push_str("static ");
        }
        if func.is_inline {
            sig.push_str("inline ");
        }

        let _ = write!(sig, "{} {}(", func.return_type, func.name);

        for (i, (ty, name)) in func.parameters.iter().enumerate() {
            if i > 0 {
                sig.push_str(", ");
            }
            let _ = write!(sig, "{} {}", ty, name);
        }
        if func.is_variadic {
            if !func.parameters.is_empty() {
                sig.push_str(", ...");
            } else {
                sig.push_str("...");
            }
        }

        sig.push(')');
        self.output.push_str(&sig);
    }

    fn emit_opening_brace(&mut self, indent: usize) {
        match self.config.brace_style {
            BraceStyle::KAndR => {
                let _ = writeln!(self.output, " {{");
            }
            BraceStyle::Allman => {
                let _ = writeln!(self.output, "");
                let _ = writeln!(self.output, "{}{{", self.indent_str(indent));
            }
            BraceStyle::GNU => {
                let _ = writeln!(self.output, "");
                let half = self.config.indent_size / 2;
                let spaces = " ".repeat(half);
                let _ = writeln!(self.output, "{}{{", spaces);
            }
            BraceStyle::Whitesmiths => {
                let _ = writeln!(self.output, "");
                let _ = writeln!(self.output, "{}    {{", self.indent_str(indent));
            }
        }
    }

    fn emit_line(&mut self, indent: usize, text: &str) {
        let _ = writeln!(self.output, "{}{}", self.indent_str(indent), text);
    }

    fn emit_newline(&mut self) {
        let _ = writeln!(self.output);
        if self.token_mode {
            self.tokens.push(CToken::Newline);
        }
    }

    fn emit_comment(&mut self, text: &str) {
        let _ = writeln!(self.output, "// {}", text);
    }

    // ------------------------------------------------------------------
    // Brace-writing helpers
    // ------------------------------------------------------------------

    fn write_control_open(&self, out: &mut String, line: &str, indent: usize) {
        match self.config.brace_style {
            BraceStyle::KAndR => {
                let _ = writeln!(out, "{} {{", line);
            }
            BraceStyle::Allman => {
                let _ = writeln!(out, "{}", line);
                let _ = writeln!(out, "{}{{", self.indent_str(indent));
            }
            BraceStyle::GNU => {
                let _ = writeln!(out, "{}", line);
                let half = self.config.indent_size / 2;
                let _ = writeln!(out, "{}{{", " ".repeat(half));
            }
            BraceStyle::Whitesmiths => {
                let _ = writeln!(out, "{}", line);
                let _ = writeln!(out, "{}    {{", self.indent_str(indent));
            }
        }
    }

    fn write_open_brace(&self, out: &mut String, indent: usize) {
        let _ = writeln!(out, "{}{{", self.indent_str(indent));
    }

    // ------------------------------------------------------------------
    // Utility
    // ------------------------------------------------------------------

    fn indent_str(&self, level: usize) -> String {
        " ".repeat(level * self.config.indent_size)
    }
}

// ============================================================================
// PrettyPrinter
// ============================================================================

/// A pretty-printer that produces a stream of [`CToken`] values from a
/// structured decompilation tree.
///
/// The pretty-printer manages indentation state and emits tokens for each
/// C construct. The resulting token stream can be rendered as plain text
/// or syntax-highlighted HTML.
pub struct PrettyPrinter {
    /// The accumulated token stream.
    tokens: Vec<CToken>,
    /// Current indentation level.
    indent_level: usize,
    /// Configuration.
    config: OutputConfig,
}

impl PrettyPrinter {
    /// Create a new pretty-printer with default settings.
    pub fn new() -> Self {
        Self {
            tokens: Vec::new(),
            indent_level: 0,
            config: OutputConfig::default(),
        }
    }

    /// Create a pretty-printer with custom configuration.
    pub fn with_config(config: OutputConfig) -> Self {
        Self {
            tokens: Vec::new(),
            indent_level: 0,
            config,
        }
    }

    /// Pretty-print a complete function.
    ///
    /// Returns the accumulated token stream.
    pub fn print_function(
        &mut self,
        func: &FunctionMetadata,
        body: &StructuredNode,
    ) -> &[CToken] {
        self.tokens.clear();
        self.indent_level = 0;

        // Function signature.
        self.print_signature(func);
        self.emit(CToken::Newline);

        // Open brace.
        self.print_indent();
        self.emit(CToken::Punctuation('{'));
        self.emit(CToken::Newline);

        // Body.
        self.indent_level += 1;
        self.print_node(body);
        self.indent_level -= 1;

        // Close brace.
        self.print_indent();
        self.emit(CToken::Punctuation('}'));
        self.emit(CToken::Newline);

        &self.tokens
    }

    /// Returns the accumulated tokens.
    pub fn tokens(&self) -> &[CToken] {
        &self.tokens
    }

    /// Serializes the token stream to plain C source text.
    pub fn to_string(&self) -> String {
        let mut out = String::new();
        let mut prev_was_newline = false;
        for token in &self.tokens {
            let text = token.text();
            // Collapse multiple consecutive newlines.
            if token == &CToken::Newline {
                if !prev_was_newline {
                    out.push('\n');
                    prev_was_newline = true;
                }
            } else {
                out.push_str(&text);
                prev_was_newline = false;
            }
        }
        out
    }

    /// Serializes to syntax-highlighted HTML.
    pub fn to_html(&self) -> String {
        let mut out = String::new();
        out.push_str("<pre class=\"decompiled-code\">\n");

        for token in &self.tokens {
            match token {
                CToken::Keyword(kw) => {
                    let _ = write!(out, "<span class=\"tk-kw\">{}</span>", html_escape(kw));
                }
                CToken::Type(ty) => {
                    let _ = write!(out, "<span class=\"tk-type\">{}</span>", html_escape(ty));
                }
                CToken::Identifier { name, address: Some(addr) } => {
                    let _ = write!(
                        out,
                        "<a class=\"tk-id\" data-addr=\"{:#x}\">{}</a>",
                        addr.offset,
                        html_escape(name)
                    );
                }
                CToken::Identifier { name, address: None } => {
                    let _ = write!(out, "<span class=\"tk-id\">{}</span>", html_escape(name));
                }
                CToken::Number { text, .. } => {
                    let _ = write!(out, "<span class=\"tk-num\">{}</span>", html_escape(text));
                }
                CToken::StringLiteral(s) => {
                    let _ = write!(
                        out,
                        "<span class=\"tk-str\">\"{}\"</span>",
                        html_escape(s)
                    );
                }
                CToken::CharLiteral(c) => {
                    let _ = write!(
                        out,
                        "<span class=\"tk-str\">'{}'</span>",
                        html_escape(c)
                    );
                }
                CToken::Comment(c) => {
                    let _ = write!(out, "<span class=\"tk-cmt\">{}</span>", html_escape(c));
                }
                CToken::Operator(op) => {
                    let _ = write!(out, "<span class=\"tk-op\">{}</span>", html_escape(op));
                }
                CToken::Punctuation(p) => {
                    let _ = write!(out, "<span class=\"tk-punct\">{}</span>", *p as char);
                }
                CToken::Whitespace(w) => {
                    out.push_str(&w.replace(' ', " "));
                }
                CToken::Newline => {
                    out.push('\n');
                }
                CToken::Address(addr) => {
                    let _ = write!(
                        out,
                        "<a class=\"tk-addr\" data-addr=\"{:#x}\">{:#x}</a>",
                        addr.offset, addr.offset
                    );
                }
                CToken::Reference { name, target } => {
                    let _ = write!(
                        out,
                        "<a class=\"tk-ref\" data-addr=\"{:#x}\">{}</a>",
                        target.offset,
                        html_escape(name)
                    );
                }
            }
        }

        out.push_str("\n</pre>");
        out
    }

    // ------------------------------------------------------------------
    // Internal: recursive pretty-printing
    // ------------------------------------------------------------------

    fn print_node(&mut self, node: &StructuredNode) {
        match node {
            StructuredNode::Block(block) => self.print_block(block),
            StructuredNode::IfElse { condition, then_branch, else_branch } => {
                self.print_if_else(condition, then_branch, else_branch.as_deref())
            }
            StructuredNode::While { condition, body } => {
                self.print_while(condition, body)
            }
            StructuredNode::DoWhile { condition, body } => {
                self.print_do_while(condition, body)
            }
            StructuredNode::For { init, condition, step, body } => {
                self.print_for(init.as_deref(), condition.as_deref(), step.as_deref(), body)
            }
            StructuredNode::Switch { expression, cases, default } => {
                self.print_switch(expression, cases, default.as_deref())
            }
            StructuredNode::Goto { label, .. } => {
                self.print_indent();
                self.emit(CToken::keyword("goto"));
                self.emit(CToken::Whitespace(" ".into()));
                self.emit(CToken::ident(label.as_str()));
                self.emit(CToken::Punctuation(';'));
                self.emit(CToken::Newline);
            }
            StructuredNode::Label { name, node } => {
                // Labels are outdented.
                if self.indent_level > 0 {
                    self.indent_level -= 1;
                }
                self.print_indent();
                self.emit(CToken::ident(name.as_str()));
                self.emit(CToken::Punctuation(':'));
                self.emit(CToken::Newline);
                self.indent_level += 1;
                self.print_node(node);
                self.indent_level -= 1;
            }
            StructuredNode::Break => {
                self.print_indent();
                self.emit(CToken::keyword("break"));
                self.emit(CToken::Punctuation(';'));
                self.emit(CToken::Newline);
            }
            StructuredNode::Continue => {
                self.print_indent();
                self.emit(CToken::keyword("continue"));
                self.emit(CToken::Punctuation(';'));
                self.emit(CToken::Newline);
            }
            StructuredNode::Return(expr) => {
                self.print_indent();
                self.emit(CToken::keyword("return"));
                if let Some(ref e) = expr {
                    self.emit(CToken::Whitespace(" ".into()));
                    self.print_expression(e);
                }
                self.emit(CToken::Punctuation(';'));
                self.emit(CToken::Newline);
            }
            StructuredNode::InfiniteLoop { body } => {
                self.print_indent();
                self.emit(CToken::keyword("for"));
                self.emit(CToken::Whitespace(" ".into()));
                self.emit(CToken::Punctuation('('));
                self.emit(CToken::Punctuation(';'));
                self.emit(CToken::Punctuation(';'));
                self.emit(CToken::Punctuation(')'));
                self.emit(CToken::Whitespace(" ".into()));
                self.emit(CToken::Punctuation('{'));
                self.emit(CToken::Newline);

                self.indent_level += 1;
                self.print_node(body);
                self.indent_level -= 1;

                self.print_indent();
                self.emit(CToken::Punctuation('}'));
                self.emit(CToken::Newline);
            }
            StructuredNode::Sequence(nodes) => {
                for n in nodes {
                    self.print_node(n);
                }
            }
        }
    }

    fn print_block(&mut self, block: &BlockData) {
        if self.config.show_addresses && !block.address.is_null() {
            self.print_indent();
            self.emit(CToken::Comment(format!("// {:#x}", block.address.offset)));
            self.emit(CToken::Newline);
        }
        for expr in &block.operations {
            self.print_indent();
            self.print_expression(expr);
            self.emit(CToken::Punctuation(';'));
            self.emit(CToken::Newline);
        }
    }

    fn print_if_else(
        &mut self,
        condition: &Expression,
        then_branch: &StructuredNode,
        else_branch: Option<&StructuredNode>,
    ) {
        self.print_indent();
        self.emit(CToken::keyword("if"));
        self.emit(CToken::Whitespace(" ".into()));
        self.emit(CToken::Punctuation('('));
        self.print_expression(condition);
        self.emit(CToken::Punctuation(')'));
        self.emit(CToken::Whitespace(" ".into()));
        self.emit(CToken::Punctuation('{'));
        self.emit(CToken::Newline);

        self.indent_level += 1;
        self.print_node(then_branch);
        self.indent_level -= 1;

        self.print_indent();
        self.emit(CToken::Punctuation('}'));

        if let Some(else_node) = else_branch {
            if matches!(else_node, StructuredNode::IfElse { .. }) {
                self.emit(CToken::Whitespace(" ".into()));
                self.emit(CToken::keyword("else"));
                self.emit(CToken::Whitespace(" ".into()));
                self.print_node(else_node);
            } else {
                self.emit(CToken::Whitespace(" ".into()));
                self.emit(CToken::keyword("else"));
                self.emit(CToken::Whitespace(" ".into()));
                self.emit(CToken::Punctuation('{'));
                self.emit(CToken::Newline);

                self.indent_level += 1;
                self.print_node(else_node);
                self.indent_level -= 1;

                self.print_indent();
                self.emit(CToken::Punctuation('}'));
                self.emit(CToken::Newline);
            }
        } else {
            self.emit(CToken::Newline);
        }
    }

    fn print_while(&mut self, condition: &Expression, body: &StructuredNode) {
        self.print_indent();
        self.emit(CToken::keyword("while"));
        self.emit(CToken::Whitespace(" ".into()));
        self.emit(CToken::Punctuation('('));
        self.print_expression(condition);
        self.emit(CToken::Punctuation(')'));
        self.emit(CToken::Whitespace(" ".into()));
        self.emit(CToken::Punctuation('{'));
        self.emit(CToken::Newline);

        self.indent_level += 1;
        self.print_node(body);
        self.indent_level -= 1;

        self.print_indent();
        self.emit(CToken::Punctuation('}'));
        self.emit(CToken::Newline);
    }

    fn print_do_while(&mut self, condition: &Expression, body: &StructuredNode) {
        self.print_indent();
        self.emit(CToken::keyword("do"));
        self.emit(CToken::Whitespace(" ".into()));
        self.emit(CToken::Punctuation('{'));
        self.emit(CToken::Newline);

        self.indent_level += 1;
        self.print_node(body);
        self.indent_level -= 1;

        self.print_indent();
        self.emit(CToken::Punctuation('}'));
        self.emit(CToken::Whitespace(" ".into()));
        self.emit(CToken::keyword("while"));
        self.emit(CToken::Whitespace(" ".into()));
        self.emit(CToken::Punctuation('('));
        self.print_expression(condition);
        self.emit(CToken::Punctuation(')'));
        self.emit(CToken::Punctuation(';'));
        self.emit(CToken::Newline);
    }

    fn print_for(
        &mut self,
        init: Option<&Expression>,
        condition: Option<&Expression>,
        step: Option<&Expression>,
        body: &StructuredNode,
    ) {
        self.print_indent();
        self.emit(CToken::keyword("for"));
        self.emit(CToken::Whitespace(" ".into()));
        self.emit(CToken::Punctuation('('));
        if let Some(e) = init {
            self.print_expression(e);
        }
        self.emit(CToken::Punctuation(';'));
        self.emit(CToken::Whitespace(" ".into()));
        if let Some(e) = condition {
            self.print_expression(e);
        }
        self.emit(CToken::Punctuation(';'));
        self.emit(CToken::Whitespace(" ".into()));
        if let Some(e) = step {
            self.print_expression(e);
        }
        self.emit(CToken::Punctuation(')'));
        self.emit(CToken::Whitespace(" ".into()));
        self.emit(CToken::Punctuation('{'));
        self.emit(CToken::Newline);

        self.indent_level += 1;
        self.print_node(body);
        self.indent_level -= 1;

        self.print_indent();
        self.emit(CToken::Punctuation('}'));
        self.emit(CToken::Newline);
    }

    fn print_switch(
        &mut self,
        expression: &Expression,
        cases: &[SwitchCase],
        default: Option<&StructuredNode>,
    ) {
        self.print_indent();
        self.emit(CToken::keyword("switch"));
        self.emit(CToken::Whitespace(" ".into()));
        self.emit(CToken::Punctuation('('));
        self.print_expression(expression);
        self.emit(CToken::Punctuation(')'));
        self.emit(CToken::Whitespace(" ".into()));
        self.emit(CToken::Punctuation('{'));
        self.emit(CToken::Newline);

        self.indent_level += 1;

        for case in cases {
            for val in &case.values {
                self.print_indent();
                self.emit(CToken::keyword("case"));
                self.emit(CToken::Whitespace(" ".into()));
                self.emit(CToken::Number {
                    text: format!("{}", val),
                    value: Some(*val as u64),
                });
                self.emit(CToken::Punctuation(':'));
                self.emit(CToken::Newline);
            }
            self.indent_level += 1;
            self.print_node(&case.body);
            self.indent_level -= 1;
            if !case.is_fallthrough {
                self.print_indent();
                self.emit(CToken::keyword("break"));
                self.emit(CToken::Punctuation(';'));
                self.emit(CToken::Newline);
            }
        }

        if let Some(default_node) = default {
            self.print_indent();
            self.emit(CToken::keyword("default"));
            self.emit(CToken::Punctuation(':'));
            self.emit(CToken::Newline);

            self.indent_level += 1;
            self.print_node(default_node);
            self.indent_level -= 1;

            self.print_indent();
            self.emit(CToken::keyword("break"));
            self.emit(CToken::Punctuation(';'));
            self.emit(CToken::Newline);
        }

        self.indent_level -= 1;
        self.print_indent();
        self.emit(CToken::Punctuation('}'));
        self.emit(CToken::Newline);
    }

    // ------------------------------------------------------------------
    // Expression printing (recursive, token-based)
    // ------------------------------------------------------------------

    fn print_expression(&mut self, expr: &Expression) {
        match expr {
            Expression::Variable { name, size: _ } => {
                self.emit(CToken::ident(name.as_str()));
            }
            Expression::Constant { value, size: _ } => {
                let text = format_constant_literal(*value);
                self.emit(CToken::Number {
                    text,
                    value: Some(*value),
                });
            }
            Expression::BinaryOp { op, left, right } => {
                self.print_expression(left);
                self.emit(CToken::Whitespace(" ".into()));
                self.emit(CToken::op(binary_op_str(*op)));
                self.emit(CToken::Whitespace(" ".into()));
                self.print_expression(right);
            }
            Expression::UnaryOp { op, operand } => {
                self.emit(CToken::op(unary_op_str(*op)));
                self.print_expression(operand);
            }
            Expression::Dereference { ptr, size: _ } => {
                self.emit(CToken::op("*"));
                self.print_expression(ptr);
            }
            Expression::AddressOf { operand } => {
                self.emit(CToken::op("&"));
                self.print_expression(operand);
            }
            Expression::Call { target, args } => {
                self.print_expression(target);
                self.emit(CToken::Punctuation('('));
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        self.emit(CToken::Punctuation(','));
                        self.emit(CToken::Whitespace(" ".into()));
                    }
                    self.print_expression(arg);
                }
                self.emit(CToken::Punctuation(')'));
            }
            Expression::Cast { target_type, expr } => {
                self.emit(CToken::Punctuation('('));
                self.emit(CToken::type_name(target_type.as_str()));
                self.emit(CToken::Punctuation(')'));
                self.print_expression(expr);
            }
            Expression::Ternary { cond, true_expr, false_expr } => {
                self.print_expression(cond);
                self.emit(CToken::Whitespace(" ".into()));
                self.emit(CToken::op("?"));
                self.emit(CToken::Whitespace(" ".into()));
                self.print_expression(true_expr);
                self.emit(CToken::Whitespace(" ".into()));
                self.emit(CToken::op(":"));
                self.emit(CToken::Whitespace(" ".into()));
                self.print_expression(false_expr);
            }
            Expression::ArrayAccess { base, index } => {
                self.print_expression(base);
                self.emit(CToken::Punctuation('['));
                self.print_expression(index);
                self.emit(CToken::Punctuation(']'));
            }
            Expression::FieldAccess { base, field } => {
                self.print_expression(base);
                self.emit(CToken::op("."));
                self.emit(CToken::ident(field.as_str()));
            }
            Expression::PcodeOp { opcode, inputs, output: _ } => {
                let inputs_str: Vec<String> = inputs
                    .iter()
                    .map(|v| format!("{}", v))
                    .collect();
                self.emit(CToken::Comment(format!(
                    "/* PCODE:{:?}({}) */",
                    opcode,
                    inputs_str.join(", ")
                )));
            }
            Expression::Assignment { lhs, rhs } => {
                self.print_expression(lhs);
                self.emit(CToken::Whitespace(" ".into()));
                self.emit(CToken::op("="));
                self.emit(CToken::Whitespace(" ".into()));
                self.print_expression(rhs);
            }
            Expression::Comma { left, right } => {
                self.print_expression(left);
                self.emit(CToken::Punctuation(','));
                self.emit(CToken::Whitespace(" ".into()));
                self.print_expression(right);
            }
            Expression::StringLiteral { value } => {
                self.emit(CToken::StringLiteral(value.clone()));
            }
            Expression::Nop => {}
        }
    }

    // ------------------------------------------------------------------
    // Emit helpers
    // ------------------------------------------------------------------

    fn emit(&mut self, token: CToken) {
        self.tokens.push(token);
    }

    fn print_indent(&mut self) {
        let spaces = " ".repeat(self.indent_level * self.config.indent_size);
        if !spaces.is_empty() {
            self.emit(CToken::Whitespace(spaces));
        }
    }

    fn print_signature(&mut self, func: &FunctionMetadata) {
        if func.is_static {
            self.emit(CToken::keyword("static"));
            self.emit(CToken::Whitespace(" ".into()));
        }
        if func.is_inline {
            self.emit(CToken::keyword("inline"));
            self.emit(CToken::Whitespace(" ".into()));
        }

        self.emit(CToken::type_name(func.return_type.as_str()));
        self.emit(CToken::Whitespace(" ".into()));
        self.emit(CToken::ident_at(func.name.as_str(), func.entry_point));

        self.emit(CToken::Punctuation('('));
        for (i, (ty, name)) in func.parameters.iter().enumerate() {
            if i > 0 {
                self.emit(CToken::Punctuation(','));
                self.emit(CToken::Whitespace(" ".into()));
            }
            self.emit(CToken::type_name(ty.as_str()));
            self.emit(CToken::Whitespace(" ".into()));
            self.emit(CToken::ident(name.as_str()));
        }
        if func.is_variadic {
            if !func.parameters.is_empty() {
                self.emit(CToken::Punctuation(','));
                self.emit(CToken::Whitespace(" ".into()));
            }
            self.emit(CToken::op("..."));
        }
        self.emit(CToken::Punctuation(')'));
    }
}

impl Default for PrettyPrinter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Expression-to-C-string helpers
// ============================================================================

/// Convert an expression to a C string representation.
fn expr_to_c(expr: &Expression, _outer_prec: u32, show_casts: bool) -> String {
    match expr {
        Expression::Variable { name, .. } => name.clone(),
        Expression::Constant { value, size: _ } => format_constant_literal(*value),
        Expression::BinaryOp { op, left, right } => {
            let lhs = expr_to_c(left, 0, show_casts);
            let rhs = expr_to_c(right, 0, show_casts);
            format!("{} {} {}", lhs, binary_op_str(*op), rhs)
        }
        Expression::UnaryOp { op, operand } => {
            let inner = expr_to_c(operand, 0, show_casts);
            format!("{}{}", unary_op_str(*op), inner)
        }
        Expression::Dereference { ptr, .. } => {
            format!("*{}", expr_to_c(ptr, 0, show_casts))
        }
        Expression::AddressOf { operand } => {
            format!("&{}", expr_to_c(operand, 0, show_casts))
        }
        Expression::Call { target, args } => {
            let args_str: Vec<String> = args
                .iter()
                .map(|a| expr_to_c(a, 0, show_casts))
                .collect();
            format!("{}({})", expr_to_c(target, 0, show_casts), args_str.join(", "))
        }
        Expression::Cast { target_type, expr } => {
            if show_casts {
                format!("({}){}", target_type, expr_to_c(expr, 0, show_casts))
            } else {
                expr_to_c(expr, 0, show_casts)
            }
        }
        Expression::Ternary { cond, true_expr, false_expr } => {
            format!(
                "{} ? {} : {}",
                expr_to_c(cond, 0, show_casts),
                expr_to_c(true_expr, 0, show_casts),
                expr_to_c(false_expr, 0, show_casts)
            )
        }
        Expression::ArrayAccess { base, index } => {
            format!(
                "{}[{}]",
                expr_to_c(base, 0, show_casts),
                expr_to_c(index, 0, show_casts)
            )
        }
        Expression::FieldAccess { base, field } => {
            format!("{}.{}", expr_to_c(base, 0, show_casts), field)
        }
        Expression::PcodeOp { opcode, inputs, output: _ } => {
            let inputs_str: Vec<String> = inputs.iter().map(|v| format!("{}", v)).collect();
            format!("/* PCODE:{:?}({}) */", opcode, inputs_str.join(", "))
        }
        Expression::Assignment { lhs, rhs } => {
            format!(
                "{} = {}",
                expr_to_c(lhs, 0, show_casts),
                expr_to_c(rhs, 0, show_casts)
            )
        }
        Expression::Comma { left, right } => {
            format!(
                "{}, {}",
                expr_to_c(left, 0, show_casts),
                expr_to_c(right, 0, show_casts)
            )
        }
        Expression::StringLiteral { value } => {
            format!("\"{}\"", value)
        }
        Expression::Nop => String::new(),
    }
}

/// Format a constant value as a C literal.
fn format_constant_literal(val: u64) -> String {
    if val <= 9 {
        format!("{}", val)
    } else if val <= 0xffff {
        format!("{:#x}", val)
    } else {
        format!("{:#x}", val)
    }
}

fn binary_op_str(op: BinaryOperator) -> &'static str {
    match op {
        BinaryOperator::Add => "+",
        BinaryOperator::Sub => "-",
        BinaryOperator::Mul => "*",
        BinaryOperator::Div => "/",
        BinaryOperator::Mod => "%",
        BinaryOperator::And => "&",
        BinaryOperator::Or => "|",
        BinaryOperator::Xor => "^",
        BinaryOperator::Shl => "<<",
        BinaryOperator::Shr => ">>",
        BinaryOperator::Eq => "==",
        BinaryOperator::Neq => "!=",
        BinaryOperator::Lt => "<",
        BinaryOperator::Le => "<=",
        BinaryOperator::Gt => ">",
        BinaryOperator::Ge => ">=",
        BinaryOperator::LogicalAnd => "&&",
        BinaryOperator::LogicalOr => "||",
    }
}

fn unary_op_str(op: UnaryOperator) -> &'static str {
    match op {
        UnaryOperator::Neg => "-",
        UnaryOperator::Not => "!",
        UnaryOperator::BitNot => "~",
        UnaryOperator::Deref => "*",
        UnaryOperator::AddressOf => "&",
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::control_flow_struct::BlockData;

    fn test_addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_ctoken_creation() {
        let kw = CToken::keyword("if");
        assert_eq!(kw.text(), "if");

        let ty = CToken::type_name("uint32_t");
        assert_eq!(ty.text(), "uint32_t");

        let id = CToken::ident("my_var");
        assert_eq!(id.text(), "my_var");

        let op = CToken::op("+=");
        assert_eq!(op.text(), "+=");

        let punct = CToken::Punctuation('{');
        assert_eq!(punct.text(), "{");
    }

    #[test]
    fn test_ctoken_is_whitespace() {
        assert!(CToken::Whitespace("  ".into()).is_whitespace());
        assert!(CToken::Newline.is_whitespace());
        assert!(!CToken::Keyword("if".into()).is_whitespace());
    }

    #[test]
    fn test_output_config_default() {
        let cfg = OutputConfig::default();
        assert_eq!(cfg.indent_size, 4);
        assert_eq!(cfg.max_line_length, 120);
        assert!(matches!(cfg.brace_style, BraceStyle::KAndR));
    }

    #[test]
    fn test_function_metadata() {
        let func = FunctionMetadata::new("main", test_addr(0x4000));
        assert_eq!(func.name, "main");
        assert_eq!(func.return_type, "void");
        assert!(func.parameters.is_empty());
    }

    #[test]
    fn test_format_function_simple() {
        let func = FunctionMetadata::new("foo", test_addr(0x1000));
        let body = StructuredNode::Return(Some(Box::new(Expression::Constant {
            value: 0,
            size: 4,
        })));

        let config = OutputConfig::default();
        let mut fmt = CFormatter::new(config);
        let output = fmt.format_function(&func, &body);

        assert!(output.contains("void foo()"));
        assert!(output.contains("return 0;"));
    }

    #[test]
    fn test_format_empty_block() {
        let config = OutputConfig::default();
        let fmt = CFormatter::new(config);
        let block = StructuredNode::Block(BlockData {
            operations: vec![],
            address: Address::NULL,
        });
        let out = fmt.format_node_owned(&block, 0);
        assert_eq!(out, "");
    }

    #[test]
    fn test_format_return_void() {
        let config = OutputConfig::default();
        let fmt = CFormatter::new(config);
        let node = StructuredNode::Return(None);
        let out = fmt.format_node_owned(&node, 0);
        assert_eq!(out.trim(), "return;");
    }

    #[test]
    fn test_pretty_printer_basic() {
        let mut pp = PrettyPrinter::new();
        let func = FunctionMetadata::new("main", test_addr(0x4000));
        let body = StructuredNode::Return(Some(Box::new(Expression::Constant {
            value: 0,
            size: 4,
        })));
        let tokens = pp.print_function(&func, &body);
        assert!(!tokens.is_empty());

        // Check for a keyword token.
        let has_return = tokens.iter().any(|t| matches!(t, CToken::Keyword(ref s) if s == "return"));
        assert!(has_return);
    }

    #[test]
    fn test_pretty_printer_to_string() {
        let mut pp = PrettyPrinter::new();
        let func = FunctionMetadata::new("foo", test_addr(0x1000));
        let body = StructuredNode::Return(None);
        pp.print_function(&func, &body);
        let text = pp.to_string();
        assert!(text.contains("void foo()"));
        assert!(text.contains("return;"));
    }

    #[test]
    fn test_pretty_printer_to_html() {
        let mut pp = PrettyPrinter::new();
        let func = FunctionMetadata::new("f", test_addr(0x1000));
        let body = StructuredNode::Return(Some(Box::new(Expression::Constant {
            value: 42,
            size: 4,
        })));
        pp.print_function(&func, &body);
        let html = pp.to_html();
        assert!(html.contains("<pre class=\"decompiled-code\">"));
        assert!(html.contains("return"));
    }

    #[test]
    fn test_pretty_printer_if_else() {
        let mut pp = PrettyPrinter::new();
        let func = FunctionMetadata::new("test_if", test_addr(0x1000));
        let body = StructuredNode::IfElse {
            condition: Expression::binary(
                BinaryOperator::Neq,
                Expression::Variable { name: "x".into(), size: 4 },
                Expression::Constant { value: 0, size: 4 },
            ),
            then_branch: Box::new(StructuredNode::Block(BlockData {
                operations: vec![Expression::Assignment {
                    lhs: Box::new(Expression::Variable { name: "y".into(), size: 4 }),
                    rhs: Box::new(Expression::Constant { value: 1, size: 4 }),
                }],
                address: Address::NULL,
            })),
            else_branch: None,
        };

        let _tokens = pp.print_function(&func, &body);
        let text = pp.to_string();
        assert!(text.contains("if"));
        assert!(text.contains("x != 0"));
    }

    #[test]
    fn test_expression_to_c() {
        let expr = Expression::binary(
            BinaryOperator::Add,
            Expression::Constant { value: 1, size: 4 },
            Expression::Constant { value: 2, size: 4 },
        );
        let c = expr_to_c(&expr, 0, true);
        assert_eq!(c, "1 + 2");
    }
}
