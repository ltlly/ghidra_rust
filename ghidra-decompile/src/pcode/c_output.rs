//! C code output generation from decompiled P-code.
//!
//! Converts decompiled P-code operations (after analysis, SSA, and
//! simplification) into human-readable C source code with structured
//! control flow.

use super::analysis::ControlFlowGraph;
use super::{OpCode, PcodeOperation, Varnode};
use ghidra_core::addr::Address;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;

// ---------------------------------------------------------------------------
// CToken
// ---------------------------------------------------------------------------

/// A token in the output C source stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CToken {
    /// A C keyword: `if`, `else`, `while`, `for`, `return`, `int`, `void`,
    /// `struct`, `switch`, `case`, `default`, `break`, `continue`, `goto`,
    /// `do`, `sizeof`, `typedef`, `const`, `static`, `unsigned`, `signed`,
    /// `char`, `short`, `long`, `float`, `double`, `enum`, `union`, `volatile`.
    Keyword(String),
    /// A type name.
    Type(String),
    /// An identifier (variable / function name).
    Identifier(String),
    /// A numeric literal.
    Number(String),
    /// A string literal.
    StringLiteral(String),
    /// A single-line or multi-line comment.
    Comment(String),
    /// An operator: `+`, `-`, `*`, `/`, `%`, `=`, `==`, `!=`, `<`, `>`,
    /// `<=`, `>=`, `&&`, `||`, `!`, `&`, `|`, `^`, `~`, `<<`, `>>`, etc.
    Operator(String),
    /// A punctuation character: `(`, `)`, `{`, `}`, `[`, `]`, `;`, `,`, `:`, `?`.
    Punctuation(char),
    /// A newline (for formatting).
    Newline,
    /// A space (for formatting).
    Space,
    /// An address label (for debugging / comments).
    Address(String),
    /// Increase indentation level.
    Indent,
    /// Decrease indentation level.
    Dedent,
    /// Raw text (fallback).
    Raw(String),
}

impl fmt::Display for CToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CToken::Keyword(k) => write!(f, "{}", k),
            CToken::Type(t) => write!(f, "{}", t),
            CToken::Identifier(id) => write!(f, "{}", id),
            CToken::Number(n) => write!(f, "{}", n),
            CToken::StringLiteral(s) => write!(f, "\"{}\"", s),
            CToken::Comment(c) => write!(f, "/* {} */", c),
            CToken::Operator(op) => write!(f, "{}", op),
            CToken::Punctuation(p) => write!(f, "{}", p),
            CToken::Newline => writeln!(f),
            CToken::Space => write!(f, " "),
            CToken::Address(a) => write!(f, "/* {} */", a),
            CToken::Indent => Ok(()),
            CToken::Dedent => Ok(()),
            CToken::Raw(s) => write!(f, "{}", s),
        }
    }
}

impl CToken {
    /// Create a keyword token.
    pub fn keyword(k: impl Into<String>) -> Self {
        CToken::Keyword(k.into())
    }

    /// Create an identifier token.
    pub fn ident(id: impl Into<String>) -> Self {
        CToken::Identifier(id.into())
    }

    /// Create a number token.
    pub fn number(n: impl fmt::Display) -> Self {
        CToken::Number(n.to_string())
    }

    /// Create an operator token.
    pub fn op(o: impl Into<String>) -> Self {
        CToken::Operator(o.into())
    }

    /// Convenience: semicolon.
    pub fn semi() -> Self {
        CToken::Punctuation(';')
    }

    /// Convenience: open paren.
    pub fn open_paren() -> Self {
        CToken::Punctuation('(')
    }

    /// Convenience: close paren.
    pub fn close_paren() -> Self {
        CToken::Punctuation(')')
    }

    /// Convenience: open brace.
    pub fn open_brace() -> Self {
        CToken::Punctuation('{')
    }

    /// Convenience: close brace.
    pub fn close_brace() -> Self {
        CToken::Punctuation('}')
    }

    /// Convenience: comma.
    pub fn comma() -> Self {
        CToken::Punctuation(',')
    }

    /// Convenience: assignment operator.
    pub fn assign() -> Self {
        CToken::Operator("=".to_string())
    }
}

// ---------------------------------------------------------------------------
// TokenOutputStream
// ---------------------------------------------------------------------------

/// A buffered token stream with automatic indentation management.
#[derive(Debug, Clone)]
pub struct TokenOutputStream {
    /// The accumulated tokens.
    tokens: Vec<CToken>,
    /// Current indentation level (number of spaces).
    indent_level: usize,
    /// Number of spaces per indent level.
    indent_width: usize,
    /// Whether the next token needs a newline before it.
    need_newline: bool,
}

impl TokenOutputStream {
    /// Create a new token output stream.
    pub fn new() -> Self {
        Self {
            tokens: Vec::new(),
            indent_level: 0,
            indent_width: 4,
            need_newline: true,
        }
    }

    /// Set the indent width.
    pub fn with_indent_width(mut self, width: usize) -> Self {
        self.indent_width = width;
        self
    }

    /// Push a single token.
    pub fn push(&mut self, token: CToken) {
        match &token {
            CToken::Newline => {
                self.tokens.push(token);
                self.need_newline = true;
            }
            CToken::Indent => {
                self.indent_level += 1;
            }
            CToken::Dedent => {
                if self.indent_level > 0 {
                    self.indent_level -= 1;
                }
            }
            _ => {
                if self.need_newline {
                    if !self.tokens.is_empty() {
                        // Emit indentation as raw spaces.
                        let indent = " ".repeat(self.indent_level * self.indent_width);
                        self.tokens.push(CToken::Raw(indent));
                    }
                    self.need_newline = false;
                }
                self.tokens.push(token);
            }
        }
    }

    /// Push a keyword.
    pub fn keyword(&mut self, kw: &str) {
        self.push(CToken::keyword(kw));
    }

    /// Push an identifier.
    pub fn ident(&mut self, id: &str) {
        self.push(CToken::ident(id));
    }

    /// Push a number.
    pub fn number(&mut self, n: impl fmt::Display) {
        self.push(CToken::number(n));
    }

    /// Push an operator.
    pub fn op(&mut self, op: &str) {
        self.push(CToken::Operator(op.to_string()));
    }

    /// Push a punctuation character.
    pub fn punct(&mut self, c: char) {
        self.push(CToken::Punctuation(c));
    }

    /// Push a newline.
    pub fn newline(&mut self) {
        self.push(CToken::Newline);
    }

    /// Push a space.
    pub fn space(&mut self) {
        self.push(CToken::Space);
    }

    /// Push a comment.
    pub fn comment(&mut self, text: &str) {
        self.push(CToken::Comment(text.to_string()));
    }

    /// Push raw text.
    pub fn raw(&mut self, text: &str) {
        self.push(CToken::Raw(text.to_string()));
    }

    /// Push a C assignment: `lhs = rhs;`
    pub fn assign_stmt(&mut self, lhs: &str, rhs: &str) {
        self.ident(lhs);
        self.space();
        self.op("=");
        self.space();
        self.raw(rhs);
        self.punct(';');
        self.newline();
    }

    /// Push a variable declaration: `type name;`
    pub fn var_decl(&mut self, ty: &str, name: &str) {
        self.raw(ty);
        self.space();
        self.ident(name);
        self.punct(';');
        self.newline();
    }

    /// Push an initialised variable declaration: `type name = init;`
    pub fn var_decl_init(&mut self, ty: &str, name: &str, init: &str) {
        self.raw(ty);
        self.space();
        self.ident(name);
        self.space();
        self.op("=");
        self.space();
        self.raw(init);
        self.punct(';');
        self.newline();
    }

    /// Push the tokens as a single rendered string.
    pub fn render(&self) -> String {
        let mut result = String::new();
        for token in &self.tokens {
            match token {
                CToken::Indent | CToken::Dedent => {}
                CToken::Raw(s) => result.push_str(s),
                CToken::Newline => result.push('\n'),
                CToken::Space => result.push(' '),
                _ => {
                    let s = token.to_string();
                    result.push_str(&s);
                }
            }
        }
        result
    }

    /// Returns the number of tokens in the stream.
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Returns true if the stream is empty.
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

impl Default for TokenOutputStream {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TokenOutputStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.render())
    }
}

// ---------------------------------------------------------------------------
// COutputFormatter
// ---------------------------------------------------------------------------

/// Formatting options for C output.
#[derive(Debug, Clone)]
pub struct CFormatOptions {
    /// Number of spaces per indentation level.
    pub indent_width: usize,
    /// Whether to emit address comments.
    pub emit_address_comments: bool,
    /// Whether to emit variable-type comments.
    pub emit_type_comments: bool,
    /// Whether to use C99-style single-line comments (`//`).
    pub c99_comments: bool,
    /// Maximum line width before wrapping.
    pub max_line_width: usize,
    /// Whether to emit `break` after every `case`.
    pub implicit_break: bool,
    /// Preferred integer type.
    pub int_type: String,
    /// Preferred pointer type prefix (`uint8_t*` vs `void*`).
    pub pointer_style: PointerStyle,
    /// Whether to use braces around single-statement bodies.
    pub braces_always: bool,
}

/// How pointers are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerStyle {
    /// `void *ptr`
    SpaceStar,
    /// `void* ptr`
    AttachedStar,
}

impl Default for CFormatOptions {
    fn default() -> Self {
        Self {
            indent_width: 4,
            emit_address_comments: true,
            emit_type_comments: false,
            c99_comments: true,
            max_line_width: 100,
            implicit_break: false,
            int_type: "int".to_string(),
            pointer_style: PointerStyle::SpaceStar,
            braces_always: true,
        }
    }
}

/// A C output formatter that manages the token stream and formatting
/// decisions.
#[derive(Debug, Clone)]
pub struct COutputFormatter {
    stream: TokenOutputStream,
    options: CFormatOptions,
}

impl COutputFormatter {
    /// Create a new formatter.
    pub fn new(options: CFormatOptions) -> Self {
        Self {
            stream: TokenOutputStream::new().with_indent_width(options.indent_width),
            options,
        }
    }

    /// Returns a reference to the internal token stream.
    pub fn stream(&self) -> &TokenOutputStream {
        &self.stream
    }

    /// Returns a mutable reference to the internal token stream.
    pub fn stream_mut(&mut self) -> &mut TokenOutputStream {
        &mut self.stream
    }

    /// Returns the formatting options.
    pub fn options(&self) -> &CFormatOptions {
        &self.options
    }

    /// Emit a function header: `return_type name(params)`.
    pub fn emit_function_header(
        &mut self,
        return_type: &str,
        name: &str,
        params: &[(String, String)], // (type, name)
    ) {
        self.stream.raw(return_type);
        self.stream.space();
        self.stream.ident(name);
        self.stream.punct('(');

        for (i, (ty, param_name)) in params.iter().enumerate() {
            if i > 0 {
                self.stream.punct(',');
                self.stream.space();
            }
            self.stream.raw(ty);
            self.stream.space();
            self.stream.ident(param_name);
        }

        self.stream.punct(')');
    }

    /// Emit an opening brace with newline and indent.
    pub fn emit_open_brace(&mut self) {
        self.stream.space();
        self.stream.punct('{');
        self.stream.newline();
        self.stream.push(CToken::Indent);
    }

    /// Emit a closing brace with dedent and newline.
    pub fn emit_close_brace(&mut self) {
        self.stream.push(CToken::Dedent);
        self.stream.punct('}');
        self.stream.newline();
    }

    /// Emit a return statement.
    pub fn emit_return(&mut self, value: Option<&str>) {
        self.stream.keyword("return");
        if let Some(v) = value {
            self.stream.space();
            self.stream.raw(v);
        }
        self.stream.punct(';');
        self.stream.newline();
    }

    /// Emit an if statement.
    pub fn emit_if(&mut self, condition: &str) {
        self.stream.keyword("if");
        self.stream.space();
        self.stream.punct('(');
        self.stream.raw(condition);
        self.stream.punct(')');
    }

    /// Emit an else keyword.
    pub fn emit_else(&mut self) {
        self.stream.keyword("else");
    }

    /// Emit a while loop header.
    pub fn emit_while(&mut self, condition: &str) {
        self.stream.keyword("while");
        self.stream.space();
        self.stream.punct('(');
        self.stream.raw(condition);
        self.stream.punct(')');
    }

    /// Emit a for loop header.
    pub fn emit_for(&mut self, init: &str, condition: &str, update: &str) {
        self.stream.keyword("for");
        self.stream.space();
        self.stream.punct('(');
        self.stream.raw(init);
        self.stream.punct(';');
        self.stream.space();
        self.stream.raw(condition);
        self.stream.punct(';');
        self.stream.space();
        self.stream.raw(update);
        self.stream.punct(')');
    }

    /// Emit a do keyword.
    pub fn emit_do(&mut self) {
        self.stream.keyword("do");
    }

    /// Emit a switch statement header.
    pub fn emit_switch(&mut self, expr: &str) {
        self.stream.keyword("switch");
        self.stream.space();
        self.stream.punct('(');
        self.stream.raw(expr);
        self.stream.punct(')');
    }

    /// Emit a case label.
    pub fn emit_case(&mut self, value: &str) {
        self.stream.push(CToken::Dedent);
        self.stream.keyword("case");
        self.stream.space();
        self.stream.raw(value);
        self.stream.punct(':');
        self.stream.newline();
        self.stream.push(CToken::Indent);
    }

    /// Emit a default label.
    pub fn emit_default(&mut self) {
        self.stream.push(CToken::Dedent);
        self.stream.keyword("default");
        self.stream.punct(':');
        self.stream.newline();
        self.stream.push(CToken::Indent);
    }

    /// Emit a break statement.
    pub fn emit_break(&mut self) {
        self.stream.keyword("break");
        self.stream.punct(';');
        self.stream.newline();
    }

    /// Emit a goto statement.
    pub fn emit_goto(&mut self, label: &str) {
        self.stream.keyword("goto");
        self.stream.space();
        self.stream.ident(label);
        self.stream.punct(';');
        self.stream.newline();
    }

    /// Emit a label for goto targets.
    pub fn emit_label(&mut self, label: &str) {
        self.stream.push(CToken::Dedent);
        self.stream.ident(label);
        self.stream.punct(':');
        self.stream.newline();
        self.stream.push(CToken::Indent);
    }

    /// Emit an address comment.
    pub fn emit_address_comment(&mut self, addr: Address) {
        if self.options.emit_address_comments {
            if self.options.c99_comments {
                self.stream.raw(&format!("// 0x{:08x}", addr.offset));
            } else {
                self.stream.raw(&format!("/* 0x{:08x} */", addr.offset));
            }
            self.stream.newline();
        }
    }

    /// Consume the formatter and return the rendered string.
    pub fn finish(self) -> String {
        self.stream.render()
    }
}

// ---------------------------------------------------------------------------
// ControlFlowStructurer
// ---------------------------------------------------------------------------

/// A structured-program node extracted from a CFG.
#[derive(Debug, Clone)]
pub enum StructuredNode {
    /// A basic block of sequential statements.
    Block {
        statements: Vec<String>,
        address: Option<Address>,
    },
    /// An if-then construct.
    IfThen {
        condition: String,
        then_body: Box<StructuredNode>,
        address: Option<Address>,
    },
    /// An if-then-else construct.
    IfElse {
        condition: String,
        then_body: Box<StructuredNode>,
        else_body: Box<StructuredNode>,
        address: Option<Address>,
    },
    /// A while loop.
    While {
        condition: String,
        body: Box<StructuredNode>,
        address: Option<Address>,
    },
    /// A do-while loop.
    DoWhile {
        condition: String,
        body: Box<StructuredNode>,
        address: Option<Address>,
    },
    /// A switch statement.
    Switch {
        expression: String,
        cases: Vec<(String, StructuredNode)>,
        default: Option<Box<StructuredNode>>,
        address: Option<Address>,
    },
    /// A sequence of nodes.
    Sequence(Vec<StructuredNode>),
    /// A goto jump (last resort).
    Goto {
        label: String,
        address: Option<Address>,
    },
    /// A goto label target.
    Label {
        name: String,
        address: Option<Address>,
    },
    /// A return statement.
    Return {
        value: Option<String>,
        address: Option<Address>,
    },
    /// A break from the enclosing loop/switch.
    Break,
    /// A continue to the next iteration of the enclosing loop.
    Continue,
}

/// Structures a control-flow graph into structured-program nodes.
pub struct ControlFlowStructurer {
    /// Variables tracked for naming.
    var_names: HashMap<Varnode, String>,
    /// Next unique variable name counter.
    var_counter: u64,
    /// Label counter for goto labels.
    label_counter: u64,
}

impl ControlFlowStructurer {
    /// Create a new structurer.
    pub fn new() -> Self {
        Self {
            var_names: HashMap::new(),
            var_counter: 0,
            label_counter: 0,
        }
    }

    /// Structure a function given its decompiled operations and CFG.
    pub fn structure(
        &mut self,
        operations: &[PcodeOperation],
        _cfg: &ControlFlowGraph,
    ) -> StructuredNode {
        // Build a list of statement strings from the operations.
        let mut statements: Vec<String> = Vec::new();
        let mut current_block_ops: Vec<String> = Vec::new();
        let mut first_addr: Option<Address> = None;

        for op in operations {
            if op.is_phi() {
                // Phi nodes are not emitted directly; they represent SSA
                // merges.  Skip for now.
                continue;
            }

            let stmt = self.operation_to_c(op);

            if op.is_terminator() {
                // End of a structured block.
                if !current_block_ops.is_empty() {
                    statements.extend(current_block_ops.drain(..));
                }
                statements.push(stmt);
                first_addr = None;
            } else {
                if first_addr.is_none() {
                    first_addr = op.address;
                }
                current_block_ops.push(stmt);
            }
        }

        // Flush remaining statements.
        if !current_block_ops.is_empty() {
            statements.extend(current_block_ops);
        }

        if statements.is_empty() {
            return StructuredNode::Block {
                statements: vec!["/* empty */".to_string()],
                address: None,
            };
        }

        StructuredNode::Block {
            statements,
            address: first_addr,
        }
    }

    /// Convert a single P-code operation to a C expression or statement
    /// string.
    pub fn operation_to_c(&mut self, op: &PcodeOperation) -> String {
        match op.opcode {
            OpCode::COPY => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                let inp = self.varnode_to_expr(&op.inputs[0]);
                format!("{} = {};", out, inp)
            }

            OpCode::LOAD => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                let ptr = self.varnode_to_expr(&op.inputs[1]);
                format!("{} = *((int*){}) /* LOAD */;", out, ptr)
            }

            OpCode::STORE => {
                let ptr = self.varnode_to_expr(&op.inputs[1]);
                let val = self.varnode_to_expr(&op.inputs[2]);
                format!("*((int*){}) = {}; /* STORE */", ptr, val)
            }

            OpCode::BRANCH => {
                if let Some(target) = op.inputs.first().and_then(|v| v.constant_value()) {
                    format!("goto LAB_0x{:08x};", target)
                } else {
                    "/* indirect branch */".to_string()
                }
            }

            OpCode::CBRANCH => {
                let cond = self.varnode_to_expr(&op.inputs[1]);
                if let Some(target) = op.inputs.first().and_then(|v| v.constant_value()) {
                    format!(
                        "if ({}) {{ goto LAB_0x{:08x}; }}",
                        cond, target
                    )
                } else {
                    format!("if ({}) {{ /* indirect branch */ }}", cond)
                }
            }

            OpCode::BRANCHIND => {
                let target = self.varnode_to_expr(&op.inputs[0]);
                format!("/* indirect branch to {} */", target)
            }

            OpCode::CALL => {
                let target = op.inputs.first()
                    .and_then(|v| v.constant_value())
                    .map(|v| format!("0x{:x}", v))
                    .unwrap_or_else(|| "unknown".to_string());
                let args: Vec<String> = op.inputs[1..]
                    .iter()
                    .map(|v| self.varnode_to_expr(v))
                    .collect();
                let call_str = format!("sub_{}({})", target, args.join(", "));

                if let Some(ref out) = op.output {
                    let out_name = self.varnode_name(out);
                    format!("{} = {};", out_name, call_str)
                } else {
                    format!("{};", call_str)
                }
            }

            OpCode::CALLIND => {
                let target = self.varnode_to_expr(&op.inputs[0]);
                let args: Vec<String> = op.inputs[1..]
                    .iter()
                    .map(|v| self.varnode_to_expr(v))
                    .collect();
                let call_str = format!("((int(*)()){})({})", target, args.join(", "));

                if let Some(ref out) = op.output {
                    let out_name = self.varnode_name(out);
                    format!("{} = {};", out_name, call_str)
                } else {
                    format!("{};", call_str)
                }
            }

            OpCode::RETURN => {
                if let Some(ref val) = op.inputs.first() {
                    format!("return {};", self.varnode_to_expr(val))
                } else {
                    "return;".to_string()
                }
            }

            OpCode::INT_ADD => self.emit_binary_op(op, "+"),
            OpCode::INT_SUB => self.emit_binary_op(op, "-"),
            OpCode::INT_MUL => self.emit_binary_op(op, "*"),
            OpCode::INT_DIV => self.emit_binary_op(op, "/"),
            OpCode::INT_SDIV => self.emit_binary_op(op, "/"),
            OpCode::INT_REM => self.emit_binary_op(op, "%"),
            OpCode::INT_SREM => self.emit_binary_op(op, "%"),
            OpCode::INT_AND => self.emit_binary_op(op, "&"),
            OpCode::INT_OR => self.emit_binary_op(op, "|"),
            OpCode::INT_XOR => self.emit_binary_op(op, "^"),
            OpCode::INT_LEFT => self.emit_binary_op(op, "<<"),
            OpCode::INT_RIGHT => self.emit_binary_op(op, ">>"),
            OpCode::INT_SRIGHT => {
                // Signed right shift in C is implementation-defined for
                // negative values in older standards, but in practice is
                // arithmetic.
                self.emit_binary_op(op, ">>")
            }

            OpCode::INT_EQUAL => self.emit_binary_op(op, "=="),
            OpCode::INT_NOTEQUAL => self.emit_binary_op(op, "!="),
            OpCode::INT_LESS => self.emit_binary_op(op, "<"),
            OpCode::INT_SLESS => self.emit_binary_op(op, "<"),
            OpCode::INT_LESSEQUAL => self.emit_binary_op(op, "<="),
            OpCode::INT_SLESSEQUAL => self.emit_binary_op(op, "<="),

            OpCode::INT_NEGATE => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                let inp = self.varnode_to_expr(&op.inputs[0]);
                format!("{} = -{};", out, inp)
            }

            OpCode::INT_SEXT | OpCode::INT_ZEXT => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                let inp = self.varnode_to_expr(&op.inputs[0]);
                format!("{} = (int){}; /* ext */", out, inp)
            }

            OpCode::BOOL_NEGATE => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                let inp = self.varnode_to_expr(&op.inputs[0]);
                format!("{} = !{};", out, inp)
            }

            OpCode::BOOL_AND => self.emit_binary_op(op, "&&"),
            OpCode::BOOL_OR => self.emit_binary_op(op, "||"),

            OpCode::FLOAT_ADD => self.emit_binary_op(op, "+"),
            OpCode::FLOAT_SUB => self.emit_binary_op(op, "-"),
            OpCode::FLOAT_MUL => self.emit_binary_op(op, "*"),
            OpCode::FLOAT_DIV => self.emit_binary_op(op, "/"),
            OpCode::FLOAT_NEG => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                let inp = self.varnode_to_expr(&op.inputs[0]);
                format!("{} = -{};", out, inp)
            }
            OpCode::FLOAT_ABS => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                let inp = self.varnode_to_expr(&op.inputs[0]);
                format!("{} = fabs({});", out, inp)
            }
            OpCode::FLOAT_SQRT => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                let inp = self.varnode_to_expr(&op.inputs[0]);
                format!("{} = sqrt({});", out, inp)
            }
            OpCode::FLOAT_INT2FLOAT => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                let inp = self.varnode_to_expr(&op.inputs[0]);
                format!("{} = (float){};", out, inp)
            }
            OpCode::FLOAT_FLOAT2INT | OpCode::FLOAT_TRUNC => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                let inp = self.varnode_to_expr(&op.inputs[0]);
                format!("{} = (float){};", out, inp)
            }
            OpCode::FLOAT_CEIL => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                let inp = self.varnode_to_expr(&op.inputs[0]);
                format!("{} = ceil({});", out, inp)
            }
            OpCode::FLOAT_FLOOR => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                let inp = self.varnode_to_expr(&op.inputs[0]);
                format!("{} = floor({});", out, inp)
            }
            OpCode::FLOAT_ROUND => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                let inp = self.varnode_to_expr(&op.inputs[0]);
                format!("{} = round({});", out, inp)
            }
            OpCode::FLOAT_NAN => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                format!("{} = NAN;", out)
            }
            OpCode::FLOAT_EQUAL => self.emit_binary_op(op, "=="),
            OpCode::FLOAT_NOTEQUAL => self.emit_binary_op(op, "!="),
            OpCode::FLOAT_LESS => self.emit_binary_op(op, "<"),
            OpCode::FLOAT_LESSEQUAL => self.emit_binary_op(op, "<="),

            OpCode::CAST => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                let inp = self.varnode_to_expr(&op.inputs[0]);
                format!("{} = (int){}; /* cast */", out, inp)
            }

            OpCode::PTRADD => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                let base = self.varnode_to_expr(&op.inputs[0]);
                let index = self.varnode_to_expr(&op.inputs[1]);
                let scale = self.varnode_to_expr(&op.inputs[2]);
                format!("{} = {} + {} * {};", out, base, index, scale)
            }

            OpCode::PTRSUB => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                let lhs = self.varnode_to_expr(&op.inputs[0]);
                let rhs = self.varnode_to_expr(&op.inputs[1]);
                format!("{} = {} - {};", out, lhs, rhs)
            }

            OpCode::PIECE => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                let hi = self.varnode_to_expr(&op.inputs[0]);
                let lo = self.varnode_to_expr(&op.inputs[1]);
                format!(
                    "{} = ((uint64_t){} << {}bits) | {};",
                    out,
                    hi,
                    op.inputs[1].size * 8,
                    lo
                )
            }

            OpCode::SUBPIECE => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                let inp = self.varnode_to_expr(&op.inputs[0]);
                let lo = self.varnode_to_expr(&op.inputs[1]);
                format!("{} = ({} >> ({} * 8)) & 0x{:x};",
                    out, inp, lo,
                    (1u64 << (op.output.as_ref().map(|o| o.size * 8).unwrap_or(8))) - 1
                )
            }

            OpCode::POPCOUNT => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                let inp = self.varnode_to_expr(&op.inputs[0]);
                format!("{} = __builtin_popcount({});", out, inp)
            }

            OpCode::LZCOUNT => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                let inp = self.varnode_to_expr(&op.inputs[0]);
                format!("{} = __builtin_clz({});", out, inp)
            }

            OpCode::NEW => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                let size = self.varnode_to_expr(&op.inputs[0]);
                format!("{} = malloc({});", out, size)
            }

            OpCode::CPOOLREF => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                format!("{} = /* cpool */ 0;", out)
            }

            OpCode::INSERT | OpCode::EXTRACT => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                format!("{} = 0; /* bitfield {} */", out, op.opcode)
            }

            OpCode::SEGMENTOP => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                format!("{} = /* segmentop */ 0;", out)
            }

            OpCode::MULTIEQUAL => {
                // Phi node; the inputs represent values from different
                // paths.  In structured code, this is already resolved by
                // the control-flow structurer.
                let out = self.varnode_name(op.output.as_ref().unwrap());
                let inputs: Vec<String> = op.inputs.iter().map(|v| self.varnode_to_expr(v)).collect();
                format!("/* phi: {} = {{{}}} */", out, inputs.join(", "))
            }

            OpCode::INDIRECT => {
                let out = self.varnode_name(op.output.as_ref().unwrap());
                format!("{} = /* indirect */ 0;", out)
            }

            OpCode::UNIMPLEMENTED => {
                "/* UNIMPLEMENTED */".to_string()
            }

            _ => {
                // Default: try generic format.
                self.emit_generic_op(op)
            }
        }
    }

    /// Emit a binary operation as a C assignment: `out = lhs op rhs;`
    fn emit_binary_op(&mut self, op: &PcodeOperation, operator: &str) -> String {
        if let Some(ref out) = op.output {
            let out_name = self.varnode_name(out);
            let lhs = self.varnode_to_expr(&op.inputs[0]);
            let rhs = self.varnode_to_expr(&op.inputs[1]);
            format!("{} = {} {} {};", out_name, lhs, operator, rhs)
        } else {
            let lhs = self.varnode_to_expr(&op.inputs[0]);
            let rhs = self.varnode_to_expr(&op.inputs[1]);
            format!("/* {} {} {} */", lhs, operator, rhs)
        }
    }

    /// Emit a generic operation for unrecognized opcodes.
    fn emit_generic_op(&mut self, op: &PcodeOperation) -> String {
        let out_str = if let Some(o) = &op.output {
            format!("{} = ", self.varnode_name(o))
        } else {
            String::new()
        };
        let mut inputs: Vec<String> = Vec::new();
        for v in &op.inputs {
            inputs.push(self.varnode_to_expr(v));
        }
        format!("{}{}({});", out_str, op.opcode, inputs.join(", "))
    }

    /// Get a human-readable name for a varnode.
    fn varnode_name(&mut self, vn: &Varnode) -> String {
        if let Some(name) = self.var_names.get(vn) {
            return name.clone();
        }

        let name = if vn.is_register() {
            format!("reg_{:x}", vn.offset)
        } else if vn.is_unique() {
            self.var_counter += 1;
            format!("var_{}", self.var_counter)
        } else if vn.is_ram() {
            format!("mem_{:x}", vn.offset)
        } else if vn.is_constant() {
            return vn.constant_value()
                .map(|v| format!("0x{:x}", v))
                .unwrap_or_else(|| "0".to_string());
        } else {
            format!("{}_{:x}", vn.space.name, vn.offset)
        };

        self.var_names.insert(vn.clone(), name.clone());
        name
    }

    /// Convert a varnode to a C expression string.
    fn varnode_to_expr(&mut self, vn: &Varnode) -> String {
        if vn.is_constant() {
            vn.constant_value()
                .map(|v| {
                    if v <= 9 {
                        format!("{}", v)
                    } else {
                        format!("0x{:x}", v)
                    }
                })
                .unwrap_or_else(|| "0".to_string())
        } else {
            self.varnode_name(vn)
        }
    }
}

impl Default for ControlFlowStructurer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DecompResults
// ---------------------------------------------------------------------------

/// The result of decompiling a function.
#[derive(Debug, Clone)]
pub struct DecompResults {
    /// The (simplified, analysis-processed) P-code operations.
    pub operations: Vec<PcodeOperation>,
    /// Variable names.
    pub variable_names: HashMap<Varnode, String>,
    /// Inferred types for variables.
    pub variable_types: HashMap<String, String>,
    /// Address of the function entry.
    pub entry_address: Address,
}

impl DecompResults {
    /// Create new decompilation results.
    pub fn new(operations: Vec<PcodeOperation>, entry_address: Address) -> Self {
        Self {
            operations,
            variable_names: HashMap::new(),
            variable_types: HashMap::new(),
            entry_address,
        }
    }
}

// ---------------------------------------------------------------------------
// FunctionInfo
// ---------------------------------------------------------------------------

/// High-level information about a function being decompiled.
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    /// Function name.
    pub name: String,
    /// Return type (C type string).
    pub return_type: String,
    /// Parameters: (type, name).
    pub parameters: Vec<(String, String)>,
    /// Function entry address.
    pub address: Address,
}

impl FunctionInfo {
    /// Create a new function info.
    pub fn new(name: impl Into<String>, address: Address) -> Self {
        Self {
            name: name.into(),
            return_type: "void".to_string(),
            parameters: Vec::new(),
            address,
        }
    }

    /// Set the return type.
    pub fn with_return_type(mut self, ty: impl Into<String>) -> Self {
        self.return_type = ty.into();
        self
    }

    /// Add a parameter.
    pub fn with_param(mut self, ty: impl Into<String>, name: impl Into<String>) -> Self {
        self.parameters.push((ty.into(), name.into()));
        self
    }
}

// ---------------------------------------------------------------------------
// format_function
// ---------------------------------------------------------------------------

/// Format a function as C source code.
///
/// This is the top-level entry point for C output generation.  Given a
/// function descriptor and decompilation results (processed P-code after
/// SSA, constant propagation, dead-code elimination, and expression
/// simplification), it produces a formatted C string.
pub fn format_function(
    function: &FunctionInfo,
    results: &DecompResults,
) -> String {
    let options = CFormatOptions::default();
    format_function_with_options(function, results, &options)
}

/// Format a function with custom C formatting options.
pub fn format_function_with_options(
    function: &FunctionInfo,
    results: &DecompResults,
    options: &CFormatOptions,
) -> String {
    let mut formatter = COutputFormatter::new(options.clone());
    let stream = formatter.stream_mut();

    // Emit function header comment.
    if options.emit_address_comments {
        if options.c99_comments {
            stream.raw(&format!(
                "// Function: {}  (entry: 0x{:08x})",
                function.name, function.address.offset
            ));
        } else {
            stream.raw(&format!(
                "/* Function: {}  (entry: 0x{:08x}) */",
                function.name, function.address.offset
            ));
        }
        stream.newline();
    }

    // Emit function signature.
    stream.raw(&function.return_type);
    stream.space();
    stream.ident(&function.name);
    stream.punct('(');

    for (i, (ty, name)) in function.parameters.iter().enumerate() {
        if i > 0 {
            stream.punct(',');
            stream.space();
        }
        stream.raw(ty);
        if !name.is_empty() {
            stream.space();
            stream.ident(name);
        }
    }

    stream.punct(')');
    stream.newline();
    stream.punct('{');
    stream.newline();
    stream.push(CToken::Indent);

    // Emit variable declarations.
    let mut declared: HashSet<String> = HashSet::new();
    for (vn, name) in &results.variable_names {
        if !declared.contains(name) && !vn.is_constant() && !vn.is_register() {
            let ty = results
                .variable_types
                .get(name)
                .cloned()
                .unwrap_or_else(|| {
                    match vn.size {
                        1 => "uint8_t".to_string(),
                        2 => "uint16_t".to_string(),
                        4 => "uint32_t".to_string(),
                        8 => "uint64_t".to_string(),
                        _ => format!("uint8_t[{}]", vn.size),
                    }
                });
            stream.raw(&ty);
            stream.space();
            stream.ident(name);
            stream.punct(';');
            stream.newline();
            declared.insert(name.clone());
        }
    }

    if !declared.is_empty() {
        stream.newline();
    }

    // Emit operations as statements.
    let mut structurer = ControlFlowStructurer::new();

    // Seed the structurer with any existing variable names.
    for (vn, name) in &results.variable_names {
        structurer.var_names.insert(vn.clone(), name.clone());
    }

    // Use the structurer to convert operations to C.
    let mut prev_addr: Option<Address> = None;

    for op in &results.operations {
        if op.is_phi() {
            continue; // Skip phi nodes in final output.
        }

        // Emit address comments when the instruction address changes.
        if let Some(addr) = op.address {
            if prev_addr.map_or(true, |p| p != addr) {
                if options.emit_address_comments {
                    if options.c99_comments {
                        stream.raw(&format!("// 0x{:08x}", addr.offset));
                    } else {
                        stream.raw(&format!("/* 0x{:08x} */", addr.offset));
                    }
                    stream.newline();
                }
                prev_addr = Some(addr);
            }
        }

        let stmt = structurer.operation_to_c(op);
        stream.raw(&stmt);
        stream.newline();
    }

    // Close function body.
    stream.push(CToken::Dedent);
    stream.punct('}');
    stream.newline();

    formatter.finish()
}

/// Structure a function body by converting P-code into structured C
/// statements, using the CFG for control-flow recovery.
pub fn structure_function_body(
    operations: &[PcodeOperation],
    cfg: &ControlFlowGraph,
    var_names: &HashMap<Varnode, String>,
) -> String {
    let mut structurer = ControlFlowStructurer::new();

    // Seed variable names.
    for (vn, name) in var_names {
        structurer.var_names.insert(vn.clone(), name.clone());
    }

    let node = structurer.structure(operations, cfg);
    format_structured_node(&node, 0, &var_names)
}

/// Format a structured node as indented C code.
fn format_structured_node(
    node: &StructuredNode,
    indent: usize,
    var_names: &HashMap<Varnode, String>,
) -> String {
    let indent_str = " ".repeat(indent * 4);
    let _ = var_names;
    match node {
        StructuredNode::Block { statements, .. } => {
            let mut result = String::new();
            for stmt in statements {
                result.push_str(&indent_str);
                result.push_str(stmt);
                result.push('\n');
            }
            result
        }

        StructuredNode::IfThen {
            condition,
            then_body,
            ..
        } => {
            let mut result = format!("{}if ({}) {{\n", indent_str, condition);
            result.push_str(&format_structured_node(then_body, indent + 1, var_names));
            result.push_str(&format!("{}}}\n", indent_str));
            result
        }

        StructuredNode::IfElse {
            condition,
            then_body,
            else_body,
            ..
        } => {
            let mut result = format!("{}if ({}) {{\n", indent_str, condition);
            result.push_str(&format_structured_node(then_body, indent + 1, var_names));
            result.push_str(&format!("{}}} else {{\n", indent_str));
            result.push_str(&format_structured_node(else_body, indent + 1, var_names));
            result.push_str(&format!("{}}}\n", indent_str));
            result
        }

        StructuredNode::While {
            condition, body, ..
        } => {
            let mut result = format!("{}while ({}) {{\n", indent_str, condition);
            result.push_str(&format_structured_node(body, indent + 1, var_names));
            result.push_str(&format!("{}}}\n", indent_str));
            result
        }

        StructuredNode::DoWhile {
            condition, body, ..
        } => {
            let mut result = format!("{}do {{\n", indent_str);
            result.push_str(&format_structured_node(body, indent + 1, var_names));
            result.push_str(&format!("{}}} while ({});\n", indent_str, condition));
            result
        }

        StructuredNode::Switch {
            expression,
            cases,
            default,
            ..
        } => {
            let mut result = format!("{}switch ({}) {{\n", indent_str, expression);
            for (value, body) in cases {
                result.push_str(&format!("{}case {}:\n", indent_str, value));
                result.push_str(&format_structured_node(body, indent + 1, var_names));
                result.push_str(&format!("{}  break;\n", indent_str));
            }
            if let Some(default_body) = default {
                result.push_str(&format!("{}default:\n", indent_str));
                result.push_str(&format_structured_node(default_body, indent + 1, var_names));
                result.push_str(&format!("{}  break;\n", indent_str));
            }
            result.push_str(&format!("{}}}\n", indent_str));
            result
        }

        StructuredNode::Sequence(nodes) => {
            let mut result = String::new();
            for node in nodes {
                result.push_str(&format_structured_node(node, indent, var_names));
            }
            result
        }

        StructuredNode::Goto { label, .. } => {
            format!("{}goto {};\n", indent_str, label)
        }

        StructuredNode::Label { name, .. } => {
            format!("{}{}:\n", indent_str, name)
        }

        StructuredNode::Return { value, .. } => {
            if let Some(v) = value {
                format!("{}return {};\n", indent_str, v)
            } else {
                format!("{}return;\n", indent_str)
            }
        }

        StructuredNode::Break => {
            format!("{}break;\n", indent_str)
        }

        StructuredNode::Continue => {
            format!("{}continue;\n", indent_str)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::{OpCode, PcodeOperation, Varnode};
    use ghidra_core::addr::{Address, AddressSpace};

    fn make_vn(name: &str, offset: u64, size: u32) -> Varnode {
        Varnode::new(AddressSpace::new(name, 8, false), offset, size)
    }

    #[test]
    fn test_token_stream_basic() {
        let mut stream = TokenOutputStream::new();
        stream.keyword("int");
        stream.space();
        stream.ident("main");
        stream.punct('(');
        stream.punct(')');
        stream.space();
        stream.punct('{');
        stream.newline();
        stream.push(CToken::Indent);
        stream.keyword("return");
        stream.space();
        stream.number(0);
        stream.punct(';');
        stream.newline();
        stream.push(CToken::Dedent);
        stream.punct('}');
        stream.newline();

        let rendered = stream.render();
        assert!(rendered.contains("int main()"));
        assert!(rendered.contains("return 0;"));
    }

    #[test]
    fn test_token_stream_indent() {
        let mut stream = TokenOutputStream::new();
        stream.keyword("if");
        stream.punct('(');
        stream.ident("x");
        stream.punct(')');
        stream.space();
        stream.punct('{');
        stream.newline();
        stream.push(CToken::Indent);
        stream.ident("y");
        stream.space();
        stream.op("=");
        stream.space();
        stream.number(1);
        stream.punct(';');
        stream.newline();
        stream.push(CToken::Dedent);
        stream.punct('}');
        stream.newline();

        let rendered = stream.render();
        assert!(rendered.contains("    y = 1;")); // indented
    }

    #[test]
    fn test_control_flow_structurer_arithmetic() {
        let mut structurer = ControlFlowStructurer::new();
        let out = make_vn("unique", 0, 4);
        let lhs = make_vn("register", 0, 4);
        let rhs = make_vn("const", 42, 4);

        let op = PcodeOperation::new_unannotated(
            OpCode::INT_ADD,
            Some(out.clone()),
            vec![lhs.clone(), rhs.clone()],
        );

        let stmt = structurer.operation_to_c(&op);
        assert!(stmt.contains("+"), "should contain '+' operator");
        assert!(stmt.ends_with(';'), "should end with semicolon");
    }

    #[test]
    fn test_control_flow_structurer_store() {
        let mut structurer = ControlFlowStructurer::new();
        let space = make_vn("const", 0, 8);
        let ptr = make_vn("register", 0, 8);
        let val = make_vn("const", 99, 4);

        let op = PcodeOperation::new_unannotated(
            OpCode::STORE,
            None,
            vec![space, ptr, val],
        );

        let stmt = structurer.operation_to_c(&op);
        assert!(stmt.contains("STORE"), "should contain STORE comment");
    }

    #[test]
    fn test_control_flow_structurer_branch() {
        let mut structurer = ControlFlowStructurer::new();
        let target = Varnode::constant(0x401000, 8);

        let op = PcodeOperation::new_unannotated(
            OpCode::BRANCH,
            None,
            vec![target],
        );

        let stmt = structurer.operation_to_c(&op);
        assert!(stmt.contains("goto"), "should emit goto");
    }

    #[test]
    fn test_format_function_simple() {
        let func = FunctionInfo::new("test_func", Address::new(0x1000))
            .with_return_type("int");

        let out = make_vn("unique", 0, 4);
        let lhs = make_vn("register", 0, 4);
        let rhs = make_vn("const", 10, 4);

        let mut results = DecompResults::new(
            vec![
                PcodeOperation::new(
                    OpCode::INT_ADD,
                    Some(out.clone()),
                    vec![lhs.clone(), rhs],
                    Some(Address::new(0x1000)),
                ),
                PcodeOperation::new(
                    OpCode::RETURN,
                    None,
                    vec![out.clone()],
                    Some(Address::new(0x1004)),
                ),
            ],
            Address::new(0x1000),
        );
        results
            .variable_names
            .insert(lhs, "param1".to_string());
        results
            .variable_names
            .insert(out, "result".to_string());

        let output = format_function(&func, &results);
        assert!(output.contains("test_func"));
        assert!(output.contains("param1"));
        assert!(output.contains("result"));
        assert!(output.contains("return"));
    }

    #[test]
    fn test_ctoken_display() {
        let kw = CToken::keyword("if");
        assert_eq!(kw.to_string(), "if");

        let id = CToken::ident("main");
        assert_eq!(id.to_string(), "main");

        let num = CToken::number(42);
        assert_eq!(num.to_string(), "42");

        let op = CToken::op("+");
        assert_eq!(op.to_string(), "+");

        let punct = CToken::Punctuation(';');
        assert_eq!(punct.to_string(), ";");

        let nl = CToken::Newline;
        assert_eq!(nl.to_string(), "\n");
    }

    #[test]
    fn test_c_output_formatter() {
        let options = CFormatOptions::default();
        let mut fmt = COutputFormatter::new(options);

        fmt.emit_function_header("int", "foo", &[
            ("int".to_string(), "a".to_string()),
            ("int".to_string(), "b".to_string()),
        ]);
        fmt.emit_open_brace();
        fmt.emit_return(Some("a + b"));
        fmt.emit_close_brace();

        let output = fmt.finish();
        assert!(output.contains("int foo(int a, int b)"));
        assert!(output.contains("return a + b;"));
    }

    #[test]
    fn test_ctoken_helpers() {
        assert_eq!(CToken::semi().to_string(), ";");
        assert_eq!(CToken::open_paren().to_string(), "(");
        assert_eq!(CToken::close_paren().to_string(), ")");
        assert_eq!(CToken::open_brace().to_string(), "{");
        assert_eq!(CToken::close_brace().to_string(), "}");
        assert_eq!(CToken::comma().to_string(), ",");
        assert_eq!(CToken::assign().to_string(), "=");
    }
}
