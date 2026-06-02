//! C code output formatter for the Ghidra decompiler.
//!
//! Converts the decompiler's structured IR ([`StructuredNode`] trees,
//! [`Expression`] nodes) into compilable C source code. Supports multiple
//! brace styles, configurable indentation, address annotations, and a
//! [`TokenOutputStream`] for GUI rendering with syntax highlighting.
//!
//! # Architecture
//!
//! 1. [`COutputFormatter`] -- Recursively walks a [`StructuredNode`] tree and
//!    emits C source text. Consults [`OutputOptions`] for formatting choices.
//! 2. [`TokenOutputStream`] -- A parallel output path that produces a sequence
//!    of [`CToken`] values instead of raw text. Suitable for IDE-style
//!    rendering with clickable addresses, syntax-coloured identifiers, etc.
//!
//! # Example
//!
//! ```ignore
//! use ghidra_decompile::analysis::c_output::COutputFormatter;
//! use ghidra_decompile::analysis::control_flow_struct::StructuredNode;
//!
//! let mut fmt = COutputFormatter::new();
//! // ... obtain a StructuredNode from the decompiler ...
//! // let c_code = fmt.format_node(&root_node, 0);
//! ```

use std::collections::HashMap;
use std::fmt::Write;

use ghidra_core::addr::Address;
use ghidra_core::data::DataType;

use super::control_flow_struct::{
    BinaryOperator, BlockData, Expression, StructuredNode, SwitchCase, UnaryOperator,
};

// ============================================================================
// OutputOptions
// ============================================================================

/// Options controlling C code output formatting.
#[derive(Debug, Clone)]
pub struct OutputOptions {
    /// Number of spaces per indentation level.
    pub indent_size: usize,
    /// Maximum line length before the formatter attempts to break.
    pub max_line_length: usize,
    /// Brace placement style.
    pub braced_style: BraceStyle,
    /// Emit `// line` comments showing the original address sequence.
    pub show_line_numbers: bool,
    /// Emit the raw hex address as a comment after each statement.
    pub show_raw_addresses: bool,
    /// Emit explicit type casts (e.g., `(int32_t)`).
    pub show_type_casts: bool,
    /// Apply expression simplification (constant folding, etc.).
    pub simplify_expressions: bool,
    /// Rename temporary/unique variables to human-friendly names.
    pub rename_variables: bool,
    /// Use typedef names rather than full type expansions when available.
    pub use_typedefs: bool,
    /// Emit decompiler-generated comments.
    pub emit_comments: bool,
    /// Emit variable declarations at the top of the function body.
    pub emit_var_decls: bool,
    /// Sort variable declarations by name (otherwise in order of first use).
    pub sort_variables: bool,
}

impl Default for OutputOptions {
    fn default() -> Self {
        Self {
            indent_size: 4,
            max_line_length: 120,
            braced_style: BraceStyle::KAndR,
            show_line_numbers: false,
            show_raw_addresses: false,
            show_type_casts: true,
            simplify_expressions: true,
            rename_variables: true,
            use_typedefs: true,
            emit_comments: true,
            emit_var_decls: true,
            sort_variables: true,
        }
    }
}

// ============================================================================
// BraceStyle
// ============================================================================

/// Brace placement styles analogous to popular C formatting conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BraceStyle {
    /// Kernighan & Ritchie: opening brace on same line as control keyword.
    ///
    /// ```c
    /// if (cond) {
    ///     body;
    /// }
    /// ```
    KAndR,

    /// Allman / ANSI: opening brace on its own line.
    ///
    /// ```c
    /// if (cond)
    /// {
    ///     body;
    /// }
    /// ```
    Allman,

    /// GNU: opening brace on its own line, indented by half the indent size.
    ///
    /// ```c
    /// if (cond)
    ///   {
    ///     body;
    ///   }
    /// ```
    GNU,

    /// Whitesmiths: both braces on their own lines, body indented.
    ///
    /// ```c
    /// if (cond)
    ///     {
    ///     body;
    ///     }
    /// ```
    Whitesmiths,

    /// Horstmann / Pico: first brace on the next line, second aligned with
    /// the control keyword. The body is indented.
    ///
    /// ```c
    /// if (cond)
    /// {   body;
    /// }
    /// ```
    Horstmann,
}

// ============================================================================
// Variable -- a named entity in the decompiled output
// ============================================================================

/// A decompiled variable (local, parameter, global, or register).
///
/// Tracked by the formatter to emit declarations and consistent naming.
#[derive(Debug, Clone)]
pub struct Variable {
    /// Human-readable name assigned to this variable.
    pub name: String,
    /// The data type of this variable.
    pub data_type: Option<DataType>,
    /// Size in bytes.
    pub size: u32,
    /// The address where this variable lives (for globals and stack locals).
    pub address: Option<Address>,
    /// Storage class hint.
    pub storage: VariableStorage,
}

impl Variable {
    /// Create a new stack local variable.
    pub fn local(name: impl Into<String>, data_type: Option<DataType>, size: u32) -> Self {
        Self {
            name: name.into(),
            data_type,
            size,
            address: None,
            storage: VariableStorage::Local,
        }
    }

    /// Create a new function parameter variable.
    pub fn parameter(
        name: impl Into<String>,
        data_type: Option<DataType>,
        size: u32,
    ) -> Self {
        Self {
            name: name.into(),
            data_type,
            size,
            address: None,
            storage: VariableStorage::Parameter,
        }
    }

    /// Create a new global variable.
    pub fn global(
        name: impl Into<String>,
        data_type: Option<DataType>,
        size: u32,
        address: Address,
    ) -> Self {
        Self {
            name: name.into(),
            data_type,
            size,
            address: Some(address),
            storage: VariableStorage::Global,
        }
    }

    /// Create a new register variable.
    pub fn register(name: impl Into<String>, size: u32) -> Self {
        Self {
            name: name.into(),
            data_type: None,
            size,
            address: None,
            storage: VariableStorage::Register,
        }
    }

    /// Convenience: create an unnamed local with a size.
    pub fn unnamed_local(id: u64, size: u32) -> Self {
        Self {
            name: format!("local_{:x}", id),
            data_type: None,
            size,
            address: None,
            storage: VariableStorage::Local,
        }
    }

    /// Returns a C type string for declarations.
    pub fn type_string(&self) -> String {
        match &self.data_type {
            Some(dt) => dt.name().to_string(),
            None => size_to_ctype(self.size),
        }
    }
}

// ============================================================================
// VariableStorage
// ============================================================================

/// Where a variable is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VariableStorage {
    /// Function-local (stack or register, scope == function).
    Local,
    /// Function parameter.
    Parameter,
    /// Global variable.
    Global,
    /// Hardware register.
    Register,
    /// Compiler temporary (not visible in the original source).
    Temporary,
}

// ============================================================================
// Statement -- a single C statement
// ============================================================================

/// A single C statement produced by the decompiler.
///
/// This is a convenience wrapper that bundles a [`StructuredNode`] (the
/// control-flow construct) with optional metadata such as the originating
/// address.
#[derive(Debug, Clone)]
pub struct Statement {
    /// The structured node representing this statement.
    pub node: StructuredNode,
    /// The address of the original machine instruction (for comments).
    pub address: Option<Address>,
    /// A decompiler-generated comment for this statement.
    pub comment: Option<String>,
}

impl Statement {
    /// Create a simple statement from a node.
    pub fn from_node(node: StructuredNode) -> Self {
        Self {
            node,
            address: None,
            comment: None,
        }
    }

    /// Create a statement with an originating address.
    pub fn with_address(node: StructuredNode, address: Address) -> Self {
        Self {
            node,
            address: Some(address),
            comment: None,
        }
    }

    /// Create a statement with a decompiler comment.
    pub fn with_comment(node: StructuredNode, comment: impl Into<String>) -> Self {
        Self {
            node,
            address: None,
            comment: Some(comment.into()),
        }
    }
}

// ============================================================================
// Function -- function metadata for code generation
// ============================================================================

/// Metadata for a function being decompiled.
#[derive(Debug, Clone)]
pub struct Function {
    /// Function name.
    pub name: String,
    /// Return type, if known.
    pub return_type: Option<DataType>,
    /// Function parameters.
    pub parameters: Vec<Variable>,
    /// Local variables.
    pub locals: Vec<Variable>,
    /// The entry-point address.
    pub entry_point: Address,
    /// Function signature comment (e.g., calling convention notes).
    pub signature_comment: Option<String>,
    /// True if this is a variadic function.
    pub is_variadic: bool,
    /// True if this function is inline.
    pub is_inline: bool,
    /// True if this function is static (file-local).
    pub is_static: bool,
}

impl Function {
    /// Create a new function with the given name and entry point.
    pub fn new(name: impl Into<String>, entry_point: Address) -> Self {
        Self {
            name: name.into(),
            return_type: None,
            parameters: Vec::new(),
            locals: Vec::new(),
            entry_point,
            signature_comment: None,
            is_variadic: false,
            is_inline: false,
            is_static: false,
        }
    }
}

// ============================================================================
// DecompileResults
// ============================================================================

/// The complete results of decompiling a single function.
#[derive(Debug, Clone)]
pub struct DecompileResults {
    /// The function that was decompiled.
    pub function: Function,
    /// The root structured node (function body).
    pub root: Option<StructuredNode>,
    /// All local variables discovered during decompilation.
    pub variables: Vec<Variable>,
    /// Address-to-line-number mapping.
    pub address_to_line: HashMap<Address, u64>,
    /// Decompiler diagnostic messages.
    pub diagnostics: Vec<String>,
    /// Whether the decompilation was fully successful.
    pub success: bool,
}

impl DecompileResults {
    /// Create a successful decompilation result.
    pub fn success(function: Function, root: StructuredNode) -> Self {
        Self {
            function,
            root: Some(root),
            variables: Vec::new(),
            address_to_line: HashMap::new(),
            diagnostics: Vec::new(),
            success: true,
        }
    }

    /// Create a failed decompilation result with diagnostics.
    pub fn failure(function: Function, diagnostics: Vec<String>) -> Self {
        Self {
            function,
            root: None,
            variables: Vec::new(),
            address_to_line: HashMap::new(),
            diagnostics,
            success: false,
        }
    }
}

// ============================================================================
// COutputFormatter
// ============================================================================

/// The C code output formatter.
///
/// Walks a [`StructuredNode`] tree and emits formatted C source code. The
/// formatter is stateless beyond its options, so a single instance can be
/// reused across many functions.
///
/// # Brace Styles
///
/// The `braced_style` field on [`OutputOptions`] controls brace placement:
///
/// | Style       | Opening brace              | Closing brace        |
/// |-------------|----------------------------|----------------------|
/// | `KAndR`     | `if (cond) {`              | `}`                  |
/// | `Allman`    | `if (cond)\n{`             | `}`                  |
/// | `GNU`       | `if (cond)\n  {`           | `  }`                |
/// | `Whitesmiths`| `if (cond)\n    {`        | `    }`              |
/// | `Horstmann` | `if (cond)\n{   body;`     | `}`                  |
#[derive(Debug, Clone)]
pub struct COutputFormatter {
    /// Output formatting options.
    pub options: OutputOptions,
    /// The indentation string (e.g., four spaces).
    pub indent: String,
    /// Prefix string for line comments.
    pub line_comment: String,
    /// Whether to emit address annotations.
    pub show_addresses: bool,
}

impl COutputFormatter {
    /// Create a new formatter with default options.
    pub fn new() -> Self {
        let options = OutputOptions::default();
        let indent = " ".repeat(options.indent_size);
        Self {
            indent,
            line_comment: "//".to_string(),
            show_addresses: options.show_raw_addresses,
            options,
        }
    }

    /// Create a formatter with custom options.
    pub fn with_options(options: OutputOptions) -> Self {
        let indent = " ".repeat(options.indent_size);
        let show_addresses = options.show_raw_addresses;
        Self {
            indent,
            line_comment: "//".to_string(),
            show_addresses,
            options,
        }
    }

    // ==================================================================
    // Top-level formatting
    // ==================================================================

    /// Format a complete decompiled function as C source code.
    ///
    /// Emits the function signature, variable declarations, and body.
    pub fn format_function(
        &self,
        func: &Function,
        decomp: &DecompileResults,
    ) -> String {
        let mut out = String::new();

        // --- Address header comment ---
        if self.options.show_raw_addresses {
            let _ = writeln!(
                out,
                "{} function at {}",
                self.line_comment, func.entry_point
            );
        }

        // --- Signature comment ---
        if self.options.emit_comments {
            if let Some(ref comment) = func.signature_comment {
                let _ = writeln!(out, "{} {}", self.line_comment, comment);
            }
        }

        // --- Function signature ---
        self.write_function_signature(&mut out, func);

        // --- If decompilation failed, emit a comment and stop ---
        if !decomp.success {
            let _ = writeln!(out, " {{");
            let _ = writeln!(
                out,
                "{} WARNING: Decompilation failed.",
                self.indent
            );
            for diag in &decomp.diagnostics {
                let _ = writeln!(out, "{} {} {}", self.indent, self.line_comment, diag);
            }
            let _ = writeln!(out, "}}");
            let _ = writeln!(out);
            return out;
        }

        // --- Opening brace ---
        self.write_opening_brace(&mut out, 0);

        // --- Diagnostics as comments ---
        if self.options.emit_comments && !decomp.diagnostics.is_empty() {
            for diag in &decomp.diagnostics {
                let _ = writeln!(
                    out,
                    "{} {} Warning: {}",
                    self.indent, self.line_comment, diag
                );
            }
            let _ = writeln!(out);
        }

        // --- Variable declarations ---
        if self.options.emit_var_decls {
            self.write_variable_declarations(&mut out, func, decomp);
        }

        // --- Function body ---
        if let Some(ref root) = decomp.root {
            let body = self.format_node(root, 1);
            if !body.is_empty() {
                let _ = write!(out, "{}", body);
            }
        }

        // --- Closing brace ---
        let _ = writeln!(out, "}}");
        let _ = writeln!(out);

        out
    }

    /// Format a structured node (and its subtree) as C code.
    pub fn format_node(&self, node: &StructuredNode, indent: usize) -> String {
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
            } => self.format_for(init.as_deref(), condition.as_deref(), step.as_deref(), body, indent),
            StructuredNode::Switch {
                expression,
                cases,
                default,
            } => self.format_switch(expression, cases, default.as_deref(), indent),
            StructuredNode::Goto { label, .. } => self.format_goto(label, indent),
            StructuredNode::Label { name, node } => self.format_label(name, node, indent),
            StructuredNode::Break => self.format_break(indent),
            StructuredNode::Continue => self.format_continue(indent),
            StructuredNode::Return(expr) => self.format_return(expr.as_deref(), indent),
            StructuredNode::InfiniteLoop { body } => self.format_infinite_loop(body, indent),
            StructuredNode::Sequence(nodes) => self.format_sequence(nodes, indent),
        }
    }

    /// Format a decompiler expression as a C expression string.
    pub fn format_expression(&self, expr: &Expression) -> String {
        self.format_expr_inner(expr, 0)
    }

    /// Format a data type as a C type string.
    pub fn format_type(&self, data_type: &DataType) -> String {
        data_type.name().to_string()
    }

    /// Format a variable declaration as a C declaration.
    pub fn format_variable_decl(&self, var: &Variable) -> String {
        let type_str = var.type_string();
        format!("{} {};", type_str, var.name)
    }

    /// Format a single statement as C code.
    pub fn format_statement(&self, stmt: &Statement) -> String {
        let mut out = String::new();
        let indent_level = 0;

        // Address comment.
        if self.options.show_raw_addresses {
            if let Some(ref addr) = stmt.address {
                let _ = writeln!(
                    out,
                    "{}{} {:#x}",
                    self.indent_prefix(indent_level),
                    self.line_comment,
                    addr.offset
                );
            }
        }

        // Decompiler comment.
        if self.options.emit_comments {
            if let Some(ref comment) = stmt.comment {
                let _ = writeln!(
                    out,
                    "{}{} {}",
                    self.indent_prefix(indent_level),
                    self.line_comment,
                    comment
                );
            }
        }

        let body = self.format_node(&stmt.node, indent_level);
        let _ = write!(out, "{}", body);
        out
    }

    // ==================================================================
    // StructuredNode dispatch
    // ==================================================================

    /// Format a basic block.
    fn format_block(&self, block: &BlockData, indent: usize) -> String {
        let mut out = String::new();
        let prefix = self.indent_prefix(indent);

        for expr in &block.operations {
            // Address annotation.
            if self.options.show_raw_addresses && !block.address.is_null() {
                let _ = writeln!(
                    out,
                    "{}{} {:#x}",
                    prefix, self.line_comment, block.address.offset
                );
            }
            let expr_str = self.format_expr_inner(expr, 0);
            let _ = writeln!(out, "{}{};", prefix, expr_str);
        }

        out
    }

    /// Format an if/else construct.
    fn format_if_else(
        &self,
        condition: &Expression,
        then_branch: &StructuredNode,
        else_branch: Option<&StructuredNode>,
        indent: usize,
    ) -> String {
        let mut out = String::new();
        let cond_str = self.format_expr_inner(condition, 0);
        let prefix = self.indent_prefix(indent);

        // `if (condition)`
        let if_line = format!("{}if ({})", prefix, cond_str);
        self.write_control_flow_opening(&mut out, &if_line, indent);

        // then body
        let then_body = self.format_node(then_branch, indent + 1);
        let _ = write!(out, "{}", then_body);

        // else
        if let Some(else_node) = else_branch {
            // If the else branch is itself an if/else, chain as `else if`.
            if let StructuredNode::IfElse {
                condition: _,
                then_branch: _,
                else_branch: _,
            } = else_node
            {
                // Close the then clause and write `else if` on the same line.
                let close_prefix = self.indent_prefix(indent);
                let else_body = self.format_node(else_node, indent);
                // The inner if/else already emits its own `if (...)`.
                let _ = write!(
                    out,
                    "{}else {}",
                    close_prefix,
                    else_body.trim_start()
                );
            } else {
                let close_prefix = self.indent_prefix(indent);
                let _ = writeln!(out, "{}else", close_prefix);

                // Opening brace on else.
                self.write_opening_brace(&mut out, indent);

                let else_body = self.format_node(else_node, indent + 1);
                let _ = write!(out, "{}", else_body);

                let _ = writeln!(out, "{}}}", self.indent_prefix(indent));
            }
        } else {
            // Close the then clause.
            let _ = writeln!(out, "{}}}", self.indent_prefix(indent));
        }

        out
    }

    /// Format a while loop.
    fn format_while(
        &self,
        condition: &Expression,
        body: &StructuredNode,
        indent: usize,
    ) -> String {
        let mut out = String::new();
        let cond_str = self.format_expr_inner(condition, 0);
        let while_line = format!("{}while ({})", self.indent_prefix(indent), cond_str);

        self.write_control_flow_opening(&mut out, &while_line, indent);
        let body_str = self.format_node(body, indent + 1);
        let _ = write!(out, "{}", body_str);
        let _ = writeln!(out, "{}}}", self.indent_prefix(indent));

        out
    }

    /// Format a do-while loop.
    fn format_do_while(
        &self,
        condition: &Expression,
        body: &StructuredNode,
        indent: usize,
    ) -> String {
        let mut out = String::new();
        let prefix = self.indent_prefix(indent);

        let _ = writeln!(out, "{}do", prefix);
        self.write_opening_brace(&mut out, indent);

        let body_str = self.format_node(body, indent + 1);
        let _ = write!(out, "{}", body_str);

        let cond_str = self.format_expr_inner(condition, 0);
        let _ = writeln!(out, "{}}} while ({});", prefix, cond_str);

        out
    }

    /// Format a for loop.
    fn format_for(
        &self,
        init: Option<&Expression>,
        condition: Option<&Expression>,
        step: Option<&Expression>,
        body: &StructuredNode,
        indent: usize,
    ) -> String {
        let mut out = String::new();
        let init_str = init
            .map(|e| self.format_expr_inner(e, 0))
            .unwrap_or_default();
        let cond_str = condition
            .map(|e| self.format_expr_inner(e, 0))
            .unwrap_or_default();
        let step_str = step
            .map(|e| self.format_expr_inner(e, 0))
            .unwrap_or_default();

        let for_line = format!(
            "{}for ({}; {}; {})",
            self.indent_prefix(indent),
            init_str,
            cond_str,
            step_str
        );

        self.write_control_flow_opening(&mut out, &for_line, indent);
        let body_str = self.format_node(body, indent + 1);
        let _ = write!(out, "{}", body_str);
        let _ = writeln!(out, "{}}}", self.indent_prefix(indent));

        out
    }

    /// Format a switch statement.
    fn format_switch(
        &self,
        expression: &Expression,
        cases: &[SwitchCase],
        default: Option<&StructuredNode>,
        indent: usize,
    ) -> String {
        let mut out = String::new();
        let prefix = self.indent_prefix(indent);
        let expr_str = self.format_expr_inner(expression, 0);

        let switch_line = format!("{}switch ({})", prefix, expr_str);
        self.write_control_flow_opening(&mut out, &switch_line, indent);

        let inner_indent = indent + 1;
        let inner_prefix = self.indent_prefix(inner_indent);

        for case in cases {
            for val in &case.values {
                let _ = writeln!(out, "{}case {}:", inner_prefix, val);
            }
            let case_body = self.format_node(&case.body, inner_indent + 1);
            let _ = write!(out, "{}", case_body);
            if !case.is_fallthrough {
                let _ = writeln!(
                    out,
                    "{}break;",
                    self.indent_prefix(inner_indent + 1)
                );
            }
        }

        if let Some(default_node) = default {
            let _ = writeln!(out, "{}default:", inner_prefix);
            let default_body = self.format_node(default_node, inner_indent + 1);
            let _ = write!(out, "{}", default_body);
            let _ = writeln!(
                out,
                "{}break;",
                self.indent_prefix(inner_indent + 1)
            );
        }

        let _ = writeln!(out, "{}}}", prefix);
        out
    }

    /// Format a goto statement.
    fn format_goto(&self, label: &str, indent: usize) -> String {
        let prefix = self.indent_prefix(indent);
        format!("{}goto {};\n", prefix, label)
    }

    /// Format a label for a goto target.
    fn format_label(&self, name: &str, node: &StructuredNode, indent: usize) -> String {
        let mut out = String::new();
        let prefix = self.indent_prefix(indent);
        // Labels are typically at one level less indentation.
        let label_indent = if indent > 0 { indent - 1 } else { 0 };
        let label_prefix = self.indent_prefix(label_indent);

        let _ = writeln!(out, "{} {}:", label_prefix, name);
        let body = self.format_node(node, indent);
        let _ = write!(out, "{}", body);
        out
    }

    /// Format a break statement.
    fn format_break(&self, indent: usize) -> String {
        format!("{}break;\n", self.indent_prefix(indent))
    }

    /// Format a continue statement.
    fn format_continue(&self, indent: usize) -> String {
        format!("{}continue;\n", self.indent_prefix(indent))
    }

    /// Format a return statement.
    fn format_return(&self, expr: Option<&Expression>, indent: usize) -> String {
        match expr {
            Some(e) => {
                format!(
                    "{}return {};\n",
                    self.indent_prefix(indent),
                    self.format_expr_inner(e, 0)
                )
            }
            None => format!("{}return;\n", self.indent_prefix(indent)),
        }
    }

    /// Format an infinite loop `for (;;) { ... }`.
    fn format_infinite_loop(&self, body: &StructuredNode, indent: usize) -> String {
        let mut out = String::new();
        let for_line = format!("{}for (;;)", self.indent_prefix(indent));

        self.write_control_flow_opening(&mut out, &for_line, indent);
        let body_str = self.format_node(body, indent + 1);
        let _ = write!(out, "{}", body_str);
        let _ = writeln!(out, "{}}}", self.indent_prefix(indent));

        out
    }

    /// Format a sequence of nodes executed in order.
    fn format_sequence(&self, nodes: &[StructuredNode], indent: usize) -> String {
        let mut out = String::new();
        for node in nodes {
            let _ = write!(out, "{}", self.format_node(node, indent));
        }
        out
    }

    // ==================================================================
    // Expression formatting (recursive, precedence-aware)
    // ==================================================================

    /// Format an expression, adding parentheses when the outer context
    /// requires higher precedence than the sub-expression's operator.
    ///
    /// `outer_prec` is the precedence of the enclosing operator (0 = top-level).
    fn format_expr_inner(&self, expr: &Expression, outer_prec: u32) -> String {
        match expr {
            Expression::Variable { name, .. } => self.simplify_variable_name(name),

            Expression::Constant { value, size } => self.format_constant(*value, *size),

            Expression::BinaryOp { op, left, right } => {
                let op_str = binary_operator_str(*op);
                let prec = operator_precedence(*op);
                let need_parens = outer_prec > prec;

                let left_str = self.format_expr_inner(left, prec);
                let right_str = self.format_expr_inner(right, prec);

                let result = format!("{} {} {}", left_str, op_str, right_str);
                if need_parens {
                    format!("({})", result)
                } else {
                    result
                }
            }

            Expression::UnaryOp { op, operand } => {
                match op {
                    UnaryOperator::Deref => {
                        // Dereference: *operand.  Use parens if operand is
                        // not a simple term.
                        let inner = self.format_expr_inner(operand, PREC_UNARY);
                        let needs_parens = is_complex_expression(operand);
                        if needs_parens {
                            format!("*({})", inner)
                        } else {
                            format!("*{}", inner)
                        }
                    }
                    UnaryOperator::AddressOf => {
                        let inner = self.format_expr_inner(operand, PREC_UNARY);
                        format!("&{}", inner)
                    }
                    _ => {
                        let op_str = unary_operator_str(*op);
                        let inner = self.format_expr_inner(operand, PREC_UNARY);
                        format!("{}{}", op_str, inner)
                    }
                }
            }

            Expression::Dereference { ptr, size: _ } => {
                let inner = self.format_expr_inner(ptr, PREC_UNARY);
                let needs_parens = is_complex_expression(ptr);
                if needs_parens {
                    format!("*({})", inner)
                } else {
                    format!("*{}", inner)
                }
            }

            Expression::AddressOf { operand } => {
                let inner = self.format_expr_inner(operand, PREC_UNARY);
                format!("&{}", inner)
            }

            Expression::Call { target, args } => {
                let target_str = self.format_expr_inner(target, 0);
                let args_str: Vec<String> = args
                    .iter()
                    .map(|a| self.format_expr_inner(a, 0))
                    .collect();
                format!("{}({})", target_str, args_str.join(", "))
            }

            Expression::Cast {
                target_type,
                expr,
            } => {
                if self.options.show_type_casts {
                    let inner = self.format_expr_inner(expr, PREC_CAST);
                    format!("({})({})", target_type, inner)
                } else {
                    self.format_expr_inner(expr, outer_prec)
                }
            }

            Expression::Ternary {
                cond,
                true_expr,
                false_expr,
            } => {
                let cond_str = self.format_expr_inner(cond, PREC_ASSIGNMENT + 1);
                let true_str = self.format_expr_inner(true_expr, 0);
                let false_str = self.format_expr_inner(false_expr, 0);
                let result = format!("{} ? {} : {}", cond_str, true_str, false_str);
                if outer_prec > PREC_TERNARY {
                    format!("({})", result)
                } else {
                    result
                }
            }

            Expression::ArrayAccess { base, index } => {
                let base_str = self.format_expr_inner(base, PREC_UNARY);
                let idx_str = self.format_expr_inner(index, 0);
                format!("{}[{}]", base_str, idx_str)
            }

            Expression::FieldAccess { base, field } => {
                let base_str = self.format_expr_inner(base, PREC_UNARY);
                format!("{}.{}", base_str, field)
            }

            Expression::PcodeOp { opcode, inputs, output: _ } => {
                // Emit a comment with the raw P-code opcode when we cannot
                // lift it.
                let inputs_str: Vec<String> = inputs
                    .iter()
                    .map(|v| format!("{}_{:x}", v.space.name, v.offset))
                    .collect();
                format!(
                    "/* PCODE:{:?}({}) */",
                    opcode,
                    inputs_str.join(", ")
                )
            }

            Expression::Assignment { lhs, rhs } => {
                let lhs_str = self.format_expr_inner(lhs, PREC_ASSIGNMENT + 1);
                let rhs_str = self.format_expr_inner(rhs, PREC_ASSIGNMENT);
                let result = format!("{} = {}", lhs_str, rhs_str);
                if outer_prec > PREC_ASSIGNMENT {
                    format!("({})", result)
                } else {
                    result
                }
            }

            Expression::Comma { left, right } => {
                let left_str = self.format_expr_inner(left, PREC_COMMA);
                let right_str = self.format_expr_inner(right, PREC_COMMA);
                let result = format!("{}, {}", left_str, right_str);
                if outer_prec > PREC_COMMA {
                    format!("({})", result)
                } else {
                    result
                }
            }

            Expression::Nop => String::new(),
        }
    }

    /// Rename a decompiler-generated variable name to a human-friendly form
    /// when `rename_variables` is enabled.
    fn simplify_variable_name(&self, name: &str) -> String {
        if !self.options.rename_variables {
            return name.to_string();
        }

        // If the name already looks like a user-defined name, leave it alone.
        if name.chars().all(|c| c.is_alphanumeric() || c == '_')
            && !name.starts_with("u_")
            && !name.starts_with("mem_")
        {
            return name.to_string();
        }

        // For decompiler internals, produce a cleaner name.
        // Keep the original as a comment if emit_comments is on.
        if let Some(stripped) = name.strip_prefix("u_") {
            if self.options.emit_comments {
                format!("var_{} /* {} */", stripped, name)
            } else {
                format!("var_{}", stripped)
            }
        } else if let Some(stripped) = name.strip_prefix("mem_") {
            if self.options.emit_comments {
                format!("gmem_{} /* {} */", stripped, name)
            } else {
                format!("gmem_{}", stripped)
            }
        } else {
            name.to_string()
        }
    }

    /// Format a numeric constant, choosing hex vs. decimal and handling
    /// signed vs. unsigned presentation.
    fn format_constant(&self, value: u64, size: u32) -> String {
        // Small constants in decimal; larger ones in hex.
        if value <= 9 {
            format!("{}", value)
        } else if value <= 0xff {
            format!("{:#x}", value)
        } else if value <= 0xffff {
            format!("{:#x}", value)
        } else if value < 0x1000 {
            // Medium values: decimal if round, otherwise hex.
            if value % 10 == 0 {
                format!("{}", value)
            } else {
                format!("{:#x}", value)
            }
        } else {
            // Large values: always hex with explicit size.
            match size {
                0..=1 => format!("{:#x}", value),
                2 => format!("{:#06x}", value),
                4 => format!("{:#010x}", value),
                _ => format!("{:#018x}", value),
            }
        }
    }

    // ==================================================================
    // Function signature helpers
    // ==================================================================

    /// Write the function signature line to the output.
    fn write_function_signature(&self, out: &mut String, func: &Function) {
        // Storage-class qualifiers.
        if func.is_static {
            let _ = write!(out, "static ");
        }
        if func.is_inline {
            let _ = write!(out, "inline ");
        }

        // Return type.
        let ret_type = match &func.return_type {
            Some(dt) => dt.name().to_string(),
            None => "void".to_string(),
        };
        let _ = write!(out, "{} ", ret_type);

        // Function name.
        let _ = write!(out, "{}(", func.name);

        // Parameters.
        let param_strs: Vec<String> = func
            .parameters
            .iter()
            .map(|p| {
                let type_str = p.type_string();
                format!("{} {}", type_str, p.name)
            })
            .collect();
        let mut param_list = param_strs.join(", ");

        if func.is_variadic {
            if !param_list.is_empty() {
                param_list.push_str(", ...");
            } else {
                param_list.push_str("...");
            }
        }

        let _ = write!(out, "{}", param_list);
        let _ = write!(out, ")");
    }

    /// Write variable declarations for all local variables.
    fn write_variable_declarations(
        &self,
        out: &mut String,
        func: &Function,
        decomp: &DecompileResults,
    ) {
        let mut locals: Vec<&Variable> = func
            .locals
            .iter()
            .chain(decomp.variables.iter())
            .collect();

        if locals.is_empty() {
            return;
        }

        if self.options.sort_variables {
            locals.sort_by(|a, b| a.name.cmp(&b.name));
        }

        let indent = self.indent.as_str();
        let _ = writeln!(
            out,
            "{}{} --- Local variables ---",
            indent, self.line_comment
        );

        for var in locals {
            let decl = self.format_variable_decl(var);
            let _ = writeln!(out, "{}{}", indent, decl);
        }

        let _ = writeln!(out);
    }

    // ==================================================================
    // Brace-writing helpers
    // ==================================================================

    /// Write the opening brace and the line that precedes it, honouring the
    /// configured brace style.
    fn write_control_flow_opening(
        &self,
        out: &mut String,
        line: &str,
        indent: usize,
    ) {
        match self.options.braced_style {
            BraceStyle::KAndR => {
                let _ = writeln!(out, "{} {{", line);
            }
            BraceStyle::Allman => {
                let _ = writeln!(out, "{}", line);
                self.write_opening_brace(out, indent);
            }
            BraceStyle::GNU => {
                let _ = writeln!(out, "{}", line);
                let prefix = self.indent_prefix(indent);
                let _ = writeln!(out, "{}{{", prefix);
            }
            BraceStyle::Whitesmiths => {
                let _ = writeln!(out, "{}", line);
                let prefix = self.indent_prefix(indent);
                let _ = writeln!(out, "{}    {{", prefix);
            }
            BraceStyle::Horstmann => {
                let _ = writeln!(out, "{}", line);
                let prefix = self.indent_prefix(indent);
                let _ = writeln!(out, "{}{{", prefix);
            }
        }
    }

    /// Write just the opening brace on its own line at the given indent.
    fn write_opening_brace(&self, out: &mut String, indent: usize) {
        let prefix = self.indent_prefix(indent);
        let _ = writeln!(out, "{}{{", prefix);
    }

    // ==================================================================
    // Utility
    // ==================================================================

    /// Return the whitespace prefix for the given indentation level.
    fn indent_prefix(&self, level: usize) -> String {
        self.indent.repeat(level)
    }
}

impl Default for COutputFormatter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Precedence constants for parenthesization
// ============================================================================

/// Precedence of the comma operator (lowest).
const PREC_COMMA: u32 = 1;
/// Precedence of assignment (=, +=, -=, etc.).
const PREC_ASSIGNMENT: u32 = 2;
/// Precedence of the ternary ?: operator.
const PREC_TERNARY: u32 = 3;
/// Precedence of logical OR (||).
const PREC_LOGICAL_OR: u32 = 4;
/// Precedence of logical AND (&&).
const PREC_LOGICAL_AND: u32 = 5;
/// Precedence of bitwise OR (|).
const PREC_BITWISE_OR: u32 = 6;
/// Precedence of bitwise XOR (^).
const PREC_BITWISE_XOR: u32 = 7;
/// Precedence of bitwise AND (&).
const PREC_BITWISE_AND: u32 = 8;
/// Precedence of equality/inequality (==, !=).
const PREC_EQUALITY: u32 = 9;
/// Precedence of relational operators (<, <=, >, >=).
const PREC_RELATIONAL: u32 = 10;
/// Precedence of shift operators (<<, >>).
const PREC_SHIFT: u32 = 11;
/// Precedence of additive operators (+, -).
const PREC_ADDITIVE: u32 = 12;
/// Precedence of multiplicative operators (*, /, %).
const PREC_MULTIPLICATIVE: u32 = 13;
/// Precedence of casts.
const PREC_CAST: u32 = 14;
/// Precedence of unary operators (!, ~, -, *, &).
const PREC_UNARY: u32 = 15;

// ============================================================================
// Operator helper functions
// ============================================================================

/// Return the C operator string for a binary operator.
fn binary_operator_str(op: BinaryOperator) -> &'static str {
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

/// Return the C operator string for a unary operator.
fn unary_operator_str(op: UnaryOperator) -> &'static str {
    match op {
        UnaryOperator::Neg => "-",
        UnaryOperator::Not => "!",
        UnaryOperator::BitNot => "~",
        UnaryOperator::Deref => "*",
        UnaryOperator::AddressOf => "&",
    }
}

/// Return the precedence level for a binary operator.
fn operator_precedence(op: BinaryOperator) -> u32 {
    match op {
        BinaryOperator::LogicalOr => PREC_LOGICAL_OR,
        BinaryOperator::LogicalAnd => PREC_LOGICAL_AND,
        BinaryOperator::Or => PREC_BITWISE_OR,
        BinaryOperator::Xor => PREC_BITWISE_XOR,
        BinaryOperator::And => PREC_BITWISE_AND,
        BinaryOperator::Eq | BinaryOperator::Neq => PREC_EQUALITY,
        BinaryOperator::Lt
        | BinaryOperator::Le
        | BinaryOperator::Gt
        | BinaryOperator::Ge => PREC_RELATIONAL,
        BinaryOperator::Shl | BinaryOperator::Shr => PREC_SHIFT,
        BinaryOperator::Add | BinaryOperator::Sub => PREC_ADDITIVE,
        BinaryOperator::Mul | BinaryOperator::Div | BinaryOperator::Mod => PREC_MULTIPLICATIVE,
    }
}

/// Return `true` if the expression is complex enough that wrapping it in
/// parentheses would improve readability (used for dereference targets).
fn is_complex_expression(expr: &Expression) -> bool {
    matches!(
        expr,
        Expression::BinaryOp { .. }
            | Expression::Ternary { .. }
            | Expression::Call { .. }
            | Expression::Cast { .. }
            | Expression::Assignment { .. }
            | Expression::Comma { .. }
    )
}

// ============================================================================
// Helper: size -> C type name
// ============================================================================

/// Map a byte size to a reasonable C primitive type name.
fn size_to_ctype(size: u32) -> String {
    match size {
        0 => "void".to_string(),
        1 => "uint8_t".to_string(),
        2 => "uint16_t".to_string(),
        4 => "uint32_t".to_string(),
        8 => "uint64_t".to_string(),
        s => format!("uint{}_t", s * 8),
    }
}

// ============================================================================
// TokenOutputStream -- for GUI / syntax-highlighted rendering
// ============================================================================

/// A stream of syntax-highlighted C tokens for GUI rendering.
///
/// Instead of producing raw text, the token stream records every lexical
/// token along with its semantic category. This enables IDEs and GUI
/// decompiler views to render identifiers as hyperlinks, display address
/// tooltips on hover, apply syntax-colour themes, etc.
#[derive(Debug, Clone)]
pub struct TokenOutputStream {
    /// The accumulated tokens.
    pub tokens: Vec<CToken>,
}

/// A single syntax-highlighted C token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CToken {
    /// A C keyword (`if`, `while`, `return`, `struct`, etc.).
    Keyword(String),
    /// A type name (`int`, `uint32_t`, `void*`, etc.).
    Type(String),
    /// A variable, function, or label identifier, optionally linked to an
    /// address for navigation.
    Identifier {
        /// The identifier text.
        name: String,
        /// The address this identifier refers to (for hyperlinks).
        address: Option<Address>,
    },
    /// A numeric literal.
    Number(String),
    /// A double-quoted string literal.
    StringLiteral(String),
    /// A single-quoted character literal.
    CharLiteral(String),
    /// A comment (line or block).
    Comment(String),
    /// An operator (`+`, `<<`, `&&`, `=`, etc.).
    Operator(String),
    /// A punctuation character (`(`, `)`, `{`, `}`, `;`, `,`).
    Punctuation(char),
    /// Inter-token whitespace (spaces, tabs, but not newlines).
    Whitespace(String),
    /// A newline token (to preserve formatting in rendered output).
    Newline,
    /// A standalone address (for navigation, not part of an identifier).
    Address(Address),
    /// A cross-reference: an identifier that references a different address.
    Reference {
        /// The displayed name.
        name: String,
        /// The target address.
        target: Address,
    },
}

impl TokenOutputStream {
    /// Create a new, empty token output stream.
    pub fn new() -> Self {
        Self {
            tokens: Vec::new(),
        }
    }

    /// Emit a keyword token.
    pub fn emit_keyword(&mut self, kw: &str) {
        self.tokens.push(CToken::Keyword(kw.to_string()));
    }

    /// Emit a type-name token.
    pub fn emit_type(&mut self, ty: &str) {
        self.tokens.push(CToken::Type(ty.to_string()));
    }

    /// Emit an identifier token, optionally with a navigation address.
    pub fn emit_identifier(&mut self, name: &str, addr: Option<Address>) {
        self.tokens.push(CToken::Identifier {
            name: name.to_string(),
            address: addr,
        });
    }

    /// Emit a numeric literal token.
    pub fn emit_number(&mut self, n: &str) {
        self.tokens.push(CToken::Number(n.to_string()));
    }

    /// Emit a string literal token (double-quoted).
    pub fn emit_string(&mut self, s: &str) {
        self.tokens.push(CToken::StringLiteral(s.to_string()));
    }

    /// Emit a comment token.
    pub fn emit_comment(&mut self, c: &str) {
        self.tokens.push(CToken::Comment(c.to_string()));
    }

    /// Emit an operator token.
    pub fn emit_operator(&mut self, op: &str) {
        self.tokens.push(CToken::Operator(op.to_string()));
    }

    /// Emit a single punctuation character.
    pub fn emit_punctuation(&mut self, p: char) {
        self.tokens.push(CToken::Punctuation(p));
    }

    /// Emit a standalone address (for clickable navigation).
    pub fn emit_address(&mut self, addr: Address) {
        self.tokens.push(CToken::Address(addr));
    }

    /// Emit a cross-reference token.
    pub fn emit_reference(&mut self, name: &str, target: Address) {
        self.tokens.push(CToken::Reference {
            name: name.to_string(),
            target,
        });
    }

    /// Emit a whitespace token. Multiple consecutive whitespace calls
    /// are collapsed into a single `Whitespace` token to keep the
    /// stream compact.
    pub fn emit_space(&mut self) {
        match self.tokens.last_mut() {
            Some(CToken::Whitespace(ref mut s)) => {
                s.push(' ');
            }
            _ => {
                self.tokens.push(CToken::Whitespace(" ".to_string()));
            }
        }
    }

    /// Emit a newline token.
    pub fn emit_newline(&mut self) {
        self.tokens.push(CToken::Newline);
    }

    // ==================================================================
    // Serialization
    // ==================================================================

    /// Serialize the token stream to a flat C string (lossy, no markup).
    ///
    /// Useful for producing plain-text C output from a token stream when
    /// syntax highlighting is not needed.
    pub fn to_string(&self) -> String {
        let mut out = String::new();
        for token in &self.tokens {
            match token {
                CToken::Keyword(kw) => out.push_str(kw),
                CToken::Type(ty) => out.push_str(ty),
                CToken::Identifier { name, .. } => out.push_str(name),
                CToken::Number(n) => out.push_str(n),
                CToken::StringLiteral(s) => {
                    out.push('"');
                    out.push_str(s);
                    out.push('"');
                }
                CToken::CharLiteral(c) => {
                    out.push('\'');
                    out.push_str(c);
                    out.push('\'');
                }
                CToken::Comment(c) => out.push_str(c),
                CToken::Operator(op) => out.push_str(op),
                CToken::Punctuation(p) => {
                    out.push(*p);
                }
                CToken::Whitespace(w) => out.push_str(w),
                CToken::Newline => out.push('\n'),
                CToken::Address(addr) => {
                    let _ = write!(out, "{:#x}", addr.offset);
                }
                CToken::Reference { name, target: _ } => {
                    out.push_str(name);
                }
            }
        }
        out
    }

    /// Serialize the token stream to syntax-highlighted HTML.
    ///
    /// Each token type is wrapped in a `<span>` with a CSS class for
    /// theming.  Identifiers with associated addresses become hyperlinks.
    /// Address tokens and references are rendered as clickable links using
    /// a custom `data-address` attribute.
    pub fn to_html(&self) -> String {
        let mut out = String::new();
        out.push_str("<pre class=\"decompiled-code\">\n");

        for token in &self.tokens {
            match token {
                CToken::Keyword(kw) => {
                    let escaped = html_escape(kw);
                    let _ = write!(out, "<span class=\"ct-keyword\">{}</span>", escaped);
                }
                CToken::Type(ty) => {
                    let escaped = html_escape(ty);
                    let _ = write!(out, "<span class=\"ct-type\">{}</span>", escaped);
                }
                CToken::Identifier { name, address } => {
                    let escaped = html_escape(name);
                    if let Some(ref addr) = address {
                        let _ = write!(
                            out,
                            "<a class=\"ct-identifier\" href=\"#\" \
                             data-address=\"{:#x}\">{}</a>",
                            addr.offset, escaped
                        );
                    } else {
                        let _ = write!(
                            out,
                            "<span class=\"ct-identifier\">{}</span>",
                            escaped
                        );
                    }
                }
                CToken::Number(n) => {
                    let escaped = html_escape(n);
                    let _ = write!(
                        out,
                        "<span class=\"ct-number\">{}</span>",
                        escaped
                    );
                }
                CToken::StringLiteral(s) => {
                    let escaped = html_escape(s);
                    let _ = write!(
                        out,
                        "<span class=\"ct-string\">\"{}\"</span>",
                        escaped
                    );
                }
                CToken::CharLiteral(c) => {
                    let escaped = html_escape(c);
                    let _ = write!(
                        out,
                        "<span class=\"ct-string\">\'{}\'</span>",
                        escaped
                    );
                }
                CToken::Comment(c) => {
                    let escaped = html_escape(c);
                    let _ = write!(
                        out,
                        "<span class=\"ct-comment\">{}</span>",
                        escaped
                    );
                }
                CToken::Operator(op) => {
                    let escaped = html_escape(op);
                    let _ = write!(
                        out,
                        "<span class=\"ct-operator\">{}</span>",
                        escaped
                    );
                }
                CToken::Punctuation(p) => {
                    let escaped = html_escape(&p.to_string());
                    let _ = write!(
                        out,
                        "<span class=\"ct-punctuation\">{}</span>",
                        escaped
                    );
                }
                CToken::Whitespace(w) => {
                    // Preserve whitespace in HTML output.
                    out.push_str(&w.replace(' ', " "));
                }
                CToken::Newline => {
                    out.push('\n');
                }
                CToken::Address(addr) => {
                    let _ = write!(
                        out,
                        "<a class=\"ct-address\" href=\"#\" \
                         data-address=\"{:#x}\">{:#x}</a>",
                        addr.offset, addr.offset
                    );
                }
                CToken::Reference { name, target } => {
                    let escaped = html_escape(name);
                    let _ = write!(
                        out,
                        "<a class=\"ct-reference\" href=\"#\" \
                         data-address=\"{:#x}\">{}</a>",
                        target.offset, escaped
                    );
                }
            }
        }

        out.push_str("\n</pre>");
        out
    }
}

impl Default for TokenOutputStream {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// HTML-escaping helper
// ============================================================================

/// Escape the four HTML-significant characters.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::control_flow_struct::BlockData;
    use ghidra_core::addr::Address;

    fn test_addr(offset: u64) -> Address {
        Address::new(offset)
    }

    // ==================================================================
    // OutputOptions
    // ==================================================================

    #[test]
    fn test_output_options_default() {
        let opts = OutputOptions::default();
        assert_eq!(opts.indent_size, 4);
        assert_eq!(opts.max_line_length, 120);
        assert!(matches!(opts.braced_style, BraceStyle::KAndR));
        assert!(!opts.show_line_numbers);
        assert!(!opts.show_raw_addresses);
        assert!(opts.show_type_casts);
        assert!(opts.simplify_expressions);
        assert!(opts.rename_variables);
        assert!(opts.use_typedefs);
        assert!(opts.emit_comments);
        assert!(opts.emit_var_decls);
        assert!(opts.sort_variables);
    }

    // ==================================================================
    // BraceStyle
    // ==================================================================

    #[test]
    fn test_brace_style_variants() {
        // Ensure all variants can be constructed and matched.
        let styles = [
            BraceStyle::KAndR,
            BraceStyle::Allman,
            BraceStyle::GNU,
            BraceStyle::Whitesmiths,
            BraceStyle::Horstmann,
        ];
        for s in &styles {
            let _ = format!("{:?}", s);
        }
    }

    // ==================================================================
    // Variable
    // ==================================================================

    #[test]
    fn test_variable_local() {
        let v = Variable::local("x", None, 4);
        assert_eq!(v.name, "x");
        assert_eq!(v.size, 4);
        assert!(matches!(v.storage, VariableStorage::Local));
    }

    #[test]
    fn test_variable_type_string() {
        let v = Variable::local("x", None, 4);
        assert_eq!(v.type_string(), "uint32_t");

        let v1 = Variable::local("y", None, 1);
        assert_eq!(v1.type_string(), "uint8_t");

        let v8 = Variable::local("z", None, 8);
        assert_eq!(v8.type_string(), "uint64_t");
    }

    #[test]
    fn test_variable_global() {
        let addr = test_addr(0x6000);
        let v = Variable::global("g_flag", None, 4, addr);
        assert_eq!(v.address, Some(addr));
        assert!(matches!(v.storage, VariableStorage::Global));
    }

    #[test]
    fn test_variable_unnamed_local() {
        let v = Variable::unnamed_local(0x1000, 8);
        assert_eq!(v.name, "local_1000");
        assert_eq!(v.size, 8);
    }

    // ==================================================================
    // Statement
    // ==================================================================

    #[test]
    fn test_statement_from_node() {
        let node = StructuredNode::empty_block();
        let stmt = Statement::from_node(node.clone());
        assert!(stmt.address.is_none());
        assert!(stmt.comment.is_none());
    }

    #[test]
    fn test_statement_with_address() {
        let node = StructuredNode::empty_block();
        let addr = test_addr(0x401000);
        let stmt = Statement::with_address(node, addr);
        assert_eq!(stmt.address, Some(addr));
    }

    #[test]
    fn test_statement_with_comment() {
        let node = StructuredNode::empty_block();
        let stmt = Statement::with_comment(node, "likely bug here");
        assert_eq!(stmt.comment, Some("likely bug here".to_string()));
    }

    // ==================================================================
    // Function
    // ==================================================================

    #[test]
    fn test_function_new() {
        let addr = test_addr(0x401000);
        let func = Function::new("main", addr);
        assert_eq!(func.name, "main");
        assert_eq!(func.entry_point, addr);
        assert!(func.parameters.is_empty());
        assert!(func.locals.is_empty());
        assert!(!func.is_variadic);
    }

    // ==================================================================
    // DecompileResults
    // ==================================================================

    #[test]
    fn test_decompile_results_success() {
        let addr = test_addr(0x401000);
        let func = Function::new("test_fn", addr);
        let root = StructuredNode::Block(BlockData {
            operations: vec![],
            address: addr,
        });
        let results = DecompileResults::success(func, root);
        assert!(results.success);
        assert!(results.root.is_some());
        assert!(results.diagnostics.is_empty());
    }

    #[test]
    fn test_decompile_results_failure() {
        let addr = test_addr(0x401000);
        let func = Function::new("bad_fn", addr);
        let diags = vec!["could not lift".to_string()];
        let results = DecompileResults::failure(func, diags.clone());
        assert!(!results.success);
        assert!(results.root.is_none());
        assert_eq!(results.diagnostics, diags);
    }

    // ==================================================================
    // COutputFormatter
    // ==================================================================

    #[test]
    fn test_formatter_new() {
        let fmt = COutputFormatter::new();
        assert_eq!(fmt.options.indent_size, 4);
        assert_eq!(fmt.indent, "    ");
        assert_eq!(fmt.line_comment, "//");
    }

    #[test]
    fn test_formatter_with_options() {
        let opts = OutputOptions {
            indent_size: 2,
            braced_style: BraceStyle::Allman,
            ..Default::default()
        };
        let fmt = COutputFormatter::with_options(opts);
        assert_eq!(fmt.indent, "  ");
        assert!(matches!(fmt.options.braced_style, BraceStyle::Allman));
    }

    #[test]
    fn test_format_empty_block() {
        let fmt = COutputFormatter::new();
        let block = StructuredNode::Block(BlockData {
            operations: vec![],
            address: Address::NULL,
        });
        let output = fmt.format_node(&block, 0);
        // An empty block produces no output.
        assert_eq!(output, "");
    }

    #[test]
    fn test_format_block_with_expression() {
        let fmt = COutputFormatter::new();
        let expr = Expression::Assignment {
            lhs: Box::new(Expression::Variable {
                name: "x".to_string(),
                size: 4,
            }),
            rhs: Box::new(Expression::Constant {
                value: 42,
                size: 4,
            }),
        };
        let block = StructuredNode::Block(BlockData {
            operations: vec![expr],
            address: Address::NULL,
        });
        let output = fmt.format_node(&block, 0);
        assert!(output.contains("x = 0x2a"));
        assert!(output.contains(';'));
    }

    #[test]
    fn test_format_return_void() {
        let fmt = COutputFormatter::new();
        let node = StructuredNode::Return(None);
        let output = fmt.format_node(&node, 0);
        assert_eq!(output.trim(), "return;");
    }

    #[test]
    fn test_format_return_value() {
        let fmt = COutputFormatter::new();
        let node = StructuredNode::Return(Some(Box::new(Expression::Constant {
            value: 0,
            size: 4,
        })));
        let output = fmt.format_node(&node, 0);
        assert!(output.contains("return 0;"));
    }

    #[test]
    fn test_format_break_continue() {
        let fmt = COutputFormatter::new();
        assert_eq!(fmt.format_node(&StructuredNode::Break, 1).trim(), "break;");
        assert_eq!(
            fmt.format_node(&StructuredNode::Continue, 1).trim(),
            "continue;"
        );
    }

    #[test]
    fn test_format_expression_variable() {
        let fmt = COutputFormatter::new();
        let expr = Expression::variable("my_var", 4);
        let out = fmt.format_expression(&expr);
        assert_eq!(out, "my_var");
    }

    #[test]
    fn test_format_expression_constant() {
        let fmt = COutputFormatter::new();
        let expr = Expression::constant(255, 4);
        let out = fmt.format_expression(&expr);
        assert_eq!(out, "0xff");

        let expr2 = Expression::constant(5, 4);
        assert_eq!(fmt.format_expression(&expr2), "5");
    }

    #[test]
    fn test_format_expression_binary_op() {
        let fmt = COutputFormatter::new();
        let expr = Expression::binary(
            BinaryOperator::Add,
            Expression::constant(1, 4),
            Expression::constant(2, 4),
        );
        let out = fmt.format_expression(&expr);
        assert_eq!(out, "1 + 2");
    }

    #[test]
    fn test_format_expression_binary_op_precedence() {
        let fmt = COutputFormatter::new();
        // (1 + 2) * 3  — needs parens because * has higher precedence than +.
        let inner = Expression::binary(
            BinaryOperator::Add,
            Expression::constant(1, 4),
            Expression::constant(2, 4),
        );
        let outer = Expression::binary(
            BinaryOperator::Mul,
            inner,
            Expression::constant(3, 4),
        );
        let out = fmt.format_expression(&outer);
        assert_eq!(out, "(1 + 2) * 3");
    }

    #[test]
    fn test_format_expression_dereference() {
        let fmt = COutputFormatter::new();
        let expr = Expression::Dereference {
            ptr: Box::new(Expression::variable("ptr", 8)),
            size: 4,
        };
        let out = fmt.format_expression(&expr);
        assert_eq!(out, "*ptr");
    }

    #[test]
    fn test_format_expression_call() {
        let fmt = COutputFormatter::new();
        let expr = Expression::Call {
            target: Box::new(Expression::variable("printf", 8)),
            args: vec![
                Expression::StringLiteral {
                    value: "hello\n".to_string(),
                },
            ],
        };
        let out = fmt.format_expression(&expr);
        assert!(out.starts_with("printf("));
    }

    #[test]
    fn test_format_expression_ternary() {
        let fmt = COutputFormatter::new();
        let expr = Expression::Ternary {
            cond: Box::new(Expression::binary(
                BinaryOperator::Gt,
                Expression::variable("x", 4),
                Expression::constant(0, 4),
            )),
            true_expr: Box::new(Expression::variable("x", 4)),
            false_expr: Box::new(Expression::constant(0, 4)),
        };
        let out = fmt.format_expression(&expr);
        assert!(out.contains("?"));
        assert!(out.contains(":"));
    }

    #[test]
    fn test_format_expression_nop() {
        let fmt = COutputFormatter::new();
        assert_eq!(fmt.format_expression(&Expression::Nop), "");
    }

    #[test]
    fn test_format_variable_decl() {
        let fmt = COutputFormatter::new();
        let var = Variable::local("count", None, 4);
        let decl = fmt.format_variable_decl(&var);
        assert_eq!(decl, "uint32_t count;");
    }

    #[test]
    fn test_format_type() {
        let fmt = COutputFormatter::new();
        let ty = ghidra_core::data::DataType::u32();
        let out = fmt.format_type(&ty);
        assert_eq!(out, "u32");
    }

    #[test]
    fn test_simplify_variable_name_renames_internal() {
        let mut opts = OutputOptions::default();
        opts.rename_variables = true;
        opts.emit_comments = true;
        let fmt = COutputFormatter::with_options(opts);
        let result = fmt.simplify_variable_name("u_deadbeef");
        assert!(result.starts_with("var_deadbeef"));
        assert!(result.contains("/* u_deadbeef */"));
    }

    #[test]
    fn test_simplify_variable_name_preserves_user_names() {
        let mut opts = OutputOptions::default();
        opts.rename_variables = true;
        let fmt = COutputFormatter::with_options(opts);
        let result = fmt.simplify_variable_name("myCounter");
        assert_eq!(result, "myCounter");
    }

    #[test]
    fn test_simplify_variable_name_disabled() {
        let mut opts = OutputOptions::default();
        opts.rename_variables = false;
        let fmt = COutputFormatter::with_options(opts);
        let result = fmt.simplify_variable_name("u_deadbeef");
        assert_eq!(result, "u_deadbeef");
    }

    // ==================================================================
    // Function formatting
    // ==================================================================

    #[test]
    fn test_format_function_signature_simple() {
        let fmt = COutputFormatter::new();
        let func = Function::new("foo", test_addr(0x401000));
        let body = StructuredNode::Return(Some(Box::new(Expression::constant(0, 4))));
        let results = DecompileResults::success(func.clone(), body);

        let output = fmt.format_function(&func, &results);
        assert!(output.contains("void foo()"));
        assert!(output.contains("return 0;"));
    }

    #[test]
    fn test_format_function_with_params() {
        let fmt = COutputFormatter::new();
        let mut func = Function::new("add", test_addr(0x401000));
        func.parameters = vec![
            Variable::parameter("a", None, 4),
            Variable::parameter("b", None, 4),
        ];

        let body = StructuredNode::Return(Some(Box::new(Expression::binary(
            BinaryOperator::Add,
            Expression::variable("a", 4),
            Expression::variable("b", 4),
        ))));
        let results = DecompileResults::success(func.clone(), body);

        let output = fmt.format_function(&func, &results);
        assert!(output.contains("void add(uint32_t a, uint32_t b)"));
    }

    #[test]
    fn test_format_function_static() {
        let fmt = COutputFormatter::new();
        let mut func = Function::new("helper", test_addr(0x401000));
        func.is_static = true;

        let body = StructuredNode::Return(None);
        let results = DecompileResults::success(func.clone(), body);

        let output = fmt.format_function(&func, &results);
        assert!(output.contains("static void helper("));
    }

    #[test]
    fn test_format_function_variadic() {
        let fmt = COutputFormatter::new();
        let mut func = Function::new("printf_wrapper", test_addr(0x401000));
        func.is_variadic = true;
        func.parameters = vec![Variable::parameter("fmt", None, 8)];

        let body = StructuredNode::Return(None);
        let results = DecompileResults::success(func.clone(), body);

        let output = fmt.format_function(&func, &results);
        assert!(output.contains("uint64_t fmt, ..."));
    }

    #[test]
    fn test_format_function_failed_decompilation() {
        let fmt = COutputFormatter::new();
        let func = Function::new("bad", test_addr(0x401000));
        let results =
            DecompileResults::failure(func.clone(), vec!["CFG is irreducible".into()]);

        let output = fmt.format_function(&func, &results);
        assert!(output.contains("WARNING: Decompilation failed"));
        assert!(output.contains("CFG is irreducible"));
    }

    // ==================================================================
    // Control flow formatting
    // ==================================================================

    #[test]
    fn test_format_if_else_kandr() {
        let fmt = COutputFormatter::new();
        let node = StructuredNode::IfElse {
            condition: Expression::binary(
                BinaryOperator::Neq,
                Expression::variable("x", 4),
                Expression::constant(0, 4),
            ),
            then_branch: Box::new(StructuredNode::Block(BlockData {
                operations: vec![Expression::Assignment {
                    lhs: Box::new(Expression::variable("y", 4)),
                    rhs: Box::new(Expression::constant(1, 4)),
                }],
                address: Address::NULL,
            })),
            else_branch: None,
        };
        let output = fmt.format_node(&node, 0);
        assert!(output.contains("if (x != 0) {"));
        assert!(output.contains("y = 1;"));
        assert!(output.contains("}"));
    }

    #[test]
    fn test_format_if_else_allman() {
        let opts = OutputOptions {
            braced_style: BraceStyle::Allman,
            ..Default::default()
        };
        let fmt = COutputFormatter::with_options(opts);
        let node = StructuredNode::IfElse {
            condition: Expression::constant(1, 1),
            then_branch: Box::new(StructuredNode::Break),
            else_branch: None,
        };
        let output = fmt.format_node(&node, 0);
        // Allman style: brace on its own line.
        assert!(output.contains("if (1)\n{"));
    }

    #[test]
    fn test_format_while_loop() {
        let fmt = COutputFormatter::new();
        let node = StructuredNode::While {
            condition: Expression::binary(
                BinaryOperator::Lt,
                Expression::variable("i", 4),
                Expression::constant(10, 4),
            ),
            body: Box::new(StructuredNode::Block(BlockData {
                operations: vec![Expression::Assignment {
                    lhs: Box::new(Expression::variable("i", 4)),
                    rhs: Box::new(Expression::binary(
                        BinaryOperator::Add,
                        Expression::variable("i", 4),
                        Expression::constant(1, 4),
                    )),
                }],
                address: Address::NULL,
            })),
        };
        let output = fmt.format_node(&node, 0);
        assert!(output.contains("while (i < 0xa) {"));
        assert!(output.contains("i = i + 1;"));
    }

    #[test]
    fn test_format_do_while() {
        let fmt = COutputFormatter::new();
        let node = StructuredNode::DoWhile {
            condition: Expression::binary(
                BinaryOperator::Neq,
                Expression::variable("x", 4),
                Expression::constant(0, 4),
            ),
            body: Box::new(StructuredNode::Break),
        };
        let output = fmt.format_node(&node, 0);
        assert!(output.contains("do"));
        assert!(output.contains("while (x != 0);"));
    }

    #[test]
    fn test_format_for_loop() {
        let fmt = COutputFormatter::new();
        let node = StructuredNode::For {
            init: Some(Box::new(Expression::Assignment {
                lhs: Box::new(Expression::variable("i", 4)),
                rhs: Box::new(Expression::constant(0, 4)),
            })),
            condition: Some(Box::new(Expression::binary(
                BinaryOperator::Lt,
                Expression::variable("i", 4),
                Expression::constant(10, 4),
            ))),
            step: Some(Box::new(Expression::Assignment {
                lhs: Box::new(Expression::variable("i", 4)),
                rhs: Box::new(Expression::binary(
                    BinaryOperator::Add,
                    Expression::variable("i", 4),
                    Expression::constant(1, 4),
                )),
            })),
            body: Box::new(StructuredNode::Break),
        };
        let output = fmt.format_node(&node, 0);
        assert!(output.contains("for (i = 0; i < 0xa; i = i + 1)"));
    }

    #[test]
    fn test_format_switch() {
        let fmt = COutputFormatter::new();
        let node = StructuredNode::Switch {
            expression: Expression::variable("mode", 4),
            cases: vec![
                SwitchCase {
                    values: vec![0],
                    body: Box::new(StructuredNode::Block(BlockData {
                        operations: vec![Expression::Assignment {
                            lhs: Box::new(Expression::variable("result", 4)),
                            rhs: Box::new(Expression::constant(1, 4)),
                        }],
                        address: Address::NULL,
                    })),
                    is_fallthrough: false,
                },
                SwitchCase {
                    values: vec![1, 2],
                    body: Box::new(StructuredNode::Block(BlockData {
                        operations: vec![Expression::Assignment {
                            lhs: Box::new(Expression::variable("result", 4)),
                            rhs: Box::new(Expression::constant(2, 4)),
                        }],
                        address: Address::NULL,
                    })),
                    is_fallthrough: false,
                },
            ],
            default: Some(Box::new(StructuredNode::Block(BlockData {
                operations: vec![Expression::Assignment {
                    lhs: Box::new(Expression::variable("result", 4)),
                    rhs: Box::new(Expression::constant(0, 4)),
                }],
                address: Address::NULL,
            }))),
        };
        let output = fmt.format_node(&node, 0);
        assert!(output.contains("switch (mode)"));
        assert!(output.contains("case 0:"));
        assert!(output.contains("case 1:"));
        assert!(output.contains("case 2:"));
        assert!(output.contains("default:"));
        assert!(output.contains("break;"));
    }

    #[test]
    fn test_format_goto_label() {
        let fmt = COutputFormatter::new();
        let goto_node = StructuredNode::Goto {
            target: test_addr(0x401200),
            label: "L1".to_string(),
        };
        let output = fmt.format_node(&goto_node, 0);
        assert!(output.contains("goto L1;"));
    }

    #[test]
    fn test_format_label() {
        let fmt = COutputFormatter::new();
        let node = StructuredNode::Label {
            name: "cleanup".to_string(),
            node: Box::new(StructuredNode::Return(None)),
        };
        let output = fmt.format_node(&node, 1);
        // Label is outdented by one level.
        assert!(output.contains("cleanup:"));
        assert!(output.contains("return;"));
    }

    #[test]
    fn test_format_infinite_loop() {
        let fmt = COutputFormatter::new();
        let node = StructuredNode::InfiniteLoop {
            body: Box::new(StructuredNode::Break),
        };
        let output = fmt.format_node(&node, 0);
        assert!(output.contains("for (;;)"));
    }

    #[test]
    fn test_format_sequence() {
        let fmt = COutputFormatter::new();
        let node = StructuredNode::Sequence(vec![
            StructuredNode::Block(BlockData {
                operations: vec![Expression::Assignment {
                    lhs: Box::new(Expression::variable("a", 4)),
                    rhs: Box::new(Expression::constant(1, 4)),
                }],
                address: Address::NULL,
            }),
            StructuredNode::Block(BlockData {
                operations: vec![Expression::Assignment {
                    lhs: Box::new(Expression::variable("b", 4)),
                    rhs: Box::new(Expression::constant(2, 4)),
                }],
                address: Address::NULL,
            }),
        ]);
        let output = fmt.format_node(&node, 0);
        assert!(output.contains("a = 1;"));
        assert!(output.contains("b = 2;"));
    }

    // ==================================================================
    // Brace style output differences
    // ==================================================================

    #[test]
    fn test_brace_style_gnu() {
        let opts = OutputOptions {
            braced_style: BraceStyle::GNU,
            ..Default::default()
        };
        let fmt = COutputFormatter::with_options(opts);
        let node = StructuredNode::While {
            condition: Expression::constant(1, 1),
            body: Box::new(StructuredNode::Break),
        };
        let output = fmt.format_node(&node, 0);
        // GNU: brace indented by half the indent size on the next line.
        assert!(output.contains("while (1)"));
    }

    #[test]
    fn test_brace_style_horstmann() {
        let opts = OutputOptions {
            braced_style: BraceStyle::Horstmann,
            ..Default::default()
        };
        let fmt = COutputFormatter::with_options(opts);
        let node = StructuredNode::IfElse {
            condition: Expression::constant(1, 1),
            then_branch: Box::new(StructuredNode::Break),
            else_branch: None,
        };
        let output = fmt.format_node(&node, 0);
        assert!(output.contains("if (1)"));
    }

    // ==================================================================
    // TokenOutputStream
    // ==================================================================

    #[test]
    fn test_token_stream_new() {
        let ts = TokenOutputStream::new();
        assert!(ts.tokens.is_empty());
    }

    #[test]
    fn test_token_stream_emit_keyword() {
        let mut ts = TokenOutputStream::new();
        ts.emit_keyword("if");
        assert_eq!(ts.tokens.len(), 1);
        assert!(matches!(ts.tokens[0], CToken::Keyword(ref k) if k == "if"));
    }

    #[test]
    fn test_token_stream_emit_identifier() {
        let mut ts = TokenOutputStream::new();
        let addr = test_addr(0x401000);
        ts.emit_identifier("main", Some(addr));
        assert_eq!(ts.tokens.len(), 1);
        assert!(matches!(
            ts.tokens[0],
            CToken::Identifier { ref name, address: Some(a) }
            if name == "main" && a == addr
        ));
    }

    #[test]
    fn test_token_stream_emit_identifier_no_address() {
        let mut ts = TokenOutputStream::new();
        ts.emit_identifier("x", None);
        assert!(matches!(
            ts.tokens[0],
            CToken::Identifier { ref name, address: None } if name == "x"
        ));
    }

    #[test]
    fn test_token_stream_emit_number() {
        let mut ts = TokenOutputStream::new();
        ts.emit_number("42");
        assert!(matches!(ts.tokens[0], CToken::Number(ref n) if n == "42"));
    }

    #[test]
    fn test_token_stream_emit_string() {
        let mut ts = TokenOutputStream::new();
        ts.emit_string("hello world");
        assert!(matches!(ts.tokens[0], CToken::StringLiteral(ref s) if s == "hello world"));
    }

    #[test]
    fn test_token_stream_emit_operator() {
        let mut ts = TokenOutputStream::new();
        ts.emit_operator("+=");
        assert!(matches!(ts.tokens[0], CToken::Operator(ref op) if op == "+="));
    }

    #[test]
    fn test_token_stream_emit_punctuation() {
        let mut ts = TokenOutputStream::new();
        ts.emit_punctuation('{');
        assert!(matches!(ts.tokens[0], CToken::Punctuation('{')));
    }

    #[test]
    fn test_token_stream_emit_space_coalescing() {
        let mut ts = TokenOutputStream::new();
        ts.emit_space();
        ts.emit_space();
        ts.emit_space();
        assert_eq!(ts.tokens.len(), 1);
        assert!(matches!(ts.tokens[0], CToken::Whitespace(ref w) if w.len() == 3));
    }

    #[test]
    fn test_token_stream_emit_newline() {
        let mut ts = TokenOutputStream::new();
        ts.emit_newline();
        assert!(matches!(ts.tokens[0], CToken::Newline));
    }

    #[test]
    fn test_token_stream_emit_address() {
        let mut ts = TokenOutputStream::new();
        let addr = test_addr(0xdeadbeef);
        ts.emit_address(addr);
        assert!(matches!(ts.tokens[0], CToken::Address(a) if a == addr));
    }

    #[test]
    fn test_token_stream_emit_reference() {
        let mut ts = TokenOutputStream::new();
        let addr = test_addr(0x6000);
        ts.emit_reference("global_var", addr);
        assert!(matches!(
            ts.tokens[0],
            CToken::Reference { ref name, target }
            if name == "global_var" && target == addr
        ));
    }

    #[test]
    fn test_token_stream_to_string() {
        let mut ts = TokenOutputStream::new();
        ts.emit_keyword("return");
        ts.emit_space();
        ts.emit_number("0");
        ts.emit_punctuation(';');
        ts.emit_newline();

        let output = ts.to_string();
        assert_eq!(output.trim(), "return 0;");
    }

    #[test]
    fn test_token_stream_to_html() {
        let mut ts = TokenOutputStream::new();
        ts.emit_keyword("if");
        ts.emit_punctuation('(');
        ts.emit_identifier("x", Some(test_addr(0x1000)));
        ts.emit_punctuation(')');
        ts.emit_space();
        ts.emit_punctuation('{');
        ts.emit_newline();

        let html = ts.to_html();
        assert!(html.contains("class=\"ct-keyword\""));
        assert!(html.contains("class=\"ct-identifier\""));
        assert!(html.contains("data-address=\"0x1000\""));
        assert!(html.contains("class=\"ct-punctuation\""));
    }

    #[test]
    fn test_token_stream_to_html_escapes() {
        let mut ts = TokenOutputStream::new();
        ts.emit_operator("<");
        ts.emit_comment("/* test & demo */");

        let html = ts.to_html();
        assert!(html.contains("&lt;"));
        assert!(html.contains("&amp;"));
    }

    // ==================================================================
    // Operator helpers
    // ==================================================================

    #[test]
    fn test_binary_operator_str_all() {
        let ops = [
            (BinaryOperator::Add, "+"),
            (BinaryOperator::Sub, "-"),
            (BinaryOperator::Mul, "*"),
            (BinaryOperator::Div, "/"),
            (BinaryOperator::Mod, "%"),
            (BinaryOperator::And, "&"),
            (BinaryOperator::Or, "|"),
            (BinaryOperator::Xor, "^"),
            (BinaryOperator::Shl, "<<"),
            (BinaryOperator::Shr, ">>"),
            (BinaryOperator::Eq, "=="),
            (BinaryOperator::Neq, "!="),
            (BinaryOperator::Lt, "<"),
            (BinaryOperator::Le, "<="),
            (BinaryOperator::Gt, ">"),
            (BinaryOperator::Ge, ">="),
            (BinaryOperator::LogicalAnd, "&&"),
            (BinaryOperator::LogicalOr, "||"),
        ];
        for (op, expected) in &ops {
            assert_eq!(binary_operator_str(*op), *expected);
        }
    }

    #[test]
    fn test_unary_operator_str_all() {
        let ops = [
            (UnaryOperator::Neg, "-"),
            (UnaryOperator::Not, "!"),
            (UnaryOperator::BitNot, "~"),
            (UnaryOperator::Deref, "*"),
            (UnaryOperator::AddressOf, "&"),
        ];
        for (op, expected) in &ops {
            assert_eq!(unary_operator_str(*op), *expected);
        }
    }

    #[test]
    fn test_size_to_ctype() {
        assert_eq!(size_to_ctype(0), "void");
        assert_eq!(size_to_ctype(1), "uint8_t");
        assert_eq!(size_to_ctype(2), "uint16_t");
        assert_eq!(size_to_ctype(4), "uint32_t");
        assert_eq!(size_to_ctype(8), "uint64_t");
        assert_eq!(size_to_ctype(16), "uint128_t");
    }

    // ==================================================================
    // is_complex_expression
    // ==================================================================

    #[test]
    fn test_is_complex_expression_true() {
        let bin = Expression::binary(
            BinaryOperator::Add,
            Expression::constant(1, 4),
            Expression::constant(2, 4),
        );
        assert!(is_complex_expression(&bin));

        let call = Expression::Call {
            target: Box::new(Expression::variable("f", 8)),
            args: vec![],
        };
        assert!(is_complex_expression(&call));
    }

    #[test]
    fn test_is_complex_expression_false() {
        let var = Expression::variable("x", 4);
        assert!(!is_complex_expression(&var));

        let cnst = Expression::constant(42, 4);
        assert!(!is_complex_expression(&cnst));

        let deref = Expression::Dereference {
            ptr: Box::new(Expression::variable("p", 8)),
            size: 4,
        };
        assert!(!is_complex_expression(&deref));
    }
}
