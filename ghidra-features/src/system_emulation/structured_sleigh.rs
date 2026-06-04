//! Structured SLEIGH: programmatic construction of SLEIGH code.
//!
//! Ported from Ghidra's `StructuredSleigh` and related classes
//! (`AssignStmt`, `IfStmt`, `WhileStmt`, `ForStmt`, `BlockStmt`, etc.).
//!
//! This module provides an AST for building SLEIGH code snippets
//! programmatically, without writing raw SLEIGH text.  It is used by
//! syscall emulation libraries and other analysis features that need to
//! generate P-code / SLEIGH instructions.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Expression types
// ---------------------------------------------------------------------------

/// A SLEIGH expression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Expr {
    /// A literal integer value.
    LiteralLong(i64),
    /// A literal floating-point value.
    LiteralFloat(f64),
    /// A variable reference by name.
    Variable(String),
    /// A raw SLEIGH expression string.
    Raw(String),
    /// Binary operation: left op right.
    BinaryOp {
        /// The operator.
        op: BinOp,
        /// Left operand.
        left: Box<Expr>,
        /// Right operand.
        right: Box<Expr>,
    },
    /// Unary operation.
    UnaryOp {
        /// The operator.
        op: UnOp,
        /// Operand.
        operand: Box<Expr>,
    },
    /// A function invocation.
    Invoke {
        /// Function name.
        name: String,
        /// Arguments.
        args: Vec<Expr>,
    },
    /// Pointer dereference.
    Deref(Box<Expr>),
    /// Array index: base[index].
    Index {
        /// Base expression.
        base: Box<Expr>,
        /// Index expression.
        index: Box<Expr>,
    },
    /// Field access: base.field.
    Field {
        /// Base expression.
        base: Box<Expr>,
        /// Field name.
        field: String,
    },
    /// A comparison expression.
    Compare {
        /// Comparison operator.
        op: CmpOp,
        /// Left operand.
        left: Box<Expr>,
        /// Right operand.
        right: Box<Expr>,
    },
    /// Boolean NOT.
    Not(Box<Expr>),
}

/// Binary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
}

/// Unary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnOp {
    Negate,
    BitNot,
    LogicalNot,
}

/// Comparison operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

// ---------------------------------------------------------------------------
// Statement types
// ---------------------------------------------------------------------------

/// A SLEIGH statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Stmt {
    /// An assignment: target = expr.
    Assign {
        /// Target variable or expression.
        target: Expr,
        /// Value expression.
        value: Expr,
    },
    /// A declaration: local var.
    Declare {
        /// Variable name.
        name: String,
        /// Optional type size (in bytes).
        size: Option<usize>,
    },
    /// An if statement.
    If {
        /// Condition expression.
        condition: Expr,
        /// Then-branch statements.
        then_body: Vec<Stmt>,
        /// Else-branch statements (optional).
        else_body: Vec<Stmt>,
    },
    /// A while loop.
    While {
        /// Condition expression.
        condition: Expr,
        /// Loop body.
        body: Vec<Stmt>,
    },
    /// A for loop.
    For {
        /// Init statement.
        init: Box<Stmt>,
        /// Condition expression.
        condition: Expr,
        /// Update statement.
        update: Box<Stmt>,
        /// Loop body.
        body: Vec<Stmt>,
    },
    /// A goto statement.
    Goto(String),
    /// A break statement.
    Break,
    /// A continue statement.
    Continue,
    /// A return statement.
    Return(Option<Expr>),
    /// A raw SLEIGH statement.
    Raw(String),
    /// A block of statements.
    Block(Vec<Stmt>),
    /// A void expression (used for calls as statements).
    ExprStmt(Expr),
}

// ---------------------------------------------------------------------------
// StructuredSleigh -- the builder / container
// ---------------------------------------------------------------------------

/// A builder for constructing SLEIGH code snippets.
///
/// # Usage
///
/// ```rust
/// use ghidra_features::system_emulation::structured_sleigh::*;
///
/// let mut s = StructuredSleigh::new();
/// s.declare("tmp", Some(4));
/// s.assign(Expr::Variable("tmp".into()), Expr::LiteralLong(42));
/// s.if_then(
///     Expr::Compare {
///         op: CmpOp::Eq,
///         left: Box::new(Expr::Variable("tmp".into())),
///         right: Box::new(Expr::LiteralLong(42)),
///     },
///     vec![Stmt::Raw("RAX = tmp;".into())],
/// );
///
/// let code = s.render();
/// assert!(code.contains("local tmp:32;"));
/// assert!(code.contains("tmp = 42;"));
/// assert!(code.contains("if (tmp == 42)"));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredSleigh {
    /// Top-level statements.
    pub statements: Vec<Stmt>,
    /// Indentation string (for pretty-printing).
    pub indent: String,
}

impl StructuredSleigh {
    /// Create a new empty SLEIGH builder.
    pub fn new() -> Self {
        Self {
            statements: Vec::new(),
            indent: "    ".to_string(),
        }
    }

    /// Add a declaration statement.
    pub fn declare(&mut self, name: &str, size: Option<usize>) {
        self.statements.push(Stmt::Declare {
            name: name.to_string(),
            size,
        });
    }

    /// Add an assignment statement.
    pub fn assign(&mut self, target: Expr, value: Expr) {
        self.statements.push(Stmt::Assign { target, value });
    }

    /// Add an if-then statement.
    pub fn if_then(&mut self, condition: Expr, body: Vec<Stmt>) {
        self.statements.push(Stmt::If {
            condition,
            then_body: body,
            else_body: Vec::new(),
        });
    }

    /// Add an if-then-else statement.
    pub fn if_then_else(&mut self, condition: Expr, then_body: Vec<Stmt>, else_body: Vec<Stmt>) {
        self.statements.push(Stmt::If {
            condition,
            then_body,
            else_body,
        });
    }

    /// Add a while loop.
    pub fn while_loop(&mut self, condition: Expr, body: Vec<Stmt>) {
        self.statements.push(Stmt::While { condition, body });
    }

    /// Add a return statement.
    pub fn return_value(&mut self, value: Expr) {
        self.statements.push(Stmt::Return(Some(value)));
    }

    /// Add a for loop.
    pub fn for_loop(&mut self, init: Stmt, condition: Expr, update: Stmt, body: Vec<Stmt>) {
        self.statements.push(Stmt::For {
            init: Box::new(init),
            condition,
            update: Box::new(update),
            body,
        });
    }

    /// Add a bare return.
    pub fn return_void(&mut self) {
        self.statements.push(Stmt::Return(None));
    }

    /// Add a raw statement.
    pub fn raw(&mut self, code: &str) {
        self.statements.push(Stmt::Raw(code.to_string()));
    }

    /// Render all statements to SLEIGH text.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for stmt in &self.statements {
            self.render_stmt(stmt, &mut out, 0);
        }
        out
    }

    /// Render a single statement at the given indentation level.
    fn render_stmt(&self, stmt: &Stmt, out: &mut String, depth: usize) {
        let indent = self.indent.repeat(depth);
        match stmt {
            Stmt::Assign { target, value } => {
                out.push_str(&format!(
                    "{}{} = {};\n",
                    indent,
                    self.render_expr(target),
                    self.render_expr(value)
                ));
            }
            Stmt::Declare { name, size } => {
                if let Some(sz) = size {
                    out.push_str(&format!("{}local {}:{};\n", indent, name, sz * 8));
                } else {
                    out.push_str(&format!("{}local {};\n", indent, name));
                }
            }
            Stmt::If {
                condition,
                then_body,
                else_body,
            } => {
                out.push_str(&format!("{}if ({}) {{\n", indent, self.render_expr(condition)));
                for s in then_body {
                    self.render_stmt(s, out, depth + 1);
                }
                if !else_body.is_empty() {
                    out.push_str(&format!("{}}} else {{\n", indent));
                    for s in else_body {
                        self.render_stmt(s, out, depth + 1);
                    }
                }
                out.push_str(&format!("{}}}\n", indent));
            }
            Stmt::While { condition, body } => {
                out.push_str(&format!(
                    "{}while ({}) {{\n",
                    indent,
                    self.render_expr(condition)
                ));
                for s in body {
                    self.render_stmt(s, out, depth + 1);
                }
                out.push_str(&format!("{}}}\n", indent));
            }
            Stmt::For {
                init,
                condition,
                update,
                body,
            } => {
                let mut init_str = String::new();
                self.render_stmt(init, &mut init_str, 0);
                let init_str = init_str.trim().trim_end_matches(';');
                let mut upd_str = String::new();
                self.render_stmt(update, &mut upd_str, 0);
                let upd_str = upd_str.trim().trim_end_matches(';');
                out.push_str(&format!(
                    "{}for ({}; {}; {}) {{\n",
                    indent,
                    init_str,
                    self.render_expr(condition),
                    upd_str
                ));
                for s in body {
                    self.render_stmt(s, out, depth + 1);
                }
                out.push_str(&format!("{}}}\n", indent));
            }
            Stmt::Goto(label) => {
                out.push_str(&format!("{}goto {};\n", indent, label));
            }
            Stmt::Break => {
                out.push_str(&format!("{}break;\n", indent));
            }
            Stmt::Continue => {
                out.push_str(&format!("{}continue;\n", indent));
            }
            Stmt::Return(Some(expr)) => {
                out.push_str(&format!("{}return {};\n", indent, self.render_expr(expr)));
            }
            Stmt::Return(None) => {
                out.push_str(&format!("{}return;\n", indent));
            }
            Stmt::Raw(code) => {
                out.push_str(&format!("{}{}\n", indent, code));
            }
            Stmt::Block(stmts) => {
                out.push_str(&format!("{}{{\n", indent));
                for s in stmts {
                    self.render_stmt(s, out, depth + 1);
                }
                out.push_str(&format!("{}}}\n", indent));
            }
            Stmt::ExprStmt(expr) => {
                out.push_str(&format!("{}{};\n", indent, self.render_expr(expr)));
            }
        }
    }

    /// Render an expression to text.
    fn render_expr(&self, expr: &Expr) -> String {
        match expr {
            Expr::LiteralLong(v) => format!("{}", v),
            Expr::LiteralFloat(v) => format!("{}", v),
            Expr::Variable(name) => name.clone(),
            Expr::Raw(s) => s.clone(),
            Expr::BinaryOp { op, left, right } => {
                let op_str = match op {
                    BinOp::Add => "+",
                    BinOp::Sub => "-",
                    BinOp::Mul => "*",
                    BinOp::Div => "/",
                    BinOp::Mod => "%",
                    BinOp::BitAnd => "&",
                    BinOp::BitOr => "|",
                    BinOp::BitXor => "^",
                    BinOp::Shl => "<<",
                    BinOp::Shr => ">>",
                };
                format!(
                    "({} {} {})",
                    self.render_expr(left),
                    op_str,
                    self.render_expr(right)
                )
            }
            Expr::UnaryOp { op, operand } => {
                let op_str = match op {
                    UnOp::Negate => "-",
                    UnOp::BitNot => "~",
                    UnOp::LogicalNot => "!",
                };
                format!("({}{})", op_str, self.render_expr(operand))
            }
            Expr::Invoke { name, args } => {
                let arg_strs: Vec<String> = args.iter().map(|a| self.render_expr(a)).collect();
                format!("{}({})", name, arg_strs.join(", "))
            }
            Expr::Deref(inner) => format!("*({})", self.render_expr(inner)),
            Expr::Index { base, index } => {
                format!("{}[{}]", self.render_expr(base), self.render_expr(index))
            }
            Expr::Field { base, field } => {
                format!("{}.{}", self.render_expr(base), field)
            }
            Expr::Compare { op, left, right } => {
                let op_str = match op {
                    CmpOp::Eq => "==",
                    CmpOp::Ne => "!=",
                    CmpOp::Lt => "<",
                    CmpOp::Le => "<=",
                    CmpOp::Gt => ">",
                    CmpOp::Ge => ">=",
                };
                format!(
                    "{} {} {}",
                    self.render_expr(left),
                    op_str,
                    self.render_expr(right)
                )
            }
            Expr::Not(inner) => format!("!({})", self.render_expr(inner)),
        }
    }
}

impl Default for StructuredSleigh {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_assignment() {
        let mut s = StructuredSleigh::new();
        s.assign(Expr::Variable("RAX".into()), Expr::LiteralLong(0));
        let code = s.render();
        assert_eq!(code.trim(), "RAX = 0;");
    }

    #[test]
    fn test_render_declaration() {
        let mut s = StructuredSleigh::new();
        s.declare("tmp", Some(4));
        let code = s.render();
        assert_eq!(code.trim(), "local tmp:32;");
    }

    #[test]
    fn test_render_if_then() {
        let mut s = StructuredSleigh::new();
        s.if_then(
            Expr::Compare {
                op: CmpOp::Eq,
                left: Box::new(Expr::Variable("RAX".into())),
                right: Box::new(Expr::LiteralLong(0)),
            },
            vec![Stmt::Assign {
                target: Expr::Variable("RBX".into()),
                value: Expr::LiteralLong(1),
            }],
        );
        let code = s.render();
        assert!(code.contains("if (RAX == 0)"));
        assert!(code.contains("RBX = 1;"));
    }

    #[test]
    fn test_render_if_then_else() {
        let mut s = StructuredSleigh::new();
        s.if_then_else(
            Expr::Compare {
                op: CmpOp::Lt,
                left: Box::new(Expr::Variable("RCX".into())),
                right: Box::new(Expr::LiteralLong(10)),
            },
            vec![Stmt::Raw("RAX = 1;".into())],
            vec![Stmt::Raw("RAX = 0;".into())],
        );
        let code = s.render();
        assert!(code.contains("if (RCX < 10)"));
        assert!(code.contains("} else {"));
    }

    #[test]
    fn test_render_while_loop() {
        let mut s = StructuredSleigh::new();
        s.while_loop(
            Expr::Compare {
                op: CmpOp::Gt,
                left: Box::new(Expr::Variable("RCX".into())),
                right: Box::new(Expr::LiteralLong(0)),
            },
            vec![Stmt::Assign {
                target: Expr::Variable("RCX".into()),
                value: Expr::BinaryOp {
                    op: BinOp::Sub,
                    left: Box::new(Expr::Variable("RCX".into())),
                    right: Box::new(Expr::LiteralLong(1)),
                },
            }],
        );
        let code = s.render();
        assert!(code.contains("while (RCX > 0)"));
        assert!(code.contains("RCX = (RCX - 1);"));
    }

    #[test]
    fn test_render_return() {
        let mut s = StructuredSleigh::new();
        s.return_value(Expr::Variable("RAX".into()));
        let code = s.render();
        assert_eq!(code.trim(), "return RAX;");
    }

    #[test]
    fn test_render_return_void() {
        let mut s = StructuredSleigh::new();
        s.return_void();
        let code = s.render();
        assert_eq!(code.trim(), "return;");
    }

    #[test]
    fn test_render_binary_expressions() {
        let expr = Expr::BinaryOp {
            op: BinOp::Add,
            left: Box::new(Expr::Variable("RAX".into())),
            right: Box::new(Expr::LiteralLong(8)),
        };
        let s = StructuredSleigh::new();
        assert_eq!(s.render_expr(&expr), "(RAX + 8)");
    }

    #[test]
    fn test_render_deref() {
        let expr = Expr::Deref(Box::new(Expr::Variable("RAX".into())));
        let s = StructuredSleigh::new();
        assert_eq!(s.render_expr(&expr), "*(RAX)");
    }

    #[test]
    fn test_render_index() {
        let expr = Expr::Index {
            base: Box::new(Expr::Variable("RAX".into())),
            index: Box::new(Expr::LiteralLong(4)),
        };
        let s = StructuredSleigh::new();
        assert_eq!(s.render_expr(&expr), "RAX[4]");
    }

    #[test]
    fn test_render_field() {
        let expr = Expr::Field {
            base: Box::new(Expr::Variable("ctx".into())),
            field: "register".to_string(),
        };
        let s = StructuredSleigh::new();
        assert_eq!(s.render_expr(&expr), "ctx.register");
    }

    #[test]
    fn test_render_invoke() {
        let expr = Expr::Invoke {
            name: "CALLOTHER".to_string(),
            args: vec![Expr::LiteralLong(1), Expr::Variable("RAX".into())],
        };
        let s = StructuredSleigh::new();
        assert_eq!(s.render_expr(&expr), "CALLOTHER(1, RAX)");
    }

    #[test]
    fn test_render_raw() {
        let mut s = StructuredSleigh::new();
        s.raw("RAX = RCX + RDX;");
        let code = s.render();
        assert_eq!(code.trim(), "RAX = RCX + RDX;");
    }

    #[test]
    fn test_render_for_loop() {
        let mut s = StructuredSleigh::new();
        s.for_loop(
            Stmt::Assign {
                target: Expr::Variable("i".into()),
                value: Expr::LiteralLong(0),
            },
            Expr::Compare {
                op: CmpOp::Lt,
                left: Box::new(Expr::Variable("i".into())),
                right: Box::new(Expr::LiteralLong(10)),
            },
            Stmt::Assign {
                target: Expr::Variable("i".into()),
                value: Expr::BinaryOp {
                    op: BinOp::Add,
                    left: Box::new(Expr::Variable("i".into())),
                    right: Box::new(Expr::LiteralLong(1)),
                },
            },
            vec![Stmt::Raw("RAX = i;".into())],
        );
        let code = s.render();
        assert!(code.contains("for (i = 0; i < 10; i = (i + 1))"));
    }

    #[test]
    fn test_serialize_deserialize() {
        let mut s = StructuredSleigh::new();
        s.assign(Expr::Variable("RAX".into()), Expr::LiteralLong(42));
        let json = serde_json::to_string(&s).unwrap();
        let parsed: StructuredSleigh = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.statements.len(), 1);
    }
}
