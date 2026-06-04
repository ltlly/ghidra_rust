//! Expression context types for p-code analysis.
//!
//! Ported from `BinaryExprContext.java`, `UnaryExprContext.java`,
//! `TernaryExprContext.java`, `CallContext.java`, and
//! `VarargsExprContext.java` in the Lisa extension.

use super::varnode_context::VarnodeContext;

/// Context for a binary expression (e.g., `a + b`).
#[derive(Debug, Clone)]
pub struct BinaryExprContext {
    /// The p-code opcode name (e.g., "INT_ADD", "INT_MULT").
    pub opcode: String,
    /// Left operand.
    pub left: VarnodeContext,
    /// Right operand.
    pub right: VarnodeContext,
    /// Output varnode.
    pub output: VarnodeContext,
}

impl BinaryExprContext {
    /// Create a new binary expression context.
    pub fn new(
        opcode: impl Into<String>,
        left: VarnodeContext,
        right: VarnodeContext,
        output: VarnodeContext,
    ) -> Self {
        Self {
            opcode: opcode.into(),
            left,
            right,
            output,
        }
    }
}

/// Context for a unary expression (e.g., `-x`).
#[derive(Debug, Clone)]
pub struct UnaryExprContext {
    /// The p-code opcode name.
    pub opcode: String,
    /// Input operand.
    pub input: VarnodeContext,
    /// Output varnode.
    pub output: VarnodeContext,
}

impl UnaryExprContext {
    /// Create a new unary expression context.
    pub fn new(
        opcode: impl Into<String>,
        input: VarnodeContext,
        output: VarnodeContext,
    ) -> Self {
        Self {
            opcode: opcode.into(),
            input,
            output,
        }
    }
}

/// Context for a ternary expression (e.g., `a ? b : c`).
#[derive(Debug, Clone)]
pub struct TernaryExprContext {
    /// The p-code opcode name.
    pub opcode: String,
    /// First input.
    pub input0: VarnodeContext,
    /// Second input.
    pub input1: VarnodeContext,
    /// Third input.
    pub input2: VarnodeContext,
    /// Output varnode.
    pub output: VarnodeContext,
}

impl TernaryExprContext {
    /// Create a new ternary expression context.
    pub fn new(
        opcode: impl Into<String>,
        input0: VarnodeContext,
        input1: VarnodeContext,
        input2: VarnodeContext,
        output: VarnodeContext,
    ) -> Self {
        Self {
            opcode: opcode.into(),
            input0,
            input1,
            input2,
            output,
        }
    }
}

/// Context for a function call expression.
#[derive(Debug, Clone)]
pub struct CallContext {
    /// The call target address.
    pub target: u64,
    /// The arguments.
    pub arguments: Vec<VarnodeContext>,
    /// The output (return value) varnode, if any.
    pub output: Option<VarnodeContext>,
}

impl CallContext {
    /// Create a new call context.
    pub fn new(target: u64, arguments: Vec<VarnodeContext>) -> Self {
        Self {
            target,
            arguments,
            output: None,
        }
    }

    /// Set the output (return value) varnode.
    pub fn with_output(mut self, output: VarnodeContext) -> Self {
        self.output = Some(output);
        self
    }

    /// Number of arguments.
    pub fn num_args(&self) -> usize {
        self.arguments.len()
    }
}

/// Context for a varargs expression (e.g., variadic function arguments).
#[derive(Debug, Clone)]
pub struct VarargsExprContext {
    /// The list of varargs.
    pub args: Vec<VarnodeContext>,
}

impl VarargsExprContext {
    /// Create a new varargs context.
    pub fn new(args: Vec<VarnodeContext>) -> Self {
        Self { args }
    }

    /// Number of varargs.
    pub fn num_args(&self) -> usize {
        self.args.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_expr() {
        let left = VarnodeContext::new("register", 0, 8);
        let right = VarnodeContext::new("register", 8, 8);
        let out = VarnodeContext::new("register", 16, 8);
        let expr = BinaryExprContext::new("INT_ADD", left, right, out);
        assert_eq!(expr.opcode, "INT_ADD");
    }

    #[test]
    fn test_unary_expr() {
        let input = VarnodeContext::new("register", 0, 8);
        let out = VarnodeContext::new("register", 8, 8);
        let expr = UnaryExprContext::new("INT_2COMP", input, out);
        assert_eq!(expr.opcode, "INT_2COMP");
    }

    #[test]
    fn test_call_context() {
        let arg0 = VarnodeContext::new("register", 0, 8);
        let arg1 = VarnodeContext::new("register", 8, 4);
        let call = CallContext::new(0x4000, vec![arg0, arg1]);
        assert_eq!(call.num_args(), 2);
        assert!(call.output.is_none());
    }

    #[test]
    fn test_call_with_output() {
        let out = VarnodeContext::new("register", 0, 8);
        let call = CallContext::new(0x4000, vec![]).with_output(out);
        assert!(call.output.is_some());
    }

    #[test]
    fn test_varargs() {
        let args = vec![
            VarnodeContext::new("register", 0, 8),
            VarnodeContext::new("register", 8, 8),
        ];
        let va = VarargsExprContext::new(args);
        assert_eq!(va.num_args(), 2);
    }
}
