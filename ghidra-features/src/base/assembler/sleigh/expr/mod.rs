//! Expression solvers for SLEIGH assembler.
//!
//! Corresponds to Java's `ghidra.app.plugin.assembler.sleigh.expr`.
//!
//! Expression solvers compute concrete values for instruction
//! operands by solving symbolic expressions extracted from SLEIGH
//! constructor constraints.  Each solver handles a specific expression
//! type (addition, subtraction, AND, OR, shifts, etc.).

pub mod masked_long;

use masked_long::MaskedLong;

// ---------------------------------------------------------------------------
// SolverHint
// ---------------------------------------------------------------------------

/// A hint to guide expression solving.
///
/// Corresponds to Java's `SolverHint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolverHint {
    /// No hint.
    None,
    /// A default value hint.
    Default(MaskedLong),
    /// A relative offset hint.
    RelativeOffset(u64),
}

/// Default solver hint (no hint).
pub fn default_hint() -> SolverHint {
    SolverHint::None
}

// ---------------------------------------------------------------------------
// NeedsBackfillException
// ---------------------------------------------------------------------------

/// Thrown when a solver cannot yet produce a concrete value and
/// requires a second pass (backfill).
///
/// Some expressions depend on values not yet known during forward
/// resolution (e.g., forward references).  The resolver will attempt
/// backfill after all forward values are known.
#[derive(Debug, Clone)]
pub struct NeedsBackfillException(pub String);

impl std::fmt::Display for NeedsBackfillException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Needs backfill: {}", self.0)
    }
}

impl std::error::Error for NeedsBackfillException {}

// ---------------------------------------------------------------------------
// SolverException
// ---------------------------------------------------------------------------

/// Thrown when an expression cannot be solved.
#[derive(Debug, Clone)]
pub struct SolverException(pub String);

impl std::fmt::Display for SolverException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Solver error: {}", self.0)
    }
}

impl std::error::Error for SolverException {}

/// Result type for solver operations.
pub type SolverResult<T> = Result<T, SolverError>;

/// Combined error for solver operations.
#[derive(Debug, Clone)]
pub enum SolverError {
    /// The solver needs a backfill pass.
    NeedsBackfill(NeedsBackfillException),
    /// The expression cannot be solved.
    Error(SolverException),
}

impl std::fmt::Display for SolverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NeedsBackfill(e) => write!(f, "{}", e),
            Self::Error(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for SolverError {}

// ---------------------------------------------------------------------------
// ExpressionSolver trait
// ---------------------------------------------------------------------------

/// Trait for expression solvers.
///
/// Each solver handles a specific expression type and attempts to
/// compute a concrete `MaskedLong` value from a symbolic expression.
pub trait ExpressionSolver: Send + Sync + std::fmt::Debug {
    /// Attempt to solve the expression for the given goal value.
    ///
    /// `goal` is the desired result; `tree` is the symbolic expression.
    /// `vals` maps operand indices to their known values.
    /// `hint` provides guidance when multiple solutions are possible.
    fn solve(
        &self,
        goal: MaskedLong,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
        hint: &SolverHint,
    ) -> SolverResult<Vec<(usize, MaskedLong)>>;

    /// Attempt to compute the value of the expression from known
    /// operand values (forward direction).
    fn compute(
        &self,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
    ) -> SolverResult<MaskedLong>;

    /// Check if this solver can handle the given expression type.
    fn handles(&self, tree: &ExpressionTree) -> bool;
}

// ---------------------------------------------------------------------------
// ExpressionTree
// ---------------------------------------------------------------------------

/// A symbolic expression extracted from a SLEIGH constructor.
///
/// Corresponds to the various expression node types in the Java
/// `ghidra.app.plugin.assembler.sleigh.expr` package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpressionTree {
    /// A constant value.
    Constant(MaskedLong),
    /// Reference to an operand by index.
    OperandValue(usize),
    /// A token field (bits from the instruction encoding).
    TokenField {
        /// Least-significant bit.
        lsb: u32,
        /// Most-significant bit.
        msb: u32,
        /// Whether the field is signed.
        signed: bool,
        /// Shift applied to the extracted value.
        shift: u32,
    },
    /// A context register field.
    ContextField {
        /// Least-significant bit.
        lsb: u32,
        /// Most-significant bit.
        msb: u32,
        /// Whether the field is signed.
        signed: bool,
        /// Shift applied to the extracted value.
        shift: u32,
    },
    /// Start of instruction address.
    StartInstruction,
    /// End of instruction address (start + length).
    EndInstruction,
    /// Next instruction address (end + 1).
    Next2Instruction,
    /// Addition of two sub-expressions.
    Plus(Box<ExpressionTree>, Box<ExpressionTree>),
    /// Subtraction of two sub-expressions.
    Minus(Box<ExpressionTree>, Box<ExpressionTree>),
    /// Multiplication.
    Mult(Box<ExpressionTree>, Box<ExpressionTree>),
    /// Integer division.
    Div(Box<ExpressionTree>, Box<ExpressionTree>),
    /// Bitwise AND.
    And(Box<ExpressionTree>, Box<ExpressionTree>),
    /// Bitwise OR.
    Or(Box<ExpressionTree>, Box<ExpressionTree>),
    /// Bitwise XOR.
    Xor(Box<ExpressionTree>, Box<ExpressionTree>),
    /// Left shift.
    LeftShift(Box<ExpressionTree>, Box<ExpressionTree>),
    /// Right shift (arithmetic or logical depending on context).
    RightShift(Box<ExpressionTree>, Box<ExpressionTree>),
    /// Bitwise NOT.
    Not(Box<ExpressionTree>),
}

// ---------------------------------------------------------------------------
// Built-in solver implementations
// ---------------------------------------------------------------------------

/// Solver for constant values.
#[derive(Debug)]
pub struct ConstantValueSolver;

impl ExpressionSolver for ConstantValueSolver {
    fn solve(
        &self,
        goal: MaskedLong,
        tree: &ExpressionTree,
        _vals: &[Option<MaskedLong>],
        _hint: &SolverHint,
    ) -> SolverResult<Vec<(usize, MaskedLong)>> {
        if let ExpressionTree::Constant(c) = tree {
            if goal.matches(*c) {
                Ok(vec![])
            } else {
                Err(SolverError::Error(SolverException(format!(
                    "Constant mismatch: goal={}, constant={}",
                    goal, c
                ))))
            }
        } else {
            Err(SolverError::Error(SolverException(
                "Not a constant expression".to_string(),
            )))
        }
    }

    fn compute(
        &self,
        tree: &ExpressionTree,
        _vals: &[Option<MaskedLong>],
    ) -> SolverResult<MaskedLong> {
        if let ExpressionTree::Constant(c) = tree {
            Ok(*c)
        } else {
            Err(SolverError::Error(SolverException(
                "Not a constant expression".to_string(),
            )))
        }
    }

    fn handles(&self, tree: &ExpressionTree) -> bool {
        matches!(tree, ExpressionTree::Constant(_))
    }
}

/// Solver for operand values.
#[derive(Debug)]
pub struct OperandValueSolver;

impl ExpressionSolver for OperandValueSolver {
    fn solve(
        &self,
        goal: MaskedLong,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
        _hint: &SolverHint,
    ) -> SolverResult<Vec<(usize, MaskedLong)>> {
        if let ExpressionTree::OperandValue(i) = tree {
            // If the value is already known, verify it matches
            if let Some(Some(v)) = vals.get(*i) {
                if !goal.matches(*v) {
                    return Err(SolverError::Error(SolverException(format!(
                        "Operand {} already set to {}, but goal is {}",
                        i, v, goal
                    ))));
                }
                return Ok(vec![]);
            }
            // Otherwise, assign the goal to this operand
            Ok(vec![(*i, goal)])
        } else {
            Err(SolverError::Error(SolverException(
                "Not an operand value expression".to_string(),
            )))
        }
    }

    fn compute(
        &self,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
    ) -> SolverResult<MaskedLong> {
        if let ExpressionTree::OperandValue(i) = tree {
            match vals.get(*i).and_then(|v| *v) {
                Some(v) => Ok(v),
                None => Err(SolverError::NeedsBackfill(NeedsBackfillException(
                    format!("Operand {} not yet resolved", i),
                ))),
            }
        } else {
            Err(SolverError::Error(SolverException(
                "Not an operand value expression".to_string(),
            )))
        }
    }

    fn handles(&self, tree: &ExpressionTree) -> bool {
        matches!(tree, ExpressionTree::OperandValue(_))
    }
}

/// Solver for bitwise AND expressions.
#[derive(Debug)]
pub struct AndExpressionSolver;

impl ExpressionSolver for AndExpressionSolver {
    fn solve(
        &self,
        goal: MaskedLong,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
        hint: &SolverHint,
    ) -> SolverResult<Vec<(usize, MaskedLong)>> {
        if let ExpressionTree::And(left, right) = tree {
            // Try to compute the known side
            let left_val = compute_sub(left, vals);
            let right_val = compute_sub(right, vals);

            match (left_val, right_val) {
                (Ok(_lv), _) => {
                    // goal = lv & x  =>  solve right for (goal) given lv
                    let sub_goal = goal; // simplified: solve sub-expression
                    solve_sub(right, sub_goal, vals, hint)
                }
                (_, Ok(_rv)) => {
                    let sub_goal = goal;
                    solve_sub(left, sub_goal, vals, hint)
                }
                _ => Err(SolverError::NeedsBackfill(NeedsBackfillException(
                    "Both AND operands unknown".to_string(),
                ))),
            }
        } else {
            Err(SolverError::Error(SolverException(
                "Not an AND expression".to_string(),
            )))
        }
    }

    fn compute(
        &self,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
    ) -> SolverResult<MaskedLong> {
        if let ExpressionTree::And(left, right) = tree {
            let lv = compute_sub(left, vals)?;
            let rv = compute_sub(right, vals)?;
            Ok(lv.and(rv))
        } else {
            Err(SolverError::Error(SolverException(
                "Not an AND expression".to_string(),
            )))
        }
    }

    fn handles(&self, tree: &ExpressionTree) -> bool {
        matches!(tree, ExpressionTree::And(_, _))
    }
}

/// Solver for bitwise OR expressions.
#[derive(Debug)]
pub struct OrExpressionSolver;

impl ExpressionSolver for OrExpressionSolver {
    fn solve(
        &self,
        goal: MaskedLong,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
        hint: &SolverHint,
    ) -> SolverResult<Vec<(usize, MaskedLong)>> {
        if let ExpressionTree::Or(left, right) = tree {
            let left_val = compute_sub(left, vals);
            let right_val = compute_sub(right, vals);

            match (left_val, right_val) {
                (Ok(lv), _) => {
                    // goal = lv | x  =>  clear bits from lv, solve for remaining
                    let sub_goal = goal.and_not(lv);
                    solve_sub(right, sub_goal, vals, hint)
                }
                (_, Ok(rv)) => {
                    let sub_goal = goal.and_not(rv);
                    solve_sub(left, sub_goal, vals, hint)
                }
                _ => Err(SolverError::NeedsBackfill(NeedsBackfillException(
                    "Both OR operands unknown".to_string(),
                ))),
            }
        } else {
            Err(SolverError::Error(SolverException(
                "Not an OR expression".to_string(),
            )))
        }
    }

    fn compute(
        &self,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
    ) -> SolverResult<MaskedLong> {
        if let ExpressionTree::Or(left, right) = tree {
            let lv = compute_sub(left, vals)?;
            let rv = compute_sub(right, vals)?;
            Ok(lv.or(rv))
        } else {
            Err(SolverError::Error(SolverException(
                "Not an OR expression".to_string(),
            )))
        }
    }

    fn handles(&self, tree: &ExpressionTree) -> bool {
        matches!(tree, ExpressionTree::Or(_, _))
    }
}

/// Solver for addition expressions.
#[derive(Debug)]
pub struct PlusExpressionSolver;

impl ExpressionSolver for PlusExpressionSolver {
    fn solve(
        &self,
        goal: MaskedLong,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
        hint: &SolverHint,
    ) -> SolverResult<Vec<(usize, MaskedLong)>> {
        if let ExpressionTree::Plus(left, right) = tree {
            let left_val = compute_sub(left, vals);
            let right_val = compute_sub(right, vals);

            match (left_val, right_val) {
                (Ok(lv), _) => {
                    // goal = lv + x  =>  x = goal - lv
                    let sub_goal = goal.sub(lv);
                    solve_sub(right, sub_goal, vals, hint)
                }
                (_, Ok(rv)) => {
                    let sub_goal = goal.sub(rv);
                    solve_sub(left, sub_goal, vals, hint)
                }
                _ => Err(SolverError::NeedsBackfill(NeedsBackfillException(
                    "Both PLUS operands unknown".to_string(),
                ))),
            }
        } else {
            Err(SolverError::Error(SolverException(
                "Not a PLUS expression".to_string(),
            )))
        }
    }

    fn compute(
        &self,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
    ) -> SolverResult<MaskedLong> {
        if let ExpressionTree::Plus(left, right) = tree {
            let lv = compute_sub(left, vals)?;
            let rv = compute_sub(right, vals)?;
            Ok(lv.add(rv))
        } else {
            Err(SolverError::Error(SolverException(
                "Not a PLUS expression".to_string(),
            )))
        }
    }

    fn handles(&self, tree: &ExpressionTree) -> bool {
        matches!(tree, ExpressionTree::Plus(_, _))
    }
}

/// Solver for subtraction expressions.
#[derive(Debug)]
pub struct MinusExpressionSolver;

impl ExpressionSolver for MinusExpressionSolver {
    fn solve(
        &self,
        goal: MaskedLong,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
        hint: &SolverHint,
    ) -> SolverResult<Vec<(usize, MaskedLong)>> {
        if let ExpressionTree::Minus(left, right) = tree {
            let left_val = compute_sub(left, vals);
            let right_val = compute_sub(right, vals);

            match (left_val, right_val) {
                (Ok(lv), _) => {
                    // goal = lv - x  =>  x = lv - goal
                    let sub_goal = lv.sub(goal);
                    solve_sub(right, sub_goal, vals, hint)
                }
                (_, Ok(rv)) => {
                    // goal = x - rv  =>  x = goal + rv
                    let sub_goal = goal.add(rv);
                    solve_sub(left, sub_goal, vals, hint)
                }
                _ => Err(SolverError::NeedsBackfill(NeedsBackfillException(
                    "Both MINUS operands unknown".to_string(),
                ))),
            }
        } else {
            Err(SolverError::Error(SolverException(
                "Not a MINUS expression".to_string(),
            )))
        }
    }

    fn compute(
        &self,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
    ) -> SolverResult<MaskedLong> {
        if let ExpressionTree::Minus(left, right) = tree {
            let lv = compute_sub(left, vals)?;
            let rv = compute_sub(right, vals)?;
            Ok(lv.sub(rv))
        } else {
            Err(SolverError::Error(SolverException(
                "Not a MINUS expression".to_string(),
            )))
        }
    }

    fn handles(&self, tree: &ExpressionTree) -> bool {
        matches!(tree, ExpressionTree::Minus(_, _))
    }
}

/// Solver for left shift expressions.
#[derive(Debug)]
pub struct LeftShiftExpressionSolver;

impl ExpressionSolver for LeftShiftExpressionSolver {
    fn solve(
        &self,
        goal: MaskedLong,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
        hint: &SolverHint,
    ) -> SolverResult<Vec<(usize, MaskedLong)>> {
        if let ExpressionTree::LeftShift(left, right) = tree {
            let right_val = compute_sub(right, vals);
            match right_val {
                Ok(rv) => {
                    let shift = rv.get_unsigned() as u32;
                    // goal = x << shift  =>  x = goal >> shift
                    let sub_goal = goal.right_shift(shift);
                    solve_sub(left, sub_goal, vals, hint)
                }
                _ => Err(SolverError::NeedsBackfill(NeedsBackfillException(
                    "Shift amount unknown".to_string(),
                ))),
            }
        } else {
            Err(SolverError::Error(SolverException(
                "Not a LEFT_SHIFT expression".to_string(),
            )))
        }
    }

    fn compute(
        &self,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
    ) -> SolverResult<MaskedLong> {
        if let ExpressionTree::LeftShift(left, right) = tree {
            let lv = compute_sub(left, vals)?;
            let rv = compute_sub(right, vals)?;
            Ok(lv.left_shift(rv.get_unsigned() as u32))
        } else {
            Err(SolverError::Error(SolverException(
                "Not a LEFT_SHIFT expression".to_string(),
            )))
        }
    }

    fn handles(&self, tree: &ExpressionTree) -> bool {
        matches!(tree, ExpressionTree::LeftShift(_, _))
    }
}

/// Solver for right shift expressions.
#[derive(Debug)]
pub struct RightShiftExpressionSolver;

impl ExpressionSolver for RightShiftExpressionSolver {
    fn solve(
        &self,
        goal: MaskedLong,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
        hint: &SolverHint,
    ) -> SolverResult<Vec<(usize, MaskedLong)>> {
        if let ExpressionTree::RightShift(left, right) = tree {
            let right_val = compute_sub(right, vals);
            match right_val {
                Ok(rv) => {
                    let shift = rv.get_unsigned() as u32;
                    // goal = x >> shift  =>  x = goal << shift
                    let sub_goal = goal.left_shift(shift);
                    solve_sub(left, sub_goal, vals, hint)
                }
                _ => Err(SolverError::NeedsBackfill(NeedsBackfillException(
                    "Shift amount unknown".to_string(),
                ))),
            }
        } else {
            Err(SolverError::Error(SolverException(
                "Not a RIGHT_SHIFT expression".to_string(),
            )))
        }
    }

    fn compute(
        &self,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
    ) -> SolverResult<MaskedLong> {
        if let ExpressionTree::RightShift(left, right) = tree {
            let lv = compute_sub(left, vals)?;
            let rv = compute_sub(right, vals)?;
            Ok(lv.right_shift(rv.get_unsigned() as u32))
        } else {
            Err(SolverError::Error(SolverException(
                "Not a RIGHT_SHIFT expression".to_string(),
            )))
        }
    }

    fn handles(&self, tree: &ExpressionTree) -> bool {
        matches!(tree, ExpressionTree::RightShift(_, _))
    }
}

/// Solver for NOT expressions.
#[derive(Debug)]
pub struct NotExpressionSolver;

impl ExpressionSolver for NotExpressionSolver {
    fn solve(
        &self,
        goal: MaskedLong,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
        hint: &SolverHint,
    ) -> SolverResult<Vec<(usize, MaskedLong)>> {
        if let ExpressionTree::Not(inner) = tree {
            // goal = !x  =>  x = !goal
            let sub_goal = goal.not();
            solve_sub(inner, sub_goal, vals, hint)
        } else {
            Err(SolverError::Error(SolverException(
                "Not a NOT expression".to_string(),
            )))
        }
    }

    fn compute(
        &self,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
    ) -> SolverResult<MaskedLong> {
        if let ExpressionTree::Not(inner) = tree {
            let v = compute_sub(inner, vals)?;
            Ok(v.not())
        } else {
            Err(SolverError::Error(SolverException(
                "Not a NOT expression".to_string(),
            )))
        }
    }

    fn handles(&self, tree: &ExpressionTree) -> bool {
        matches!(tree, ExpressionTree::Not(_))
    }
}

/// Solver for multiplication expressions.
#[derive(Debug)]
pub struct MultExpressionSolver;

impl ExpressionSolver for MultExpressionSolver {
    fn solve(
        &self,
        goal: MaskedLong,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
        hint: &SolverHint,
    ) -> SolverResult<Vec<(usize, MaskedLong)>> {
        if let ExpressionTree::Mult(left, right) = tree {
            let left_val = compute_sub(left, vals);
            let right_val = compute_sub(right, vals);

            match (left_val, right_val) {
                (Ok(lv), _) => {
                    if lv.get_unsigned() == 0 {
                        return Err(SolverError::Error(SolverException(
                            "Division by zero in MULT solve".to_string(),
                        )));
                    }
                    // goal = lv * x  =>  x = goal / lv
                    let sub_goal = goal.div(lv);
                    solve_sub(right, sub_goal, vals, hint)
                }
                (_, Ok(rv)) => {
                    if rv.get_unsigned() == 0 {
                        return Err(SolverError::Error(SolverException(
                            "Division by zero in MULT solve".to_string(),
                        )));
                    }
                    let sub_goal = goal.div(rv);
                    solve_sub(left, sub_goal, vals, hint)
                }
                _ => Err(SolverError::NeedsBackfill(NeedsBackfillException(
                    "Both MULT operands unknown".to_string(),
                ))),
            }
        } else {
            Err(SolverError::Error(SolverException(
                "Not a MULT expression".to_string(),
            )))
        }
    }

    fn compute(
        &self,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
    ) -> SolverResult<MaskedLong> {
        if let ExpressionTree::Mult(left, right) = tree {
            let lv = compute_sub(left, vals)?;
            let rv = compute_sub(right, vals)?;
            Ok(lv.mult(rv))
        } else {
            Err(SolverError::Error(SolverException(
                "Not a MULT expression".to_string(),
            )))
        }
    }

    fn handles(&self, tree: &ExpressionTree) -> bool {
        matches!(tree, ExpressionTree::Mult(_, _))
    }
}

/// Solver for division expressions.
#[derive(Debug)]
pub struct DivExpressionSolver;

impl ExpressionSolver for DivExpressionSolver {
    fn solve(
        &self,
        goal: MaskedLong,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
        hint: &SolverHint,
    ) -> SolverResult<Vec<(usize, MaskedLong)>> {
        if let ExpressionTree::Div(left, right) = tree {
            let left_val = compute_sub(left, vals);
            let right_val = compute_sub(right, vals);

            match (left_val, right_val) {
                (Ok(lv), _) => {
                    // goal = lv / x  =>  x = lv / goal
                    if goal.get_unsigned() == 0 {
                        return Err(SolverError::Error(SolverException(
                            "Division by zero in DIV solve".to_string(),
                        )));
                    }
                    let sub_goal = lv.div(goal);
                    solve_sub(right, sub_goal, vals, hint)
                }
                (_, Ok(rv)) => {
                    // goal = x / rv  =>  x = goal * rv
                    let sub_goal = goal.mult(rv);
                    solve_sub(left, sub_goal, vals, hint)
                }
                _ => Err(SolverError::NeedsBackfill(NeedsBackfillException(
                    "Both DIV operands unknown".to_string(),
                ))),
            }
        } else {
            Err(SolverError::Error(SolverException(
                "Not a DIV expression".to_string(),
            )))
        }
    }

    fn compute(
        &self,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
    ) -> SolverResult<MaskedLong> {
        if let ExpressionTree::Div(left, right) = tree {
            let lv = compute_sub(left, vals)?;
            let rv = compute_sub(right, vals)?;
            if rv.get_unsigned() == 0 {
                return Err(SolverError::Error(SolverException(
                    "Division by zero".to_string(),
                )));
            }
            Ok(lv.div(rv))
        } else {
            Err(SolverError::Error(SolverException(
                "Not a DIV expression".to_string(),
            )))
        }
    }

    fn handles(&self, tree: &ExpressionTree) -> bool {
        matches!(tree, ExpressionTree::Div(_, _))
    }
}

/// Solver for XOR expressions.
#[derive(Debug)]
pub struct XorExpressionSolver;

impl ExpressionSolver for XorExpressionSolver {
    fn solve(
        &self,
        goal: MaskedLong,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
        hint: &SolverHint,
    ) -> SolverResult<Vec<(usize, MaskedLong)>> {
        if let ExpressionTree::Xor(left, right) = tree {
            let left_val = compute_sub(left, vals);
            let right_val = compute_sub(right, vals);

            match (left_val, right_val) {
                (Ok(lv), _) => {
                    // goal = lv ^ x  =>  x = goal ^ lv
                    let sub_goal = goal.xor(lv);
                    solve_sub(right, sub_goal, vals, hint)
                }
                (_, Ok(rv)) => {
                    let sub_goal = goal.xor(rv);
                    solve_sub(left, sub_goal, vals, hint)
                }
                _ => Err(SolverError::NeedsBackfill(NeedsBackfillException(
                    "Both XOR operands unknown".to_string(),
                ))),
            }
        } else {
            Err(SolverError::Error(SolverException(
                "Not an XOR expression".to_string(),
            )))
        }
    }

    fn compute(
        &self,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
    ) -> SolverResult<MaskedLong> {
        if let ExpressionTree::Xor(left, right) = tree {
            let lv = compute_sub(left, vals)?;
            let rv = compute_sub(right, vals)?;
            Ok(lv.xor(rv))
        } else {
            Err(SolverError::Error(SolverException(
                "Not an XOR expression".to_string(),
            )))
        }
    }

    fn handles(&self, tree: &ExpressionTree) -> bool {
        matches!(tree, ExpressionTree::Xor(_, _))
    }
}

// ---------------------------------------------------------------------------
// Recursive descent solver
// ---------------------------------------------------------------------------

/// A solver that dispatches to the appropriate built-in solver
/// based on the expression tree shape.
///
/// This is the top-level entry point for solving expressions,
/// corresponding to Java's `RecursiveDescentSolver`.
#[derive(Debug)]
pub struct RecursiveDescentSolver {
    solvers: Vec<Box<dyn ExpressionSolver>>,
}

impl Default for RecursiveDescentSolver {
    fn default() -> Self {
        Self::new()
    }
}

impl RecursiveDescentSolver {
    /// Create a new recursive descent solver with all built-in solvers.
    pub fn new() -> Self {
        Self {
            solvers: vec![
                Box::new(ConstantValueSolver),
                Box::new(OperandValueSolver),
                Box::new(PlusExpressionSolver),
                Box::new(MinusExpressionSolver),
                Box::new(MultExpressionSolver),
                Box::new(DivExpressionSolver),
                Box::new(AndExpressionSolver),
                Box::new(OrExpressionSolver),
                Box::new(XorExpressionSolver),
                Box::new(LeftShiftExpressionSolver),
                Box::new(RightShiftExpressionSolver),
                Box::new(NotExpressionSolver),
            ],
        }
    }

    /// Solve an expression tree for the given goal value.
    pub fn solve(
        &self,
        goal: MaskedLong,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
        hint: &SolverHint,
    ) -> SolverResult<Vec<(usize, MaskedLong)>> {
        for solver in &self.solvers {
            if solver.handles(tree) {
                return solver.solve(goal, tree, vals, hint);
            }
        }
        Err(SolverError::Error(SolverException(format!(
            "No solver for expression: {:?}",
            tree
        ))))
    }

    /// Compute the value of an expression from known operands.
    pub fn compute(
        &self,
        tree: &ExpressionTree,
        vals: &[Option<MaskedLong>],
    ) -> SolverResult<MaskedLong> {
        for solver in &self.solvers {
            if solver.handles(tree) {
                return solver.compute(tree, vals);
            }
        }
        Err(SolverError::Error(SolverException(format!(
            "No solver for expression: {:?}",
            tree
        ))))
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Compute a sub-expression's value (convenience wrapper).
fn compute_sub(tree: &ExpressionTree, vals: &[Option<MaskedLong>]) -> SolverResult<MaskedLong> {
    let solver = RecursiveDescentSolver::new();
    solver.compute(tree, vals)
}

/// Solve a sub-expression for a goal (convenience wrapper).
fn solve_sub(
    tree: &ExpressionTree,
    goal: MaskedLong,
    vals: &[Option<MaskedLong>],
    hint: &SolverHint,
) -> SolverResult<Vec<(usize, MaskedLong)>> {
    let solver = RecursiveDescentSolver::new();
    solver.solve(goal, tree, vals, hint)
}
