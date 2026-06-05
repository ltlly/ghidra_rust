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

#[cfg(test)]
mod tests {
    use super::*;

    // ---- SolverHint ----

    #[test]
    fn test_solver_hint_none() {
        assert_eq!(default_hint(), SolverHint::None);
    }

    #[test]
    fn test_solver_hint_clone() {
        let h = SolverHint::Default(MaskedLong::from_u64(42));
        let h2 = h.clone();
        assert_eq!(h, h2);
    }

    #[test]
    fn test_solver_hint_relative() {
        let h = SolverHint::RelativeOffset(0x1000);
        if let SolverHint::RelativeOffset(off) = h {
            assert_eq!(off, 0x1000);
        } else {
            panic!("expected RelativeOffset");
        }
    }

    // ---- NeedsBackfillException ----

    #[test]
    fn test_needs_backfill_display() {
        let e = NeedsBackfillException("forward ref".to_string());
        assert_eq!(format!("{}", e), "Needs backfill: forward ref");
    }

    #[test]
    fn test_needs_backfill_is_error() {
        let e = NeedsBackfillException("test".to_string());
        let _: &dyn std::error::Error = &e;
    }

    // ---- SolverException ----

    #[test]
    fn test_solver_exception_display() {
        let e = SolverException("bad expr".to_string());
        assert_eq!(format!("{}", e), "Solver error: bad expr");
    }

    #[test]
    fn test_solver_error_display() {
        let e = SolverError::Error(SolverException("oops".to_string()));
        assert!(format!("{}", e).contains("oops"));

        let e2 = SolverError::NeedsBackfill(NeedsBackfillException("fb".to_string()));
        assert!(format!("{}", e2).contains("fb"));
    }

    // ---- ExpressionTree variants ----

    #[test]
    fn test_expression_tree_variants() {
        let c = ExpressionTree::Constant(MaskedLong::from_u64(0x42));
        let o = ExpressionTree::OperandValue(0);
        let tf = ExpressionTree::TokenField { lsb: 0, msb: 7, signed: false, shift: 0 };
        let cf = ExpressionTree::ContextField { lsb: 8, msb: 15, signed: true, shift: 2 };
        let si = ExpressionTree::StartInstruction;
        let ei = ExpressionTree::EndInstruction;
        let n2 = ExpressionTree::Next2Instruction;

        assert!(matches!(c, ExpressionTree::Constant(_)));
        assert!(matches!(o, ExpressionTree::OperandValue(0)));
        assert!(matches!(tf, ExpressionTree::TokenField { msb: 7, .. }));
        assert!(matches!(cf, ExpressionTree::ContextField { signed: true, .. }));
        assert!(matches!(si, ExpressionTree::StartInstruction));
        assert!(matches!(ei, ExpressionTree::EndInstruction));
        assert!(matches!(n2, ExpressionTree::Next2Instruction));
    }

    #[test]
    fn test_expression_tree_binary_ops() {
        let l = Box::new(ExpressionTree::Constant(MaskedLong::from_u64(1)));
        let r = Box::new(ExpressionTree::Constant(MaskedLong::from_u64(2)));

        let plus = ExpressionTree::Plus(l.clone(), r.clone());
        let minus = ExpressionTree::Minus(l.clone(), r.clone());
        let mult = ExpressionTree::Mult(l.clone(), r.clone());
        let div = ExpressionTree::Div(l.clone(), r.clone());
        let and = ExpressionTree::And(l.clone(), r.clone());
        let or = ExpressionTree::Or(l.clone(), r.clone());
        let xor = ExpressionTree::Xor(l.clone(), r.clone());
        let lsh = ExpressionTree::LeftShift(l.clone(), r.clone());
        let rsh = ExpressionTree::RightShift(l.clone(), r.clone());
        let not = ExpressionTree::Not(l.clone());

        assert!(matches!(plus, ExpressionTree::Plus(_, _)));
        assert!(matches!(minus, ExpressionTree::Minus(_, _)));
        assert!(matches!(mult, ExpressionTree::Mult(_, _)));
        assert!(matches!(div, ExpressionTree::Div(_, _)));
        assert!(matches!(and, ExpressionTree::And(_, _)));
        assert!(matches!(or, ExpressionTree::Or(_, _)));
        assert!(matches!(xor, ExpressionTree::Xor(_, _)));
        assert!(matches!(lsh, ExpressionTree::LeftShift(_, _)));
        assert!(matches!(rsh, ExpressionTree::RightShift(_, _)));
        assert!(matches!(not, ExpressionTree::Not(_)));
    }

    #[test]
    fn test_expression_tree_clone_eq() {
        let t1 = ExpressionTree::Plus(
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(10))),
            Box::new(ExpressionTree::OperandValue(1)),
        );
        let t2 = t1.clone();
        assert_eq!(t1, t2);
    }

    // ---- ConstantValueSolver ----

    #[test]
    fn test_constant_solver_handles() {
        let s = ConstantValueSolver;
        let c = ExpressionTree::Constant(MaskedLong::from_u64(5));
        let o = ExpressionTree::OperandValue(0);
        assert!(s.handles(&c));
        assert!(!s.handles(&o));
    }

    #[test]
    fn test_constant_solver_compute() {
        let s = ConstantValueSolver;
        let c = ExpressionTree::Constant(MaskedLong::from_u64(0xAB));
        let result = s.compute(&c, &[]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().get_unsigned(), 0xAB);
    }

    #[test]
    fn test_constant_solver_compute_wrong_type() {
        let s = ConstantValueSolver;
        let o = ExpressionTree::OperandValue(0);
        assert!(s.compute(&o, &[]).is_err());
    }

    #[test]
    fn test_constant_solver_solve_match() {
        let s = ConstantValueSolver;
        let c = ExpressionTree::Constant(MaskedLong::from_u64(42));
        let goal = MaskedLong::from_u64(42);
        let result = s.solve(goal, &c, &[], &SolverHint::None);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_constant_solver_solve_mismatch() {
        let s = ConstantValueSolver;
        let c = ExpressionTree::Constant(MaskedLong::from_u64(42));
        let goal = MaskedLong::from_u64(99);
        assert!(s.solve(goal, &c, &[], &SolverHint::None).is_err());
    }

    // ---- OperandValueSolver ----

    #[test]
    fn test_operand_solver_handles() {
        let s = OperandValueSolver;
        let o = ExpressionTree::OperandValue(3);
        let c = ExpressionTree::Constant(MaskedLong::from_u64(1));
        assert!(s.handles(&o));
        assert!(!s.handles(&c));
    }

    #[test]
    fn test_operand_solver_compute_known() {
        let s = OperandValueSolver;
        let o = ExpressionTree::OperandValue(1);
        let vals = vec![None, Some(MaskedLong::from_u64(0xFF))];
        let result = s.compute(&o, &vals);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().get_unsigned(), 0xFF);
    }

    #[test]
    fn test_operand_solver_compute_unknown() {
        let s = OperandValueSolver;
        let o = ExpressionTree::OperandValue(1);
        let vals = vec![None, None];
        let result = s.compute(&o, &vals);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SolverError::NeedsBackfill(_)));
    }

    #[test]
    fn test_operand_solver_solve_assign() {
        let s = OperandValueSolver;
        let o = ExpressionTree::OperandValue(2);
        let goal = MaskedLong::from_u64(0x1000);
        let vals = vec![None, None, None];
        let result = s.solve(goal, &o, &vals, &SolverHint::None);
        assert!(result.is_ok());
        let assignments = result.unwrap();
        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].0, 2);
        assert_eq!(assignments[0].1.get_unsigned(), 0x1000);
    }

    #[test]
    fn test_operand_solver_solve_already_set_match() {
        let s = OperandValueSolver;
        let o = ExpressionTree::OperandValue(0);
        let goal = MaskedLong::from_u64(42);
        let vals = vec![Some(MaskedLong::from_u64(42))];
        let result = s.solve(goal, &o, &vals, &SolverHint::None);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_operand_solver_solve_already_set_mismatch() {
        let s = OperandValueSolver;
        let o = ExpressionTree::OperandValue(0);
        let goal = MaskedLong::from_u64(42);
        let vals = vec![Some(MaskedLong::from_u64(99))];
        assert!(s.solve(goal, &o, &vals, &SolverHint::None).is_err());
    }

    // ---- PlusExpressionSolver ----

    #[test]
    fn test_plus_solver_handles() {
        let s = PlusExpressionSolver;
        let p = ExpressionTree::Plus(
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(1))),
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(2))),
        );
        assert!(s.handles(&p));
        assert!(!s.handles(&ExpressionTree::Constant(MaskedLong::from_u64(1))));
    }

    #[test]
    fn test_plus_solver_compute() {
        let s = PlusExpressionSolver;
        let tree = ExpressionTree::Plus(
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(10))),
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(20))),
        );
        let result = s.compute(&tree, &[]);
        assert_eq!(result.unwrap().get_unsigned(), 30);
    }

    #[test]
    fn test_plus_solver_solve_one_known() {
        let s = PlusExpressionSolver;
        // goal = 10 + operand[0]  =>  operand[0] = goal - 10
        let tree = ExpressionTree::Plus(
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(10))),
            Box::new(ExpressionTree::OperandValue(0)),
        );
        let goal = MaskedLong::from_u64(30);
        let result = s.solve(goal, &tree, &[], &SolverHint::None);
        assert!(result.is_ok());
        let assignments = result.unwrap();
        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].0, 0);
        assert_eq!(assignments[0].1.get_unsigned(), 20);
    }

    #[test]
    fn test_plus_solver_needs_backfill() {
        let s = PlusExpressionSolver;
        let tree = ExpressionTree::Plus(
            Box::new(ExpressionTree::OperandValue(0)),
            Box::new(ExpressionTree::OperandValue(1)),
        );
        let goal = MaskedLong::from_u64(30);
        let result = s.solve(goal, &tree, &[None, None], &SolverHint::None);
        assert!(matches!(result.unwrap_err(), SolverError::NeedsBackfill(_)));
    }

    // ---- MinusExpressionSolver ----

    #[test]
    fn test_minus_solver_compute() {
        let s = MinusExpressionSolver;
        let tree = ExpressionTree::Minus(
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(50))),
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(20))),
        );
        assert_eq!(s.compute(&tree, &[]).unwrap().get_unsigned(), 30);
    }

    // ---- AndExpressionSolver ----

    #[test]
    fn test_and_solver_compute() {
        let s = AndExpressionSolver;
        let tree = ExpressionTree::And(
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(0xFF))),
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(0x0F))),
        );
        assert_eq!(s.compute(&tree, &[]).unwrap().get_unsigned(), 0x0F);
    }

    // ---- OrExpressionSolver ----

    #[test]
    fn test_or_solver_compute() {
        let s = OrExpressionSolver;
        let tree = ExpressionTree::Or(
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(0xF0))),
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(0x0F))),
        );
        assert_eq!(s.compute(&tree, &[]).unwrap().get_unsigned(), 0xFF);
    }

    // ---- XorExpressionSolver ----

    #[test]
    fn test_xor_solver_compute() {
        let s = XorExpressionSolver;
        let tree = ExpressionTree::Xor(
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(0xFF))),
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(0x0F))),
        );
        assert_eq!(s.compute(&tree, &[]).unwrap().get_unsigned(), 0xF0);
    }

    // ---- LeftShiftExpressionSolver ----

    #[test]
    fn test_left_shift_solver_compute() {
        let s = LeftShiftExpressionSolver;
        let tree = ExpressionTree::LeftShift(
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(1))),
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(4))),
        );
        assert_eq!(s.compute(&tree, &[]).unwrap().get_unsigned(), 16);
    }

    // ---- RightShiftExpressionSolver ----

    #[test]
    fn test_right_shift_solver_compute() {
        let s = RightShiftExpressionSolver;
        let tree = ExpressionTree::RightShift(
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(256))),
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(4))),
        );
        assert_eq!(s.compute(&tree, &[]).unwrap().get_unsigned(), 16);
    }

    // ---- NotExpressionSolver ----

    #[test]
    fn test_not_solver_compute() {
        let s = NotExpressionSolver;
        let tree = ExpressionTree::Not(Box::new(ExpressionTree::Constant(
            MaskedLong::from_u64(0xFF00),
        )));
        let result = s.compute(&tree, &[]);
        // NOT of 0xFF00 in 64-bit = 0xFFFFFFFFFFFF00FF
        assert_eq!(result.unwrap().get_unsigned(), !0xFF00u64);
    }

    // ---- MultExpressionSolver ----

    #[test]
    fn test_mult_solver_compute() {
        let s = MultExpressionSolver;
        let tree = ExpressionTree::Mult(
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(6))),
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(7))),
        );
        assert_eq!(s.compute(&tree, &[]).unwrap().get_unsigned(), 42);
    }

    // ---- DivExpressionSolver ----

    #[test]
    fn test_div_solver_compute() {
        let s = DivExpressionSolver;
        let tree = ExpressionTree::Div(
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(100))),
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(5))),
        );
        assert_eq!(s.compute(&tree, &[]).unwrap().get_unsigned(), 20);
    }

    #[test]
    fn test_div_solver_division_by_zero() {
        let s = DivExpressionSolver;
        let tree = ExpressionTree::Div(
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(100))),
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(0))),
        );
        assert!(s.compute(&tree, &[]).is_err());
    }

    // ---- RecursiveDescentSolver ----

    #[test]
    fn test_recursive_solver_dispatches_constant() {
        let solver = RecursiveDescentSolver::new();
        let tree = ExpressionTree::Constant(MaskedLong::from_u64(99));
        let result = solver.compute(&tree, &[]);
        assert_eq!(result.unwrap().get_unsigned(), 99);
    }

    #[test]
    fn test_recursive_solver_dispatches_plus() {
        let solver = RecursiveDescentSolver::new();
        let tree = ExpressionTree::Plus(
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(3))),
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(4))),
        );
        assert_eq!(solver.compute(&tree, &[]).unwrap().get_unsigned(), 7);
    }

    #[test]
    fn test_recursive_solver_dispatches_operand() {
        let solver = RecursiveDescentSolver::new();
        let tree = ExpressionTree::OperandValue(0);
        let vals = vec![Some(MaskedLong::from_u64(0xABC))];
        assert_eq!(solver.compute(&tree, &vals).unwrap().get_unsigned(), 0xABC);
    }

    #[test]
    fn test_recursive_solver_unknown_expression() {
        let solver = RecursiveDescentSolver::new();
        let tree = ExpressionTree::StartInstruction;
        let result = solver.compute(&tree, &[]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SolverError::Error(_)));
    }

    #[test]
    fn test_recursive_solver_nested() {
        let solver = RecursiveDescentSolver::new();
        // (1 + 2) * 3 = 9
        let tree = ExpressionTree::Mult(
            Box::new(ExpressionTree::Plus(
                Box::new(ExpressionTree::Constant(MaskedLong::from_u64(1))),
                Box::new(ExpressionTree::Constant(MaskedLong::from_u64(2))),
            )),
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(3))),
        );
        assert_eq!(solver.compute(&tree, &[]).unwrap().get_unsigned(), 9);
    }

    #[test]
    fn test_recursive_solver_solve_plus() {
        let solver = RecursiveDescentSolver::new();
        // 10 + x = 25  =>  x = 15
        let tree = ExpressionTree::Plus(
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(10))),
            Box::new(ExpressionTree::OperandValue(0)),
        );
        let goal = MaskedLong::from_u64(25);
        let result = solver.solve(goal, &tree, &[], &SolverHint::None).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, 0);
        assert_eq!(result[0].1.get_unsigned(), 15);
    }

    #[test]
    fn test_recursive_solver_default() {
        let solver = RecursiveDescentSolver::default();
        let tree = ExpressionTree::Constant(MaskedLong::from_u64(7));
        assert_eq!(solver.compute(&tree, &[]).unwrap().get_unsigned(), 7);
    }

    // ---- Error handling ----

    #[test]
    fn test_wrong_solver_for_tree() {
        let s = PlusExpressionSolver;
        let tree = ExpressionTree::Constant(MaskedLong::from_u64(5));
        assert!(s.compute(&tree, &[]).is_err());

        let s2 = ConstantValueSolver;
        let tree2 = ExpressionTree::Plus(
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(1))),
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(2))),
        );
        assert!(s2.compute(&tree2, &[]).is_err());
    }

    #[test]
    fn test_mult_solve_by_zero() {
        let s = MultExpressionSolver;
        let tree = ExpressionTree::Mult(
            Box::new(ExpressionTree::Constant(MaskedLong::from_u64(0))),
            Box::new(ExpressionTree::OperandValue(0)),
        );
        let goal = MaskedLong::from_u64(42);
        // When left is 0, solving for right would require division by 0
        let result = s.solve(goal, &tree, &[], &SolverHint::None);
        assert!(result.is_err());
    }
}
