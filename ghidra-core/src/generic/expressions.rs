//! Numeric expression evaluator for Ghidra Rust.
//!
//! A full port of Ghidra's `generic.expressions` package. Supports parsing and
//! evaluating arithmetic expressions with operators, parentheses, and optional
//! symbol resolution.
//!
//! # Supported operators
//!
//! | Operator | Type   | Precedence |
//! |----------|--------|------------|
//! | `~`      | Unary  | 1          |
//! | `!`      | Unary  | 1          |
//! | `+` (unary)| Unary| 1          |
//! | `-` (unary)| Unary| 1          |
//! | `*`      | Binary | 2          |
//! | `/`      | Binary | 2          |
//! | `+`      | Binary | 3          |
//! | `-`      | Binary | 3          |
//! | `<<`     | Binary | 4          |
//! | `>>`     | Binary | 4          |
//! | `<`      | Binary | 5          |
//! | `>`      | Binary | 5          |
//! | `<=`     | Binary | 5          |
//! | `>=`     | Binary | 5          |
//! | `==`     | Binary | 6          |
//! | `!=`     | Binary | 6          |
//! | `&`      | Binary | 7          |
//! | `^`      | Binary | 8          |
//! | `\|`     | Binary | 9          |
//! | `&&`     | Binary | 10         |
//! | `\|\|`   | Binary | 11         |

use std::collections::BTreeMap;
use std::fmt;

// ============================================================================
// ExpressionException
// ============================================================================

/// Error during expression evaluation.
#[derive(Debug, Clone)]
pub struct ExpressionException {
    pub message: String,
}

impl ExpressionException {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ExpressionException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExpressionException: {}", self.message)
    }
}

impl std::error::Error for ExpressionException {}

// ============================================================================
// ExpressionOperator
// ============================================================================

/// Whether an operator is unary or binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpType {
    Unary,
    Binary,
}

/// All supported expression operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExpressionOperator {
    // Unary
    BitwiseNot,
    LogicalNot,
    UnaryPlus,
    UnaryMinus,
    // Multiplicative
    Multiply,
    Divide,
    // Additive
    Add,
    Subtract,
    // Shift
    ShiftLeft,
    ShiftRight,
    // Relational
    LessThan,
    GreaterThan,
    LessThanOrEqual,
    GreaterThanOrEqual,
    // Equality
    Equals,
    NotEquals,
    // Bitwise
    BitwiseAnd,
    BitwiseXor,
    BitwiseOr,
    // Logical
    LogicalAnd,
    LogicalOr,
}

impl ExpressionOperator {
    pub fn name(&self) -> &'static str {
        match self {
            Self::BitwiseNot => "~",
            Self::LogicalNot => "!",
            Self::UnaryPlus => "+",
            Self::UnaryMinus => "-",
            Self::Multiply => "*",
            Self::Divide => "/",
            Self::Add => "+",
            Self::Subtract => "-",
            Self::ShiftLeft => "<<",
            Self::ShiftRight => ">>",
            Self::LessThan => "<",
            Self::GreaterThan => ">",
            Self::LessThanOrEqual => "<=",
            Self::GreaterThanOrEqual => ">=",
            Self::Equals => "==",
            Self::NotEquals => "!=",
            Self::BitwiseAnd => "&",
            Self::BitwiseXor => "^",
            Self::BitwiseOr => "|",
            Self::LogicalAnd => "&&",
            Self::LogicalOr => "||",
        }
    }

    pub fn op_type(&self) -> OpType {
        match self {
            Self::BitwiseNot | Self::LogicalNot | Self::UnaryPlus | Self::UnaryMinus => {
                OpType::Unary
            }
            _ => OpType::Binary,
        }
    }

    pub fn is_unary(&self) -> bool {
        self.op_type() == OpType::Unary
    }

    pub fn is_binary(&self) -> bool {
        self.op_type() == OpType::Binary
    }

    pub fn precedence(&self) -> u32 {
        match self {
            Self::BitwiseNot | Self::LogicalNot | Self::UnaryPlus | Self::UnaryMinus => 1,
            Self::Multiply | Self::Divide => 2,
            Self::Add | Self::Subtract => 3,
            Self::ShiftLeft | Self::ShiftRight => 4,
            Self::LessThan | Self::GreaterThan | Self::LessThanOrEqual
            | Self::GreaterThanOrEqual => 5,
            Self::Equals | Self::NotEquals => 6,
            Self::BitwiseAnd => 7,
            Self::BitwiseXor => 8,
            Self::BitwiseOr => 9,
            Self::LogicalAnd => 10,
            Self::LogicalOr => 11,
        }
    }

    pub fn char_count(&self) -> usize {
        self.name().len()
    }

    /// Get binary operators grouped by precedence (ascending).
    pub fn binary_operators_by_precedence() -> Vec<Vec<ExpressionOperator>> {
        let mut map: BTreeMap<u32, Vec<ExpressionOperator>> = BTreeMap::new();
        let all = [
            Self::Multiply,
            Self::Divide,
            Self::Add,
            Self::Subtract,
            Self::ShiftLeft,
            Self::ShiftRight,
            Self::LessThan,
            Self::GreaterThan,
            Self::LessThanOrEqual,
            Self::GreaterThanOrEqual,
            Self::Equals,
            Self::NotEquals,
            Self::BitwiseAnd,
            Self::BitwiseXor,
            Self::BitwiseOr,
            Self::LogicalAnd,
            Self::LogicalOr,
        ];
        for op in &all {
            map.entry(op.precedence()).or_default().push(*op);
        }
        map.into_values().collect()
    }

    /// Find an operator matching the token and next token, preferring binary
    /// operators when `prefer_binary` is true.
    pub fn get_operator(token: &str, next_token: Option<&str>, prefer_binary: bool) -> Option<Self> {
        // Try two-char operators first
        if let Some(nt) = next_token {
            let double = format!("{}{}", token, nt);
            if let Some(op) = Self::find_operator(&double, prefer_binary) {
                return Some(op);
            }
        }
        Self::find_operator(token, prefer_binary)
    }

    fn find_operator(tokens: &str, expect_binary: bool) -> Option<Self> {
        let all = [
            Self::BitwiseNot,
            Self::LogicalNot,
            Self::UnaryPlus,
            Self::UnaryMinus,
            Self::Multiply,
            Self::Divide,
            Self::Add,
            Self::Subtract,
            Self::ShiftLeft,
            Self::ShiftRight,
            Self::LessThan,
            Self::GreaterThan,
            Self::LessThanOrEqual,
            Self::GreaterThanOrEqual,
            Self::Equals,
            Self::NotEquals,
            Self::BitwiseAnd,
            Self::BitwiseXor,
            Self::BitwiseOr,
            Self::LogicalAnd,
            Self::LogicalOr,
        ];
        for op in &all {
            if op.name() == tokens && op.is_binary() == expect_binary {
                return Some(*op);
            }
        }
        None
    }
}

impl fmt::Display for ExpressionOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// ExpressionElement — enum variant for expression parsing
// ============================================================================

/// An element in an expression: a value, an operator, or a grouping delimiter.
#[derive(Debug, Clone)]
pub enum ExpressionElement {
    /// A long value.
    Value(i64),
    /// An operator.
    Operator(ExpressionOperator),
    /// A left parenthesis.
    LeftParen,
    /// A right parenthesis.
    RightParen,
}

// ============================================================================
// ExpressionEvaluator
// ============================================================================

/// Evaluates numeric expressions.
///
/// All values are interpreted as `i64`. Optionally, a symbol evaluator
/// function can be provided for resolving string tokens to numeric values.
///
/// # Examples
///
/// ```
/// use ghidra_core::generic::expressions::ExpressionEvaluator;
///
/// let result = ExpressionEvaluator::evaluate_to_long("2 + 3 * 4").unwrap();
/// assert_eq!(result, 14);
///
/// let result = ExpressionEvaluator::evaluate_to_long("0xFF & 0x0F").unwrap();
/// assert_eq!(result, 15);
/// ```
pub struct ExpressionEvaluator {
    assume_hex: bool,
    symbol_evaluator: Option<Box<dyn Fn(&str) -> Option<i64>>>,
}

impl ExpressionEvaluator {
    /// Evaluate an expression in decimal mode and return the long result.
    pub fn evaluate_to_long(input: &str) -> Result<i64, ExpressionException> {
        Self::evaluate_to_long_with_hex(input, false)
    }

    /// Evaluate an expression, optionally assuming all numbers are hex.
    pub fn evaluate_to_long_with_hex(
        input: &str,
        assume_hex: bool,
    ) -> Result<i64, ExpressionException> {
        let evaluator = Self::new(assume_hex);
        evaluator.parse_as_long(input)
    }

    /// Evaluate an expression with a symbol evaluator.
    pub fn evaluate_with_symbols(
        input: &str,
        symbol_evaluator: impl Fn(&str) -> Option<i64> + 'static,
    ) -> Result<i64, ExpressionException> {
        let evaluator = Self {
            assume_hex: false,
            symbol_evaluator: Some(Box::new(symbol_evaluator)),
        };
        evaluator.parse_as_long(input)
    }

    /// Create a new evaluator in decimal mode.
    pub fn new(assume_hex: bool) -> Self {
        Self {
            assume_hex,
            symbol_evaluator: None,
        }
    }

    /// Create a new evaluator with a symbol evaluator.
    pub fn with_symbol_evaluator(
        assume_hex: bool,
        evaluator: impl Fn(&str) -> Option<i64> + 'static,
    ) -> Self {
        Self {
            assume_hex,
            symbol_evaluator: Some(Box::new(evaluator)),
        }
    }

    /// Parse and evaluate the expression, returning a long value.
    pub fn parse_as_long(&self, input: &str) -> Result<i64, ExpressionException> {
        let mut list = Vec::new();
        self.parse_to_list(input, &mut list)?;
        let value = self.eval(&mut list)?;
        Ok(value)
    }

    fn parse_to_list(
        &self,
        input: &str,
        list: &mut Vec<ExpressionElement>,
    ) -> Result<(), ExpressionException> {
        let mut tokenizer = LookAheadTokenizer::new(input);
        while tokenizer.has_more_tokens() {
            let token = tokenizer.current_token().to_string();

            if token.chars().all(|c| c.is_whitespace()) {
                tokenizer.advance(1);
            } else if self.process_group_token(list, &token) {
                tokenizer.advance(1);
            } else if self.process_operator(
                list,
                &token,
                tokenizer.next_token(),
            ) {
                if let Some(ExpressionElement::Operator(op)) = list.last() {
                    tokenizer.advance(op.char_count());
                }
            } else if self.process_number(list, &token) {
                tokenizer.advance(1);
            } else if self.process_symbol(list, &token) {
                tokenizer.advance(1);
            } else {
                return Err(ExpressionException::new(format!(
                    "Could not evaluate token \"{}\"",
                    token
                )));
            }
        }
        if list.is_empty() {
            return Err(ExpressionException::new("Expression is empty. Nothing to parse!"));
        }
        Ok(())
    }

    fn eval(&self, list: &mut Vec<ExpressionElement>) -> Result<i64, ExpressionException> {
        self.process_groups(list)?;
        self.process_unary_operators(list)?;
        self.process_binary_operators(list)?;

        if list.len() != 1 {
            let result: Vec<String> = list.iter().map(|e| format!("{:?}", e)).collect();
            return Err(ExpressionException::new(format!(
                "Parse failed! Stopped at \"{}\"",
                result.join(" ")
            )));
        }

        match &list[0] {
            ExpressionElement::Value(v) => Ok(*v),
            _ => Err(ExpressionException::new(
                "Parse failed to evaluate to a value!",
            )),
        }
    }

    fn process_binary_operators(
        &self,
        list: &mut Vec<ExpressionElement>,
    ) -> Result<(), ExpressionException> {
        let ops_by_prec = ExpressionOperator::binary_operators_by_precedence();
        for ops in &ops_by_prec {
            self.process_binary_operators_at_precedence(list, ops)?;
        }
        Ok(())
    }

    fn process_binary_operators_at_precedence(
        &self,
        list: &mut Vec<ExpressionElement>,
        operators: &[ExpressionOperator],
    ) -> Result<(), ExpressionException> {
        let mut i = 1;
        while i < list.len() - 1 {
            if let ExpressionElement::Operator(op) = &list[i] {
                if operators.contains(op) {
                    let op = *op;
                    if let (ExpressionElement::Value(v1), ExpressionElement::Value(v2)) =
                        (&list[i - 1], &list[i + 1])
                    {
                        let (v1, v2) = (*v1, *v2);
                        let new_value = apply_binary_op(op, v1, v2);
                        list[i - 1] = ExpressionElement::Value(new_value);
                        list.drain(i..=i + 1);
                        continue;
                    }
                }
            }
            i += 1;
        }
        Ok(())
    }

    fn process_unary_operators(
        &self,
        list: &mut Vec<ExpressionElement>,
    ) -> Result<(), ExpressionException> {
        let mut i = 0;
        while i < list.len() - 1 {
            if let ExpressionElement::Operator(op) = &list[i] {
                if op.is_unary() {
                    let op = *op;
                    if let ExpressionElement::Value(v) = &list[i + 1] {
                        let v = *v;
                        let new_value = apply_unary_op(op, v);
                        list.remove(i);
                        list[i] = ExpressionElement::Value(new_value);
                        continue;
                    }
                }
            }
            i += 1;
        }
        Ok(())
    }

    fn process_groups(
        &self,
        list: &mut Vec<ExpressionElement>,
    ) -> Result<(), ExpressionException> {
        while let Some(group_start) = find_group_start(list) {
            let group_end = find_group_end(list, group_start)
                .ok_or_else(|| ExpressionException::new("Missing end parenthesis!"))?;
            // Extract the sublist between parentheses into a new Vec and evaluate it.
            // We use to_vec() because we can't hold a mutable slice while calling eval.
            let mut sublist: Vec<ExpressionElement> = list[group_start + 1..group_end].to_vec();
            let value = self.eval(&mut sublist)?;
            // Replace the opening paren with the result
            list[group_start] = ExpressionElement::Value(value);
            // Drain the evaluated elements + the closing paren
            // group_start+1..group_end is the original content (which is now reduced to one value in our extracted copy)
            // group_end is the closing paren
            list.drain(group_start + 1..=group_end);
        }
        Ok(())
    }

    fn process_group_token(&self, list: &mut Vec<ExpressionElement>, token: &str) -> bool {
        match token {
            "(" => {
                list.push(ExpressionElement::LeftParen);
                true
            }
            ")" => {
                list.push(ExpressionElement::RightParen);
                true
            }
            _ => false,
        }
    }

    fn should_prefer_binary_op(&self, list: &[ExpressionElement]) -> bool {
        if list.is_empty() {
            return false;
        }
        match list.last().unwrap() {
            ExpressionElement::Value(_) => true,
            ExpressionElement::Operator(_) => false,
            ExpressionElement::LeftParen => false,
            ExpressionElement::RightParen => true,
        }
    }

    fn process_operator(
        &self,
        list: &mut Vec<ExpressionElement>,
        token: &str,
        next_token: Option<&str>,
    ) -> bool {
        let prefer_binary = self.should_prefer_binary_op(list);
        if let Some(op) = ExpressionOperator::get_operator(token, next_token, prefer_binary) {
            list.push(ExpressionElement::Operator(op));
            true
        } else {
            false
        }
    }

    fn process_number(&self, list: &mut Vec<ExpressionElement>, token: &str) -> bool {
        let trimmed = token.trim();

        if self.assume_hex {
            if let Ok(v) = parse_hex_long(trimmed) {
                list.push(ExpressionElement::Value(v as i64));
                return true;
            }
        }

        let lower = trimmed.to_lowercase();
        let cleaned = remove_number_decorators(&lower);

        if let Some(hex_part) = cleaned.strip_prefix("0x") {
            if let Ok(v) = i64::from_str_radix(hex_part, 16) {
                list.push(ExpressionElement::Value(v));
                return true;
            }
        }

        if let Ok(v) = cleaned.parse::<i64>() {
            list.push(ExpressionElement::Value(v));
            return true;
        }

        false
    }

    fn process_symbol(&self, list: &mut Vec<ExpressionElement>, token: &str) -> bool {
        if let Some(ref evaluator) = self.symbol_evaluator {
            if let Some(v) = evaluator(token) {
                list.push(ExpressionElement::Value(v));
                return true;
            }
        }
        false
    }
}

fn apply_unary_op(op: ExpressionOperator, value: i64) -> i64 {
    match op {
        ExpressionOperator::BitwiseNot => !value,
        ExpressionOperator::LogicalNot => {
            if value == 0 { 1 } else { 0 }
        }
        ExpressionOperator::UnaryMinus => -value,
        ExpressionOperator::UnaryPlus => value,
        _ => value,
    }
}

fn apply_binary_op(op: ExpressionOperator, left: i64, right: i64) -> i64 {
    match op {
        ExpressionOperator::BitwiseAnd => left & right,
        ExpressionOperator::BitwiseOr => left | right,
        ExpressionOperator::BitwiseXor => left ^ right,
        ExpressionOperator::Divide => {
            if right == 0 {
                0
            } else {
                left / right
            }
        }
        ExpressionOperator::Equals => {
            if left == right {
                1
            } else {
                0
            }
        }
        ExpressionOperator::GreaterThan => {
            if left > right {
                1
            } else {
                0
            }
        }
        ExpressionOperator::GreaterThanOrEqual => {
            if left >= right {
                1
            } else {
                0
            }
        }
        ExpressionOperator::ShiftLeft => left << right,
        ExpressionOperator::LessThan => {
            if left < right {
                1
            } else {
                0
            }
        }
        ExpressionOperator::LessThanOrEqual => {
            if left <= right {
                1
            } else {
                0
            }
        }
        ExpressionOperator::LogicalAnd => {
            let b1 = if left == 0 { 0 } else { 1 };
            let b2 = if right == 0 { 0 } else { 1 };
            b1 & b2
        }
        ExpressionOperator::LogicalOr => {
            let b1 = if left == 0 { 0 } else { 1 };
            let b2 = if right == 0 { 0 } else { 1 };
            b1 | b2
        }
        ExpressionOperator::Subtract => left - right,
        ExpressionOperator::NotEquals => {
            if left == right {
                0
            } else {
                1
            }
        }
        ExpressionOperator::Add => left + right,
        ExpressionOperator::ShiftRight => left >> right,
        ExpressionOperator::Multiply => left.wrapping_mul(right),
        _ => 0,
    }
}

// ============================================================================
// Tokenizer
// ============================================================================

const TOKEN_CHARS: &str = "+-*/()<>|^&~ =!";

struct LookAheadTokenizer {
    tokens: Vec<String>,
    pos: usize,
}

impl LookAheadTokenizer {
    fn new(input: &str) -> Self {
        let tokens = Self::tokenize(input);
        Self { tokens, pos: 0 }
    }

    fn tokenize(input: &str) -> Vec<String> {
        let mut result = Vec::new();
        let chars: Vec<char> = input.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if TOKEN_CHARS.contains(chars[i]) {
                result.push(chars[i].to_string());
                i += 1;
            } else {
                // Collect non-token chars
                let mut s = String::new();
                while i < chars.len() && !TOKEN_CHARS.contains(chars[i]) {
                    s.push(chars[i]);
                    i += 1;
                }
                result.push(s);
            }
        }
        result
    }

    fn has_more_tokens(&self) -> bool {
        self.pos < self.tokens.len()
    }

    fn current_token(&self) -> &str {
        if self.pos < self.tokens.len() {
            &self.tokens[self.pos]
        } else {
            ""
        }
    }

    fn next_token(&self) -> Option<&str> {
        if self.pos + 1 < self.tokens.len() {
            Some(&self.tokens[self.pos + 1])
        } else {
            None
        }
    }

    fn advance(&mut self, count: usize) {
        self.pos += count;
    }
}

fn find_group_start(list: &[ExpressionElement]) -> Option<usize> {
    list.iter().position(|e| matches!(e, ExpressionElement::LeftParen))
}

fn find_group_end(list: &[ExpressionElement], group_start: usize) -> Option<usize> {
    let mut depth = 1;
    for i in group_start + 1..list.len() {
        match &list[i] {
            ExpressionElement::LeftParen => depth += 1,
            ExpressionElement::RightParen => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

fn remove_number_decorators(token: &str) -> String {
    let s = token.to_lowercase();
    if let Some(rest) = s.strip_suffix("ull").or_else(|| s.strip_suffix("llu")) {
        return rest.to_string();
    }
    if let Some(rest) = s
        .strip_suffix("ul")
        .or_else(|| s.strip_suffix("lu"))
        .or_else(|| s.strip_suffix("ll"))
    {
        return rest.to_string();
    }
    if let Some(rest) = s.strip_suffix('l').or_else(|| s.strip_suffix('u')) {
        return rest.to_string();
    }
    s
}

fn parse_hex_long(token: &str) -> Result<u64, std::num::ParseIntError> {
    let s = token
        .strip_prefix("0x")
        .or(token.strip_prefix("0X"))
        .unwrap_or(token);
    u64::from_str_radix(s, 16)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_arithmetic() {
        assert_eq!(ExpressionEvaluator::evaluate_to_long("2 + 3").unwrap(), 5);
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("10 - 4").unwrap(),
            6
        );
        assert_eq!(ExpressionEvaluator::evaluate_to_long("3 * 7").unwrap(), 21);
        assert_eq!(ExpressionEvaluator::evaluate_to_long("20 / 4").unwrap(), 5);
    }

    #[test]
    fn test_operator_precedence() {
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("2 + 3 * 4").unwrap(),
            14
        );
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("2 * 3 + 4").unwrap(),
            10
        );
    }

    #[test]
    fn test_parentheses() {
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("(2 + 3) * 4").unwrap(),
            20
        );
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("2 * (3 + 4)").unwrap(),
            14
        );
    }

    #[test]
    fn test_hex_values() {
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("0xFF").unwrap(),
            255
        );
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("0xFF & 0x0F").unwrap(),
            15
        );
    }

    #[test]
    fn test_hex_mode() {
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long_with_hex("FF", true).unwrap(),
            255
        );
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long_with_hex("10", true).unwrap(),
            16
        );
    }

    #[test]
    fn test_bitwise_operators() {
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("0xFF & 0x0F").unwrap(),
            15
        );
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("0xF0 | 0x0F").unwrap(),
            255
        );
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("0xFF ^ 0x0F").unwrap(),
            240
        );
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("~0").unwrap(),
            -1
        );
    }

    #[test]
    fn test_shift_operators() {
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("1 << 8").unwrap(),
            256
        );
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("256 >> 4").unwrap(),
            16
        );
    }

    #[test]
    fn test_comparison_operators() {
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("5 > 3").unwrap(),
            1
        );
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("3 > 5").unwrap(),
            0
        );
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("5 == 5").unwrap(),
            1
        );
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("5 != 5").unwrap(),
            0
        );
    }

    #[test]
    fn test_unary_minus() {
        assert_eq!(ExpressionEvaluator::evaluate_to_long("-5").unwrap(), -5);
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("-5 + 3").unwrap(),
            -2
        );
    }

    #[test]
    fn test_logical_operators() {
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("1 && 1").unwrap(),
            1
        );
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("1 && 0").unwrap(),
            0
        );
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("0 || 1").unwrap(),
            1
        );
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("0 || 0").unwrap(),
            0
        );
    }

    #[test]
    fn test_number_decorators() {
        // Should strip "U", "L", "LL", "ULL" etc.
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("42ULL").unwrap(),
            42
        );
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("42L").unwrap(),
            42
        );
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("42U").unwrap(),
            42
        );
    }

    #[test]
    fn test_symbol_evaluator() {
        let result = ExpressionEvaluator::evaluate_with_symbols("MY_CONST + 1", |s| match s {
            "MY_CONST" => Some(42),
            _ => None,
        })
        .unwrap();
        assert_eq!(result, 43);
    }

    #[test]
    fn test_empty_expression() {
        assert!(ExpressionEvaluator::evaluate_to_long("").is_err());
    }

    #[test]
    fn test_invalid_token() {
        assert!(ExpressionEvaluator::evaluate_to_long("abc").is_err());
    }

    #[test]
    fn test_complex_expression() {
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("(1 + 2) * (3 + 4) - 5").unwrap(),
            16
        );
    }

    #[test]
    fn test_nested_parentheses() {
        assert_eq!(
            ExpressionEvaluator::evaluate_to_long("((2 + 3) * (4 + 1))").unwrap(),
            25
        );
    }

    #[test]
    fn test_logical_not() {
        assert_eq!(ExpressionEvaluator::evaluate_to_long("!0").unwrap(), 1);
        assert_eq!(ExpressionEvaluator::evaluate_to_long("!1").unwrap(), 0);
    }
}
