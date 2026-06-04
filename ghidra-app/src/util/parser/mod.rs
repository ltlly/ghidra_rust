//! Expression and address parsing (ported from `ghidra.app.util.parser`).

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error during parsing.
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("unexpected token: {0}")]
    UnexpectedToken(String),
    #[error("expected {expected}, got {actual}")]
    Expected {
        expected: String,
        actual: String,
    },
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("unknown symbol: {0}")]
    UnknownSymbol(String),
}

/// An address expression that can be evaluated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AddressExpression {
    /// A literal hex/decimal address.
    Literal(u64),
    /// A symbol reference.
    Symbol(String),
    /// Binary operation (add, sub, etc.).
    BinaryOp {
        op: BinaryOp,
        left: Box<AddressExpression>,
        right: Box<AddressExpression>,
    },
    /// Dereference (read value at address).
    Deref(Box<AddressExpression>),
}

/// Binary operators for address expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    Xor,
}

impl AddressExpression {
    /// Parse a simple hex literal expression.
    pub fn parse_hex(s: &str) -> Result<Self, ParseError> {
        let s = s.trim();
        let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
        u64::from_str_radix(s, 16)
            .map(Self::Literal)
            .map_err(|_| ParseError::InvalidAddress(s.to_string()))
    }

    /// Evaluate the expression given a symbol resolver.
    pub fn evaluate(
        &self,
        symbol_resolver: &dyn Fn(&str) -> Option<u64>,
    ) -> Result<u64, ParseError> {
        match self {
            Self::Literal(v) => Ok(*v),
            Self::Symbol(name) => symbol_resolver(name)
                .ok_or_else(|| ParseError::UnknownSymbol(name.clone())),
            Self::BinaryOp { op, left, right } => {
                let l = left.evaluate(symbol_resolver)?;
                let r = right.evaluate(symbol_resolver)?;
                Ok(match op {
                    BinaryOp::Add => l.wrapping_add(r),
                    BinaryOp::Sub => l.wrapping_sub(r),
                    BinaryOp::Mul => l.wrapping_mul(r),
                    BinaryOp::Div => l.checked_div(r).unwrap_or(0),
                    BinaryOp::And => l & r,
                    BinaryOp::Or => l | r,
                    BinaryOp::Xor => l ^ r,
                })
            }
            Self::Deref(inner) => {
                let _addr = inner.evaluate(symbol_resolver)?;
                // In a real implementation, this would read from memory
                Err(ParseError::UnexpectedToken(
                    "dereference not supported in expression evaluator".into(),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_literal() {
        assert_eq!(
            AddressExpression::parse_hex("0xDEAD").unwrap(),
            AddressExpression::Literal(0xDEAD)
        );
        assert_eq!(
            AddressExpression::parse_hex("0X1234").unwrap(),
            AddressExpression::Literal(0x1234)
        );
        assert_eq!(
            AddressExpression::parse_hex("256").unwrap(),
            AddressExpression::Literal(256)
        );
    }

    #[test]
    fn evaluate_literal() {
        let expr = AddressExpression::Literal(0x400000);
        assert_eq!(expr.evaluate(&|_| None).unwrap(), 0x400000);
    }

    #[test]
    fn evaluate_symbol() {
        let expr = AddressExpression::Symbol("main".into());
        let resolver = |name: &str| match name {
            "main" => Some(0x401000),
            _ => None,
        };
        assert_eq!(expr.evaluate(&resolver).unwrap(), 0x401000);
    }

    #[test]
    fn evaluate_symbol_not_found() {
        let expr = AddressExpression::Symbol("missing".into());
        assert!(expr.evaluate(&|_| None).is_err());
    }

    #[test]
    fn evaluate_binary_op() {
        let expr = AddressExpression::BinaryOp {
            op: BinaryOp::Add,
            left: Box::new(AddressExpression::Literal(0x400000)),
            right: Box::new(AddressExpression::Literal(0x100)),
        };
        assert_eq!(expr.evaluate(&|_| None).unwrap(), 0x400100);
    }

    #[test]
    fn evaluate_binary_sub() {
        let expr = AddressExpression::BinaryOp {
            op: BinaryOp::Sub,
            left: Box::new(AddressExpression::Literal(0x500)),
            right: Box::new(AddressExpression::Literal(0x100)),
        };
        assert_eq!(expr.evaluate(&|_| None).unwrap(), 0x400);
    }

    #[test]
    fn evaluate_binary_xor() {
        let expr = AddressExpression::BinaryOp {
            op: BinaryOp::Xor,
            left: Box::new(AddressExpression::Literal(0xFF)),
            right: Box::new(AddressExpression::Literal(0x0F)),
        };
        assert_eq!(expr.evaluate(&|_| None).unwrap(), 0xF0);
    }

    #[test]
    fn parse_error_display() {
        let e = ParseError::InvalidAddress("xyz".into());
        assert!(e.to_string().contains("xyz"));
    }
}
