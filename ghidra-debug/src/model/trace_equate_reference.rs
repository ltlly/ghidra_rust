//! TraceEquateReference - references to equate constants in a trace.
//!
//! Ported from Ghidra's `ghidra.trace.model.symbol.TraceEquateReference`.

use serde::{Deserialize, Serialize};

use super::Lifespan;

/// A reference to an equate (named constant) within a trace.
///
/// Equate references link an instruction operand to an equate name/value.
/// They are ephemeral within a given snap and address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEquateReference {
    /// Unique key for this reference.
    pub key: i64,
    /// The equate key this reference refers to.
    pub equate_key: i64,
    /// The lifespan (snap range) during which this reference is valid.
    pub lifespan: Lifespan,
    /// The thread key (for register space references), or None for memory.
    pub thread_key: Option<i64>,
    /// The address where this reference is attached.
    pub address: u64,
    /// The address space name.
    pub space: String,
    /// The operand index at the "from" address (-1 for mnemonic).
    pub operand_index: i32,
    /// The varnode data for the reference (serialized bytes), if applicable.
    pub varnode_data: Option<Vec<u8>>,
}

impl TraceEquateReference {
    /// Create a new equate reference.
    pub fn new(
        key: i64,
        equate_key: i64,
        lifespan: Lifespan,
        address: u64,
        space: impl Into<String>,
        operand_index: i32,
    ) -> Self {
        Self {
            key,
            equate_key,
            lifespan,
            thread_key: None,
            address,
            space: space.into(),
            operand_index,
            varnode_data: None,
        }
    }

    /// Create a register-space equate reference.
    pub fn register(
        key: i64,
        equate_key: i64,
        lifespan: Lifespan,
        thread_key: i64,
        address: u64,
        operand_index: i32,
    ) -> Self {
        Self {
            key,
            equate_key,
            lifespan,
            thread_key: Some(thread_key),
            address,
            space: "register".into(),
            operand_index,
            varnode_data: None,
        }
    }

    /// Get the start snap of this reference's lifespan.
    pub fn start_snap(&self) -> i64 {
        self.lifespan.lmin()
    }

    /// Check if this reference is for a register space.
    pub fn is_register(&self) -> bool {
        self.thread_key.is_some()
    }

    /// Check if this reference is for the mnemonic (not an operand).
    pub fn is_mnemonic(&self) -> bool {
        self.operand_index < 0
    }

    /// Check if this reference is for a specific operand.
    pub fn is_operand(&self) -> bool {
        self.operand_index >= 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equate_reference_creation() {
        let r#ref = TraceEquateReference::new(1, 10, Lifespan::span(0, 100), 0x400000, "ram", 0);
        assert_eq!(r#ref.equate_key, 10);
        assert_eq!(r#ref.address, 0x400000);
        assert!(r#ref.is_operand());
        assert!(!r#ref.is_mnemonic());
    }

    #[test]
    fn test_register_reference() {
        let r#ref = TraceEquateReference::register(2, 10, Lifespan::span(0, 50), 1, 0x10, -1);
        assert!(r#ref.is_register());
        assert!(r#ref.is_mnemonic());
        assert_eq!(r#ref.thread_key, Some(1));
    }

    #[test]
    fn test_lifespan_access() {
        let r#ref = TraceEquateReference::new(1, 10, Lifespan::span(5, 100), 0x1000, "ram", 0);
        assert_eq!(r#ref.start_snap(), 5);
        assert!(r#ref.lifespan.contains(50));
        assert!(!r#ref.lifespan.contains(0));
    }

    #[test]
    fn test_serde() {
        let r#ref = TraceEquateReference::new(1, 10, Lifespan::span(0, 100), 0x400000, "ram", 2);
        let json = serde_json::to_string(&r#ref).unwrap();
        let back: TraceEquateReference = serde_json::from_str(&json).unwrap();
        assert_eq!(back.key, 1);
        assert_eq!(back.address, 0x400000);
    }
}
