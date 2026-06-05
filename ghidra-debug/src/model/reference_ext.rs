//! Extended reference types for trace symbols.
//!
//! Ported from Ghidra's `ghidra.trace.model.symbol` reference variants:
//! - TraceStackReference
//! - TraceOffsetReference
//! - TraceShiftedReference
//!
//! These extend the base TraceReference with additional semantics.

use serde::{Deserialize, Serialize};

use super::symbol::{TraceReference, TraceReferenceKind};
use super::Lifespan;

/// A stack reference in a trace.
///
/// A stack reference points to a stack-relative address. The `stack_offset`
/// is a signed value relative to the frame pointer (positive for parameters,
/// negative for locals).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStackReference {
    /// The base reference data.
    pub base: TraceReference,
    /// The stack offset (signed, relative to frame pointer).
    pub stack_offset: i32,
}

impl TraceStackReference {
    /// Create a new stack reference.
    pub fn new(
        key: i64,
        from_address: u64,
        stack_offset: i32,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            base: TraceReference {
                key,
                from_address,
                to_address: (stack_offset as i64 as u64),
                kind: TraceReferenceKind::Stack,
                lifespan,
                is_primary: false,
            },
            stack_offset,
        }
    }

    /// Whether this is a stack reference.
    pub fn is_stack_reference(&self) -> bool {
        true
    }

    /// Get the stack offset.
    pub fn get_stack_offset(&self) -> i32 {
        self.stack_offset
    }

    /// Get the from address.
    pub fn from_address(&self) -> u64 {
        self.base.from_address
    }

    /// Get the lifespan.
    pub fn lifespan(&self) -> Lifespan {
        self.base.lifespan
    }
}

/// An offset reference in a trace.
///
/// An offset reference records that one address references another via
/// an offset calculation (e.g., `mov rax, [rbx + 0x10]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceOffsetReference {
    /// The base reference data.
    pub base: TraceReference,
}

impl TraceOffsetReference {
    /// Create a new offset reference.
    pub fn new(key: i64, from_address: u64, to_address: u64, lifespan: Lifespan) -> Self {
        Self {
            base: TraceReference {
                key,
                from_address,
                to_address,
                kind: TraceReferenceKind::Offset,
                lifespan,
                is_primary: false,
            },
        }
    }

    /// Whether this is an offset reference.
    pub fn is_offset_reference(&self) -> bool {
        true
    }

    /// Get the from address.
    pub fn from_address(&self) -> u64 {
        self.base.from_address
    }

    /// Get the to address.
    pub fn to_address(&self) -> u64 {
        self.base.to_address
    }

    /// Get the lifespan.
    pub fn lifespan(&self) -> Lifespan {
        self.base.lifespan
    }
}

/// A shifted reference in a trace.
///
/// A shifted reference is like an offset reference but with an additional
/// bit-shift applied to the address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceShiftedReference {
    /// The base reference data.
    pub base: TraceReference,
    /// The shift amount (in bits).
    pub shift: i32,
}

impl TraceShiftedReference {
    /// Create a new shifted reference.
    pub fn new(
        key: i64,
        from_address: u64,
        to_address: u64,
        shift: i32,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            base: TraceReference {
                key,
                from_address,
                to_address,
                kind: TraceReferenceKind::Shifted,
                lifespan,
                is_primary: false,
            },
            shift,
        }
    }

    /// Whether this is a shifted reference.
    pub fn is_shifted_reference(&self) -> bool {
        true
    }

    /// Get the shift amount.
    pub fn get_shift(&self) -> i32 {
        self.shift
    }

    /// Get the from address.
    pub fn from_address(&self) -> u64 {
        self.base.from_address
    }

    /// Get the to address.
    pub fn to_address(&self) -> u64 {
        self.base.to_address
    }

    /// Get the lifespan.
    pub fn lifespan(&self) -> Lifespan {
        self.base.lifespan
    }
}

/// A unified enum over all trace reference types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TraceReferenceVariant {
    /// A plain memory reference.
    Memory(TraceReference),
    /// A stack reference.
    Stack(TraceStackReference),
    /// An offset reference.
    Offset(TraceOffsetReference),
    /// A shifted reference.
    Shifted(TraceShiftedReference),
}

impl TraceReferenceVariant {
    /// Get the from address regardless of variant.
    pub fn from_address(&self) -> u64 {
        match self {
            Self::Memory(r) => r.from_address,
            Self::Stack(r) => r.from_address(),
            Self::Offset(r) => r.from_address(),
            Self::Shifted(r) => r.from_address(),
        }
    }

    /// Get the to address regardless of variant.
    pub fn to_address(&self) -> u64 {
        match self {
            Self::Memory(r) => r.to_address,
            Self::Stack(r) => r.base.to_address,
            Self::Offset(r) => r.to_address(),
            Self::Shifted(r) => r.to_address(),
        }
    }

    /// Get the lifespan regardless of variant.
    pub fn lifespan(&self) -> Lifespan {
        match self {
            Self::Memory(r) => r.lifespan,
            Self::Stack(r) => r.lifespan(),
            Self::Offset(r) => r.lifespan(),
            Self::Shifted(r) => r.lifespan(),
        }
    }

    /// Whether this is a memory reference.
    pub fn is_memory_reference(&self) -> bool {
        matches!(self, Self::Memory(_))
    }

    /// Whether this is a stack reference.
    pub fn is_stack_reference(&self) -> bool {
        matches!(self, Self::Stack(_))
    }

    /// Whether this is an offset reference.
    pub fn is_offset_reference(&self) -> bool {
        matches!(self, Self::Offset(_))
    }

    /// Whether this is a shifted reference.
    pub fn is_shifted_reference(&self) -> bool {
        matches!(self, Self::Shifted(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_reference() {
        let sr = TraceStackReference::new(1, 0x400000, -8, Lifespan::ALL);
        assert!(sr.is_stack_reference());
        assert_eq!(sr.get_stack_offset(), -8);
        assert_eq!(sr.from_address(), 0x400000);
    }

    #[test]
    fn test_stack_reference_positive() {
        let sr = TraceStackReference::new(1, 0x400000, 16, Lifespan::ALL);
        assert_eq!(sr.get_stack_offset(), 16);
    }

    #[test]
    fn test_offset_reference() {
        let or = TraceOffsetReference::new(1, 0x400000, 0x401000, Lifespan::ALL);
        assert!(or.is_offset_reference());
        assert_eq!(or.from_address(), 0x400000);
        assert_eq!(or.to_address(), 0x401000);
    }

    #[test]
    fn test_shifted_reference() {
        let sr = TraceShiftedReference::new(1, 0x400000, 0x401000, 2, Lifespan::ALL);
        assert!(sr.is_shifted_reference());
        assert_eq!(sr.get_shift(), 2);
    }

    #[test]
    fn test_variant_memory() {
        let v = TraceReferenceVariant::Memory(TraceReference::memory(
            1,
            0x100,
            0x200,
            Lifespan::ALL,
        ));
        assert!(v.is_memory_reference());
        assert!(!v.is_stack_reference());
        assert_eq!(v.from_address(), 0x100);
        assert_eq!(v.to_address(), 0x200);
    }

    #[test]
    fn test_variant_stack() {
        let v = TraceReferenceVariant::Stack(TraceStackReference::new(
            1, 0x100, -16, Lifespan::ALL,
        ));
        assert!(v.is_stack_reference());
    }

    #[test]
    fn test_variant_offset() {
        let v = TraceReferenceVariant::Offset(TraceOffsetReference::new(
            1, 0x100, 0x200, Lifespan::ALL,
        ));
        assert!(v.is_offset_reference());
    }

    #[test]
    fn test_variant_shifted() {
        let v = TraceReferenceVariant::Shifted(TraceShiftedReference::new(
            1, 0x100, 0x200, 4, Lifespan::ALL,
        ));
        assert!(v.is_shifted_reference());
    }

    #[test]
    fn test_reference_variant_serde() {
        let v = TraceReferenceVariant::Stack(TraceStackReference::new(
            1, 0x400000, -8, Lifespan::ALL,
        ));
        let json = serde_json::to_string(&v).unwrap();
        let back: TraceReferenceVariant = serde_json::from_str(&json).unwrap();
        assert!(back.is_stack_reference());
    }
}
