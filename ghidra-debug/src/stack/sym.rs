//! Symbolic values for stack unwind analysis.
//!
//! Ported from Ghidra's `Sym` sealed interface hierarchy.
//!
//! During stack analysis, each value in the p-code executor state is
//! represented as a `Sym`. The variants model:
//! - `Opaque`: unknown/complex expressions.
//! - `Const`: a known constant with a given byte-size.
//! - `Register`: a reference to a register (optionally masked).
//! - `StackOffset`: the stack pointer plus a constant offset (SP + c).
//! - `StackDeref`: a dereference of a stack offset (*(SP + c)).
//!
//! Arithmetic rules:
//! - Opaque + anything => Opaque
//! - Const + Const => Const (add values)
//! - Const + Register(SP) => StackOffset
//! - StackOffset + Const => StackOffset (add offsets)
//! - *StackOffset => StackDeref
//! - *Register(SP) => StackDeref(offset=0)

use serde::{Deserialize, Serialize};
use std::fmt;

/// A symbolic value used during stack unwind analysis.
///
/// This is an enum rather than a trait object to keep things simple
/// and avoid dynamic dispatch overhead.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Sym {
    /// Opaque (unknown) value.
    Opaque(OpaqueSym),
    /// A constant value.
    Const(ConstSym),
    /// A register reference.
    Register(RegisterSym),
    /// Stack pointer + constant offset.
    StackOffset(StackOffsetSym),
    /// Dereference of a stack offset: *(SP + offset).
    StackDeref(StackDerefSym),
}

impl Sym {
    /// Create the opaque symbol.
    pub fn opaque() -> Self {
        Sym::Opaque(OpaqueSym)
    }

    /// Create a constant symbol.
    pub fn constant(value: i64) -> Self {
        Sym::Const(ConstSym { value, size: 8 })
    }

    /// Create a constant symbol with a given size.
    pub fn constant_sized(value: i64, size: u32) -> Self {
        Sym::Const(ConstSym { value, size })
    }

    /// Create a register symbol.
    pub fn register(name: impl Into<String>, size: u32) -> Self {
        Sym::Register(RegisterSym {
            register_name: name.into(),
            mask: u64::MAX,
            size,
        })
    }

    /// Create a stack offset symbol (SP + offset).
    pub fn stack_offset(offset: i64) -> Self {
        Sym::StackOffset(StackOffsetSym { offset })
    }

    /// Create a stack dereference symbol (*(SP + offset)).
    pub fn stack_deref(offset: i64, size: u32) -> Self {
        Sym::StackDeref(StackDerefSym {
            offset,
            mask: u64::MAX,
            size,
        })
    }

    /// Add two symbols.
    ///
    /// Rules:
    /// - Opaque + _ => Opaque
    /// - Const(a) + Const(b) => Const(a+b)
    /// - Const(c) + Register(SP) => StackOffset(c)
    /// - StackOffset(o) + Const(c) => StackOffset(o+c)
    /// - Otherwise => Opaque
    pub fn add(&self, sp_name: &str, rhs: &Sym) -> Sym {
        match (self, rhs) {
            (Sym::Opaque(_), _) | (_, Sym::Opaque(_)) => Sym::opaque(),
            (Sym::Const(a), Sym::Const(b)) => {
                Sym::Const(ConstSym {
                    value: a.value.wrapping_add(b.value),
                    size: a.size.max(b.size),
                })
            }
            (Sym::Const(c), Sym::Register(reg)) if reg.register_name == sp_name => {
                Sym::StackOffset(StackOffsetSym { offset: c.value })
            }
            (Sym::Register(reg), Sym::Const(c)) if reg.register_name == sp_name => {
                Sym::StackOffset(StackOffsetSym { offset: c.value })
            }
            (Sym::StackOffset(off), Sym::Const(c)) => {
                Sym::StackOffset(StackOffsetSym {
                    offset: off.offset.wrapping_add(c.value),
                })
            }
            (Sym::Const(c), Sym::StackOffset(off)) => {
                Sym::StackOffset(StackOffsetSym {
                    offset: c.value.wrapping_add(off.offset),
                })
            }
            (Sym::StackDeref(d), Sym::Const(c)) => {
                // Adding to a deref keeps it opaque (we don't know the base)
                let _ = (d, c);
                Sym::opaque()
            }
            _ => Sym::opaque(),
        }
    }

    /// Subtract another symbol from this one.
    pub fn sub(&self, sp_name: &str, rhs: &Sym) -> Sym {
        match rhs {
            Sym::Const(c) => {
                let negated = Sym::Const(ConstSym {
                    value: c.value.wrapping_neg(),
                    size: c.size,
                });
                self.add(sp_name, &negated)
            }
            _ => Sym::opaque(),
        }
    }

    /// Two's complement (negation).
    pub fn twos_comp(&self) -> Sym {
        match self {
            Sym::Const(c) => Sym::Const(ConstSym {
                value: c.value.wrapping_neg(),
                size: c.size,
            }),
            _ => Sym::opaque(),
        }
    }

    /// Bitwise AND.
    pub fn and(&self, _sp_name: &str, rhs: &Sym) -> Sym {
        match (self, rhs) {
            (Sym::Opaque(_), _) | (_, Sym::Opaque(_)) => Sym::opaque(),
            (Sym::Const(a), Sym::Const(b)) => Sym::Const(ConstSym {
                value: a.value & b.value,
                size: a.size.max(b.size),
            }),
            (Sym::Const(c), Sym::Register(reg)) => {
                Sym::Register(RegisterSym {
                    register_name: reg.register_name.clone(),
                    mask: reg.mask & c.value as u64,
                    size: reg.size,
                })
            }
            (Sym::Register(reg), Sym::Const(c)) => {
                Sym::Register(RegisterSym {
                    register_name: reg.register_name.clone(),
                    mask: reg.mask & c.value as u64,
                    size: reg.size,
                })
            }
            (Sym::Const(c), Sym::StackDeref(deref)) => {
                Sym::StackDeref(StackDerefSym {
                    offset: deref.offset,
                    mask: deref.mask & c.value as u64,
                    size: deref.size,
                })
            }
            (Sym::StackDeref(deref), Sym::Const(c)) => {
                Sym::StackDeref(StackDerefSym {
                    offset: deref.offset,
                    mask: deref.mask & c.value as u64,
                    size: deref.size,
                })
            }
            _ => Sym::opaque(),
        }
    }

    /// Dereference: treating this symbol as an address in the given space,
    /// produce the symbol that would result from reading through it.
    ///
    /// - `*StackOffset(c)` => `StackDeref(c)`
    /// - `*Register(SP)` => `StackDeref(0)`
    /// - Otherwise => Opaque
    pub fn deref(&self, sp_name: &str) -> Sym {
        match self {
            Sym::StackOffset(off) => Sym::StackDeref(StackDerefSym {
                offset: off.offset,
                mask: u64::MAX,
                size: 8,
            }),
            Sym::Register(reg) if reg.register_name == sp_name => {
                Sym::StackDeref(StackDerefSym {
                    offset: 0,
                    mask: u64::MAX,
                    size: 8,
                })
            }
            _ => Sym::opaque(),
        }
    }

    /// Whether this is an opaque symbol.
    pub fn is_opaque(&self) -> bool {
        matches!(self, Sym::Opaque(_))
    }

    /// Whether this is a constant.
    pub fn is_const(&self) -> bool {
        matches!(self, Sym::Const(_))
    }

    /// Whether this is a stack dereference.
    pub fn is_stack_deref(&self) -> bool {
        matches!(self, Sym::StackDeref(_))
    }

    /// Get the size in bytes if known.
    pub fn size(&self) -> Option<u32> {
        match self {
            Sym::Const(c) => Some(c.size),
            Sym::Register(r) => Some(r.size),
            Sym::StackDeref(d) => Some(d.size),
            _ => None,
        }
    }

    /// Try to extract a constant value.
    pub fn as_const_value(&self) -> Option<i64> {
        match self {
            Sym::Const(c) => Some(c.value),
            _ => None,
        }
    }
}

impl fmt::Display for Sym {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Sym::Opaque(_) => write!(f, "Opaque"),
            Sym::Const(c) => write!(f, "Const(0x{:x}, {}B)", c.value, c.size),
            Sym::Register(r) => write!(f, "Reg({})", r.register_name),
            Sym::StackOffset(o) => write!(f, "SP{:+}", o.offset),
            Sym::StackDeref(d) => write!(f, "*(SP{:+})", d.offset),
        }
    }
}

/// Opaque (unknown) symbolic value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OpaqueSym;

/// A constant symbolic value with a known byte-size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConstSym {
    /// The constant value.
    pub value: i64,
    /// Size in bytes.
    pub size: u32,
}

/// A register symbolic value with an optional mask.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegisterSym {
    /// The register name (e.g., "RAX", "x30").
    pub register_name: String,
    /// Bit mask applied to the register value.
    pub mask: u64,
    /// Size in bytes.
    pub size: u32,
}

impl RegisterSym {
    /// Apply an additional mask.
    pub fn with_applied_mask(&self, mask: u64) -> Self {
        Self {
            register_name: self.register_name.clone(),
            mask: self.mask & mask,
            size: self.size,
        }
    }
}

/// A stack offset symbol: SP + offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StackOffsetSym {
    /// The offset from the stack pointer (may be negative).
    pub offset: i64,
}

/// A stack dereference symbol: *(SP + offset).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StackDerefSym {
    /// The offset from the stack pointer.
    pub offset: i64,
    /// Bit mask applied after dereferencing.
    pub mask: u64,
    /// Size in bytes of the dereferenced value.
    pub size: u32,
}

impl StackDerefSym {
    /// Apply an additional mask.
    pub fn with_applied_mask(&self, mask: u64) -> Self {
        Self {
            offset: self.offset,
            mask: self.mask & mask,
            size: self.size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SP: &str = "SP";

    #[test]
    fn test_const_add_const() {
        let a = Sym::constant(10);
        let b = Sym::constant(20);
        let result = a.add(SP, &b);
        assert_eq!(result, Sym::Const(ConstSym { value: 30, size: 8 }));
    }

    #[test]
    fn test_const_add_sp_register() {
        let c = Sym::constant(0x10);
        let sp = Sym::register("SP", 8);
        let result = c.add(SP, &sp);
        assert_eq!(result, Sym::StackOffset(StackOffsetSym { offset: 0x10 }));
    }

    #[test]
    fn test_sp_register_add_const() {
        let sp = Sym::register("SP", 8);
        let c = Sym::constant(-8);
        let result = sp.add(SP, &c);
        assert_eq!(result, Sym::StackOffset(StackOffsetSym { offset: -8 }));
    }

    #[test]
    fn test_stack_offset_add_const() {
        let off = Sym::stack_offset(-0x20);
        let c = Sym::constant(8);
        let result = off.add(SP, &c);
        assert_eq!(result, Sym::StackOffset(StackOffsetSym { offset: -0x18 }));
    }

    #[test]
    fn test_opaque_absorbs() {
        let o = Sym::opaque();
        let c = Sym::constant(5);
        assert!(o.add(SP, &c).is_opaque());
        assert!(c.add(SP, &o).is_opaque());
    }

    #[test]
    fn test_sub_const() {
        let a = Sym::constant(50);
        let b = Sym::constant(20);
        let result = a.sub(SP, &b);
        assert_eq!(result.as_const_value(), Some(30));
    }

    #[test]
    fn test_twos_comp() {
        let c = Sym::constant(42);
        let result = c.twos_comp();
        assert_eq!(result.as_const_value(), Some(-42));
    }

    #[test]
    fn test_and_consts() {
        let a = Sym::constant(0xFF);
        let b = Sym::constant(0x0F);
        let result = a.and(SP, &b);
        assert_eq!(result.as_const_value(), Some(0x0F));
    }

    #[test]
    fn test_and_const_register() {
        let c = Sym::constant_sized(0xFFFF, 8);
        let r = Sym::register("R30", 8);
        let result = c.and(SP, &r);
        match result {
            Sym::Register(reg) => {
                assert_eq!(reg.mask, 0xFFFF);
                assert_eq!(reg.register_name, "R30");
            }
            _ => panic!("expected register"),
        }
    }

    #[test]
    fn test_deref_stack_offset() {
        let off = Sym::stack_offset(-8);
        let result = off.deref(SP);
        assert_eq!(
            result,
            Sym::StackDeref(StackDerefSym {
                offset: -8,
                mask: u64::MAX,
                size: 8,
            })
        );
    }

    #[test]
    fn test_deref_sp_register() {
        let sp = Sym::register("SP", 8);
        let result = sp.deref(SP);
        assert_eq!(
            result,
            Sym::StackDeref(StackDerefSym {
                offset: 0,
                mask: u64::MAX,
                size: 8,
            })
        );
    }

    #[test]
    fn test_deref_other_register_is_opaque() {
        let r = Sym::register("RAX", 8);
        assert!(r.deref(SP).is_opaque());
    }

    #[test]
    fn test_stack_deref_with_mask() {
        let d = Sym::stack_deref(-0x10, 8);
        let mask = Sym::constant_sized(0xFFFF, 8);
        let result = d.and(SP, &mask);
        match result {
            Sym::StackDeref(sd) => {
                assert_eq!(sd.offset, -0x10);
                assert_eq!(sd.mask, 0xFFFF);
            }
            _ => panic!("expected stack deref"),
        }
    }

    #[test]
    fn test_display() {
        assert_eq!(Sym::opaque().to_string(), "Opaque");
        assert_eq!(Sym::constant(42).to_string(), "Const(0x2a, 8B)");
        assert_eq!(Sym::stack_offset(-8).to_string(), "SP-8");
        assert_eq!(Sym::stack_deref(-16, 8).to_string(), "*(SP-16)");
    }

    #[test]
    fn test_size() {
        assert_eq!(Sym::constant_sized(0, 4).size(), Some(4));
        assert_eq!(Sym::register("RAX", 8).size(), Some(8));
        assert_eq!(Sym::opaque().size(), None);
    }

    #[test]
    fn test_serde() {
        let s = Sym::StackOffset(StackOffsetSym { offset: -32 });
        let json = serde_json::to_string(&s).unwrap();
        let back: Sym = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}
