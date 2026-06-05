//! Symbolic p-code executor state for stack analysis.
//!
//! Ported from Ghidra's `SymPcodeExecutorState`. Maintains symbolic values
//! in stack, register, and unique address spaces. When a read encounters an
//! unknown location, a fresh symbolic value is generated.

use std::collections::BTreeMap;
use std::fmt;

use super::sym::Sym;
use super::sym_arithmetic::SymArithmetic;
use super::unwind_warning::{UnwindWarning, UnwindWarningKind};

/// A single space in the symbolic state, mapping offsets to symbolic values.
#[derive(Debug, Clone, Default)]
pub struct SymStateSpace {
    entries: BTreeMap<i64, Sym>,
}

impl SymStateSpace {
    /// Create an empty space.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a symbolic value at the given offset.
    pub fn set(&mut self, offset: i64, sym: Sym) {
        self.entries.insert(offset, sym);
    }

    /// Get the symbolic value at the given offset, if present.
    pub fn get(&self, offset: i64) -> Option<&Sym> {
        self.entries.get(&offset)
    }

    /// Get all entries.
    pub fn entries(&self) -> &BTreeMap<i64, Sym> {
        &self.entries
    }

    /// Find all entries whose value is a `StackDeref`, mapping
    /// (deref_offset -> register_name).
    pub fn find_stack_derefs(&self) -> Vec<(i64, i64, u32)> {
        self.entries
            .iter()
            .filter_map(|(addr, sym)| {
                if let Sym::StackDeref(d) = sym {
                    Some((*addr, d.offset, d.size))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Find all entries that are register symbols, returning
    /// (register_name, address).
    pub fn find_register_syms(&self) -> Vec<(String, i64)> {
        self.entries
            .iter()
            .filter_map(|(addr, sym)| {
                if let Sym::Register(r) = sym {
                    Some((r.register_name.clone(), *addr))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Fork this space (deep copy).
    pub fn fork(&self) -> Self {
        Self {
            entries: self.entries.clone(),
        }
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the space is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl fmt::Display for SymStateSpace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (offset, sym) in &self.entries {
            writeln!(f, "  [0x{:x}] = {}", offset, sym)?;
        }
        Ok(())
    }
}

/// The symbolic p-code executor state used during stack unwind analysis.
///
/// Maintains three address spaces: stack, register, and unique.
/// Each space maps addresses to `Sym` values.
#[derive(Debug, Clone)]
pub struct SymState {
    /// Symbolic arithmetic engine.
    pub arithmetic: SymArithmetic,
    /// The stack address space.
    pub stack: SymStateSpace,
    /// The register address space.
    pub registers: SymStateSpace,
    /// The unique (temporary) address space.
    pub unique: SymStateSpace,
    /// Warnings accumulated during analysis.
    pub warnings: Vec<UnwindWarning>,
}

impl SymState {
    /// Create a new symbolic state.
    pub fn new(arithmetic: SymArithmetic) -> Self {
        Self {
            arithmetic,
            stack: SymStateSpace::new(),
            registers: SymStateSpace::new(),
            unique: SymStateSpace::new(),
            warnings: Vec::new(),
        }
    }

    /// Get a mutable reference to the appropriate space for a given space name.
    fn space_mut(&mut self, space: &str) -> &mut SymStateSpace {
        match space {
            "stack" | "Stack" => &mut self.stack,
            "register" | "Register" => &mut self.registers,
            "unique" | "Unique" | "UniqueSpace" => &mut self.unique,
            // Treat unknown spaces (physical memory, etc.) as unique
            _ => &mut self.unique,
        }
    }

    fn space_ref(&self, space: &str) -> &SymStateSpace {
        match space {
            "stack" | "Stack" => &self.stack,
            "register" | "Register" => &self.registers,
            "unique" | "Unique" | "UniqueSpace" => &self.unique,
            _ => &self.unique,
        }
    }

    /// Read a symbolic value from the given space and offset.
    ///
    /// If the location is not populated, a fresh symbol is generated:
    /// - Stack space: `Sym::stack_offset(offset)` (assumes SP-relative).
    /// - Register space: `Sym::register(name, size)` where name is
    ///   resolved from the offset.
    /// - Other spaces: `Sym::opaque()`.
    pub fn read_sym(&self, space: &str, offset: i64, size: u32) -> Sym {
        if let Some(sym) = self.space_ref(space).get(offset) {
            return sym.clone();
        }
        // Generate a fresh symbol for unknown locations
        match space {
            "register" | "Register" => {
                // For register space, create a register symbol
                // We use the offset as a synthetic register identifier
                Sym::Register(super::sym::RegisterSym {
                    register_name: format!("REG_0x{:x}", offset),
                    mask: u64::MAX,
                    size,
                })
            }
            "stack" | "Stack" => Sym::stack_offset(offset),
            _ => Sym::opaque(),
        }
    }

    /// Write a symbolic value to the given space and offset.
    pub fn write_sym(&mut self, space: &str, offset: i64, sym: Sym) {
        self.space_mut(space).set(offset, sym);
    }

    /// Read a value from the state for p-code execution.
    ///
    /// The offset is a symbolic `Sym`. If it resolves to a concrete address,
    /// we look it up in the appropriate space. Otherwise, we return opaque.
    pub fn read(&self, space: &str, offset: &Sym, size: u32) -> Sym {
        if let Some(addr) = offset.as_const_value() {
            self.read_sym(space, addr, size)
        } else if let Sym::StackOffset(off) = offset {
            // Stack offsets become stack dereferences
            self.read_sym(space, off.offset, size)
        } else {
            Sym::opaque()
        }
    }

    /// Write a value to the state.
    pub fn write(&mut self, space: &str, offset: &Sym, value: Sym) {
        if let Some(addr) = offset.as_const_value() {
            self.write_sym(space, addr, value);
        }
    }

    /// Fork the registers portion of the state, clearing the stack.
    ///
    /// Used to analyze the path from PC to return with register knowledge
    /// from entry-to-PC, but a fresh stack view.
    pub fn fork_regs(&self) -> Self {
        Self {
            arithmetic: self.arithmetic.clone(),
            stack: SymStateSpace::new(),
            registers: self.registers.fork(),
            unique: SymStateSpace::new(),
            warnings: Vec::new(),
        }
    }

    /// Compute the stack depth from the symbolic stack pointer value.
    ///
    /// Looks at the SP register; if it's a `StackOffset(c)`, returns `-c`
    /// (positive depth = stack has grown).
    pub fn compute_stack_depth(&self) -> Option<i64> {
        // Find the SP register value
        let sp_name = &self.arithmetic.sp_name;
        for (name, _addr) in self.registers.find_register_syms() {
            if name == *sp_name {
                // Look for the most recent SP value
                if let Some(Sym::StackOffset(off)) = self.registers.get(0) {
                    return Some(-off.offset);
                }
            }
        }
        // Also check if SP was set directly via a register symbol
        for (_addr, sym) in self.registers.entries() {
            if let Sym::StackOffset(off) = sym {
                return Some(-off.offset);
            }
        }
        None
    }

    /// Search the stack for register symbols and build a map of
    /// `(stack_address, register_name)`.
    ///
    /// This detects registers that have been saved to the stack.
    pub fn compute_saved_registers_from_stack(&self) -> Vec<(i64, String)> {
        self.stack
            .find_register_syms()
            .into_iter()
            .map(|(name, addr)| (addr, name))
            .collect()
    }

    /// Search the registers for stack dereference symbols.
    ///
    /// These indicate registers that were restored from the stack.
    pub fn compute_restored_from_registers(&self) -> Vec<(i64, i64, u32)> {
        self.registers.find_stack_derefs()
    }

    /// Compute the location of the return address.
    ///
    /// Examines the PC register after execution to a return instruction.
    /// If the PC value is a `StackDeref(offset)`, the return address is
    /// at `SP + offset`. If it's a `Register`, it's in that register.
    pub fn compute_return_address_location(&self) -> Option<ReturnAddressLocation> {
        // Check for stack dereference in PC register
        for (_addr, sym) in self.registers.entries() {
            if let Sym::StackDeref(deref) = sym {
                return Some(ReturnAddressLocation::Stack {
                    offset: deref.offset,
                    size: deref.size,
                });
            }
        }
        // Check for a register symbol in PC
        for (_addr, sym) in self.registers.entries() {
            if let Sym::Register(reg) = sym {
                return Some(ReturnAddressLocation::Register {
                    name: reg.register_name.clone(),
                    mask: reg.mask,
                    size: reg.size,
                });
            }
        }
        None
    }

    /// Add a warning.
    pub fn add_warning(&mut self, warning: UnwindWarning) {
        self.warnings.push(warning);
    }

    /// Register that a non-return path was encountered.
    pub fn warn_no_return_path(&mut self, address: u64) {
        self.warnings.push(UnwindWarning {
            kind: UnwindWarningKind::NoReturnPath,
            message: format!("No return path found from address 0x{:x}", address),
        });
    }

    /// Register that a return path is opaque/unanalyzable.
    pub fn warn_opaque_return_path(&mut self, address: u64, detail: &str) {
        self.warnings.push(UnwindWarning {
            kind: UnwindWarningKind::OpaqueReturnPath,
            message: format!(
                "Opaque return path at 0x{:x}: {}",
                address, detail
            ),
        });
    }
}

impl fmt::Display for SymState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "SymState {{")?;
        writeln!(f, "  stack:")?;
        write!(f, "{}", self.stack)?;
        writeln!(f, "  registers:")?;
        write!(f, "{}", self.registers)?;
        writeln!(f, "  unique:")?;
        write!(f, "{}", self.unique)?;
        writeln!(f, "}}")?;
        Ok(())
    }
}

/// Where the return address is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReturnAddressLocation {
    /// The return address is on the stack at (SP + offset).
    Stack {
        /// Offset from the stack pointer.
        offset: i64,
        /// Size in bytes.
        size: u32,
    },
    /// The return address is in a register.
    Register {
        /// Register name.
        name: String,
        /// Bit mask.
        mask: u64,
        /// Size in bytes.
        size: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stack::sym::Sym;
    use crate::stack::sym_arithmetic::SymArithmetic;

    fn make_state() -> SymState {
        SymState::new(SymArithmetic::new("SP", false))
    }

    #[test]
    fn test_read_write_sym() {
        let mut state = make_state();
        state.write_sym("stack", 0x100, Sym::constant(42));
        let val = state.read_sym("stack", 0x100, 8);
        assert_eq!(val.as_const_value(), Some(42));
    }

    #[test]
    fn test_read_unknown_stack_generates_offset() {
        let state = make_state();
        let val = state.read_sym("stack", -0x20, 8);
        assert_eq!(val, Sym::stack_offset(-0x20));
    }

    #[test]
    fn test_read_unknown_register_generates_register_sym() {
        let state = make_state();
        let val = state.read_sym("register", 0x10, 8);
        match val {
            Sym::Register(r) => {
                assert_eq!(r.register_name, "REG_0x10");
                assert_eq!(r.size, 8);
            }
            _ => panic!("expected register symbol"),
        }
    }

    #[test]
    fn test_fork_regs_preserves_registers_clears_stack() {
        let mut state = make_state();
        state.write_sym("stack", -8, Sym::constant(100));
        state.write_sym("register", 0, Sym::constant(42));

        let forked = state.fork_regs();
        // Stack is cleared
        assert!(forked.stack.is_empty());
        // Registers are preserved
        let reg = forked.read_sym("register", 0, 8);
        assert_eq!(reg.as_const_value(), Some(42));
    }

    #[test]
    fn test_compute_saved_registers_from_stack() {
        let mut state = make_state();
        state.write_sym("stack", -8, Sym::register("R30", 8));
        state.write_sym("stack", -16, Sym::register("R29", 8));
        state.write_sym("stack", -24, Sym::constant(42));

        let saved = state.compute_saved_registers_from_stack();
        assert_eq!(saved.len(), 2);
        assert!(saved.iter().any(|(_, name)| name == "R30"));
        assert!(saved.iter().any(|(_, name)| name == "R29"));
    }

    #[test]
    fn test_compute_return_address_stack_location() {
        let mut state = make_state();
        state.write_sym("register", 0, Sym::stack_deref(-8, 8));

        let loc = state.compute_return_address_location();
        assert_eq!(
            loc,
            Some(ReturnAddressLocation::Stack {
                offset: -8,
                size: 8
            })
        );
    }

    #[test]
    fn test_compute_return_address_register_location() {
        let mut state = make_state();
        state.write_sym("register", 0, Sym::register("R30", 8));

        let loc = state.compute_return_address_location();
        assert_eq!(
            loc,
            Some(ReturnAddressLocation::Register {
                name: "R30".into(),
                mask: u64::MAX,
                size: 8,
            })
        );
    }

    #[test]
    fn test_sym_state_space_find_register_syms() {
        let mut space = SymStateSpace::new();
        space.set(0, Sym::register("RAX", 8));
        space.set(8, Sym::constant(42));
        space.set(16, Sym::register("RBX", 8));

        let found = space.find_register_syms();
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn test_sym_state_space_find_stack_derefs() {
        let mut space = SymStateSpace::new();
        space.set(0, Sym::stack_deref(-8, 8));
        space.set(8, Sym::constant(42));

        let found = space.find_stack_derefs();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1, -8); // deref offset
    }

    #[test]
    fn test_display() {
        let mut state = make_state();
        state.write_sym("stack", -8, Sym::constant(42));
        let display = format!("{}", state);
        assert!(display.contains("stack:"));
        assert!(display.contains("registers:"));
    }
}
