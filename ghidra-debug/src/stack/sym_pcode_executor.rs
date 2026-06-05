//! SymPcodeExecutor - symbolic p-code executor for stack unwind analysis.
//!
//! Ported from Ghidra's `SymPcodeExecutor` from `ghidra.app.plugin.core.debug.stack`.
//!
//! This executor interprets p-code instructions using symbolic values (`Sym`)
//! to track how values flow through registers and the stack. It is used
//! during stack unwinding to determine:
//! - Which registers have been saved to the stack and where
//! - The return address location (register or stack offset)
//! - The stack depth and adjustment at the program counter
//! - How to map variables to their storage locations

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::sym::Sym;
use super::sym_arithmetic::SymArithmetic;
use super::sym_state::SymState;

/// A symbolic p-code executor that interprets instructions symbolically.
///
/// Ported from Ghidra's `SymPcodeExecutor`. Wraps a `SymState` and
/// `SymArithmetic` to provide a complete symbolic execution environment.
#[derive(Debug)]
pub struct SymPcodeExecutor {
    /// The symbolic state (register bank, memory spaces).
    pub state: SymState,
    /// Whether to track memory reads for later analysis.
    pub track_reads: bool,
    /// Accumulated p-code operations executed.
    pub ops_executed: u64,
}

impl SymPcodeExecutor {
    /// Create a new symbolic p-code executor with the given arithmetic engine.
    pub fn new(sp_name: impl Into<String>, big_endian: bool) -> Self {
        let arithmetic = SymArithmetic::new(sp_name, big_endian);
        Self {
            state: SymState::new(arithmetic),
            track_reads: true,
            ops_executed: 0,
        }
    }

    /// Create an executor pre-populated with the given state.
    pub fn with_state(state: SymState) -> Self {
        Self {
            state,
            track_reads: true,
            ops_executed: 0,
        }
    }

    /// Execute a single symbolic p-code operation.
    ///
    /// Returns the symbolic result of the operation.
    pub fn execute_op(&mut self, op: &PcodeOpSymbolic) -> Sym {
        self.ops_executed += 1;
        let arith = &self.state.arithmetic;
        let sp_name = &arith.sp_name;
        match op {
            PcodeOpSymbolic::Copy { input, output } => {
                let val = self.read_varnode(input);
                self.write_varnode(output, val.clone());
                val
            }
            PcodeOpSymbolic::IntAdd { a, b, output } => {
                let va = self.read_varnode(a);
                let vb = self.read_varnode(b);
                let result = va.add(sp_name, &vb);
                self.write_varnode(output, result.clone());
                result
            }
            PcodeOpSymbolic::IntSub { a, b, output } => {
                let va = self.read_varnode(a);
                let vb = self.read_varnode(b);
                let result = va.sub(sp_name, &vb);
                self.write_varnode(output, result.clone());
                result
            }
            PcodeOpSymbolic::Store { space, addr, value } => {
                let addr_sym = self.read_varnode(addr);
                let val_sym = self.read_varnode(value);
                self.state.write(&space_name(*space), &addr_sym, val_sym.clone());
                val_sym
            }
            PcodeOpSymbolic::Load { space, addr, output } => {
                let addr_sym = self.read_varnode(addr);
                let size = 8u32; // default pointer size
                let val = self.state.read(&space_name(*space), &addr_sym, size);
                self.write_varnode(output, val.clone());
                val
            }
            PcodeOpSymbolic::IntAnd { a, b, output } => {
                let va = self.read_varnode(a);
                let vb = self.read_varnode(b);
                let result = va.and(sp_name, &vb);
                self.write_varnode(output, result.clone());
                result
            }
            PcodeOpSymbolic::Int2Comp { input, output } => {
                let val = self.read_varnode(input);
                let result = val.twos_comp();
                self.write_varnode(output, result.clone());
                result
            }
            PcodeOpSymbolic::IntNot { input, output } => {
                // Bitwise NOT is not directly tracked symbolically;
                // treat as opaque unless constant
                let val = self.read_varnode(input);
                let result = match &val {
                    Sym::Const(c) => Sym::constant(!c.value),
                    _ => Sym::opaque(),
                };
                self.write_varnode(output, result.clone());
                result
            }
            PcodeOpSymbolic::Subpiece { input, output, .. } => {
                // Subpiece preserves the symbolic identity for stack analysis
                let val = self.read_varnode(input);
                self.write_varnode(output, val.clone());
                val
            }
            // IntOr, IntXor, IntLeft, IntRight, IntSRight all produce opaque
            _ => Sym::opaque(),
        }
    }

    /// Read a symbolic value from a varnode identifier.
    fn read_varnode(&self, vn: &VarnodeId) -> Sym {
        match vn {
            VarnodeId::Register(name) => {
                // Try to find in register space by searching entries
                for (_addr, sym) in self.state.registers.entries() {
                    if let Sym::Register(reg) = sym {
                        if reg.register_name == *name {
                            return sym.clone();
                        }
                    }
                }
                // Generate fresh register symbol
                Sym::register(name, 8)
            }
            VarnodeId::StackOffset(offset) => {
                self.state.read_sym("stack", *offset, 8)
            }
            VarnodeId::Constant(val) => Sym::constant(*val as i64),
            VarnodeId::Unique(addr) => {
                self.state.read_sym("unique", *addr as i64, 8)
            }
        }
    }

    /// Write a symbolic value to a varnode identifier.
    fn write_varnode(&mut self, vn: &VarnodeId, sym: Sym) {
        match vn {
            VarnodeId::Register(name) => {
                // Store with a hash-based offset for the register name
                let addr = register_name_to_addr(name);
                self.state.write_sym("register", addr, sym);
            }
            VarnodeId::StackOffset(offset) => {
                self.state.write_sym("stack", *offset, sym);
            }
            VarnodeId::Constant(_) => {
                // Cannot write to a constant; ignore
            }
            VarnodeId::Unique(addr) => {
                self.state.write_sym("unique", *addr as i64, sym);
            }
        }
    }

    /// Get the current stack depth (symbolic value in SP register).
    pub fn compute_stack_depth(&self) -> Option<i64> {
        self.state.compute_stack_depth()
    }

    /// Search the stack for register symbols and build a map from
    /// stack offsets to the registers they hold.
    pub fn compute_map_using_stack(&self) -> BTreeMap<i64, String> {
        self.state
            .compute_saved_registers_from_stack()
            .into_iter()
            .collect()
    }

    /// Search registers for stack dereference symbols to find which
    /// registers hold stack values (for register restoration).
    pub fn compute_map_using_registers(&self) -> BTreeMap<String, i64> {
        self.state
            .compute_restored_from_registers()
            .into_iter()
            .map(|(offset, _deref_offset, _size)| {
                (format!("REG_0x{:x}", offset), offset)
            })
            .collect()
    }

    /// Fork the register state while keeping stack state.
    ///
    /// Used to reset stack state between entry-to-PC and PC-to-return analyses.
    pub fn fork_regs(&self) -> SymState {
        self.state.fork_regs()
    }

    /// Get the number of symbolic operations executed.
    pub fn ops_count(&self) -> u64 {
        self.ops_executed
    }
}

impl Default for SymPcodeExecutor {
    fn default() -> Self {
        Self::new("RSP", false)
    }
}

/// Convert a numeric space ID to a space name string.
fn space_name(id: u16) -> String {
    match id {
        0 => "register".to_string(),
        1 => "stack".to_string(),
        256 => "unique".to_string(),
        _ => format!("space_{}", id),
    }
}

/// Convert a register name to a deterministic address in register space.
pub fn register_name_to_addr(name: &str) -> i64 {
    // Simple hash for register name -> offset mapping
    let mut h: i64 = 0;
    for b in name.bytes() {
        h = h.wrapping_mul(31).wrapping_add(b as i64);
    }
    h.abs() % 0x10000
}

/// A symbolic representation of a p-code operation.
///
/// These are simplified p-code ops that capture the operations
/// relevant to stack unwinding analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PcodeOpSymbolic {
    /// COPY: input -> output
    Copy {
        /// Source varnode.
        input: VarnodeId,
        /// Destination varnode.
        output: VarnodeId,
    },
    /// INT_ADD: a + b -> output
    IntAdd {
        /// First operand.
        a: VarnodeId,
        /// Second operand.
        b: VarnodeId,
        /// Result.
        output: VarnodeId,
    },
    /// INT_SUB: a - b -> output
    IntSub {
        /// First operand.
        a: VarnodeId,
        /// Second operand.
        b: VarnodeId,
        /// Result.
        output: VarnodeId,
    },
    /// STORE: value -> memory[space][addr]
    Store {
        /// Address space identifier.
        space: u16,
        /// Address varnode.
        addr: VarnodeId,
        /// Value varnode.
        value: VarnodeId,
    },
    /// LOAD: memory[space][addr] -> output
    Load {
        /// Address space identifier.
        space: u16,
        /// Address varnode.
        addr: VarnodeId,
        /// Result.
        output: VarnodeId,
    },
    /// INT_AND: a & b -> output
    IntAnd {
        /// First operand.
        a: VarnodeId,
        /// Second operand.
        b: VarnodeId,
        /// Result.
        output: VarnodeId,
    },
    /// INT_OR: a | b -> output (produces opaque for stack analysis)
    IntOr {
        /// First operand.
        a: VarnodeId,
        /// Second operand.
        b: VarnodeId,
        /// Result.
        output: VarnodeId,
    },
    /// INT_XOR: a ^ b -> output (produces opaque for stack analysis)
    IntXor {
        /// First operand.
        a: VarnodeId,
        /// Second operand.
        b: VarnodeId,
        /// Result.
        output: VarnodeId,
    },
    /// INT_LEFT: a << b -> output (produces opaque)
    IntLeft {
        /// Shift value.
        a: VarnodeId,
        /// Shift amount.
        b: VarnodeId,
        /// Result.
        output: VarnodeId,
    },
    /// INT_RIGHT: a >> b (logical) -> output (produces opaque)
    IntRight {
        /// Shift value.
        a: VarnodeId,
        /// Shift amount.
        b: VarnodeId,
        /// Result.
        output: VarnodeId,
    },
    /// INT_SRIGHT: a >> b (arithmetic) -> output (produces opaque)
    IntSRight {
        /// Shift value.
        a: VarnodeId,
        /// Shift amount.
        b: VarnodeId,
        /// Result.
        output: VarnodeId,
    },
    /// INT_2COMP: -input -> output
    Int2Comp {
        /// Input.
        input: VarnodeId,
        /// Result.
        output: VarnodeId,
    },
    /// INT_NOT: ~input -> output
    IntNot {
        /// Input.
        input: VarnodeId,
        /// Result.
        output: VarnodeId,
    },
    /// SUBPIECE: input[offset..] -> output
    Subpiece {
        /// Input.
        input: VarnodeId,
        /// Result.
        output: VarnodeId,
        /// Byte offset.
        offset: u8,
    },
}

/// Identifier for a varnode in the symbolic execution context.
///
/// Varnodes can be registers (identified by name), stack locations
/// (identified by offset), or constants.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VarnodeId {
    /// A named register (e.g., "rsp", "rbp").
    Register(String),
    /// A stack location at the given offset from the frame base.
    StackOffset(i64),
    /// A constant value.
    Constant(u64),
    /// A unique space temporary.
    Unique(u64),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stack::sym::ConstSym;

    #[test]
    fn test_executor_creation() {
        let exec = SymPcodeExecutor::new("RSP", false);
        assert_eq!(exec.ops_count(), 0);
        assert!(exec.track_reads);
    }

    #[test]
    fn test_executor_default() {
        let exec = SymPcodeExecutor::default();
        assert_eq!(exec.ops_count(), 0);
    }

    #[test]
    fn test_execute_copy() {
        let mut exec = SymPcodeExecutor::new("RSP", false);
        exec.state
            .write_sym("register", 1, Sym::Const(ConstSym { value: 0x1234, size: 8 }));
        let op = PcodeOpSymbolic::Copy {
            input: VarnodeId::Constant(0x1234),
            output: VarnodeId::Register("rbx".into()),
        };
        let result = exec.execute_op(&op);
        assert_eq!(exec.ops_count(), 1);
        if let Sym::Const(c) = result {
            assert_eq!(c.value, 0x1234);
        } else {
            panic!("Expected constant");
        }
    }

    #[test]
    fn test_execute_add() {
        let mut exec = SymPcodeExecutor::new("RSP", false);
        let op = PcodeOpSymbolic::IntAdd {
            a: VarnodeId::Constant(10),
            b: VarnodeId::Constant(20),
            output: VarnodeId::Register("rcx".into()),
        };
        let result = exec.execute_op(&op);
        if let Sym::Const(c) = result {
            assert_eq!(c.value, 30);
        } else {
            panic!("Expected constant 30, got {:?}", result);
        }
    }

    #[test]
    fn test_execute_sub_sp() {
        let mut exec = SymPcodeExecutor::new("RSP", false);
        // RSP = RSP symbol
        let sp_addr = register_name_to_addr("RSP");
        exec.state.write_sym("register", sp_addr, Sym::register("RSP", 8));
        let op = PcodeOpSymbolic::IntSub {
            a: VarnodeId::Register("RSP".into()),
            b: VarnodeId::Constant(8),
            output: VarnodeId::Register("RSP".into()),
        };
        let result = exec.execute_op(&op);
        // RSP - 8 should produce a stack offset
        assert!(matches!(result, Sym::StackOffset(_)));
    }

    #[test]
    fn test_varnode_id_serde() {
        let vn = VarnodeId::Register("rsp".into());
        let json = serde_json::to_string(&vn).unwrap();
        let back: VarnodeId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, VarnodeId::Register("rsp".into()));
    }

    #[test]
    fn test_execute_int2comp() {
        let mut exec = SymPcodeExecutor::new("RSP", false);
        let op = PcodeOpSymbolic::Int2Comp {
            input: VarnodeId::Constant(42),
            output: VarnodeId::Register("rax".into()),
        };
        let result = exec.execute_op(&op);
        if let Sym::Const(c) = result {
            assert_eq!(c.value, -42);
        } else {
            panic!("Expected constant -42, got {:?}", result);
        }
    }

    #[test]
    fn test_fork_regs() {
        let mut exec = SymPcodeExecutor::new("RSP", false);
        exec.state
            .write_sym("register", 0, Sym::Const(ConstSym { value: 42, size: 8 }));
        let forked = exec.fork_regs();
        // Forked state should preserve register values
        let val = forked.read_sym("register", 0, 8);
        assert_eq!(val.as_const_value(), Some(42));
        // Stack should be empty
        assert!(forked.stack.is_empty());
    }

    #[test]
    fn test_compute_map_using_stack() {
        let mut exec = SymPcodeExecutor::new("RSP", false);
        exec.state
            .write_sym("stack", -8, Sym::register("R30", 8));
        exec.state
            .write_sym("stack", -16, Sym::register("R29", 8));
        let map = exec.compute_map_using_stack();
        assert_eq!(map.len(), 2);
        assert!(map.contains_key(&-8i64));
        assert!(map.contains_key(&-16i64));
    }

    #[test]
    fn test_space_name() {
        assert_eq!(space_name(0), "register");
        assert_eq!(space_name(1), "stack");
        assert_eq!(space_name(256), "unique");
        assert_eq!(space_name(999), "space_999");
    }

    #[test]
    fn test_register_name_to_addr_deterministic() {
        let a1 = register_name_to_addr("RSP");
        let a2 = register_name_to_addr("RSP");
        assert_eq!(a1, a2);
        // Different names should (very likely) map differently
        let b = register_name_to_addr("RAX");
        // Not guaranteed but extremely likely
        assert_ne!(a1, b);
    }
}
