//! P-code operations and storage varnodes.
//!
//! Provides the [`Varnode`] structure representing a storage location in
//! P-code, and the [`PcodeOperation`] structure representing a single P-code
//! operation.

use super::opcodes::OpCode;
use ghidra_core::addr::{Address, AddressSpace, AddrSpaceType};
use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Varnode
// ---------------------------------------------------------------------------

/// A storage location: (address-space, offset, size).
///
/// Every value in P-code lives in a varnode.  The address space determines
/// whether the value is in RAM, a register, a constant, or a unique
/// (temporary) location.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Varnode {
    /// The address space this varnode lives in (e.g., `"register"`, `"ram"`,
    /// `"const"`, `"unique"`).
    pub space: AddressSpace,
    /// Byte offset within the address space.
    pub offset: u64,
    /// Size of the varnode in bytes.
    pub size: u32,
}

impl Varnode {
    /// Create a new varnode.
    pub fn new(space: AddressSpace, offset: u64, size: u32) -> Self {
        Self {
            space,
            offset,
            size,
        }
    }

    /// Create a constant varnode (space = `"const"`).
    pub fn constant(value: u64, size: u32) -> Self {
        Self {
            space: AddressSpace::new("const", size as usize, false, AddrSpaceType::Constant, 3),
            offset: value,
            size,
        }
    }

    /// Create a register varnode (space = `"register"`).
    pub fn register(name: &str, offset: u64, size: u32) -> Self {
        Self {
            space: AddressSpace::new(name, size as usize, false, AddrSpaceType::Register, 2),
            offset,
            size,
        }
    }

    /// Create a unique/temporary varnode (space = `"unique"`).
    pub fn unique(id: u64, size: u32) -> Self {
        Self {
            space: AddressSpace::new("unique", size as usize, false, AddrSpaceType::Unique, 4),
            offset: id,
            size,
        }
    }

    /// Create a RAM varnode (space = `"ram"`).
    pub fn ram(offset: u64, size: u32) -> Self {
        Self {
            space: AddressSpace::new("ram", size as usize, false, AddrSpaceType::Ram, 1),
            offset,
            size,
        }
    }

    /// Returns true if this varnode lives in the constant space.
    pub fn is_constant(&self) -> bool {
        self.space.space_type == AddrSpaceType::Constant
    }

    /// Returns true if this varnode lives in the register space.
    pub fn is_register(&self) -> bool {
        self.space.space_type == AddrSpaceType::Register
    }

    /// Returns true if this varnode lives in the unique (temporary) space.
    pub fn is_unique(&self) -> bool {
        self.space.space_type == AddrSpaceType::Unique
    }

    /// Returns true if this varnode lives in the RAM space.
    pub fn is_ram(&self) -> bool {
        self.space.space_type == AddrSpaceType::Ram
    }

    /// Returns the value of this varnode if it is a constant, otherwise `None`.
    pub fn constant_value(&self) -> Option<u64> {
        if self.is_constant() {
            Some(self.offset)
        } else {
            None
        }
    }

    /// Create a new varnode with the same space but a different offset.
    pub fn with_offset(&self, offset: u64) -> Self {
        Self {
            space: self.space.clone(),
            offset,
            size: self.size,
        }
    }

    /// Create a new varnode with the same space/offset but a different size.
    pub fn with_size(&self, size: u32) -> Self {
        Self {
            space: self.space.clone(),
            offset: self.offset,
            size,
        }
    }

    /// Returns the byte range `[offset, offset + size)`.
    pub fn byte_range(&self) -> std::ops::Range<u64> {
        self.offset..(self.offset + self.size as u64)
    }

    /// Returns true when two varnodes overlap in the same address space.
    pub fn overlaps(&self, other: &Varnode) -> bool {
        self.space == other.space
            && self.offset < other.offset + other.size as u64
            && other.offset < self.offset + self.size as u64
    }

    /// Returns true if this varnode fully contains `other` in the same space.
    pub fn contains(&self, other: &Varnode) -> bool {
        self.space == other.space
            && self.offset <= other.offset
            && other.offset + other.size as u64 <= self.offset + self.size as u64
    }
}

impl PartialOrd for Varnode {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Varnode {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.space
            .name
            .cmp(&other.space.name)
            .then_with(|| self.offset.cmp(&other.offset))
            .then_with(|| self.size.cmp(&other.size))
    }
}

impl fmt::Display for Varnode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "({}, 0x{:x}, {})",
            self.space.name, self.offset, self.size
        )
    }
}

// ---------------------------------------------------------------------------
// PcodeOperation
// ---------------------------------------------------------------------------

/// A single P-code operation.
///
/// An operation has an opcode, an optional output varnode, a (possibly empty)
/// list of input varnodes, and an optional machine-instruction address (used
/// to track provenance through analysis).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcodeOperation {
    /// The operation code.
    pub opcode: OpCode,
    /// The output varnode, if any.
    pub output: Option<Varnode>,
    /// The input varnodes.  The semantic role of each input depends on the
    /// opcode.
    pub inputs: Vec<Varnode>,
    /// The address of the machine instruction that produced this P-code op
    /// (useful for debugging / tracing).
    pub address: Option<Address>,
}

impl PcodeOperation {
    /// Create a new P-code operation.
    pub fn new(
        opcode: OpCode,
        output: Option<Varnode>,
        inputs: Vec<Varnode>,
        address: Option<Address>,
    ) -> Self {
        Self {
            opcode,
            output,
            inputs,
            address,
        }
    }

    /// Create a new operation without an address annotation.
    pub fn new_unannotated(
        opcode: OpCode,
        output: Option<Varnode>,
        inputs: Vec<Varnode>,
    ) -> Self {
        Self {
            opcode,
            output,
            inputs,
            address: None,
        }
    }

    /// Returns true if this operation has side effects.
    pub fn has_side_effects(&self) -> bool {
        self.opcode.has_side_effects()
    }

    /// Returns true if this operation is a terminator (ends a basic block).
    pub fn is_terminator(&self) -> bool {
        self.opcode.is_flow()
    }

    /// Returns true if this is a phi-node (for SSA analysis).
    pub fn is_phi(&self) -> bool {
        self.opcode == OpCode::MULTIEQUAL
    }

    /// Returns the number of input varnodes.
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    /// Get input at index, or `None`.
    pub fn input(&self, index: usize) -> Option<&Varnode> {
        self.inputs.get(index)
    }

    /// Returns all varnodes referenced by this operation (output + inputs).
    pub fn all_varnodes(&self) -> Vec<&Varnode> {
        let mut v = Vec::with_capacity(1 + self.inputs.len());
        if let Some(ref out) = self.output {
            v.push(out);
        }
        v.extend(self.inputs.iter());
        v
    }

    /// Returns true if `varnode` is used as an input to this operation.
    pub fn uses(&self, varnode: &Varnode) -> bool {
        self.inputs.iter().any(|v| v == varnode)
    }

    /// Returns true if `varnode` is defined (written) by this operation.
    pub fn defines(&self, varnode: &Varnode) -> bool {
        self.output.as_ref() == Some(varnode)
    }

    /// Replace an input varnode with a new one.
    ///
    /// Returns true if a replacement was made.
    pub fn replace_input(&mut self, old: &Varnode, new: Varnode) -> bool {
        let mut found = false;
        for inp in self.inputs.iter_mut() {
            if inp == old {
                *inp = new.clone();
                found = true;
            }
        }
        found
    }

    /// Replace the output varnode if it matches `old`.
    ///
    /// Returns true if a replacement was made.
    pub fn replace_output(&mut self, old: &Varnode, new: Varnode) -> bool {
        if self.output.as_ref() == Some(old) {
            self.output = Some(new);
            true
        } else {
            false
        }
    }

    /// Apply a mapping function to every varnode in this operation.
    pub fn map_varnodes<F>(&mut self, mut f: F)
    where
        F: FnMut(&Varnode) -> Varnode,
    {
        if let Some(ref out) = self.output {
            self.output = Some(f(out));
        }
        for inp in self.inputs.iter_mut() {
            *inp = f(inp);
        }
    }
}

impl fmt::Display for PcodeOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref out) = self.output {
            write!(f, "{} = {} ", out, self.opcode)?;
        } else {
            write!(f, "{} ", self.opcode)?;
        }
        for (i, inp) in self.inputs.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", inp)?;
        }
        if let Some(ref addr) = self.address {
            write!(f, "  ; @{}", addr)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_space(name: &str) -> AddressSpace {
        AddressSpace::new(name, 8, false, AddrSpaceType::Unique, 4)
    }

    #[test]
    fn test_varnode_ordering() {
        let a = Varnode::new(make_space("ram"), 0x1000, 4);
        let b = Varnode::new(make_space("ram"), 0x2000, 4);
        let c = Varnode::new(make_space("register"), 0, 8);
        assert!(a < b);
        assert!(a < c); // "ram" < "register" lexicographically
    }

    #[test]
    fn test_varnode_overlap() {
        let a = Varnode::new(make_space("ram"), 0x100, 4);
        let b = Varnode::new(make_space("ram"), 0x102, 4);
        let c = Varnode::new(make_space("ram"), 0x104, 4);
        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c));
    }

    #[test]
    fn test_varnode_contains() {
        let big = Varnode::new(make_space("ram"), 0x100, 8);
        let small = Varnode::new(make_space("ram"), 0x102, 4);
        let outside = Varnode::new(make_space("ram"), 0x108, 2);
        let diff_space = Varnode::new(make_space("register"), 0x102, 4);
        assert!(big.contains(&small));
        assert!(!big.contains(&outside));
        assert!(!big.contains(&diff_space));
    }

    #[test]
    fn test_varnode_constant() {
        let v = Varnode::constant(42, 4);
        assert!(v.is_constant());
        assert_eq!(v.constant_value(), Some(42));
    }

    #[test]
    fn test_varnode_display() {
        let v = Varnode::new(make_space("ram"), 0x1000, 4);
        assert_eq!(v.to_string(), "(ram, 0x1000, 4)");
    }

    #[test]
    fn test_pcode_operation_display() {
        let out = Varnode::unique(0, 4);
        let lhs = Varnode::register("eax", 0, 4);
        let rhs = Varnode::constant(1, 4);
        let op = PcodeOperation::new(OpCode::INT_ADD, Some(out.clone()), vec![lhs, rhs], None);
        let s = op.to_string();
        assert!(s.starts_with("(unique, 0x0, 4) = INT_ADD "));
    }

    #[test]
    fn test_pcode_operation_uses_defines() {
        let out = Varnode::unique(0, 4);
        let x = Varnode::register("r0", 0, 4);
        let y = Varnode::register("r1", 4, 4);
        let op = PcodeOperation::new(OpCode::INT_ADD, Some(out.clone()), vec![x.clone(), y], None);
        assert!(op.uses(&x));
        assert!(!op.uses(&out));
        assert!(op.defines(&out));
        assert!(!op.defines(&x));
    }

    #[test]
    fn test_pcode_operation_replace() {
        let out = Varnode::unique(0, 4);
        let old = Varnode::register("r0", 0, 4);
        let new_opnd = Varnode::register("r2", 8, 4);
        let mut op = PcodeOperation::new(
            OpCode::INT_ADD,
            Some(out.clone()),
            vec![old.clone(), Varnode::constant(1, 4)],
            None,
        );
        assert!(op.replace_input(&old, new_opnd.clone()));
        assert!(op.uses(&new_opnd));
        assert!(!op.uses(&old));
    }
}
