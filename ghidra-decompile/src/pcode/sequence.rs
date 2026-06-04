//! P-code instruction sequences.
//!
//! Provides [`PcodeSequence`] for representing the set of P-code operations
//! that correspond to a single machine instruction, and [`SequenceBuilder`]
//! for constructing sequences incrementally.

use super::opcodes::OpCode;
use super::operation::{PcodeOperation, Varnode};
use ghidra_core::addr::Address;

// ---------------------------------------------------------------------------
// PcodeSequence
// ---------------------------------------------------------------------------

/// A sequence of P-code operations that correspond to a single machine
/// instruction.
///
/// Each SLEIGH instruction pattern translates into exactly one
/// `PcodeSequence`.
#[derive(Debug, Clone)]
pub struct PcodeSequence {
    /// The P-code operations in execution order.
    pub operations: Vec<PcodeOperation>,
    /// The address of the machine instruction.
    pub instruction_address: Address,
    /// Length of the machine instruction in bytes.
    pub length: u32,
}

impl PcodeSequence {
    /// Create a new sequence.
    pub fn new(
        operations: Vec<PcodeOperation>,
        instruction_address: Address,
        length: u32,
    ) -> Self {
        Self {
            operations,
            instruction_address,
            length,
        }
    }

    /// Returns an iterator over the operations.
    pub fn iter(&self) -> std::slice::Iter<'_, PcodeOperation> {
        self.operations.iter()
    }

    /// Returns the number of operations.
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    /// Returns true if there are no operations.
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Returns true if any operation in this sequence has side effects.
    pub fn has_side_effects(&self) -> bool {
        self.operations.iter().any(|op| op.has_side_effects())
    }

    /// Returns true if the last operation is a terminator.
    pub fn ends_with_terminator(&self) -> bool {
        self.operations
            .last()
            .map_or(false, |op| op.is_terminator())
    }

    /// Flatten all operations in this sequence into a single vec, annotated
    /// with this sequence's instruction address.
    pub fn flatten(&self) -> Vec<PcodeOperation> {
        self.operations
            .iter()
            .map(|op| {
                let mut op = op.clone();
                if op.address.is_none() {
                    op.address = Some(self.instruction_address);
                }
                op
            })
            .collect()
    }

    /// Get the last operation, if any.
    pub fn last(&self) -> Option<&PcodeOperation> {
        self.operations.last()
    }

    /// Get the first operation, if any.
    pub fn first(&self) -> Option<&PcodeOperation> {
        self.operations.first()
    }

    /// Collect all varnodes that are defined (written) by operations in this
    /// sequence.
    pub fn defined_varnodes(&self) -> Vec<&Varnode> {
        self.operations
            .iter()
            .filter_map(|op| op.output.as_ref())
            .collect()
    }

    /// Collect all varnodes that are used (read) by operations in this
    /// sequence.
    pub fn used_varnodes(&self) -> Vec<&Varnode> {
        self.operations
            .iter()
            .flat_map(|op| op.inputs.iter())
            .collect()
    }
}

impl<'a> IntoIterator for &'a PcodeSequence {
    type Item = &'a PcodeOperation;
    type IntoIter = std::slice::Iter<'a, PcodeOperation>;

    fn into_iter(self) -> Self::IntoIter {
        self.operations.iter()
    }
}

// ---------------------------------------------------------------------------
// SequenceBuilder
// ---------------------------------------------------------------------------

/// Builder for constructing a [`PcodeSequence`] (or individual
/// [`PcodeOperation`]s) incrementally.
///
/// # Example
///
/// ```ignore
/// let seq = SequenceBuilder::new(addr, 4)
///     .copy(out, inp)
///     .int_add(sum, lhs, rhs)
///     .store(ptr, val)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct SequenceBuilder {
    operations: Vec<PcodeOperation>,
    instruction_address: Address,
    length: u32,
}

impl SequenceBuilder {
    /// Start building a new sequence for an instruction at `address` with the
    /// given byte length.
    pub fn new(address: Address, length: u32) -> Self {
        Self {
            operations: Vec::new(),
            instruction_address: address,
            length,
        }
    }

    /// Returns the current number of operations.
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    /// Returns true if no operations have been added yet.
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Add a pre-built operation.
    pub fn push(&mut self, op: PcodeOperation) -> &mut Self {
        self.operations.push(op);
        self
    }

    /// Add an operation with the given opcode.
    pub fn emit(
        &mut self,
        opcode: OpCode,
        output: Option<Varnode>,
        inputs: Vec<Varnode>,
    ) -> &mut Self {
        self.operations.push(PcodeOperation::new_unannotated(
            opcode, output, inputs,
        ));
        self
    }

    // -- convenience constructors for common opcodes -------------------------

    /// `out = in0`
    pub fn copy(&mut self, out: Varnode, inp: Varnode) -> &mut Self {
        self.emit(OpCode::COPY, Some(out), vec![inp])
    }

    /// `out = *[space]ptr`
    pub fn load(&mut self, out: Varnode, space: Varnode, ptr: Varnode) -> &mut Self {
        self.emit(OpCode::LOAD, Some(out), vec![space, ptr])
    }

    /// `*[space]ptr = value`
    pub fn store(&mut self, space: Varnode, ptr: Varnode, value: Varnode) -> &mut Self {
        self.emit(OpCode::STORE, None, vec![space, ptr, value])
    }

    /// `out = in0 + in1`
    pub fn int_add(&mut self, out: Varnode, lhs: Varnode, rhs: Varnode) -> &mut Self {
        self.emit(OpCode::INT_ADD, Some(out), vec![lhs, rhs])
    }

    /// `out = in0 - in1`
    pub fn int_sub(&mut self, out: Varnode, lhs: Varnode, rhs: Varnode) -> &mut Self {
        self.emit(OpCode::INT_SUB, Some(out), vec![lhs, rhs])
    }

    /// `out = in0 * in1`
    pub fn int_mul(&mut self, out: Varnode, lhs: Varnode, rhs: Varnode) -> &mut Self {
        self.emit(OpCode::INT_MUL, Some(out), vec![lhs, rhs])
    }

    /// `out = in0 / in1`  (unsigned)
    pub fn int_div(&mut self, out: Varnode, lhs: Varnode, rhs: Varnode) -> &mut Self {
        self.emit(OpCode::INT_DIV, Some(out), vec![lhs, rhs])
    }

    /// `out = in0 /s in1`  (signed)
    pub fn int_sdiv(&mut self, out: Varnode, lhs: Varnode, rhs: Varnode) -> &mut Self {
        self.emit(OpCode::INT_SDIV, Some(out), vec![lhs, rhs])
    }

    /// `out = in0 % in1`  (unsigned)
    pub fn int_rem(&mut self, out: Varnode, lhs: Varnode, rhs: Varnode) -> &mut Self {
        self.emit(OpCode::INT_REM, Some(out), vec![lhs, rhs])
    }

    /// `out = in0 %s in1`  (signed)
    pub fn int_srem(&mut self, out: Varnode, lhs: Varnode, rhs: Varnode) -> &mut Self {
        self.emit(OpCode::INT_SREM, Some(out), vec![lhs, rhs])
    }

    /// `out = in0 & in1`
    pub fn int_and(&mut self, out: Varnode, lhs: Varnode, rhs: Varnode) -> &mut Self {
        self.emit(OpCode::INT_AND, Some(out), vec![lhs, rhs])
    }

    /// `out = in0 | in1`
    pub fn int_or(&mut self, out: Varnode, lhs: Varnode, rhs: Varnode) -> &mut Self {
        self.emit(OpCode::INT_OR, Some(out), vec![lhs, rhs])
    }

    /// `out = in0 ^ in1`
    pub fn int_xor(&mut self, out: Varnode, lhs: Varnode, rhs: Varnode) -> &mut Self {
        self.emit(OpCode::INT_XOR, Some(out), vec![lhs, rhs])
    }

    /// `out = in0 << in1`
    pub fn int_left(&mut self, out: Varnode, lhs: Varnode, rhs: Varnode) -> &mut Self {
        self.emit(OpCode::INT_LEFT, Some(out), vec![lhs, rhs])
    }

    /// `out = in0 >> in1` (logical)
    pub fn int_right(&mut self, out: Varnode, lhs: Varnode, rhs: Varnode) -> &mut Self {
        self.emit(OpCode::INT_RIGHT, Some(out), vec![lhs, rhs])
    }

    /// `out = in0 >>> in1` (arithmetic)
    pub fn int_sright(&mut self, out: Varnode, lhs: Varnode, rhs: Varnode) -> &mut Self {
        self.emit(OpCode::INT_SRIGHT, Some(out), vec![lhs, rhs])
    }

    /// `out = sext(in0)`
    pub fn int_sext(&mut self, out: Varnode, inp: Varnode) -> &mut Self {
        self.emit(OpCode::INT_SEXT, Some(out), vec![inp])
    }

    /// `out = zext(in0)`
    pub fn int_zext(&mut self, out: Varnode, inp: Varnode) -> &mut Self {
        self.emit(OpCode::INT_ZEXT, Some(out), vec![inp])
    }

    /// `out = -in0`
    pub fn int_negate(&mut self, out: Varnode, inp: Varnode) -> &mut Self {
        self.emit(OpCode::INT_NEGATE, Some(out), vec![inp])
    }

    /// `out = (in0 == in1) ? 1 : 0`
    pub fn int_equal(&mut self, out: Varnode, lhs: Varnode, rhs: Varnode) -> &mut Self {
        self.emit(OpCode::INT_EQUAL, Some(out), vec![lhs, rhs])
    }

    /// `out = (in0 != in1) ? 1 : 0`
    pub fn int_not_equal(&mut self, out: Varnode, lhs: Varnode, rhs: Varnode) -> &mut Self {
        self.emit(OpCode::INT_NOTEQUAL, Some(out), vec![lhs, rhs])
    }

    /// `out = (in0 < in1) ? 1 : 0`  (unsigned)
    pub fn int_less(&mut self, out: Varnode, lhs: Varnode, rhs: Varnode) -> &mut Self {
        self.emit(OpCode::INT_LESS, Some(out), vec![lhs, rhs])
    }

    /// `out = (in0 <= in1) ? 1 : 0`  (unsigned)
    pub fn int_less_equal(&mut self, out: Varnode, lhs: Varnode, rhs: Varnode) -> &mut Self {
        self.emit(OpCode::INT_LESSEQUAL, Some(out), vec![lhs, rhs])
    }

    /// `out = (in0 <s in1) ? 1 : 0`  (signed)
    pub fn int_sless(&mut self, out: Varnode, lhs: Varnode, rhs: Varnode) -> &mut Self {
        self.emit(OpCode::INT_SLESS, Some(out), vec![lhs, rhs])
    }

    /// `out = (in0 <=s in1) ? 1 : 0`  (signed)
    pub fn int_sless_equal(&mut self, out: Varnode, lhs: Varnode, rhs: Varnode) -> &mut Self {
        self.emit(OpCode::INT_SLESSEQUAL, Some(out), vec![lhs, rhs])
    }

    /// `out = !in0`
    pub fn bool_negate(&mut self, out: Varnode, inp: Varnode) -> &mut Self {
        self.emit(OpCode::BOOL_NEGATE, Some(out), vec![inp])
    }

    /// `out = in0 || in1`  (boolean OR)
    pub fn bool_or(&mut self, out: Varnode, lhs: Varnode, rhs: Varnode) -> &mut Self {
        self.emit(OpCode::BOOL_OR, Some(out), vec![lhs, rhs])
    }

    /// `out = in0 && in1`  (boolean AND)
    pub fn bool_and(&mut self, out: Varnode, lhs: Varnode, rhs: Varnode) -> &mut Self {
        self.emit(OpCode::BOOL_AND, Some(out), vec![lhs, rhs])
    }

    /// `out = in0 + (in1 * in2)`  (pointer arithmetic)
    pub fn ptr_add(
        &mut self,
        out: Varnode,
        base: Varnode,
        index: Varnode,
        scale: Varnode,
    ) -> &mut Self {
        self.emit(OpCode::PTRADD, Some(out), vec![base, index, scale])
    }

    /// `out = in0 - in1`  (pointer subtraction)
    pub fn ptr_sub(&mut self, out: Varnode, lhs: Varnode, rhs: Varnode) -> &mut Self {
        self.emit(OpCode::PTRSUB, Some(out), vec![lhs, rhs])
    }

    /// `out = in0 || in1`  (concatenation; `in0` = most-significant)
    pub fn piece(&mut self, out: Varnode, hi: Varnode, lo: Varnode) -> &mut Self {
        self.emit(OpCode::PIECE, Some(out), vec![hi, lo])
    }

    /// `out = in0[low..low+size]`  (truncation)
    pub fn subpiece(&mut self, out: Varnode, inp: Varnode, low_byte: Varnode) -> &mut Self {
        self.emit(OpCode::SUBPIECE, Some(out), vec![inp, low_byte])
    }

    /// `out = (cast)in0`
    pub fn cast(&mut self, out: Varnode, inp: Varnode) -> &mut Self {
        self.emit(OpCode::CAST, Some(out), vec![inp])
    }

    /// Branch to target address.
    pub fn branch(&mut self, target: Address) -> &mut Self {
        let target_vn = Varnode::constant(target.offset, 8);
        self.emit(OpCode::BRANCH, None, vec![target_vn])
    }

    /// Conditional branch: if `cond` then goto `target`.
    pub fn cbranch(&mut self, cond: Varnode, target: Address) -> &mut Self {
        let target_vn = Varnode::constant(target.offset, 8);
        self.emit(OpCode::CBRANCH, None, vec![target_vn, cond])
    }

    /// Indirect branch through a register or varnode.
    pub fn branch_ind(&mut self, target: Varnode) -> &mut Self {
        self.emit(OpCode::BRANCHIND, None, vec![target])
    }

    /// Call a function at `target`, optionally returning a value.
    pub fn call(
        &mut self,
        target: Address,
        inputs: &[Varnode],
        output: Option<Varnode>,
    ) -> &mut Self {
        let mut args = vec![Varnode::constant(target.offset, 8)];
        args.extend_from_slice(inputs);
        self.emit(OpCode::CALL, output, args)
    }

    /// Indirect call through a register or varnode.
    pub fn call_ind(
        &mut self,
        target: Varnode,
        inputs: &[Varnode],
        output: Option<Varnode>,
    ) -> &mut Self {
        let mut args = vec![target];
        args.extend_from_slice(inputs);
        self.emit(OpCode::CALLIND, output, args)
    }

    /// Return from function, optionally with a value.
    pub fn return_(&mut self, value: Option<Varnode>) -> &mut Self {
        let inputs = value.into_iter().collect();
        self.emit(OpCode::RETURN, None, inputs)
    }

    /// Consume the builder and produce a [`PcodeSequence`].
    pub fn build(self) -> PcodeSequence {
        PcodeSequence {
            operations: self.operations,
            instruction_address: self.instruction_address,
            length: self.length,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;

    #[test]
    fn test_sequence_builder() {
        let addr = Address::new(0x1000);
        let out = Varnode::unique(0, 4);
        let lhs = Varnode::register("eax", 0, 4);
        let rhs = Varnode::constant(1, 4);

        let mut builder = SequenceBuilder::new(addr, 4);
        builder.int_add(out.clone(), lhs.clone(), rhs);
        let seq = builder.build();

        assert_eq!(seq.len(), 1);
        assert_eq!(seq.instruction_address, addr);
        assert_eq!(seq.operations[0].opcode, OpCode::INT_ADD);
        assert_eq!(seq.operations[0].output, Some(out));
    }

    #[test]
    fn test_sequence_builder_branch() {
        let addr = Address::new(0x1000);
        let target = Address::new(0x2000);

        let mut builder = SequenceBuilder::new(addr, 4);
        builder.branch(target);
        let seq = builder.build();

        assert_eq!(seq.len(), 1);
        assert_eq!(seq.operations[0].opcode, OpCode::BRANCH);
        assert!(seq.ends_with_terminator());
    }

    #[test]
    fn test_sequence_builder_multi_op() {
        let addr = Address::new(0x1000);
        let out = Varnode::unique(0, 4);
        let x = Varnode::register("eax", 0, 4);
        let y = Varnode::register("ebx", 0, 4);
        let one = Varnode::constant(1, 4);

        let mut builder = SequenceBuilder::new(addr, 4);
        builder.copy(out.clone(), x);
        builder.int_add(out.clone(), out.clone(), one);
        builder.int_mul(out.clone(), out.clone(), y.clone());
        let seq = builder.build();

        assert_eq!(seq.len(), 3);
        assert_eq!(seq.operations[0].opcode, OpCode::COPY);
        assert_eq!(seq.operations[1].opcode, OpCode::INT_ADD);
        assert_eq!(seq.operations[2].opcode, OpCode::INT_MUL);
    }

    #[test]
    fn test_sequence_empty() {
        let addr = Address::new(0x1000);
        let seq = SequenceBuilder::new(addr, 4).build();
        assert!(seq.is_empty());
        assert_eq!(seq.len(), 0);
    }

    #[test]
    fn test_sequence_flatten() {
        let addr = Address::new(0x1000);
        let x = Varnode::register("eax", 0, 4);
        let y = Varnode::register("ebx", 0, 4);

        let mut builder = SequenceBuilder::new(addr, 4);
        builder.int_add(Varnode::unique(0, 4), x, y);
        let seq = builder.build();

        let flat = seq.flatten();
        assert_eq!(flat.len(), 1);
        assert_eq!(flat[0].address, Some(addr));
    }

    #[test]
    fn test_sequence_defined_used_varnodes() {
        let addr = Address::new(0x1000);
        let out = Varnode::unique(0, 4);
        let x = Varnode::register("eax", 0, 4);
        let y = Varnode::register("ebx", 0, 4);

        let mut builder = SequenceBuilder::new(addr, 4);
        builder.int_add(out.clone(), x.clone(), y.clone());
        let seq = builder.build();

        let defs = seq.defined_varnodes();
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0], &out);

        let uses = seq.used_varnodes();
        assert_eq!(uses.len(), 2);
        assert!(uses.contains(&&x));
        assert!(uses.contains(&&y));
    }
}
