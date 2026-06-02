//! Semantic construction interfaces.
//!
//! Provides traits used during SLEIGH disassembly to construct P-code.
//!
//! - [`ConstructSem`] is implemented by SLEIGH constructors to provide semantic
//!   actions that build P-code sequences during instruction disassembly.
//! - [`PcodeEmitter`] is implemented by components that receive and collect
//!   emitted P-code operations.

use super::opcodes::OpCode;
use super::operation::{PcodeOperation, Varnode};
use ghidra_core::addr::Address;

// ---------------------------------------------------------------------------
// ConstructSem trait
// ---------------------------------------------------------------------------

/// Trait for semantic actions during SLEIGH disassembly.
///
/// Each SLEIGH constructor (e.g., a table entry that matches a bit pattern)
/// implements `ConstructSem` to emit the P-code operations that represent
/// the matched instruction's semantics.
///
/// # Example
///
/// ```ignore
/// struct AddConstructor;
///
/// impl ConstructSem for AddConstructor {
///     fn construct(&self, emitter: &mut dyn PcodeEmitter) {
///         // rd = rs1 + rs2
///         emitter.emit_int_add(rd, rs1, rs2, None);
///     }
/// }
/// ```
pub trait ConstructSem {
    /// Emit the P-code operations for this semantic action.
    ///
    /// Called during disassembly once a SLEIGH constructor matches a bit
    /// pattern. The implementor should call methods on `emitter` to produce
    /// the sequence of P-code operations.
    fn construct(&self, emitter: &mut dyn PcodeEmitter);

    /// Return a human-readable label for this constructor (used in
    /// disassembly listing).
    fn label(&self) -> &str {
        ""
    }

    /// Return the length in bytes of the machine instruction this constructor
    /// produces, if known at compile time. Returning `None` means the length
    /// is variable.
    fn length(&self) -> Option<u32> {
        None
    }
}

// ---------------------------------------------------------------------------
// PcodeEmitter trait
// ---------------------------------------------------------------------------

/// Trait for components that emit P-code operations.
///
/// SLEIGH constructors call methods on an implementation of this trait while
/// evaluating instruction patterns.  Each method corresponds to a common
/// P-code opcode.
///
/// A blanket implementation forwards every method to [`emit_op`] so that
/// implementors only need to override the methods relevant to their use-case.
///
/// [`emit_op`]: PcodeEmitter::emit_op
pub trait PcodeEmitter {
    /// Emit an arbitrary P-code operation.
    fn emit_op(&mut self, op: PcodeOperation);

    /// Set the address context for subsequently-emitted operations (used for
    /// branch targets, etc.).
    fn set_address(&mut self, _addr: Address) {}

    /// `out = in0`
    fn emit_copy(
        &mut self,
        output: Varnode,
        input: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::COPY,
            Some(output),
            vec![input],
            addr,
        ));
    }

    /// `out = *[space]ptr`
    fn emit_load(
        &mut self,
        output: Varnode,
        space: Varnode,
        ptr: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::LOAD,
            Some(output),
            vec![space, ptr],
            addr,
        ));
    }

    /// `*[space]ptr = value`
    fn emit_store(
        &mut self,
        space: Varnode,
        ptr: Varnode,
        value: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::STORE,
            None,
            vec![space, ptr, value],
            addr,
        ));
    }

    /// Unconditional branch.
    fn emit_branch(&mut self, target: Address) {
        self.emit_op(PcodeOperation::new(
            OpCode::BRANCH,
            None,
            vec![Varnode::constant(target.offset, 8)],
            Some(target),
        ));
    }

    /// Conditional branch.
    fn emit_cbranch(&mut self, cond: Varnode, target: Address) {
        self.emit_op(PcodeOperation::new(
            OpCode::CBRANCH,
            None,
            vec![Varnode::constant(target.offset, 8), cond],
            Some(target),
        ));
    }

    /// Indirect branch.
    fn emit_branchind(&mut self, target: Varnode) {
        self.emit_op(PcodeOperation::new(
            OpCode::BRANCHIND,
            None,
            vec![target],
            None,
        ));
    }

    /// Direct call.
    fn emit_call(
        &mut self,
        target: Address,
        inputs: &[Varnode],
        output: Option<Varnode>,
    ) {
        let mut args = vec![Varnode::constant(target.offset, 8)];
        args.extend_from_slice(inputs);
        self.emit_op(PcodeOperation::new(
            OpCode::CALL,
            output,
            args,
            Some(target),
        ));
    }

    /// Indirect call.
    fn emit_callind(
        &mut self,
        target: Varnode,
        inputs: &[Varnode],
        output: Option<Varnode>,
    ) {
        let mut args = vec![target];
        args.extend_from_slice(inputs);
        self.emit_op(PcodeOperation::new(
            OpCode::CALLIND,
            output,
            args,
            None,
        ));
    }

    /// `return [value]`
    fn emit_return(&mut self, value: Option<Varnode>, addr: Option<Address>) {
        let inputs = value.into_iter().collect();
        self.emit_op(PcodeOperation::new(
            OpCode::RETURN,
            None,
            inputs,
            addr,
        ));
    }

    /// `out = in0 + in1`
    fn emit_int_add(
        &mut self,
        output: Varnode,
        lhs: Varnode,
        rhs: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::INT_ADD,
            Some(output),
            vec![lhs, rhs],
            addr,
        ));
    }

    /// `out = in0 - in1`
    fn emit_int_sub(
        &mut self,
        output: Varnode,
        lhs: Varnode,
        rhs: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::INT_SUB,
            Some(output),
            vec![lhs, rhs],
            addr,
        ));
    }

    /// `out = in0 * in1`
    fn emit_int_mul(
        &mut self,
        output: Varnode,
        lhs: Varnode,
        rhs: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::INT_MUL,
            Some(output),
            vec![lhs, rhs],
            addr,
        ));
    }

    /// `out = in0 / in1` (unsigned)
    fn emit_int_div(
        &mut self,
        output: Varnode,
        lhs: Varnode,
        rhs: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::INT_DIV,
            Some(output),
            vec![lhs, rhs],
            addr,
        ));
    }

    /// `out = in0 /s in1` (signed)
    fn emit_int_sdiv(
        &mut self,
        output: Varnode,
        lhs: Varnode,
        rhs: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::INT_SDIV,
            Some(output),
            vec![lhs, rhs],
            addr,
        ));
    }

    /// `out = in0 % in1` (unsigned)
    fn emit_int_rem(
        &mut self,
        output: Varnode,
        lhs: Varnode,
        rhs: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::INT_REM,
            Some(output),
            vec![lhs, rhs],
            addr,
        ));
    }

    /// `out = in0 %s in1` (signed)
    fn emit_int_srem(
        &mut self,
        output: Varnode,
        lhs: Varnode,
        rhs: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::INT_SREM,
            Some(output),
            vec![lhs, rhs],
            addr,
        ));
    }

    /// `out = in0 & in1`
    fn emit_int_and(
        &mut self,
        output: Varnode,
        lhs: Varnode,
        rhs: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::INT_AND,
            Some(output),
            vec![lhs, rhs],
            addr,
        ));
    }

    /// `out = in0 | in1`
    fn emit_int_or(
        &mut self,
        output: Varnode,
        lhs: Varnode,
        rhs: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::INT_OR,
            Some(output),
            vec![lhs, rhs],
            addr,
        ));
    }

    /// `out = in0 ^ in1`
    fn emit_int_xor(
        &mut self,
        output: Varnode,
        lhs: Varnode,
        rhs: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::INT_XOR,
            Some(output),
            vec![lhs, rhs],
            addr,
        ));
    }

    /// `out = in0 << in1`
    fn emit_int_left(
        &mut self,
        output: Varnode,
        lhs: Varnode,
        rhs: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::INT_LEFT,
            Some(output),
            vec![lhs, rhs],
            addr,
        ));
    }

    /// `out = in0 >> in1` (logical)
    fn emit_int_right(
        &mut self,
        output: Varnode,
        lhs: Varnode,
        rhs: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::INT_RIGHT,
            Some(output),
            vec![lhs, rhs],
            addr,
        ));
    }

    /// `out = in0 >>> in1` (arithmetic)
    fn emit_int_sright(
        &mut self,
        output: Varnode,
        lhs: Varnode,
        rhs: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::INT_SRIGHT,
            Some(output),
            vec![lhs, rhs],
            addr,
        ));
    }

    /// `out = sext(in0)`
    fn emit_int_sext(
        &mut self,
        output: Varnode,
        input: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::INT_SEXT,
            Some(output),
            vec![input],
            addr,
        ));
    }

    /// `out = zext(in0)`
    fn emit_int_zext(
        &mut self,
        output: Varnode,
        input: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::INT_ZEXT,
            Some(output),
            vec![input],
            addr,
        ));
    }

    /// `out = -in0`
    fn emit_int_negate(
        &mut self,
        output: Varnode,
        input: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::INT_NEGATE,
            Some(output),
            vec![input],
            addr,
        ));
    }

    /// `out = (in0 == in1) ? 1 : 0`
    fn emit_int_equal(
        &mut self,
        output: Varnode,
        lhs: Varnode,
        rhs: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::INT_EQUAL,
            Some(output),
            vec![lhs, rhs],
            addr,
        ));
    }

    /// `out = (in0 != in1) ? 1 : 0`
    fn emit_int_not_equal(
        &mut self,
        output: Varnode,
        lhs: Varnode,
        rhs: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::INT_NOTEQUAL,
            Some(output),
            vec![lhs, rhs],
            addr,
        ));
    }

    /// `out = (in0 < in1) ? 1 : 0`  (unsigned)
    fn emit_int_less(
        &mut self,
        output: Varnode,
        lhs: Varnode,
        rhs: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::INT_LESS,
            Some(output),
            vec![lhs, rhs],
            addr,
        ));
    }

    /// `out = (in0 <= in1) ? 1 : 0`  (unsigned)
    fn emit_int_less_equal(
        &mut self,
        output: Varnode,
        lhs: Varnode,
        rhs: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::INT_LESSEQUAL,
            Some(output),
            vec![lhs, rhs],
            addr,
        ));
    }

    /// `out = (in0 <s in1) ? 1 : 0`  (signed)
    fn emit_int_sless(
        &mut self,
        output: Varnode,
        lhs: Varnode,
        rhs: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::INT_SLESS,
            Some(output),
            vec![lhs, rhs],
            addr,
        ));
    }

    /// `out = (in0 <=s in1) ? 1 : 0`  (signed)
    fn emit_int_sless_equal(
        &mut self,
        output: Varnode,
        lhs: Varnode,
        rhs: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::INT_SLESSEQUAL,
            Some(output),
            vec![lhs, rhs],
            addr,
        ));
    }

    /// `out = !in0`
    fn emit_bool_negate(
        &mut self,
        output: Varnode,
        input: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::BOOL_NEGATE,
            Some(output),
            vec![input],
            addr,
        ));
    }

    /// `out = in0 && in1`
    fn emit_bool_and(
        &mut self,
        output: Varnode,
        lhs: Varnode,
        rhs: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::BOOL_AND,
            Some(output),
            vec![lhs, rhs],
            addr,
        ));
    }

    /// `out = in0 || in1`
    fn emit_bool_or(
        &mut self,
        output: Varnode,
        lhs: Varnode,
        rhs: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::BOOL_OR,
            Some(output),
            vec![lhs, rhs],
            addr,
        ));
    }

    /// `out = (cast)in0`
    fn emit_cast(
        &mut self,
        output: Varnode,
        input: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::CAST,
            Some(output),
            vec![input],
            addr,
        ));
    }

    /// `out = in0 || in1`  (concatenation; `in0` = most-significant)
    fn emit_piece(
        &mut self,
        output: Varnode,
        hi: Varnode,
        lo: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::PIECE,
            Some(output),
            vec![hi, lo],
            addr,
        ));
    }

    /// `out = in0[low..]`
    fn emit_subpiece(
        &mut self,
        output: Varnode,
        input: Varnode,
        low_byte: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::SUBPIECE,
            Some(output),
            vec![input, low_byte],
            addr,
        ));
    }

    /// `out = in0 + (in1 * in2)`  (base + index * scale)
    fn emit_ptr_add(
        &mut self,
        output: Varnode,
        base: Varnode,
        index: Varnode,
        scale: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::PTRADD,
            Some(output),
            vec![base, index, scale],
            addr,
        ));
    }

    /// `out = in0 - in1`  (pointer subtraction)
    fn emit_ptr_sub(
        &mut self,
        output: Varnode,
        lhs: Varnode,
        rhs: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::PTRSUB,
            Some(output),
            vec![lhs, rhs],
            addr,
        ));
    }

    /// Emit a phi-node (SSA form): `out = phi(in0, in1, ...)`
    fn emit_multi_equal(
        &mut self,
        output: Varnode,
        inputs: Vec<Varnode>,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::MULTIEQUAL,
            Some(output),
            inputs,
            addr,
        ));
    }

    /// `out = in0` with an indirect effect annotation.
    fn emit_indirect(
        &mut self,
        output: Varnode,
        input: Varnode,
        addr: Option<Address>,
    ) {
        self.emit_op(PcodeOperation::new(
            OpCode::INDIRECT,
            Some(output),
            vec![input],
            addr,
        ));
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A simple P-code collector for testing.
    struct Collector(Vec<PcodeOperation>);

    impl PcodeEmitter for Collector {
        fn emit_op(&mut self, op: PcodeOperation) {
            self.0.push(op);
        }
    }

    #[test]
    fn test_emitter_int_add() {
        let mut c = Collector(Vec::new());
        let out = Varnode::unique(0, 4);
        let x = Varnode::register("r0", 0, 4);
        let y = Varnode::register("r1", 1, 4);
        c.emit_int_add(out.clone(), x, y, None);
        assert_eq!(c.0.len(), 1);
        assert_eq!(c.0[0].opcode, OpCode::INT_ADD);
        assert_eq!(c.0[0].output, Some(out));
    }

    #[test]
    fn test_emitter_copy() {
        let mut c = Collector(Vec::new());
        let out = Varnode::unique(0, 4);
        let inp = Varnode::register("eax", 0, 4);
        c.emit_copy(out.clone(), inp.clone(), None);
        assert_eq!(c.0.len(), 1);
        assert_eq!(c.0[0].opcode, OpCode::COPY);
        assert!(c.0[0].uses(&inp));
    }

    #[test]
    fn test_emitter_store() {
        let mut c = Collector(Vec::new());
        let space = Varnode::constant(0, 4); // ram space id
        let ptr = Varnode::register("rsp", 0, 8);
        let val = Varnode::register("eax", 0, 4);
        c.emit_store(space.clone(), ptr.clone(), val.clone(), None);
        assert_eq!(c.0.len(), 1);
        assert_eq!(c.0[0].opcode, OpCode::STORE);
        assert_eq!(c.0[0].output, None);
        assert_eq!(c.0[0].inputs.len(), 3);
    }

    #[test]
    fn test_emitter_branch() {
        let mut c = Collector(Vec::new());
        let target = Address::new(0x2000);
        c.emit_branch(target);
        assert_eq!(c.0.len(), 1);
        assert_eq!(c.0[0].opcode, OpCode::BRANCH);
        assert_eq!(c.0[0].address, Some(target));
    }

    #[test]
    fn test_emitter_cbranch() {
        let mut c = Collector(Vec::new());
        let cond = Varnode::register("flags", 0, 1);
        let target = Address::new(0x3000);
        c.emit_cbranch(cond.clone(), target);
        assert_eq!(c.0.len(), 1);
        assert_eq!(c.0[0].opcode, OpCode::CBRANCH);
        assert!(c.0[0].uses(&cond));
    }

    #[test]
    fn test_emitter_call() {
        let mut c = Collector(Vec::new());
        let target = Address::new(0x4000);
        let ret = Varnode::register("eax", 0, 4);
        c.emit_call(target, &[], Some(ret.clone()));
        assert_eq!(c.0.len(), 1);
        assert_eq!(c.0[0].opcode, OpCode::CALL);
        assert_eq!(c.0[0].output, Some(ret));
    }

    #[test]
    fn test_emitter_return() {
        let mut c = Collector(Vec::new());
        c.emit_return(None, None);
        assert_eq!(c.0.len(), 1);
        assert_eq!(c.0[0].opcode, OpCode::RETURN);
        assert!(c.0[0].inputs.is_empty());
    }

    #[test]
    fn test_construct_sem_trait() {
        /// A trivial constructor that emits a NOP (copy of a constant to
        /// itself is effectively a no-op but valid P-code).
        struct NopConstructor;

        impl ConstructSem for NopConstructor {
            fn construct(&self, emitter: &mut dyn PcodeEmitter) {
                let v = Varnode::unique(0, 1);
                emitter.emit_copy(v.clone(), Varnode::constant(0, 1), None);
            }

            fn label(&self) -> &str {
                "nop"
            }

            fn length(&self) -> Option<u32> {
                Some(1)
            }
        }

        let mut c = Collector(Vec::new());
        let sem = NopConstructor;
        sem.construct(&mut c);
        assert_eq!(c.0.len(), 1);
        assert_eq!(c.0[0].opcode, OpCode::COPY);
        assert_eq!(sem.label(), "nop");
        assert_eq!(sem.length(), Some(1));
    }
}
