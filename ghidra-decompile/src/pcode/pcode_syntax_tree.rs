//! PcodeSyntaxTree and PcodeFactory - the AST container.
//!
//! Ports Ghidra's `PcodeSyntaxTree` (implements `PcodeFactory`) which
//! is the coherent graph structure holding Varnodes and PcodeOps, and
//! provides the factory interface for creating them.

use super::blocks::PcodeBlockBasic;
use super::high_level::HighSymbol;
use super::operation::{PcodeOperation, Varnode};
use super::opcodes::OpCode;
use super::sequence::SequenceNumber;
use ghidra_core::addr::Address;
use std::collections::HashMap;

// ============================================================================
// PcodeFactory trait
// ============================================================================

/// Interface for classes that build PcodeOps and Varnodes.
///
/// This is the Rust equivalent of Ghidra's `PcodeFactory` interface.
pub trait PcodeFactory {
    /// Create a new Varnode with the given size and address.
    fn new_varnode(&mut self, size: u32, address: Address) -> u64;

    /// Create a new Varnode with a specific reference id.
    fn new_varnode_with_id(&mut self, size: u32, address: Address, ref_id: u64) -> u64;

    /// Get a Varnode by reference id.
    fn get_ref(&self, ref_id: u64) -> Option<&Varnode>;

    /// Get a PcodeOp by reference id.
    fn get_op_ref(&self, ref_id: u64) -> Option<&PcodeOperation>;

    /// Get a HighSymbol by id.
    fn get_symbol(&self, symbol_id: u64) -> Option<&HighSymbol>;

    /// Create a new PcodeOp.
    fn new_op(
        &mut self,
        seqnum: SequenceNumber,
        opcode: OpCode,
        inputs: Vec<Varnode>,
        output: Option<Varnode>,
    ) -> u64;
}

// ============================================================================
// VarnodeAST - a varnode in the AST with def-use tracking
// ============================================================================

/// A Varnode in the Abstract Syntax Tree with def-use edges.
///
/// Extends the basic Varnode with information about the PcodeOp that
/// defines it (in-edge) and the PcodeOps that use it (out-edges).
#[derive(Debug, Clone)]
pub struct VarnodeAST {
    /// The basic varnode data.
    pub varnode: Varnode,
    /// Unique id for distinguishing otherwise identical varnodes.
    pub unique_id: u64,
    /// Whether this is an input to the function.
    pub is_input: bool,
    /// Whether this varnode is address-tied.
    pub is_addr_tied: bool,
    /// Whether this varnode is persistent.
    pub is_persistent: bool,
    /// Whether this varnode is unaffected.
    pub is_unaffected: bool,
    /// Whether this varnode is free (not part of the AST).
    pub is_free: bool,
    /// Forced merge group within this varnode's high.
    pub merge_group: i16,
    /// Index of the PcodeOp that defines this varnode (in-edge).
    pub def_op: Option<usize>,
    /// Indices of PcodeOps that use this varnode (out-edges).
    pub descendants: Vec<usize>,
    /// Associated high variable id (index into HighFunction.high_variables).
    pub high_variable: Option<usize>,
}

impl VarnodeAST {
    /// Create a new VarnodeAST.
    pub fn new(varnode: Varnode, unique_id: u64) -> Self {
        Self {
            varnode,
            unique_id,
            is_input: false,
            is_addr_tied: false,
            is_persistent: false,
            is_unaffected: false,
            is_free: true,
            merge_group: 0,
            def_op: None,
            descendants: Vec::new(),
            high_variable: None,
        }
    }

    /// Returns true if this varnode is free (not attached to the AST).
    pub fn is_free(&self) -> bool {
        self.is_free
    }

    /// Returns true if this is an input varnode.
    pub fn is_input(&self) -> bool {
        self.is_input
    }

    /// Returns true if this varnode is address-tied.
    pub fn is_addr_tied(&self) -> bool {
        self.is_addr_tied
    }

    /// Returns true if this varnode is persistent.
    pub fn is_persistent(&self) -> bool {
        self.is_persistent
    }

    /// Returns true if this varnode is unaffected.
    pub fn is_unaffected(&self) -> bool {
        self.is_unaffected
    }

    /// Get the defining PcodeOp index.
    pub fn get_def(&self) -> Option<usize> {
        self.def_op
    }

    /// Get the descendants (PcodeOps that use this varnode).
    pub fn get_descendants(&self) -> &[usize] {
        &self.descendants
    }

    /// Get the lone descendant, if there is exactly one.
    pub fn get_lone_descend(&self) -> Option<usize> {
        if self.descendants.len() == 1 {
            self.descendants.first().copied()
        } else {
            None
        }
    }

    /// Returns true if no PcodeOps use this varnode.
    pub fn has_no_descend(&self) -> bool {
        self.descendants.is_empty()
    }

    /// Get the unique id.
    pub fn get_unique_id(&self) -> u64 {
        self.unique_id
    }

    /// Get the merge group.
    pub fn get_merge_group(&self) -> i16 {
        self.merge_group
    }

    /// Set the merge group.
    pub fn set_merge_group(&mut self, val: i16) {
        self.merge_group = val;
    }

    /// Set whether this is address-tied.
    pub fn set_addr_tied(&mut self, val: bool) {
        self.is_addr_tied = val;
    }

    /// Set whether this is an input.
    pub fn set_input(&mut self, val: bool) {
        self.is_input = val;
        if val {
            self.is_free = false;
            self.def_op = None;
        }
    }

    /// Set whether this is persistent.
    pub fn set_persistent(&mut self, val: bool) {
        self.is_persistent = val;
    }

    /// Set whether this is unaffected.
    pub fn set_unaffected(&mut self, val: bool) {
        self.is_unaffected = val;
    }

    /// Set whether this is free.
    pub fn set_free(&mut self, val: bool) {
        self.is_free = val;
    }

    /// Set the defining PcodeOp.
    pub fn set_def(&mut self, op: Option<usize>) {
        self.def_op = op;
        if op.is_some() {
            self.is_free = false;
            self.is_input = false;
        }
    }

    /// Add a descendant PcodeOp.
    pub fn add_descendant(&mut self, op: usize) {
        self.descendants.push(op);
    }

    /// Remove a descendant PcodeOp.
    pub fn remove_descendant(&mut self, op: usize) {
        self.descendants.retain(|&x| x != op);
    }

    /// Set the associated high variable.
    pub fn set_high(&mut self, high_idx: Option<usize>) {
        self.high_variable = high_idx;
    }

    /// Get the associated high variable.
    pub fn get_high(&self) -> Option<usize> {
        self.high_variable
    }

    /// Replace all references to another VarnodeAST with this one.
    pub fn descend_replace(
        &mut self,
        _other_idx: usize,
        _other_descendants: &[usize],
        _ops: &mut [PcodeOpAST],
        self_idx: usize,
    ) {
        for &op_idx in _other_descendants {
            if let Some(op) = _ops.get_mut(op_idx) {
                // Skip if this varnode is the output of the op (can't be input to own definition)
                if op.output == Some(_other_idx) {
                    continue;
                }
                // Replace the other varnode in the op's inputs
                for inp in op.inputs.iter_mut() {
                    if *inp == _other_idx {
                        *inp = self_idx;
                        self.descendants.push(op_idx);
                        break;
                    }
                }
            }
        }
    }
}

// ============================================================================
// PcodeOpAST - a PcodeOp in the AST
// ============================================================================

/// A PcodeOp in the Abstract Syntax Tree with parent block tracking.
#[derive(Debug, Clone)]
pub struct PcodeOpAST {
    /// The sequence number (address + time).
    pub seqnum: SequenceNumber,
    /// The opcode.
    pub opcode: OpCode,
    /// Input varnode indices (into the varnode bank).
    pub inputs: Vec<usize>,
    /// Output varnode index (into the varnode bank).
    pub output: Option<usize>,
    /// Whether this operation is currently dead (not in the syntax tree).
    pub is_dead: bool,
    /// Index of the parent basic block.
    pub parent_block: Option<usize>,
    /// Position within the basic block.
    pub order: i32,
}

impl PcodeOpAST {
    /// Create a new PcodeOpAST.
    pub fn new(seqnum: SequenceNumber, opcode: OpCode, num_inputs: usize) -> Self {
        Self {
            seqnum,
            opcode,
            inputs: vec![usize::MAX; num_inputs],
            output: None,
            is_dead: true,
            parent_block: None,
            order: 0,
        }
    }

    /// Returns true if this op is dead.
    pub fn is_dead(&self) -> bool {
        self.is_dead
    }

    /// Get the parent basic block index.
    pub fn get_parent(&self) -> Option<usize> {
        self.parent_block
    }

    /// Set the parent basic block.
    pub fn set_parent(&mut self, block: Option<usize>) {
        self.parent_block = block;
    }

    /// Get the opcode.
    pub fn get_opcode(&self) -> OpCode {
        self.opcode
    }

    /// Set the opcode.
    pub fn set_opcode(&mut self, opc: OpCode) {
        self.opcode = opc;
    }

    /// Get the sequence number.
    pub fn get_seqnum(&self) -> &SequenceNumber {
        &self.seqnum
    }

    /// Get the number of inputs.
    pub fn get_num_inputs(&self) -> usize {
        self.inputs.len()
    }

    /// Get an input varnode index.
    pub fn get_input(&self, i: usize) -> Option<usize> {
        self.inputs.get(i).copied()
    }

    /// Set an input varnode index.
    pub fn set_input(&mut self, i: usize, vn_idx: usize) {
        if i >= self.inputs.len() {
            self.inputs.resize(i + 1, usize::MAX);
        }
        self.inputs[i] = vn_idx;
    }

    /// Get the output varnode index.
    pub fn get_output(&self) -> Option<usize> {
        self.output
    }

    /// Set the output varnode index.
    pub fn set_output(&mut self, vn_idx: Option<usize>) {
        self.output = vn_idx;
    }

    /// Set the order within the basic block.
    pub fn set_order(&mut self, ord: i32) {
        self.order = ord;
    }

    /// Get the order.
    pub fn get_order(&self) -> i32 {
        self.order
    }

    /// Returns true if this operation has an output.
    pub fn is_assignment(&self) -> bool {
        self.output.is_some()
    }
}

// ============================================================================
// PcodeOpBank - container for PcodeOpASTs
// ============================================================================

/// Container for PcodeOpASTs, sorted by SequenceNumber.
#[derive(Debug, Clone)]
pub struct PcodeOpBank {
    /// All ops sorted by SequenceNumber, indexed by (time) for lookup.
    pub ops: Vec<PcodeOpAST>,
    /// Map from seqnum time to op index.
    pub time_to_index: HashMap<i32, usize>,
    /// Indices of alive ops.
    pub alive: Vec<usize>,
    /// Indices of dead ops.
    pub dead: Vec<usize>,
    /// Next unique time index.
    pub next_unique: i32,
}

impl PcodeOpBank {
    /// Create a new empty op bank.
    pub fn new() -> Self {
        Self {
            ops: Vec::new(),
            time_to_index: HashMap::new(),
            alive: Vec::new(),
            dead: Vec::new(),
            next_unique: 0,
        }
    }

    /// Get the size (number of ops).
    pub fn size(&self) -> usize {
        self.ops.len()
    }

    /// Returns true if the bank is empty.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Create a new PcodeOpAST.
    pub fn create(&mut self, opcode: OpCode, num_inputs: usize, address: Address) -> usize {
        let time = self.next_unique;
        self.next_unique += 1;
        let seqnum = SequenceNumber::new(address, time);
        let mut op = PcodeOpAST::new(seqnum, opcode, num_inputs);
        let idx = self.ops.len();
        op.is_dead = true;
        self.ops.push(op);
        self.dead.push(idx);
        self.time_to_index.insert(time, idx);
        idx
    }

    /// Create a new PcodeOpAST with a specific SequenceNumber.
    pub fn create_with_seqnum(&mut self, opcode: OpCode, num_inputs: usize, sq: SequenceNumber) -> usize {
        if sq.time >= self.next_unique {
            self.next_unique = sq.time + 1;
        }
        let time = sq.time;
        let mut op = PcodeOpAST::new(sq, opcode, num_inputs);
        let idx = self.ops.len();
        op.is_dead = true;
        self.ops.push(op);
        self.dead.push(idx);
        self.time_to_index.insert(time, idx);
        idx
    }

    /// Mark an op as alive.
    pub fn mark_alive(&mut self, idx: usize) {
        if let Some(op) = self.ops.get_mut(idx) {
            op.is_dead = false;
        }
        self.dead.retain(|&x| x != idx);
        if !self.alive.contains(&idx) {
            self.alive.push(idx);
        }
    }

    /// Mark an op as dead.
    pub fn mark_dead(&mut self, idx: usize) {
        if let Some(op) = self.ops.get_mut(idx) {
            op.is_dead = true;
        }
        self.alive.retain(|&x| x != idx);
        if !self.dead.contains(&idx) {
            self.dead.push(idx);
        }
    }

    /// Destroy an op (remove from the bank).
    pub fn destroy(&mut self, idx: usize) {
        if let Some(op) = self.ops.get(idx) {
            if !op.is_dead {
                return; // Should throw exception in Java; skip in Rust
            }
            self.dead.retain(|&x| x != idx);
            self.alive.retain(|&x| x != idx);
            // Mark as destroyed (set opcode to UNIMPLEMENTED)
            if let Some(op) = self.ops.get_mut(idx) {
                op.opcode = OpCode::UNIMPLEMENTED;
            }
        }
    }

    /// Change the opcode of an op.
    pub fn change_opcode(&mut self, idx: usize, new_opc: OpCode) {
        if let Some(op) = self.ops.get_mut(idx) {
            op.opcode = new_opc;
        }
    }

    /// Find an op by SequenceNumber.
    pub fn find_op(&self, sq: &SequenceNumber) -> Option<usize> {
        self.time_to_index.get(&sq.time).copied()
    }

    /// Get all ops in SequenceNumber order.
    pub fn all_ordered(&self) -> impl Iterator<Item = (usize, &PcodeOpAST)> {
        self.ops.iter().enumerate()
    }

    /// Get all ops at a specific address.
    pub fn all_ordered_at(&self, address: Address) -> Vec<(usize, &PcodeOpAST)> {
        self.ops
            .iter()
            .enumerate()
            .filter(|(_, op)| op.seqnum.address == address)
            .collect()
    }

    /// Get all alive ops.
    pub fn all_alive(&self) -> &[usize] {
        &self.alive
    }

    /// Get all dead ops.
    pub fn all_dead(&self) -> &[usize] {
        &self.dead
    }

    /// Clear the bank.
    pub fn clear(&mut self) {
        self.ops.clear();
        self.time_to_index.clear();
        self.alive.clear();
        self.dead.clear();
        self.next_unique = 0;
    }
}

impl Default for PcodeOpBank {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// VarnodeBank - container for VarnodeASTs
// ============================================================================

/// Container for VarnodeASTs, sorted by location.
#[derive(Debug, Clone)]
pub struct VarnodeBank {
    /// All varnodes.
    pub varnodes: Vec<VarnodeAST>,
    /// Map from unique_id to varnode index.
    pub id_to_index: HashMap<u64, usize>,
    /// Next unique id.
    pub next_unique_id: u64,
}

impl VarnodeBank {
    /// Create a new empty varnode bank.
    pub fn new() -> Self {
        Self {
            varnodes: Vec::new(),
            id_to_index: HashMap::new(),
            next_unique_id: 0,
        }
    }

    /// Get the size (number of varnodes).
    pub fn size(&self) -> usize {
        self.varnodes.len()
    }

    /// Returns true if the bank is empty.
    pub fn is_empty(&self) -> bool {
        self.varnodes.is_empty()
    }

    /// Create a new VarnodeAST.
    pub fn create(&mut self, size: u32, address: Address, id: u64) -> usize {
        use ghidra_core::addr::{AddrSpaceType, AddressSpace};
        let space = AddressSpace::new("ram", 8, false, AddrSpaceType::Ram, 1);
        let vn = Varnode::new(space, address.offset, size);
        let vn_ast = VarnodeAST::new(vn, id);
        let idx = self.varnodes.len();
        self.varnodes.push(vn_ast);
        self.id_to_index.insert(id, idx);
        if id >= self.next_unique_id {
            self.next_unique_id = id + 1;
        }
        idx
    }

    /// Find a varnode by id.
    pub fn find_by_id(&self, id: u64) -> Option<usize> {
        self.id_to_index.get(&id).copied()
    }

    /// Get a varnode by index.
    pub fn get(&self, idx: usize) -> Option<&VarnodeAST> {
        self.varnodes.get(idx)
    }

    /// Get a mutable varnode by index.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut VarnodeAST> {
        self.varnodes.get_mut(idx)
    }

    /// Make a varnode free (clear def-use info).
    pub fn make_free(&mut self, idx: usize) {
        if let Some(vn) = self.varnodes.get_mut(idx) {
            vn.def_op = None;
            vn.is_input = false;
            vn.is_free = true;
        }
    }

    /// Set a varnode as an input.
    pub fn set_input(&mut self, idx: usize) {
        if let Some(vn) = self.varnodes.get_mut(idx) {
            if vn.is_free && !vn.varnode.is_constant() {
                vn.is_input = true;
                vn.is_free = false;
            }
        }
    }

    /// Set the defining PcodeOp for a varnode.
    pub fn set_def(&mut self, vn_idx: usize, op_idx: usize) {
        if let Some(vn) = self.varnodes.get_mut(vn_idx) {
            if vn.is_free && !vn.varnode.is_constant() {
                vn.def_op = Some(op_idx);
                vn.is_free = false;
            }
        }
    }

    /// Clear the bank.
    pub fn clear(&mut self) {
        self.varnodes.clear();
        self.id_to_index.clear();
        self.next_unique_id = 0;
    }
}

impl Default for VarnodeBank {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// PcodeSyntaxTree
// ============================================================================

/// Varnodes and PcodeOps in a coherent graph structure.
///
/// This is the Rust equivalent of Ghidra's `PcodeSyntaxTree`.
/// It contains the varnode bank, op bank, basic blocks, and provides
/// the factory interface for creating and manipulating the AST.
#[derive(Debug, Clone)]
pub struct PcodeSyntaxTree {
    /// The varnode bank.
    pub vbank: VarnodeBank,
    /// The op bank.
    pub opbank: PcodeOpBank,
    /// Basic blocks.
    pub bblocks: Vec<PcodeBlockBasic>,
    /// Varnode reference map (id -> varnode index).
    pub ref_map: HashMap<u64, usize>,
    /// Op reference map (time -> op index).
    pub op_ref_map: HashMap<i32, usize>,
    /// Next unique id for varnodes.
    pub uniq_id: u64,
}

impl PcodeSyntaxTree {
    /// Create a new empty syntax tree.
    pub fn new() -> Self {
        Self {
            vbank: VarnodeBank::new(),
            opbank: PcodeOpBank::new(),
            bblocks: Vec::new(),
            ref_map: HashMap::new(),
            op_ref_map: HashMap::new(),
            uniq_id: 0,
        }
    }

    /// Clear all data.
    pub fn clear(&mut self) {
        self.ref_map.clear();
        self.op_ref_map.clear();
        self.vbank.clear();
        self.opbank.clear();
        self.bblocks.clear();
        self.uniq_id = 0;
    }

    /// Create a new varnode.
    pub fn new_varnode(&mut self, size: u32, address: Address) -> usize {
        let id = self.uniq_id;
        self.uniq_id += 1;
        let idx = self.vbank.create(size, address, id);
        self.ref_map.insert(id, idx);
        idx
    }

    /// Create a new varnode with a specific id.
    pub fn new_varnode_with_id(&mut self, size: u32, address: Address, id: u64) -> usize {
        let idx = self.vbank.create(size, address, id);
        if id >= self.uniq_id {
            self.uniq_id = id + 1;
        }
        self.ref_map.insert(id, idx);
        idx
    }

    /// Get a varnode by reference id.
    pub fn get_ref(&self, id: u64) -> Option<usize> {
        self.ref_map.get(&id).copied()
    }

    /// Get an op by time reference.
    pub fn get_op_ref(&self, time: i32) -> Option<usize> {
        self.op_ref_map.get(&time).copied()
    }

    /// Get the number of varnodes.
    pub fn get_num_varnodes(&self) -> usize {
        self.vbank.size()
    }

    /// Get all basic blocks.
    pub fn get_basic_blocks(&self) -> &[PcodeBlockBasic] {
        &self.bblocks
    }

    /// Get the varnode bank.
    pub fn get_vbank(&self) -> &VarnodeBank {
        &self.vbank
    }

    /// Get the op bank.
    pub fn get_opbank(&self) -> &PcodeOpBank {
        &self.opbank
    }

    /// Insert a new op before another op in the same block.
    pub fn insert_before(&mut self, new_op_idx: usize, follow_idx: usize) {
        if let Some(follow) = self.opbank.ops.get(follow_idx) {
            let block = follow.parent_block;
            if let Some(new_op) = self.opbank.ops.get_mut(new_op_idx) {
                new_op.parent_block = block;
                new_op.is_dead = false;
            }
        }
    }

    /// Insert a new op after another op in the same block.
    pub fn insert_after(&mut self, new_op_idx: usize, prev_idx: usize) {
        if let Some(prev) = self.opbank.ops.get(prev_idx) {
            let block = prev.parent_block;
            if let Some(new_op) = self.opbank.ops.get_mut(new_op_idx) {
                new_op.parent_block = block;
                new_op.is_dead = false;
            }
        }
    }

    /// Set the opcode of an op.
    pub fn set_opcode(&mut self, idx: usize, opc: OpCode) {
        self.opbank.change_opcode(idx, opc);
    }

    /// Set the output of an op.
    pub fn set_output(&mut self, op_idx: usize, vn_idx: usize) {
        // Remove old output def
        if let Some(old_out) = self.opbank.ops.get(op_idx).and_then(|op| op.output) {
            self.vbank.make_free(old_out);
        }
        // Set the new def
        self.vbank.set_def(vn_idx, op_idx);
        // Set the op's output
        if let Some(op) = self.opbank.ops.get_mut(op_idx) {
            op.output = Some(vn_idx);
        }
    }

    /// Unset the output of an op.
    pub fn unset_output(&mut self, op_idx: usize) {
        if let Some(op) = self.opbank.ops.get_mut(op_idx) {
            if let Some(vn_idx) = op.output.take() {
                self.vbank.make_free(vn_idx);
            }
        }
    }

    /// Set an input of an op.
    pub fn set_input(&mut self, op_idx: usize, vn_idx: usize, slot: usize) {
        // Remove old input
        if let Some(old_inp) = self.opbank.ops.get(op_idx).and_then(|op| op.inputs.get(slot)).copied() {
            if old_inp != usize::MAX {
                if let Some(vn) = self.vbank.get_mut(old_inp) {
                    vn.remove_descendant(op_idx);
                }
            }
        }
        // Add new input
        if let Some(vn) = self.vbank.get_mut(vn_idx) {
            vn.add_descendant(op_idx);
        }
        if let Some(op) = self.opbank.ops.get_mut(op_idx) {
            op.set_input(slot, vn_idx);
        }
    }

    /// Unset an input of an op.
    pub fn unset_input(&mut self, op_idx: usize, slot: usize) {
        if let Some(vn_idx) = self.opbank.ops.get(op_idx).and_then(|op| op.inputs.get(slot)).copied() {
            if vn_idx != usize::MAX {
                if let Some(vn) = self.vbank.get_mut(vn_idx) {
                    vn.remove_descendant(op_idx);
                }
            }
        }
        if let Some(op) = self.opbank.ops.get_mut(op_idx) {
            op.set_input(slot, usize::MAX);
        }
    }

    /// Remove an op from its block (but don't destroy it).
    pub fn uninsert(&mut self, op_idx: usize) {
        self.opbank.mark_dead(op_idx);
        if let Some(op) = self.opbank.ops.get_mut(op_idx) {
            op.parent_block = None;
        }
    }

    /// Delete an op entirely.
    pub fn delete(&mut self, op_idx: usize) {
        self.opbank.destroy(op_idx);
    }

    /// Unlink an op (remove all edges and from block).
    pub fn unlink(&mut self, op_idx: usize) {
        self.unset_output(op_idx);
        let num_inputs = self.opbank.ops.get(op_idx).map_or(0, |op| op.inputs.len());
        for i in 0..num_inputs {
            self.unset_input(op_idx, i);
        }
        if self.opbank.ops.get(op_idx).and_then(|op| op.parent_block).is_some() {
            self.uninsert(op_idx);
        }
    }
}

impl Default for PcodeSyntaxTree {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varnode_ast_new() {
        let vn = VarnodeAST::new(Varnode::ram(0x1000, 4), 0);
        assert!(vn.is_free());
        assert!(!vn.is_input());
        assert!(vn.has_no_descend());
        assert_eq!(vn.get_unique_id(), 0);
    }

    #[test]
    fn test_varnode_ast_def_use() {
        let mut vn = VarnodeAST::new(Varnode::ram(0x1000, 4), 0);
        vn.set_def(Some(5));
        assert!(!vn.is_free());
        assert_eq!(vn.get_def(), Some(5));

        vn.add_descendant(10);
        vn.add_descendant(11);
        assert_eq!(vn.get_descendants().len(), 2);
        assert_eq!(vn.get_lone_descend(), None);

        vn.remove_descendant(10);
        assert_eq!(vn.get_lone_descend(), Some(11));
    }

    #[test]
    fn test_varnode_ast_input() {
        let mut vn = VarnodeAST::new(Varnode::register("eax", 0, 4), 1);
        vn.set_input(true);
        assert!(vn.is_input());
        assert!(!vn.is_free());
    }

    #[test]
    fn test_pcode_op_ast_new() {
        let sq = SequenceNumber::new(Address::new(0x1000), 0);
        let op = PcodeOpAST::new(sq, OpCode::INT_ADD, 2);
        assert!(op.is_dead());
        assert_eq!(op.get_num_inputs(), 2);
        assert_eq!(op.get_opcode(), OpCode::INT_ADD);
        assert!(op.is_assignment() == false); // no output yet
    }

    #[test]
    fn test_pcode_op_ast_setters() {
        let sq = SequenceNumber::new(Address::new(0x1000), 0);
        let mut op = PcodeOpAST::new(sq, OpCode::INT_ADD, 2);
        op.set_output(Some(5));
        assert!(op.is_assignment());
        assert_eq!(op.get_output(), Some(5));

        op.set_opcode(OpCode::INT_SUB);
        assert_eq!(op.get_opcode(), OpCode::INT_SUB);
    }

    #[test]
    fn test_pcode_op_bank_create() {
        let mut bank = PcodeOpBank::new();
        let idx = bank.create(OpCode::INT_ADD, 2, Address::new(0x1000));
        assert_eq!(bank.size(), 1);
        assert!(!bank.is_empty());
        assert!(bank.all_dead().contains(&idx));

        bank.mark_alive(idx);
        assert!(bank.all_alive().contains(&idx));
        assert!(!bank.all_dead().contains(&idx));
    }

    #[test]
    fn test_varnode_bank_create() {
        let mut bank = VarnodeBank::new();
        let idx = bank.create(4, Address::new(0x1000), 0);
        assert_eq!(bank.size(), 1);
        assert!(bank.get(idx).is_some());
        assert_eq!(bank.find_by_id(0), Some(idx));
    }

    #[test]
    fn test_varnode_bank_def_use() {
        let mut bank = VarnodeBank::new();
        let vn_idx = bank.create(4, Address::new(0x1000), 0);
        bank.set_def(vn_idx, 5);
        assert_eq!(bank.get(vn_idx).unwrap().get_def(), Some(5));

        bank.make_free(vn_idx);
        assert!(bank.get(vn_idx).unwrap().is_free());
    }

    #[test]
    fn test_pcode_syntax_tree() {
        let mut tree = PcodeSyntaxTree::new();
        let vn_idx = tree.new_varnode(4, Address::new(0x1000));
        assert_eq!(tree.get_num_varnodes(), 1);

        let vn_ref = tree.get_ref(0);
        assert_eq!(vn_ref, Some(vn_idx));
    }

    #[test]
    fn test_pcode_syntax_tree_ops() {
        let mut tree = PcodeSyntaxTree::new();
        let out_vn = tree.new_varnode(4, Address::new(0));
        let in1_vn = tree.new_varnode(4, Address::new(0));
        let in2_vn = tree.new_varnode(4, Address::new(0));

        let op_idx = tree.opbank.create(OpCode::INT_ADD, 2, Address::new(0x1000));
        tree.opbank.mark_alive(op_idx);

        tree.set_output(op_idx, out_vn);
        tree.set_input(op_idx, in1_vn, 0);
        tree.set_input(op_idx, in2_vn, 1);

        let op = &tree.opbank.ops[op_idx];
        assert_eq!(op.output, Some(out_vn));
        assert_eq!(op.inputs[0], in1_vn);
        assert_eq!(op.inputs[1], in2_vn);
    }

    #[test]
    fn test_pcode_syntax_tree_unlink() {
        let mut tree = PcodeSyntaxTree::new();
        let out_vn = tree.new_varnode(4, Address::new(0));

        let op_idx = tree.opbank.create(OpCode::COPY, 1, Address::new(0x1000));
        tree.opbank.mark_alive(op_idx);
        tree.set_output(op_idx, out_vn);
        tree.set_input(op_idx, out_vn, 0);

        tree.unlink(op_idx);
        let op = &tree.opbank.ops[op_idx];
        assert!(op.output.is_none());
        assert!(tree.vbank.get(out_vn).unwrap().is_free());
    }

    #[test]
    fn test_sequence_number() {
        let sq = SequenceNumber::new(Address::new(0x1000), 5);
        assert_eq!(sq.time, 5);
        assert_eq!(sq.address, Address::new(0x1000));
    }
}
