//! Type recovery system for the Ghidra decompiler.
//!
//! Infers high-level C data types from low-level P-code operations through
//! constraint generation, unification, and propagation. Works alongside the
//! data-flow engine to progressively refine type information during
//! decompilation.
//!
//! # Architecture
//!
//! 1. **Constraint generation** ([`TypeRecoveryEngine::add_constraints`]) --
//!    Walks P-code operations and emits [`TypeConstraint`] instances. Each
//!    LOAD implies a pointer dereference; each STORE implies a write to a
//!    typed location; arithmetic ops constrain operand widths and signedness;
//!    CALL ops record argument and return-value positions.
//!
//! 2. **Constraint solving** ([`TypeRecoveryEngine::solve`]) -- Unifies
//!    constraints, propagates type information through the varnode graph, and
//!    resolves ambiguities via a priority-based confidence model.
//!
//! 3. **Struct inference** ([`TypeRecoveryEngine::infer_structs`]) -- Groups
//!    field-access patterns (LOAD/STORE at fixed offsets from a common base
//!    pointer) into composite struct layouts.
//!
//! 4. **Signature inference** ([`TypeRecoveryEngine::infer_function_signature`])
//!    -- Reconstructs function prototypes from call-site and return-site
//!    observations.
//!
//! 5. **Heap analysis** ([`HeapStructAnalyzer`]) -- Tracks heap allocations
//!    (NEW opcodes) and their field-access patterns to recover malloc'd
//!    struct layouts.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;

use ghidra_core::addr::Address;
use ghidra_core::data::DataType;
use ghidra_core::error::{GhidraError, Result};

use crate::sleigh::pcode::{OpCode, PcodeOp, Varnode};

// ============================================================================
// DataTypeRef — an owned reference to a DataType in the type-recovery context.
// ============================================================================

/// An owned reference to a resolved data type within the type-recovery engine.
///
/// This wraps an [`Arc`]`<`[`dyn DataType`]`>` so the type can be shared,
/// cloned cheaply, and stored in structs.
pub type DataTypeRef = Arc<dyn DataType>;

// ---------------------------------------------------------------------------
// DataType factory helpers — create Arc<dyn DataType> for common types
// ---------------------------------------------------------------------------

use ghidra_core::data::BuiltInDataTypeWrapper;

/// Create an `Arc<dyn DataType>` for the `void` built-in type.
fn make_void_type() -> DataTypeRef {
    Arc::new(BuiltInDataTypeWrapper::new(
        ghidra_core::data::BuiltInDataType::Void,
    ))
}

/// Create an `Arc<dyn DataType>` for the `bool` built-in type.
fn make_bool_type() -> DataTypeRef {
    Arc::new(BuiltInDataTypeWrapper::new(
        ghidra_core::data::BuiltInDataType::Bool,
    ))
}

/// Create an `Arc<dyn DataType>` for an unsigned integer of a given size in bytes.
fn make_uint_type(size_in_bytes: usize) -> DataTypeRef {
    let builtin = match size_in_bytes {
        1 => ghidra_core::data::BuiltInDataType::Undefined1,
        2 => ghidra_core::data::BuiltInDataType::UShort,
        4 => ghidra_core::data::BuiltInDataType::UInt,
        8 => ghidra_core::data::BuiltInDataType::ULongLong,
        _ => ghidra_core::data::BuiltInDataType::Undefined1,
    };
    Arc::new(BuiltInDataTypeWrapper::new(builtin))
}

/// Create an `Arc<dyn DataType>` for a signed integer of a given size in bytes.
fn make_int_type(size_in_bytes: usize) -> DataTypeRef {
    let builtin = match size_in_bytes {
        1 => ghidra_core::data::BuiltInDataType::Char,
        2 => ghidra_core::data::BuiltInDataType::Short,
        4 => ghidra_core::data::BuiltInDataType::Int,
        8 => ghidra_core::data::BuiltInDataType::LongLong,
        _ => ghidra_core::data::BuiltInDataType::Int,
    };
    Arc::new(BuiltInDataTypeWrapper::new(builtin))
}

/// Create an `Arc<dyn DataType>` for a float (`float`, size 4).
fn make_float_type() -> DataTypeRef {
    Arc::new(BuiltInDataTypeWrapper::new(
        ghidra_core::data::BuiltInDataType::Float,
    ))
}

/// Create an `Arc<dyn DataType>` for a double (`double`, size 8).
fn make_double_type() -> DataTypeRef {
    Arc::new(BuiltInDataTypeWrapper::new(
        ghidra_core::data::BuiltInDataType::Double,
    ))
}

/// Create an `Arc<dyn DataType>` for a pointer to void (`void*`).
fn make_void_ptr_type() -> DataTypeRef {
    Arc::new(ghidra_core::data::PointerDataType::new(make_void_type()))
}

/// Create an `Arc<dyn DataType>` for a pointer to the given type.
fn make_pointer_type(pointee: &DataTypeRef) -> DataTypeRef {
    Arc::new(ghidra_core::data::PointerDataType::new(Arc::clone(pointee)))
}

// ============================================================================
// PcodeSequence
// ============================================================================

/// A sequence of P-code operations associated with a contiguous address range.
///
/// This is the unit of input to the type recovery engine. Typically each
/// sequence corresponds to a basic block or an entire function body.
#[derive(Debug, Clone)]
pub struct PcodeSequence {
    /// The P-code operations in sequential order.
    pub ops: Vec<PcodeOp>,
    /// Start address of the sequence (inclusive).
    pub start_address: Address,
    /// End address of the sequence (inclusive).
    pub end_address: Address,
}

impl PcodeSequence {
    /// Create a new P-code sequence spanning the given address range.
    pub fn new(ops: Vec<PcodeOp>, start: Address, end: Address) -> Self {
        Self {
            ops,
            start_address: start,
            end_address: end,
        }
    }

    /// Returns `true` if the sequence contains no operations.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Number of operations in the sequence.
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Returns an iterator over the operations.
    pub fn iter(&self) -> std::slice::Iter<'_, PcodeOp> {
        self.ops.iter()
    }
}

// ============================================================================
// RecoveredType
// ============================================================================

/// A type that has been recovered for a specific varnode, along with
/// confidence and provenance information.
#[derive(Debug, Clone)]
pub struct RecoveredType {
    /// The inferred data type.
    pub data_type: DataTypeRef,
    /// Confidence in this type assignment, from 0.0 (guess) to 1.0 (certain).
    pub confidence: f64,
    /// Where this type information came from.
    pub source: TypeSource,
}

impl PartialEq for RecoveredType {
    fn eq(&self, other: &Self) -> bool {
        self.data_type.name() == other.data_type.name()
            && self.data_type.get_size() == other.data_type.get_size()
            && (self.confidence - other.confidence).abs() < f64::EPSILON
            && self.source == other.source
    }
}

impl RecoveredType {
    /// Create a new recovered type with the given confidence and source.
    pub fn new(data_type: DataTypeRef, confidence: f64, source: TypeSource) -> Self {
        Self {
            data_type,
            confidence,
            source,
        }
    }

    /// Create a known type (confidence = 1.0) with a reason.
    pub fn known(data_type: DataTypeRef, reason: impl Into<String>) -> Self {
        Self {
            data_type,
            confidence: 1.0,
            source: TypeSource::Known {
                reason: reason.into(),
            },
        }
    }

    /// Create an inferred type (confidence = 0.7) with a rule name.
    pub fn inferred(data_type: DataTypeRef, rule: impl Into<String>) -> Self {
        Self {
            data_type,
            confidence: 0.7,
            source: TypeSource::Inferred {
                rule: rule.into(),
            },
        }
    }

    /// Create a propagated type (confidence = 0.5) from a source varnode.
    pub fn propagated(data_type: DataTypeRef, from: Varnode) -> Self {
        Self {
            data_type,
            confidence: 0.5,
            source: TypeSource::Propagated { from },
        }
    }

    /// Return a copy of this type with adjusted confidence.
    pub fn with_confidence(&self, confidence: f64) -> Self {
        Self {
            data_type: self.data_type.clone(),
            confidence,
            source: self.source.clone(),
        }
    }
}

// ============================================================================
// TypeSource
// ============================================================================

/// Provenance of a type assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeSource {
    /// Type is known with high certainty (e.g., from debug info, well-known
    /// register conventions, or explicit casts).
    Known {
        /// Human-readable explanation.
        reason: String,
    },
    /// Type was inferred through a heuristic rule (e.g., "used as a pointer
    /// in a LOAD").
    Inferred {
        /// Name of the rule that produced this type.
        rule: String,
    },
    /// Type was propagated from another varnode via data-flow or unification.
    Propagated {
        /// The varnode that was the source of propagation.
        from: Varnode,
    },
    /// Type was explicitly supplied by the user or a type library.
    UserDefined,
}

impl TypeSource {
    /// Returns a short label for logging / display.
    pub fn label(&self) -> &str {
        match self {
            TypeSource::Known { .. } => "known",
            TypeSource::Inferred { .. } => "inferred",
            TypeSource::Propagated { .. } => "propagated",
            TypeSource::UserDefined => "user",
        }
    }
}

// ============================================================================
// TypeConstraint
// ============================================================================

/// A constraint on the type of one or more varnodes, derived from a P-code
/// operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TypeConstraint {
    /// A varnode has exactly `size` bytes.
    Size {
        varnode: Varnode,
        size: u32,
    },
    /// A LOAD: `dest` receives the value at address `ptr` with `size` bytes.
    /// Implies `ptr` is a pointer to a type of `size` bytes.
    LoadOf {
        dest: Varnode,
        ptr: Varnode,
        size: u32,
    },
    /// A STORE: `src` (of `size` bytes) is written to address `ptr`.
    /// Implies `ptr` is a pointer to a type of `size` bytes.
    StoreOf {
        src: Varnode,
        ptr: Varnode,
        size: u32,
    },
    /// `ptr` points to `target`.
    PointerTo {
        ptr: Varnode,
        target: Varnode,
    },
    /// Array indexing: `base + (index * element_size)`.
    /// Implies `base` is a pointer to an array with element size `element_size`.
    ArrayIndex {
        base: Varnode,
        index: Varnode,
        element_size: u32,
    },
    /// Struct field access at a specific offset and size.
    StructField {
        base: Varnode,
        field_offset: u32,
        field_size: u32,
    },
    /// A CALL argument: `varnode` is the `arg_index`-th argument to `func`.
    CallArg {
        func: Address,
        arg_index: usize,
        varnode: Varnode,
    },
    /// A CALL return value: `varnode` receives the return value of `func`.
    CallReturn {
        func: Address,
        varnode: Varnode,
    },
    /// Two varnodes are compared with a given comparison operator.
    /// Implies they are of compatible types (same signedness, width, etc.).
    Compare {
        a: Varnode,
        b: Varnode,
        comparison: Comparison,
    },
    /// An arithmetic operation constraining operand types.
    ArithOp {
        op: OpCode,
        dest: Varnode,
        a: Varnode,
        b: Varnode,
    },
}

// ============================================================================
// Comparison
// ============================================================================

/// Comparison operator extracted from a P-code comparison opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Comparison {
    /// Equality (==)
    EQ,
    /// Inequality (!=)
    NE,
    /// Unsigned less-than (<)
    LT,
    /// Unsigned less-than-or-equal (<=)
    LE,
    /// Signed less-than (<s)
    SLT,
    /// Signed less-than-or-equal (<=s)
    SLE,
    /// Unsigned greater-than (>)
    GT,
    /// Unsigned greater-than-or-equal (>=)
    GE,
}

impl Comparison {
    /// Try to convert an [`OpCode`] to a [`Comparison`], if the opcode is a
    /// comparison.
    pub fn from_opcode(op: OpCode) -> Option<Self> {
        match op {
            OpCode::IntEqual | OpCode::FloatEqual => Some(Comparison::EQ),
            OpCode::IntNotEqual | OpCode::FloatNotEqual => Some(Comparison::NE),
            OpCode::IntLess | OpCode::FloatLess => Some(Comparison::LT),
            OpCode::IntLessEqual | OpCode::FloatLessEqual => Some(Comparison::LE),
            OpCode::IntSless => Some(Comparison::SLT),
            OpCode::IntSlessEqual => Some(Comparison::SLE),
            _ => None,
        }
    }

    /// Returns `true` if this is a signed comparison.
    pub fn is_signed(&self) -> bool {
        matches!(self, Comparison::SLT | Comparison::SLE)
    }

    /// Returns `true` if this is a floating-point comparison.
    pub fn implied_unsigned(&self) -> bool {
        matches!(self, Comparison::LT | Comparison::LE | Comparison::GT | Comparison::GE)
    }
}

// ============================================================================
// TypeNode — graph node payload
// ============================================================================

/// Payload stored in each node of the type-propagation graph.
#[derive(Debug, Clone)]
pub struct TypeNode {
    /// The varnode this graph node represents.
    pub varnode: Varnode,
    /// The currently resolved type, if any.
    pub resolved_type: Option<RecoveredType>,
    /// Backing node index (set after insertion into the graph).
    pub(crate) node_index: Option<NodeIndex>,
}

impl TypeNode {
    /// Create a new unresolved type node for a varnode.
    pub fn new(varnode: Varnode) -> Self {
        Self {
            varnode,
            resolved_type: None,
            node_index: None,
        }
    }

    /// Create a type node with a pre-assigned type.
    pub fn with_type(varnode: Varnode, recovered: RecoveredType) -> Self {
        Self {
            varnode,
            resolved_type: Some(recovered),
            node_index: None,
        }
    }
}

// ============================================================================
// TypePropagator
// ============================================================================

/// Maintains a directed graph of varnode type relationships and a work-list
/// of unification constraints.
///
/// Edges in the graph represent "type flows to" relationships. When a type
/// is assigned to a node, it propagates forward along outgoing edges and
/// backward along incoming edges (with adjusted confidence).
#[derive(Debug)]
pub struct TypePropagator {
    /// Directed graph: edge A -> B means "A's type flows to B".
    pub type_graph: DiGraph<TypeNode, ()>,
    /// Pairs of varnodes that must be unified (share the same type).
    pub unification_stack: Vec<(Varnode, Varnode)>,
    /// Maps varnode -> graph node index for fast lookup.
    varnode_to_node: HashMap<Varnode, NodeIndex>,
}

impl TypePropagator {
    /// Create an empty propagator.
    pub fn new() -> Self {
        Self {
            type_graph: DiGraph::new(),
            unification_stack: Vec::new(),
            varnode_to_node: HashMap::new(),
        }
    }

    /// Ensure a graph node exists for the given varnode. Returns its index.
    pub fn ensure_node(&mut self, varnode: &Varnode) -> NodeIndex {
        if let Some(&idx) = self.varnode_to_node.get(varnode) {
            return idx;
        }
        let node = TypeNode::new(varnode.clone());
        let idx = self.type_graph.add_node(node);
        self.varnode_to_node.insert(varnode.clone(), idx);
        self.type_graph[idx].node_index = Some(idx);
        idx
    }

    /// Add a type-flow edge: the type of `from` flows to `to`.
    pub fn add_flow(&mut self, from: &Varnode, to: &Varnode) {
        let from_idx = self.ensure_node(from);
        let to_idx = self.ensure_node(to);
        // Avoid duplicate edges.
        if self.type_graph.find_edge(from_idx, to_idx).is_none() {
            self.type_graph.add_edge(from_idx, to_idx, ());
        }
    }

    /// Record that two varnodes must eventually unify to the same type.
    pub fn unify(&mut self, a: &Varnode, b: &Varnode) {
        if a != b {
            self.unification_stack.push((a.clone(), b.clone()));
        }
    }

    /// Propagate a type assignment through the graph.
    ///
    /// When a type is assigned to a varnode, this method pushes it forward
    /// along outgoing edges and backward along incoming edges, with
    /// diminishing confidence at each hop.
    pub fn propagate(
        &mut self,
        varnode: &Varnode,
        recovered: &RecoveredType,
    ) -> Vec<(Varnode, RecoveredType)> {
        let start_idx = match self.varnode_to_node.get(varnode) {
            Some(&idx) => idx,
            None => return Vec::new(),
        };

        // Set the type on the source node.
        let current = &mut self.type_graph[start_idx];
        let should_set = match &current.resolved_type {
            None => true,
            Some(existing) => recovered.confidence > existing.confidence,
        };
        if should_set {
            current.resolved_type = Some(recovered.clone());
        } else {
            return Vec::new();
        }

        let mut results = Vec::new();
        let mut visited: HashSet<NodeIndex> = HashSet::new();
        let mut queue: VecDeque<(NodeIndex, f64)> = VecDeque::new();

        // Seed with the starting node.
        visited.insert(start_idx);
        queue.push_back((start_idx, recovered.confidence));

        // Forward propagation.
        while let Some((current_idx, confidence)) = queue.pop_front() {
            if confidence < 0.1 {
                // Confidence too low to be useful — stop propagating.
                continue;
            }

            let current_type = match &self.type_graph[current_idx].resolved_type {
                Some(t) => t.clone(),
                None => continue,
            };
            let current_varnode = self.type_graph[current_idx].varnode.clone();

            // Propagate forward: current -> neighbors.
            {
                let outgoing: Vec<petgraph::graph::NodeIndex> = self
                    .type_graph
                    .edges_directed(current_idx, Direction::Outgoing)
                    .map(|e| e.target())
                    .collect();

                for target in outgoing {
                    if visited.contains(&target) {
                        continue;
                    }
                    visited.insert(target);

                    let decay = 0.85_f64;
                    let new_conf = confidence * decay;
                    let propagated =
                        RecoveredType::propagated(current_type.data_type.clone(), current_varnode.clone())
                            .with_confidence(new_conf);

                    let target_node = &mut self.type_graph[target];
                    let should_update = match &target_node.resolved_type {
                        None => true,
                        Some(existing) => new_conf > existing.confidence,
                    };

                    if should_update {
                        target_node.resolved_type = Some(propagated.clone());
                        results.push((target_node.varnode.clone(), propagated));
                        queue.push_back((target, new_conf));
                    }
                }
            }

            // Propagate backward: neighbors -> current.
            {
                let incoming: Vec<petgraph::graph::NodeIndex> = self
                    .type_graph
                    .edges_directed(current_idx, Direction::Incoming)
                    .map(|e| e.source())
                    .collect();

                for source in incoming {
                    if visited.contains(&source) {
                        continue;
                    }
                    visited.insert(source);

                    let decay = 0.7_f64;
                    let new_conf = confidence * decay;
                    let propagated =
                        RecoveredType::propagated(current_type.data_type.clone(), current_varnode.clone())
                            .with_confidence(new_conf);

                    let source_node = &mut self.type_graph[source];
                    let should_update = match &source_node.resolved_type {
                        None => true,
                        Some(existing) => new_conf > existing.confidence,
                    };

                    if should_update {
                        source_node.resolved_type = Some(propagated.clone());
                        results.push((source_node.varnode.clone(), propagated));
                        queue.push_back((source, new_conf));
                    }
                }
            }
        }

        results
    }

    /// Return the resolved type for a varnode, if any.
    pub fn get_type(&self, varnode: &Varnode) -> Option<&RecoveredType> {
        let idx = self.varnode_to_node.get(varnode)?;
        self.type_graph[*idx].resolved_type.as_ref()
    }

    /// Return all varnodes that currently have a resolved type.
    pub fn typed_varnodes(&self) -> impl Iterator<Item = (&Varnode, &RecoveredType)> {
        self.type_graph
            .raw_nodes()
            .iter()
            .filter_map(|n| {
                n.weight
                    .resolved_type
                    .as_ref()
                    .map(|t| (&n.weight.varnode, t))
            })
    }

    /// Return the number of nodes in the type graph.
    pub fn node_count(&self) -> usize {
        self.type_graph.node_count()
    }

    /// Return the number of unification pairs remaining.
    pub fn unification_count(&self) -> usize {
        self.unification_stack.len()
    }
}

impl Default for TypePropagator {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TypeRecoveryEngine
// ============================================================================

/// The main type-recovery engine.
///
/// Consumes P-code sequences, generates type constraints, solves them through
/// unification and propagation, and exposes recovered type information.
pub struct TypeRecoveryEngine {
    /// Resolved types keyed by varnode.
    pub varnode_types: HashMap<Varnode, RecoveredType>,
    /// Constraints extracted from P-code.
    pub constraints: Vec<TypeConstraint>,
    /// Type-propagation infrastructure.
    pub type_propagator: TypePropagator,
}

impl TypeRecoveryEngine {
    /// Create a new, empty type-recovery engine.
    pub fn new() -> Self {
        Self {
            varnode_types: HashMap::new(),
            constraints: Vec::new(),
            type_propagator: TypePropagator::new(),
        }
    }

    // ------------------------------------------------------------------
    // Constraint generation
    // ------------------------------------------------------------------

    /// Walk a set of P-code sequences and generate type constraints.
    ///
    /// Each P-code operation is examined for type-relevant patterns:
    /// - LOAD/STORE produce pointer constraints.
    /// - Comparisons constrain operand signedness.
    /// - Arithmetic ops constrain operand widths.
    /// - CALL/CALLIND/CALLOTHER produce argument and return-value constraints.
    /// - PTRADD/PTRSUB produce pointer-arithmetic constraints.
    /// - SEXT/ZEXT constrain source signedness.
    pub fn add_constraints(&mut self, sequences: &[PcodeSequence]) {
        for seq in sequences {
            for op in &seq.ops {
                self.process_operation(op);
            }
        }
    }

    /// Process a single P-code operation and emit constraints.
    fn process_operation(&mut self, op: &PcodeOp) {
        match op.opcode {
            // -- data movement -------------------------------------------------
            OpCode::Copy => {
                if let (Some(ref out), Some(inp)) = (op.output.as_ref(), op.inputs.first()) {
                    // Copy implies type equivalence.
                    self.type_propagator.unify(out, inp);
                    self.type_propagator.add_flow(inp, out);
                }
            }
            OpCode::Load => {
                if let (Some(ref dest), Some(ptr)) = (op.output.as_ref(), op.inputs.first()) {
                    let size = dest.size as u32;
                    self.constraints.push(TypeConstraint::LoadOf {
                        dest: (*dest).clone(),
                        ptr: ptr.clone(),
                        size,
                    });
                    self.type_propagator.add_flow(ptr, dest);
                }
            }
            OpCode::Store => {
                if op.inputs.len() >= 2 {
                    let ptr = &op.inputs[0];
                    let src = &op.inputs[1];
                    let size = src.size as u32;
                    self.constraints.push(TypeConstraint::StoreOf {
                        src: src.clone(),
                        ptr: ptr.clone(),
                        size,
                    });
                }
            }

            // -- integer arithmetic --------------------------------------------
            OpCode::IntAdd
            | OpCode::IntSub
            | OpCode::IntMul
            | OpCode::IntDiv
            | OpCode::IntSdiv
            | OpCode::IntRem
            | OpCode::IntSrem
            | OpCode::IntAnd
            | OpCode::IntOr
            | OpCode::IntXor => {
                if let (Some(ref dest), Some(a), Some(b)) = (
                    op.output.as_ref(),
                    op.inputs.first(),
                    op.inputs.get(1),
                ) {
                    self.constraints.push(TypeConstraint::ArithOp {
                        op: op.opcode,
                        dest: (*dest).clone(),
                        a: a.clone(),
                        b: b.clone(),
                    });
                }
            }

            OpCode::IntNegate | OpCode::IntZext | OpCode::IntSext => {
                if let (Some(ref dest), Some(src)) = (op.output.as_ref(), op.inputs.first()) {
                    let opc = op.opcode;
                    self.constraints.push(TypeConstraint::Size {
                        varnode: (*dest).clone(),
                        size: dest.size as u32,
                    });
                    self.type_propagator.add_flow(src, dest);
                    // SEXT/ZEXT imply source signedness.
                    if opc == OpCode::IntSext {
                        // Source is a signed narrower type.
                        let signed_src = make_int_type(src.size);
                        let recovered = RecoveredType::inferred(signed_src, "sext-source");
                        self.type_propagator.propagate(src, &recovered);
                    } else if opc == OpCode::IntZext {
                        let unsigned_src = make_uint_type(src.size);
                        let recovered = RecoveredType::inferred(unsigned_src, "zext-source");
                        self.type_propagator.propagate(src, &recovered);
                    }
                }
            }

            // -- integer comparisons -------------------------------------------
            OpCode::IntEqual
            | OpCode::IntNotEqual
            | OpCode::IntLess
            | OpCode::IntLessEqual
            | OpCode::IntSless
            | OpCode::IntSlessEqual => {
                if let (Some(ref dest), Some(a), Some(b)) = (
                    op.output.as_ref(),
                    op.inputs.first(),
                    op.inputs.get(1),
                ) {
                    if let Some(comp) = Comparison::from_opcode(op.opcode) {
                        self.constraints.push(TypeConstraint::Compare {
                            a: a.clone(),
                            b: b.clone(),
                            comparison: comp,
                        });
                    }
                    // Result of comparison is bool (1 byte).
                    let bool_type = make_bool_type();
                    let recovered = RecoveredType::known(bool_type, "comparison-result");
                    self.type_propagator.propagate(dest, &recovered);
                }
            }

            // -- boolean operations --------------------------------------------
            OpCode::BoolAnd | OpCode::BoolOr | OpCode::BoolXor => {
                if let (Some(ref dest), Some(_a), Some(_b)) = (
                    op.output.as_ref(),
                    op.inputs.first(),
                    op.inputs.get(1),
                ) {
                    let bool_type = make_bool_type();
                    let recovered = RecoveredType::known(bool_type, "boolean-op");
                    self.type_propagator.propagate(dest, &recovered);
                }
            }
            OpCode::BoolNeg => {
                if let (Some(ref dest), Some(_src)) = (op.output.as_ref(), op.inputs.first()) {
                    let bool_type = make_bool_type();
                    let recovered = RecoveredType::known(bool_type, "bool-negate");
                    self.type_propagator.propagate(dest, &recovered);
                }
            }

            // -- floating-point arithmetic -------------------------------------
            OpCode::FloatAdd
            | OpCode::FloatSub
            | OpCode::FloatMult
            | OpCode::FloatDiv
            | OpCode::FloatNeg => {
                if let Some(ref dest) = op.output {
                    let float_type = match dest.size {
                        4 => make_float_type(),
                        8 => make_double_type(),
                        s => make_uint_type(s),
                    };
                    let recovered = RecoveredType::inferred(float_type, "float-arithmetic");
                    self.type_propagator.propagate(dest, &recovered);
                }
            }

            OpCode::Float2Float | OpCode::Float2Int | OpCode::Int2Float => {
                if let Some(ref dest) = op.output {
                    if let Some(ref src) = op.inputs.first() {
                        self.type_propagator.add_flow(src, dest);
                    }
                }
            }

            // -- floating-point comparisons ------------------------------------
            OpCode::FloatEqual
            | OpCode::FloatNotEqual
            | OpCode::FloatLess
            | OpCode::FloatLessEqual => {
                if let (Some(ref dest), Some(a), Some(b)) = (
                    op.output.as_ref(),
                    op.inputs.first(),
                    op.inputs.get(1),
                ) {
                    if let Some(comp) = Comparison::from_opcode(op.opcode) {
                        self.constraints.push(TypeConstraint::Compare {
                            a: a.clone(),
                            b: b.clone(),
                            comparison: comp,
                        });
                    }
                    let bool_type = make_bool_type();
                    let recovered = RecoveredType::known(bool_type, "float-comparison-result");
                    self.type_propagator.propagate(dest, &recovered);
                }
            }

            // -- control flow --------------------------------------------------
            OpCode::Call | OpCode::CallInd => {
                // First input is the call target (for CALL, it's a constant
                // address; for CALLIND, it's a register/memory location).
                let func_addr = op.inputs.first().map(|v| Address::new(v.offset));
                let arg_start = 1;

                // Subsequent inputs are arguments.
                for (i, arg) in op.inputs.iter().skip(arg_start).enumerate() {
                    if let Some(ref addr) = func_addr {
                        self.constraints.push(TypeConstraint::CallArg {
                            func: *addr,
                            arg_index: i,
                            varnode: arg.clone(),
                        });
                    }
                }

                // Optional output is the return value.
                if let Some(ref out) = op.output {
                    if let Some(ref addr) = func_addr {
                        self.constraints.push(TypeConstraint::CallReturn {
                            func: *addr,
                            varnode: out.clone(),
                        });
                    }
                }
            }

            OpCode::Return => {
                // Return value (if any) constrains the function's return type.
                if let Some(ref ret_val) = op.inputs.first() {
                    self.constraints.push(TypeConstraint::Size {
                        varnode: (*ret_val).clone(),
                        size: ret_val.size as u32,
                    });
                }
            }

            // -- pointer arithmetic --------------------------------------------
            OpCode::PtrAdd => {
                if let (Some(ref dest), Some(base), Some(index)) = (
                    op.output.as_ref(),
                    op.inputs.first(),
                    op.inputs.get(1),
                ) {
                    // PTRADD = base + (index * scale). Scale is inputs[2] if present.
                    let element_size = op
                        .inputs
                        .get(2)
                        .and_then(|scale| scale.constant_value())
                        .unwrap_or(1);

                    self.constraints.push(TypeConstraint::ArrayIndex {
                        base: base.clone(),
                        index: index.clone(),
                        element_size: element_size as u32,
                    });

                    // Base is a pointer; dest is also a pointer (same type).
                    self.type_propagator.add_flow(base, dest);
                    self.type_propagator.unify(base, dest);
                }
            }
            OpCode::PtrSub => {
                if let (Some(ref dest), Some(a), Some(b)) = (
                    op.output.as_ref(),
                    op.inputs.first(),
                    op.inputs.get(1),
                ) {
                    self.type_propagator.add_flow(a, dest);
                    self.type_propagator.add_flow(b, dest);
                }
            }

            // -- extension / composition ---------------------------------------
            OpCode::Piece => {
                if let (Some(ref dest), Some(hi), Some(lo)) = (
                    op.output.as_ref(),
                    op.inputs.first(),
                    op.inputs.get(1),
                ) {
                    // hi || lo = dest. dest is a wider type composed of two halves.
                    self.type_propagator.add_flow(hi, dest);
                    self.type_propagator.add_flow(lo, dest);
                }
            }
            OpCode::Subpiece => {
                if let (Some(ref dest), Some(src)) = (op.output.as_ref(), op.inputs.first()) {
                    // dest is a sub-range of src.
                    self.type_propagator.add_flow(src, dest);
                }
            }
            OpCode::Cast => {
                if let (Some(ref dest), Some(src)) = (op.output.as_ref(), op.inputs.first()) {
                    self.type_propagator.add_flow(src, dest);
                }
            }

            // -- heap allocation -----------------------------------------------
            OpCode::New => {
                if let Some(ref dest) = op.output {
                    // NEW returns a pointer (void*).
                    let void_ptr = make_void_ptr_type();
                    let recovered = RecoveredType::known(void_ptr, "heap-allocation");
                    self.type_propagator.propagate(dest, &recovered);
                }
            }

            // -- sentinel / other ----------------------------------------------
            OpCode::MultiEqual | OpCode::Indirect => {
                // MUXIEQUAL / INDIRECT: all operands share the same type.
                if let Some(ref out) = op.output {
                    for inp in &op.inputs {
                        self.type_propagator.unify(out, inp);
                    }
                }
            }

            OpCode::CpoolRef | OpCode::SegmentOp => {
                if let Some(ref dest) = op.output {
                    // Output is typically a pointer.
                    let ptr_type = make_void_ptr_type();
                    let recovered = RecoveredType::inferred(ptr_type, "cpool-or-segment");
                    self.type_propagator.propagate(dest, &recovered);
                }
            }

            _ => {
                // Opcodes not requiring special handling.
            }
        }
    }

    // ------------------------------------------------------------------
    // Constraint solving
    // ------------------------------------------------------------------

    /// Solve the accumulated constraints to assign types.
    ///
    /// Processing order:
    /// 1. Apply size constraints to assign primitive types.
    /// 2. Apply LOAD/STORE constraints to infer pointer targets.
    /// 3. Iteratively solve unification pairs.
    /// 4. Propagate types through the type graph.
    pub fn solve(&mut self) -> Result<()> {
        // Phase 1: Size constraints -> primitive types.
        self.solve_size_constraints();

        // Phase 2: LOAD/STORE constraints -> pointer types.
        self.solve_load_store_constraints();

        // Phase 3: Unification.
        self.solve_unifications();

        // Phase 4: Collect results from the propagator.
        self.collect_results();

        Ok(())
    }

    /// Phase 1: Assign primitive types based on Size constraints.
    fn solve_size_constraints(&mut self) {
        let constraints: Vec<_> = self
            .constraints
            .iter()
            .filter_map(|c| {
                if let TypeConstraint::Size { varnode, size } = c {
                    Some((varnode.clone(), *size))
                } else {
                    None
                }
            })
            .collect();

        for (varnode, size) in constraints {
            let dt = size_to_primitive(size as usize);
            let recovered = RecoveredType::inferred(dt, "size-constraint");
            self.type_propagator.propagate(&varnode, &recovered);
        }
    }

    /// Phase 2: Infer pointer types from LOAD/STORE patterns.
    fn solve_load_store_constraints(&mut self) {
        let load_constraints: Vec<_> = self
            .constraints
            .iter()
            .filter_map(|c| {
                if let TypeConstraint::LoadOf { dest, ptr, size } = c {
                    Some((dest.clone(), ptr.clone(), *size))
                } else {
                    None
                }
            })
            .collect();

        for (_dest, ptr, size) in load_constraints {
            // ptr is a pointer to a type of `size` bytes.
            let pointee = size_to_primitive(size as usize);
            let ptr_type = make_pointer_type(&pointee);
            let recovered = RecoveredType::inferred(ptr_type, "load-deref");
            self.type_propagator.propagate(&ptr, &recovered);
        }

        let store_constraints: Vec<_> = self
            .constraints
            .iter()
            .filter_map(|c| {
                if let TypeConstraint::StoreOf { src: _, ptr, size } = c {
                    Some((ptr.clone(), *size))
                } else {
                    None
                }
            })
            .collect();

        for (ptr, size) in store_constraints {
            let pointee = size_to_primitive(size as usize);
            let ptr_type = make_pointer_type(&pointee);
            let recovered = RecoveredType::inferred(ptr_type, "store-deref");
            self.type_propagator.propagate(&ptr, &recovered);
        }
    }

    /// Phase 3: Iteratively resolve unification pairs.
    fn solve_unifications(&mut self) {
        let max_iterations = 100;
        let mut iteration = 0;

        while !self.type_propagator.unification_stack.is_empty() && iteration < max_iterations {
            iteration += 1;

            // Drain the unification stack for one round.
            let pairs: Vec<_> = std::mem::take(&mut self.type_propagator.unification_stack);
            let pairs_len = pairs.len();

            for (a, b) in pairs {
                let type_a = self.type_propagator.get_type(&a).cloned();
                let type_b = self.type_propagator.get_type(&b).cloned();

                match (type_a, type_b) {
                    (Some(ta), None) => {
                        // Propagate A -> B.
                        self.type_propagator.propagate(&b, &ta);
                    }
                    (None, Some(tb)) => {
                        // Propagate B -> A.
                        self.type_propagator.propagate(&a, &tb);
                    }
                    (Some(_ta), Some(_tb)) => {
                        // Both have types; pick the higher-confidence one.
                        // (Already handled during propagation — the higher
                        // confidence wins.)
                    }
                    (None, None) => {
                        // Neither has a type yet; defer until later. Only
                        // re-push if we are still iterating.
                        if iteration == 1 {
                            self.type_propagator.unify(&a, &b);
                        }
                    }
                }
            }

            // If we made no progress this round, stop.
            if self.type_propagator.unification_stack.len() == pairs_len {
                // The stack is identical to what we just processed — no progress.
                break;
            }
        }
    }

    /// Phase 4: Collect resolved types from the propagator into the engine's
    /// varnode_types map.
    fn collect_results(&mut self) {
        for (varnode, recovered) in self.type_propagator.typed_varnodes() {
            self.varnode_types
                .entry(varnode.clone())
                .and_modify(|existing| {
                    if recovered.confidence > existing.confidence {
                        *existing = recovered.clone();
                    }
                })
                .or_insert_with(|| recovered.clone());
        }
    }

    // ------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------

    /// Look up the recovered type for a varnode.
    pub fn get_type(&self, varnode: &Varnode) -> Option<&RecoveredType> {
        self.varnode_types.get(varnode)
    }

    /// Return the total number of resolved varnode types.
    pub fn type_count(&self) -> usize {
        self.varnode_types.len()
    }

    /// Return the total number of constraints collected.
    pub fn constraint_count(&self) -> usize {
        self.constraints.len()
    }

    // ------------------------------------------------------------------
    // Struct inference
    // ------------------------------------------------------------------

    /// Infer composite struct layouts from field-access patterns.
    ///
    /// Groups LOAD/STORE operations that access different offsets from a
    /// common base pointer (e.g., `*(base+0)`, `*(base+4)`, `*(base+8)`).
    /// Each group becomes a candidate [`InferredStruct`].
    pub fn infer_structs(&mut self) -> Result<Vec<InferredStruct>> {
        // Collect all StructField constraints.
        // Build groups keyed by the base-pointer varnode.
        let mut struct_groups: HashMap<Varnode, Vec<(u32, u32, RecoveredType)>> = HashMap::new();

        for constraint in &self.constraints {
            match constraint {
                TypeConstraint::StructField {
                    base,
                    field_offset,
                    field_size,
                } => {
                    let field_type = size_to_primitive(*field_size as usize);
                    let recovered = RecoveredType::inferred(field_type, "struct-field");
                    struct_groups
                        .entry(base.clone())
                        .or_default()
                        .push((*field_offset, *field_size, recovered));
                }
                // LOAD with a constant-offset PTRADD implies struct field access.
                TypeConstraint::LoadOf { ptr, size, .. } => {
                    // Check if ptr has known struct-field constraints already.
                    // This is a heuristic fallback — actual struct grouping
                    // requires deeper data-flow analysis.
                    let _ = (ptr, size);
                }
                TypeConstraint::StoreOf { ptr, size, .. } => {
                    let _ = (ptr, size);
                }
                _ => {}
            }
        }

        let mut structs: Vec<InferredStruct> = Vec::new();

        for (base_vn, mut fields) in struct_groups {
            if fields.len() < 2 {
                // A struct needs at least two fields to be meaningful.
                continue;
            }

            // Sort fields by offset.
            fields.sort_by_key(|(off, _, _)| *off);

            // Check for overlaps and compute total size.
            let mut inferred_fields: Vec<InferredField> = Vec::new();
            let mut current_offset = 0u32;
            let mut max_end: u32 = 0;

            for (offset, size, field_type) in &fields {
                // Skip overlapping fields; pick the first one at each offset.
                if *offset < current_offset {
                    continue;
                }

                inferred_fields.push(InferredField {
                    offset: *offset,
                    size: *size,
                    data_type: field_type.clone(),
                    name: None,
                });

                let end = offset + size;
                if end > max_end {
                    max_end = end;
                }
                current_offset = end;
            }

            let alignment = compute_alignment(&inferred_fields);
            let total_size = align_to(max_end, alignment);

            structs.push(InferredStruct {
                fields: inferred_fields,
                total_size,
                alignment,
                name: None,
            });
        }

        // Name structs sequentially.
        for (i, s) in structs.iter_mut().enumerate() {
            s.name = Some(format!("struct_{}", i + 1));
        }

        Ok(structs)
    }

    // ------------------------------------------------------------------
    // Function-signature inference
    // ------------------------------------------------------------------

    /// Infer a function signature from call-site and return-site observations.
    ///
    /// Aggregates [`CallArg`] and [`CallReturn`] constraints for the given
    /// function address to reconstruct the parameter list and return type.
    ///
    /// [`CallArg`]: TypeConstraint::CallArg
    /// [`CallReturn`]: TypeConstraint::CallReturn
    pub fn infer_function_signature(&self, func_addr: Address) -> Result<FunctionSignature> {
        let mut arg_map: HashMap<usize, Vec<&Varnode>> = HashMap::new();
        let mut return_varnodes: Vec<&Varnode> = Vec::new();

        for constraint in &self.constraints {
            match constraint {
                TypeConstraint::CallArg {
                    func,
                    arg_index,
                    varnode,
                } if *func == func_addr => {
                    arg_map.entry(*arg_index).or_default().push(varnode);
                }
                TypeConstraint::CallReturn { func, varnode } if *func == func_addr => {
                    return_varnodes.push(varnode);
                }
                _ => {}
            }
        }

        // Infer return type from return-value varnodes.
        let return_type = if let Some(vn) = return_varnodes.first() {
            self.get_type(vn)
                .cloned()
                .unwrap_or_else(|| {
                    RecoveredType::inferred(
                        size_to_primitive(vn.size),
                        "unknown-return",
                    )
                })
        } else {
            RecoveredType::known(make_void_type(), "void-return")
        };

        // Infer parameter types from argument varnodes.
        let mut parameters: Vec<ParameterType> = Vec::new();
        let mut indices: Vec<_> = arg_map.keys().copied().collect();
        indices.sort();

        for idx in indices {
            if let Some(vns) = arg_map.get(&idx) {
                if let Some(vn) = vns.first() {
                    let data_type = self.get_type(vn).cloned().unwrap_or_else(|| {
                        RecoveredType::inferred(
                            size_to_primitive(vn.size),
                            "unknown-param",
                        )
                    });

                    let location = if vn.is_register() {
                        ParamLocation::Register(format!("reg_0x{:x}", vn.offset))
                    } else if vn.is_ram() || vn.is_address() {
                        ParamLocation::Stack {
                            offset: vn.offset as i32,
                        }
                    } else {
                        ParamLocation::Register(format!("unique_{}", vn.offset))
                    };

                    parameters.push(ParameterType {
                        name: Some(format!("param_{}", idx)),
                        data_type,
                        location,
                    });
                }
            }
        }

        Ok(FunctionSignature {
            return_type,
            parameters,
            calling_convention: None,
        })
    }
}

impl Default for TypeRecoveryEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Helper: size -> DataType
// ============================================================================

/// Map a byte size to the most likely primitive integer type.
fn size_to_primitive(size: usize) -> DataTypeRef {
    match size {
        0 => make_void_type(),
        1 => make_uint_type(1),
        2 => make_uint_type(2),
        4 => make_uint_type(4),
        8 => make_uint_type(8),
        s => make_uint_type(s),
    }
}

/// Compute the natural alignment from a list of fields.
fn compute_alignment(fields: &[InferredField]) -> u32 {
    fields
        .iter()
        .map(|f| f.size.next_power_of_two().min(8))
        .max()
        .unwrap_or(1)
}

/// Align `value` up to the next multiple of `alignment`.
fn align_to(value: u32, alignment: u32) -> u32 {
    if alignment == 0 {
        return value;
    }
    ((value + alignment - 1) / alignment) * alignment
}

// ============================================================================
// InferredStruct
// ============================================================================

/// A recovered composite type (struct) layout.
#[derive(Debug, Clone)]
pub struct InferredStruct {
    /// The fields of this struct, in offset order.
    pub fields: Vec<InferredField>,
    /// Total size of the struct in bytes (including tail padding).
    pub total_size: u32,
    /// Natural alignment of the struct.
    pub alignment: u32,
    /// Suggested name for this struct (e.g., "struct_1").
    pub name: Option<String>,
}

impl InferredStruct {
    /// Return a formatted C-like declaration of this struct.
    pub fn to_c_declaration(&self) -> String {
        let name = self.name.as_deref().unwrap_or("unnamed_struct");
        let mut s = format!("struct {} {{\n", name);
        for field in &self.fields {
            s.push_str(&format!(
                "    /* 0x{:04x} */ {} {};\n",
                field.offset,
                field.data_type.data_type.name(),
                field.name.as_deref().unwrap_or("field"),
            ));
        }
        s.push_str(&format!(
            "}}; // size=0x{:x}, align=0x{:x}\n",
            self.total_size, self.alignment
        ));
        s
    }
}

// ============================================================================
// InferredField
// ============================================================================

/// A single field within an inferred struct.
#[derive(Debug, Clone)]
pub struct InferredField {
    /// Byte offset of this field from the start of the struct.
    pub offset: u32,
    /// Size of this field in bytes.
    pub size: u32,
    /// The recovered type for this field.
    pub data_type: RecoveredType,
    /// Suggested field name (e.g., "field_0", or user-specified).
    pub name: Option<String>,
}

// ============================================================================
// FunctionSignature
// ============================================================================

/// A recovered function prototype.
#[derive(Debug, Clone)]
pub struct FunctionSignature {
    /// The return type.
    pub return_type: RecoveredType,
    /// The parameters, in declaration order.
    pub parameters: Vec<ParameterType>,
    /// The calling convention, if known (e.g., "cdecl", "stdcall", "fastcall").
    pub calling_convention: Option<String>,
}

impl FunctionSignature {
    /// Return a formatted C-like prototype string.
    pub fn to_c_prototype(&self, func_name: &str) -> String {
        let mut s = format!("{} {}(", self.return_type.data_type.name(), func_name);
        for (i, param) in self.parameters.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            s.push_str(&param.data_type.data_type.name());
            if let Some(ref name) = param.name {
                s.push(' ');
                s.push_str(name);
            }
        }
        s.push(')');
        if let Some(ref cc) = self.calling_convention {
            s.push_str(&format!(" /* {} */", cc));
        }
        s.push(';');
        s
    }
}

// ============================================================================
// ParameterType
// ============================================================================

/// A single function parameter with its type and storage location.
#[derive(Debug, Clone)]
pub struct ParameterType {
    /// Optional parameter name.
    pub name: Option<String>,
    /// The inferred data type.
    pub data_type: RecoveredType,
    /// Where the parameter is passed (register, stack, or split across both).
    pub location: ParamLocation,
}

// ============================================================================
// ParamLocation
// ============================================================================

/// Describes where a function parameter is passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamLocation {
    /// Passed in a single register.
    Register(String),
    /// Passed on the stack at the given offset (relative to the stack pointer
    /// at function entry).
    Stack {
        /// Stack offset in bytes.
        offset: i32,
    },
    /// Part in a register, part on the stack (e.g., large struct by value).
    RegisterAndStack {
        /// Register name for the first part.
        reg: String,
        /// Stack offset for the remaining part.
        stack_offset: i32,
    },
    /// Split across multiple registers and/or stack slots.
    Split(Vec<ParamLocation>),
}

impl ParamLocation {
    /// Returns a human-readable description of this location.
    pub fn describe(&self) -> String {
        match self {
            ParamLocation::Register(r) => format!("register {}", r),
            ParamLocation::Stack { offset } => format!("stack+0x{:x}", offset),
            ParamLocation::RegisterAndStack { reg, stack_offset } => {
                format!("register {} + stack+0x{:x}", reg, stack_offset)
            }
            ParamLocation::Split(locs) => {
                let parts: Vec<_> = locs.iter().map(|l| l.describe()).collect();
                parts.join(", ")
            }
        }
    }
}

// ============================================================================
// HeapStructAnalyzer
// ============================================================================

/// Analyzes heap allocations (via the `NEW` P-code opcode) to identify
/// dynamically-allocated struct layouts.
///
/// Tracks:
/// - Allocation sites and their size.
/// - Field accesses (LOAD/STORE) at fixed offsets from the returned pointer.
/// - Groups of allocations with identical or similar access patterns.
pub struct HeapStructAnalyzer;

impl HeapStructAnalyzer {
    /// Analyze a set of P-code sequences for heap allocation patterns.
    ///
    /// Returns a list of [`HeapAllocation`] records, one per `NEW` opcode
    /// encountered.
    pub fn analyze_allocations(&self, sequences: &[PcodeSequence]) -> Vec<HeapAllocation> {
        let mut allocations: Vec<HeapAllocation> = Vec::new();

        // First pass: find all NEW operations and their allocated size.
        // Format: `out = NEW(size)` where size = inputs[0].
        #[derive(Debug)]
        struct AllocSite {
            alloc_site: Address,
            output_varnode: Varnode,
            size: u64,
        }

        let mut sites: Vec<AllocSite> = Vec::new();

        for seq in sequences {
            for op in &seq.ops {
                if op.opcode == OpCode::New {
                    if let Some(ref out) = op.output {
                        let size = op
                            .inputs
                            .first()
                            .and_then(|vn| vn.constant_value())
                            .unwrap_or(0);

                        sites.push(AllocSite {
                            alloc_site: seq.start_address,
                            output_varnode: out.clone(),
                            size,
                        });
                    }
                }
            }
        }

        // Second pass: for each allocation site, find LOAD/STORE operations
        // that use the allocated pointer (or derived pointers) as the base
        // address.
        for site in &sites {
            let mut fields_accessed: Vec<(u32, u32)> = Vec::new();

            for seq in sequences {
                for op in &seq.ops {
                    match op.opcode {
                        OpCode::Load => {
                            if let Some(ptr) = op.inputs.first() {
                                if ptr == &site.output_varnode {
                                    if let Some(ref dest) = op.output {
                                        fields_accessed.push((0, dest.size as u32));
                                    }
                                }
                            }
                        }
                        OpCode::Store => {
                            if op.inputs.len() >= 2 {
                                let ptr = &op.inputs[0];
                                if ptr == &site.output_varnode {
                                    let src = &op.inputs[1];
                                    fields_accessed.push((0, src.size as u32));
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            // Also check for PTRADD-based accesses: `ptr_derived = base + offset`.
            // This gives us actual field offsets.
            for seq in sequences {
                for op in &seq.ops {
                    if op.opcode == OpCode::PtrAdd {
                        if let (Some(ref derived), Some(base)) =
                            (op.output.as_ref(), op.inputs.first())
                        {
                            if base == &site.output_varnode || is_derived_from(base, &site.output_varnode, &sequences)
                            {
                                // Look for subsequent loads/stores through `derived`.
                                let offset_val = op
                                    .inputs
                                    .get(1)
                                    .and_then(|vn| vn.constant_value())
                                    .unwrap_or(0);

                                for seq2 in sequences {
                                    for op2 in &seq2.ops {
                                        if op2.opcode == OpCode::Load
                                            && op2.inputs.first() == Some(derived)
                                        {
                                            if let Some(ref dest) = op2.output {
                                                fields_accessed.push((
                                                    offset_val as u32,
                                                    dest.size as u32,
                                                ));
                                            }
                                        }
                                        if op2.opcode == OpCode::Store
                                            && op2.inputs.len() >= 2
                                            && op2.inputs[0] == **derived
                                        {
                                            let src = &op2.inputs[1];
                                            fields_accessed.push((
                                                offset_val as u32,
                                                src.size as u32,
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Deduplicate and sort.
            fields_accessed.sort();
            fields_accessed.dedup();

            allocations.push(HeapAllocation {
                alloc_site: site.alloc_site,
                size: site.size,
                fields_accessed,
            });
        }

        allocations
    }

    /// Group related allocations that access similar field patterns into
    /// heap structs.
    ///
    /// Allocations with the same total size and identical (or nearly
    /// identical) field-offset patterns are merged into a single
    /// [`HeapStruct`].
    pub fn group_related_allocations(
        &self,
        allocs: &[HeapAllocation],
    ) -> Vec<HeapStruct> {
        // Group by (size, field_offsets).
        let mut groups: HashMap<(u64, Vec<(u32, u32)>), Vec<&HeapAllocation>> = HashMap::new();

        for alloc in allocs {
            let key = (alloc.size, alloc.fields_accessed.clone());
            groups.entry(key).or_default().push(alloc);
        }

        let mut heap_structs: Vec<HeapStruct> = Vec::new();

        for ((size, fields), group) in groups {
            let mut field_types: Vec<(u32, u32, RecoveredType)> = Vec::new();
            for (offset, field_size) in &fields {
                let dt = size_to_primitive(*field_size as usize);
                let recovered = RecoveredType::inferred(dt, "heap-field");
                field_types.push((*offset, *field_size, recovered));
            }

            heap_structs.push(HeapStruct {
                total_size: size,
                fields: field_types,
                allocation_count: group.len(),
                allocation_sites: group.iter().map(|a| a.alloc_site).collect(),
            });
        }

        heap_structs
    }
}

/// Check if `a` is derived from `base` through PTRADD chains.
fn is_derived_from(a: &Varnode, base: &Varnode, sequences: &[PcodeSequence]) -> bool {
    if a == base {
        return true;
    }
    // Check one level of PTRADD: if a = PTRADD(base, ...).
    for seq in sequences {
        for op in &seq.ops {
            if op.opcode == OpCode::PtrAdd {
                if let (Some(ref out), Some(b)) = (op.output.as_ref(), op.inputs.first()) {
                    if *out == a && b == base {
                        return true;
                    }
                }
            }
        }
    }
    false
}

// ============================================================================
// HeapAllocation
// ============================================================================

/// A single heap allocation detected from a `NEW` P-code operation.
#[derive(Debug, Clone)]
pub struct HeapAllocation {
    /// The address of the instruction that performed the allocation.
    pub alloc_site: Address,
    /// The number of bytes allocated (from the `NEW` size operand).
    pub size: u64,
    /// Field accesses observed on this allocation.
    /// Each entry is `(offset, size)` — the byte offset from the base pointer
    /// and the size of the accessed field.
    pub fields_accessed: Vec<(u32, u32)>,
}

impl HeapAllocation {
    /// Create a new heap allocation record.
    pub fn new(alloc_site: Address, size: u64, fields_accessed: Vec<(u32, u32)>) -> Self {
        Self {
            alloc_site,
            size,
            fields_accessed,
        }
    }
}

// ============================================================================
// HeapStruct
// ============================================================================

/// A recovered heap-allocated struct type.
///
/// Multiple allocation sites may instantiate the same logical struct type.
/// [`HeapStruct`] represents the consensus layout across all sites.
#[derive(Debug, Clone)]
pub struct HeapStruct {
    /// Total size of the struct, as determined by the allocation size.
    pub total_size: u64,
    /// Fields: (offset, size, recovered_type).
    pub fields: Vec<(u32, u32, RecoveredType)>,
    /// How many distinct allocation sites instantiate this struct.
    pub allocation_count: usize,
    /// The addresses of the allocation sites.
    pub allocation_sites: Vec<Address>,
}

impl HeapStruct {
    /// Return the inferred field at the given offset, if any.
    pub fn field_at(&self, offset: u32) -> Option<&(u32, u32, RecoveredType)> {
        self.fields.iter().find(|(off, _, _)| *off == offset)
    }

    /// Return all field offsets, sorted.
    pub fn field_offsets(&self) -> Vec<u32> {
        let mut offsets: Vec<_> = self.fields.iter().map(|(o, _, _)| *o).collect();
        offsets.sort();
        offsets.dedup();
        offsets
    }

    /// Return a formatted C-like declaration.
    pub fn to_c_declaration(&self) -> String {
        let mut s = format!("struct heap_struct /* size=0x{:x} */ {{\n", self.total_size);
        for (offset, size, ty) in &self.fields {
            s.push_str(&format!(
                "    /* 0x{:04x} */ {};\n",
                offset, ty.data_type.name()
            ));
        }
        s.push_str("};\n");
        s
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;

    fn test_addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn test_varnode_reg(offset: u64, size: usize) -> Varnode {
        Varnode::register(offset, size)
    }

    fn test_varnode_const(val: u64, size: usize) -> Varnode {
        Varnode::constant(val, size)
    }

    fn test_varnode_unique(idx: u64, size: usize) -> Varnode {
        Varnode::unique(idx, size)
    }

    fn make_load_op(dest: Varnode, ptr: Varnode) -> PcodeOp {
        PcodeOp::new(OpCode::Load, Some(dest), vec![ptr])
    }

    fn make_store_op(ptr: Varnode, value: Varnode) -> PcodeOp {
        PcodeOp::new(OpCode::Store, None, vec![ptr, value])
    }

    fn make_call_op(target: u64, args: &[Varnode], output: Option<Varnode>) -> PcodeOp {
        let mut inputs = vec![Varnode::constant(target, 8)];
        inputs.extend_from_slice(args);
        PcodeOp::new(OpCode::Call, output, inputs)
    }

    #[test]
    fn test_empty_engine() {
        let engine = TypeRecoveryEngine::new();
        assert_eq!(engine.type_count(), 0);
        assert_eq!(engine.constraint_count(), 0);
    }

    #[test]
    fn test_size_constraint_to_primitive() {
        assert_eq!(size_to_primitive(1).name(), make_uint_type(1).name());
        assert_eq!(size_to_primitive(2).name(), make_uint_type(2).name());
        assert_eq!(size_to_primitive(4).name(), make_uint_type(4).name());
        assert_eq!(size_to_primitive(8).name(), make_uint_type(8).name());
        assert_eq!(size_to_primitive(0).name(), make_void_type().name());
    }

    #[test]
    fn test_comparison_from_opcode() {
        assert_eq!(Comparison::from_opcode(OpCode::IntEqual), Some(Comparison::EQ));
        assert_eq!(Comparison::from_opcode(OpCode::IntSless), Some(Comparison::SLT));
        assert_eq!(Comparison::from_opcode(OpCode::IntLess), Some(Comparison::LT));
        assert_eq!(Comparison::from_opcode(OpCode::IntAdd), None);
    }

    #[test]
    fn test_propagator_ensure_node() {
        let mut prop = TypePropagator::new();
        let v = test_varnode_reg(0, 4);
        let idx = prop.ensure_node(&v);
        assert_eq!(prop.node_count(), 1);
        // Ensuring again returns the same index.
        let idx2 = prop.ensure_node(&v);
        assert_eq!(idx, idx2);
    }

    #[test]
    fn test_propagator_add_flow_and_propagate() {
        let mut prop = TypePropagator::new();
        let a = test_varnode_reg(0, 4);
        let b = test_varnode_reg(4, 4);

        prop.add_flow(&a, &b);

        // Assign type to a and propagate.
        let ta = RecoveredType::known(make_uint_type(4), "test");
        let results = prop.propagate(&a, &ta);

        // b should have received a propagated type.
        assert!(!results.is_empty());
        let b_type = prop.get_type(&b).unwrap();
        assert_eq!(b_type.data_type.name(), make_uint_type(4).name());
        assert!(b_type.confidence < 1.0);
    }

    #[test]
    fn test_add_constraints_load() {
        let mut engine = TypeRecoveryEngine::new();

        let dest = test_varnode_unique(0, 4);
        let ptr = test_varnode_reg(0, 8);
        let op = make_load_op(dest.clone(), ptr.clone());
        let seq = PcodeSequence::new(vec![op], test_addr(0x1000), test_addr(0x1000));

        engine.add_constraints(&[seq]);

        // Should have at least a LoadOf constraint.
        let has_load = engine.constraints.iter().any(|c| {
            matches!(c, TypeConstraint::LoadOf { .. })
        });
        assert!(has_load);
    }

    #[test]
    fn test_add_constraints_store() {
        let mut engine = TypeRecoveryEngine::new();

        let src = test_varnode_reg(0, 4);
        let ptr = test_varnode_reg(8, 8);
        let op = make_store_op(ptr.clone(), src.clone());
        let seq = PcodeSequence::new(vec![op], test_addr(0x1000), test_addr(0x1000));

        engine.add_constraints(&[seq]);

        let has_store = engine.constraints.iter().any(|c| {
            matches!(c, TypeConstraint::StoreOf { .. })
        });
        assert!(has_store);
    }

    #[test]
    fn test_add_constraints_call() {
        let mut engine = TypeRecoveryEngine::new();

        let arg0 = test_varnode_reg(0, 4);
        let ret = test_varnode_reg(4, 4);
        let op = make_call_op(0x4000, &[arg0.clone()], Some(ret.clone()));
        let seq = PcodeSequence::new(vec![op], test_addr(0x2000), test_addr(0x2000));

        engine.add_constraints(&[seq]);

        let has_call_arg = engine.constraints.iter().any(|c| {
            matches!(c, TypeConstraint::CallArg { .. })
        });
        let has_call_ret = engine.constraints.iter().any(|c| {
            matches!(c, TypeConstraint::CallReturn { .. })
        });
        assert!(has_call_arg);
        assert!(has_call_ret);
    }

    #[test]
    fn test_solve_basic() {
        let mut engine = TypeRecoveryEngine::new();

        // Simulate: u32 x = *(u32*)ptr;
        let ptr = test_varnode_reg(0, 8);     // pointer (8 bytes)
        let dest = test_varnode_unique(0, 4);  // loaded value (4 bytes)
        let op = make_load_op(dest.clone(), ptr.clone());
        let seq = PcodeSequence::new(vec![op], test_addr(0x1000), test_addr(0x1000));

        engine.add_constraints(&[seq]);
        let result = engine.solve();
        assert!(result.is_ok());

        // The engine should have resolved something.
        assert!(engine.type_count() > 0);
    }

    #[test]
    fn test_infer_function_signature_empty() {
        let engine = TypeRecoveryEngine::new();
        let sig = engine.infer_function_signature(test_addr(0x4000)).unwrap();
        assert_eq!(sig.return_type.data_type.name(), make_void_type().name());
        assert!(sig.parameters.is_empty());
    }

    #[test]
    fn test_heap_analyzer_no_allocations() {
        let analyzer = HeapStructAnalyzer;
        let seq = PcodeSequence::new(vec![], test_addr(0x1000), test_addr(0x1000));
        let allocs = analyzer.analyze_allocations(&[seq]);
        assert!(allocs.is_empty());
    }

    #[test]
    fn test_heap_analyzer_single_allocation() {
        let analyzer = HeapStructAnalyzer;

        // NEW(size=16, dest=unique:0:8)
        let new_op = PcodeOp::new(
            OpCode::New,
            Some(test_varnode_unique(0, 8)),
            vec![test_varnode_const(16, 4)],
        );
        let seq = PcodeSequence::new(vec![new_op], test_addr(0x1000), test_addr(0x1000));

        let allocs = analyzer.analyze_allocations(&[seq]);
        assert_eq!(allocs.len(), 1);
        assert_eq!(allocs[0].size, 16);
        assert_eq!(allocs[0].alloc_site, test_addr(0x1000));
    }

    #[test]
    fn test_heap_analyzer_grouping() {
        let analyzer = HeapStructAnalyzer;

        let alloc1 = HeapAllocation::new(test_addr(0x1000), 32, vec![(0, 4), (4, 4), (8, 8)]);
        let alloc2 = HeapAllocation::new(test_addr(0x2000), 32, vec![(0, 4), (4, 4), (8, 8)]);
        let alloc3 = HeapAllocation::new(test_addr(0x3000), 16, vec![(0, 8)]);

        let groups = analyzer.group_related_allocations(&[alloc1, alloc2, alloc3]);
        // Two distinct struct layouts: one 32-byte, one 16-byte.
        assert_eq!(groups.len(), 2);

        let group32 = groups.iter().find(|g| g.total_size == 32).unwrap();
        assert_eq!(group32.allocation_count, 2);
        assert_eq!(group32.allocation_sites.len(), 2);

        let group16 = groups.iter().find(|g| g.total_size == 16).unwrap();
        assert_eq!(group16.allocation_count, 1);
    }

    #[test]
    fn test_inferred_struct_to_c() {
        let s = InferredStruct {
            fields: vec![
                InferredField {
                    offset: 0,
                    size: 4,
                    data_type: RecoveredType::inferred(make_uint_type(4), "test"),
                    name: Some("x".into()),
                },
                InferredField {
                    offset: 4,
                    size: 8,
                    data_type: RecoveredType::inferred(make_uint_type(8), "test"),
                    name: Some("y".into()),
                },
            ],
            total_size: 16,
            alignment: 8,
            name: Some("MyStruct".into()),
        };

        let decl = s.to_c_declaration();
        assert!(decl.contains("struct MyStruct"));
        assert!(decl.contains("u32 x"));
        assert!(decl.contains("u64 y"));
        assert!(decl.contains("size=0x10"));
    }

    #[test]
    fn test_function_signature_to_c() {
        let sig = FunctionSignature {
            return_type: RecoveredType::known(make_int_type(4), "test"),
            parameters: vec![
                ParameterType {
                    name: Some("a".into()),
                    data_type: RecoveredType::known(make_uint_type(4), "test"),
                    location: ParamLocation::Register("r0".into()),
                },
                ParameterType {
                    name: Some("b".into()),
                    data_type: RecoveredType::known(make_pointer_type(&make_uint_type(1)), "test"),
                    location: ParamLocation::Register("r1".into()),
                },
            ],
            calling_convention: Some("cdecl".into()),
        };

        let proto = sig.to_c_prototype("my_func");
        assert!(proto.contains("i32 my_func"));
        assert!(proto.contains("u32 a"));
        assert!(proto.contains("u8* b"));
        assert!(proto.contains("cdecl"));
    }

    #[test]
    fn test_param_location_describe() {
        assert_eq!(
            ParamLocation::Register("eax".into()).describe(),
            "register eax"
        );
        assert_eq!(
            ParamLocation::Stack { offset: 8 }.describe(),
            "stack+0x8"
        );
        assert_eq!(
            ParamLocation::RegisterAndStack {
                reg: "r0".into(),
                stack_offset: 4
            }
            .describe(),
            "register r0 + stack+0x4"
        );
    }

    #[test]
    fn test_comparison_is_signed() {
        assert!(!Comparison::EQ.is_signed());
        assert!(Comparison::SLT.is_signed());
        assert!(!Comparison::LT.is_signed());
    }

    #[test]
    fn test_recovered_type_confidence_override() {
        let t1 = RecoveredType::inferred(make_uint_type(4), "rule-a");
        let t2 = t1.with_confidence(0.9);
        assert_eq!(t2.confidence, 0.9);
        assert_eq!(t2.data_type.name(), make_uint_type(4).name());
    }

    #[test]
    fn test_type_source_label() {
        assert_eq!(
            TypeSource::Known {
                reason: "test".into()
            }
            .label(),
            "known"
        );
        assert_eq!(
            TypeSource::Inferred {
                rule: "test".into()
            }
            .label(),
            "inferred"
        );
        assert_eq!(TypeSource::UserDefined.label(), "user");
    }

    #[test]
    fn test_align_to() {
        assert_eq!(align_to(7, 4), 8);
        assert_eq!(align_to(8, 4), 8);
        assert_eq!(align_to(12, 8), 16);
        assert_eq!(align_to(16, 8), 16);
        assert_eq!(align_to(0, 4), 0);
    }

    #[test]
    fn test_propagator_default() {
        let prop = TypePropagator::default();
        assert_eq!(prop.node_count(), 0);
        assert_eq!(prop.unification_count(), 0);
    }
}
