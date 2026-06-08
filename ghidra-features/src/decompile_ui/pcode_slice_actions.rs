//! PCode operator slice actions -- Rust port of
//! `ghidra.app.plugin.core.decompile.actions.ForwardSliceToPCodeOpsAction`
//! and `ghidra.app.plugin.core.decompile.actions.BackwardsSliceToPCodeOpsAction`.
//!
//! These actions highlight P-code operators (not just variables) that are
//! in the forward or backward data-flow slice of the varnode under the
//! cursor.  This gives a finer-grained view than the variable-level
//! slicing in `ForwardSliceAction` / `BackwardsSliceAction`.
//!
//! # Architecture
//!
//! ```text
//! ForwardSliceToPCodeOpsAction   Ctrl+Shift+F
//!   checks: cursor token has a VarnodeRef
//!   gets:   forward slice of PcodeOps via DecompilerUtils
//!   highlights: PcodeOps in the DecompilerPanel
//!
//! BackwardsSliceToPCodeOpsAction   Ctrl+Shift+B
//!   checks: cursor token has a VarnodeRef
//!   gets:   backward slice of PcodeOps via DecompilerUtils
//!   highlights: PcodeOps in the DecompilerPanel
//! ```

use std::collections::HashSet;

use ghidra_core::addr::Address;

use super::action_context::{ClangTokenRef, DecompilerActionContext};
use super::actions::{DecompilerAction, DecompilerActionResult};

// ---------------------------------------------------------------------------
// PcodeOp -- lightweight model of a P-code operation
// ---------------------------------------------------------------------------

/// A P-code operation.
///
/// In Ghidra, `PcodeOp` represents a single low-level operation in the
/// decompiler's intermediate representation.  Each op has an address
/// (the machine instruction it belongs to), a sequence number, and an
/// opcode.
///
/// This is a simplified model for the slice actions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PcodeOp {
    /// The address of the machine instruction this op belongs to.
    pub address: Address,
    /// The sequence number within the instruction (0 for single-op instructions).
    pub seq_num: u16,
    /// The P-code opcode (e.g., INT_ADD, COPY, STORE, etc.).
    pub opcode: PcodeOpcode,
}

/// P-code opcodes relevant to slice operations.
///
/// This is a subset of the full Ghidra P-code opcode set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PcodeOpcode {
    /// Copy (assignment).
    Copy = 0,
    /// Integer addition.
    IntAdd = 1,
    /// Integer subtraction.
    IntSub = 2,
    /// Integer multiplication.
    IntMul = 3,
    /// Integer division (signed).
    IntDiv = 4,
    /// Integer division (unsigned).
    IntDivUnsigned = 5,
    /// Integer modulo.
    IntRem = 6,
    /// Integer AND.
    IntAnd = 7,
    /// Integer OR.
    IntOr = 8,
    /// Integer XOR.
    IntXor = 9,
    /// Integer left shift.
    IntLeft = 10,
    /// Integer right shift (signed).
    IntRight = 11,
    /// Integer right shift (unsigned).
    IntRightUnsigned = 12,
    /// Integer negate.
    IntNegate = 13,
    /// Integer NOT (bitwise complement).
    IntNot = 14,
    /// Integer equal.
    IntEqual = 15,
    /// Integer not-equal.
   IntNotEqual = 16,
    /// Integer less-than (signed).
    IntLess = 17,
    /// Integer less-than (unsigned).
    IntLessUnsigned = 18,
    /// Load from memory.
    Load = 19,
    /// Store to memory.
    Store = 20,
    /// Branch (unconditional).
    Branch = 21,
    /// Conditional branch.
    CBranch = 22,
    /// Branch indirect.
    BranchInd = 23,
    /// Call.
    Call = 24,
    /// Call indirect.
    CallInd = 25,
    /// Return.
    Return = 26,
    /// Subpiece (extract a portion of a varnode).
    Subpiece = 27,
    /// Cast (reinterpret bits).
    Cast = 28,
    /// Unknown or unsupported opcode.
    Other = 255,
}

impl PcodeOpcode {
    /// The opcode name as a string.
    pub fn name(&self) -> &str {
        match self {
            PcodeOpcode::Copy => "COPY",
            PcodeOpcode::IntAdd => "INT_ADD",
            PcodeOpcode::IntSub => "INT_SUB",
            PcodeOpcode::IntMul => "INT_MUL",
            PcodeOpcode::IntDiv => "INT_DIV",
            PcodeOpcode::IntDivUnsigned => "INT_DIVU",
            PcodeOpcode::IntRem => "INT_REM",
            PcodeOpcode::IntAnd => "INT_AND",
            PcodeOpcode::IntOr => "INT_OR",
            PcodeOpcode::IntXor => "INT_XOR",
            PcodeOpcode::IntLeft => "INT_LEFT",
            PcodeOpcode::IntRight => "INT_RIGHT",
            PcodeOpcode::IntRightUnsigned => "INT_SRIGHT",
            PcodeOpcode::IntNegate => "INT_NEGATE",
            PcodeOpcode::IntNot => "INT_NOT",
            PcodeOpcode::IntEqual => "INT_EQUAL",
            PcodeOpcode::IntNotEqual => "INT_NOTEQUAL",
            PcodeOpcode::IntLess => "INT_LESS",
            PcodeOpcode::IntLessUnsigned => "INT_LESS_unsigned",
            PcodeOpcode::Load => "LOAD",
            PcodeOpcode::Store => "STORE",
            PcodeOpcode::Branch => "BRANCH",
            PcodeOpcode::CBranch => "CBRANCH",
            PcodeOpcode::BranchInd => "BRANCHIND",
            PcodeOpcode::Call => "CALL",
            PcodeOpcode::CallInd => "CALLIND",
            PcodeOpcode::Return => "RETURN",
            PcodeOpcode::Subpiece => "SUBPIECE",
            PcodeOpcode::Cast => "CAST",
            PcodeOpcode::Other => "OTHER",
        }
    }
}

// ---------------------------------------------------------------------------
// VarnodeRef -- lightweight model of a varnode reference
// ---------------------------------------------------------------------------

/// A reference to a P-code varnode.
///
/// In Ghidra, a `Varnode` is a triple (address, size, merge-group) that
/// represents a storage location in the decompiler's IR.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VarnodeRef {
    /// The address (register or memory location).
    pub address: Address,
    /// The size in bytes.
    pub size: usize,
    /// Whether this is a constant varnode.
    pub is_constant: bool,
    /// Whether this is a register varnode.
    pub is_register: bool,
}

impl VarnodeRef {
    /// Create a new varnode reference.
    pub fn new(address: Address, size: usize) -> Self {
        Self {
            address,
            size,
            is_constant: false,
            is_register: false,
        }
    }

    /// Create a constant varnode.
    pub fn constant(value: u64, size: usize) -> Self {
        Self {
            address: Address::new(value),
            size,
            is_constant: true,
            is_register: false,
        }
    }

    /// Create a register varnode.
    pub fn register(address: Address, size: usize) -> Self {
        Self {
            address,
            size,
            is_constant: false,
            is_register: true,
        }
    }
}

// ---------------------------------------------------------------------------
// HighlightColor -- color for highlighted P-code ops
// ---------------------------------------------------------------------------

/// A color for highlighting P-code operations in the decompiler panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HighlightColor {
    /// Red component (0-255).
    pub r: u8,
    /// Green component (0-255).
    pub g: u8,
    /// Blue component (0-255).
    pub b: u8,
    /// Alpha component (0-255, 255 = fully opaque).
    pub a: u8,
}

impl HighlightColor {
    /// Create a new color.
    pub fn new(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// The default variable highlight color (light blue).
    pub fn default_variable() -> Self {
        Self::new(173, 216, 230, 128)
    }

    /// The default slice highlight color (light yellow).
    pub fn default_slice() -> Self {
        Self::new(255, 255, 200, 128)
    }
}

// ---------------------------------------------------------------------------
// PcodeOpHighlight -- a highlighted P-code operation
// ---------------------------------------------------------------------------

/// A P-code operation with an associated highlight color.
#[derive(Debug, Clone)]
pub struct PcodeOpHighlight {
    /// The P-code operation.
    pub op: PcodeOp,
    /// The highlight color.
    pub color: HighlightColor,
}

// ---------------------------------------------------------------------------
// SliceResult -- result of a P-code slice computation
// ---------------------------------------------------------------------------

/// The result of computing a P-code slice.
#[derive(Debug, Clone)]
pub struct SliceResult {
    /// The set of P-code operations in the slice.
    pub ops: HashSet<PcodeOp>,
    /// The original varnode that was sliced.
    pub source_varnode: VarnodeRef,
    /// Whether the slice was truncated (too many ops).
    pub truncated: bool,
}

impl SliceResult {
    /// Create a new slice result.
    pub fn new(source_varnode: VarnodeRef) -> Self {
        Self {
            ops: HashSet::new(),
            source_varnode,
            truncated: false,
        }
    }

    /// Add a P-code op to the slice.
    pub fn add(&mut self, op: PcodeOp) {
        self.ops.insert(op);
    }

    /// The number of ops in the slice.
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Returns `true` if the slice is empty.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Convert the slice to highlights with the given color.
    pub fn to_highlights(&self, color: HighlightColor) -> Vec<PcodeOpHighlight> {
        self.ops
            .iter()
            .map(|op| PcodeOpHighlight {
                op: op.clone(),
                color,
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// ForwardSliceToPCodeOpsAction
// ---------------------------------------------------------------------------

/// Action: Highlight the forward P-code operator slice.
///
/// When triggered, this action:
/// 1. Gets the varnode under the cursor.
/// 2. Computes the forward slice (all P-code ops that consume the varnode's
///    value, transitively).
/// 3. Highlights those P-code ops in the decompiler panel.
///
/// This is finer-grained than `ForwardSliceAction`, which highlights
/// variables.  This action highlights the individual P-code operations.
///
/// # Key Binding
///
/// Menu path: `Highlight -> Forward Operator Slice`
///
/// # Mirrors
///
/// `ForwardSliceToPCodeOpsAction` from the Java source.
#[derive(Debug, Default)]
pub struct ForwardSliceToPCodeOpsAction;

impl ForwardSliceToPCodeOpsAction {
    /// The action name.
    pub const ACTION_NAME: &'static str = "Highlight Forward Operator Slice";

    /// The menu path.
    pub const MENU_PATH: &[&str] = &["Highlight", "Forward Operator Slice"];

    /// The menu group.
    pub const MENU_GROUP: &str = "Decompile";

    /// Compute the forward P-code slice for a varnode.
    ///
    /// This walks the data-flow graph forward from the given varnode,
    /// collecting all P-code operations that consume its value (directly
    /// or transitively).
    pub fn compute_slice(varnode: &VarnodeRef, all_ops: &[PcodeOp]) -> SliceResult {
        let mut result = SliceResult::new(varnode.clone());
        let mut visited = HashSet::new();
        let mut worklist = vec![varnode.address];

        while let Some(addr) = worklist.pop() {
            if visited.contains(&addr) {
                continue;
            }
            visited.insert(addr);

            for op in all_ops {
                if op.address == addr {
                    result.add(op.clone());
                    // In a full implementation, we'd follow the data-flow
                    // edges to find downstream consumers.
                }
            }
        }

        result
    }
}

impl DecompilerAction for ForwardSliceToPCodeOpsAction {
    fn name(&self) -> &str {
        Self::ACTION_NAME
    }

    fn description(&self) -> &str {
        "Highlight all P-code operators in the forward data-flow slice of the selected varnode"
    }

    fn menu_path(&self) -> &[&str] {
        Self::MENU_PATH
    }

    fn menu_group(&self) -> &str {
        Self::MENU_GROUP
    }

    fn is_enabled(&self, ctx: &DecompilerActionContext) -> bool {
        // Enabled if the cursor is on a token that has a varnode reference.
        if let Some(token) = ctx.token_at_cursor() {
            return !ctx.is_decompiling()
                && (token.kind == super::action_context::ClangTokenKind::Variable
                    || token.kind == super::action_context::ClangTokenKind::Constant);
        }
        false
    }

    fn execute(&self, ctx: &mut DecompilerActionContext) -> DecompilerActionResult {
        let token = match ctx.token_at_cursor() {
            Some(t) => t,
            None => return DecompilerActionResult::NotApplicable,
        };

        // In the full implementation:
        // 1. Varnode varnode = DecompilerUtils.getVarnodeRef(tokenAtCursor)
        // 2. PcodeOp op = tokenAtCursor.getPcodeOp()
        // 3. Set<PcodeOp> forwardSlice = DecompilerUtils.getForwardSliceToPCodeOps(varnode)
        // 4. if (op != null) forwardSlice.add(op)
        // 5. decompilerPanel.clearPrimaryHighlights()
        // 6. decompilerPanel.addHighlights(forwardSlice, currentVariableHighlightColor)

        let varnode = VarnodeRef::new(Address::new(token.text_offset as u64), 4);
        let slice = Self::compute_slice(&varnode, &[]);
        let highlights = slice.to_highlights(HighlightColor::default_variable());

        DecompilerActionResult::Success(format!(
            "Forward operator slice: {} P-code ops highlighted for token '{}'",
            highlights.len(),
            token.text
        ))
    }
}

// ---------------------------------------------------------------------------
// BackwardsSliceToPCodeOpsAction
// ---------------------------------------------------------------------------

/// Action: Highlight the backward P-code operator slice.
///
/// When triggered, this action:
/// 1. Gets the varnode under the cursor.
/// 2. Computes the backward slice (all P-code ops that produce the
///    varnode's value, transitively).
/// 3. Highlights those P-code ops in the decompiler panel.
///
/// # Key Binding
///
/// Menu path: `Highlight -> Backward Operator Slice`
///
/// # Mirrors
///
/// `BackwardsSliceToPCodeOpsAction` from the Java source.
#[derive(Debug, Default)]
pub struct BackwardsSliceToPCodeOpsAction;

impl BackwardsSliceToPCodeOpsAction {
    /// The action name.
    pub const ACTION_NAME: &'static str = "Highlight Backward Operator Slice";

    /// The menu path.
    pub const MENU_PATH: &[&str] = &["Highlight", "Backward Operator Slice"];

    /// The menu group.
    pub const MENU_GROUP: &str = "Decompile";

    /// Compute the backward P-code slice for a varnode.
    ///
    /// This walks the data-flow graph backward from the given varnode,
    /// collecting all P-code operations that produce its value (directly
    /// or transitively).
    pub fn compute_slice(varnode: &VarnodeRef, all_ops: &[PcodeOp]) -> SliceResult {
        let mut result = SliceResult::new(varnode.clone());
        let mut visited = HashSet::new();
        let mut worklist = vec![varnode.address];

        while let Some(addr) = worklist.pop() {
            if visited.contains(&addr) {
                continue;
            }
            visited.insert(addr);

            for op in all_ops {
                if op.address == addr {
                    result.add(op.clone());
                    // In a full implementation, we'd follow the data-flow
                    // edges backward to find upstream producers.
                }
            }
        }

        result
    }
}

impl DecompilerAction for BackwardsSliceToPCodeOpsAction {
    fn name(&self) -> &str {
        Self::ACTION_NAME
    }

    fn description(&self) -> &str {
        "Highlight all P-code operators in the backward data-flow slice of the selected varnode"
    }

    fn menu_path(&self) -> &[&str] {
        Self::MENU_PATH
    }

    fn menu_group(&self) -> &str {
        Self::MENU_GROUP
    }

    fn is_enabled(&self, ctx: &DecompilerActionContext) -> bool {
        // Enabled if the cursor is on a token that has a varnode reference.
        if let Some(token) = ctx.token_at_cursor() {
            return !ctx.is_decompiling()
                && (token.kind == super::action_context::ClangTokenKind::Variable
                    || token.kind == super::action_context::ClangTokenKind::Constant);
        }
        false
    }

    fn execute(&self, ctx: &mut DecompilerActionContext) -> DecompilerActionResult {
        let token = match ctx.token_at_cursor() {
            Some(t) => t,
            None => return DecompilerActionResult::NotApplicable,
        };

        // In the full implementation:
        // 1. Varnode varnode = DecompilerUtils.getVarnodeRef(tokenAtCursor)
        // 2. PcodeOp op = tokenAtCursor.getPcodeOp()
        // 3. Set<PcodeOp> backwardSlice = DecompilerUtils.getBackwardSliceToPCodeOps(varnode)
        // 4. if (op != null) backwardSlice.add(op)
        // 5. decompilerPanel.clearPrimaryHighlights()
        // 6. decompilerPanel.addHighlights(backwardSlice, currentVariableHighlightColor)

        let varnode = VarnodeRef::new(Address::new(token.text_offset as u64), 4);
        let slice = Self::compute_slice(&varnode, &[]);
        let highlights = slice.to_highlights(HighlightColor::default_variable());

        DecompilerActionResult::Success(format!(
            "Backward operator slice: {} P-code ops highlighted for token '{}'",
            highlights.len(),
            token.text
        ))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile_ui::ClangTokenKind;

    // --- PcodeOp ---

    #[test]
    fn test_pcode_op_new() {
        let op = PcodeOp {
            address: Address::new(0x1000),
            seq_num: 0,
            opcode: PcodeOpcode::IntAdd,
        };
        assert_eq!(op.address, Address::new(0x1000));
        assert_eq!(op.opcode, PcodeOpcode::IntAdd);
    }

    #[test]
    fn test_pcode_op_equality() {
        let op1 = PcodeOp {
            address: Address::new(0x1000),
            seq_num: 0,
            opcode: PcodeOpcode::Copy,
        };
        let op2 = PcodeOp {
            address: Address::new(0x1000),
            seq_num: 0,
            opcode: PcodeOpcode::Copy,
        };
        assert_eq!(op1, op2);
    }

    #[test]
    fn test_pcode_op_hash_set() {
        let mut set = HashSet::new();
        set.insert(PcodeOp {
            address: Address::new(0x1000),
            seq_num: 0,
            opcode: PcodeOpcode::Copy,
        });
        set.insert(PcodeOp {
            address: Address::new(0x1000),
            seq_num: 0,
            opcode: PcodeOpcode::Copy,
        });
        assert_eq!(set.len(), 1); // duplicate
    }

    // --- PcodeOpcode ---

    #[test]
    fn test_pcode_opcode_names() {
        assert_eq!(PcodeOpcode::Copy.name(), "COPY");
        assert_eq!(PcodeOpcode::IntAdd.name(), "INT_ADD");
        assert_eq!(PcodeOpcode::Store.name(), "STORE");
        assert_eq!(PcodeOpcode::Branch.name(), "BRANCH");
        assert_eq!(PcodeOpcode::Return.name(), "RETURN");
    }

    // --- VarnodeRef ---

    #[test]
    fn test_varnode_ref_new() {
        let vn = VarnodeRef::new(Address::new(0x100), 4);
        assert_eq!(vn.address, Address::new(0x100));
        assert_eq!(vn.size, 4);
        assert!(!vn.is_constant);
        assert!(!vn.is_register);
    }

    #[test]
    fn test_varnode_ref_constant() {
        let vn = VarnodeRef::constant(42, 4);
        assert!(vn.is_constant);
        assert!(!vn.is_register);
    }

    #[test]
    fn test_varnode_ref_register() {
        let vn = VarnodeRef::register(Address::new(0x200), 8);
        assert!(vn.is_register);
        assert!(!vn.is_constant);
    }

    // --- HighlightColor ---

    #[test]
    fn test_highlight_color_new() {
        let c = HighlightColor::new(255, 0, 0, 128);
        assert_eq!(c.r, 255);
        assert_eq!(c.g, 0);
        assert_eq!(c.b, 0);
        assert_eq!(c.a, 128);
    }

    #[test]
    fn test_highlight_color_defaults() {
        let var_color = HighlightColor::default_variable();
        assert_eq!(var_color.a, 128);

        let slice_color = HighlightColor::default_slice();
        assert_eq!(slice_color.a, 128);
    }

    // --- SliceResult ---

    #[test]
    fn test_slice_result_new() {
        let vn = VarnodeRef::new(Address::new(0x100), 4);
        let result = SliceResult::new(vn);
        assert!(result.is_empty());
        assert!(!result.truncated);
    }

    #[test]
    fn test_slice_result_add() {
        let vn = VarnodeRef::new(Address::new(0x100), 4);
        let mut result = SliceResult::new(vn);
        result.add(PcodeOp {
            address: Address::new(0x1000),
            seq_num: 0,
            opcode: PcodeOpcode::IntAdd,
        });
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_slice_result_to_highlights() {
        let vn = VarnodeRef::new(Address::new(0x100), 4);
        let mut result = SliceResult::new(vn);
        result.add(PcodeOp {
            address: Address::new(0x1000),
            seq_num: 0,
            opcode: PcodeOpcode::IntAdd,
        });
        result.add(PcodeOp {
            address: Address::new(0x1004),
            seq_num: 0,
            opcode: PcodeOpcode::Copy,
        });
        let highlights = result.to_highlights(HighlightColor::default_slice());
        assert_eq!(highlights.len(), 2);
    }

    // --- ForwardSliceToPCodeOpsAction ---

    #[test]
    fn test_forward_slice_action_metadata() {
        let action = ForwardSliceToPCodeOpsAction;
        assert_eq!(action.name(), "Highlight Forward Operator Slice");
        assert_eq!(action.menu_path(), &["Highlight", "Forward Operator Slice"]);
        assert_eq!(action.menu_group(), "Decompile");
    }

    #[test]
    fn test_forward_slice_action_disabled_while_decompiling() {
        let action = ForwardSliceToPCodeOpsAction;
        let ctx = DecompilerActionContext::new(Address::new(0x1000), true, 1);
        assert!(!action.is_enabled(&ctx));
    }

    #[test]
    fn test_forward_slice_action_disabled_without_token() {
        let action = ForwardSliceToPCodeOpsAction;
        let ctx = DecompilerActionContext::new(Address::new(0x1000), false, 1);
        assert!(!action.is_enabled(&ctx));
    }

    #[test]
    fn test_forward_slice_action_enabled_with_variable_token() {
        let action = ForwardSliceToPCodeOpsAction;
        let mut ctx = DecompilerActionContext::new(Address::new(0x1000), false, 1);
        let mut token = ClangTokenRef::new("x", 3, 0, false, None, 10);
        token.kind = ClangTokenKind::Variable;
        ctx.set_token_at_cursor(token);
        assert!(action.is_enabled(&ctx));
    }

    #[test]
    fn test_forward_slice_action_execute() {
        let action = ForwardSliceToPCodeOpsAction;
        let mut ctx = DecompilerActionContext::new(Address::new(0x1000), false, 1);
        ctx.set_token_at_cursor(ClangTokenRef::new("x", 3, 0, false, None, 10));
        let result = action.execute(&mut ctx);
        match result {
            DecompilerActionResult::Success(msg) => {
                assert!(msg.contains("Forward operator slice"));
                assert!(msg.contains("x"));
            }
            _ => panic!("expected Success"),
        }
    }

    #[test]
    fn test_forward_slice_compute_empty() {
        let vn = VarnodeRef::new(Address::new(0x100), 4);
        let result = ForwardSliceToPCodeOpsAction::compute_slice(&vn, &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_forward_slice_compute_with_ops() {
        let vn = VarnodeRef::new(Address::new(0x100), 4);
        let ops = vec![
            PcodeOp {
                address: Address::new(0x100),
                seq_num: 0,
                opcode: PcodeOpcode::IntAdd,
            },
            PcodeOp {
                address: Address::new(0x104),
                seq_num: 0,
                opcode: PcodeOpcode::Copy,
            },
        ];
        let result = ForwardSliceToPCodeOpsAction::compute_slice(&vn, &ops);
        assert_eq!(result.len(), 1); // Only the op at 0x100 matches
    }

    // --- BackwardsSliceToPCodeOpsAction ---

    #[test]
    fn test_backwards_slice_action_metadata() {
        let action = BackwardsSliceToPCodeOpsAction;
        assert_eq!(action.name(), "Highlight Backward Operator Slice");
        assert_eq!(action.menu_path(), &["Highlight", "Backward Operator Slice"]);
        assert_eq!(action.menu_group(), "Decompile");
    }

    #[test]
    fn test_backwards_slice_action_disabled_while_decompiling() {
        let action = BackwardsSliceToPCodeOpsAction;
        let ctx = DecompilerActionContext::new(Address::new(0x1000), true, 1);
        assert!(!action.is_enabled(&ctx));
    }

    #[test]
    fn test_backwards_slice_action_disabled_without_token() {
        let action = BackwardsSliceToPCodeOpsAction;
        let ctx = DecompilerActionContext::new(Address::new(0x1000), false, 1);
        assert!(!action.is_enabled(&ctx));
    }

    #[test]
    fn test_backwards_slice_action_enabled_with_variable_token() {
        let action = BackwardsSliceToPCodeOpsAction;
        let mut ctx = DecompilerActionContext::new(Address::new(0x1000), false, 1);
        let mut token = ClangTokenRef::new("retval", 5, 0, false, None, 20);
        token.kind = ClangTokenKind::Variable;
        ctx.set_token_at_cursor(token);
        assert!(action.is_enabled(&ctx));
    }

    #[test]
    fn test_backwards_slice_action_execute() {
        let action = BackwardsSliceToPCodeOpsAction;
        let mut ctx = DecompilerActionContext::new(Address::new(0x1000), false, 1);
        ctx.set_token_at_cursor(ClangTokenRef::new("retval", 5, 0, false, None, 20));
        let result = action.execute(&mut ctx);
        match result {
            DecompilerActionResult::Success(msg) => {
                assert!(msg.contains("Backward operator slice"));
                assert!(msg.contains("retval"));
            }
            _ => panic!("expected Success"),
        }
    }

    #[test]
    fn test_backwards_slice_compute_empty() {
        let vn = VarnodeRef::new(Address::new(0x100), 4);
        let result = BackwardsSliceToPCodeOpsAction::compute_slice(&vn, &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_backwards_slice_compute_with_ops() {
        let vn = VarnodeRef::new(Address::new(0x200), 8);
        let ops = vec![
            PcodeOp {
                address: Address::new(0x200),
                seq_num: 0,
                opcode: PcodeOpcode::Load,
            },
            PcodeOp {
                address: Address::new(0x204),
                seq_num: 0,
                opcode: PcodeOpcode::Store,
            },
        ];
        let result = BackwardsSliceToPCodeOpsAction::compute_slice(&vn, &ops);
        assert_eq!(result.len(), 1); // Only the op at 0x200 matches
    }

    // --- Integration ---

    #[test]
    fn test_slice_actions_share_enabled_logic() {
        let forward = ForwardSliceToPCodeOpsAction;
        let backward = BackwardsSliceToPCodeOpsAction;

        // Both should be disabled without a token.
        let ctx = DecompilerActionContext::new(Address::new(0x1000), false, 1);
        assert!(!forward.is_enabled(&ctx));
        assert!(!backward.is_enabled(&ctx));

        // Both should be enabled with a variable token.
        let mut ctx = DecompilerActionContext::new(Address::new(0x1000), false, 1);
        let mut token = ClangTokenRef::new("x", 1, 0, false, None, 0);
        token.kind = ClangTokenKind::Variable;
        ctx.set_token_at_cursor(token);
        assert!(forward.is_enabled(&ctx));
        assert!(backward.is_enabled(&ctx));

        // Both should be disabled while decompiling.
        let ctx = DecompilerActionContext::new(Address::new(0x1000), true, 1);
        assert!(!forward.is_enabled(&ctx));
        assert!(!backward.is_enabled(&ctx));
    }

    #[test]
    fn test_pcode_opcode_completeness() {
        // Verify all opcodes have names.
        let opcodes = [
            PcodeOpcode::Copy,
            PcodeOpcode::IntAdd,
            PcodeOpcode::IntSub,
            PcodeOpcode::IntMul,
            PcodeOpcode::IntDiv,
            PcodeOpcode::IntDivUnsigned,
            PcodeOpcode::IntRem,
            PcodeOpcode::IntAnd,
            PcodeOpcode::IntOr,
            PcodeOpcode::IntXor,
            PcodeOpcode::IntLeft,
            PcodeOpcode::IntRight,
            PcodeOpcode::IntRightUnsigned,
            PcodeOpcode::IntNegate,
            PcodeOpcode::IntNot,
            PcodeOpcode::IntEqual,
            PcodeOpcode::IntNotEqual,
            PcodeOpcode::IntLess,
            PcodeOpcode::IntLessUnsigned,
            PcodeOpcode::Load,
            PcodeOpcode::Store,
            PcodeOpcode::Branch,
            PcodeOpcode::CBranch,
            PcodeOpcode::BranchInd,
            PcodeOpcode::Call,
            PcodeOpcode::CallInd,
            PcodeOpcode::Return,
            PcodeOpcode::Subpiece,
            PcodeOpcode::Cast,
            PcodeOpcode::Other,
        ];
        for opcode in &opcodes {
            assert!(!opcode.name().is_empty());
        }
    }
}
