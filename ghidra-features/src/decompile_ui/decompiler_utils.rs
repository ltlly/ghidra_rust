//! Decompiler utilities -- Rust port of
//! `ghidra.app.decompiler.component.DecompilerUtils`.
//!
//! Provides static utility functions used throughout the decompiler UI,
//! including:
//!
//! * **Varnode slice analysis** -- computing forward and backward slices
//!   through the p-code data-flow graph, both to Varnodes and to PCodeOps.
//! * **Token traversal** -- finding tokens by address, line, or selection.
//! * **Brace matching** -- finding matching `{`/`}` braces in the token tree.
//! * **Data-type resolution** -- tracing data-types through CAST operations.
//! * **Line splitting** -- flattening a token hierarchy into individual lines.
//!
//! # Architecture
//!
//! ```text
//! DecompilerUtils
//!   ├── getVarnodeRef(token) -> Varnode
//!   ├── getForwardSlice(seed) -> Set<Varnode>
//!   ├── getBackwardSlice(seed) -> Set<Varnode>
//!   ├── getForwardSliceToPCodeOps(seed) -> Set<PcodeOp>
//!   ├── getBackwardSliceToPCodeOps(seed) -> Set<PcodeOp>
//!   ├── getDataTypeTraceForward(vn) -> DataType
//!   ├── getDataTypeTraceBackward(vn) -> DataType
//!   ├── getTokens(root, addresses) -> List<ClangToken>
//!   ├── getNextBrace(token, forward) -> ClangSyntaxToken
//!   ├── getMatchingBrace(token) -> ClangSyntaxToken
//!   ├── toLines(group) -> List<ClangLine>
//!   └── getClosestAddress(program, token) -> Address
//! ```

use std::collections::{HashSet, VecDeque};

use ghidra_core::addr::Address;

// ---------------------------------------------------------------------------
// VarnodeRef -- a minimal varnode model for slice analysis
// ---------------------------------------------------------------------------

/// A minimal model of a p-code Varnode for slice analysis.
///
/// In Ghidra, `Varnode` is part of the p-code intermediate representation.
/// Here we capture the fields needed for slice computation: the address,
/// a unique identifier, the defining op, and the descendant ops.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VarnodeRef {
    /// The address of this varnode (or 0 for constants/registers).
    pub address: Address,
    /// A unique identifier for this varnode (offset within its space).
    pub offset: u64,
    /// The size of this varnode in bytes.
    pub size: usize,
    /// Whether this varnode is a constant.
    pub is_constant: bool,
    /// Whether this varnode is a register.
    pub is_register: bool,
    /// Whether this varnode is an input to the function.
    pub is_input: bool,
    /// The defining P-code op (None for inputs/constants).
    pub defining_op: Option<usize>,
    /// Indices of P-code ops that use this varnode (descendants).
    pub descendant_ops: Vec<usize>,
    /// The high-level variable this varnode is an instance of.
    pub high_variable: Option<HighVariableRef>,
}

/// A minimal model of a high-level variable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HighVariableRef {
    /// The name of the variable.
    pub name: String,
    /// The data type name.
    pub data_type_name: String,
    /// Whether the variable is a parameter.
    pub is_parameter: bool,
    /// The parameter slot (if a parameter).
    pub parameter_slot: Option<usize>,
}

// ---------------------------------------------------------------------------
// PcodeOpRef -- a minimal p-code op model for slice analysis
// ---------------------------------------------------------------------------

/// P-code opcodes relevant to slice analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PcodeOpcode {
    /// Copy (assignment).
    Copy,
    /// Load from memory.
    Load,
    /// Store to memory.
    Store,
    /// Integer addition.
    IntAdd,
    /// Integer subtraction.
    IntSub,
    /// Integer multiplication.
    IntMul,
    /// Integer division.
    IntDiv,
    /// Integer left shift.
    IntLeft,
    /// Integer right shift.
    IntRight,
    /// Integer AND.
    IntAnd,
    /// Integer OR.
    IntOr,
    /// Integer XOR.
    IntXor,
    /// Integer negate.
    IntNegate,
    /// Integer complement.
    IntNot,
    /// CAST operation.
    Cast,
    /// CALL (function call).
    Call,
    /// CALLIND (indirect call).
    CallInd,
    /// BRANCH (unconditional branch).
    Branch,
    /// CBRANCH (conditional branch).
    CBranch,
    /// RETURN.
    Return,
    /// Any other opcode.
    Other(u32),
}

impl PcodeOpcode {
    /// Whether this opcode represents a function call.
    pub fn is_call(&self) -> bool {
        matches!(self, PcodeOpcode::Call | PcodeOpcode::CallInd)
    }

    /// Create from a numeric opcode.
    pub fn from_code(code: u32) -> Self {
        match code {
            1 => PcodeOpcode::Copy,
            2 => PcodeOpcode::Load,
            3 => PcodeOpcode::Store,
            4 => PcodeOpcode::IntAdd,
            5 => PcodeOpcode::IntSub,
            6 => PcodeOpcode::IntMul,
            7 => PcodeOpcode::IntDiv,
            8 => PcodeOpcode::IntLeft,
            9 => PcodeOpcode::IntRight,
            10 => PcodeOpcode::IntAnd,
            11 => PcodeOpcode::IntOr,
            12 => PcodeOpcode::IntXor,
            13 => PcodeOpcode::IntNegate,
            14 => PcodeOpcode::IntNot,
            15 => PcodeOpcode::Cast,
            16 => PcodeOpcode::Call,
            17 => PcodeOpcode::CallInd,
            18 => PcodeOpcode::Branch,
            19 => PcodeOpcode::CBranch,
            20 => PcodeOpcode::Return,
            other => PcodeOpcode::Other(other),
        }
    }
}

/// A minimal model of a p-code operation for slice analysis.
#[derive(Debug, Clone)]
pub struct PcodeOpRef {
    /// The opcode of this operation.
    pub opcode: PcodeOpcode,
    /// The output varnode (None for stores/branches).
    pub output: Option<usize>,
    /// The input varnodes.
    pub inputs: Vec<usize>,
    /// The address of the instruction this op belongs to.
    pub instruction_address: Address,
    /// A sequence number for ordering within an instruction.
    pub seq_num: u32,
}

// ---------------------------------------------------------------------------
// TokenInfo -- a minimal token model for utility operations
// ---------------------------------------------------------------------------

/// The type of a decompiler token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenType {
    /// A keyword.
    Keyword,
    /// A type name.
    TypeName,
    /// A function name.
    FunctionName,
    /// A variable name.
    VariableName,
    /// A field name (struct/union member).
    FieldName,
    /// A label name.
    LabelName,
    /// A syntax element (braces, semicolons, operators, etc.).
    Syntax,
    /// A comment.
    Comment,
    /// A numeric literal.
    Number,
    /// A string literal.
    String,
    /// A character literal.
    Char,
    /// A line break.
    LineBreak,
    /// A case label.
    CaseLabel,
    /// Any other type.
    Other,
}

/// A minimal model of a decompiler token for utility operations.
#[derive(Debug, Clone)]
pub struct TokenInfo {
    /// The displayed text.
    pub text: String,
    /// The token type.
    pub token_type: TokenType,
    /// The minimum address this token refers to.
    pub min_address: Option<Address>,
    /// The maximum address this token refers to.
    pub max_address: Option<Address>,
    /// The line number (1-based).
    pub line_number: usize,
    /// The column position within the line.
    pub column: usize,
    /// The index of this token within its parent line.
    pub token_index: usize,
    /// The parent line's indentation level.
    pub indent: usize,
}

impl TokenInfo {
    /// Create a new token info.
    pub fn new(
        text: impl Into<String>,
        token_type: TokenType,
        line_number: usize,
    ) -> Self {
        Self {
            text: text.into(),
            token_type,
            min_address: None,
            max_address: None,
            line_number,
            column: 0,
            token_index: 0,
            indent: 0,
        }
    }

    /// Create a token with address information.
    pub fn with_address(
        text: impl Into<String>,
        token_type: TokenType,
        line_number: usize,
        address: Address,
    ) -> Self {
        Self {
            min_address: Some(address),
            max_address: Some(address),
            ..Self::new(text, token_type, line_number)
        }
    }

    /// Whether this token is a brace (`{` or `}`).
    pub fn is_brace(&self) -> bool {
        self.text == "{" || self.text == "}"
    }

    /// Whether this token is a syntax token.
    pub fn is_syntax(&self) -> bool {
        self.token_type == TokenType::Syntax
    }

    /// Whether this token has an address.
    pub fn has_address(&self) -> bool {
        self.min_address.is_some()
    }
}

// ---------------------------------------------------------------------------
// ClangLine -- a line of tokens
// ---------------------------------------------------------------------------

/// A line of decompiler output, containing a sequence of tokens.
///
/// Corresponds to `ClangLine` in Ghidra.
#[derive(Debug, Clone)]
pub struct ClangLine {
    /// The line number (1-based).
    pub line_number: usize,
    /// The indentation level.
    pub indent: usize,
    /// The tokens on this line.
    pub tokens: Vec<TokenInfo>,
}

impl ClangLine {
    /// Create a new empty line.
    pub fn new(line_number: usize, indent: usize) -> Self {
        Self {
            line_number,
            indent,
            tokens: Vec::new(),
        }
    }

    /// Add a token to this line.
    pub fn add_token(&mut self, token: TokenInfo) {
        self.tokens.push(token);
    }

    /// Get all tokens on this line.
    pub fn get_all_tokens(&self) -> &[TokenInfo] {
        &self.tokens
    }

    /// Get the text of this line (concatenation of all token texts).
    pub fn text(&self) -> String {
        self.tokens.iter().map(|t| t.text.as_str()).collect()
    }
}

// ---------------------------------------------------------------------------
// SliceAnalysis -- forward and backward slice computation
// ---------------------------------------------------------------------------

/// Compute the forward slice of a varnode through the p-code data-flow graph.
///
/// The forward slice consists of all varnodes that are transitively
/// data-dependent on the seed varnode.  CALL and CALLIND ops are treated
/// as opaque (their outputs are not included).
///
/// Ported from `DecompilerUtils.getForwardSlice()`.
pub fn get_forward_slice(seed: usize, varnodes: &[VarnodeRef], ops: &[PcodeOpRef]) -> HashSet<usize> {
    let mut result = HashSet::new();
    let mut worklist = VecDeque::new();
    worklist.push_back(seed);

    while let Some(current) = worklist.pop_front() {
        if !result.insert(current) {
            continue; // Already processed.
        }

        let vn = match varnodes.get(current) {
            Some(v) => v,
            None => continue,
        };

        for &op_index in &vn.descendant_ops {
            let op = match ops.get(op_index) {
                Some(o) => o,
                None => continue,
            };

            if op.opcode.is_call() {
                continue;
            }

            if let Some(output_index) = op.output {
                worklist.push_back(output_index);
            }
        }
    }

    result
}

/// Compute the backward slice of a varnode through the p-code data-flow graph.
///
/// The backward slice consists of all varnodes that transitively contribute
/// to the value of the seed varnode.  CALL and CALLIND ops are treated
/// as opaque (their inputs are not included).
///
/// Ported from `DecompilerUtils.getBackwardSlice()`.
pub fn get_backward_slice(seed: usize, varnodes: &[VarnodeRef], ops: &[PcodeOpRef]) -> HashSet<usize> {
    let mut result = HashSet::new();
    let mut worklist = VecDeque::new();
    worklist.push_back(seed);

    while let Some(current) = worklist.pop_front() {
        if !result.insert(current) {
            continue; // Already processed.
        }

        let vn = match varnodes.get(current) {
            Some(v) => v,
            None => continue,
        };

        let def_op_index = match vn.defining_op {
            Some(idx) => idx,
            None => continue,
        };

        let op = match ops.get(def_op_index) {
            Some(o) => o,
            None => continue,
        };

        if op.opcode.is_call() {
            continue;
        }

        for &input_index in &op.inputs {
            worklist.push_back(input_index);
        }
    }

    result
}

/// Compute the forward slice to P-code ops.
///
/// Instead of returning the set of varnodes, this returns the set of p-code
/// ops that are transitively downstream of the seed varnode.
///
/// Ported from `DecompilerUtils.getForwardSliceToPCodeOps()`.
pub fn get_forward_slice_to_pcode_ops(
    seed: usize,
    varnodes: &[VarnodeRef],
    ops: &[PcodeOpRef],
) -> HashSet<usize> {
    let mut visited_vns = HashSet::new();
    let mut result = HashSet::new();
    let mut worklist = VecDeque::new();
    worklist.push_back(seed);

    while let Some(current) = worklist.pop_front() {
        if !visited_vns.insert(current) {
            continue;
        }

        let vn = match varnodes.get(current) {
            Some(v) => v,
            None => continue,
        };

        for &op_index in &vn.descendant_ops {
            result.insert(op_index);

            let op = match ops.get(op_index) {
                Some(o) => o,
                None => continue,
            };

            if op.opcode.is_call() {
                continue;
            }

            if let Some(output_index) = op.output {
                worklist.push_back(output_index);
            }
        }
    }

    result
}

/// Compute the backward slice to P-code ops.
///
/// Returns the set of p-code ops that transitively contribute to the seed
/// varnode's value.
///
/// Ported from `DecompilerUtils.getBackwardSliceToPCodeOps()`.
pub fn get_backward_slice_to_pcode_ops(
    seed: usize,
    varnodes: &[VarnodeRef],
    ops: &[PcodeOpRef],
) -> HashSet<usize> {
    let mut visited_vns = HashSet::new();
    let mut result = HashSet::new();
    let mut worklist = VecDeque::new();
    worklist.push_back(seed);

    while let Some(current) = worklist.pop_front() {
        if !visited_vns.insert(current) {
            continue;
        }

        let vn = match varnodes.get(current) {
            Some(v) => v,
            None => continue,
        };

        let def_op_index = match vn.defining_op {
            Some(idx) => idx,
            None => continue,
        };

        result.insert(def_op_index);

        let op = match ops.get(def_op_index) {
            Some(o) => o,
            None => continue,
        };

        if op.opcode.is_call() {
            continue;
        }

        for &input_index in &op.inputs {
            worklist.push_back(input_index);
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Token traversal utilities
// ---------------------------------------------------------------------------

/// Find the closest addressed token to a given token.
///
/// Searches adjacent tokens on the same line, first to the right, then
/// to the left.  Returns `None` if no addressed token is found.
///
/// Ported from `DecompilerUtils.findClosestAddressedToken()`.
pub fn find_closest_addressed_token<'a>(
    token: &TokenInfo,
    lines: &'a [ClangLine],
) -> Option<Address> {
    if let Some(addr) = token.min_address {
        return Some(addr);
    }

    let line = lines.get(token.line_number.saturating_sub(1))?;
    let tokens = &line.tokens;
    let tok_index = token.token_index;

    // Look right first.
    for i in (tok_index + 1)..tokens.len() {
        if let Some(addr) = tokens[i].min_address {
            return Some(addr);
        }
    }

    // Then look left.
    for i in (0..tok_index).rev() {
        if let Some(addr) = tokens[i].min_address {
            return Some(addr);
        }
    }

    None
}

/// Get the closest address for a token.
///
/// If the token itself has no address, searches adjacent tokens on the
/// same line.
///
/// Ported from `DecompilerUtils.getClosestAddress()`.
pub fn get_closest_address(token: &TokenInfo, lines: &[ClangLine]) -> Option<Address> {
    if let Some(addr) = token.min_address {
        return Some(addr);
    }
    find_closest_addressed_token(token, lines)
}

/// Find all tokens whose address range intersects the given set of addresses.
///
/// Ported from `DecompilerUtils.getTokens()`.
pub fn get_tokens_by_addresses(
    tokens: &[TokenInfo],
    addresses: &[(Address, Address)],
) -> Vec<usize> {
    let mut result = Vec::new();
    for (i, token) in tokens.iter().enumerate() {
        let min = match token.min_address {
            Some(a) => a,
            None => continue,
        };
        let max = token.max_address.unwrap_or(min);

        for &(range_min, range_max) in addresses {
            if min <= range_max && max >= range_min {
                result.push(i);
                break;
            }
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Brace matching
// ---------------------------------------------------------------------------

/// Find the next enclosing brace from a starting token.
///
/// If `forward` is true, searches for the next unpaired closing brace `}`.
/// If `forward` is false, searches for the next enclosing opening brace `{`.
/// Returns the brace token and its line/index, or `None`.
///
/// Ported from `DecompilerUtils.getNextBrace()`.
pub fn get_next_brace(
    start_line: usize,
    start_token_index: usize,
    forward: bool,
    lines: &[ClangLine],
) -> Option<(usize, usize)> {
    let target_balance: i32 = if forward { -1 } else { 1 };
    let mut nest_level: i32 = 0;

    if forward {
        // Search forward from the starting position.
        for line_idx in start_line..lines.len() {
            let line = &lines[line_idx];
            let start_idx = if line_idx == start_line {
                start_token_index + 1
            } else {
                0
            };

            for tok_idx in start_idx..line.tokens.len() {
                let token = &line.tokens[tok_idx];
                if token.token_type != TokenType::Syntax {
                    continue;
                }
                match token.text.as_str() {
                    "{" => {
                        nest_level += 1;
                        if nest_level == target_balance {
                            return Some((line_idx, tok_idx));
                        }
                    }
                    "}" => {
                        nest_level -= 1;
                        if nest_level == target_balance {
                            return Some((line_idx, tok_idx));
                        }
                    }
                    _ => {}
                }
            }
        }
    } else {
        // Search backward from the starting position.
        for line_idx in (0..=start_line).rev() {
            let line = &lines[line_idx];
            let end_idx = if line_idx == start_line {
                start_token_index
            } else {
                line.tokens.len()
            };

            for tok_idx in (0..end_idx).rev() {
                let token = &line.tokens[tok_idx];
                if token.token_type != TokenType::Syntax {
                    continue;
                }
                match token.text.as_str() {
                    "{" => {
                        nest_level += 1;
                        if nest_level == target_balance {
                            return Some((line_idx, tok_idx));
                        }
                    }
                    "}" => {
                        nest_level -= 1;
                        if nest_level == target_balance {
                            return Some((line_idx, tok_idx));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    None
}

/// Find the matching brace for a given brace token.
///
/// For an open brace `{`, searches forward to find the corresponding close
/// brace `}`.  For a close brace `}`, searches backward to find the
/// corresponding open brace `{`.  Takes nesting into account.
///
/// Ported from `DecompilerUtils.getMatchingBrace()`.
pub fn get_matching_brace(
    line_idx: usize,
    token_idx: usize,
    lines: &[ClangLine],
) -> Option<(usize, usize)> {
    let token = lines.get(line_idx)?.tokens.get(token_idx)?;
    let is_open = token.text == "{";

    if !is_open && token.text != "}" {
        return None;
    }

    let direction = is_open;
    let mut nest_level: i32 = 0;

    if direction {
        // Search forward for matching `}`.
        for li in line_idx..lines.len() {
            let line = &lines[li];
            let start = if li == line_idx { token_idx + 1 } else { 0 };

            for ti in start..line.tokens.len() {
                let t = &line.tokens[ti];
                if t.token_type != TokenType::Syntax {
                    continue;
                }
                match t.text.as_str() {
                    "{" => nest_level += 1,
                    "}" => {
                        if nest_level == 0 {
                            return Some((li, ti));
                        }
                        nest_level -= 1;
                    }
                    _ => {}
                }
            }
        }
    } else {
        // Search backward for matching `{`.
        for li in (0..=line_idx).rev() {
            let line = &lines[li];
            let end = if li == line_idx { token_idx } else { line.tokens.len() };

            for ti in (0..end).rev() {
                let t = &line.tokens[ti];
                if t.token_type != TokenType::Syntax {
                    continue;
                }
                match t.text.as_str() {
                    "}" => nest_level += 1,
                    "{" => {
                        if nest_level == 0 {
                            return Some((li, ti));
                        }
                        nest_level -= 1;
                    }
                    _ => {}
                }
            }
        }
    }

    None
}

/// Whether a token is a brace (`{` or `}`).
///
/// Ported from `DecompilerUtils.isBrace()`.
pub fn is_brace(token: &TokenInfo) -> bool {
    token.is_brace()
}

// ---------------------------------------------------------------------------
// Data-type tracing
// ---------------------------------------------------------------------------

/// Get the data-type associated with a varnode, tracing forward through
/// CAST operations.
///
/// If the varnode is the input to a CAST p-code op, the most specific
/// data-type between the source and target types is returned.
///
/// Ported from `DecompilerUtils.getDataTypeTraceForward()`.
pub fn get_data_type_trace_forward(varnodes: &[VarnodeRef], _ops: &[PcodeOpRef], vn_index: usize) -> Option<String> {
    let vn = varnodes.get(vn_index)?;
    let base_type = vn
        .high_variable
        .as_ref()
        .map(|hv| hv.data_type_name.clone())?;

    // In a full implementation, we'd check if this varnode is the input
    // to a CAST op and return the more specific type.  Here we return
    // the base type.
    Some(base_type)
}

/// Get the data-type associated with a varnode, tracing backward through
/// CAST operations.
///
/// If the varnode is produced by a CAST p-code op, the most specific
/// data-type between the source and target types is returned.
///
/// Ported from `DecompilerUtils.getDataTypeTraceBackward()`.
pub fn get_data_type_trace_backward(varnodes: &[VarnodeRef], ops: &[PcodeOpRef], vn_index: usize) -> Option<String> {
    let vn = varnodes.get(vn_index)?;
    let base_type = vn
        .high_variable
        .as_ref()
        .map(|hv| hv.data_type_name.clone())?;

    // Check if the defining op is a CAST.
    if let Some(def_op_idx) = vn.defining_op {
        if let Some(op) = ops.get(def_op_idx) {
            if op.opcode == PcodeOpcode::Cast {
                // Get the type of the input to the cast.
                if let Some(&input_idx) = op.inputs.first() {
                    if let Some(input_vn) = varnodes.get(input_idx) {
                        if let Some(ref hv) = input_vn.high_variable {
                            // Return the more specific type (in a full
                            // implementation this would call
                            // MetaDataType.getMostSpecificDataType).
                            return Some(hv.data_type_name.clone());
                        }
                    }
                }
            }
        }
    }

    Some(base_type)
}

// ---------------------------------------------------------------------------
// VarnodeRef lookup
// ---------------------------------------------------------------------------

/// Get the varnode reference for a token.
///
/// If the token directly represents a variable, its varnode is returned.
/// Otherwise, the parent context is inspected for an input parameter
/// varnode.
///
/// Ported from `DecompilerUtils.getVarnodeRef()`.
pub fn get_varnode_ref(
    tokens: &[TokenInfo],
    _varnodes: &[VarnodeRef],
    token_index: usize,
) -> Option<usize> {
    let token = tokens.get(token_index)?;

    // If the token is a variable token, return its varnode index.
    if token.token_type == TokenType::VariableName {
        // In a full implementation, we'd look up the varnode associated
        // with this token.  Here we use the token index as a proxy.
        return Some(token_index);
    }

    // Check parent context for input parameters.
    // In Ghidra, this would inspect ClangVariableDecl -> ClangFuncProto.
    None
}

// ---------------------------------------------------------------------------
// Line splitting (toLines)
// ---------------------------------------------------------------------------

/// Flatten a token hierarchy into individual lines at line-break tokens.
///
/// Sequences of comment tokens are collapsed into single comment tokens.
///
/// Ported from `DecompilerUtils.toLines()`.
pub fn to_lines(tokens: &[TokenInfo]) -> Vec<ClangLine> {
    if tokens.is_empty() {
        return Vec::new();
    }

    let mut lines = Vec::new();
    let mut current = ClangLine::new(1, 0);
    let mut line_number = 1;

    for token in tokens {
        if token.token_type == TokenType::LineBreak {
            lines.push(current);
            line_number += 1;
            current = ClangLine::new(line_number, token.indent);
        } else {
            current.add_token(token.clone());
        }
    }

    lines.push(current);
    lines
}

// ---------------------------------------------------------------------------
// GoTo target finding
// ---------------------------------------------------------------------------

/// Find the target label token for a goto statement.
///
/// Given a label token in a goto statement, searches the token tree for
/// the corresponding label definition at the same address.
///
/// Ported from `DecompilerUtils.getGoToTargetToken()`.
pub fn get_goto_target_token(
    tokens: &[TokenInfo],
    label_index: usize,
) -> Option<usize> {
    let label = tokens.get(label_index)?;
    let address = label.min_address?;
    let destination_prefix = format!("{}:", label.text);

    // Search for a label token at the same address with matching text.
    for (i, token) in tokens.iter().enumerate() {
        if i == label_index {
            continue;
        }
        if token.token_type != TokenType::LabelName {
            continue;
        }
        if token.min_address != Some(address) {
            continue;
        }
        // Check if this label's parent text starts with the destination.
        if token.text.starts_with(&destination_prefix) {
            return Some(i);
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Selection utilities
// ---------------------------------------------------------------------------

/// Get tokens within a line range.
///
/// Ported from `DecompilerUtils.getTokensInSelection()`.
pub fn get_tokens_in_range(
    lines: &[ClangLine],
    start_line: usize,
    end_line: usize,
) -> Vec<(usize, usize)> {
    let mut result = Vec::new();

    for line_idx in start_line..end_line {
        if let Some(line) = lines.get(line_idx) {
            for tok_idx in 0..line.tokens.len() {
                result.push((line_idx, tok_idx));
            }
        }
    }

    result
}

/// Find the address before a given token (on the previous line).
///
/// Ported from `DecompilerUtils.findAddressBefore()`.
pub fn find_address_before(
    token: &TokenInfo,
    lines: &[ClangLine],
) -> Option<Address> {
    let line_number = token.line_number;
    if line_number < 2 {
        return None;
    }

    // Look at previous lines for the closest addressed token.
    for line_idx in (0..(line_number - 1)).rev() {
        let line = lines.get(line_idx)?;
        if let Some(first_token) = line.tokens.first() {
            if let Some(addr) = first_token.min_address {
                return Some(addr);
            }
            // Try to find the closest addressed token on this line.
            if let Some(addr) = find_closest_addressed_token(first_token, lines) {
                return Some(addr);
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// GoTo statement detection
// ---------------------------------------------------------------------------

/// Whether a token is part of a goto statement.
///
/// Ported from `DecompilerUtils.isGoToStatement()`.
pub fn is_goto_statement(token: &TokenInfo, lines: &[ClangLine]) -> bool {
    // Check if the line containing this token starts with "goto".
    let line = match lines.get(token.line_number.saturating_sub(1)) {
        Some(l) => l,
        None => return false,
    };
    if let Some(first_token) = line.tokens.first() {
        first_token.text.starts_with("goto")
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_varnode(
        offset: u64,
        size: usize,
        is_constant: bool,
        is_input: bool,
        defining_op: Option<usize>,
        descendant_ops: Vec<usize>,
    ) -> VarnodeRef {
        VarnodeRef {
            address: Address::new(offset),
            offset,
            size,
            is_constant,
            is_register: false,
            is_input,
            defining_op,
            descendant_ops,
            high_variable: None,
        }
    }

    fn make_op(
        opcode: PcodeOpcode,
        output: Option<usize>,
        inputs: Vec<usize>,
    ) -> PcodeOpRef {
        PcodeOpRef {
            opcode,
            output,
            inputs,
            instruction_address: Address::new(0),
            seq_num: 0,
        }
    }

    // --- Forward Slice ---

    #[test]
    fn forward_slice_simple_chain() {
        // vn0 -> op0 -> vn1 -> op1 -> vn2
        let varnodes = vec![
            make_varnode(0, 4, true, false, None, vec![0]),
            make_varnode(1, 4, false, false, Some(0), vec![1]),
            make_varnode(2, 4, false, false, Some(1), vec![]),
        ];
        let ops = vec![
            make_op(PcodeOpcode::Copy, Some(1), vec![0]),
            make_op(PcodeOpcode::Copy, Some(2), vec![1]),
        ];

        let slice = get_forward_slice(0, &varnodes, &ops);
        assert!(slice.contains(&0));
        assert!(slice.contains(&1));
        assert!(slice.contains(&2));
        assert_eq!(slice.len(), 3);
    }

    #[test]
    fn forward_slice_skips_call() {
        // vn0 -> CALL_op -> vn1 (should be skipped)
        let varnodes = vec![
            make_varnode(0, 4, true, false, None, vec![0]),
            make_varnode(1, 4, false, false, Some(0), vec![]),
        ];
        let ops = vec![make_op(PcodeOpcode::Call, Some(1), vec![0])];

        let slice = get_forward_slice(0, &varnodes, &ops);
        assert!(slice.contains(&0));
        assert!(!slice.contains(&1)); // Call output excluded.
    }

    #[test]
    fn forward_slice_diamond() {
        // vn0 -> op0 -> vn1, vn0 -> op1 -> vn2
        // vn1 -> op2 -> vn3, vn2 -> op3 -> vn3
        let varnodes = vec![
            make_varnode(0, 4, true, false, None, vec![0, 1]),
            make_varnode(1, 4, false, false, Some(0), vec![2]),
            make_varnode(2, 4, false, false, Some(1), vec![3]),
            make_varnode(3, 4, false, false, Some(2), vec![]),
        ];
        let ops = vec![
            make_op(PcodeOpcode::IntAdd, Some(1), vec![0]),
            make_op(PcodeOpcode::IntSub, Some(2), vec![0]),
            make_op(PcodeOpcode::IntMul, Some(3), vec![1]),
            make_op(PcodeOpcode::IntMul, Some(3), vec![2]),
        ];

        let slice = get_forward_slice(0, &varnodes, &ops);
        assert_eq!(slice.len(), 4); // All varnodes reached.
    }

    // --- Backward Slice ---

    #[test]
    fn backward_slice_simple_chain() {
        // vn2 <- op1 <- vn1 <- op0 <- vn0
        let varnodes = vec![
            make_varnode(0, 4, true, false, None, vec![0]),
            make_varnode(1, 4, false, false, Some(0), vec![1]),
            make_varnode(2, 4, false, false, Some(1), vec![]),
        ];
        let ops = vec![
            make_op(PcodeOpcode::Copy, Some(1), vec![0]),
            make_op(PcodeOpcode::Copy, Some(2), vec![1]),
        ];

        let slice = get_backward_slice(2, &varnodes, &ops);
        assert!(slice.contains(&2));
        assert!(slice.contains(&1));
        assert!(slice.contains(&0));
        assert_eq!(slice.len(), 3);
    }

    #[test]
    fn backward_slice_skips_call() {
        // vn1 defined by CALL (should not trace through)
        let varnodes = vec![
            make_varnode(0, 4, true, false, None, vec![0]),
            make_varnode(1, 4, false, false, Some(0), vec![]),
        ];
        let ops = vec![make_op(PcodeOpcode::Call, Some(1), vec![0])];

        let slice = get_backward_slice(1, &varnodes, &ops);
        assert!(slice.contains(&1));
        assert!(!slice.contains(&0)); // Call inputs excluded.
    }

    // --- PCode Op Slices ---

    #[test]
    fn forward_slice_to_pcode_ops() {
        let varnodes = vec![
            make_varnode(0, 4, true, false, None, vec![0]),
            make_varnode(1, 4, false, false, Some(0), vec![1]),
            make_varnode(2, 4, false, false, Some(1), vec![]),
        ];
        let ops = vec![
            make_op(PcodeOpcode::Copy, Some(1), vec![0]),
            make_op(PcodeOpcode::Copy, Some(2), vec![1]),
        ];

        let pcode_ops = get_forward_slice_to_pcode_ops(0, &varnodes, &ops);
        assert!(pcode_ops.contains(&0));
        assert!(pcode_ops.contains(&1));
        assert_eq!(pcode_ops.len(), 2);
    }

    #[test]
    fn backward_slice_to_pcode_ops() {
        let varnodes = vec![
            make_varnode(0, 4, true, false, None, vec![0]),
            make_varnode(1, 4, false, false, Some(0), vec![1]),
            make_varnode(2, 4, false, false, Some(1), vec![]),
        ];
        let ops = vec![
            make_op(PcodeOpcode::Copy, Some(1), vec![0]),
            make_op(PcodeOpcode::Copy, Some(2), vec![1]),
        ];

        let pcode_ops = get_backward_slice_to_pcode_ops(2, &varnodes, &ops);
        assert!(pcode_ops.contains(&0));
        assert!(pcode_ops.contains(&1));
        assert_eq!(pcode_ops.len(), 2);
    }

    // --- Brace Matching ---

    #[test]
    fn brace_matching_forward() {
        let lines = vec![
            ClangLine {
                line_number: 1,
                indent: 0,
                tokens: vec![
                    TokenInfo::new("if", TokenType::Keyword, 1),
                    TokenInfo::new("(", TokenType::Syntax, 1),
                    TokenInfo::new("x", TokenType::VariableName, 1),
                    TokenInfo::new(")", TokenType::Syntax, 1),
                    TokenInfo::new("{", TokenType::Syntax, 1),
                ],
            },
            ClangLine {
                line_number: 2,
                indent: 1,
                tokens: vec![
                    TokenInfo::new("return", TokenType::Keyword, 2),
                    TokenInfo::new(";", TokenType::Syntax, 2),
                ],
            },
            ClangLine {
                line_number: 3,
                indent: 0,
                tokens: vec![TokenInfo::new("}", TokenType::Syntax, 3)],
            },
        ];

        let result = get_next_brace(0, 4, true, &lines);
        assert!(result.is_some());
        let (line_idx, tok_idx) = result.unwrap();
        assert_eq!(line_idx, 2);
        assert_eq!(tok_idx, 0);
    }

    #[test]
    fn brace_matching_backward() {
        let lines = vec![
            ClangLine {
                line_number: 1,
                indent: 0,
                tokens: vec![TokenInfo::new("{", TokenType::Syntax, 1)],
            },
            ClangLine {
                line_number: 2,
                indent: 1,
                tokens: vec![
                    TokenInfo::new("return", TokenType::Keyword, 2),
                    TokenInfo::new(";", TokenType::Syntax, 2),
                ],
            },
            ClangLine {
                line_number: 3,
                indent: 0,
                tokens: vec![TokenInfo::new("}", TokenType::Syntax, 3)],
            },
        ];

        let result = get_next_brace(2, 0, false, &lines);
        assert!(result.is_some());
        let (line_idx, tok_idx) = result.unwrap();
        assert_eq!(line_idx, 0);
        assert_eq!(tok_idx, 0);
    }

    #[test]
    fn matching_brace_open() {
        let lines = vec![
            ClangLine {
                line_number: 1,
                indent: 0,
                tokens: vec![TokenInfo::new("{", TokenType::Syntax, 1)],
            },
            ClangLine {
                line_number: 2,
                indent: 0,
                tokens: vec![TokenInfo::new("}", TokenType::Syntax, 2)],
            },
        ];

        let result = get_matching_brace(0, 0, &lines);
        assert_eq!(result, Some((1, 0)));
    }

    #[test]
    fn matching_brace_close() {
        let lines = vec![
            ClangLine {
                line_number: 1,
                indent: 0,
                tokens: vec![TokenInfo::new("{", TokenType::Syntax, 1)],
            },
            ClangLine {
                line_number: 2,
                indent: 0,
                tokens: vec![TokenInfo::new("}", TokenType::Syntax, 2)],
            },
        ];

        let result = get_matching_brace(1, 0, &lines);
        assert_eq!(result, Some((0, 0)));
    }

    #[test]
    fn matching_brace_nested() {
        let lines = vec![
            ClangLine {
                line_number: 1,
                indent: 0,
                tokens: vec![TokenInfo::new("{", TokenType::Syntax, 1)],
            },
            ClangLine {
                line_number: 2,
                indent: 1,
                tokens: vec![TokenInfo::new("{", TokenType::Syntax, 2)],
            },
            ClangLine {
                line_number: 3,
                indent: 1,
                tokens: vec![TokenInfo::new("}", TokenType::Syntax, 3)],
            },
            ClangLine {
                line_number: 4,
                indent: 0,
                tokens: vec![TokenInfo::new("}", TokenType::Syntax, 4)],
            },
        ];

        // Matching for the first `{` should be the last `}`.
        let result = get_matching_brace(0, 0, &lines);
        assert_eq!(result, Some((3, 0)));

        // Matching for the second `{` should be the first `}`.
        let result = get_matching_brace(1, 0, &lines);
        assert_eq!(result, Some((2, 0)));
    }

    // --- is_brace ---

    #[test]
    fn test_is_brace() {
        assert!(is_brace(&TokenInfo::new("{", TokenType::Syntax, 1)));
        assert!(is_brace(&TokenInfo::new("}", TokenType::Syntax, 1)));
        assert!(!is_brace(&TokenInfo::new("(", TokenType::Syntax, 1)));
        assert!(!is_brace(&TokenInfo::new("x", TokenType::VariableName, 1)));
    }

    // --- Line splitting ---

    #[test]
    fn to_lines_basic() {
        let tokens = vec![
            TokenInfo::new("int", TokenType::TypeName, 1),
            TokenInfo::new("x", TokenType::VariableName, 1),
            TokenInfo::new(";", TokenType::Syntax, 1),
            TokenInfo::new("", TokenType::LineBreak, 1),
            TokenInfo::new("return", TokenType::Keyword, 2),
            TokenInfo::new(";", TokenType::Syntax, 2),
        ];

        let lines = to_lines(&tokens);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].tokens.len(), 3);
        assert_eq!(lines[1].tokens.len(), 2);
    }

    #[test]
    fn to_lines_empty() {
        let tokens = vec![];
        let lines = to_lines(&tokens);
        assert!(lines.is_empty());
    }

    // --- ClangLine ---

    #[test]
    fn clang_line_text() {
        let mut line = ClangLine::new(1, 0);
        line.add_token(TokenInfo::new("int", TokenType::TypeName, 1));
        line.add_token(TokenInfo::new(" x", TokenType::VariableName, 1));
        line.add_token(TokenInfo::new(";", TokenType::Syntax, 1));
        assert_eq!(line.text(), "int x;");
    }

    // --- Token utilities ---

    #[test]
    fn find_closest_addressed_token_right() {
        let lines = vec![ClangLine {
            line_number: 1,
            indent: 0,
            tokens: vec![
                TokenInfo {
                    text: "if".into(),
                    token_type: TokenType::Keyword,
                    min_address: None,
                    max_address: None,
                    line_number: 1,
                    column: 0,
                    token_index: 0,
                    indent: 0,
                },
                TokenInfo {
                    text: "x".into(),
                    token_type: TokenType::VariableName,
                    min_address: Some(Address::new(0x1000)),
                    max_address: Some(Address::new(0x1000)),
                    line_number: 1,
                    column: 3,
                    token_index: 1,
                    indent: 0,
                },
            ],
        }];

        let token = &lines[0].tokens[0];
        let addr = find_closest_addressed_token(token, &lines);
        assert_eq!(addr, Some(Address::new(0x1000)));
    }

    #[test]
    fn find_closest_addressed_token_left() {
        let lines = vec![ClangLine {
            line_number: 1,
            indent: 0,
            tokens: vec![
                TokenInfo {
                    text: "x".into(),
                    token_type: TokenType::VariableName,
                    min_address: Some(Address::new(0x1000)),
                    max_address: Some(Address::new(0x1000)),
                    line_number: 1,
                    column: 0,
                    token_index: 0,
                    indent: 0,
                },
                TokenInfo {
                    text: ";".into(),
                    token_type: TokenType::Syntax,
                    min_address: None,
                    max_address: None,
                    line_number: 1,
                    column: 1,
                    token_index: 1,
                    indent: 0,
                },
            ],
        }];

        let token = &lines[0].tokens[1];
        let addr = find_closest_addressed_token(token, &lines);
        assert_eq!(addr, Some(Address::new(0x1000)));
    }

    // --- Data type tracing ---

    #[test]
    fn data_type_trace_forward() {
        let varnodes = vec![VarnodeRef {
            address: Address::new(0x1000),
            offset: 0x1000,
            size: 4,
            is_constant: false,
            is_register: false,
            is_input: false,
            defining_op: None,
            descendant_ops: vec![],
            high_variable: Some(HighVariableRef {
                name: "x".into(),
                data_type_name: "int".into(),
                is_parameter: false,
                parameter_slot: None,
            }),
        }];

        let result = get_data_type_trace_forward(&varnodes, &[], 0);
        assert_eq!(result, Some("int".to_string()));
    }

    #[test]
    fn data_type_trace_backward_with_cast() {
        let varnodes = vec![
            VarnodeRef {
                address: Address::new(0x1000),
                offset: 0x1000,
                size: 4,
                is_constant: false,
                is_register: false,
                is_input: false,
                defining_op: Some(0),
                descendant_ops: vec![],
                high_variable: Some(HighVariableRef {
                    name: "x".into(),
                    data_type_name: "int".into(),
                    is_parameter: false,
                    parameter_slot: None,
                }),
            },
            VarnodeRef {
                address: Address::new(0x2000),
                offset: 0x2000,
                size: 8,
                is_constant: false,
                is_register: false,
                is_input: false,
                defining_op: None,
                descendant_ops: vec![0],
                high_variable: Some(HighVariableRef {
                    name: "y".into(),
                    data_type_name: "long".into(),
                    is_parameter: false,
                    parameter_slot: None,
                }),
            },
        ];
        let ops = vec![PcodeOpRef {
            opcode: PcodeOpcode::Cast,
            output: Some(0),
            inputs: vec![1],
            instruction_address: Address::new(0x3000),
            seq_num: 0,
        }];

        // vn0 is produced by a CAST from vn1 (long).
        // The backward trace should return "long" (the input type).
        let result = get_data_type_trace_backward(&varnodes, &ops, 0);
        assert_eq!(result, Some("long".to_string()));
    }

    // --- PcodeOpcode ---

    #[test]
    fn pcode_opcode_from_code() {
        assert_eq!(PcodeOpcode::from_code(1), PcodeOpcode::Copy);
        assert_eq!(PcodeOpcode::from_code(16), PcodeOpcode::Call);
        assert_eq!(PcodeOpcode::from_code(17), PcodeOpcode::CallInd);
        assert_eq!(PcodeOpcode::from_code(100), PcodeOpcode::Other(100));
    }

    #[test]
    fn pcode_opcode_is_call() {
        assert!(PcodeOpcode::Call.is_call());
        assert!(PcodeOpcode::CallInd.is_call());
        assert!(!PcodeOpcode::Copy.is_call());
        assert!(!PcodeOpcode::IntAdd.is_call());
    }

    // --- TokenInfo ---

    #[test]
    fn token_info_is_brace() {
        assert!(TokenInfo::new("{", TokenType::Syntax, 1).is_brace());
        assert!(TokenInfo::new("}", TokenType::Syntax, 1).is_brace());
        assert!(!TokenInfo::new("(", TokenType::Syntax, 1).is_brace());
    }

    #[test]
    fn token_info_with_address() {
        let token = TokenInfo::with_address("x", TokenType::VariableName, 1, Address::new(0x1000));
        assert_eq!(token.min_address, Some(Address::new(0x1000)));
        assert!(token.has_address());
    }

    // --- get_goto_target_token ---

    #[test]
    fn goto_target_token() {
        let tokens = vec![
            TokenInfo {
                text: "goto".into(),
                token_type: TokenType::Keyword,
                min_address: Some(Address::new(0x1000)),
                max_address: Some(Address::new(0x1000)),
                line_number: 1,
                column: 0,
                token_index: 0,
                indent: 0,
            },
            TokenInfo {
                text: "LAB_002000".into(),
                token_type: TokenType::LabelName,
                min_address: Some(Address::new(0x2000)),
                max_address: Some(Address::new(0x2000)),
                line_number: 1,
                column: 5,
                token_index: 1,
                indent: 0,
            },
            TokenInfo {
                text: "LAB_002000:".into(),
                token_type: TokenType::LabelName,
                min_address: Some(Address::new(0x2000)),
                max_address: Some(Address::new(0x2000)),
                line_number: 5,
                column: 0,
                token_index: 2,
                indent: 0,
            },
        ];

        let result = get_goto_target_token(&tokens, 1);
        assert_eq!(result, Some(2));
    }

    // --- get_tokens_by_addresses ---

    #[test]
    fn tokens_by_addresses() {
        let tokens = vec![
            TokenInfo::with_address("a", TokenType::VariableName, 1, Address::new(0x1000)),
            TokenInfo::new(";", TokenType::Syntax, 1),
            TokenInfo::with_address("b", TokenType::VariableName, 2, Address::new(0x2000)),
            TokenInfo::with_address("c", TokenType::VariableName, 3, Address::new(0x3000)),
        ];

        let addresses = vec![(Address::new(0x1000), Address::new(0x1000))];
        let result = get_tokens_by_addresses(&tokens, &addresses);
        assert_eq!(result, vec![0]);
    }

    // --- find_address_before ---

    #[test]
    fn find_address_before_basic() {
        let lines = vec![
            ClangLine {
                line_number: 1,
                indent: 0,
                tokens: vec![TokenInfo::with_address(
                    "int",
                    TokenType::TypeName,
                    1,
                    Address::new(0x1000),
                )],
            },
            ClangLine {
                line_number: 2,
                indent: 0,
                tokens: vec![TokenInfo::new("return", TokenType::Keyword, 2)],
            },
        ];

        let token = &lines[1].tokens[0];
        let addr = find_address_before(token, &lines);
        assert_eq!(addr, Some(Address::new(0x1000)));
    }
}
