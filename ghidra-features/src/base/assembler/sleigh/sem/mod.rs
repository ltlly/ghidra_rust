//! Semantic resolution for SLEIGH assembly.
//!
//! Corresponds to Java's `ghidra.app.plugin.assembler.sleigh.sem`.
//!
//! This module converts parse trees into concrete machine code patterns.
//! It resolves symbolic expressions in instruction operands and
//! produces `AssemblyResolvedPatterns` -- a byte-level representation
//! of the assembled instruction with associated masks.

use std::collections::BTreeMap;
use std::fmt;

use crate::base::assembler::sleigh::expr::masked_long::MaskedLong;

// ---------------------------------------------------------------------------
// AssemblyPatternBlock
// ---------------------------------------------------------------------------

/// A block of bytes with associated masks.
///
/// This is the fundamental representation of assembled instruction bytes.
/// Each byte has a corresponding mask byte: bits set to 1 in the mask
/// are "known" (constrained by the encoding), while 0 bits are "don't care".
///
/// Corresponds to Java's `AssemblyPatternBlock`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AssemblyPatternBlock {
    /// The byte values.
    vals: Vec<u8>,
    /// The mask bytes (1 = known, 0 = don't care).
    masks: Vec<u8>,
    /// Optional shift (in bits) applied to this block.
    shift: u32,
}

impl AssemblyPatternBlock {
    /// Create a new empty pattern block with the given length.
    pub fn new_empty(length: usize) -> Self {
        Self {
            vals: vec![0; length],
            masks: vec![0; length],
            shift: 0,
        }
    }

    /// Create a pattern block from raw values and masks.
    pub fn from_vals_and_masks(vals: Vec<u8>, masks: Vec<u8>, shift: u32) -> Self {
        assert_eq!(vals.len(), masks.len());
        let masked_vals: Vec<u8> = vals
            .iter()
            .zip(masks.iter())
            .map(|(v, m)| v & m)
            .collect();
        Self {
            vals: masked_vals,
            masks,
            shift,
        }
    }

    /// Create a fully-known block (all mask bits set).
    pub fn from_vals(vals: Vec<u8>) -> Self {
        let masks = vec![0xFF; vals.len()];
        Self {
            vals,
            masks,
            shift: 0,
        }
    }

    /// Create from a register value (context register).
    ///
    /// The register value provides both the value bytes and a mask
    /// indicating which bytes are valid.
    pub fn from_register_value(vals: &[u8], valid_mask: &[u8]) -> Self {
        Self::from_vals_and_masks(vals.to_vec(), valid_mask.to_vec(), 0)
    }

    /// Get the raw values.
    pub fn vals(&self) -> &[u8] {
        &self.vals
    }

    /// Get the masks.
    pub fn masks(&self) -> &[u8] {
        &self.masks
    }

    /// Get the length in bytes.
    pub fn length(&self) -> usize {
        self.vals.len()
    }

    /// Get the shift.
    pub fn shift(&self) -> u32 {
        self.shift
    }

    /// Check if all bits are fully specified (all mask bytes are 0xFF).
    pub fn is_full_mask(&self) -> bool {
        self.masks.iter().all(|&m| m == 0xFF)
    }

    /// Fill unknown mask bits to create a fully-specified block.
    ///
    /// Unknown bits in the value are set to 0.
    pub fn fill_mask(&self) -> Self {
        Self {
            vals: self.vals.clone(),
            masks: vec![0xFF; self.masks.len()],
            shift: self.shift,
        }
    }

    /// Combine this block with another, checking for compatibility.
    ///
    /// Two blocks can be combined if their corresponding defined bits
    /// agree.  When combined, the defined bits are taken from either
    /// block.  If both blocks define a bit but with opposite values,
    /// the result is `None` (conflict).
    pub fn combine(&self, other: &AssemblyPatternBlock) -> Option<AssemblyPatternBlock> {
        if self.shift != other.shift {
            return None;
        }
        let len = self.vals.len().max(other.vals.len());
        let mut vals = vec![0u8; len];
        let mut masks = vec![0u8; len];

        // Common mask bits (both define this bit)
        let mut common_mask = vec![0u8; len];
        for i in 0..len {
            let sm = self.masks.get(i).copied().unwrap_or(0);
            let om = other.masks.get(i).copied().unwrap_or(0);
            common_mask[i] = sm & om;
        }

        // Check for conflicts: where both define a bit, values must agree
        for i in 0..len {
            let sv = self.vals.get(i).copied().unwrap_or(0);
            let ov = other.vals.get(i).copied().unwrap_or(0);
            let cm = common_mask[i];
            if (sv & cm) != (ov & cm) {
                return None;
            }
        }

        // Build result: OR the values and masks
        for i in 0..len {
            let sv = self.vals.get(i).copied().unwrap_or(0);
            let sm = self.masks.get(i).copied().unwrap_or(0);
            let ov = other.vals.get(i).copied().unwrap_or(0);
            let om = other.masks.get(i).copied().unwrap_or(0);
            vals[i] = sv | ov;
            masks[i] = sm | om;
        }

        Some(Self {
            vals,
            masks,
            shift: self.shift,
        })
    }

    /// Get a MaskedLong representing this block (up to 8 bytes).
    pub fn to_masked_long(&self) -> MaskedLong {
        let len = self.vals.len().min(8);
        let mut val = 0u64;
        let mut mask = 0u64;
        for i in 0..len {
            val |= (self.vals[i] as u64) << (i * 8);
            mask |= (self.masks[i] as u64) << (i * 8);
        }
        MaskedLong::new(val, mask)
    }

    /// Set a range of bits in the block.
    pub fn set_bits(&mut self, lsb: u32, msb: u32, value: u64) {
        for bit in lsb..=msb {
            let byte_idx = (bit / 8) as usize;
            let bit_idx = bit % 8;
            if byte_idx < self.vals.len() {
                let bit_val = ((value >> (bit - lsb)) & 1) as u8;
                self.vals[byte_idx] =
                    (self.vals[byte_idx] & !(1 << bit_idx)) | (bit_val << bit_idx);
                self.masks[byte_idx] |= 1 << bit_idx;
            }
        }
    }

    /// Get bits [lsb, msb] from the block.
    pub fn get_bits(&self, lsb: u32, msb: u32) -> MaskedLong {
        let mut val = 0u64;
        let mut mask = 0u64;
        for bit in lsb..=msb {
            let byte_idx = (bit / 8) as usize;
            let bit_idx = bit % 8;
            if byte_idx < self.vals.len() {
                let v = ((self.vals[byte_idx] >> bit_idx) & 1) as u64;
                let m = ((self.masks[byte_idx] >> bit_idx) & 1) as u64;
                val |= v << (bit - lsb);
                mask |= m << (bit - lsb);
            }
        }
        MaskedLong::new(val, mask)
    }
}

impl fmt::Display for AssemblyPatternBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "vals=[")?;
        for (i, v) in self.vals.iter().enumerate() {
            if i > 0 {
                write!(f, " ")?;
            }
            write!(f, "{:02x}", v)?;
        }
        write!(f, "] masks=[")?;
        for (i, m) in self.masks.iter().enumerate() {
            if i > 0 {
                write!(f, " ")?;
            }
            write!(f, "{:02x}", m)?;
        }
        write!(f, "] shift={}", self.shift)
    }
}

impl Default for AssemblyPatternBlock {
    fn default() -> Self {
        Self::new_empty(0)
    }
}

// ---------------------------------------------------------------------------
// AssemblyResolvedPatterns
// ---------------------------------------------------------------------------

/// A resolved instruction with its encoding patterns.
///
/// This represents a fully-resolved instruction: the instruction bytes,
/// the context register values, and the source tree that produced it.
///
/// Corresponds to Java's `AssemblyResolvedPatterns`.
#[derive(Debug, Clone)]
pub struct AssemblyResolvedPatterns {
    /// The instruction byte pattern.
    instruction: AssemblyPatternBlock,
    /// The context register pattern.
    context: AssemblyPatternBlock,
    /// Description of how this resolution was produced.
    #[allow(dead_code)]
    description: String,
}

impl AssemblyResolvedPatterns {
    /// Create a new resolved pattern.
    pub fn new(
        instruction: AssemblyPatternBlock,
        context: AssemblyPatternBlock,
        description: impl Into<String>,
    ) -> Self {
        Self {
            instruction,
            context,
            description: description.into(),
        }
    }

    /// Get the instruction pattern.
    pub fn get_instruction(&self) -> &AssemblyPatternBlock {
        &self.instruction
    }

    /// Get the context pattern.
    pub fn get_context(&self) -> AssemblyPatternBlock {
        self.context.clone()
    }

    /// Get the description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Combine with another resolved pattern.
    pub fn combine(&self, other: &AssemblyResolvedPatterns) -> Option<AssemblyResolvedPatterns> {
        let instr = self.instruction.combine(&other.instruction)?;
        let ctx = self.context.combine(&other.context)?;
        Some(Self {
            instruction: instr,
            context: ctx,
            description: format!("{} + {}", self.description, other.description),
        })
    }

    /// Select a specific value for masked bits.
    pub fn select(&self, ins: &AssemblyPatternBlock, ctx: &AssemblyPatternBlock) -> Option<Self> {
        let instruction = self.instruction.combine(ins)?;
        let context = self.context.combine(ctx)?;
        Some(Self {
            instruction,
            context,
            description: self.description.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// AssemblyResolvedError
// ---------------------------------------------------------------------------

/// A resolution error representing a semantic problem during assembly.
///
/// Corresponds to Java's `AssemblyResolvedError`.
#[derive(Debug, Clone)]
pub struct AssemblyResolvedError {
    message: String,
    description: String,
}

impl AssemblyResolvedError {
    /// Create a new resolved error.
    pub fn new(message: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            description: description.into(),
        }
    }

    /// Get the error message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Get the description.
    pub fn description(&self) -> &str {
        &self.description
    }
}

impl fmt::Display for AssemblyResolvedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.description, self.message)
    }
}

// ---------------------------------------------------------------------------
// AssemblyResolvedBackfill
// ---------------------------------------------------------------------------

/// A resolution that needs a backfill pass.
///
/// Some operand values depend on forward references that are not
/// yet known.  The backfill mechanism allows these to be resolved
/// in a second pass.
///
/// Corresponds to Java's `AssemblyResolvedBackfill`.
#[derive(Debug, Clone)]
pub struct AssemblyResolvedBackfill {
    /// The partially-resolved patterns.
    patterns: AssemblyResolvedPatterns,
    /// The operand indices that need backfilling.
    needed: Vec<usize>,
    /// Description.
    #[allow(dead_code)]
    description: String,
}

impl AssemblyResolvedBackfill {
    /// Create a new backfill entry.
    pub fn new(
        patterns: AssemblyResolvedPatterns,
        needed: Vec<usize>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            patterns,
            needed,
            description: description.into(),
        }
    }

    /// Get the partially-resolved patterns.
    pub fn patterns(&self) -> &AssemblyResolvedPatterns {
        &self.patterns
    }

    /// Get the operand indices that need backfilling.
    pub fn needed(&self) -> &[usize] {
        &self.needed
    }

    /// Check if all needed operands are now resolved.
    pub fn is_ready(&self, resolved: &[bool]) -> bool {
        self.needed.iter().all(|&i| resolved.get(i).copied().unwrap_or(false))
    }
}

// ---------------------------------------------------------------------------
// AssemblyResolution (enum)
// ---------------------------------------------------------------------------

/// A single resolution result from the assembler.
///
/// This is a tagged union of the three possible outcomes:
/// fully resolved, needs backfill, or error.
///
/// Corresponds to Java's `AssemblyResolution`.
#[derive(Debug, Clone)]
pub enum AssemblyResolution {
    /// A fully resolved instruction pattern.
    Patterns(AssemblyResolvedPatterns),
    /// A partial resolution that needs backfilling.
    Backfill(AssemblyResolvedBackfill),
    /// An error during resolution.
    Error(AssemblyResolvedError),
}

impl AssemblyResolution {
    /// Check if this is an error.
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error(_))
    }

    /// Check if this is a patterns result.
    pub fn is_patterns(&self) -> bool {
        matches!(self, Self::Patterns(_))
    }

    /// Check if this is a backfill result.
    pub fn is_backfill(&self) -> bool {
        matches!(self, Self::Backfill(_))
    }

    /// Get the patterns (if patterns).
    pub fn as_patterns(&self) -> Option<&AssemblyResolvedPatterns> {
        match self {
            Self::Patterns(p) => Some(p),
            _ => None,
        }
    }

    /// Get the error (if error).
    pub fn as_error(&self) -> Option<&AssemblyResolvedError> {
        match self {
            Self::Error(e) => Some(e),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// AssemblyResolutionResults
// ---------------------------------------------------------------------------

/// A collection of resolution results.
///
/// The resolver may produce multiple candidate instructions for a
/// single textual instruction (due to different constructor choices).
///
/// Corresponds to Java's `AssemblyResolutionResults`.
#[derive(Debug, Clone, Default)]
pub struct AssemblyResolutionResults {
    results: Vec<AssemblyResolution>,
}

impl AssemblyResolutionResults {
    /// Create a new empty results set.
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
        }
    }

    /// Add a resolution result.
    pub fn push(&mut self, resolution: AssemblyResolution) {
        self.results.push(resolution);
    }

    /// Absorb all results from another set.
    pub fn absorb(&mut self, other: AssemblyResolutionResults) {
        self.results.extend(other.results);
    }

    /// Get the number of results.
    pub fn len(&self) -> usize {
        self.results.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    /// Iterate over the results.
    pub fn iter(&self) -> impl Iterator<Item = &AssemblyResolution> {
        self.results.iter()
    }

    /// Get only the resolved patterns (non-error, non-backfill).
    pub fn patterns(&self) -> Vec<&AssemblyResolvedPatterns> {
        self.results
            .iter()
            .filter_map(|r| match r {
                AssemblyResolution::Patterns(p) => Some(p),
                _ => None,
            })
            .collect()
    }

    /// Get only the errors.
    pub fn errors(&self) -> Vec<&AssemblyResolvedError> {
        self.results
            .iter()
            .filter_map(|r| match r {
                AssemblyResolution::Error(e) => Some(e),
                _ => None,
            })
            .collect()
    }

    /// Get only the backfill entries.
    pub fn backfills(&self) -> Vec<&AssemblyResolvedBackfill> {
        self.results
            .iter()
            .filter_map(|r| match r {
                AssemblyResolution::Backfill(b) => Some(b),
                _ => None,
            })
            .collect()
    }

    /// Check if all results are errors.
    pub fn all_errors(&self) -> bool {
        self.results.iter().all(|r| r.is_error())
    }

    /// Check if there is at least one successful resolution.
    pub fn has_success(&self) -> bool {
        self.results.iter().any(|r| r.is_patterns())
    }

    /// Convert into a Vec.
    pub fn into_vec(self) -> Vec<AssemblyResolution> {
        self.results
    }
}

impl IntoIterator for AssemblyResolutionResults {
    type Item = AssemblyResolution;
    type IntoIter = std::vec::IntoIter<AssemblyResolution>;

    fn into_iter(self) -> Self::IntoIter {
        self.results.into_iter()
    }
}

// ---------------------------------------------------------------------------
// AssemblyConstructorSemantic
// ---------------------------------------------------------------------------

/// The semantic information associated with a SLEIGH constructor.
///
/// This describes how to encode the instruction, handle operands,
/// and apply context changes for a specific constructor.
///
/// Corresponds to Java's `AssemblyConstructorSemantic`.
#[derive(Debug, Clone)]
pub struct AssemblyConstructorSemantic {
    /// The constructor's display name.
    pub name: String,
    /// The instruction encoding mask/value pairs.
    pub pattern: AssemblyPatternBlock,
    /// Operand expressions (indexed).
    pub operands: Vec<OperandSemantic>,
    /// Context changes applied after encoding.
    pub context_changes: BTreeMap<String, u64>,
    /// Hidden operand indices (consumed but not displayed).
    pub hidden_operands: Vec<usize>,
}

/// Semantic information for a single operand.
#[derive(Debug, Clone)]
pub struct OperandSemantic {
    /// The operand index.
    pub index: usize,
    /// Whether this operand is a sub-table (non-terminal).
    pub is_subtable: bool,
    /// The sub-table name (if non-terminal).
    pub subtable: Option<String>,
}

// ---------------------------------------------------------------------------
// AssemblyDefaultContext
// ---------------------------------------------------------------------------

/// The default context register values for a language.
///
/// Corresponds to Java's `AssemblyDefaultContext`.
#[derive(Debug, Clone, Default)]
pub struct AssemblyDefaultContext {
    /// Default context register values.
    defaults: BTreeMap<u64, AssemblyPatternBlock>,
}

impl AssemblyDefaultContext {
    /// Create a new empty default context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the default context at a given address.
    pub fn set_default(&mut self, addr: u64, ctx: AssemblyPatternBlock) {
        self.defaults.insert(addr, ctx);
    }

    /// Get the default context at a given address.
    ///
    /// Returns the nearest default context at or before the address.
    pub fn get_default_at(&self, addr_offset: u64) -> AssemblyPatternBlock {
        // Find the nearest entry at or before addr
        self.defaults
            .range(..=addr_offset)
            .next_back()
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| AssemblyPatternBlock::new_empty(0))
    }
}

// ---------------------------------------------------------------------------
// AssemblyContextGraph
// ---------------------------------------------------------------------------

/// The context register dependency graph.
///
/// This tracks which context registers depend on each other,
/// allowing the assembler to properly propagate context changes
/// through instruction sequences.
///
/// Corresponds to Java's `AssemblyContextGraph`.
#[derive(Debug, Clone, Default)]
pub struct AssemblyContextGraph {
    /// Adjacency list: register name -> dependent register names.
    pub dependencies: BTreeMap<String, Vec<String>>,
}

impl AssemblyContextGraph {
    /// Create a new empty context graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a dependency: `from` register affects `to` register.
    pub fn add_dependency(&mut self, from: impl Into<String>, to: impl Into<String>) {
        self.dependencies
            .entry(from.into())
            .or_default()
            .push(to.into());
    }

    /// Get the registers that depend on the given register.
    pub fn get_dependents(&self, register: &str) -> &[String] {
        self.dependencies
            .get(register)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_block_basic() {
        let block = AssemblyPatternBlock::from_vals(vec![0xAB, 0xCD]);
        assert_eq!(block.vals(), &[0xAB, 0xCD]);
        assert_eq!(block.length(), 2);
        assert!(block.is_full_mask());
    }

    #[test]
    fn test_pattern_block_partial_mask() {
        let block = AssemblyPatternBlock::from_vals_and_masks(vec![0xFF, 0x00], vec![0xF0, 0x0F], 0);
        assert!(!block.is_full_mask());
        assert_eq!(block.vals(), &[0xF0, 0x00]); // masked values
    }

    #[test]
    fn test_pattern_block_combine() {
        // a: val=0xAB (masked to 0xAB), mask=0xFF
        // b: val=0xFB masked to 0x0B, mask=0x0F (low nibble matches a's)
        // combined: vals = 0xAB | 0x0B = 0xAB, mask = 0xFF | 0x0F = 0xFF
        let a = AssemblyPatternBlock::from_vals_and_masks(vec![0xAB], vec![0xFF], 0);
        let b = AssemblyPatternBlock::from_vals_and_masks(vec![0xFB], vec![0x0F], 0);
        let combined = a.combine(&b).unwrap();
        assert_eq!(combined.vals(), &[0xAB]); // OR of masked values (0xAB | 0x0B = 0xAB)
        assert_eq!(combined.masks(), &[0xFF]);
    }

    #[test]
    fn test_pattern_block_combine_conflict() {
        let a = AssemblyPatternBlock::from_vals_and_masks(vec![0xAB], vec![0xFF], 0);
        let b = AssemblyPatternBlock::from_vals_and_masks(vec![0xCD], vec![0xFF], 0);
        assert!(a.combine(&b).is_none());
    }

    #[test]
    fn test_pattern_block_fill_mask() {
        // from_vals_and_masks stores masked value: 0xAB & 0x0F = 0x0B
        let block = AssemblyPatternBlock::from_vals_and_masks(vec![0xAB], vec![0x0F], 0);
        assert_eq!(block.vals(), &[0x0B]); // masked
        let filled = block.fill_mask();
        assert!(filled.is_full_mask());
        assert_eq!(filled.vals(), &[0x0B]); // preserved masked value
    }

    #[test]
    fn test_pattern_block_set_get_bits() {
        let mut block = AssemblyPatternBlock::new_empty(2);
        block.set_bits(0, 3, 0xA);
        block.set_bits(4, 7, 0xB);
        assert_eq!(block.vals(), &[0xBA, 0x00]);

        let bits = block.get_bits(0, 7);
        assert_eq!(bits.get_unsigned(), 0xBA);
    }

    #[test]
    fn test_resolved_patterns() {
        let ins = AssemblyPatternBlock::from_vals(vec![0x90]);
        let ctx = AssemblyPatternBlock::new_empty(0);
        let rp = AssemblyResolvedPatterns::new(ins, ctx, "NOP");
        assert!(rp.get_instruction().is_full_mask());
    }

    #[test]
    fn test_resolution_results() {
        let mut results = AssemblyResolutionResults::new();
        assert!(results.is_empty());

        let ins = AssemblyPatternBlock::from_vals(vec![0x90]);
        let ctx = AssemblyPatternBlock::new_empty(0);
        let rp = AssemblyResolvedPatterns::new(ins, ctx, "NOP");
        results.push(AssemblyResolution::Patterns(rp));

        assert_eq!(results.len(), 1);
        assert!(results.has_success());
        assert!(!results.all_errors());
    }

    #[test]
    fn test_resolution_results_errors() {
        let mut results = AssemblyResolutionResults::new();
        results.push(AssemblyResolution::Error(AssemblyResolvedError::new(
            "out of range",
            "imm8",
        )));
        assert!(results.all_errors());
        assert!(!results.has_success());
    }

    #[test]
    fn test_resolution_results_absorb() {
        let mut r1 = AssemblyResolutionResults::new();
        let mut r2 = AssemblyResolutionResults::new();
        r2.push(AssemblyResolution::Error(AssemblyResolvedError::new(
            "test", "desc",
        )));
        r1.absorb(r2);
        assert_eq!(r1.len(), 1);
    }

    #[test]
    fn test_context_graph() {
        let mut graph = AssemblyContextGraph::new();
        graph.add_dependency("ISAMode", "addrsize");
        graph.add_dependency("ISAMode", "opsize");

        let deps = graph.get_dependents("ISAMode");
        assert_eq!(deps.len(), 2);
        assert!(deps.contains(&"addrsize".to_string()));
    }

    #[test]
    fn test_default_context() {
        let mut ctx = AssemblyDefaultContext::new();
        let block = AssemblyPatternBlock::from_vals(vec![0x01]);
        ctx.set_default(0x1000, block);

        let at = ctx.get_default_at(0x1000);
        assert_eq!(at.vals(), &[0x01]);

        // Default before any set entry
        let before = ctx.get_default_at(0x0000);
        assert_eq!(before.length(), 0);
    }

    #[test]
    fn test_pattern_block_to_masked_long() {
        let block = AssemblyPatternBlock::from_vals_and_masks(
            vec![0xEF, 0xBE, 0xAD, 0xDE],
            vec![0xFF, 0xFF, 0xFF, 0xFF],
            0,
        );
        let ml = block.to_masked_long();
        assert_eq!(ml.get_unsigned(), 0xDEADBEEF);
        // Mask is 0xFFFFFFFF (4 bytes fully known), not u64::MAX
        assert_eq!(ml.get_mask(), 0xFFFFFFFF);
        // Check with an 8-byte block for full mask
        let block8 = AssemblyPatternBlock::from_vals(
            vec![0xEF, 0xBE, 0xAD, 0xDE, 0xFE, 0xCA, 0xBE, 0xBA],
        );
        let ml8 = block8.to_masked_long();
        assert!(ml8.is_full_mask());
    }
}
