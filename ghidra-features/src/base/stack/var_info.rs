//! Stack variable information -- accumulates stack variable metadata
//! during analysis.

use std::collections::BTreeMap;

use crate::base::analyzer::core::Address;

// ============================================================================
// StackVariableKind
// ============================================================================

/// Whether a stack variable is a parameter or a local.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StackVariableKind {
    /// A function parameter (positive offset from frame base in x86).
    Parameter,
    /// A local variable (negative offset from frame base in x86).
    Local,
}

impl StackVariableKind {
    pub fn is_parameter(&self) -> bool {
        matches!(self, StackVariableKind::Parameter)
    }

    pub fn is_local(&self) -> bool {
        matches!(self, StackVariableKind::Local)
    }
}

// ============================================================================
// StackVariableInfo
// ============================================================================

/// Accumulated information about a single stack variable discovered
/// during analysis.
///
/// Each record tracks the stack offset, the maximum size observed at
/// that offset, the kind (parameter vs local), and the instruction
/// addresses that reference it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackVariableInfo {
    /// Stack offset (signed; positive = param, negative = local on x86).
    pub offset: i64,
    /// Maximum reference size in bytes seen at this offset.
    pub max_ref_size: usize,
    /// Kind of variable (parameter or local).
    pub kind: StackVariableKind,
    /// Instruction addresses that reference this stack location.
    pub referencing_instructions: Vec<Address>,
}

impl StackVariableInfo {
    /// Create a new variable info record.
    pub fn new(offset: i64, ref_size: usize, kind: StackVariableKind) -> Self {
        Self {
            offset,
            max_ref_size: ref_size,
            kind,
            referencing_instructions: Vec::new(),
        }
    }

    /// Record an additional reference from the given instruction address,
    /// expanding the max_ref_size if needed.
    pub fn add_reference(&mut self, instr_addr: Address, ref_size: usize) {
        self.referencing_instructions.push(instr_addr);
        if ref_size > self.max_ref_size {
            self.max_ref_size = ref_size;
        }
    }

    /// Whether this variable has any references.
    pub fn has_references(&self) -> bool {
        !self.referencing_instructions.is_empty()
    }
}

// ============================================================================
// StackVariableAccumulator
// ============================================================================

/// Accumulates [`StackVariableInfo`]s during stack analysis, keyed by
/// stack offset.
///
/// This mirrors the sorted-variable list maintained by Ghidra's
/// `NewFunctionStackAnalysisCmd`.
#[derive(Debug, Clone, Default)]
pub struct StackVariableAccumulator {
    /// Variables keyed by stack offset.
    vars: BTreeMap<i64, StackVariableInfo>,
}

impl StackVariableAccumulator {
    /// Create an empty accumulator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a stack reference at the given offset.
    ///
    /// If no variable exists at this offset yet, one is created with
    /// the given size and kind.  Otherwise the existing variable is
    /// updated (max_ref_size expanded, reference added).
    pub fn record_reference(
        &mut self,
        offset: i64,
        ref_size: usize,
        kind: StackVariableKind,
        instr_addr: Address,
    ) {
        let entry = self.vars.entry(offset).or_insert_with(|| {
            StackVariableInfo::new(offset, ref_size, kind)
        });
        entry.add_reference(instr_addr, ref_size);
    }

    /// Merge overlapping or intersecting variables.
    ///
    /// After merging, no two variables will overlap in the range
    /// `[offset, offset + max_ref_size)`.
    pub fn merge_overlapping(&mut self) {
        let offsets: Vec<i64> = self.vars.keys().copied().collect();
        let mut to_remove = Vec::new();
        let mut i = 0;
        while i < offsets.len() {
            let off_i = offsets[i];
            let size_i = match self.vars.get(&off_i) {
                Some(v) => v.max_ref_size as i64,
                None => { i += 1; continue; }
            };
            let end_i = off_i + size_i - 1;

            let mut j = i + 1;
            while j < offsets.len() {
                let off_j = offsets[j];
                let size_j = match self.vars.get(&off_j) {
                    Some(v) => v.max_ref_size as i64,
                    None => { j += 1; continue; }
                };
                let end_j = off_j + size_j - 1;

                // Check if [off_i, end_i] overlaps [off_j, end_j]
                if end_i >= off_j && off_i <= end_j {
                    // Merge j into i
                    let new_start = off_i.min(off_j);
                    let new_end = end_i.max(end_j);
                    let new_size = (new_end - new_start + 1) as usize;
                    to_remove.push(off_j);

                    // Clone references from j before mutating i
                    let extra_refs: Vec<Address> = self.vars.get(&off_j)
                        .map(|vj| vj.referencing_instructions.clone())
                        .unwrap_or_default();

                    if let Some(v) = self.vars.get_mut(&off_i) {
                        v.offset = new_start;
                        v.max_ref_size = new_size;
                        v.referencing_instructions.extend(extra_refs);
                    }
                }
                j += 1;
            }
            i += 1;
        }
        for off in to_remove {
            self.vars.remove(&off);
        }
    }

    /// Get a reference to the variable at the given offset, if any.
    pub fn get(&self, offset: i64) -> Option<&StackVariableInfo> {
        self.vars.get(&offset)
    }

    /// Get a mutable reference to the variable at the given offset, if any.
    pub fn get_mut(&mut self, offset: i64) -> Option<&mut StackVariableInfo> {
        self.vars.get_mut(&offset)
    }

    /// All variables sorted by offset.
    pub fn sorted_variables(&self) -> Vec<&StackVariableInfo> {
        self.vars.values().collect()
    }

    /// Number of accumulated variables.
    pub fn len(&self) -> usize {
        self.vars.len()
    }

    /// Whether the accumulator is empty.
    pub fn is_empty(&self) -> bool {
        self.vars.is_empty()
    }

    /// Remove the variable at the given offset.
    pub fn remove(&mut self, offset: i64) -> Option<StackVariableInfo> {
        self.vars.remove(&offset)
    }

    /// Clear all variables.
    pub fn clear(&mut self) {
        self.vars.clear();
    }

    /// Check if the accumulator contains a variable at the given offset.
    pub fn contains(&self, offset: i64) -> bool {
        self.vars.contains_key(&offset)
    }

    /// Find the variable containing the given offset (i.e., the variable
    /// whose range `[offset, offset + max_ref_size)` includes `target`).
    pub fn get_variable_containing(&self, target: i64) -> Option<&StackVariableInfo> {
        // Binary search for the rightmost variable whose offset <= target.
        // Then check if it covers the target.
        for (_, var) in self.vars.range(..=target).rev() {
            if var.offset + var.max_ref_size as i64 > target {
                return Some(var);
            }
            break;
        }
        None
    }

    /// Find all variables that intersect the range
    /// `[offset, offset + size)`.
    pub fn get_intersecting(&self, offset: i64, size: usize) -> Vec<&StackVariableInfo> {
        let end = offset + size as i64;
        self.vars
            .values()
            .filter(|v| {
                let v_end = v.offset + v.max_ref_size as i64;
                v.offset < end && v_end > offset
            })
            .collect()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    // -- StackVariableInfo tests --

    #[test]
    fn test_var_info_creation() {
        let v = StackVariableInfo::new(-8, 4, StackVariableKind::Local);
        assert_eq!(v.offset, -8);
        assert_eq!(v.max_ref_size, 4);
        assert!(v.kind.is_local());
        assert!(!v.has_references());
    }

    #[test]
    fn test_var_info_add_reference() {
        let mut v = StackVariableInfo::new(8, 4, StackVariableKind::Parameter);
        v.add_reference(addr(0x401000), 4);
        v.add_reference(addr(0x401010), 8); // larger size
        assert!(v.has_references());
        assert_eq!(v.max_ref_size, 8); // expanded
        assert_eq!(v.referencing_instructions.len(), 2);
    }

    #[test]
    fn test_var_info_kind_checks() {
        assert!(StackVariableKind::Parameter.is_parameter());
        assert!(!StackVariableKind::Parameter.is_local());
        assert!(StackVariableKind::Local.is_local());
        assert!(!StackVariableKind::Local.is_parameter());
    }

    // -- StackVariableAccumulator tests --

    #[test]
    fn test_accumulator_empty() {
        let acc = StackVariableAccumulator::new();
        assert!(acc.is_empty());
        assert_eq!(acc.len(), 0);
    }

    #[test]
    fn test_accumulator_record_reference() {
        let mut acc = StackVariableAccumulator::new();
        acc.record_reference(-8, 4, StackVariableKind::Local, addr(0x401000));
        assert_eq!(acc.len(), 1);
        assert!(acc.contains(-8));
        let var = acc.get(-8).unwrap();
        assert_eq!(var.max_ref_size, 4);
        assert!(var.has_references());
    }

    #[test]
    fn test_accumulator_record_same_offset_expands_size() {
        let mut acc = StackVariableAccumulator::new();
        acc.record_reference(-8, 4, StackVariableKind::Local, addr(0x401000));
        acc.record_reference(-8, 8, StackVariableKind::Local, addr(0x401010));
        assert_eq!(acc.len(), 1);
        let var = acc.get(-8).unwrap();
        assert_eq!(var.max_ref_size, 8);
        assert_eq!(var.referencing_instructions.len(), 2);
    }

    #[test]
    fn test_accumulator_sorted_variables() {
        let mut acc = StackVariableAccumulator::new();
        acc.record_reference(8, 4, StackVariableKind::Parameter, addr(0x401000));
        acc.record_reference(-8, 4, StackVariableKind::Local, addr(0x401000));
        acc.record_reference(-16, 4, StackVariableKind::Local, addr(0x401000));
        let sorted = acc.sorted_variables();
        assert_eq!(sorted.len(), 3);
        // BTreeMap is sorted by key
        assert_eq!(sorted[0].offset, -16);
        assert_eq!(sorted[1].offset, -8);
        assert_eq!(sorted[2].offset, 8);
    }

    #[test]
    fn test_accumulator_get_variable_containing() {
        let mut acc = StackVariableAccumulator::new();
        acc.record_reference(-16, 8, StackVariableKind::Local, addr(0x401000));
        acc.record_reference(-8, 4, StackVariableKind::Local, addr(0x401000));
        acc.record_reference(8, 4, StackVariableKind::Parameter, addr(0x401000));

        // -16 covers [-16, -9] (size 8)
        assert!(acc.get_variable_containing(-16).is_some());
        assert!(acc.get_variable_containing(-9).is_some());
        assert!(acc.get_variable_containing(-8).is_some()); // -8 var
        assert!(acc.get_variable_containing(-5).is_some()); // -8 var (covers [-8, -5))
        assert!(acc.get_variable_containing(0).is_none());
        assert!(acc.get_variable_containing(8).is_some());
        assert!(acc.get_variable_containing(11).is_some());
        assert!(acc.get_variable_containing(12).is_none());
    }

    #[test]
    fn test_accumulator_get_intersecting() {
        let mut acc = StackVariableAccumulator::new();
        acc.record_reference(-16, 8, StackVariableKind::Local, addr(0x401000));
        acc.record_reference(-8, 4, StackVariableKind::Local, addr(0x401000));
        acc.record_reference(8, 4, StackVariableKind::Parameter, addr(0x401000));

        // Range [-12, -12+4) = [-12, -8) intersects -16 var but not -8 var
        let intersecting = acc.get_intersecting(-12, 4);
        assert_eq!(intersecting.len(), 1);
        assert_eq!(intersecting[0].offset, -16);

        // Range [-10, -10+8) = [-10, -2) intersects both -16 and -8
        let intersecting = acc.get_intersecting(-10, 8);
        assert_eq!(intersecting.len(), 2);
    }

    #[test]
    fn test_accumulator_remove() {
        let mut acc = StackVariableAccumulator::new();
        acc.record_reference(-8, 4, StackVariableKind::Local, addr(0x401000));
        let removed = acc.remove(-8);
        assert!(removed.is_some());
        assert!(acc.is_empty());
    }

    #[test]
    fn test_accumulator_clear() {
        let mut acc = StackVariableAccumulator::new();
        acc.record_reference(-8, 4, StackVariableKind::Local, addr(0x401000));
        acc.record_reference(8, 4, StackVariableKind::Parameter, addr(0x401000));
        acc.clear();
        assert!(acc.is_empty());
    }

    #[test]
    fn test_accumulator_merge_overlapping() {
        let mut acc = StackVariableAccumulator::new();
        // Two overlapping locals: -16 size 8 covers [-16..-9], -12 size 4 covers [-12..-9]
        acc.record_reference(-16, 8, StackVariableKind::Local, addr(0x401000));
        acc.record_reference(-12, 4, StackVariableKind::Local, addr(0x401010));
        acc.merge_overlapping();
        // Should be merged into one variable at -16 with size 8
        assert_eq!(acc.len(), 1);
        let var = acc.get(-16).unwrap();
        assert_eq!(var.max_ref_size, 8);
    }

    #[test]
    fn test_accumulator_merge_non_overlapping() {
        let mut acc = StackVariableAccumulator::new();
        acc.record_reference(-16, 4, StackVariableKind::Local, addr(0x401000));
        acc.record_reference(-8, 4, StackVariableKind::Local, addr(0x401010));
        acc.merge_overlapping();
        // Should remain two separate variables
        assert_eq!(acc.len(), 2);
    }

    #[test]
    fn test_get_mutable() {
        let mut acc = StackVariableAccumulator::new();
        acc.record_reference(-8, 4, StackVariableKind::Local, addr(0x401000));
        {
            let var = acc.get_mut(-8).unwrap();
            var.max_ref_size = 16;
        }
        assert_eq!(acc.get(-8).unwrap().max_ref_size, 16);
    }
}
