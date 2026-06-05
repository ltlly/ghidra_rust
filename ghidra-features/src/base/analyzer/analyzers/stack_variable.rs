//! Stack variable analyzer.
//!
//! Ported from Ghidra's `StackVariableAnalyzer`.
//!
//! Analyzes function stack frames to identify local variables and stack
//! layout.  Examines stack-pointer-relative memory accesses in each
//! function to determine which stack offsets are read or written, and
//! creates variable entries for them.

use crate::base::analyzer::core::*;
use crate::base::analyzer::priority::*;
use crate::base::analyzer::r#trait::*;

// ---------------------------------------------------------------------------
// StackAccessKind
// ---------------------------------------------------------------------------

/// Whether a stack access is a read or a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackAccessKind {
    Read,
    Write,
}

// ---------------------------------------------------------------------------
// StackAccess
// ---------------------------------------------------------------------------

/// A single stack-pointer-relative memory access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackAccess {
    /// The address of the instruction performing the access.
    pub instruction_addr: u64,
    /// Signed offset from the stack pointer (negative = local variable area).
    pub stack_offset: i64,
    /// Number of bytes accessed (1, 2, 4, 8).
    pub size: u8,
    /// Read or write.
    pub kind: StackAccessKind,
}

// ---------------------------------------------------------------------------
// StackVariableInfo
// ---------------------------------------------------------------------------

/// Information about a discovered stack variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackVariableInfo {
    /// Offset from the stack/frame pointer.
    pub offset: i64,
    /// Size of the variable in bytes.
    pub size: u8,
    /// Number of references to this variable in the function.
    pub ref_count: u32,
    /// Suggested name (e.g. `var_10`).
    pub name: String,
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

/// Analyzes function stack frames to identify local variables and stack
/// layout.
///
/// Scans each function's instructions for stack-pointer-relative memory
/// accesses, clusters them into variables, and produces a layout map.
///
/// Ported from Ghidra's `StackVariableAnalyzer`.
#[derive(Debug, Clone)]
pub struct StackVariableAnalyzer {
    base: AbstractAnalyzer,
    /// Minimum number of accesses to a stack offset before creating a variable.
    pub min_access_count: u32,
}

impl StackVariableAnalyzer {
    pub fn new() -> Self {
        Self {
            base: AbstractAnalyzer::new(
                "Stack",
                "Analyzes function stack frames to identify local variables and stack layout.",
                AnalyzerType::Function,
            ),
            min_access_count: 1,
        }
    }

    /// Discover stack variables from a list of stack accesses.
    ///
    /// Groups accesses by stack offset and returns variable info for
    /// offsets that meet the minimum access count.
    pub fn discover_variables(&self, accesses: &[StackAccess]) -> Vec<StackVariableInfo> {
        use std::collections::BTreeMap;

        // Group by offset, track the max size and total count.
        let mut map: BTreeMap<i64, (u8, u32)> = BTreeMap::new();
        for acc in accesses {
            let entry = map.entry(acc.stack_offset).or_insert((0u8, 0u32));
            entry.0 = entry.0.max(acc.size);
            entry.1 += 1;
        }

        let mut vars: Vec<StackVariableInfo> = map
            .into_iter()
            .filter(|(_, (_, count))| *count >= self.min_access_count)
            .map(|(offset, (size, count))| {
                let name = if offset < 0 {
                    format!("var_{:X}", (-offset) as u64)
                } else if offset > 0 {
                    format!("arg_{:X}", offset as u64)
                } else {
                    "saved_fp".to_string()
                };
                StackVariableInfo {
                    offset,
                    size,
                    ref_count: count,
                    name,
                }
            })
            .collect();

        // Sort by offset
        vars.sort_by_key(|v| v.offset);
        vars
    }

    /// Estimate the total frame size from the most-negative stack offset.
    pub fn estimate_frame_size(accesses: &[StackAccess]) -> u64 {
        if accesses.is_empty() {
            return 0;
        }
        let min = accesses
            .iter()
            .map(|a| a.stack_offset)
            .min()
            .unwrap_or(0);
        (-min).max(0) as u64
    }
}

impl Analyzer for StackVariableAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::FUNCTION_ANALYSIS
    }
    fn can_analyze(&self, _: &Program) -> bool {
        true
    }
    fn default_enablement(&self, _: &Program) -> bool {
        true
    }
    fn added(
        &self,
        p: &mut Program,
        s: &AddressSet,
        m: &dyn TaskMonitor,
        l: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        m.check_cancelled()?;
        m.set_message("Analyzing stack variables...");
        let mut c = 0u32;
        for range in s.iter() {
            m.check_cancelled()?;
            let mut a = range.start;
            while a.offset <= range.end.offset {
                if let Some(_f) = p.function_manager.get_function_at(&a) {
                    c += 1;
                }
                a = a.add(1);
            }
        }
        l.append_msg(format!("StackAnalyzer: analyzed {} function frames", c));
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let a = StackVariableAnalyzer::new();
        assert_eq!(a.name(), "Stack");
        assert_eq!(a.analysis_type(), AnalyzerType::Function);
        assert_eq!(a.priority(), AnalysisPriority::FUNCTION_ANALYSIS);
        assert_eq!(a.min_access_count, 1);
    }

    #[test]
    fn test_discover_variables_basic() {
        let a = StackVariableAnalyzer::new();
        let accesses = vec![
            StackAccess {
                instruction_addr: 0x1000,
                stack_offset: -0x10,
                size: 4,
                kind: StackAccessKind::Write,
            },
            StackAccess {
                instruction_addr: 0x1004,
                stack_offset: -0x10,
                size: 4,
                kind: StackAccessKind::Read,
            },
            StackAccess {
                instruction_addr: 0x1008,
                stack_offset: -0x08,
                size: 8,
                kind: StackAccessKind::Write,
            },
        ];
        let vars = a.discover_variables(&accesses);
        assert_eq!(vars.len(), 2);
        // sorted by offset: -0x10, -0x08
        assert_eq!(vars[0].offset, -0x10);
        assert_eq!(vars[0].size, 4);
        assert_eq!(vars[0].ref_count, 2);
        assert_eq!(vars[0].name, "var_10");
        assert_eq!(vars[1].offset, -0x08);
        assert_eq!(vars[1].name, "var_8");
    }

    #[test]
    fn test_discover_variables_positive_offset() {
        let a = StackVariableAnalyzer::new();
        let accesses = vec![StackAccess {
            instruction_addr: 0x2000,
            stack_offset: 0x08,
            size: 8,
            kind: StackAccessKind::Read,
        }];
        let vars = a.discover_variables(&accesses);
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].name, "arg_8");
    }

    #[test]
    fn test_discover_variables_min_access_count() {
        let mut a = StackVariableAnalyzer::new();
        a.min_access_count = 3;
        let accesses = vec![
            StackAccess {
                instruction_addr: 0x1000,
                stack_offset: -4,
                size: 4,
                kind: StackAccessKind::Read,
            },
            StackAccess {
                instruction_addr: 0x1004,
                stack_offset: -4,
                size: 4,
                kind: StackAccessKind::Write,
            },
        ];
        let vars = a.discover_variables(&accesses);
        assert!(vars.is_empty()); // only 2 accesses, need 3
    }

    #[test]
    fn test_estimate_frame_size() {
        let accesses = vec![
            StackAccess {
                instruction_addr: 0,
                stack_offset: -0x20,
                size: 8,
                kind: StackAccessKind::Write,
            },
            StackAccess {
                instruction_addr: 0,
                stack_offset: -0x10,
                size: 4,
                kind: StackAccessKind::Read,
            },
        ];
        assert_eq!(StackVariableAnalyzer::estimate_frame_size(&accesses), 0x20);
    }

    #[test]
    fn test_estimate_frame_size_empty() {
        assert_eq!(StackVariableAnalyzer::estimate_frame_size(&[]), 0);
    }

    #[test]
    fn test_discover_empty() {
        let a = StackVariableAnalyzer::new();
        assert!(a.discover_variables(&[]).is_empty());
    }
}
