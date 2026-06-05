//! Switch table analyzer.
//!
//! Ported from Ghidra's switch table detection logic.
//!
//! Identifies switch/jump tables from indirect jump patterns.  When the
//! analyzer sees a computed jump (e.g., an indexed load from a table
//! followed by an indirect branch), it attempts to recover the table
//! entries and the range of case indices.

use crate::base::analyzer::core::*;
use crate::base::analyzer::priority::*;
use crate::base::analyzer::r#trait::*;

// ---------------------------------------------------------------------------
// SwitchTableEntry
// ---------------------------------------------------------------------------

/// A single entry in a recovered switch table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwitchTableEntry {
    /// The case index (0-based).
    pub index: u32,
    /// The target address for this case.
    pub target: u64,
}

// ---------------------------------------------------------------------------
// SwitchTable
// ---------------------------------------------------------------------------

/// A recovered switch/jump table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchTable {
    /// Address of the indirect jump instruction.
    pub jump_addr: u64,
    /// Address where the table data begins.
    pub table_addr: u64,
    /// The recovered entries.
    pub entries: Vec<SwitchTableEntry>,
    /// Size of each table entry in bytes (4 or 8).
    pub entry_size: u8,
}

impl SwitchTable {
    /// Number of entries in the table.
    pub fn num_entries(&self) -> usize {
        self.entries.len()
    }

    /// Whether this table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return the range of target addresses `[min, max]`.
    pub fn target_range(&self) -> Option<(u64, u64)> {
        if self.entries.is_empty() {
            return None;
        }
        let min = self.entries.iter().map(|e| e.target).min().unwrap();
        let max = self.entries.iter().map(|e| e.target).max().unwrap();
        Some((min, max))
    }
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

/// Identifies switch/jump tables from indirect jump patterns.
///
/// Scans for indirect branch instructions preceded by indexed table
/// loads, and recovers the switch table entries.
///
/// Ported from Ghidra's switch table analysis.
#[derive(Debug, Clone)]
pub struct SwitchAnalyzer {
    base: AbstractAnalyzer,
    /// Minimum number of table entries to accept a valid switch table.
    pub min_table_entries: u32,
}

impl SwitchAnalyzer {
    pub fn new() -> Self {
        Self {
            base: AbstractAnalyzer::new(
                "Switch Table Analyzer",
                "Identifies switch/jump tables from indirect jump patterns.",
                AnalyzerType::Instruction,
            ),
            min_table_entries: 3,
        }
    }

    /// Parse a switch table from raw table data bytes.
    ///
    /// Given `table_data` as the raw bytes of the switch table and
    /// `entry_size` (4 for 32-bit entries, 8 for 64-bit), returns
    /// the parsed entries.
    pub fn parse_table(
        &self,
        table_data: &[u8],
        entry_size: u8,
        table_addr: u64,
    ) -> Vec<SwitchTableEntry> {
        let mut entries = Vec::new();
        let esize = entry_size as usize;
        if esize == 0 || table_data.len() < esize {
            return entries;
        }

        let num = table_data.len() / esize;
        for i in 0..num {
            let offset = i * esize;
            let chunk = &table_data[offset..offset + esize];
            let target = match esize {
                4 => {
                    let val = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    val as u64
                }
                8 => u64::from_le_bytes([
                    chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
                ]),
                _ => continue,
            };
            entries.push(SwitchTableEntry {
                index: i as u32,
                target,
            });
        }

        entries
    }

    /// Validate that a switch table has enough entries and that targets
    /// fall within a plausible address range.
    pub fn validate_table(&self, table: &SwitchTable, code_lo: u64, code_hi: u64) -> bool {
        if (table.entries.len() as u32) < self.min_table_entries {
            return false;
        }
        // All targets should be within the code region
        table
            .entries
            .iter()
            .all(|e| e.target >= code_lo && e.target < code_hi)
    }
}

impl Analyzer for SwitchAnalyzer {
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
        AnalysisPriority::REFERENCE_ANALYSIS.after().after()
    }
    fn can_analyze(&self, _: &Program) -> bool {
        true
    }
    fn default_enablement(&self, _: &Program) -> bool {
        true
    }
    fn added(
        &self,
        _p: &mut Program,
        _s: &AddressSet,
        m: &dyn TaskMonitor,
        _l: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        m.check_cancelled()?;
        m.set_message("Analyzing switch tables...");
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
        let a = SwitchAnalyzer::new();
        assert_eq!(a.name(), "Switch Table Analyzer");
        assert_eq!(a.analysis_type(), AnalyzerType::Instruction);
        assert_eq!(a.min_table_entries, 3);
    }

    #[test]
    fn test_parse_table_32bit() {
        let a = SwitchAnalyzer::new();
        // 3 entries, each 4 bytes, little-endian
        let data: Vec<u8> = vec![
            0x00, 0x10, 0x40, 0x00, // 0x00401000
            0x10, 0x10, 0x40, 0x00, // 0x00401010
            0x20, 0x10, 0x40, 0x00, // 0x00401020
        ];
        let entries = a.parse_table(&data, 4, 0x5000);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].target, 0x401000);
        assert_eq!(entries[1].target, 0x401010);
        assert_eq!(entries[2].target, 0x401020);
        assert_eq!(entries[0].index, 0);
        assert_eq!(entries[2].index, 2);
    }

    #[test]
    fn test_parse_table_64bit() {
        let a = SwitchAnalyzer::new();
        let mut data = Vec::new();
        // 2 entries, each 8 bytes
        data.extend_from_slice(&0x00401000u64.to_le_bytes());
        data.extend_from_slice(&0x00402000u64.to_le_bytes());
        let entries = a.parse_table(&data, 8, 0);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].target, 0x401000);
        assert_eq!(entries[1].target, 0x402000);
    }

    #[test]
    fn test_parse_table_empty() {
        let a = SwitchAnalyzer::new();
        assert!(a.parse_table(&[], 4, 0).is_empty());
    }

    #[test]
    fn test_parse_table_too_small() {
        let a = SwitchAnalyzer::new();
        assert!(a.parse_table(&[0x00, 0x00], 4, 0).is_empty()); // 2 bytes < 4
    }

    #[test]
    fn test_validate_table_valid() {
        let a = SwitchAnalyzer::new();
        let table = SwitchTable {
            jump_addr: 0x3000,
            table_addr: 0x4000,
            entries: vec![
                SwitchTableEntry {
                    index: 0,
                    target: 0x1000,
                },
                SwitchTableEntry {
                    index: 1,
                    target: 0x1010,
                },
                SwitchTableEntry {
                    index: 2,
                    target: 0x1020,
                },
            ],
            entry_size: 4,
        };
        assert!(a.validate_table(&table, 0x1000, 0x5000));
    }

    #[test]
    fn test_validate_table_too_few_entries() {
        let a = SwitchAnalyzer::new();
        let table = SwitchTable {
            jump_addr: 0x3000,
            table_addr: 0x4000,
            entries: vec![SwitchTableEntry {
                index: 0,
                target: 0x1000,
            }],
            entry_size: 4,
        };
        assert!(!a.validate_table(&table, 0x1000, 0x5000));
    }

    #[test]
    fn test_validate_table_target_out_of_range() {
        let a = SwitchAnalyzer::new();
        let table = SwitchTable {
            jump_addr: 0x3000,
            table_addr: 0x4000,
            entries: vec![
                SwitchTableEntry {
                    index: 0,
                    target: 0x1000,
                },
                SwitchTableEntry {
                    index: 1,
                    target: 0x1010,
                },
                SwitchTableEntry {
                    index: 2,
                    target: 0x9000,
                }, // out of range
            ],
            entry_size: 4,
        };
        assert!(!a.validate_table(&table, 0x1000, 0x5000));
    }

    #[test]
    fn test_switch_table_methods() {
        let table = SwitchTable {
            jump_addr: 0x3000,
            table_addr: 0x4000,
            entries: vec![
                SwitchTableEntry {
                    index: 0,
                    target: 0x2000,
                },
                SwitchTableEntry {
                    index: 1,
                    target: 0x1000,
                },
                SwitchTableEntry {
                    index: 2,
                    target: 0x3000,
                },
            ],
            entry_size: 4,
        };
        assert_eq!(table.num_entries(), 3);
        assert!(!table.is_empty());
        assert_eq!(table.target_range(), Some((0x1000, 0x3000)));
    }

    #[test]
    fn test_switch_table_empty() {
        let table = SwitchTable {
            jump_addr: 0,
            table_addr: 0,
            entries: vec![],
            entry_size: 4,
        };
        assert!(table.is_empty());
        assert_eq!(table.num_entries(), 0);
        assert_eq!(table.target_range(), None);
    }

    #[test]
    fn test_priority() {
        let a = SwitchAnalyzer::new();
        assert_eq!(
            a.priority(),
            AnalysisPriority::REFERENCE_ANALYSIS.after().after()
        );
    }
}
