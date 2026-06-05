//! Copy actions for transferring data between traces and programs.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.copying` package.
//! Provides plans for copying memory, registers, and other data between
//! the live trace and static program views.

use serde::{Deserialize, Serialize};

/// The direction of a copy operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum CopyDirection {
    /// Copy from a program (static) into a trace (dynamic).
    #[default]
    ProgramToTrace,
    /// Copy from a trace (dynamic) into a program (static).
    TraceToProgram,
}

/// A source or destination for a copy operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CopyEndpoint {
    /// A memory region in a trace.
    TraceMemory {
        /// Start address.
        address: u64,
        /// Length in bytes.
        length: u64,
    },
    /// A memory region in a program.
    ProgramMemory {
        /// Program URL.
        program_url: String,
        /// Start address.
        address: u64,
        /// Length in bytes.
        length: u64,
    },
    /// Register values in a trace.
    TraceRegisters {
        /// Register names and sizes.
        registers: Vec<(String, u32)>,
    },
}

/// A single entry in a copy plan: maps a source range to a destination range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopyEntry {
    /// The source endpoint.
    pub source: CopyEndpoint,
    /// The destination endpoint.
    pub destination: CopyEndpoint,
    /// The number of bytes to copy.
    pub length: u64,
    /// Whether this entry has been completed.
    pub done: bool,
}

impl CopyEntry {
    /// Create a new copy entry.
    pub fn new(source: CopyEndpoint, destination: CopyEndpoint, length: u64) -> Self {
        Self {
            source,
            destination,
            length,
            done: false,
        }
    }

    /// Mark as done.
    pub fn mark_done(&mut self) {
        self.done = true;
    }
}

/// A plan for copying data between a trace and a program.
///
/// Ported from Ghidra's `DebuggerCopyPlan`. Contains a list of entries
/// describing what to copy where.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CopyPlan {
    /// The direction of the copy.
    pub direction: CopyDirection,
    /// The entries in the plan.
    pub entries: Vec<CopyEntry>,
    /// A description of the plan for display.
    pub description: String,
}

impl CopyPlan {
    /// Create a new empty copy plan.
    pub fn new(direction: CopyDirection) -> Self {
        Self {
            direction,
            entries: Vec::new(),
            description: String::new(),
        }
    }

    /// Add an entry.
    pub fn add_entry(&mut self, entry: CopyEntry) {
        self.entries.push(entry);
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the plan is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The total number of bytes to copy.
    pub fn total_bytes(&self) -> u64 {
        self.entries.iter().map(|e| e.length).sum()
    }

    /// The number of completed entries.
    pub fn completed_count(&self) -> usize {
        self.entries.iter().filter(|e| e.done).count()
    }

    /// Whether all entries are done.
    pub fn is_complete(&self) -> bool {
        self.entries.iter().all(|e| e.done)
    }

    /// Get the progress as a fraction (0.0 to 1.0).
    pub fn progress(&self) -> f64 {
        if self.entries.is_empty() {
            return 1.0;
        }
        let done_bytes: u64 = self.entries.iter().filter(|e| e.done).map(|e| e.length).sum();
        let total = self.total_bytes();
        if total == 0 {
            1.0
        } else {
            done_bytes as f64 / total as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_copy_plan_basic() {
        let mut plan = CopyPlan::new(CopyDirection::ProgramToTrace)
            .with_description("Copy .text section");
        assert_eq!(plan.direction, CopyDirection::ProgramToTrace);

        plan.add_entry(CopyEntry::new(
            CopyEndpoint::ProgramMemory {
                program_url: "file:///test".into(),
                address: 0x400000,
                length: 0x1000,
            },
            CopyEndpoint::TraceMemory {
                address: 0x400000,
                length: 0x1000,
            },
            0x1000,
        ));

        assert_eq!(plan.len(), 1);
        assert_eq!(plan.total_bytes(), 0x1000);
        assert!(!plan.is_complete());
        assert_eq!(plan.progress(), 0.0);
    }

    #[test]
    fn test_copy_plan_progress() {
        let mut plan = CopyPlan::new(CopyDirection::TraceToProgram);
        plan.add_entry(CopyEntry::new(
            CopyEndpoint::TraceMemory {
                address: 0,
                length: 100,
            },
            CopyEndpoint::ProgramMemory {
                program_url: "p1".into(),
                address: 0,
                length: 100,
            },
            100,
        ));
        plan.add_entry(CopyEntry::new(
            CopyEndpoint::TraceMemory {
                address: 100,
                length: 200,
            },
            CopyEndpoint::ProgramMemory {
                program_url: "p1".into(),
                address: 100,
                length: 200,
            },
            200,
        ));

        plan.entries[0].mark_done();
        assert_eq!(plan.completed_count(), 1);
        assert!((plan.progress() - 1.0 / 3.0).abs() < 0.01);

        plan.entries[1].mark_done();
        assert!(plan.is_complete());
        assert_eq!(plan.progress(), 1.0);
    }

    #[test]
    fn test_empty_plan() {
        let plan = CopyPlan::new(CopyDirection::ProgramToTrace);
        assert!(plan.is_empty());
        assert_eq!(plan.progress(), 1.0);
    }

    #[test]
    fn test_register_copy_endpoint() {
        let endpoint = CopyEndpoint::TraceRegisters {
            registers: vec![("RAX".into(), 8), ("RBX".into(), 8)],
        };
        match endpoint {
            CopyEndpoint::TraceRegisters { registers } => {
                assert_eq!(registers.len(), 2);
            }
            _ => panic!("expected registers"),
        }
    }

    #[test]
    fn test_copy_plan_serde() {
        let mut plan = CopyPlan::new(CopyDirection::ProgramToTrace);
        plan.add_entry(CopyEntry::new(
            CopyEndpoint::TraceMemory {
                address: 0,
                length: 10,
            },
            CopyEndpoint::TraceMemory {
                address: 0x1000,
                length: 10,
            },
            10,
        ));
        let json = serde_json::to_string(&plan).unwrap();
        let back: CopyPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
    }
}
