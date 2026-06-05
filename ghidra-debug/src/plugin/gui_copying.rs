//! Copy actions data model for the debugger.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.copying` package.
//! Provides the data model for copying values between trace locations,
//! supporting memory-to-memory, register-to-register, and mixed transfers.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The direction of a copy operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CopyDirection {
    /// Copy from the trace to a program (static analysis).
    TraceToProgram,
    /// Copy from a program to the trace.
    ProgramToTrace,
    /// Copy between two traces.
    TraceToTrace,
}

/// The source or destination of a copy operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CopyEndpoint {
    /// A memory location in a trace.
    TraceMemory {
        /// The address.
        address: u64,
        /// The address space name.
        space: String,
        /// The snap.
        snap: i64,
    },
    /// A register value.
    Register {
        /// The register name.
        name: String,
        /// The register value bytes.
        value: Vec<u8>,
    },
    /// A program memory location.
    ProgramMemory {
        /// The address.
        address: u64,
    },
}

/// A single entry in a copy plan, mapping source to destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopyEntry {
    /// The source endpoint.
    pub source: CopyEndpoint,
    /// The destination endpoint.
    pub destination: CopyEndpoint,
    /// The number of bytes to copy.
    pub length: usize,
    /// A human-readable description of this entry.
    pub description: String,
}

impl CopyEntry {
    /// Create a new copy entry.
    pub fn new(
        source: CopyEndpoint,
        destination: CopyEndpoint,
        length: usize,
    ) -> Self {
        Self {
            source,
            destination,
            length,
            description: String::new(),
        }
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }
}

/// A complete plan for copying data between locations.
///
/// Ported from Ghidra's `CopyPlan`. A copy plan is a sequence of entries
/// that describes all the transfers needed to complete a copy operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopyPlan {
    /// The direction of the copy.
    pub direction: CopyDirection,
    /// The entries in the plan.
    pub entries: Vec<CopyEntry>,
    /// Whether the plan has been executed.
    pub executed: bool,
}

impl CopyPlan {
    /// Create a new empty copy plan.
    pub fn new(direction: CopyDirection) -> Self {
        Self {
            direction,
            entries: Vec::new(),
            executed: false,
        }
    }

    /// Add an entry to the plan.
    pub fn add_entry(&mut self, entry: CopyEntry) {
        self.entries.push(entry);
    }

    /// Get the total number of bytes to transfer.
    pub fn total_bytes(&self) -> usize {
        self.entries.iter().map(|e| e.length).sum()
    }

    /// Get the number of entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Whether the plan is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Mark the plan as executed.
    pub fn mark_executed(&mut self) {
        self.executed = true;
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.executed = false;
    }
}

/// Builder for creating copy plans.
#[derive(Debug)]
pub struct CopyPlanBuilder {
    plan: CopyPlan,
}

impl CopyPlanBuilder {
    /// Start building a copy plan.
    pub fn new(direction: CopyDirection) -> Self {
        Self {
            plan: CopyPlan::new(direction),
        }
    }

    /// Add a memory-to-memory copy.
    pub fn memory_to_memory(
        mut self,
        src_addr: u64,
        src_space: &str,
        src_snap: i64,
        dst_addr: u64,
        dst_space: &str,
        dst_snap: i64,
        length: usize,
    ) -> Self {
        self.plan.add_entry(
            CopyEntry::new(
                CopyEndpoint::TraceMemory {
                    address: src_addr,
                    space: src_space.to_string(),
                    snap: src_snap,
                },
                CopyEndpoint::TraceMemory {
                    address: dst_addr,
                    space: dst_space.to_string(),
                    snap: dst_snap,
                },
                length,
            )
            .with_description(format!("Copy {} bytes from 0x{:x} to 0x{:x}", length, src_addr, dst_addr)),
        );
        self
    }

    /// Add a register copy.
    pub fn register_copy(
        mut self,
        src_name: &str,
        src_value: Vec<u8>,
        dst_name: &str,
    ) -> Self {
        let len = src_value.len();
        self.plan.add_entry(
            CopyEntry::new(
                CopyEndpoint::Register {
                    name: src_name.to_string(),
                    value: src_value,
                },
                CopyEndpoint::Register {
                    name: dst_name.to_string(),
                    value: Vec::new(),
                },
                len,
            )
            .with_description(format!("Copy register {}", src_name)),
        );
        self
    }

    /// Build the plan.
    pub fn build(self) -> CopyPlan {
        self.plan
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_copy_direction() {
        assert_ne!(CopyDirection::TraceToProgram, CopyDirection::ProgramToTrace);
    }

    #[test]
    fn test_copy_entry() {
        let entry = CopyEntry::new(
            CopyEndpoint::TraceMemory {
                address: 0x1000,
                space: "ram".into(),
                snap: 0,
            },
            CopyEndpoint::TraceMemory {
                address: 0x2000,
                space: "ram".into(),
                snap: 1,
            },
            256,
        )
        .with_description("copy .text section");
        assert_eq!(entry.length, 256);
        assert!(!entry.description.is_empty());
    }

    #[test]
    fn test_copy_plan() {
        let mut plan = CopyPlan::new(CopyDirection::TraceToTrace);
        assert!(plan.is_empty());

        plan.add_entry(CopyEntry::new(
            CopyEndpoint::TraceMemory {
                address: 0,
                space: "ram".into(),
                snap: 0,
            },
            CopyEndpoint::TraceMemory {
                address: 0x1000,
                space: "ram".into(),
                snap: 1,
            },
            100,
        ));
        assert_eq!(plan.entry_count(), 1);
        assert_eq!(plan.total_bytes(), 100);
        assert!(!plan.executed);

        plan.mark_executed();
        assert!(plan.executed);
    }

    #[test]
    fn test_copy_plan_builder() {
        let plan = CopyPlanBuilder::new(CopyDirection::TraceToProgram)
            .memory_to_memory(0x400000, "ram", 0, 0x400000, "ram", 1, 0x1000)
            .build();

        assert_eq!(plan.entry_count(), 1);
        assert_eq!(plan.total_bytes(), 0x1000);
    }

    #[test]
    fn test_copy_plan_builder_register() {
        let plan = CopyPlanBuilder::new(CopyDirection::TraceToTrace)
            .register_copy("RAX", vec![0x78, 0x56, 0x34, 0x12], "RAX")
            .build();

        assert_eq!(plan.entry_count(), 1);
        assert_eq!(plan.total_bytes(), 4);
    }

    #[test]
    fn test_copy_plan_clear() {
        let mut plan = CopyPlanBuilder::new(CopyDirection::TraceToProgram)
            .memory_to_memory(0, "ram", 0, 0, "ram", 1, 100)
            .build();

        assert_eq!(plan.entry_count(), 1);
        plan.mark_executed();
        plan.clear();
        assert!(plan.is_empty());
        assert!(!plan.executed);
    }

    #[test]
    fn test_copy_endpoint_equality() {
        let a = CopyEndpoint::TraceMemory {
            address: 0x1000,
            space: "ram".into(),
            snap: 0,
        };
        let b = CopyEndpoint::TraceMemory {
            address: 0x1000,
            space: "ram".into(),
            snap: 0,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn test_copy_plan_serde() {
        let plan = CopyPlanBuilder::new(CopyDirection::TraceToTrace)
            .memory_to_memory(0, "ram", 0, 0x1000, "ram", 1, 128)
            .build();

        let json = serde_json::to_string(&plan).unwrap();
        let back: CopyPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(back.entry_count(), 1);
        assert_eq!(back.total_bytes(), 128);
    }
}
