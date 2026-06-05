//! Memory object for the target object hierarchy.
//!
//! Ported from Ghidra's `DBTraceObjectMemory` in
//! `ghidra.trace.database.memory`. Represents a memory object
//! (address space) within the target object hierarchy.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A memory object in the target object hierarchy.
///
/// Ported from Ghidra's `DBTraceObjectMemory`. Represents a memory
/// region or address space visible in the debug target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceObjectMemory {
    /// Database object ID.
    pub object_id: i64,
    /// The memory object name (e.g., "Memory", "ram").
    pub name: String,
    /// The address space this memory corresponds to.
    pub address_space: String,
    /// Minimum address offset.
    pub min_offset: u64,
    /// Maximum address offset.
    pub max_offset: u64,
    /// Whether this memory is readable.
    pub readable: bool,
    /// Whether this memory is writable.
    pub writable: bool,
    /// Whether this memory is executable.
    pub executable: bool,
    /// The snap range.
    pub min_snap: i64,
    pub max_snap: i64,
}

impl DbTraceObjectMemory {
    /// Create a new memory object.
    pub fn new(
        object_id: i64,
        name: impl Into<String>,
        address_space: impl Into<String>,
        min_offset: u64,
        max_offset: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            object_id,
            name: name.into(),
            address_space: address_space.into(),
            min_offset,
            max_offset,
            readable: true,
            writable: false,
            executable: false,
            min_snap: lifespan.lmin(),
            max_snap: lifespan.lmax(),
        }
    }

    /// Get the lifespan.
    pub fn lifespan(&self) -> Lifespan {
        Lifespan::span(self.min_snap, self.max_snap)
    }

    /// Whether this memory covers the given offset.
    pub fn covers(&self, offset: u64) -> bool {
        offset >= self.min_offset && offset <= self.max_offset
    }

    /// Get the size of this memory region.
    pub fn size(&self) -> u64 {
        self.max_offset - self.min_offset + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_object_creation() {
        let mem = DbTraceObjectMemory::new(
            1, "ram", "ram", 0x0, 0xFFFF, Lifespan::span(0, 100),
        );
        assert_eq!(mem.name, "ram");
        assert!(mem.readable);
        assert!(!mem.writable);
    }

    #[test]
    fn test_memory_object_covers() {
        let mem = DbTraceObjectMemory::new(
            1, "ram", "ram", 0x1000, 0x2000, Lifespan::span(0, 100),
        );
        assert!(mem.covers(0x1000));
        assert!(mem.covers(0x1500));
        assert!(!mem.covers(0x2001));
    }

    #[test]
    fn test_memory_object_size() {
        let mem = DbTraceObjectMemory::new(
            1, "ram", "ram", 0x1000, 0x1FFF, Lifespan::span(0, 100),
        );
        assert_eq!(mem.size(), 0x1000);
    }
}
