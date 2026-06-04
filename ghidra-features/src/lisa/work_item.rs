//! Work item for fixpoint analysis.
//!
//! Ported from `WorkItem.java` in the Lisa extension.
//!
//! Represents a unit of work in the fixpoint iteration queue. Each
//! work item identifies a basic block that needs to be (re-)analyzed.

/// A work item in the fixpoint analysis worklist.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WorkItem {
    /// The block index (in the CFG).
    pub block_index: u32,
    /// The address of the block entry.
    pub address: u64,
    /// The iteration count (how many times this block has been processed).
    pub iteration: u32,
}

impl WorkItem {
    /// Create a new work item.
    pub fn new(block_index: u32, address: u64) -> Self {
        Self {
            block_index,
            address,
            iteration: 0,
        }
    }

    /// Create a work item for a specific iteration.
    pub fn with_iteration(mut self, iteration: u32) -> Self {
        self.iteration = iteration;
        self
    }
}

impl PartialOrd for WorkItem {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for WorkItem {
    /// Reverse ordering: lower iteration = higher priority (processed first).
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .iteration
            .cmp(&self.iteration)
            .then(self.block_index.cmp(&other.block_index))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BinaryHeap;

    #[test]
    fn test_work_item() {
        let wi = WorkItem::new(0, 0x1000);
        assert_eq!(wi.block_index, 0);
        assert_eq!(wi.iteration, 0);
    }

    #[test]
    fn test_work_item_priority() {
        let mut heap = BinaryHeap::new();
        heap.push(WorkItem::new(0, 0x1000).with_iteration(2));
        heap.push(WorkItem::new(1, 0x2000).with_iteration(1));
        heap.push(WorkItem::new(2, 0x3000).with_iteration(0));

        // Lower iteration = higher priority
        let first = heap.pop().unwrap();
        assert_eq!(first.iteration, 0);
    }

    #[test]
    fn test_work_item_with_iteration() {
        let wi = WorkItem::new(5, 0x5000).with_iteration(3);
        assert_eq!(wi.iteration, 3);
    }
}
