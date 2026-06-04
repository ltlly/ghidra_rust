//! Disassembler queue -- ported from Ghidra's `DisassemblerQueue.java`.
//!
//! Manages a priority queue of instruction block flows to be disassembled.
//! The queue maintains three priority levels:
//! 1. Seed queue -- initial start points and discovered CALL points
//! 2. Priority queue -- branch flows from previous instruction sets
//! 3. Current branch queue -- branches from the current instruction set

use std::collections::{BTreeSet, HashSet};

use crate::base::analyzer::core::*;
use crate::base::disassembler::core::{BlockFlowType, InstructionBlock};

// ---------------------------------------------------------------------------
// InstructionBlockFlow
// ---------------------------------------------------------------------------

/// A flow from one instruction block to another, used by the queue.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InstructionBlockFlow {
    /// The destination address to disassemble.
    pub destination: Address,
    /// The address this flow originates from.
    pub flow_from: Option<Address>,
    /// The type of flow.
    pub flow_type: BlockFlowType,
}

impl InstructionBlockFlow {
    /// Create a new block flow.
    pub fn new(destination: Address, flow_from: Option<Address>, flow_type: BlockFlowType) -> Self {
        Self {
            destination,
            flow_from,
            flow_type,
        }
    }

    /// Get the destination address.
    pub fn destination_address(&self) -> Address {
        self.destination
    }

    /// Get the flow-from address, if any.
    pub fn flow_from_address(&self) -> Option<Address> {
        self.flow_from
    }

    /// Get the flow type.
    pub fn flow_type(&self) -> BlockFlowType {
        self.flow_type
    }
}

impl PartialOrd for InstructionBlockFlow {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for InstructionBlockFlow {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Primary sort by flow type, then by destination address
        self.flow_type
            .cmp(&other.flow_type)
            .then_with(|| self.destination.cmp(&other.destination))
    }
}

// ---------------------------------------------------------------------------
// DisassemblerQueue
// ---------------------------------------------------------------------------

/// Queue managing disassembly work items.
///
/// Manages three priority levels of disassembly work:
/// - **seed queue**: initial start points and discovered CALL targets
/// - **priority queue**: branch flows from previous instruction sets
/// - **current branch queue**: branches discovered in the current instruction set
///
/// Flows are ordered by type (Priority < Call < Branch < Computed),
/// then by destination address within each type.
pub struct DisassemblerQueue {
    /// Initial start points and discovered CALL points.
    ordered_seed_queue: BTreeSet<InstructionBlockFlow>,
    /// Branch flows from previous instruction sets.
    priority_queue: BTreeSet<InstructionBlockFlow>,
    /// Branch flows from the current instruction set.
    current_branch_queue: BTreeSet<InstructionBlockFlow>,
    /// Flows already processed in the current instruction set.
    processed_branch_flows: HashSet<InstructionBlockFlow>,
    /// Optional address set restriction.
    restricted_address_set: Option<AddressSet>,
    /// Last block processed.
    last_block: Option<InstructionBlock>,
    /// Address of the last block processed.
    last_block_addr: Option<Address>,
    /// Address the last block flowed from.
    last_flow_from: Option<Address>,
}

impl DisassemblerQueue {
    /// Create a new queue with a single starting address.
    pub fn new(start_addr: Address) -> Self {
        let mut seed_queue = BTreeSet::new();
        seed_queue.insert(InstructionBlockFlow::new(
            start_addr,
            None,
            BlockFlowType::Priority,
        ));

        Self {
            ordered_seed_queue: seed_queue,
            priority_queue: BTreeSet::new(),
            current_branch_queue: BTreeSet::new(),
            processed_branch_flows: HashSet::new(),
            restricted_address_set: None,
            last_block: None,
            last_block_addr: None,
            last_flow_from: None,
        }
    }

    /// Create a new queue with a restricted address set.
    pub fn with_restriction(start_addr: Address, restricted: AddressSet) -> Self {
        let mut queue = Self::new(start_addr);
        queue.restricted_address_set = Some(restricted);
        queue
    }

    /// Determine if additional instruction sets may be produced.
    ///
    /// If true, the queue is ready to produce instruction set blocks.
    /// Returns false if the monitor is cancelled or no more work remains.
    pub fn continue_producing_instruction_sets(&mut self, monitor: &dyn TaskMonitor) -> bool {
        self.current_branch_queue.clear();
        self.processed_branch_flows.clear();
        self.last_block = None;
        self.last_block_addr = None;
        self.last_flow_from = None;

        if monitor.is_cancelled() {
            return false;
        }

        if !self.priority_queue.is_empty() {
            return true;
        }

        if self.ordered_seed_queue.is_empty() {
            return false;
        }

        // Promote the first seed item to the priority queue
        if let Some(flow) = self.ordered_seed_queue.iter().next().cloned() {
            self.ordered_seed_queue.remove(&flow);
            self.priority_queue.insert(flow);
            return true;
        }

        false
    }

    /// Get the next block to disassemble.
    ///
    /// Returns `None` if no more blocks are available or the monitor
    /// has been cancelled.
    pub fn get_next_block(&mut self, monitor: &dyn TaskMonitor) -> Option<InstructionBlock> {
        if monitor.is_cancelled() {
            self.last_block = None;
            return None;
        }

        // Process from priority queue first, then current branch queue
        let flow = if !self.priority_queue.is_empty() {
            let flow = self.priority_queue.iter().next().cloned()?;
            self.priority_queue.remove(&flow);
            flow
        } else if !self.current_branch_queue.is_empty() {
            let flow = self.current_branch_queue.iter().next().cloned()?;
            self.current_branch_queue.remove(&flow);
            flow
        } else {
            return None;
        };

        let block_addr = flow.destination;
        self.processed_branch_flows.insert(flow.clone());

        // Check restriction
        if let Some(ref restricted) = self.restricted_address_set {
            if !restricted.contains(&block_addr) {
                return None;
            }
        }

        let mut block = InstructionBlock::new(block_addr);
        block.set_flow_from(flow.flow_from.unwrap_or(Address::ZERO));
        block.set_start_of_flow(flow.flow_type == BlockFlowType::Priority);

        self.last_block_addr = Some(block_addr);
        self.last_flow_from = flow.flow_from;
        self.last_block = Some(block.clone());

        Some(block)
    }

    /// Add a deferred flow to the appropriate queue.
    ///
    /// Call flows go to the seed queue; branch flows go to the priority queue.
    pub fn add_flow(&mut self, flow: InstructionBlockFlow) {
        match flow.flow_type {
            BlockFlowType::Call => {
                self.ordered_seed_queue.insert(flow);
            }
            _ => {
                self.priority_queue.insert(flow);
            }
        }
    }

    /// Add a branch flow discovered within the current instruction set.
    pub fn add_current_branch(&mut self, flow: InstructionBlockFlow) {
        self.current_branch_queue.insert(flow);
    }

    /// Get the address of the last block processed.
    pub fn last_block_address(&self) -> Option<Address> {
        self.last_block_addr
    }

    /// Get the flow-from address of the last block processed.
    pub fn last_flow_from_address(&self) -> Option<Address> {
        self.last_flow_from
    }

    /// Check if the seed queue is empty.
    pub fn is_empty(&self) -> bool {
        self.ordered_seed_queue.is_empty()
            && self.priority_queue.is_empty()
            && self.current_branch_queue.is_empty()
    }

    /// Get the total number of pending flows across all queues.
    pub fn pending_count(&self) -> usize {
        self.ordered_seed_queue.len()
            + self.priority_queue.len()
            + self.current_branch_queue.len()
    }

    /// Commit an instruction set: process conflicts, add discovered flows.
    ///
    /// Returns the number of instructions added to the program.
    pub fn commit_instruction_set(
        &mut self,
        blocks: &[InstructionBlock],
        program: &mut Program,
    ) -> usize {
        let mut disassemble_count = 0;
        let mut conflict_addrs = AddressSet::new();

        for block in blocks {
            // Handle instruction conflicts
            if let Some(ref conflict) = block.conflict {
                program.set_bookmark(
                    conflict.address,
                    BookmarkType::Error,
                    "Bad Instruction",
                    &conflict.message,
                );
                let block_end = block.max_address().unwrap_or(conflict.address);
                if conflict.address.offset <= block_end.offset {
                    conflict_addrs.add_range(AddressRange::new(conflict.address, block_end));
                }
            }

            let instr_count = block.instructions_added_count();
            if instr_count == 0 {
                continue;
            }

            // Add deferred flows for successfully added instructions
            for flow in &block.block_flows {
                let ibf = InstructionBlockFlow::new(
                    flow.destination,
                    Some(flow.flow_from),
                    flow.flow_type,
                );
                if flow.flow_type != BlockFlowType::Call
                    && self.processed_branch_flows.contains(&ibf)
                {
                    continue;
                }
                if block.conflict.is_none()
                    || block.conflict.as_ref().unwrap().address.offset > flow.flow_from.offset
                {
                    if flow.flow_type == BlockFlowType::Call {
                        self.ordered_seed_queue.insert(ibf);
                    } else {
                        self.priority_queue.insert(ibf);
                    }
                }
            }

            disassemble_count += instr_count;
        }

        disassemble_count
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_queue_creation() {
        let queue = DisassemblerQueue::new(Address::new(0x1000));
        assert!(!queue.is_empty());
        assert_eq!(queue.pending_count(), 1);
    }

    #[test]
    fn test_queue_priority_ordering() {
        let mut queue = DisassemblerQueue::new(Address::new(0x1000));
        // Add a branch flow and a call flow
        queue.add_flow(InstructionBlockFlow::new(
            Address::new(0x3000),
            Some(Address::new(0x2000)),
            BlockFlowType::Branch,
        ));
        queue.add_flow(InstructionBlockFlow::new(
            Address::new(0x4000),
            Some(Address::new(0x2000)),
            BlockFlowType::Call,
        ));
        // Priority < Call < Branch in ordering
        assert!(queue.pending_count() >= 3);
    }

    #[test]
    fn test_queue_restriction() {
        let mut restricted = AddressSet::new();
        restricted.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x2000)));

        let mut queue =
            DisassemblerQueue::with_restriction(Address::new(0x1000), restricted);
        let monitor = BasicTaskMonitor::new();

        // Must call continue_producing_instruction_sets first to promote seed to priority
        assert!(queue.continue_producing_instruction_sets(&monitor));
        // Should produce a block within range
        let block = queue.get_next_block(&monitor);
        assert!(block.is_some());
    }

    #[test]
    fn test_instruction_block_flow_ordering() {
        let f1 = InstructionBlockFlow::new(Address::new(0x1000), None, BlockFlowType::Priority);
        let f2 = InstructionBlockFlow::new(Address::new(0x1000), None, BlockFlowType::Call);
        let f3 = InstructionBlockFlow::new(Address::new(0x1000), None, BlockFlowType::Branch);
        assert!(f1 < f2);
        assert!(f2 < f3);
    }

    #[test]
    fn test_queue_produces_instruction_sets() {
        let mut queue = DisassemblerQueue::new(Address::new(0x1000));
        let monitor = BasicTaskMonitor::new();

        assert!(queue.continue_producing_instruction_sets(&monitor));
        assert!(!monitor.is_cancelled());
    }
}
