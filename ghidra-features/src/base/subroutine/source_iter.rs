//! Subroutine source reference iterator -- ported from
//! `SubroutineSourceReferenceIterator.java`.
//!
//! A unidirectional iterator over the source [`CodeBlockReference`]s
//! flowing into a subroutine (code block).  For each basic block
//! inside the subroutine the iterator examines every incoming edge and
//! collects:
//!
//! - **Calls** -- all call references from outside the subroutine are
//!   included unconditionally.
//! - **Jumps / fall-throughs** -- only those whose source address
//!   falls *outside* the containing subroutine are included.
//!
//! For overlapping-block models, all containing source blocks at the
//! referent address are collected.  Otherwise the source block is set
//! to `None` (lazy resolution).

use super::block_model::{
    BlockFlowType, CodeBlock, CodeBlockModel, CodeBlockReference, TaskMonitor,
};
use crate::base::analyzer::core::{Address, AddressSet, CancelledError};

// ============================================================================
// SubroutineSourceReferenceIterator
// ============================================================================

/// Iterator over source [`CodeBlockReference`]s for a subroutine.
///
/// The iterator eagerly collects all references when constructed and
/// yields them one at a time.
pub struct SubroutineSourceReferenceIterator {
    queue: Vec<CodeBlockReference>,
}

impl SubroutineSourceReferenceIterator {
    /// Construct a new iterator that collects all source references
    /// flowing into `block`.
    pub fn new(
        block: &CodeBlock,
        model: &dyn CodeBlockModel,
        monitor: &dyn TaskMonitor,
    ) -> Result<Self, CancelledError> {
        let mut queue = Vec::new();
        Self::collect_sources_inner(block, model, &mut queue, monitor)?;
        Ok(Self { queue })
    }

    /// Count the number of source references flowing into `block`
    /// without returning the full queue.
    pub fn count(
        block: &CodeBlock,
        model: &dyn CodeBlockModel,
        monitor: &dyn TaskMonitor,
    ) -> Result<usize, CancelledError> {
        let queue = Self::build_queue(block, model, monitor)?;
        Ok(queue.len())
    }

    // ---- private helpers ----

    fn build_queue(
        block: &CodeBlock,
        model: &dyn CodeBlockModel,
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<CodeBlockReference>, CancelledError> {
        let mut queue = Vec::new();
        Self::collect_sources_inner(block, model, &mut queue, monitor)?;
        Ok(queue)
    }

    fn collect_sources_inner(
        block: &CodeBlock,
        model: &dyn CodeBlockModel,
        queue: &mut Vec<CodeBlockReference>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledError> {
        let min_addr = block.min_address();
        if min_addr == Address::ZERO && block.num_addresses() == 0 {
            return Ok(());
        }

        let bb_model = model.get_basic_block_model();
        let allows_overlap = model.allows_block_overlap();

        // Iterate over all basic blocks within the specified subroutine block.
        let basic_blocks = bb_model.get_code_blocks_containing(
            &AddressSet::from_range(block.primary_range),
            monitor,
        )?;

        for bblock in basic_blocks {
            monitor.check_cancelled()?;

            // Get basic block sources
            let sources = bblock.get_sources(monitor);
            for bb_src_ref in sources {
                let ref_flow_type = bb_src_ref.flow_type;

                if ref_flow_type.is_call() {
                    // Add all call references to queue
                    Self::queue_source_references(
                        queue,
                        block,
                        bb_src_ref.reference_address,
                        bb_src_ref.referent_address,
                        ref_flow_type,
                        model,
                        allows_overlap,
                        monitor,
                    )?;
                } else if ref_flow_type.is_jump() || ref_flow_type.is_fallthrough() {
                    // Add external jump and fall-through references to queue
                    let src_addr = bb_src_ref.referent_address;
                    if !block.contains(&src_addr) {
                        // Only include if there is a valid source block
                        let src_block =
                            model.get_first_code_block_containing(&src_addr, monitor)?;
                        if src_block.is_some() {
                            Self::queue_source_references(
                                queue,
                                block,
                                bb_src_ref.reference_address,
                                src_addr,
                                ref_flow_type,
                                model,
                                allows_overlap,
                                monitor,
                            )?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Create source block reference(s) and add to the queue.
    ///
    /// For models that allow block overlap, all source blocks at the
    /// referent address are added.  Otherwise, a reference with `None`
    /// source block is added.
    fn queue_source_references(
        queue: &mut Vec<CodeBlockReference>,
        dest_block: &CodeBlock,
        dest_addr: Address,
        src_addr: Address,
        flow_type: BlockFlowType,
        model: &dyn CodeBlockModel,
        allows_overlap: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledError> {
        if allows_overlap {
            let src_blocks = model.get_code_blocks_containing(
                &AddressSet::from_address(src_addr),
                monitor,
            )?;
            let cnt = src_blocks.len();
            for src_block in src_blocks {
                queue.push(CodeBlockReference::new(
                    Some(src_block),
                    Some(dest_block.clone()),
                    flow_type,
                    dest_addr,
                    src_addr,
                ));
            }
            if cnt != 0 {
                return Ok(());
            }
        }

        // Non-overlapping or no source block found
        queue.push(CodeBlockReference::new(
            None,
            Some(dest_block.clone()),
            flow_type,
            dest_addr,
            src_addr,
        ));
        Ok(())
    }
}

impl Iterator for SubroutineSourceReferenceIterator {
    type Item = Result<CodeBlockReference, CancelledError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.queue.is_empty() {
            None
        } else {
            Some(Ok(self.queue.remove(0)))
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::block_model::DummyMonitor;
    use crate::base::analyzer::core::AddressRange;

    /// Minimal test model with configurable blocks.
    struct TestModel {
        blocks: Vec<CodeBlock>,
        overlap: bool,
    }

    impl TestModel {
        fn new(blocks: Vec<CodeBlock>, overlap: bool) -> Self {
            Self { blocks, overlap }
        }
    }

    impl CodeBlockModel for TestModel {
        fn name(&self) -> &str {
            "TestModel"
        }

        fn get_code_block_at(
            &self,
            addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<CodeBlock>, CancelledError> {
            Ok(self.blocks.iter().find(|b| b.contains(addr)).cloned())
        }

        fn get_code_blocks_containing(
            &self,
            set: &AddressSet,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Vec<CodeBlock>, CancelledError> {
            Ok(self
                .blocks
                .iter()
                .filter(|b| set.contains(&b.min_address()))
                .cloned()
                .collect())
        }

        fn get_code_blocks(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Vec<CodeBlock>, CancelledError> {
            Ok(self.blocks.clone())
        }

        fn get_first_code_block_containing(
            &self,
            addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<CodeBlock>, CancelledError> {
            Ok(self.blocks.iter().find(|b| b.contains(addr)).cloned())
        }

        fn get_basic_block_model(&self) -> &dyn CodeBlockModel {
            self
        }

        fn allows_block_overlap(&self) -> bool {
            self.overlap
        }

        fn externals_included(&self) -> bool {
            true
        }
    }

    #[test]
    fn test_empty_block_no_sources() {
        let block = CodeBlock::new(
            "empty",
            AddressRange::new(Address::new(0x1000), Address::new(0x1000)),
            "M",
        );
        let model = TestModel::new(vec![], false);
        let monitor = DummyMonitor;
        let iter = SubroutineSourceReferenceIterator::new(&block, &model, &monitor).unwrap();
        let refs: Vec<_> = iter.collect::<Result<Vec<_>, _>>().unwrap();
        assert!(refs.is_empty());
    }

    #[test]
    fn test_count_returns_zero_for_empty() {
        let block = CodeBlock::new(
            "empty",
            AddressRange::new(Address::new(0x1000), Address::new(0x1000)),
            "M",
        );
        let model = TestModel::new(vec![], false);
        let monitor = DummyMonitor;
        let count = SubroutineSourceReferenceIterator::count(&block, &model, &monitor).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_overlapping_model_flag() {
        let model = TestModel::new(vec![], true);
        assert!(model.allows_block_overlap());
        let model2 = TestModel::new(vec![], false);
        assert!(!model2.allows_block_overlap());
    }

    #[test]
    fn test_source_iterator_yields_nothing_for_no_sources() {
        // A basic block with no incoming edges
        let bb = CodeBlock::new(
            "bb",
            AddressRange::new(Address::new(0x401000), Address::new(0x401010)),
            "BB",
        );
        let sub = CodeBlock::new(
            "sub",
            AddressRange::new(Address::new(0x401000), Address::new(0x401010)),
            "M",
        );
        let model = TestModel::new(vec![bb], false);
        let monitor = DummyMonitor;
        let iter = SubroutineSourceReferenceIterator::new(&sub, &model, &monitor).unwrap();
        let refs: Vec<_> = iter.collect::<Result<Vec<_>, _>>().unwrap();
        // Default CodeBlock::get_sources returns empty
        assert!(refs.is_empty());
    }
}
