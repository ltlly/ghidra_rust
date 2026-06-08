//! Subroutine block model -- ported from `SubroutineBlockModel.java`.
//!
//! A `SubroutineBlockModel` partitions a program's code into subroutines
//! (i.e., functions).  This trait extends the general [`CodeBlockModel`]
//! with a method to retrieve the underlying "base" model (typically the
//! multi-entry sub-model).

use crate::base::analyzer::core::{Address, AddressRange, AddressSet, CancelledError};

// ============================================================================
// FlowType -- lightweight copy for block references
// ============================================================================

/// The control-flow type of a block reference edge.
///
/// This is a subset of the listing `FlowType` tailored for code-block
/// reference traversal.  It distinguishes calls from other flow types
/// so that subroutine-level analysis can identify external call edges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockFlowType {
    /// A call to another subroutine.
    Call,
    /// A conditional call.
    ConditionalCall,
    /// An unconditional jump.
    Jump,
    /// A conditional jump.
    ConditionalJump,
    /// A fall-through to the next sequential instruction.
    Fallthrough,
    /// A return from subroutine.
    Return,
    /// A system call or software interrupt.
    SystemCall,
}

impl BlockFlowType {
    /// Returns `true` if this flow type is some kind of call.
    pub fn is_call(&self) -> bool {
        matches!(self, BlockFlowType::Call | BlockFlowType::ConditionalCall)
    }

    /// Returns `true` if this flow type is a jump (conditional or not).
    pub fn is_jump(&self) -> bool {
        matches!(self, BlockFlowType::Jump | BlockFlowType::ConditionalJump)
    }

    /// Returns `true` if this flow type represents a fall-through.
    pub fn is_fallthrough(&self) -> bool {
        matches!(self, BlockFlowType::Fallthrough)
    }

    /// Returns `true` if this is a terminal flow (return or system call).
    pub fn is_terminal(&self) -> bool {
        matches!(self, BlockFlowType::Return | BlockFlowType::SystemCall)
    }
}

// ============================================================================
// CodeBlock
// ============================================================================

/// A contiguous or non-contiguous range of addresses forming a basic block
/// or a subroutine block.
///
/// Mirrors Ghidra's `CodeBlock`.  A code block has a name, a primary
/// address range, and an associated [`CodeBlockModel`].
#[derive(Debug, Clone)]
pub struct CodeBlock {
    /// Human-readable name (typically the entry-point label).
    pub name: String,
    /// The primary address range (minimum to maximum address).
    pub primary_range: AddressRange,
    /// Additional (non-contiguous) address ranges in this block.
    pub extra_ranges: Vec<AddressRange>,
    /// The model that produced this block.
    pub model_name: String,
    /// Whether this block includes external address space references.
    pub includes_externals: bool,
}

impl CodeBlock {
    /// Create a new code block with a single contiguous range.
    pub fn new(
        name: impl Into<String>,
        range: AddressRange,
        model_name: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            primary_range: range,
            extra_ranges: Vec::new(),
            model_name: model_name.into(),
            includes_externals: false,
        }
    }

    /// The minimum (start) address of this block.
    pub fn min_address(&self) -> Address {
        self.primary_range.start
    }

    /// The maximum (end) address of this block.
    pub fn max_address(&self) -> Address {
        self.primary_range.end
    }

    /// Total number of addresses spanned by this block.
    pub fn num_addresses(&self) -> u64 {
        let primary = self.primary_range.len();
        let extra: u64 = self.extra_ranges.iter().map(|r| r.len()).sum();
        primary + extra
    }

    /// Returns all address ranges (primary + extra) in this block.
    pub fn address_ranges(&self) -> Vec<AddressRange> {
        let mut ranges = vec![self.primary_range];
        ranges.extend_from_slice(&self.extra_ranges);
        ranges
    }

    /// Returns `true` if this block contains the given address.
    pub fn contains(&self, addr: &Address) -> bool {
        if self.primary_range.contains(addr) {
            return true;
        }
        self.extra_ranges.iter().any(|r| r.contains(addr))
    }

    /// Get the destination references flowing out of this block.
    ///
    /// This returns an empty vec by default; implementors of
    /// [`CodeBlockModel`] should populate destinations.
    pub fn get_destinations(&self, _monitor: &dyn TaskMonitor) -> Vec<CodeBlockReference> {
        Vec::new()
    }

    /// Get the source references flowing into this block.
    ///
    /// This returns an empty vec by default; implementors of
    /// [`CodeBlockModel`] should populate sources.
    pub fn get_sources(&self, _monitor: &dyn TaskMonitor) -> Vec<CodeBlockReference> {
        Vec::new()
    }
}

// ============================================================================
// CodeBlockReference
// ============================================================================

/// A reference (edge) between two code blocks.
///
/// Mirrors Ghidra's `CodeBlockReference`.  A reference has a source
/// block, a destination address, a referent address, and a flow type.
#[derive(Debug, Clone)]
pub struct CodeBlockReference {
    /// The source block (the block the reference comes FROM).
    pub source_block: Option<CodeBlock>,
    /// The destination block (the block the reference goes TO).
    pub destination_block: Option<CodeBlock>,
    /// The flow type of this reference (call, jump, fall-through, etc.).
    pub flow_type: BlockFlowType,
    /// The address being referenced (destination address).
    pub reference_address: Address,
    /// The address from which the reference originates (referent).
    pub referent_address: Address,
}

impl CodeBlockReference {
    /// Create a new code block reference.
    pub fn new(
        source: Option<CodeBlock>,
        destination: Option<CodeBlock>,
        flow_type: BlockFlowType,
        ref_addr: Address,
        referent_addr: Address,
    ) -> Self {
        Self {
            source_block: source,
            destination_block: destination,
            flow_type,
            reference_address: ref_addr,
            referent_address: referent_addr,
        }
    }

    /// The flow type of this reference.
    pub fn flow_type(&self) -> BlockFlowType {
        self.flow_type
    }

    /// The destination address.
    pub fn reference(&self) -> Address {
        self.reference_address
    }

    /// The source (referent) address.
    pub fn referent(&self) -> Address {
        self.referent_address
    }
}

// ============================================================================
// CodeBlockReferenceIterator
// ============================================================================

/// A unidirectional iterator over [`CodeBlockReference`]s.
///
/// This trait mirrors Ghidra's `CodeBlockReferenceIterator`.
pub trait CodeBlockReferenceIterator {
    /// Returns the next reference, or `None` if exhausted.
    fn next_ref(&mut self) -> Result<Option<CodeBlockReference>, CancelledError>;

    /// Returns `true` if there are more references.
    fn has_next(&self) -> bool;
}

// ============================================================================
// CodeBlockModel trait
// ============================================================================

/// Trait for models that partition a program's code into blocks.
///
/// Mirrors Ghidra's `CodeBlockModel` interface.  Implementations include
/// basic-block models, subroutine models, and multi-entry sub models.
pub trait CodeBlockModel: Send + Sync {
    /// Human-readable name of this model.
    fn name(&self) -> &str;

    /// Get a code block that contains the specified address.
    fn get_code_block_at(
        &self,
        addr: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<CodeBlock>, CancelledError>;

    /// Get all code blocks that contain any address in the given set.
    fn get_code_blocks_containing(
        &self,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<CodeBlock>, CancelledError>;

    /// Get all code blocks in the program.
    fn get_code_blocks(
        &self,
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<CodeBlock>, CancelledError>;

    /// Get the first code block that contains the given address.
    fn get_first_code_block_containing(
        &self,
        addr: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<CodeBlock>, CancelledError>;

    /// Get the basic block model associated with this model.
    fn get_basic_block_model(&self) -> &dyn CodeBlockModel;

    /// Whether this model supports overlapping blocks.
    fn allows_block_overlap(&self) -> bool;

    /// Whether external addresses are included in results.
    fn externals_included(&self) -> bool;
}

// ============================================================================
// SubroutineBlockModel trait
// ============================================================================

/// A code block model that partitions code into subroutines (functions).
///
/// Mirrors Ghidra's `SubroutineBlockModel` interface.  Extends
/// [`CodeBlockModel`] with a method to get the underlying base model
/// (typically the multi-entry sub-model).
pub trait SubroutineBlockModel: CodeBlockModel {
    /// Get the underlying base subroutine model.
    ///
    /// This is generally the multi-entry sub-model (M-Model).  If there
    /// is no base model, `self` is returned.
    fn get_base_subroutine_model(&self) -> &dyn SubroutineBlockModel;
}

// ============================================================================
// TaskMonitor trait (minimal local copy for this module)
// ============================================================================

/// Minimal task monitor trait used by this module.
///
/// This is a re-export / local version of the core `TaskMonitor` trait
/// that allows callers to check for cancellation.
pub trait TaskMonitor: Send + Sync {
    /// Check whether the operation should be cancelled.
    fn check_cancelled(&self) -> Result<(), CancelledError>;
}

/// A simple no-op monitor that never cancels.
pub struct DummyMonitor;

impl TaskMonitor for DummyMonitor {
    fn check_cancelled(&self) -> Result<(), CancelledError> {
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_flow_type_is_call() {
        assert!(BlockFlowType::Call.is_call());
        assert!(BlockFlowType::ConditionalCall.is_call());
        assert!(!BlockFlowType::Jump.is_call());
        assert!(!BlockFlowType::Fallthrough.is_call());
    }

    #[test]
    fn test_block_flow_type_is_jump() {
        assert!(BlockFlowType::Jump.is_jump());
        assert!(BlockFlowType::ConditionalJump.is_jump());
        assert!(!BlockFlowType::Call.is_jump());
    }

    #[test]
    fn test_block_flow_type_is_fallthrough() {
        assert!(BlockFlowType::Fallthrough.is_fallthrough());
        assert!(!BlockFlowType::Jump.is_fallthrough());
    }

    #[test]
    fn test_block_flow_type_is_terminal() {
        assert!(BlockFlowType::Return.is_terminal());
        assert!(BlockFlowType::SystemCall.is_terminal());
        assert!(!BlockFlowType::Call.is_terminal());
        assert!(!BlockFlowType::Jump.is_terminal());
    }

    #[test]
    fn test_code_block_single_range() {
        let block = CodeBlock::new(
            "main",
            AddressRange::new(Address::new(0x401000), Address::new(0x401100)),
            "SubroutineModel",
        );
        assert_eq!(block.name, "main");
        assert_eq!(block.min_address(), Address::new(0x401000));
        assert_eq!(block.max_address(), Address::new(0x401100));
        assert_eq!(block.num_addresses(), 0x101);
        assert!(block.contains(&Address::new(0x401050)));
        assert!(block.contains(&Address::new(0x401000)));
        assert!(block.contains(&Address::new(0x401100)));
        assert!(!block.contains(&Address::new(0x401101)));
        assert!(!block.contains(&Address::new(0x400FFF)));
    }

    #[test]
    fn test_code_block_with_extra_ranges() {
        let mut block = CodeBlock::new(
            "switch_case",
            AddressRange::new(Address::new(0x401000), Address::new(0x401010)),
            "SubroutineModel",
        );
        block
            .extra_ranges
            .push(AddressRange::new(Address::new(0x401020), Address::new(0x401030)));
        assert_eq!(block.num_addresses(), 0x11 + 0x11); // 17 + 17
        assert!(block.contains(&Address::new(0x401025)));
        assert!(!block.contains(&Address::new(0x401015)));
    }

    #[test]
    fn test_code_block_address_ranges() {
        let mut block = CodeBlock::new(
            "func",
            AddressRange::new(Address::new(0x1000), Address::new(0x10FF)),
            "M",
        );
        block
            .extra_ranges
            .push(AddressRange::new(Address::new(0x2000), Address::new(0x20FF)));
        let ranges = block.address_ranges();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start, Address::new(0x1000));
        assert_eq!(ranges[1].start, Address::new(0x2000));
    }

    #[test]
    fn test_code_block_reference_creation() {
        let src = CodeBlock::new(
            "caller",
            AddressRange::new(Address::new(0x401000), Address::new(0x401010)),
            "M",
        );
        let dst = CodeBlock::new(
            "callee",
            AddressRange::new(Address::new(0x402000), Address::new(0x402050)),
            "M",
        );
        let cref = CodeBlockReference::new(
            Some(src),
            Some(dst),
            BlockFlowType::Call,
            Address::new(0x402000),
            Address::new(0x401010),
        );
        assert_eq!(cref.flow_type(), BlockFlowType::Call);
        assert_eq!(cref.reference(), Address::new(0x402000));
        assert_eq!(cref.referent(), Address::new(0x401010));
        assert!(cref.source_block.is_some());
        assert!(cref.destination_block.is_some());
    }

    #[test]
    fn test_code_block_reference_without_blocks() {
        let cref = CodeBlockReference::new(
            None,
            None,
            BlockFlowType::Jump,
            Address::new(0x403000),
            Address::new(0x401050),
        );
        assert_eq!(cref.flow_type(), BlockFlowType::Jump);
        assert!(cref.source_block.is_none());
        assert!(cref.destination_block.is_none());
    }

    #[test]
    fn test_dummy_monitor_never_cancels() {
        let m = DummyMonitor;
        assert!(m.check_cancelled().is_ok());
    }
}
