//! Stack reference record -- records a stack pointer reference
//! discovered during analysis.

use crate::base::analyzer::core::Address;

// ============================================================================
// RefType
// ============================================================================

/// The type of a reference (read, write, or read-write).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefType {
    /// A read from the stack location.
    Read,
    /// A write to the stack location.
    Write,
    /// Both read and write.
    ReadWrite,
}

impl RefType {
    /// Upgrade this ref type to include a write if the other is a write.
    pub fn combine(self, other: RefType) -> RefType {
        match (self, other) {
            (RefType::Read, RefType::Write) | (RefType::Write, RefType::Read) => RefType::ReadWrite,
            (RefType::ReadWrite, _) | (_, RefType::ReadWrite) => RefType::ReadWrite,
            (RefType::Read, RefType::Read) => RefType::Read,
            (RefType::Write, RefType::Write) => RefType::Write,
        }
    }

    pub fn is_read(&self) -> bool {
        matches!(self, RefType::Read | RefType::ReadWrite)
    }

    pub fn is_write(&self) -> bool {
        matches!(self, RefType::Write | RefType::ReadWrite)
    }
}

// ============================================================================
// StackReferenceRecord
// ============================================================================

/// A stack reference discovered during stack analysis.
///
/// Each record captures the instruction address, operand index, stack
/// offset, reference size, and the type of access (read/write).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackReferenceRecord {
    /// Address of the instruction that makes the reference.
    pub instruction_address: Address,
    /// Operand index within the instruction.
    pub operand_index: u32,
    /// Stack offset being referenced (signed; positive = param area,
    /// negative = local area on x86).
    pub stack_offset: i64,
    /// Size of the access in bytes.
    pub ref_size: usize,
    /// Type of access (read, write, or read-write).
    pub ref_type: RefType,
    /// Source of the reference (analysis, user, imported, etc.)
    pub source: ReferenceSource,
}

impl StackReferenceRecord {
    /// Create a new stack reference record.
    pub fn new(
        instruction_address: Address,
        operand_index: u32,
        stack_offset: i64,
        ref_size: usize,
        ref_type: RefType,
        source: ReferenceSource,
    ) -> Self {
        Self {
            instruction_address,
            operand_index,
            stack_offset,
            ref_size,
            ref_type,
            source,
        }
    }

    /// Whether this reference is a read.
    pub fn is_read(&self) -> bool {
        self.ref_type.is_read()
    }

    /// Whether this reference is a write.
    pub fn is_write(&self) -> bool {
        self.ref_type.is_write()
    }
}

// ============================================================================
// ReferenceSource
// ============================================================================

/// The origin of a stack reference.
///
/// Mirrors Ghidra's `SourceType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReferenceSource {
    /// Default analysis source.
    Default,
    /// Automatic analysis source.
    Analysis,
    /// User-defined (manual) source.
    UserDefined,
    /// Imported from an external format (e.g., XML, PDB).
    Imported,
}

impl ReferenceSource {
    /// Whether this source has priority >= the given source.
    pub fn is_higher_or_equal_priority_than(&self, other: ReferenceSource) -> bool {
        *self >= other
    }
}

// ============================================================================
// StackReferenceCollection
// ============================================================================

/// A collection of stack reference records, keyed by instruction address
/// and operand index.
///
/// This is the primary output of a stack analysis pass.
#[derive(Debug, Clone, Default)]
pub struct StackReferenceCollection {
    records: Vec<StackReferenceRecord>,
}

impl StackReferenceCollection {
    /// Create an empty collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a reference record.
    pub fn push(&mut self, record: StackReferenceRecord) {
        self.records.push(record);
    }

    /// Get all records.
    pub fn records(&self) -> &[StackReferenceRecord] {
        &self.records
    }

    /// Number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the collection is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Find all references to the given stack offset.
    pub fn get_references_to_offset(&self, offset: i64) -> Vec<&StackReferenceRecord> {
        self.records
            .iter()
            .filter(|r| r.stack_offset == offset)
            .collect()
    }

    /// Find all references from the given instruction address.
    pub fn get_references_from(&self, addr: &Address) -> Vec<&StackReferenceRecord> {
        self.records
            .iter()
            .filter(|r| r.instruction_address == *addr)
            .collect()
    }

    /// Find the reference at the given instruction + operand, if any.
    pub fn get_reference(
        &self,
        addr: &Address,
        operand_index: u32,
    ) -> Option<&StackReferenceRecord> {
        self.records
            .iter()
            .find(|r| r.instruction_address == *addr && r.operand_index == operand_index)
    }

    /// Update the ref type of an existing record (combine if needed).
    ///
    /// Returns `true` if a record was updated, `false` if no matching
    /// record was found.
    pub fn update_ref_type(
        &mut self,
        addr: &Address,
        operand_index: u32,
        new_type: RefType,
    ) -> bool {
        if let Some(record) = self
            .records
            .iter_mut()
            .find(|r| r.instruction_address == *addr && r.operand_index == operand_index)
        {
            record.ref_type = record.ref_type.combine(new_type);
            true
        } else {
            false
        }
    }

    /// Clear all records.
    pub fn clear(&mut self) {
        self.records.clear();
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

    // -- RefType tests --

    #[test]
    fn test_ref_type_combine() {
        assert_eq!(RefType::Read.combine(RefType::Read), RefType::Read);
        assert_eq!(RefType::Write.combine(RefType::Write), RefType::Write);
        assert_eq!(RefType::Read.combine(RefType::Write), RefType::ReadWrite);
        assert_eq!(RefType::Write.combine(RefType::Read), RefType::ReadWrite);
        assert_eq!(RefType::ReadWrite.combine(RefType::Read), RefType::ReadWrite);
        assert_eq!(RefType::Read.combine(RefType::ReadWrite), RefType::ReadWrite);
    }

    #[test]
    fn test_ref_type_checks() {
        assert!(RefType::Read.is_read());
        assert!(!RefType::Read.is_write());
        assert!(RefType::Write.is_write());
        assert!(!RefType::Write.is_read());
        assert!(RefType::ReadWrite.is_read());
        assert!(RefType::ReadWrite.is_write());
    }

    // -- ReferenceSource tests --

    #[test]
    fn test_reference_source_ordering() {
        assert!(ReferenceSource::Imported.is_higher_or_equal_priority_than(ReferenceSource::Analysis));
        assert!(ReferenceSource::UserDefined.is_higher_or_equal_priority_than(ReferenceSource::Default));
        assert!(!ReferenceSource::Default.is_higher_or_equal_priority_than(ReferenceSource::Analysis));
    }

    // -- StackReferenceRecord tests --

    #[test]
    fn test_reference_record_creation() {
        let record = StackReferenceRecord::new(
            addr(0x401000),
            0,
            -8,
            4,
            RefType::Read,
            ReferenceSource::Analysis,
        );
        assert_eq!(record.instruction_address, addr(0x401000));
        assert_eq!(record.operand_index, 0);
        assert_eq!(record.stack_offset, -8);
        assert_eq!(record.ref_size, 4);
        assert!(record.is_read());
        assert!(!record.is_write());
    }

    #[test]
    fn test_reference_record_write() {
        let record = StackReferenceRecord::new(
            addr(0x401000),
            1,
            8,
            8,
            RefType::Write,
            ReferenceSource::UserDefined,
        );
        assert!(!record.is_read());
        assert!(record.is_write());
    }

    // -- StackReferenceCollection tests --

    #[test]
    fn test_collection_empty() {
        let coll = StackReferenceCollection::new();
        assert!(coll.is_empty());
        assert_eq!(coll.len(), 0);
    }

    #[test]
    fn test_collection_push_and_query() {
        let mut coll = StackReferenceCollection::new();
        coll.push(StackReferenceRecord::new(
            addr(0x401000), 0, -8, 4, RefType::Read, ReferenceSource::Analysis,
        ));
        coll.push(StackReferenceRecord::new(
            addr(0x401010), 0, -16, 8, RefType::Write, ReferenceSource::Analysis,
        ));
        coll.push(StackReferenceRecord::new(
            addr(0x401020), 1, 8, 4, RefType::Read, ReferenceSource::Analysis,
        ));

        assert_eq!(coll.len(), 3);

        // Get references to offset -8
        let refs = coll.get_references_to_offset(-8);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].instruction_address, addr(0x401000));

        // Get references from address 0x401010
        let refs = coll.get_references_from(&addr(0x401010));
        assert_eq!(refs.len(), 1);

        // Get specific reference
        let r = coll.get_reference(&addr(0x401000), 0);
        assert!(r.is_some());
        let r = coll.get_reference(&addr(0x401000), 1);
        assert!(r.is_none());
    }

    #[test]
    fn test_collection_update_ref_type() {
        let mut coll = StackReferenceCollection::new();
        coll.push(StackReferenceRecord::new(
            addr(0x401000), 0, -8, 4, RefType::Read, ReferenceSource::Analysis,
        ));

        // Update with Write -> should become ReadWrite
        assert!(coll.update_ref_type(&addr(0x401000), 0, RefType::Write));
        let r = coll.get_reference(&addr(0x401000), 0).unwrap();
        assert_eq!(r.ref_type, RefType::ReadWrite);

        // Update non-existent
        assert!(!coll.update_ref_type(&addr(0x402000), 0, RefType::Read));
    }

    #[test]
    fn test_collection_clear() {
        let mut coll = StackReferenceCollection::new();
        coll.push(StackReferenceRecord::new(
            addr(0x401000), 0, -8, 4, RefType::Read, ReferenceSource::Analysis,
        ));
        assert!(!coll.is_empty());
        coll.clear();
        assert!(coll.is_empty());
    }
}
