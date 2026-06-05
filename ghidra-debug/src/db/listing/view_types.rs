//! View types for code unit iteration and querying.
//!
//! Ported from Ghidra's various view interfaces:
//! - `DBTraceCodeUnitsView`, `DBTraceCodeUnitsMemoryView`
//! - `DBTraceDefinedUnitsView`, `DBTraceDefinedUnitsMemoryView`
//! - `DBTraceInstructionsView`, `DBTraceInstructionsMemoryView`
//! - `DBTraceDataView`, `DBTraceDataMemoryView`
//! - `DBTraceDefinedDataView`, `DBTraceDefinedDataMemoryView`
//! - `DBTraceUndefinedDataView`, `DBTraceUndefinedDataMemoryView`

use crate::db::listing::code_unit::{CodeUnitKind, CodeUnitRef};
use crate::db::listing::code_space::DbTraceCodeSpace;
use crate::db::listing::data_types::TraceCodeDataType;
use crate::model::Lifespan;

/// A view over all code units in a space at a given snap.
///
/// Provides iteration and lookup over instructions, data, and undefined regions.
pub struct CodeUnitsView<'a> {
    space: &'a DbTraceCodeSpace,
    snap: i64,
    min_offset: u64,
    max_offset: u64,
}

impl<'a> CodeUnitsView<'a> {
    /// Create a new code units view for a space and snap.
    pub fn new(space: &'a DbTraceCodeSpace, snap: i64) -> Self {
        Self {
            space,
            snap,
            min_offset: 0,
            max_offset: u64::MAX,
        }
    }

    /// Create a view restricted to an offset range.
    pub fn with_range(space: &'a DbTraceCodeSpace, snap: i64, min: u64, max: u64) -> Self {
        Self {
            space,
            snap,
            min_offset: min,
            max_offset: max,
        }
    }

    /// Get the snap this view operates on.
    pub fn snap(&self) -> i64 {
        self.snap
    }

    /// Check if there is an instruction at the given offset.
    pub fn has_instruction_at(&self, offset: u64) -> bool {
        offset >= self.min_offset
            && offset <= self.max_offset
            && self.space.get_instruction(self.snap, offset).is_some()
    }

    /// Check if there is defined data at the given offset.
    pub fn has_data_at(&self, offset: u64) -> bool {
        offset >= self.min_offset
            && offset <= self.max_offset
            && self.space.get_data(self.snap, offset).is_some()
    }
}

/// A view over code units that includes memory byte access.
pub struct CodeUnitsMemoryView<'a> {
    inner: CodeUnitsView<'a>,
    memory_bytes: Option<&'a [u8]>,
    memory_base: u64,
}

impl<'a> CodeUnitsMemoryView<'a> {
    /// Create a new memory view wrapping a code units view.
    pub fn new(inner: CodeUnitsView<'a>) -> Self {
        Self {
            inner,
            memory_bytes: None,
            memory_base: 0,
        }
    }

    /// Attach memory bytes to this view for byte-level access.
    pub fn with_memory(mut self, base: u64, bytes: &'a [u8]) -> Self {
        self.memory_base = base;
        self.memory_bytes = Some(bytes);
        self
    }

    /// Get the byte at the given offset from the attached memory.
    pub fn get_byte(&self, offset: u64) -> Option<u8> {
        self.memory_bytes.and_then(|bytes| {
            let idx = offset.checked_sub(self.memory_base)?;
            bytes.get(idx as usize).copied()
        })
    }

    /// Get a slice of bytes from the attached memory.
    pub fn get_bytes(&self, offset: u64, len: usize) -> Option<&[u8]> {
        self.memory_bytes.and_then(|bytes| {
            let start = offset.checked_sub(self.memory_base)? as usize;
            bytes.get(start..start + len)
        })
    }

    /// Access the underlying view.
    pub fn view(&self) -> &CodeUnitsView<'a> {
        &self.inner
    }
}

/// A view over only defined units (instructions + data, no undefined).
pub struct DefinedUnitsView<'a> {
    space: &'a DbTraceCodeSpace,
    snap: i64,
}

impl<'a> DefinedUnitsView<'a> {
    /// Create a new defined units view.
    pub fn new(space: &'a DbTraceCodeSpace, snap: i64) -> Self {
        Self { space, snap }
    }

    /// Get instruction count at this snap.
    pub fn instruction_count(&self) -> usize {
        self.space.instructions_at_snap(self.snap).len()
    }

    /// Get data count at this snap.
    pub fn data_count(&self) -> usize {
        self.space.data_at_snap(self.snap).len()
    }

    /// Total defined unit count.
    pub fn total_count(&self) -> usize {
        self.instruction_count() + self.data_count()
    }
}

/// A view over defined units with memory byte access.
pub struct DefinedUnitsMemoryView<'a> {
    inner: DefinedUnitsView<'a>,
    memory_bytes: Option<&'a [u8]>,
    memory_base: u64,
}

impl<'a> DefinedUnitsMemoryView<'a> {
    /// Create a new defined units memory view.
    pub fn new(inner: DefinedUnitsView<'a>) -> Self {
        Self {
            inner,
            memory_bytes: None,
            memory_base: 0,
        }
    }

    /// Attach memory bytes.
    pub fn with_memory(mut self, base: u64, bytes: &'a [u8]) -> Self {
        self.memory_base = base;
        self.memory_bytes = Some(bytes);
        self
    }

    /// Get a byte at the given offset.
    pub fn get_byte(&self, offset: u64) -> Option<u8> {
        self.memory_bytes.and_then(|bytes| {
            let idx = offset.checked_sub(self.memory_base)?;
            bytes.get(idx as usize).copied()
        })
    }
}

/// A view over instructions only.
pub struct InstructionsView<'a> {
    space: &'a DbTraceCodeSpace,
    snap: i64,
}

impl<'a> InstructionsView<'a> {
    /// Create a new instructions view.
    pub fn new(space: &'a DbTraceCodeSpace, snap: i64) -> Self {
        Self { space, snap }
    }

    /// Get the instruction count at this snap.
    pub fn count(&self) -> usize {
        self.space.instructions_at_snap(self.snap).len()
    }
}

/// A view over instructions with memory byte access.
pub struct InstructionsMemoryView<'a> {
    inner: InstructionsView<'a>,
    memory_bytes: Option<&'a [u8]>,
    memory_base: u64,
}

impl<'a> InstructionsMemoryView<'a> {
    /// Create a new instructions memory view.
    pub fn new(inner: InstructionsView<'a>) -> Self {
        Self {
            inner,
            memory_bytes: None,
            memory_base: 0,
        }
    }

    /// Attach memory bytes.
    pub fn with_memory(mut self, base: u64, bytes: &'a [u8]) -> Self {
        self.memory_base = base;
        self.memory_bytes = Some(bytes);
        self
    }

    /// Get a byte at the given offset.
    pub fn get_byte(&self, offset: u64) -> Option<u8> {
        self.memory_bytes.and_then(|bytes| {
            let idx = offset.checked_sub(self.memory_base)?;
            bytes.get(idx as usize).copied()
        })
    }
}

/// A view over defined data only.
pub struct DefinedDataView<'a> {
    space: &'a DbTraceCodeSpace,
    snap: i64,
}

impl<'a> DefinedDataView<'a> {
    /// Create a new defined data view.
    pub fn new(space: &'a DbTraceCodeSpace, snap: i64) -> Self {
        Self { space, snap }
    }

    /// Get the data count at this snap.
    pub fn count(&self) -> usize {
        self.space.data_at_snap(self.snap).len()
    }
}

/// A view over defined data with memory byte access.
pub struct DefinedDataMemoryView<'a> {
    inner: DefinedDataView<'a>,
    memory_bytes: Option<&'a [u8]>,
    memory_base: u64,
}

impl<'a> DefinedDataMemoryView<'a> {
    /// Create a new defined data memory view.
    pub fn new(inner: DefinedDataView<'a>) -> Self {
        Self {
            inner,
            memory_bytes: None,
            memory_base: 0,
        }
    }

    /// Attach memory bytes.
    pub fn with_memory(mut self, base: u64, bytes: &'a [u8]) -> Self {
        self.memory_base = base;
        self.memory_bytes = Some(bytes);
        self
    }

    /// Get a byte at the given offset.
    pub fn get_byte(&self, offset: u64) -> Option<u8> {
        self.memory_bytes.and_then(|bytes| {
            let idx = offset.checked_sub(self.memory_base)?;
            bytes.get(idx as usize).copied()
        })
    }
}

/// A view over undefined data only.
pub struct UndefinedDataView<'a> {
    space: &'a DbTraceCodeSpace,
    snap: i64,
}

impl<'a> UndefinedDataView<'a> {
    /// Create a new undefined data view.
    pub fn new(space: &'a DbTraceCodeSpace, snap: i64) -> Self {
        Self { space, snap }
    }

    /// Check if an offset is undefined.
    pub fn is_undefined_at(&self, offset: u64) -> bool {
        self.space.get_undefined(self.snap, offset).is_some()
    }
}

/// A view over undefined data with memory byte access.
pub struct UndefinedDataMemoryView<'a> {
    inner: UndefinedDataView<'a>,
    memory_bytes: Option<&'a [u8]>,
    memory_base: u64,
}

impl<'a> UndefinedDataMemoryView<'a> {
    /// Create a new undefined data memory view.
    pub fn new(inner: UndefinedDataView<'a>) -> Self {
        Self {
            inner,
            memory_bytes: None,
            memory_base: 0,
        }
    }

    /// Attach memory bytes.
    pub fn with_memory(mut self, base: u64, bytes: &'a [u8]) -> Self {
        self.memory_base = base;
        self.memory_bytes = Some(bytes);
        self
    }

    /// Get a byte at the given offset.
    pub fn get_byte(&self, offset: u64) -> Option<u8> {
        self.memory_bytes.and_then(|bytes| {
            let idx = offset.checked_sub(self.memory_base)?;
            bytes.get(idx as usize).copied()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::listing::code_unit::DbTraceData;
    use crate::db::listing::instruction::DbTraceInstruction;

    #[test]
    fn test_code_units_view() {
        let mut space = DbTraceCodeSpace::new("ram");
        space.add_instruction(0, DbTraceInstruction::new(0x1000, 1, 0, "x86", vec![0x90]));
        space.add_data(0, DbTraceData::new(0x2000, 4, 0, "dword"));

        let view = CodeUnitsView::new(&space, 0);
        assert!(view.has_instruction_at(0x1000));
        assert!(view.has_data_at(0x2000));
        assert!(!view.has_instruction_at(0x2000));
    }

    #[test]
    fn test_memory_view() {
        let space = DbTraceCodeSpace::new("ram");
        let view = CodeUnitsView::new(&space, 0);
        let mem_view = CodeUnitsMemoryView::new(view).with_memory(0x1000, &[0x90, 0xCC, 0xFF]);

        assert_eq!(mem_view.get_byte(0x1000), Some(0x90));
        assert_eq!(mem_view.get_byte(0x1002), Some(0xFF));
        assert!(mem_view.get_byte(0x2000).is_none());

        let slice = mem_view.get_bytes(0x1001, 2);
        assert_eq!(slice, Some([0xCC, 0xFF].as_slice()));
    }

    #[test]
    fn test_defined_units_view() {
        let mut space = DbTraceCodeSpace::new("ram");
        space.add_instruction(0, DbTraceInstruction::new(0x1000, 1, 0, "x86", vec![0x90]));
        space.add_data(0, DbTraceData::new(0x2000, 4, 0, "dword"));

        let view = DefinedUnitsView::new(&space, 0);
        assert_eq!(view.instruction_count(), 1);
        assert_eq!(view.data_count(), 1);
        assert_eq!(view.total_count(), 2);
    }
}
