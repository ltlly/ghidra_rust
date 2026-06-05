//! Extended listing view types for database-backed traces.
//!
//! Ported from Ghidra's `ghidra.trace.database.listing` package.
//! Provides abstract view types for code units, data, and instructions
//! that the program view delegates to.

use std::collections::BTreeMap;

use crate::model::listing::CodeUnitType;

/// Snapshot of a code unit entry in the listing view.
#[derive(Debug, Clone, PartialEq)]
pub struct CodeUnitViewEntry {
    /// Address offset.
    pub offset: u64,
    /// Length in bytes.
    pub length: u64,
    /// Type of code unit.
    pub code_unit_type: CodeUnitType,
    /// For data: the data type name.
    pub data_type_name: Option<String>,
    /// For instructions: the mnemonic.
    pub mnemonic: Option<String>,
    /// The snap (time) this entry exists at.
    pub snap: i64,
}

impl CodeUnitViewEntry {
    /// Create a code unit view entry.
    pub fn new(
        offset: u64,
        length: u64,
        code_unit_type: CodeUnitType,
        snap: i64,
    ) -> Self {
        Self {
            offset,
            length,
            code_unit_type,
            data_type_name: None,
            mnemonic: None,
            snap,
        }
    }

    /// Create an instruction entry.
    pub fn instruction(offset: u64, length: u64, snap: i64, mnemonic: impl Into<String>) -> Self {
        Self {
            offset,
            length,
            code_unit_type: CodeUnitType::Instruction,
            data_type_name: None,
            mnemonic: Some(mnemonic.into()),
            snap,
        }
    }

    /// Create a data entry.
    pub fn data(offset: u64, length: u64, snap: i64, type_name: impl Into<String>) -> Self {
        Self {
            offset,
            length,
            code_unit_type: CodeUnitType::Data,
            data_type_name: Some(type_name.into()),
            mnemonic: None,
            snap,
        }
    }

    /// Create an undefined entry.
    pub fn undefined(offset: u64, snap: i64) -> Self {
        Self {
            offset,
            length: 1,
            code_unit_type: CodeUnitType::Undefined,
            data_type_name: None,
            mnemonic: None,
            snap,
        }
    }

    /// Get the end offset (exclusive).
    pub fn end_offset(&self) -> u64 {
        self.offset + self.length
    }
}

/// Memory view that provides code units within a specific memory region.
///
/// Corresponds to Java's `AbstractBaseDBTraceCodeUnitsMemoryView`.
/// Aggregates code unit entries for an address space and time range.
#[derive(Debug)]
pub struct CodeUnitsMemoryView {
    /// Address space name.
    pub space_name: String,
    /// Minimum snap (inclusive).
    pub snap_min: i64,
    /// Maximum snap (inclusive).
    pub snap_max: i64,
    /// The code unit entries sorted by offset.
    entries: BTreeMap<u64, CodeUnitViewEntry>,
}

impl CodeUnitsMemoryView {
    /// Create a new code units memory view.
    pub fn new(space_name: impl Into<String>, snap_min: i64, snap_max: i64) -> Self {
        Self {
            space_name: space_name.into(),
            snap_min,
            snap_max,
            entries: BTreeMap::new(),
        }
    }

    /// Add a code unit entry.
    pub fn add_entry(&mut self, entry: CodeUnitViewEntry) {
        self.entries.insert(entry.offset, entry);
    }

    /// Get a code unit at a specific offset.
    pub fn get_at(&self, offset: u64) -> Option<&CodeUnitViewEntry> {
        // Check exact match first
        if let Some(entry) = self.entries.get(&offset) {
            return Some(entry);
        }
        // Check if offset falls within a multi-byte entry
        for (_, entry) in self.entries.range(..=offset) {
            if offset >= entry.offset && offset < entry.end_offset() {
                return Some(entry);
            }
        }
        None
    }

    /// Get all entries in the view.
    pub fn all_entries(&self) -> Vec<&CodeUnitViewEntry> {
        self.entries.values().collect()
    }

    /// Get entries within an offset range.
    pub fn entries_in_range(&self, min_offset: u64, max_offset: u64) -> Vec<&CodeUnitViewEntry> {
        self.entries
            .range(min_offset..=max_offset)
            .map(|(_, e)| e)
            .collect()
    }

    /// Get only instruction entries.
    pub fn instructions(&self) -> Vec<&CodeUnitViewEntry> {
        self.entries
            .values()
            .filter(|e| e.code_unit_type == CodeUnitType::Instruction)
            .collect()
    }

    /// Get only data entries.
    pub fn data_entries(&self) -> Vec<&CodeUnitViewEntry> {
        self.entries
            .values()
            .filter(|e| e.code_unit_type == CodeUnitType::Data)
            .collect()
    }

    /// Get only undefined entries.
    pub fn undefined_entries(&self) -> Vec<&CodeUnitViewEntry> {
        self.entries
            .values()
            .filter(|e| e.code_unit_type == CodeUnitType::Undefined)
            .collect()
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the view is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Composed view that merges multiple code unit views.
///
/// Corresponds to Java's `AbstractComposedDBTraceCodeUnitsView`.
/// Merges entries from multiple memory space views into a single
/// unified view.
#[derive(Debug)]
pub struct ComposedCodeUnitsView {
    /// The individual space views by name.
    views: BTreeMap<String, CodeUnitsMemoryView>,
}

impl ComposedCodeUnitsView {
    /// Create a new composed view.
    pub fn new() -> Self {
        Self {
            views: BTreeMap::new(),
        }
    }

    /// Add a space view.
    pub fn add_view(&mut self, view: CodeUnitsMemoryView) {
        self.views.insert(view.space_name.clone(), view);
    }

    /// Get a view for a specific space.
    pub fn get_view(&self, space_name: &str) -> Option<&CodeUnitsMemoryView> {
        self.views.get(space_name)
    }

    /// Get a mutable view for a specific space.
    pub fn get_view_mut(&mut self, space_name: &str) -> Option<&mut CodeUnitsMemoryView> {
        self.views.get_mut(space_name)
    }

    /// Get all space names.
    pub fn space_names(&self) -> Vec<&str> {
        self.views.keys().map(|s| s.as_str()).collect()
    }

    /// Get the total number of entries across all views.
    pub fn total_entries(&self) -> usize {
        self.views.values().map(|v| v.len()).sum()
    }

    /// Check if the composed view is empty.
    pub fn is_empty(&self) -> bool {
        self.views.values().all(|v| v.is_empty())
    }
}

impl Default for ComposedCodeUnitsView {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_unit_view_entry_instruction() {
        let entry = CodeUnitViewEntry::instruction(0x400000, 3, 0, "MOV");
        assert_eq!(entry.offset, 0x400000);
        assert_eq!(entry.length, 3);
        assert_eq!(entry.code_unit_type, CodeUnitType::Instruction);
        assert_eq!(entry.mnemonic.as_deref(), Some("MOV"));
        assert_eq!(entry.end_offset(), 0x400003);
    }

    #[test]
    fn test_code_unit_view_entry_data() {
        let entry = CodeUnitViewEntry::data(0x500000, 4, 0, "dword");
        assert_eq!(entry.code_unit_type, CodeUnitType::Data);
        assert_eq!(entry.data_type_name.as_deref(), Some("dword"));
    }

    #[test]
    fn test_code_unit_view_entry_undefined() {
        let entry = CodeUnitViewEntry::undefined(0x600000, 0);
        assert_eq!(entry.code_unit_type, CodeUnitType::Undefined);
        assert_eq!(entry.length, 1);
    }

    #[test]
    fn test_memory_view_basic() {
        let mut view = CodeUnitsMemoryView::new("ram", 0, 100);
        assert!(view.is_empty());

        view.add_entry(CodeUnitViewEntry::instruction(0x400000, 3, 0, "NOP"));
        view.add_entry(CodeUnitViewEntry::instruction(0x400003, 5, 0, "CALL"));
        view.add_entry(CodeUnitViewEntry::data(0x400008, 4, 0, "dword"));

        assert_eq!(view.len(), 3);
        assert!(!view.is_empty());
    }

    #[test]
    fn test_memory_view_get_at() {
        let mut view = CodeUnitsMemoryView::new("ram", 0, 100);
        view.add_entry(CodeUnitViewEntry::instruction(0x400000, 5, 0, "CALL"));

        assert!(view.get_at(0x400000).is_some());
        assert!(view.get_at(0x400002).is_some()); // Within the instruction
        assert!(view.get_at(0x400005).is_none()); // After the instruction
    }

    #[test]
    fn test_memory_view_filtering() {
        let mut view = CodeUnitsMemoryView::new("ram", 0, 100);
        view.add_entry(CodeUnitViewEntry::instruction(0x1000, 3, 0, "NOP"));
        view.add_entry(CodeUnitViewEntry::data(0x2000, 4, 0, "dword"));
        view.add_entry(CodeUnitViewEntry::undefined(0x3000, 0));

        assert_eq!(view.instructions().len(), 1);
        assert_eq!(view.data_entries().len(), 1);
        assert_eq!(view.undefined_entries().len(), 1);
    }

    #[test]
    fn test_memory_view_range_query() {
        let mut view = CodeUnitsMemoryView::new("ram", 0, 100);
        view.add_entry(CodeUnitViewEntry::instruction(0x1000, 3, 0, "NOP"));
        view.add_entry(CodeUnitViewEntry::instruction(0x2000, 3, 0, "NOP"));
        view.add_entry(CodeUnitViewEntry::instruction(0x3000, 3, 0, "NOP"));

        let in_range = view.entries_in_range(0x1000, 0x2000);
        assert_eq!(in_range.len(), 2);
    }

    #[test]
    fn test_composed_view() {
        let mut composed = ComposedCodeUnitsView::new();
        assert!(composed.is_empty());

        let mut ram_view = CodeUnitsMemoryView::new("ram", 0, 100);
        ram_view.add_entry(CodeUnitViewEntry::instruction(0x400000, 3, 0, "NOP"));

        let mut reg_view = CodeUnitsMemoryView::new("register", 0, 100);

        composed.add_view(ram_view);
        composed.add_view(reg_view);

        assert_eq!(composed.space_names().len(), 2);
        assert_eq!(composed.total_entries(), 1);
        assert!(composed.get_view("ram").is_some());
        assert!(composed.get_view("nonexistent").is_none());
    }
}
