//! FillOutStructureHelper -- helper for structure field completion.
//!
//! Port of Ghidra's `ghidra.app.decompiler.util.FillOutStructureHelper`
//! and `ghidra.app.decompiler.util.FillOutStructureCmd`.
//!
//! Provides utilities for analyzing decompiled functions and proposing
//! structure field definitions based on observed field accesses.

use std::collections::HashMap;

/// A structure field entry discovered during decompilation analysis.
///
/// Port of Ghidra's `ghidra.app.decompiler.util.StructFieldEntry`.
#[derive(Debug, Clone)]
pub struct StructFieldEntry {
    /// Byte offset of the field within the structure.
    pub offset: i64,
    /// Size of the field in bytes.
    pub size: usize,
    /// The data type name (e.g., "int", "char*", "undefined4").
    pub datatype_name: String,
    /// The data type id.
    pub datatype_id: Option<u64>,
    /// Whether this field is a pointer.
    pub is_pointer: bool,
    /// Whether the field access is a read.
    pub is_read: bool,
    /// Whether the field access is a write.
    pub is_write: bool,
    /// Source location where this field was observed.
    pub source_address: u64,
}

impl StructFieldEntry {
    /// Create a new struct field entry.
    pub fn new(offset: i64, size: usize, datatype_name: impl Into<String>) -> Self {
        Self {
            offset,
            size,
            datatype_name: datatype_name.into(),
            datatype_id: None,
            is_pointer: false,
            is_read: false,
            is_write: false,
            source_address: 0,
        }
    }

    /// Set the data type id.
    pub fn with_datatype_id(mut self, id: u64) -> Self {
        self.datatype_id = Some(id);
        self
    }

    /// Mark as pointer.
    pub fn as_pointer(mut self) -> Self {
        self.is_pointer = true;
        self
    }

    /// Mark as read access.
    pub fn as_read(mut self) -> Self {
        self.is_read = true;
        self
    }

    /// Mark as write access.
    pub fn as_write(mut self) -> Self {
        self.is_write = true;
        self
    }

    /// Set the source address.
    pub fn with_source(mut self, addr: u64) -> Self {
        self.source_address = addr;
        self
    }

    /// Get the end offset (offset + size).
    pub fn end_offset(&self) -> i64 {
        self.offset + self.size as i64
    }

    /// Check if this field overlaps with another.
    pub fn overlaps(&self, other: &StructFieldEntry) -> bool {
        self.offset < other.end_offset() && other.offset < self.end_offset()
    }
}

/// Helper for filling out structure fields from decompiler output.
///
/// Port of Ghidra's `ghidra.app.decompiler.util.FillOutStructureHelper`.
#[derive(Debug)]
pub struct FillOutStructureHelper {
    /// Discovered field entries, keyed by offset.
    entries: HashMap<i64, Vec<StructFieldEntry>>,
    /// The base address of the structure pointer.
    base_address: u64,
    /// The structure name (if known).
    struct_name: Option<String>,
}

impl FillOutStructureHelper {
    /// Create a new helper for the given base address.
    pub fn new(base_address: u64) -> Self {
        Self {
            entries: HashMap::new(),
            base_address,
            struct_name: None,
        }
    }

    /// Set the structure name.
    pub fn with_struct_name(mut self, name: impl Into<String>) -> Self {
        self.struct_name = Some(name.into());
        self
    }

    /// Get the base address.
    pub fn base_address(&self) -> u64 {
        self.base_address
    }

    /// Get the structure name.
    pub fn struct_name(&self) -> Option<&str> {
        self.struct_name.as_deref()
    }

    /// Add a discovered field entry.
    pub fn add_entry(&mut self, entry: StructFieldEntry) {
        self.entries.entry(entry.offset).or_default().push(entry);
    }

    /// Add multiple entries.
    pub fn add_entries(&mut self, entries: Vec<StructFieldEntry>) {
        for entry in entries {
            self.add_entry(entry);
        }
    }

    /// Get all unique offsets that have field entries.
    pub fn offsets(&self) -> Vec<i64> {
        let mut offsets: Vec<i64> = self.entries.keys().copied().collect();
        offsets.sort();
        offsets
    }

    /// Get the entries for a specific offset.
    pub fn entries_at(&self, offset: i64) -> Option<&[StructFieldEntry]> {
        self.entries.get(&offset).map(|v| v.as_slice())
    }

    /// Get all entries as a flat list sorted by offset.
    pub fn all_entries(&self) -> Vec<&StructFieldEntry> {
        let mut result: Vec<&StructFieldEntry> = self.entries.values().flatten().collect();
        result.sort_by_key(|e| e.offset);
        result
    }

    /// Get the number of unique field offsets.
    pub fn field_count(&self) -> usize {
        self.entries.len()
    }

    /// Get the maximum offset + size (total structure size estimate).
    pub fn estimated_size(&self) -> i64 {
        self.entries
            .values()
            .flatten()
            .map(|e| e.end_offset())
            .max()
            .unwrap_or(0)
    }

    /// Merge non-overlapping entries, preferring larger field sizes.
    pub fn merge_entries(&self) -> Vec<StructFieldEntry> {
        let mut by_offset: HashMap<i64, &StructFieldEntry> = HashMap::new();

        for entry in self.entries.values().flatten() {
            match by_offset.get(&entry.offset) {
                Some(existing) => {
                    if entry.size > existing.size {
                        by_offset.insert(entry.offset, entry);
                    }
                }
                None => {
                    by_offset.insert(entry.offset, entry);
                }
            }
        }

        let mut result: Vec<StructFieldEntry> =
            by_offset.into_values().cloned().collect();
        result.sort_by_key(|e| e.offset);
        result
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Result of a FillOutStructure analysis.
#[derive(Debug, Clone)]
pub struct FillOutStructureResult {
    /// Merged field entries.
    pub fields: Vec<StructFieldEntry>,
    /// Estimated structure size in bytes.
    pub estimated_size: i64,
    /// Number of unique offsets observed.
    pub unique_offsets: usize,
    /// Whether there are overlapping field accesses.
    pub has_overlaps: bool,
}

impl FillOutStructureResult {
    /// Create from a helper.
    pub fn from_helper(helper: &FillOutStructureHelper) -> Self {
        let fields = helper.merge_entries();
        let estimated_size = helper.estimated_size();
        let unique_offsets = helper.field_count();

        // Check for overlaps in the merged entries
        let mut has_overlaps = false;
        for i in 0..fields.len() {
            for j in (i + 1)..fields.len() {
                if fields[i].overlaps(&fields[j]) {
                    has_overlaps = true;
                    break;
                }
            }
            if has_overlaps {
                break;
            }
        }

        Self {
            fields,
            estimated_size,
            unique_offsets,
            has_overlaps,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_field_entry_basic() {
        let entry = StructFieldEntry::new(0, 4, "int");
        assert_eq!(entry.offset, 0);
        assert_eq!(entry.size, 4);
        assert_eq!(entry.end_offset(), 4);
        assert!(!entry.is_pointer);
    }

    #[test]
    fn struct_field_entry_builder() {
        let entry = StructFieldEntry::new(8, 8, "long")
            .with_datatype_id(42)
            .as_pointer()
            .as_read()
            .with_source(0x1000);
        assert_eq!(entry.datatype_id, Some(42));
        assert!(entry.is_pointer);
        assert!(entry.is_read);
        assert!(!entry.is_write);
        assert_eq!(entry.source_address, 0x1000);
    }

    #[test]
    fn struct_field_overlap() {
        let a = StructFieldEntry::new(0, 8, "long");
        let b = StructFieldEntry::new(4, 4, "int");
        let c = StructFieldEntry::new(8, 4, "int");
        assert!(a.overlaps(&b));  // 0..8 overlaps 4..8
        assert!(!a.overlaps(&c)); // 0..8 does not overlap 8..12
    }

    #[test]
    fn helper_basic() {
        let mut helper = FillOutStructureHelper::new(0x2000);
        helper.add_entry(StructFieldEntry::new(0, 4, "int").as_read());
        helper.add_entry(StructFieldEntry::new(4, 8, "long").as_write());

        assert_eq!(helper.field_count(), 2);
        assert_eq!(helper.estimated_size(), 12);
        assert_eq!(helper.base_address(), 0x2000);
    }

    #[test]
    fn helper_entries_at() {
        let mut helper = FillOutStructureHelper::new(0);
        helper.add_entry(StructFieldEntry::new(0, 4, "int"));
        helper.add_entry(StructFieldEntry::new(0, 4, "uint32_t")); // same offset

        let entries = helper.entries_at(0).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(helper.entries_at(8).is_none());
    }

    #[test]
    fn helper_merge_prefers_larger() {
        let mut helper = FillOutStructureHelper::new(0);
        helper.add_entry(StructFieldEntry::new(0, 2, "short"));
        helper.add_entry(StructFieldEntry::new(0, 4, "int")); // larger, should be preferred

        let merged = helper.merge_entries();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].size, 4);
        assert_eq!(merged[0].datatype_name, "int");
    }

    #[test]
    fn helper_struct_name() {
        let helper = FillOutStructureHelper::new(0).with_struct_name("my_struct");
        assert_eq!(helper.struct_name(), Some("my_struct"));
    }

    #[test]
    fn helper_all_entries_sorted() {
        let mut helper = FillOutStructureHelper::new(0);
        helper.add_entry(StructFieldEntry::new(8, 4, "int"));
        helper.add_entry(StructFieldEntry::new(0, 4, "int"));
        helper.add_entry(StructFieldEntry::new(4, 4, "int"));

        let entries = helper.all_entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].offset, 0);
        assert_eq!(entries[1].offset, 4);
        assert_eq!(entries[2].offset, 8);
    }

    #[test]
    fn helper_offsets_sorted() {
        let mut helper = FillOutStructureHelper::new(0);
        helper.add_entry(StructFieldEntry::new(8, 4, "a"));
        helper.add_entry(StructFieldEntry::new(0, 4, "b"));
        helper.add_entry(StructFieldEntry::new(4, 4, "c"));

        let offsets = helper.offsets();
        assert_eq!(offsets, vec![0, 4, 8]);
    }

    #[test]
    fn result_from_helper() {
        let mut helper = FillOutStructureHelper::new(0x1000);
        helper.add_entry(StructFieldEntry::new(0, 4, "int").as_read());
        helper.add_entry(StructFieldEntry::new(4, 8, "long").as_write());
        helper.add_entry(StructFieldEntry::new(12, 1, "char"));

        let result = FillOutStructureResult::from_helper(&helper);
        assert_eq!(result.unique_offsets, 3);
        assert_eq!(result.estimated_size, 13);
        assert!(!result.has_overlaps);
        assert_eq!(result.fields.len(), 3);
    }

    #[test]
    fn result_overlaps() {
        let mut helper = FillOutStructureHelper::new(0);
        // Add overlapping entries at the same offset but different sizes
        helper.add_entry(StructFieldEntry::new(0, 2, "short"));
        helper.add_entry(StructFieldEntry::new(0, 4, "int"));

        // After merge, only the larger one remains, so no overlaps
        let result = FillOutStructureResult::from_helper(&helper);
        assert!(!result.has_overlaps);
    }

    #[test]
    fn helper_clear() {
        let mut helper = FillOutStructureHelper::new(0);
        helper.add_entry(StructFieldEntry::new(0, 4, "int"));
        assert_eq!(helper.field_count(), 1);
        helper.clear();
        assert_eq!(helper.field_count(), 0);
    }

    #[test]
    fn helper_add_entries_batch() {
        let mut helper = FillOutStructureHelper::new(0);
        let entries = vec![
            StructFieldEntry::new(0, 4, "int"),
            StructFieldEntry::new(4, 4, "int"),
            StructFieldEntry::new(8, 8, "long"),
        ];
        helper.add_entries(entries);
        assert_eq!(helper.field_count(), 3);
    }
}
