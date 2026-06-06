//! Trace data views ported from Framework-TraceModeling listing package.
//!
//! Provides the view hierarchy for code units in a trace, including
//! data views, instruction views, and composed views.

use serde::{Deserialize, Serialize};

/// The type of a code unit in a trace listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ViewCodeUnitType {
    /// A disassembled instruction.
    Instruction,
    /// A defined data value.
    DefinedData,
    /// Undefined/uninitialized data.
    UndefinedData,
    /// A comment-only entry.
    Comment,
    /// A composite (struct/union) field.
    CompositeField,
    /// An array element.
    ArrayElement,
}

/// Configuration for creating data views.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewDataConfig {
    /// The address space name.
    pub space_name: String,
    /// The snap (time) to view at.
    pub snap: i64,
    /// Minimum address offset.
    pub min_offset: u64,
    /// Maximum address offset.
    pub max_offset: u64,
    /// Whether to include undefined data gaps.
    pub include_undefined: bool,
    /// Whether to follow cross-references.
    pub follow_references: bool,
}

impl ViewDataConfig {
    /// Create a new view config for a space at a snap.
    pub fn new(space_name: impl Into<String>, snap: i64) -> Self {
        Self {
            space_name: space_name.into(),
            snap,
            min_offset: 0,
            max_offset: u64::MAX,
            include_undefined: false,
            follow_references: false,
        }
    }

    /// Set the address range.
    pub fn with_range(mut self, min: u64, max: u64) -> Self {
        self.min_offset = min;
        self.max_offset = max;
        self
    }

    /// Include undefined data in the view.
    pub fn with_undefined(mut self, include: bool) -> Self {
        self.include_undefined = include;
        self
    }

    /// Set whether to follow cross-references.
    pub fn with_references(mut self, follow: bool) -> Self {
        self.follow_references = follow;
        self
    }
}

/// A single data view entry (code unit) from the trace listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewDataEntry {
    /// The address offset.
    pub offset: u64,
    /// The type of this code unit.
    pub unit_type: ViewCodeUnitType,
    /// The size in bytes.
    pub size: u32,
    /// The data type name (e.g., "dword", "pointer", "string").
    pub data_type: Option<String>,
    /// The raw bytes at this location.
    pub bytes: Vec<u8>,
    /// A display mnemonic or value representation.
    pub display: String,
    /// Reference information, if applicable.
    pub references: Vec<ViewReferenceInfo>,
}

/// Reference information for a code unit in a data view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewReferenceInfo {
    /// The type of reference.
    pub ref_type: ViewReferenceType,
    /// The source address offset.
    pub from_offset: u64,
    /// The source address space name.
    pub from_space: String,
    /// The label or symbol at the source.
    pub label: Option<String>,
}

/// Types of cross-references in trace listing views.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ViewReferenceType {
    /// A read (data) reference.
    Read,
    /// A write (data) reference.
    Write,
    /// A flow (control) reference.
    Flow,
    /// A call reference.
    Call,
    /// An indirect reference.
    Indirect,
}

/// A view over code units in a trace that includes both defined and
/// undefined data.
///
/// Ported from Ghidra's `DBTraceModelCodeUnitsView` and related view types.
#[derive(Debug, Clone)]
pub struct ModelCodeUnitsView {
    /// The view configuration.
    pub config: ViewDataConfig,
    /// The cached entries in the view.
    entries: Vec<ViewDataEntry>,
}

impl ModelCodeUnitsView {
    /// Create a new code units view.
    pub fn new(config: ViewDataConfig) -> Self {
        Self {
            config,
            entries: Vec::new(),
        }
    }

    /// Add an entry to the view (used during construction/refresh).
    pub fn push_entry(&mut self, entry: ViewDataEntry) {
        self.entries.push(entry);
    }

    /// Get the number of entries in the view.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the view is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over entries.
    pub fn entries(&self) -> &[ViewDataEntry] {
        &self.entries
    }

    /// Find the entry at a specific address offset.
    pub fn entry_at(&self, offset: u64) -> Option<&ViewDataEntry> {
        self.entries.iter().find(|e| e.offset == offset)
    }

    /// Get entries within a range.
    pub fn entries_in_range(&self, min: u64, max: u64) -> Vec<&ViewDataEntry> {
        self.entries
            .iter()
            .filter(|e| e.offset >= min && e.offset <= max)
            .collect()
    }

    /// Get only instruction entries.
    pub fn instructions(&self) -> Vec<&ViewDataEntry> {
        self.entries
            .iter()
            .filter(|e| e.unit_type == ViewCodeUnitType::Instruction)
            .collect()
    }

    /// Get only defined data entries.
    pub fn defined_data(&self) -> Vec<&ViewDataEntry> {
        self.entries
            .iter()
            .filter(|e| e.unit_type == ViewCodeUnitType::DefinedData)
            .collect()
    }

    /// Get only undefined data entries.
    pub fn undefined_data(&self) -> Vec<&ViewDataEntry> {
        self.entries
            .iter()
            .filter(|e| e.unit_type == ViewCodeUnitType::UndefinedData)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_view_config() {
        let config = ViewDataConfig::new("ram", 0)
            .with_range(0x1000, 0x2000)
            .with_undefined(true);
        assert_eq!(config.space_name, "ram");
        assert_eq!(config.snap, 0);
        assert_eq!(config.min_offset, 0x1000);
        assert!(config.include_undefined);
    }

    #[test]
    fn test_code_units_view() {
        let config = ViewDataConfig::new("ram", 0);
        let mut view = ModelCodeUnitsView::new(config);

        view.push_entry(ViewDataEntry {
            offset: 0x1000,
            unit_type: ViewCodeUnitType::Instruction,
            size: 4,
            data_type: None,
            bytes: vec![0x55, 0x48, 0x89, 0xe5],
            display: "PUSH RBP".into(),
            references: vec![],
        });

        view.push_entry(ViewDataEntry {
            offset: 0x1004,
            unit_type: ViewCodeUnitType::DefinedData,
            size: 4,
            data_type: Some("dword".into()),
            bytes: vec![0x01, 0x00, 0x00, 0x00],
            display: "0x00000001".into(),
            references: vec![],
        });

        assert_eq!(view.len(), 2);
        assert!(view.entry_at(0x1000).is_some());
        assert!(view.entry_at(0x3000).is_none());
        assert_eq!(view.instructions().len(), 1);
        assert_eq!(view.defined_data().len(), 1);
    }

    #[test]
    fn test_code_unit_view_type_variants() {
        assert_ne!(ViewCodeUnitType::Instruction, ViewCodeUnitType::DefinedData);
        assert_ne!(ViewCodeUnitType::UndefinedData, ViewCodeUnitType::Comment);
    }

    #[test]
    fn test_reference_type_variants() {
        assert_ne!(ViewReferenceType::Read, ViewReferenceType::Write);
        assert_ne!(ViewReferenceType::Flow, ViewReferenceType::Call);
    }

    #[test]
    fn test_entries_in_range() {
        let config = ViewDataConfig::new("ram", 0);
        let mut view = ModelCodeUnitsView::new(config);

        for i in 0..10 {
            view.push_entry(ViewDataEntry {
                offset: 0x1000 + i * 4,
                unit_type: ViewCodeUnitType::Instruction,
                size: 4,
                data_type: None,
                bytes: vec![0x90; 4],
                display: "NOP".into(),
                references: vec![],
            });
        }

        // Entry offsets: 0x1000, 0x1004, 0x1008, 0x100c, 0x1010, 0x1014, 0x1018, 0x101c, 0x1020, 0x1024
        let in_range = view.entries_in_range(0x1008, 0x1010);
        assert_eq!(in_range.len(), 3); // 0x1008, 0x100c, 0x1010
    }
}
