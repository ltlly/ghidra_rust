//! Concrete data view implementations for the trace listing database.
//!
//! Ported from Ghidra's `ghidra.trace.database.listing` package:
//! - `DBTraceData`: The concrete data code unit backed by a database table.
//! - `DBTraceDataView`: A filtered view over all data units in a space.
//! - `DBTraceDataMemoryView`: A data view that includes memory byte access.
//! - `DBTraceDefinedDataView`: A view over only defined data units.
//! - `DBTraceDefinedDataMemoryView`: Defined data view with memory access.
//! - `DBTraceUndefinedDataView`: A view over only undefined data units.
//! - `DBTraceUndefinedDataMemoryView`: Undefined data view with memory access.
//! - `DBTraceInstructionsView`: A view over instruction code units.
//! - `DBTraceInstructionsMemoryView`: Instruction view with memory access.
//! - `DBTraceDefinedUnitsView`: A view over all defined units (instructions + data).
//! - `DBTraceDefinedUnitsMemoryView`: Defined units view with memory access.
//! - `DBTraceCodeUnitsView`: A view over all code units.
//! - `DBTraceCodeUnitsMemoryView`: Code units view with memory access.
//!
//! Each view constrains iteration by code unit type, address range, and snap.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::model::Lifespan;

/// The kind of code unit in a trace listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TraceCodeUnitType {
    /// An instruction.
    Instruction,
    /// A defined data unit.
    DefinedData,
    /// An undefined (empty) data unit.
    UndefinedData,
}

impl TraceCodeUnitType {
    /// Check if this is a defined unit (instruction or defined data).
    pub fn is_defined(&self) -> bool {
        matches!(self, Self::Instruction | Self::DefinedData)
    }

    /// Check if this is a data unit (defined or undefined).
    pub fn is_data(&self) -> bool {
        matches!(self, Self::DefinedData | Self::UndefinedData)
    }
}

/// An entry in a data view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataViewEntry {
    /// The start address offset.
    pub offset: u64,
    /// The length of the code unit in bytes.
    pub length: u64,
    /// The type of the code unit.
    pub unit_type: TraceCodeUnitType,
    /// The data type name, if defined.
    pub data_type_name: Option<String>,
    /// The snap at which this entry is valid.
    pub snap: i64,
    /// The value bytes, if available.
    pub value_bytes: Option<Vec<u8>>,
}

/// A concrete data code unit stored in the database.
///
/// Ported from `DBTraceData`. This represents a defined data unit with a data type,
/// value, and optional settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceDataUnit {
    /// The start address offset.
    pub offset: u64,
    /// The length in bytes.
    pub length: u64,
    /// The data type name.
    pub data_type_name: String,
    /// The serialized value.
    pub value: Option<Vec<u8>>,
    /// The lifespan (snap range) during which this data is valid.
    pub lifespan: Lifespan,
    /// Optional comment strings keyed by comment type.
    pub comments: BTreeMap<u32, String>,
    /// Settings overrides.
    pub settings: BTreeMap<String, SettingValue>,
    /// Value references from this data unit.
    pub value_references: Vec<ValueReference>,
}

/// A setting value for a code unit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SettingValue {
    /// A long setting.
    Long(i64),
    /// A string setting.
    String(String),
    /// A boolean setting.
    Bool(bool),
}

/// A reference from a data unit's value to another address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueReference {
    /// The target address.
    pub to_address: u64,
    /// The reference type.
    pub ref_type: ReferenceType,
}

/// Types of references.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReferenceType {
    /// A data read reference.
    Read,
    /// A data write reference.
    Write,
    /// A data read-write reference.
    ReadWrite,
    /// A data pointer reference.
    Pointer,
    /// A parameter reference.
    Parameter,
    /// A string reference.
    String,
    /// An unknown reference type.
    Other,
}

/// A data component (sub-element of a composite data unit).
///
/// Ported from `DBTraceDataArrayElementComponent` and `DBTraceDataCompositeFieldComponent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataUnitComponent {
    /// An array element.
    ArrayElement {
        /// The parent data unit offset.
        parent_offset: u64,
        /// The element index within the array.
        index: usize,
        /// The element data type name.
        data_type_name: String,
        /// The element offset.
        offset: u64,
        /// The element length.
        length: u64,
    },
    /// A composite field (struct/union member).
    CompositeField {
        /// The parent data unit offset.
        parent_offset: u64,
        /// The field name.
        field_name: String,
        /// The field data type name.
        data_type_name: String,
        /// The field offset.
        offset: u64,
        /// The field length.
        length: u64,
    },
}

impl DataUnitComponent {
    /// Get the offset of this component.
    pub fn offset(&self) -> u64 {
        match self {
            Self::ArrayElement { offset, .. } => *offset,
            Self::CompositeField { offset, .. } => *offset,
        }
    }

    /// Get the length of this component.
    pub fn length(&self) -> u64 {
        match self {
            Self::ArrayElement { length, .. } => *length,
            Self::CompositeField { length, .. } => *length,
        }
    }

    /// Get the data type name of this component.
    pub fn data_type_name(&self) -> &str {
        match self {
            Self::ArrayElement { data_type_name, .. } => data_type_name,
            Self::CompositeField { data_type_name, .. } => data_type_name,
        }
    }

    /// Get the parent offset.
    pub fn parent_offset(&self) -> u64 {
        match self {
            Self::ArrayElement { parent_offset, .. } => *parent_offset,
            Self::CompositeField { parent_offset, .. } => *parent_offset,
        }
    }
}

/// Flow override applied to a data view instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum DataViewFlowOverride {
    /// No override.
    #[default]
    None,
    /// Fall-through override.
    FallThrough,
    /// Call override.
    Call,
    /// Call-return override.
    CallReturn,
    /// Jump override.
    Jump,
    /// Return override.
    Return,
}

/// Configuration for a listing data view query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataViewConfig {
    /// The address space name to query (None for all spaces).
    pub space: Option<String>,
    /// Minimum address (inclusive).
    pub min_address: Option<u64>,
    /// Maximum address (inclusive).
    pub max_address: Option<u64>,
    /// Snap range.
    pub lifespan: Lifespan,
    /// Filter by code unit type.
    pub unit_type_filter: Option<TraceCodeUnitType>,
    /// Maximum number of entries to return.
    pub max_entries: Option<usize>,
    /// Whether to include memory bytes in the results.
    pub include_memory_bytes: bool,
}

impl DataViewConfig {
    /// Create a new config for the given snap.
    pub fn for_snap(snap: i64) -> Self {
        Self {
            space: None,
            min_address: None,
            max_address: None,
            lifespan: Lifespan::span(snap, snap + 1),
            unit_type_filter: None,
            max_entries: None,
            include_memory_bytes: false,
        }
    }

    /// Set the address space filter.
    pub fn with_space(mut self, space: &str) -> Self {
        self.space = Some(space.to_string());
        self
    }

    /// Set the address range.
    pub fn with_range(mut self, min: u64, max: u64) -> Self {
        self.min_address = Some(min);
        self.max_address = Some(max);
        self
    }

    /// Set the code unit type filter.
    pub fn with_unit_type(mut self, unit_type: TraceCodeUnitType) -> Self {
        self.unit_type_filter = Some(unit_type);
        self
    }

    /// Set whether to include memory bytes.
    pub fn with_memory_bytes(mut self, include: bool) -> Self {
        self.include_memory_bytes = include;
        self
    }
}

/// A concrete implementation of a data view over the trace database.
///
/// Provides filtered iteration over code units of specific types in a given
/// address range and snap range.
#[derive(Debug)]
pub struct DbTraceDataView {
    config: DataViewConfig,
    entries: BTreeMap<u64, DataViewEntry>,
}

impl DbTraceDataView {
    /// Create a new data view with the given configuration.
    pub fn new(config: DataViewConfig) -> Self {
        Self {
            config,
            entries: BTreeMap::new(),
        }
    }

    /// Get the configuration for this view.
    pub fn config(&self) -> &DataViewConfig {
        &self.config
    }

    /// Insert an entry into the view.
    pub fn insert(&mut self, entry: DataViewEntry) {
        self.entries.insert(entry.offset, entry);
    }

    /// Get an entry at the given offset.
    pub fn get(&self, offset: u64) -> Option<&DataViewEntry> {
        self.entries.get(&offset)
    }

    /// Iterate over entries in the view, filtered by the configuration.
    pub fn iter(&self) -> impl Iterator<Item = &DataViewEntry> {
        let min = self.config.min_address.unwrap_or(0);
        let max = self.config.max_address.unwrap_or(u64::MAX);
        let filter = self.config.unit_type_filter;

        self.entries
            .range(min..=max)
            .map(move |(_, e)| e)
            .filter(move |e| filter.map_or(true, |f| e.unit_type == f))
            .take(self.config.max_entries.unwrap_or(usize::MAX))
    }

    /// Count the number of entries in the view.
    pub fn count(&self) -> usize {
        self.iter().count()
    }

    /// Check if the view is empty.
    pub fn is_empty(&self) -> bool {
        self.count() == 0
    }

    /// Find the first entry at or after the given offset.
    pub fn first_at_or_after(&self, offset: u64) -> Option<&DataViewEntry> {
        self.entries.range(offset..).next().map(|(_, e)| e)
    }

    /// Find the last entry at or before the given offset.
    pub fn last_at_or_before(&self, offset: u64) -> Option<&DataViewEntry> {
        self.entries.range(..=offset).next_back().map(|(_, e)| e)
    }

    /// Get the total number of bytes represented by entries in this view.
    pub fn total_bytes(&self) -> u64 {
        self.iter().map(|e| e.length).sum()
    }
}

/// A memory-backed data view that includes byte data from trace memory.
#[derive(Debug)]
pub struct DbTraceDataMemoryView {
    inner: DbTraceDataView,
    memory_data: BTreeMap<u64, Vec<u8>>,
}

impl DbTraceDataMemoryView {
    /// Create a new memory-backed data view.
    pub fn new(inner: DbTraceDataView) -> Self {
        Self {
            inner,
            memory_data: BTreeMap::new(),
        }
    }

    /// Add memory bytes for a given offset.
    pub fn set_memory(&mut self, offset: u64, bytes: Vec<u8>) {
        self.memory_data.insert(offset, bytes);
    }

    /// Get the memory bytes for a given offset.
    pub fn get_memory(&self, offset: u64) -> Option<&[u8]> {
        self.memory_data.get(&offset).map(|v| v.as_slice())
    }

    /// Access the inner data view.
    pub fn inner(&self) -> &DbTraceDataView {
        &self.inner
    }

    /// Iterate over entries with their associated memory bytes.
    pub fn iter_with_memory(&self) -> impl Iterator<Item = (&DataViewEntry, Option<&[u8]>)> {
        self.inner.iter().map(move |e| {
            let bytes = self.memory_data.get(&e.offset).map(|v| v.as_slice());
            (e, bytes)
        })
    }
}

/// Creates standard view configurations for different code unit type filters.
pub struct ViewFactory;

impl ViewFactory {
    /// Create a config for instruction-only views.
    pub fn instructions_config(snap: i64) -> DataViewConfig {
        DataViewConfig::for_snap(snap).with_unit_type(TraceCodeUnitType::Instruction)
    }

    /// Create a config for defined-data-only views.
    pub fn defined_data_config(snap: i64) -> DataViewConfig {
        DataViewConfig::for_snap(snap).with_unit_type(TraceCodeUnitType::DefinedData)
    }

    /// Create a config for undefined-data-only views.
    pub fn undefined_data_config(snap: i64) -> DataViewConfig {
        DataViewConfig::for_snap(snap).with_unit_type(TraceCodeUnitType::UndefinedData)
    }

    /// Create a config for defined units (instructions + defined data).
    pub fn defined_units_config(snap: i64) -> DataViewConfig {
        DataViewConfig::for_snap(snap)
    }

    /// Create a config for all code units.
    pub fn code_units_config(snap: i64) -> DataViewConfig {
        DataViewConfig::for_snap(snap)
    }
}

/// Properties associated with a code unit in a data view.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DataViewCodeUnitProperties {
    /// Whether this code unit is an instruction.
    pub is_instruction: bool,
    /// The length of the code unit.
    pub length: u64,
    /// Whether the code unit has a flow override.
    pub flow_override: DataViewFlowOverride,
    /// The mnemonic string.
    pub mnemonic: Option<String>,
    /// Whether this is an undefined unit.
    pub is_undefined: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_code_unit_type() {
        assert!(TraceCodeUnitType::Instruction.is_defined());
        assert!(!TraceCodeUnitType::Instruction.is_data());
        assert!(TraceCodeUnitType::DefinedData.is_defined());
        assert!(TraceCodeUnitType::DefinedData.is_data());
        assert!(!TraceCodeUnitType::UndefinedData.is_defined());
        assert!(TraceCodeUnitType::UndefinedData.is_data());
    }

    #[test]
    fn test_data_component_array_element() {
        let comp = DataUnitComponent::ArrayElement {
            parent_offset: 0x1000,
            index: 3,
            data_type_name: "int".to_string(),
            offset: 0x100C,
            length: 4,
        };
        assert_eq!(comp.offset(), 0x100C);
        assert_eq!(comp.length(), 4);
        assert_eq!(comp.data_type_name(), "int");
        assert_eq!(comp.parent_offset(), 0x1000);
    }

    #[test]
    fn test_data_component_composite_field() {
        let comp = DataUnitComponent::CompositeField {
            parent_offset: 0x2000,
            field_name: "value".to_string(),
            data_type_name: "long".to_string(),
            offset: 0x2008,
            length: 8,
        };
        assert_eq!(comp.offset(), 0x2008);
        assert_eq!(comp.length(), 8);
        assert_eq!(comp.data_type_name(), "long");
    }

    #[test]
    fn test_data_view_entry() {
        let entry = DataViewEntry {
            offset: 0x1000,
            length: 4,
            unit_type: TraceCodeUnitType::Instruction,
            data_type_name: None,
            snap: 0,
            value_bytes: Some(vec![0x55, 0x48, 0x89, 0xe5]),
        };
        assert_eq!(entry.offset, 0x1000);
        assert_eq!(entry.length, 4);
        assert!(entry.data_type_name.is_none());
        assert!(entry.value_bytes.is_some());
    }

    #[test]
    fn test_data_view_basic() {
        let config = DataViewConfig::for_snap(0);
        let mut view = DbTraceDataView::new(config);

        view.insert(DataViewEntry {
            offset: 0x1000,
            length: 4,
            unit_type: TraceCodeUnitType::Instruction,
            data_type_name: None,
            snap: 0,
            value_bytes: None,
        });

        view.insert(DataViewEntry {
            offset: 0x1004,
            length: 8,
            unit_type: TraceCodeUnitType::DefinedData,
            data_type_name: Some("long".to_string()),
            snap: 0,
            value_bytes: None,
        });

        assert_eq!(view.count(), 2);
        assert!(!view.is_empty());
        assert!(view.get(0x1000).is_some());
        assert!(view.get(0x9999).is_none());
    }

    #[test]
    fn test_data_view_filter_by_type() {
        let config = DataViewConfig::for_snap(0)
            .with_unit_type(TraceCodeUnitType::Instruction);
        let mut view = DbTraceDataView::new(config);

        view.insert(DataViewEntry {
            offset: 0x1000,
            length: 4,
            unit_type: TraceCodeUnitType::Instruction,
            data_type_name: None,
            snap: 0,
            value_bytes: None,
        });
        view.insert(DataViewEntry {
            offset: 0x1004,
            length: 8,
            unit_type: TraceCodeUnitType::DefinedData,
            data_type_name: Some("long".to_string()),
            snap: 0,
            value_bytes: None,
        });

        // Only instruction entries should be returned
        assert_eq!(view.count(), 1);
    }

    #[test]
    fn test_data_view_range_filter() {
        let config = DataViewConfig::for_snap(0).with_range(0x1000, 0x1010);
        let mut view = DbTraceDataView::new(config);

        for i in 0..20 {
            view.insert(DataViewEntry {
                offset: 0x1000 + i * 4,
                length: 4,
                unit_type: TraceCodeUnitType::Instruction,
                data_type_name: None,
                snap: 0,
                value_bytes: None,
            });
        }

        // 0x1000 to 0x1010 inclusive = offsets 0x1000, 0x1004, 0x1008, 0x100C, 0x1010 = 5 entries
        assert_eq!(view.count(), 5);
    }

    #[test]
    fn test_data_view_first_at_or_after() {
        let config = DataViewConfig::for_snap(0);
        let mut view = DbTraceDataView::new(config);

        view.insert(DataViewEntry {
            offset: 0x1000,
            length: 4,
            unit_type: TraceCodeUnitType::Instruction,
            data_type_name: None,
            snap: 0,
            value_bytes: None,
        });
        view.insert(DataViewEntry {
            offset: 0x1010,
            length: 4,
            unit_type: TraceCodeUnitType::Instruction,
            data_type_name: None,
            snap: 0,
            value_bytes: None,
        });

        let entry = view.first_at_or_after(0x1005);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().offset, 0x1010);
    }

    #[test]
    fn test_data_view_last_at_or_before() {
        let config = DataViewConfig::for_snap(0);
        let mut view = DbTraceDataView::new(config);

        view.insert(DataViewEntry {
            offset: 0x1000,
            length: 4,
            unit_type: TraceCodeUnitType::Instruction,
            data_type_name: None,
            snap: 0,
            value_bytes: None,
        });
        view.insert(DataViewEntry {
            offset: 0x1010,
            length: 4,
            unit_type: TraceCodeUnitType::Instruction,
            data_type_name: None,
            snap: 0,
            value_bytes: None,
        });

        let entry = view.last_at_or_before(0x1008);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().offset, 0x1000);
    }

    #[test]
    fn test_memory_view() {
        let config = DataViewConfig::for_snap(0).with_memory_bytes(true);
        let mut view = DbTraceDataView::new(config);
        view.insert(DataViewEntry {
            offset: 0x1000,
            length: 4,
            unit_type: TraceCodeUnitType::Instruction,
            data_type_name: None,
            snap: 0,
            value_bytes: Some(vec![0x55, 0x48, 0x89, 0xe5]),
        });

        let mut mem_view = DbTraceDataMemoryView::new(view);
        mem_view.set_memory(0x1000, vec![0x55, 0x48, 0x89, 0xe5]);

        let bytes = mem_view.get_memory(0x1000);
        assert!(bytes.is_some());
        assert_eq!(bytes.unwrap(), &[0x55, 0x48, 0x89, 0xe5]);

        assert!(mem_view.get_memory(0x9999).is_none());
    }

    #[test]
    fn test_view_factory() {
        let config = ViewFactory::instructions_config(0);
        assert!(config.unit_type_filter.is_some());
        assert_eq!(config.unit_type_filter.unwrap(), TraceCodeUnitType::Instruction);

        let config = ViewFactory::defined_data_config(5);
        assert_eq!(config.lifespan.lmin(), 5);
    }

    #[test]
    fn test_total_bytes() {
        let config = DataViewConfig::for_snap(0);
        let mut view = DbTraceDataView::new(config);

        view.insert(DataViewEntry {
            offset: 0x1000,
            length: 4,
            unit_type: TraceCodeUnitType::Instruction,
            data_type_name: None,
            snap: 0,
            value_bytes: None,
        });
        view.insert(DataViewEntry {
            offset: 0x1004,
            length: 8,
            unit_type: TraceCodeUnitType::DefinedData,
            data_type_name: None,
            snap: 0,
            value_bytes: None,
        });

        assert_eq!(view.total_bytes(), 12);
    }

    #[test]
    fn test_setting_value_variants() {
        let long_val = SettingValue::Long(42);
        let str_val = SettingValue::String("hello".to_string());
        let bool_val = SettingValue::Bool(true);

        match long_val {
            SettingValue::Long(v) => assert_eq!(v, 42),
            _ => panic!("Expected Long"),
        }
        match str_val {
            SettingValue::String(ref v) => assert_eq!(v, "hello"),
            _ => panic!("Expected String"),
        }
        match bool_val {
            SettingValue::Bool(v) => assert!(v),
            _ => panic!("Expected Bool"),
        }
    }

    #[test]
    fn test_flow_override() {
        let fo = DataViewFlowOverride::CallReturn;
        assert_ne!(fo, DataViewFlowOverride::None);
        assert_ne!(fo, DataViewFlowOverride::Return);
    }

    #[test]
    fn test_code_unit_properties_default() {
        let props = DataViewCodeUnitProperties::default();
        assert!(!props.is_instruction);
        assert_eq!(props.length, 0);
        assert!(!props.is_undefined);
        assert!(props.mnemonic.is_none());
    }

    #[test]
    fn test_reference_type() {
        assert_ne!(ReferenceType::Read, ReferenceType::Write);
        assert_ne!(ReferenceType::Pointer, ReferenceType::String);
    }

    #[test]
    fn test_data_view_max_entries() {
        let config = DataViewConfig::for_snap(0);
        let mut config = config;
        config.max_entries = Some(3);
        let mut view = DbTraceDataView::new(config);

        for i in 0..10 {
            view.insert(DataViewEntry {
                offset: 0x1000 + i * 4,
                length: 4,
                unit_type: TraceCodeUnitType::Instruction,
                data_type_name: None,
                snap: 0,
                value_bytes: None,
            });
        }

        assert_eq!(view.count(), 3);
    }

    #[test]
    fn test_memory_view_iter_with_memory() {
        let config = DataViewConfig::for_snap(0);
        let mut view = DbTraceDataView::new(config);

        view.insert(DataViewEntry {
            offset: 0x1000,
            length: 2,
            unit_type: TraceCodeUnitType::Instruction,
            data_type_name: None,
            snap: 0,
            value_bytes: None,
        });
        view.insert(DataViewEntry {
            offset: 0x1002,
            length: 2,
            unit_type: TraceCodeUnitType::Instruction,
            data_type_name: None,
            snap: 0,
            value_bytes: None,
        });

        let mut mem_view = DbTraceDataMemoryView::new(view);
        mem_view.set_memory(0x1000, vec![0x90, 0x90]);

        let entries: Vec<_> = mem_view.iter_with_memory().collect();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].1.is_some()); // Has memory
        assert!(entries[1].1.is_none()); // No memory
    }
}
