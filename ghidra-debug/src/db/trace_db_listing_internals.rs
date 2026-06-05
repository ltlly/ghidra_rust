//! Internal listing view abstractions.
//!
//! Ported from Ghidra's `ghidra.trace.database.listing` package internal interfaces:
//! - `InternalTraceBaseDefinedUnitsView`: Combines base defined units view with internal ops.
//! - `InternalTraceDefinedDataView`: Data-specific internal view.
//! - `AbstractBaseDBTraceDefinedUnitsView`: Abstract base for defined units views.
//! - `AbstractDBTraceDataComponent`: Abstract data component base.
//! - `AbstractSingleDBTraceCodeUnitsView`: Single-address code units view base.
//! - `AbstractWithUndefinedDBTraceCodeUnitsMemoryView`: Memory view with undefined data.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A code unit type in the trace listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InternalCodeUnitKind {
    /// An instruction.
    Instruction,
    /// Defined data.
    Data,
    /// Undefined data.
    UndefinedData,
}

/// A clear operation on the listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListingClearOp {
    /// The lifespan to clear.
    pub lifespan: Lifespan,
    /// The start address.
    pub start: u64,
    /// The end address.
    pub end: u64,
    /// Whether to clear register context too.
    pub clear_context: bool,
}

impl ListingClearOp {
    /// Create a new listing clear operation.
    pub fn new(lifespan: Lifespan, start: u64, end: u64) -> Self {
        Self {
            lifespan,
            start,
            end,
            clear_context: true,
        }
    }
}

/// Internal interface for base defined units view.
///
/// Ported from Ghidra's `InternalTraceBaseDefinedUnitsView<T>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalTraceBaseDefinedUnitsView {
    /// The space name.
    pub space: String,
    /// The snap.
    pub snap: i64,
}

impl InternalTraceBaseDefinedUnitsView {
    /// Create a new internal base defined units view.
    pub fn new(space: impl Into<String>, snap: i64) -> Self {
        Self {
            space: space.into(),
            snap,
        }
    }

    /// Clear register context in the given span.
    pub fn clear_register(&self, lifespan: &Lifespan, register_name: &str) -> ListingClearOp {
        let _ = register_name;
        ListingClearOp::new(lifespan.clone(), 0, u64::MAX)
    }
}

/// Internal interface for defined data view.
///
/// Ported from Ghidra's `InternalTraceDefinedDataView`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalTraceDefinedDataView {
    /// The base view.
    pub base: InternalTraceBaseDefinedUnitsView,
    /// The data type name.
    pub data_type_name: String,
}

impl InternalTraceDefinedDataView {
    /// Create a new internal defined data view.
    pub fn new(space: impl Into<String>, snap: i64, data_type_name: impl Into<String>) -> Self {
        Self {
            base: InternalTraceBaseDefinedUnitsView::new(space, snap),
            data_type_name: data_type_name.into(),
        }
    }
}

/// Abstract base for DB trace defined units views.
///
/// Ported from Ghidra's `AbstractBaseDBTraceDefinedUnitsView`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbstractBaseDBTraceDefinedUnitsView {
    /// The space name.
    pub space: String,
    /// The snap.
    pub snap: i64,
    /// The kind of code unit.
    pub kind: InternalCodeUnitKind,
}

impl AbstractBaseDBTraceDefinedUnitsView {
    /// Create a new abstract defined units view.
    pub fn new(space: impl Into<String>, snap: i64, kind: InternalCodeUnitKind) -> Self {
        Self {
            space: space.into(),
            snap,
            kind,
        }
    }
}

/// Abstract data component in a trace.
///
/// Ported from Ghidra's `AbstractDBTraceDataComponent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbstractDBTraceDataComponent {
    /// The parent data address.
    pub parent_address: u64,
    /// The component offset within the parent.
    pub component_offset: usize,
    /// The field name.
    pub field_name: String,
    /// The data type name.
    pub data_type_name: String,
}

impl AbstractDBTraceDataComponent {
    /// Create a new data component.
    pub fn new(
        parent_address: u64,
        component_offset: usize,
        field_name: impl Into<String>,
        data_type_name: impl Into<String>,
    ) -> Self {
        Self {
            parent_address,
            component_offset,
            field_name: field_name.into(),
            data_type_name: data_type_name.into(),
        }
    }
}

/// Abstract single-address code units view.
///
/// Ported from Ghidra's `AbstractSingleDBTraceCodeUnitsView`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbstractSingleDBTraceCodeUnitsView {
    /// The target address.
    pub address: u64,
    /// The snap.
    pub snap: i64,
    /// The space name.
    pub space: String,
}

impl AbstractSingleDBTraceCodeUnitsView {
    /// Create a new single-address view.
    pub fn new(address: u64, snap: i64, space: impl Into<String>) -> Self {
        Self {
            address,
            snap,
            space: space.into(),
        }
    }
}

/// Abstract memory view that includes undefined data.
///
/// Ported from Ghidra's `AbstractWithUndefinedDBTraceCodeUnitsMemoryView`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbstractWithUndefinedDBTraceCodeUnitsMemoryView {
    /// The space name.
    pub space: String,
    /// The snap.
    pub snap: i64,
    /// Whether to include undefined data.
    pub include_undefined: bool,
}

impl AbstractWithUndefinedDBTraceCodeUnitsMemoryView {
    /// Create a new memory view with undefined data.
    pub fn new(space: impl Into<String>, snap: i64) -> Self {
        Self {
            space: space.into(),
            snap,
            include_undefined: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_internal_base_defined_units_view() {
        let view = InternalTraceBaseDefinedUnitsView::new("ram", 10);
        assert_eq!(view.space, "ram");
        assert_eq!(view.snap, 10);

        let lifespan = Lifespan::span(5, 15);
        let op = view.clear_register(&lifespan, "R0");
        assert_eq!(op.start, 0);
        assert!(op.clear_context);
    }

    #[test]
    fn test_internal_defined_data_view() {
        let view = InternalTraceDefinedDataView::new("ram", 5, "uint32_t");
        assert_eq!(view.data_type_name, "uint32_t");
        assert_eq!(view.base.space, "ram");
    }

    #[test]
    fn test_abstract_base_defined_units_view() {
        let view = AbstractBaseDBTraceDefinedUnitsView::new("ram", 5, InternalCodeUnitKind::Data);
        assert_eq!(view.kind, InternalCodeUnitKind::Data);
    }

    #[test]
    fn test_abstract_data_component() {
        let comp = AbstractDBTraceDataComponent::new(0x1000, 4, "field1", "int32_t");
        assert_eq!(comp.parent_address, 0x1000);
        assert_eq!(comp.component_offset, 4);
        assert_eq!(comp.field_name, "field1");
    }

    #[test]
    fn test_abstract_single_code_units_view() {
        let view = AbstractSingleDBTraceCodeUnitsView::new(0x2000, 10, "ram");
        assert_eq!(view.address, 0x2000);
    }

    #[test]
    fn test_abstract_with_undefined_memory_view() {
        let view = AbstractWithUndefinedDBTraceCodeUnitsMemoryView::new("ram", 5);
        assert!(view.include_undefined);
    }

    #[test]
    fn test_code_unit_kind_serde() {
        let kinds = [
            InternalCodeUnitKind::Instruction,
            InternalCodeUnitKind::Data,
            InternalCodeUnitKind::UndefinedData,
        ];
        for kind in &kinds {
            let json = serde_json::to_string(kind).unwrap();
            let back: InternalCodeUnitKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, *kind);
        }
    }

    #[test]
    fn test_listing_clear_op() {
        let op = ListingClearOp::new(Lifespan::span(0, 100), 0x1000, 0x2000);
        assert_eq!(op.start, 0x1000);
        assert_eq!(op.end, 0x2000);
        assert!(op.clear_context);
    }
}
