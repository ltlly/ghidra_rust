//! GUI types for taint-aware register display.
//!
//! Ported from Ghidra's `ghidra.taint.gui.field` package.

use serde::{Deserialize, Serialize};

use super::model::TaintVec;

/// A column identifier for the taint register table.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaintColumn {
    /// Register name column.
    RegisterName,
    /// Register value column.
    Value,
    /// Taint status column.
    TaintStatus,
    /// Taint marks column.
    TaintMarks,
}

/// Location information for a taint field in the register view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintFieldLocation {
    /// The row index.
    pub row: usize,
    /// The column.
    pub column: TaintColumn,
    /// The register name.
    pub register_name: String,
    /// The address space name.
    pub space_name: String,
    /// The register offset.
    pub offset: u64,
}

impl TaintFieldLocation {
    /// Create a new field location.
    pub fn new(
        row: usize,
        column: TaintColumn,
        register_name: impl Into<String>,
        space_name: impl Into<String>,
        offset: u64,
    ) -> Self {
        Self {
            row,
            column,
            register_name: register_name.into(),
            space_name: space_name.into(),
            offset,
        }
    }
}

/// Factory for creating taint-aware register columns.
///
/// Ported from Ghidra's `TaintDebuggerRegisterColumnFactory`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaintFieldFactory {
    /// Columns provided by this factory.
    columns: Vec<TaintColumn>,
}

impl TaintFieldFactory {
    /// Create a factory with default taint columns.
    pub fn new() -> Self {
        Self {
            columns: vec![
                TaintColumn::RegisterName,
                TaintColumn::Value,
                TaintColumn::TaintStatus,
                TaintColumn::TaintMarks,
            ],
        }
    }

    /// Get the column definitions.
    pub fn columns(&self) -> &[TaintColumn] {
        &self.columns
    }

    /// Format the taint vector for display in the TaintMarks column.
    pub fn format_taint_marks(vec: &TaintVec) -> String {
        if vec.is_clean() {
            "clean".to_string()
        } else {
            vec.to_string()
        }
    }

    /// Format the taint status for display.
    pub fn format_taint_status(vec: &TaintVec) -> &'static str {
        if vec.is_clean() {
            "CLEAN"
        } else {
            "TAINTED"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taint_analysis::model::{TaintMark, TaintSet};

    #[test]
    fn test_field_location() {
        let loc = TaintFieldLocation::new(0, TaintColumn::TaintMarks, "RAX", "register", 0);
        assert_eq!(loc.row, 0);
        assert_eq!(loc.column, TaintColumn::TaintMarks);
    }

    #[test]
    fn test_field_factory_columns() {
        let factory = TaintFieldFactory::new();
        assert_eq!(factory.columns().len(), 4);
    }

    #[test]
    fn test_format_taint_marks_clean() {
        let v = TaintVec::new(4);
        assert_eq!(TaintFieldFactory::format_taint_marks(&v), "clean");
    }

    #[test]
    fn test_format_taint_marks_tainted() {
        let mut v = TaintVec::new(2);
        v.set(0, TaintSet::of([TaintMark::new("input")]));
        let s = TaintFieldFactory::format_taint_marks(&v);
        assert!(s.contains("input"));
    }

    #[test]
    fn test_format_taint_status() {
        let clean = TaintVec::new(4);
        assert_eq!(TaintFieldFactory::format_taint_status(&clean), "CLEAN");

        let mut tainted = TaintVec::new(4);
        tainted.set(0, TaintSet::of([TaintMark::new("x")]));
        assert_eq!(TaintFieldFactory::format_taint_status(&tainted), "TAINTED");
    }
}
