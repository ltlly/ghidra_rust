//! Varnode table model for the function storage editor.
//!
//! Ported from `VarnodeTableModel.java` in
//! `ghidra.app.plugin.core.function.editor`.
//!
//! Provides a table model that displays varnode storage information
//! (type, location, size) and allows editing through column-specific
//! cell editors.

use super::{StorageAddressModel, VarnodeInfo, VarnodeType};

// ---------------------------------------------------------------------------
// VarnodeColumn
// ---------------------------------------------------------------------------

/// Column definitions for the varnode table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VarnodeColumn {
    /// The storage type (Register, Stack, Memory).
    Type,
    /// The storage location (register name, address, stack offset).
    Location,
    /// The storage size in bytes.
    Size,
}

impl VarnodeColumn {
    /// All columns in display order.
    pub fn all() -> &'static [VarnodeColumn] {
        &[Self::Type, Self::Location, Self::Size]
    }

    /// Column header text.
    pub fn header(&self) -> &'static str {
        match self {
            Self::Type => "Type",
            Self::Location => "Location",
            Self::Size => "Size",
        }
    }

    /// Whether this column is editable.
    pub fn is_editable(&self) -> bool {
        match self {
            Self::Type => true,
            Self::Location => true,
            Self::Size => false,
        }
    }

    /// Preferred column width in pixels.
    pub fn preferred_width(&self) -> usize {
        match self {
            Self::Type => 80,
            Self::Location => 150,
            Self::Size => 60,
        }
    }
}

// ---------------------------------------------------------------------------
// VarnodeTableModel
// ---------------------------------------------------------------------------

/// Table model for displaying and editing varnodes in the function
/// storage editor.
///
/// Each row represents a single [`VarnodeInfo`], with columns for
/// the type, location, and size.
///
/// # Example
///
/// ```
/// use ghidra_features::base::function::editor::*;
/// use ghidra_features::base::function::editor::varnode_table::*;
///
/// let mut model = StorageAddressModel::new(8);
/// model.add_varnode(VarnodeInfo::register("RAX", 8));
///
/// let table = VarnodeTableModel::new(&model);
/// assert_eq!(table.row_count(), 1);
/// assert_eq!(table.column_count(), 3);
/// assert_eq!(table.column_header(VarnodeColumn::Type), "Type");
/// ```
#[derive(Debug, Clone)]
pub struct VarnodeTableModel {
    /// The varnode data.
    varnodes: Vec<VarnodeInfo>,
    /// Column definitions.
    columns: Vec<VarnodeColumn>,
}

impl VarnodeTableModel {
    /// Create a new table model from a storage address model.
    pub fn new(storage_model: &StorageAddressModel) -> Self {
        Self {
            varnodes: storage_model.varnodes().to_vec(),
            columns: VarnodeColumn::all().to_vec(),
        }
    }

    /// Create a table model from a list of varnodes.
    pub fn from_varnodes(varnodes: Vec<VarnodeInfo>) -> Self {
        Self {
            varnodes,
            columns: VarnodeColumn::all().to_vec(),
        }
    }

    /// Number of rows (varnodes).
    pub fn row_count(&self) -> usize {
        self.varnodes.len()
    }

    /// Number of columns.
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Get the header text for a column.
    pub fn column_header(&self, col: VarnodeColumn) -> &'static str {
        col.header()
    }

    /// Get the header text by column index.
    pub fn column_header_at(&self, index: usize) -> Option<&'static str> {
        self.columns.get(index).map(|c| c.header())
    }

    /// Get the value for a cell.
    pub fn cell_value(&self, row: usize, col: VarnodeColumn) -> Option<String> {
        self.varnodes.get(row).map(|vn| match col {
            VarnodeColumn::Type => vn.varnode_type().label().to_string(),
            VarnodeColumn::Location => vn.name().to_string(),
            VarnodeColumn::Size => vn.size().to_string(),
        })
    }

    /// Get the value for a cell by column index.
    pub fn cell_value_at(&self, row: usize, col: usize) -> Option<String> {
        self.columns.get(col).copied().and_then(|c| self.cell_value(row, c))
    }

    /// Whether a cell is editable.
    pub fn is_cell_editable(&self, row: usize, col: VarnodeColumn) -> bool {
        row < self.varnodes.len() && col.is_editable()
    }

    /// Whether a cell is editable by column index.
    pub fn is_cell_editable_at(&self, row: usize, col: usize) -> bool {
        self.columns
            .get(col)
            .map_or(false, |c| self.is_cell_editable(row, *c))
    }

    /// Set the value of a cell (only for editable columns).
    ///
    /// Returns `true` if the value was set.
    pub fn set_cell_value(&mut self, row: usize, col: VarnodeColumn, value: &str) -> bool {
        if !self.is_cell_editable(row, col) {
            return false;
        }
        let vn = match self.varnodes.get_mut(row) {
            Some(v) => v,
            None => return false,
        };
        match col {
            VarnodeColumn::Type => {
                if let Some(new_type) = parse_varnode_type(value) {
                    *vn = match new_type {
                        VarnodeType::Register => VarnodeInfo::register(vn.name(), vn.size()),
                        VarnodeType::Stack => VarnodeInfo::stack(0, vn.size()),
                        VarnodeType::Memory => VarnodeInfo::memory(0, vn.size()),
                    };
                    true
                } else {
                    false
                }
            }
            VarnodeColumn::Location => {
                // For location, the interpretation depends on the type
                match vn.varnode_type() {
                    VarnodeType::Register => {
                        *vn = VarnodeInfo::register(value, vn.size());
                        true
                    }
                    VarnodeType::Stack => {
                        if let Ok(offset) = value.parse::<i64>() {
                            *vn = VarnodeInfo::stack(offset, vn.size());
                            true
                        } else {
                            false
                        }
                    }
                    VarnodeType::Memory => {
                        let addr_str = value.trim_start_matches("0x").trim_start_matches("0X");
                        if let Ok(addr) = u64::from_str_radix(addr_str, 16) {
                            *vn = VarnodeInfo::memory(addr, vn.size());
                            true
                        } else {
                            false
                        }
                    }
                }
            }
            VarnodeColumn::Size => false, // Size is not directly editable
        }
    }

    /// Get the preferred width for a column.
    pub fn preferred_width(&self, col: VarnodeColumn) -> usize {
        col.preferred_width()
    }

    /// Get the preferred width by column index.
    pub fn preferred_width_at(&self, index: usize) -> usize {
        self.columns
            .get(index)
            .map_or(80, |c| c.preferred_width())
    }

    /// Get the varnode at a specific row.
    pub fn varnode(&self, row: usize) -> Option<&VarnodeInfo> {
        self.varnodes.get(row)
    }

    /// Get all varnodes.
    pub fn varnodes(&self) -> &[VarnodeInfo] {
        &self.varnodes
    }

    /// Refresh the table from a storage address model.
    pub fn refresh(&mut self, storage_model: &StorageAddressModel) {
        self.varnodes = storage_model.varnodes().to_vec();
    }
}

/// Parse a varnode type string.
fn parse_varnode_type(s: &str) -> Option<VarnodeType> {
    match s.to_lowercase().as_str() {
        "register" => Some(VarnodeType::Register),
        "stack" => Some(VarnodeType::Stack),
        "memory" => Some(VarnodeType::Memory),
        _ => None,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_varnodes() -> Vec<VarnodeInfo> {
        vec![
            VarnodeInfo::register("RAX", 8),
            VarnodeInfo::stack(-8, 4),
            VarnodeInfo::memory(0x100000, 8),
        ]
    }

    #[test]
    fn test_table_from_varnodes() {
        let table = VarnodeTableModel::from_varnodes(sample_varnodes());
        assert_eq!(table.row_count(), 3);
        assert_eq!(table.column_count(), 3);
    }

    #[test]
    fn test_table_from_model() {
        let mut model = StorageAddressModel::new(20);
        for vn in sample_varnodes() {
            model.add_varnode(vn);
        }
        let table = VarnodeTableModel::new(&model);
        assert_eq!(table.row_count(), 3);
    }

    #[test]
    fn test_column_headers() {
        let table = VarnodeTableModel::from_varnodes(vec![]);
        assert_eq!(table.column_header_at(0), Some("Type"));
        assert_eq!(table.column_header_at(1), Some("Location"));
        assert_eq!(table.column_header_at(2), Some("Size"));
        assert_eq!(table.column_header_at(3), None);
    }

    #[test]
    fn test_cell_values_register() {
        let table = VarnodeTableModel::from_varnodes(vec![VarnodeInfo::register("RAX", 8)]);
        assert_eq!(table.cell_value_at(0, 0), Some("Register".into()));
        assert_eq!(table.cell_value_at(0, 1), Some("RAX".into()));
        assert_eq!(table.cell_value_at(0, 2), Some("8".into()));
    }

    #[test]
    fn test_cell_values_stack() {
        let table = VarnodeTableModel::from_varnodes(vec![VarnodeInfo::stack(-8, 4)]);
        assert_eq!(table.cell_value_at(0, 0), Some("Stack".into()));
        assert_eq!(table.cell_value_at(0, 1), Some("Stack[-8]".into()));
        assert_eq!(table.cell_value_at(0, 2), Some("4".into()));
    }

    #[test]
    fn test_cell_values_memory() {
        let table = VarnodeTableModel::from_varnodes(vec![VarnodeInfo::memory(0x100000, 8)]);
        assert_eq!(table.cell_value_at(0, 0), Some("Memory".into()));
        assert_eq!(table.cell_value_at(0, 1), Some("0x100000".into()));
        assert_eq!(table.cell_value_at(0, 2), Some("8".into()));
    }

    #[test]
    fn test_editable_cells() {
        let table = VarnodeTableModel::from_varnodes(vec![VarnodeInfo::register("RAX", 8)]);
        assert!(table.is_cell_editable_at(0, 0)); // Type
        assert!(table.is_cell_editable_at(0, 1)); // Location
        assert!(!table.is_cell_editable_at(0, 2)); // Size
    }

    #[test]
    fn test_out_of_range() {
        let table = VarnodeTableModel::from_varnodes(vec![]);
        assert_eq!(table.cell_value_at(0, 0), None);
        assert!(!table.is_cell_editable_at(0, 0));
    }

    #[test]
    fn test_set_type() {
        let mut table =
            VarnodeTableModel::from_varnodes(vec![VarnodeInfo::register("RAX", 8)]);
        assert!(table.set_cell_value(0, VarnodeColumn::Type, "stack"));
        assert_eq!(table.cell_value_at(0, 0), Some("Stack".into()));
    }

    #[test]
    fn test_set_location_register() {
        let mut table =
            VarnodeTableModel::from_varnodes(vec![VarnodeInfo::register("RAX", 8)]);
        assert!(table.set_cell_value(0, VarnodeColumn::Location, "RBX"));
        assert_eq!(table.cell_value_at(0, 1), Some("RBX".into()));
    }

    #[test]
    fn test_set_location_stack() {
        let mut table = VarnodeTableModel::from_varnodes(vec![VarnodeInfo::stack(0, 4)]);
        assert!(table.set_cell_value(0, VarnodeColumn::Location, "-16"));
        assert_eq!(table.cell_value_at(0, 1), Some("Stack[-16]".into()));
    }

    #[test]
    fn test_set_location_memory() {
        let mut table =
            VarnodeTableModel::from_varnodes(vec![VarnodeInfo::memory(0, 8)]);
        assert!(table.set_cell_value(0, VarnodeColumn::Location, "0x200000"));
        assert_eq!(table.cell_value_at(0, 1), Some("0x200000".into()));
    }

    #[test]
    fn test_invalid_type_value() {
        let mut table =
            VarnodeTableModel::from_varnodes(vec![VarnodeInfo::register("RAX", 8)]);
        assert!(!table.set_cell_value(0, VarnodeColumn::Type, "invalid"));
    }

    #[test]
    fn test_invalid_stack_offset() {
        let mut table = VarnodeTableModel::from_varnodes(vec![VarnodeInfo::stack(0, 4)]);
        assert!(!table.set_cell_value(0, VarnodeColumn::Location, "not_a_number"));
    }

    #[test]
    fn test_preferred_widths() {
        let table = VarnodeTableModel::from_varnodes(vec![]);
        assert_eq!(table.preferred_width_at(0), 80);
        assert_eq!(table.preferred_width_at(1), 150);
        assert_eq!(table.preferred_width_at(2), 60);
    }

    #[test]
    fn test_refresh() {
        let mut table = VarnodeTableModel::from_varnodes(vec![]);
        let mut model = StorageAddressModel::new(8);
        model.add_varnode(VarnodeInfo::register("RAX", 8));
        table.refresh(&model);
        assert_eq!(table.row_count(), 1);
    }

    #[test]
    fn test_column_definitions() {
        let cols = VarnodeColumn::all();
        assert_eq!(cols.len(), 3);
        assert!(cols[0].is_editable());
        assert!(cols[1].is_editable());
        assert!(!cols[2].is_editable());
    }

    #[test]
    fn test_parse_varnode_type() {
        assert_eq!(parse_varnode_type("Register"), Some(VarnodeType::Register));
        assert_eq!(parse_varnode_type("stack"), Some(VarnodeType::Stack));
        assert_eq!(parse_varnode_type("MEMORY"), Some(VarnodeType::Memory));
        assert_eq!(parse_varnode_type("invalid"), None);
    }
}
