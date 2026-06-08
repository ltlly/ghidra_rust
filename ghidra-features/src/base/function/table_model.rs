//! Function table model -- ported from `FunctionTableModel.java` and
//! `FunctionData.java` in `ghidra.app.plugin.core.function`.
//!
//! Provides table-model abstractions for displaying function lists in
//! table views, as well as [`FunctionData`] row objects used by the
//! chooser and table panels.

use serde::{Deserialize, Serialize};


// ---------------------------------------------------------------------------
// FunctionTableColumn -- column descriptors for function table views
// ---------------------------------------------------------------------------

/// Columns available in a function table view.
///
/// Ported from `FunctionTableModel` columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FunctionTableColumn {
    /// Entry point address.
    Address,
    /// Function name.
    Name,
    /// Function size in bytes.
    Size,
    /// Calling convention.
    CallingConvention,
    /// Return type.
    ReturnType,
    /// Number of parameters.
    ParameterCount,
    /// Number of local variables.
    LocalVariableCount,
    /// Stack frame size.
    StackFrameSize,
    /// Whether the function is a thunk.
    IsThunk,
    /// Whether the function has no return.
    NoReturn,
    /// Whether the function is inline.
    Inline,
    /// Library name (for external functions).
    Library,
    /// Function tag names.
    Tags,
    /// Function comment.
    Comment,
}

impl FunctionTableColumn {
    /// Display name for this column.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Address => "Address",
            Self::Name => "Name",
            Self::Size => "Size",
            Self::CallingConvention => "Calling Convention",
            Self::ReturnType => "Return Type",
            Self::ParameterCount => "Params",
            Self::LocalVariableCount => "Locals",
            Self::StackFrameSize => "Stack Frame",
            Self::IsThunk => "Thunk",
            Self::NoReturn => "No Return",
            Self::Inline => "Inline",
            Self::Library => "Library",
            Self::Tags => "Tags",
            Self::Comment => "Comment",
        }
    }

    /// All columns in display order.
    pub fn all() -> &'static [FunctionTableColumn] {
        &[
            Self::Address,
            Self::Name,
            Self::Size,
            Self::CallingConvention,
            Self::ReturnType,
            Self::ParameterCount,
            Self::LocalVariableCount,
            Self::StackFrameSize,
            Self::IsThunk,
            Self::NoReturn,
            Self::Inline,
            Self::Library,
            Self::Tags,
            Self::Comment,
        ]
    }
}

// ---------------------------------------------------------------------------
// FunctionRowData -- a row in the function table
// ---------------------------------------------------------------------------

/// Data for a single row in a function table view.
///
/// Ported from `FunctionData` and `FunctionTableModel`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionRowData {
    /// Entry point address.
    pub address: u64,
    /// Function name (symbol name).
    pub name: String,
    /// Function body size in bytes.
    pub size: u64,
    /// Calling convention name.
    pub calling_convention: String,
    /// Return type name.
    pub return_type: String,
    /// Number of parameters.
    pub parameter_count: usize,
    /// Number of local variables.
    pub local_variable_count: usize,
    /// Stack frame size.
    pub stack_frame_size: i64,
    /// Whether this is a thunk function.
    pub is_thunk: bool,
    /// Whether the function is marked no-return.
    pub no_return: bool,
    /// Whether the function is inline.
    pub inline: bool,
    /// Library name (for external functions, empty otherwise).
    pub library: String,
    /// Tag names associated with this function.
    pub tags: Vec<String>,
    /// Function comment (plate or pre).
    pub comment: String,
    /// Full namespace path.
    pub namespace: String,
}

impl FunctionRowData {
    /// Create a new function row data with defaults.
    pub fn new(address: u64, name: impl Into<String>) -> Self {
        Self {
            address,
            name: name.into(),
            size: 0,
            calling_convention: String::new(),
            return_type: "void".into(),
            parameter_count: 0,
            local_variable_count: 0,
            stack_frame_size: 0,
            is_thunk: false,
            no_return: false,
            inline: false,
            library: String::new(),
            tags: Vec::new(),
            comment: String::new(),
            namespace: String::new(),
        }
    }

    /// Get value for a given column.
    pub fn column_value(&self, col: FunctionTableColumn) -> String {
        match col {
            FunctionTableColumn::Address => format!("0x{:x}", self.address),
            FunctionTableColumn::Name => self.name.clone(),
            FunctionTableColumn::Size => self.size.to_string(),
            FunctionTableColumn::CallingConvention => self.calling_convention.clone(),
            FunctionTableColumn::ReturnType => self.return_type.clone(),
            FunctionTableColumn::ParameterCount => self.parameter_count.to_string(),
            FunctionTableColumn::LocalVariableCount => self.local_variable_count.to_string(),
            FunctionTableColumn::StackFrameSize => self.stack_frame_size.to_string(),
            FunctionTableColumn::IsThunk => self.is_thunk.to_string(),
            FunctionTableColumn::NoReturn => self.no_return.to_string(),
            FunctionTableColumn::Inline => self.inline.to_string(),
            FunctionTableColumn::Library => self.library.clone(),
            FunctionTableColumn::Tags => self.tags.join(", "),
            FunctionTableColumn::Comment => self.comment.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// FunctionTableModel -- thread-safe table model
// ---------------------------------------------------------------------------

/// A table model for function lists, supporting sorting, filtering,
/// and incremental loading.
///
/// Ported from `FunctionTableModel`.
#[derive(Debug)]
pub struct FunctionTableModel {
    /// Column definitions.
    columns: Vec<FunctionTableColumn>,
    /// Row data.
    rows: Vec<FunctionRowData>,
    /// Sort column (if any).
    sort_column: Option<FunctionTableColumn>,
    /// Sort ascending.
    sort_ascending: bool,
    /// Text filter.
    filter_text: Option<String>,
}

impl FunctionTableModel {
    /// Create a new function table model with default columns.
    pub fn new() -> Self {
        Self {
            columns: FunctionTableColumn::all().to_vec(),
            rows: Vec::new(),
            sort_column: None,
            sort_ascending: true,
            filter_text: None,
        }
    }

    /// Create with specific columns.
    pub fn with_columns(columns: Vec<FunctionTableColumn>) -> Self {
        Self {
            columns,
            rows: Vec::new(),
            sort_column: None,
            sort_ascending: true,
            filter_text: None,
        }
    }

    /// Add a row to the model.
    pub fn add_row(&mut self, row: FunctionRowData) {
        self.rows.push(row);
    }

    /// Get the number of rows.
    pub fn row_count(&self) -> usize {
        self.filtered_rows().len()
    }

    /// Get the number of columns.
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Get column at index.
    pub fn column(&self, index: usize) -> Option<FunctionTableColumn> {
        self.columns.get(index).copied()
    }

    /// Get cell value.
    pub fn cell_value(&self, row: usize, col: usize) -> Option<String> {
        let filtered = self.filtered_rows();
        let data = filtered.get(row)?;
        let column = self.columns.get(col)?;
        Some(data.column_value(*column))
    }

    /// Sort by a column.
    pub fn sort_by(&mut self, col: FunctionTableColumn, ascending: bool) {
        self.sort_column = Some(col);
        self.sort_ascending = ascending;
        self.rows.sort_by(|a, b| {
            let va = a.column_value(col);
            let vb = b.column_value(col);
            let cmp = va.cmp(&vb);
            if ascending { cmp } else { cmp.reverse() }
        });
    }

    /// Set a text filter.
    pub fn set_filter(&mut self, text: Option<String>) {
        self.filter_text = text;
    }

    /// Get filtered rows.
    fn filtered_rows(&self) -> Vec<&FunctionRowData> {
        match &self.filter_text {
            None => self.rows.iter().collect(),
            Some(text) => {
                let lower = text.to_lowercase();
                self.rows
                    .iter()
                    .filter(|r| {
                        r.name.to_lowercase().contains(&lower)
                            || r.return_type.to_lowercase().contains(&lower)
                            || r.comment.to_lowercase().contains(&lower)
                    })
                    .collect()
            }
        }
    }

    /// Clear all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
    }

    /// Get all rows.
    pub fn rows(&self) -> &[FunctionRowData] {
        &self.rows
    }
}

impl Default for FunctionTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FunctionVariableData -- row data for the variable table
// ---------------------------------------------------------------------------

/// Data for a single row in the function variable table.
///
/// Ported from `FunctionVariableData`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionVariableData {
    /// Variable name.
    pub name: String,
    /// Data type name.
    pub data_type: String,
    /// Storage location description (register, stack, etc.).
    pub storage: String,
    /// Stack offset (for stack variables).
    pub stack_offset: Option<i64>,
    /// Register name (for register variables).
    pub register: Option<String>,
    /// First use offset.
    pub first_use_offset: u32,
    /// Variable comment.
    pub comment: String,
    /// Whether this variable is a parameter.
    pub is_parameter: bool,
    /// Parameter ordinal (0-indexed, if parameter).
    pub ordinal: Option<usize>,
}

impl FunctionVariableData {
    /// Create a new variable data.
    pub fn new(
        name: impl Into<String>,
        data_type: impl Into<String>,
        storage: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            data_type: data_type.into(),
            storage: storage.into(),
            stack_offset: None,
            register: None,
            first_use_offset: 0,
            comment: String::new(),
            is_parameter: false,
            ordinal: None,
        }
    }
}

// ---------------------------------------------------------------------------
// VarnodeType -- classification of variable storage
// ---------------------------------------------------------------------------

/// How a function variable is stored.
///
/// Ported from `VarnodeType.java`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VarnodeType {
    /// Stored in a register.
    Register,
    /// Stored on the stack.
    Stack,
    /// Stored at a memory address.
    Memory,
    /// Storage type is unknown/unresolved.
    Unknown,
}

impl VarnodeType {
    /// Display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Register => "Register",
            Self::Stack => "Stack",
            Self::Memory => "Memory",
            Self::Unknown => "Unknown",
        }
    }
}

/// Varnode information for a function variable.
///
/// Ported from `VarnodeInfo.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VarnodeInfo {
    /// The storage type.
    pub varnode_type: VarnodeType,
    /// Size in bytes.
    pub size: usize,
    /// Register name (if register).
    pub register_name: Option<String>,
    /// Stack offset (if stack).
    pub stack_offset: Option<i64>,
    /// Address (if memory).
    pub address: Option<u64>,
}

impl VarnodeInfo {
    /// Create a register varnode.
    pub fn register(name: impl Into<String>, size: usize) -> Self {
        Self {
            varnode_type: VarnodeType::Register,
            size,
            register_name: Some(name.into()),
            stack_offset: None,
            address: None,
        }
    }

    /// Create a stack varnode.
    pub fn stack(offset: i64, size: usize) -> Self {
        Self {
            varnode_type: VarnodeType::Stack,
            size,
            register_name: None,
            stack_offset: Some(offset),
            address: None,
        }
    }

    /// Create a memory varnode.
    pub fn memory(address: u64, size: usize) -> Self {
        Self {
            varnode_type: VarnodeType::Memory,
            size,
            register_name: None,
            stack_offset: None,
            address: Some(address),
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_table_column_display() {
        assert_eq!(FunctionTableColumn::Address.display_name(), "Address");
        assert_eq!(FunctionTableColumn::Name.display_name(), "Name");
        assert_eq!(FunctionTableColumn::all().len(), 14);
    }

    #[test]
    fn test_function_row_data() {
        let row = FunctionRowData::new(0x400000, "main");
        assert_eq!(row.address, 0x400000);
        assert_eq!(row.name, "main");
        assert_eq!(row.return_type, "void");
        assert!(!row.is_thunk);
    }

    #[test]
    fn test_function_row_data_column_value() {
        let mut row = FunctionRowData::new(0x400000, "main");
        row.size = 256;
        row.parameter_count = 2;
        assert_eq!(row.column_value(FunctionTableColumn::Address), "0x400000");
        assert_eq!(row.column_value(FunctionTableColumn::Size), "256");
        assert_eq!(row.column_value(FunctionTableColumn::ParameterCount), "2");
    }

    #[test]
    fn test_function_table_model() {
        let mut model = FunctionTableModel::new();
        assert_eq!(model.row_count(), 0);
        assert_eq!(model.column_count(), 14);

        model.add_row(FunctionRowData::new(0x400000, "main"));
        model.add_row(FunctionRowData::new(0x401000, "init"));
        assert_eq!(model.row_count(), 2);
    }

    #[test]
    fn test_function_table_model_filter() {
        let mut model = FunctionTableModel::new();
        model.add_row(FunctionRowData::new(0x400000, "main"));
        model.add_row(FunctionRowData::new(0x401000, "init"));
        model.add_row(FunctionRowData::new(0x402000, "main_loop"));

        model.set_filter(Some("main".into()));
        assert_eq!(model.row_count(), 2);

        model.set_filter(None);
        assert_eq!(model.row_count(), 3);
    }

    #[test]
    fn test_function_table_model_sort() {
        let mut model = FunctionTableModel::new();
        model.add_row(FunctionRowData::new(0x402000, "zebra"));
        model.add_row(FunctionRowData::new(0x400000, "alpha"));

        model.sort_by(FunctionTableColumn::Name, true);
        assert_eq!(model.cell_value(0, 1), Some("alpha".into()));
        assert_eq!(model.cell_value(1, 1), Some("zebra".into()));

        model.sort_by(FunctionTableColumn::Name, false);
        assert_eq!(model.cell_value(0, 1), Some("zebra".into()));
    }

    #[test]
    fn test_function_variable_data() {
        let var = FunctionVariableData::new("buf", "char[256]", "Stack[-0x100]");
        assert_eq!(var.name, "buf");
        assert_eq!(var.data_type, "char[256]");
        assert!(!var.is_parameter);
    }

    #[test]
    fn test_varnode_info() {
        let reg = VarnodeInfo::register("RAX", 8);
        assert_eq!(reg.varnode_type, VarnodeType::Register);
        assert_eq!(reg.size, 8);
        assert_eq!(reg.register_name.as_deref(), Some("RAX"));

        let stack = VarnodeInfo::stack(-0x10, 4);
        assert_eq!(stack.varnode_type, VarnodeType::Stack);
        assert_eq!(stack.stack_offset, Some(-0x10));

        let mem = VarnodeInfo::memory(0x400000, 2);
        assert_eq!(mem.varnode_type, VarnodeType::Memory);
    }

    #[test]
    fn test_varnode_type_display() {
        assert_eq!(VarnodeType::Register.display_name(), "Register");
        assert_eq!(VarnodeType::Stack.display_name(), "Stack");
    }

    #[test]
    fn test_model_with_columns() {
        let cols = vec![FunctionTableColumn::Address, FunctionTableColumn::Name];
        let mut model = FunctionTableModel::with_columns(cols);
        assert_eq!(model.column_count(), 2);
        model.add_row(FunctionRowData::new(0x100, "f"));
        assert_eq!(model.cell_value(0, 0), Some("0x100".into()));
        assert_eq!(model.cell_value(0, 1), Some("f".into()));
    }
}
