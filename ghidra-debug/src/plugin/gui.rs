//! Debugger GUI provider types (non-UI data model layer).
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui` package.
//! These are data model types backing the debugger GUI; actual rendering
//! is out of scope for the Rust port.

use serde::{Deserialize, Serialize};

use crate::api::breakpoint::LogicalBreakpoint;
use crate::model::Lifespan;

/// A row in the breakpoints provider table.
///
/// Ported from Ghidra's `BreakpointLocationRow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointLocationRow {
    /// The breakpoint address.
    pub address: u64,
    /// The thread key (if thread-specific).
    pub thread_key: Option<i64>,
    /// The trace ID.
    pub trace_id: String,
    /// Whether the breakpoint is enabled.
    pub enabled: bool,
    /// The breakpoint kind.
    pub kind: BreakpointRowKind,
}

/// The kind of breakpoint row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BreakpointRowKind {
    /// Software breakpoint.
    Software,
    /// Hardware breakpoint.
    Hardware,
    /// Read watchpoint.
    ReadWatch,
    /// Write watchpoint.
    WriteWatch,
    /// Access watchpoint.
    AccessWatch,
}

/// A row in the logical breakpoints table.
///
/// Ported from Ghidra's `LogicalBreakpointRow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogicalBreakpointRow {
    /// The name/expression.
    pub expression: String,
    /// The status string.
    pub status: String,
    /// Whether it's enabled.
    pub enabled: bool,
    /// The program URL.
    pub program_url: Option<String>,
    /// The trace ID.
    pub trace_id: Option<String>,
    /// The address offset.
    pub address: u64,
}

/// A column descriptor for the model table.
///
/// Ported from Ghidra's `DebuggerColumns`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableColumn {
    /// The column name.
    pub name: String,
    /// The column display name.
    pub display_name: String,
    /// The column width (in pixels).
    pub width: u32,
    /// Whether this column is visible by default.
    pub visible: bool,
    /// The column type hint.
    pub column_type: ColumnType,
}

/// The type hint for a table column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ColumnType {
    /// String/text.
    Text,
    /// Integer.
    Integer,
    /// Hex address.
    HexAddress,
    /// Boolean.
    Boolean,
    /// Icon.
    Icon,
}

impl TableColumn {
    /// Create a new text column.
    pub fn text(name: impl Into<String>, display: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            display_name: display.into(),
            width: 100,
            visible: true,
            column_type: ColumnType::Text,
        }
    }

    /// Create a new hex address column.
    pub fn hex_address(name: impl Into<String>, display: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            display_name: display.into(),
            width: 120,
            visible: true,
            column_type: ColumnType::HexAddress,
        }
    }

    /// Set the width.
    pub fn with_width(mut self, width: u32) -> Self {
        self.width = width;
        self
    }

    /// Set hidden by default.
    pub fn hidden(mut self) -> Self {
        self.visible = false;
        self
    }
}

/// A register row for the registers provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRow {
    /// The register name.
    pub name: String,
    /// The register value (as bytes).
    pub value: Vec<u8>,
    /// The display value (hex string).
    pub display_value: String,
    /// The register group (e.g., "General Purpose", "Flags").
    pub group: String,
    /// Whether the value has changed since last update.
    pub changed: bool,
}

impl RegisterRow {
    /// Create a new register row.
    pub fn new(
        name: impl Into<String>,
        value: &[u8],
        group: impl Into<String>,
    ) -> Self {
        let display_value = value
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("");
        Self {
            name: name.into(),
            value: value.to_vec(),
            display_value,
            group: group.into(),
            changed: false,
        }
    }

    /// Mark as changed.
    pub fn mark_changed(&mut self) {
        self.changed = true;
    }
}

/// A thread row for the threads provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadRow {
    /// The thread key.
    pub key: i64,
    /// The thread name.
    pub name: String,
    /// The process key.
    pub process_key: i64,
    /// The process name.
    pub process_name: String,
    /// Whether this is the active thread.
    pub active: bool,
    /// The PC offset if known.
    pub pc: Option<u64>,
}

/// A stack frame row for the stack provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrameRow {
    /// The frame level (0 = innermost).
    pub level: u32,
    /// The return address.
    pub return_address: Option<u64>,
    /// The function name.
    pub function_name: Option<String>,
    /// The frame pointer.
    pub frame_pointer: Option<u64>,
    /// The program URL for this frame.
    pub program_url: Option<String>,
}

/// Watch row for variable watch display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchValueRow {
    /// The expression being watched.
    pub expression: String,
    /// The current value.
    pub value: String,
    /// The value type.
    pub value_type: String,
    /// Whether the value has changed since last update.
    pub changed: bool,
}

/// The model type for the trace object tree.
///
/// Ported from Ghidra's tree model classes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectTreeNode {
    /// The object key path.
    pub key_path: Vec<String>,
    /// The display name.
    pub display_name: String,
    /// The object type name.
    pub object_type: String,
    /// Number of children.
    pub child_count: usize,
    /// Whether this node is expanded.
    pub expanded: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_breakpoint_location_row() {
        let row = BreakpointLocationRow {
            address: 0x400000,
            thread_key: None,
            trace_id: "trace1".into(),
            enabled: true,
            kind: BreakpointRowKind::Software,
        };
        assert!(row.enabled);
        assert_eq!(row.kind, BreakpointRowKind::Software);
    }

    #[test]
    fn test_table_column() {
        let col = TableColumn::hex_address("addr", "Address").with_width(150);
        assert_eq!(col.column_type, ColumnType::HexAddress);
        assert_eq!(col.width, 150);
        assert!(col.visible);

        let col = TableColumn::text("name", "Name").hidden();
        assert!(!col.visible);
    }

    #[test]
    fn test_register_row() {
        let row = RegisterRow::new("RAX", &[0x48, 0x89, 0xe5], "General Purpose");
        assert_eq!(row.name, "RAX");
        assert_eq!(row.display_value, "4889e5");
        assert!(!row.changed);

        let mut row = row;
        row.mark_changed();
        assert!(row.changed);
    }

    #[test]
    fn test_thread_row() {
        let row = ThreadRow {
            key: 1,
            name: "main".into(),
            process_key: 1,
            process_name: "target".into(),
            active: true,
            pc: Some(0x400000),
        };
        assert!(row.active);
    }

    #[test]
    fn test_stack_frame_row() {
        let row = StackFrameRow {
            level: 0,
            return_address: Some(0x400080),
            function_name: Some("main".into()),
            frame_pointer: Some(0x7fff0000),
            program_url: None,
        };
        assert_eq!(row.level, 0);
        assert!(row.function_name.is_some());
    }

    #[test]
    fn test_watch_value_row() {
        let row = WatchValueRow {
            expression: "RAX".into(),
            value: "0x42".into(),
            value_type: "long".into(),
            changed: true,
        };
        assert!(row.changed);
    }

    #[test]
    fn test_object_tree_node() {
        let node = ObjectTreeNode {
            key_path: vec!["Processes".into(), "1234".into()],
            display_name: "target".into(),
            object_type: "Process".into(),
            child_count: 5,
            expanded: false,
        };
        assert_eq!(node.key_path.len(), 2);
    }

    #[test]
    fn test_logical_breakpoint_row() {
        let row = LogicalBreakpointRow {
            expression: "0x400000".into(),
            status: "Enabled".into(),
            enabled: true,
            program_url: Some("file:///prog".into()),
            trace_id: None,
            address: 0x400000,
        };
        assert!(row.enabled);
    }

    #[test]
    fn test_breakpoint_row_kinds() {
        assert_ne!(BreakpointRowKind::Software, BreakpointRowKind::Hardware);
        assert_ne!(BreakpointRowKind::ReadWatch, BreakpointRowKind::WriteWatch);
    }

    #[test]
    fn test_register_row_serde() {
        let row = RegisterRow::new("RIP", &[0x00, 0x00, 0x40, 0x00], "General");
        let json = serde_json::to_string(&row).unwrap();
        let back: RegisterRow = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "RIP");
    }
}
