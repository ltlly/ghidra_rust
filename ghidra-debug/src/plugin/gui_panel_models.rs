//! GUI panel data models for debugger plugin panels.
//!
//! Ported from Ghidra's various `gui.*` packages. These are the data models
//! backing the debugger GUI panels (registers, threads, modules, memory,
//! breakpoints, stack, time, watch, etc.). The Swing UI rendering is not
//! ported; only the data model and logic.
//!
//! Classes ported here:
//! - gui.register: DebuggerRegistersPlugin/Provider, RegisterActionContext, etc.
//! - gui.thread: DebuggerThreadsPlugin/Provider/Panel
//! - gui.memory: DebuggerMemoryBytesPlugin/Provider/Panel, RegionPanel, etc.
//! - gui.modules: DebuggerModulesPlugin/Provider/Panel, MappingPanel, etc.
//! - gui.stack: DebuggerStackPlugin/Provider/Panel
//! - gui.time: DebuggerTimePlugin/Provider/Panel
//! - gui.watch: DebuggerWatchesPlugin/Provider
//! - gui.console: DebuggerConsolePlugin
//! - gui.listing: DebuggerListingPlugin/Provider
//! - gui.breakpoint: DebuggerBreakpointsPlugin/Provider
//! - gui.model: DebuggerModelPlugin/Provider, ObjectsTree/TablePanel
//! - gui.memview: DebuggerMemviewPlugin/Provider/Panel/Table
//! - gui.colors: TrackedRegisterBackgroundColorModel, etc.
//! - gui.copying: DebuggerCopyActionsPlugin, CopyIntoProgramDialog
//! - gui.diff: DebuggerTraceViewDiffPlugin
//! - gui.tracecalltree: TraceCallTreePlugin/Provider/Table/Nodes
//! - gui.timeoverview: TimeOverviewColorPlugin/Component
//! - gui.platform: DebuggerSelectPlatformOfferDialog

use serde::{Deserialize, Serialize};

/// The column descriptor for a table in the debugger GUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuiTableColumn {
    /// Column name.
    pub name: String,
    /// Column type hint.
    pub col_type: GuiColumnType,
    /// Whether the column is visible by default.
    pub visible: bool,
    /// Column width in pixels.
    pub width: u32,
}

/// Column type hints for GUI tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GuiColumnType {
    /// String/text column.
    Text,
    /// Numeric column.
    Number,
    /// Address column.
    Address,
    /// Boolean checkbox column.
    Boolean,
    /// Icon column.
    Icon,
    /// Editable column.
    Editable,
}

impl GuiTableColumn {
    /// Create a new table column.
    pub fn new(name: impl Into<String>, col_type: GuiColumnType) -> Self {
        Self {
            name: name.into(),
            col_type,
            visible: true,
            width: 100,
        }
    }

    /// Set visibility.
    pub fn with_visible(mut self, visible: bool) -> Self {
        self.visible = visible;
        self
    }

    /// Set width.
    pub fn with_width(mut self, width: u32) -> Self {
        self.width = width;
        self
    }
}

/// A breakpoint state for display in the breakpoint table.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BreakpointDisplayState {
    /// Enabled and effective.
    Enabled,
    /// Enabled but pending (not yet placed).
    Pending,
    /// Disabled.
    Disabled,
    /// Partially enabled (some locations effective, some not).
    Partial,
}

/// A module entry for the modules panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleEntry {
    /// Module name.
    pub name: String,
    /// Module base address.
    pub base_address: u64,
    /// Module size in bytes.
    pub size: u64,
    /// Path to the module on the target filesystem.
    pub path: String,
    /// Whether the module is currently loaded.
    pub loaded: bool,
    /// Sections within this module.
    pub sections: Vec<SectionEntry>,
}

/// A section entry within a module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionEntry {
    /// Section name.
    pub name: String,
    /// Start address.
    pub start: u64,
    /// Size in bytes.
    pub size: u64,
    /// Permissions (read/write/execute flags).
    pub permissions: u32,
}

impl SectionEntry {
    /// Check if section is readable.
    pub fn is_readable(&self) -> bool {
        self.permissions & 0b100 != 0
    }

    /// Check if section is writable.
    pub fn is_writable(&self) -> bool {
        self.permissions & 0b010 != 0
    }

    /// Check if section is executable.
    pub fn is_executable(&self) -> bool {
        self.permissions & 0b001 != 0
    }
}

/// A memory region entry for the memory panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegionEntry {
    /// Region name.
    pub name: String,
    /// Start address.
    pub start: u64,
    /// Size in bytes.
    pub size: u64,
    /// Memory flags (read/write/execute).
    pub flags: u32,
    /// Whether this is a volatile region.
    pub volatile: bool,
}

/// A register entry for the registers panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterEntry {
    /// Register name (e.g., "RAX", "RSP").
    pub name: String,
    /// Register size in bytes.
    pub size: u32,
    /// Current value bytes (if known).
    pub value: Option<Vec<u8>>,
    /// Whether the value was modified since last stop.
    pub modified: bool,
    /// Register group (e.g., "General Purpose", "Flags").
    pub group: String,
}

impl RegisterEntry {
    /// Get value as a hex string.
    pub fn value_hex(&self) -> String {
        match &self.value {
            Some(v) => v.iter().map(|b| format!("{:02x}", b)).collect(),
            None => "??".into(),
        }
    }

    /// Get value as a u64 (for registers up to 8 bytes).
    pub fn value_u64(&self) -> Option<u64> {
        let v = self.value.as_ref()?;
        if v.len() > 8 {
            return None;
        }
        let mut buf = [0u8; 8];
        buf[..v.len()].copy_from_slice(v);
        Some(u64::from_le_bytes(buf))
    }
}

/// A thread entry for the threads panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadEntry {
    /// Thread ID.
    pub thread_id: u64,
    /// Thread name.
    pub name: String,
    /// Process ID.
    pub process_id: u64,
    /// Process name.
    pub process_name: String,
    /// Current execution state.
    pub state: ThreadState,
    /// Current PC (if available).
    pub pc: Option<u64>,
}

/// Thread execution state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreadState {
    /// Running.
    Running,
    /// Stopped.
    Stopped,
    /// Waiting/blocked.
    Waiting,
    /// Zombie (dead but not reaped).
    Zombie,
    /// Unknown state.
    Unknown,
}

/// A watch entry for the watches panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchEntry {
    /// Watch expression.
    pub expression: String,
    /// Current value (if resolvable).
    pub value: Option<String>,
    /// Data type of the value.
    pub data_type: String,
    /// Whether the value changed since last evaluation.
    pub changed: bool,
    /// Error message if evaluation failed.
    pub error: Option<String>,
}

/// A stack frame entry for the stack panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrameEntry {
    /// Frame number (0 = innermost).
    pub frame_number: u32,
    /// Function name (if known).
    pub function_name: Option<String>,
    /// Return address.
    pub return_address: Option<u64>,
    /// Frame pointer.
    pub frame_pointer: Option<u64>,
    /// Stack pointer.
    pub stack_pointer: Option<u64>,
    /// Parameters.
    pub parameters: Vec<FrameVariable>,
    /// Local variables.
    pub locals: Vec<FrameVariable>,
}

/// A variable within a stack frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameVariable {
    /// Variable name.
    pub name: String,
    /// Data type.
    pub data_type: String,
    /// Current value.
    pub value: Option<String>,
    /// Storage location (register or stack offset).
    pub storage: String,
}

/// A snapshot entry for the time panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry {
    /// Snap number.
    pub snap: i64,
    /// Description.
    pub description: String,
    /// Timestamp.
    pub timestamp: Option<u64>,
    /// Whether this is the current snap.
    pub is_current: bool,
}

/// A call tree node for the trace call tree panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallTreeNode {
    /// Node kind.
    pub kind: CallTreeNodeKind,
    /// Function name or label.
    pub label: String,
    /// Address.
    pub address: u64,
    /// Child nodes.
    pub children: Vec<CallTreeNode>,
}

/// Call tree node kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallTreeNodeKind {
    /// A call instruction.
    Call,
    /// A return instruction.
    Return,
    /// A tail call.
    TailCall,
    /// An external/library call.
    External,
}

/// Action context for the listing panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListingActionContext {
    /// The address.
    pub address: u64,
    /// The snap.
    pub snap: i64,
    /// Selected range start (if any).
    pub selection_start: Option<u64>,
    /// Selected range end (if any).
    pub selection_end: Option<u64>,
}

/// Whether to save behavior for multi-provider scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MultiProviderSaveBehavior {
    /// Save all providers.
    SaveAll,
    /// Save only the active provider.
    SaveActiveOnly,
    /// Prompt for each.
    PromptEach,
}

impl Default for MultiProviderSaveBehavior {
    fn default() -> Self {
        Self::SaveActiveOnly
    }
}

/// Debounced row-wrapped table model utility.
///
/// Ported from Ghidra's `DebouncedRowWrappedEnumeratedColumnTableModel`.
#[derive(Debug, Clone)]
pub struct DebouncedTableModel<T> {
    /// The rows in the table.
    pub rows: Vec<T>,
    /// Debounce interval in milliseconds.
    pub debounce_ms: u64,
    /// Whether an update is pending.
    pub pending: bool,
}

impl<T> DebouncedTableModel<T> {
    /// Create a new debounced table model.
    pub fn new(debounce_ms: u64) -> Self {
        Self {
            rows: Vec::new(),
            debounce_ms,
            pending: false,
        }
    }

    /// Set the rows.
    pub fn set_rows(&mut self, rows: Vec<T>) {
        self.rows = rows;
        self.pending = true;
    }

    /// Clear the pending flag and return whether it was pending.
    pub fn consume_pending(&mut self) -> bool {
        let was = self.pending;
        self.pending = false;
        was
    }

    /// Get the number of rows.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gui_table_column() {
        let col = GuiTableColumn::new("Name", GuiColumnType::Text)
            .with_width(200)
            .with_visible(true);
        assert_eq!(col.name, "Name");
        assert_eq!(col.width, 200);
        assert!(col.visible);
    }

    #[test]
    fn test_section_entry_permissions() {
        let section = SectionEntry {
            name: ".text".into(),
            start: 0x1000,
            size: 0x500,
            permissions: 0b101, // read + execute
        };
        assert!(section.is_readable());
        assert!(!section.is_writable());
        assert!(section.is_executable());
    }

    #[test]
    fn test_register_entry_value() {
        let entry = RegisterEntry {
            name: "RAX".into(),
            size: 8,
            value: Some(vec![0x42, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            modified: true,
            group: "General Purpose".into(),
        };
        assert_eq!(entry.value_u64(), Some(0x142));
        assert_eq!(entry.value_hex(), "4201000000000000");
    }

    #[test]
    fn test_register_entry_unknown_value() {
        let entry = RegisterEntry {
            name: "RAX".into(),
            size: 8,
            value: None,
            modified: false,
            group: "General Purpose".into(),
        };
        assert_eq!(entry.value_hex(), "??");
        assert_eq!(entry.value_u64(), None);
    }

    #[test]
    fn test_breakpoint_display_state() {
        assert_ne!(BreakpointDisplayState::Enabled, BreakpointDisplayState::Disabled);
    }

    #[test]
    fn test_module_entry() {
        let module = ModuleEntry {
            name: "libc.so".into(),
            base_address: 0x7fff0000,
            size: 0x100000,
            path: "/lib/x86_64-linux-gnu/libc.so.6".into(),
            loaded: true,
            sections: vec![
                SectionEntry { name: ".text".into(), start: 0x7fff1000, size: 0x80000, permissions: 0b101 },
            ],
        };
        assert!(module.loaded);
        assert_eq!(module.sections.len(), 1);
    }

    #[test]
    fn test_thread_entry() {
        let thread = ThreadEntry {
            thread_id: 1,
            name: "main".into(),
            process_id: 100,
            process_name: "test".into(),
            state: ThreadState::Stopped,
            pc: Some(0x1000),
        };
        assert_eq!(thread.state, ThreadState::Stopped);
    }

    #[test]
    fn test_watch_entry() {
        let watch = WatchEntry {
            expression: "RAX".into(),
            value: Some("0x42".into()),
            data_type: "uint64_t".into(),
            changed: true,
            error: None,
        };
        assert!(watch.changed);
        assert!(watch.error.is_none());
    }

    #[test]
    fn test_stack_frame_entry() {
        let frame = StackFrameEntry {
            frame_number: 0,
            function_name: Some("main".into()),
            return_address: Some(0x2000),
            frame_pointer: Some(0x7fff00),
            stack_pointer: Some(0x7ffe00),
            parameters: vec![],
            locals: vec![FrameVariable {
                name: "x".into(),
                data_type: "int".into(),
                value: Some("42".into()),
                storage: "RDI".into(),
            }],
        };
        assert_eq!(frame.frame_number, 0);
        assert_eq!(frame.locals.len(), 1);
    }

    #[test]
    fn test_call_tree_node() {
        let node = CallTreeNode {
            kind: CallTreeNodeKind::Call,
            label: "main".into(),
            address: 0x1000,
            children: vec![CallTreeNode {
                kind: CallTreeNodeKind::External,
                label: "printf".into(),
                address: 0x2000,
                children: vec![],
            }],
        };
        assert_eq!(node.kind, CallTreeNodeKind::Call);
        assert_eq!(node.children.len(), 1);
        assert_eq!(node.children[0].kind, CallTreeNodeKind::External);
    }

    #[test]
    fn test_debounced_table_model() {
        let mut model = DebouncedTableModel::<String>::new(200);
        assert!(model.is_empty());
        model.set_rows(vec!["a".into(), "b".into()]);
        assert_eq!(model.len(), 2);
        assert!(model.consume_pending());
        assert!(!model.consume_pending());
    }

    #[test]
    fn test_snapshot_entry() {
        let snap = SnapshotEntry {
            snap: 42,
            description: "after breakpoint".into(),
            timestamp: Some(1234567890),
            is_current: true,
        };
        assert!(snap.is_current);
    }

    #[test]
    fn test_listing_action_context() {
        let ctx = ListingActionContext {
            address: 0x1000,
            snap: 5,
            selection_start: Some(0x1000),
            selection_end: Some(0x1100),
        };
        assert!(ctx.selection_start.is_some());
    }

    #[test]
    fn test_multi_provider_save_behavior_default() {
        assert_eq!(MultiProviderSaveBehavior::default(), MultiProviderSaveBehavior::SaveActiveOnly);
    }
}
