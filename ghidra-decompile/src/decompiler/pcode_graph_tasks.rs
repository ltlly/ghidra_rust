//! P-code graph task types for building and displaying P-code CFG and DFG graphs.
//!
//! Ports Ghidra's `ghidra.app.plugin.core.decompile.actions.PCodeCfgGraphTask`,
//! `PCodeDfgGraphTask`, `SelectedPCodeDfgGraphTask`, `PCodeCfgDisplayListener`,
//! `PCodeDfgDisplayListener`, and `PCodeCombinedGraphTask`.
//!
//! In the Rust port, these are data structures that represent graph construction
//! and display tasks. The actual graph rendering is handled by the GUI layer.

use super::actions::PCodeCfgGraphType;
use super::actions::PCodeDfgDisplayOptions;
use super::actions::PCodeDfgGraphType;

// ============================================================================
// PCodeGraphTaskStatus
// ============================================================================

/// Status of a P-code graph task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PCodeGraphTaskStatus {
    /// Task has not started yet.
    Pending,
    /// Task is currently running.
    Running,
    /// Task completed successfully.
    Completed,
    /// Task failed with an error.
    Failed,
    /// Task was cancelled.
    Cancelled,
}

impl Default for PCodeGraphTaskStatus {
    fn default() -> Self {
        PCodeGraphTaskStatus::Pending
    }
}

// ============================================================================
// PCodeCfgGraphTask
// ============================================================================

/// A task for building and displaying a P-code control-flow graph.
///
/// Port of Ghidra's `PCodeCfgGraphTask`. In the Java version, this extends
/// `Task` and runs on a background thread. In Rust, this is a data structure
/// that describes the CFG construction parameters.
#[derive(Debug, Clone)]
pub struct PCodeCfgGraphTask {
    /// The type of CFG to build.
    pub graph_type: PCodeCfgGraphType,
    /// The function entry address.
    pub function_entry: u64,
    /// The function name.
    pub function_name: String,
    /// Whether to include basic block boundaries.
    pub include_block_boundaries: bool,
    /// Whether to include instruction-level details.
    pub include_instruction_details: bool,
    /// Maximum number of blocks to display.
    pub max_blocks: Option<usize>,
    /// Current status.
    pub status: PCodeGraphTaskStatus,
    /// Error message if status is Failed.
    pub error_message: Option<String>,
}

impl PCodeCfgGraphTask {
    /// Create a new PCode CFG graph task.
    pub fn new(
        graph_type: PCodeCfgGraphType,
        function_entry: u64,
        function_name: impl Into<String>,
    ) -> Self {
        Self {
            graph_type,
            function_entry,
            function_name: function_name.into(),
            include_block_boundaries: true,
            include_instruction_details: false,
            max_blocks: None,
            status: PCodeGraphTaskStatus::Pending,
            error_message: None,
        }
    }

    /// Create a basic-block CFG task.
    pub fn basic_block_cfg(function_entry: u64, function_name: impl Into<String>) -> Self {
        Self::new(PCodeCfgGraphType::BasicBlock, function_entry, function_name)
    }

    /// Create an instruction-level CFG task.
    pub fn instruction_cfg(function_entry: u64, function_name: impl Into<String>) -> Self {
        Self::new(
            PCodeCfgGraphType::Instruction,
            function_entry,
            function_name,
        )
    }

    /// Mark the task as running.
    pub fn start(&mut self) {
        self.status = PCodeGraphTaskStatus::Running;
    }

    /// Mark the task as completed.
    pub fn complete(&mut self) {
        self.status = PCodeGraphTaskStatus::Completed;
    }

    /// Mark the task as failed with an error message.
    pub fn fail(&mut self, message: impl Into<String>) {
        self.status = PCodeGraphTaskStatus::Failed;
        self.error_message = Some(message.into());
    }

    /// Mark the task as cancelled.
    pub fn cancel(&mut self) {
        self.status = PCodeGraphTaskStatus::Cancelled;
    }

    /// Whether the task is in a terminal state (completed, failed, or cancelled).
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            PCodeGraphTaskStatus::Completed
                | PCodeGraphTaskStatus::Failed
                | PCodeGraphTaskStatus::Cancelled
        )
    }
}

// ============================================================================
// PCodeDfgGraphTask
// ============================================================================

/// A task for building and displaying a P-code data-flow graph.
///
/// Port of Ghidra's `PCodeDfgGraphTask`. In the Java version, this extends
/// `Task` and runs on a background thread, constructing the DFG from the
/// decompiler's P-code and displaying it in a graph viewer.
#[derive(Debug, Clone)]
pub struct PCodeDfgGraphTask {
    /// The type of DFG to build.
    pub graph_type: PCodeDfgGraphType,
    /// The function entry address.
    pub function_entry: u64,
    /// The function name.
    pub function_name: String,
    /// Display options for the DFG.
    pub display_options: PCodeDfgDisplayOptions,
    /// Whether to include variable definitions and uses.
    pub include_var_def_use: bool,
    /// Whether to highlight the selected operation's dependencies.
    pub highlight_dependencies: bool,
    /// The selected operation address (if any).
    pub selected_op_address: Option<u64>,
    /// Maximum number of operations to display.
    pub max_operations: Option<usize>,
    /// Current status.
    pub status: PCodeGraphTaskStatus,
    /// Error message if status is Failed.
    pub error_message: Option<String>,
}

impl PCodeDfgGraphTask {
    /// Create a new PCode DFG graph task.
    pub fn new(
        graph_type: PCodeDfgGraphType,
        function_entry: u64,
        function_name: impl Into<String>,
    ) -> Self {
        Self {
            graph_type,
            function_entry,
            function_name: function_name.into(),
            display_options: PCodeDfgDisplayOptions::default(),
            include_var_def_use: true,
            highlight_dependencies: false,
            selected_op_address: None,
            max_operations: None,
            status: PCodeGraphTaskStatus::Pending,
            error_message: None,
        }
    }

    /// Create a full DFG task.
    pub fn full_dfg(function_entry: u64, function_name: impl Into<String>) -> Self {
        Self::new(PCodeDfgGraphType::Full, function_entry, function_name)
    }

    /// Create a selected-operations DFG task.
    pub fn selected_dfg(
        function_entry: u64,
        function_name: impl Into<String>,
        selected_address: u64,
    ) -> Self {
        let mut task = Self::new(
            PCodeDfgGraphType::Selected,
            function_entry,
            function_name,
        );
        task.selected_op_address = Some(selected_address);
        task.highlight_dependencies = true;
        task
    }

    /// Set the display options.
    pub fn with_display_options(mut self, options: PCodeDfgDisplayOptions) -> Self {
        self.display_options = options;
        self
    }

    /// Mark the task as running.
    pub fn start(&mut self) {
        self.status = PCodeGraphTaskStatus::Running;
    }

    /// Mark the task as completed.
    pub fn complete(&mut self) {
        self.status = PCodeGraphTaskStatus::Completed;
    }

    /// Mark the task as failed.
    pub fn fail(&mut self, message: impl Into<String>) {
        self.status = PCodeGraphTaskStatus::Failed;
        self.error_message = Some(message.into());
    }

    /// Whether the task is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            PCodeGraphTaskStatus::Completed
                | PCodeGraphTaskStatus::Failed
                | PCodeGraphTaskStatus::Cancelled
        )
    }
}

// ============================================================================
// SelectedPCodeDfgGraphTask
// ============================================================================

/// A task for building a DFG from selected P-code operations only.
///
/// Port of Ghidra's `SelectedPCodeDfgGraphTask`. This is a specialized variant
/// of `PCodeDfgGraphTask` that only includes operations selected by the user
/// in the decompiler view.
#[derive(Debug, Clone)]
pub struct SelectedPCodeDfgGraphTask {
    /// The parent DFG task configuration.
    pub parent_task: PCodeDfgGraphTask,
    /// Addresses of the selected operations.
    pub selected_op_addresses: Vec<u64>,
    /// Whether to include operations that use or define the same varnodes
    /// as the selected operations (expanding the selection).
    pub expand_to_varnode_users: bool,
    /// Whether to show only the direct data dependencies of the selection.
    pub direct_dependencies_only: bool,
}

impl SelectedPCodeDfgGraphTask {
    /// Create a new selected DFG task.
    pub fn new(
        function_entry: u64,
        function_name: impl Into<String>,
        selected_op_addresses: Vec<u64>,
    ) -> Self {
        Self {
            parent_task: PCodeDfgGraphTask::new(
                PCodeDfgGraphType::Selected,
                function_entry,
                function_name,
            ),
            selected_op_addresses,
            expand_to_varnode_users: true,
            direct_dependencies_only: false,
        }
    }

    /// Whether the selection includes the given operation address.
    pub fn includes_op(&self, address: u64) -> bool {
        self.selected_op_addresses.contains(&address)
    }

    /// Get the number of selected operations.
    pub fn selection_count(&self) -> usize {
        self.selected_op_addresses.len()
    }
}

// ============================================================================
// PCodeCombinedGraphTask
// ============================================================================

/// A task for building a combined CFG+DFG display.
///
/// Port of Ghidra's `PCodeCombinedGraphTask`. This combines both the
/// control-flow and data-flow views of a function into a single graph.
#[derive(Debug, Clone)]
pub struct PCodeCombinedGraphTask {
    /// The CFG task configuration.
    pub cfg_task: PCodeCfgGraphTask,
    /// The DFG task configuration.
    pub dfg_task: PCodeDfgGraphTask,
    /// Whether to overlay the DFG on top of the CFG.
    pub overlay_mode: bool,
    /// Whether to show edges between related nodes in both graphs.
    pub show_cross_links: bool,
    /// Current status.
    pub status: PCodeGraphTaskStatus,
}

impl PCodeCombinedGraphTask {
    /// Create a new combined graph task.
    pub fn new(
        function_entry: u64,
        function_name: impl Into<String>,
    ) -> Self {
        let name = function_name.into();
        Self {
            cfg_task: PCodeCfgGraphTask::basic_block_cfg(function_entry, &name),
            dfg_task: PCodeDfgGraphTask::full_dfg(function_entry, &name),
            overlay_mode: false,
            show_cross_links: true,
            status: PCodeGraphTaskStatus::Pending,
        }
    }

    /// Enable overlay mode (DFG drawn on top of CFG).
    pub fn with_overlay_mode(mut self, overlay: bool) -> Self {
        self.overlay_mode = overlay;
        self
    }

    /// Set whether to show cross-links between CFG and DFG nodes.
    pub fn with_cross_links(mut self, show: bool) -> Self {
        self.show_cross_links = show;
        self
    }

    /// Mark the combined task as running.
    pub fn start(&mut self) {
        self.status = PCodeGraphTaskStatus::Running;
        self.cfg_task.start();
        self.dfg_task.start();
    }

    /// Mark the combined task as completed.
    pub fn complete(&mut self) {
        self.status = PCodeGraphTaskStatus::Completed;
        self.cfg_task.complete();
        self.dfg_task.complete();
    }

    /// Whether both sub-tasks are in a terminal state.
    pub fn is_terminal(&self) -> bool {
        self.cfg_task.is_terminal() && self.dfg_task.is_terminal()
    }
}

// ============================================================================
// PCodeGraphDisplayListener
// ============================================================================

/// Trait for receiving notifications about P-code graph display events.
///
/// Port of Ghidra's `PCodeCfgDisplayListener` and `PCodeDfgDisplayListener`.
pub trait PCodeGraphDisplayListener: Send + Sync {
    /// Called when the graph has been constructed and is about to be displayed.
    fn on_graph_ready(&self, node_count: usize, edge_count: usize);

    /// Called when a node is selected in the graph.
    fn on_node_selected(&self, node_address: u64);

    /// Called when an edge is selected in the graph.
    fn on_edge_selected(&self, source_address: u64, target_address: u64);

    /// Called when the graph display is closed.
    fn on_display_closed(&self);

    /// Called when a graph construction error occurs.
    fn on_error(&self, message: &str);
}

/// A no-op implementation of the display listener.
#[derive(Debug, Clone, Default)]
pub struct NullPCodeGraphDisplayListener;

impl PCodeGraphDisplayListener for NullPCodeGraphDisplayListener {
    fn on_graph_ready(&self, _node_count: usize, _edge_count: usize) {}
    fn on_node_selected(&self, _node_address: u64) {}
    fn on_edge_selected(&self, _source_address: u64, _target_address: u64) {}
    fn on_display_closed(&self) {}
    fn on_error(&self, _message: &str) {}
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcode_cfg_graph_task_creation() {
        let task = PCodeCfgGraphTask::basic_block_cfg(0x1000, "main");
        assert_eq!(task.graph_type, PCodeCfgGraphType::BasicBlock);
        assert_eq!(task.function_entry, 0x1000);
        assert_eq!(task.function_name, "main");
        assert_eq!(task.status, PCodeGraphTaskStatus::Pending);
    }

    #[test]
    fn pcode_cfg_graph_task_lifecycle() {
        let mut task = PCodeCfgGraphTask::instruction_cfg(0x2000, "process");
        assert_eq!(task.status, PCodeGraphTaskStatus::Pending);
        assert!(!task.is_terminal());

        task.start();
        assert_eq!(task.status, PCodeGraphTaskStatus::Running);
        assert!(!task.is_terminal());

        task.complete();
        assert_eq!(task.status, PCodeGraphTaskStatus::Completed);
        assert!(task.is_terminal());
    }

    #[test]
    fn pcode_cfg_graph_task_fail() {
        let mut task = PCodeCfgGraphTask::new(
            PCodeCfgGraphType::BasicBlock,
            0x1000,
            "test",
        );
        task.fail("decompilation error");
        assert_eq!(task.status, PCodeGraphTaskStatus::Failed);
        assert_eq!(task.error_message.as_deref(), Some("decompilation error"));
        assert!(task.is_terminal());
    }

    #[test]
    fn pcode_cfg_graph_task_cancel() {
        let mut task = PCodeCfgGraphTask::new(
            PCodeCfgGraphType::BasicBlock,
            0x1000,
            "test",
        );
        task.start();
        task.cancel();
        assert_eq!(task.status, PCodeGraphTaskStatus::Cancelled);
        assert!(task.is_terminal());
    }

    #[test]
    fn pcode_dfg_graph_task_creation() {
        let task = PCodeDfgGraphTask::full_dfg(0x1000, "main");
        assert_eq!(task.graph_type, PCodeDfgGraphType::Full);
        assert!(task.include_var_def_use);
        assert!(!task.highlight_dependencies);
        assert!(task.selected_op_address.is_none());
    }

    #[test]
    fn pcode_dfg_graph_task_selected() {
        let task = PCodeDfgGraphTask::selected_dfg(0x1000, "main", 0x1020);
        assert_eq!(task.graph_type, PCodeDfgGraphType::Selected);
        assert_eq!(task.selected_op_address, Some(0x1020));
        assert!(task.highlight_dependencies);
    }

    #[test]
    fn pcode_dfg_graph_task_with_display_options() {
        let mut opts = PCodeDfgDisplayOptions::new();
        opts.show_constants = true;
        opts.max_depth = Some(5);

        let task = PCodeDfgGraphTask::new(
            PCodeDfgGraphType::Full,
            0x1000,
            "test",
        )
        .with_display_options(opts);

        assert!(task.display_options.show_constants);
        assert_eq!(task.display_options.max_depth, Some(5));
    }

    #[test]
    fn pcode_dfg_graph_task_lifecycle() {
        let mut task = PCodeDfgGraphTask::full_dfg(0x1000, "test");
        task.start();
        assert_eq!(task.status, PCodeGraphTaskStatus::Running);

        task.complete();
        assert!(task.is_terminal());
    }

    #[test]
    fn selected_pcode_dfg_graph_task() {
        let task = SelectedPCodeDfgGraphTask::new(
            0x1000,
            "main",
            vec![0x1020, 0x1030, 0x1040],
        );

        assert_eq!(task.selection_count(), 3);
        assert!(task.includes_op(0x1020));
        assert!(task.includes_op(0x1030));
        assert!(!task.includes_op(0x9999));
        assert!(task.expand_to_varnode_users);
        assert!(!task.direct_dependencies_only);
    }

    #[test]
    fn pcode_combined_graph_task() {
        let mut task = PCodeCombinedGraphTask::new(0x1000, "main")
            .with_overlay_mode(true)
            .with_cross_links(false);

        assert!(task.overlay_mode);
        assert!(!task.show_cross_links);

        task.start();
        assert_eq!(task.status, PCodeGraphTaskStatus::Running);
        assert_eq!(task.cfg_task.status, PCodeGraphTaskStatus::Running);
        assert_eq!(task.dfg_task.status, PCodeGraphTaskStatus::Running);

        task.complete();
        assert!(task.is_terminal());
    }

    #[test]
    fn pcode_graph_task_status_default() {
        assert_eq!(PCodeGraphTaskStatus::default(), PCodeGraphTaskStatus::Pending);
    }

    #[test]
    fn null_display_listener() {
        let listener = NullPCodeGraphDisplayListener;
        listener.on_graph_ready(10, 15);
        listener.on_node_selected(0x1000);
        listener.on_edge_selected(0x1000, 0x2000);
        listener.on_display_closed();
        listener.on_error("no error");
    }

    #[test]
    fn pcode_cfg_graph_task_max_blocks() {
        let mut task = PCodeCfgGraphTask::basic_block_cfg(0x1000, "big_func");
        task.max_blocks = Some(100);
        task.include_instruction_details = true;
        assert_eq!(task.max_blocks, Some(100));
        assert!(task.include_instruction_details);
    }
}
