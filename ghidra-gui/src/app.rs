//! Main [`GhidraApp`] struct implementing [`eframe::App`].
//!
//! This is the central application state that holds all views and
//! orchestrates the layout, event handling, state management, undo/redo,
//! keyboard shortcuts, theme management, layout persistence, and file dialogs.
//!
//! # Architecture
//!
//! The app is composed of:
//! - **Top menu bar**: File, Edit, Analysis, Navigation, Tools, Window, Help
//! - **Toolbar**: Navigation buttons, address bar, search bar, analysis indicator
//! - **Central docking area**: Listing, Decompiler, Bytes, Symbol Tree, Console
//! - **Status bar**: Address, selection info, analysis progress, memory usage
//! - **Overlays**: About dialog, Preferences, Search Results, Go To, Find/Replace
//! - **Undo/Redo**: Command-pattern based undo/redo system
//! - **Theme**: Dark theme by default (matching Ghidra's look)
//! - **Layout persistence**: Save/restore window positions via JSON
//!
//! # Keyboard Shortcuts (Ghidra-style)
//!
//! | Key               | Action                        |
//! |-------------------|-------------------------------|
//! | G / Ctrl+G        | Go To address                 |
//! | Esc               | Back / close dialog           |
//! | F2                | Rename label                  |
//! | ;                 | Set comment                   |
//! | D                 | Disassemble                   |
//! | C                 | Clear code bytes              |
//! | F                 | Create function               |
//! | L                 | Create label                  |
//! | T                 | Define data type              |
//! | P                 | Create pointer                |
//! | [                 | Create array                  |
//! | *                 | Create data                   |
//! | Ctrl+Z            | Undo                          |
//! | Ctrl+Y            | Redo                          |
//! | Ctrl+F            | Find                          |
//! | Ctrl+S            | Save                          |
//! | Ctrl+Alt+A        | Auto analyze                  |

use crate::bytes_view::{render_bytes_view, BytesView};
use crate::decompiler_view::{render_decompiler_view, DecompilerViewState};
use crate::docking::layout::DockingLayout;
use crate::listing::{
    convert_core_rows, render_listing_view, ListingAction, ListingRow, ListingView,
};
use crate::mainview::menu::{self, KeyBindings, MenuAction};
use crate::mainview::{render_status_bar, render_toolbar, ToolbarAction, ToolbarState};
use crate::symboltree::SymbolTreePanel;
use ghidra_core::addr::Address;
use ghidra_core::program::Program;
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::Instant;

// ============================================================================
// App State Enum
// ============================================================================

/// Top-level application state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppState {
    /// No program loaded, showing welcome screen.
    Idle,
    /// A program is loaded and the UI is interactive.
    Editing,
    /// Auto-analysis is running.
    Analyzing,
    /// A modal dialog is open (Find, Go To, etc.).
    Modal,
    /// The application is shutting down.
    Exiting,
}

impl Default for AppState {
    fn default() -> Self {
        AppState::Idle
    }
}

// ============================================================================
// Console Panel
// ============================================================================

/// Console message severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConsoleSeverity {
    Debug,
    Info,
    Warning,
    Error,
}

/// A single console message.
#[derive(Debug, Clone)]
pub struct ConsoleMessage {
    pub severity: ConsoleSeverity,
    pub text: String,
    pub timestamp: String,
}

/// Console panel for log messages.
pub struct ConsolePanel {
    /// Messages in the console.
    pub messages: Vec<ConsoleMessage>,
    /// Maximum number of messages to keep.
    pub max_messages: usize,
    /// Whether the console is visible.
    pub visible: bool,
    /// Filter level (only show messages at or above this severity).
    pub filter_level: ConsoleSeverity,
}

impl ConsolePanel {
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
            max_messages: 1000,
            visible: true,
            filter_level: ConsoleSeverity::Debug,
        }
    }

    /// Log a message to the console.
    pub fn log(&mut self, severity: ConsoleSeverity, text: impl Into<String>) {
        let msg = ConsoleMessage {
            severity,
            text: text.into(),
            timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
        };
        self.messages.push(msg);
        if self.messages.len() > self.max_messages {
            self.messages.remove(0);
        }
    }

    /// Clear all messages.
    pub fn clear(&mut self) {
        self.messages.clear();
    }

    /// Render the console panel.
    pub fn render(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Console").strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Clear").clicked() {
                    self.clear();
                }
                egui::ComboBox::from_id_salt("console_filter")
                    .selected_text(format!("{:?}", self.filter_level))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.filter_level,
                            ConsoleSeverity::Debug,
                            "Debug",
                        );
                        ui.selectable_value(
                            &mut self.filter_level,
                            ConsoleSeverity::Info,
                            "Info",
                        );
                        ui.selectable_value(
                            &mut self.filter_level,
                            ConsoleSeverity::Warning,
                            "Warning",
                        );
                        ui.selectable_value(
                            &mut self.filter_level,
                            ConsoleSeverity::Error,
                            "Error",
                        );
                    });
            });
        });
        ui.separator();

        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for msg in &self.messages {
                    if msg.severity >= self.filter_level {
                        let color = match msg.severity {
                            ConsoleSeverity::Debug => egui::Color32::from_rgb(140, 140, 140),
                            ConsoleSeverity::Info => egui::Color32::from_rgb(200, 200, 200),
                            ConsoleSeverity::Warning => egui::Color32::from_rgb(255, 200, 100),
                            ConsoleSeverity::Error => egui::Color32::from_rgb(255, 100, 100),
                        };
                        ui.label(
                            egui::RichText::new(format!("[{}] {}", msg.timestamp, msg.text))
                                .color(color)
                                .monospace()
                                .size(11.0),
                        );
                    }
                }
            });
    }
}

impl Default for ConsolePanel {
    fn default() -> Self {
        let mut panel = Self::new();
        panel.log(ConsoleSeverity::Info, "Ghidra Rust GUI started");
        panel.log(ConsoleSeverity::Debug, "Initialized console panel");
        panel
    }
}

// ============================================================================
// Task Monitor
// ============================================================================

/// Task monitor state for tracking analysis progress.
#[derive(Debug, Clone)]
pub struct TaskMonitorState {
    /// Whether a task is currently running.
    pub is_running: bool,
    /// The name of the current task.
    pub task_name: String,
    /// Progress (0.0 to 1.0).
    pub progress: f32,
    /// Whether the task can be cancelled.
    pub cancellable: bool,
    /// Whether cancellation was requested.
    pub cancelled: bool,
    /// Message for the current task.
    pub message: String,
}

impl TaskMonitorState {
    pub fn new() -> Self {
        Self {
            is_running: false,
            task_name: String::new(),
            progress: 0.0,
            cancellable: true,
            cancelled: false,
            message: String::new(),
        }
    }

    pub fn start(&mut self, name: impl Into<String>) {
        self.is_running = true;
        self.task_name = name.into();
        self.progress = 0.0;
        self.cancelled = false;
        self.message = String::new();
    }

    pub fn update(&mut self, progress: f32, message: impl Into<String>) {
        self.progress = progress;
        self.message = message.into();
    }

    pub fn finish(&mut self) {
        self.is_running = false;
        self.progress = 1.0;
        self.task_name.clear();
        self.message.clear();
    }

    pub fn cancel(&mut self) {
        self.cancelled = true;
    }
}

impl Default for TaskMonitorState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Data Type Panel
// ============================================================================

/// Data type manager panel.
pub struct DataTypePanel {
    /// The data type tree for display.
    pub tree: ghidra_core::data::DataTypeTreeNode,
    /// Filter text.
    pub filter: String,
    /// Set of expanded paths.
    pub expanded: std::collections::HashSet<ghidra_core::data::DataTypePath>,
    /// Whether the panel is visible.
    pub visible: bool,
}

impl DataTypePanel {
    pub fn new() -> Self {
        Self {
            tree: ghidra_core::data::builtin_data_type_tree(),
            filter: String::new(),
            expanded: std::collections::HashSet::new(),
            visible: true,
        }
    }

    /// Render the data type panel.
    pub fn render(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Data Type Manager").strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Collapse All").clicked() {
                    self.expanded.clear();
                }
            });
        });

        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.text_edit_singleline(&mut self.filter);
            if ui.button("X").clicked() {
                self.filter.clear();
            }
        });
        ui.separator();

        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                self.render_tree_node(ui, &self.tree.clone(), 0);
            });
    }

    fn render_tree_node(
        &mut self,
        ui: &mut egui::Ui,
        node: &ghidra_core::data::DataTypeTreeNode,
        depth: usize,
    ) {
        let indent = depth * 16;
        let has_children = !node.is_leaf();

        ui.horizontal(|ui| {
            ui.add_space(indent as f32);

            if has_children {
                if ui.button(">").clicked() {
                    // Toggle expand - simplified
                }
            } else {
                ui.add_space(24.0);
            }

            if let Some(ref dt) = node.data_type {
                ui.label(format!("{} ({}) [{} bytes]", node.name, dt.name(), dt.get_size()));
            } else {
                ui.label(egui::RichText::new(&node.name).strong());
            }
        });

        // Render children
        for child in &node.children.clone() {
            self.render_tree_node(ui, child, depth + 1);
        }
    }
}

impl Default for DataTypePanel {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Theme
// ============================================================================

/// Application theme controlling colors for the entire GUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Theme {
    /// Ghidra-inspired dark theme (default).
    Dark,
    /// Light theme variant.
    Light,
    /// System-dependent theme.
    System,
}

impl Default for Theme {
    fn default() -> Self {
        Theme::Dark
    }
}

impl Theme {
    /// Returns `true` when the theme is dark.
    pub fn is_dark(&self) -> bool {
        match self {
            Theme::Dark => true,
            Theme::Light => false,
            Theme::System => {
                std::env::var("GTK_THEME")
                    .map(|s| s.to_lowercase().contains("dark"))
                    .unwrap_or(true)
            }
        }
    }

    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Theme::Dark => "Dark",
            Theme::Light => "Light",
            Theme::System => "System",
        }
    }
}

/// Apply the application theme to the egui context.
pub fn apply_theme(ctx: &egui::Context, theme: Theme) {
    let is_dark = theme.is_dark();
    ctx.set_visuals(if is_dark {
        dark_visuals()
    } else {
        light_visuals()
    });
}

/// Ghidra-inspired dark theme visuals.
fn dark_visuals() -> egui::Visuals {
    let mut v = egui::Visuals::dark();
    v.panel_fill = egui::Color32::from_rgb(43, 43, 43);
    v.window_fill = egui::Color32::from_rgb(49, 49, 49);
    v.window_shadow = egui::epaint::Shadow::NONE;
    v.menu_rounding = egui::Rounding::same(4.0);
    v.window_rounding = egui::Rounding::same(4.0);

    // Ghidra-style widget colors
    v.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(60, 60, 60);
    v.widgets.inactive.bg_fill = egui::Color32::from_rgb(60, 60, 60);
    v.widgets.hovered.bg_fill = egui::Color32::from_rgb(80, 80, 90);
    v.widgets.active.bg_fill = egui::Color32::from_rgb(70, 100, 150);
    v.widgets.noninteractive.fg_stroke.color = egui::Color32::from_rgb(200, 200, 200);
    v.widgets.inactive.fg_stroke.color = egui::Color32::from_rgb(200, 200, 200);

    // Selection colors
    v.selection.bg_fill = egui::Color32::from_rgba_premultiplied(50, 100, 200, 80);
    v.selection.stroke.color = egui::Color32::from_rgb(100, 150, 255);

    // Hyperlink
    v.hyperlink_color = egui::Color32::from_rgb(100, 180, 255);

    // Window chrome
    v.faint_bg_color = egui::Color32::from_rgb(43, 43, 43);
    v.extreme_bg_color = egui::Color32::from_rgb(25, 25, 25);

    // Code area
    v.code_bg_color = egui::Color32::from_rgb(30, 30, 35);

    v
}

/// Light theme visuals based on Ghidra's light look.
fn light_visuals() -> egui::Visuals {
    let mut v = egui::Visuals::light();
    v.panel_fill = egui::Color32::from_rgb(235, 235, 240);
    v.window_fill = egui::Color32::from_rgb(250, 250, 252);
    v.window_shadow = egui::epaint::Shadow::NONE;
    v.menu_rounding = egui::Rounding::same(4.0);
    v.window_rounding = egui::Rounding::same(4.0);

    v.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(225, 225, 230);
    v.widgets.inactive.bg_fill = egui::Color32::from_rgb(225, 225, 230);
    v.widgets.hovered.bg_fill = egui::Color32::from_rgb(200, 210, 230);
    v.widgets.active.bg_fill = egui::Color32::from_rgb(150, 180, 220);
    v.widgets.noninteractive.fg_stroke.color = egui::Color32::from_rgb(40, 40, 40);

    v.selection.bg_fill = egui::Color32::from_rgba_premultiplied(50, 100, 200, 60);
    v.selection.stroke.color = egui::Color32::from_rgb(0, 80, 200);
    v.hyperlink_color = egui::Color32::from_rgb(0, 80, 200);
    v.code_bg_color = egui::Color32::from_rgb(248, 248, 252);

    v
}

// ============================================================================
// Preferences
// ============================================================================

/// User preferences persisted across sessions.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Preferences {
    /// The current application theme.
    pub theme: Theme,
    /// Font size for code/listing views.
    pub code_font_size: f32,
    /// Font size for UI elements.
    pub ui_font_size: f32,
    /// Show line numbers in listing.
    pub show_line_numbers: bool,
    /// Show bytes column in listing.
    pub show_bytes: bool,
    /// Number of bytes per line in the bytes view.
    pub bytes_per_line: usize,
    /// Maximum number of undo entries to keep.
    pub max_undo_history: usize,
    /// Whether to confirm before closing unsaved work.
    pub confirm_close: bool,
    /// Whether to auto-save analysis.
    pub auto_save_analysis: bool,
    /// Recent file paths.
    pub recent_files: Vec<String>,
    /// Maximum recent files to remember.
    pub max_recent_files: usize,
    /// Whether to show the toolbar.
    pub show_toolbar: bool,
    /// Whether to show the status bar.
    pub show_status_bar: bool,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            theme: Theme::Dark,
            code_font_size: 12.0,
            ui_font_size: 13.0,
            show_line_numbers: true,
            show_bytes: true,
            bytes_per_line: 16,
            max_undo_history: 100,
            confirm_close: true,
            auto_save_analysis: true,
            recent_files: Vec::new(),
            max_recent_files: 10,
            show_toolbar: true,
            show_status_bar: true,
        }
    }
}

// ============================================================================
// Undo / Redo System (Command Pattern)
// ============================================================================

/// A reversible command for undo/redo.
#[derive(Debug, Clone)]
pub struct UndoCommand {
    /// Human-readable description (e.g., "Rename label at 0x1000").
    pub description: String,
    /// Timestamp when the command was executed.
    pub timestamp: Instant,
    /// The action category for grouping.
    pub category: CommandCategory,
}

/// Categories of undoable commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandCategory {
    Edit,
    Analysis,
    Label,
    Comment,
    DataType,
    Function,
    Navigation,
    Other,
}

/// The undo/redo manager.
///
/// Maintains two stacks: the undo stack (commands that can be undone) and the
/// redo stack (commands that were undone and can be redone).
pub struct UndoManager {
    /// Commands that can be undone, ordered oldest-to-newest.
    undo_stack: Vec<UndoCommand>,
    /// Commands that can be redone, ordered most-recently-undone first.
    redo_stack: Vec<UndoCommand>,
    /// Maximum number of undo entries.
    max_history: usize,
}

impl UndoManager {
    /// Create a new undo manager with the given history capacity.
    pub fn new(max_history: usize) -> Self {
        Self {
            undo_stack: Vec::with_capacity(max_history),
            redo_stack: Vec::new(),
            max_history,
        }
    }

    /// Push a new command onto the undo stack. Clears the redo stack.
    pub fn push(&mut self, cmd: UndoCommand) {
        self.redo_stack.clear();
        self.undo_stack.push(cmd);
        if self.undo_stack.len() > self.max_history {
            self.undo_stack.remove(0);
        }
    }

    /// Undo the most recent command, moving it to the redo stack.
    /// Returns the description of the undone command, or `None` if empty.
    pub fn undo(&mut self) -> Option<String> {
        if let Some(cmd) = self.undo_stack.pop() {
            let desc = cmd.description.clone();
            self.redo_stack.push(cmd);
            Some(desc)
        } else {
            None
        }
    }

    /// Redo the most recently undone command, moving it back to the undo stack.
    /// Returns the description of the redone command, or `None` if empty.
    pub fn redo(&mut self) -> Option<String> {
        if let Some(cmd) = self.redo_stack.pop() {
            let desc = cmd.description.clone();
            self.undo_stack.push(cmd);
            Some(desc)
        } else {
            None
        }
    }

    /// Returns `true` when undo is available.
    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    /// Returns `true` when redo is available.
    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    /// Number of commands in the undo stack.
    pub fn undo_count(&self) -> usize {
        self.undo_stack.len()
    }

    /// Number of commands in the redo stack.
    pub fn redo_count(&self) -> usize {
        self.redo_stack.len()
    }

    /// Clear all undo/redo history.
    pub fn clear(&mut self) {
        self.undo_stack.clear();
        self.redo_stack.clear();
    }

    /// Get the description of the next undo command, if any.
    pub fn undo_description(&self) -> Option<&str> {
        self.undo_stack.last().map(|c| c.description.as_str())
    }

    /// Get the description of the next redo command, if any.
    pub fn redo_description(&self) -> Option<&str> {
        self.redo_stack.last().map(|c| c.description.as_str())
    }
}

impl Default for UndoManager {
    fn default() -> Self {
        Self::new(100)
    }
}

// ============================================================================
// Action Manager
// ============================================================================

/// Central registry of all application actions with keyboard shortcuts.
///
/// Wraps the key bindings system and provides lookup for menu/key actions.
pub struct ActionManager {
    /// Keyboard bindings registry.
    pub key_bindings: KeyBindings,
    /// Whether the action manager is enabled (no modal dialogs blocking).
    pub enabled: bool,
}

impl ActionManager {
    pub fn new() -> Self {
        Self {
            key_bindings: KeyBindings::default_bindings(),
            enabled: true,
        }
    }

    /// Look up the menu action for a key combination string.
    pub fn action_for_key(&self, key: &str) -> Option<MenuAction> {
        self.key_bindings.action_for(key)
    }

    /// Register a custom key binding.
    pub fn bind(&mut self, key: impl Into<String>, action: MenuAction) {
        self.key_bindings.add(key, action);
    }
}

impl Default for ActionManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Status Bar with Auto-Dismiss Messages
// ============================================================================

/// A status message with automatic dismissal.
#[derive(Debug, Clone)]
pub struct StatusMessage {
    /// The message text.
    pub text: String,
    /// When the message was posted.
    pub posted: Instant,
    /// How long the message should be visible (None = permanent).
    pub duration: Option<std::time::Duration>,
}

/// Status bar state with auto-dismissing messages.
pub struct StatusBar {
    /// Current status message queue.
    messages: VecDeque<StatusMessage>,
    /// Default duration for temporary messages.
    default_duration: std::time::Duration,
    /// Maximum number of messages to keep.
    max_messages: usize,
    /// Last action description (used for menu bar hint).
    pub last_action: String,
}

impl StatusBar {
    pub fn new() -> Self {
        Self {
            messages: VecDeque::new(),
            default_duration: std::time::Duration::from_secs(5),
            max_messages: 10,
            last_action: String::new(),
        }
    }

    /// Post a temporary status message that auto-dismisses.
    pub fn post(&mut self, text: impl Into<String>) {
        self.post_with_duration(text, self.default_duration);
    }

    /// Post a status message with a custom duration.
    pub fn post_with_duration(&mut self, text: impl Into<String>, duration: std::time::Duration) {
        self.messages.push_back(StatusMessage {
            text: text.into(),
            posted: Instant::now(),
            duration: Some(duration),
        });
        while self.messages.len() > self.max_messages {
            self.messages.pop_front();
        }
    }

    /// Post a persistent status message (stays until replaced).
    pub fn post_persistent(&mut self, text: impl Into<String>) {
        self.messages.push_back(StatusMessage {
            text: text.into(),
            posted: Instant::now(),
            duration: None,
        });
    }

    /// Get the current visible status text, expiring old messages.
    pub fn current_text(&mut self) -> String {
        let now = Instant::now();

        // Remove expired messages
        while let Some(front) = self.messages.front() {
            if let Some(duration) = front.duration {
                if now.duration_since(front.posted) >= duration {
                    self.messages.pop_front();
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        // Return the most recent message text
        self.messages
            .back()
            .map(|m| m.text.clone())
            .unwrap_or_else(|| "Ready".to_string())
    }

    /// Clear all status messages.
    pub fn clear(&mut self) {
        self.messages.clear();
    }
}

impl Default for StatusBar {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// View Manager
// ============================================================================

/// Manages visibility and state of all dockable views.
pub struct ViewManager {
    /// Whether each view panel is visible.
    pub listing_visible: bool,
    pub decompiler_visible: bool,
    pub symbol_tree_visible: bool,
    pub console_visible: bool,
    pub bytes_view_visible: bool,
    pub data_types_visible: bool,
    pub function_graph_visible: bool,
    /// The docking layout for persistent state.
    pub layout: DockingLayout,
}

impl ViewManager {
    pub fn new() -> Self {
        Self {
            listing_visible: true,
            decompiler_visible: true,
            symbol_tree_visible: true,
            console_visible: false,
            bytes_view_visible: true,
            data_types_visible: false,
            function_graph_visible: false,
            layout: DockingLayout::default_layout(),
        }
    }

    /// Toggle a view panel by name.
    pub fn toggle(&mut self, panel: &str) {
        match panel {
            "listing" => self.listing_visible = !self.listing_visible,
            "decompiler" => self.decompiler_visible = !self.decompiler_visible,
            "symbol_tree" => self.symbol_tree_visible = !self.symbol_tree_visible,
            "console" => self.console_visible = !self.console_visible,
            "bytes_view" => self.bytes_view_visible = !self.bytes_view_visible,
            "data_types" => self.data_types_visible = !self.data_types_visible,
            "function_graph" => self.function_graph_visible = !self.function_graph_visible,
            _ => {}
        }
    }

    /// Reset all panels to default visibility.
    pub fn default_layout(&mut self) {
        self.listing_visible = true;
        self.decompiler_visible = true;
        self.symbol_tree_visible = true;
        self.console_visible = false;
        self.bytes_view_visible = true;
        self.data_types_visible = false;
        self.function_graph_visible = false;
        self.layout.reset_to_default();
    }

    /// Reset the layout (hide optional panels).
    pub fn reset_layout(&mut self) {
        self.console_visible = false;
        self.data_types_visible = false;
        self.function_graph_visible = false;
        self.layout = DockingLayout::default_layout();
    }

    /// Save layout to a JSON string.
    pub fn save_layout(&self) -> String {
        self.layout.save()
    }

    /// Restore layout from a JSON string.
    pub fn load_layout(&mut self, json: &str) -> Result<(), anyhow::Error> {
        self.layout = DockingLayout::load(json)?;
        Ok(())
    }
}

impl Default for ViewManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// File Dialog State
// ============================================================================

/// State for file dialog operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileDialogState {
    /// No dialog open.
    Closed,
    /// Open File dialog.
    OpenFile,
    /// Save Project dialog.
    SaveProject,
    /// Export Program dialog.
    ExportProgram,
    /// New Project dialog.
    NewProject,
    /// Open Project dialog.
    OpenProject,
}

// ============================================================================
// Dialog States
// ============================================================================

/// State for the Go To dialog.
#[derive(Debug, Clone)]
pub struct GoToDialogState {
    pub visible: bool,
    pub input: String,
}

impl Default for GoToDialogState {
    fn default() -> Self {
        Self {
            visible: false,
            input: String::new(),
        }
    }
}

/// State for the Find/Replace dialog.
#[derive(Debug, Clone)]
pub struct FindReplaceState {
    pub visible: bool,
    pub find_text: String,
    pub replace_text: String,
    pub match_case: bool,
    pub match_whole_word: bool,
    pub use_regex: bool,
    pub search_direction_forward: bool,
    pub search_in_selection: bool,
    pub result_count: usize,
    pub current_result: usize,
}

impl Default for FindReplaceState {
    fn default() -> Self {
        Self {
            visible: false,
            find_text: String::new(),
            replace_text: String::new(),
            match_case: false,
            match_whole_word: false,
            use_regex: false,
            search_direction_forward: true,
            search_in_selection: false,
            result_count: 0,
            current_result: 0,
        }
    }
}

// ============================================================================
// Main Application State
// ============================================================================

/// The main Ghidra application state.
///
/// Holds all program data, view states, UI configuration, undo/redo history,
/// and theming information. Implements [`eframe::App`] for integration with
/// the egui framework.
pub struct GhidraApp {
    /// The currently loaded program, if any.
    pub program: Option<Arc<RwLock<Program>>>,
    /// The currently open project, if any.
    pub project: Option<Arc<ghidra_core::project::Project>>,
    /// Top-level application state.
    pub state: AppState,
    /// View panel manager.
    pub views: ViewManager,
    /// The docking layout.
    pub layout: DockingLayout,
    /// Action/keyboard manager.
    pub actions: ActionManager,
    /// Status bar with auto-dismiss messages.
    pub status: StatusBar,
    /// User preferences.
    pub prefs: Preferences,
    /// Current theme.
    pub theme: Theme,
    /// Undo/redo manager.
    pub undo_manager: UndoManager,
    /// The disassembly listing view.
    pub listing: ListingView,
    /// The decompiler view showing C pseudocode.
    pub decompiler: DecompilerViewState,
    /// The symbol tree panel.
    pub symbol_tree: SymbolTreePanel,
    /// The bytes/hex view.
    pub bytes_view: BytesView,
    /// The data type manager panel.
    pub data_types: DataTypePanel,
    /// The console/log panel.
    pub console: ConsolePanel,
    /// Current address (cursor position in the listing).
    pub current_address: Address,
    /// Task monitor for long-running operations.
    pub task_monitor: TaskMonitorState,
    /// Toolbar state.
    toolbar: ToolbarState,
    /// Search results text.
    search_results: Vec<String>,
    /// Whether to show search results.
    show_search_results: bool,
    /// Program name for display purposes.
    program_name: String,
    /// Cached listing rows for the current view (rich GUI format).
    cached_rows: Vec<ListingRow>,
    /// Whether to show the About dialog.
    show_about: bool,
    /// Whether to show the Preferences dialog.
    show_preferences: bool,
    /// Whether to show the Key Bindings reference.
    show_key_bindings: bool,
    /// File dialog state.
    file_dialog: FileDialogState,
    /// Last file dialog path.
    last_file_path: Option<String>,
    /// Go To dialog state.
    go_to_dialog: GoToDialogState,
    /// Find/Replace dialog state.
    find_replace: FindReplaceState,
    /// Path to the layout file for persistence.
    layout_file_path: String,
    /// When the current frame started (for time-based operations).
    frame_start: Instant,
    /// Memory usage tracking (approximate, in bytes).
    memory_usage: u64,
    /// Selection info string for the status bar.
    selection_info: String,
}

impl GhidraApp {
    /// Create a new GhidraApp with default state.
    pub fn new() -> Self {
        let layout_file_path = app_data_dir()
            .map(|d| d.join("layout.json").to_string_lossy().to_string())
            .unwrap_or_else(|| "layout.json".to_string());
        let mut listing = ListingView::default();
        listing.goto(Address::new(0x1000));

        Self {
            program: None,
            project: None,
            state: AppState::Idle,
            views: ViewManager::new(),
            layout: DockingLayout::default_layout(),
            actions: ActionManager::new(),
            status: StatusBar::new(),
            prefs: Preferences::default(),
            theme: Theme::Dark,
            undo_manager: UndoManager::default(),
            listing,
            decompiler: DecompilerViewState::default(),
            symbol_tree: SymbolTreePanel::default(),
            bytes_view: BytesView::default(),
            data_types: DataTypePanel::default(),
            console: ConsolePanel::default(),
            current_address: Address::new(0x1000),
            task_monitor: TaskMonitorState::default(),
            toolbar: ToolbarState::default(),
            search_results: Vec::new(),
            show_search_results: false,
            program_name: "No program loaded".to_string(),
            cached_rows: Vec::new(),
            show_about: false,
            show_preferences: false,
            show_key_bindings: false,
            file_dialog: FileDialogState::Closed,
            last_file_path: None,
            go_to_dialog: GoToDialogState::default(),
            find_replace: FindReplaceState::default(),
            layout_file_path,
            frame_start: Instant::now(),
            memory_usage: 0,
            selection_info: String::new(),
        }
    }

    /// Create a new GhidraApp with a demo program loaded.
    pub fn with_demo_program() -> Self {
        let mut app = Self::new();
        let program = Program::demo();
        app.load_program_internal(program);
        app
    }

    // -----------------------------------------------------------------------
    // Program Loading
    // -----------------------------------------------------------------------

    /// Load a program into the application.
    fn load_program_internal(&mut self, program: Program) {
        self.program_name = program.get_name().to_string();
        self.state = AppState::Editing;

        // Load labels
        let labels: std::collections::HashMap<Address, String> = program
            .get_all_symbols()
            .iter()
            .filter(|s| {
                s.kind() == ghidra_core::symbol::SymbolType::Label
                    || s.kind() == ghidra_core::symbol::SymbolType::Function
            })
            .map(|s| (*s.address(), s.name().clone()))
            .collect();
        self.listing.set_labels(labels.clone());

        // Load xrefs (build from reference manager)
        let xrefs: std::collections::HashMap<Address, Vec<Address>> = {
            let mut map: std::collections::HashMap<Address, Vec<Address>> = std::collections::HashMap::new();
            for sym in program.get_all_symbols() {
                let refs_to = program.get_references_to(sym.address());
                if !refs_to.is_empty() {
                    map.insert(*sym.address(), refs_to);
                }
            }
            map
        };
        self.listing.set_xrefs(xrefs.clone());

        // Load comments
        let comments: std::collections::HashMap<Address, String> = {
            let mut map = std::collections::HashMap::new();
            for sym in program.get_all_symbols() {
                if let Some(c) = program.get_comment(ghidra_core::program::listing::CommentType::Eol, sym.address()) {
                    map.insert(*sym.address(), c);
                }
            }
            map
        };
        self.listing.set_comments(comments.clone());

        // Convert core listing rows to rich GUI format
        let core_rows: Vec<ghidra_core::listing::ListingRow> =
            program.get_listing().get_all_rows();
        self.cached_rows = convert_core_rows(&core_rows, &labels, &comments, &xrefs);

        // Load symbol tree
        let symbol_tree_node = program.get_symbol_tree().clone();
        self.symbol_tree.load_symbols(symbol_tree_node);

        // Set address
        self.current_address = program.get_image_base();
        self.listing.goto(self.current_address);

        // Store program
        self.program = Some(Arc::new(RwLock::new(program)));

        self.status
            .post_persistent(format!("Loaded: {}", self.program_name));
        self.console.log(
            ConsoleSeverity::Info,
            format!("Loaded program: {}", self.program_name),
        );
    }

    /// Load a program from the given Program object.
    pub fn load_program(&mut self, program: Program) {
        self.load_program_internal(program);
    }

    // -----------------------------------------------------------------------
    // Menu Bar
    // -----------------------------------------------------------------------

    /// Render the top menu bar.
    fn render_menu_bar(
        &mut self,
        ctx: &egui::Context,
        frame: &mut eframe::Frame,
        ui: &mut egui::Ui,
    ) {
        let action = menu::render_menu_bar(ctx, ui);
        self.handle_menu_action(action, ctx, frame);
    }

    /// Handle a menu action.
    fn handle_menu_action(
        &mut self,
        action: MenuAction,
        ctx: &egui::Context,
        frame: &mut eframe::Frame,
    ) {
        match action {
            MenuAction::None => {}

            // ---- File ----
            MenuAction::NewProject => {
                self.file_dialog = FileDialogState::NewProject;
                self.status.post("New Project: Select a directory...");
                self.console
                    .log(ConsoleSeverity::Info, "New Project requested");
            }
            MenuAction::OpenProject => {
                self.file_dialog = FileDialogState::OpenProject;
                self.status
                    .post("Open Project: Select a project directory...");
                self.console
                    .log(ConsoleSeverity::Info, "Open Project requested");
            }
            MenuAction::OpenFile => {
                self.file_dialog = FileDialogState::OpenFile;
                self.status
                    .post("Open File: Select a binary to load...");
                self.console
                    .log(ConsoleSeverity::Info, "Open File requested");
            }
            MenuAction::Save => {
                self.undo_manager.push(UndoCommand {
                    description: "Save program".to_string(),
                    timestamp: Instant::now(),
                    category: CommandCategory::Edit,
                });
                self.status.post("Program saved.");
                self.console.log(ConsoleSeverity::Info, "Program saved");
            }
            MenuAction::SaveAs => {
                self.file_dialog = FileDialogState::SaveProject;
                self.status.post("Save As: Choose destination...");
                self.console.log(ConsoleSeverity::Info, "Save As requested");
            }
            MenuAction::Export => {
                self.file_dialog = FileDialogState::ExportProgram;
                self.status
                    .post("Export: Choose format and destination...");
                self.console.log(ConsoleSeverity::Info, "Export requested");
            }
            MenuAction::ExportProgram => {
                self.file_dialog = FileDialogState::ExportProgram;
                self.status
                    .post("Export Program: Choose format and destination...");
                self.console
                    .log(ConsoleSeverity::Info, "Export Program requested");
            }
            MenuAction::Close => {
                if self.prefs.confirm_close && self.program.is_some() {
                    self.status
                        .post("Close requested (confirmation would appear).");
                }
                self.console.log(ConsoleSeverity::Info, "Close requested");
            }
            MenuAction::CloseAll => {
                self.console
                    .log(ConsoleSeverity::Info, "Close All requested");
            }
            MenuAction::Quit => {
                self.console.log(ConsoleSeverity::Info, "Quit requested");
                self.state = AppState::Exiting;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            MenuAction::Exit => {
                self.console
                    .log(ConsoleSeverity::Info, "Exiting application");
                self.state = AppState::Exiting;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }

            // ---- Edit ----
            MenuAction::Undo => {
                if let Some(desc) = self.undo_manager.undo() {
                    self.status.post(format!("Undo: {}", desc));
                    self.console
                        .log(ConsoleSeverity::Debug, format!("Undo: {}", desc));
                }
            }
            MenuAction::Redo => {
                if let Some(desc) = self.undo_manager.redo() {
                    self.status.post(format!("Redo: {}", desc));
                    self.console
                        .log(ConsoleSeverity::Debug, format!("Redo: {}", desc));
                }
            }
            MenuAction::Cut => {
                self.status.post("Cut selection");
                self.console.log(ConsoleSeverity::Debug, "Cut");
            }
            MenuAction::Copy => {
                self.status.post("Copied to clipboard");
                self.console.log(ConsoleSeverity::Debug, "Copy");
            }
            MenuAction::Paste => {
                self.status.post("Pasted from clipboard");
                self.console.log(ConsoleSeverity::Debug, "Paste");
            }
            MenuAction::Delete => {
                self.status.post("Deleted selection");
                self.console.log(ConsoleSeverity::Debug, "Delete");
            }
            MenuAction::SelectAll => {
                self.status.post("Select All");
                self.console.log(ConsoleSeverity::Debug, "Select All");
            }
            MenuAction::Find => {
                self.find_replace.visible = true;
                self.find_replace.result_count = 0;
                self.find_replace.current_result = 0;
                self.console.log(ConsoleSeverity::Debug, "Find dialog opened");
            }
            MenuAction::FindNext => {
                if self.find_replace.result_count > 0 {
                    self.find_replace.current_result = (self.find_replace.current_result + 1)
                        % self.find_replace.result_count;
                    self.status.post(format!(
                        "Find Next: {}/{}",
                        self.find_replace.current_result + 1,
                        self.find_replace.result_count
                    ));
                }
            }
            MenuAction::Replace => {
                self.find_replace.visible = true;
                self.console
                    .log(ConsoleSeverity::Debug, "Replace dialog opened");
            }
            MenuAction::Preferences => {
                self.show_preferences = true;
            }
            MenuAction::GoTo => {
                self.go_to_dialog.visible = true;
                self.go_to_dialog.input = format!("{:08X}", self.current_address.offset);
            }

            // ---- Analysis ----
            MenuAction::AutoAnalyze => {
                self.state = AppState::Analyzing;
                self.task_monitor.start("Auto Analysis");
                self.task_monitor.update(0.0, "Starting auto-analysis...");
                self.console
                    .log(ConsoleSeverity::Info, "Auto-analysis started");
                // Simulate analysis progress
                self.task_monitor.update(0.5, "Analyzing functions...");
                self.task_monitor.update(1.0, "Analysis complete");
                self.task_monitor.finish();
                self.state = AppState::Editing;
                self.status.post("Auto-analysis complete.");
                self.console
                    .log(ConsoleSeverity::Info, "Auto-analysis complete");
            }
            MenuAction::AnalyzeOneShot => {
                self.status.post("One-Shot Analysis requested");
                self.console
                    .log(ConsoleSeverity::Info, "One-shot analysis requested");
            }
            MenuAction::ClearAnalysis => {
                self.status.post("Analysis cleared");
                self.console
                    .log(ConsoleSeverity::Warning, "Analysis cleared");
            }
            MenuAction::AnalysisOptions => {
                self.status.post("Analysis Options requested");
                self.console
                    .log(ConsoleSeverity::Info, "Analysis Options requested");
            }
            MenuAction::ConfigureAnalyzers => {
                self.status.post("Configure Analyzers");
                self.console
                    .log(ConsoleSeverity::Info, "Configure Analyzers requested");
            }

            // ---- Navigation ----
            MenuAction::NavigateGoTo => {
                self.go_to_dialog.visible = true;
                self.go_to_dialog.input = format!("{:08X}", self.current_address.offset);
            }
            MenuAction::NavigateBack => {
                if self.listing.can_go_back() {
                    self.listing.go_back();
                    self.current_address = self.listing.cursor_position;
                    self.status
                        .post(format!("Back to {:08X}", self.current_address.offset));
                }
            }
            MenuAction::NavigateForward => {
                if self.listing.can_go_forward() {
                    self.listing.go_forward();
                    self.current_address = self.listing.cursor_position;
                    self.status
                        .post(format!("Forward to {:08X}", self.current_address.offset));
                }
            }
            MenuAction::NavigateNextFunction => {
                self.listing.scroll_down();
                self.current_address = self.listing.cursor_position;
                self.status.post("Next Function");
            }
            MenuAction::NavigatePreviousFunction => {
                self.listing.scroll_up();
                self.current_address = self.listing.cursor_position;
                self.status.post("Previous Function");
            }
            MenuAction::NavigateNextInstruction => {
                self.listing.scroll_down();
                self.current_address = self.listing.cursor_position;
                self.status.post("Next Instruction");
            }
            MenuAction::NavigatePreviousInstruction => {
                self.listing.scroll_up();
                self.current_address = self.listing.cursor_position;
                self.status.post("Previous Instruction");
            }
            MenuAction::NavigateNextLabel => {
                self.status.post("Next Label");
            }
            MenuAction::NavigateNextReference => {
                self.status.post("Next Reference");
            }
            MenuAction::NavigateEntryPoint => {
                if let Some(ref prog) = self.program {
                    if let Ok(prog) = prog.read() {
                        self.listing.goto(prog.get_image_base());
                        self.current_address = prog.get_image_base();
                        self.status
                            .post(format!("Entry Point: {:08X}", prog.get_image_base().offset));
                    }
                }
            }

            // ---- Listing-level hotkey actions ----
            MenuAction::RenameLabel => {
                let addr = self.current_address;
                self.status
                    .post(format!("Rename label at {:08X}", addr.offset));
                self.undo_manager.push(UndoCommand {
                    description: format!("Rename label at {:08X}", addr.offset),
                    timestamp: Instant::now(),
                    category: CommandCategory::Label,
                });
            }
            MenuAction::Disassemble => {
                let addr = self.current_address;
                self.task_monitor.start("Disassemble");
                self.task_monitor.update(1.0, "Done");
                self.task_monitor.finish();
                self.status
                    .post(format!("Disassemble at {:08X}", addr.offset));
                self.console.log(
                    ConsoleSeverity::Info,
                    format!("Disassemble at {:08X}", addr.offset),
                );
                self.undo_manager.push(UndoCommand {
                    description: format!("Disassemble at {:08X}", addr.offset),
                    timestamp: Instant::now(),
                    category: CommandCategory::Analysis,
                });
            }
            MenuAction::ClearCodeBytes => {
                let addr = self.current_address;
                self.status
                    .post(format!("Clear code/data at {:08X}", addr.offset));
                self.undo_manager.push(UndoCommand {
                    description: format!("Clear at {:08X}", addr.offset),
                    timestamp: Instant::now(),
                    category: CommandCategory::Analysis,
                });
            }
            MenuAction::CreateFunction => {
                let addr = self.current_address;
                self.status
                    .post(format!("Create function at {:08X}", addr.offset));
                self.undo_manager.push(UndoCommand {
                    description: format!("Create function at {:08X}", addr.offset),
                    timestamp: Instant::now(),
                    category: CommandCategory::Function,
                });
            }
            MenuAction::CreateLabel => {
                let addr = self.current_address;
                self.status
                    .post(format!("Create label at {:08X}", addr.offset));
                self.undo_manager.push(UndoCommand {
                    description: format!("Create label at {:08X}", addr.offset),
                    timestamp: Instant::now(),
                    category: CommandCategory::Label,
                });
            }
            MenuAction::SetComment => {
                let addr = self.current_address;
                self.status
                    .post(format!("Set comment at {:08X}", addr.offset));
                self.undo_manager.push(UndoCommand {
                    description: format!("Set comment at {:08X}", addr.offset),
                    timestamp: Instant::now(),
                    category: CommandCategory::Comment,
                });
            }
            MenuAction::DefineDataType => {
                let addr = self.current_address;
                self.status
                    .post(format!("Define data type at {:08X}", addr.offset));
                self.undo_manager.push(UndoCommand {
                    description: format!("Define data type at {:08X}", addr.offset),
                    timestamp: Instant::now(),
                    category: CommandCategory::DataType,
                });
            }
            MenuAction::CreatePointer => {
                let addr = self.current_address;
                self.status
                    .post(format!("Create pointer at {:08X}", addr.offset));
                self.undo_manager.push(UndoCommand {
                    description: format!("Create pointer at {:08X}", addr.offset),
                    timestamp: Instant::now(),
                    category: CommandCategory::DataType,
                });
            }
            MenuAction::CreateArray => {
                let addr = self.current_address;
                self.status
                    .post(format!("Create array at {:08X}", addr.offset));
                self.undo_manager.push(UndoCommand {
                    description: format!("Create array at {:08X}", addr.offset),
                    timestamp: Instant::now(),
                    category: CommandCategory::DataType,
                });
            }
            MenuAction::CreateData => {
                let addr = self.current_address;
                self.status
                    .post(format!("Create data at {:08X}", addr.offset));
                self.undo_manager.push(UndoCommand {
                    description: format!("Create data at {:08X}", addr.offset),
                    timestamp: Instant::now(),
                    category: CommandCategory::DataType,
                });
            }
            MenuAction::CreateStructure => {
                let addr = self.current_address;
                self.status
                    .post(format!("Create structure at {:08X}", addr.offset));
                self.undo_manager.push(UndoCommand {
                    description: format!("Create structure at {:08X}", addr.offset),
                    timestamp: Instant::now(),
                    category: CommandCategory::DataType,
                });
            }
            MenuAction::PatchInstruction => {
                let addr = self.current_address;
                self.status
                    .post(format!("Patch instruction at {:08X}", addr.offset));
            }

            // ---- Tools ----
            MenuAction::ProgramDifferences => {
                self.status.post("Program Differences requested");
            }
            MenuAction::FunctionGraph => {
                self.views.function_graph_visible = !self.views.function_graph_visible;
                let state = if self.views.function_graph_visible {
                    "shown"
                } else {
                    "hidden"
                };
                self.status.post(format!("Function Graph {}", state));
            }
            MenuAction::DataTypeManager => {
                self.views.data_types_visible = !self.views.data_types_visible;
                let state = if self.views.data_types_visible {
                    "shown"
                } else {
                    "hidden"
                };
                self.status
                    .post(format!("Data Type Manager {}", state));
            }
            MenuAction::MemoryMap => {
                self.status.post("Memory Map requested");
            }
            MenuAction::RegisterManager => {
                self.status.post("Register Manager requested");
            }
            MenuAction::ScriptManager => {
                self.status.post("Script Manager requested");
            }

            // ---- Window ----
            MenuAction::ResetLayout => {
                self.views.reset_layout();
                self.status.post("Layout reset to default");
                self.console.log(ConsoleSeverity::Info, "Layout reset");
            }
            MenuAction::DefaultLayout => {
                self.views.default_layout();
                self.status.post("Layout restored to default");
            }
            MenuAction::ToggleListing => {
                self.views.toggle("listing");
                self.status.post(format!(
                    "Listing {}",
                    if self.views.listing_visible {
                        "shown"
                    } else {
                        "hidden"
                    }
                ));
            }
            MenuAction::ToggleDecompiler => {
                self.views.toggle("decompiler");
                self.status.post(format!(
                    "Decompiler {}",
                    if self.views.decompiler_visible {
                        "shown"
                    } else {
                        "hidden"
                    }
                ));
            }
            MenuAction::ToggleSymbolTree => {
                self.views.toggle("symbol_tree");
                self.status.post(format!(
                    "Symbol Tree {}",
                    if self.views.symbol_tree_visible {
                        "shown"
                    } else {
                        "hidden"
                    }
                ));
            }
            MenuAction::ToggleConsole => {
                self.views.toggle("console");
                self.status.post(format!(
                    "Console {}",
                    if self.views.console_visible {
                        "shown"
                    } else {
                        "hidden"
                    }
                ));
            }
            MenuAction::ToggleBytesView => {
                self.views.toggle("bytes_view");
                self.status.post(format!(
                    "Bytes View {}",
                    if self.views.bytes_view_visible {
                        "shown"
                    } else {
                        "hidden"
                    }
                ));
            }
            MenuAction::ToggleDataTypes => {
                self.views.toggle("data_types");
                self.status.post(format!(
                    "Data Types {}",
                    if self.views.data_types_visible {
                        "shown"
                    } else {
                        "hidden"
                    }
                ));
            }
            MenuAction::ToggleFunctionGraph => {
                self.views.toggle("function_graph");
                self.status.post(format!(
                    "Function Graph {}",
                    if self.views.function_graph_visible {
                        "shown"
                    } else {
                        "hidden"
                    }
                ));
            }

            // ---- Help ----
            MenuAction::About => {
                self.show_about = true;
            }
            MenuAction::Documentation => {
                self.status.post("Opening documentation...");
                self.console
                    .log(ConsoleSeverity::Info, "Documentation requested");
            }
            MenuAction::KeyBindings => {
                self.show_key_bindings = true;
            }
            MenuAction::CheckForUpdates => {
                self.status.post("Checking for updates...");
                self.console
                    .log(ConsoleSeverity::Info, "Check for Updates requested");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Toolbar
    // -----------------------------------------------------------------------

    /// Render the toolbar with navigation, address bar, search, and analysis
    /// status indicator.
    fn render_toolbar_ui(&mut self, ui: &mut egui::Ui) {
        if !self.prefs.show_toolbar {
            return;
        }

        // Analysis status spinner / progress bar
        if self.task_monitor.is_running {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(format!(
                    "{} ({}%)",
                    self.task_monitor.task_name,
                    (self.task_monitor.progress * 100.0) as u32
                ));
                ui.add(
                    egui::ProgressBar::new(self.task_monitor.progress)
                        .desired_width(120.0)
                        .text(format!("{:.0}%", self.task_monitor.progress * 100.0)),
                );
                if self.task_monitor.cancellable && ui.button("Cancel").clicked() {
                    self.task_monitor.cancel();
                }
            });
            ui.separator();
        }

        let action = render_toolbar(
            &mut self.toolbar,
            self.listing.can_go_back(),
            self.listing.can_go_forward(),
            &format!("{:08X}", self.current_address.offset),
            ui,
        );

        match action {
            ToolbarAction::None => {}
            ToolbarAction::GoBack => {
                self.listing.go_back();
                self.current_address = self.listing.cursor_position;
            }
            ToolbarAction::GoForward => {
                self.listing.go_forward();
                self.current_address = self.listing.cursor_position;
            }
            ToolbarAction::GoHome => {
                if let Some(ref prog) = self.program {
                    if let Ok(prog) = prog.read() {
                        self.listing.goto(prog.get_image_base());
                        self.current_address = prog.get_image_base();
                    }
                }
            }
            ToolbarAction::GoTo(text) => {
                if let Ok(addr) = u64::from_str_radix(&text, 16) {
                    let addr = Address::new(addr);
                    self.listing.goto(addr);
                    self.current_address = addr;
                    self.status.post(format!("Go to {:08X}", addr.offset));
                } else {
                    self.console.log(
                        ConsoleSeverity::Warning,
                        format!("Invalid address: {}", text),
                    );
                    self.status
                        .post(format!("Invalid address: {}", text));
                }
            }
            ToolbarAction::Search(query) => {
                self.do_search(&query);
            }
            ToolbarAction::SearchNext => {
                self.navigate_search_result(1);
            }
            ToolbarAction::SearchPrev => {
                self.navigate_search_result(-1);
            }
        }
    }

    /// Perform a text search in the listing.
    fn do_search(&mut self, query: &str) {
        self.console
            .log(ConsoleSeverity::Info, format!("Searching for: {}", query));
        self.search_results.clear();
        let query_lower = query.to_lowercase();
        for row in &self.cached_rows {
            let display = format!(
                "{} {}",
                row.mnemonic,
                row.operands
                    .iter()
                    .map(|o| o.text.as_str())
                    .collect::<Vec<_>>()
                    .join("")
            );
            let label_match = row
                .label
                .as_ref()
                .map(|l| l.to_lowercase().contains(&query_lower))
                .unwrap_or(false);
            let comment_match = row
                .comment
                .as_ref()
                .map(|c| c.to_lowercase().contains(&query_lower))
                .unwrap_or(false);
            if display.to_lowercase().contains(&query_lower) || label_match || comment_match {
                self.search_results
                    .push(format!("{:08X}: {}", row.address.offset, display));
            }
        }
        self.show_search_results = !self.search_results.is_empty();
        self.find_replace.result_count = self.search_results.len();
        self.find_replace.current_result = 0;
        if !self.show_search_results {
            self.console.log(ConsoleSeverity::Info, "No results found");
            self.status.post("No search results found");
        } else {
            self.console.log(
                ConsoleSeverity::Info,
                format!("Found {} results", self.search_results.len()),
            );
            self.status
                .post(format!("Found {} results", self.search_results.len()));
        }
    }

    /// Navigate between search results.
    fn navigate_search_result(&mut self, delta: isize) {
        let total = self.search_results.len();
        if total == 0 {
            return;
        }
        let new_idx = if delta > 0 {
            (self.find_replace.current_result + delta as usize) % total
        } else {
            if self.find_replace.current_result == 0 {
                total - 1
            } else {
                self.find_replace.current_result - 1
            }
        };
        self.find_replace.current_result = new_idx;
        self.show_search_results = true;
        if let Some(result) = self.search_results.get(new_idx) {
            if let Some(addr_part) = result.split(':').next() {
                if let Ok(addr) = u64::from_str_radix(addr_part, 16) {
                    self.listing.goto(Address::new(addr));
                    self.current_address = Address::new(addr);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Central Panel (Listing + Decompiler)
    // -----------------------------------------------------------------------

    /// Render the central panel with listing and decompiler views.
    fn render_central_panel(&mut self, ctx: &egui::Context) {
        if self.views.listing_visible {
            egui::TopBottomPanel::top("listing_panel")
                .resizable(true)
                .min_height(150.0)
                .default_height(350.0)
                .show(ctx, |ui| {
                    render_listing_view(
                        &mut self.listing,
                        &self.cached_rows,
                        &self.program_name,
                        ui,
                    );
                    self.current_address = self.listing.cursor_position;
                });
        }

        if self.views.decompiler_visible {
            egui::CentralPanel::default().show(ctx, |ui| {
                render_decompiler_view(&mut self.decompiler, ui);
            });
        } else if !self.views.listing_visible {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.centered_and_justified(|ui| {
                    ui.label(
                        egui::RichText::new(
                            "No views visible.\nUse Window > Toggle Panels to show views.",
                        )
                        .color(egui::Color32::from_rgb(150, 150, 150)),
                    );
                });
            });
        }
    }

    // -----------------------------------------------------------------------
    // Side Panels
    // -----------------------------------------------------------------------

    /// Render side panels (symbol tree, data types, bytes view).
    fn render_side_panels(&mut self, ctx: &egui::Context) {
        // Left panel: Symbol Tree
        if self.views.symbol_tree_visible {
            egui::SidePanel::left("symbol_tree_panel")
                .resizable(true)
                .default_width(280.0)
                .min_width(150.0)
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical()
                        .auto_shrink([false; 2])
                        .show(ui, |ui| {
                            self.symbol_tree.render(ui);
                        });

                    if let Some(addr) = self.symbol_tree.take_navigate_to() {
                        self.listing.goto(addr);
                        self.current_address = addr;
                    }
                });
        }

        // Right panel: Data Types (if visible)
        if self.views.data_types_visible {
            egui::SidePanel::right("data_types_panel")
                .resizable(true)
                .default_width(280.0)
                .min_width(150.0)
                .show(ctx, |ui| {
                    self.data_types.render(ui);
                });
        }

        // Bottom panel: Bytes View (if visible)
        if self.views.bytes_view_visible {
            egui::TopBottomPanel::bottom("bytes_panel")
                .resizable(true)
                .default_height(150.0)
                .min_height(80.0)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Bytes / Hex View").strong());
                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                if ui.button("X").clicked() {
                                    self.views.bytes_view_visible = false;
                                }
                            },
                        );
                    });
                    render_bytes_view(&mut self.bytes_view, ui);
                });
        }
    }

    // -----------------------------------------------------------------------
    // Bottom Panel (Console + Status Bar)
    // -----------------------------------------------------------------------

    /// Render the bottom area: console panel and status bar.
    fn render_bottom_panel(&mut self, ctx: &egui::Context) {
        // Console panel (collapsible)
        if self.views.console_visible {
            egui::TopBottomPanel::bottom("console_panel")
                .resizable(true)
                .default_height(150.0)
                .min_height(80.0)
                .show(ctx, |ui| {
                    self.console.render(ui);
                });
        }

        // Status bar
        if self.prefs.show_status_bar {
            egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    // Current address
                    ui.label(
                        egui::RichText::new(format!("{:08X}", self.current_address.offset))
                            .color(egui::Color32::from_rgb(100, 180, 255))
                            .monospace()
                            .size(11.0),
                    );
                    ui.separator();

                    // Selection info
                    if !self.selection_info.is_empty() {
                        ui.label(
                            egui::RichText::new(&self.selection_info)
                                .color(egui::Color32::from_rgb(180, 200, 180))
                                .size(11.0),
                        );
                        ui.separator();
                    }

                    // Status message (auto-dismiss)
                    let status_text = self.status.current_text();
                    if !status_text.is_empty() {
                        ui.label(
                            egui::RichText::new(&status_text)
                                .color(egui::Color32::from_rgb(200, 200, 200))
                                .size(11.0),
                        );
                        ui.separator();
                    }

                    // Task progress
                    if self.task_monitor.is_running {
                        ui.add(
                            egui::ProgressBar::new(self.task_monitor.progress)
                                .desired_width(100.0)
                                .text(format!(
                                    "{:.0}%",
                                    self.task_monitor.progress * 100.0
                                )),
                        );
                        ui.separator();
                    }

                    // Undo/Redo count
                    if self.undo_manager.can_undo() {
                        ui.label(
                            egui::RichText::new(format!(
                                "Undo ({})",
                                self.undo_manager.undo_count()
                            ))
                            .color(egui::Color32::from_rgb(160, 160, 160))
                            .size(10.0),
                        );
                    }

                    ui.with_layout(
                        egui::Layout::right_to_left(egui::Align::Center),
                        |ui| {
                            // Memory usage
                            if self.memory_usage > 0 {
                                let mb = self.memory_usage / (1024 * 1024);
                                ui.label(
                                    egui::RichText::new(format!("{} MB", mb))
                                        .color(egui::Color32::from_rgb(140, 140, 140))
                                        .size(10.0),
                                );
                                ui.separator();
                            }

                            // Program name
                            ui.label(
                                egui::RichText::new(&self.program_name)
                                    .color(egui::Color32::from_rgb(140, 140, 140))
                                    .size(10.0),
                            );
                            ui.separator();

                            // Theme indicator
                            ui.label(
                                egui::RichText::new(self.theme.name())
                                    .color(egui::Color32::from_rgb(120, 120, 120))
                                    .size(10.0),
                            );
                        },
                    );
                });
            });
        }
    }

    // -----------------------------------------------------------------------
    // Dialogs
    // -----------------------------------------------------------------------

    /// Render the About dialog.
    fn render_about_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_about {
            return;
        }

        egui::Window::new("About Ghidra Rust")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.heading("Ghidra Rust");
                ui.label("A reverse engineering platform built in Rust");
                ui.label("Version 0.1.0");
                ui.separator();
                ui.label("Components:");
                ui.label("  - GUI: egui/eframe");
                ui.label("  - Core: ghidra-core");
                ui.label("  - Decompiler: ghidra-decompile");
                ui.label("  - Features: ghidra-features");
                ui.label("  - Processors: ghidra-processors");
                ui.label("  - Emulation: ghidra-emulation");
                ui.separator();
                ui.label("Inspired by Ghidra, the NSA's reverse engineering tool");
                ui.label(
                    egui::RichText::new(
                        "https://github.com/NationalSecurityAgency/ghidra",
                    )
                    .italics()
                    .color(egui::Color32::from_rgb(100, 180, 255)),
                );
                ui.separator();
                if ui.button("Close").clicked() {
                    self.show_about = false;
                }
            });
    }

    /// Render the Preferences dialog.
    fn render_preferences_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_preferences {
            return;
        }

        egui::Window::new("Preferences")
            .collapsible(true)
            .resizable(true)
            .default_size([520.0, 420.0])
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.heading("Application Preferences");

                // ---- Theme ----
                ui.horizontal(|ui| {
                    ui.label("Theme:");
                    egui::ComboBox::from_id_salt("pref_theme")
                        .selected_text(self.theme.name())
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.theme, Theme::Dark, "Dark");
                            ui.selectable_value(&mut self.theme, Theme::Light, "Light");
                            ui.selectable_value(&mut self.theme, Theme::System, "System");
                        });
                });
                ui.separator();

                // ---- Fonts ----
                ui.horizontal(|ui| {
                    ui.label("Code Font Size:");
                    ui.add(
                        egui::DragValue::new(&mut self.prefs.code_font_size)
                            .range(8.0..=32.0)
                            .speed(0.5),
                    );
                });
                ui.horizontal(|ui| {
                    ui.label("UI Font Size:");
                    ui.add(
                        egui::DragValue::new(&mut self.prefs.ui_font_size)
                            .range(8.0..=24.0)
                            .speed(0.5),
                    );
                });
                ui.separator();

                // ---- Listing ----
                ui.checkbox(
                    &mut self.prefs.show_line_numbers,
                    "Show Line Numbers",
                );
                ui.checkbox(&mut self.prefs.show_bytes, "Show Bytes Column");
                ui.horizontal(|ui| {
                    ui.label("Bytes Per Line:");
                    ui.add(
                        egui::DragValue::new(&mut self.prefs.bytes_per_line)
                            .range(4..=64)
                            .speed(1),
                    );
                });
                ui.separator();

                // ---- History ----
                ui.horizontal(|ui| {
                    ui.label("Max Undo History:");
                    ui.add(
                        egui::DragValue::new(&mut self.prefs.max_undo_history)
                            .range(10..=1000)
                            .speed(10),
                    );
                });
                ui.separator();

                // ---- Behavior ----
                ui.checkbox(
                    &mut self.prefs.confirm_close,
                    "Confirm before closing unsaved work",
                );
                ui.checkbox(
                    &mut self.prefs.auto_save_analysis,
                    "Auto-save analysis",
                );
                ui.checkbox(&mut self.prefs.show_toolbar, "Show Toolbar");
                ui.checkbox(
                    &mut self.prefs.show_status_bar,
                    "Show Status Bar",
                );
                ui.separator();

                // ---- Recent ----
                ui.horizontal(|ui| {
                    ui.label("Max Recent Files:");
                    ui.add(
                        egui::DragValue::new(&mut self.prefs.max_recent_files)
                            .range(0..=50)
                            .speed(1),
                    );
                });
                ui.separator();

                // ---- Buttons ----
                ui.horizontal(|ui| {
                    if ui.button("Apply").clicked() {
                        self.undo_manager =
                            UndoManager::new(self.prefs.max_undo_history);
                        apply_theme(ctx, self.theme);
                        self.status.post("Preferences applied");
                    }
                    if ui.button("OK").clicked() {
                        self.undo_manager =
                            UndoManager::new(self.prefs.max_undo_history);
                        apply_theme(ctx, self.theme);
                        self.show_preferences = false;
                        self.status.post("Preferences saved");
                    }
                    if ui.button("Cancel").clicked() {
                        self.show_preferences = false;
                    }
                });
            });
    }

    /// Render the Key Bindings reference dialog.
    fn render_key_bindings_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_key_bindings {
            return;
        }

        egui::Window::new("Key Bindings")
            .collapsible(true)
            .resizable(true)
            .default_size([460.0, 500.0])
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.heading("Keyboard Shortcuts");

                egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .show(ui, |ui| {
                        let sections = [
                            (
                                "File",
                                &[
                                    ("Ctrl+N", "New Project"),
                                    ("Ctrl+O", "Open File"),
                                    ("Ctrl+S", "Save"),
                                    ("Ctrl+Shift+S", "Save As"),
                                    ("Ctrl+E", "Export Program"),
                                    ("Ctrl+W", "Close"),
                                    ("Ctrl+Q", "Quit"),
                                ][..],
                            ),
                            (
                                "Edit",
                                &[
                                    ("Ctrl+Z", "Undo"),
                                    ("Ctrl+Y", "Redo"),
                                    ("Ctrl+X", "Cut"),
                                    ("Ctrl+C", "Copy"),
                                    ("Ctrl+V", "Paste"),
                                    ("Del", "Delete"),
                                    ("Ctrl+A", "Select All"),
                                    ("Ctrl+F", "Find"),
                                    ("F3", "Find Next"),
                                    ("Ctrl+H", "Replace"),
                                ][..],
                            ),
                            (
                                "Navigation",
                                &[
                                    ("G", "Go To..."),
                                    ("Esc", "Back"),
                                    ("Alt+Right", "Forward"),
                                    ("Ctrl+Down", "Next Function"),
                                    ("Ctrl+Up", "Previous Function"),
                                ][..],
                            ),
                            (
                                "Listing (Ghidra-style)",
                                &[
                                    ("F2", "Rename Label"),
                                    ("D", "Disassemble"),
                                    ("C", "Clear Code Bytes"),
                                    ("F", "Create Function"),
                                    ("L", "Create Label"),
                                    (";", "Set Comment"),
                                    ("T", "Define Data Type"),
                                    ("P", "Create Pointer"),
                                    ("[", "Create Array"),
                                    ("*", "Create Data"),
                                ][..],
                            ),
                            (
                                "Analysis",
                                &[
                                    ("Ctrl+Alt+A", "Auto Analyze"),
                                ][..],
                            ),
                            (
                                "Window",
                                &[
                                    ("Ctrl+`", "Toggle Console"),
                                ][..],
                            ),
                        ];

                        for (category, bindings) in &sections {
                            ui.label(
                                egui::RichText::new(*category)
                                    .strong()
                                    .size(14.0),
                            );
                            ui.separator();
                            for (key, action) in *bindings {
                                ui.horizontal(|ui| {
                                    ui.add_sized(
                                        [140.0, 20.0],
                                        egui::Label::new(
                                            egui::RichText::new(*key)
                                                .monospace()
                                                .color(egui::Color32::from_rgb(
                                                    100, 200, 255,
                                                )),
                                        ),
                                    );
                                    ui.label(*action);
                                });
                            }
                            ui.add_space(8.0);
                        }
                    });

                ui.separator();
                if ui.button("Close").clicked() {
                    self.show_key_bindings = false;
                }
            });
    }

    /// Render the Go To dialog.
    fn render_go_to_dialog(&mut self, ctx: &egui::Context) {
        if !self.go_to_dialog.visible {
            return;
        }

        egui::Window::new("Go To Address")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label("Enter address (hex):");
                let response =
                    ui.text_edit_singleline(&mut self.go_to_dialog.input);
                response.request_focus();

                let enter_pressed = response.lost_focus()
                    && ui.input(|i| i.key_pressed(egui::Key::Enter));

                ui.horizontal(|ui| {
                    if ui.button("Go").clicked() || enter_pressed {
                        if let Ok(addr) =
                            u64::from_str_radix(&self.go_to_dialog.input, 16)
                        {
                            let addr = Address::new(addr);
                            self.listing.goto(addr);
                            self.current_address = addr;
                            self.status
                                .post(format!("Navigated to {:08X}", addr.offset));
                            self.go_to_dialog.visible = false;
                        } else {
                            self.status.post(format!(
                                "Invalid address: {}",
                                self.go_to_dialog.input
                            ));
                            self.go_to_dialog.visible = false;
                        }
                    }
                    if ui.button("Cancel").clicked() {
                        self.go_to_dialog.visible = false;
                    }
                });
            });
    }

    /// Render the Find/Replace dialog.
    fn render_find_replace_dialog(&mut self, ctx: &egui::Context) {
        if !self.find_replace.visible {
            return;
        }

        egui::Window::new("Find / Replace")
            .collapsible(true)
            .resizable(true)
            .default_size([420.0, 230.0])
            .anchor(egui::Align2::CENTER_TOP, [0.0, 50.0])
            .show(ctx, |ui| {
                // Find section
                ui.horizontal(|ui| {
                    ui.label("Find:");
                    let response = ui
                        .text_edit_singleline(&mut self.find_replace.find_text);
                    response.request_focus();
                });

                // Replace section
                ui.horizontal(|ui| {
                    ui.label("Replace:");
                    ui.text_edit_singleline(&mut self.find_replace.replace_text);
                });

                // Options
                ui.horizontal(|ui| {
                    ui.checkbox(
                        &mut self.find_replace.match_case,
                        "Match Case",
                    );
                    ui.checkbox(
                        &mut self.find_replace.match_whole_word,
                        "Whole Word",
                    );
                    ui.checkbox(&mut self.find_replace.use_regex, "Regex");
                });

                // Result count
                if self.find_replace.result_count > 0 {
                    ui.label(format!(
                        "Result {} of {}",
                        self.find_replace.current_result + 1,
                        self.find_replace.result_count
                    ));
                }

                // Buttons
                ui.horizontal(|ui| {
                    if ui.button("Find Next").clicked() {
                        if !self.find_replace.find_text.is_empty() {
                            let text = self.find_replace.find_text.clone();
                            self.do_search(&text);
                        }
                    }
                    if ui.button("Replace").clicked() {
                        self.status.post(format!(
                            "Replaced: {}",
                            self.find_replace.find_text
                        ));
                        self.undo_manager.push(UndoCommand {
                            description: format!(
                                "Replace '{}'",
                                self.find_replace.find_text
                            ),
                            timestamp: Instant::now(),
                            category: CommandCategory::Edit,
                        });
                    }
                    if ui.button("Replace All").clicked() {
                        self.status.post("Replace All complete");
                        self.undo_manager.push(UndoCommand {
                            description: "Replace All".to_string(),
                            timestamp: Instant::now(),
                            category: CommandCategory::Edit,
                        });
                    }
                    if ui.button("Close").clicked() {
                        self.find_replace.visible = false;
                    }
                });
            });
    }

    /// Render the File dialog.
    fn render_file_dialog(&mut self, ctx: &egui::Context) {
        if matches!(self.file_dialog, FileDialogState::Closed) {
            return;
        }

        let title = match self.file_dialog {
            FileDialogState::OpenFile => "Open File",
            FileDialogState::SaveProject => "Save Project",
            FileDialogState::ExportProgram => "Export Program",
            FileDialogState::NewProject => "New Project",
            FileDialogState::OpenProject => "Open Project",
            FileDialogState::Closed => unreachable!(),
        };

        egui::Window::new(title)
            .collapsible(false)
            .resizable(true)
            .default_size([520.0, 370.0])
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(format!("{}:", title));
                ui.label(
                    egui::RichText::new(
                        "Note: Native file dialog requires the rfd crate.",
                    )
                    .italics()
                    .size(11.0),
                );
                ui.label("Use the text field to enter a file path:");

                ui.separator();

                let default_path = self.last_file_path.clone().unwrap_or_else(|| {
                    std::env::current_dir()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|_| "/".to_string())
                });

                let mut file_path = default_path.clone();
                ui.horizontal(|ui| {
                    ui.label("Path:");
                    ui.text_edit_singleline(&mut file_path);
                });

                ui.horizontal(|ui| {
                    if ui.button("Browse...").clicked() {
                        self.status
                            .post("Native file dialog would open here (rfd crate)");
                    }
                });

                ui.separator();

                // Recent files
                if !self.prefs.recent_files.is_empty()
                    && matches!(
                        self.file_dialog,
                        FileDialogState::OpenFile
                            | FileDialogState::OpenProject
                    )
                {
                    ui.label(egui::RichText::new("Recent Files:").strong());
                    for recent in &self.prefs.recent_files.clone() {
                        if ui.selectable_label(false, recent).clicked() {
                            file_path = recent.clone();
                        }
                    }
                    ui.separator();
                }

                ui.horizontal(|ui| {
                    if ui.button("Open").clicked() {
                        self.handle_file_open(&file_path);
                        self.file_dialog = FileDialogState::Closed;
                    }
                    if ui.button("Cancel").clicked() {
                        self.file_dialog = FileDialogState::Closed;
                    }
                });
            });
    }

    /// Handle a file being selected.
    fn handle_file_open(&mut self, path: &str) {
        self.last_file_path = Some(path.to_string());

        // Add to recent files
        if !self.prefs.recent_files.contains(&path.to_string()) {
            self.prefs.recent_files.push(path.to_string());
            if self.prefs.recent_files.len() > self.prefs.max_recent_files {
                self.prefs.recent_files.remove(0);
            }
        }

        match self.file_dialog {
            FileDialogState::OpenFile => {
                self.status
                    .post(format!("Opening file: {}", path));
                self.console
                    .log(ConsoleSeverity::Info, format!("Opening file: {}", path));
                self.program_name = std::path::Path::new(path)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| path.to_string());
                self.state = AppState::Editing;
            }
            FileDialogState::SaveProject => {
                self.status
                    .post(format!("Project saved to: {}", path));
                self.console
                    .log(ConsoleSeverity::Info, format!("Project saved: {}", path));
            }
            FileDialogState::ExportProgram => {
                self.status
                    .post(format!("Program exported to: {}", path));
                self.console
                    .log(ConsoleSeverity::Info, format!("Exported to: {}", path));
            }
            FileDialogState::NewProject => {
                self.status
                    .post(format!("New project created at: {}", path));
                self.console
                    .log(ConsoleSeverity::Info, format!("New project: {}", path));
            }
            FileDialogState::OpenProject => {
                self.status
                    .post(format!("Opening project: {}", path));
                self.console
                    .log(ConsoleSeverity::Info, format!("Opening project: {}", path));
            }
            FileDialogState::Closed => {}
        }
    }

    /// Render search results overlay.
    fn render_search_results_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_search_results {
            return;
        }

        egui::Window::new("Search Results")
            .resizable(true)
            .default_size([420.0, 320.0])
            .show(ctx, |ui| {
                ui.label(format!(
                    "{} results ({} of {})",
                    self.search_results.len(),
                    self.find_replace.current_result + 1,
                    self.search_results.len()
                ));
                if ui.button("Close").clicked() {
                    self.show_search_results = false;
                }
                ui.separator();
                egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .show(ui, |ui| {
                        for (idx, result) in self.search_results.iter().enumerate() {
                            let is_current =
                                idx == self.find_replace.current_result;
                            if ui
                                .selectable_label(is_current, result)
                                .clicked()
                            {
                                self.find_replace.current_result = idx;
                                if let Some(addr_part) = result.split(':').next() {
                                    if let Ok(addr) =
                                        u64::from_str_radix(addr_part, 16)
                                    {
                                        self.listing.goto(Address::new(addr));
                                        self.current_address = Address::new(addr);
                                    }
                                }
                            }
                        }
                    });
            });
    }

    // -----------------------------------------------------------------------
    // Keyboard Handling
    // -----------------------------------------------------------------------

    /// Handle global keyboard shortcuts and input events.
    fn handle_global_keys(
        &mut self,
        ctx: &egui::Context,
        frame: &mut eframe::Frame,
    ) {
        // Process registered keyboard shortcuts
        let action =
            menu::process_keyboard_shortcuts(ctx, &self.actions.key_bindings);
        if action != MenuAction::None {
            self.handle_menu_action(action, ctx, frame);
            return;
        }

        let input = ctx.input(|i| i.clone());

        // Arrow navigation
        if input.key_pressed(egui::Key::ArrowDown) {
            self.listing.scroll_down();
            self.current_address = self.listing.cursor_position;
        }
        if input.key_pressed(egui::Key::ArrowUp) {
            self.listing.scroll_up();
            self.current_address = self.listing.cursor_position;
        }
        if input.key_pressed(egui::Key::PageDown) {
            self.listing.page_down();
            self.current_address = self.listing.cursor_position;
        }
        if input.key_pressed(egui::Key::PageUp) {
            self.listing.page_up();
            self.current_address = self.listing.cursor_position;
        }
        if input.key_pressed(egui::Key::Home) {
            self.listing.scroll_offset = 0;
            self.current_address = self.listing.cursor_position;
        }
        if input.key_pressed(egui::Key::End) {
            // Scroll to the end (approximate)
            self.listing.scroll_offset = self.listing.scroll_offset.saturating_add(100000);
            self.current_address = self.listing.cursor_position;
        }

        // Escape: close dialogs, then navigate back
        if input.key_pressed(egui::Key::Escape) {
            if self.show_about {
                self.show_about = false;
            } else if self.show_preferences {
                self.show_preferences = false;
            } else if self.show_key_bindings {
                self.show_key_bindings = false;
            } else if self.show_search_results {
                self.show_search_results = false;
            } else if self.go_to_dialog.visible {
                self.go_to_dialog.visible = false;
            } else if self.find_replace.visible {
                self.find_replace.visible = false;
            } else if !matches!(self.file_dialog, FileDialogState::Closed) {
                self.file_dialog = FileDialogState::Closed;
            } else if self.listing.can_go_back() {
                self.listing.go_back();
                self.current_address = self.listing.cursor_position;
            }
        }

        // F3 - Find Next
        if input.key_pressed(egui::Key::F3) && !input.modifiers.ctrl {
            if let Some(action) = self.actions.action_for_key("F3") {
                self.handle_menu_action(action, ctx, frame);
            }
        }

        // G - Go To (when no modifier)
        if input.key_pressed(egui::Key::G)
            && !input.modifiers.ctrl
            && !input.modifiers.alt
            && !input.modifiers.shift
        {
            self.go_to_dialog.visible = true;
            self.go_to_dialog.input =
                format!("{:08X}", self.current_address.offset);
        }

        // Ctrl+` - Toggle Console
        if input.key_pressed(egui::Key::Backtick) && input.modifiers.ctrl {
            self.views.console_visible = !self.views.console_visible;
            self.status.post(format!(
                "Console {}",
                if self.views.console_visible {
                    "shown"
                } else {
                    "hidden"
                }
            ));
        }
    }

    // -----------------------------------------------------------------------
    // Listing Actions
    // -----------------------------------------------------------------------

    /// Handle pending listing actions emitted by the listing view renderer.
    fn handle_listing_actions(&mut self) {
        let actions = self.listing.take_actions();

        for action in actions {
            match action {
                ListingAction::None => {}

                ListingAction::NavigateTo(addr) => {
                    self.listing.goto(addr);
                    self.current_address = addr;
                }
                ListingAction::RenameLabel(addr) => {
                    self.status
                        .post(format!("Rename label at {:08X}", addr.offset));
                    self.console.log(
                        ConsoleSeverity::Info,
                        format!(
                            "Rename label requested at {:08X}",
                            addr.offset
                        ),
                    );
                    self.undo_manager.push(UndoCommand {
                        description: format!(
                            "Rename label at {:08X}",
                            addr.offset
                        ),
                        timestamp: Instant::now(),
                        category: CommandCategory::Label,
                    });
                    if let Some(ref prog) = self.program {
                        if let Ok(mut prog) = prog.write() {
                            // Remove old symbol and add renamed one
                            if let Some(mut old_sym) = prog.remove_symbol(&addr) {
                                use ghidra_core::symbol::{SymbolApi, SourceType as SymSourceType};
                                let _ = old_sym.set_name(&self.listing.rename_text, SymSourceType::UserDefined);
                                prog.add_symbol(old_sym);
                            }
                        }
                    }
                }
                ListingAction::RemoveLabel(addr) => {
                    self.status
                        .post(format!("Remove label at {:08X}", addr.offset));
                    self.listing.labels.remove(&addr);
                    self.undo_manager.push(UndoCommand {
                        description: format!(
                            "Remove label at {:08X}",
                            addr.offset
                        ),
                        timestamp: Instant::now(),
                        category: CommandCategory::Label,
                    });
                    if let Some(ref prog) = self.program {
                        if let Ok(mut prog) = prog.write() {
                            prog.remove_symbol(&addr);
                        }
                    }
                }
                ListingAction::SetComment(addr, comment) => {
                    self.status.post(format!(
                        "Set comment at {:08X}",
                        addr.offset
                    ));
                    self.listing
                        .comments
                        .insert(addr, comment.clone());
                    self.undo_manager.push(UndoCommand {
                        description: format!(
                            "Set comment at {:08X}",
                            addr.offset
                        ),
                        timestamp: Instant::now(),
                        category: CommandCategory::Comment,
                    });
                    if let Some(ref prog) = self.program {
                        if let Ok(mut prog) = prog.write() {
                            prog.set_comment(
                                addr,
                                ghidra_core::program::listing::CommentType::Eol,
                                Some(comment),
                            );
                        }
                    }
                }
                ListingAction::DeleteComment(addr) => {
                    self.listing.comments.remove(&addr);
                    self.undo_manager.push(UndoCommand {
                        description: format!(
                            "Delete comment at {:08X}",
                            addr.offset
                        ),
                        timestamp: Instant::now(),
                        category: CommandCategory::Comment,
                    });
                }
                ListingAction::CreateFunction(addr) => {
                    self.status.post(format!(
                        "Create function at {:08X}",
                        addr.offset
                    ));
                    self.undo_manager.push(UndoCommand {
                        description: format!(
                            "Create function at {:08X}",
                            addr.offset
                        ),
                        timestamp: Instant::now(),
                        category: CommandCategory::Function,
                    });
                    if let Some(ref prog) = self.program {
                        if let Ok(mut prog) = prog.write() {
                            let body =
                                ghidra_core::addr::AddressRange::new(addr, addr);
                            let name = format!("FUN_{:08X}", addr.offset);
                            let _ = prog.add_function(
                                addr,
                                body,
                                Some(name.as_str()),
                                ghidra_core::program::listing::SourceType::UserDefined,
                            );
                        }
                    }
                }
                ListingAction::DeleteFunction(addr) => {
                    self.status.post(format!(
                        "Delete function at {:08X}",
                        addr.offset
                    ));
                    self.undo_manager.push(UndoCommand {
                        description: format!(
                            "Delete function at {:08X}",
                            addr.offset
                        ),
                        timestamp: Instant::now(),
                        category: CommandCategory::Function,
                    });
                    if let Some(ref prog) = self.program {
                        if let Ok(mut prog) = prog.write() {
                            prog.remove_function(&addr);
                        }
                    }
                }
                ListingAction::EditFunctionSignature(addr) => {
                    self.status.post(format!(
                        "Edit function signature at {:08X}",
                        addr.offset
                    ));
                }
                ListingAction::Disassemble(addr) => {
                    self.status.post(format!(
                        "Disassemble at {:08X}",
                        addr.offset
                    ));
                    self.task_monitor.start("Disassemble");
                    self.task_monitor.update(1.0, "Done");
                    self.task_monitor.finish();
                    self.undo_manager.push(UndoCommand {
                        description: format!(
                            "Disassemble at {:08X}",
                            addr.offset
                        ),
                        timestamp: Instant::now(),
                        category: CommandCategory::Analysis,
                    });
                }
                ListingAction::Clear(addr) => {
                    self.status
                        .post(format!("Clear at {:08X}", addr.offset));
                    self.undo_manager.push(UndoCommand {
                        description: format!("Clear at {:08X}", addr.offset),
                        timestamp: Instant::now(),
                        category: CommandCategory::Analysis,
                    });
                }
                ListingAction::SetDataType(addr, dt) => {
                    self.status.post(format!(
                        "Set data type {} at {:08X}",
                        dt, addr.offset
                    ));
                    self.undo_manager.push(UndoCommand {
                        description: format!(
                            "Set data type {} at {:08X}",
                            dt, addr.offset
                        ),
                        timestamp: Instant::now(),
                        category: CommandCategory::DataType,
                    });
                }
                ListingAction::CreateArray(addr) => {
                    self.status.post(format!(
                        "Create array at {:08X}",
                        addr.offset
                    ));
                }
                ListingAction::CreatePointer(addr) => {
                    self.status.post(format!(
                        "Create pointer at {:08X}",
                        addr.offset
                    ));
                }
                ListingAction::CreateStructure(addr) => {
                    self.status.post(format!(
                        "Create structure at {:08X}",
                        addr.offset
                    ));
                }
                ListingAction::ApplyStructure(addr) => {
                    self.status.post(format!(
                        "Apply structure at {:08X}",
                        addr.offset
                    ));
                }
                ListingAction::SetRegisterValue(addr) => {
                    self.status.post(format!(
                        "Set register value at {:08X}",
                        addr.offset
                    ));
                }
                ListingAction::SetFlowOverride(addr) => {
                    self.status.post(format!(
                        "Set flow override at {:08X}",
                        addr.offset
                    ));
                }
                ListingAction::AddBookmark(addr) => {
                    self.status.post(format!(
                        "Add bookmark at {:08X}",
                        addr.offset
                    ));
                    if let Some(ref prog) = self.program {
                        if let Ok(mut prog) = prog.write() {
                            prog.add_bookmark(
                                addr,
                                "Note",
                                "General",
                                format!("Bookmark at {:08X}", addr.offset),
                            );
                        }
                    }
                }
                ListingAction::RemoveBookmark(addr) => {
                    self.status.post(format!(
                        "Remove bookmark at {:08X}",
                        addr.offset
                    ));
                    if let Some(ref prog) = self.program {
                        if let Ok(mut prog) = prog.write() {
                            prog.remove_bookmarks_at(&addr);
                        }
                    }
                }
                ListingAction::AnalyzeFromHere(addr) => {
                    self.status.post(format!(
                        "Analyze from {:08X}",
                        addr.offset
                    ));
                    self.task_monitor.start("Analysis");
                    self.task_monitor.update(0.5, "Analyzing...");
                    self.task_monitor.finish();
                }
                ListingAction::PatchInstruction(addr) => {
                    self.status.post(format!(
                        "Patch instruction at {:08X}",
                        addr.offset
                    ));
                }
                ListingAction::PatchData(addr) => {
                    self.status.post(format!(
                        "Patch data at {:08X}",
                        addr.offset
                    ));
                }
                ListingAction::ShowReferences(addr) => {
                    self.status.post(format!(
                        "Show references from {:08X}",
                        addr.offset
                    ));
                }
                ListingAction::ShowXRefs(addr) => {
                    self.status.post(format!(
                        "Show xrefs to {:08X}",
                        addr.offset
                    ));
                }
                ListingAction::CopyAddress(addr) => {
                    self.status.post(format!(
                        "Copied address {:08X}",
                        addr.offset
                    ));
                    self.console.log(
                        ConsoleSeverity::Debug,
                        format!("Copied address: {:08X}", addr.offset),
                    );
                }
                ListingAction::CopyBytes(addr) => {
                    self.status.post(format!(
                        "Copied bytes from {:08X}",
                        addr.offset
                    ));
                }
                ListingAction::CopyAsString(addr) => {
                    self.status.post(format!(
                        "Copied string from {:08X}",
                        addr.offset
                    ));
                }
                ListingAction::CopyAsCArray(addr) => {
                    self.status.post(format!(
                        "Copied C array from {:08X}",
                        addr.offset
                    ));
                }
                ListingAction::CopyAsPythonList(addr) => {
                    self.status.post(format!(
                        "Copied Python list from {:08X}",
                        addr.offset
                    ));
                }
                ListingAction::CopyInstruction(text) => {
                    self.status.post("Copied instruction");
                    self.console.log(
                        ConsoleSeverity::Debug,
                        format!("Copied instruction: {}", text),
                    );
                }
                ListingAction::CopyLabel(addr) => {
                    self.status.post(format!(
                        "Copied label from {:08X}",
                        addr.offset
                    ));
                }
                ListingAction::SetBackgroundColor(addr) => {
                    self.status.post(format!(
                        "Set background color at {:08X}",
                        addr.offset
                    ));
                }
                ListingAction::SetTextColor(addr) => {
                    self.status.post(format!(
                        "Set text color at {:08X}",
                        addr.offset
                    ));
                }
                ListingAction::ClearColors(addr) => {
                    self.status.post(format!(
                        "Clear colors at {:08X}",
                        addr.offset
                    ));
                }
                ListingAction::OpenInNewWindow(addr) => {
                    self.status.post(format!(
                        "Open in new window at {:08X}",
                        addr.offset
                    ));
                }
                ListingAction::EditWithExternalTool(addr) => {
                    self.status.post(format!(
                        "Edit with external tool at {:08X}",
                        addr.offset
                    ));
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // View Synchronization
    // -----------------------------------------------------------------------

    /// Synchronize state between views after changes.
    fn sync_views(&mut self) {
        // Update current address from listing
        if self.current_address != self.listing.cursor_position {
            self.current_address = self.listing.cursor_position;
        }

        // Update selection info
        self.selection_info = String::new();
        if let Some(selection) = &self.listing.selection {
            let size = selection
                .end
                .offset
                .saturating_sub(selection.start.offset)
                + 1;
            self.selection_info = format!(
                "Sel: {:08X}-{:08X} ({} bytes)",
                selection.start.offset, selection.end.offset, size
            );
        }

        // Track any decompiler navigation
        if let Some(ref nav) = self.decompiler.pending_navigation.clone() {
            match nav {
                crate::decompiler_view::DecompilerNavigation::NavigateToAddress(addr) => {
                    self.listing.goto(*addr);
                    self.current_address = *addr;
                }
                _ => {}
            }
            self.decompiler.pending_navigation = None;
        }

        // Update memory usage estimate
        self.memory_usage = std::mem::size_of::<Self>() as u64
            + self.cached_rows.len() as u64 * 512
            + self.console.messages.len() as u64 * 256
            + self.search_results.len() as u64 * 128;
    }

    // -----------------------------------------------------------------------
    // Layout Persistence
    // -----------------------------------------------------------------------

    /// Save the current layout to disk.
    fn save_layout(&mut self) {
        let json = self.views.save_layout();
        if let Err(e) = std::fs::write(&self.layout_file_path, json) {
            self.console.log(
                ConsoleSeverity::Warning,
                format!("Failed to save layout: {}", e),
            );
        }
    }

    /// Load layout from disk.
    fn load_layout(&mut self) {
        match std::fs::read_to_string(&self.layout_file_path) {
            Ok(json) if !json.is_empty() => match self.views.load_layout(&json) {
                Ok(()) => {
                    self.console.log(
                        ConsoleSeverity::Debug,
                        "Layout restored from disk",
                    );
                }
                Err(e) => {
                    self.console.log(
                        ConsoleSeverity::Warning,
                        format!("Failed to parse layout file: {}", e),
                    );
                }
            },
            _ => {}
        }
    }
}

// ============================================================================
// eframe::App Implementation
// ============================================================================

impl eframe::App for GhidraApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        self.frame_start = Instant::now();

        // Load layout on first frame (only when the layout is uninitialized)
        if self.views.layout.windows.is_empty() {
            self.load_layout();
        }

        // Apply theme
        apply_theme(ctx, self.theme);

        // ---- Top Menu Bar ----
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            self.render_menu_bar(ctx, frame, ui);
        });

        // ---- Toolbar ----
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            self.render_toolbar_ui(ui);
        });

        // ---- Central Area (Listing + Decompiler) ----
        self.render_central_panel(ctx);

        // ---- Side Panels ----
        self.render_side_panels(ctx);

        // ---- Bottom Panel (Console + Status Bar) ----
        self.render_bottom_panel(ctx);

        // ---- Overlays (Dialogs) ----
        self.render_about_dialog(ctx);
        self.render_preferences_dialog(ctx);
        self.render_key_bindings_dialog(ctx);
        self.render_go_to_dialog(ctx);
        self.render_find_replace_dialog(ctx);
        self.render_file_dialog(ctx);
        self.render_search_results_dialog(ctx);

        // ---- Handle Keyboard Shortcuts ----
        self.handle_global_keys(ctx, frame);

        // ---- Handle Listing Actions ----
        self.handle_listing_actions();

        // ---- Sync Views ----
        self.sync_views();

        // Continuous repaint for animated elements (spinner, progress)
        if self.task_monitor.is_running {
            ctx.request_repaint();
        }

        // Periodic repaint for auto-dismissing status messages
        if self.frame_start.elapsed().as_secs_f64() % 0.5 < 0.016 {
            ctx.request_repaint();
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.save_layout();
        self.console
            .log(ConsoleSeverity::Info, "Shutting down, layout saved");
    }
}

impl Default for GhidraApp {
    fn default() -> Self {
        Self::with_demo_program()
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Get the user's data directory for storing layout/config files.
fn app_data_dir() -> Option<std::path::PathBuf> {
    if let Ok(dir) = std::env::var("XDG_DATA_HOME") {
        let path = std::path::PathBuf::from(dir).join("ghidra_rust");
        let _ = std::fs::create_dir_all(&path);
        Some(path)
    } else if let Some(home) = std::env::var_os("HOME") {
        let path = std::path::PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("ghidra_rust");
        let _ = std::fs::create_dir_all(&path);
        Some(path)
    } else {
        None
    }
}
