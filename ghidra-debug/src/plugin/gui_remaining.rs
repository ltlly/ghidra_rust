//! Remaining GUI data-model types ported from Ghidra's Debugger module.
//!
//! Ported from the following Java packages:
//! - `ghidra.app.plugin.core.debug.gui` (DebuggerByteSource, DebuggerLocationLabel,
//!   PasteIntoTargetMixin, AbstractDebuggerMapProposalDialog,
//!   AbstractDebuggerParameterDialog, DebuggerBlockChooserDialog)
//! - `ghidra.app.plugin.core.debug.gui.breakpoint` (BreakpointsDecompilerMarginProvider,
//!   DebuggerBreakpointStateTableCellEditor, DebuggerBreakpointsProvider,
//!   BreakpointTimelineActions)
//! - `ghidra.app.plugin.core.debug.gui.colors` (DebuggerTrackedRegisterBackgroundColorModel,
//!   MultiSelectionBlendedLayoutBackgroundColorManager)
//! - `ghidra.app.plugin.core.debug.gui.console` (ConsoleActionsCellEditor,
//!   HtmlOrProgressCellRenderer)
//! - `ghidra.app.plugin.core.debug.gui.control` (ResumeAction, StepIntoAction)
//! - `ghidra.app.plugin.core.debug.gui.copying` (DebuggerCopyIntoProgramDialog)
//! - `ghidra.app.plugin.core.debug.gui.listing` (CursorBackgroundColorModel,
//!   DebuggerListingProvider, DebuggerTrackedRegisterListingBackgroundColorModel,
//!   MemoryStateListingBackgroundColorModel)
//! - `ghidra.app.plugin.core.debug.gui.memory` (7 types)
//! - `ghidra.app.plugin.core.debug.gui.memview` (MemviewPanel, MemviewProvider, MemviewTable)
//! - `ghidra.app.plugin.core.debug.gui.model` (9 types)
//! - `ghidra.app.plugin.core.debug.gui.modules` (8 types)
//! - `ghidra.app.plugin.core.debug.gui.register` (3 types)
//! - `ghidra.app.plugin.core.debug.gui.stack` (2 types)
//! - `ghidra.app.plugin.core.debug.gui.stack.vars` (VariableValueHoverService)
//! - `ghidra.app.plugin.core.debug.gui.thread` (2 types)
//! - `ghidra.app.plugin.core.debug.gui.time` (3 types)
//! - `ghidra.app.plugin.core.debug.gui.timeoverview` (4 types)
//! - `ghidra.app.plugin.core.debug.gui.tracecalltree` (6 types)
//! - `ghidra.app.plugin.core.debug.gui.watch` (DebuggerWatchesProvider)
//!
//! Since Rust has no Swing, these are the non-GUI data models, configuration
//! structs, enums, and traits that back the GUI components.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ===========================================================================
// gui/ - Top-level GUI types
// ===========================================================================

/// Debugger byte source for memory search.
///
/// Ported from `DebuggerByteSource`. Provides a view of possibly-live target
/// memory for search operations. Manages the view, target reference, and
/// mapping service to translate between dynamic and static addresses.
#[derive(Debug, Clone)]
pub struct DebuggerByteSourceData {
    /// The current trace program view key.
    pub view_key: Option<i64>,
    /// The target key.
    pub target_key: Option<i64>,
    /// Physical address spaces available for searching.
    pub searchable_spaces: Vec<String>,
}

impl DebuggerByteSourceData {
    /// Create a new byte source with no view or target.
    pub fn new() -> Self {
        Self {
            view_key: None,
            target_key: None,
            searchable_spaces: Vec::new(),
        }
    }

    /// Check if this byte source has a valid view.
    pub fn has_view(&self) -> bool {
        self.view_key.is_some()
    }
}

impl Default for DebuggerByteSourceData {
    fn default() -> Self {
        Self::new()
    }
}

/// Location label model for displaying section/module/region at an address.
///
/// Ported from `DebuggerLocationLabel`. Computes a human-readable location
/// string (section, module, or region name) for a given address and snapshot.
#[derive(Debug, Clone, Default)]
pub struct DebuggerLocationLabelData {
    /// Current trace key.
    pub trace_key: Option<i64>,
    /// Current snap.
    pub snap: i64,
    /// Current address being displayed.
    pub address: Option<u64>,
    /// Computed location string.
    pub label: String,
}

impl DebuggerLocationLabelData {
    /// Create a new location label with no coordinates.
    pub fn new() -> Self {
        Self::default()
    }

    /// Update the coordinates and recompute the label.
    pub fn update(&mut self, trace_key: Option<i64>, snap: i64, address: Option<u64>) {
        self.trace_key = trace_key;
        self.snap = snap;
        self.address = address;
        if address.is_none() {
            self.label = "(nowhere)".into();
        } else {
            self.label = "(unknown)".into();
        }
    }

    /// Set the label explicitly.
    pub fn set_label(&mut self, label: String) {
        self.label = label;
    }
}

/// Mixin for pasting data into a debug target.
///
/// Ported from `PasteIntoTargetMixin`. Provides the data model for
/// paste-into-target operations.
#[derive(Debug, Clone)]
pub struct PasteIntoTargetData {
    /// Source addresses to paste from.
    pub source_addresses: Vec<u64>,
    /// Target addresses to paste to.
    pub target_addresses: Vec<u64>,
    /// Byte data to paste.
    pub data: Vec<u8>,
}

impl PasteIntoTargetData {
    /// Create a new paste data.
    pub fn new() -> Self {
        Self {
            source_addresses: Vec::new(),
            target_addresses: Vec::new(),
            data: Vec::new(),
        }
    }
}

impl Default for PasteIntoTargetData {
    fn default() -> Self {
        Self::new()
    }
}

/// Abstract map proposal dialog state.
///
/// Ported from `AbstractDebuggerMapProposalDialog`. Tracks the state of a
/// dialog proposing static mappings between program and trace address ranges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapProposalDialogState {
    /// The proposed entries: (program_min, program_max, trace_min, trace_max).
    pub entries: Vec<(u64, u64, u64, u64)>,
    /// Whether the dialog was accepted.
    pub accepted: bool,
    /// Current selection index.
    pub selected_index: Option<usize>,
}

impl MapProposalDialogState {
    /// Create a new empty proposal dialog state.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            accepted: false,
            selected_index: None,
        }
    }

    /// Add a mapping entry.
    pub fn add_entry(&mut self, prog_min: u64, prog_max: u64, trace_min: u64, trace_max: u64) {
        self.entries.push((prog_min, prog_max, trace_min, trace_max));
    }
}

impl Default for MapProposalDialogState {
    fn default() -> Self {
        Self::new()
    }
}

/// Abstract parameter dialog state.
///
/// Ported from `AbstractDebuggerParameterDialog`. Manages the state of a
/// dialog for collecting launch/invocation parameters from the user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterDialogState {
    /// Parameter name-value pairs.
    pub parameters: HashMap<String, ParameterValue>,
    /// Dialog title.
    pub title: String,
    /// Whether the dialog was accepted.
    pub accepted: bool,
}

/// A parameter value in a dialog, which can be one of several types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParameterValue {
    /// A string value.
    String(String),
    /// A numeric value.
    Number(i64),
    /// A boolean toggle.
    Bool(bool),
    /// An address value.
    Address(u64),
    /// A choice from a list.
    Choice { options: Vec<String>, selected: usize },
}

impl ParameterDialogState {
    /// Create a new parameter dialog state.
    pub fn new(title: &str) -> Self {
        Self {
            parameters: HashMap::new(),
            title: title.into(),
            accepted: false,
        }
    }

    /// Add a string parameter.
    pub fn add_string(&mut self, name: &str, default: &str) {
        self.parameters
            .insert(name.into(), ParameterValue::String(default.into()));
    }

    /// Add a boolean parameter.
    pub fn add_bool(&mut self, name: &str, default: bool) {
        self.parameters
            .insert(name.into(), ParameterValue::Bool(default));
    }

    /// Get a string parameter value.
    pub fn get_string(&self, name: &str) -> Option<&str> {
        match self.parameters.get(name) {
            Some(ParameterValue::String(s)) => Some(s),
            _ => None,
        }
    }
}

/// Block chooser dialog state for selecting memory blocks.
///
/// Ported from `DebuggerBlockChooserDialog`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockChooserDialogState {
    /// Available blocks: (name, space_id, start, end).
    pub blocks: Vec<BlockInfo>,
    /// Selected block index.
    pub selected: Option<usize>,
    /// Whether the dialog was accepted.
    pub accepted: bool,
}

/// Information about a memory block in the chooser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockInfo {
    /// Block name.
    pub name: String,
    /// Address space identifier.
    pub space_id: u16,
    /// Start address.
    pub start: u64,
    /// End address.
    pub end: u64,
}

impl BlockChooserDialogState {
    /// Create a new empty block chooser.
    pub fn new() -> Self {
        Self {
            blocks: Vec::new(),
            selected: None,
            accepted: false,
        }
    }
}

impl Default for BlockChooserDialogState {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// gui/control/ - Control action interfaces
// ===========================================================================

/// Resume action constants.
///
/// Ported from `ResumeAction` interface.
#[derive(Debug, Clone)]
pub struct ResumeActionSpec {
    /// Sub-group for ordering.
    pub sub_group: u32,
    /// Key binding key code (VK_F5 = 116).
    pub key_code: u32,
    /// Key binding modifiers (0 = none).
    pub modifiers: u32,
}

impl Default for ResumeActionSpec {
    fn default() -> Self {
        Self {
            sub_group: 0,
            key_code: 116, // VK_F5
            modifiers: 0,
        }
    }
}

/// Step-into action constants.
///
/// Ported from `StepIntoAction` interface.
#[derive(Debug, Clone)]
pub struct StepIntoActionSpec {
    /// Sub-group for ordering.
    pub sub_group: u32,
    /// Key binding key code (VK_F8 = 119).
    pub key_code: u32,
    /// Key binding modifiers (0 = none).
    pub modifiers: u32,
}

impl Default for StepIntoActionSpec {
    fn default() -> Self {
        Self {
            sub_group: 3,
            key_code: 119, // VK_F8
            modifiers: 0,
        }
    }
}

// ===========================================================================
// gui/colors/ - Background color models
// ===========================================================================

/// Background color model for tracked register locations in the listing.
///
/// Ported from `DebuggerTrackedRegisterBackgroundColorModel`. Highlights
/// addresses where tracked registers point.
#[derive(Debug, Clone)]
pub struct TrackedRegisterColorModel {
    /// Default background color (RGBA).
    pub default_background: [u8; 4],
    /// Tracking highlight color (RGBA).
    pub tracking_color: [u8; 4],
    /// The currently tracked address, if any.
    pub tracked_address: Option<u64>,
}

impl TrackedRegisterColorModel {
    /// Create a new color model with default colors.
    pub fn new() -> Self {
        Self {
            default_background: [0xff, 0xff, 0xff, 0xff],
            tracking_color: [0xd0, 0xd0, 0xff, 0xff],
            tracked_address: None,
        }
    }

    /// Get the background color for the given address.
    pub fn color_for(&self, address: u64) -> [u8; 4] {
        match self.tracked_address {
            Some(tracked) if tracked == address => self.tracking_color,
            _ => self.default_background,
        }
    }
}

impl Default for TrackedRegisterColorModel {
    fn default() -> Self {
        Self::new()
    }
}

/// Multi-selection blended layout background color manager.
///
/// Ported from `MultiSelectionBlendedLayoutBackgroundColorManager`. Blends
/// multiple colored selections to produce a final background color for
/// each field in a listing layout.
#[derive(Debug, Clone)]
pub struct MultiSelectionBlendedColorManager {
    /// Layout index this manager is for.
    pub index: u64,
    /// Background color (RGBA).
    pub background_color: [u8; 4],
    /// Left border color (RGBA).
    pub left_border_color: [u8; 4],
    /// Right border color (RGBA).
    pub right_border_color: [u8; 4],
    /// Colored selections active at this index.
    pub selections: Vec<ColoredFieldSelection>,
}

/// A field selection with an associated color.
#[derive(Debug, Clone)]
pub struct ColoredFieldSelection {
    /// Selection ranges: (field_num, start_col, end_col).
    pub ranges: Vec<(u32, u32, u32)>,
    /// The selection color (RGBA).
    pub color: [u8; 4],
}

impl MultiSelectionBlendedColorManager {
    /// Create a new blended color manager.
    pub fn new(index: u64, background_color: [u8; 4]) -> Self {
        Self {
            index,
            background_color,
            left_border_color: background_color,
            right_border_color: background_color,
            selections: Vec::new(),
        }
    }

    /// Add a colored selection.
    pub fn add_selection(&mut self, selection: ColoredFieldSelection) {
        self.selections.push(selection);
    }

    /// Compute the blended background color.
    pub fn get_background_color(&self) -> [u8; 4] {
        if self.selections.is_empty() {
            return self.background_color;
        }
        blend_colors(
            &self.background_color,
            self.selections.iter().map(|s| &s.color),
        )
    }
}

/// Blend multiple RGBA colors with the base color.
fn blend_colors<'a>(base: &[u8; 4], others: impl Iterator<Item = &'a [u8; 4]>) -> [u8; 4] {
    let mut r = base[0] as u32;
    let mut g = base[1] as u32;
    let mut b = base[2] as u32;
    let mut count = 1u32;
    for c in others {
        r += c[0] as u32;
        g += c[1] as u32;
        b += c[2] as u32;
        count += 1;
    }
    [(r / count) as u8, (g / count) as u8, (b / count) as u8, 0xff]
}

// ===========================================================================
// gui/listing/ - Listing-specific color models
// ===========================================================================

/// Cursor background color model for the listing.
///
/// Ported from `CursorBackgroundColorModel`. Highlights the current cursor
/// line in the listing.
#[derive(Debug, Clone)]
pub struct CursorBackgroundColorModelData {
    /// Default background color (RGBA).
    pub default_background: [u8; 4],
    /// Cursor line color (RGBA).
    pub cursor_color: [u8; 4],
    /// Whether cursor highlighting is enabled.
    pub highlight_enabled: bool,
    /// Current cursor address.
    pub cursor_address: Option<u64>,
}

impl Default for CursorBackgroundColorModelData {
    fn default() -> Self {
        Self {
            default_background: [0xff, 0xff, 0xff, 0xff],
            cursor_color: [0xc8, 0xc8, 0xff, 0xff],
            highlight_enabled: true,
            cursor_address: None,
        }
    }
}

impl CursorBackgroundColorModelData {
    /// Get the color for the given address.
    pub fn color_for(&self, address: u64) -> [u8; 4] {
        if self.highlight_enabled && self.cursor_address == Some(address) {
            self.cursor_color
        } else {
            self.default_background
        }
    }
}

/// Memory state listing background color model.
///
/// Ported from `MemoryStateListingBackgroundColorModel`. Colors listing
/// addresses based on their memory state (known, unknown, error).
#[derive(Debug, Clone)]
pub struct MemoryStateColorModelData {
    /// Color for error state (RGBA).
    pub error_color: [u8; 4],
    /// Color for unknown/stale state (RGBA).
    pub unknown_color: [u8; 4],
    /// Blended unknown color with reduced alpha.
    pub unknown_blended_color: [u8; 4],
    /// Default background (RGBA).
    pub default_background: [u8; 4],
    /// Address states: address -> memory state enum.
    pub states: HashMap<u64, MemoryStateEnum>,
}

/// Memory state for listing coloring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryStateEnum {
    /// Memory state is known (bytes available).
    Known,
    /// Memory state is unknown (needs to be fetched).
    Unknown,
    /// Error reading memory.
    Error,
}

impl Default for MemoryStateColorModelData {
    fn default() -> Self {
        Self {
            error_color: [0xff, 0xd0, 0xd0, 0xff],
            unknown_color: [0xd0, 0xd0, 0xff, 0xff],
            unknown_blended_color: [0xd0, 0xd0, 0xff, 0x80],
            default_background: [0xff, 0xff, 0xff, 0xff],
            states: HashMap::new(),
        }
    }
}

impl MemoryStateColorModelData {
    /// Get the color for the given address.
    pub fn color_for(&self, address: u64) -> [u8; 4] {
        match self.states.get(&address) {
            Some(MemoryStateEnum::Error) => self.error_color,
            Some(MemoryStateEnum::Unknown) => self.unknown_blended_color,
            _ => self.default_background,
        }
    }

    /// Set the state for an address range.
    pub fn set_state(&mut self, start: u64, end: u64, state: MemoryStateEnum) {
        for addr in start..=end {
            self.states.insert(addr, state);
        }
    }
}

/// Tracked register listing background color model.
///
/// Ported from `DebuggerTrackedRegisterListingBackgroundColorModel`.
#[derive(Debug, Clone)]
pub struct TrackedRegisterListingColorModelData {
    /// Base tracked register color model.
    pub base: TrackedRegisterColorModel,
    /// Whether the listing panel is active.
    pub active: bool,
}

impl Default for TrackedRegisterListingColorModelData {
    fn default() -> Self {
        Self {
            base: TrackedRegisterColorModel::new(),
            active: true,
        }
    }
}

// ===========================================================================
// gui/model/ - Object/table/tree model types
// ===========================================================================

/// Colors-modified interface for rendering diff colors.
///
/// Ported from `ColorsModified`. Provides foreground color selection
/// for modified/unmodified and selected/unselected states.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColorsModifiedConfig {
    /// Color for normal foreground.
    pub foreground: [u8; 4],
    /// Color for normal selected foreground.
    pub selected_foreground: [u8; 4],
    /// Color for modified/diff foreground.
    pub diff_foreground: [u8; 4],
    /// Color for modified/diff selected foreground.
    pub diff_selected_foreground: [u8; 4],
}

impl ColorsModifiedConfig {
    /// Get the foreground color for the given state.
    pub fn foreground_for(&self, is_modified: bool, is_selected: bool) -> [u8; 4] {
        match (is_modified, is_selected) {
            (true, true) => self.diff_selected_foreground,
            (true, false) => self.diff_foreground,
            (false, true) => self.selected_foreground,
            (false, false) => self.foreground,
        }
    }
}

impl Default for ColorsModifiedConfig {
    fn default() -> Self {
        Self {
            foreground: [0x00, 0x00, 0x00, 0xff],
            selected_foreground: [0xff, 0xff, 0xff, 0xff],
            diff_foreground: [0xcc, 0x00, 0x00, 0xff],
            diff_selected_foreground: [0xff, 0x66, 0x66, 0xff],
        }
    }
}

/// Displays-modified mixin for showing object modification state.
///
/// Ported from `DisplaysModified`. Tracks whether trace objects have been
/// modified for diff-highlighting in the UI.
#[derive(Debug, Clone, Default)]
pub struct DisplaysModifiedState {
    /// Set of modified object paths.
    pub modified_paths: Vec<Vec<String>>,
    /// Current snap for change detection.
    pub snap: i64,
}

impl DisplaysModifiedState {
    /// Check if a path is marked as modified.
    pub fn is_modified(&self, path: &[String]) -> bool {
        self.modified_paths.iter().any(|p| p == path)
    }

    /// Mark a path as modified.
    pub fn mark_modified(&mut self, path: Vec<String>) {
        if !self.modified_paths.contains(&path) {
            self.modified_paths.push(path);
        }
    }

    /// Clear all modification markers.
    pub fn clear(&mut self) {
        self.modified_paths.clear();
    }
}

/// Default actions mixin for object model rows.
///
/// Ported from `ObjectDefaultActionsMixin`. Provides the action dispatch
/// data for interacting with target objects (go-to, invoke, navigate).
#[derive(Debug, Clone)]
pub struct ObjectDefaultActionsData {
    /// Available actions for the current object.
    pub actions: Vec<ActionEntryData>,
    /// Current object path.
    pub current_path: Vec<String>,
    /// Current coordinates key.
    pub coordinates_key: Option<i64>,
}

/// An action entry available on a target object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionEntryData {
    /// Action name identifier.
    pub action_name: String,
    /// Display name for the action.
    pub display_name: String,
    /// Whether this action requires arguments.
    pub requires_arguments: bool,
}

impl ObjectDefaultActionsData {
    /// Create empty actions data.
    pub fn new() -> Self {
        Self {
            actions: Vec::new(),
            current_path: Vec::new(),
            coordinates_key: None,
        }
    }
}

impl Default for ObjectDefaultActionsData {
    fn default() -> Self {
        Self::new()
    }
}

/// Abstract query table model data.
///
/// Ported from `AbstractQueryTableModel`. Tracks the query parameters and
/// sort state for a table displaying trace object data.
#[derive(Debug, Clone)]
pub struct QueryTableModelState {
    /// Current trace key.
    pub trace_key: Option<i64>,
    /// Current snap.
    pub snap: i64,
    /// Sort column index.
    pub sort_column: Option<usize>,
    /// Sort ascending.
    pub sort_ascending: bool,
    /// Total row count.
    pub row_count: usize,
    /// Whether the model is currently loading.
    pub loading: bool,
}

impl Default for QueryTableModelState {
    fn default() -> Self {
        Self {
            trace_key: None,
            snap: 0,
            sort_column: None,
            sort_ascending: true,
            row_count: 0,
            loading: false,
        }
    }
}

/// Model provider state for the object model panel.
///
/// Ported from `DebuggerModelProvider`.
#[derive(Debug, Clone, Default)]
pub struct ModelProviderState {
    /// Whether showing the table view (vs tree view).
    pub show_table: bool,
    /// Current coordinates key.
    pub coordinates_key: Option<i64>,
    /// Filter text.
    pub filter: String,
    /// Whether auto-refresh is enabled.
    pub auto_refresh: bool,
}

/// Object table panel state.
///
/// Ported from `ObjectsTablePanel`.
#[derive(Debug, Clone, Default)]
pub struct ObjectsTablePanelState {
    /// Column descriptors.
    pub columns: Vec<ColumnDescriptor>,
    /// Selected row indices.
    pub selected_rows: Vec<usize>,
}

/// A column descriptor for object tables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnDescriptor {
    /// Column key.
    pub key: String,
    /// Display header.
    pub header: String,
    /// Column width in pixels.
    pub width: u32,
    /// Whether the column is editable.
    pub editable: bool,
}

/// Object tree panel state.
///
/// Ported from `ObjectsTreePanel`.
#[derive(Debug, Clone, Default)]
pub struct ObjectsTreePanelState {
    /// Expanded node paths.
    pub expanded_paths: Vec<Vec<String>>,
    /// Selected node paths.
    pub selected_paths: Vec<Vec<String>>,
    /// Root node key.
    pub root_key: Option<String>,
}

/// Paths table panel state.
///
/// Ported from `PathsTablePanel`.
#[derive(Debug, Clone, Default)]
pub struct PathsTablePanelState {
    /// Displayed path rows.
    pub paths: Vec<PathRowData>,
    /// Selected index.
    pub selected: Option<usize>,
}

/// A row in the paths table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathRowData {
    /// The key path.
    pub path: Vec<String>,
    /// Display label.
    pub label: String,
    /// Lifespan (min_snap, max_snap).
    pub lifespan: (i64, i64),
}

// ===========================================================================
// gui/breakpoint/ - Breakpoint GUI types
// ===========================================================================

/// Breakpoint state table cell editor data.
///
/// Ported from `DebuggerBreakpointStateTableCellEditor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointStateCellEditorData {
    /// Current breakpoint state.
    pub state: BreakpointStateEnum,
    /// Row key being edited.
    pub row_key: Option<String>,
}

/// Breakpoint state for the cell editor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BreakpointStateEnum {
    /// No breakpoint.
    None,
    /// Breakpoint is enabled.
    Enabled,
    /// Breakpoint is disabled.
    Disabled,
    /// Breakpoint is pending.
    Pending,
}

impl Default for BreakpointStateCellEditorData {
    fn default() -> Self {
        Self {
            state: BreakpointStateEnum::None,
            row_key: None,
        }
    }
}

/// Breakpoints decompiler margin provider data.
///
/// Ported from `BreakpointsDecompilerMarginProvider`.
#[derive(Debug, Clone, Default)]
pub struct DecompilerMarginProviderData {
    /// Program key for the current view.
    pub program_key: Option<i64>,
    /// Breakpoint addresses to render in margin.
    pub breakpoint_addresses: Vec<u64>,
    /// Selected breakpoint addresses.
    pub selected_addresses: Vec<u64>,
}

/// Breakpoints provider state.
///
/// Ported from `DebuggerBreakpointsProvider`.
#[derive(Debug, Clone, Default)]
pub struct BreakpointsProviderState {
    /// Current coordinates key.
    pub coordinates_key: Option<i64>,
    /// Filter text.
    pub filter: String,
    /// Whether to show only enabled breakpoints.
    pub show_enabled_only: bool,
    /// Breakpoint rows.
    pub rows: Vec<BreakpointRowData>,
}

/// A breakpoint row in the provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointRowData {
    /// Logical breakpoint offset.
    pub offset: u64,
    /// Expression or address string.
    pub expression: String,
    /// Current state.
    pub state: BreakpointStateEnum,
    /// Kinds (read, write, execute).
    pub kinds: Vec<String>,
    /// Trace-specific location info.
    pub trace_location: Option<String>,
}

/// Breakpoint timeline actions state.
///
/// Ported from `BreakpointTimelineActions`.
#[derive(Debug, Clone)]
pub struct BreakpointTimelineActionsData {
    /// Address/snap pairs for timeline markers.
    pub markers: Vec<AddressSnapPair>,
    /// Whether the timeline is visible.
    pub visible: bool,
}

/// An address/snap pair for timeline markers.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AddressSnapPair {
    /// The address.
    pub address: u64,
    /// The snap, if known.
    pub snap: Option<i64>,
}

impl Default for BreakpointTimelineActionsData {
    fn default() -> Self {
        Self {
            markers: Vec::new(),
            visible: false,
        }
    }
}

// ===========================================================================
// gui/console/ - Console GUI types
// ===========================================================================

/// Console actions cell editor data.
///
/// Ported from `ConsoleActionsCellEditor`.
#[derive(Debug, Clone, Default)]
pub struct ConsoleActionsCellEditorData {
    /// Available actions for the current row.
    pub actions: Vec<ConsoleActionEntry>,
    /// Background color (RGBA).
    pub background: [u8; 4],
}

/// A console action entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleActionEntry {
    /// Action identifier.
    pub id: String,
    /// Display label.
    pub label: String,
    /// Whether enabled.
    pub enabled: bool,
}

/// HTML or progress cell renderer selection.
///
/// Ported from `HtmlOrProgressCellRenderer`. Selects the appropriate
/// renderer based on the cell value type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleCellRendererKind {
    /// Render as HTML text.
    Html,
    /// Render as progress monitor.
    Progress,
    /// Render as plain text.
    Plain,
}

impl ConsoleCellRendererKind {
    /// Determine the renderer kind for the given value type.
    pub fn for_value_type(value_type: &str) -> Self {
        match value_type {
            "html" => Self::Html,
            "monitor" | "progress" => Self::Progress,
            _ => Self::Plain,
        }
    }
}

// ===========================================================================
// gui/copying/ - Copy dialog types
// ===========================================================================

/// Copy-into-program dialog state.
///
/// Ported from `DebuggerCopyIntoProgramDialog`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopyIntoProgramDialogState {
    /// Source trace addresses.
    pub source_ranges: Vec<(u64, u64)>,
    /// Target program URL.
    pub target_program_url: Option<String>,
    /// Target start address.
    pub target_address: Option<u64>,
    /// Whether to overwrite existing data.
    pub overwrite: bool,
    /// Whether the dialog was accepted.
    pub accepted: bool,
}

impl Default for CopyIntoProgramDialogState {
    fn default() -> Self {
        Self {
            source_ranges: Vec::new(),
            target_program_url: None,
            target_address: None,
            overwrite: false,
            accepted: false,
        }
    }
}

// ===========================================================================
// gui/memory/ - Memory regions panel types
// ===========================================================================

/// Add region dialog state.
///
/// Ported from `DebuggerAddRegionDialog`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddRegionDialogState {
    /// Region name.
    pub name: String,
    /// Start address.
    pub start_address: u64,
    /// Length in bytes.
    pub length: u64,
    /// Whether readable.
    pub readable: bool,
    /// Whether writable.
    pub writable: bool,
    /// Whether executable.
    pub executable: bool,
    /// Whether the dialog was accepted.
    pub accepted: bool,
}

impl Default for AddRegionDialogState {
    fn default() -> Self {
        Self {
            name: String::new(),
            start_address: 0,
            length: 0x1000,
            readable: true,
            writable: true,
            executable: false,
            accepted: false,
        }
    }
}

/// Region map proposal dialog state.
///
/// Ported from `DebuggerRegionMapProposalDialog`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegionMapProposalDialogState {
    /// Proposed region mappings: (region_name, trace_min, trace_max, prog_min, prog_max).
    pub proposals: Vec<(String, u64, u64, u64, u64)>,
    /// Accepted state.
    pub accepted: bool,
}

/// Memory bytes panel state.
///
/// Ported from `DebuggerMemoryBytesPanel`.
#[derive(Debug, Clone, Default)]
pub struct MemoryBytesPanelState {
    /// Current data format (hex, octal, binary, etc.).
    pub format: DataFormat,
    /// Bytes per line.
    pub bytes_per_line: u32,
    /// Current selection range.
    pub selection: Option<(u64, u64)>,
}

/// Data format for the byte viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataFormat {
    /// Hexadecimal.
    Hex,
    /// Octal.
    Octal,
    /// Binary.
    Binary,
    /// Decimal.
    Decimal,
    /// Character.
    Char,
}

impl Default for DataFormat {
    fn default() -> Self {
        Self::Hex
    }
}

/// Memory bytes provider state.
///
/// Ported from `DebuggerMemoryBytesProvider`.
#[derive(Debug, Clone, Default)]
pub struct MemoryBytesProviderState {
    /// Current coordinates key.
    pub coordinates_key: Option<i64>,
    /// Current address.
    pub current_address: Option<u64>,
    /// Data format.
    pub format: DataFormat,
    /// Whether synchronized with listing.
    pub sync_with_listing: bool,
}

/// Memory byte viewer component state.
///
/// Ported from `DebuggerMemoryByteViewerComponent`.
#[derive(Debug, Clone, Default)]
pub struct MemoryByteViewerComponentState {
    /// Active colored selections for multi-selection highlighting.
    pub selections: Vec<ColoredFieldSelection>,
    /// Current background color (RGBA).
    pub background_color: [u8; 4],
}

/// Memory regions plugin state.
///
/// Ported from `DebuggerRegionsPlugin`.
#[derive(Debug, Clone, Default)]
pub struct RegionsPluginState {
    /// Whether the plugin is active.
    pub active: bool,
}

/// Memory regions provider state.
///
/// Ported from `DebuggerRegionsProvider`.
#[derive(Debug, Clone, Default)]
pub struct RegionsProviderState {
    /// Current coordinates key.
    pub coordinates_key: Option<i64>,
    /// Region rows.
    pub regions: Vec<RegionRowData>,
    /// Selected region indices.
    pub selected_indices: Vec<usize>,
}

/// A memory region row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionRowData {
    /// Region name.
    pub name: String,
    /// Start address.
    pub start: u64,
    /// Length in bytes.
    pub length: u64,
    /// Whether readable.
    pub readable: bool,
    /// Whether writable.
    pub writable: bool,
    /// Whether executable.
    pub executable: bool,
    /// Lifespan (min_snap, max_snap).
    pub lifespan: (i64, i64),
}

// ===========================================================================
// gui/memview/ - Memory view types
// ===========================================================================

/// Memview panel state.
///
/// Ported from `MemviewPanel`.
#[derive(Debug, Clone, Default)]
pub struct MemviewPanelState {
    /// Current zoom level.
    pub zoom_level: f32,
    /// Visible address range.
    pub visible_range: Option<(u64, u64)>,
}

/// Memview provider state.
///
/// Ported from `MemviewProvider`.
#[derive(Debug, Clone, Default)]
pub struct MemviewProviderState {
    /// Current coordinates key.
    pub coordinates_key: Option<i64>,
    /// Whether the view is active.
    pub active: bool,
}

/// Memview table state.
///
/// Ported from `MemviewTable`.
#[derive(Debug, Clone, Default)]
pub struct MemviewTableState {
    /// Column configuration.
    pub columns: Vec<ColumnDescriptor>,
    /// Sort state.
    pub sort_column: Option<usize>,
}

// ===========================================================================
// gui/modules/ - Modules/sections panel types
// ===========================================================================

/// Modules panel state.
///
/// Ported from `DebuggerModulesPanel`.
#[derive(Debug, Clone, Default)]
pub struct ModulesPanelState {
    /// Selected module names.
    pub selected_modules: Vec<String>,
}

/// Modules provider state.
///
/// Ported from `DebuggerModulesProvider`.
#[derive(Debug, Clone, Default)]
pub struct ModulesProviderState {
    /// Current coordinates key.
    pub coordinates_key: Option<i64>,
    /// Module rows.
    pub modules: Vec<ModuleRowData>,
    /// Selected module indices.
    pub selected_indices: Vec<usize>,
}

/// A module row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleRowData {
    /// Module name.
    pub name: String,
    /// Start address.
    pub start: u64,
    /// Length in bytes.
    pub length: u64,
    /// Whether mapped to a static program.
    pub mapped: bool,
    /// Mapped program name, if any.
    pub mapped_program: Option<String>,
}

/// Sections panel state.
///
/// Ported from `DebuggerSectionsPanel`.
#[derive(Debug, Clone, Default)]
pub struct SectionsPanelState {
    /// Section rows.
    pub sections: Vec<SectionRowData>,
    /// Selected section indices.
    pub selected_indices: Vec<usize>,
}

/// A section row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionRowData {
    /// Section name.
    pub name: String,
    /// Parent module name.
    pub module_name: String,
    /// Start address.
    pub start: u64,
    /// Length in bytes.
    pub length: u64,
}

/// Static mapping plugin state.
///
/// Ported from `DebuggerStaticMappingPlugin`.
#[derive(Debug, Clone, Default)]
pub struct StaticMappingPluginState {
    /// Whether the plugin is active.
    pub active: bool,
}

/// Static mapping provider state.
///
/// Ported from `DebuggerStaticMappingProvider`.
#[derive(Debug, Clone, Default)]
pub struct StaticMappingProviderState {
    /// Mapping rows.
    pub mappings: Vec<StaticMappingRowData>,
    /// Selected mapping indices.
    pub selected_indices: Vec<usize>,
}

/// A static mapping row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticMappingRowData {
    /// Program URL.
    pub program_url: String,
    /// Program address range (min, max).
    pub program_range: (u64, u64),
    /// Trace address range (min, max).
    pub trace_range: (u64, u64),
    /// Lifespan (min_snap, max_snap).
    pub lifespan: (i64, i64),
}

/// Add mapping dialog state.
///
/// Ported from `DebuggerAddMappingDialog`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AddMappingDialogState {
    /// Program URL.
    pub program_url: Option<String>,
    /// Program start address.
    pub program_start: Option<u64>,
    /// Program length.
    pub program_length: Option<u64>,
    /// Trace start address.
    pub trace_start: Option<u64>,
    /// Trace length.
    pub trace_length: Option<u64>,
    /// Whether the dialog was accepted.
    pub accepted: bool,
}

/// Module map proposal dialog state.
///
/// Ported from `DebuggerModuleMapProposalDialog`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleMapProposalDialogState {
    /// Module name.
    pub module_name: Option<String>,
    /// Proposed mappings.
    pub proposals: Vec<(u64, u64, u64, u64)>,
    /// Accepted.
    pub accepted: bool,
}

/// Section map proposal dialog state.
///
/// Ported from `DebuggerSectionMapProposalDialog`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SectionMapProposalDialogState {
    /// Section name.
    pub section_name: Option<String>,
    /// Proposed mappings.
    pub proposals: Vec<(u64, u64, u64, u64)>,
    /// Accepted.
    pub accepted: bool,
}

// ===========================================================================
// gui/register/ - Registers panel types
// ===========================================================================

/// Registers provider state.
///
/// Ported from `DebuggerRegistersProvider`.
#[derive(Debug, Clone, Default)]
pub struct RegistersProviderState {
    /// Current coordinates key.
    pub coordinates_key: Option<i64>,
    /// Register rows.
    pub registers: Vec<RegisterRowData>,
    /// Selected register indices.
    pub selected_indices: Vec<usize>,
}

/// A register row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRowData {
    /// Register name.
    pub name: String,
    /// Register value (as bytes).
    pub value: Vec<u8>,
    /// Whether the register value has changed.
    pub changed: bool,
    /// Register group name.
    pub group: String,
}

/// Register column factory data.
///
/// Ported from `DebuggerRegisterColumnFactory`.
#[derive(Debug, Clone, Default)]
pub struct RegisterColumnFactoryData {
    /// Column definitions.
    pub columns: Vec<ColumnDescriptor>,
}

/// Available registers dialog state.
///
/// Ported from `DebuggerAvailableRegistersDialog`.
#[derive(Debug, Clone, Default)]
pub struct AvailableRegistersDialogState {
    /// Available register names.
    pub available: Vec<String>,
    /// Currently visible registers.
    pub visible: Vec<String>,
    /// Accepted.
    pub accepted: bool,
}

// ===========================================================================
// gui/stack/ - Stack panel types
// ===========================================================================

/// Stack panel state.
///
/// Ported from `DebuggerStackPanel`.
#[derive(Debug, Clone, Default)]
pub struct StackPanelState {
    /// Frame rows.
    pub frames: Vec<StackFrameRowData>,
    /// Selected frame index.
    pub selected_frame: Option<usize>,
}

/// A stack frame row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrameRowData {
    /// Frame level (0 = innermost).
    pub level: usize,
    /// Program counter.
    pub pc: Option<u64>,
    /// Function name, if known.
    pub function_name: Option<String>,
    /// Module name, if known.
    pub module_name: Option<String>,
}

/// Stack provider state.
///
/// Ported from `DebuggerStackProvider`.
#[derive(Debug, Clone, Default)]
pub struct StackProviderState {
    /// Current coordinates key.
    pub coordinates_key: Option<i64>,
    /// Panel state.
    pub panel: StackPanelState,
}

// ===========================================================================
// gui/stack/vars/ - Variable value hover service
// ===========================================================================

/// Variable value hover service data.
///
/// Ported from `VariableValueHoverService`. Manages the data for hovering
/// over variables in the listing/stack to show their values.
#[derive(Debug, Clone, Default)]
pub struct VariableValueHoverServiceData {
    /// Current variable values at the hovered address.
    pub values: Vec<VariableValueEntry>,
    /// Whether the service is active.
    pub active: bool,
}

/// A variable value entry for hover display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableValueEntry {
    /// Variable name.
    pub name: String,
    /// Variable value as string.
    pub value: String,
    /// Variable type name.
    pub type_name: String,
    /// Stack frame level.
    pub frame_level: usize,
}

// ===========================================================================
// gui/thread/ - Thread panel types
// ===========================================================================

/// Threads panel state.
///
/// Ported from `DebuggerThreadsPanel`.
#[derive(Debug, Clone, Default)]
pub struct ThreadsPanelState {
    /// Thread rows.
    pub threads: Vec<ThreadRowData>,
    /// Selected thread indices.
    pub selected_indices: Vec<usize>,
}

/// A thread row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadRowData {
    /// Thread ID.
    pub tid: i64,
    /// Thread name.
    pub name: String,
    /// Current state (running, stopped, etc.).
    pub state: String,
    /// Program counter, if stopped.
    pub pc: Option<u64>,
    /// Process ID.
    pub pid: i64,
}

/// Threads provider state.
///
/// Ported from `DebuggerThreadsProvider`.
#[derive(Debug, Clone, Default)]
pub struct ThreadsProviderState {
    /// Current coordinates key.
    pub coordinates_key: Option<i64>,
    /// Panel state.
    pub panel: ThreadsPanelState,
}

// ===========================================================================
// gui/time/ - Time/snapshot panel types
// ===========================================================================

/// Snapshot table panel state.
///
/// Ported from `DebuggerSnapshotTablePanel`.
#[derive(Debug, Clone, Default)]
pub struct SnapshotTablePanelState {
    /// Snapshot rows.
    pub snapshots: Vec<SnapshotRowData>,
    /// Selected snapshot indices.
    pub selected_indices: Vec<usize>,
    /// Current snap.
    pub current_snap: i64,
}

/// A snapshot row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRowData {
    /// Snapshot key.
    pub snap: i64,
    /// Description, if any.
    pub description: Option<String>,
    /// Creation timestamp.
    pub timestamp: Option<String>,
}

/// Time provider state.
///
/// Ported from `DebuggerTimeProvider`.
#[derive(Debug, Clone, Default)]
pub struct TimeProviderState {
    /// Current coordinates key.
    pub coordinates_key: Option<i64>,
    /// Panel state.
    pub panel: SnapshotTablePanelState,
}

/// Time selection dialog state.
///
/// Ported from `DebuggerTimeSelectionDialog`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimeSelectionDialogState {
    /// Minimum snap.
    pub min_snap: i64,
    /// Maximum snap.
    pub max_snap: i64,
    /// Selected snap.
    pub selected_snap: i64,
    /// Accepted.
    pub accepted: bool,
}

// ===========================================================================
// gui/timeoverview/ - Time overview types
// ===========================================================================

/// Time overview color component data.
///
/// Ported from `TimeOverviewColorComponent`.
#[derive(Debug, Clone, Default)]
pub struct TimeOverviewColorComponentData {
    /// Color entries for each time slot.
    pub entries: Vec<TimeOverviewEntry>,
}

/// A time overview color entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeOverviewEntry {
    /// Snap value.
    pub snap: i64,
    /// Color (RGBA).
    pub color: [u8; 4],
}

/// Break type overview legend panel data.
///
/// Ported from `BreakTypeOverviewLegendPanel`.
#[derive(Debug, Clone, Default)]
pub struct BreakTypeLegendData {
    /// Legend entries.
    pub entries: Vec<BreakTypeLegendEntry>,
}

/// A break type legend entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakTypeLegendEntry {
    /// Display label.
    pub label: String,
    /// Color (RGBA).
    pub color: [u8; 4],
}

/// Breakpoint time overview color service data.
///
/// Ported from `BreakpointTimeOverviewColorService`.
#[derive(Debug, Clone, Default)]
pub struct BreakpointTimeOverviewData {
    /// Color entries per snap.
    pub entries: Vec<TimeOverviewEntry>,
    /// Breakpoint types being tracked.
    pub tracked_types: Vec<String>,
}

/// Time type overview legend panel data.
///
/// Ported from `TimeTypeOverviewLegendPanel`.
#[derive(Debug, Clone, Default)]
pub struct TimeTypeLegendData {
    /// Legend entries.
    pub entries: Vec<TimeTypeLegendEntry>,
}

/// A time type legend entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeTypeLegendEntry {
    /// Display label.
    pub label: String,
    /// Color (RGBA).
    pub color: [u8; 4],
    /// Time type identifier.
    pub time_type: String,
}

// ===========================================================================
// gui/tracecalltree/ - Trace call tree types
// ===========================================================================

/// Call tree node kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallTreeNodeKind {
    /// A regular call.
    Call,
    /// An external (library) call.
    External,
    /// A return from a call.
    Return,
    /// A tail call.
    TailCall,
}

/// Abstract trace call tree node data.
///
/// Ported from `AbstractTraceCallTreeNode` and its subclasses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCallTreeNodeData {
    /// Node kind.
    pub kind: CallTreeNodeKind,
    /// Function name.
    pub name: String,
    /// Module name.
    pub module_name: String,
    /// Snapshot key.
    pub snap: i64,
    /// Parameters.
    pub parameters: Vec<ParamNameToBytes>,
    /// Return value bytes.
    pub return_value: Vec<u8>,
    /// Child nodes.
    pub children: Vec<TraceCallTreeNodeData>,
}

/// A parameter name-to-bytes mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamNameToBytes {
    /// Parameter name.
    pub name: String,
    /// Parameter value as bytes.
    pub bytes: Vec<u8>,
}

impl TraceCallTreeNodeData {
    /// Get the display text for this node.
    pub fn get_tree_data(&self) -> String {
        match self.kind {
            CallTreeNodeKind::Call => format!("Call: {}", self.name),
            CallTreeNodeKind::External => format!("External: {}", self.name),
            CallTreeNodeKind::Return => format!("Return: {}", self.name),
            CallTreeNodeKind::TailCall => format!("Tail Call: {}", self.name),
        }
    }
}

/// Call tree provider state.
///
/// Ported from `TraceCallTreeProvider`.
#[derive(Debug, Clone, Default)]
pub struct CallTreeProviderState {
    /// Current coordinates key.
    pub coordinates_key: Option<i64>,
    /// Root nodes.
    pub roots: Vec<TraceCallTreeNodeData>,
    /// Status message.
    pub status_message: Option<String>,
    /// Whether currently loading.
    pub loading: bool,
}

/// Call tree table state.
///
/// Ported from `TraceCallTreeTable`.
#[derive(Debug, Clone, Default)]
pub struct CallTreeTableState {
    /// Sort column.
    pub sort_column: Option<usize>,
    /// Status message overlay.
    pub status_message: Option<String>,
}

// ===========================================================================
// gui/watch/ - Watches panel types
// ===========================================================================

/// Watches provider state.
///
/// Ported from `DebuggerWatchesProvider`.
#[derive(Debug, Clone, Default)]
pub struct WatchesProviderState {
    /// Current coordinates key.
    pub coordinates_key: Option<i64>,
    /// Watch rows.
    pub watches: Vec<WatchRowData>,
    /// Selected watch indices.
    pub selected_indices: Vec<usize>,
}

/// A watch row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchRowData {
    /// Watch expression.
    pub expression: String,
    /// Current value as string.
    pub value: Option<String>,
    /// Current value as bytes.
    pub value_bytes: Vec<u8>,
    /// Value type name.
    pub type_name: Option<String>,
    /// Error message, if evaluation failed.
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_source_data() {
        let src = DebuggerByteSourceData::new();
        assert!(!src.has_view());
        let mut src2 = src;
        src2.view_key = Some(1);
        assert!(src2.has_view());
    }

    #[test]
    fn test_location_label() {
        let mut label = DebuggerLocationLabelData::new();
        assert_eq!(label.label, "");
        label.update(None, 0, None);
        assert_eq!(label.label, "(nowhere)");
        label.update(Some(1), 5, Some(0x400000));
        assert_eq!(label.label, "(unknown)");
        label.set_label("libc.so:__libc_start_main".into());
        assert!(label.label.contains("libc"));
    }

    #[test]
    fn test_parameter_dialog() {
        let mut dlg = ParameterDialogState::new("Launch GDB");
        dlg.add_string("host", "localhost");
        dlg.add_string("port", "23946");
        dlg.add_bool("use_pipe", true);
        assert_eq!(dlg.get_string("host"), Some("localhost"));
        assert_eq!(dlg.get_string("missing"), None);
    }

    #[test]
    fn test_resume_action_spec() {
        let spec = ResumeActionSpec::default();
        assert_eq!(spec.sub_group, 0);
        assert_eq!(spec.key_code, 116); // F5
    }

    #[test]
    fn test_step_into_action_spec() {
        let spec = StepIntoActionSpec::default();
        assert_eq!(spec.sub_group, 3);
        assert_eq!(spec.key_code, 119); // F8
    }

    #[test]
    fn test_tracked_register_color_model() {
        let model = TrackedRegisterColorModel::new();
        let normal = model.color_for(0x1000);
        assert_eq!(normal, model.default_background);

        let mut model2 = model.clone();
        model2.tracked_address = Some(0x1000);
        let tracked = model2.color_for(0x1000);
        assert_eq!(tracked, model2.tracking_color);

        let other = model2.color_for(0x2000);
        assert_eq!(other, model2.default_background);
    }

    #[test]
    fn test_multi_selection_blended() {
        let mut mgr = MultiSelectionBlendedColorManager::new(0, [0xff, 0xff, 0xff, 0xff]);
        assert_eq!(mgr.get_background_color(), [0xff, 0xff, 0xff, 0xff]);

        mgr.add_selection(ColoredFieldSelection {
            ranges: vec![(0, 0, 10)],
            color: [0x00, 0x00, 0xff, 0xff],
        });
        let blended = mgr.get_background_color();
        // Should be blend of white and blue
        assert!(blended[2] > blended[0]); // more blue than red
    }

    #[test]
    fn test_colors_modified_config() {
        let config = ColorsModifiedConfig::default();
        assert_eq!(config.foreground_for(false, false), config.foreground);
        assert_eq!(config.foreground_for(false, true), config.selected_foreground);
        assert_eq!(config.foreground_for(true, false), config.diff_foreground);
        assert_eq!(config.foreground_for(true, true), config.diff_selected_foreground);
    }

    #[test]
    fn test_displays_modified_state() {
        let mut state = DisplaysModifiedState::default();
        assert!(!state.is_modified(&["a".into(), "b".into()]));
        state.mark_modified(vec!["a".into(), "b".into()]);
        assert!(state.is_modified(&["a".into(), "b".into()]));
        state.clear();
        assert!(!state.is_modified(&["a".into(), "b".into()]));
    }

    #[test]
    fn test_cursor_color_model() {
        let mut model = CursorBackgroundColorModelData::default();
        assert_eq!(model.color_for(0x1000), model.default_background);

        model.cursor_address = Some(0x1000);
        assert_eq!(model.color_for(0x1000), model.cursor_color);
        assert_eq!(model.color_for(0x2000), model.default_background);

        model.highlight_enabled = false;
        assert_eq!(model.color_for(0x1000), model.default_background);
    }

    #[test]
    fn test_memory_state_color_model() {
        let mut model = MemoryStateColorModelData::default();
        assert_eq!(model.color_for(0x1000), model.default_background);

        model.set_state(0x1000, 0x10FF, MemoryStateEnum::Unknown);
        assert_eq!(model.color_for(0x1000), model.unknown_blended_color);
        assert_eq!(model.color_for(0x1100), model.default_background);

        model.states.insert(0x2000, MemoryStateEnum::Error);
        assert_eq!(model.color_for(0x2000), model.error_color);
    }

    #[test]
    fn test_breakpoint_state_enum() {
        assert_ne!(BreakpointStateEnum::None, BreakpointStateEnum::Enabled);
        let editor = BreakpointStateCellEditorData::default();
        assert_eq!(editor.state, BreakpointStateEnum::None);
    }

    #[test]
    fn test_console_cell_renderer_kind() {
        assert_eq!(ConsoleCellRendererKind::for_value_type("html"), ConsoleCellRendererKind::Html);
        assert_eq!(ConsoleCellRendererKind::for_value_type("monitor"), ConsoleCellRendererKind::Progress);
        assert_eq!(ConsoleCellRendererKind::for_value_type("text"), ConsoleCellRendererKind::Plain);
    }

    #[test]
    fn test_call_tree_node() {
        let node = TraceCallTreeNodeData {
            kind: CallTreeNodeKind::External,
            name: "malloc".into(),
            module_name: "libc.so".into(),
            snap: 0,
            parameters: vec![ParamNameToBytes { name: "size".into(), bytes: vec![0x10, 0x00] }],
            return_value: vec![0x00, 0x40, 0x00, 0x00],
            children: vec![],
        };
        assert_eq!(node.get_tree_data(), "External: malloc");
    }

    #[test]
    fn test_add_region_dialog() {
        let mut state = AddRegionDialogState::default();
        assert!(!state.accepted);
        state.name = ".text".into();
        state.start_address = 0x400000;
        state.length = 0x10000;
        state.accepted = true;
        assert!(state.accepted);
        assert_eq!(state.name, ".text");
    }

    #[test]
    fn test_copy_into_program_dialog() {
        let mut state = CopyIntoProgramDialogState::default();
        state.source_ranges.push((0x400000, 0x401000));
        state.target_address = Some(0x100000);
        assert_eq!(state.source_ranges.len(), 1);
    }

    #[test]
    fn test_watch_row_data() {
        let row = WatchRowData {
            expression: "eax".into(),
            value: Some("0x42".into()),
            value_bytes: vec![0x42, 0x00, 0x00, 0x00],
            type_name: Some("int".into()),
            error: None,
        };
        assert_eq!(row.expression, "eax");
        assert!(row.error.is_none());
    }

    #[test]
    fn test_snapshot_row_data() {
        let row = SnapshotRowData {
            snap: 5,
            description: Some("After breakpoint hit".into()),
            timestamp: Some("2024-01-01T00:00:00Z".into()),
        };
        assert_eq!(row.snap, 5);
    }

    #[test]
    fn test_thread_row_data() {
        let row = ThreadRowData {
            tid: 1234,
            name: "main".into(),
            state: "stopped".into(),
            pc: Some(0x400000),
            pid: 100,
        };
        assert_eq!(row.state, "stopped");
    }

    #[test]
    fn test_module_row_data() {
        let row = ModuleRowData {
            name: "libc.so".into(),
            start: 0x7f0000000000,
            length: 0x200000,
            mapped: true,
            mapped_program: Some("/lib/x86_64-linux-gnu/libc.so".into()),
        };
        assert!(row.mapped);
    }

    #[test]
    fn test_data_format_default() {
        assert_eq!(DataFormat::default(), DataFormat::Hex);
    }

    #[test]
    fn test_static_mapping_row_data() {
        let row = StaticMappingRowData {
            program_url: "file:///home/user/program".into(),
            program_range: (0x400000, 0x401000),
            trace_range: (0x7f0000000000, 0x7f0000001000),
            lifespan: (0, i64::MAX),
        };
        assert_eq!(row.program_range.1 - row.program_range.0, 0x1000);
    }

    #[test]
    fn test_time_overview_entries() {
        let data = BreakpointTimeOverviewData {
            entries: vec![
                TimeOverviewEntry { snap: 0, color: [0xff, 0x00, 0x00, 0xff] },
                TimeOverviewEntry { snap: 1, color: [0x00, 0xff, 0x00, 0xff] },
            ],
            tracked_types: vec!["SW_EXECUTE".into()],
        };
        assert_eq!(data.entries.len(), 2);
    }

    #[test]
    fn test_variable_value_hover() {
        let mut data = VariableValueHoverServiceData::default();
        data.values.push(VariableValueEntry {
            name: "x".into(),
            value: "42".into(),
            type_name: "int".into(),
            frame_level: 0,
        });
        data.active = true;
        assert_eq!(data.values.len(), 1);
        assert!(data.active);
    }
}
