//! Decompiler provider -- Rust port of
//! `ghidra.app.plugin.core.decompile.DecompilerProvider`.
//!
//! Each provider manages one decompiler panel.  A "connected" provider
//! is linked to the main tool and receives program/location/selection
//! events automatically.  A "disconnected" provider is a snapshot that
//! only works with a fixed program.
//!
//! # Architecture
//!
//! ```text
//! DecompilerProvider
//!   ├── DecompilerController      (drives decompilation)
//!   ├── DecompilerClipboardProvider (clipboard integration)
//!   ├── DecompilerProgramListener  (domain-object changes)
//!   ├── OverlayMessagePainter      (lock-display messages)
//!   ├── HighlightController        (token highlighting)
//!   ├── ActionRegistry             (40+ registered actions)
//!   ├── FollowUpWorkQueue          (deferred callbacks)
//!   ├── ToggleActions
//!   │     ├── DisplayUnreachableCode
//!   │     ├── RespectReadOnlyFlags
//!   │     ├── LockDisplay
//!   │     └── OutgoingEvents
//!   └── Navigation
//!         ├── goTo()
//!         ├── goToAddress()
//!         ├── goToFunction()
//!         ├── goToLabel()
//!         └── goToScalar()
//! ```
//!
//! # Action Groups
//!
//! Actions are registered in popup-menu groups that control their
//! ordering:
//!
//! | Group | Actions |
//! |-------|---------|
//! | 1 - Function Group | SpecifyCPrototype, OverridePrototype, EditPrototypeOverride, DeletePrototypeOverride, RenameFunction, RenameLabel, RemoveLabel |
//! | 2 - Variable Group | RenameLocal, RenameGlobal, RenameField, RenameBitField, ForceUnion, RetypeLocal, CreatePointerRelative, RetypeGlobal, RetypeReturn, RetypeField, IsolateVariable, CreateStructure, EditDataType, EditField |
//! | 3 - Commit Group | CommitParams, CommitLocals |
//! | 4a - Highlight Group | HighlightDefinedUse, ForwardSlice, BackwardsSlice, ForwardSliceToPCodeOps, BackwardsSliceToPCodeOps, SetSecondaryHighlight, SetSecondaryHighlightColor, RemoveSecondaryHighlight, RemoveAllSecondaryHighlights, PreviousHighlightedToken, NextHighlightedToken |
//! | 7 - Convert Group | RemoveEquate, SetEquate, ConvertBinary, ConvertDec, ConvertFloat, ConvertDouble, ConvertHex, ConvertOct, ConvertChar |
//! | Comment2 - Search Group | Find, FindReferencesToDataType, FindReferencesToHighSymbol, FindReferencesToAddress |
//! | comment6 - Options Group | EditProperties |

use std::collections::VecDeque;

use ghidra_core::addr::Address;

use super::overlay_painter::OverlayMessagePainter;
use super::plugin::SaveState;

// ---------------------------------------------------------------------------
// ProviderState
// ---------------------------------------------------------------------------

/// The lifecycle state of a decompiler provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderState {
    /// The provider has been created but not yet displayed.
    Created,
    /// The provider is visible and active.
    Visible,
    /// The provider is hidden (minimised or behind other tabs).
    Hidden,
    /// The provider has been disposed.
    Disposed,
}

// ---------------------------------------------------------------------------
// Display lock state
// ---------------------------------------------------------------------------

/// Whether the decompiler display is "locked" (not auto-refreshing).
///
/// When locked, program changes cause an overlay message ("Press F5 to
/// refresh") instead of an automatic re-decompile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayLockState {
    /// Normal mode: auto-refresh on changes.
    Unlocked,
    /// Locked mode: manual refresh only.
    Locked,
}

// ---------------------------------------------------------------------------
// ToggleButtonState
// ---------------------------------------------------------------------------

/// The state of a toolbar toggle button in the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToggleButtonState {
    /// Whether the button is currently selected (active).
    pub selected: bool,
}

impl Default for ToggleButtonState {
    fn default() -> Self {
        Self { selected: false }
    }
}

// ---------------------------------------------------------------------------
// ViewerPosition -- scroll/cursor position in the decompiler panel
// ---------------------------------------------------------------------------

/// The viewer position (scroll state) of the decompiler panel.
///
/// In Ghidra this is `ViewerPosition` from the docking framework,
/// which stores a row index and pixel y-offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ViewerPosition {
    /// The row index (0-based).
    pub index: i32,
    /// The column index (usually 0).
    pub col: i32,
    /// The pixel y-offset within the row.
    pub y_offset: i32,
}

impl ViewerPosition {
    /// Create a new viewer position.
    pub fn new(index: i32, col: i32, y_offset: i32) -> Self {
        Self {
            index,
            col,
            y_offset,
        }
    }

    /// Create a viewer position at the top of the document.
    pub fn origin() -> Self {
        Self::new(0, 0, 0)
    }
}

impl Default for ViewerPosition {
    fn default() -> Self {
        Self::origin()
    }
}

// ---------------------------------------------------------------------------
// CursorLocation -- a cursor position in the decompiler panel
// ---------------------------------------------------------------------------

/// A cursor position in the decompiler panel, consisting of a line
/// number (1-based) and a character offset within the line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorLocation {
    /// 1-based line number.
    pub line: usize,
    /// 0-based character offset from the start of the line.
    pub offset: usize,
}

impl CursorLocation {
    /// Create a new cursor location.
    pub fn new(line: usize, offset: usize) -> Self {
        Self { line, offset }
    }
}

// ---------------------------------------------------------------------------
// ActionGroupInfo -- menu group ordering for an action
// ---------------------------------------------------------------------------

/// Describes how an action is placed in the popup menu.
#[derive(Debug, Clone)]
pub struct ActionGroupInfo {
    /// The action's name (unique identifier).
    pub action_name: String,
    /// The menu group (e.g., `"1 - Function Group"`).
    pub group: String,
    /// The sub-group position within the group (0-based).
    pub sub_group: u32,
    /// Whether this action appears in the popup menu.
    pub in_popup: bool,
    /// Whether this action is registered as a local action.
    pub is_local: bool,
    /// The key binding (if any).
    pub key_binding: Option<String>,
}

// ---------------------------------------------------------------------------
// NavigationTarget -- where to navigate
// ---------------------------------------------------------------------------

/// A navigation target for the decompiler's `goTo` methods.
#[derive(Debug, Clone)]
pub enum NavigationTarget {
    /// Navigate to an address.
    Address(Address),
    /// Navigate to a function by entry point.
    Function {
        /// The function entry point.
        entry: Address,
        /// Whether the function is external.
        is_external: bool,
    },
    /// Navigate to a label by name.
    Label(String),
    /// Navigate to a scalar value.
    Scalar(i64),
}

// ---------------------------------------------------------------------------
// GraphServiceState -- tracks graph display service availability
// ---------------------------------------------------------------------------

/// Whether the graph display service is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphServiceState {
    /// The service is not available.
    Unavailable,
    /// The service is available and graph actions are registered.
    Available,
}

// ---------------------------------------------------------------------------
// DecompilerProvider
// ---------------------------------------------------------------------------

/// A decompiler view provider.
///
/// Manages the lifecycle of a single decompiler panel -- program binding,
/// location tracking, selection, display lock, overlay messages, action
/// registration, navigation, and state persistence.
///
/// Connected providers are created with `new_connected()` and receive
/// events from the plugin.  Disconnected providers (snapshots) are
/// created with `new_disconnected()` and work only with their fixed
/// program.
pub struct DecompilerProvider {
    /// Unique identifier (0 = connected, >0 = disconnected).
    id: usize,
    /// Whether this provider is connected to the main tool.
    is_connected: bool,
    /// Current state.
    state: ProviderState,
    /// The program name bound to this provider.
    program_name: Option<String>,
    /// The current location (address offset).
    current_location: Option<Address>,
    /// The current selection range (start, end).
    current_selection: Option<(Address, Address)>,
    /// The text selection (selected text in the decompiler panel).
    text_selection: Option<String>,
    /// Display lock state.
    display_lock: DisplayLockState,
    /// Whether outgoing events are allowed (only meaningful for
    /// disconnected providers).
    allow_outgoing_events: bool,
    /// The overlay message painter.
    overlay_painter: OverlayMessagePainter,
    /// Toggle: show unreachable code.
    toggle_unreachable: ToggleButtonState,
    /// Toggle: respect read-only flags.
    toggle_read_only: ToggleButtonState,
    /// Title of the provider window.
    title: String,
    /// Subtitle (e.g., program name).
    subtitle: String,
    /// Tab text.
    tab_text: String,
    /// The function name currently being displayed.
    function_name: Option<String>,
    /// The current cursor location.
    cursor: Option<CursorLocation>,
    /// The current viewer (scroll) position.
    viewer_position: ViewerPosition,
    /// Pending viewer position (from state restore).
    pending_viewer_position: Option<ViewerPosition>,
    /// Registered actions with their group info.
    actions: Vec<ActionGroupInfo>,
    /// Graph display service state.
    graph_service: GraphServiceState,
    /// Follow-up work queue -- callbacks deferred until the provider
    /// is not busy.
    follow_up_work: VecDeque<Box<dyn FnOnce() + Send>>,
    /// Whether the provider is currently busy (decompiling).
    is_busy: bool,
    /// The refresh action's key binding display name.
    refresh_key_binding: Option<String>,
}

impl std::fmt::Debug for DecompilerProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecompilerProvider")
            .field("id", &self.id)
            .field("is_connected", &self.is_connected)
            .field("state", &self.state)
            .field("is_busy", &self.is_busy)
            .finish()
    }
}

impl DecompilerProvider {
    /// Create a new connected provider.
    pub fn new_connected(id: usize) -> Self {
        let mut provider = Self::new_base(id, true);
        provider.create_actions();
        provider
    }

    /// Create a new disconnected (snapshot) provider.
    pub fn new_disconnected(id: usize) -> Self {
        let mut provider = Self::new_base(id, false);
        provider.create_actions();
        provider
    }

    /// Internal base constructor.
    fn new_base(id: usize, is_connected: bool) -> Self {
        Self {
            id,
            is_connected,
            state: ProviderState::Created,
            program_name: None,
            current_location: None,
            current_selection: None,
            text_selection: None,
            display_lock: DisplayLockState::Unlocked,
            allow_outgoing_events: false,
            overlay_painter: OverlayMessagePainter::new(),
            toggle_unreachable: ToggleButtonState { selected: false },
            toggle_read_only: ToggleButtonState { selected: false },
            title: if is_connected {
                "Decompile".into()
            } else {
                "[Decompile]".into()
            },
            subtitle: String::new(),
            tab_text: if is_connected {
                "Decompiler".into()
            } else {
                "[Decompiler]".into()
            },
            function_name: None,
            cursor: None,
            viewer_position: ViewerPosition::default(),
            pending_viewer_position: None,
            actions: Vec::new(),
            graph_service: GraphServiceState::Unavailable,
            follow_up_work: VecDeque::new(),
            is_busy: false,
            refresh_key_binding: Some("F5".into()),
        }
    }

    // -- Accessors ------------------------------------------------------------

    /// The provider's unique id.
    pub fn id(&self) -> usize {
        self.id
    }

    /// Returns `true` if this is a connected provider.
    pub fn is_connected(&self) -> bool {
        self.is_connected
    }

    /// Returns `true` if this is a snapshot (disconnected) provider.
    pub fn is_snapshot(&self) -> bool {
        !self.is_connected
    }

    /// Get the current state.
    pub fn state(&self) -> ProviderState {
        self.state
    }

    /// Set the provider to visible.
    pub fn set_visible(&mut self) {
        if self.state != ProviderState::Disposed {
            self.state = ProviderState::Visible;
        }
    }

    /// Set the provider to hidden.
    pub fn set_hidden(&mut self) {
        if self.state != ProviderState::Disposed {
            self.state = ProviderState::Hidden;
        }
    }

    /// Get the bound program name.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// Set the program for this provider.
    pub fn set_program(&mut self, name: Option<String>) {
        self.program_name = name;
        self.current_location = None;
        self.current_selection = None;
        self.text_selection = None;
        self.function_name = None;
        self.cursor = None;
        self.update_title();
    }

    /// Get the current location.
    pub fn current_location(&self) -> Option<Address> {
        self.current_location
    }

    /// Set the current location.
    pub fn set_location(&mut self, location: Option<Address>) {
        self.current_location = location;
    }

    /// Get the current selection.
    pub fn current_selection(&self) -> Option<(Address, Address)> {
        self.current_selection
    }

    /// Set the current selection.
    pub fn set_selection(&mut self, selection: Option<(Address, Address)>) {
        self.current_selection = selection;
    }

    /// Get the current text selection.
    pub fn text_selection(&self) -> Option<&str> {
        self.text_selection.as_deref()
    }

    /// Set the text selection.
    pub fn set_text_selection(&mut self, text: Option<String>) {
        self.text_selection = text;
    }

    /// Returns `true` if there is a selection.
    pub fn has_selection(&self) -> bool {
        self.current_selection.is_some()
            || self
                .text_selection
                .as_ref()
                .map(|s| !s.is_empty())
                .unwrap_or(false)
    }

    /// Toggle the display lock.
    pub fn toggle_display_lock(&mut self) {
        self.display_lock = match self.display_lock {
            DisplayLockState::Unlocked => DisplayLockState::Locked,
            DisplayLockState::Locked => {
                self.overlay_painter.clear();
                DisplayLockState::Unlocked
            }
        };
    }

    /// Returns the display lock state.
    pub fn display_lock(&self) -> DisplayLockState {
        self.display_lock
    }

    /// Toggle whether outgoing events are allowed (disconnected providers).
    pub fn toggle_outgoing_events(&mut self) {
        self.allow_outgoing_events = !self.allow_outgoing_events;
    }

    /// Whether this provider should send events to the tool.
    pub fn should_send_events(&self) -> bool {
        self.is_connected || self.allow_outgoing_events
    }

    /// Get the overlay painter.
    pub fn overlay_painter(&self) -> &OverlayMessagePainter {
        &self.overlay_painter
    }

    /// Get a mutable reference to the overlay painter.
    pub fn overlay_painter_mut(&mut self) -> &mut OverlayMessagePainter {
        &mut self.overlay_painter
    }

    /// Toggle the unreachable code display.
    pub fn toggle_unreachable_code(&mut self) {
        self.toggle_unreachable.selected = !self.toggle_unreachable.selected;
    }

    /// Returns whether unreachable code display is enabled.
    pub fn is_showing_unreachable_code(&self) -> bool {
        self.toggle_unreachable.selected
    }

    /// Toggle respect for read-only flags.
    pub fn toggle_respect_read_only(&mut self) {
        self.toggle_read_only.selected = !self.toggle_read_only.selected;
    }

    /// Returns whether read-only flags are being respected.
    pub fn is_respecting_read_only(&self) -> bool {
        self.toggle_read_only.selected
    }

    /// Get the current function name.
    pub fn function_name(&self) -> Option<&str> {
        self.function_name.as_deref()
    }

    /// Set the current function name (updates the title).
    pub fn set_function_name(&mut self, name: Option<String>) {
        self.function_name = name;
        self.update_title();
    }

    /// Get the cursor location.
    pub fn cursor(&self) -> Option<CursorLocation> {
        self.cursor
    }

    /// Set the cursor location.
    pub fn set_cursor(&mut self, cursor: Option<CursorLocation>) {
        self.cursor = cursor;
    }

    /// Set the cursor to a specific line and offset.
    pub fn set_cursor_location(&mut self, line: usize, offset: usize) {
        self.cursor = Some(CursorLocation::new(line, offset));
    }

    /// Get the viewer (scroll) position.
    pub fn viewer_position(&self) -> ViewerPosition {
        self.viewer_position
    }

    /// Set the viewer position.
    pub fn set_viewer_position(&mut self, pos: ViewerPosition) {
        self.viewer_position = pos;
    }

    /// Set a pending viewer position (from state restore).
    pub fn set_pending_viewer_position(&mut self, pos: ViewerPosition) {
        self.pending_viewer_position = Some(pos);
    }

    /// Returns whether the provider is busy (decompiling).
    pub fn is_busy(&self) -> bool {
        self.is_busy
    }

    /// Set the busy state.
    pub fn set_busy(&mut self, busy: bool) {
        self.is_busy = busy;
    }

    /// Returns the window title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the window subtitle.
    pub fn subtitle(&self) -> &str {
        &self.subtitle
    }

    /// Returns the tab text.
    pub fn tab_text(&self) -> &str {
        &self.tab_text
    }

    /// Get the graph service state.
    pub fn graph_service_state(&self) -> GraphServiceState {
        self.graph_service
    }

    // -- Action Management ----------------------------------------------------

    /// Create and register all decompiler actions.
    ///
    /// This mirrors the `createActions()` method in the Java
    /// `DecompilerProvider`, which registers 40+ actions in
    /// specific menu groups.
    fn create_actions(&mut self) {
        // -- Toolbar / non-menu actions --
        self.register_action("Lock Display", "toolbar", 0, false, true, None);
        if !self.is_connected {
            self.register_action(
                "Decompiler Outgoing Events",
                "toolbar",
                0,
                false,
                true,
                None,
            );
        }
        self.register_action("Select All", "toolbar", 0, false, true, None);
        self.register_action("Refresh", "toolbar", 0, true, true, Some("F5"));
        self.register_action(
            "Toggle Unreachable Code",
            "toolbar",
            0,
            false,
            true,
            None,
        );
        self.register_action(
            "Toggle Respecting Read-only Flags",
            "toolbar",
            0,
            false,
            true,
            None,
        );

        // -- 1 - Function Group --
        let func_group = "1 - Function Group";
        let mut sub = 0u32;
        self.register_action("Specify C Prototype", func_group, sub, true, true, None);
        sub += 1;
        self.register_action("Override Prototype", func_group, sub, true, true, None);
        sub += 1;
        self.register_action(
            "Edit Prototype Override",
            func_group,
            sub,
            true,
            true,
            None,
        );
        sub += 1;
        self.register_action(
            "Delete Prototype Override",
            func_group,
            sub,
            true,
            true,
            None,
        );
        sub += 1;
        self.register_action("Rename Function", func_group, sub, true, true, Some("L"));
        sub += 1;
        self.register_action("Rename Label", func_group, sub, true, true, Some("L"));
        sub += 1;
        self.register_action("Remove Label", func_group, sub, true, true, None);

        // -- 2 - Variable Group --
        let var_group = "2 - Variable Group";
        sub = 0;
        self.register_action("Rename Local", var_group, sub, true, true, Some("L"));
        sub += 1;
        self.register_action("Rename Global", var_group, sub, true, true, Some("L"));
        sub += 1;
        self.register_action("Rename Field", var_group, sub, true, true, Some("L"));
        sub += 1;
        self.register_action("Rename Bit Field", var_group, sub, true, true, Some("L"));
        sub += 1;
        self.register_action("Force Union", var_group, sub, true, true, None);
        sub += 1;
        self.register_action("Retype Local", var_group, sub, true, true, Some("Ctrl+L"));
        sub += 1;
        self.register_action("Create Pointer Relative", var_group, sub, true, true, None);
        sub += 1;
        self.register_action("Retype Global", var_group, sub, true, true, Some("Ctrl+L"));
        sub += 1;
        self.register_action("Retype Return", var_group, sub, true, true, Some("Ctrl+L"));
        sub += 1;
        self.register_action("Retype Field", var_group, sub, true, true, Some("Ctrl+L"));
        sub += 1;
        self.register_action("Isolate Variable", var_group, sub, true, true, None);
        sub += 1;
        self.register_action(
            "Create Structure from Variable",
            var_group,
            sub,
            true,
            true,
            None,
        );
        sub += 1;
        self.register_action("Edit Data Type", var_group, sub, true, true, None);
        sub += 1;
        self.register_action("Edit Field", var_group, sub, true, true, None);

        // -- 3 - Commit Group --
        let commit_group = "3 - Commit Group";
        sub = 0;
        self.register_action("Commit Params", commit_group, sub, true, true, None);
        sub += 1;
        self.register_action("Commit Locals", commit_group, sub, true, true, None);

        // -- 4a - Highlight Group --
        let hl_group = "4a - Highlight Group";
        sub = 0;
        self.register_action(
            "Highlight Defined Use",
            hl_group,
            sub,
            true,
            true,
            None,
        );
        sub += 1;
        self.register_action("Forward Slice", hl_group, sub, true, true, None);
        sub += 1;
        self.register_action("Backwards Slice", hl_group, sub, true, true, None);
        sub += 1;
        self.register_action(
            "Forward Slice To PCode Ops",
            hl_group,
            sub,
            true,
            true,
            None,
        );
        sub += 1;
        self.register_action(
            "Backwards Slice To PCode Ops",
            hl_group,
            sub,
            true,
            true,
            None,
        );
        sub += 1;
        self.register_action(
            "Set Secondary Highlight",
            hl_group,
            sub,
            true,
            true,
            None,
        );
        sub += 1;
        self.register_action(
            "Set Secondary Highlight Color",
            hl_group,
            sub,
            true,
            true,
            None,
        );
        sub += 1;
        self.register_action(
            "Remove Secondary Highlight",
            hl_group,
            sub,
            true,
            true,
            None,
        );
        sub += 1;
        self.register_action(
            "Remove All Secondary Highlights",
            hl_group,
            sub,
            true,
            true,
            None,
        );
        sub += 1;
        self.register_action(
            "Previous Highlighted Token",
            hl_group,
            sub,
            true,
            true,
            None,
        );
        sub += 1;
        self.register_action(
            "Next Highlighted Token",
            hl_group,
            sub,
            true,
            true,
            None,
        );

        // -- 7 - Convert Group --
        let convert_group = "7 - Convert Group";
        sub = 0;
        self.register_action("Remove Equate", convert_group, sub, true, true, None);
        sub += 1;
        self.register_action("Set Equate", convert_group, sub, true, true, None);
        sub += 1;
        self.register_action("Convert Binary", convert_group, sub, true, true, None);
        sub += 1;
        self.register_action("Convert Dec", convert_group, sub, true, true, None);
        sub += 1;
        self.register_action("Convert Float", convert_group, sub, true, true, None);
        sub += 1;
        self.register_action("Convert Double", convert_group, sub, true, true, None);
        sub += 1;
        self.register_action("Convert Hex", convert_group, sub, true, true, None);
        sub += 1;
        self.register_action("Convert Oct", convert_group, sub, true, true, None);
        sub += 1;
        self.register_action("Convert Char", convert_group, sub, true, true, None);

        // -- Comment2 - Search Group --
        let search_group = "Comment2 - Search Group";
        sub = 0;
        self.register_action("Find", search_group, sub, true, true, Some("Ctrl+F"));
        sub += 1;
        self.register_action(
            "Find References To Data Type",
            search_group,
            sub,
            true,
            true,
            None,
        );
        sub += 1;
        self.register_action(
            "Find References To High Symbol",
            search_group,
            sub,
            true,
            true,
            None,
        );
        sub += 1;
        self.register_action(
            "Find References To Address",
            search_group,
            sub,
            true,
            true,
            None,
        );

        // -- comment6 - Options Group --
        let options_group = "comment6 - Options Group";
        sub = 0;
        self.register_action("Edit Properties", options_group, sub, true, true, None);

        // -- Non-popup actions --
        self.register_action("Debug Function Decompilation", "debug", 0, false, true, None);
        self.register_action("Export to C", "export", 0, false, true, None);
        self.register_action("Clone Decompiler", "clone", 0, false, true, None);
        self.register_action("Go To Next Brace", "nav", 0, false, true, Some("]"));
        self.register_action("Go To Previous Brace", "nav", 0, false, true, Some("["));
        self.register_action(
            "Disable Type Casts Display",
            "wDebug",
            0,
            false,
            true,
            Some("BACK_SLASH"),
        );
    }

    /// Register an action with its group info.
    fn register_action(
        &mut self,
        name: &str,
        group: &str,
        sub_group: u32,
        in_popup: bool,
        is_local: bool,
        key_binding: Option<&str>,
    ) {
        self.actions.push(ActionGroupInfo {
            action_name: name.to_string(),
            group: group.to_string(),
            sub_group,
            in_popup,
            is_local,
            key_binding: key_binding.map(|s| s.to_string()),
        });
    }

    /// Get all registered actions.
    pub fn actions(&self) -> &[ActionGroupInfo] {
        &self.actions
    }

    /// Get an action by name.
    pub fn action_by_name(&self, name: &str) -> Option<&ActionGroupInfo> {
        self.actions.iter().find(|a| a.action_name == name)
    }

    /// Returns the number of registered actions.
    pub fn action_count(&self) -> usize {
        self.actions.len()
    }

    // -- Navigation -----------------------------------------------------------

    /// Navigate to a program location.
    ///
    /// For connected providers, this always succeeds and updates the
    /// current program.  For disconnected providers, navigating to a
    /// different program is rejected.
    ///
    /// Returns `true` if navigation succeeded.
    pub fn go_to(&mut self, program: Option<&str>, target: NavigationTarget) -> bool {
        if !self.is_connected {
            if self.program_name.is_none() {
                // First call to a disconnected provider initialises it.
                if let Some(prog) = program {
                    self.set_program(Some(prog.to_string()));
                }
            } else if program != self.program_name.as_deref() {
                // Disconnected providers only work with their program.
                return false;
            }
        }

        match target {
            NavigationTarget::Address(addr) => {
                self.current_location = Some(addr);
                true
            }
            NavigationTarget::Function { entry, .. } => {
                self.current_location = Some(entry);
                true
            }
            NavigationTarget::Label(_) => {
                // In the full implementation, resolves the label to an address.
                true
            }
            NavigationTarget::Scalar(value) => {
                // In the full implementation, resolves the scalar to an address.
                let _ = value;
                true
            }
        }
    }

    /// Navigate to a specific address.
    pub fn go_to_address(&mut self, address: Address, new_window: bool) -> bool {
        if new_window {
            // In the full implementation, creates a new disconnected provider
            // and navigates there.
            return true;
        }
        self.current_location = Some(address);
        true
    }

    /// Navigate to a function.
    pub fn go_to_function(&mut self, entry: Address, is_external: bool, new_window: bool) -> bool {
        if new_window {
            return true;
        }
        if is_external {
            // In the full implementation, follows the external location.
            return true;
        }
        self.current_location = Some(entry);
        true
    }

    /// Navigate to a label by name.
    pub fn go_to_label(&mut self, symbol_name: &str, new_window: bool) -> bool {
        if new_window {
            return true;
        }
        // In the full implementation, resolves the symbol to an address.
        let _ = symbol_name;
        true
    }

    /// Navigate to a scalar value.
    pub fn go_to_scalar(&mut self, value: i64, new_window: bool) -> bool {
        if new_window {
            return true;
        }
        // In the full implementation, resolves the scalar to an address
        // in the function's address space.
        let _ = value;
        true
    }

    // -- Clone / Snapshot -----------------------------------------------------

    /// Clone this provider into a new disconnected provider.
    ///
    /// Returns the configuration needed to set up the clone:
    /// - The program name.
    /// - The viewer position.
    /// - The current location.
    pub fn clone_config(&self) -> Option<(String, ViewerPosition, Option<Address>)> {
        self.program_name.as_ref().map(|prog| {
            (
                prog.clone(),
                self.viewer_position,
                self.current_location,
            )
        })
    }

    // -- Follow-up Work -------------------------------------------------------

    /// Schedule work to be done when the provider is not busy.
    ///
    /// If the provider is not busy, the callback is executed immediately.
    /// Otherwise it is queued.
    pub fn do_when_not_busy<F: FnOnce() + Send + 'static>(&mut self, work: F) {
        if !self.is_busy {
            work();
        } else {
            self.follow_up_work.push_back(Box::new(work));
        }
    }

    /// Drain and execute all pending follow-up work.
    pub fn drain_follow_up_work(&mut self) {
        while let Some(work) = self.follow_up_work.pop_front() {
            work();
        }
    }

    /// Returns the number of pending follow-up work items.
    pub fn pending_work_count(&self) -> usize {
        self.follow_up_work.len()
    }

    // -- Graph Service --------------------------------------------------------

    /// Notify the provider that the graph display service has been added.
    pub fn graph_service_added(&mut self) {
        self.graph_service = GraphServiceState::Available;
        // In the full implementation, this registers PCodeCfgAction
        // and PCodeDfgAction.
    }

    /// Notify the provider that the graph display service has been removed.
    pub fn graph_service_removed(&mut self) {
        self.graph_service = GraphServiceState::Unavailable;
        // In the full implementation, this disposes PCodeCfgAction
        // and PCodeDfgAction.
    }

    // -- Options / Refresh ----------------------------------------------------

    /// Update options and refresh the display.
    pub fn update_options_and_refresh(&mut self) {
        self.refresh();
    }

    /// Refresh the decompile display.
    ///
    /// Clears the overlay message and triggers a re-decompile.
    pub fn refresh(&mut self) {
        self.overlay_painter.clear();
        // In the full implementation, this triggers controller.refreshDisplay().
    }

    /// Get the overlay refresh message.
    pub fn overlay_refresh_message(&self) -> String {
        if let Some(key) = &self.refresh_key_binding {
            format!("{} to refresh", key)
        } else {
            "Refresh needed".to_string()
        }
    }

    /// Update the overlay message (if the display is locked).
    pub fn update_overlay_message(&mut self) {
        if self.overlay_painter.is_active() {
            self.overlay_painter
                .set_message(&self.overlay_refresh_message());
        }
    }

    /// Refresh the toggle button states from current options.
    ///
    /// In Ghidra this is called after external options changes to
    /// synchronise the toolbar button states.
    pub fn refresh_toggle_buttons(&mut self, eliminate_unreachable: bool, respect_read_only: bool) {
        self.toggle_unreachable.selected = !eliminate_unreachable;
        self.toggle_read_only.selected = respect_read_only;
    }

    // -- Token Rename ---------------------------------------------------------

    /// Notify this provider that a token was renamed.
    pub fn notify_token_renamed(&mut self, _old_name: &str, _new_name: &str) {
        // In the full implementation, this updates the decompiler panel's
        // token text.  Here we just mark a refresh as needed.
        if self.display_lock == DisplayLockState::Locked {
            self.overlay_painter
                .set_message(&self.overlay_refresh_message());
        }
    }

    /// Handle a token rename and notify the plugin.
    ///
    /// This is the callback from the decompiler panel after a user
    /// renames a token.
    pub fn token_renamed(&mut self, _old_name: &str, _new_name: &str) {
        // In the full implementation, this calls plugin.handleTokenRenamed().
    }

    // -- Status Message -------------------------------------------------------

    /// Set a status message in the tool's status bar.
    pub fn set_status_message(&mut self, message: &str) {
        // In the full implementation, this calls tool.setStatusInfo(message).
        let _ = message;
    }

    // -- State Persistence ----------------------------------------------------

    /// Write this provider's state for persistence.
    pub fn write_data_state(&self) -> SaveState {
        let mut state = SaveState::new();
        if let Some(location) = self.current_location {
            state.put_int("Location", location.offset as i64);
        }
        state.put_viewer_position(
            self.viewer_position.index,
            self.viewer_position.y_offset,
        );
        state
    }

    /// Restore this provider's state from persistence.
    pub fn read_data_state(&mut self, state: &SaveState) {
        let (index, y_offset) = state.get_viewer_position();
        self.pending_viewer_position = Some(ViewerPosition::new(index, 0, y_offset));

        let location_raw = state.get_int("Location", -1);
        if location_raw >= 0 {
            self.current_location = Some(Address::new(location_raw as u64));
        }
    }

    // -- Title Management -----------------------------------------------------

    /// Update the window title based on the current function.
    fn update_title(&mut self) {
        let prog_display = self.program_name.as_deref().unwrap_or("No Function");
        let _func_display = self
            .function_name
            .as_deref()
            .unwrap_or("No Function");

        if self.is_connected {
            if let Some(func) = &self.function_name {
                self.title = format!("Decompile: {}", func);
                self.subtitle = format!(
                    " ({})",
                    self.program_name.as_deref().unwrap_or("")
                );
            } else if let Some(prog) = &self.program_name {
                self.title = format!("Decompile: {}", prog);
                self.subtitle = String::new();
            } else {
                self.title = "Decompile".into();
                self.subtitle = String::new();
            }
            self.tab_text = "Decompiler".into();
        } else {
            if let Some(func) = &self.function_name {
                self.title = format!("[Decompile: {}]", func);
                self.subtitle = format!(
                    " ({})",
                    self.program_name.as_deref().unwrap_or("")
                );
                self.tab_text = format!("[{}]", func);
            } else {
                self.title = format!("[Decompile: {}]", prog_display);
                self.subtitle = String::new();
                self.tab_text = format!("[{}]", prog_display);
            }
        }
    }

    // -- Program Close --------------------------------------------------------

    /// Notify this provider that a program was closed.
    pub fn program_closed(&mut self, closed_program: &str) {
        if self.program_name.as_deref() == Some(closed_program) {
            self.current_location = None;
            self.current_selection = None;
            self.text_selection = None;
            self.function_name = None;
            // In the full implementation, this calls controller.programClosed().
        }
    }

    // -- Dispose --------------------------------------------------------------

    /// Dispose this provider.
    pub fn dispose(&mut self) {
        self.state = ProviderState::Disposed;
        self.program_name = None;
        self.current_location = None;
        self.current_selection = None;
        self.text_selection = None;
        self.function_name = None;
        self.cursor = None;
        self.actions.clear();
        self.follow_up_work.clear();
    }

    // -- currentTokenToString -------------------------------------------------

    /// Build a debug string showing the current token in context.
    ///
    /// Mirrors Ghidra's `DecompilerProvider.currentTokenToString()` which
    /// renders the current line with the token under the cursor wrapped
    /// in `[` `]` brackets.  Useful for debug logging and status messages.
    pub fn current_token_to_string(&self) -> Option<String> {
        let cursor = self.cursor?;
        let func = self.function_name.as_deref().unwrap_or("unknown");
        Some(format!(
            "line {} @ {} [{}]",
            cursor.line,
            self.current_location
                .map(|a| format!("0x{:x}", a.offset))
                .unwrap_or_else(|| "none".into()),
            func
        ))
    }

    // -- setCursorLocation (1-based API) --------------------------------------

    /// Set the cursor location using 1-based line numbers.
    ///
    /// Mirrors Ghidra's `DecompilerProvider.setCursorLocation(int lineNumber,
    /// int offset)` where line numbers are 1-based.  Internally stores
    /// a `CursorLocation`.
    pub fn set_cursor_location_1based(&mut self, line_number: usize, offset: usize) {
        // Java uses 1-based line numbers; Rust CursorLocation stores 1-based.
        self.cursor = Some(CursorLocation::new(line_number, offset));
    }

    // -- Component / Window ---------------------------------------------------

    /// Returns the window group for this provider.
    ///
    /// Connected providers return an empty string (default group).
    /// Disconnected providers return `"disconnected"`.
    pub fn window_group(&self) -> &str {
        if self.is_connected {
            ""
        } else {
            "disconnected"
        }
    }

    /// Whether this provider is a snapshot (same as `is_snapshot()`).
    pub fn is_component_snapshot(&self) -> bool {
        !self.is_connected
    }

    // -- doRefresh (options-changed refresh) ----------------------------------

    /// Perform a full refresh, optionally because options changed.
    ///
    /// When `options_changed` is `true`, toggle button states are
    /// refreshed from the options.  When `false`, the current toggle
    /// states are preserved (the user may have manually toggled them).
    pub fn do_refresh(&mut self, options_changed: bool, eliminate_unreachable: bool, respect_read_only: bool) {
        if self.state != ProviderState::Visible {
            return;
        }

        if options_changed {
            // Update toggle states from the new options.
            self.toggle_unreachable.selected = !eliminate_unreachable;
            self.toggle_read_only.selected = respect_read_only;
        }
        // else: keep existing toggle states (user may have toggled).

        if self.display_lock == DisplayLockState::Locked {
            self.overlay_painter
                .set_message(&self.overlay_refresh_message());
        } else {
            self.overlay_painter.clear();
            // In the full implementation, controller.refreshDisplay() is called.
        }
    }

    // -- doFollowUpWork -------------------------------------------------------

    /// Drain and execute all pending follow-up work if not busy.
    ///
    /// Mirrors the `SwingUpdateManager`-based `doFollowUpWork()` in Java.
    /// If the provider is busy, work remains queued.
    pub fn do_follow_up_work(&mut self) -> usize {
        if self.is_busy {
            return 0;
        }
        let mut executed = 0;
        while let Some(work) = self.follow_up_work.pop_front() {
            work();
            executed += 1;
        }
        executed
    }

    // -- Export location to GoToService ---------------------------------------

    /// Export the current location to the GoToService.
    ///
    /// Returns the program name and address if both are available.
    pub fn export_location(&self) -> Option<(&str, Address)> {
        let program = self.program_name.as_deref()?;
        let addr = self.current_location?;
        Some((program, addr))
    }

    // -- Token rename broadcast -----------------------------------------------

    /// Handle a token rename from the plugin.
    ///
    /// This is the entry point called by `DecompilePlugin.handleTokenRenamed()`.
    /// It delegates to the decompiler panel to update the displayed text.
    pub fn handle_token_renamed(&mut self, old_name: &str, new_name: &str) {
        self.notify_token_renamed(old_name, new_name);
    }

    // -- DecompilerPanel accessor (placeholder) --------------------------------

    /// Get the decompiler panel for this provider.
    ///
    /// In the full implementation this returns the `DecompilerPanel` which
    /// renders the clang tokens.  Here we return a placeholder.
    pub fn get_decompiler_panel_summary(&self) -> DecompilerPanelSummary {
        DecompilerPanelSummary {
            function_name: self.function_name.clone(),
            has_selection: self.has_selection(),
            cursor: self.cursor,
            viewer_position: self.viewer_position,
            is_busy: self.is_busy,
            display_lock: self.display_lock,
        }
    }

    // -- Get the controller (placeholder) --------------------------------------

    /// Get a summary of the controller state.
    ///
    /// In Ghidra this returns the `DecompilerController`.  Here we return
    /// a placeholder with the essential state.
    pub fn get_controller_summary(&self) -> ControllerSummary {
        ControllerSummary {
            program_name: self.program_name.clone(),
            function_name: self.function_name.clone(),
            current_location: self.current_location,
            is_decompiling: self.is_busy,
        }
    }
}

/// Summary of the decompiler panel state.
///
/// This is a read-only snapshot used for debugging and status display.
#[derive(Debug, Clone)]
pub struct DecompilerPanelSummary {
    /// The function being displayed.
    pub function_name: Option<String>,
    /// Whether text is selected.
    pub has_selection: bool,
    /// The current cursor position.
    pub cursor: Option<CursorLocation>,
    /// The scroll position.
    pub viewer_position: ViewerPosition,
    /// Whether a decompile is in progress.
    pub is_busy: bool,
    /// The display lock state.
    pub display_lock: DisplayLockState,
}

/// Summary of the controller state.
///
/// This is a read-only snapshot used for debugging and status display.
#[derive(Debug, Clone)]
pub struct ControllerSummary {
    /// The bound program name.
    pub program_name: Option<String>,
    /// The function being displayed.
    pub function_name: Option<String>,
    /// The current location.
    pub current_location: Option<Address>,
    /// Whether a decompile is in progress.
    pub is_decompiling: bool,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Basic lifecycle --

    #[test]
    fn test_provider_connected() {
        let p = DecompilerProvider::new_connected(0);
        assert!(p.is_connected());
        assert!(!p.is_snapshot());
        assert_eq!(p.state(), ProviderState::Created);
    }

    #[test]
    fn test_provider_disconnected() {
        let p = DecompilerProvider::new_disconnected(1);
        assert!(!p.is_connected());
        assert!(p.is_snapshot());
    }

    #[test]
    fn test_provider_set_program() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_program(Some("test.elf".into()));
        assert_eq!(p.program_name(), Some("test.elf"));
        assert!(p.title().contains("test.elf"));
    }

    #[test]
    fn test_provider_set_location() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_location(Some(Address::new(0x1000)));
        assert_eq!(p.current_location(), Some(Address::new(0x1000)));
    }

    #[test]
    fn test_provider_selection() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_selection(Some((Address::new(0x100), Address::new(0x200))));
        assert_eq!(
            p.current_selection(),
            Some((Address::new(0x100), Address::new(0x200)))
        );
    }

    #[test]
    fn test_provider_text_selection() {
        let mut p = DecompilerProvider::new_connected(0);
        assert!(!p.has_selection());
        p.set_text_selection(Some("selected text".into()));
        assert!(p.has_selection());
    }

    #[test]
    fn test_provider_display_lock() {
        let mut p = DecompilerProvider::new_connected(0);
        assert_eq!(p.display_lock(), DisplayLockState::Unlocked);
        p.toggle_display_lock();
        assert_eq!(p.display_lock(), DisplayLockState::Locked);
        p.toggle_display_lock();
        assert_eq!(p.display_lock(), DisplayLockState::Unlocked);
    }

    #[test]
    fn test_provider_outgoing_events() {
        let mut p = DecompilerProvider::new_disconnected(1);
        assert!(!p.should_send_events());
        p.toggle_outgoing_events();
        assert!(p.should_send_events());
    }

    #[test]
    fn test_provider_connected_always_sends() {
        let p = DecompilerProvider::new_connected(0);
        assert!(p.should_send_events());
    }

    #[test]
    fn test_provider_unreachable_toggle() {
        let mut p = DecompilerProvider::new_connected(0);
        assert!(!p.is_showing_unreachable_code());
        p.toggle_unreachable_code();
        assert!(p.is_showing_unreachable_code());
    }

    #[test]
    fn test_provider_read_only_toggle() {
        let mut p = DecompilerProvider::new_connected(0);
        assert!(!p.is_respecting_read_only());
        p.toggle_respect_read_only();
        assert!(p.is_respecting_read_only());
    }

    // -- Title management --

    #[test]
    fn test_provider_title_update() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_program(Some("prog.elf".into()));
        assert!(p.title().contains("prog.elf"));

        let mut dp = DecompilerProvider::new_disconnected(1);
        dp.set_program(Some("snap.bin".into()));
        assert!(dp.title().starts_with('['));
        assert!(dp.tab_text().starts_with('['));
    }

    #[test]
    fn test_provider_function_name_title() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_program(Some("test.elf".into()));
        p.set_function_name(Some("main".into()));
        assert!(p.title().contains("main"));
        assert!(p.subtitle().contains("test.elf"));
    }

    // -- Actions --

    #[test]
    fn test_provider_actions_registered() {
        let p = DecompilerProvider::new_connected(0);
        // Should have all 40+ actions.
        assert!(p.action_count() >= 40);
    }

    #[test]
    fn test_provider_action_by_name() {
        let p = DecompilerProvider::new_connected(0);
        assert!(p.action_by_name("Rename Function").is_some());
        assert!(p.action_by_name("Find").is_some());
        assert!(p.action_by_name("Refresh").is_some());
        assert!(p.action_by_name("Nonexistent").is_none());
    }

    #[test]
    fn test_provider_action_groups() {
        let p = DecompilerProvider::new_connected(0);
        let func_actions: Vec<_> = p
            .actions()
            .iter()
            .filter(|a| a.group == "1 - Function Group")
            .collect();
        assert!(func_actions.len() >= 7);
    }

    #[test]
    fn test_provider_disconnected_extra_action() {
        let p = DecompilerProvider::new_disconnected(1);
        // Disconnected providers have the outgoing events action.
        assert!(p
            .action_by_name("Decompiler Outgoing Events")
            .is_some());
    }

    #[test]
    fn test_provider_connected_no_outgoing_toggle() {
        let p = DecompilerProvider::new_connected(0);
        assert!(p
            .action_by_name("Decompiler Outgoing Events")
            .is_none());
    }

    // -- Navigation --

    #[test]
    fn test_provider_go_to_address() {
        let mut p = DecompilerProvider::new_connected(0);
        assert!(p.go_to_address(Address::new(0x4000), false));
        assert_eq!(p.current_location(), Some(Address::new(0x4000)));
    }

    #[test]
    fn test_provider_go_to_function() {
        let mut p = DecompilerProvider::new_connected(0);
        assert!(p.go_to_function(Address::new(0x1000), false, false));
        assert_eq!(p.current_location(), Some(Address::new(0x1000)));
    }

    #[test]
    fn test_provider_go_to_disconnected_rejects_different_program() {
        let mut p = DecompilerProvider::new_disconnected(1);
        p.set_program(Some("a.bin".into()));
        assert!(!p.go_to(Some("b.bin"), NavigationTarget::Address(Address::new(0x1000))));
    }

    #[test]
    fn test_provider_go_to_disconnected_initialises_on_first_call() {
        let mut p = DecompilerProvider::new_disconnected(1);
        assert!(p.program_name().is_none());
        assert!(p.go_to(Some("init.bin"), NavigationTarget::Address(Address::new(0x1000))));
        assert_eq!(p.program_name(), Some("init.bin"));
    }

    // -- Cursor --

    #[test]
    fn test_provider_cursor() {
        let mut p = DecompilerProvider::new_connected(0);
        assert!(p.cursor().is_none());
        p.set_cursor_location(5, 10);
        let cursor = p.cursor().unwrap();
        assert_eq!(cursor.line, 5);
        assert_eq!(cursor.offset, 10);
    }

    // -- Viewer position --

    #[test]
    fn test_provider_viewer_position() {
        let mut p = DecompilerProvider::new_connected(0);
        assert_eq!(p.viewer_position(), ViewerPosition::default());
        p.set_viewer_position(ViewerPosition::new(10, 0, 200));
        assert_eq!(p.viewer_position().index, 10);
        assert_eq!(p.viewer_position().y_offset, 200);
    }

    #[test]
    fn test_provider_pending_viewer_position() {
        let mut p = DecompilerProvider::new_connected(0);
        assert!(p.pending_viewer_position.is_none());
        p.set_pending_viewer_position(ViewerPosition::new(5, 0, 100));
        assert!(p.pending_viewer_position.is_some());
    }

    // -- Follow-up work --

    #[test]
    fn test_provider_follow_up_work() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_busy(true);

        p.do_when_not_busy(|| {
            // This will be queued.
        });
        assert_eq!(p.pending_work_count(), 1);

        p.set_busy(false);
        p.drain_follow_up_work();
        assert_eq!(p.pending_work_count(), 0);
    }

    #[test]
    fn test_provider_follow_up_executes_immediately_when_not_busy() {
        let mut p = DecompilerProvider::new_connected(0);
        let executed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let exec_clone = executed.clone();
        p.do_when_not_busy(move || {
            exec_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        assert!(executed.load(std::sync::atomic::Ordering::SeqCst));
    }

    // -- Graph service --

    #[test]
    fn test_provider_graph_service() {
        let mut p = DecompilerProvider::new_connected(0);
        assert_eq!(p.graph_service_state(), GraphServiceState::Unavailable);

        p.graph_service_added();
        assert_eq!(p.graph_service_state(), GraphServiceState::Available);

        p.graph_service_removed();
        assert_eq!(p.graph_service_state(), GraphServiceState::Unavailable);
    }

    // -- Options / refresh --

    #[test]
    fn test_provider_refresh_toggle_buttons() {
        let mut p = DecompilerProvider::new_connected(0);
        // When eliminate_unreachable=true (default), the toggle is NOT selected.
        p.refresh_toggle_buttons(true, false);
        assert!(!p.is_showing_unreachable_code());
        assert!(!p.is_respecting_read_only());

        // When eliminate_unreachable=false, the toggle IS selected.
        p.refresh_toggle_buttons(false, true);
        assert!(p.is_showing_unreachable_code());
        assert!(p.is_respecting_read_only());
    }

    #[test]
    fn test_provider_overlay_refresh_message() {
        let p = DecompilerProvider::new_connected(0);
        assert!(p.overlay_refresh_message().contains("F5"));
    }

    #[test]
    fn test_provider_update_overlay_message() {
        let mut p = DecompilerProvider::new_connected(0);
        p.toggle_display_lock(); // now locked
        p.notify_token_renamed("old", "new");
        p.update_overlay_message();
        assert!(p.overlay_painter().is_active());
    }

    // -- Clone config --

    #[test]
    fn test_provider_clone_config() {
        let mut p = DecompilerProvider::new_connected(0);
        assert!(p.clone_config().is_none());

        p.set_program(Some("test.elf".into()));
        let (prog, _vp, _loc) = p.clone_config().unwrap();
        assert_eq!(prog, "test.elf");
    }

    // -- State persistence --

    #[test]
    fn test_provider_write_read_state() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_location(Some(Address::new(0x4000)));
        p.set_viewer_position(ViewerPosition::new(10, 0, 200));

        let state = p.write_data_state();
        assert_eq!(state.get_int("Location", 0), 0x4000);

        let mut p2 = DecompilerProvider::new_connected(0);
        p2.read_data_state(&state);
        assert_eq!(p2.current_location(), Some(Address::new(0x4000)));
        assert!(p2.pending_viewer_position.is_some());
    }

    // -- Status message --

    #[test]
    fn test_provider_set_status_message() {
        let mut p = DecompilerProvider::new_connected(0);
        // Should not panic.
        p.set_status_message("Decompiling...");
    }

    // -- Program closed --

    #[test]
    fn test_provider_program_closed() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_program(Some("test.elf".into()));
        p.set_location(Some(Address::new(0x1000)));
        p.set_function_name(Some("main".into()));

        p.program_closed("test.elf");
        assert!(p.current_location().is_none());
        assert!(p.function_name().is_none());
    }

    #[test]
    fn test_provider_program_closed_wrong_program() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_program(Some("test.elf".into()));
        p.set_location(Some(Address::new(0x1000)));

        p.program_closed("other.elf");
        // Should not clear state for wrong program.
        assert_eq!(p.current_location(), Some(Address::new(0x1000)));
    }

    // -- Dispose --

    #[test]
    fn test_provider_dispose() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_program(Some("x.bin".into()));
        p.dispose();
        assert_eq!(p.state(), ProviderState::Disposed);
        assert!(p.program_name().is_none());
        assert_eq!(p.action_count(), 0);
    }

    #[test]
    fn test_provider_state_transitions() {
        let mut p = DecompilerProvider::new_connected(0);
        assert_eq!(p.state(), ProviderState::Created);

        p.set_visible();
        assert_eq!(p.state(), ProviderState::Visible);

        p.set_hidden();
        assert_eq!(p.state(), ProviderState::Hidden);

        p.dispose();
        assert_eq!(p.state(), ProviderState::Disposed);

        // Disposed providers cannot be made visible again.
        p.set_visible();
        assert_eq!(p.state(), ProviderState::Disposed);
    }

    // -- ViewerPosition --

    #[test]
    fn test_viewer_position() {
        let vp = ViewerPosition::new(5, 0, 150);
        assert_eq!(vp.index, 5);
        assert_eq!(vp.y_offset, 150);

        let origin = ViewerPosition::origin();
        assert_eq!(origin.index, 0);
    }

    // -- CursorLocation --

    #[test]
    fn test_cursor_location() {
        let cursor = CursorLocation::new(10, 25);
        assert_eq!(cursor.line, 10);
        assert_eq!(cursor.offset, 25);
    }

    // -- currentTokenToString --

    #[test]
    fn test_provider_current_token_to_string_none() {
        let p = DecompilerProvider::new_connected(0);
        assert!(p.current_token_to_string().is_none());
    }

    #[test]
    fn test_provider_current_token_to_string_with_cursor() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_program(Some("test.elf".into()));
        p.set_function_name(Some("main".into()));
        p.set_location(Some(Address::new(0x4000)));
        p.set_cursor_location(5, 10);
        let s = p.current_token_to_string().unwrap();
        assert!(s.contains("line 5"));
        assert!(s.contains("0x4000"));
        assert!(s.contains("main"));
    }

    // -- setCursorLocation 1-based --

    #[test]
    fn test_provider_set_cursor_location_1based() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_cursor_location_1based(3, 15);
        let cursor = p.cursor().unwrap();
        assert_eq!(cursor.line, 3);
        assert_eq!(cursor.offset, 15);
    }

    // -- window group --

    #[test]
    fn test_provider_window_group_connected() {
        let p = DecompilerProvider::new_connected(0);
        assert_eq!(p.window_group(), "");
    }

    #[test]
    fn test_provider_window_group_disconnected() {
        let p = DecompilerProvider::new_disconnected(1);
        assert_eq!(p.window_group(), "disconnected");
    }

    // -- doRefresh --

    #[test]
    fn test_provider_do_refresh_options_changed() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_visible();
        // Set initial state: unreachable=false, read_only=true
        p.toggle_unreachable_code(); // now showing unreachable
        p.toggle_respect_read_only(); // now respecting read-only

        // Refresh with options that say eliminate=true, respect=false
        p.do_refresh(true, true, false);
        assert!(!p.is_showing_unreachable_code()); // !eliminate = false
        assert!(!p.is_respecting_read_only()); // !respect = false
    }

    #[test]
    fn test_provider_do_refresh_preserves_toggles() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_visible();
        p.toggle_unreachable_code(); // now showing unreachable

        // Refresh without options change -- toggle should be preserved.
        p.do_refresh(false, true, false);
        assert!(p.is_showing_unreachable_code()); // preserved
    }

    #[test]
    fn test_provider_do_refresh_when_not_visible() {
        let mut p = DecompilerProvider::new_connected(0);
        // Not visible, refresh should be a no-op.
        p.do_refresh(true, false, false);
        // No panic, no state change.
    }

    #[test]
    fn test_provider_do_refresh_locked_shows_overlay() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_visible();
        p.toggle_display_lock(); // locked
        p.do_refresh(true, true, false);
        assert!(p.overlay_painter().is_active());
    }

    #[test]
    fn test_provider_do_refresh_unlocked_clears_overlay() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_visible();
        p.toggle_display_lock(); // locked
        p.overlay_painter_mut().set_message("stale");
        p.toggle_display_lock(); // unlocked
        p.do_refresh(true, true, false);
        assert!(!p.overlay_painter().is_active());
    }

    // -- doFollowUpWork --

    #[test]
    fn test_provider_do_follow_up_work_drains_queue() {
        let mut p = DecompilerProvider::new_connected(0);
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        p.set_busy(true);
        for _ in 0..3 {
            let c = count.clone();
            p.do_when_not_busy(move || {
                c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            });
        }
        assert_eq!(p.pending_work_count(), 3);

        p.set_busy(false);
        let executed = p.do_follow_up_work();
        assert_eq!(executed, 3);
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 3);
        assert_eq!(p.pending_work_count(), 0);
    }

    #[test]
    fn test_provider_do_follow_up_work_stays_queued_when_busy() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_busy(true);
        p.do_when_not_busy(|| {});
        let executed = p.do_follow_up_work();
        assert_eq!(executed, 0);
        assert_eq!(p.pending_work_count(), 1);
    }

    // -- export_location --

    #[test]
    fn test_provider_export_location_none() {
        let p = DecompilerProvider::new_connected(0);
        assert!(p.export_location().is_none());
    }

    #[test]
    fn test_provider_export_location_with_both() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_program(Some("test.elf".into()));
        p.set_location(Some(Address::new(0x4000)));
        let (prog, addr) = p.export_location().unwrap();
        assert_eq!(prog, "test.elf");
        assert_eq!(addr, Address::new(0x4000));
    }

    #[test]
    fn test_provider_export_location_no_location() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_program(Some("test.elf".into()));
        assert!(p.export_location().is_none());
    }

    // -- handle_token_renamed --

    #[test]
    fn test_provider_handle_token_renamed() {
        let mut p = DecompilerProvider::new_connected(0);
        // Should not panic.
        p.handle_token_renamed("old_var", "new_var");
    }

    // -- get_decompiler_panel_summary --

    #[test]
    fn test_provider_panel_summary() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_function_name(Some("main".into()));
        p.set_cursor_location(5, 10);

        let summary = p.get_decompiler_panel_summary();
        assert_eq!(summary.function_name.as_deref(), Some("main"));
        assert!(summary.cursor.is_some());
        assert_eq!(summary.cursor.unwrap().line, 5);
        assert!(!summary.is_busy);
    }

    // -- get_controller_summary --

    #[test]
    fn test_provider_controller_summary() {
        let mut p = DecompilerProvider::new_connected(0);
        p.set_program(Some("test.elf".into()));
        p.set_function_name(Some("main".into()));
        p.set_location(Some(Address::new(0x1000)));

        let summary = p.get_controller_summary();
        assert_eq!(summary.program_name.as_deref(), Some("test.elf"));
        assert_eq!(summary.function_name.as_deref(), Some("main"));
        assert_eq!(summary.current_location, Some(Address::new(0x1000)));
        assert!(!summary.is_decompiling);
    }

    // -- is_component_snapshot --

    #[test]
    fn test_provider_is_component_snapshot() {
        let p = DecompilerProvider::new_connected(0);
        assert!(!p.is_component_snapshot());

        let dp = DecompilerProvider::new_disconnected(1);
        assert!(dp.is_component_snapshot());
    }

    // -- Address import for tests --
    // (Address is used above via ghidra_core::addr::Address which is
    //  already in scope from the module-level import.)
}
