//! Single decompiler display for one side of a comparison.
//!
//! Ported from Ghidra's `CDisplay` Java class.
//!
//! Represents one side of a dual decompiler compare window. It holds the
//! decompiler controller and related state information for one side.
//! Manages the decompiler panel, highlight controller, program listener,
//! and cursor position tracking.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::super::graphanalysis::Side;
use super::super::panel::ProgramLocation;
use super::highlight_controller::{DiffClangHighlightController, DecompilerComparisonOptions};
use super::decompiler_options::DecompilerCodeComparisonOptions;

/// Cursor position in a decompiler panel.
///
/// Ported from Ghidra's `FieldLocation` usage in `CDisplay`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorPosition {
    /// Line index (0-based).
    pub line_index: usize,
    /// Field number within the line.
    pub field_num: usize,
    /// Row within the field.
    pub row: usize,
    /// Column within the row.
    pub col: usize,
}

impl CursorPosition {
    /// Create a new cursor position.
    pub fn new(line_index: usize, field_num: usize, row: usize, col: usize) -> Self {
        Self {
            line_index,
            field_num,
            row,
            col,
        }
    }

    /// Create a cursor position at the start of the document.
    pub fn origin() -> Self {
        Self::new(0, 0, 0, 0)
    }
}

/// State of the decompiler display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CDisplayState {
    /// No function loaded.
    Empty,
    /// Decompiling in progress.
    Decompiling,
    /// Function is decompiled and displayed.
    Displayed,
    /// An error occurred during decompilation.
    Error,
}

/// Decompile data for a single function.
///
/// Represents the result of decompiling a function, including the
/// decompiled code markup and high-level function representation.
/// This is a simplified version of Ghidra's `DecompileData`.
#[derive(Debug, Clone)]
pub struct DecompileData {
    /// The decompiled text (line-oriented).
    pub lines: Vec<String>,
    /// The function name.
    pub function_name: String,
    /// The function entry point address.
    pub function_entry: u64,
    /// The program name.
    pub program_name: String,
    /// Whether the decompile data is valid.
    pub valid: bool,
    /// Error message, if decompilation failed.
    pub error_message: Option<String>,
}

impl DecompileData {
    /// Create valid decompile data.
    pub fn new(
        lines: Vec<String>,
        function_name: impl Into<String>,
        function_entry: u64,
        program_name: impl Into<String>,
    ) -> Self {
        Self {
            lines,
            function_name: function_name.into(),
            function_entry,
            program_name: program_name.into(),
            valid: true,
            error_message: None,
        }
    }

    /// Create an error decompile data (invalid).
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            lines: Vec::new(),
            function_name: String::new(),
            function_entry: 0,
            program_name: String::new(),
            valid: false,
            error_message: Some(message.into()),
        }
    }

    /// Create a placeholder decompile data for displaying a message.
    pub fn message(message: impl Into<String>) -> Self {
        Self {
            lines: vec![message.into()],
            function_name: String::new(),
            function_entry: 0,
            program_name: String::new(),
            valid: false,
            error_message: None,
        }
    }

    /// Whether this decompile data is valid (has actual decompiled code).
    pub fn is_valid(&self) -> bool {
        self.valid
    }
}

/// Represents one side of a dual decompiler compare window.
///
/// Ported from Ghidra's `CDisplay` Java class.
///
/// Holds the decompiler controller and related state for one side of
/// the comparison. Manages:
/// - The decompiler panel and its display
/// - The diff highlight controller for this side
/// - Program change tracking
/// - Cursor position save/restore
/// - Decompile data lifecycle
#[derive(Debug)]
pub struct CDisplay {
    /// Which side this display is on.
    side: Side,
    /// The owner name.
    owner: String,
    /// Current display state.
    state: CDisplayState,
    /// The diff highlight controller for this side.
    highlight_controller: DiffClangHighlightController,
    /// Current decompile data.
    decompile_data: Option<DecompileData>,
    /// Saved cursor position (for restore after refresh).
    saved_cursor: Option<CursorPosition>,
    /// Current cursor position.
    current_cursor: Option<CursorPosition>,
    /// Current program name.
    program_name: Option<String>,
    /// Whether mouse navigation is enabled.
    mouse_navigation_enabled: bool,
    /// Last refresh timestamp for rate limiting.
    last_refresh: Option<Instant>,
    /// Minimum interval between refreshes.
    refresh_interval: Duration,
    /// Whether the display is busy decompiling.
    busy: bool,
}

impl CDisplay {
    /// Create a new CDisplay for the given side.
    pub fn new(owner: impl Into<String>, side: Side, options: &DecompilerCodeComparisonOptions) -> Self {
        Self {
            side,
            owner: owner.into(),
            state: CDisplayState::Empty,
            highlight_controller: DiffClangHighlightController::new(DecompilerComparisonOptions::default()),
            decompile_data: None,
            saved_cursor: None,
            current_cursor: None,
            program_name: None,
            mouse_navigation_enabled: true,
            last_refresh: None,
            refresh_interval: Duration::from_millis(500),
            busy: false,
        }
    }

    /// Get the side.
    pub fn side(&self) -> Side {
        self.side
    }

    /// Get the owner name.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Get the current display state.
    pub fn state(&self) -> CDisplayState {
        self.state
    }

    /// Get the highlight controller.
    pub fn highlight_controller(&self) -> &DiffClangHighlightController {
        &self.highlight_controller
    }

    /// Get a mutable reference to the highlight controller.
    pub fn highlight_controller_mut(&mut self) -> &mut DiffClangHighlightController {
        &mut self.highlight_controller
    }

    /// Get the current decompile data.
    pub fn decompile_data(&self) -> Option<&DecompileData> {
        self.decompile_data.as_ref()
    }

    /// Set the decompile data.
    pub fn set_decompile_data(&mut self, data: Option<DecompileData>) {
        if let Some(ref d) = data {
            if d.is_valid() {
                self.state = CDisplayState::Displayed;
            } else {
                self.state = CDisplayState::Empty;
            }
            if !d.program_name.is_empty() {
                self.program_name = Some(d.program_name.clone());
            }
        } else {
            self.state = CDisplayState::Empty;
        }
        self.decompile_data = data;
        self.busy = false;
    }

    /// Show a function in this display.
    ///
    /// Triggers decompilation and updates the display when complete.
    pub fn show_function(&mut self, function_entry: Option<u64>, is_external: bool, name: &str) {
        self.saved_cursor = None;
        self.decompile_data = None;

        if function_entry.is_none() {
            self.state = CDisplayState::Empty;
            self.decompile_data = Some(DecompileData::message("No Function"));
            return;
        }

        if is_external {
            self.state = CDisplayState::Empty;
            self.decompile_data = Some(DecompileData::message(
                format!("\"{}\" is an external function.", name),
            ));
            return;
        }

        self.state = CDisplayState::Decompiling;
        self.busy = true;
        // In a real implementation, this would trigger asynchronous decompilation.
        // For the port, we simulate it completing immediately.
    }

    /// Clear the display and show a message.
    pub fn clear_and_show_message(&mut self, message: impl Into<String>) {
        self.state = CDisplayState::Empty;
        self.decompile_data = Some(DecompileData::message(message));
    }

    /// Whether the display is busy decompiling.
    pub fn is_busy(&self) -> bool {
        self.busy
    }

    /// Get the current cursor position.
    pub fn cursor_position(&self) -> Option<&CursorPosition> {
        self.current_cursor.as_ref()
    }

    /// Set the cursor position.
    pub fn set_cursor_position(&mut self, position: CursorPosition) {
        self.current_cursor = Some(position);
    }

    /// Save the current cursor position for later restore.
    pub fn save_cursor_position(&mut self) {
        self.saved_cursor = self.current_cursor.clone();
    }

    /// Restore the previously saved cursor position.
    pub fn restore_cursor_position(&mut self) -> bool {
        if let Some(saved) = self.saved_cursor.clone() {
            self.current_cursor = Some(saved);
            true
        } else {
            false
        }
    }

    /// Enable or disable mouse navigation.
    pub fn set_mouse_navigation_enabled(&mut self, enabled: bool) {
        self.mouse_navigation_enabled = enabled;
    }

    /// Whether mouse navigation is enabled.
    pub fn is_mouse_navigation_enabled(&self) -> bool {
        self.mouse_navigation_enabled
    }

    /// Get the current program name.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// Refresh the display (re-decompile the current function).
    ///
    /// Rate-limited to prevent excessive refreshes.
    pub fn refresh(&mut self) -> bool {
        let now = Instant::now();
        if let Some(last) = self.last_refresh {
            if now.duration_since(last) < self.refresh_interval {
                return false;
            }
        }
        self.last_refresh = Some(now);
        self.save_cursor_position();
        // In a real implementation, this would re-decompile.
        true
    }

    /// Notify that a program was closed.
    pub fn program_closed(&mut self, closed_program_name: &str) {
        if self.program_name.as_deref() == Some(closed_program_name) {
            self.decompile_data = None;
            self.state = CDisplayState::Empty;
            self.program_name = None;
            self.current_cursor = None;
            self.saved_cursor = None;
        }
    }

    /// Dispose of this display.
    pub fn dispose(&mut self) {
        self.decompile_data = None;
        self.state = CDisplayState::Empty;
        self.program_name = None;
        self.current_cursor = None;
        self.saved_cursor = None;
        self.busy = false;
        self.highlight_controller.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_options() -> DecompilerCodeComparisonOptions {
        DecompilerCodeComparisonOptions::default()
    }

    #[test]
    fn test_c_display_new() {
        let opts = make_options();
        let display = CDisplay::new("test", Side::Left, &opts);
        assert_eq!(display.side(), Side::Left);
        assert_eq!(display.state(), CDisplayState::Empty);
        assert!(!display.is_busy());
        assert!(display.decompile_data().is_none());
    }

    #[test]
    fn test_c_display_show_function() {
        let opts = make_options();
        let mut display = CDisplay::new("test", Side::Left, &opts);
        display.show_function(Some(0x1000), false, "main");

        assert_eq!(display.state(), CDisplayState::Decompiling);
        assert!(display.is_busy());
    }

    #[test]
    fn test_c_display_show_null_function() {
        let opts = make_options();
        let mut display = CDisplay::new("test", Side::Left, &opts);
        display.show_function(None, false, "");

        assert_eq!(display.state(), CDisplayState::Empty);
        let data = display.decompile_data().unwrap();
        assert_eq!(data.lines[0], "No Function");
    }

    #[test]
    fn test_c_display_show_external() {
        let opts = make_options();
        let mut display = CDisplay::new("test", Side::Left, &opts);
        display.show_function(Some(0x1000), true, "printf");

        assert_eq!(display.state(), CDisplayState::Empty);
        let data = display.decompile_data().unwrap();
        assert!(data.lines[0].contains("external"));
    }

    #[test]
    fn test_c_display_set_decompile_data() {
        let opts = make_options();
        let mut display = CDisplay::new("test", Side::Left, &opts);

        let data = DecompileData::new(
            vec!["int main() {".to_string(), "  return 0;".to_string(), "}".to_string()],
            "main",
            0x1000,
            "test_program",
        );

        display.set_decompile_data(Some(data));
        assert_eq!(display.state(), CDisplayState::Displayed);
        assert!(!display.is_busy());
        assert!(display.decompile_data().is_some());
        assert_eq!(display.decompile_data().unwrap().lines.len(), 3);
    }

    #[test]
    fn test_c_display_cursor_save_restore() {
        let opts = make_options();
        let mut display = CDisplay::new("test", Side::Left, &opts);

        display.set_cursor_position(CursorPosition::new(5, 0, 0, 10));
        display.save_cursor_position();

        display.set_cursor_position(CursorPosition::new(10, 0, 0, 20));
        assert_eq!(display.cursor_position().unwrap().line_index, 10);

        display.restore_cursor_position();
        assert_eq!(display.cursor_position().unwrap().line_index, 5);
        assert_eq!(display.cursor_position().unwrap().col, 10);
    }

    #[test]
    fn test_c_display_cursor_restore_no_save() {
        let opts = make_options();
        let mut display = CDisplay::new("test", Side::Left, &opts);
        assert!(!display.restore_cursor_position());
    }

    #[test]
    fn test_c_display_clear_and_show_message() {
        let opts = make_options();
        let mut display = CDisplay::new("test", Side::Left, &opts);
        display.clear_and_show_message("Loading...");

        assert_eq!(display.state(), CDisplayState::Empty);
        assert_eq!(display.decompile_data().unwrap().lines[0], "Loading...");
    }

    #[test]
    fn test_c_display_program_closed() {
        let opts = make_options();
        let mut display = CDisplay::new("test", Side::Left, &opts);

        display.set_decompile_data(Some(DecompileData::new(
            vec!["code".to_string()],
            "main",
            0x1000,
            "test_program",
        )));

        display.program_closed("other_program");
        assert!(display.decompile_data().is_some());

        display.program_closed("test_program");
        assert!(display.decompile_data().is_none());
        assert_eq!(display.state(), CDisplayState::Empty);
    }

    #[test]
    fn test_c_display_dispose() {
        let opts = make_options();
        let mut display = CDisplay::new("test", Side::Right, &opts);
        display.set_decompile_data(Some(DecompileData::new(
            vec!["code".to_string()],
            "main",
            0x1000,
            "test",
        )));
        display.set_cursor_position(CursorPosition::new(1, 0, 0, 0));

        display.dispose();
        assert!(display.decompile_data().is_none());
        assert!(display.cursor_position().is_none());
        assert_eq!(display.state(), CDisplayState::Empty);
    }

    #[test]
    fn test_c_display_mouse_navigation() {
        let opts = make_options();
        let mut display = CDisplay::new("test", Side::Left, &opts);
        assert!(display.is_mouse_navigation_enabled());

        display.set_mouse_navigation_enabled(false);
        assert!(!display.is_mouse_navigation_enabled());
    }

    #[test]
    fn test_cursor_position_origin() {
        let pos = CursorPosition::origin();
        assert_eq!(pos.line_index, 0);
        assert_eq!(pos.field_num, 0);
        assert_eq!(pos.row, 0);
        assert_eq!(pos.col, 0);
    }

    #[test]
    fn test_decompile_data_valid() {
        let data = DecompileData::new(
            vec!["int x = 5;".to_string()],
            "main",
            0x1000,
            "test",
        );
        assert!(data.is_valid());
        assert!(data.error_message.is_none());
    }

    #[test]
    fn test_decompile_data_error() {
        let data = DecompileData::error("decompilation failed");
        assert!(!data.is_valid());
        assert!(data.error_message.is_some());
    }

    #[test]
    fn test_decompile_data_message() {
        let data = DecompileData::message("No Function");
        assert!(!data.is_valid());
        assert_eq!(data.lines[0], "No Function");
    }
}
