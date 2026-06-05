// ===========================================================================
// Control Panel & Widgets -- ported from Ghidra's
// `ghidra.app.plugin.core.instructionsearch.ui` package.
//
// Includes:
// - ControlPanel              -- main control panel model
// - ControlPanelWidget        -- widget for search controls
// - EndianFlipWidget          -- endianness toggle
// - InsertBytesWidget         -- insert raw bytes widget
// - SearchDirectionWidget     -- forward/backward search selector
// - SelectionModeWidget       -- search mode selector (binary/hex/mnemonic)
// - SelectionScopeWidget      -- scope selector (all/selection)
// - HintTextArea              -- hint/help text display
// - MessagePanel              -- status/error message display
// ===========================================================================

// Re-export the SearchDirection from the parent module.
use super::SearchDirection;

/// The search scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SearchScope {
    /// Search the entire program.
    All,
    /// Search only the current selection.
    Selection,
}

impl Default for SearchScope {
    fn default() -> Self {
        Self::All
    }
}

/// The search input mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SearchInputMode {
    /// Binary representation (0s and 1s).
    Binary,
    /// Hex representation.
    Hex,
    /// Mnemonic (assembly) representation.
    Mnemonic,
}

impl Default for SearchInputMode {
    fn default() -> Self {
        Self::Hex
    }
}

/// The endianness of the search pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endianness {
    /// Little-endian byte order.
    LittleEndian,
    /// Big-endian byte order.
    BigEndian,
}

impl Default for Endianness {
    fn default() -> Self {
        Self::LittleEndian
    }
}

// ---------------------------------------------------------------------------
// ControlPanel
// ---------------------------------------------------------------------------

/// The main control panel for instruction search.
///
/// Manages the search configuration state and coordinates between widgets.
///
/// Ported from `ghidra.app.plugin.core.instructionsearch.ui.ControlPanel`.
#[derive(Debug, Clone)]
pub struct ControlPanel {
    /// Current search direction.
    pub direction: SearchDirection,
    /// Current search scope.
    pub scope: SearchScope,
    /// Current input mode.
    pub input_mode: SearchInputMode,
    /// Current endianness.
    pub endianness: Endianness,
    /// Whether the search pattern is valid.
    pub pattern_valid: bool,
    /// Current pattern text.
    pub pattern_text: String,
    /// Whether the search is currently running.
    pub is_searching: bool,
    /// Status message.
    pub status: Option<StatusMessage>,
}

/// A status message displayed in the control panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusMessage {
    /// The message severity.
    pub severity: MessageSeverity,
    /// The message text.
    pub text: String,
}

/// Message severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageSeverity {
    /// Informational message.
    Info,
    /// Warning message.
    Warning,
    /// Error message.
    Error,
}

impl ControlPanel {
    /// Create a new control panel with defaults.
    pub fn new() -> Self {
        Self {
            direction: SearchDirection::Forward,
            scope: SearchScope::All,
            input_mode: SearchInputMode::Hex,
            endianness: Endianness::LittleEndian,
            pattern_valid: false,
            pattern_text: String::new(),
            is_searching: false,
            status: None,
        }
    }

    /// Set the search pattern.
    pub fn set_pattern(&mut self, pattern: impl Into<String>) {
        self.pattern_text = pattern.into();
        self.validate_pattern();
    }

    /// Validate the current pattern.
    fn validate_pattern(&mut self) {
        self.pattern_valid = match self.input_mode {
            SearchInputMode::Binary => {
                self.pattern_text
                    .chars()
                    .all(|c| c == '0' || c == '1' || c == ' ' || c == '?')
                    && !self.pattern_text.is_empty()
            }
            SearchInputMode::Hex => {
                self.pattern_text.chars().all(|c| {
                    c.is_ascii_hexdigit() || c == ' ' || c == '?'
                }) && !self.pattern_text.is_empty()
            }
            SearchInputMode::Mnemonic => !self.pattern_text.is_empty(),
        };
    }

    /// Flip the endianness.
    pub fn flip_endian(&mut self) {
        self.endianness = match self.endianness {
            Endianness::LittleEndian => Endianness::BigEndian,
            Endianness::BigEndian => Endianness::LittleEndian,
        };
    }

    /// Set a status message.
    pub fn set_status(&mut self, severity: MessageSeverity, text: impl Into<String>) {
        self.status = Some(StatusMessage {
            severity,
            text: text.into(),
        });
    }

    /// Clear the status message.
    pub fn clear_status(&mut self) {
        self.status = None;
    }
}

impl Default for ControlPanel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ControlPanelWidget
// ---------------------------------------------------------------------------

/// A widget in the control panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPanelWidget {
    /// The widget identifier.
    pub id: String,
    /// Display label.
    pub label: String,
    /// Whether the widget is enabled.
    pub enabled: bool,
    /// Tooltip text.
    pub tooltip: Option<String>,
}

impl ControlPanelWidget {
    /// Create a new widget.
    pub fn new(id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            enabled: true,
            tooltip: None,
        }
    }

    /// Set the tooltip.
    pub fn with_tooltip(mut self, tooltip: impl Into<String>) -> Self {
        self.tooltip = Some(tooltip.into());
        self
    }
}

// ---------------------------------------------------------------------------
// EndianFlipWidget
// ---------------------------------------------------------------------------

/// Widget for toggling endianness.
///
/// Ported from `ghidra.app.plugin.core.instructionsearch.ui.EndianFlipWidget`.
#[derive(Debug, Clone)]
pub struct EndianFlipWidget {
    /// The widget state.
    pub widget: ControlPanelWidget,
    /// Current endianness.
    pub endianness: Endianness,
}

impl EndianFlipWidget {
    /// Create a new widget.
    pub fn new() -> Self {
        Self {
            widget: ControlPanelWidget::new("endian_flip", "Endian")
                .with_tooltip("Toggle search pattern endianness"),
            endianness: Endianness::LittleEndian,
        }
    }

    /// Toggle the endianness.
    pub fn toggle(&mut self) {
        self.endianness = match self.endianness {
            Endianness::LittleEndian => Endianness::BigEndian,
            Endianness::BigEndian => Endianness::LittleEndian,
        };
    }
}

impl Default for EndianFlipWidget {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// InsertBytesWidget
// ---------------------------------------------------------------------------

/// Widget for inserting raw bytes into the search pattern.
///
/// Ported from `ghidra.app.plugin.core.instructionsearch.ui.InsertBytesWidget`.
#[derive(Debug, Clone)]
pub struct InsertBytesWidget {
    /// The widget state.
    pub widget: ControlPanelWidget,
    /// The bytes to insert.
    pub bytes: Vec<u8>,
    /// Whether to apply a mask.
    pub apply_mask: bool,
    /// The mask bytes.
    pub mask: Vec<u8>,
}

impl InsertBytesWidget {
    /// Create a new widget.
    pub fn new() -> Self {
        Self {
            widget: ControlPanelWidget::new("insert_bytes", "Insert Bytes")
                .with_tooltip("Insert raw bytes for search pattern"),
            bytes: Vec::new(),
            apply_mask: false,
            mask: Vec::new(),
        }
    }

    /// Set the bytes to insert.
    pub fn set_bytes(&mut self, bytes: Vec<u8>) {
        self.bytes = bytes;
        if self.apply_mask && self.mask.len() < self.bytes.len() {
            self.mask.resize(self.bytes.len(), 0xFF);
        }
    }

    /// Set the mask bytes.
    pub fn set_mask(&mut self, mask: Vec<u8>) {
        self.mask = mask;
        self.apply_mask = true;
    }

    /// Get the effective bytes (applying mask if set).
    pub fn effective_bytes(&self) -> Vec<u8> {
        if self.apply_mask {
            self.bytes
                .iter()
                .zip(self.mask.iter().chain(std::iter::repeat(&0xFF)))
                .map(|(b, m)| b & m)
                .collect()
        } else {
            self.bytes.clone()
        }
    }
}

impl Default for InsertBytesWidget {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SearchDirectionWidget
// ---------------------------------------------------------------------------

/// Widget for selecting the search direction.
///
/// Ported from `ghidra.app.plugin.core.instructionsearch.ui.SearchDirectionWidget`.
#[derive(Debug, Clone)]
pub struct SearchDirectionWidget {
    /// The widget state.
    pub widget: ControlPanelWidget,
    /// Current direction.
    pub direction: SearchDirection,
}

impl SearchDirectionWidget {
    /// Create a new widget.
    pub fn new() -> Self {
        Self {
            widget: ControlPanelWidget::new("search_direction", "Direction")
                .with_tooltip("Search forward or backward from cursor"),
            direction: SearchDirection::Forward,
        }
    }

    /// Toggle direction.
    pub fn toggle(&mut self) {
        self.direction = match self.direction {
            SearchDirection::Forward => SearchDirection::Backward,
            SearchDirection::Backward => SearchDirection::Forward,
        };
    }
}

impl Default for SearchDirectionWidget {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SelectionModeWidget
// ---------------------------------------------------------------------------

/// Widget for selecting the input mode (binary, hex, mnemonic).
///
/// Ported from `ghidra.app.plugin.core.instructionsearch.ui.SelectionModeWidget`.
#[derive(Debug, Clone)]
pub struct SelectionModeWidget {
    /// The widget state.
    pub widget: ControlPanelWidget,
    /// Current mode.
    pub mode: SearchInputMode,
}

impl SelectionModeWidget {
    /// Create a new widget.
    pub fn new() -> Self {
        Self {
            widget: ControlPanelWidget::new("selection_mode", "Mode")
                .with_tooltip("Select input format: Binary, Hex, or Mnemonic"),
            mode: SearchInputMode::Hex,
        }
    }

    /// Set the mode.
    pub fn set_mode(&mut self, mode: SearchInputMode) {
        self.mode = mode;
    }
}

impl Default for SelectionModeWidget {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SelectionScopeWidget
// ---------------------------------------------------------------------------

/// Widget for selecting the search scope (all or selection).
///
/// Ported from `ghidra.app.plugin.core.instructionsearch.ui.SelectionScopeWidget`.
#[derive(Debug, Clone)]
pub struct SelectionScopeWidget {
    /// The widget state.
    pub widget: ControlPanelWidget,
    /// Current scope.
    pub scope: SearchScope,
}

impl SelectionScopeWidget {
    /// Create a new widget.
    pub fn new() -> Self {
        Self {
            widget: ControlPanelWidget::new("selection_scope", "Scope")
                .with_tooltip("Search all or selected addresses only"),
            scope: SearchScope::All,
        }
    }

    /// Set the scope.
    pub fn set_scope(&mut self, scope: SearchScope) {
        self.scope = scope;
    }
}

impl Default for SelectionScopeWidget {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// HintTextArea
// ---------------------------------------------------------------------------

/// A hint/help text area that displays contextual information.
///
/// Ported from `ghidra.app.plugin.core.instructionsearch.ui.HintTextArea`.
#[derive(Debug, Clone)]
pub struct HintTextArea {
    /// The current hint text.
    pub text: String,
    /// Whether the hint area is visible.
    pub visible: bool,
}

impl HintTextArea {
    /// Create a new hint text area.
    pub fn new() -> Self {
        Self {
            text: String::new(),
            visible: false,
        }
    }

    /// Show a hint.
    pub fn show(&mut self, text: impl Into<String>) {
        self.text = text.into();
        self.visible = true;
    }

    /// Hide the hint area.
    pub fn hide(&mut self) {
        self.visible = false;
    }
}

impl Default for HintTextArea {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MessagePanel
// ---------------------------------------------------------------------------

/// A panel for displaying status and error messages.
///
/// Ported from `ghidra.app.plugin.core.instructionsearch.ui.MessagePanel`.
#[derive(Debug, Clone)]
pub struct MessagePanel {
    /// Current messages.
    pub messages: Vec<StatusMessage>,
}

impl MessagePanel {
    /// Create a new message panel.
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
        }
    }

    /// Add an info message.
    pub fn info(&mut self, text: impl Into<String>) {
        self.messages.push(StatusMessage {
            severity: MessageSeverity::Info,
            text: text.into(),
        });
    }

    /// Add a warning message.
    pub fn warn(&mut self, text: impl Into<String>) {
        self.messages.push(StatusMessage {
            severity: MessageSeverity::Warning,
            text: text.into(),
        });
    }

    /// Add an error message.
    pub fn error(&mut self, text: impl Into<String>) {
        self.messages.push(StatusMessage {
            severity: MessageSeverity::Error,
            text: text.into(),
        });
    }

    /// Clear all messages.
    pub fn clear(&mut self) {
        self.messages.clear();
    }

    /// Get the latest message (if any).
    pub fn latest(&self) -> Option<&StatusMessage> {
        self.messages.last()
    }
}

impl Default for MessagePanel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_panel_defaults() {
        let panel = ControlPanel::new();
        assert_eq!(panel.direction, SearchDirection::Forward);
        assert_eq!(panel.scope, SearchScope::All);
        assert_eq!(panel.input_mode, SearchInputMode::Hex);
        assert!(!panel.pattern_valid);
    }

    #[test]
    fn test_control_panel_validate_hex() {
        let mut panel = ControlPanel::new();
        panel.set_pattern("90 C3 ??");
        assert!(panel.pattern_valid);
        panel.set_pattern("ZZZ");
        assert!(!panel.pattern_valid);
    }

    #[test]
    fn test_control_panel_validate_binary() {
        let mut panel = ControlPanel::new();
        panel.input_mode = SearchInputMode::Binary;
        panel.set_pattern("1001 0000 ?");
        assert!(panel.pattern_valid);
        panel.set_pattern("1002");
        assert!(!panel.pattern_valid);
    }

    #[test]
    fn test_endian_flip_widget() {
        let mut widget = EndianFlipWidget::new();
        assert_eq!(widget.endianness, Endianness::LittleEndian);
        widget.toggle();
        assert_eq!(widget.endianness, Endianness::BigEndian);
        widget.toggle();
        assert_eq!(widget.endianness, Endianness::LittleEndian);
    }

    #[test]
    fn test_insert_bytes_widget() {
        let mut widget = InsertBytesWidget::new();
        widget.set_bytes(vec![0x90, 0xC3]);
        assert_eq!(widget.effective_bytes(), vec![0x90, 0xC3]);

        widget.set_mask(vec![0xFF, 0x00]);
        assert_eq!(widget.effective_bytes(), vec![0x90, 0x00]);
    }

    #[test]
    fn test_search_direction_widget() {
        let mut widget = SearchDirectionWidget::new();
        assert_eq!(widget.direction, SearchDirection::Forward);
        widget.toggle();
        assert_eq!(widget.direction, SearchDirection::Backward);
    }

    #[test]
    fn test_selection_mode_widget() {
        let mut widget = SelectionModeWidget::new();
        assert_eq!(widget.mode, SearchInputMode::Hex);
        widget.set_mode(SearchInputMode::Mnemonic);
        assert_eq!(widget.mode, SearchInputMode::Mnemonic);
    }

    #[test]
    fn test_selection_scope_widget() {
        let mut widget = SelectionScopeWidget::new();
        widget.set_scope(SearchScope::Selection);
        assert_eq!(widget.scope, SearchScope::Selection);
    }

    #[test]
    fn test_hint_text_area() {
        let mut hint = HintTextArea::new();
        assert!(!hint.visible);
        hint.show("Enter a hex pattern");
        assert!(hint.visible);
        assert_eq!(hint.text, "Enter a hex pattern");
        hint.hide();
        assert!(!hint.visible);
    }

    #[test]
    fn test_message_panel() {
        let mut panel = MessagePanel::new();
        panel.info("Searching...");
        panel.warn("Pattern is slow");
        panel.error("Invalid input");
        assert_eq!(panel.messages.len(), 3);
        assert_eq!(
            panel.latest().unwrap().severity,
            MessageSeverity::Error
        );
        panel.clear();
        assert!(panel.messages.is_empty());
    }
}
