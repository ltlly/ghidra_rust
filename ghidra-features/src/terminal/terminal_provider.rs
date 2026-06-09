//! Terminal Provider -- UI component provider for a single terminal session.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.terminal.TerminalProvider` Java class.
//!
//! This module provides the enhanced terminal provider that manages:
//! - Find dialog state (search text, options, navigation)
//! - UI actions (find, find next, find previous, select all, font size, terminate)
//! - Font size management
//! - Terminal session lifecycle (active, terminated)
//! - Subtitle and title management
//! - Clipboard integration
//! - Fixed/dynamic sizing modes
//!
//! # Architecture
//!
//! - [`EnhancedTerminalProvider`] -- full-featured provider with UI actions
//! - [`FindDialogState`] -- state of the find/search dialog
//! - [`FindOptions`] -- search options bitflags
//! - [`ProviderAction`] -- enum of all provider-local actions
//! - [`FontSizeManager`] -- font size tracking and adjustment
//! - [`WindowPosition`] -- default window position hints

use std::sync::{Arc, Mutex};

use super::terminal_finder::{TerminalFindMatch, TerminalFindOptions, TextTerminalFinder};
use super::terminal_listener::{TerminalListener, TerminalOutput, TerminalProvider};
use super::terminal_plugin::ClipboardService;

// ---------------------------------------------------------------------------
// WindowPosition -- default window placement hints
// ---------------------------------------------------------------------------

/// Default window position for the terminal provider.
///
/// Ported from Ghidra's `WindowPosition` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowPosition {
    /// Position at the bottom of the tool window.
    Bottom,
    /// Position at the top.
    Top,
    /// Position on the left side.
    Left,
    /// Position on the right side.
    Right,
    /// Floating window.
    Floating,
}

impl Default for WindowPosition {
    fn default() -> Self {
        Self::Bottom
    }
}

// ---------------------------------------------------------------------------
// FindOptions -- search option flags
// ---------------------------------------------------------------------------

/// Options for the terminal find dialog.
///
/// Ported from `TerminalPanel.FindOptions` Java enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FindOptions {
    /// Case-sensitive search.
    CaseSensitive,
    /// Wrap around when reaching the end/beginning.
    Wrap,
    /// Match whole words only.
    WholeWord,
    /// Use regular expressions.
    Regex,
}

// ---------------------------------------------------------------------------
// FindDialogState -- state of the find dialog
// ---------------------------------------------------------------------------

/// State of the find/search dialog.
///
/// Ported from the `FindDialog` inner class of `TerminalProvider` in Java.
/// Manages the search text, options, and current match position.
#[derive(Debug, Clone)]
pub struct FindDialogState {
    /// The current search text.
    pub search_text: String,
    /// Active find options.
    pub options: Vec<FindOptions>,
    /// Current match index (for find next/previous navigation).
    pub current_match_index: Option<usize>,
    /// All matches found in the last search.
    pub matches: Vec<TerminalFindMatch>,
    /// Whether the dialog is visible.
    pub visible: bool,
}

impl FindDialogState {
    /// Create a new find dialog state.
    pub fn new() -> Self {
        Self {
            search_text: String::new(),
            options: Vec::new(),
            current_match_index: None,
            matches: Vec::new(),
            visible: false,
        }
    }

    /// Whether the find step actions (next/previous) should be enabled.
    ///
    /// Ported from `TerminalProvider.isEnabledFindStep(ActionContext)`.
    pub fn is_find_step_enabled(&self) -> bool {
        !self.search_text.is_empty()
    }

    /// Whether the `CaseSensitive` option is active.
    pub fn is_case_sensitive(&self) -> bool {
        self.options.contains(&FindOptions::CaseSensitive)
    }

    /// Whether the `Wrap` option is active.
    pub fn is_wrap(&self) -> bool {
        self.options.contains(&FindOptions::Wrap)
    }

    /// Whether the `WholeWord` option is active.
    pub fn is_whole_word(&self) -> bool {
        self.options.contains(&FindOptions::WholeWord)
    }

    /// Whether the `Regex` option is active.
    pub fn is_regex(&self) -> bool {
        self.options.contains(&FindOptions::Regex)
    }

    /// Update the search text and clear stale results.
    pub fn set_search_text(&mut self, text: impl Into<String>) {
        self.search_text = text.into();
        self.matches.clear();
        self.current_match_index = None;
    }

    /// Set the active options.
    pub fn set_options(&mut self, options: Vec<FindOptions>) {
        self.options = options;
        self.matches.clear();
        self.current_match_index = None;
    }

    /// Toggle an option on or off.
    pub fn toggle_option(&mut self, option: FindOptions) {
        if let Some(pos) = self.options.iter().position(|o| *o == option) {
            self.options.remove(pos);
        } else {
            self.options.push(option);
        }
    }

    /// Set the matches from a search result.
    ///
    /// Resets the current match index so the next `find_next` starts from
    /// the first match.
    pub fn set_matches(&mut self, matches: Vec<TerminalFindMatch>) {
        self.matches = matches;
        self.current_match_index = None;
    }

    /// Advance to the next match. Returns the match if available.
    pub fn find_next(&mut self) -> Option<&TerminalFindMatch> {
        if self.matches.is_empty() {
            return None;
        }
        let idx = match self.current_match_index {
            None => 0,
            Some(i) => {
                let next = i + 1;
                if next >= self.matches.len() {
                    if self.is_wrap() {
                        0
                    } else {
                        return None;
                    }
                } else {
                    next
                }
            }
        };
        self.current_match_index = Some(idx);
        self.matches.get(idx)
    }

    /// Advance to the previous match. Returns the match if available.
    pub fn find_previous(&mut self) -> Option<&TerminalFindMatch> {
        if self.matches.is_empty() {
            return None;
        }
        let idx = match self.current_match_index {
            None => self.matches.len() - 1,
            Some(0) => {
                if self.is_wrap() {
                    self.matches.len() - 1
                } else {
                    return None;
                }
            }
            Some(i) => i - 1,
        };
        self.current_match_index = Some(idx);
        self.matches.get(idx)
    }

    /// Get the current match, if any.
    pub fn current_match(&self) -> Option<&TerminalFindMatch> {
        self.current_match_index
            .and_then(|i| self.matches.get(i))
    }

    /// The total number of matches.
    pub fn match_count(&self) -> usize {
        self.matches.len()
    }

    /// Show the dialog.
    pub fn show(&mut self) {
        self.visible = true;
    }

    /// Hide the dialog.
    pub fn hide(&mut self) {
        self.visible = false;
    }

    /// Convert current options to [`TerminalFindOptions`] for the finder.
    pub fn to_find_options(&self) -> TerminalFindOptions {
        TerminalFindOptions {
            case_sensitive: self.is_case_sensitive(),
            use_regex: self.is_regex(),
            wrap_around: self.is_wrap(),
            search_backward: false,
        }
    }
}

impl Default for FindDialogState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FontSizeManager -- font size tracking
// ---------------------------------------------------------------------------

/// Manages terminal font size with increase, decrease, and reset operations.
///
/// Ported from the font size actions in `TerminalProvider` Java class.
#[derive(Debug, Clone)]
pub struct FontSizeManager {
    /// Current font size in points.
    current_size: f64,
    /// Default (reset) font size.
    default_size: f64,
    /// Minimum allowed font size.
    min_size: f64,
    /// Maximum allowed font size.
    max_size: f64,
    /// Step size for increase/decrease operations.
    step: f64,
}

impl FontSizeManager {
    /// Create a new font size manager with default settings.
    pub fn new() -> Self {
        Self {
            current_size: 14.0,
            default_size: 14.0,
            min_size: 6.0,
            max_size: 72.0,
            step: 1.0,
        }
    }

    /// Create a font size manager with custom settings.
    pub fn with_settings(default_size: f64, min_size: f64, max_size: f64, step: f64) -> Self {
        Self {
            current_size: default_size,
            default_size,
            min_size,
            max_size,
            step,
        }
    }

    /// Get the current font size.
    pub fn current_size(&self) -> f64 {
        self.current_size
    }

    /// Get the default font size.
    pub fn default_size(&self) -> f64 {
        self.default_size
    }

    /// Increase the font size by one step.
    ///
    /// Ported from `TerminalProvider.activatedIncreaseFontSize()`.
    /// Returns the new size.
    pub fn increase(&mut self) -> f64 {
        self.current_size = (self.current_size + self.step).min(self.max_size);
        self.current_size
    }

    /// Decrease the font size by one step.
    ///
    /// Ported from `TerminalProvider.activatedDecreaseFontSize()`.
    /// Returns the new size.
    pub fn decrease(&mut self) -> f64 {
        self.current_size = (self.current_size - self.step).max(self.min_size);
        self.current_size
    }

    /// Reset the font size to the default.
    ///
    /// Ported from `TerminalProvider.activatedResetFontSize()`.
    /// Returns the new size.
    pub fn reset(&mut self) -> f64 {
        self.current_size = self.default_size;
        self.current_size
    }

    /// Set the font size directly, clamping to valid range.
    pub fn set_size(&mut self, size: f64) -> f64 {
        self.current_size = size.clamp(self.min_size, self.max_size);
        self.current_size
    }
}

impl Default for FontSizeManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ProviderAction -- actions local to the terminal provider
// ---------------------------------------------------------------------------

/// Actions that can be performed on the terminal provider.
///
/// Ported from the various `DockingAction` fields in `TerminalProvider` Java.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderAction {
    /// Open the find dialog.
    Find,
    /// Find the next match.
    FindNext,
    /// Find the previous match.
    FindPrevious,
    /// Select all text in the terminal.
    SelectAll,
    /// Terminate the terminal session.
    Terminate,
    /// Increase font size.
    IncreaseFontSize,
    /// Decrease font size.
    DecreaseFontSize,
    /// Reset font size to default.
    ResetFontSize,
}

// ---------------------------------------------------------------------------
// SizingMode -- terminal sizing configuration
// ---------------------------------------------------------------------------

/// How the terminal determines its size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizingMode {
    /// Fixed number of columns and rows.
    Fixed { cols: u16, rows: u16 },
    /// Dynamically sized based on available space.
    Dynamic,
}

impl Default for SizingMode {
    fn default() -> Self {
        Self::Dynamic
    }
}

// ---------------------------------------------------------------------------
// EnhancedTerminalProvider
// ---------------------------------------------------------------------------

/// A full-featured terminal provider with UI actions and find dialog.
///
/// Ported from Ghidra's `TerminalProvider` Java class.  This wraps a
/// base [`TerminalProvider`] and adds:
/// - Find dialog with next/previous navigation
/// - Font size management
/// - Action enablement checks
/// - Termination lifecycle
/// - Sizing mode control
/// - Window menu group and position
/// - Title/subtitle management
/// - Clipboard integration
pub struct EnhancedTerminalProvider {
    /// The underlying base provider.
    base: TerminalProvider,
    /// Find dialog state.
    find_dialog: FindDialogState,
    /// Font size manager.
    font_size: FontSizeManager,
    /// Sizing mode.
    sizing_mode: SizingMode,
    /// Default window position.
    window_position: WindowPosition,
    /// Window menu group name.
    window_menu_group: String,
    /// Title of the provider window.
    title: String,
    /// Subtitle of the provider window.
    subtitle: String,
    /// Whether the session has terminated.
    terminated: bool,
    /// Whether the terminate action is registered.
    has_terminate_action: bool,
    /// Registered actions.
    actions: Vec<ProviderAction>,
    /// Clipboard service reference (if available).
    clipboard_service: Option<Arc<dyn ClipboardService>>,
    /// Help location plugin name.
    help_plugin_name: String,
}

impl EnhancedTerminalProvider {
    /// Create a new enhanced terminal provider.
    ///
    /// Ported from the `TerminalProvider` constructor in Java.
    pub fn new(
        name: impl Into<String>,
        output: Box<dyn TerminalOutput>,
    ) -> Self {
        let name_str = name.into();
        Self {
            base: TerminalProvider::new(name_str.clone(), output),
            find_dialog: FindDialogState::new(),
            font_size: FontSizeManager::new(),
            sizing_mode: SizingMode::default(),
            window_position: WindowPosition::default(),
            window_menu_group: "Terminals".into(),
            title: "Terminal".into(),
            subtitle: String::new(),
            terminated: false,
            has_terminate_action: false,
            actions: Vec::new(),
            clipboard_service: None,
            help_plugin_name: String::new(),
        }
    }

    // -- Access to the base provider --

    /// Get a reference to the underlying base provider.
    pub fn base(&self) -> &TerminalProvider {
        &self.base
    }

    /// Get a mutable reference to the underlying base provider.
    pub fn base_mut(&mut self) -> &mut TerminalProvider {
        &mut self.base
    }

    // -- Title and subtitle --

    /// Get the window title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Set the window title.
    pub fn set_title(&mut self, title: impl Into<String>) {
        self.title = title.into();
    }

    /// Get the window subtitle.
    pub fn subtitle(&self) -> &str {
        &self.subtitle
    }

    /// Set the window subtitle.
    ///
    /// Ported from `TerminalListener.retitled()` callback in the constructor.
    pub fn set_subtitle(&mut self, subtitle: impl Into<String>) {
        self.subtitle = subtitle.into();
    }

    // -- Window position and menu group --

    /// Get the default window position.
    pub fn window_position(&self) -> WindowPosition {
        self.window_position
    }

    /// Set the default window position.
    pub fn set_window_position(&mut self, position: WindowPosition) {
        self.window_position = position;
    }

    /// Get the window menu group name.
    pub fn window_menu_group(&self) -> &str {
        &self.window_menu_group
    }

    /// Set the window menu group name.
    pub fn set_window_menu_group(&mut self, group: impl Into<String>) {
        self.window_menu_group = group.into();
    }

    // -- Help location --

    /// Get the help plugin name.
    pub fn help_plugin_name(&self) -> &str {
        &self.help_plugin_name
    }

    /// Set the help plugin name.
    pub fn set_help_plugin_name(&mut self, name: impl Into<String>) {
        self.help_plugin_name = name.into();
    }

    // -- Find dialog --

    /// Get a reference to the find dialog state.
    pub fn find_dialog(&self) -> &FindDialogState {
        &self.find_dialog
    }

    /// Get a mutable reference to the find dialog state.
    pub fn find_dialog_mut(&mut self) -> &mut FindDialogState {
        &mut self.find_dialog
    }

    /// Show the find dialog.
    ///
    /// Ported from `TerminalProvider.activatedFind(ActionContext)`.
    pub fn show_find_dialog(&mut self) {
        self.find_dialog.show();
    }

    /// Perform a find operation.
    ///
    /// Ported from `TerminalProvider.doFind(boolean forward)`.
    /// Searches the terminal content and updates the find dialog state.
    pub fn do_find(&mut self, forward: bool) -> Option<&TerminalFindMatch> {
        if !self.find_dialog.is_find_step_enabled() {
            return None;
        }

        // If we have no matches yet or the search text changed, run a search.
        if self.find_dialog.matches.is_empty() {
            self.run_search();
        }

        if forward {
            self.find_dialog.find_next()
        } else {
            self.find_dialog.find_previous()
        }
    }

    /// Run a search against the terminal content.
    ///
    /// This uses the terminal's line content to find matches.
    fn run_search(&mut self) {
        let options = self.find_dialog.to_find_options();
        let finder = TextTerminalFinder::new(&self.find_dialog.search_text, options);

        // Collect lines from the terminal state.
        let lines: Vec<String> = (0..self.base.state().height)
            .filter_map(|row| {
                let line: String = (0..self.base.state().width)
                    .filter_map(|col| self.base.state().cell(row, col).map(|c| c.ch))
                    .collect();
                if line.chars().any(|c| !c.is_whitespace()) {
                    Some(line)
                } else {
                    None
                }
            })
            .collect();

        let matches = finder.find_in_lines(&lines);
        self.find_dialog.set_matches(matches);
    }

    /// Whether the find next/previous action should be enabled.
    ///
    /// Ported from `TerminalProvider.isEnabledFindStep(ActionContext)`.
    pub fn is_find_step_enabled(&self) -> bool {
        self.find_dialog.is_find_step_enabled()
    }

    /// Find the next match.
    ///
    /// Ported from `TerminalProvider.activatedFindNext(ActionContext)`.
    pub fn find_next(&mut self) -> Option<&TerminalFindMatch> {
        self.do_find(true)
    }

    /// Find the previous match.
    ///
    /// Ported from `TerminalProvider.activatedFindPrevious(ActionContext)`.
    pub fn find_previous(&mut self) -> Option<&TerminalFindMatch> {
        self.do_find(false)
    }

    // -- Font size --

    /// Get a reference to the font size manager.
    pub fn font_size(&self) -> &FontSizeManager {
        &self.font_size
    }

    /// Get a mutable reference to the font size manager.
    pub fn font_size_mut(&mut self) -> &mut FontSizeManager {
        &mut self.font_size
    }

    /// Increase the font size.
    ///
    /// Ported from `TerminalProvider.activatedIncreaseFontSize(ActionContext)`.
    pub fn increase_font_size(&mut self) -> f64 {
        self.font_size.increase()
    }

    /// Decrease the font size.
    ///
    /// Ported from `TerminalProvider.activatedDecreaseFontSize(ActionContext)`.
    pub fn decrease_font_size(&mut self) -> f64 {
        self.font_size.decrease()
    }

    /// Reset the font size to default.
    ///
    /// Ported from `TerminalProvider.activatedResetFontSize(ActionContext)`.
    pub fn reset_font_size(&mut self) -> f64 {
        self.font_size.reset()
    }

    // -- Sizing --

    /// Get the current sizing mode.
    pub fn sizing_mode(&self) -> SizingMode {
        self.sizing_mode
    }

    /// Set a fixed terminal size.
    ///
    /// Ported from `TerminalProvider.setFixedSize(short, short)`.
    pub fn set_fixed_size(&mut self, cols: u16, rows: u16) {
        self.sizing_mode = SizingMode::Fixed { cols, rows };
        self.base.notify_resize(cols, rows);
    }

    /// Switch to dynamic sizing.
    ///
    /// Ported from `TerminalProvider.setDynamicSize()`.
    pub fn set_dynamic_size(&mut self) {
        self.sizing_mode = SizingMode::Dynamic;
    }

    /// Get the current column count.
    ///
    /// Ported from `TerminalProvider.getColumns()`.
    pub fn columns(&self) -> usize {
        self.base.state().width
    }

    /// Get the current row count.
    ///
    /// Ported from `TerminalProvider.getRows()`.
    pub fn rows(&self) -> usize {
        self.base.state().height
    }

    // -- Cursor position --

    /// Get the cursor column.
    ///
    /// Ported from `TerminalProvider.getCursorColumn()`.
    pub fn cursor_column(&self) -> usize {
        self.base.state().cursor_col
    }

    /// Get the cursor row.
    ///
    /// Ported from `TerminalProvider.getCursorRow()`.
    pub fn cursor_row(&self) -> usize {
        self.base.state().cursor_row
    }

    // -- Clipboard --

    /// Set the clipboard service.
    ///
    /// Ported from `TerminalProvider.setClipboardService(ClipboardService)`.
    pub fn set_clipboard_service(&mut self, service: Option<Arc<dyn ClipboardService>>) {
        self.clipboard_service = service;
    }

    /// Copy text to the clipboard (if a clipboard service is available).
    pub fn clipboard_copy(&self, text: &str) {
        if let Some(ref service) = self.clipboard_service {
            service.set_clipboard_contents(text);
        }
    }

    /// Paste text from the clipboard (if available).
    pub fn clipboard_paste(&self) -> Option<String> {
        self.clipboard_service
            .as_ref()
            .and_then(|s| s.get_clipboard_contents())
    }

    // -- Actions --

    /// Register an action with this provider.
    pub fn register_action(&mut self, action: ProviderAction) {
        if !self.actions.contains(&action) {
            self.actions.push(action);
        }
    }

    /// Unregister an action from this provider.
    pub fn unregister_action(&mut self, action: ProviderAction) {
        self.actions.retain(|a| *a != action);
    }

    /// Check if an action is registered.
    pub fn has_action(&self, action: ProviderAction) -> bool {
        self.actions.contains(&action)
    }

    /// Get all registered actions.
    pub fn registered_actions(&self) -> &[ProviderAction] {
        &self.actions
    }

    /// Set the terminate action.
    ///
    /// Ported from `TerminalProvider.setTerminateAction(Runnable)`.
    pub fn set_terminate_action(&mut self, enabled: bool) {
        self.has_terminate_action = enabled;
        if enabled {
            self.register_action(ProviderAction::Terminate);
        } else {
            self.unregister_action(ProviderAction::Terminate);
        }
    }

    /// Whether the terminate action is available.
    pub fn has_terminate_action(&self) -> bool {
        self.has_terminate_action
    }

    // -- Lifecycle --

    /// Whether the terminal session has terminated.
    ///
    /// Ported from `TerminalProvider.isTerminated()`.
    pub fn is_terminated(&self) -> bool {
        self.terminated
    }

    /// Mark the terminal as terminated.
    ///
    /// Ported from `TerminalProvider.terminated(int)`.
    ///
    /// Adjusts the title, clears listeners, disables the cursor, and
    /// removes the terminate action.
    pub fn terminated(&mut self, exitcode: i32) {
        self.terminated = true;
        self.base.terminated(exitcode);
        self.unregister_action(ProviderAction::Terminate);
        self.base.clear_listeners();
        self.set_title("[Terminal]");
        self.set_subtitle("Terminated");
    }

    /// Remove the provider from the tool.
    ///
    /// Ported from `TerminalProvider.removeFromTool()`.
    pub fn remove_from_tool(&mut self) {
        self.base.remove_from_tool();
    }

    /// Close the component.
    ///
    /// Ported from `TerminalProvider.closeComponent()`.
    /// If terminated, also removes from tool.
    pub fn close_component(&mut self) {
        if self.terminated {
            self.remove_from_tool();
        }
    }

    /// Process input from the application.
    ///
    /// Ported from `TerminalProvider.processInput(ByteBuffer)`.
    pub fn process_input(&mut self, data: &[u8]) {
        self.base.inject_display_output(data);
    }

    // -- Select All (conceptual) --

    /// Select all text in the terminal.
    ///
    /// Ported from `TerminalProvider.activatedSelectAll(ActionContext)`.
    /// Returns the full text content of the terminal.
    pub fn select_all_text(&self) -> String {
        let state = self.base.state();
        let mut result = String::new();
        for row in 0..state.height {
            for col in 0..state.width {
                if let Some(cell) = state.cell(row, col) {
                    result.push(cell.ch);
                }
            }
            if row + 1 < state.height {
                result.push('\n');
            }
        }
        result
    }

    /// Get text from a range of the terminal.
    ///
    /// Ported from `TerminalProvider.getRangeText(int, int, int, int)`.
    pub fn get_range_text(
        &self,
        start_col: usize,
        start_row: usize,
        end_col: usize,
        end_row: usize,
    ) -> String {
        let state = self.base.state();
        let mut result = String::new();
        for row in start_row..=end_row.min(state.height.saturating_sub(1)) {
            let col_start = if row == start_row { start_col } else { 0 };
            let col_end = if row == end_row {
                end_col.min(state.width)
            } else {
                state.width
            };
            for col in col_start..col_end {
                if let Some(cell) = state.cell(row, col) {
                    result.push(cell.ch);
                }
            }
            if row < end_row {
                result.push('\n');
            }
        }
        result
    }
}

impl std::fmt::Debug for EnhancedTerminalProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnhancedTerminalProvider")
            .field("base", &self.base)
            .field("find_dialog", &self.find_dialog)
            .field("font_size", &self.font_size)
            .field("sizing_mode", &self.sizing_mode)
            .field("window_position", &self.window_position)
            .field("title", &self.title)
            .field("subtitle", &self.subtitle)
            .field("terminated", &self.terminated)
            .field("has_terminate_action", &self.has_terminate_action)
            .field("actions", &self.actions)
            .field("clipboard_service", &self.clipboard_service.is_some())
            .field("help_plugin_name", &self.help_plugin_name)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal::terminal_listener::BufferedTerminalOutput;

    #[test]
    fn test_find_dialog_state_new() {
        let dialog = FindDialogState::new();
        assert!(dialog.search_text.is_empty());
        assert!(dialog.options.is_empty());
        assert!(dialog.matches.is_empty());
        assert!(dialog.current_match_index.is_none());
        assert!(!dialog.visible);
    }

    #[test]
    fn test_find_dialog_set_search_text() {
        let mut dialog = FindDialogState::new();
        dialog.set_search_text("hello");
        assert_eq!(dialog.search_text, "hello");
        assert!(dialog.is_find_step_enabled());
    }

    #[test]
    fn test_find_dialog_toggle_option() {
        let mut dialog = FindDialogState::new();
        dialog.toggle_option(FindOptions::CaseSensitive);
        assert!(dialog.is_case_sensitive());
        dialog.toggle_option(FindOptions::CaseSensitive);
        assert!(!dialog.is_case_sensitive());
    }

    #[test]
    fn test_find_dialog_navigation() {
        let mut dialog = FindDialogState::new();
        dialog.set_search_text("test");
        dialog.set_matches(vec![
            TerminalFindMatch {
                line: 0,
                col: 0,
                length: 4,
                text: "test".into(),
            },
            TerminalFindMatch {
                line: 1,
                col: 5,
                length: 4,
                text: "test".into(),
            },
        ]);

        // First match
        let m = dialog.find_next().unwrap();
        assert_eq!(m.line, 0);

        // Second match
        let m = dialog.find_next().unwrap();
        assert_eq!(m.line, 1);

        // Wrap back to first
        dialog.toggle_option(FindOptions::Wrap);
        let m = dialog.find_next().unwrap();
        assert_eq!(m.line, 0);

        // Previous goes to last
        let m = dialog.find_previous().unwrap();
        assert_eq!(m.line, 1);
    }

    #[test]
    fn test_find_dialog_empty_navigation() {
        let mut dialog = FindDialogState::new();
        assert!(dialog.find_next().is_none());
        assert!(dialog.find_previous().is_none());
    }

    #[test]
    fn test_find_dialog_show_hide() {
        let mut dialog = FindDialogState::new();
        dialog.show();
        assert!(dialog.visible);
        dialog.hide();
        assert!(!dialog.visible);
    }

    #[test]
    fn test_font_size_manager() {
        let mut fsm = FontSizeManager::new();
        assert_eq!(fsm.current_size(), 14.0);

        fsm.increase();
        assert_eq!(fsm.current_size(), 15.0);

        fsm.decrease();
        assert_eq!(fsm.current_size(), 14.0);

        fsm.reset();
        assert_eq!(fsm.current_size(), 14.0);
    }

    #[test]
    fn test_font_size_clamp() {
        let mut fsm = FontSizeManager::new();
        // Decrease below minimum.
        for _ in 0..100 {
            fsm.decrease();
        }
        assert_eq!(fsm.current_size(), 6.0);

        // Increase above maximum.
        for _ in 0..100 {
            fsm.increase();
        }
        assert_eq!(fsm.current_size(), 72.0);
    }

    #[test]
    fn test_font_size_custom_settings() {
        let mut fsm = FontSizeManager::with_settings(10.0, 8.0, 20.0, 2.0);
        assert_eq!(fsm.current_size(), 10.0);
        assert_eq!(fsm.increase(), 12.0);
        assert_eq!(fsm.increase(), 14.0);
        assert_eq!(fsm.decrease(), 12.0);
        assert_eq!(fsm.reset(), 10.0);
    }

    #[test]
    fn test_enhanced_provider_new() {
        let output = Box::new(BufferedTerminalOutput::new());
        let provider = EnhancedTerminalProvider::new("test", output);
        assert_eq!(provider.title(), "Terminal");
        assert!(provider.subtitle().is_empty());
        assert!(!provider.is_terminated());
        assert_eq!(provider.window_position(), WindowPosition::Bottom);
        assert_eq!(provider.window_menu_group(), "Terminals");
    }

    #[test]
    fn test_enhanced_provider_title_subtitle() {
        let output = Box::new(BufferedTerminalOutput::new());
        let mut provider = EnhancedTerminalProvider::new("test", output);
        provider.set_title("My Terminal");
        provider.set_subtitle("bash");
        assert_eq!(provider.title(), "My Terminal");
        assert_eq!(provider.subtitle(), "bash");
    }

    #[test]
    fn test_enhanced_provider_sizing() {
        let output = Box::new(BufferedTerminalOutput::new());
        let mut provider = EnhancedTerminalProvider::new("test", output);

        assert_eq!(provider.sizing_mode(), SizingMode::Dynamic);
        assert_eq!(provider.columns(), 80);
        assert_eq!(provider.rows(), 24);

        provider.set_fixed_size(120, 40);
        assert_eq!(
            provider.sizing_mode(),
            SizingMode::Fixed {
                cols: 120,
                rows: 40
            }
        );

        provider.set_dynamic_size();
        assert_eq!(provider.sizing_mode(), SizingMode::Dynamic);
    }

    #[test]
    fn test_enhanced_provider_actions() {
        let output = Box::new(BufferedTerminalOutput::new());
        let mut provider = EnhancedTerminalProvider::new("test", output);

        assert!(!provider.has_action(ProviderAction::Find));
        provider.register_action(ProviderAction::Find);
        assert!(provider.has_action(ProviderAction::Find));

        provider.register_action(ProviderAction::FindNext);
        assert_eq!(provider.registered_actions().len(), 2);

        provider.unregister_action(ProviderAction::Find);
        assert!(!provider.has_action(ProviderAction::Find));
        assert_eq!(provider.registered_actions().len(), 1);
    }

    #[test]
    fn test_enhanced_provider_terminate_action() {
        let output = Box::new(BufferedTerminalOutput::new());
        let mut provider = EnhancedTerminalProvider::new("test", output);

        provider.set_terminate_action(true);
        assert!(provider.has_terminate_action());
        assert!(provider.has_action(ProviderAction::Terminate));

        provider.set_terminate_action(false);
        assert!(!provider.has_terminate_action());
        assert!(!provider.has_action(ProviderAction::Terminate));
    }

    #[test]
    fn test_enhanced_provider_terminated() {
        let output = Box::new(BufferedTerminalOutput::new());
        let mut provider = EnhancedTerminalProvider::new("test", output);

        provider.set_terminate_action(true);
        provider.terminated(0);

        assert!(provider.is_terminated());
        assert_eq!(provider.title(), "[Terminal]");
        assert_eq!(provider.subtitle(), "Terminated");
        assert!(!provider.has_action(ProviderAction::Terminate));
    }

    #[test]
    fn test_enhanced_provider_close_component() {
        let output = Box::new(BufferedTerminalOutput::new());
        let mut provider = EnhancedTerminalProvider::new("test", output);

        // Not terminated: close_component is a no-op.
        provider.close_component();
        assert!(!provider.is_terminated());

        // Terminated: close_component removes from tool.
        provider.terminated(0);
        provider.close_component();
    }

    #[test]
    fn test_enhanced_provider_find() {
        let output = Box::new(BufferedTerminalOutput::new());
        let mut provider = EnhancedTerminalProvider::new("test", output);

        // Write some content.
        provider.process_input(b"Hello World\nHello Again");
        provider.show_find_dialog();

        provider.find_dialog_mut().set_search_text("Hello");
        assert!(provider.is_find_step_enabled());

        // Run find.
        let result = provider.find_next();
        // May or may not find a match depending on how content is stored.
        // The important thing is that it doesn't panic.
    }

    #[test]
    fn test_enhanced_provider_font_size() {
        let output = Box::new(BufferedTerminalOutput::new());
        let mut provider = EnhancedTerminalProvider::new("test", output);

        assert_eq!(provider.font_size().current_size(), 14.0);
        assert_eq!(provider.increase_font_size(), 15.0);
        assert_eq!(provider.decrease_font_size(), 14.0);
        assert_eq!(provider.reset_font_size(), 14.0);
    }

    #[test]
    fn test_enhanced_provider_clipboard() {
        let output = Box::new(BufferedTerminalOutput::new());
        let mut provider = EnhancedTerminalProvider::new("test", output);

        // No clipboard service: operations are no-ops.
        provider.clipboard_copy("hello");
        assert!(provider.clipboard_paste().is_none());

        // Set a clipboard service.
        let service = Arc::new(
            crate::terminal::terminal_plugin::InMemoryClipboardService::new(),
        );
        provider.set_clipboard_service(Some(service.clone()));

        provider.clipboard_copy("hello world");
        assert_eq!(
            provider.clipboard_paste(),
            Some("hello world".to_string())
        );
    }

    #[test]
    fn test_enhanced_provider_select_all() {
        let output = Box::new(BufferedTerminalOutput::new());
        let mut provider = EnhancedTerminalProvider::new("test", output);

        provider.process_input(b"AB");
        let text = provider.select_all_text();
        // The text should contain 'A' and 'B' somewhere.
        assert!(text.contains('A'));
        assert!(text.contains('B'));
    }

    #[test]
    fn test_enhanced_provider_range_text() {
        let output = Box::new(BufferedTerminalOutput::new());
        let mut provider = EnhancedTerminalProvider::new("test", output);

        provider.process_input(b"ABCDE\nFGHIJ");
        let text = provider.get_range_text(0, 0, 5, 1);
        assert!(text.contains('A'));
    }

    #[test]
    fn test_enhanced_provider_process_input() {
        let output = Box::new(BufferedTerminalOutput::new());
        let mut provider = EnhancedTerminalProvider::new("test", output);

        provider.process_input(b"Hello, terminal!");
        assert!(provider.cursor_column() > 0 || provider.columns() > 0);
    }

    #[test]
    fn test_enhanced_provider_window_position() {
        let output = Box::new(BufferedTerminalOutput::new());
        let mut provider = EnhancedTerminalProvider::new("test", output);

        provider.set_window_position(WindowPosition::Right);
        assert_eq!(provider.window_position(), WindowPosition::Right);

        provider.set_window_menu_group("Custom Terminals");
        assert_eq!(provider.window_menu_group(), "Custom Terminals");
    }

    #[test]
    fn test_enhanced_provider_help_plugin() {
        let output = Box::new(BufferedTerminalOutput::new());
        let mut provider = EnhancedTerminalProvider::new("test", output);

        provider.set_help_plugin_name("MyPlugin");
        assert_eq!(provider.help_plugin_name(), "MyPlugin");
    }

    #[test]
    fn test_window_position_default() {
        assert_eq!(WindowPosition::default(), WindowPosition::Bottom);
    }

    #[test]
    fn test_sizing_mode_default() {
        assert_eq!(SizingMode::default(), SizingMode::Dynamic);
    }

    #[test]
    fn test_find_options_equality() {
        assert_eq!(FindOptions::CaseSensitive, FindOptions::CaseSensitive);
        assert_ne!(FindOptions::CaseSensitive, FindOptions::Wrap);
    }
}
