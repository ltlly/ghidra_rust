//! Compile Provider -- displays compilation output and error listing.
//!
//! Ported from Ghidra's `CompileProvider` Java class.
//!
//! The provider is responsible for:
//! - Displaying raw compiler output (stdout/stderr)
//! - Listing parsed diagnostic messages (errors, warnings, info)
//! - Supporting navigation to source locations from messages
//! - Tracking output state (clear, append, scroll)
//!
//! # Architecture
//!
//! ```text
//! CompileProvider
//!   ├── output_lines       (raw compiler output buffer)
//!   ├── messages           (parsed diagnostic messages)
//!   ├── selected_message   (currently selected message index)
//!   ├── config             (display configuration)
//!   └── filter             (message severity filter)
//! ```

use std::path::{Path, PathBuf};

use super::{CompileMessage, CompileSeverity, CompileStatus};

// ============================================================================
// CompileProviderConfig -- display configuration
// ============================================================================

/// Configuration for the compile provider display.
#[derive(Debug, Clone)]
pub struct CompileProviderConfig {
    /// Maximum number of output lines to retain.
    pub max_output_lines: usize,
    /// Maximum number of messages to retain.
    pub max_messages: usize,
    /// Whether to auto-scroll to the latest output.
    pub auto_scroll: bool,
    /// Whether to show timestamps on output lines.
    pub show_timestamps: bool,
    /// Severity filter -- only show messages at or above this severity.
    pub min_severity: Option<CompileSeverity>,
    /// Whether to wrap long output lines.
    pub wrap_lines: bool,
}

impl CompileProviderConfig {
    /// Create a new provider configuration with sensible defaults.
    pub fn new() -> Self {
        Self {
            max_output_lines: 10_000,
            max_messages: 5_000,
            auto_scroll: true,
            show_timestamps: false,
            min_severity: None,
            wrap_lines: true,
        }
    }

    /// Set the severity filter.
    pub fn filter_severity(mut self, min: CompileSeverity) -> Self {
        self.min_severity = Some(min);
        self
    }

    /// Enable or disable timestamps.
    pub fn timestamps(mut self, show: bool) -> Self {
        self.show_timestamps = show;
        self
    }
}

impl Default for CompileProviderConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// CompileProvider -- the provider struct
// ============================================================================

/// The compile provider managing output display and message listing.
///
/// Ported from Ghidra's `CompileProvider`.
#[derive(Debug)]
pub struct CompileProvider {
    /// Raw output lines from the compiler.
    output_lines: Vec<String>,
    /// Parsed diagnostic messages.
    messages: Vec<CompileMessage>,
    /// Index of the currently selected message (if any).
    selected_message: Option<usize>,
    /// Display configuration.
    config: CompileProviderConfig,
    /// Whether the provider is currently visible.
    visible: bool,
    /// Whether the provider is connected to a program.
    connected: bool,
    /// The source file root for resolving relative paths.
    source_root: Option<PathBuf>,
}

impl CompileProvider {
    /// Create a new compile provider with default configuration.
    pub fn new() -> Self {
        Self {
            output_lines: Vec::new(),
            messages: Vec::new(),
            selected_message: None,
            config: CompileProviderConfig::default(),
            visible: false,
            connected: false,
            source_root: None,
        }
    }

    /// Create a new compile provider with a specific configuration.
    pub fn with_config(config: CompileProviderConfig) -> Self {
        Self {
            output_lines: Vec::new(),
            messages: Vec::new(),
            selected_message: None,
            config,
            visible: false,
            connected: false,
            source_root: None,
        }
    }

    // -----------------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------------

    /// Get the provider configuration.
    pub fn config(&self) -> &CompileProviderConfig {
        &self.config
    }

    /// Set the provider configuration.
    pub fn set_config(&mut self, config: CompileProviderConfig) {
        self.config = config;
        self.trim_output();
        self.trim_messages();
    }

    /// Get or set the source root for resolving relative paths.
    pub fn source_root(&self) -> Option<&Path> {
        self.source_root.as_deref()
    }

    /// Set the source root directory.
    pub fn set_source_root(&mut self, root: impl Into<PathBuf>) {
        self.source_root = Some(root.into());
    }

    // -----------------------------------------------------------------------
    // Visibility and connection
    // -----------------------------------------------------------------------

    /// Whether the provider is currently visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Whether the provider is connected to a program.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Connect the provider.
    pub fn connect(&mut self) {
        self.connected = true;
    }

    /// Disconnect the provider.
    pub fn disconnect(&mut self) {
        self.connected = false;
    }

    // -----------------------------------------------------------------------
    // Output management
    // -----------------------------------------------------------------------

    /// Append a single line of output.
    pub fn append_output_line(&mut self, line: &str) {
        self.output_lines.push(line.to_string());
        self.trim_output();
    }

    /// Append multiple lines of output.
    pub fn append_output(&mut self, text: &str) {
        for line in text.lines() {
            self.output_lines.push(line.to_string());
        }
        self.trim_output();
    }

    /// Get all output lines.
    pub fn output_lines(&self) -> &[String] {
        &self.output_lines
    }

    /// Get the full output as a single string.
    pub fn output_text(&self) -> String {
        self.output_lines.join("\n")
    }

    /// Get the number of output lines.
    pub fn output_line_count(&self) -> usize {
        self.output_lines.len()
    }

    /// Clear all output.
    pub fn clear_output(&mut self) {
        self.output_lines.clear();
    }

    fn trim_output(&mut self) {
        let max = self.config.max_output_lines;
        if self.output_lines.len() > max {
            let drain_count = self.output_lines.len() - max;
            self.output_lines.drain(..drain_count);
        }
    }

    // -----------------------------------------------------------------------
    // Message management
    // -----------------------------------------------------------------------

    /// Add a diagnostic message.
    pub fn add_message(&mut self, message: CompileMessage) {
        self.messages.push(message);
        self.trim_messages();
    }

    /// Get all messages (filtered by severity if configured).
    pub fn messages(&self) -> Vec<&CompileMessage> {
        match self.config.min_severity {
            Some(min) => self.messages.iter().filter(|m| m.severity >= min).collect(),
            None => self.messages.iter().collect(),
        }
    }

    /// Get all messages unfiltered.
    pub fn all_messages(&self) -> &[CompileMessage] {
        &self.messages
    }

    /// Get the number of messages (unfiltered).
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    /// Get the number of error messages.
    pub fn error_count(&self) -> usize {
        self.messages
            .iter()
            .filter(|m| m.is_error())
            .count()
    }

    /// Get the number of warning messages.
    pub fn warning_count(&self) -> usize {
        self.messages
            .iter()
            .filter(|m| m.severity == CompileSeverity::Warning)
            .count()
    }

    /// Clear all messages.
    pub fn clear_messages(&mut self) {
        self.messages.clear();
        self.selected_message = None;
    }

    fn trim_messages(&mut self) {
        let max = self.config.max_messages;
        if self.messages.len() > max {
            let drain_count = self.messages.len() - max;
            self.messages.drain(..drain_count);
            // Adjust selected index
            if let Some(sel) = self.selected_message {
                self.selected_message = if sel >= drain_count {
                    Some(sel - drain_count)
                } else {
                    None
                };
            }
        }
    }

    // -----------------------------------------------------------------------
    // Message selection
    // -----------------------------------------------------------------------

    /// Get the currently selected message index.
    pub fn selected_message_index(&self) -> Option<usize> {
        self.selected_message
    }

    /// Get the currently selected message.
    pub fn selected_message(&self) -> Option<&CompileMessage> {
        self.selected_message.and_then(|i| self.messages.get(i))
    }

    /// Select a message by index.
    pub fn select_message(&mut self, index: Option<usize>) {
        if let Some(i) = index {
            if i < self.messages.len() {
                self.selected_message = Some(i);
            }
        } else {
            self.selected_message = None;
        }
    }

    /// Select the next message (wrapping around).
    pub fn select_next_message(&mut self) -> Option<&CompileMessage> {
        if self.messages.is_empty() {
            return None;
        }
        let next = match self.selected_message {
            Some(i) => (i + 1) % self.messages.len(),
            None => 0,
        };
        self.selected_message = Some(next);
        self.messages.get(next)
    }

    /// Select the previous message (wrapping around).
    pub fn select_previous_message(&mut self) -> Option<&CompileMessage> {
        if self.messages.is_empty() {
            return None;
        }
        let prev = match self.selected_message {
            Some(0) => self.messages.len() - 1,
            Some(i) => i - 1,
            None => self.messages.len() - 1,
        };
        self.selected_message = Some(prev);
        self.messages.get(prev)
    }

    /// Select the first error message, if any.
    pub fn select_first_error(&mut self) -> Option<&CompileMessage> {
        let idx = self.messages.iter().position(|m| m.is_error());
        self.selected_message = idx;
        idx.and_then(|i| self.messages.get(i))
    }

    /// Select the next error message from the current selection.
    pub fn select_next_error(&mut self) -> Option<&CompileMessage> {
        if self.messages.is_empty() {
            return None;
        }
        let start = self.selected_message.map(|i| i + 1).unwrap_or(0);
        let len = self.messages.len();
        for offset in 0..len {
            let idx = (start + offset) % len;
            if self.messages[idx].is_error() {
                self.selected_message = Some(idx);
                return self.messages.get(idx);
            }
        }
        None
    }

    // -----------------------------------------------------------------------
    // Navigation support
    // -----------------------------------------------------------------------

    /// Resolve the source file path for the currently selected message.
    ///
    /// If the message has a relative file path and a source root is set,
    /// the path is resolved against the source root.
    pub fn resolve_selected_source_path(&self) -> Option<PathBuf> {
        let msg = self.selected_message()?;
        let file = msg.file.as_ref()?;

        if file.is_absolute() {
            return Some(file.clone());
        }

        match &self.source_root {
            Some(root) => Some(root.join(file)),
            None => Some(file.clone()),
        }
    }

    /// Get the source location of the currently selected message as
    /// `(file, line, column)`.
    pub fn selected_source_location(&self) -> Option<(PathBuf, u32, Option<u32>)> {
        let msg = self.selected_message()?;
        let file = msg.file.as_ref()?;
        let line = msg.line?;

        let resolved = if file.is_absolute() {
            file.clone()
        } else {
            match &self.source_root {
                Some(root) => root.join(file),
                None => file.clone(),
            }
        };

        Some((resolved, line, msg.column))
    }

    // -----------------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------------

    /// Generate a summary string of the current state.
    pub fn summary(&self) -> String {
        let err = self.error_count();
        let warn = self.warning_count();
        let total = self.message_count();
        let lines = self.output_line_count();

        if total == 0 {
            return format!("{} output lines, no messages", lines);
        }

        let mut parts = Vec::new();
        if err > 0 {
            parts.push(format!("{} error{}", err, if err == 1 { "" } else { "s" }));
        }
        if warn > 0 {
            parts.push(format!(
                "{} warning{}",
                warn,
                if warn == 1 { "" } else { "s" }
            ));
        }
        let info = total - err - warn;
        if info > 0 {
            parts.push(format!("{} info", info));
        }

        format!(
            "{} output lines, {} ({})",
            lines,
            total,
            parts.join(", ")
        )
    }

    // -----------------------------------------------------------------------
    // Reset
    // -----------------------------------------------------------------------

    /// Reset the provider to its initial state.
    pub fn reset(&mut self) {
        self.output_lines.clear();
        self.messages.clear();
        self.selected_message = None;
    }
}

impl Default for CompileProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_new() {
        let provider = CompileProvider::new();
        assert!(provider.output_lines().is_empty());
        assert!(provider.messages().is_empty());
        assert_eq!(provider.selected_message_index(), None);
        assert!(!provider.is_visible());
        assert!(!provider.is_connected());
    }

    #[test]
    fn test_provider_with_config() {
        let config = CompileProviderConfig::new()
            .filter_severity(CompileSeverity::Warning)
            .timestamps(true);
        let provider = CompileProvider::with_config(config);
        assert_eq!(provider.config().min_severity, Some(CompileSeverity::Warning));
        assert!(provider.config().show_timestamps);
    }

    #[test]
    fn test_provider_visibility() {
        let mut provider = CompileProvider::new();
        assert!(!provider.is_visible());
        provider.set_visible(true);
        assert!(provider.is_visible());
    }

    #[test]
    fn test_provider_connection() {
        let mut provider = CompileProvider::new();
        assert!(!provider.is_connected());
        provider.connect();
        assert!(provider.is_connected());
        provider.disconnect();
        assert!(!provider.is_connected());
    }

    #[test]
    fn test_provider_append_output() {
        let mut provider = CompileProvider::new();
        provider.append_output_line("line 1");
        provider.append_output_line("line 2");
        assert_eq!(provider.output_line_count(), 2);
        assert_eq!(provider.output_lines()[0], "line 1");
        assert_eq!(provider.output_lines()[1], "line 2");
    }

    #[test]
    fn test_provider_append_multiline() {
        let mut provider = CompileProvider::new();
        provider.append_output("line a\nline b\nline c");
        assert_eq!(provider.output_line_count(), 3);
    }

    #[test]
    fn test_provider_output_text() {
        let mut provider = CompileProvider::new();
        provider.append_output_line("hello");
        provider.append_output_line("world");
        assert_eq!(provider.output_text(), "hello\nworld");
    }

    #[test]
    fn test_provider_clear_output() {
        let mut provider = CompileProvider::new();
        provider.append_output_line("line 1");
        provider.clear_output();
        assert_eq!(provider.output_line_count(), 0);
    }

    #[test]
    fn test_provider_trim_output() {
        let config = CompileProviderConfig::new(); // max 10000
        let mut provider = CompileProvider::with_config(config);
        // Default max is 10000, add a few
        for i in 0..10 {
            provider.append_output_line(&format!("line {}", i));
        }
        assert_eq!(provider.output_line_count(), 10);
    }

    #[test]
    fn test_provider_trim_output_small_max() {
        let config = CompileProviderConfig {
            max_output_lines: 3,
            ..CompileProviderConfig::default()
        };
        let mut provider = CompileProvider::with_config(config);
        for i in 0..5 {
            provider.append_output_line(&format!("line {}", i));
        }
        // Only last 3 should remain
        assert_eq!(provider.output_line_count(), 3);
        assert_eq!(provider.output_lines()[0], "line 2");
        assert_eq!(provider.output_lines()[2], "line 4");
    }

    #[test]
    fn test_provider_add_message() {
        let mut provider = CompileProvider::new();
        provider.add_message(CompileMessage::error("err1"));
        provider.add_message(CompileMessage::warning("warn1"));
        provider.add_message(CompileMessage::info("info1"));
        assert_eq!(provider.message_count(), 3);
        assert_eq!(provider.error_count(), 1);
        assert_eq!(provider.warning_count(), 1);
    }

    #[test]
    fn test_provider_messages_filtered() {
        let config = CompileProviderConfig::new()
            .filter_severity(CompileSeverity::Warning);
        let mut provider = CompileProvider::with_config(config);
        provider.add_message(CompileMessage::info("info"));
        provider.add_message(CompileMessage::warning("warn"));
        provider.add_message(CompileMessage::error("err"));

        // Filtered: only warning and above
        let filtered = provider.messages();
        assert_eq!(filtered.len(), 2);
        // Unfiltered
        assert_eq!(provider.all_messages().len(), 3);
    }

    #[test]
    fn test_provider_clear_messages() {
        let mut provider = CompileProvider::new();
        provider.add_message(CompileMessage::error("err"));
        provider.select_message(Some(0));
        provider.clear_messages();
        assert_eq!(provider.message_count(), 0);
        assert_eq!(provider.selected_message_index(), None);
    }

    #[test]
    fn test_provider_select_message() {
        let mut provider = CompileProvider::new();
        provider.add_message(CompileMessage::error("err1"));
        provider.add_message(CompileMessage::warning("warn1"));

        provider.select_message(Some(0));
        assert_eq!(provider.selected_message_index(), Some(0));
        assert_eq!(provider.selected_message().unwrap().message, "err1");

        provider.select_message(Some(1));
        assert_eq!(provider.selected_message_index(), Some(1));
        assert_eq!(provider.selected_message().unwrap().message, "warn1");

        // Out of bounds -- should not change
        provider.select_message(Some(5));
        assert_eq!(provider.selected_message_index(), Some(1));

        // None -- deselect
        provider.select_message(None);
        assert_eq!(provider.selected_message_index(), None);
    }

    #[test]
    fn test_provider_select_next_previous() {
        let mut provider = CompileProvider::new();
        provider.add_message(CompileMessage::error("err1"));
        provider.add_message(CompileMessage::warning("warn1"));
        provider.add_message(CompileMessage::info("info1"));

        // Start from none
        let msg = provider.select_next_message();
        assert_eq!(msg.unwrap().message, "err1");

        let msg = provider.select_next_message();
        assert_eq!(msg.unwrap().message, "warn1");

        let msg = provider.select_next_message();
        assert_eq!(msg.unwrap().message, "info1");

        // Wraps around
        let msg = provider.select_next_message();
        assert_eq!(msg.unwrap().message, "err1");

        // Previous
        let msg = provider.select_previous_message();
        assert_eq!(msg.unwrap().message, "info1");
    }

    #[test]
    fn test_provider_select_next_previous_empty() {
        let mut provider = CompileProvider::new();
        assert!(provider.select_next_message().is_none());
        assert!(provider.select_previous_message().is_none());
    }

    #[test]
    fn test_provider_select_first_error() {
        let mut provider = CompileProvider::new();
        provider.add_message(CompileMessage::info("info"));
        provider.add_message(CompileMessage::warning("warn"));
        provider.add_message(CompileMessage::error("err1"));
        provider.add_message(CompileMessage::error("err2"));

        let msg = provider.select_first_error();
        assert_eq!(msg.unwrap().message, "err1");
        assert_eq!(provider.selected_message_index(), Some(2));
    }

    #[test]
    fn test_provider_select_first_error_none() {
        let mut provider = CompileProvider::new();
        provider.add_message(CompileMessage::info("info"));
        assert!(provider.select_first_error().is_none());
    }

    #[test]
    fn test_provider_select_next_error() {
        let mut provider = CompileProvider::new();
        provider.add_message(CompileMessage::error("err1"));
        provider.add_message(CompileMessage::warning("warn"));
        provider.add_message(CompileMessage::error("err2"));
        provider.add_message(CompileMessage::info("info"));

        provider.select_message(Some(0));
        let msg = provider.select_next_error();
        assert_eq!(msg.unwrap().message, "err2");

        // Wraps around
        let msg = provider.select_next_error();
        assert_eq!(msg.unwrap().message, "err1");
    }

    #[test]
    fn test_provider_resolve_source_path() {
        let mut provider = CompileProvider::new();
        provider.set_source_root("/project/src");
        provider.add_message(
            CompileMessage::error("err").with_location("main.rs", 10, None),
        );
        provider.select_message(Some(0));

        let path = provider.resolve_selected_source_path().unwrap();
        assert_eq!(path, PathBuf::from("/project/src/main.rs"));
    }

    #[test]
    fn test_provider_resolve_absolute_path() {
        let mut provider = CompileProvider::new();
        provider.set_source_root("/project/src");
        provider.add_message(
            CompileMessage::error("err").with_location("/absolute/path.rs", 5, None),
        );
        provider.select_message(Some(0));

        let path = provider.resolve_selected_source_path().unwrap();
        assert_eq!(path, PathBuf::from("/absolute/path.rs"));
    }

    #[test]
    fn test_provider_resolve_no_file() {
        let mut provider = CompileProvider::new();
        provider.add_message(CompileMessage::error("no location"));
        provider.select_message(Some(0));
        assert!(provider.resolve_selected_source_path().is_none());
    }

    #[test]
    fn test_provider_selected_source_location() {
        let mut provider = CompileProvider::new();
        provider.add_message(
            CompileMessage::error("err").with_location("main.rs", 42, Some(10)),
        );
        provider.select_message(Some(0));

        let (file, line, col) = provider.selected_source_location().unwrap();
        assert_eq!(file, PathBuf::from("main.rs"));
        assert_eq!(line, 42);
        assert_eq!(col, Some(10));
    }

    #[test]
    fn test_provider_summary_empty() {
        let provider = CompileProvider::new();
        assert_eq!(provider.summary(), "0 output lines, no messages");
    }

    #[test]
    fn test_provider_summary_with_messages() {
        let mut provider = CompileProvider::new();
        provider.append_output_line("line 1");
        provider.append_output_line("line 2");
        provider.add_message(CompileMessage::error("err"));
        provider.add_message(CompileMessage::warning("warn"));
        provider.add_message(CompileMessage::info("info"));

        let summary = provider.summary();
        assert!(summary.contains("2 output lines"));
        assert!(summary.contains("3"));
        assert!(summary.contains("1 error"));
        assert!(summary.contains("1 warning"));
    }

    #[test]
    fn test_provider_reset() {
        let mut provider = CompileProvider::new();
        provider.append_output_line("line");
        provider.add_message(CompileMessage::error("err"));
        provider.select_message(Some(0));
        provider.set_visible(true);

        provider.reset();
        assert_eq!(provider.output_line_count(), 0);
        assert_eq!(provider.message_count(), 0);
        assert_eq!(provider.selected_message_index(), None);
        // Visibility is not reset
        assert!(provider.is_visible());
    }

    #[test]
    fn test_provider_config_defaults() {
        let config = CompileProviderConfig::default();
        assert_eq!(config.max_output_lines, 10_000);
        assert_eq!(config.max_messages, 5_000);
        assert!(config.auto_scroll);
        assert!(!config.show_timestamps);
        assert!(config.min_severity.is_none());
        assert!(config.wrap_lines);
    }

    #[test]
    fn test_provider_trim_messages_preserves_selection() {
        let config = CompileProviderConfig {
            max_messages: 3,
            ..CompileProviderConfig::default()
        };
        let mut provider = CompileProvider::with_config(config);

        for i in 0..5 {
            provider.add_message(CompileMessage::error(format!("err{}", i)));
        }

        // Only last 3 messages kept: err2, err3, err4
        assert_eq!(provider.message_count(), 3);
        assert_eq!(provider.all_messages()[0].message, "err2");
    }
}
