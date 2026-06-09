//! Compile Plugin -- top-level plugin managing the compilation lifecycle.
//!
//! Ported from Ghidra's `CompilePlugin` Java class.
//!
//! The plugin is responsible for:
//! - Managing the lifecycle of the compile provider
//! - Dispatching build/clean/rebuild actions
//! - Tracking compilation state across program changes
//! - Parsing compiler output into structured messages
//!
//! # Architecture
//!
//! ```text
//! CompilePlugin
//!   ├── CompileProvider         (primary output provider)
//!   ├── current_config          (active compilation configuration)
//!   ├── compile_history         (history of past compilations)
//!   ├── compile_actions         (build, clean, rebuild, cancel)
//!   └── output_parser           (compiler output message parser)
//! ```

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use super::{
    CompileConfig, CompileMessage, CompileResult, CompileSeverity, CompileStatus,
};
use super::compile_provider::{CompileProvider, CompileProviderConfig};

// ============================================================================
// CompileAction -- actions dispatched by the plugin
// ============================================================================

/// Actions that the compile plugin supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompileAction {
    /// Start a new compilation.
    Build,
    /// Clean build artifacts.
    Clean,
    /// Clean and rebuild from scratch.
    Rebuild,
    /// Cancel the running compilation.
    Cancel,
    /// Open the compile settings dialog.
    Settings,
}

impl CompileAction {
    /// Human-readable label for this action.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Build => "Build",
            Self::Clean => "Clean",
            Self::Rebuild => "Rebuild",
            Self::Cancel => "Cancel Build",
            Self::Settings => "Compile Settings...",
        }
    }

    /// Description for this action.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Build => "Compile the current source files.",
            Self::Clean => "Remove all build artifacts.",
            Self::Rebuild => "Clean and recompile all source files.",
            Self::Cancel => "Cancel the currently running compilation.",
            Self::Settings => "Configure compilation options.",
        }
    }

    /// Whether this action is enabled given the current compile status.
    pub fn is_enabled_for(&self, status: CompileStatus) -> bool {
        match self {
            Self::Build | Self::Rebuild => {
                status == CompileStatus::Idle
                    || status == CompileStatus::Success
                    || status == CompileStatus::Failed
                    || status == CompileStatus::Cancelled
            }
            Self::Clean => status != CompileStatus::Building,
            Self::Cancel => status == CompileStatus::Building,
            Self::Settings => status != CompileStatus::Building,
        }
    }
}

// ============================================================================
// CompilePluginEvent -- events emitted by the plugin
// ============================================================================

/// Events emitted by the compile plugin.
#[derive(Debug, Clone)]
pub enum CompilePluginEvent {
    /// A compilation has started.
    BuildStarted {
        /// The configuration used for the build.
        config: CompileConfig,
    },
    /// Progress update during compilation.
    BuildProgress {
        /// Progress message (e.g., "Compiling file.rs...").
        message: String,
        /// Percentage complete (0-100), if known.
        percent: Option<u8>,
    },
    /// A compilation has finished.
    BuildFinished {
        /// The result of the compilation.
        result: CompileResult,
    },
    /// Build artifacts were cleaned.
    CleanCompleted,
    /// A message was emitted by the compiler.
    MessageEmitted {
        /// The compile message.
        message: CompileMessage,
    },
}

// ============================================================================
// CompilePlugin -- the main plugin struct
// ============================================================================

/// The compile plugin managing compilation lifecycle and provider.
///
/// Ported from Ghidra's `CompilePlugin`.
#[derive(Debug)]
pub struct CompilePlugin {
    /// The primary compile provider.
    provider: CompileProvider,
    /// Current active configuration.
    current_config: CompileConfig,
    /// History of past compilation results.
    compile_history: VecDeque<CompileResult>,
    /// Maximum history entries to keep.
    max_history: usize,
    /// Current compilation status.
    status: CompileStatus,
    /// Pending events to be consumed by the tool.
    pending_events: Vec<CompilePluginEvent>,
    /// Whether the plugin has been disposed.
    disposed: bool,
}

impl CompilePlugin {
    /// Create a new compile plugin with the default configuration.
    pub fn new() -> Self {
        Self {
            provider: CompileProvider::new(),
            current_config: CompileConfig::default(),
            compile_history: VecDeque::new(),
            max_history: 50,
            status: CompileStatus::Idle,
            pending_events: Vec::new(),
            disposed: false,
        }
    }

    /// Create a new compile plugin with a specific configuration.
    pub fn with_config(config: CompileConfig) -> Self {
        Self {
            provider: CompileProvider::new(),
            current_config: config,
            compile_history: VecDeque::new(),
            max_history: 50,
            status: CompileStatus::Idle,
            pending_events: Vec::new(),
            disposed: false,
        }
    }

    // -----------------------------------------------------------------------
    // Provider access
    // -----------------------------------------------------------------------

    /// Get a reference to the compile provider.
    pub fn provider(&self) -> &CompileProvider {
        &self.provider
    }

    /// Get a mutable reference to the compile provider.
    pub fn provider_mut(&mut self) -> &mut CompileProvider {
        &mut self.provider
    }

    // -----------------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------------

    /// Get the current compile configuration.
    pub fn config(&self) -> &CompileConfig {
        &self.current_config
    }

    /// Set the compile configuration.
    pub fn set_config(&mut self, config: CompileConfig) {
        self.current_config = config;
    }

    /// Set the maximum number of history entries.
    pub fn set_max_history(&mut self, max: usize) {
        self.max_history = max;
        self.trim_history();
    }

    // -----------------------------------------------------------------------
    // Status
    // -----------------------------------------------------------------------

    /// Get the current compilation status.
    pub fn status(&self) -> CompileStatus {
        self.status
    }

    /// Returns `true` if a compilation is currently in progress.
    pub fn is_building(&self) -> bool {
        self.status == CompileStatus::Building
    }

    /// Returns `true` if the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    // -----------------------------------------------------------------------
    // Actions
    // -----------------------------------------------------------------------

    /// Execute a compile action.
    ///
    /// Returns `true` if the action was dispatched, `false` if it was
    /// rejected (e.g., build while already building).
    pub fn execute_action(&mut self, action: CompileAction) -> bool {
        if !action.is_enabled_for(self.status) {
            return false;
        }

        match action {
            CompileAction::Build => self.start_build(),
            CompileAction::Clean => self.clean(),
            CompileAction::Rebuild => {
                self.clean();
                self.start_build();
            }
            CompileAction::Cancel => self.cancel_build(),
            CompileAction::Settings => {
                // Settings dialog would be opened here in a GUI context.
                // For now, this is a no-op in the headless implementation.
            }
        }
        true
    }

    /// Get all available actions and their enabled state.
    pub fn available_actions(&self) -> Vec<(CompileAction, bool)> {
        vec![
            CompileAction::Build,
            CompileAction::Clean,
            CompileAction::Rebuild,
            CompileAction::Cancel,
            CompileAction::Settings,
        ]
        .into_iter()
        .map(|a| (a, a.is_enabled_for(self.status)))
        .collect()
    }

    // -----------------------------------------------------------------------
    // Build lifecycle
    // -----------------------------------------------------------------------

    /// Start a new compilation with the current configuration.
    fn start_build(&mut self) {
        self.status = CompileStatus::Building;
        self.provider.clear_output();
        self.provider.append_output_line("Build started...");
        self.pending_events.push(CompilePluginEvent::BuildStarted {
            config: self.current_config.clone(),
        });
    }

    /// Process a line of compiler output.
    ///
    /// This should be called as output arrives from the compiler process.
    pub fn process_output_line(&mut self, line: &str) {
        self.provider.append_output_line(line);

        if let Some(msg) = Self::parse_output_line(line) {
            self.provider.add_message(msg.clone());
            self.pending_events
                .push(CompilePluginEvent::MessageEmitted { message: msg });
        }
    }

    /// Report a build progress update.
    pub fn report_progress(&mut self, message: impl Into<String>, percent: Option<u8>) {
        let msg = message.into();
        self.provider.append_output_line(&msg);
        self.pending_events.push(CompilePluginEvent::BuildProgress {
            message: msg,
            percent,
        });
    }

    /// Finish the current compilation with the given result.
    pub fn finish_build(&mut self, result: CompileResult) {
        self.status = result.status;

        // Copy messages to the provider
        for msg in &result.messages {
            self.provider.add_message(msg.clone());
        }

        // Copy output
        if !result.stdout.is_empty() {
            self.provider.append_output_line(&result.stdout);
        }
        if !result.stderr.is_empty() {
            self.provider.append_output_line(&result.stderr);
        }

        self.provider.append_output_line(&result.summary());

        // Add to history
        self.compile_history.push_front(result.clone());
        self.trim_history();

        self.pending_events
            .push(CompilePluginEvent::BuildFinished { result });
    }

    /// Cancel the current build.
    fn cancel_build(&mut self) {
        self.status = CompileStatus::Cancelled;
        self.provider.append_output_line("Build cancelled by user.");
    }

    /// Clean build artifacts.
    fn clean(&mut self) {
        self.provider.clear_output();
        self.provider.append_output_line("Cleaning build artifacts...");
        self.pending_events
            .push(CompilePluginEvent::CleanCompleted);
    }

    // -----------------------------------------------------------------------
    // History
    // -----------------------------------------------------------------------

    /// Get the compilation history (most recent first).
    pub fn history(&self) -> &VecDeque<CompileResult> {
        &self.compile_history
    }

    /// Get the most recent compilation result, if any.
    pub fn last_result(&self) -> Option<&CompileResult> {
        self.compile_history.front()
    }

    /// Clear the compilation history.
    pub fn clear_history(&mut self) {
        self.compile_history.clear();
    }

    fn trim_history(&mut self) {
        while self.compile_history.len() > self.max_history {
            self.compile_history.pop_back();
        }
    }

    // -----------------------------------------------------------------------
    // Event consumption
    // -----------------------------------------------------------------------

    /// Drain and return all pending plugin events.
    pub fn drain_events(&mut self) -> Vec<CompilePluginEvent> {
        std::mem::take(&mut self.pending_events)
    }

    /// Check if there are pending events.
    pub fn has_pending_events(&self) -> bool {
        !self.pending_events.is_empty()
    }

    // -----------------------------------------------------------------------
    // Output parsing
    // -----------------------------------------------------------------------

    /// Parse a single line of compiler output into a `CompileMessage`, if it
    /// matches a recognized diagnostic pattern.
    ///
    /// Supports common formats:
    /// - GCC/Clang: `file.rs:10:5: error: message`
    /// - Rust: `error[E0308]: message`
    /// - Simple: `error: message`, `warning: message`
    pub fn parse_output_line(line: &str) -> Option<CompileMessage> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return None;
        }

        // Try GCC/Clang format: file:line:col: severity: message
        if let Some(msg) = Self::parse_gcc_format(trimmed) {
            return Some(msg);
        }

        // Try Rust format: error[Exxxx]: message
        if let Some(msg) = Self::parse_rust_error_code(trimmed) {
            return Some(msg);
        }

        // Try simple format: severity: message
        if let Some(msg) = Self::parse_simple_format(trimmed) {
            return Some(msg);
        }

        None
    }

    fn parse_gcc_format(line: &str) -> Option<CompileMessage> {
        // Pattern: file:line:col: severity: message
        let parts: Vec<&str> = line.splitn(4, ": ").collect();
        if parts.len() < 3 {
            return None;
        }

        // First part should be file:line[:col]
        let loc_parts: Vec<&str> = parts[0].split(':').collect();
        if loc_parts.len() < 2 {
            return None;
        }

        let file = loc_parts[0];
        let line_num: u32 = loc_parts[1].parse().ok()?;
        let col_num: Option<u32> = loc_parts.get(2).and_then(|c| c.parse().ok());

        let severity_str = if parts.len() >= 4 { parts[1] } else { parts.get(1)? };
        let message_idx = if parts.len() >= 4 { 3 } else { 2 };
        let message = parts.get(message_idx)?;

        let severity = match severity_str {
            "error" | "fatal error" => CompileSeverity::Error,
            "warning" => CompileSeverity::Warning,
            "note" | "info" => CompileSeverity::Info,
            _ => return None,
        };

        Some(
            CompileMessage {
                severity,
                file: Some(PathBuf::from(file)),
                line: Some(line_num),
                column: col_num,
                message: message.to_string(),
                error_code: None,
            },
        )
    }

    fn parse_rust_error_code(line: &str) -> Option<CompileMessage> {
        // Pattern: error[Exxxx]: message
        if let Some(rest) = line.strip_prefix("error[") {
            if let Some(bracket_end) = rest.find(']') {
                let code = &rest[..bracket_end];
                // Skip "]: " (bracket + colon + space = 3 chars)
                let message = rest.get(bracket_end + 1..)?.strip_prefix(": ")?;
                return Some(
                    CompileMessage::error(message).with_error_code(code),
                );
            }
        }
        if let Some(rest) = line.strip_prefix("warning[") {
            if let Some(bracket_end) = rest.find(']') {
                let code = &rest[..bracket_end];
                let message = rest.get(bracket_end + 1..)?.strip_prefix(": ")?;
                return Some(
                    CompileMessage::warning(message).with_error_code(code),
                );
            }
        }
        None
    }

    fn parse_simple_format(line: &str) -> Option<CompileMessage> {
        if let Some(rest) = line.strip_prefix("error: ") {
            return Some(CompileMessage::error(rest));
        }
        if let Some(rest) = line.strip_prefix("warning: ") {
            return Some(CompileMessage::warning(rest));
        }
        if let Some(rest) = line.strip_prefix("fatal error: ") {
            return Some(CompileMessage::fatal(rest));
        }
        None
    }

    // -----------------------------------------------------------------------
    // Disposal
    // -----------------------------------------------------------------------

    /// Dispose the plugin, releasing resources.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        self.provider.clear_output();
        self.compile_history.clear();
        self.pending_events.clear();
        self.status = CompileStatus::Idle;
    }
}

impl Default for CompilePlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for CompilePlugin {
    fn drop(&mut self) {
        self.dispose();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_new() {
        let plugin = CompilePlugin::new();
        assert_eq!(plugin.status(), CompileStatus::Idle);
        assert!(!plugin.is_building());
        assert!(!plugin.is_disposed());
        assert!(plugin.history().is_empty());
        assert!(plugin.last_result().is_none());
    }

    #[test]
    fn test_plugin_with_config() {
        let config = CompileConfig::new("rustc").flag("--release");
        let plugin = CompilePlugin::with_config(config);
        assert_eq!(plugin.config().compiler, "rustc");
        assert!(plugin.config().flags.contains(&"--release".to_string()));
    }

    #[test]
    fn test_plugin_build_lifecycle() {
        let mut plugin = CompilePlugin::new();
        assert_eq!(plugin.status(), CompileStatus::Idle);

        // Start build
        plugin.start_build();
        assert_eq!(plugin.status(), CompileStatus::Building);
        assert!(plugin.is_building());

        // Process output
        plugin.process_output_line("Compiling main.rs");

        // Finish with success
        let mut result = CompileResult::new(plugin.config().clone());
        result.status = CompileStatus::Success;
        result.elapsed_ms = 1500;
        plugin.finish_build(result);

        assert_eq!(plugin.status(), CompileStatus::Success);
        assert!(!plugin.is_building());
        assert_eq!(plugin.history().len(), 1);
    }

    #[test]
    fn test_plugin_cancel_build() {
        let mut plugin = CompilePlugin::new();
        plugin.start_build();
        assert!(plugin.is_building());

        plugin.cancel_build();
        assert_eq!(plugin.status(), CompileStatus::Cancelled);
    }

    #[test]
    fn test_plugin_execute_action() {
        let mut plugin = CompilePlugin::new();

        // Build should succeed when idle
        assert!(plugin.execute_action(CompileAction::Build));
        assert_eq!(plugin.status(), CompileStatus::Building);

        // Build should fail when already building
        assert!(!plugin.execute_action(CompileAction::Build));

        // Cancel should succeed when building
        assert!(plugin.execute_action(CompileAction::Cancel));
        assert_eq!(plugin.status(), CompileStatus::Cancelled);

        // Clean should succeed when not building
        assert!(plugin.execute_action(CompileAction::Clean));
    }

    #[test]
    fn test_plugin_available_actions() {
        let plugin = CompilePlugin::new();
        let actions = plugin.available_actions();
        assert_eq!(actions.len(), 5);

        // Build should be enabled when idle
        let build = actions.iter().find(|(a, _)| *a == CompileAction::Build).unwrap();
        assert!(build.1);

        // Cancel should be disabled when idle
        let cancel = actions.iter().find(|(a, _)| *a == CompileAction::Cancel).unwrap();
        assert!(!cancel.1);
    }

    #[test]
    fn test_plugin_action_labels() {
        assert_eq!(CompileAction::Build.label(), "Build");
        assert_eq!(CompileAction::Clean.label(), "Clean");
        assert_eq!(CompileAction::Rebuild.label(), "Rebuild");
        assert_eq!(CompileAction::Cancel.label(), "Cancel Build");
        assert_eq!(CompileAction::Settings.label(), "Compile Settings...");
    }

    #[test]
    fn test_plugin_events() {
        let mut plugin = CompilePlugin::new();
        assert!(!plugin.has_pending_events());

        plugin.start_build();
        assert!(plugin.has_pending_events());

        let events = plugin.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], CompilePluginEvent::BuildStarted { .. }));
        assert!(!plugin.has_pending_events());
    }

    #[test]
    fn test_plugin_history() {
        let mut plugin = CompilePlugin::new();
        plugin.set_max_history(3);

        for i in 0..5 {
            plugin.start_build();
            let mut result = CompileResult::new(plugin.config().clone());
            result.status = CompileStatus::Success;
            result.elapsed_ms = i * 1000;
            plugin.finish_build(result);
        }

        // Only last 3 should be kept
        assert_eq!(plugin.history().len(), 3);
        assert_eq!(plugin.last_result().unwrap().elapsed_ms, 4000);
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = CompilePlugin::new();
        plugin.start_build();
        plugin.dispose();

        assert!(plugin.is_disposed());
        assert_eq!(plugin.status(), CompileStatus::Idle);
        assert!(plugin.history().is_empty());
    }

    #[test]
    fn test_plugin_drop() {
        let mut plugin = CompilePlugin::new();
        plugin.start_build();
        drop(plugin);
        // Should not panic
    }

    // -----------------------------------------------------------------------
    // Output parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_gcc_format() {
        let msg = CompilePlugin::parse_output_line("main.rs:10:5: error: undefined variable `x`");
        let msg = msg.unwrap();
        assert_eq!(msg.severity, CompileSeverity::Error);
        assert_eq!(msg.line, Some(10));
        assert_eq!(msg.column, Some(5));
        assert!(msg.message.contains("undefined variable"));
    }

    #[test]
    fn test_parse_gcc_format_no_column() {
        let msg = CompilePlugin::parse_output_line("lib.rs:42: warning: unused import");
        let msg = msg.unwrap();
        assert_eq!(msg.severity, CompileSeverity::Warning);
        assert_eq!(msg.line, Some(42));
        assert_eq!(msg.column, None);
    }

    #[test]
    fn test_parse_rust_error_code() {
        let msg = CompilePlugin::parse_output_line("error[E0308]: mismatched types");
        let msg = msg.unwrap();
        assert_eq!(msg.severity, CompileSeverity::Error);
        assert_eq!(msg.error_code.as_deref(), Some("E0308"));
        assert_eq!(msg.message, "mismatched types");
    }

    #[test]
    fn test_parse_rust_warning_code() {
        let msg = CompilePlugin::parse_output_line("warning[W0001]: some warning");
        let msg = msg.unwrap();
        assert_eq!(msg.severity, CompileSeverity::Warning);
        assert_eq!(msg.error_code.as_deref(), Some("W0001"));
    }

    #[test]
    fn test_parse_simple_error() {
        let msg = CompilePlugin::parse_output_line("error: linker failed");
        let msg = msg.unwrap();
        assert_eq!(msg.severity, CompileSeverity::Error);
        assert_eq!(msg.message, "linker failed");
    }

    #[test]
    fn test_parse_simple_warning() {
        let msg = CompilePlugin::parse_output_line("warning: deprecated function");
        let msg = msg.unwrap();
        assert_eq!(msg.severity, CompileSeverity::Warning);
    }

    #[test]
    fn test_parse_fatal_error() {
        let msg = CompilePlugin::parse_output_line("fatal error: stdio.h: No such file or directory");
        let msg = msg.unwrap();
        assert_eq!(msg.severity, CompileSeverity::Fatal);
        assert!(msg.message.contains("No such file"));
    }

    #[test]
    fn test_parse_empty_line() {
        assert!(CompilePlugin::parse_output_line("").is_none());
        assert!(CompilePlugin::parse_output_line("   ").is_none());
    }

    #[test]
    fn test_parse_unrecognized_line() {
        assert!(CompilePlugin::parse_output_line("Compiling foo v0.1.0").is_none());
    }

    #[test]
    fn test_process_output_line_adds_to_provider() {
        let mut plugin = CompilePlugin::new();
        plugin.start_build();
        plugin.process_output_line("error: something broke");
        // The provider should have the raw line and the parsed message
        let msgs = plugin.provider().messages();
        assert!(!msgs.is_empty());
    }
}
