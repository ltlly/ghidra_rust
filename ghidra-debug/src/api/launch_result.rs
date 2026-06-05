//! Launch result and configurator types for TraceRmi.
//!
//! Ported from Ghidra's `TraceRmiLaunchOffer.LaunchResult`,
//! `LaunchConfigurator`, `PromptMode`, and `RelPrompt` types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::tracermi::{TerminalSession, TraceRmiAcceptor};

/// When programmatically customizing launch configuration, describes
/// callback timing relative to prompting the user.
///
/// Ported from Ghidra's `TraceRmiLaunchOffer.RelPrompt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelPrompt {
    /// The user is not prompted for parameters. This will be the only callback.
    None,
    /// The user will be prompted. This callback can pre-populate suggested
    /// parameters. Another callback will be issued if the user does not cancel.
    Before,
    /// The user has confirmed the parameters. This callback can validate or
    /// override the user's parameters. This is the final callback.
    After,
}

/// Whether and when the user is prompted for launch parameters.
///
/// Ported from Ghidra's `TraceRmiLaunchOffer.PromptMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PromptMode {
    /// The user is always prompted for parameters.
    Always,
    /// The user is never prompted for parameters.
    Never,
    /// The user is prompted after an error.
    OnError,
}

impl Default for PromptMode {
    fn default() -> Self {
        PromptMode::Never
    }
}

/// A value with a string representation.
///
/// Ported from Ghidra's `ValStr<T>`. This pairs an optional typed value
/// with its string form, allowing both human-readable and typed access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValStr<T: Clone> {
    /// The typed value, if available.
    pub val: Option<T>,
    /// The string representation.
    pub str_val: String,
}

impl<T: Clone + std::fmt::Display> ValStr<T> {
    /// Create a new ValStr from a typed value.
    pub fn new(val: T) -> Self {
        Self {
            str_val: val.to_string(),
            val: Some(val),
        }
    }

    /// Create a ValStr with only a string value.
    pub fn from_string(str_val: impl Into<String>) -> Self {
        Self {
            val: None,
            str_val: str_val.into(),
        }
    }
}

impl<T: Clone> ValStr<T> {
    /// Get the value, falling back to None.
    pub fn value(&self) -> Option<&T> {
        self.val.as_ref()
    }

    /// Get the string representation.
    pub fn str_value(&self) -> &str {
        &self.str_val
    }
}

/// The result of launching a program with a TraceRmi connection.
///
/// Ported from Ghidra's `TraceRmiLaunchOffer.LaunchResult`. The launch may
/// not always be completely successful. Instead of tearing things down,
/// partial launches are left in place, in case the user wishes to repair
/// or complete the steps manually.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchResult {
    /// Any terminal sessions created during the launch.
    /// If empty, there was likely a catastrophic error.
    pub sessions: BTreeMap<String, TerminalSession>,
    /// The acceptor, if waiting for a connection.
    pub acceptor: Option<TraceRmiAcceptor>,
    /// The connection ID, if the target connected back.
    pub connection_id: Option<u64>,
    /// The trace key, if the connection started a trace.
    pub trace_key: Option<String>,
    /// Optional error, if the launch failed.
    pub error: Option<String>,
    /// Whether this result represents a successful launch.
    pub success: bool,
}

impl LaunchResult {
    /// Create a successful launch result.
    pub fn success(
        connection_id: u64,
        trace_key: impl Into<String>,
    ) -> Self {
        Self {
            sessions: BTreeMap::new(),
            acceptor: None,
            connection_id: Some(connection_id),
            trace_key: Some(trace_key.into()),
            error: None,
            success: true,
        }
    }

    /// Create a failed launch result.
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            sessions: BTreeMap::new(),
            acceptor: None,
            connection_id: None,
            trace_key: None,
            error: Some(error.into()),
            success: false,
        }
    }

    /// Create a partial launch result (connection established but trace failed).
    pub fn partial(connection_id: u64, error: impl Into<String>) -> Self {
        Self {
            sessions: BTreeMap::new(),
            acceptor: None,
            connection_id: Some(connection_id),
            trace_key: None,
            error: Some(error.into()),
            success: false,
        }
    }

    /// Add a terminal session.
    pub fn with_session(mut self, name: impl Into<String>, session: TerminalSession) -> Self {
        self.sessions.insert(name.into(), session);
        self
    }

    /// Set the acceptor.
    pub fn with_acceptor(mut self, acceptor: TraceRmiAcceptor) -> Self {
        self.acceptor = Some(acceptor);
        self
    }

    /// Whether the launch has an active connection.
    pub fn has_connection(&self) -> bool {
        self.connection_id.is_some()
    }

    /// Whether the launch produced a trace.
    pub fn has_trace(&self) -> bool {
        self.trace_key.is_some()
    }

    /// Whether the launch failed.
    pub fn is_failure(&self) -> bool {
        !self.success
    }

    /// Close the result, cleaning up resources.
    pub fn close(&mut self) {
        for session in self.sessions.values_mut() {
            session.close();
        }
        self.acceptor = None;
    }
}

/// Callback interface for customizing launch configuration.
///
/// Ported from Ghidra's `TraceRmiLaunchOffer.LaunchConfigurator`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LaunchConfigurator {
    /// The prompt mode.
    pub prompt_mode: PromptMode,
    /// Custom launcher arguments.
    pub launcher_args: BTreeMap<String, String>,
    /// Custom environment overrides.
    pub env_overrides: BTreeMap<String, String>,
}

impl LaunchConfigurator {
    /// Create a configurator that never prompts.
    pub fn nop() -> Self {
        Self {
            prompt_mode: PromptMode::Never,
            launcher_args: BTreeMap::new(),
            env_overrides: BTreeMap::new(),
        }
    }

    /// Create a configurator that always prompts.
    pub fn always_prompt() -> Self {
        Self {
            prompt_mode: PromptMode::Always,
            launcher_args: BTreeMap::new(),
            env_overrides: BTreeMap::new(),
        }
    }

    /// Create a configurator that prompts on error.
    pub fn on_error() -> Self {
        Self {
            prompt_mode: PromptMode::OnError,
            launcher_args: BTreeMap::new(),
            env_overrides: BTreeMap::new(),
        }
    }

    /// Set a launcher argument override.
    pub fn with_arg(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.launcher_args.insert(key.into(), value.into());
        self
    }

    /// Set an environment variable override.
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_overrides.insert(key.into(), value.into());
        self
    }

    /// Configure launcher arguments based on timing relative to user prompt.
    ///
    /// Returns the adjusted arguments.
    pub fn configure_launcher(
        &self,
        arguments: &BTreeMap<String, String>,
        _rel_prompt: RelPrompt,
    ) -> BTreeMap<String, String> {
        let mut result = arguments.clone();
        for (k, v) in &self.launcher_args {
            result.insert(k.clone(), v.clone());
        }
        result
    }
}

/// A complete launch offer description.
///
/// Ported from Ghidra's `TraceRmiLaunchOffer`. Each offer is configured
/// with the program it will launch and knows how to work with a specific
/// connector and platform to obtain a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRmiLaunchOffer {
    /// The configuration name (saved to config files for preferences).
    pub config_name: String,
    /// Display title for the quick-launch menu.
    pub title: String,
    /// HTML description of the connector.
    pub description: String,
    /// Menu path (subordinate to "Debugger.Debug [imagePath]").
    pub menu_path: Vec<String>,
    /// Menu group for ordering.
    pub menu_group: String,
    /// Menu order within the group.
    pub menu_order: String,
    /// Launch parameters.
    pub parameters: BTreeMap<String, String>,
    /// Whether this offer requires an open program.
    pub requires_image: bool,
    /// Whether this offer supports an image parameter.
    pub supports_image: bool,
}

impl TraceRmiLaunchOffer {
    /// Create a new launch offer.
    pub fn new(
        config_name: impl Into<String>,
        title: impl Into<String>,
    ) -> Self {
        let title_str: String = title.into();
        Self {
            config_name: config_name.into(),
            title: title_str.clone(),
            description: String::new(),
            menu_path: vec![title_str],
            menu_group: String::new(),
            menu_order: String::new(),
            parameters: BTreeMap::new(),
            requires_image: false,
            supports_image: false,
        }
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Set the menu path.
    pub fn with_menu_path(mut self, path: Vec<String>) -> Self {
        self.menu_path = path;
        self
    }

    /// Set the menu group.
    pub fn with_menu_group(mut self, group: impl Into<String>) -> Self {
        self.menu_group = group.into();
        self
    }

    /// Set whether an image is required.
    pub fn with_requires_image(mut self, requires: bool) -> Self {
        self.requires_image = requires;
        self.supports_image = true;
        self
    }

    /// Add a parameter.
    pub fn with_parameter(mut self, name: impl Into<String>, default: impl Into<String>) -> Self {
        self.parameters.insert(name.into(), default.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_val_str() {
        let vs = ValStr::new(42i32);
        assert_eq!(vs.value(), Some(&42));
        assert_eq!(vs.str_value(), "42");

        let vs = ValStr::<i32>::from_string("hello");
        assert!(vs.value().is_none());
        assert_eq!(vs.str_value(), "hello");
    }

    #[test]
    fn test_launch_result_success() {
        let result = LaunchResult::success(1, "trace-0");
        assert!(result.success);
        assert!(result.has_connection());
        assert!(result.has_trace());
        assert!(!result.is_failure());
        assert!(result.error.is_none());
    }

    #[test]
    fn test_launch_result_failure() {
        let result = LaunchResult::failure("binary not found");
        assert!(!result.success);
        assert!(!result.has_connection());
        assert!(!result.has_trace());
        assert!(result.is_failure());
        assert_eq!(result.error.as_deref(), Some("binary not found"));
    }

    #[test]
    fn test_launch_result_partial() {
        let result = LaunchResult::partial(42, "module mapping failed");
        assert!(!result.success);
        assert!(result.has_connection());
        assert!(!result.has_trace());
    }

    #[test]
    fn test_launch_result_with_session() {
        let session = TerminalSession::new("term-1");
        let mut result = LaunchResult::success(1, "t").with_session("main", session);
        assert_eq!(result.sessions.len(), 1);
        result.close();
        assert!(result.sessions["main"].active == false);
    }

    #[test]
    fn test_launch_configurator_nop() {
        let cfg = LaunchConfigurator::nop();
        assert_eq!(cfg.prompt_mode, PromptMode::Never);
    }

    #[test]
    fn test_launch_configurator_with_arg() {
        let cfg = LaunchConfigurator::nop()
            .with_arg("cmd", "gdb")
            .with_env("PATH", "/usr/bin");
        assert_eq!(cfg.launcher_args["cmd"], "gdb");
        assert_eq!(cfg.env_overrides["PATH"], "/usr/bin");
    }

    #[test]
    fn test_launch_configurator_configure() {
        let cfg = LaunchConfigurator::nop().with_arg("timeout", "30");
        let mut args = BTreeMap::new();
        args.insert("cmd".into(), "gdb".into());
        let result = cfg.configure_launcher(&args, RelPrompt::None);
        assert_eq!(result["cmd"], "gdb");
        assert_eq!(result["timeout"], "30");
    }

    #[test]
    fn test_prompt_mode() {
        assert_ne!(PromptMode::Always, PromptMode::Never);
        assert_ne!(PromptMode::OnError, PromptMode::Always);
    }

    #[test]
    fn test_rel_prompt() {
        assert_ne!(RelPrompt::None, RelPrompt::After);
        assert_ne!(RelPrompt::Before, RelPrompt::After);
    }

    #[test]
    fn test_trace_rmi_launch_offer() {
        let offer = TraceRmiLaunchOffer::new("gdb", "Debug with GDB")
            .with_description("GNU Debugger")
            .with_menu_group("gdb")
            .with_requires_image(true)
            .with_parameter("cmd", "gdb");

        assert_eq!(offer.config_name, "gdb");
        assert_eq!(offer.title, "Debug with GDB");
        assert!(offer.requires_image);
        assert!(offer.supports_image);
        assert_eq!(offer.parameters["cmd"], "gdb");
    }

    #[test]
    fn test_launch_offer_menu_path_default() {
        let offer = TraceRmiLaunchOffer::new("test", "My Title");
        assert_eq!(offer.menu_path, vec!["My Title".to_string()]);
    }

    #[test]
    fn test_launch_result_serde() {
        let result = LaunchResult::success(1, "trace-0");
        let json = serde_json::to_string(&result).unwrap();
        let back: LaunchResult = serde_json::from_str(&json).unwrap();
        assert!(back.success);
        assert_eq!(back.trace_key, Some("trace-0".into()));
    }

    #[test]
    fn test_launch_configurator_serde() {
        let cfg = LaunchConfigurator::always_prompt();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: LaunchConfigurator = serde_json::from_str(&json).unwrap();
        assert_eq!(back.prompt_mode, PromptMode::Always);
    }
}
