//! Tool state factory for creating GhidraToolState instances.
//!
//! Ported from `ghidra.app.factory.GhidraToolStateFactory` and
//! `ghidra.framework.data.ToolStateFactory`.
//!
//! The factory pattern decouples tool state creation from the plugin
//! framework.  A [`ToolStateFactory`] knows how to produce a
//! [`ToolState`] for a given tool + domain-object pair, while the
//! concrete [`GhidraToolStateFactory`] creates [`GhidraToolState`]
//! instances specific to the Ghidra application.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// DomainObject -- minimal trait for a program / domain file
// ---------------------------------------------------------------------------

/// A domain object (program, function manager, etc.) that a tool operates on.
///
/// This is a simplified port of `ghidra.framework.model.DomainObject`.
pub trait DomainObject: Send + Sync + fmt::Debug {
    /// The unique domain-object ID (e.g. program URL or UUID).
    fn domain_id(&self) -> &str;

    /// Human-readable name.
    fn name(&self) -> &str;

    /// Whether the object has unsaved changes.
    fn is_changed(&self) -> bool;
}

// ---------------------------------------------------------------------------
// PluginTool -- minimal trait for the hosting tool
// ---------------------------------------------------------------------------

/// A plugin tool that owns component providers and manages state.
///
/// Simplified port of `ghidra.framework.plugintool.PluginTool`.
pub trait PluginTool: Send + Sync + fmt::Debug {
    /// The tool instance name.
    fn tool_name(&self) -> &str;

    /// The tool's unique ID.
    fn tool_id(&self) -> &str;

    /// Whether the tool is active (has focus or is running).
    fn is_active(&self) -> bool;
}

// ---------------------------------------------------------------------------
// ToolState
// ---------------------------------------------------------------------------

/// Serializable snapshot of a tool's configuration with respect to a
/// specific domain object.
///
/// Ported from `ghidra.framework.data.ToolState`.
#[derive(Debug, Clone)]
pub struct ToolState {
    /// Name of the tool that produced this state.
    pub tool_name: String,
    /// ID of the tool.
    pub tool_id: String,
    /// Domain-object ID this state is associated with.
    pub domain_id: String,
    /// Domain-object name (for display).
    pub domain_name: String,
    /// Key-value pairs of tool-specific configuration data.
    pub config: HashMap<String, String>,
    /// Whether the tool was active when the state was captured.
    pub was_active: bool,
}

impl ToolState {
    /// Creates a new tool state snapshot.
    pub fn new(
        tool_name: impl Into<String>,
        tool_id: impl Into<String>,
        domain_id: impl Into<String>,
        domain_name: impl Into<String>,
    ) -> Self {
        Self {
            tool_name: tool_name.into(),
            tool_id: tool_id.into(),
            domain_id: domain_id.into(),
            domain_name: domain_name.into(),
            config: HashMap::new(),
            was_active: false,
        }
    }

    /// Adds a configuration entry.
    pub fn with_config(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.config.insert(key.into(), value.into());
        self
    }

    /// Marks the tool as active at capture time.
    pub fn with_active(mut self, active: bool) -> Self {
        self.was_active = active;
        self
    }

    /// Returns the number of configuration entries.
    pub fn config_len(&self) -> usize {
        self.config.len()
    }

    /// Returns whether configuration is empty.
    pub fn config_is_empty(&self) -> bool {
        self.config.is_empty()
    }

    /// Retrieves a configuration value by key.
    pub fn get_config(&self, key: &str) -> Option<&str> {
        self.config.get(key).map(|s| s.as_str())
    }
}

impl fmt::Display for ToolState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ToolState({}, tool={}, domain={})",
            self.tool_name, self.tool_id, self.domain_id
        )
    }
}

// ---------------------------------------------------------------------------
// ToolStateFactory trait
// ---------------------------------------------------------------------------

/// Factory for creating [`ToolState`] instances.
///
/// Subclasses (e.g. [`GhidraToolStateFactory`]) override
/// [`do_create_tool_state`] to produce the appropriate concrete type.
///
/// Ported from `ghidra.framework.data.ToolStateFactory`.
pub trait ToolStateFactory: Send + Sync + fmt::Debug {
    /// Creates a new tool state for the given tool and domain object.
    fn create_tool_state(
        &self,
        tool: &dyn PluginTool,
        domain_object: &dyn DomainObject,
    ) -> ToolState;

    /// Creates a "default" (empty) tool state for a tool, with no
    /// associated domain object.
    fn create_default_state(&self, tool: &dyn PluginTool) -> ToolState {
        ToolState::new(
            tool.tool_name(),
            tool.tool_id(),
            "",
            "",
        )
        .with_active(tool.is_active())
    }
}

// ---------------------------------------------------------------------------
// GhidraToolStateFactory
// ---------------------------------------------------------------------------

/// Concrete factory that produces [`GhidraToolState`] instances.
///
/// This is the Ghidra application's default factory, registered with
/// the framework so that tool state management uses Ghidra-specific
/// semantics (e.g. persisting program-specific analysis flags).
///
/// Ported from `ghidra.app.factory.GhidraToolStateFactory`.
#[derive(Debug, Default)]
pub struct GhidraToolStateFactory;

impl GhidraToolStateFactory {
    /// Creates a new Ghidra tool state factory.
    pub fn new() -> Self {
        Self
    }
}

impl ToolStateFactory for GhidraToolStateFactory {
    fn create_tool_state(
        &self,
        tool: &dyn PluginTool,
        domain_object: &dyn DomainObject,
    ) -> ToolState {
        ToolState::new(
            tool.tool_name(),
            tool.tool_id(),
            domain_object.domain_id(),
            domain_object.name(),
        )
        .with_active(tool.is_active())
    }
}

// ---------------------------------------------------------------------------
// GhidraToolState -- extended ToolState with Ghidra-specific fields
// ---------------------------------------------------------------------------

/// Ghidra-specific tool state that extends the base [`ToolState`] with
/// additional analysis-related metadata.
///
/// Ported from `ghidra.framework.data.GhidraToolState`.
#[derive(Debug, Clone)]
pub struct GhidraToolState {
    /// Base tool state data.
    pub base: ToolState,
    /// Whether auto-analysis was enabled when the state was captured.
    pub auto_analysis_enabled: bool,
    /// The analysis priority for the domain object.
    pub analysis_priority: u32,
    /// Registered view names (e.g. "Listing", "Byte Viewer").
    pub views: Vec<String>,
}

impl GhidraToolState {
    /// Creates a Ghidra tool state from a base [`ToolState`].
    pub fn from_base(base: ToolState) -> Self {
        Self {
            base,
            auto_analysis_enabled: true,
            analysis_priority: 0,
            views: Vec::new(),
        }
    }

    /// Sets auto-analysis enabled state.
    pub fn with_auto_analysis(mut self, enabled: bool) -> Self {
        self.auto_analysis_enabled = enabled;
        self
    }

    /// Sets the analysis priority.
    pub fn with_analysis_priority(mut self, priority: u32) -> Self {
        self.analysis_priority = priority;
        self
    }

    /// Adds a view name.
    pub fn with_view(mut self, view: impl Into<String>) -> Self {
        self.views.push(view.into());
        self
    }

    /// Returns the number of registered views.
    pub fn view_count(&self) -> usize {
        self.views.len()
    }
}

impl fmt::Display for GhidraToolState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GhidraToolState({}, views={}, analysis={})",
            self.base.tool_name,
            self.views.len(),
            self.auto_analysis_enabled
        )
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Mock types ---

    #[derive(Debug)]
    struct MockTool {
        name: String,
        id: String,
        active: bool,
    }

    impl MockTool {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                id: format!("tool-{}", name),
                active: true,
            }
        }
    }

    impl PluginTool for MockTool {
        fn tool_name(&self) -> &str {
            &self.name
        }
        fn tool_id(&self) -> &str {
            &self.id
        }
        fn is_active(&self) -> bool {
            self.active
        }
    }

    #[derive(Debug)]
    struct MockDomainObject {
        id: String,
        name: String,
        changed: bool,
    }

    impl MockDomainObject {
        fn new(id: &str, name: &str) -> Self {
            Self {
                id: id.to_string(),
                name: name.to_string(),
                changed: false,
            }
        }
    }

    impl DomainObject for MockDomainObject {
        fn domain_id(&self) -> &str {
            &self.id
        }
        fn name(&self) -> &str {
            &self.name
        }
        fn is_changed(&self) -> bool {
            self.changed
        }
    }

    // --- ToolState ---

    #[test]
    fn test_tool_state_creation() {
        let state = ToolState::new("CodeBrowser", "tool-1", "prog-001", "test.exe");
        assert_eq!(state.tool_name, "CodeBrowser");
        assert_eq!(state.tool_id, "tool-1");
        assert_eq!(state.domain_id, "prog-001");
        assert_eq!(state.domain_name, "test.exe");
        assert!(!state.was_active);
        assert!(state.config_is_empty());
    }

    #[test]
    fn test_tool_state_builder() {
        let state = ToolState::new("CB", "t1", "d1", "prog")
            .with_config("key1", "val1")
            .with_config("key2", "val2")
            .with_active(true);

        assert!(state.was_active);
        assert_eq!(state.config_len(), 2);
        assert_eq!(state.get_config("key1"), Some("val1"));
        assert_eq!(state.get_config("key2"), Some("val2"));
        assert_eq!(state.get_config("missing"), None);
    }

    #[test]
    fn test_tool_state_display() {
        let state = ToolState::new("MyTool", "t1", "d1", "prog");
        let s = format!("{}", state);
        assert!(s.contains("MyTool"));
        assert!(s.contains("d1"));
    }

    // --- GhidraToolStateFactory ---

    #[test]
    fn test_ghidra_factory_create() {
        let factory = GhidraToolStateFactory::new();
        let tool = MockTool::new("CodeBrowser");
        let domain = MockDomainObject::new("prog-001", "test.exe");

        let state = factory.create_tool_state(&tool, &domain);
        assert_eq!(state.tool_name, "CodeBrowser");
        assert_eq!(state.domain_id, "prog-001");
        assert_eq!(state.domain_name, "test.exe");
        assert!(state.was_active);
    }

    #[test]
    fn test_ghidra_factory_default_state() {
        let factory = GhidraToolStateFactory::new();
        let tool = MockTool::new("ListingTool");

        let state = factory.create_default_state(&tool);
        assert_eq!(state.tool_name, "ListingTool");
        assert_eq!(state.domain_id, "");
    }

    // --- GhidraToolState ---

    #[test]
    fn test_ghidra_tool_state_from_base() {
        let base = ToolState::new("CB", "t1", "d1", "prog");
        let ghidra_state = GhidraToolState::from_base(base)
            .with_auto_analysis(false)
            .with_analysis_priority(5)
            .with_view("Listing")
            .with_view("ByteViewer");

        assert!(!ghidra_state.auto_analysis_enabled);
        assert_eq!(ghidra_state.analysis_priority, 5);
        assert_eq!(ghidra_state.view_count(), 2);
        assert!(ghidra_state.views.contains(&"Listing".to_string()));
    }

    #[test]
    fn test_ghidra_tool_state_display() {
        let base = ToolState::new("CB", "t1", "d1", "prog");
        let state = GhidraToolState::from_base(base).with_view("V1");
        let s = format!("{}", state);
        assert!(s.contains("CB"));
        assert!(s.contains("views=1"));
    }
}
