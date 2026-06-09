//! The `DockingTool` trait for the docking framework.
//!
//! Port of Ghidra's `docking.DockingTool` interface.  In Java this is
//! the interface that tool implementations satisfy.  It exposes the
//! programmatic API that plugins and components use to interact with
//! the tool without depending on a concrete implementation.
//!
//! The existing [`super::tool::DockingTool`] struct provides a concrete
//! implementation; this trait defines the abstract contract.

use std::fmt;

use super::action::DockingAction;
use super::action_context::DockingActionContext;
use super::component::{ComponentProvider as ProviderType, WindowPosition};

// ---------------------------------------------------------------------------
// DockingTool trait
// ---------------------------------------------------------------------------

/// The abstract tool interface for the docking framework.
///
/// This trait exposes the API that plugins, component providers, and
/// actions use to interact with the tool.  It covers:
/// - Project and program management
/// - Action registration and dispatch
/// - Component provider management
/// - Layout persistence
/// - Event notification
/// - Service registry
/// - Focus management
pub trait DockingTool: fmt::Debug + Send + Sync {
    /// The name of the tool (e.g. "CodeBrowser").
    fn tool_name(&self) -> &str;

    /// Set the tool name.
    fn set_tool_name(&mut self, name: &str);

    // -- Project / program --

    /// The currently active project name, if any.
    fn active_project(&self) -> Option<&str>;

    /// Set the active project.
    fn set_project(&mut self, project: &str);

    /// Clear the active project.
    fn clear_project(&mut self);

    /// The currently active program name, if any.
    fn active_program(&self) -> Option<&str>;

    /// Set the active program.
    fn set_program(&mut self, program: &str);

    /// Clear the active program.
    fn clear_program(&mut self);

    // -- Actions --

    /// Register a top-level action with the tool.
    fn add_action(&mut self, action: DockingAction);

    /// Remove an action by name.
    fn remove_action(&mut self, name: &str) -> Option<DockingAction>;

    /// Find an action by name.
    fn find_action(&self, name: &str) -> Option<&DockingAction>;

    /// Enable or disable an action by name.
    fn set_action_enabled(&mut self, name: &str, enabled: bool) -> bool;

    /// Trigger an action by name with context.
    fn trigger_action(&self, name: &str, context: &DockingActionContext) -> bool;

    // -- Components --

    /// Show a component provider.
    fn show_component(&mut self, provider: ProviderType, name: &str);

    /// Hide a component provider.
    fn hide_component(&mut self, provider: ProviderType, name: &str);

    /// Toggle visibility of a component provider.
    fn toggle_component(&mut self, provider: ProviderType, name: &str);

    /// Whether a component is visible.
    fn is_component_visible(&self, provider: &ProviderType, name: &str) -> bool;

    // -- Layout --

    /// Serialize the current layout to a string.
    fn save_layout(&self) -> String;

    /// Restore the layout from a serialized string.
    fn load_layout(&mut self, data: &str) -> Result<(), String>;

    /// Reset to the default layout.
    fn reset_layout(&mut self);

    // -- Focus --

    /// Set focus to a specific component.
    fn set_focus(&mut self, provider: ProviderType, name: &str);

    /// Get the currently focused component.
    fn get_focused(&self) -> Option<(ProviderType, String)>;

    /// Clear focus.
    fn clear_focus(&mut self);

    // -- Context --

    /// Get the current action context.
    fn current_context(&self) -> DockingActionContext;

    /// Set the current action context.
    fn set_context(&mut self, context: DockingActionContext);

    // -- Services --

    /// Register a service with the tool.
    fn add_service(&mut self, name: &str, data: &str);

    /// Get a service by name.
    fn get_service(&self, name: &str) -> Option<&str>;

    /// Remove a service by name.
    fn remove_service(&mut self, name: &str) -> Option<String>;

    // -- Properties --

    /// Set a tool-wide property.
    fn set_property(&mut self, key: &str, value: &str);

    /// Get a tool-wide property.
    fn get_property(&self, key: &str) -> Option<&str>;

    /// Remove a tool-wide property.
    fn remove_property(&mut self, key: &str) -> Option<String>;

    // -- Window position --

    /// Get the default window position for a component provider.
    fn default_position_for(&self, _provider: &ProviderType) -> WindowPosition {
        WindowPosition::Center
    }

    // -- Lifecycle --

    /// Close the tool.
    fn close(&mut self);

    /// Whether the tool has been closed.
    fn is_closed(&self) -> bool {
        false
    }

    /// Dispose of the tool and all its resources.
    fn dispose(&mut self);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct MockTool {
        name: String,
        project: Option<String>,
        program: Option<String>,
        closed: bool,
    }

    impl MockTool {
        fn new() -> Self {
            Self {
                name: "CodeBrowser".into(),
                project: None,
                program: None,
                closed: false,
            }
        }
    }

    impl DockingTool for MockTool {
        fn tool_name(&self) -> &str { &self.name }
        fn set_tool_name(&mut self, name: &str) { self.name = name.to_owned(); }
        fn active_project(&self) -> Option<&str> { self.project.as_deref() }
        fn set_project(&mut self, project: &str) { self.project = Some(project.to_owned()); }
        fn clear_project(&mut self) { self.project = None; }
        fn active_program(&self) -> Option<&str> { self.program.as_deref() }
        fn set_program(&mut self, program: &str) { self.program = Some(program.to_owned()); }
        fn clear_program(&mut self) { self.program = None; }
        fn add_action(&mut self, _action: DockingAction) {}
        fn remove_action(&mut self, _name: &str) -> Option<DockingAction> { None }
        fn find_action(&self, _name: &str) -> Option<&DockingAction> { None }
        fn set_action_enabled(&mut self, _name: &str, _enabled: bool) -> bool { false }
        fn trigger_action(&self, _name: &str, _ctx: &DockingActionContext) -> bool { false }
        fn show_component(&mut self, _p: ProviderType, _n: &str) {}
        fn hide_component(&mut self, _p: ProviderType, _n: &str) {}
        fn toggle_component(&mut self, _p: ProviderType, _n: &str) {}
        fn is_component_visible(&self, _p: &ProviderType, _n: &str) -> bool { false }
        fn save_layout(&self) -> String { String::new() }
        fn load_layout(&mut self, _data: &str) -> Result<(), String> { Ok(()) }
        fn reset_layout(&mut self) {}
        fn set_focus(&mut self, _p: ProviderType, _n: &str) {}
        fn get_focused(&self) -> Option<(ProviderType, String)> { None }
        fn clear_focus(&mut self) {}
        fn current_context(&self) -> DockingActionContext { DockingActionContext::new() }
        fn set_context(&mut self, _ctx: DockingActionContext) {}
        fn add_service(&mut self, _name: &str, _data: &str) {}
        fn get_service(&self, _name: &str) -> Option<&str> { None }
        fn remove_service(&mut self, _name: &str) -> Option<String> { None }
        fn set_property(&mut self, _key: &str, _value: &str) {}
        fn get_property(&self, _key: &str) -> Option<&str> { None }
        fn remove_property(&mut self, _key: &str) -> Option<String> { None }
        fn close(&mut self) { self.closed = true; }
        fn is_closed(&self) -> bool { self.closed }
        fn dispose(&mut self) { self.closed = true; }
    }

    #[test]
    fn test_tool_trait_basic() {
        let mut tool = MockTool::new();
        assert_eq!(tool.tool_name(), "CodeBrowser");
        assert!(tool.active_project().is_none());
        assert!(tool.active_program().is_none());
        assert!(!tool.is_closed());
    }

    #[test]
    fn test_tool_trait_project_program() {
        let mut tool = MockTool::new();
        tool.set_project("my-project");
        assert_eq!(tool.active_project(), Some("my-project"));

        tool.set_program("test.exe");
        assert_eq!(tool.active_program(), Some("test.exe"));

        tool.clear_program();
        assert!(tool.active_program().is_none());
        assert_eq!(tool.active_project(), Some("my-project"));

        tool.clear_project();
        assert!(tool.active_project().is_none());
    }

    #[test]
    fn test_tool_trait_name() {
        let mut tool = MockTool::new();
        assert_eq!(tool.tool_name(), "CodeBrowser");
        tool.set_tool_name("NewTool");
        assert_eq!(tool.tool_name(), "NewTool");
    }

    #[test]
    fn test_tool_trait_lifecycle() {
        let mut tool = MockTool::new();
        assert!(!tool.is_closed());
        tool.close();
        assert!(tool.is_closed());
    }

    #[test]
    fn test_tool_trait_defaults() {
        let tool = MockTool::new();
        assert_eq!(
            tool.default_position_for(&ProviderType::Console),
            WindowPosition::Center
        );
    }

    #[test]
    fn test_tool_trait_as_trait_object() {
        let tool: Box<dyn DockingTool> = Box::new(MockTool::new());
        assert_eq!(tool.tool_name(), "CodeBrowser");
    }
}
