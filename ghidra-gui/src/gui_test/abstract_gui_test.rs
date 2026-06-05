//! Abstract GUI test framework.
//!
//! Ports Ghidra's `generic.test.AbstractGuiTest` from the Java source.
//!
//! Provides a reusable test harness for GUI component testing with:
//! - Test environment setup and teardown
//! - Component tree inspection utilities
//! - Wait-for-synchronization helpers
//! - Assertion utilities for GUI state

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A virtual component in the test GUI tree.
#[derive(Debug, Clone)]
pub struct TestComponent {
    /// Unique component ID.
    pub id: u64,
    /// Component type name.
    pub component_type: String,
    /// Component name (for identification).
    pub name: Option<String>,
    /// Component bounds (x, y, width, height).
    pub bounds: (i32, i32, u32, u32),
    /// Whether the component is visible.
    pub visible: bool,
    /// Whether the component is enabled.
    pub enabled: bool,
    /// Child component IDs.
    pub children: Vec<u64>,
    /// Parent component ID (None for root).
    pub parent: Option<u64>,
    /// Properties attached to this component.
    pub properties: HashMap<String, String>,
}

impl TestComponent {
    /// Create a new test component.
    pub fn new(id: u64, component_type: impl Into<String>) -> Self {
        Self {
            id,
            component_type: component_type.into(),
            name: None,
            bounds: (0, 0, 100, 30),
            visible: true,
            enabled: true,
            children: Vec::new(),
            parent: None,
            properties: HashMap::new(),
        }
    }

    /// Set the component name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the component bounds.
    pub fn with_bounds(mut self, x: i32, y: i32, w: u32, h: u32) -> Self {
        self.bounds = (x, y, w, h);
        self
    }

    /// Set visibility.
    pub fn with_visible(mut self, visible: bool) -> Self {
        self.visible = visible;
        self
    }

    /// Set enabled state.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Add a property.
    pub fn with_property(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.properties.insert(key.into(), value.into());
        self
    }
}

/// The abstract GUI test environment.
///
/// Provides infrastructure for setting up a virtual component tree
/// and performing assertions on GUI state.
#[derive(Debug)]
pub struct AbstractGuiTest {
    /// The component tree, keyed by ID.
    components: HashMap<u64, TestComponent>,
    /// Next component ID to allocate.
    next_id: u64,
    /// Root component ID.
    root_id: Option<u64>,
    /// Simulated screen dimensions.
    screen_size: (u32, u32),
    /// Event log for debugging.
    event_log: Arc<Mutex<Vec<String>>>,
}

impl AbstractGuiTest {
    /// Create a new GUI test environment.
    pub fn new() -> Self {
        Self {
            components: HashMap::new(),
            next_id: 1,
            root_id: None,
            screen_size: (1920, 1080),
            event_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create a new GUI test environment with custom screen size.
    pub fn with_screen_size(width: u32, height: u32) -> Self {
        Self {
            screen_size: (width, height),
            ..Self::new()
        }
    }

    /// Add a component to the tree and return its ID.
    pub fn add_component(&mut self, mut comp: TestComponent) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        comp.id = id;
        self.components.insert(id, comp);
        id
    }

    /// Add a component as a child of a parent.
    pub fn add_child(&mut self, parent_id: u64, mut comp: TestComponent) -> Option<u64> {
        if !self.components.contains_key(&parent_id) {
            return None;
        }
        let id = self.next_id;
        self.next_id += 1;
        comp.id = id;
        comp.parent = Some(parent_id);
        self.components.insert(id, comp);
        // Update parent's children list
        if let Some(parent) = self.components.get_mut(&parent_id) {
            parent.children.push(id);
        }
        Some(id)
    }

    /// Set the root component.
    pub fn set_root(&mut self, id: u64) {
        if self.components.contains_key(&id) {
            self.root_id = Some(id);
        }
    }

    /// Get a component by ID.
    pub fn get_component(&self, id: u64) -> Option<&TestComponent> {
        self.components.get(&id)
    }

    /// Get a mutable reference to a component.
    pub fn get_component_mut(&mut self, id: u64) -> Option<&mut TestComponent> {
        self.components.get_mut(&id)
    }

    /// Find components by type name.
    pub fn find_by_type(&self, component_type: &str) -> Vec<&TestComponent> {
        self.components
            .values()
            .filter(|c| c.component_type == component_type)
            .collect()
    }

    /// Find components by name.
    pub fn find_by_name(&self, name: &str) -> Vec<&TestComponent> {
        self.components
            .values()
            .filter(|c| c.name.as_deref() == Some(name))
            .collect()
    }

    /// Get all children of a component.
    pub fn children_of(&self, parent_id: u64) -> Vec<&TestComponent> {
        self.components
            .get(&parent_id)
            .map(|p| {
                p.children
                    .iter()
                    .filter_map(|&cid| self.components.get(&cid))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get the root component.
    pub fn root(&self) -> Option<&TestComponent> {
        self.root_id.and_then(|id| self.components.get(&id))
    }

    /// Get the total number of components.
    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    /// Get the screen size.
    pub fn screen_size(&self) -> (u32, u32) {
        self.screen_size
    }

    /// Log an event for debugging.
    pub fn log_event(&self, event: impl Into<String>) {
        self.event_log.lock().unwrap().push(event.into());
    }

    /// Get the event log.
    pub fn event_log(&self) -> Vec<String> {
        self.event_log.lock().unwrap().clone()
    }

    /// Clear the event log.
    pub fn clear_event_log(&self) {
        self.event_log.lock().unwrap().clear();
    }

    /// Wait for a condition to become true, with timeout.
    ///
    /// Returns true if the condition was met, false if timed out.
    pub fn wait_for<F: Fn() -> bool>(&self, condition: F, timeout: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if condition() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    /// Assert that a component is visible.
    pub fn assert_visible(&self, id: u64) {
        let comp = self.components.get(&id).expect("component not found");
        assert!(comp.visible, "component {} (type={}) should be visible", id, comp.component_type);
    }

    /// Assert that a component is hidden.
    pub fn assert_hidden(&self, id: u64) {
        let comp = self.components.get(&id).expect("component not found");
        assert!(!comp.visible, "component {} (type={}) should be hidden", id, comp.component_type);
    }

    /// Assert that a component is enabled.
    pub fn assert_enabled(&self, id: u64) {
        let comp = self.components.get(&id).expect("component not found");
        assert!(comp.enabled, "component {} (type={}) should be enabled", id, comp.component_type);
    }

    /// Assert that a component is disabled.
    pub fn assert_disabled(&self, id: u64) {
        let comp = self.components.get(&id).expect("component not found");
        assert!(!comp.enabled, "component {} (type={}) should be disabled", id, comp.component_type);
    }

    /// Assert the number of children of a component.
    pub fn assert_child_count(&self, parent_id: u64, expected: usize) {
        let comp = self.components.get(&parent_id).expect("component not found");
        assert_eq!(
            comp.children.len(),
            expected,
            "component {} expected {} children, found {}",
            parent_id,
            expected,
            comp.children.len()
        );
    }

    /// Reset the test environment.
    pub fn reset(&mut self) {
        self.components.clear();
        self.next_id = 1;
        self.root_id = None;
        self.clear_event_log();
    }
}

impl Default for AbstractGuiTest {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for setting up a standard test GUI tree.
#[derive(Debug)]
pub struct GuiTestBuilder {
    env: AbstractGuiTest,
}

impl GuiTestBuilder {
    /// Create a new test builder.
    pub fn new() -> Self {
        Self { env: AbstractGuiTest::new() }
    }

    /// Add a panel component.
    pub fn panel(mut self, name: impl Into<String>) -> Self {
        let comp = TestComponent::new(0, "Panel").with_name(name);
        self.env.add_component(comp);
        self
    }

    /// Add a button component.
    pub fn button(mut self, name: impl Into<String>) -> Self {
        let comp = TestComponent::new(0, "Button").with_name(name);
        self.env.add_component(comp);
        self
    }

    /// Add a label component.
    pub fn label(mut self, text: impl Into<String>) -> Self {
        let comp = TestComponent::new(0, "Label").with_name(text);
        self.env.add_component(comp);
        self
    }

    /// Build the test environment.
    pub fn build(self) -> AbstractGuiTest {
        self.env
    }
}

impl Default for GuiTestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_component_new() {
        let comp = TestComponent::new(1, "Button");
        assert_eq!(comp.id, 1);
        assert_eq!(comp.component_type, "Button");
        assert!(comp.visible);
        assert!(comp.enabled);
        assert!(comp.children.is_empty());
    }

    #[test]
    fn test_component_builder() {
        let comp = TestComponent::new(1, "Panel")
            .with_name("MyPanel")
            .with_bounds(10, 20, 300, 200)
            .with_visible(false)
            .with_enabled(false)
            .with_property("key", "value");
        assert_eq!(comp.name.as_deref(), Some("MyPanel"));
        assert_eq!(comp.bounds, (10, 20, 300, 200));
        assert!(!comp.visible);
        assert!(!comp.enabled);
        assert_eq!(comp.properties.get("key").map(|s| s.as_str()), Some("value"));
    }

    #[test]
    fn test_gui_test_add_component() {
        let mut env = AbstractGuiTest::new();
        let id = env.add_component(TestComponent::new(0, "Panel").with_name("Root"));
        assert_eq!(id, 1);
        assert!(env.get_component(id).is_some());
        assert_eq!(env.component_count(), 1);
    }

    #[test]
    fn test_gui_test_parent_child() {
        let mut env = AbstractGuiTest::new();
        let parent_id = env.add_component(TestComponent::new(0, "Frame").with_name("Main"));
        let child_id = env.add_child(parent_id, TestComponent::new(0, "Button").with_name("OK")).unwrap();
        assert_eq!(env.children_of(parent_id).len(), 1);
        assert_eq!(env.children_of(parent_id)[0].id, child_id);
        assert_eq!(env.get_component(child_id).unwrap().parent, Some(parent_id));
    }

    #[test]
    fn test_gui_test_find_by_type() {
        let mut env = AbstractGuiTest::new();
        env.add_component(TestComponent::new(0, "Button").with_name("A"));
        env.add_component(TestComponent::new(0, "Button").with_name("B"));
        env.add_component(TestComponent::new(0, "Label").with_name("C"));
        let buttons = env.find_by_type("Button");
        assert_eq!(buttons.len(), 2);
    }

    #[test]
    fn test_gui_test_find_by_name() {
        let mut env = AbstractGuiTest::new();
        env.add_component(TestComponent::new(0, "Button").with_name("Submit"));
        env.add_component(TestComponent::new(0, "Button").with_name("Cancel"));
        let found = env.find_by_name("Submit");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].component_type, "Button");
    }

    #[test]
    fn test_gui_test_root() {
        let mut env = AbstractGuiTest::new();
        let id = env.add_component(TestComponent::new(0, "Frame"));
        assert!(env.root().is_none());
        env.set_root(id);
        assert!(env.root().is_some());
        assert_eq!(env.root().unwrap().id, id);
    }

    #[test]
    fn test_gui_test_assertions() {
        let mut env = AbstractGuiTest::new();
        let visible_id = env.add_component(TestComponent::new(0, "Panel").with_visible(true));
        let hidden_id = env.add_component(TestComponent::new(0, "Panel").with_visible(false));
        env.assert_visible(visible_id);
        env.assert_hidden(hidden_id);
    }

    #[test]
    fn test_gui_test_assert_enabled_disabled() {
        let mut env = AbstractGuiTest::new();
        let enabled_id = env.add_component(TestComponent::new(0, "Button").with_enabled(true));
        let disabled_id = env.add_component(TestComponent::new(0, "Button").with_enabled(false));
        env.assert_enabled(enabled_id);
        env.assert_disabled(disabled_id);
    }

    #[test]
    fn test_gui_test_child_count() {
        let mut env = AbstractGuiTest::new();
        let parent = env.add_component(TestComponent::new(0, "Panel"));
        env.add_child(parent, TestComponent::new(0, "Button")).unwrap();
        env.add_child(parent, TestComponent::new(0, "Button")).unwrap();
        env.assert_child_count(parent, 2);
    }

    #[test]
    fn test_gui_test_event_log() {
        let env = AbstractGuiTest::new();
        assert!(env.event_log().is_empty());
        env.log_event("button clicked");
        env.log_event("label updated");
        assert_eq!(env.event_log().len(), 2);
        assert_eq!(env.event_log()[0], "button clicked");
        env.clear_event_log();
        assert!(env.event_log().is_empty());
    }

    #[test]
    fn test_gui_test_screen_size() {
        let env = AbstractGuiTest::with_screen_size(800, 600);
        assert_eq!(env.screen_size(), (800, 600));
    }

    #[test]
    fn test_gui_test_reset() {
        let mut env = AbstractGuiTest::new();
        env.add_component(TestComponent::new(0, "Panel"));
        env.log_event("test");
        assert_eq!(env.component_count(), 1);
        env.reset();
        assert_eq!(env.component_count(), 0);
        assert!(env.root().is_none());
        assert!(env.event_log().is_empty());
    }

    #[test]
    fn test_gui_test_add_child_invalid_parent() {
        let mut env = AbstractGuiTest::new();
        let result = env.add_child(999, TestComponent::new(0, "Button"));
        assert!(result.is_none());
    }

    #[test]
    fn test_gui_test_builder() {
        let env = GuiTestBuilder::new()
            .panel("MainPanel")
            .button("OK")
            .button("Cancel")
            .label("Status")
            .build();
        assert_eq!(env.component_count(), 4);
        assert_eq!(env.find_by_type("Button").len(), 2);
        assert_eq!(env.find_by_type("Label").len(), 1);
    }

    #[test]
    fn test_gui_test_wait_for_immediate() {
        let env = AbstractGuiTest::new();
        let result = env.wait_for(|| true, Duration::from_secs(1));
        assert!(result);
    }

    #[test]
    fn test_gui_test_wait_for_timeout() {
        let env = AbstractGuiTest::new();
        let result = env.wait_for(|| false, Duration::from_millis(50));
        assert!(!result);
    }
}
