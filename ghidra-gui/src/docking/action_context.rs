//! Concrete action context for the docking framework.
//!
//! Port of Ghidra's `docking.ActionContext` class.  In Java this is a
//! class (not an interface) that carries the provider, context object,
//! source object, and click modifiers needed by actions that operate on
//! program data.  The existing [`super::context::ActionContext`] trait
//! defines the abstract interface; this module provides a standalone,
//! serialisable concrete type that mirrors the Ghidra class more
//! directly.

use std::fmt;

use super::component::{ComponentProvider, WindowPosition};

// ---------------------------------------------------------------------------
// DockingActionContext — the concrete Ghidra-style ActionContext class
// ---------------------------------------------------------------------------

/// A concrete action context carrying the state an action needs to execute.
///
/// Unlike [`super::context::ActionContext`] (a trait), this is a plain data
/// struct that can be cloned, serialised, and passed across thread
/// boundaries.
#[derive(Debug, Clone)]
pub struct DockingActionContext {
    /// The component provider that originated this context.
    provider: Option<ComponentProvider>,
    /// The address or object under the cursor.
    context_object: Option<String>,
    /// The UI element that generated the context (e.g. a table row).
    source_object: Option<String>,
    /// The component identifier (e.g. "ListingView:listing").
    source_component: Option<String>,
    /// Platform click modifier flags.
    click_modifiers: u32,
    /// Whether the context has been consumed (prevents double-firing).
    consumed: bool,
}

impl DockingActionContext {
    /// Create an empty (default) context.
    pub fn new() -> Self {
        Self {
            provider: None,
            context_object: None,
            source_object: None,
            source_component: None,
            click_modifiers: 0,
            consumed: false,
        }
    }

    /// Create with a provider.
    pub fn with_provider(provider: ComponentProvider) -> Self {
        Self {
            provider: Some(provider),
            ..Self::new()
        }
    }

    /// Create with a provider and context object.
    pub fn with_context(
        provider: ComponentProvider,
        context_object: impl Into<String>,
    ) -> Self {
        Self {
            provider: Some(provider),
            context_object: Some(context_object.into()),
            ..Self::new()
        }
    }

    /// Create a full context with all fields populated.
    pub fn full(
        provider: ComponentProvider,
        context_object: impl Into<String>,
        source_object: impl Into<String>,
        source_component: impl Into<String>,
        click_modifiers: u32,
    ) -> Self {
        Self {
            provider: Some(provider),
            context_object: Some(context_object.into()),
            source_object: Some(source_object.into()),
            source_component: Some(source_component.into()),
            click_modifiers,
            consumed: false,
        }
    }

    // -- Getters --

    /// The originating provider, if any.
    pub fn provider(&self) -> Option<ComponentProvider> {
        self.provider
    }

    /// The context object (address, selection, etc.).
    pub fn context_object(&self) -> Option<&str> {
        self.context_object.as_deref()
    }

    /// The source UI element.
    pub fn source_object(&self) -> Option<&str> {
        self.source_object.as_deref()
    }

    /// The source component identifier.
    pub fn source_component(&self) -> Option<&str> {
        self.source_component.as_deref()
    }

    /// The click modifier flags.
    pub fn click_modifiers(&self) -> u32 {
        self.click_modifiers
    }

    /// Whether any of the given modifier bits are set.
    pub fn has_any_click_modifiers(&self, mask: u32) -> bool {
        (self.click_modifiers & mask) != 0
    }

    /// Whether this context is a "default" (empty) context.
    pub fn is_default(&self) -> bool {
        self.provider.is_none() && self.context_object.is_none()
    }

    /// Whether the context has been consumed.
    pub fn is_consumed(&self) -> bool {
        self.consumed
    }

    // -- Setters --

    /// Set the provider.
    pub fn set_provider(&mut self, provider: ComponentProvider) {
        self.provider = Some(provider);
    }

    /// Set the context object.
    pub fn set_context_object(&mut self, obj: impl Into<String>) {
        self.context_object = Some(obj.into());
    }

    /// Set the source object.
    pub fn set_source_object(&mut self, obj: impl Into<String>) {
        self.source_object = Some(obj.into());
    }

    /// Set the source component.
    pub fn set_source_component(&mut self, comp: impl Into<String>) {
        self.source_component = Some(comp.into());
    }

    /// Set the click modifiers.
    pub fn set_click_modifiers(&mut self, mods: u32) {
        self.click_modifiers = mods;
    }

    /// Mark this context as consumed (action has been dispatched).
    pub fn consume(&mut self) {
        self.consumed = true;
    }

    /// Reset the consumed flag.
    pub fn unconsume(&mut self) {
        self.consumed = false;
    }

    // -- Helpers --

    /// Get the preferred window position for a component opened from this
    /// context.  Defaults to Center.
    pub fn preferred_window_position(&self) -> WindowPosition {
        WindowPosition::default()
    }

    /// Whether the context carries a program reference.
    pub fn has_program(&self) -> bool {
        // Convention: context_object starting with "program:" indicates a
        // program reference.
        self.context_object
            .as_deref()
            .map(|s| s.starts_with("program:"))
            .unwrap_or(false)
    }

    /// Whether the context carries a function reference.
    pub fn has_function(&self) -> bool {
        self.context_object
            .as_deref()
            .map(|s| s.starts_with("function:"))
            .unwrap_or(false)
    }

    /// Whether the context carries an address reference.
    pub fn has_address(&self) -> bool {
        self.context_object
            .as_deref()
            .map(|s| s.starts_with("0x") || s.starts_with("addr:"))
            .unwrap_or(false)
    }
}

impl Default for DockingActionContext {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DockingActionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DockingActionContext(provider={:?}, object={:?}, source={:?})",
            self.provider, self.context_object, self.source_component,
        )
    }
}

// ---------------------------------------------------------------------------
// Click modifier constants
// ---------------------------------------------------------------------------

/// Modifier bit: no modifier (plain click).
pub const MODIFIER_NONE: u32 = 0x00;
/// Modifier bit: Control held.
pub const MODIFIER_CTRL: u32 = 0x01;
/// Modifier bit: Shift held.
pub const MODIFIER_SHIFT: u32 = 0x02;
/// Modifier bit: Alt held.
pub const MODIFIER_ALT: u32 = 0x04;
/// Modifier bit: right-click / context-menu trigger.
pub const MODIFIER_CONTEXT: u32 = 0x08;
/// Modifier bit: double-click.
pub const MODIFIER_DOUBLE_CLICK: u32 = 0x10;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_context_is_default() {
        let ctx = DockingActionContext::new();
        assert!(ctx.is_default());
        assert!(!ctx.is_consumed());
        assert_eq!(ctx.click_modifiers(), 0);
    }

    #[test]
    fn test_with_provider() {
        let ctx = DockingActionContext::with_provider(ComponentProvider::ListingView);
        assert_eq!(ctx.provider(), Some(ComponentProvider::ListingView));
        assert!(ctx.context_object().is_none());
        // Has provider but no context object => not default (provider is set).
        assert!(!ctx.is_default());
    }

    #[test]
    fn test_with_context() {
        let ctx = DockingActionContext::with_context(
            ComponentProvider::Console,
            "addr:0x100000",
        );
        assert!(!ctx.is_default());
        assert!(ctx.has_address());
    }

    #[test]
    fn test_full_context() {
        let ctx = DockingActionContext::full(
            ComponentProvider::SymbolTree,
            "function:main",
            "tree_node",
            "symbol_tree_panel",
            MODIFIER_CTRL | MODIFIER_SHIFT,
        );
        assert_eq!(ctx.provider(), Some(ComponentProvider::SymbolTree));
        assert!(ctx.has_function());
        assert!(ctx.has_any_click_modifiers(MODIFIER_CTRL));
        assert!(ctx.has_any_click_modifiers(MODIFIER_SHIFT));
        assert!(!ctx.has_any_click_modifiers(MODIFIER_ALT));
    }

    #[test]
    fn test_consume() {
        let mut ctx = DockingActionContext::new();
        assert!(!ctx.is_consumed());
        ctx.consume();
        assert!(ctx.is_consumed());
        ctx.unconsume();
        assert!(!ctx.is_consumed());
    }

    #[test]
    fn test_setters() {
        let mut ctx = DockingActionContext::new();
        ctx.set_provider(ComponentProvider::Console);
        ctx.set_context_object("selected_text");
        ctx.set_source_object("editor");
        ctx.set_source_component("code_editor");
        ctx.set_click_modifiers(MODIFIER_CONTEXT);

        assert_eq!(ctx.provider(), Some(ComponentProvider::Console));
        assert_eq!(ctx.context_object(), Some("selected_text"));
        assert_eq!(ctx.source_object(), Some("editor"));
        assert_eq!(ctx.source_component(), Some("code_editor"));
        assert!(ctx.has_any_click_modifiers(MODIFIER_CONTEXT));
    }

    #[test]
    fn test_has_address() {
        let ctx = DockingActionContext::with_context(
            ComponentProvider::ListingView,
            "0x00401000",
        );
        assert!(ctx.has_address());
        assert!(!ctx.has_function());
        assert!(!ctx.has_program());
    }

    #[test]
    fn test_has_program() {
        let ctx = DockingActionContext::with_context(
            ComponentProvider::ListingView,
            "program:test.exe",
        );
        assert!(ctx.has_program());
        assert!(!ctx.has_address());
    }

    #[test]
    fn test_preferred_window_position() {
        let ctx = DockingActionContext::new();
        assert_eq!(ctx.preferred_window_position(), WindowPosition::Center);
    }

    #[test]
    fn test_display() {
        let ctx = DockingActionContext::with_context(
            ComponentProvider::Console,
            "test",
        );
        let s = format!("{}", ctx);
        assert!(s.contains("Console"));
        assert!(s.contains("test"));
    }

    #[test]
    fn test_modifier_constants() {
        assert_eq!(MODIFIER_NONE, 0x00);
        assert!(MODIFIER_CTRL != 0);
        assert!(MODIFIER_SHIFT != 0);
        assert!(MODIFIER_ALT != 0);
        assert!(MODIFIER_CONTEXT != 0);
        assert!(MODIFIER_DOUBLE_CLICK != 0);
    }
}
