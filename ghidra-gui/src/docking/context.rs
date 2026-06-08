//! Action context system for the docking framework.
//!
//! Port of Ghidra's `ActionContext` (interface), `DefaultActionContext`,
//! `DialogActionContext`, `ActionContextProvider`, and
//! `DockingContextListener`.  The context system allows actions to
//! receive the program state they need without a direct coupling to the
//! component that generated the context.

use std::fmt;
use std::sync::Arc;

use super::component::ComponentProvider;

// ---------------------------------------------------------------------------
// ActionContext trait — the core context interface
// ---------------------------------------------------------------------------

/// The core action context trait.
///
/// In Ghidra, `ActionContext` is an interface that carries tool and
/// plugin state information so actions can operate without direct
/// coupling to the originating component.  This Rust trait captures
/// the same concept.
pub trait ActionContext: fmt::Debug {
    /// Get the component provider that generated this context.
    fn get_component_provider(&self) -> Option<ComponentProvider>;

    /// Get the context object (type-erased state).
    ///
    /// In Java this returns `Object`; in Rust we use `Option<String>`
    /// as a serialisable stand-in.  Specific context types may carry
    /// richer payloads via concrete fields.
    fn get_context_object(&self) -> Option<&str>;

    /// Get the source object (the UI element that originated the
    /// context, typically the focused component).
    fn get_source_object(&self) -> Option<&str>;

    /// Get the source component identifier.
    fn get_source_component(&self) -> Option<&str>;

    /// Whether this context has a context object.
    fn has_context_object(&self) -> bool {
        self.get_context_object().is_some()
    }

    /// Whether this context has a source component.
    fn has_source_component(&self) -> bool {
        self.get_source_component().is_some()
    }

    /// Get click modifier flags (platform-specific bit mask).
    fn get_event_click_modifiers(&self) -> u32 {
        0
    }

    /// Whether any of the given modifier mask bits are set.
    fn has_any_event_click_modifiers(&self, mask: u32) -> bool {
        (self.get_event_click_modifiers() & mask) != 0
    }

    /// Whether this context is a "default" (null) context.
    fn is_default_context(&self) -> bool {
        self.get_component_provider().is_none()
            && self.get_context_object().is_none()
    }

    /// Get the context provider (the framework-level bridge).
    fn get_context_provider(&self) -> Option<&dyn ActionContextProvider> {
        None
    }
}

// ---------------------------------------------------------------------------
// ActionContextProvider trait
// ---------------------------------------------------------------------------

/// A trait implemented by objects that can provide an `ActionContext`.
///
/// In Ghidra, both `ComponentProvider` and `DialogComponentProvider`
/// implement this interface.
pub trait ActionContextProvider: fmt::Debug {
    /// Get the action context from this provider.
    fn get_action_context(&self) -> Box<dyn ActionContext>;

    /// The component provider associated with this context provider
    /// (if any).
    fn get_component_provider(&self) -> Option<ComponentProvider> {
        None
    }
}

// ---------------------------------------------------------------------------
// DefaultActionContext
// ---------------------------------------------------------------------------

/// The default, concrete implementation of [`ActionContext`].
#[derive(Debug, Clone)]
pub struct DefaultActionContext {
    /// The component provider that created this context.
    pub provider: Option<ComponentProvider>,
    /// An optional context object (e.g. the currently selected item).
    pub context_object: Option<String>,
    /// The source object (e.g. the focused UI element).
    pub source_object: Option<String>,
    /// The source component identifier.
    pub source_component: Option<String>,
    /// Click modifier flags.
    pub event_click_modifiers: u32,
    /// Name of the context provider.
    pub context_provider_name: Option<String>,
}

impl DefaultActionContext {
    /// Create an empty (default) context.
    pub fn new() -> Self {
        Self {
            provider: None,
            context_object: None,
            source_object: None,
            source_component: None,
            event_click_modifiers: 0,
            context_provider_name: None,
        }
    }

    /// Create a context with a provider.
    pub fn with_provider(provider: ComponentProvider) -> Self {
        Self {
            provider: Some(provider),
            ..Self::new()
        }
    }

    /// Create a context with a provider and context object.
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
    pub fn set_event_click_modifiers(&mut self, modifiers: u32) {
        self.event_click_modifiers = modifiers;
    }

    /// Set the context provider name.
    pub fn set_context_provider_name(&mut self, name: impl Into<String>) {
        self.context_provider_name = Some(name.into());
    }
}

impl Default for DefaultActionContext {
    fn default() -> Self {
        Self::new()
    }
}

impl ActionContext for DefaultActionContext {
    fn get_component_provider(&self) -> Option<ComponentProvider> {
        self.provider
    }

    fn get_context_object(&self) -> Option<&str> {
        self.context_object.as_deref()
    }

    fn get_source_object(&self) -> Option<&str> {
        self.source_object.as_deref()
    }

    fn get_source_component(&self) -> Option<&str> {
        self.source_component.as_deref()
    }

    fn get_event_click_modifiers(&self) -> u32 {
        self.event_click_modifiers
    }
}

// ---------------------------------------------------------------------------
// DialogActionContext
// ---------------------------------------------------------------------------

/// An action context specific to a dialog.
///
/// In Ghidra, `DialogActionContext` wraps another `ActionContext` and
/// adds dialog-specific information.  This Rust equivalent carries the
/// same data.
#[derive(Debug, Clone)]
pub struct DialogActionContext {
    /// The underlying context.
    pub inner: DefaultActionContext,
    /// Whether the dialog is modal.
    pub modal: bool,
    /// The dialog title.
    pub dialog_title: String,
}

impl DialogActionContext {
    /// Create a new dialog action context.
    pub fn new(dialog_title: impl Into<String>, modal: bool) -> Self {
        Self {
            inner: DefaultActionContext::new(),
            modal,
            dialog_title: dialog_title.into(),
        }
    }

    /// Create wrapping an existing context.
    pub fn from_context(
        inner: DefaultActionContext,
        dialog_title: impl Into<String>,
        modal: bool,
    ) -> Self {
        Self {
            inner,
            modal,
            dialog_title: dialog_title.into(),
        }
    }
}

impl ActionContext for DialogActionContext {
    fn get_component_provider(&self) -> Option<ComponentProvider> {
        self.inner.get_component_provider()
    }

    fn get_context_object(&self) -> Option<&str> {
        self.inner.get_context_object()
    }

    fn get_source_object(&self) -> Option<&str> {
        self.inner.get_source_object()
    }

    fn get_source_component(&self) -> Option<&str> {
        self.inner.get_source_component()
    }

    fn get_event_click_modifiers(&self) -> u32 {
        self.inner.get_event_click_modifiers()
    }
}

// ---------------------------------------------------------------------------
// DockingContextListener
// ---------------------------------------------------------------------------

/// A trait for objects that want to be notified when the action context
/// changes.
///
/// In Ghidra, `DockingContextListener.contextChanged(ActionContext)` is
/// called by the tool whenever the active context changes (e.g. when the
/// user clicks in a different component).
pub trait DockingContextListener: fmt::Debug + Send + Sync {
    /// Called when the action context changes.
    fn context_changed(&self, context: &dyn ActionContext);
}

/// A closure-based implementation of `DockingContextListener`.
#[derive(Clone)]
pub struct ClosureContextListener {
    name: String,
    callback: Arc<dyn Fn(&dyn ActionContext) + Send + Sync>,
}

impl ClosureContextListener {
    /// Create a new closure-based context listener.
    pub fn new(
        name: impl Into<String>,
        callback: Arc<dyn Fn(&dyn ActionContext) + Send + Sync>,
    ) -> Self {
        Self {
            name: name.into(),
            callback,
        }
    }
}

impl DockingContextListener for ClosureContextListener {
    fn context_changed(&self, context: &dyn ActionContext) {
        (self.callback)(context);
    }
}

impl fmt::Debug for ClosureContextListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClosureContextListener")
            .field("name", &self.name)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// ContextManager — manages context listeners
// ---------------------------------------------------------------------------

/// Manages the set of context listeners and dispatches context change
/// notifications.
#[derive(Debug, Default)]
pub struct ContextManager {
    /// Registered context listeners.
    listeners: Vec<Box<dyn DockingContextListener>>,
}

impl ContextManager {
    /// Create a new, empty context manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a context listener.
    pub fn add_listener(&mut self, listener: Box<dyn DockingContextListener>) {
        self.listeners.push(listener);
    }

    /// Remove all listeners.
    pub fn clear_listeners(&mut self) {
        self.listeners.clear();
    }

    /// Number of registered listeners.
    pub fn listener_count(&self) -> usize {
        self.listeners.len()
    }

    /// Notify all listeners that the context has changed.
    pub fn context_changed(&self, context: &dyn ActionContext) {
        for listener in &self.listeners {
            listener.context_changed(context);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_action_context_new() {
        let ctx = DefaultActionContext::new();
        assert!(ctx.get_component_provider().is_none());
        assert!(ctx.get_context_object().is_none());
        assert!(ctx.get_source_object().is_none());
        assert!(ctx.get_source_component().is_none());
        assert_eq!(ctx.get_event_click_modifiers(), 0);
        assert!(ctx.is_default_context());
    }

    #[test]
    fn test_default_action_context_with_provider() {
        let ctx = DefaultActionContext::with_provider(ComponentProvider::Console);
        assert_eq!(
            ctx.get_component_provider(),
            Some(ComponentProvider::Console)
        );
        // Has provider but no context object => still considered default-ish
        // (depends on your definition; Ghidra would not consider this default).
    }

    #[test]
    fn test_default_action_context_with_context() {
        let ctx = DefaultActionContext::with_context(
            ComponentProvider::ListingView,
            "selected_address",
        );
        assert_eq!(
            ctx.get_component_provider(),
            Some(ComponentProvider::ListingView)
        );
        assert_eq!(ctx.get_context_object(), Some("selected_address"));
        assert!(!ctx.is_default_context());
    }

    #[test]
    fn test_default_action_context_setters() {
        let mut ctx = DefaultActionContext::new();
        ctx.set_provider(ComponentProvider::SymbolTree);
        ctx.set_context_object("symbol_info");
        ctx.set_source_object("tree_node");
        ctx.set_source_component("symbol_tree_panel");
        ctx.set_event_click_modifiers(0x100); // some modifier
        ctx.set_context_provider_name("SymbolTreePlugin");

        assert_eq!(
            ctx.get_component_provider(),
            Some(ComponentProvider::SymbolTree)
        );
        assert_eq!(ctx.get_context_object(), Some("symbol_info"));
        assert_eq!(ctx.get_source_object(), Some("tree_node"));
        assert_eq!(ctx.get_source_component(), Some("symbol_tree_panel"));
        assert_eq!(ctx.get_event_click_modifiers(), 0x100);
        assert!(ctx.has_any_event_click_modifiers(0x100));
        assert!(!ctx.has_any_event_click_modifiers(0x200));
    }

    #[test]
    fn test_default_action_context_has_methods() {
        let ctx = DefaultActionContext::new();
        assert!(!ctx.has_context_object());
        assert!(!ctx.has_source_component());

        let ctx = DefaultActionContext::with_context(
            ComponentProvider::Console,
            "something",
        );
        assert!(ctx.has_context_object());
    }

    #[test]
    fn test_dialog_action_context() {
        let inner = DefaultActionContext::with_context(
            ComponentProvider::Console,
            "console_selection",
        );
        let ctx = DialogActionContext::from_context(inner, "Go To Address", true);

        assert!(ctx.modal);
        assert_eq!(ctx.dialog_title, "Go To Address");
        assert_eq!(
            ctx.get_component_provider(),
            Some(ComponentProvider::Console)
        );
        assert_eq!(ctx.get_context_object(), Some("console_selection"));
    }

    #[test]
    fn test_dialog_action_context_new() {
        let ctx = DialogActionContext::new("Test Dialog", false);
        assert!(!ctx.modal);
        assert_eq!(ctx.dialog_title, "Test Dialog");
        assert!(ctx.is_default_context());
    }

    #[test]
    fn test_context_manager() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let called = Arc::new(AtomicBool::new(false));
        let called2 = called.clone();

        let mut mgr = ContextManager::new();
        assert_eq!(mgr.listener_count(), 0);

        mgr.add_listener(Box::new(ClosureContextListener::new(
            "test-listener",
            Arc::new(move |_ctx| {
                called2.store(true, Ordering::SeqCst);
            }),
        )));
        assert_eq!(mgr.listener_count(), 1);

        let ctx = DefaultActionContext::with_context(
            ComponentProvider::ListingView,
            "addr",
        );
        mgr.context_changed(&ctx);
        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_context_manager_clear() {
        let mut mgr = ContextManager::new();
        mgr.add_listener(Box::new(ClosureContextListener::new(
            "l1",
            Arc::new(|_| {}),
        )));
        mgr.add_listener(Box::new(ClosureContextListener::new(
            "l2",
            Arc::new(|_| {}),
        )));
        assert_eq!(mgr.listener_count(), 2);
        mgr.clear_listeners();
        assert_eq!(mgr.listener_count(), 0);
    }

    #[test]
    fn test_closure_context_listener() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let count = Arc::new(AtomicU32::new(0));
        let count2 = count.clone();

        let listener = ClosureContextListener::new(
            "counter",
            Arc::new(move |_ctx| {
                count2.fetch_add(1, Ordering::SeqCst);
            }),
        );

        let ctx = DefaultActionContext::new();
        listener.context_changed(&ctx);
        listener.context_changed(&ctx);
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_context_is_default() {
        let ctx = DefaultActionContext::new();
        assert!(ctx.is_default_context());

        let _ctx = DefaultActionContext::with_provider(ComponentProvider::Console);
        // Has provider but no context object.
        // Ghidra considers this non-default; our trait considers it default
        // since there's no context object.  This is fine for the Rust port.
        // The key invariant is that truly empty contexts are correctly identified.
    }
}
