//! Listener types for the program tree.
//!
//! Ported from `ghidra.app.plugin.core.programtree.TreeListener` and
//! `ghidra.app.plugin.core.programtree.ViewChangeListener`.
//!
//! These callbacks are used to notify the plugin when the tree view
//! changes (selection, expansion, navigation).

use ghidra_core::Address;

/// Events emitted by the program tree to its listeners.
#[derive(Debug, Clone)]
pub enum TreeEvent {
    /// The view has changed (visible address set).
    ViewChanged,
    /// A go-to navigation was requested.
    GoTo(Address),
    /// The selection changed.
    SelectionChanged,
    /// A node was expanded.
    NodeExpanded(String),
    /// A node was collapsed.
    NodeCollapsed(String),
    /// A node was renamed.
    NodeRenamed {
        /// Old name of the node.
        old_name: String,
        /// New name of the node.
        new_name: String,
    },
    /// A node was added.
    NodeAdded(String),
    /// A node was removed.
    NodeRemoved(String),
}

/// Trait for objects that listen to program tree events.
///
/// Ported from Ghidra's `TreeListener` interface.
pub trait TreeListener {
    /// Called when the tree view has changed.
    fn tree_view_changed(&self, event: &TreeEvent);

    /// Called when a go-to navigation is requested.
    fn go_to(&self, address: Address);
}

/// Trait for objects that listen to view changes on the view manager.
///
/// Ported from Ghidra's `ViewChangeListener` interface.
pub trait ViewChangeListener {
    /// Called when the view's name has changed.
    fn view_name_changed(&self, old_name: &str, new_name: &str);

    /// Called when the view's content has changed.
    fn view_content_changed(&self);

    /// Called when the view is about to be closed.
    fn view_closing(&self);

    /// Called when the view has been closed.
    fn view_closed(&self);
}

/// A simple callback-based tree listener implementation.
pub struct CallbackTreeListener {
    on_view_changed: Option<Box<dyn Fn(&TreeEvent) + Send + Sync>>,
    on_go_to: Option<Box<dyn Fn(Address) + Send + Sync>>,
}

impl std::fmt::Debug for CallbackTreeListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallbackTreeListener")
            .field("has_view_changed", &self.on_view_changed.is_some())
            .field("has_go_to", &self.on_go_to.is_some())
            .finish()
    }
}

impl CallbackTreeListener {
    /// Create a new callback tree listener.
    pub fn new() -> Self {
        Self {
            on_view_changed: None,
            on_go_to: None,
        }
    }

    /// Set the view-changed callback.
    pub fn with_view_changed<F>(mut self, f: F) -> Self
    where
        F: Fn(&TreeEvent) + Send + Sync + 'static,
    {
        self.on_view_changed = Some(Box::new(f));
        self
    }

    /// Set the go-to callback.
    pub fn with_go_to<F>(mut self, f: F) -> Self
    where
        F: Fn(Address) + Send + Sync + 'static,
    {
        self.on_go_to = Some(Box::new(f));
        self
    }
}

impl Default for CallbackTreeListener {
    fn default() -> Self {
        Self::new()
    }
}

impl TreeListener for CallbackTreeListener {
    fn tree_view_changed(&self, event: &TreeEvent) {
        if let Some(ref cb) = self.on_view_changed {
            cb(event);
        }
    }

    fn go_to(&self, address: Address) {
        if let Some(ref cb) = self.on_go_to {
            cb(address);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_callback_tree_listener_view_changed() {
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();

        let listener = CallbackTreeListener::new()
            .with_view_changed(move |_event| {
                called_clone.store(true, Ordering::SeqCst);
            });

        listener.tree_view_changed(&TreeEvent::ViewChanged);
        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_callback_tree_listener_go_to() {
        let addr_value = Arc::new(AtomicU64::new(0));
        let addr_clone = addr_value.clone();

        let listener = CallbackTreeListener::new()
            .with_go_to(move |addr| {
                addr_clone.store(addr.offset, Ordering::SeqCst);
            });

        listener.go_to(Address::new(0xDEAD));
        assert_eq!(addr_value.load(Ordering::SeqCst), 0xDEAD);
    }

    #[test]
    fn test_tree_event_variants() {
        let events = vec![
            TreeEvent::ViewChanged,
            TreeEvent::GoTo(Address::new(0x100)),
            TreeEvent::SelectionChanged,
            TreeEvent::NodeExpanded("root".into()),
            TreeEvent::NodeCollapsed("root".into()),
            TreeEvent::NodeRenamed {
                old_name: "old".into(),
                new_name: "new".into(),
            },
            TreeEvent::NodeAdded("child".into()),
            TreeEvent::NodeRemoved("child".into()),
        ];
        assert_eq!(events.len(), 8);
    }

    #[test]
    fn test_default_callback_listener() {
        let listener = CallbackTreeListener::default();
        // Should not panic with no callbacks set.
        listener.tree_view_changed(&TreeEvent::ViewChanged);
        listener.go_to(Address::new(0));
    }
}
