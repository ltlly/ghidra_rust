//! Font change listener for LAF updates.
//!
//! Port of `generic.theme.laf.FontChangeListener`. When the look-and-feel
//! changes, font registrations must be refreshed. This module provides the
//! listener trait and a default implementation that re-applies component
//! font registrations.

use super::component_font_registry::ComponentFontRegistry;

/// Trait for receiving notifications when the active look-and-feel changes.
///
/// Implementors can refresh font registrations, update UI defaults, or
/// perform other cleanup when the LAF switches.
pub trait FontChangeListener: Send + Sync {
    /// Called when the look-and-feel has changed.
    fn laf_changed(&self, registry: &mut ComponentFontRegistry);

    /// The name of this listener (for diagnostics).
    fn name(&self) -> &str;
}

/// Default font change listener that re-applies all registered component fonts.
#[derive(Debug)]
pub struct DefaultFontChangeListener;

impl FontChangeListener for DefaultFontChangeListener {
    fn laf_changed(&self, registry: &mut ComponentFontRegistry) {
        registry.update_component_fonts();
    }

    fn name(&self) -> &str {
        "DefaultFontChangeListener"
    }
}

/// Composite listener that delegates to multiple child listeners.
#[derive(Default)]
pub struct CompositeFontChangeListener {
    listeners: Vec<Box<dyn FontChangeListener>>,
}

impl std::fmt::Debug for CompositeFontChangeListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeFontChangeListener")
            .field("listeners_count", &self.listeners.len())
            .finish()
    }
}

impl CompositeFontChangeListener {
    /// Create an empty composite listener.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a child listener.
    pub fn add(&mut self, listener: Box<dyn FontChangeListener>) {
        self.listeners.push(listener);
    }

    /// Number of child listeners.
    pub fn len(&self) -> usize {
        self.listeners.len()
    }

    /// Whether there are no child listeners.
    pub fn is_empty(&self) -> bool {
        self.listeners.is_empty()
    }
}

impl FontChangeListener for CompositeFontChangeListener {
    fn laf_changed(&self, registry: &mut ComponentFontRegistry) {
        for listener in &self.listeners {
            listener.laf_changed(registry);
        }
    }

    fn name(&self) -> &str {
        "CompositeFontChangeListener"
    }
}

/// Event payload for font change notifications.
#[derive(Debug, Clone)]
pub struct FontChangeEvent {
    /// The old LAF type name (e.g., "Metal", "FlatDark").
    pub old_laf: String,
    /// The new LAF type name.
    pub new_laf: String,
    /// Whether the change was a full LAF switch (vs. a preference tweak).
    pub is_full_switch: bool,
}

impl FontChangeEvent {
    /// Create a new font change event.
    pub fn new(
        old_laf: impl Into<String>,
        new_laf: impl Into<String>,
        is_full_switch: bool,
    ) -> Self {
        Self {
            old_laf: old_laf.into(),
            new_laf: new_laf.into(),
            is_full_switch,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_listener_name() {
        let listener = DefaultFontChangeListener;
        assert_eq!(listener.name(), "DefaultFontChangeListener");
    }

    #[test]
    fn composite_listener_add_and_count() {
        let mut composite = CompositeFontChangeListener::new();
        assert!(composite.is_empty());
        composite.add(Box::new(DefaultFontChangeListener));
        assert_eq!(composite.len(), 1);
        assert!(!composite.is_empty());
    }

    #[test]
    fn composite_listener_name() {
        let composite = CompositeFontChangeListener::new();
        assert_eq!(composite.name(), "CompositeFontChangeListener");
    }

    #[test]
    fn font_change_event_creation() {
        let event = FontChangeEvent::new("Metal", "FlatDark", true);
        assert_eq!(event.old_laf, "Metal");
        assert_eq!(event.new_laf, "FlatDark");
        assert!(event.is_full_switch);
    }

    #[test]
    fn font_change_event_clone() {
        let event = FontChangeEvent::new("A", "B", false);
        let cloned = event.clone();
        assert_eq!(cloned.old_laf, "A");
        assert_eq!(cloned.new_laf, "B");
        assert!(!cloned.is_full_switch);
    }

    #[test]
    fn composite_delegates_to_children() {
        // Just verify the composite calls through without panicking
        let mut composite = CompositeFontChangeListener::new();
        composite.add(Box::new(DefaultFontChangeListener));
        composite.add(Box::new(DefaultFontChangeListener));

        let mut registry = ComponentFontRegistry::new();
        composite.laf_changed(&mut registry);
    }
}
