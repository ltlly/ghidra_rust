//! Decompiler margin service -- Rust port of the `DecompilerMarginService`
//! and `DecompilerMarginProvider` interfaces from
//! `ghidra.app.plugin.core.decompile.DecompilerProvider`.
//!
//! In Ghidra, the `DecompilerProvider` implements `DecompilerMarginService`
//! which allows other plugins to add custom margin providers to the
//! decompiler panel's left margin area.  Margin providers can render
//! annotations such as:
//!
//! - Breakpoint markers
//! - Bookmark indicators
//! - Version control change indicators
//! - Coverage highlights
//!
//! # Architecture
//!
//! ```text
//! DecompilerMarginService
//!   └── Vec<MarginProviderRegistration>
//!         ├── { id, provider, priority, enabled, width_px }
//!         ├── { id, provider, priority, enabled, width_px }
//!         └── ...
//!
//! DecompilerMarginProvider (trait)
//!   ├── name() -> &str
//!   ├── paint() -> MarginPaintResult
//!   ├── get_width() -> usize
//!   └── dispose()
//! ```

use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// MarginPaintResult -- result of painting a margin line
// ---------------------------------------------------------------------------

/// The result of painting a single line in the margin.
///
/// Each margin provider returns a paint result for each visible line,
/// indicating what (if anything) to render.
#[derive(Debug, Clone)]
pub enum MarginPaintResult {
    /// No annotation for this line.
    Empty,
    /// A filled marker (e.g., a breakpoint dot).
    Marker {
        /// The color of the marker (as an RGBA hex value).
        color: u32,
        /// The tooltip text to show on hover.
        tooltip: Option<String>,
    },
    /// An icon annotation.
    Icon {
        /// The icon identifier (for lookup in the icon registry).
        icon_id: String,
        /// The tooltip text to show on hover.
        tooltip: Option<String>,
    },
    /// A colored highlight band across the margin.
    Highlight {
        /// The highlight color (as an RGBA hex value).
        color: u32,
        /// The opacity (0.0 = transparent, 1.0 = opaque).
        opacity: f32,
    },
}

// ---------------------------------------------------------------------------
// MarginLineInfo -- context for painting a margin line
// ---------------------------------------------------------------------------

/// Information about the line being painted in the margin.
///
/// Margin providers receive this when asked to paint, so they can
/// determine what annotation (if any) to show.
#[derive(Debug, Clone)]
pub struct MarginLineInfo {
    /// The 0-based line number in the decompiler output.
    pub line_number: usize,
    /// The address of the first token on this line (if any).
    pub address: Option<u64>,
    /// Whether this line is part of the current function's body.
    pub in_function_body: bool,
    /// The text of the line (for pattern matching).
    pub line_text: Option<String>,
}

// ---------------------------------------------------------------------------
// DecompilerMarginProvider -- trait for custom margin renderers
// ---------------------------------------------------------------------------

/// A trait for objects that can render annotations in the decompiler margin.
///
/// In Ghidra, this is the `DecompilerMarginProvider` interface.  Each
/// provider is responsible for painting one or more lines of the margin.
pub trait DecompilerMarginProvider: std::fmt::Debug {
    /// A unique name for this margin provider (e.g., "Breakpoint Margin").
    fn name(&self) -> &str;

    /// Paint the margin for a specific line.
    ///
    /// Returns the paint result indicating what to render for this line.
    fn paint(&self, line_info: &MarginLineInfo) -> MarginPaintResult;

    /// The width of this margin provider in pixels.
    ///
    /// If multiple providers are active, their widths are summed.
    fn get_width(&self) -> usize;

    /// Whether this provider is currently enabled.
    fn is_enabled(&self) -> bool {
        true
    }

    /// Set the enabled state.
    fn set_enabled(&mut self, _enabled: bool) {}

    /// Called when the provider is being removed from the margin service.
    fn dispose(&mut self) {}
}

// ---------------------------------------------------------------------------
// MarginProviderRegistration -- a registered margin provider
// ---------------------------------------------------------------------------

/// A registered margin provider with its configuration.
#[derive(Debug)]
pub struct MarginProviderRegistration {
    /// A unique identifier for this registration.
    pub id: String,
    /// The margin provider.
    pub provider: Box<dyn DecompilerMarginProvider>,
    /// The priority (lower values are painted first, closer to the text).
    pub priority: i32,
    /// Whether this registration is currently active.
    pub active: bool,
}

// ---------------------------------------------------------------------------
// MarginInteraction -- user interaction with the margin
// ---------------------------------------------------------------------------

/// An interaction event in the margin area.
#[derive(Debug, Clone)]
pub struct MarginInteraction {
    /// The line number where the interaction occurred.
    pub line_number: usize,
    /// The x coordinate within the margin (in pixels).
    pub x: usize,
    /// The y coordinate within the margin (in pixels).
    pub y: usize,
    /// The type of interaction.
    pub kind: MarginInteractionKind,
}

/// The type of user interaction in the margin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarginInteractionKind {
    /// A single mouse click.
    Click,
    /// A double mouse click.
    DoubleClick,
    /// A right-click (context menu).
    RightClick,
    /// A mouse hover.
    Hover,
}

// ---------------------------------------------------------------------------
// DecompilerMarginServiceImpl -- the margin service implementation
// ---------------------------------------------------------------------------

/// The decompiler margin service implementation.
///
/// Manages a collection of margin providers that render annotations in
/// the decompiler panel's left margin.  Providers are registered with
/// a priority that controls their ordering (lower priority = closer to
/// the text).
///
/// # Lifecycle
///
/// 1. Created during provider construction.
/// 2. Other plugins call `add_margin_provider()` to register providers.
/// 3. Providers are called to paint for each visible line.
/// 4. `remove_margin_provider()` or `dispose()` cleans up.
///
/// # Painting Order
///
/// Providers are painted from highest priority (furthest from text) to
/// lowest priority (closest to text), so lower-priority providers
/// visually overlay higher-priority ones.
#[derive(Debug)]
pub struct DecompilerMarginServiceImpl {
    /// Registered margin providers, keyed by id.
    registrations: BTreeMap<String, MarginProviderRegistration>,
    /// Next auto-generated id.
    next_id: usize,
    /// Total width of all active providers (cached).
    total_width: usize,
    /// Whether the width cache is dirty.
    width_dirty: bool,
    /// Whether the service has been disposed.
    disposed: bool,
}

impl DecompilerMarginServiceImpl {
    /// Create a new margin service.
    pub fn new() -> Self {
        Self {
            registrations: BTreeMap::new(),
            next_id: 0,
            total_width: 0,
            width_dirty: true,
            disposed: false,
        }
    }

    /// Add a margin provider with the given priority.
    ///
    /// Returns the registration id.
    pub fn add_margin_provider(
        &mut self,
        provider: Box<dyn DecompilerMarginProvider>,
        priority: i32,
    ) -> String {
        let id = format!("margin_{}", self.next_id);
        self.next_id += 1;

        self.registrations.insert(
            id.clone(),
            MarginProviderRegistration {
                id: id.clone(),
                provider,
                priority,
                active: true,
            },
        );

        self.width_dirty = true;
        id
    }

    /// Remove a margin provider by its registration id.
    ///
    /// Returns `true` if the provider was found and removed.
    pub fn remove_margin_provider(&mut self, id: &str) -> bool {
        if let Some(mut reg) = self.registrations.remove(id) {
            reg.provider.dispose();
            self.width_dirty = true;
            true
        } else {
            false
        }
    }

    /// Returns the number of registered providers.
    pub fn provider_count(&self) -> usize {
        self.registrations.len()
    }

    /// Returns the number of active (enabled) providers.
    pub fn active_provider_count(&self) -> usize {
        self.registrations
            .values()
            .filter(|r| r.active && r.provider.is_enabled())
            .count()
    }

    /// Get the total width of all active providers in pixels.
    pub fn total_width(&mut self) -> usize {
        if self.width_dirty {
            self.total_width = self
                .registrations
                .values()
                .filter(|r| r.active && r.provider.is_enabled())
                .map(|r| r.provider.get_width())
                .sum();
            self.width_dirty = false;
        }
        self.total_width
    }

    /// Paint the margin for a specific line.
    ///
    /// Returns a map of provider id to paint result, in priority order
    /// (highest priority first).
    pub fn paint_line(&self, line_info: &MarginLineInfo) -> Vec<(String, MarginPaintResult)> {
        let mut results = Vec::new();

        // Collect all active registrations sorted by priority (highest first).
        let mut sorted: Vec<_> = self
            .registrations
            .values()
            .filter(|r| r.active && r.provider.is_enabled())
            .collect();
        sorted.sort_by(|a, b| b.priority.cmp(&a.priority));

        for reg in sorted {
            let result = reg.provider.paint(line_info);
            results.push((reg.id.clone(), result));
        }

        results
    }

    /// Handle a user interaction in the margin.
    ///
    /// Returns the id of the provider that handled the interaction, if any.
    pub fn handle_interaction(&self, interaction: &MarginInteraction) -> Option<String> {
        // In the full implementation, this delegates to the provider
        // whose margin area contains the click coordinates.
        // For now, we return the first active provider.
        self.registrations
            .values()
            .find(|r| r.active && r.provider.is_enabled())
            .map(|r| r.id.clone())
    }

    /// Get a reference to a provider registration by id.
    pub fn get_provider(&self, id: &str) -> Option<&MarginProviderRegistration> {
        self.registrations.get(id)
    }

    /// Get all provider ids.
    pub fn provider_ids(&self) -> Vec<String> {
        self.registrations.keys().cloned().collect()
    }

    /// Check whether the service has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Dispose the margin service, cleaning up all providers.
    pub fn dispose(&mut self) {
        let keys: Vec<_> = self.registrations.keys().cloned().collect();
        for key in keys {
            if let Some(mut reg) = self.registrations.remove(&key) {
                reg.provider.dispose();
            }
        }
        self.total_width = 0;
        self.width_dirty = true;
        self.disposed = true;
    }
}

impl Default for DecompilerMarginServiceImpl {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Example margin providers
// ---------------------------------------------------------------------------

/// A simple marker margin provider that shows colored dots.
///
/// This models a typical breakpoint or bookmark margin provider.
#[derive(Debug)]
pub struct MarkerMarginProvider {
    name: String,
    width: usize,
    enabled: bool,
    /// A map of line number to (color, tooltip).
    markers: BTreeMap<usize, (u32, Option<String>)>,
}

impl MarkerMarginProvider {
    /// Create a new marker margin provider.
    pub fn new(name: impl Into<String>, width: usize) -> Self {
        Self {
            name: name.into(),
            width,
            enabled: true,
            markers: BTreeMap::new(),
        }
    }

    /// Add a marker at a specific line.
    pub fn add_marker(&mut self, line: usize, color: u32, tooltip: Option<String>) {
        self.markers.insert(line, (color, tooltip));
    }

    /// Remove a marker at a specific line.
    pub fn remove_marker(&mut self, line: usize) {
        self.markers.remove(&line);
    }

    /// Get the number of markers.
    pub fn marker_count(&self) -> usize {
        self.markers.len()
    }

    /// Clear all markers.
    pub fn clear_markers(&mut self) {
        self.markers.clear();
    }
}

impl DecompilerMarginProvider for MarkerMarginProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn paint(&self, line_info: &MarginLineInfo) -> MarginPaintResult {
        if let Some(&(color, ref tooltip)) = self.markers.get(&line_info.line_number) {
            MarginPaintResult::Marker {
                color,
                tooltip: tooltip.clone(),
            }
        } else {
            MarginPaintResult::Empty
        }
    }

    fn get_width(&self) -> usize {
        self.width
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    fn dispose(&mut self) {
        self.markers.clear();
        self.enabled = false;
    }
}

/// A highlight band margin provider.
///
/// Renders a colored band in the margin for lines that match certain
/// criteria (e.g., modified lines in version control).
#[derive(Debug)]
pub struct HighlightMarginProvider {
    name: String,
    width: usize,
    enabled: bool,
    /// A map of line number to (color, opacity).
    highlights: BTreeMap<usize, (u32, f32)>,
}

impl HighlightMarginProvider {
    /// Create a new highlight margin provider.
    pub fn new(name: impl Into<String>, width: usize) -> Self {
        Self {
            name: name.into(),
            width,
            enabled: true,
            highlights: BTreeMap::new(),
        }
    }

    /// Add a highlight at a specific line.
    pub fn add_highlight(&mut self, line: usize, color: u32, opacity: f32) {
        self.highlights.insert(line, (color, opacity));
    }

    /// Remove a highlight at a specific line.
    pub fn remove_highlight(&mut self, line: usize) {
        self.highlights.remove(&line);
    }

    /// Clear all highlights.
    pub fn clear_highlights(&mut self) {
        self.highlights.clear();
    }
}

impl DecompilerMarginProvider for HighlightMarginProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn paint(&self, line_info: &MarginLineInfo) -> MarginPaintResult {
        if let Some(&(color, opacity)) = self.highlights.get(&line_info.line_number) {
            MarginPaintResult::Highlight { color, opacity }
        } else {
            MarginPaintResult::Empty
        }
    }

    fn get_width(&self) -> usize {
        self.width
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    fn dispose(&mut self) {
        self.highlights.clear();
        self.enabled = false;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- MarginPaintResult --

    #[test]
    fn test_paint_result_empty() {
        let result = MarginPaintResult::Empty;
        assert!(matches!(result, MarginPaintResult::Empty));
    }

    #[test]
    fn test_paint_result_marker() {
        let result = MarginPaintResult::Marker {
            color: 0xFF0000FF,
            tooltip: Some("Breakpoint".into()),
        };
        if let MarginPaintResult::Marker { color, tooltip } = result {
            assert_eq!(color, 0xFF0000FF);
            assert_eq!(tooltip.as_deref(), Some("Breakpoint"));
        } else {
            panic!("expected Marker");
        }
    }

    #[test]
    fn test_paint_result_highlight() {
        let result = MarginPaintResult::Highlight {
            color: 0x00FF00FF,
            opacity: 0.5,
        };
        if let MarginPaintResult::Highlight { color, opacity } = result {
            assert_eq!(color, 0x00FF00FF);
            assert!((opacity - 0.5).abs() < f32::EPSILON);
        } else {
            panic!("expected Highlight");
        }
    }

    // -- MarginLineInfo --

    #[test]
    fn test_margin_line_info() {
        let info = MarginLineInfo {
            line_number: 42,
            address: Some(0x4000),
            in_function_body: true,
            line_text: Some("int x = 0;".into()),
        };
        assert_eq!(info.line_number, 42);
        assert!(info.in_function_body);
    }

    // -- MarkerMarginProvider --

    #[test]
    fn test_marker_provider_new() {
        let provider = MarkerMarginProvider::new("Breakpoints", 16);
        assert_eq!(provider.name(), "Breakpoints");
        assert_eq!(provider.get_width(), 16);
        assert!(provider.is_enabled());
        assert_eq!(provider.marker_count(), 0);
    }

    #[test]
    fn test_marker_provider_paint_empty() {
        let provider = MarkerMarginProvider::new("Test", 10);
        let info = MarginLineInfo {
            line_number: 5,
            address: None,
            in_function_body: true,
            line_text: None,
        };
        assert!(matches!(provider.paint(&info), MarginPaintResult::Empty));
    }

    #[test]
    fn test_marker_provider_paint_marker() {
        let mut provider = MarkerMarginProvider::new("Test", 10);
        provider.add_marker(5, 0xFF0000FF, Some("BP".into()));

        let info = MarginLineInfo {
            line_number: 5,
            address: Some(0x1000),
            in_function_body: true,
            line_text: None,
        };
        let result = provider.paint(&info);
        if let MarginPaintResult::Marker { color, tooltip } = result {
            assert_eq!(color, 0xFF0000FF);
            assert_eq!(tooltip.as_deref(), Some("BP"));
        } else {
            panic!("expected Marker");
        }
    }

    #[test]
    fn test_marker_provider_remove() {
        let mut provider = MarkerMarginProvider::new("Test", 10);
        provider.add_marker(1, 0xFF, None);
        provider.add_marker(2, 0xFF, None);
        assert_eq!(provider.marker_count(), 2);

        provider.remove_marker(1);
        assert_eq!(provider.marker_count(), 1);
    }

    #[test]
    fn test_marker_provider_clear() {
        let mut provider = MarkerMarginProvider::new("Test", 10);
        provider.add_marker(1, 0xFF, None);
        provider.add_marker(2, 0xFF, None);
        provider.clear_markers();
        assert_eq!(provider.marker_count(), 0);
    }

    #[test]
    fn test_marker_provider_enable_disable() {
        let mut provider = MarkerMarginProvider::new("Test", 10);
        assert!(provider.is_enabled());

        provider.set_enabled(false);
        assert!(!provider.is_enabled());
    }

    #[test]
    fn test_marker_provider_dispose() {
        let mut provider = MarkerMarginProvider::new("Test", 10);
        provider.add_marker(1, 0xFF, None);
        provider.dispose();
        assert!(!provider.is_enabled());
        assert_eq!(provider.marker_count(), 0);
    }

    // -- HighlightMarginProvider --

    #[test]
    fn test_highlight_provider_new() {
        let provider = HighlightMarginProvider::new("Changes", 8);
        assert_eq!(provider.name(), "Changes");
        assert_eq!(provider.get_width(), 8);
    }

    #[test]
    fn test_highlight_provider_paint() {
        let mut provider = HighlightMarginProvider::new("Test", 8);
        provider.add_highlight(10, 0x00FF00FF, 0.3);

        let info = MarginLineInfo {
            line_number: 10,
            address: Some(0x2000),
            in_function_body: true,
            line_text: None,
        };
        let result = provider.paint(&info);
        if let MarginPaintResult::Highlight { color, opacity } = result {
            assert_eq!(color, 0x00FF00FF);
            assert!((opacity - 0.3).abs() < f32::EPSILON);
        } else {
            panic!("expected Highlight");
        }
    }

    #[test]
    fn test_highlight_provider_no_highlight() {
        let provider = HighlightMarginProvider::new("Test", 8);
        let info = MarginLineInfo {
            line_number: 5,
            address: None,
            in_function_body: false,
            line_text: None,
        };
        assert!(matches!(provider.paint(&info), MarginPaintResult::Empty));
    }

    // -- DecompilerMarginServiceImpl --

    #[test]
    fn test_margin_service_new() {
        let service = DecompilerMarginServiceImpl::new();
        assert_eq!(service.provider_count(), 0);
        assert!(!service.is_disposed());
    }

    #[test]
    fn test_margin_service_add_provider() {
        let mut service = DecompilerMarginServiceImpl::new();
        let provider = MarkerMarginProvider::new("BP", 16);
        let id = service.add_margin_provider(Box::new(provider), 10);
        assert_eq!(service.provider_count(), 1);
        assert!(id.starts_with("margin_"));
    }

    #[test]
    fn test_margin_service_remove_provider() {
        let mut service = DecompilerMarginServiceImpl::new();
        let provider = MarkerMarginProvider::new("BP", 16);
        let id = service.add_margin_provider(Box::new(provider), 10);
        assert_eq!(service.provider_count(), 1);

        assert!(service.remove_margin_provider(&id));
        assert_eq!(service.provider_count(), 0);

        // Removing again returns false.
        assert!(!service.remove_margin_provider(&id));
    }

    #[test]
    fn test_margin_service_remove_nonexistent() {
        let mut service = DecompilerMarginServiceImpl::new();
        assert!(!service.remove_margin_provider("nonexistent"));
    }

    #[test]
    fn test_margin_service_total_width() {
        let mut service = DecompilerMarginServiceImpl::new();
        service.add_margin_provider(Box::new(MarkerMarginProvider::new("A", 10)), 1);
        service.add_margin_provider(Box::new(HighlightMarginProvider::new("B", 8)), 2);
        assert_eq!(service.total_width(), 18);
    }

    #[test]
    fn test_margin_service_total_width_with_disabled() {
        let mut service = DecompilerMarginServiceImpl::new();
        let mut provider = MarkerMarginProvider::new("A", 10);
        provider.set_enabled(false);
        service.add_margin_provider(Box::new(provider), 1);
        service.add_margin_provider(Box::new(HighlightMarginProvider::new("B", 8)), 2);
        // Only the enabled provider counts.
        assert_eq!(service.total_width(), 8);
    }

    #[test]
    fn test_margin_service_paint_line() {
        let mut service = DecompilerMarginServiceImpl::new();
        let mut bp = MarkerMarginProvider::new("BP", 10);
        bp.add_marker(5, 0xFF0000FF, Some("break".into()));
        service.add_margin_provider(Box::new(bp), 100);

        let info = MarginLineInfo {
            line_number: 5,
            address: Some(0x1000),
            in_function_body: true,
            line_text: None,
        };
        let results = service.paint_line(&info);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0].1, MarginPaintResult::Marker { .. }));
    }

    #[test]
    fn test_margin_service_paint_line_priority_order() {
        let mut service = DecompilerMarginServiceImpl::new();
        service.add_margin_provider(
            Box::new(MarkerMarginProvider::new("Low", 10)),
            10, // low priority
        );
        service.add_margin_provider(
            Box::new(HighlightMarginProvider::new("High", 8)),
            100, // high priority
        );

        let info = MarginLineInfo {
            line_number: 0,
            address: None,
            in_function_body: true,
            line_text: None,
        };
        let results = service.paint_line(&info);
        assert_eq!(results.len(), 2);
        // High priority first.
        assert_eq!(results[0].0, "margin_1");
        assert_eq!(results[1].0, "margin_0");
    }

    #[test]
    fn test_margin_service_active_count() {
        let mut service = DecompilerMarginServiceImpl::new();
        service.add_margin_provider(Box::new(MarkerMarginProvider::new("A", 10)), 1);
        service.add_margin_provider(Box::new(MarkerMarginProvider::new("B", 10)), 2);
        assert_eq!(service.active_provider_count(), 2);
    }

    #[test]
    fn test_margin_service_provider_ids() {
        let mut service = DecompilerMarginServiceImpl::new();
        let id1 = service.add_margin_provider(Box::new(MarkerMarginProvider::new("A", 10)), 1);
        let id2 = service.add_margin_provider(Box::new(MarkerMarginProvider::new("B", 10)), 2);
        let ids = service.provider_ids();
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
    }

    #[test]
    fn test_margin_service_get_provider() {
        let mut service = DecompilerMarginServiceImpl::new();
        let id = service.add_margin_provider(Box::new(MarkerMarginProvider::new("Test", 10)), 1);
        let reg = service.get_provider(&id).unwrap();
        assert_eq!(reg.provider.name(), "Test");
        assert_eq!(reg.priority, 1);
        assert!(reg.active);
    }

    #[test]
    fn test_margin_service_get_provider_nonexistent() {
        let service = DecompilerMarginServiceImpl::new();
        assert!(service.get_provider("nonexistent").is_none());
    }

    #[test]
    fn test_margin_service_dispose() {
        let mut service = DecompilerMarginServiceImpl::new();
        service.add_margin_provider(Box::new(MarkerMarginProvider::new("A", 10)), 1);
        service.add_margin_provider(Box::new(MarkerMarginProvider::new("B", 10)), 2);

        service.dispose();
        assert!(service.is_disposed());
        assert_eq!(service.provider_count(), 0);
        assert_eq!(service.total_width(), 0);
    }

    #[test]
    fn test_margin_service_default() {
        let service = DecompilerMarginServiceImpl::default();
        assert_eq!(service.provider_count(), 0);
    }

    // -- MarginInteraction --

    #[test]
    fn test_margin_interaction() {
        let interaction = MarginInteraction {
            line_number: 5,
            x: 8,
            y: 100,
            kind: MarginInteractionKind::Click,
        };
        assert_eq!(interaction.line_number, 5);
        assert_eq!(interaction.kind, MarginInteractionKind::Click);
    }

    #[test]
    fn test_margin_interaction_kinds() {
        assert_ne!(
            MarginInteractionKind::Click,
            MarginInteractionKind::DoubleClick
        );
        assert_ne!(
            MarginInteractionKind::RightClick,
            MarginInteractionKind::Hover
        );
    }

    // -- Integration tests --

    #[test]
    fn test_full_margin_workflow() {
        let mut service = DecompilerMarginServiceImpl::new();

        // Add a breakpoint provider.
        let mut bp = MarkerMarginProvider::new("Breakpoints", 16);
        bp.add_marker(10, 0xFF0000FF, Some("BP at main+0x10".into()));
        bp.add_marker(25, 0xFF0000FF, Some("BP at main+0x20".into()));
        let bp_id = service.add_margin_provider(Box::new(bp), 100);

        // Add a highlight provider.
        let mut hl = HighlightMarginProvider::new("Changes", 8);
        hl.add_highlight(10, 0x00FF0080, 0.5);
        hl.add_highlight(15, 0x00FF0080, 0.5);
        let hl_id = service.add_margin_provider(Box::new(hl), 50);

        // Verify counts and widths.
        assert_eq!(service.provider_count(), 2);
        assert_eq!(service.active_provider_count(), 2);
        assert_eq!(service.total_width(), 24); // 16 + 8

        // Paint line 10 (should have both breakpoint and highlight).
        let info_10 = MarginLineInfo {
            line_number: 10,
            address: Some(0x4000),
            in_function_body: true,
            line_text: Some("x = func();".into()),
        };
        let results = service.paint_line(&info_10);
        assert_eq!(results.len(), 2);
        // Higher priority (bp=100) first.
        assert!(matches!(&results[0].1, MarginPaintResult::Marker { .. }));
        assert!(matches!(&results[1].1, MarginPaintResult::Highlight { .. }));

        // Paint line 15 (should have only highlight).
        let info_15 = MarginLineInfo {
            line_number: 15,
            address: Some(0x4020),
            in_function_body: true,
            line_text: None,
        };
        let results = service.paint_line(&info_15);
        assert_eq!(results.len(), 2);
        assert!(matches!(&results[0].1, MarginPaintResult::Empty));
        assert!(matches!(&results[1].1, MarginPaintResult::Highlight { .. }));

        // Paint line 20 (should be empty for both).
        let info_20 = MarginLineInfo {
            line_number: 20,
            address: None,
            in_function_body: true,
            line_text: None,
        };
        let results = service.paint_line(&info_20);
        assert!(results.iter().all(|(_, r)| matches!(r, MarginPaintResult::Empty)));

        // Remove the breakpoint provider.
        assert!(service.remove_margin_provider(&bp_id));
        assert_eq!(service.provider_count(), 1);
        assert_eq!(service.total_width(), 8);

        // Clean up.
        service.dispose();
        assert!(service.is_disposed());
    }

    #[test]
    fn test_margin_service_width_cache_invalidation() {
        let mut service = DecompilerMarginServiceImpl::new();
        service.add_margin_provider(Box::new(MarkerMarginProvider::new("A", 10)), 1);
        assert_eq!(service.total_width(), 10);

        // Adding a provider should invalidate the cache.
        service.add_margin_provider(Box::new(HighlightMarginProvider::new("B", 5)), 2);
        assert_eq!(service.total_width(), 15);

        // Removing a provider should invalidate the cache.
        let ids = service.provider_ids();
        service.remove_margin_provider(&ids[0]);
        assert_eq!(service.total_width(), 5);
    }
}
