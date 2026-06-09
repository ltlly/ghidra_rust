//! Diff Apply Panel -- UI logic for configuring and applying program differences.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.diff.DiffApplyPanel` Java class.
//!
//! The `DiffApplyPanel` manages the user-facing configuration for how
//! differences between two programs are applied (merged).  It holds the
//! current [`ProgramMergeFilter`](super::merge_filter::ProgramMergeFilter),
//! provides per-category action selection, and exposes operations such as
//! "apply selected", "ignore selected", and "apply all".
//!
//! In the original Java, `DiffApplyPanel` extends `JPanel` and wires up
//! radio-button groups for each merge category.  In this Rust port we
//! capture the logical state and behaviour without the Swing dependency.
//!
//! # Key types
//!
//! - [`DiffApplyPanel`] -- the panel state
//! - [`ApplyPanelEvent`] -- events emitted by the panel
//! - [`ApplyPanelListener`] -- trait for receiving panel events

use std::sync::{Arc, Mutex};

use super::diff_controller::{AddressSet, DiffController};
use super::merge_filter::{MergeAction, MergeCategory, ProgramMergeFilter};
use super::program_diff_plugin::DiffPluginListener;
use super::{DiffResult, DiffType, ProgramDiffFilter, ProgramSnapshot, diff_programs};

// ---------------------------------------------------------------------------
// ApplyPanelEvent
// ---------------------------------------------------------------------------

/// Events emitted by the diff apply panel.
#[derive(Debug, Clone)]
pub enum ApplyPanelEvent {
    /// The merge filter was changed.
    FilterChanged,
    /// An apply operation was requested.
    ApplyRequested {
        /// The address set to apply.
        address_count: u64,
    },
    /// An ignore operation was requested.
    IgnoreRequested {
        /// The address set to ignore.
        address_count: u64,
    },
    /// The "apply all" action was triggered.
    ApplyAllRequested,
    /// The "ignore all" action was triggered.
    IgnoreAllRequested,
    /// The "replace all" action was triggered.
    ReplaceAllRequested,
}

// ---------------------------------------------------------------------------
// ApplyPanelListener
// ---------------------------------------------------------------------------

/// Trait for receiving diff apply panel events.
pub trait ApplyPanelListener: Send + Sync {
    /// Called when a panel event occurs.
    fn on_event(&self, event: &ApplyPanelEvent);
}

/// A simple listener that records events for testing.
#[derive(Debug, Default)]
pub struct RecordingApplyListener {
    events: Mutex<Vec<ApplyPanelEvent>>,
}

impl RecordingApplyListener {
    /// Create a new recording listener.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the number of events received.
    pub fn event_count(&self) -> usize {
        self.events.lock().unwrap().len()
    }

    /// Get a snapshot of all received events.
    pub fn events(&self) -> Vec<ApplyPanelEvent> {
        self.events.lock().unwrap().clone()
    }
}

impl ApplyPanelListener for RecordingApplyListener {
    fn on_event(&self, event: &ApplyPanelEvent) {
        self.events.lock().unwrap().push(event.clone());
    }
}

// ---------------------------------------------------------------------------
// CategoryActionState
// ---------------------------------------------------------------------------

/// The action selected for a single merge category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CategoryActionState {
    /// The merge category.
    pub category: MergeCategory,
    /// The selected action.
    pub action: MergeAction,
    /// Whether this category supports the Merge action (vs only Ignore/Replace).
    pub supports_merge: bool,
}

impl CategoryActionState {
    /// Create a new category action state.
    pub fn new(category: MergeCategory, action: MergeAction, supports_merge: bool) -> Self {
        Self {
            category,
            action,
            supports_merge,
        }
    }

    /// Get the label for the current action.
    pub fn action_label(&self) -> &'static str {
        self.action.label()
    }

    /// Cycle to the next action.
    ///
    /// For categories that support merge: Ignore -> Replace -> Merge -> Ignore.
    /// For categories that do not: Ignore -> Replace -> Ignore.
    pub fn cycle_action(&mut self) {
        self.action = match self.action {
            MergeAction::Ignore => MergeAction::Replace,
            MergeAction::Replace => {
                if self.supports_merge {
                    MergeAction::Merge
                } else {
                    MergeAction::Ignore
                }
            }
            MergeAction::Merge => MergeAction::Ignore,
        };
    }
}

// ---------------------------------------------------------------------------
// DiffApplyPanel
// ---------------------------------------------------------------------------

/// The diff apply panel state.
///
/// Manages the user-facing configuration for how differences are applied
/// during a merge operation.
///
/// Ported from Ghidra's `DiffApplyPanel` Java class.
///
/// # Example
///
/// ```rust
/// use ghidra_features::programdiff::diff_apply_panel::*;
/// use ghidra_features::programdiff::merge_filter::*;
/// use ghidra_features::programdiff::*;
///
/// let mut panel = DiffApplyPanel::new();
///
/// // Set the action for a specific category
/// panel.set_category_action(MergeCategory::Bytes, MergeAction::Replace);
/// assert_eq!(
///     panel.category_action(MergeCategory::Bytes),
///     Some(MergeAction::Replace)
/// );
///
/// // Use a preset
/// panel.apply_preset(ApplyPreset::MergeAll);
/// assert_eq!(
///     panel.category_action(MergeCategory::Bytes),
///     Some(MergeAction::Merge)
/// );
/// ```
pub struct DiffApplyPanel {
    /// The current merge filter.
    merge_filter: ProgramMergeFilter,
    /// Per-category action states.
    category_states: Vec<CategoryActionState>,
    /// Event listeners.
    listeners: Vec<Arc<dyn ApplyPanelListener>>,
    /// Whether the panel is enabled (can accept user input).
    enabled: bool,
}

impl DiffApplyPanel {
    /// Create a new diff apply panel with default settings.
    pub fn new() -> Self {
        let merge_filter = ProgramMergeFilter::defaults();
        let category_states = Self::default_category_states();
        Self {
            merge_filter,
            category_states,
            listeners: Vec::new(),
            enabled: true,
        }
    }

    /// Create a diff apply panel with a specific merge filter.
    pub fn with_filter(merge_filter: ProgramMergeFilter) -> Self {
        let category_states = Self::default_category_states();
        Self {
            merge_filter,
            category_states,
            listeners: Vec::new(),
            enabled: true,
        }
    }

    /// Build the default category states.
    fn default_category_states() -> Vec<CategoryActionState> {
        // Categories that support Merge (in addition to Ignore/Replace).
        const MERGEABLE: &[MergeCategory] = &[
            MergeCategory::ProgramContext,
            MergeCategory::Bytes,
            MergeCategory::Instructions,
            MergeCategory::Data,
            MergeCategory::CodeUnits,
            MergeCategory::Equates,
            MergeCategory::References,
            MergeCategory::Functions,
            MergeCategory::Symbols,
            MergeCategory::Bookmarks,
            MergeCategory::FunctionTags,
        ];

        // All categories in display order.
        let all_categories = [
            MergeCategory::ProgramContext,
            MergeCategory::Bytes,
            MergeCategory::Instructions,
            MergeCategory::Data,
            MergeCategory::CodeUnits,
            MergeCategory::Equates,
            MergeCategory::References,
            MergeCategory::Functions,
            MergeCategory::Symbols,
            MergeCategory::PrimarySymbol,
            MergeCategory::Bookmarks,
            MergeCategory::PlateComments,
            MergeCategory::PreComments,
            MergeCategory::EolComments,
            MergeCategory::RepeatableComments,
            MergeCategory::PostComments,
            MergeCategory::Comments,
            MergeCategory::Properties,
            MergeCategory::FunctionTags,
            MergeCategory::SourceMap,
            MergeCategory::All,
        ];

        all_categories
            .iter()
            .map(|cat| {
                let supports_merge = MERGEABLE.contains(cat);
                CategoryActionState::new(*cat, MergeAction::Ignore, supports_merge)
            })
            .collect()
    }

    // -- Listener management -------------------------------------------------

    /// Add a listener for panel events.
    pub fn add_listener(&mut self, listener: Arc<dyn ApplyPanelListener>) {
        self.listeners.push(listener);
    }

    /// Remove all listeners.
    pub fn clear_listeners(&mut self) {
        self.listeners.clear();
    }

    /// Fire an event to all listeners.
    fn fire_event(&self, event: ApplyPanelEvent) {
        for listener in &self.listeners {
            listener.on_event(&event);
        }
    }

    // -- Enabled state --------------------------------------------------------

    /// Check if the panel is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set whether the panel is enabled.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    // -- Category actions -----------------------------------------------------

    /// Get the action for a specific category.
    pub fn category_action(&self, category: MergeCategory) -> Option<MergeAction> {
        self.category_states
            .iter()
            .find(|s| s.category == category)
            .map(|s| s.action)
    }

    /// Set the action for a specific category.
    pub fn set_category_action(&mut self, category: MergeCategory, action: MergeAction) {
        if let Some(state) = self.category_states.iter_mut().find(|s| s.category == category) {
            state.action = action;
            self.sync_to_merge_filter();
            self.fire_event(ApplyPanelEvent::FilterChanged);
        }
    }

    /// Cycle the action for a specific category.
    pub fn cycle_category_action(&mut self, category: MergeCategory) {
        if let Some(state) = self.category_states.iter_mut().find(|s| s.category == category) {
            state.cycle_action();
            self.sync_to_merge_filter();
            self.fire_event(ApplyPanelEvent::FilterChanged);
        }
    }

    /// Get all category action states.
    pub fn category_states(&self) -> &[CategoryActionState] {
        &self.category_states
    }

    // -- Presets --------------------------------------------------------------

    /// Apply a preset configuration.
    pub fn apply_preset(&mut self, preset: ApplyPreset) {
        let action = preset.action();
        for state in &mut self.category_states {
            if preset.applies_to(state.category) {
                state.action = action;
            }
        }
        self.sync_to_merge_filter();
        self.fire_event(ApplyPanelEvent::FilterChanged);
    }

    // -- Bulk operations ------------------------------------------------------

    /// Set all categories to Ignore.
    pub fn ignore_all(&mut self) {
        for state in &mut self.category_states {
            state.action = MergeAction::Ignore;
        }
        self.sync_to_merge_filter();
        self.fire_event(ApplyPanelEvent::IgnoreAllRequested);
        self.fire_event(ApplyPanelEvent::FilterChanged);
    }

    /// Set all categories to Replace.
    pub fn replace_all(&mut self) {
        for state in &mut self.category_states {
            state.action = MergeAction::Replace;
        }
        self.sync_to_merge_filter();
        self.fire_event(ApplyPanelEvent::ReplaceAllRequested);
        self.fire_event(ApplyPanelEvent::FilterChanged);
    }

    /// Set all categories to Merge (or Replace if merge is not supported).
    pub fn merge_all(&mut self) {
        for state in &mut self.category_states {
            if state.supports_merge {
                state.action = MergeAction::Merge;
            } else {
                state.action = MergeAction::Replace;
            }
        }
        self.sync_to_merge_filter();
        self.fire_event(ApplyPanelEvent::ApplyAllRequested);
        self.fire_event(ApplyPanelEvent::FilterChanged);
    }

    // -- Merge filter ---------------------------------------------------------

    /// Get the current merge filter.
    pub fn merge_filter(&self) -> &ProgramMergeFilter {
        &self.merge_filter
    }

    /// Set the merge filter directly.
    pub fn set_merge_filter(&mut self, filter: ProgramMergeFilter) {
        self.merge_filter = filter;
        self.sync_from_merge_filter();
        self.fire_event(ApplyPanelEvent::FilterChanged);
    }

    /// Sync the category states to the merge filter.
    fn sync_to_merge_filter(&mut self) {
        let mut filter = ProgramMergeFilter::new();
        for state in &self.category_states {
            filter.set_filter(state.category, state.action);
        }
        self.merge_filter = filter;
    }

    /// Sync the category states from the merge filter.
    fn sync_from_merge_filter(&mut self) {
        for state in &mut self.category_states {
            state.action = self.merge_filter.get_filter(state.category);
        }
    }

    // -- Summary --------------------------------------------------------------

    /// Get a summary of the current configuration.
    pub fn summary(&self) -> String {
        let ignore_count = self
            .category_states
            .iter()
            .filter(|s| s.action == MergeAction::Ignore)
            .count();
        let replace_count = self
            .category_states
            .iter()
            .filter(|s| s.action == MergeAction::Replace)
            .count();
        let merge_count = self
            .category_states
            .iter()
            .filter(|s| s.action == MergeAction::Merge)
            .count();

        format!(
            "{} ignore, {} replace, {} merge",
            ignore_count, replace_count, merge_count
        )
    }

    /// Get a list of categories that will be applied (not ignored).
    pub fn active_categories(&self) -> Vec<MergeCategory> {
        self.category_states
            .iter()
            .filter(|s| s.action != MergeAction::Ignore)
            .map(|s| s.category)
            .collect()
    }
}

impl Default for DiffApplyPanel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ApplyPreset
// ---------------------------------------------------------------------------

/// Predefined configurations for the apply panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApplyPreset {
    /// Set all categories to Ignore.
    IgnoreAll,
    /// Set all categories to Replace.
    ReplaceAll,
    /// Set all categories to Merge (or Replace if merge not supported).
    MergeAll,
    /// Set only comment categories to Replace.
    CommentsOnly,
    /// Set only code-related categories to Replace.
    CodeOnly,
    /// Set only data-related categories to Replace.
    DataOnly,
}

impl ApplyPreset {
    /// All presets.
    pub const ALL: &[ApplyPreset] = &[
        Self::IgnoreAll,
        Self::ReplaceAll,
        Self::MergeAll,
        Self::CommentsOnly,
        Self::CodeOnly,
        Self::DataOnly,
    ];

    /// Get the action this preset applies.
    fn action(&self) -> MergeAction {
        match self {
            Self::IgnoreAll => MergeAction::Ignore,
            Self::ReplaceAll | Self::CommentsOnly | Self::CodeOnly | Self::DataOnly => {
                MergeAction::Replace
            }
            Self::MergeAll => MergeAction::Merge,
        }
    }

    /// Check if this preset applies to a given category.
    fn applies_to(&self, category: MergeCategory) -> bool {
        match self {
            Self::IgnoreAll | Self::ReplaceAll | Self::MergeAll => true,
            Self::CommentsOnly => matches!(
                category,
                MergeCategory::PlateComments
                    | MergeCategory::PreComments
                    | MergeCategory::EolComments
                    | MergeCategory::RepeatableComments
                    | MergeCategory::PostComments
                    | MergeCategory::Comments
            ),
            Self::CodeOnly => matches!(
                category,
                MergeCategory::Bytes
                    | MergeCategory::Instructions
                    | MergeCategory::CodeUnits
                    | MergeCategory::Functions
            ),
            Self::DataOnly => matches!(
                category,
                MergeCategory::Data
                    | MergeCategory::Symbols
                    | MergeCategory::Equates
                    | MergeCategory::ProgramContext
            ),
        }
    }

    /// Get a human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::IgnoreAll => "Ignore All",
            Self::ReplaceAll => "Replace All",
            Self::MergeAll => "Merge All",
            Self::CommentsOnly => "Comments Only",
            Self::CodeOnly => "Code Only",
            Self::DataOnly => "Data Only",
        }
    }

    /// Get a description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::IgnoreAll => "Set all categories to Ignore.",
            Self::ReplaceAll => "Set all categories to Replace.",
            Self::MergeAll => "Set all categories to Merge (or Replace where merge is not supported).",
            Self::CommentsOnly => "Set only comment categories to Replace.",
            Self::CodeOnly => "Set only code-related categories to Replace.",
            Self::DataOnly => "Set only data-related categories to Replace.",
        }
    }
}

impl std::fmt::Display for ApplyPreset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_panel_new() {
        let panel = DiffApplyPanel::new();
        assert!(panel.is_enabled());
        assert!(!panel.category_states().is_empty());
    }

    #[test]
    fn test_panel_default() {
        let panel = DiffApplyPanel::default();
        assert!(panel.is_enabled());
    }

    #[test]
    fn test_panel_with_filter() {
        let filter = ProgramMergeFilter::all_with_action(MergeAction::Replace);
        let panel = DiffApplyPanel::with_filter(filter);
        // All categories should be Replace
        for state in panel.category_states() {
            assert_eq!(state.action, MergeAction::Replace);
        }
    }

    #[test]
    fn test_set_enabled() {
        let mut panel = DiffApplyPanel::new();
        assert!(panel.is_enabled());
        panel.set_enabled(false);
        assert!(!panel.is_enabled());
        panel.set_enabled(true);
        assert!(panel.is_enabled());
    }

    #[test]
    fn test_category_action() {
        let mut panel = DiffApplyPanel::new();
        assert_eq!(
            panel.category_action(MergeCategory::Bytes),
            Some(MergeAction::Ignore)
        );
        panel.set_category_action(MergeCategory::Bytes, MergeAction::Replace);
        assert_eq!(
            panel.category_action(MergeCategory::Bytes),
            Some(MergeAction::Replace)
        );
    }

    #[test]
    fn test_cycle_category_action() {
        let mut panel = DiffApplyPanel::new();

        // Bytes supports merge: Ignore -> Replace -> Merge -> Ignore
        assert_eq!(
            panel.category_action(MergeCategory::Bytes),
            Some(MergeAction::Ignore)
        );
        panel.cycle_category_action(MergeCategory::Bytes);
        assert_eq!(
            panel.category_action(MergeCategory::Bytes),
            Some(MergeAction::Replace)
        );
        panel.cycle_category_action(MergeCategory::Bytes);
        assert_eq!(
            panel.category_action(MergeCategory::Bytes),
            Some(MergeAction::Merge)
        );
        panel.cycle_category_action(MergeCategory::Bytes);
        assert_eq!(
            panel.category_action(MergeCategory::Bytes),
            Some(MergeAction::Ignore)
        );
    }

    #[test]
    fn test_cycle_category_action_no_merge() {
        let mut panel = DiffApplyPanel::new();

        // Comments do not support merge: Ignore -> Replace -> Ignore
        assert_eq!(
            panel.category_action(MergeCategory::PlateComments),
            Some(MergeAction::Ignore)
        );
        panel.cycle_category_action(MergeCategory::PlateComments);
        assert_eq!(
            panel.category_action(MergeCategory::PlateComments),
            Some(MergeAction::Replace)
        );
        panel.cycle_category_action(MergeCategory::PlateComments);
        assert_eq!(
            panel.category_action(MergeCategory::PlateComments),
            Some(MergeAction::Ignore)
        );
    }

    #[test]
    fn test_ignore_all() {
        let mut panel = DiffApplyPanel::new();
        panel.set_category_action(MergeCategory::Bytes, MergeAction::Replace);
        panel.ignore_all();
        for state in panel.category_states() {
            assert_eq!(state.action, MergeAction::Ignore);
        }
    }

    #[test]
    fn test_replace_all() {
        let mut panel = DiffApplyPanel::new();
        panel.replace_all();
        for state in panel.category_states() {
            assert_eq!(state.action, MergeAction::Replace);
        }
    }

    #[test]
    fn test_merge_all() {
        let mut panel = DiffApplyPanel::new();
        panel.merge_all();
        for state in panel.category_states() {
            if state.supports_merge {
                assert_eq!(state.action, MergeAction::Merge);
            } else {
                assert_eq!(state.action, MergeAction::Replace);
            }
        }
    }

    #[test]
    fn test_preset_ignore_all() {
        let mut panel = DiffApplyPanel::new();
        panel.replace_all();
        panel.apply_preset(ApplyPreset::IgnoreAll);
        for state in panel.category_states() {
            assert_eq!(state.action, MergeAction::Ignore);
        }
    }

    #[test]
    fn test_preset_replace_all() {
        let mut panel = DiffApplyPanel::new();
        panel.apply_preset(ApplyPreset::ReplaceAll);
        for state in panel.category_states() {
            assert_eq!(state.action, MergeAction::Replace);
        }
    }

    #[test]
    fn test_preset_merge_all() {
        let mut panel = DiffApplyPanel::new();
        panel.apply_preset(ApplyPreset::MergeAll);
        for state in panel.category_states() {
            if state.supports_merge {
                assert_eq!(state.action, MergeAction::Merge);
            } else {
                assert_eq!(state.action, MergeAction::Replace);
            }
        }
    }

    #[test]
    fn test_preset_comments_only() {
        let mut panel = DiffApplyPanel::new();
        panel.apply_preset(ApplyPreset::CommentsOnly);
        assert_eq!(
            panel.category_action(MergeCategory::PlateComments),
            Some(MergeAction::Replace)
        );
        assert_eq!(
            panel.category_action(MergeCategory::EolComments),
            Some(MergeAction::Replace)
        );
        assert_eq!(
            panel.category_action(MergeCategory::Bytes),
            Some(MergeAction::Ignore)
        );
    }

    #[test]
    fn test_preset_code_only() {
        let mut panel = DiffApplyPanel::new();
        panel.apply_preset(ApplyPreset::CodeOnly);
        assert_eq!(
            panel.category_action(MergeCategory::Bytes),
            Some(MergeAction::Replace)
        );
        assert_eq!(
            panel.category_action(MergeCategory::Instructions),
            Some(MergeAction::Replace)
        );
        assert_eq!(
            panel.category_action(MergeCategory::Functions),
            Some(MergeAction::Replace)
        );
        assert_eq!(
            panel.category_action(MergeCategory::Symbols),
            Some(MergeAction::Ignore)
        );
    }

    #[test]
    fn test_preset_data_only() {
        let mut panel = DiffApplyPanel::new();
        panel.apply_preset(ApplyPreset::DataOnly);
        assert_eq!(
            panel.category_action(MergeCategory::Data),
            Some(MergeAction::Replace)
        );
        assert_eq!(
            panel.category_action(MergeCategory::Symbols),
            Some(MergeAction::Replace)
        );
        assert_eq!(
            panel.category_action(MergeCategory::Bytes),
            Some(MergeAction::Ignore)
        );
    }

    #[test]
    fn test_preset_label() {
        assert_eq!(ApplyPreset::IgnoreAll.label(), "Ignore All");
        assert_eq!(ApplyPreset::MergeAll.label(), "Merge All");
    }

    #[test]
    fn test_preset_description() {
        for preset in ApplyPreset::ALL {
            assert!(!preset.description().is_empty());
        }
    }

    #[test]
    fn test_preset_display() {
        assert_eq!(format!("{}", ApplyPreset::IgnoreAll), "Ignore All");
    }

    #[test]
    fn test_merge_filter_sync() {
        let mut panel = DiffApplyPanel::new();
        panel.set_category_action(MergeCategory::Bytes, MergeAction::Replace);
        let filter = panel.merge_filter().clone();
        assert_eq!(filter.get_filter(MergeCategory::Bytes), MergeAction::Replace);
    }

    #[test]
    fn test_set_merge_filter() {
        let mut panel = DiffApplyPanel::new();
        let filter = ProgramMergeFilter::all_with_action(MergeAction::Replace);
        panel.set_merge_filter(filter);
        for state in panel.category_states() {
            assert_eq!(state.action, MergeAction::Replace);
        }
    }

    #[test]
    fn test_summary() {
        let mut panel = DiffApplyPanel::new();
        let summary = panel.summary();
        assert!(summary.contains("ignore"));

        panel.replace_all();
        let summary = panel.summary();
        assert!(summary.contains("replace"));
    }

    #[test]
    fn test_active_categories() {
        let mut panel = DiffApplyPanel::new();
        assert!(panel.active_categories().is_empty());

        panel.set_category_action(MergeCategory::Bytes, MergeAction::Replace);
        let active = panel.active_categories();
        assert_eq!(active.len(), 1);
        assert!(active.contains(&MergeCategory::Bytes));
    }

    #[test]
    fn test_listeners_filter_changed() {
        let mut panel = DiffApplyPanel::new();
        let listener = Arc::new(RecordingApplyListener::new());
        panel.add_listener(listener.clone());

        panel.set_category_action(MergeCategory::Bytes, MergeAction::Replace);
        assert_eq!(listener.event_count(), 1);
    }

    #[test]
    fn test_listeners_ignore_all() {
        let mut panel = DiffApplyPanel::new();
        let listener = Arc::new(RecordingApplyListener::new());
        panel.add_listener(listener.clone());

        panel.ignore_all();
        // IgnoreAllRequested + FilterChanged
        assert_eq!(listener.event_count(), 2);
    }

    #[test]
    fn test_listeners_replace_all() {
        let mut panel = DiffApplyPanel::new();
        let listener = Arc::new(RecordingApplyListener::new());
        panel.add_listener(listener.clone());

        panel.replace_all();
        // ReplaceAllRequested + FilterChanged
        assert_eq!(listener.event_count(), 2);
    }

    #[test]
    fn test_listeners_merge_all() {
        let mut panel = DiffApplyPanel::new();
        let listener = Arc::new(RecordingApplyListener::new());
        panel.add_listener(listener.clone());

        panel.merge_all();
        // ApplyAllRequested + FilterChanged
        assert_eq!(listener.event_count(), 2);
    }

    #[test]
    fn test_listeners_preset() {
        let mut panel = DiffApplyPanel::new();
        let listener = Arc::new(RecordingApplyListener::new());
        panel.add_listener(listener.clone());

        panel.apply_preset(ApplyPreset::CodeOnly);
        assert_eq!(listener.event_count(), 1);
    }

    #[test]
    fn test_clear_listeners() {
        let mut panel = DiffApplyPanel::new();
        let listener = Arc::new(RecordingApplyListener::new());
        panel.add_listener(listener.clone());
        panel.clear_listeners();

        panel.set_category_action(MergeCategory::Bytes, MergeAction::Replace);
        assert_eq!(listener.event_count(), 0);
    }

    #[test]
    fn test_category_action_state() {
        let mut state = CategoryActionState::new(MergeCategory::Bytes, MergeAction::Ignore, true);
        assert_eq!(state.action_label(), "Ignore");

        state.cycle_action();
        assert_eq!(state.action, MergeAction::Replace);

        state.cycle_action();
        assert_eq!(state.action, MergeAction::Merge);

        state.cycle_action();
        assert_eq!(state.action, MergeAction::Ignore);
    }

    #[test]
    fn test_category_action_state_no_merge() {
        let mut state =
            CategoryActionState::new(MergeCategory::PlateComments, MergeAction::Ignore, false);
        state.cycle_action();
        assert_eq!(state.action, MergeAction::Replace);
        state.cycle_action();
        assert_eq!(state.action, MergeAction::Ignore);
    }

    #[test]
    fn test_recording_apply_listener() {
        let listener = RecordingApplyListener::new();
        assert_eq!(listener.event_count(), 0);
        assert!(listener.events().is_empty());

        listener.on_event(&ApplyPanelEvent::FilterChanged);
        assert_eq!(listener.event_count(), 1);
    }

    #[test]
    fn test_apply_panel_event_debug() {
        let event = ApplyPanelEvent::ApplyRequested { address_count: 5 };
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("ApplyRequested"));
    }
}
