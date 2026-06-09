//! Program Diff Plugin -- manages diff providers and program events.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.diff.ProgramDiffPlugin` Java class.
//!
//! The `ProgramDiffPlugin` is the main plugin entry point for the program
//! difference feature.  It manages the lifecycle of diff providers (one per
//! open program pair), listens for program events (open / close / save),
//! and coordinates with [`DiffService`](super::diff_service::DiffService)
//! to launch and terminate diffs.
//!
//! In the original Java, `ProgramDiffPlugin` extends `ProgramPlugin` and
//! implements `DomainObjectListener`.  In this Rust port we capture the
//! logical state and behaviour without the Ghidra plugin framework
//! dependency.
//!
//! # Key types
//!
//! - [`ProgramDiffPlugin`] -- the main plugin state
//! - [`DiffProviderInfo`] -- metadata about a running diff provider
//! - [`DiffPluginEvent`] -- events emitted by the plugin
//! - [`DiffPluginListener`] -- trait for receiving plugin events
//!
//! # Plugin features (ported from Java)
//!
//! - Diff highlight management: tracking which addresses are highlighted as
//!   different between the two programs
//! - Program selection synchronization: mapping selections between program 1
//!   and program 2
//! - Diff navigation: next/previous diff, apply-and-go-next
//! - Task state tracking: whether a diff or apply task is in progress
//! - Select-all-diffs for bulk operations
//! - Diff details at a given address

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use super::diff_controller::{AddressRange, AddressSet, DiffController};
use super::diff_service::DiffService;
use super::diff_actions::DiffTaskListener;
use super::merge_filter::{MergeAction, MergeCategory, ProgramMergeFilter};
use super::{DiffResult, ProgramDiffFilter, ProgramSnapshot, diff_programs};

// ---------------------------------------------------------------------------
// Provider ID generator
// ---------------------------------------------------------------------------

static NEXT_PROVIDER_ID: AtomicU64 = AtomicU64::new(1);

fn next_provider_id() -> u64 {
    NEXT_PROVIDER_ID.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// DiffPluginEvent
// ---------------------------------------------------------------------------

/// Events emitted by the program diff plugin.
#[derive(Debug, Clone)]
pub enum DiffPluginEvent {
    /// A new diff provider was created.
    ProviderCreated {
        /// The provider ID.
        provider_id: u64,
    },
    /// A diff provider was closed.
    ProviderClosed {
        /// The provider ID.
        provider_id: u64,
    },
    /// A diff was started between two programs.
    DiffStarted {
        /// The provider ID.
        provider_id: u64,
        /// Name of program 1.
        program1_name: String,
        /// Name of program 2.
        program2_name: String,
    },
    /// The diff filter was changed for a provider.
    FilterChanged {
        /// The provider ID.
        provider_id: u64,
    },
    /// The diff was terminated.
    DiffTerminated {
        /// The provider ID.
        provider_id: u64,
    },
}

// ---------------------------------------------------------------------------
// DiffPluginListener
// ---------------------------------------------------------------------------

/// Trait for receiving diff plugin events.
pub trait DiffPluginListener: Send + Sync {
    /// Called when a plugin event occurs.
    fn on_event(&self, event: &DiffPluginEvent);
}

/// A simple listener that records events for testing.
#[derive(Debug, Default)]
pub struct RecordingDiffListener {
    events: Mutex<Vec<DiffPluginEvent>>,
}

impl RecordingDiffListener {
    /// Create a new recording listener.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the number of events received.
    pub fn event_count(&self) -> usize {
        self.events.lock().unwrap().len()
    }

    /// Get a snapshot of all received events.
    pub fn events(&self) -> Vec<DiffPluginEvent> {
        self.events.lock().unwrap().clone()
    }
}

impl DiffPluginListener for RecordingDiffListener {
    fn on_event(&self, event: &DiffPluginEvent) {
        self.events.lock().unwrap().push(event.clone());
    }
}

// ---------------------------------------------------------------------------
// DiffProviderInfo
// ---------------------------------------------------------------------------

/// Metadata about a running diff provider.
///
/// Each diff session between two programs is represented by a
/// `DiffProviderInfo` that tracks the provider's identity, the programs
/// being compared, and the active filter settings.
#[derive(Debug, Clone)]
pub struct DiffProviderInfo {
    /// Unique provider ID.
    pub id: u64,
    /// Name/path of program 1 (the "from" program).
    pub program1_name: String,
    /// Name/path of program 2 (the "to" program).
    pub program2_name: String,
    /// The current diff filter.
    pub diff_filter: ProgramDiffFilter,
    /// The current merge filter.
    pub merge_filter: ProgramMergeFilter,
    /// Whether this provider is currently the active/focused one.
    pub is_active: bool,
}

impl DiffProviderInfo {
    /// Create new provider info.
    pub fn new(
        program1_name: impl Into<String>,
        program2_name: impl Into<String>,
    ) -> Self {
        Self {
            id: next_provider_id(),
            program1_name: program1_name.into(),
            program2_name: program2_name.into(),
            diff_filter: ProgramDiffFilter::all(),
            merge_filter: ProgramMergeFilter::default(),
            is_active: true,
        }
    }

    /// Get a display label for this provider (e.g. "p1 vs p2").
    pub fn display_label(&self) -> String {
        format!("{} vs {}", self.program1_name, self.program2_name)
    }
}

// ---------------------------------------------------------------------------
// ProgramDiffPlugin
// ---------------------------------------------------------------------------

/// The main program diff plugin.
///
/// Manages diff providers and coordinates program difference operations.
///
/// Ported from Ghidra's `ProgramDiffPlugin` Java class.
///
/// # Example
///
/// ```rust
/// use ghidra_features::programdiff::program_diff_plugin::*;
/// use ghidra_features::programdiff::*;
///
/// let mut plugin = ProgramDiffPlugin::new();
///
/// // Set up two programs to diff
/// let mut prog1 = ProgramSnapshot::new("main.exe");
/// prog1.add_block(".text", 0x1000, vec![0x90, 0xC3, 0xCC]);
/// prog1.add_symbol(0x1000, "main");
///
/// let mut prog2 = ProgramSnapshot::new("main_patched.exe");
/// prog2.add_block(".text", 0x1000, vec![0x90, 0xCB, 0xCC]);
/// prog2.add_symbol(0x1000, "main");
///
/// // Start a diff
/// let provider_id = plugin.start_diff(prog1, prog2);
/// assert!(provider_id.is_some());
/// assert_eq!(plugin.provider_count(), 1);
///
/// // Get the diff results
/// let results = plugin.get_diff_results(provider_id.unwrap());
/// assert!(!results.is_empty());
/// ```
pub struct ProgramDiffPlugin {
    /// Active diff providers, keyed by provider ID.
    providers: HashMap<u64, DiffProviderInfo>,
    /// Diff controllers for each provider.
    controllers: HashMap<u64, DiffController>,
    /// Program 1 snapshots.
    program1_snapshots: HashMap<u64, ProgramSnapshot>,
    /// Program 2 snapshots.
    program2_snapshots: HashMap<u64, ProgramSnapshot>,
    /// The currently active provider ID.
    active_provider_id: Option<u64>,
    /// Event listeners.
    listeners: Vec<Arc<dyn DiffPluginListener>>,
    /// Whether a diff or apply task is currently in progress.
    task_in_progress: bool,
}

impl ProgramDiffPlugin {
    /// Create a new program diff plugin.
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            controllers: HashMap::new(),
            program1_snapshots: HashMap::new(),
            program2_snapshots: HashMap::new(),
            active_provider_id: None,
            listeners: Vec::new(),
            task_in_progress: false,
        }
    }

    // -- Listener management -------------------------------------------------

    /// Add a listener for plugin events.
    pub fn add_listener(&mut self, listener: Arc<dyn DiffPluginListener>) {
        self.listeners.push(listener);
    }

    /// Remove all listeners.
    pub fn clear_listeners(&mut self) {
        self.listeners.clear();
    }

    /// Fire an event to all listeners.
    fn fire_event(&self, event: DiffPluginEvent) {
        for listener in &self.listeners {
            listener.on_event(&event);
        }
    }

    // -- Diff lifecycle -------------------------------------------------------

    /// Start a diff between two program snapshots.
    ///
    /// Returns the provider ID if successful.
    pub fn start_diff(
        &mut self,
        program1: ProgramSnapshot,
        program2: ProgramSnapshot,
    ) -> Option<u64> {
        let info = DiffProviderInfo::new(&program1.name, &program2.name);
        let provider_id = info.id;

        let controller = DiffController::new(
            program1.clone(),
            program2.clone(),
            None,
            info.diff_filter,
            info.merge_filter.clone(),
        );

        self.providers.insert(provider_id, info);
        self.controllers.insert(provider_id, controller);
        self.program1_snapshots.insert(provider_id, program1);
        self.program2_snapshots.insert(provider_id, program2);
        self.active_provider_id = Some(provider_id);

        self.fire_event(DiffPluginEvent::ProviderCreated { provider_id });
        self.fire_event(DiffPluginEvent::DiffStarted {
            provider_id,
            program1_name: self.program1_snapshots[&provider_id].name.clone(),
            program2_name: self.program2_snapshots[&provider_id].name.clone(),
        });

        Some(provider_id)
    }

    /// Terminate the diff for the given provider.
    pub fn terminate_diff(&mut self, provider_id: u64) {
        if self.providers.remove(&provider_id).is_some() {
            self.controllers.remove(&provider_id);
            self.program1_snapshots.remove(&provider_id);
            self.program2_snapshots.remove(&provider_id);

            if self.active_provider_id == Some(provider_id) {
                self.active_provider_id = self.providers.keys().copied().next();
            }

            self.fire_event(DiffPluginEvent::DiffTerminated { provider_id });
            self.fire_event(DiffPluginEvent::ProviderClosed { provider_id });
        }
    }

    /// Terminate all active diffs.
    pub fn terminate_all(&mut self) {
        let ids: Vec<u64> = self.providers.keys().copied().collect();
        for id in ids {
            self.terminate_diff(id);
        }
    }

    // -- Provider queries -----------------------------------------------------

    /// Get the number of active providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Check if any providers are active.
    pub fn has_providers(&self) -> bool {
        !self.providers.is_empty()
    }

    /// Get the active provider ID.
    pub fn active_provider_id(&self) -> Option<u64> {
        self.active_provider_id
    }

    /// Set the active provider.
    pub fn set_active_provider(&mut self, provider_id: u64) {
        if self.providers.contains_key(&provider_id) {
            self.active_provider_id = Some(provider_id);
        }
    }

    /// Get provider info by ID.
    pub fn provider_info(&self, provider_id: u64) -> Option<&DiffProviderInfo> {
        self.providers.get(&provider_id)
    }

    /// Get all provider IDs.
    pub fn provider_ids(&self) -> Vec<u64> {
        self.providers.keys().copied().collect()
    }

    // -- Diff operations ------------------------------------------------------

    /// Set the diff filter for a provider and re-run the diff.
    pub fn set_diff_filter(&mut self, provider_id: u64, filter: ProgramDiffFilter) {
        if let Some(info) = self.providers.get_mut(&provider_id) {
            info.diff_filter = filter;

            // Re-create the controller with the new filter
            if let (Some(p1), Some(p2)) = (
                self.program1_snapshots.get(&provider_id),
                self.program2_snapshots.get(&provider_id),
            ) {
                let controller = DiffController::new(
                    p1.clone(),
                    p2.clone(),
                    None,
                    filter,
                    info.merge_filter.clone(),
                );
                self.controllers.insert(provider_id, controller);
            }

            self.fire_event(DiffPluginEvent::FilterChanged { provider_id });
        }
    }

    /// Get the diff results for a provider.
    ///
    /// Computes differences between the two programs using the current
    /// diff filter and returns the list of [`DiffResult`]s.
    pub fn get_diff_results(&self, provider_id: u64) -> Vec<DiffResult> {
        if let (Some(p1), Some(p2), Some(info)) = (
            self.program1_snapshots.get(&provider_id),
            self.program2_snapshots.get(&provider_id),
            self.providers.get(&provider_id),
        ) {
            diff_programs(p1, p2, info.diff_filter)
        } else {
            Vec::new()
        }
    }

    /// Get the diff controller for a provider.
    pub fn controller(&self, provider_id: u64) -> Option<&DiffController> {
        self.controllers.get(&provider_id)
    }

    /// Get a mutable reference to the diff controller for a provider.
    pub fn controller_mut(&mut self, provider_id: u64) -> Option<&mut DiffController> {
        self.controllers.get_mut(&provider_id)
    }

    /// Get the display label for a provider.
    pub fn display_label(&self, provider_id: u64) -> Option<String> {
        self.providers.get(&provider_id).map(|info| info.display_label())
    }

    /// Get the number of differences for a provider.
    pub fn diff_count(&self, provider_id: u64) -> usize {
        self.get_diff_results(provider_id).len()
    }

    /// Check if a provider has any differences.
    pub fn has_differences(&self, provider_id: u64) -> bool {
        self.diff_count(provider_id) > 0
    }

    // -- Diff navigation (ported from Java) ---------------------------------

    /// Ensure differences are computed for the given provider.
    ///
    /// The [`DiffController`] lazily computes differences; this method
    /// triggers computation if it hasn't happened yet.
    fn ensure_computed(&mut self, provider_id: u64) {
        if let Some(controller) = self.controllers.get_mut(&provider_id) {
            controller.get_filtered_differences();
        }
    }

    /// Navigate to the next difference for the active provider.
    ///
    /// Returns the address of the next difference, or `None` if there is
    /// no next difference or no active provider.
    ///
    /// Ported from `ProgramDiffPlugin.nextDiff()`.
    pub fn next_diff(&mut self, provider_id: u64) -> Option<u64> {
        self.ensure_computed(provider_id);
        let controller = self.controllers.get_mut(&provider_id)?;
        if controller.has_next() {
            controller.next();
            controller.current_address()
        } else {
            None
        }
    }

    /// Navigate to the previous difference for the active provider.
    ///
    /// Returns the address of the previous difference, or `None` if there is
    /// no previous difference or no active provider.
    ///
    /// Ported from `ProgramDiffPlugin.previousDiff()`.
    pub fn previous_diff(&mut self, provider_id: u64) -> Option<u64> {
        self.ensure_computed(provider_id);
        let controller = self.controllers.get_mut(&provider_id)?;
        if controller.has_previous() {
            controller.previous();
            controller.current_address()
        } else {
            None
        }
    }

    /// Check if there is a next difference for the given provider.
    pub fn has_next_diff(&mut self, provider_id: u64) -> bool {
        self.ensure_computed(provider_id);
        self.controllers
            .get(&provider_id)
            .map_or(false, |c| c.has_next())
    }

    /// Check if there is a previous difference for the given provider.
    pub fn has_previous_diff(&mut self, provider_id: u64) -> bool {
        self.ensure_computed(provider_id);
        self.controllers
            .get(&provider_id)
            .map_or(false, |c| c.has_previous())
    }

    // -- Diff highlight management (ported from Java) -----------------------

    /// Get the diff highlight address set for a provider.
    ///
    /// The diff highlight represents the set of addresses where differences
    /// have been found between the two programs (after filtering and ignoring).
    ///
    /// Ported from `ProgramDiffPlugin.setDiffHighlight()`.
    pub fn get_diff_highlight(&mut self, provider_id: u64) -> AddressSet {
        self.ensure_computed(provider_id);
        if let Some(controller) = self.controllers.get_mut(&provider_id) {
            controller.differences().clone()
        } else {
            AddressSet::new()
        }
    }

    /// Get the diff highlight as a list of address ranges.
    pub fn get_diff_highlight_ranges(&mut self, provider_id: u64) -> Vec<AddressRange> {
        let highlight = self.get_diff_highlight(provider_id);
        highlight.ranges().to_vec()
    }

    /// Get the range containing the given address from the diff highlight.
    ///
    /// Ported from the inner `getDiffHighlightBlock()` method.
    pub fn get_diff_highlight_range_at(
        &mut self,
        provider_id: u64,
        address: u64,
    ) -> Option<AddressRange> {
        let highlight = self.get_diff_highlight(provider_id);
        for range in highlight.ranges() {
            if range.contains(address) {
                return Some(*range);
            }
        }
        None
    }

    // -- Program selection sync (ported from Java) --------------------------

    /// Set program 2 selection for a provider and return the corresponding
    /// addresses in program 1's address space.
    ///
    /// In Ghidra, selections in the diff listing panel (program 2) need to
    /// be mapped to program 1's address space for the primary listing.
    /// This method performs that mapping using the diff controller.
    ///
    /// Ported from `ProgramDiffPlugin.setProgram2Selection()`.
    pub fn set_program2_selection(
        &mut self,
        provider_id: u64,
        p2_addresses: &AddressSet,
    ) -> AddressSet {
        // Intersect with the diff highlight to limit selection to diff regions
        let highlight = self.get_diff_highlight(provider_id);
        let intersection = highlight.intersect(p2_addresses);

        // The addresses are already in the shared address space in this
        // simplified model, so the mapping is identity.
        intersection
    }

    /// Select all differences for a provider.
    ///
    /// Returns an address set covering all current differences.
    ///
    /// Ported from `ProgramDiffPlugin.selectAllDiffs()`.
    pub fn select_all_diffs(&mut self, provider_id: u64) -> AddressSet {
        self.get_diff_highlight(provider_id)
    }

    // -- Apply operations (ported from Java) --------------------------------

    /// Apply differences in the given address set from program 2 to program 1.
    ///
    /// Returns the list of diff results that were applied (respecting the
    /// merge filter).
    ///
    /// Ported from `ProgramDiffPlugin.applyDiff()`.
    pub fn apply_diff(
        &mut self,
        provider_id: u64,
        address_set: &AddressSet,
    ) -> Vec<DiffResult> {
        self.ensure_computed(provider_id);
        if let Some(controller) = self.controllers.get(&provider_id) {
            controller.apply(address_set)
        } else {
            Vec::new()
        }
    }

    /// Apply the current difference and advance to the next one.
    ///
    /// Returns the applied diff results and the address of the next
    /// difference, if any.
    ///
    /// Ported from `ProgramDiffPlugin.applyDiffAndGoNext()`.
    pub fn apply_diff_and_go_next(
        &mut self,
        provider_id: u64,
    ) -> (Vec<DiffResult>, Option<u64>) {
        // Get the current diff range to apply
        let current = self
            .controllers
            .get(&provider_id)
            .and_then(|c| c.current_address());

        let applied = if let Some(addr) = current {
            let mut apply_set = AddressSet::new();
            apply_set.add_address(addr);
            self.apply_diff(provider_id, &apply_set)
        } else {
            Vec::new()
        };

        let next = self.next_diff(provider_id);
        (applied, next)
    }

    // -- Ignore operations (ported from Java) -------------------------------

    /// Ignore differences in the given address set.
    ///
    /// The ignored addresses will be excluded from future diff results.
    ///
    /// Ported from `ProgramDiffPlugin.ignoreDiff()`.
    pub fn ignore_diff(&mut self, provider_id: u64, address_set: &AddressSet) {
        self.ensure_computed(provider_id);
        if let Some(controller) = self.controllers.get_mut(&provider_id) {
            controller.ignore(address_set);
        }
        // Notify listeners
        self.fire_event(DiffPluginEvent::FilterChanged { provider_id });
    }

    /// Ignore the current difference and advance to the next one.
    ///
    /// Returns the address of the next difference, if any.
    pub fn ignore_and_go_next(&mut self, provider_id: u64) -> Option<u64> {
        let current = self
            .controllers
            .get(&provider_id)
            .and_then(|c| c.current_address());

        if let Some(addr) = current {
            let mut ignore_set = AddressSet::new();
            ignore_set.add_address(addr);
            self.ignore_diff(provider_id, &ignore_set);
        }

        self.next_diff(provider_id)
    }

    // -- Task state tracking (ported from Java) -----------------------------

    /// Check if a diff task is currently in progress.
    pub fn is_task_in_progress(&self) -> bool {
        self.task_in_progress
    }

    /// Set the diff task in-progress state.
    pub fn set_task_in_progress(&mut self, in_progress: bool) {
        self.task_in_progress = in_progress;
    }

    // -- Diff detail queries (ported from Java) -----------------------------

    /// Get the count of address ranges in the diff highlight.
    ///
    /// Ported from the `getDiffCountInfo()` method which reports
    /// "Diff address range X of Y".
    pub fn diff_range_count(&mut self, provider_id: u64) -> usize {
        self.get_diff_highlight_ranges(provider_id).len()
    }

    /// Get the 1-based index of the range containing the given address.
    ///
    /// Returns a string like "Diff address range 3 of 10." or `None` if
    /// the address is not in any diff range.
    ///
    /// Ported from `ProgramDiffPlugin.getDiffCountInfo()`.
    pub fn diff_count_info(&mut self, provider_id: u64, address: u64) -> Option<String> {
        let ranges = self.get_diff_highlight_ranges(provider_id);
        let range_count = ranges.len();
        for (i, range) in ranges.iter().enumerate() {
            if range.contains(address) {
                return Some(format!(
                    "Diff address range {} of {}.",
                    i + 1,
                    range_count
                ));
            }
        }
        None
    }

    // -- Merge filter management (ported from Java) -------------------------

    /// Set the merge filter for a provider.
    pub fn set_merge_filter(&mut self, provider_id: u64, filter: ProgramMergeFilter) {
        if let Some(info) = self.providers.get_mut(&provider_id) {
            info.merge_filter = filter.clone();
        }
        if let Some(controller) = self.controllers.get_mut(&provider_id) {
            controller.set_merge_filter(filter);
        }
    }

    /// Check if the merge filter has any non-ignore actions set.
    ///
    /// Ported from the private `applyIsSet()` method.
    pub fn is_apply_set(&self, provider_id: u64) -> bool {
        if let Some(controller) = self.controllers.get(&provider_id) {
            let filter = controller.merge_filter();
            for category in &[
                MergeCategory::Bytes,
                MergeCategory::CodeUnits,
                MergeCategory::Data,
                MergeCategory::Symbols,
                MergeCategory::Equates,
                MergeCategory::Functions,
                MergeCategory::References,
                MergeCategory::Bookmarks,
                MergeCategory::Comments,
                MergeCategory::Properties,
            ] {
                if filter.get_filter(*category) != MergeAction::Ignore {
                    return true;
                }
            }
        }
        false
    }

    // -- Refresh (ported from Java) -----------------------------------------

    /// Refresh the diff for a provider, recomputing all differences.
    ///
    /// If `keep_ignored` is true, previously ignored addresses remain ignored.
    ///
    /// Ported from the private `reloadDiff()` and `createDiff()` methods.
    pub fn refresh_diff(&mut self, provider_id: u64, keep_ignored: bool) {
        if let Some(controller) = self.controllers.get_mut(&provider_id) {
            controller.refresh(keep_ignored);
        }
        self.fire_event(DiffPluginEvent::FilterChanged { provider_id });
    }

    // -- Diff controller access with listener support -----------------------

    /// Set the diff controller for a provider, replacing any existing one.
    ///
    /// Ported from `ProgramDiffPlugin.setDiffController()`.
    pub fn set_diff_controller(&mut self, provider_id: u64, controller: DiffController) {
        if let Some(info) = self.providers.get_mut(&provider_id) {
            info.diff_filter = *controller.diff_filter();
            info.merge_filter = controller.merge_filter().clone();
        }
        self.controllers.insert(provider_id, controller);
    }
}

impl Default for ProgramDiffPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_prog(name: &str, bytes: Vec<u8>) -> ProgramSnapshot {
        let mut prog = ProgramSnapshot::new(name);
        prog.add_block(".text", 0x1000, bytes);
        prog
    }

    #[test]
    fn test_plugin_new() {
        let plugin = ProgramDiffPlugin::new();
        assert_eq!(plugin.provider_count(), 0);
        assert!(!plugin.has_providers());
        assert!(plugin.active_provider_id().is_none());
    }

    #[test]
    fn test_plugin_default() {
        let plugin = ProgramDiffPlugin::default();
        assert_eq!(plugin.provider_count(), 0);
    }

    #[test]
    fn test_start_diff() {
        let mut plugin = ProgramDiffPlugin::new();
        let prog1 = make_prog("p1", vec![0x90, 0xC3]);
        let prog2 = make_prog("p2", vec![0x90, 0xCB]);

        let id = plugin.start_diff(prog1, prog2);
        assert!(id.is_some());
        assert_eq!(plugin.provider_count(), 1);
        assert_eq!(plugin.active_provider_id(), id);
    }

    #[test]
    fn test_start_diff_with_differences() {
        let mut plugin = ProgramDiffPlugin::new();
        let prog1 = make_prog("p1", vec![0x90, 0xC3, 0xCC]);
        let prog2 = make_prog("p2", vec![0x90, 0xCB, 0xCC]);

        let id = plugin.start_diff(prog1, prog2).unwrap();
        let results = plugin.get_diff_results(id);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, 0x1001);
    }

    #[test]
    fn test_terminate_diff() {
        let mut plugin = ProgramDiffPlugin::new();
        let prog1 = make_prog("p1", vec![0x90]);
        let prog2 = make_prog("p2", vec![0xCB]);

        let id = plugin.start_diff(prog1, prog2).unwrap();
        assert_eq!(plugin.provider_count(), 1);

        plugin.terminate_diff(id);
        assert_eq!(plugin.provider_count(), 0);
        assert!(plugin.active_provider_id().is_none());
    }

    #[test]
    fn test_terminate_nonexistent() {
        let mut plugin = ProgramDiffPlugin::new();
        plugin.terminate_diff(999);
        assert_eq!(plugin.provider_count(), 0);
    }

    #[test]
    fn test_multiple_providers() {
        let mut plugin = ProgramDiffPlugin::new();

        let id1 = plugin.start_diff(make_prog("a1", vec![0x00]), make_prog("a2", vec![0x01]));
        let id2 = plugin.start_diff(make_prog("b1", vec![0x00]), make_prog("b2", vec![0x02]));

        assert_eq!(plugin.provider_count(), 2);
        assert_eq!(plugin.active_provider_id(), id2);

        plugin.terminate_diff(id1.unwrap());
        assert_eq!(plugin.provider_count(), 1);
        assert_eq!(plugin.active_provider_id(), id2);
    }

    #[test]
    fn test_set_active_provider() {
        let mut plugin = ProgramDiffPlugin::new();

        let id1 = plugin.start_diff(make_prog("a1", vec![0x00]), make_prog("a2", vec![0x01]));
        let id2 = plugin.start_diff(make_prog("b1", vec![0x00]), make_prog("b2", vec![0x02]));

        assert_eq!(plugin.active_provider_id(), id2);

        plugin.set_active_provider(id1.unwrap());
        assert_eq!(plugin.active_provider_id(), id1);

        // Setting to nonexistent ID should not change anything
        plugin.set_active_provider(999);
        assert_eq!(plugin.active_provider_id(), id1);
    }

    #[test]
    fn test_set_diff_filter() {
        let mut plugin = ProgramDiffPlugin::new();
        let mut prog1 = make_prog("p1", vec![0x90, 0xC3]);
        prog1.add_symbol(0x1000, "main");
        let mut prog2 = make_prog("p2", vec![0x90, 0xCB]);
        prog2.add_symbol(0x1000, "main");

        let id = plugin.start_diff(prog1, prog2).unwrap();

        // With all filters, we get byte diff
        let all_results = plugin.get_diff_results(id);
        assert_eq!(all_results.len(), 1);

        // Change filter to only symbols
        plugin.set_diff_filter(id, ProgramDiffFilter::SYMBOLS);
        let symbol_results = plugin.get_diff_results(id);
        assert!(symbol_results.is_empty()); // symbols are the same
    }

    #[test]
    fn test_display_label() {
        let mut plugin = ProgramDiffPlugin::new();
        let id = plugin
            .start_diff(make_prog("original", vec![0x00]), make_prog("patched", vec![0x01]))
            .unwrap();

        assert_eq!(plugin.display_label(id), Some("original vs patched".to_string()));
        assert!(plugin.display_label(999).is_none());
    }

    #[test]
    fn test_diff_count() {
        let mut plugin = ProgramDiffPlugin::new();
        let id = plugin
            .start_diff(make_prog("p1", vec![0x00, 0x01]), make_prog("p2", vec![0xFF, 0xFF]))
            .unwrap();

        assert_eq!(plugin.diff_count(id), 2);
        assert!(plugin.has_differences(id));
        assert_eq!(plugin.diff_count(999), 0);
        assert!(!plugin.has_differences(999));
    }

    #[test]
    fn test_provider_info() {
        let mut plugin = ProgramDiffPlugin::new();
        let id = plugin
            .start_diff(make_prog("a", vec![0x00]), make_prog("b", vec![0x01]))
            .unwrap();

        let info = plugin.provider_info(id).unwrap();
        assert_eq!(info.program1_name, "a");
        assert_eq!(info.program2_name, "b");
        assert!(info.is_active);

        assert!(plugin.provider_info(999).is_none());
    }

    #[test]
    fn test_provider_ids() {
        let mut plugin = ProgramDiffPlugin::new();
        plugin.start_diff(make_prog("a1", vec![0x00]), make_prog("a2", vec![0x01]));
        plugin.start_diff(make_prog("b1", vec![0x00]), make_prog("b2", vec![0x01]));

        let ids = plugin.provider_ids();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn test_terminate_all() {
        let mut plugin = ProgramDiffPlugin::new();
        plugin.start_diff(make_prog("a1", vec![0x00]), make_prog("a2", vec![0x01]));
        plugin.start_diff(make_prog("b1", vec![0x00]), make_prog("b2", vec![0x01]));

        assert_eq!(plugin.provider_count(), 2);
        plugin.terminate_all();
        assert_eq!(plugin.provider_count(), 0);
    }

    #[test]
    fn test_listeners() {
        let mut plugin = ProgramDiffPlugin::new();
        let listener = Arc::new(RecordingDiffListener::new());
        plugin.add_listener(listener.clone());

        let id = plugin
            .start_diff(make_prog("p1", vec![0x00]), make_prog("p2", vec![0x01]))
            .unwrap();

        // ProviderCreated + DiffStarted
        assert_eq!(listener.event_count(), 2);

        plugin.terminate_diff(id);
        // + DiffTerminated + ProviderClosed
        assert_eq!(listener.event_count(), 4);
    }

    #[test]
    fn test_listener_filter_changed() {
        let mut plugin = ProgramDiffPlugin::new();
        let listener = Arc::new(RecordingDiffListener::new());
        plugin.add_listener(listener.clone());

        let id = plugin
            .start_diff(make_prog("p1", vec![0x00]), make_prog("p2", vec![0x01]))
            .unwrap();

        let count_before = listener.event_count();
        plugin.set_diff_filter(id, ProgramDiffFilter::SYMBOLS);
        assert_eq!(listener.event_count(), count_before + 1);
    }

    #[test]
    fn test_clear_listeners() {
        let mut plugin = ProgramDiffPlugin::new();
        let listener = Arc::new(RecordingDiffListener::new());
        plugin.add_listener(listener.clone());
        plugin.clear_listeners();

        plugin.start_diff(make_prog("p1", vec![0x00]), make_prog("p2", vec![0x01]));
        assert_eq!(listener.event_count(), 0);
    }

    #[test]
    fn test_recording_listener_events() {
        let listener = RecordingDiffListener::new();
        assert_eq!(listener.event_count(), 0);
        assert!(listener.events().is_empty());

        listener.on_event(&DiffPluginEvent::ProviderCreated { provider_id: 1 });
        assert_eq!(listener.event_count(), 1);
    }

    #[test]
    fn test_provider_info_display_label() {
        let info = DiffProviderInfo::new("original.exe", "patched.exe");
        assert_eq!(info.display_label(), "original.exe vs patched.exe");
    }

    #[test]
    fn test_diff_plugin_event_debug() {
        let event = DiffPluginEvent::DiffStarted {
            provider_id: 1,
            program1_name: "a".into(),
            program2_name: "b".into(),
        };
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("DiffStarted"));
    }

    // -- Navigation tests ---------------------------------------------------

    #[test]
    fn test_next_diff() {
        let mut plugin = ProgramDiffPlugin::new();
        let prog1 = make_prog("p1", vec![0x00, 0x00, 0x00]);
        let prog2 = make_prog("p2", vec![0xFF, 0xFF, 0xFF]);
        let id = plugin.start_diff(prog1, prog2).unwrap();

        assert!(plugin.has_next_diff(id));
        let addr = plugin.next_diff(id);
        assert!(addr.is_some());
    }

    #[test]
    fn test_previous_diff() {
        let mut plugin = ProgramDiffPlugin::new();
        let prog1 = make_prog("p1", vec![0x00, 0x00, 0x00]);
        let prog2 = make_prog("p2", vec![0xFF, 0xFF, 0xFF]);
        let id = plugin.start_diff(prog1, prog2).unwrap();

        // No previous at start
        assert!(!plugin.has_previous_diff(id));
        assert!(plugin.previous_diff(id).is_none());

        // After next, there should be a previous
        plugin.next_diff(id);
        assert!(plugin.has_previous_diff(id));
    }

    #[test]
    fn test_next_diff_nonexistent_provider() {
        let mut plugin = ProgramDiffPlugin::new();
        assert!(plugin.next_diff(999).is_none());
        assert!(!plugin.has_next_diff(999));
        assert!(!plugin.has_previous_diff(999));
    }

    // -- Diff highlight tests -----------------------------------------------

    #[test]
    fn test_get_diff_highlight() {
        let mut plugin = ProgramDiffPlugin::new();
        let prog1 = make_prog("p1", vec![0x00, 0x00, 0x00]);
        let prog2 = make_prog("p2", vec![0xFF, 0xFF, 0xFF]);
        let id = plugin.start_diff(prog1, prog2).unwrap();

        let highlight = plugin.get_diff_highlight(id);
        assert!(!highlight.is_empty());
        assert!(highlight.contains(0x1000));
        assert!(highlight.contains(0x1001));
        assert!(highlight.contains(0x1002));
    }

    #[test]
    fn test_get_diff_highlight_ranges() {
        let mut plugin = ProgramDiffPlugin::new();
        let prog1 = make_prog("p1", vec![0x00, 0x00, 0x00]);
        let prog2 = make_prog("p2", vec![0xFF, 0xFF, 0xFF]);
        let id = plugin.start_diff(prog1, prog2).unwrap();

        let ranges = plugin.get_diff_highlight_ranges(id);
        assert!(!ranges.is_empty());
    }

    #[test]
    fn test_get_diff_highlight_range_at() {
        let mut plugin = ProgramDiffPlugin::new();
        let prog1 = make_prog("p1", vec![0x00, 0x00, 0x00]);
        let prog2 = make_prog("p2", vec![0xFF, 0xFF, 0xFF]);
        let id = plugin.start_diff(prog1, prog2).unwrap();

        let range = plugin.get_diff_highlight_range_at(id, 0x1000);
        assert!(range.is_some());

        // Address not in diff
        let no_range = plugin.get_diff_highlight_range_at(id, 0x2000);
        assert!(no_range.is_none());
    }

    #[test]
    fn test_diff_highlight_nonexistent_provider() {
        let mut plugin = ProgramDiffPlugin::new();
        let highlight = plugin.get_diff_highlight(999);
        assert!(highlight.is_empty());
    }

    // -- Selection sync tests -----------------------------------------------

    #[test]
    fn test_select_all_diffs() {
        let mut plugin = ProgramDiffPlugin::new();
        let prog1 = make_prog("p1", vec![0x00, 0x00, 0x00]);
        let prog2 = make_prog("p2", vec![0xFF, 0xFF, 0xFF]);
        let id = plugin.start_diff(prog1, prog2).unwrap();

        let all = plugin.select_all_diffs(id);
        assert_eq!(all.num_addresses(), 3);
    }

    #[test]
    fn test_set_program2_selection() {
        let mut plugin = ProgramDiffPlugin::new();
        let prog1 = make_prog("p1", vec![0x00, 0x00, 0x00]);
        let prog2 = make_prog("p2", vec![0xFF, 0xFF, 0xFF]);
        let id = plugin.start_diff(prog1, prog2).unwrap();

        let mut p2_sel = AddressSet::new();
        p2_sel.add_address(0x1000);
        let mapped = plugin.set_program2_selection(id, &p2_sel);
        assert!(mapped.contains(0x1000));
    }

    // -- Apply/Ignore tests -------------------------------------------------

    #[test]
    fn test_apply_diff() {
        let mut plugin = ProgramDiffPlugin::new();
        let prog1 = make_prog("p1", vec![0x90, 0xC3]);
        let prog2 = make_prog("p2", vec![0x90, 0xCB]);
        let id = plugin.start_diff(prog1, prog2).unwrap();

        let mut apply_set = AddressSet::new();
        apply_set.add_address(0x1001);
        let applied = plugin.apply_diff(id, &apply_set);
        assert_eq!(applied.len(), 1);
    }

    #[test]
    fn test_apply_diff_and_go_next() {
        let mut plugin = ProgramDiffPlugin::new();
        let prog1 = make_prog("p1", vec![0x00, 0x00]);
        let prog2 = make_prog("p2", vec![0xFF, 0xFF]);
        let id = plugin.start_diff(prog1, prog2).unwrap();

        let (applied, next) = plugin.apply_diff_and_go_next(id);
        assert!(!applied.is_empty());
        // next should be Some since there are 2 diffs
        assert!(next.is_some());
    }

    #[test]
    fn test_ignore_diff() {
        let mut plugin = ProgramDiffPlugin::new();
        let prog1 = make_prog("p1", vec![0x00, 0x00, 0x00]);
        let prog2 = make_prog("p2", vec![0xFF, 0xFF, 0xFF]);
        let id = plugin.start_diff(prog1, prog2).unwrap();

        // Get initial highlight count (uses controller with ignore support)
        let highlight_before = plugin.get_diff_highlight(id);
        let count_before = highlight_before.num_addresses();
        assert_eq!(count_before, 3);

        let mut ignore_set = AddressSet::new();
        ignore_set.add_address(0x1000);
        plugin.ignore_diff(id, &ignore_set);

        // The highlight count should decrease (controller-based, respects ignores)
        let highlight_after = plugin.get_diff_highlight(id);
        assert!(highlight_after.num_addresses() < count_before);
        assert!(!highlight_after.contains(0x1000));
    }

    #[test]
    fn test_ignore_and_go_next() {
        let mut plugin = ProgramDiffPlugin::new();
        let prog1 = make_prog("p1", vec![0x00, 0x00, 0x00]);
        let prog2 = make_prog("p2", vec![0xFF, 0xFF, 0xFF]);
        let id = plugin.start_diff(prog1, prog2).unwrap();

        let next = plugin.ignore_and_go_next(id);
        assert!(next.is_some());
    }

    // -- Task state tests ---------------------------------------------------

    #[test]
    fn test_task_in_progress() {
        let mut plugin = ProgramDiffPlugin::new();
        assert!(!plugin.is_task_in_progress());
        plugin.set_task_in_progress(true);
        assert!(plugin.is_task_in_progress());
        plugin.set_task_in_progress(false);
        assert!(!plugin.is_task_in_progress());
    }

    // -- Diff detail tests --------------------------------------------------

    #[test]
    fn test_diff_range_count() {
        let mut plugin = ProgramDiffPlugin::new();
        let prog1 = make_prog("p1", vec![0x00, 0x00, 0x00]);
        let prog2 = make_prog("p2", vec![0xFF, 0xFF, 0xFF]);
        let id = plugin.start_diff(prog1, prog2).unwrap();

        let count = plugin.diff_range_count(id);
        assert!(count > 0);
    }

    #[test]
    fn test_diff_count_info() {
        let mut plugin = ProgramDiffPlugin::new();
        let prog1 = make_prog("p1", vec![0x00, 0x00, 0x00]);
        let prog2 = make_prog("p2", vec![0xFF, 0xFF, 0xFF]);
        let id = plugin.start_diff(prog1, prog2).unwrap();

        let info = plugin.diff_count_info(id, 0x1000);
        assert!(info.is_some());
        assert!(info.unwrap().contains("Diff address range"));
    }

    #[test]
    fn test_diff_count_info_not_in_range() {
        let mut plugin = ProgramDiffPlugin::new();
        let prog1 = make_prog("p1", vec![0x00]);
        let prog2 = make_prog("p2", vec![0xFF]);
        let id = plugin.start_diff(prog1, prog2).unwrap();

        let info = plugin.diff_count_info(id, 0x2000);
        assert!(info.is_none());
    }

    // -- Merge filter tests -------------------------------------------------

    #[test]
    fn test_set_merge_filter() {
        let mut plugin = ProgramDiffPlugin::new();
        let prog1 = make_prog("p1", vec![0x00]);
        let prog2 = make_prog("p2", vec![0xFF]);
        let id = plugin.start_diff(prog1, prog2).unwrap();

        let filter = ProgramMergeFilter::all_with_action(MergeAction::Replace);
        plugin.set_merge_filter(id, filter);
        assert!(plugin.is_apply_set(id));
    }

    #[test]
    fn test_is_apply_set_default() {
        let mut plugin = ProgramDiffPlugin::new();
        let prog1 = make_prog("p1", vec![0x00]);
        let prog2 = make_prog("p2", vec![0xFF]);
        let id = plugin.start_diff(prog1, prog2).unwrap();

        // Default merge filter has Replace on Bytes
        assert!(plugin.is_apply_set(id));
    }

    // -- Refresh tests ------------------------------------------------------

    #[test]
    fn test_refresh_diff() {
        let mut plugin = ProgramDiffPlugin::new();
        let prog1 = make_prog("p1", vec![0x00, 0x00]);
        let prog2 = make_prog("p2", vec![0xFF, 0xFF]);
        let id = plugin.start_diff(prog1, prog2).unwrap();

        let count_before = plugin.diff_count(id);
        plugin.refresh_diff(id, false);
        let count_after = plugin.diff_count(id);
        assert_eq!(count_before, count_after);
    }

    #[test]
    fn test_refresh_diff_keep_ignored() {
        let mut plugin = ProgramDiffPlugin::new();
        let prog1 = make_prog("p1", vec![0x00, 0x00, 0x00]);
        let prog2 = make_prog("p2", vec![0xFF, 0xFF, 0xFF]);
        let id = plugin.start_diff(prog1, prog2).unwrap();

        // Ignore one address
        let mut ignore_set = AddressSet::new();
        ignore_set.add_address(0x1000);
        plugin.ignore_diff(id, &ignore_set);
        let count_after_ignore = plugin.diff_count(id);

        // Refresh keeping ignored
        plugin.refresh_diff(id, true);
        assert_eq!(plugin.diff_count(id), count_after_ignore);

        // Refresh without keeping ignored
        plugin.refresh_diff(id, false);
        assert_eq!(plugin.diff_count(id), 3);
    }

    // -- set_diff_controller test -------------------------------------------

    #[test]
    fn test_set_diff_controller() {
        let mut plugin = ProgramDiffPlugin::new();
        let prog1 = make_prog("p1", vec![0x00]);
        let prog2 = make_prog("p2", vec![0xFF]);
        let id = plugin.start_diff(prog1, prog2).unwrap();

        let new_controller = DiffController::new(
            make_prog("p1b", vec![0x00]),
            make_prog("p2b", vec![0xFF]),
            None,
            ProgramDiffFilter::BYTES,
            ProgramMergeFilter::defaults(),
        );
        plugin.set_diff_controller(id, new_controller);
        assert!(plugin.controller(id).is_some());
    }
}
