//! Decompiler program listener -- Rust port of
//! `ghidra.app.decompiler.component.DecompilerProgramListener`.
//!
//! Listens for program domain-object changes and triggers a decompiler
//! refresh.  Program events are buffered using a coalescing update
//! mechanism (similar to Ghidra's `SwingUpdateManager`) before the
//! actual decompile refresh is triggered.
//!
//! # Architecture
//!
//! ```text
//! DecompilerProgramListener
//!   ├── controller: DecompilerController (reset on structural changes)
//!   ├── updater: UpdateCoalescer (debounce rapid changes)
//!   └── pending_reset: bool (flag for structural changes)
//!
//! Events that trigger resetDecompiler():
//!   - MEMORY_BLOCK_ADDED
//!   - MEMORY_BLOCK_REMOVED
//!   - RESTORED (full restore)
//!   - PROPERTY_CHANGED (spec extension changes)
//!
//! All other changes trigger updater.update() which debounces and
//! eventually calls the refresh callback.
//! ```

use std::collections::VecDeque;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// DomainObjectEventType -- program domain object change types
// ---------------------------------------------------------------------------

/// Types of domain-object events that the program listener reacts to.
///
/// In Ghidra these come from `DomainObjectEvent` and `ProgramEvent`.
/// Here we model only the subset relevant to the decompiler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainObjectEventType {
    /// A memory block was added to the program.
    MemoryBlockAdded,
    /// A memory block was removed from the program.
    MemoryBlockRemoved,
    /// The program was fully restored (e.g., from undo or file reload).
    Restored,
    /// A program property changed.
    PropertyChanged,
    /// A memory block was changed (e.g., bytes modified).
    MemoryBlockChanged,
    /// A function was added.
    FunctionAdded,
    /// A function was removed.
    FunctionRemoved,
    /// A function was changed (body, signature, etc.).
    FunctionChanged,
    /// A symbol was added.
    SymbolAdded,
    /// A symbol was removed.
    SymbolRemoved,
    /// A symbol was renamed.
    SymbolRenamed,
    /// A data type was changed.
    DataTypeChanged,
    /// An equate was added/changed/removed.
    EquateChanged,
    /// Some other program change.
    Other,
}

/// A batch of domain-object change events.
///
/// In Ghidra, `DomainObjectChangedEvent` contains a list of
/// `DomainObjectChangeRecord` entries.  Here we model this as a
/// vector of event types.
#[derive(Debug, Clone, Default)]
pub struct DomainObjectChangeEvent {
    /// The event types in this change batch.
    pub events: Vec<DomainObjectEventType>,
    /// Property names for `PropertyChanged` events.
    pub changed_properties: Vec<String>,
}

impl DomainObjectChangeEvent {
    /// Create an empty change event.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether this event batch contains any of the given event types.
    pub fn contains(&self, event_type: DomainObjectEventType) -> bool {
        self.events.contains(&event_type)
    }

    /// Check whether this event batch contains any of the given event types.
    pub fn contains_any(&self, types: &[DomainObjectEventType]) -> bool {
        types.iter().any(|t| self.events.contains(t))
    }

    /// Check whether a spec-extension property changed.
    ///
    /// In Ghidra, spec extension changes require a full decompiler reset
    /// because they can change the compiler spec and calling conventions.
    pub fn has_spec_extension_change(&self) -> bool {
        self.changed_properties
            .iter()
            .any(|p| p.starts_with("SpecExtension"))
    }

    /// Add an event type.
    pub fn push(&mut self, event_type: DomainObjectEventType) {
        self.events.push(event_type);
    }

    /// Add a property-changed event.
    pub fn push_property_changed(&mut self, property_name: impl Into<String>) {
        self.events.push(DomainObjectEventType::PropertyChanged);
        self.changed_properties.push(property_name.into());
    }

    /// Returns `true` if there are no events.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

// ---------------------------------------------------------------------------
// UpdateCoalescer -- debounce rapid-fire updates
// ---------------------------------------------------------------------------

/// A coalescing update mechanism that debounces rapid-fire events.
///
/// Mirrors Ghidra's `SwingUpdateManager`.  When `update()` is called,
/// the coalescer schedules a callback after `min_delay`.  If additional
/// `update()` calls arrive before the callback fires, the timer is
/// reset.  The callback is guaranteed to fire no later than
/// `max_delay` after the first `update()` call.
///
/// # Design
///
/// The coalescer is time-based.  In a real GUI integration, this would
/// use a timer thread or async runtime.  Here we provide a
/// `check_and_fire()` method that should be called periodically.
#[derive(Debug)]
pub struct UpdateCoalescer {
    /// Minimum delay before firing (debounce window).
    min_delay: Duration,
    /// Maximum delay before forced firing.
    max_delay: Duration,
    /// When the first `update()` in the current batch was called.
    first_update: Option<Instant>,
    /// When the most recent `update()` was called.
    last_update: Option<Instant>,
    /// Whether a fire is pending.
    pending: bool,
    /// Number of updates received in the current batch.
    update_count: usize,
    /// Total number of fires.
    fire_count: usize,
}

impl UpdateCoalescer {
    /// Create a new coalescer with the given delays.
    pub fn new(min_delay: Duration, max_delay: Duration) -> Self {
        Self {
            min_delay,
            max_delay,
            first_update: None,
            last_update: None,
            pending: false,
            update_count: 0,
            fire_count: 0,
        }
    }

    /// Create a coalescer with Ghidra's default delays (500ms min, 5000ms max).
    pub fn with_defaults() -> Self {
        Self::new(Duration::from_millis(500), Duration::from_millis(5000))
    }

    /// Signal that an update has occurred.
    ///
    /// This resets the debounce timer.  The callback will fire after
    /// `min_delay` has elapsed since the last `update()`, or after
    /// `max_delay` has elapsed since the first `update()` in the batch.
    pub fn update(&mut self) {
        let now = Instant::now();
        if self.first_update.is_none() {
            self.first_update = Some(now);
        }
        self.last_update = Some(now);
        self.pending = true;
        self.update_count += 1;
    }

    /// Check whether the coalescer is ready to fire.
    ///
    /// Returns `true` if the callback should be invoked.  This should
    /// be called periodically (e.g., in an event loop or timer callback).
    pub fn should_fire(&self) -> bool {
        if !self.pending {
            return false;
        }

        let now = Instant::now();

        // Check max delay first (forced fire).
        if let Some(first) = self.first_update {
            if now.duration_since(first) >= self.max_delay {
                return true;
            }
        }

        // Check min delay (debounce).
        if let Some(last) = self.last_update {
            if now.duration_since(last) >= self.min_delay {
                return true;
            }
        }

        false
    }

    /// Mark the coalescer as having fired, resetting its state.
    pub fn fire(&mut self) {
        self.pending = false;
        self.first_update = None;
        self.last_update = None;
        self.fire_count += 1;
    }

    /// Check whether a fire is pending.
    pub fn is_pending(&self) -> bool {
        self.pending
    }

    /// Get the number of updates received in the current batch.
    pub fn update_count(&self) -> usize {
        self.update_count
    }

    /// Get the total number of fires.
    pub fn fire_count(&self) -> usize {
        self.fire_count
    }

    /// Dispose the coalescer, canceling any pending fire.
    pub fn dispose(&mut self) {
        self.pending = false;
        self.first_update = None;
        self.last_update = None;
    }
}

// ---------------------------------------------------------------------------
// DecompilerProgramListener
// ---------------------------------------------------------------------------

/// Listener for program domain-object changes that triggers decompiler refreshes.
///
/// In Ghidra, this is a `DomainObjectListener` registered on the `Program`.
/// When program events arrive, they are categorized:
///
/// * **Structural changes** (memory block add/remove, restore, spec extension):
///   The decompiler process is fully reset (`resetDecompiler()`).
/// * **Other changes**: The update coalescer is kicked, which eventually
///   triggers a decompile refresh.
///
/// # Usage
///
/// ```rust,no_run
/// use std::time::Duration;
/// use ghidra_features::decompile_ui::program_listener::*;
///
/// let mut listener = DecompilerProgramListener::new(Duration::from_millis(500), Duration::from_millis(5000));
///
/// // Simulate a memory block being added.
/// let mut event = DomainObjectChangeEvent::new();
/// event.push(DomainObjectEventType::MemoryBlockAdded);
/// let action = listener.process_event(&event);
/// assert!(action.should_reset_decompiler());
/// ```
#[derive(Debug)]
pub struct DecompilerProgramListener {
    /// The update coalescer for debouncing.
    updater: UpdateCoalescer,
    /// Whether a structural reset is pending.
    pending_reset: bool,
    /// Total events processed.
    events_processed: usize,
    /// Total resets triggered.
    resets_triggered: usize,
}

impl DecompilerProgramListener {
    /// Create a new program listener with the given coalescer delays.
    pub fn new(min_delay: Duration, max_delay: Duration) -> Self {
        Self {
            updater: UpdateCoalescer::new(min_delay, max_delay),
            pending_reset: false,
            events_processed: 0,
            resets_triggered: 0,
        }
    }

    /// Create a listener with Ghidra's default delays (500ms/5000ms).
    pub fn with_defaults() -> Self {
        Self {
            updater: UpdateCoalescer::with_defaults(),
            pending_reset: false,
            events_processed: 0,
            resets_triggered: 0,
        }
    }

    /// Process a domain-object change event.
    ///
    /// Returns a [`ListenerAction`] describing what the caller should do.
    pub fn process_event(&mut self, event: &DomainObjectChangeEvent) -> ListenerAction {
        self.events_processed += 1;

        // Check for structural changes that require a full decompiler reset.
        let needs_reset = event.contains(DomainObjectEventType::MemoryBlockAdded)
            || event.contains(DomainObjectEventType::MemoryBlockRemoved)
            || event.contains(DomainObjectEventType::Restored)
            || event.has_spec_extension_change();

        if needs_reset {
            self.pending_reset = true;
            self.resets_triggered += 1;
            return ListenerAction::ResetDecompiler;
        }

        // For all other changes, kick the coalescer.
        self.updater.update();
        ListenerAction::Update
    }

    /// Check whether the coalescer is ready to fire a refresh.
    pub fn should_refresh(&self) -> bool {
        self.updater.should_fire()
    }

    /// Mark the refresh as having been performed.
    pub fn mark_refreshed(&mut self) {
        self.updater.fire();
        self.pending_reset = false;
    }

    /// Check whether a structural reset is pending.
    pub fn is_reset_pending(&self) -> bool {
        self.pending_reset
    }

    /// Get the total number of events processed.
    pub fn events_processed(&self) -> usize {
        self.events_processed
    }

    /// Get the total number of resets triggered.
    pub fn resets_triggered(&self) -> usize {
        self.resets_triggered
    }

    /// Dispose the listener, canceling any pending updates.
    pub fn dispose(&mut self) {
        self.updater.dispose();
        self.pending_reset = false;
    }
}

// ---------------------------------------------------------------------------
// ListenerAction -- what the caller should do after processing an event
// ---------------------------------------------------------------------------

/// The action the caller should take after a program event is processed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerAction {
    /// The decompiler process should be fully reset (structural change).
    ResetDecompiler,
    /// An update was scheduled; the coalescer will fire when ready.
    Update,
    /// No action needed.
    None,
}

impl ListenerAction {
    /// Returns `true` if the decompiler should be reset.
    pub fn should_reset_decompiler(&self) -> bool {
        matches!(self, ListenerAction::ResetDecompiler)
    }

    /// Returns `true` if an update was scheduled.
    pub fn is_update(&self) -> bool {
        matches!(self, ListenerAction::Update)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- DomainObjectChangeEvent ---

    #[test]
    fn test_event_new_empty() {
        let event = DomainObjectChangeEvent::new();
        assert!(event.is_empty());
        assert!(!event.contains(DomainObjectEventType::MemoryBlockAdded));
    }

    #[test]
    fn test_event_push() {
        let mut event = DomainObjectChangeEvent::new();
        event.push(DomainObjectEventType::MemoryBlockAdded);
        assert!(!event.is_empty());
        assert!(event.contains(DomainObjectEventType::MemoryBlockAdded));
        assert!(!event.contains(DomainObjectEventType::MemoryBlockRemoved));
    }

    #[test]
    fn test_event_contains_any() {
        let mut event = DomainObjectChangeEvent::new();
        event.push(DomainObjectEventType::FunctionChanged);
        assert!(event.contains_any(&[
            DomainObjectEventType::MemoryBlockAdded,
            DomainObjectEventType::FunctionChanged,
        ]));
        assert!(!event.contains_any(&[
            DomainObjectEventType::MemoryBlockAdded,
            DomainObjectEventType::MemoryBlockRemoved,
        ]));
    }

    #[test]
    fn test_event_property_changed() {
        let mut event = DomainObjectChangeEvent::new();
        event.push_property_changed("SpecExtension.something");
        assert!(event.contains(DomainObjectEventType::PropertyChanged));
        assert!(event.has_spec_extension_change());
    }

    #[test]
    fn test_event_no_spec_extension() {
        let mut event = DomainObjectChangeEvent::new();
        event.push_property_changed("SomeOtherProperty");
        assert!(!event.has_spec_extension_change());
    }

    // --- UpdateCoalescer ---

    #[test]
    fn test_coalescer_new() {
        let coalescer = UpdateCoalescer::with_defaults();
        assert!(!coalescer.is_pending());
        assert!(!coalescer.should_fire());
        assert_eq!(coalescer.update_count(), 0);
        assert_eq!(coalescer.fire_count(), 0);
    }

    #[test]
    fn test_coalescer_update_sets_pending() {
        let mut coalescer = UpdateCoalescer::with_defaults();
        coalescer.update();
        assert!(coalescer.is_pending());
        assert_eq!(coalescer.update_count(), 1);
    }

    #[test]
    fn test_coalescer_fire_resets() {
        let mut coalescer = UpdateCoalescer::with_defaults();
        coalescer.update();
        assert!(coalescer.is_pending());
        coalescer.fire();
        assert!(!coalescer.is_pending());
        assert_eq!(coalescer.fire_count(), 1);
    }

    #[test]
    fn test_coalescer_dispose() {
        let mut coalescer = UpdateCoalescer::with_defaults();
        coalescer.update();
        assert!(coalescer.is_pending());
        coalescer.dispose();
        assert!(!coalescer.is_pending());
    }

    #[test]
    fn test_coalescer_multiple_updates() {
        let mut coalescer = UpdateCoalescer::with_defaults();
        coalescer.update();
        coalescer.update();
        coalescer.update();
        assert_eq!(coalescer.update_count(), 3);
        assert!(coalescer.is_pending());
    }

    #[test]
    fn test_coalescer_should_fire_with_zero_delay() {
        let mut coalescer = UpdateCoalescer::new(Duration::ZERO, Duration::ZERO);
        coalescer.update();
        // With zero delay, should fire immediately.
        assert!(coalescer.should_fire());
    }

    // --- DecompilerProgramListener ---

    #[test]
    fn test_listener_new() {
        let listener = DecompilerProgramListener::with_defaults();
        assert_eq!(listener.events_processed(), 0);
        assert_eq!(listener.resets_triggered(), 0);
        assert!(!listener.is_reset_pending());
    }

    #[test]
    fn test_listener_memory_block_added_triggers_reset() {
        let mut listener = DecompilerProgramListener::with_defaults();
        let mut event = DomainObjectChangeEvent::new();
        event.push(DomainObjectEventType::MemoryBlockAdded);
        let action = listener.process_event(&event);
        assert_eq!(action, ListenerAction::ResetDecompiler);
        assert!(listener.is_reset_pending());
        assert_eq!(listener.resets_triggered(), 1);
    }

    #[test]
    fn test_listener_memory_block_removed_triggers_reset() {
        let mut listener = DecompilerProgramListener::with_defaults();
        let mut event = DomainObjectChangeEvent::new();
        event.push(DomainObjectEventType::MemoryBlockRemoved);
        let action = listener.process_event(&event);
        assert_eq!(action, ListenerAction::ResetDecompiler);
    }

    #[test]
    fn test_listener_restored_triggers_reset() {
        let mut listener = DecompilerProgramListener::with_defaults();
        let mut event = DomainObjectChangeEvent::new();
        event.push(DomainObjectEventType::Restored);
        let action = listener.process_event(&event);
        assert_eq!(action, ListenerAction::ResetDecompiler);
    }

    #[test]
    fn test_listener_spec_extension_triggers_reset() {
        let mut listener = DecompilerProgramListener::with_defaults();
        let mut event = DomainObjectChangeEvent::new();
        event.push_property_changed("SpecExtension.x86");
        let action = listener.process_event(&event);
        assert_eq!(action, ListenerAction::ResetDecompiler);
    }

    #[test]
    fn test_listener_function_changed_triggers_update() {
        let mut listener = DecompilerProgramListener::with_defaults();
        let mut event = DomainObjectChangeEvent::new();
        event.push(DomainObjectEventType::FunctionChanged);
        let action = listener.process_event(&event);
        assert_eq!(action, ListenerAction::Update);
        assert!(!listener.is_reset_pending());
    }

    #[test]
    fn test_listener_symbol_renamed_triggers_update() {
        let mut listener = DecompilerProgramListener::with_defaults();
        let mut event = DomainObjectChangeEvent::new();
        event.push(DomainObjectEventType::SymbolRenamed);
        let action = listener.process_event(&event);
        assert_eq!(action, ListenerAction::Update);
    }

    #[test]
    fn test_listener_data_type_changed_triggers_update() {
        let mut listener = DecompilerProgramListener::with_defaults();
        let mut event = DomainObjectChangeEvent::new();
        event.push(DomainObjectEventType::DataTypeChanged);
        let action = listener.process_event(&event);
        assert_eq!(action, ListenerAction::Update);
    }

    #[test]
    fn test_listener_events_processed_counter() {
        let mut listener = DecompilerProgramListener::with_defaults();

        let mut event1 = DomainObjectChangeEvent::new();
        event1.push(DomainObjectEventType::FunctionChanged);
        listener.process_event(&event1);

        let mut event2 = DomainObjectChangeEvent::new();
        event2.push(DomainObjectEventType::MemoryBlockAdded);
        listener.process_event(&event2);

        assert_eq!(listener.events_processed(), 2);
        assert_eq!(listener.resets_triggered(), 1);
    }

    #[test]
    fn test_listener_mark_refreshed() {
        let mut listener = DecompilerProgramListener::with_defaults();
        let mut event = DomainObjectChangeEvent::new();
        event.push(DomainObjectEventType::MemoryBlockAdded);
        listener.process_event(&event);
        assert!(listener.is_reset_pending());

        listener.mark_refreshed();
        assert!(!listener.is_reset_pending());
    }

    #[test]
    fn test_listener_dispose() {
        let mut listener = DecompilerProgramListener::with_defaults();
        let mut event = DomainObjectChangeEvent::new();
        event.push(DomainObjectEventType::MemoryBlockAdded);
        listener.process_event(&event);
        assert!(listener.is_reset_pending());

        listener.dispose();
        assert!(!listener.is_reset_pending());
    }

    // --- ListenerAction ---

    #[test]
    fn test_listener_action_reset() {
        let action = ListenerAction::ResetDecompiler;
        assert!(action.should_reset_decompiler());
        assert!(!action.is_update());
    }

    #[test]
    fn test_listener_action_update() {
        let action = ListenerAction::Update;
        assert!(!action.should_reset_decompiler());
        assert!(action.is_update());
    }

    #[test]
    fn test_listener_action_none() {
        let action = ListenerAction::None;
        assert!(!action.should_reset_decompiler());
        assert!(!action.is_update());
    }

    // --- Edge cases ---

    #[test]
    fn test_listener_multiple_structural_events() {
        let mut listener = DecompilerProgramListener::with_defaults();
        let mut event = DomainObjectChangeEvent::new();
        event.push(DomainObjectEventType::MemoryBlockAdded);
        event.push(DomainObjectEventType::MemoryBlockRemoved);
        event.push(DomainObjectEventType::Restored);
        let action = listener.process_event(&event);
        // Should still just be one reset.
        assert_eq!(action, ListenerAction::ResetDecompiler);
        assert_eq!(listener.resets_triggered(), 1);
    }

    #[test]
    fn test_listener_non_spec_property_does_not_reset() {
        let mut listener = DecompilerProgramListener::with_defaults();
        let mut event = DomainObjectChangeEvent::new();
        event.push_property_changed("SomeOtherProperty");
        let action = listener.process_event(&event);
        assert_eq!(action, ListenerAction::Update);
    }
}
