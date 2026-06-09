//! ModelObserver -- generic observation pattern for trace model changes.
//!
//! Ported from Ghidra's `ModelObserver` / `ModelChangeListener` in the
//! `Framework-TraceModeling` package.
//!
//! Provides a type-safe, composable observer pattern for monitoring changes
//! to the trace model: object insertions, deletions, attribute mutations,
//! lifespan changes, and snapshot creation.

use std::fmt;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// ModelChangeKind
// ---------------------------------------------------------------------------

/// The kind of model change that an observer can receive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModelChangeKind {
    /// A new object was inserted into the model.
    ObjectInserted,
    /// An existing object was deleted from the model.
    ObjectDeleted,
    /// An attribute value was set or changed.
    AttributeSet,
    /// An attribute was removed.
    AttributeRemoved,
    /// An element value was set or changed.
    ElementSet,
    /// An element was removed.
    ElementRemoved,
    /// The lifespan of an entry was changed.
    LifespanChanged,
    /// A new snapshot was created.
    SnapshotCreated,
    /// The entire model was restored (full refresh).
    ModelRestored,
}

impl ModelChangeKind {
    /// Whether this change involves an object lifecycle event.
    pub fn is_object_event(&self) -> bool {
        matches!(self, Self::ObjectInserted | Self::ObjectDeleted)
    }

    /// Whether this change involves a value mutation.
    pub fn is_value_event(&self) -> bool {
        matches!(
            self,
            Self::AttributeSet
                | Self::AttributeRemoved
                | Self::ElementSet
                | Self::ElementRemoved
        )
    }
}

impl fmt::Display for ModelChangeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObjectInserted => write!(f, "object-inserted"),
            Self::ObjectDeleted => write!(f, "object-deleted"),
            Self::AttributeSet => write!(f, "attribute-set"),
            Self::AttributeRemoved => write!(f, "attribute-removed"),
            Self::ElementSet => write!(f, "element-set"),
            Self::ElementRemoved => write!(f, "element-removed"),
            Self::LifespanChanged => write!(f, "lifespan-changed"),
            Self::SnapshotCreated => write!(f, "snapshot-created"),
            Self::ModelRestored => write!(f, "model-restored"),
        }
    }
}

// ---------------------------------------------------------------------------
// ModelChangeRecord
// ---------------------------------------------------------------------------

/// A single record describing a model change.
#[derive(Debug, Clone)]
pub struct ModelChangeRecord {
    /// The kind of change.
    pub kind: ModelChangeKind,
    /// The object key affected, if applicable.
    pub object_key: Option<i64>,
    /// The entry key (attribute name or element index), if applicable.
    pub entry_key: Option<String>,
    /// The snap range affected [min, max], if applicable.
    pub snap_range: Option<(i64, i64)>,
    /// A human-readable detail.
    pub detail: Option<String>,
}

impl ModelChangeRecord {
    /// Create a new change record.
    pub fn new(kind: ModelChangeKind) -> Self {
        Self {
            kind,
            object_key: None,
            entry_key: None,
            snap_range: None,
            detail: None,
        }
    }

    /// Set the object key.
    pub fn with_object_key(mut self, key: i64) -> Self {
        self.object_key = Some(key);
        self
    }

    /// Set the entry key.
    pub fn with_entry_key(mut self, key: impl Into<String>) -> Self {
        self.entry_key = Some(key.into());
        self
    }

    /// Set the snap range.
    pub fn with_snap_range(mut self, min: i64, max: i64) -> Self {
        self.snap_range = Some((min, max));
        self
    }

    /// Set a detail string.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

// ---------------------------------------------------------------------------
// ModelObserver trait
// ---------------------------------------------------------------------------

/// A trait for observing changes to the trace model.
///
/// Implementors receive a `ModelChangeRecord` for each change. Observers
/// are registered on a `ModelObservable` and called in registration order.
pub trait ModelObserver: Send + Sync {
    /// Called when any model change occurs.
    fn on_change(&self, record: &ModelChangeRecord);

    /// Called when the model is restored (full refresh).
    fn on_restored(&self) {
        // Default: no-op
    }

    /// Called when a snapshot is created.
    fn on_snapshot_created(&self, _snap: i64) {
        // Default: no-op
    }
}

// ---------------------------------------------------------------------------
// ModelObservable
// ---------------------------------------------------------------------------

/// A container that manages registered `ModelObserver` instances
/// and dispatches change records to them.
pub struct ModelObservable {
    observers: Vec<Arc<dyn ModelObserver>>,
}

impl ModelObservable {
    /// Create a new observable.
    pub fn new() -> Self {
        Self {
            observers: Vec::new(),
        }
    }

    /// Register an observer.
    pub fn add_observer(&mut self, observer: Arc<dyn ModelObserver>) {
        self.observers.push(observer);
    }

    /// Remove all observers.
    pub fn clear_observers(&mut self) {
        self.observers.clear();
    }

    /// The number of registered observers.
    pub fn observer_count(&self) -> usize {
        self.observers.len()
    }

    /// Dispatch a change record to all observers.
    pub fn notify(&self, record: &ModelChangeRecord) {
        for obs in &self.observers {
            obs.on_change(record);
        }
    }

    /// Dispatch a restore event to all observers.
    pub fn notify_restored(&self) {
        for obs in &self.observers {
            obs.on_restored();
        }
    }

    /// Dispatch a snapshot-created event to all observers.
    pub fn notify_snapshot_created(&self, snap: i64) {
        for obs in &self.observers {
            obs.on_snapshot_created(snap);
        }
    }
}

impl Default for ModelObservable {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ModelObservable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModelObservable")
            .field("observer_count", &self.observers.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// CollectingObserver -- a convenience observer that collects records
// ---------------------------------------------------------------------------

/// An observer that collects all received change records into a shared vec.
///
/// Useful for testing and debugging.
#[derive(Clone)]
pub struct CollectingObserver {
    records: Arc<Mutex<Vec<ModelChangeRecord>>>,
    restored_count: Arc<Mutex<usize>>,
    snapshot_snaps: Arc<Mutex<Vec<i64>>>,
}

impl CollectingObserver {
    /// Create a new collecting observer.
    pub fn new() -> Self {
        Self {
            records: Arc::new(Mutex::new(Vec::new())),
            restored_count: Arc::new(Mutex::new(0)),
            snapshot_snaps: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Get all collected records.
    pub fn records(&self) -> Vec<ModelChangeRecord> {
        self.records.lock().unwrap().clone()
    }

    /// Get the number of collected records.
    pub fn record_count(&self) -> usize {
        self.records.lock().unwrap().len()
    }

    /// Get the number of restore events received.
    pub fn restored_count(&self) -> usize {
        *self.restored_count.lock().unwrap()
    }

    /// Get all snapshot snaps received.
    pub fn snapshot_snaps(&self) -> Vec<i64> {
        self.snapshot_snaps.lock().unwrap().clone()
    }

    /// Clear all collected data.
    pub fn clear(&self) {
        self.records.lock().unwrap().clear();
        *self.restored_count.lock().unwrap() = 0;
        self.snapshot_snaps.lock().unwrap().clear();
    }
}

impl Default for CollectingObserver {
    fn default() -> Self {
        Self::new()
    }
}

impl ModelObserver for CollectingObserver {
    fn on_change(&self, record: &ModelChangeRecord) {
        self.records.lock().unwrap().push(record.clone());
    }

    fn on_restored(&self) {
        *self.restored_count.lock().unwrap() += 1;
    }

    fn on_snapshot_created(&self, snap: i64) {
        self.snapshot_snaps.lock().unwrap().push(snap);
    }
}

impl fmt::Debug for CollectingObserver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CollectingObserver")
            .field("record_count", &self.record_count())
            .field("restored_count", &self.restored_count())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_model_change_kind_display() {
        assert_eq!(ModelChangeKind::ObjectInserted.to_string(), "object-inserted");
        assert_eq!(ModelChangeKind::ModelRestored.to_string(), "model-restored");
    }

    #[test]
    fn test_model_change_kind_classification() {
        assert!(ModelChangeKind::ObjectInserted.is_object_event());
        assert!(!ModelChangeKind::AttributeSet.is_object_event());
        assert!(ModelChangeKind::AttributeSet.is_value_event());
        assert!(ModelChangeKind::ElementRemoved.is_value_event());
        assert!(!ModelChangeKind::SnapshotCreated.is_value_event());
    }

    #[test]
    fn test_change_record_builder() {
        let r = ModelChangeRecord::new(ModelChangeKind::AttributeSet)
            .with_object_key(5)
            .with_entry_key("name")
            .with_snap_range(0, 10)
            .with_detail("changed value");
        assert_eq!(r.kind, ModelChangeKind::AttributeSet);
        assert_eq!(r.object_key, Some(5));
        assert_eq!(r.entry_key.as_deref(), Some("name"));
        assert_eq!(r.snap_range, Some((0, 10)));
        assert_eq!(r.detail.as_deref(), Some("changed value"));
    }

    #[test]
    fn test_change_record_minimal() {
        let r = ModelChangeRecord::new(ModelChangeKind::ModelRestored);
        assert_eq!(r.kind, ModelChangeKind::ModelRestored);
        assert!(r.object_key.is_none());
        assert!(r.entry_key.is_none());
    }

    #[test]
    fn test_observable_dispatch() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c2 = counter.clone();

        struct Counter(Arc<AtomicUsize>);
        impl ModelObserver for Counter {
            fn on_change(&self, _record: &ModelChangeRecord) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let mut obs = ModelObservable::new();
        obs.add_observer(Arc::new(Counter(counter)));
        obs.add_observer(Arc::new(Counter(c2)));

        let record = ModelChangeRecord::new(ModelChangeKind::ObjectInserted);
        obs.notify(&record);
        assert_eq!(obs.observer_count(), 2);
    }

    #[test]
    fn test_observable_restored() {
        let restored = Arc::new(AtomicUsize::new(0));
        let r2 = restored.clone();

        struct RestoredCounter(Arc<AtomicUsize>);
        impl ModelObserver for RestoredCounter {
            fn on_change(&self, _record: &ModelChangeRecord) {}
            fn on_restored(&self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let mut obs = ModelObservable::new();
        obs.add_observer(Arc::new(RestoredCounter(restored)));
        obs.add_observer(Arc::new(RestoredCounter(r2)));

        obs.notify_restored();
    }

    #[test]
    fn test_collecting_observer() {
        let collector = CollectingObserver::new();
        let record = ModelChangeRecord::new(ModelChangeKind::AttributeSet)
            .with_object_key(1);
        collector.on_change(&record);
        collector.on_change(&record);
        assert_eq!(collector.record_count(), 2);

        collector.on_restored();
        assert_eq!(collector.restored_count(), 1);

        collector.on_snapshot_created(5);
        assert_eq!(collector.snapshot_snaps(), vec![5]);

        collector.clear();
        assert_eq!(collector.record_count(), 0);
        assert_eq!(collector.restored_count(), 0);
    }

    #[test]
    fn test_default_methods() {
        struct Minimal;
        impl ModelObserver for Minimal {
            fn on_change(&self, _record: &ModelChangeRecord) {}
        }
        let m = Minimal;
        m.on_restored();
        m.on_snapshot_created(0);
    }

    #[test]
    fn test_all_change_kinds() {
        let kinds = [
            ModelChangeKind::ObjectInserted,
            ModelChangeKind::ObjectDeleted,
            ModelChangeKind::AttributeSet,
            ModelChangeKind::AttributeRemoved,
            ModelChangeKind::ElementSet,
            ModelChangeKind::ElementRemoved,
            ModelChangeKind::LifespanChanged,
            ModelChangeKind::SnapshotCreated,
            ModelChangeKind::ModelRestored,
        ];
        assert_eq!(kinds.len(), 9);
    }

    #[test]
    fn test_observable_clear() {
        let mut obs = ModelObservable::new();
        struct NoOp;
        impl ModelObserver for NoOp {
            fn on_change(&self, _: &ModelChangeRecord) {}
        }
        obs.add_observer(Arc::new(NoOp));
        assert_eq!(obs.observer_count(), 1);
        obs.clear_observers();
        assert_eq!(obs.observer_count(), 0);
    }
}
