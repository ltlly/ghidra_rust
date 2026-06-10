//! DebuggerWatchesService - service for managing watch expressions.
//!
//! Ported from Ghidra's `ghidra.debug.api.watches.DebuggerWatchesService`.
//!
//! This service manages the set of watch expressions that the user is
//! monitoring during a debug session. It handles adding, removing, reordering,
//! and evaluating watches.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use super::watch::{ValueFormat, WatchRow};

/// A unique identifier for a watch entry.
pub type WatchId = u64;

/// A watch entry in the watches panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchEntry {
    /// Unique identifier.
    pub id: WatchId,
    /// The watch row data.
    pub row: WatchRow,
    /// User-specified display label (optional override).
    pub label: Option<String>,
    /// Whether this entry is currently selected in the UI.
    pub selected: bool,
}

impl WatchEntry {
    /// Create a new watch entry.
    pub fn new(id: WatchId, expression: &str) -> Self {
        Self {
            id,
            row: WatchRow::new(expression),
            label: None,
            selected: false,
        }
    }

    /// Get the display label (user label or expression).
    pub fn display_label(&self) -> &str {
        self.label.as_deref().unwrap_or(&self.row.expression)
    }
}

/// Listener for watch change events.
pub trait WatchesListener: Send + Sync {
    /// Called when a watch entry is added.
    fn watch_added(&self, entry: &WatchEntry);

    /// Called when a watch entry is removed.
    fn watch_removed(&self, id: WatchId);

    /// Called when a watch entry is updated (value changed, format changed, etc).
    fn watch_updated(&self, entry: &WatchEntry);

    /// Called when the watch list is reordered.
    fn watches_reordered(&self, ids: &[WatchId]);

    /// Called when all watches are cleared.
    fn watches_cleared(&self);
}

/// Service for managing debugger watch expressions.
///
/// The watches service provides:
/// - Adding/removing watch expressions
/// - Reordering watches
/// - Updating watch values (from evaluation)
/// - Selection management
/// - Listener notifications for UI updates
pub struct DebuggerWatchesService {
    /// The watch entries, keyed by id.
    entries: RwLock<HashMap<WatchId, WatchEntry>>,
    /// Ordered list of watch ids (maintains insertion/reorder order).
    order: RwLock<Vec<WatchId>>,
    /// Next id counter.
    next_id: Mutex<WatchId>,
    /// Registered listeners.
    listeners: Mutex<Vec<Arc<dyn WatchesListener>>>,
}

impl DebuggerWatchesService {
    /// Create a new watches service.
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            order: RwLock::new(Vec::new()),
            next_id: Mutex::new(1),
            listeners: Mutex::new(Vec::new()),
        }
    }

    /// Register a listener.
    pub fn add_listener(&self, listener: Arc<dyn WatchesListener>) {
        if let Ok(mut listeners) = self.listeners.lock() {
            listeners.push(listener);
        }
    }

    /// Allocate the next watch id.
    fn alloc_id(&self) -> WatchId {
        self.next_id
            .lock()
            .map(|mut id| {
                let current = *id;
                *id = current + 1;
                current
            })
            .unwrap_or(0)
    }

    /// Add a new watch expression.
    ///
    /// Returns the id of the newly created watch entry.
    pub fn add_watch(&self, expression: &str) -> WatchId {
        let id = self.alloc_id();
        let entry = WatchEntry::new(id, expression);

        if let Ok(mut entries) = self.entries.write() {
            entries.insert(id, entry.clone());
        }
        if let Ok(mut order) = self.order.write() {
            order.push(id);
        }

        if let Ok(listeners) = self.listeners.lock() {
            for listener in listeners.iter() {
                listener.watch_added(&entry);
            }
        }

        id
    }

    /// Remove a watch by id.
    ///
    /// Returns true if the watch was found and removed.
    pub fn remove_watch(&self, id: WatchId) -> bool {
        let removed = if let Ok(mut entries) = self.entries.write() {
            entries.remove(&id).is_some()
        } else {
            false
        };

        if removed {
            if let Ok(mut order) = self.order.write() {
                order.retain(|&oid| oid != id);
            }
            if let Ok(listeners) = self.listeners.lock() {
                for listener in listeners.iter() {
                    listener.watch_removed(id);
                }
            }
        }

        removed
    }

    /// Get a watch entry by id.
    pub fn get_watch(&self, id: WatchId) -> Option<WatchEntry> {
        self.entries
            .read()
            .ok()
            .and_then(|entries| entries.get(&id).cloned())
    }

    /// Get all watch entries in order.
    pub fn watches(&self) -> Vec<WatchEntry> {
        let order = self.order.read().ok();
        let entries = self.entries.read().ok();

        match (order, entries) {
            (Some(order), Some(entries)) => order
                .iter()
                .filter_map(|id| entries.get(id).cloned())
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Get the number of watches.
    pub fn watch_count(&self) -> usize {
        self.order.read().map(|o| o.len()).unwrap_or(0)
    }

    /// Update the value of a watch entry.
    ///
    /// Typically called after evaluating the expression at a new snap.
    pub fn update_value(&self, id: WatchId, value: Option<Vec<u8>>, error: Option<String>) -> bool {
        let entry = if let Ok(mut entries) = self.entries.write() {
            entries.get_mut(&id).map(|entry| {
                entry.row.value = value;
                entry.row.error = error;
                entry.clone()
            })
        } else {
            None
        };

        if let Some(ref entry) = entry {
            if let Ok(listeners) = self.listeners.lock() {
                for listener in listeners.iter() {
                    listener.watch_updated(entry);
                }
            }
            true
        } else {
            false
        }
    }

    /// Update the format of a watch entry.
    pub fn update_format(&self, id: WatchId, format: ValueFormat) -> bool {
        let entry = if let Ok(mut entries) = self.entries.write() {
            entries.get_mut(&id).map(|entry| {
                entry.row.format = format;
                entry.clone()
            })
        } else {
            None
        };

        if let Some(ref entry) = entry {
            if let Ok(listeners) = self.listeners.lock() {
                for listener in listeners.iter() {
                    listener.watch_updated(entry);
                }
            }
            true
        } else {
            false
        }
    }

    /// Reorder watches by providing the new id order.
    ///
    /// The `ids` slice must contain exactly the same ids as the current set.
    pub fn reorder(&self, ids: &[WatchId]) -> bool {
        let current_count = self.watch_count();
        if ids.len() != current_count {
            return false;
        }

        // Verify all ids exist.
        if let Ok(entries) = self.entries.read() {
            for &id in ids {
                if !entries.contains_key(&id) {
                    return false;
                }
            }
        } else {
            return false;
        }

        if let Ok(mut order) = self.order.write() {
            *order = ids.to_vec();
        }

        if let Ok(listeners) = self.listeners.lock() {
            for listener in listeners.iter() {
                listener.watches_reordered(ids);
            }
        }

        true
    }

    /// Move a watch entry up in the list.
    pub fn move_up(&self, id: WatchId) -> bool {
        if let Ok(mut order) = self.order.write() {
            if let Some(pos) = order.iter().position(|&oid| oid == id) {
                if pos > 0 {
                    order.swap(pos, pos - 1);
                    if let Ok(listeners) = self.listeners.lock() {
                        drop(order);
                        if let Ok(ord) = self.order.read() {
                            for listener in listeners.iter() {
                                listener.watches_reordered(&ord);
                            }
                        }
                    }
                    return true;
                }
            }
        }
        false
    }

    /// Move a watch entry down in the list.
    pub fn move_down(&self, id: WatchId) -> bool {
        if let Ok(mut order) = self.order.write() {
            if let Some(pos) = order.iter().position(|&oid| oid == id) {
                if pos + 1 < order.len() {
                    order.swap(pos, pos + 1);
                    if let Ok(listeners) = self.listeners.lock() {
                        drop(order);
                        if let Ok(ord) = self.order.read() {
                            for listener in listeners.iter() {
                                listener.watches_reordered(&ord);
                            }
                        }
                    }
                    return true;
                }
            }
        }
        false
    }

    /// Set the selected state of a watch entry.
    pub fn set_selected(&self, id: WatchId, selected: bool) {
        if let Ok(mut entries) = self.entries.write() {
            if let Some(entry) = entries.get_mut(&id) {
                entry.selected = selected;
            }
        }
    }

    /// Get the ids of all selected watch entries.
    pub fn selected_ids(&self) -> Vec<WatchId> {
        self.entries
            .read()
            .map(|entries| {
                entries
                    .values()
                    .filter(|e| e.selected)
                    .map(|e| e.id)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Remove all selected watches.
    pub fn remove_selected(&self) -> usize {
        let ids: Vec<WatchId> = self.selected_ids();
        let count = ids.len();
        for id in ids {
            self.remove_watch(id);
        }
        count
    }

    /// Clear all watches.
    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.write() {
            entries.clear();
        }
        if let Ok(mut order) = self.order.write() {
            order.clear();
        }
        if let Ok(listeners) = self.listeners.lock() {
            for listener in listeners.iter() {
                listener.watches_cleared();
            }
        }
    }

    /// Find a watch by expression text.
    pub fn find_by_expression(&self, expression: &str) -> Option<WatchEntry> {
        self.entries
            .read()
            .ok()
            .and_then(|entries| {
                entries
                    .values()
                    .find(|e| e.row.expression == expression)
                    .cloned()
            })
    }
}

impl Default for DebuggerWatchesService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestListener {
        added: AtomicUsize,
        removed: AtomicUsize,
        updated: AtomicUsize,
        reordered: AtomicUsize,
        cleared: AtomicUsize,
    }

    impl TestListener {
        fn new() -> Self {
            Self {
                added: AtomicUsize::new(0),
                removed: AtomicUsize::new(0),
                updated: AtomicUsize::new(0),
                reordered: AtomicUsize::new(0),
                cleared: AtomicUsize::new(0),
            }
        }
    }

    impl WatchesListener for TestListener {
        fn watch_added(&self, _: &WatchEntry) {
            self.added.fetch_add(1, Ordering::SeqCst);
        }
        fn watch_removed(&self, _: WatchId) {
            self.removed.fetch_add(1, Ordering::SeqCst);
        }
        fn watch_updated(&self, _: &WatchEntry) {
            self.updated.fetch_add(1, Ordering::SeqCst);
        }
        fn watches_reordered(&self, _: &[WatchId]) {
            self.reordered.fetch_add(1, Ordering::SeqCst);
        }
        fn watches_cleared(&self) {
            self.cleared.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_add_and_get() {
        let svc = DebuggerWatchesService::new();
        let id = svc.add_watch("RAX");
        assert_eq!(svc.watch_count(), 1);
        let entry = svc.get_watch(id).unwrap();
        assert_eq!(entry.row.expression, "RAX");
    }

    #[test]
    fn test_remove() {
        let svc = DebuggerWatchesService::new();
        let id = svc.add_watch("RAX");
        assert!(svc.remove_watch(id));
        assert_eq!(svc.watch_count(), 0);
        assert!(svc.get_watch(id).is_none());
    }

    #[test]
    fn test_ordering() {
        let svc = DebuggerWatchesService::new();
        let id1 = svc.add_watch("RAX");
        let id2 = svc.add_watch("RBX");
        let id3 = svc.add_watch("RCX");

        let watches = svc.watches();
        assert_eq!(watches[0].id, id1);
        assert_eq!(watches[1].id, id2);
        assert_eq!(watches[2].id, id3);
    }

    #[test]
    fn test_reorder() {
        let svc = DebuggerWatchesService::new();
        let id1 = svc.add_watch("RAX");
        let id2 = svc.add_watch("RBX");
        let id3 = svc.add_watch("RCX");

        assert!(svc.reorder(&[id3, id1, id2]));
        let watches = svc.watches();
        assert_eq!(watches[0].id, id3);
        assert_eq!(watches[1].id, id1);
        assert_eq!(watches[2].id, id2);
    }

    #[test]
    fn test_reorder_invalid_count() {
        let svc = DebuggerWatchesService::new();
        let id1 = svc.add_watch("RAX");
        assert!(!svc.reorder(&[id1, 999]));
    }

    #[test]
    fn test_update_value() {
        let svc = DebuggerWatchesService::new();
        let id = svc.add_watch("RAX");
        assert!(svc.update_value(id, Some(vec![0x42, 0x00, 0x00, 0x00]), None));
        let entry = svc.get_watch(id).unwrap();
        assert_eq!(entry.row.value, Some(vec![0x42, 0x00, 0x00, 0x00]));
    }

    #[test]
    fn test_update_format() {
        let svc = DebuggerWatchesService::new();
        let id = svc.add_watch("RAX");
        assert!(svc.update_format(id, ValueFormat::Decimal));
        let entry = svc.get_watch(id).unwrap();
        assert_eq!(entry.row.format, ValueFormat::Decimal);
    }

    #[test]
    fn test_move_up_down() {
        let svc = DebuggerWatchesService::new();
        let id1 = svc.add_watch("RAX");
        let id2 = svc.add_watch("RBX");
        let _id3 = svc.add_watch("RCX");

        assert!(svc.move_down(id1));
        let watches = svc.watches();
        assert_eq!(watches[0].id, id2);
        assert_eq!(watches[1].id, id1);

        assert!(svc.move_up(id1));
        let watches = svc.watches();
        assert_eq!(watches[0].id, id1);
        assert_eq!(watches[1].id, id2);
    }

    #[test]
    fn test_move_first_up_fails() {
        let svc = DebuggerWatchesService::new();
        let id = svc.add_watch("RAX");
        assert!(!svc.move_up(id));
    }

    #[test]
    fn test_move_last_down_fails() {
        let svc = DebuggerWatchesService::new();
        let id = svc.add_watch("RAX");
        assert!(!svc.move_down(id));
    }

    #[test]
    fn test_selection() {
        let svc = DebuggerWatchesService::new();
        let id1 = svc.add_watch("RAX");
        let id2 = svc.add_watch("RBX");

        svc.set_selected(id1, true);
        svc.set_selected(id2, true);
        let selected = svc.selected_ids();
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn test_remove_selected() {
        let svc = DebuggerWatchesService::new();
        let id1 = svc.add_watch("RAX");
        let _id2 = svc.add_watch("RBX");
        svc.set_selected(id1, true);

        let removed = svc.remove_selected();
        assert_eq!(removed, 1);
        assert_eq!(svc.watch_count(), 1);
    }

    #[test]
    fn test_find_by_expression() {
        let svc = DebuggerWatchesService::new();
        svc.add_watch("RAX");
        svc.add_watch("RBX");

        let found = svc.find_by_expression("RAX");
        assert!(found.is_some());
        assert_eq!(found.unwrap().row.expression, "RAX");

        assert!(svc.find_by_expression("nonexistent").is_none());
    }

    #[test]
    fn test_clear() {
        let svc = DebuggerWatchesService::new();
        svc.add_watch("RAX");
        svc.add_watch("RBX");
        svc.clear();
        assert_eq!(svc.watch_count(), 0);
    }

    #[test]
    fn test_listener_notifications() {
        let listener = Arc::new(TestListener::new());
        let svc = DebuggerWatchesService::new();
        svc.add_listener(listener.clone());

        let id = svc.add_watch("RAX");
        svc.update_value(id, Some(vec![0x42, 0x00, 0x00, 0x00]), None);
        svc.remove_watch(id);
        svc.clear();

        assert_eq!(listener.added.load(Ordering::SeqCst), 1);
        assert_eq!(listener.updated.load(Ordering::SeqCst), 1);
        assert_eq!(listener.removed.load(Ordering::SeqCst), 1);
        assert_eq!(listener.cleared.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_display_label() {
        let svc = DebuggerWatchesService::new();
        let id = svc.add_watch("RAX");
        let mut entry = svc.get_watch(id).unwrap();
        assert_eq!(entry.display_label(), "RAX");

        entry.label = Some("Register A".to_string());
        assert_eq!(entry.display_label(), "Register A");
    }
}
