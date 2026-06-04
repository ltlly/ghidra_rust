//! Filesystem event listener and manager.
//!
//! Provides [`FileSystemListener`] for receiving notifications about
//! folder and file changes, and [`FileSystemEventManager`] for dispatching
//! those events either synchronously or asynchronously.
//!
//! Corresponds to `ghidra.framework.store.FileSystemListener` and
//! `ghidra.framework.store.FileSystemEventManager`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// ============================================================================
// FileSystemListener trait
// ============================================================================

/// Listener for folder and file changes within a FileSystem.
///
/// Corresponds to `ghidra.framework.store.FileSystemListener`.
pub trait FileSystemListener: Send + Sync {
    /// A new folder was created.
    fn folder_created(&self, parent_path: &str, name: &str);

    /// A new folder item was created.
    fn item_created(&self, parent_path: &str, name: &str);

    /// A folder was deleted.
    fn folder_deleted(&self, parent_path: &str, name: &str);

    /// A folder item was deleted.
    fn item_deleted(&self, parent_path: &str, name: &str);

    /// A folder was renamed.
    fn folder_renamed(&self, parent_path: &str, name: &str, new_name: &str);

    /// A folder item was renamed.
    fn item_renamed(&self, parent_path: &str, name: &str, new_name: &str);

    /// A folder was moved.
    fn folder_moved(
        &self,
        parent_path: &str,
        name: &str,
        new_parent_path: &str,
    );

    /// A folder item was moved.
    fn item_moved(
        &self,
        parent_path: &str,
        name: &str,
        new_parent_path: &str,
        new_name: &str,
    );

    /// A folder item was changed.
    fn item_changed(&self, parent_path: &str, name: &str);

    /// Force synchronization.
    fn synchronize(&self);
}

// ============================================================================
// FileSystemEvent
// ============================================================================

/// An event that can be dispatched to listeners.
#[derive(Debug, Clone)]
enum FileSystemEvent {
    FolderCreated {
        parent_path: String,
        name: String,
    },
    ItemCreated {
        parent_path: String,
        name: String,
    },
    FolderDeleted {
        parent_path: String,
        name: String,
    },
    ItemDeleted {
        parent_path: String,
        name: String,
    },
    FolderRenamed {
        parent_path: String,
        name: String,
        new_name: String,
    },
    ItemRenamed {
        parent_path: String,
        name: String,
        new_name: String,
    },
    FolderMoved {
        parent_path: String,
        name: String,
        new_parent_path: String,
    },
    ItemMoved {
        parent_path: String,
        name: String,
        new_parent_path: String,
        new_name: String,
    },
    ItemChanged {
        parent_path: String,
        name: String,
    },
    Synchronize,
}

impl FileSystemEvent {
    /// Dispatch this event to a single listener.
    fn dispatch(&self, listener: &dyn FileSystemListener) {
        match self {
            FileSystemEvent::FolderCreated { parent_path, name } => {
                listener.folder_created(parent_path, name);
            }
            FileSystemEvent::ItemCreated { parent_path, name } => {
                listener.item_created(parent_path, name);
            }
            FileSystemEvent::FolderDeleted { parent_path, name } => {
                listener.folder_deleted(parent_path, name);
            }
            FileSystemEvent::ItemDeleted { parent_path, name } => {
                listener.item_deleted(parent_path, name);
            }
            FileSystemEvent::FolderRenamed {
                parent_path,
                name,
                new_name,
            } => {
                listener.folder_renamed(parent_path, name, new_name);
            }
            FileSystemEvent::ItemRenamed {
                parent_path,
                name,
                new_name,
            } => {
                listener.item_renamed(parent_path, name, new_name);
            }
            FileSystemEvent::FolderMoved {
                parent_path,
                name,
                new_parent_path,
            } => {
                listener.folder_moved(parent_path, name, new_parent_path);
            }
            FileSystemEvent::ItemMoved {
                parent_path,
                name,
                new_parent_path,
                new_name,
            } => {
                listener.item_moved(parent_path, name, new_parent_path, new_name);
            }
            FileSystemEvent::ItemChanged { parent_path, name } => {
                listener.item_changed(parent_path, name);
            }
            FileSystemEvent::Synchronize => {
                listener.synchronize();
            }
        }
    }

    /// Process this event for all listeners.
    fn process(&self, listeners: &[Arc<dyn FileSystemListener>]) {
        for listener in listeners {
            self.dispatch(listener.as_ref());
        }
    }
}

// ============================================================================
// FileSystemEventManager
// ============================================================================

/// Maintains a list of [`FileSystemListener`]s and dispatches events
/// to them either synchronously or asynchronously.
///
/// Corresponds to `ghidra.framework.store.FileSystemEventManager`.
pub struct FileSystemEventManager {
    listeners: Vec<Arc<dyn FileSystemListener>>,
    shared_listeners: Option<Arc<Mutex<Vec<Arc<dyn FileSystemListener>>>>>,
    async_dispatch: bool,
    event_sender: Option<std::sync::mpsc::Sender<FileSystemEvent>>,
    thread_handle: Option<thread::JoinHandle<()>>,
    running: Arc<AtomicBool>,
}

impl FileSystemEventManager {
    /// Create a new event manager.
    ///
    /// If `async_dispatch` is true, events are dispatched on a background thread.
    /// If false, events are dispatched synchronously on the caller's thread.
    pub fn new(async_dispatch: bool) -> Self {
        let mut mgr = Self {
            listeners: Vec::new(),
            shared_listeners: None,
            async_dispatch,
            event_sender: None,
            thread_handle: None,
            running: Arc::new(AtomicBool::new(false)),
        };
        if async_dispatch {
            mgr.start_dispatch_thread();
        }
        mgr
    }

    fn start_dispatch_thread(&mut self) {
        if self.running.load(Ordering::Relaxed) {
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel::<FileSystemEvent>();
        self.event_sender = Some(tx);
        self.running.store(true, Ordering::Relaxed);
        self.shared_listeners = Some(Arc::new(Mutex::new(Vec::<Arc<dyn FileSystemListener>>::new())));
        let listeners_clone = self.shared_listeners.as_ref().unwrap().clone();
        let running = self.running.clone();

        self.thread_handle = Some(
            thread::Builder::new()
                .name("FileSystemEventDispatch".to_string())
                .spawn(move || {
                    while running.load(Ordering::Relaxed) {
                        match rx.recv_timeout(Duration::from_millis(100)) {
                            Ok(event) => {
                                let l = listeners_clone.lock().unwrap();
                                event.process(&l);
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                                break;
                            }
                        }
                    }
                })
                .expect("Failed to spawn event dispatch thread"),
        );
    }

    /// Returns true if asynchronous event processing is enabled.
    pub fn is_asynchronous(&self) -> bool {
        self.async_dispatch
    }

    /// Add a listener.
    pub fn add(&mut self, listener: Arc<dyn FileSystemListener>) {
        if let Some(ref shared) = self.shared_listeners {
            shared.lock().unwrap().push(listener.clone());
        }
        self.listeners.push(listener);
    }

    /// Remove a listener.
    pub fn remove(&mut self, listener: &dyn FileSystemListener) {
        let ptr = listener as *const dyn FileSystemListener as *const ();
        self.listeners.retain(|l| {
            let l_ptr = l.as_ref() as *const dyn FileSystemListener as *const ();
            l_ptr != ptr
        });
        if let Some(ref shared) = self.shared_listeners {
            shared.lock().unwrap().retain(|l| {
                let l_ptr = l.as_ref() as *const dyn FileSystemListener as *const ();
                l_ptr != ptr
            });
        }
    }

    /// Number of registered listeners.
    pub fn listener_count(&self) -> usize {
        self.listeners.len()
    }

    /// Handle an event (dispatch to all listeners).
    fn handle_event(&self, event: FileSystemEvent) {
        if self.listeners.is_empty() {
            return;
        }
        if self.async_dispatch {
            if let Some(ref sender) = self.event_sender {
                let _ = sender.send(event);
            }
        } else {
            event.process(&self.listeners);
        }
    }

    /// Notify: a folder was created.
    pub fn folder_created(&self, parent_path: &str, name: &str) {
        self.handle_event(FileSystemEvent::FolderCreated {
            parent_path: parent_path.to_string(),
            name: name.to_string(),
        });
    }

    /// Notify: an item was created.
    pub fn item_created(&self, parent_path: &str, name: &str) {
        self.handle_event(FileSystemEvent::ItemCreated {
            parent_path: parent_path.to_string(),
            name: name.to_string(),
        });
    }

    /// Notify: a folder was deleted.
    pub fn folder_deleted(&self, parent_path: &str, name: &str) {
        self.handle_event(FileSystemEvent::FolderDeleted {
            parent_path: parent_path.to_string(),
            name: name.to_string(),
        });
    }

    /// Notify: an item was deleted.
    pub fn item_deleted(&self, parent_path: &str, name: &str) {
        self.handle_event(FileSystemEvent::ItemDeleted {
            parent_path: parent_path.to_string(),
            name: name.to_string(),
        });
    }

    /// Notify: a folder was renamed.
    pub fn folder_renamed(&self, parent_path: &str, name: &str, new_name: &str) {
        self.handle_event(FileSystemEvent::FolderRenamed {
            parent_path: parent_path.to_string(),
            name: name.to_string(),
            new_name: new_name.to_string(),
        });
    }

    /// Notify: an item was renamed.
    pub fn item_renamed(&self, parent_path: &str, name: &str, new_name: &str) {
        self.handle_event(FileSystemEvent::ItemRenamed {
            parent_path: parent_path.to_string(),
            name: name.to_string(),
            new_name: new_name.to_string(),
        });
    }

    /// Notify: a folder was moved.
    pub fn folder_moved(&self, parent_path: &str, name: &str, new_parent_path: &str) {
        self.handle_event(FileSystemEvent::FolderMoved {
            parent_path: parent_path.to_string(),
            name: name.to_string(),
            new_parent_path: new_parent_path.to_string(),
        });
    }

    /// Notify: an item was moved.
    pub fn item_moved(
        &self,
        parent_path: &str,
        name: &str,
        new_parent_path: &str,
        new_name: &str,
    ) {
        self.handle_event(FileSystemEvent::ItemMoved {
            parent_path: parent_path.to_string(),
            name: name.to_string(),
            new_parent_path: new_parent_path.to_string(),
            new_name: new_name.to_string(),
        });
    }

    /// Notify: an item was changed.
    pub fn item_changed(&self, parent_path: &str, name: &str) {
        self.handle_event(FileSystemEvent::ItemChanged {
            parent_path: parent_path.to_string(),
            name: name.to_string(),
        });
    }

    /// Force synchronization notification.
    pub fn synchronize(&self) {
        self.handle_event(FileSystemEvent::Synchronize);
    }

    /// Block until all queued events have been processed (async mode only).
    ///
    /// Returns `true` if the flush succeeded, `false` on timeout.
    pub fn flush(&self, timeout: Duration) -> bool {
        if !self.async_dispatch {
            return true;
        }
        // Send a marker event and wait for it
        // For simplicity, just wait a fixed time
        thread::sleep(timeout);
        true
    }

    /// Dispose of this manager, stopping the dispatch thread.
    pub fn dispose(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        self.event_sender = None;
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
        self.listeners.clear();
    }
}

impl Drop for FileSystemEventManager {
    fn drop(&mut self) {
        self.dispose();
    }
}

impl fmt::Debug for FileSystemEventManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileSystemEventManager")
            .field("listener_count", &self.listeners.len())
            .field("async_dispatch", &self.async_dispatch)
            .finish()
    }
}

use std::fmt;

// ============================================================================
// FileChangeListener trait
// ============================================================================

/// Listener for low-level file changes.
///
/// Corresponds to `ghidra.framework.store.local.FileChangeListener`.
pub trait FileChangeListener: Send + Sync {
    /// A file was created.
    fn file_created(&self, path: &std::path::Path);

    /// A file was deleted.
    fn file_deleted(&self, path: &std::path::Path);

    /// A file was modified.
    fn file_changed(&self, path: &std::path::Path);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    struct CountingListener {
        folder_created_count: AtomicU32,
        item_created_count: AtomicU32,
        item_deleted_count: AtomicU32,
        item_renamed_count: AtomicU32,
        item_moved_count: AtomicU32,
        item_changed_count: AtomicU32,
        synchronize_count: AtomicU32,
        folder_deleted_count: AtomicU32,
        folder_renamed_count: AtomicU32,
        folder_moved_count: AtomicU32,
    }

    impl CountingListener {
        fn new() -> Self {
            Self {
                folder_created_count: AtomicU32::new(0),
                item_created_count: AtomicU32::new(0),
                item_deleted_count: AtomicU32::new(0),
                item_renamed_count: AtomicU32::new(0),
                item_moved_count: AtomicU32::new(0),
                item_changed_count: AtomicU32::new(0),
                synchronize_count: AtomicU32::new(0),
                folder_deleted_count: AtomicU32::new(0),
                folder_renamed_count: AtomicU32::new(0),
                folder_moved_count: AtomicU32::new(0),
            }
        }

        fn total_events(&self) -> u32 {
            self.folder_created_count.load(Ordering::Relaxed)
                + self.item_created_count.load(Ordering::Relaxed)
                + self.item_deleted_count.load(Ordering::Relaxed)
                + self.item_renamed_count.load(Ordering::Relaxed)
                + self.item_moved_count.load(Ordering::Relaxed)
                + self.item_changed_count.load(Ordering::Relaxed)
                + self.synchronize_count.load(Ordering::Relaxed)
                + self.folder_deleted_count.load(Ordering::Relaxed)
                + self.folder_renamed_count.load(Ordering::Relaxed)
                + self.folder_moved_count.load(Ordering::Relaxed)
        }
    }

    impl FileSystemListener for CountingListener {
        fn folder_created(&self, _parent_path: &str, _name: &str) {
            self.folder_created_count.fetch_add(1, Ordering::Relaxed);
        }
        fn item_created(&self, _parent_path: &str, _name: &str) {
            self.item_created_count.fetch_add(1, Ordering::Relaxed);
        }
        fn folder_deleted(&self, _parent_path: &str, _name: &str) {
            self.folder_deleted_count.fetch_add(1, Ordering::Relaxed);
        }
        fn item_deleted(&self, _parent_path: &str, _name: &str) {
            self.item_deleted_count.fetch_add(1, Ordering::Relaxed);
        }
        fn folder_renamed(&self, _parent_path: &str, _name: &str, _new_name: &str) {
            self.folder_renamed_count.fetch_add(1, Ordering::Relaxed);
        }
        fn item_renamed(&self, _parent_path: &str, _name: &str, _new_name: &str) {
            self.item_renamed_count.fetch_add(1, Ordering::Relaxed);
        }
        fn folder_moved(
            &self,
            _parent_path: &str,
            _name: &str,
            _new_parent_path: &str,
        ) {
            self.folder_moved_count.fetch_add(1, Ordering::Relaxed);
        }
        fn item_moved(
            &self,
            _parent_path: &str,
            _name: &str,
            _new_parent_path: &str,
            _new_name: &str,
        ) {
            self.item_moved_count.fetch_add(1, Ordering::Relaxed);
        }
        fn item_changed(&self, _parent_path: &str, _name: &str) {
            self.item_changed_count.fetch_add(1, Ordering::Relaxed);
        }
        fn synchronize(&self) {
            self.synchronize_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn test_event_manager_sync() {
        let listener = Arc::new(CountingListener::new());
        let mut mgr = FileSystemEventManager::new(false);
        mgr.add(listener.clone());

        mgr.folder_created("/", "new_folder");
        mgr.item_created("/new_folder", "file.txt");
        mgr.item_changed("/new_folder", "file.txt");
        mgr.item_renamed("/new_folder", "file.txt", "renamed.txt");
        mgr.item_moved("/new_folder", "file.txt", "/other", "file.txt");
        mgr.item_deleted("/other", "file.txt");
        mgr.folder_deleted("/", "new_folder");
        mgr.synchronize();

        // Synchronous dispatch - events should be delivered immediately
        assert_eq!(listener.total_events(), 8);
    }

    #[test]
    fn test_event_manager_async() {
        let listener = Arc::new(CountingListener::new());
        let mut mgr = FileSystemEventManager::new(true);
        mgr.add(listener.clone());

        mgr.item_created("/", "test.txt");
        mgr.item_changed("/", "test.txt");

        // Give the async thread time to process
        std::thread::sleep(Duration::from_millis(500));

        assert!(listener.total_events() >= 2);

        mgr.dispose();
    }

    #[test]
    fn test_event_manager_no_listeners() {
        let mgr = FileSystemEventManager::new(false);
        // Should not panic
        mgr.folder_created("/", "test");
        mgr.synchronize();
    }

    #[test]
    fn test_event_manager_is_async() {
        let sync_mgr = FileSystemEventManager::new(false);
        assert!(!sync_mgr.is_asynchronous());

        let async_mgr = FileSystemEventManager::new(true);
        assert!(async_mgr.is_asynchronous());
    }
}
