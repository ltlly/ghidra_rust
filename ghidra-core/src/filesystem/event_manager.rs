//! Filesystem event management.
//!
//! Re-exports the [`FileSystemListener`] trait and [`FileSystemEventManager`]
//! from `crate::filesystem::store::listener`, providing convenient top-level
//! access to the event dispatch infrastructure.
//!
//! Also provides [`SimpleFileSystemListener`], a convenient callback-based
//! listener for use in tests and lightweight scenarios.

// Re-export everything from the store listener module.
pub use crate::filesystem::store::listener::*;

use std::sync::Arc;

// ============================================================================
// SimpleFileSystemListener – callback-based listener
// ============================================================================

/// A convenient listener that accepts optional closures for each event type.
///
/// Unset callbacks are silently ignored. This is useful for tests and
/// lightweight scenarios where implementing the full trait is overkill.
///
/// # Example
///
/// ```
/// use ghidra_core::filesystem::event_manager::SimpleFileSystemListener;
/// use std::sync::Arc;
///
/// let listener = SimpleFileSystemListener::builder()
///     .on_item_created(|parent, name| {
///         println!("Created: {}/{}", parent, name);
///     })
///     .build();
///
/// // Use with FileSystemEventManager
/// ```
pub struct SimpleFileSystemListener {
    on_folder_created: Option<Box<dyn Fn(&str, &str) + Send + Sync>>,
    on_item_created: Option<Box<dyn Fn(&str, &str) + Send + Sync>>,
    on_folder_deleted: Option<Box<dyn Fn(&str, &str) + Send + Sync>>,
    on_item_deleted: Option<Box<dyn Fn(&str, &str) + Send + Sync>>,
    on_folder_renamed: Option<Box<dyn Fn(&str, &str, &str) + Send + Sync>>,
    on_item_renamed: Option<Box<dyn Fn(&str, &str, &str) + Send + Sync>>,
    on_folder_moved: Option<Box<dyn Fn(&str, &str, &str) + Send + Sync>>,
    on_item_moved: Option<Box<dyn Fn(&str, &str, &str, &str) + Send + Sync>>,
    on_item_changed: Option<Box<dyn Fn(&str, &str) + Send + Sync>>,
    on_synchronize: Option<Box<dyn Fn() + Send + Sync>>,
}

impl SimpleFileSystemListener {
    /// Create a builder for constructing a `SimpleFileSystemListener`.
    pub fn builder() -> SimpleFileSystemListenerBuilder {
        SimpleFileSystemListenerBuilder::default()
    }

    /// Invoke the folder-created callback if set.
    pub fn fire_folder_created(&self, parent_path: &str, name: &str) {
        if let Some(ref cb) = self.on_folder_created {
            cb(parent_path, name);
        }
    }

    /// Invoke the item-created callback if set.
    pub fn fire_item_created(&self, parent_path: &str, name: &str) {
        if let Some(ref cb) = self.on_item_created {
            cb(parent_path, name);
        }
    }
}

impl FileSystemListener for SimpleFileSystemListener {
    fn folder_created(&self, parent_path: &str, name: &str) {
        if let Some(ref cb) = self.on_folder_created {
            cb(parent_path, name);
        }
    }
    fn item_created(&self, parent_path: &str, name: &str) {
        if let Some(ref cb) = self.on_item_created {
            cb(parent_path, name);
        }
    }
    fn folder_deleted(&self, parent_path: &str, name: &str) {
        if let Some(ref cb) = self.on_folder_deleted {
            cb(parent_path, name);
        }
    }
    fn item_deleted(&self, parent_path: &str, name: &str) {
        if let Some(ref cb) = self.on_item_deleted {
            cb(parent_path, name);
        }
    }
    fn folder_renamed(&self, parent_path: &str, name: &str, new_name: &str) {
        if let Some(ref cb) = self.on_folder_renamed {
            cb(parent_path, name, new_name);
        }
    }
    fn item_renamed(&self, parent_path: &str, name: &str, new_name: &str) {
        if let Some(ref cb) = self.on_item_renamed {
            cb(parent_path, name, new_name);
        }
    }
    fn folder_moved(&self, parent_path: &str, name: &str, new_parent_path: &str) {
        if let Some(ref cb) = self.on_folder_moved {
            cb(parent_path, name, new_parent_path);
        }
    }
    fn item_moved(
        &self,
        parent_path: &str,
        name: &str,
        new_parent_path: &str,
        new_name: &str,
    ) {
        if let Some(ref cb) = self.on_item_moved {
            cb(parent_path, name, new_parent_path, new_name);
        }
    }
    fn item_changed(&self, parent_path: &str, name: &str) {
        if let Some(ref cb) = self.on_item_changed {
            cb(parent_path, name);
        }
    }
    fn synchronize(&self) {
        if let Some(ref cb) = self.on_synchronize {
            cb();
        }
    }
}

// ============================================================================
// Builder
// ============================================================================

/// Builder for [`SimpleFileSystemListener`].
#[derive(Default)]
pub struct SimpleFileSystemListenerBuilder {
    on_folder_created: Option<Box<dyn Fn(&str, &str) + Send + Sync>>,
    on_item_created: Option<Box<dyn Fn(&str, &str) + Send + Sync>>,
    on_folder_deleted: Option<Box<dyn Fn(&str, &str) + Send + Sync>>,
    on_item_deleted: Option<Box<dyn Fn(&str, &str) + Send + Sync>>,
    on_folder_renamed: Option<Box<dyn Fn(&str, &str, &str) + Send + Sync>>,
    on_item_renamed: Option<Box<dyn Fn(&str, &str, &str) + Send + Sync>>,
    on_folder_moved: Option<Box<dyn Fn(&str, &str, &str) + Send + Sync>>,
    on_item_moved: Option<Box<dyn Fn(&str, &str, &str, &str) + Send + Sync>>,
    on_item_changed: Option<Box<dyn Fn(&str, &str) + Send + Sync>>,
    on_synchronize: Option<Box<dyn Fn() + Send + Sync>>,
}

impl SimpleFileSystemListenerBuilder {
    pub fn on_folder_created<F: Fn(&str, &str) + Send + Sync + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.on_folder_created = Some(Box::new(f));
        self
    }
    pub fn on_item_created<F: Fn(&str, &str) + Send + Sync + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.on_item_created = Some(Box::new(f));
        self
    }
    pub fn on_folder_deleted<F: Fn(&str, &str) + Send + Sync + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.on_folder_deleted = Some(Box::new(f));
        self
    }
    pub fn on_item_deleted<F: Fn(&str, &str) + Send + Sync + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.on_item_deleted = Some(Box::new(f));
        self
    }
    pub fn on_folder_renamed<F: Fn(&str, &str, &str) + Send + Sync + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.on_folder_renamed = Some(Box::new(f));
        self
    }
    pub fn on_item_renamed<F: Fn(&str, &str, &str) + Send + Sync + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.on_item_renamed = Some(Box::new(f));
        self
    }
    pub fn on_folder_moved<F: Fn(&str, &str, &str) + Send + Sync + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.on_folder_moved = Some(Box::new(f));
        self
    }
    pub fn on_item_moved<F: Fn(&str, &str, &str, &str) + Send + Sync + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.on_item_moved = Some(Box::new(f));
        self
    }
    pub fn on_item_changed<F: Fn(&str, &str) + Send + Sync + 'static>(
        mut self,
        f: F,
    ) -> Self {
        self.on_item_changed = Some(Box::new(f));
        self
    }
    pub fn on_synchronize<F: Fn() + Send + Sync + 'static>(mut self, f: F) -> Self {
        self.on_synchronize = Some(Box::new(f));
        self
    }
    pub fn build(self) -> SimpleFileSystemListener {
        SimpleFileSystemListener {
            on_folder_created: self.on_folder_created,
            on_item_created: self.on_item_created,
            on_folder_deleted: self.on_folder_deleted,
            on_item_deleted: self.on_item_deleted,
            on_folder_renamed: self.on_folder_renamed,
            on_item_renamed: self.on_item_renamed,
            on_folder_moved: self.on_folder_moved,
            on_item_moved: self.on_item_moved,
            on_item_changed: self.on_item_changed,
            on_synchronize: self.on_synchronize,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn test_simple_listener_builder() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let listener = SimpleFileSystemListener::builder()
            .on_item_created(move |_parent, _name| {
                counter_clone.fetch_add(1, Ordering::Relaxed);
            })
            .build();

        listener.item_created("/", "test.txt");
        listener.item_created("/dir", "file.txt");
        assert_eq!(counter.load(Ordering::Relaxed), 2);

        // Unset callbacks should be silently ignored
        listener.folder_created("/", "folder");
    }

    #[test]
    fn test_simple_listener_with_event_manager() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let listener = Arc::new(
            SimpleFileSystemListener::builder()
                .on_item_created(move |_, _| {
                    counter_clone.fetch_add(1, Ordering::Relaxed);
                })
                .on_item_deleted(move |_, _| {})
                .build(),
        );

        let mut mgr = FileSystemEventManager::new(false);
        mgr.add(listener);

        mgr.item_created("/", "a.txt");
        mgr.item_created("/", "b.txt");
        mgr.item_deleted("/", "a.txt");

        assert_eq!(counter.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_builder_chaining_all_events() {
        let listener = SimpleFileSystemListener::builder()
            .on_folder_created(|_, _| {})
            .on_item_created(|_, _| {})
            .on_folder_deleted(|_, _| {})
            .on_item_deleted(|_, _| {})
            .on_folder_renamed(|_, _, _| {})
            .on_item_renamed(|_, _, _| {})
            .on_folder_moved(|_, _, _| {})
            .on_item_moved(|_, _, _, _| {})
            .on_item_changed(|_, _| {})
            .on_synchronize(|| {})
            .build();

        // All callbacks should be set and callable without panicking
        listener.folder_created("/", "f");
        listener.item_created("/", "i");
        listener.folder_deleted("/", "f");
        listener.item_deleted("/", "i");
        listener.folder_renamed("/", "old", "new");
        listener.item_renamed("/", "old", "new");
        listener.folder_moved("/", "f", "/dest");
        listener.item_moved("/", "i", "/dest", "i2");
        listener.item_changed("/", "i");
        listener.synchronize();
    }
}
