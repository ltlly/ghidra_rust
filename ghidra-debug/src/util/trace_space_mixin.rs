//! Trace space mixin providing shared space-based behavior.
//!
//! Ported from `ghidra/trace/util/TraceSpaceMixin.java`.
//! Provides a mixin trait that trace managers can use for
//! address-space-based storage and delegation.

use std::collections::BTreeMap;

/// A mixin trait for space-based trace operations.
///
/// Provides common functionality for managers that maintain
/// per-address-space storage, including delegation and iteration.
pub trait TraceSpaceMixin<S: std::fmt::Debug + 'static>: std::fmt::Debug {
    /// Get all spaces.
    fn spaces(&self) -> &BTreeMap<String, S>;

    /// Get a mutable reference to all spaces.
    fn spaces_mut(&mut self) -> &mut BTreeMap<String, S>;

    /// Get or create a space by name.
    fn get_or_create_space(&mut self, name: &str) -> &mut S
    where
        S: Default;

    /// Get a space by name (immutable).
    fn get_space(&self, name: &str) -> Option<&S> {
        self.spaces().get(name)
    }

    /// Get a space by name (mutable).
    fn get_space_mut(&mut self, name: &str) -> Option<&mut S> {
        self.spaces_mut().get_mut(name)
    }

    /// Get the number of spaces.
    fn space_count(&self) -> usize {
        self.spaces().len()
    }

    /// Get all space names.
    fn space_names(&self) -> Vec<&str> {
        self.spaces().keys().map(|s| s.as_str()).collect()
    }
}

/// A wrapper providing space-based delegation for read operations.
///
/// Ported from `TraceSpaceMixin.java` delegation pattern.
pub struct SpaceDelegate<T> {
    /// The spaces storage.
    pub spaces: BTreeMap<String, T>,
}

impl<T: std::fmt::Debug> std::fmt::Debug for SpaceDelegate<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpaceDelegate")
            .field("space_count", &self.spaces.len())
            .finish()
    }
}

impl<T> SpaceDelegate<T> {
    /// Create a new empty delegate.
    pub fn new() -> Self {
        Self {
            spaces: BTreeMap::new(),
        }
    }

    /// Get a space.
    pub fn get(&self, name: &str) -> Option<&T> {
        self.spaces.get(name)
    }

    /// Get a mutable space.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut T> {
        self.spaces.get_mut(name)
    }

    /// Get or create a space.
    pub fn get_or_create(&mut self, name: &str) -> &mut T
    where
        T: Default,
    {
        self.spaces
            .entry(name.to_string())
            .or_insert_with(T::default)
    }

    /// Delegate a read operation to a specific space.
    pub fn delegate_read<R, F>(&self, space_name: &str, f: F) -> Option<R>
    where
        F: FnOnce(&T) -> R,
    {
        self.spaces.get(space_name).map(f)
    }

    /// Delegate a write operation to a specific space.
    pub fn delegate_write<R, F>(&mut self, space_name: &str, f: F) -> R
    where
        T: Default,
        F: FnOnce(&mut T) -> R,
    {
        let space = self.get_or_create(space_name);
        f(space)
    }

    /// Collect results from all spaces.
    pub fn collect_all<R, F>(&self, f: F) -> Vec<R>
    where
        F: Fn(&T) -> Option<R>,
    {
        self.spaces.values().filter_map(|s| f(s)).collect()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.spaces.is_empty()
    }

    /// Number of spaces.
    pub fn len(&self) -> usize {
        self.spaces.len()
    }
}

impl<T> Default for SpaceDelegate<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Default)]
    struct TestSpace {
        data: Vec<u32>,
    }

    #[test]
    fn test_space_delegate() {
        let mut delegate = SpaceDelegate::<TestSpace>::new();
        assert!(delegate.is_empty());

        delegate.get_or_create("ram").data.push(42);
        assert_eq!(delegate.len(), 1);

        let val = delegate.delegate_read("ram", |s| s.data.first().copied());
        assert_eq!(val, Some(Some(42)));
    }

    #[test]
    fn test_space_delegate_write() {
        let mut delegate = SpaceDelegate::<TestSpace>::new();
        delegate.delegate_write("ram", |s| s.data.push(100));
        assert_eq!(delegate.get("ram").unwrap().data, vec![100]);
    }

    #[test]
    fn test_space_delegate_collect() {
        let mut delegate = SpaceDelegate::<TestSpace>::new();
        delegate.get_or_create("ram").data.push(1);
        delegate.get_or_create("rom").data.push(2);

        let all: Vec<u32> = delegate.collect_all(|s| s.data.first().copied());
        assert_eq!(all.len(), 2);
    }
}
