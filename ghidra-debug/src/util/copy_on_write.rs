//! CopyOnWrite - lazy cloning wrapper for shared data.
//!
//! Ported from Ghidra's `ghidra.trace.util.CopyOnWrite`.

use std::sync::Arc;

/// A copy-on-write wrapper around shared data.
///
/// Ported from Ghidra's `CopyOnWrite`. Provides cheap reads via `Arc`
/// and only clones on mutation.
#[derive(Debug)]
pub struct CopyOnWrite<T: Clone> {
    inner: Arc<T>,
}

impl<T: Clone> CopyOnWrite<T> {
    /// Create a new CopyOnWrite wrapping the given value.
    pub fn new(value: T) -> Self {
        Self {
            inner: Arc::new(value),
        }
    }

    /// Get a reference to the inner value (cheap, no clone).
    pub fn get(&self) -> &T {
        &self.inner
    }

    /// Get a mutable reference. Clones the inner value if shared.
    pub fn get_mut(&mut self) -> &mut T {
        Arc::make_mut(&mut self.inner)
    }

    /// Set the value, replacing the current one.
    pub fn set(&mut self, value: T) {
        self.inner = Arc::new(value);
    }

    /// Whether this is the only reference to the data.
    pub fn is_unique(&self) -> bool {
        Arc::strong_count(&self.inner) == 1
    }

    /// Consume and return the inner value, cloning only if shared.
    pub fn into_inner(mut self) -> T {
        Arc::make_mut(&mut self.inner);
        Arc::try_unwrap(self.inner).unwrap_or_else(|arc| (*arc).clone())
    }
}

impl<T: Clone> Clone for CopyOnWrite<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T: Clone + Default> Default for CopyOnWrite<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cow_read() {
        let cow = CopyOnWrite::new(vec![1, 2, 3]);
        assert_eq!(cow.get(), &[1, 2, 3]);
    }

    #[test]
    fn test_cow_write_clones() {
        let cow1 = CopyOnWrite::new(vec![1, 2, 3]);
        let mut cow2 = cow1.clone();
        assert!(!cow1.is_unique()); // two refs

        cow2.get_mut().push(4);
        assert_eq!(cow1.get(), &[1, 2, 3]);
        assert_eq!(cow2.get(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_cow_no_clone_when_unique() {
        let mut cow = CopyOnWrite::new(vec![1]);
        assert!(cow.is_unique());
        cow.get_mut().push(2);
        assert_eq!(cow.get(), &[1, 2]);
    }

    #[test]
    fn test_cow_set() {
        let mut cow = CopyOnWrite::new(10);
        cow.set(20);
        assert_eq!(*cow.get(), 20);
    }

    #[test]
    fn test_cow_into_inner() {
        let cow = CopyOnWrite::new(String::from("hello"));
        let s = cow.into_inner();
        assert_eq!(s, "hello");
    }

    #[test]
    fn test_cow_default() {
        let cow = CopyOnWrite::<Vec<i32>>::default();
        assert!(cow.get().is_empty());
    }
}
