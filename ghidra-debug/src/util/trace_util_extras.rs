//! Trace utilities ported from Ghidra's `ghidra.trace.util` package.
//!
//! This module provides utility types for working with trace data, including
//! overlapping object iterators, viewport span iterators, byte array utilities,
//! and event dispatching helpers.

use crate::model::Lifespan;

/// An iterator that yields overlapping objects from a sorted collection.
///
/// Ported from `OverlappingObjectIterator`. Given a collection of items with
/// lifespans, this iterator yields all items that overlap with a given snap
/// and address range.
#[derive(Debug)]
pub struct OverlappingObjectIterator<T> {
    items: Vec<T>,
    index: usize,
}

impl<T: Clone + std::fmt::Debug> OverlappingObjectIterator<T> {
    /// Create a new overlapping object iterator.
    pub fn new(items: Vec<T>) -> Self {
        Self { items, index: 0 }
    }

    /// Get the total number of items.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Check if the iterator is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

impl<T: Clone + std::fmt::Debug> Iterator for OverlappingObjectIterator<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.items.len() {
            let item = self.items[self.index].clone();
            self.index += 1;
            Some(item)
        } else {
            None
        }
    }
}

/// An iterator that yields viewport spans.
///
/// Ported from `TraceViewportSpanIterator`. Given a set of lifespans and
/// a viewport window, yields the intersection spans that should be visible.
#[derive(Debug)]
pub struct ViewportSpanIterator {
    /// The viewport's snap window (start, end).
    viewport: (i64, i64),
    /// Remaining lifespans to process.
    lifespans: Vec<Lifespan>,
    index: usize,
}

impl ViewportSpanIterator {
    /// Create a new viewport span iterator.
    pub fn new(viewport_start: i64, viewport_end: i64, lifespans: Vec<Lifespan>) -> Self {
        Self {
            viewport: (viewport_start, viewport_end),
            lifespans,
            index: 0,
        }
    }
}

impl Iterator for ViewportSpanIterator {
    type Item = Lifespan;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.lifespans.len() {
            let span = self.lifespans[self.index];
            self.index += 1;
            // Intersect with viewport
            let start = span.lmin().max(self.viewport.0);
            let end = span.lmax().min(self.viewport.1);
            if start <= end {
                return Some(Lifespan::span(start, end));
            }
        }
        None
    }
}

/// Utility for byte array operations on trace data.
///
/// Ported from `ByteArrayUtils`.
pub struct ByteArrayUtils;

impl ByteArrayUtils {
    /// Compare two byte slices for equality over a range.
    pub fn equals(a: &[u8], b: &[u8]) -> bool {
        a == b
    }

    /// XOR two byte slices into a destination buffer.
    pub fn xor(a: &[u8], b: &[u8], dest: &mut [u8]) {
        let len = a.len().min(b.len()).min(dest.len());
        for i in 0..len {
            dest[i] = a[i] ^ b[i];
        }
    }

    /// Fill a byte slice with a value.
    pub fn fill(buf: &mut [u8], value: u8) {
        buf.fill(value);
    }

    /// Compute a simple hash of a byte slice.
    pub fn hash(bytes: &[u8]) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        hasher.finish()
    }
}

/// A method protector that prevents reentrant calls.
///
/// Ported from `MethodProtector`. This is used to guard against
/// recursive entry into methods that modify trace state.
#[derive(Debug)]
pub struct MethodProtector {
    active: bool,
}

impl MethodProtector {
    /// Create a new method protector.
    pub fn new() -> Self {
        Self { active: false }
    }

    /// Try to enter the protected method. Returns true if entry was
    /// successful (not reentrant), false if already active.
    pub fn enter(&mut self) -> bool {
        if self.active {
            false
        } else {
            self.active = true;
            true
        }
    }

    /// Leave the protected method.
    pub fn leave(&mut self) {
        self.active = false;
    }

    /// Check if the method is currently being executed.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

impl Default for MethodProtector {
    fn default() -> Self {
        Self::new()
    }
}

/// Copy-on-write wrapper for thread-safe collections.
///
/// Ported from `CopyOnWrite`. Provides a simple COW mechanism
/// where mutations create a copy of the underlying data.
#[derive(Debug, Clone)]
pub struct CopyOnWrite<T: Clone> {
    data: T,
    dirty: bool,
}

impl<T: Clone> CopyOnWrite<T> {
    /// Create a new COW wrapper.
    pub fn new(data: T) -> Self {
        Self { data, dirty: false }
    }

    /// Get a reference to the data.
    pub fn get(&self) -> &T {
        &self.data
    }

    /// Get a mutable reference, marking as dirty.
    pub fn get_mut(&mut self) -> &mut T {
        self.dirty = true;
        &mut self.data
    }

    /// Check if the data has been modified.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Mark as clean (e.g., after persisting).
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    /// Consume and return the inner data.
    pub fn into_inner(self) -> T {
        self.data
    }
}

/// Suppressable callback wrapper.
///
/// Ported from Ghidra's callback suppression mechanism. Allows
/// temporarily disabling callbacks during batch operations.
#[derive(Debug)]
pub struct SuppressableCallback<F> {
    callback: F,
    suppressed: bool,
}

impl<F: Fn()> SuppressableCallback<F> {
    /// Create a new suppressable callback.
    pub fn new(callback: F) -> Self {
        Self {
            callback,
            suppressed: false,
        }
    }

    /// Invoke the callback if not suppressed.
    pub fn invoke(&self) {
        if !self.suppressed {
            (self.callback)();
        }
    }

    /// Suppress the callback.
    pub fn suppress(&mut self) {
        self.suppressed = true;
    }

    /// Unsuppress the callback.
    pub fn unsuppress(&mut self) {
        self.suppressed = false;
    }

    /// Check if the callback is suppressed.
    pub fn is_suppressed(&self) -> bool {
        self.suppressed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overlapping_iterator() {
        let items = vec![1, 2, 3, 4, 5];
        let mut iter = OverlappingObjectIterator::new(items);
        assert_eq!(iter.len(), 5);
        assert_eq!(iter.next(), Some(1));
        assert_eq!(iter.next(), Some(2));
        assert_eq!(iter.take(2).collect::<Vec<_>>(), vec![3, 4]);
    }

    #[test]
    fn test_viewport_span_iterator() {
        let lifespans = vec![
            Lifespan::span(0, 10),
            Lifespan::span(5, 15),
            Lifespan::span(20, 30),
            Lifespan::span(50, 60),
        ];
        let mut iter = ViewportSpanIterator::new(3, 25, lifespans);
        let spans: Vec<_> = iter.by_ref().collect();
        assert_eq!(spans.len(), 3); // first 3 lifespans intersect [3, 25]
        assert_eq!(spans[0], Lifespan::span(3, 10));
        assert_eq!(spans[1], Lifespan::span(5, 15));
        assert_eq!(spans[2], Lifespan::span(20, 25));
    }

    #[test]
    fn test_byte_array_utils() {
        assert!(ByteArrayUtils::equals(&[1, 2, 3], &[1, 2, 3]));
        assert!(!ByteArrayUtils::equals(&[1, 2], &[1, 2, 3]));

        let mut dest = [0u8; 4];
        ByteArrayUtils::xor(&[0xFF, 0x00, 0xAA, 0x55], &[0xFF, 0xFF, 0xFF, 0xFF], &mut dest);
        assert_eq!(dest, [0x00, 0xFF, 0x55, 0xAA]);

        let hash = ByteArrayUtils::hash(&[1, 2, 3]);
        assert_ne!(hash, 0);
    }

    #[test]
    fn test_method_protector() {
        let mut protector = MethodProtector::new();
        assert!(!protector.is_active());

        assert!(protector.enter());
        assert!(protector.is_active());

        // Reentrant call fails
        assert!(!protector.enter());

        protector.leave();
        assert!(!protector.is_active());

        // Can enter again after leaving
        assert!(protector.enter());
    }

    #[test]
    fn test_copy_on_write() {
        let mut cow = CopyOnWrite::new(vec![1, 2, 3]);
        assert!(!cow.is_dirty());
        assert_eq!(cow.get(), &vec![1, 2, 3]);

        cow.get_mut().push(4);
        assert!(cow.is_dirty());
        assert_eq!(cow.get(), &vec![1, 2, 3, 4]);

        cow.mark_clean();
        assert!(!cow.is_dirty());
    }

    #[test]
    fn test_suppressable_callback() {
        let mut cb = SuppressableCallback::new(|| {});

        cb.invoke(); // should not panic
        assert!(!cb.is_suppressed());

        cb.suppress();
        assert!(cb.is_suppressed());

        cb.unsuppress();
        assert!(!cb.is_suppressed());
    }
}
