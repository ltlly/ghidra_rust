//! Iterator utilities for Ghidra Rust.
//!
//! Ports Ghidra's `generic.util` iterator classes: `FilteredIterator`,
//! `MultiIterator`, `PeekableIterator`, `MergeSortingIterator`, and
//! `FlattenedIterator`.

use std::collections::BinaryHeap;
use std::cmp::Reverse;

// ============================================================================
// FilteredIterator
// ============================================================================

/// An iterator that filters elements from an inner iterator using a predicate.
///
/// Corresponds to Ghidra's `generic.FilteredIterator`.
pub struct FilteredIterator<T, I: Iterator<Item = T>, F: Fn(&T) -> bool> {
    inner: I,
    filter: F,
    next_item: Option<T>,
}

impl<T, I: Iterator<Item = T>, F: Fn(&T) -> bool> FilteredIterator<T, I, F> {
    pub fn new(inner: I, filter: F) -> Self {
        Self {
            inner,
            filter,
            next_item: None,
        }
    }
}

impl<T, I: Iterator<Item = T>, F: Fn(&T) -> bool> Iterator for FilteredIterator<T, I, F> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(item) = self.next_item.take() {
            return Some(item);
        }
        loop {
            match self.inner.next() {
                Some(item) => {
                    if (self.filter)(&item) {
                        return Some(item);
                    }
                }
                None => return None,
            }
        }
    }
}

// ============================================================================
// MultiIterator — iterate over multiple iterators sequentially
// ============================================================================

/// An iterator that chains multiple iterators of the same type.
///
/// Corresponds to Ghidra's `generic.util.MultiIterator`.
pub struct MultiIterator<T> {
    iters: std::vec::IntoIter<Box<dyn Iterator<Item = T>>>,
    current: Option<Box<dyn Iterator<Item = T>>>,
}

impl<T> MultiIterator<T> {
    pub fn new(iterators: Vec<Box<dyn Iterator<Item = T>>>) -> Self {
        let mut iters = iterators.into_iter();
        let current = iters.next();
        Self { iters, current }
    }
}

impl<T> Iterator for MultiIterator<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(ref mut current) = self.current {
                if let Some(item) = current.next() {
                    return Some(item);
                }
            }
            self.current = self.iters.next();
            if self.current.is_none() {
                return None;
            }
        }
    }
}

// ============================================================================
// PeekableIterator — wraps an iterator with peek support
// ============================================================================

/// An iterator that allows peeking at the next element without consuming it.
///
/// Corresponds to Ghidra's `generic.util.PeekableIterator`.
pub struct GhidraPeekableIterator<T, I: Iterator<Item = T>> {
    inner: I,
    peeked: Option<Option<T>>,
}

impl<T, I: Iterator<Item = T>> GhidraPeekableIterator<T, I> {
    pub fn new(inner: I) -> Self {
        Self {
            inner,
            peeked: None,
        }
    }

    /// Peek at the next element without consuming it.
    pub fn peek(&mut self) -> Option<&T> {
        if self.peeked.is_none() {
            self.peeked = Some(self.inner.next());
        }
        self.peeked.as_ref().unwrap().as_ref()
    }

    /// Returns `true` if the iterator has more elements.
    pub fn has_next(&mut self) -> bool {
        self.peek().is_some()
    }
}

impl<T, I: Iterator<Item = T>> Iterator for GhidraPeekableIterator<T, I> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(peeked) = self.peeked.take() {
            return peeked;
        }
        self.inner.next()
    }
}

// ============================================================================
// MergeSortingIterator — merge multiple sorted iterators
// ============================================================================

/// An iterator that merges multiple sorted iterators into a single sorted stream.
///
/// Corresponds to Ghidra's `generic.util.MergeSortingIterator`.
pub struct MergeSortingIterator<T: Ord> {
    heap: BinaryHeap<Reverse<(T, usize)>>,
    sources: Vec<Box<dyn Iterator<Item = T>>>,
}

impl<T: Ord> MergeSortingIterator<T> {
    /// Create a new merge-sorting iterator from multiple sorted iterators.
    pub fn new(sources: Vec<Box<dyn Iterator<Item = T>>>) -> Self {
        let mut heap = BinaryHeap::new();
        let mut sources = sources;
        // Initialize: peek at the first element of each source
        for (i, source) in sources.iter_mut().enumerate() {
            if let Some(item) = source.next() {
                heap.push(Reverse((item, i)));
            }
        }
        Self { heap, sources }
    }
}

impl<T: Ord> Iterator for MergeSortingIterator<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(Reverse((item, source_idx))) = self.heap.pop() {
            // Replenish from the same source
            if let Some(next_item) = self.sources[source_idx].next() {
                self.heap.push(Reverse((next_item, source_idx)));
            }
            Some(item)
        } else {
            None
        }
    }
}

// ============================================================================
// FlattenedIterator — flatten nested iterators
// ============================================================================

/// An iterator that flattens an iterator of iterators.
///
/// Corresponds to Ghidra's `generic.util.FlattenedIterator`.
pub struct FlattenedIterator<T, O: Iterator<Item = Box<dyn Iterator<Item = T>>>> {
    outer: O,
    current_inner: Option<Box<dyn Iterator<Item = T>>>,
}

impl<T, O: Iterator<Item = Box<dyn Iterator<Item = T>>>> FlattenedIterator<T, O> {
    pub fn new(outer: O) -> Self {
        Self {
            outer,
            current_inner: None,
        }
    }
}

impl<T, O: Iterator<Item = Box<dyn Iterator<Item = T>>>> Iterator for FlattenedIterator<T, O> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(ref mut inner) = self.current_inner {
                if let Some(item) = inner.next() {
                    return Some(item);
                }
            }
            self.current_inner = self.outer.next();
            if self.current_inner.is_none() {
                return None;
            }
        }
    }
}

// ============================================================================
// WrappingPeekableIterator — peekable that wraps around
// ============================================================================

/// An iterator that, when it reaches the end, wraps back to the beginning.
///
/// Useful for circular iteration. Corresponds to Ghidra's
/// `generic.util.WrappingPeekableIterator`.
pub struct WrappingIterator<T: Clone> {
    items: Vec<T>,
    pos: usize,
}

impl<T: Clone> WrappingIterator<T> {
    pub fn new(items: Vec<T>) -> Self {
        Self { items, pos: 0 }
    }

    /// Get the current item.
    pub fn current(&self) -> Option<&T> {
        self.items.get(self.pos)
    }

    /// Advance to the next position (wrapping).
    pub fn advance(&mut self) {
        if !self.items.is_empty() {
            self.pos = (self.pos + 1) % self.items.len();
        }
    }

    /// Peek at the next position without advancing.
    pub fn peek(&self) -> Option<&T> {
        if self.items.is_empty() {
            None
        } else {
            self.items.get((self.pos + 1) % self.items.len())
        }
    }

    /// The number of items.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the iterator is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

impl<T: Clone> Iterator for WrappingIterator<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.items.is_empty() {
            return None;
        }
        let item = self.items[self.pos].clone();
        self.pos = (self.pos + 1) % self.items.len();
        Some(item)
    }
}

// ============================================================================
// PeekableIterators — utility functions for peekable iterators
// ============================================================================

/// Collect all elements from an iterator while the predicate holds, plus one more.
///
/// Corresponds to Ghidra's `PeekableIterators.peekWhile()`.
pub fn collect_while<T>(
    iter: &mut impl Iterator<Item = T>,
    predicate: impl Fn(&T) -> bool,
) -> Vec<T> {
    let mut result = Vec::new();
    for item in iter {
        if predicate(&item) {
            result.push(item);
        } else {
            result.push(item);
            break;
        }
    }
    result
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filtered_iterator() {
        let data = vec![1, 2, 3, 4, 5, 6];
        let filtered: Vec<i32> = FilteredIterator::new(data.into_iter(), |x| x % 2 == 0).collect();
        assert_eq!(filtered, vec![2, 4, 6]);
    }

    #[test]
    fn test_multi_iterator() {
        let it1 = vec![1, 2].into_iter();
        let it2 = vec![3, 4].into_iter();
        let it3 = vec![5].into_iter();
        let multi = MultiIterator::new(vec![
            Box::new(it1) as Box<dyn Iterator<Item = i32>>,
            Box::new(it2),
            Box::new(it3),
        ]);
        let result: Vec<i32> = multi.collect();
        assert_eq!(result, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_peekable_iterator() {
        let mut peekable = GhidraPeekableIterator::new(vec![1, 2, 3].into_iter());
        assert_eq!(peekable.peek(), Some(&1));
        assert_eq!(peekable.peek(), Some(&1)); // peek doesn't consume
        assert_eq!(peekable.next(), Some(1));
        assert_eq!(peekable.peek(), Some(&2));
        assert_eq!(peekable.next(), Some(2));
        assert_eq!(peekable.next(), Some(3));
        assert!(peekable.peek().is_none());
    }

    #[test]
    fn test_merge_sorting_iterator() {
        let it1 = vec![1, 3, 5].into_iter();
        let it2 = vec![2, 4, 6].into_iter();
        let it3 = vec![0, 7].into_iter();
        let merged = MergeSortingIterator::new(vec![
            Box::new(it1) as Box<dyn Iterator<Item = i32>>,
            Box::new(it2),
            Box::new(it3),
        ]);
        let result: Vec<i32> = merged.collect();
        assert_eq!(result, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn test_flattened_iterator() {
        let outer: Vec<Box<dyn Iterator<Item = i32>>> = vec![
            Box::new(vec![1, 2].into_iter()),
            Box::new(vec![3, 4].into_iter()),
            Box::new(vec![5].into_iter()),
        ];
        let flat = FlattenedIterator::new(outer.into_iter());
        let result: Vec<i32> = flat.collect();
        assert_eq!(result, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_wrapping_iterator() {
        let mut wrap = WrappingIterator::new(vec![1, 2, 3]);
        assert_eq!(wrap.current(), Some(&1));
        assert_eq!(wrap.peek(), Some(&2));
        assert_eq!(wrap.next(), Some(1));
        assert_eq!(wrap.next(), Some(2));
        assert_eq!(wrap.next(), Some(3));
        // Wraps around
        assert_eq!(wrap.next(), Some(1));
    }

    #[test]
    fn test_wrapping_iterator_empty() {
        let mut wrap: WrappingIterator<i32> = WrappingIterator::new(vec![]);
        assert!(wrap.next().is_none());
        assert!(wrap.current().is_none());
        assert!(wrap.peek().is_none());
    }

    #[test]
    fn test_multi_iterator_empty() {
        let empty: Vec<Box<dyn Iterator<Item = i32>>> = vec![];
        let multi = MultiIterator::new(empty);
        let result: Vec<i32> = multi.collect();
        assert!(result.is_empty());
    }

    #[test]
    fn test_filtered_iterator_all_pass() {
        let data = vec![1, 2, 3];
        let filtered: Vec<i32> =
            FilteredIterator::new(data.into_iter(), |_| true).collect();
        assert_eq!(filtered, vec![1, 2, 3]);
    }

    #[test]
    fn test_filtered_iterator_none_pass() {
        let data = vec![1, 2, 3];
        let filtered: Vec<i32> =
            FilteredIterator::new(data.into_iter(), |_| false).collect();
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_merge_sorting_single_source() {
        let it = vec![1, 2, 3].into_iter();
        let merged = MergeSortingIterator::new(vec![
            Box::new(it) as Box<dyn Iterator<Item = i32>>
        ]);
        let result: Vec<i32> = merged.collect();
        // MergeSortingIterator merges sorted sources; single source preserves order
        assert_eq!(result, vec![1, 2, 3]);
    }
}
