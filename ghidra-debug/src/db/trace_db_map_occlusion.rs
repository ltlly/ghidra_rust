//! Occlusion iterators for address-snap range property maps.
//!
//! Ported from Ghidra's `ghidra.trace.database.map` package.
//! Provides iterators that compute occluded (shadowed) regions when
//! viewing property maps forward or backward in time.

use crate::model::lifespan::Lifespan;

/// Direction for occlusion queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcclusionDirection {
    /// Look forward in time (future values occlude past).
    IntoFuture,
    /// Look backward in time (past values occlude future).
    IntoPast,
}

/// A single occlusion entry: the value and its occluding time range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcclusionEntry<T: Clone> {
    /// The value being occluded.
    pub value: T,
    /// The lifespan of the original value.
    pub lifespan: Lifespan,
    /// The range of snaps that occlude this value.
    pub occluding_range: Option<Lifespan>,
}

impl<T: Clone> OcclusionEntry<T> {
    /// Create a new occlusion entry.
    pub fn new(value: T, lifespan: Lifespan, occluding_range: Option<Lifespan>) -> Self {
        Self {
            value,
            lifespan,
            occluding_range,
        }
    }

    /// Whether this entry is actually occluded (has an occluding range).
    pub fn is_occluded(&self) -> bool {
        self.occluding_range.is_some()
    }
}

/// Iterator over occluded property map entries looking into the future.
///
/// For each entry, computes the range of future snaps where a higher-priority
/// entry overrides the current one.
///
/// Corresponds to Java's `DBTraceAddressSnapRangePropertyMapOcclusionIntoFutureIterable`.
#[derive(Debug)]
pub struct OcclusionIntoFutureIterator<T: Clone> {
    entries: Vec<OcclusionEntry<T>>,
    index: usize,
}

impl<T: Clone> OcclusionIntoFutureIterator<T> {
    /// Create a new iterator over occluded entries looking into the future.
    pub fn new(entries: Vec<OcclusionEntry<T>>) -> Self {
        Self { entries, index: 0 }
    }

    /// Compute the occlusion range for a given lifespan looking into the future.
    ///
    /// Returns `None` if there's no occlusion, or `Some(range)` of occluding snaps.
    pub fn compute_occlusion_range(lifespan: &Lifespan) -> Option<Lifespan> {
        let lower = lifespan.lmin();
        if lower == i64::MIN {
            return None;
        }
        Some(Lifespan::span(i64::MIN, lower - 1))
    }
}

impl<T: Clone> Iterator for OcclusionIntoFutureIterator<T> {
    type Item = OcclusionEntry<T>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.entries.len() {
            return None;
        }
        let entry = self.entries[self.index].clone();
        self.index += 1;
        Some(entry)
    }
}

/// Iterator over occluded property map entries looking into the past.
///
/// For each entry, computes the range of past snaps where a higher-priority
/// entry overrides the current one.
///
/// Corresponds to Java's `DBTraceAddressSnapRangePropertyMapOcclusionIntoPastIterable`.
#[derive(Debug)]
pub struct OcclusionIntoPastIterator<T: Clone> {
    entries: Vec<OcclusionEntry<T>>,
    index: usize,
}

impl<T: Clone> OcclusionIntoPastIterator<T> {
    /// Create a new iterator over occluded entries looking into the past.
    pub fn new(entries: Vec<OcclusionEntry<T>>) -> Self {
        Self { entries, index: 0 }
    }

    /// Compute the occlusion range for a given lifespan looking into the past.
    ///
    /// Returns `None` if there's no occlusion, or `Some(range)` of occluding snaps.
    pub fn compute_occlusion_range(lifespan: &Lifespan) -> Option<Lifespan> {
        let upper = lifespan.lmax();
        if upper == i64::MAX {
            return None;
        }
        Some(Lifespan::span(upper + 1, i64::MAX))
    }
}

impl<T: Clone> Iterator for OcclusionIntoPastIterator<T> {
    type Item = OcclusionEntry<T>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.entries.len() {
            return None;
        }
        let entry = self.entries[self.index].clone();
        self.index += 1;
        Some(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_occlusion_direction() {
        assert_ne!(OcclusionDirection::IntoFuture, OcclusionDirection::IntoPast);
    }

    #[test]
    fn test_occlusion_entry_new() {
        let entry = OcclusionEntry::new(
            "test".to_string(),
            Lifespan::span(0, 100),
            None,
        );
        assert_eq!(entry.value, "test");
        assert!(!entry.is_occluded());
    }

    #[test]
    fn test_occlusion_entry_occluded() {
        let entry = OcclusionEntry::new(
            42u32,
            Lifespan::span(0, 100),
            Some(Lifespan::span(50, 100)),
        );
        assert!(entry.is_occluded());
    }

    #[test]
    fn test_occlusion_into_future_range() {
        let lifespan = Lifespan::span(10, 100);
        let range = OcclusionIntoFutureIterator::<()>::compute_occlusion_range(&lifespan);
        assert!(range.is_some());
        let r = range.unwrap();
        assert_eq!(r.lmin(), i64::MIN);
        assert_eq!(r.lmax(), 9);
    }

    #[test]
    fn test_occlusion_into_future_no_occlusion() {
        let lifespan = Lifespan::span(i64::MIN, 100);
        let range = OcclusionIntoFutureIterator::<()>::compute_occlusion_range(&lifespan);
        assert!(range.is_none());
    }

    #[test]
    fn test_occlusion_into_past_range() {
        let lifespan = Lifespan::span(0, 100);
        let range = OcclusionIntoPastIterator::<()>::compute_occlusion_range(&lifespan);
        assert!(range.is_some());
        let r = range.unwrap();
        assert_eq!(r.lmin(), 101);
        assert_eq!(r.lmax(), i64::MAX);
    }

    #[test]
    fn test_occlusion_into_past_no_occlusion() {
        let lifespan = Lifespan::span(0, i64::MAX);
        let range = OcclusionIntoPastIterator::<()>::compute_occlusion_range(&lifespan);
        assert!(range.is_none());
    }

    #[test]
    fn test_future_iterator_yields_entries() {
        let entries = vec![
            OcclusionEntry::new(1, Lifespan::span(0, 50), None),
            OcclusionEntry::new(2, Lifespan::span(51, 100), Some(Lifespan::span(75, 100))),
        ];
        let mut iter = OcclusionIntoFutureIterator::new(entries);
        assert_eq!(iter.next().unwrap().value, 1);
        assert_eq!(iter.next().unwrap().value, 2);
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_past_iterator_yields_entries() {
        let entries = vec![
            OcclusionEntry::new("a", Lifespan::span(0, 50), None),
            OcclusionEntry::new("b", Lifespan::span(51, 100), None),
        ];
        let mut iter = OcclusionIntoPastIterator::new(entries);
        let first = iter.next().unwrap();
        assert_eq!(first.value, "a");
        let second = iter.next().unwrap();
        assert_eq!(second.value, "b");
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_empty_iterator() {
        let mut iter = OcclusionIntoFutureIterator::<i32>::new(vec![]);
        assert!(iter.next().is_none());
    }
}
