//! ExternalLocationIterator -- iterating over external locations.
//!
//! Ported from `ghidra.program.model.symbol.ExternalLocationIterator`
//! (interface) and `ExternalManagerDB.ExternalLocationDBIterator`
//! (implementation).
//!
//! Provides a standard iterator interface over external locations,
//! optionally filtered by memory address.

use super::external_location_db::ExternalLocationDB;

/// Iterator over external locations.
///
/// This trait mirrors the Java `ExternalLocationIterator` interface,
/// which extends `Iterator<ExternalLocation>`.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::external_location_iterator::*;
/// use ghidra_features::external::ExternalLocationDB;
/// use ghidra_core::symbol::SourceType;
/// use ghidra_core::Address;
///
/// let locations = vec![
///     ExternalLocationDB::new_function("libc", "printf", Some(Address::new(0x1000)), SourceType::Imported),
///     ExternalLocationDB::new_function("libc", "puts", Some(Address::new(0x2000)), SourceType::Imported),
///     ExternalLocationDB::new_function("libm", "sin", Some(Address::new(0x3000)), SourceType::Imported),
/// ];
///
/// let mut iter = ExternalLocationVecIterator::new(locations);
/// assert!(iter.has_next());
///
/// let first = ExternalLocationIterator::next(&mut iter).unwrap();
/// assert_eq!(first.label(), Some("printf"));
///
/// assert_eq!(Iterator::count(&mut iter), 2); // consume the rest
/// ```
pub trait ExternalLocationIterator {
    /// Returns `true` if there is another external location available.
    fn has_next(&mut self) -> bool;

    /// Returns the next external location, or `None` if exhausted.
    fn next(&mut self) -> Option<ExternalLocationDB>;
}

/// A simple vector-backed external location iterator.
///
/// Iterates over a pre-built list of external locations in order.
#[derive(Debug, Clone)]
pub struct ExternalLocationVecIterator {
    locations: Vec<ExternalLocationDB>,
    index: usize,
}

impl ExternalLocationVecIterator {
    /// Create a new iterator over the given locations.
    pub fn new(locations: Vec<ExternalLocationDB>) -> Self {
        Self {
            locations,
            index: 0,
        }
    }

    /// Create an empty iterator.
    pub fn empty() -> Self {
        Self {
            locations: Vec::new(),
            index: 0,
        }
    }

    /// Returns the number of remaining elements.
    pub fn remaining(&self) -> usize {
        self.locations.len().saturating_sub(self.index)
    }
}

impl ExternalLocationIterator for ExternalLocationVecIterator {
    fn has_next(&mut self) -> bool {
        self.index < self.locations.len()
    }

    fn next(&mut self) -> Option<ExternalLocationDB> {
        if self.index < self.locations.len() {
            let loc = self.locations[self.index].clone();
            self.index += 1;
            Some(loc)
        } else {
            None
        }
    }
}

impl Iterator for ExternalLocationVecIterator {
    type Item = ExternalLocationDB;

    fn next(&mut self) -> Option<Self::Item> {
        ExternalLocationIterator::next(self)
    }
}

/// An external location iterator that filters by a matching memory address.
///
/// Ported from the inner `ExternalLocationDBIterator` class in
/// `ExternalManagerDB.java`.  When a `matching_address` is specified,
/// only locations whose external program address matches are yielded.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::external_location_iterator::*;
/// use ghidra_features::external::ExternalLocationDB;
/// use ghidra_core::symbol::SourceType;
/// use ghidra_core::Address;
///
/// let locations = vec![
///     ExternalLocationDB::new_function("libc", "printf", Some(Address::new(0x1000)), SourceType::Imported),
///     ExternalLocationDB::new_function("libc", "puts", Some(Address::new(0x2000)), SourceType::Imported),
/// ];
///
/// // Filter to only locations at address 0x1000
/// let mut iter = FilteredExternalLocationIterator::new(locations, Some(Address::new(0x1000)));
/// assert!(iter.has_next());
/// let loc = ExternalLocationIterator::next(&mut iter).unwrap();
/// assert_eq!(loc.label(), Some("printf"));
/// assert!(!iter.has_next()); // "puts" doesn't match
/// ```
#[derive(Debug, Clone)]
pub struct FilteredExternalLocationIterator {
    locations: Vec<ExternalLocationDB>,
    index: usize,
    matching_address: Option<ghidra_core::addr::Address>,
}

impl FilteredExternalLocationIterator {
    /// Create a new filtered iterator.
    ///
    /// If `matching_address` is `None`, all locations are yielded.
    pub fn new(
        locations: Vec<ExternalLocationDB>,
        matching_address: Option<ghidra_core::addr::Address>,
    ) -> Self {
        Self {
            locations,
            index: 0,
            matching_address,
        }
    }

    /// Create an empty filtered iterator.
    pub fn empty(matching_address: Option<ghidra_core::addr::Address>) -> Self {
        Self {
            locations: Vec::new(),
            index: 0,
            matching_address,
        }
    }

    /// Check whether a location matches the address filter.
    fn matches(&self, loc: &ExternalLocationDB) -> bool {
        match self.matching_address {
            Some(addr) => loc.external_program_address() == Some(addr),
            None => true,
        }
    }
}

impl ExternalLocationIterator for FilteredExternalLocationIterator {
    fn has_next(&mut self) -> bool {
        // Scan forward to find the next matching location
        while self.index < self.locations.len() {
            if self.matches(&self.locations[self.index]) {
                return true;
            }
            self.index += 1;
        }
        false
    }

    fn next(&mut self) -> Option<ExternalLocationDB> {
        while self.index < self.locations.len() {
            let loc = self.locations[self.index].clone();
            self.index += 1;
            if self.matches(&loc) {
                return Some(loc);
            }
        }
        None
    }
}

impl Iterator for FilteredExternalLocationIterator {
    type Item = ExternalLocationDB;

    fn next(&mut self) -> Option<Self::Item> {
        ExternalLocationIterator::next(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;
    use ghidra_core::symbol::SourceType;

    fn make_locations() -> Vec<ExternalLocationDB> {
        vec![
            ExternalLocationDB::new_function(
                "libc",
                "printf",
                Some(Address::new(0x1000)),
                SourceType::Imported,
            ),
            ExternalLocationDB::new_function(
                "libc",
                "puts",
                Some(Address::new(0x2000)),
                SourceType::Imported,
            ),
            ExternalLocationDB::new_function(
                "libm",
                "sin",
                Some(Address::new(0x3000)),
                SourceType::Imported,
            ),
        ]
    }

    #[test]
    fn test_vec_iterator_basic() {
        let mut iter = ExternalLocationVecIterator::new(make_locations());
        assert!(ExternalLocationIterator::has_next(&mut iter));

        let first = ExternalLocationIterator::next(&mut iter).unwrap();
        assert_eq!(first.label(), Some("printf"));

        let second = ExternalLocationIterator::next(&mut iter).unwrap();
        assert_eq!(second.label(), Some("puts"));

        let third = ExternalLocationIterator::next(&mut iter).unwrap();
        assert_eq!(third.label(), Some("sin"));

        assert!(!ExternalLocationIterator::has_next(&mut iter));
        assert!(ExternalLocationIterator::next(&mut iter).is_none());
    }

    #[test]
    fn test_vec_iterator_empty() {
        let mut iter = ExternalLocationVecIterator::empty();
        assert!(!ExternalLocationIterator::has_next(&mut iter));
        assert!(ExternalLocationIterator::next(&mut iter).is_none());
    }

    #[test]
    fn test_vec_iterator_remaining() {
        let mut iter = ExternalLocationVecIterator::new(make_locations());
        assert_eq!(iter.remaining(), 3);
        ExternalLocationIterator::next(&mut iter);
        assert_eq!(iter.remaining(), 2);
        ExternalLocationIterator::next(&mut iter);
        assert_eq!(iter.remaining(), 1);
        ExternalLocationIterator::next(&mut iter);
        assert_eq!(iter.remaining(), 0);
    }

    #[test]
    fn test_vec_iterator_std_trait() {
        let iter = ExternalLocationVecIterator::new(make_locations());
        let names: Vec<_> = iter.filter_map(|loc| loc.label().map(String::from)).collect();
        assert_eq!(names, vec!["printf", "puts", "sin"]);
    }

    #[test]
    fn test_filtered_iterator_with_address() {
        let mut iter =
            FilteredExternalLocationIterator::new(make_locations(), Some(Address::new(0x2000)));
        assert!(ExternalLocationIterator::has_next(&mut iter));
        let loc = ExternalLocationIterator::next(&mut iter).unwrap();
        assert_eq!(loc.label(), Some("puts"));
        assert!(!ExternalLocationIterator::has_next(&mut iter));
    }

    #[test]
    fn test_filtered_iterator_no_match() {
        let mut iter =
            FilteredExternalLocationIterator::new(make_locations(), Some(Address::new(0x9999)));
        assert!(!ExternalLocationIterator::has_next(&mut iter));
        assert!(ExternalLocationIterator::next(&mut iter).is_none());
    }

    #[test]
    fn test_filtered_iterator_no_filter() {
        let mut iter = FilteredExternalLocationIterator::new(make_locations(), None);
        assert!(ExternalLocationIterator::has_next(&mut iter));
        assert_eq!(ExternalLocationIterator::next(&mut iter).unwrap().label(), Some("printf"));
        assert_eq!(ExternalLocationIterator::next(&mut iter).unwrap().label(), Some("puts"));
        assert_eq!(ExternalLocationIterator::next(&mut iter).unwrap().label(), Some("sin"));
        assert!(!ExternalLocationIterator::has_next(&mut iter));
    }

    #[test]
    fn test_filtered_iterator_empty() {
        let mut iter = FilteredExternalLocationIterator::empty(None);
        assert!(!ExternalLocationIterator::has_next(&mut iter));
        assert!(ExternalLocationIterator::next(&mut iter).is_none());
    }

    #[test]
    fn test_filtered_iterator_std_trait() {
        let iter =
            FilteredExternalLocationIterator::new(make_locations(), Some(Address::new(0x1000)));
        let names: Vec<_> = iter.filter_map(|loc| loc.label().map(String::from)).collect();
        assert_eq!(names, vec!["printf"]);
    }

    #[test]
    fn test_filtered_iterator_multiple_same_address() {
        let locations = vec![
            ExternalLocationDB::new_function(
                "libc",
                "printf",
                Some(Address::new(0x1000)),
                SourceType::Imported,
            ),
            ExternalLocationDB::new_data(
                "libc",
                "errno",
                Some(Address::new(0x1000)),
                SourceType::Analysis,
            ),
        ];

        let mut iter =
            FilteredExternalLocationIterator::new(locations, Some(Address::new(0x1000)));
        assert_eq!(ExternalLocationIterator::next(&mut iter).unwrap().label(), Some("printf"));
        assert_eq!(ExternalLocationIterator::next(&mut iter).unwrap().label(), Some("errno"));
        assert!(!ExternalLocationIterator::has_next(&mut iter));
    }
}
