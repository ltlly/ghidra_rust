//! Search result combiners -- set operations on search results.
//!
//! Ported from `ghidra.features.base.memsearch.combiner`.
//!
//! Each [`Combiner`] determines how to merge two sets of memory search results.

use std::collections::BTreeSet;

use crate::memsearch::searcher::MemoryMatch;

/// Enum of search result combiner operations.
///
/// Determines how new search results are combined with existing results.
/// "A" represents current/existing results, "B" represents new results.
///
/// Ported from `ghidra.features.base.memsearch.combiner.Combiner`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Combiner {
    /// Replace all existing results with new results.
    Replace,
    /// Add new results to existing results (union).
    Union,
    /// Keep only addresses present in both sets.
    Intersect,
    /// Keep addresses present in exactly one set (symmetric difference).
    Xor,
    /// Keep existing results minus new results (A - B).
    AMinusB,
    /// Keep new results minus existing results (B - A).
    BMinusA,
}

impl Combiner {
    /// Get the display name of this combiner.
    pub fn name(&self) -> &str {
        match self {
            Combiner::Replace => "New",
            Combiner::Union => "Add To",
            Combiner::Intersect => "Intersect",
            Combiner::Xor => "Xor",
            Combiner::AMinusB => "A-B",
            Combiner::BMinusA => "B-A",
        }
    }

    /// Returns true if this combiner merges results (not a full replace).
    pub fn is_merge(&self) -> bool {
        *self != Combiner::Replace
    }

    /// Combine two sets of memory matches.
    pub fn combine(
        &self,
        existing: &[MemoryMatch],
        new_results: &[MemoryMatch],
    ) -> Vec<MemoryMatch> {
        match self {
            Combiner::Replace => replace(existing, new_results),
            Combiner::Union => union(existing, new_results),
            Combiner::Intersect => intersect(existing, new_results),
            Combiner::Xor => xor(existing, new_results),
            Combiner::AMinusB => a_minus_b(existing, new_results),
            Combiner::BMinusA => b_minus_a(existing, new_results),
        }
    }

    /// Get all available combiners.
    pub fn all() -> [Combiner; 6] {
        [
            Combiner::Replace,
            Combiner::Union,
            Combiner::Intersect,
            Combiner::Xor,
            Combiner::AMinusB,
            Combiner::BMinusA,
        ]
    }
}

impl std::fmt::Display for Combiner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

fn address_set(matches: &[MemoryMatch]) -> BTreeSet<u64> {
    matches.iter().map(|m| m.address()).collect()
}

fn replace(_existing: &[MemoryMatch], new_results: &[MemoryMatch]) -> Vec<MemoryMatch> {
    new_results.to_vec()
}

fn union(existing: &[MemoryMatch], new_results: &[MemoryMatch]) -> Vec<MemoryMatch> {
    let mut result: Vec<MemoryMatch> = existing.to_vec();
    let existing_addrs: BTreeSet<u64> = address_set(existing);
    for m in new_results {
        if !existing_addrs.contains(&m.address()) {
            result.push(m.clone());
        }
    }
    result.sort();
    result
}

fn intersect(existing: &[MemoryMatch], new_results: &[MemoryMatch]) -> Vec<MemoryMatch> {
    let new_addrs = address_set(new_results);
    let mut result: Vec<MemoryMatch> = existing
        .iter()
        .filter(|m| new_addrs.contains(&m.address()))
        .cloned()
        .collect();
    result.sort();
    result
}

fn xor(existing: &[MemoryMatch], new_results: &[MemoryMatch]) -> Vec<MemoryMatch> {
    let existing_addrs = address_set(existing);
    let new_addrs = address_set(new_results);

    let mut result = Vec::new();
    for m in existing {
        if !new_addrs.contains(&m.address()) {
            result.push(m.clone());
        }
    }
    for m in new_results {
        if !existing_addrs.contains(&m.address()) {
            result.push(m.clone());
        }
    }
    result.sort();
    result
}

fn a_minus_b(existing: &[MemoryMatch], new_results: &[MemoryMatch]) -> Vec<MemoryMatch> {
    let new_addrs = address_set(new_results);
    let mut result: Vec<MemoryMatch> = existing
        .iter()
        .filter(|m| !new_addrs.contains(&m.address()))
        .cloned()
        .collect();
    result.sort();
    result
}

fn b_minus_a(existing: &[MemoryMatch], new_results: &[MemoryMatch]) -> Vec<MemoryMatch> {
    let existing_addrs = address_set(existing);
    let mut result: Vec<MemoryMatch> = new_results
        .iter()
        .filter(|m| !existing_addrs.contains(&m.address()))
        .cloned()
        .collect();
    result.sort();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_match(addr: u64) -> MemoryMatch {
        MemoryMatch::new(addr, vec![0x55])
    }

    fn make_matches(addrs: &[u64]) -> Vec<MemoryMatch> {
        addrs.iter().map(|a| make_match(*a)).collect()
    }

    #[test]
    fn test_replace() {
        let existing = make_matches(&[1, 2, 3]);
        let new = make_matches(&[4, 5]);
        let result = Combiner::Replace.combine(&existing, &new);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_union() {
        let existing = make_matches(&[1, 2, 3]);
        let new = make_matches(&[2, 3, 4]);
        let result = Combiner::Union.combine(&existing, &new);
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn test_intersect() {
        let existing = make_matches(&[1, 2, 3]);
        let new = make_matches(&[2, 3, 4]);
        let result = Combiner::Intersect.combine(&existing, &new);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_xor() {
        let existing = make_matches(&[1, 2, 3]);
        let new = make_matches(&[2, 3, 4]);
        let result = Combiner::Xor.combine(&existing, &new);
        assert_eq!(result.len(), 2); // 1 and 4
    }

    #[test]
    fn test_a_minus_b() {
        let existing = make_matches(&[1, 2, 3]);
        let new = make_matches(&[2, 3, 4]);
        let result = Combiner::AMinusB.combine(&existing, &new);
        assert_eq!(result.len(), 1); // 1
    }

    #[test]
    fn test_b_minus_a() {
        let existing = make_matches(&[1, 2, 3]);
        let new = make_matches(&[2, 3, 4]);
        let result = Combiner::BMinusA.combine(&existing, &new);
        assert_eq!(result.len(), 1); // 4
    }

    #[test]
    fn test_is_merge() {
        assert!(!Combiner::Replace.is_merge());
        assert!(Combiner::Union.is_merge());
        assert!(Combiner::Intersect.is_merge());
    }

    #[test]
    fn test_all_combiners() {
        assert_eq!(Combiner::all().len(), 6);
    }

    #[test]
    fn test_name() {
        assert_eq!(Combiner::Replace.name(), "New");
        assert_eq!(Combiner::Union.name(), "Add To");
        assert_eq!(Combiner::Intersect.name(), "Intersect");
    }
}
