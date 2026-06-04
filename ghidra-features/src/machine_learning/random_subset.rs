//! Random subset utilities.
//!
//! Ported from `RandomSubsetUtils.java` in the MachineLearning extension.
//!
//! Generates random subsets of address ranges using a Fisher-Yates
//! permutation-based approach.

use std::collections::HashMap;

/// Utility class for generating random subsets.
///
/// Uses a lazy Fisher-Yates permutation to select `k` random indices
/// from `[0, n)` without materializing the full permutation array.
pub struct RandomSubsetUtils;

impl RandomSubsetUtils {
    /// Generate a random subset of size `k` from the set `[0, 1, ..., n-1]`.
    ///
    /// Uses a sparse Fisher-Yates permutation: only the first `k` elements
    /// of the permutation are computed, using a `HashMap` to track swaps
    /// instead of allocating a full `n`-element array.
    ///
    /// # Parameters
    ///
    /// * `n` -- total number of elements (must be >= 0)
    /// * `k` -- size of the subset (must be <= `n`)
    /// * `rng` -- a function that returns a random `u64` in `[low, high)`
    ///
    /// # Returns
    ///
    /// A `Vec<u64>` of `k` indices in `[0, n)`.
    ///
    /// # Panics
    ///
    /// Panics if `k > n`.
    pub fn generate_random_integer_subset<F>(n: u64, k: u64, mut rng: F) -> Vec<u64>
    where
        F: FnMut(u64, u64) -> u64,
    {
        assert!(k <= n, "size of subset ({k}) cannot be larger than size of set ({n})");

        // Sparse permutation: only track elements that have been swapped.
        let mut permutation: HashMap<u64, u64> = HashMap::new();

        for i in 0..k {
            let j = rng(i, n);
            Self::swap(&mut permutation, i, j);
        }

        let mut result = Vec::with_capacity(k as usize);
        for i in 0..k {
            let val = permutation.get(&i).copied().unwrap_or(i);
            result.push(val);
        }
        result
    }

    /// Swap two elements in the sparse permutation.
    ///
    /// Elements not in the map are assumed to map to themselves (p(i) = i).
    fn swap(permutation: &mut HashMap<u64, u64>, i: u64, j: u64) {
        if i == j {
            return;
        }
        let ith = permutation.get(&i).copied().unwrap_or(i);
        let jth = permutation.get(&j).copied().unwrap_or(j);
        permutation.insert(i, jth);
        permutation.insert(j, ith);
    }

    /// Generate a random subset of addresses from an address range list.
    ///
    /// # Parameters
    ///
    /// * `ranges` -- sorted list of `(start, end)` address ranges (inclusive).
    ///   Ranges must be non-overlapping and sorted by start address.
    /// * `k` -- number of addresses to randomly select.
    /// * `rng` -- random number generator function.
    ///
    /// # Returns
    ///
    /// A `Vec<u64>` of `k` randomly selected addresses from the ranges.
    pub fn random_subset_from_ranges<F>(
        ranges: &[(u64, u64)],
        k: u64,
        rng: F,
    ) -> Vec<u64>
    where
        F: FnMut(u64, u64) -> u64,
    {
        let total: u64 = ranges.iter().map(|(s, e)| e - s + 1).sum();
        let k = k.min(total);
        let indices = Self::generate_random_integer_subset(total, k, rng);

        let mut sorted_indices = indices;
        sorted_indices.sort_unstable();

        let mut addresses = Vec::with_capacity(sorted_indices.len());
        let mut visited = 0u64;
        let mut list_idx = 0;

        for &(start, end) in ranges {
            let range_len = end - start + 1;
            let range_end = visited + range_len;

            while list_idx < sorted_indices.len() {
                let next = sorted_indices[list_idx];
                if next >= range_end {
                    break;
                }
                addresses.push(start + (next - visited));
                list_idx += 1;
            }

            if list_idx >= sorted_indices.len() {
                break;
            }
            visited += range_len;
        }

        addresses
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic "random" number generator for testing.
    /// Returns consecutive values from a pre-defined sequence.
    struct DeterministicRng {
        values: Vec<(u64, u64)>,
        idx: usize,
    }

    impl DeterministicRng {
        fn new(values: Vec<(u64, u64)>) -> Self {
            Self { values, idx: 0 }
        }

        fn call(&mut self, low: u64, high: u64) -> u64 {
            if self.idx < self.values.len() {
                let (l, h) = self.values[self.idx];
                self.idx += 1;
                assert_eq!(l, low);
                assert_eq!(h, high);
                l
            } else {
                low
            }
        }
    }

    #[test]
    fn test_generate_subset_k_equals_n() {
        // When k == n, the subset is [0, 1, ..., n-1].
        let result = RandomSubsetUtils::generate_random_integer_subset(5, 5, |low, _high| low);
        let mut sorted = result.clone();
        sorted.sort();
        assert_eq!(sorted, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn test_generate_subset_k_zero() {
        let result = RandomSubsetUtils::generate_random_integer_subset(100, 0, |low, _| low);
        assert!(result.is_empty());
    }

    #[test]
    fn test_generate_subset_no_duplicates() {
        let result = RandomSubsetUtils::generate_random_integer_subset(100, 50, |low, _| low);
        let mut sorted = result.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 50);
    }

    #[test]
    #[should_panic(expected = "cannot be larger")]
    fn test_generate_subset_k_greater_than_n() {
        RandomSubsetUtils::generate_random_integer_subset(5, 10, |low, _| low);
    }

    #[test]
    fn test_swap_basic() {
        let mut perm = HashMap::new();
        RandomSubsetUtils::swap(&mut perm, 0, 3);
        assert_eq!(perm[&0], 3);
        assert_eq!(perm[&3], 0);
    }

    #[test]
    fn test_swap_identity() {
        let mut perm = HashMap::new();
        RandomSubsetUtils::swap(&mut perm, 5, 5);
        assert!(perm.is_empty());
    }

    #[test]
    fn test_random_subset_from_ranges() {
        let ranges = vec![(10, 14), (20, 24)];
        // Total: 10 addresses. Pick 3.
        let result =
            RandomSubsetUtils::random_subset_from_ranges(&ranges, 3, |low, _high| low);
        assert_eq!(result.len(), 3);
        // All addresses should be within the ranges
        for &addr in &result {
            assert!(
                (10..=14).contains(&addr) || (20..=24).contains(&addr),
                "Address {addr} outside ranges"
            );
        }
    }

    #[test]
    fn test_random_subset_from_ranges_k_greater_than_total() {
        let ranges = vec![(0, 2)];
        // Total: 3 addresses. Pick 5 -> capped to 3.
        let result =
            RandomSubsetUtils::random_subset_from_ranges(&ranges, 5, |low, _| low);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_random_subset_sorted_output() {
        let ranges = vec![(0, 99)];
        let result =
            RandomSubsetUtils::random_subset_from_ranges(&ranges, 10, |low, _| low);
        // Output should be sorted (indices are sorted before mapping)
        for window in result.windows(2) {
            assert!(window[0] <= window[1]);
        }
    }
}
