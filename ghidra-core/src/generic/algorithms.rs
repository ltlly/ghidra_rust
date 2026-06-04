//! Algorithm utilities for Ghidra Rust.
//!
//! Ports Ghidra's `generic.algorithms` package: LCS (Longest Common
//! Subsequence) computation, word diffing, and reducing LCS variants.

// ============================================================================
// LCS — Longest Common Subsequence
// ============================================================================

/// Compute the Longest Common Subsequence (LCS) of two slices.
///
/// Returns the length of the LCS.
///
/// Corresponds to Ghidra's `generic.algorithms.Lcs`.
pub fn lcs_length<T: PartialEq>(a: &[T], b: &[T]) -> usize {
    let m = a.len();
    let n = b.len();
    if m == 0 || n == 0 {
        return 0;
    }

    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            if a[i - 1] == b[j - 1] {
                dp[i][j] = dp[i - 1][j - 1] + 1;
            } else {
                dp[i][j] = dp[i - 1][j].max(dp[i][j - 1]);
            }
        }
    }
    dp[m][n]
}

/// Compute the LCS and return the actual subsequence elements.
///
/// Returns the shared elements in order.
pub fn lcs<T: PartialEq + Clone>(a: &[T], b: &[T]) -> Vec<T> {
    let m = a.len();
    let n = b.len();
    if m == 0 || n == 0 {
        return Vec::new();
    }

    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            if a[i - 1] == b[j - 1] {
                dp[i][j] = dp[i - 1][j - 1] + 1;
            } else {
                dp[i][j] = dp[i - 1][j].max(dp[i][j - 1]);
            }
        }
    }

    // Backtrack
    let mut result = Vec::new();
    let (mut i, mut j) = (m, n);
    while i > 0 && j > 0 {
        if a[i - 1] == b[j - 1] {
            result.push(a[i - 1].clone());
            i -= 1;
            j -= 1;
        } else if dp[i - 1][j] > dp[i][j - 1] {
            i -= 1;
        } else {
            j -= 1;
        }
    }
    result.reverse();
    result
}

/// Compute the LCS length using a memory-optimized O(min(m,n)) approach.
///
/// Corresponds to Ghidra's `generic.algorithms.ReducingLcs`.
pub fn lcs_length_reducing<T: PartialEq>(a: &[T], b: &[T]) -> usize {
    let m = a.len();
    let n = b.len();
    if m == 0 || n == 0 {
        return 0;
    }

    // Ensure we iterate over the shorter one to minimize memory
    let (short, long) = if m <= n { (a, b) } else { (b, a) };

    let mut prev = vec![0usize; short.len() + 1];
    let mut curr = vec![0usize; short.len() + 1];

    for i in 1..=long.len() {
        for j in 1..=short.len() {
            if long[i - 1] == short[j - 1] {
                curr[j] = prev[j - 1] + 1;
            } else {
                curr[j] = prev[j].max(curr[j - 1]);
            }
        }
        std::mem::swap(&mut prev, &mut curr);
        curr.fill(0);
    }
    prev[short.len()]
}

// ============================================================================
// WordDiffer — diff two strings by word boundaries
// ============================================================================

/// A diff operation between two word sequences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffOp<T> {
    /// An element present only in the left sequence.
    Delete(T),
    /// An element present only in the right sequence.
    Insert(T),
    /// An element present in both sequences.
    Equal(T),
}

/// Compute a word-level diff between two slices.
///
/// Returns a sequence of `DiffOp` that transforms `old` into `new_`.
///
/// Corresponds to Ghidra's `generic.algorithms.WordDiffer`.
pub fn word_diff<T: PartialEq + Clone>(old: &[T], new_: &[T]) -> Vec<DiffOp<T>> {
    let lcs_result = lcs(old, new_);
    let mut result = Vec::new();
    let mut i = 0;
    let mut j = 0;
    let mut k = 0;

    while i < old.len() || j < new_.len() {
        if k < lcs_result.len() && i < old.len() && old[i] == lcs_result[k] {
            if j < new_.len() && new_[j] == lcs_result[k] {
                result.push(DiffOp::Equal(lcs_result[k].clone()));
                i += 1;
                j += 1;
                k += 1;
            } else {
                result.push(DiffOp::Insert(new_[j].clone()));
                j += 1;
            }
        } else if j < new_.len() && k < lcs_result.len() && new_[j] == lcs_result[k] {
            result.push(DiffOp::Delete(old[i].clone()));
            i += 1;
        } else {
            if i < old.len() {
                result.push(DiffOp::Delete(old[i].clone()));
                i += 1;
            }
            if j < new_.len() {
                result.push(DiffOp::Insert(new_[j].clone()));
                j += 1;
            }
        }
    }
    result
}

/// Diff two strings by splitting on whitespace.
pub fn string_word_diff(old: &str, new_: &str) -> Vec<DiffOp<String>> {
    let old_words: Vec<String> = old.split_whitespace().map(|s| s.to_string()).collect();
    let new_words: Vec<String> = new_.split_whitespace().map(|s| s.to_string()).collect();
    word_diff(&old_words, &new_words)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lcs_length_basic() {
        assert_eq!(lcs_length(b"ABCBDAB", b"BDCAB"), 4);
        assert_eq!(lcs_length(b"", b"abc"), 0);
        assert_eq!(lcs_length(b"abc", b"abc"), 3);
    }

    #[test]
    fn test_lcs_elements() {
        let a = vec!['A', 'B', 'C', 'B', 'D', 'A', 'B'];
        let b = vec!['B', 'D', 'C', 'A', 'B'];
        let result = lcs(&a, &b);
        assert_eq!(result.len(), 4);
        // LCS could be B,C,A,B or B,D,A,B
    }

    #[test]
    fn test_lcs_identical() {
        let a = vec![1, 2, 3];
        let result = lcs(&a, &a);
        assert_eq!(result, vec![1, 2, 3]);
    }

    #[test]
    fn test_lcs_no_common() {
        let a = vec![1, 2, 3];
        let b = vec![4, 5, 6];
        let result = lcs(&a, &b);
        assert!(result.is_empty());
    }

    #[test]
    fn test_lcs_reducing() {
        assert_eq!(lcs_length_reducing(b"ABCBDAB", b"BDCAB"), 4);
        assert_eq!(lcs_length_reducing(b"", b"abc"), 0);
        assert_eq!(lcs_length_reducing(b"abc", b"abc"), 3);
    }

    #[test]
    fn test_word_diff() {
        let old = vec!["a", "b", "c"];
        let new_ = vec!["a", "x", "c"];
        let diff = word_diff(&old, &new_);
        assert!(diff.contains(&DiffOp::Equal("a")));
        assert!(diff.contains(&DiffOp::Equal("c")));
        assert!(diff.contains(&DiffOp::Delete("b")));
        assert!(diff.contains(&DiffOp::Insert("x")));
    }

    #[test]
    fn test_string_word_diff() {
        let diff = string_word_diff("hello world", "hello brave world");
        // "hello" and "world" should be equal, "brave" should be inserted
        assert!(diff.contains(&DiffOp::Equal("hello".to_string())));
        assert!(diff.contains(&DiffOp::Equal("world".to_string())));
        assert!(diff.contains(&DiffOp::Insert("brave".to_string())));
    }

    #[test]
    fn test_word_diff_identical() {
        let old = vec!["a", "b"];
        let new_ = vec!["a", "b"];
        let diff = word_diff(&old, &new_);
        assert_eq!(diff, vec![
            DiffOp::Equal("a"),
            DiffOp::Equal("b"),
        ]);
    }
}
