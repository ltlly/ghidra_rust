//! Aggregated result for a single executable in BSim search results.
//!
//! Ports Ghidra's `ghidra.features.bsim.gui.search.results.ExecutableResult`.

use super::b_sim_match_result::BSimMatchResult;

/// Aggregates match information for a single executable.
///
/// Each `ExecutableResult` tracks the number of matching functions
/// and the sum of their significance scores.
#[derive(Debug, Clone)]
pub struct ExecutableResult {
    /// Name of the executable.
    pub executable_name: String,
    /// MD5 of the executable.
    pub md5: String,
    /// Architecture of the executable.
    pub architecture: String,
    /// Compiler used to build the executable.
    pub compiler: String,
    /// Number of matching functions.
    function_count: usize,
    /// Sum of significance scores for all matching functions.
    significance_sum: f64,
}

impl ExecutableResult {
    /// Create a new empty executable result.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new executable result with the given executable info.
    pub fn with_info(
        executable_name: String,
        md5: String,
        architecture: String,
        compiler: String,
    ) -> Self {
        Self {
            executable_name,
            md5,
            architecture,
            compiler,
            function_count: 0,
            significance_sum: 0.0,
        }
    }

    /// Add a matching function with the given significance.
    pub fn add_function(&mut self, significance: f64) {
        self.function_count += 1;
        self.significance_sum += significance;
    }

    /// Get the number of functions with matches into this executable.
    pub fn function_count(&self) -> usize {
        self.function_count
    }

    /// Get the sum of significance scores for all matching functions.
    pub fn significance_sum(&self) -> f64 {
        self.significance_sum
    }

    /// Generate executable results from match rows.
    ///
    /// For each unique executable, aggregates the maximum significance
    /// per original function, then sums across all original functions.
    pub fn generate_from_match_rows(match_rows: &[BSimMatchResult]) -> Vec<ExecutableResult> {
        use std::collections::BTreeMap;

        // Map: (original_func_name, executable_md5) -> max significance
        let mut per_func_exe: BTreeMap<(String, String), f64> = BTreeMap::new();
        // Map: executable_md5 -> ExecutableResult info
        let mut exe_info: BTreeMap<String, ExecutableResult> = BTreeMap::new();

        for row in match_rows {
            let key = (row.original_function_name.clone(), row.md5.clone());
            let entry = per_func_exe.entry(key).or_insert(0.0);
            if row.significance > *entry {
                *entry = row.significance;
            }

            exe_info.entry(row.md5.clone()).or_insert_with(|| {
                ExecutableResult::with_info(
                    row.executable_name.clone(),
                    row.md5.clone(),
                    row.architecture.clone(),
                    row.compiler_name.clone(),
                )
            });
        }

        // Aggregate per-function significances into each executable
        let mut results: Vec<ExecutableResult> = exe_info.into_values().collect();
        for ((_func_name, exe_md5), sig) in &per_func_exe {
            if let Some(result) = results.iter_mut().find(|r| &r.md5 == exe_md5) {
                result.add_function(*sig);
            }
        }

        results
    }
}

impl Default for ExecutableResult {
    fn default() -> Self {
        Self {
            executable_name: String::new(),
            md5: String::new(),
            architecture: String::new(),
            compiler: String::new(),
            function_count: 0,
            significance_sum: 0.0,
        }
    }
}

impl PartialEq for ExecutableResult {
    fn eq(&self, other: &Self) -> bool {
        self.md5 == other.md5
    }
}

impl Eq for ExecutableResult {}

impl PartialOrd for ExecutableResult {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ExecutableResult {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.md5.cmp(&other.md5)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let r = ExecutableResult::new();
        assert_eq!(r.function_count(), 0);
        assert_eq!(r.significance_sum(), 0.0);
    }

    #[test]
    fn test_add_function() {
        let mut r = ExecutableResult::new();
        r.add_function(5.0);
        r.add_function(3.0);
        assert_eq!(r.function_count(), 2);
        assert!((r.significance_sum() - 8.0).abs() < 1e-9);
    }

    #[test]
    fn test_with_info() {
        let r = ExecutableResult::with_info(
            "test.exe".to_string(),
            "abc123".to_string(),
            "x86".to_string(),
            "gcc".to_string(),
        );
        assert_eq!(r.executable_name, "test.exe");
        assert_eq!(r.function_count(), 0);
    }

    #[test]
    fn test_ordering() {
        let a = ExecutableResult::with_info(
            "a.exe".to_string(),
            "aaa".to_string(),
            "x86".to_string(),
            "gcc".to_string(),
        );
        let b = ExecutableResult::with_info(
            "b.exe".to_string(),
            "bbb".to_string(),
            "x86".to_string(),
            "gcc".to_string(),
        );
        assert!(a < b);
    }

    #[test]
    fn test_equality_by_md5() {
        let a = ExecutableResult::with_info(
            "a.exe".to_string(),
            "same_md5".to_string(),
            "x86".to_string(),
            "gcc".to_string(),
        );
        let b = ExecutableResult::with_info(
            "b.exe".to_string(),
            "same_md5".to_string(),
            "arm".to_string(),
            "clang".to_string(),
        );
        assert_eq!(a, b);
    }
}
