//! BSim search results types.
//!
//! Port of Ghidra's `ghidra.features.bsim.gui.search.results` package.
//!
//! Provides data types for displaying, filtering, and applying BSim
//! search results (function similarity matches).

use super::{BSimMatchResult, BSimResultStatus};

/// A group of search results from the same executable.
#[derive(Debug, Clone)]
pub struct BSimResultGroup {
    /// The executable name.
    pub executable_name: String,
    /// The executable architecture.
    pub architecture: String,
    /// The results in this group.
    pub results: Vec<BSimMatchResult>,
    /// Whether this group is expanded in the UI.
    pub expanded: bool,
}

impl BSimResultGroup {
    /// Create a new result group.
    pub fn new(executable_name: String, architecture: String) -> Self {
        Self {
            executable_name,
            architecture,
            results: Vec::new(),
            expanded: true,
        }
    }

    /// Add a result to this group.
    pub fn add_result(&mut self, result: BSimMatchResult) {
        self.results.push(result);
    }

    /// Get the number of results.
    pub fn count(&self) -> usize {
        self.results.len()
    }

    /// Get the average similarity across all results.
    pub fn average_similarity(&self) -> f64 {
        if self.results.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.results.iter().map(|r| r.similarity).sum();
        sum / self.results.len() as f64
    }

    /// Get pending (not yet acted upon) results.
    pub fn pending_results(&self) -> Vec<&BSimMatchResult> {
        self.results
            .iter()
            .filter(|r| r.status == BSimResultStatus::Pending)
            .collect()
    }

    /// Get applied results.
    pub fn applied_results(&self) -> Vec<&BSimMatchResult> {
        self.results
            .iter()
            .filter(|r| r.status == BSimResultStatus::Applied)
            .collect()
    }

    /// Toggle the expanded state.
    pub fn toggle(&mut self) {
        self.expanded = !self.expanded;
    }
}

/// The complete set of search results, organized into groups.
#[derive(Debug, Clone, Default)]
pub struct BSimSearchResultModel {
    /// Result groups (one per executable).
    pub groups: Vec<BSimResultGroup>,
    /// The currently focused result (group index, result index).
    pub focused: Option<(usize, usize)>,
    /// Minimum similarity for display.
    pub display_threshold: f64,
    /// Sort order.
    pub sort_order: ResultSortOrder,
}

/// Sort order for search results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResultSortOrder {
    /// Sort by similarity (highest first).
    BySimilarity,
    /// Sort by confidence (highest first).
    ByConfidence,
    /// Sort by function name.
    ByName,
    /// Sort by executable.
    ByExecutable,
}

impl Default for ResultSortOrder {
    fn default() -> Self {
        Self::BySimilarity
    }
}

impl BSimSearchResultModel {
    /// Create a new empty result model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a result group.
    pub fn add_group(&mut self, group: BSimResultGroup) {
        self.groups.push(group);
    }

    /// Get the total number of results across all groups.
    pub fn total_results(&self) -> usize {
        self.groups.iter().map(|g| g.count()).sum()
    }

    /// Get the number of pending results across all groups.
    pub fn total_pending(&self) -> usize {
        self.groups.iter().map(|g| g.pending_results().len()).sum()
    }

    /// Get the number of applied results across all groups.
    pub fn total_applied(&self) -> usize {
        self.groups.iter().map(|g| g.applied_results().len()).sum()
    }

    /// Focus a specific result.
    pub fn focus(&mut self, group_index: usize, result_index: usize) {
        self.focused = Some((group_index, result_index));
    }

    /// Get the currently focused result.
    pub fn focused_result(&self) -> Option<&BSimMatchResult> {
        self.focused.and_then(|(gi, ri)| {
            self.groups.get(gi).and_then(|g| g.results.get(ri))
        })
    }

    /// Mark a result as applied.
    pub fn mark_applied(&mut self, group_index: usize, result_index: usize) {
        if let Some(group) = self.groups.get_mut(group_index) {
            if let Some(result) = group.results.get_mut(result_index) {
                result.status = BSimResultStatus::Applied;
            }
        }
    }

    /// Mark a result as ignored.
    pub fn mark_ignored(&mut self, group_index: usize, result_index: usize) {
        if let Some(group) = self.groups.get_mut(group_index) {
            if let Some(result) = group.results.get_mut(result_index) {
                result.status = BSimResultStatus::Ignored;
            }
        }
    }

    /// Mark a result as rejected.
    pub fn mark_rejected(&mut self, group_index: usize, result_index: usize) {
        if let Some(group) = self.groups.get_mut(group_index) {
            if let Some(result) = group.results.get_mut(result_index) {
                result.status = BSimResultStatus::Rejected;
            }
        }
    }

    /// Apply all pending results in all groups.
    pub fn apply_all_pending(&mut self) {
        for group in &mut self.groups {
            for result in &mut group.results {
                if result.status == BSimResultStatus::Pending {
                    result.status = BSimResultStatus::Applied;
                }
            }
        }
    }

    /// Sort all results within each group.
    pub fn sort(&mut self, order: ResultSortOrder) {
        self.sort_order = order;
        for group in &mut self.groups {
            match order {
                ResultSortOrder::BySimilarity => {
                    group.results.sort_by(|a, b| {
                        b.similarity.partial_cmp(&a.similarity).unwrap_or(std::cmp::Ordering::Equal)
                    });
                }
                ResultSortOrder::ByConfidence => {
                    group.results.sort_by(|a, b| {
                        b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal)
                    });
                }
                ResultSortOrder::ByName => {
                    group.results.sort_by(|a, b| {
                        a.matched_function_name.cmp(&b.matched_function_name)
                    });
                }
                ResultSortOrder::ByExecutable => {
                    // Groups are already organized by executable
                }
            }
        }
    }

    /// Clear all results.
    pub fn clear(&mut self) {
        self.groups.clear();
        self.focused = None;
    }
}

/// An action to apply a BSim result (transfer name/namespace).
#[derive(Debug, Clone)]
pub struct ApplyResultAction {
    /// The group index.
    pub group_index: usize,
    /// The result index within the group.
    pub result_index: usize,
    /// The source function name (from BSim).
    pub source_name: String,
    /// The target function address.
    pub target_address: String,
    /// Whether to also apply the namespace.
    pub apply_namespace: bool,
    /// Whether to also apply function tags.
    pub apply_tags: bool,
}

impl ApplyResultAction {
    /// Create a new apply action.
    pub fn new(
        group_index: usize,
        result_index: usize,
        source_name: String,
        target_address: String,
    ) -> Self {
        Self {
            group_index,
            result_index,
            source_name,
            target_address,
            apply_namespace: false,
            apply_tags: false,
        }
    }

    /// Also apply the namespace.
    pub fn with_namespace(mut self) -> Self {
        self.apply_namespace = true;
        self
    }

    /// Also apply function tags.
    pub fn with_tags(mut self) -> Self {
        self.apply_tags = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result(name: &str, similarity: f64, confidence: f64) -> BSimMatchResult {
        BSimMatchResult {
            query_hash: [0u8; 32],
            matched_function_name: name.to_string(),
            matched_address: "0x1000".to_string(),
            similarity,
            confidence,
            status: BSimResultStatus::Pending,
        }
    }

    #[test]
    fn test_result_group_new() {
        let group = BSimResultGroup::new("libc".to_string(), "x86".to_string());
        assert_eq!(group.count(), 0);
        assert!(group.expanded);
    }

    #[test]
    fn test_result_group_add() {
        let mut group = BSimResultGroup::new("libc".to_string(), "x86".to_string());
        group.add_result(make_result("malloc", 0.95, 0.85));
        group.add_result(make_result("free", 0.90, 0.80));
        assert_eq!(group.count(), 2);
    }

    #[test]
    fn test_result_group_average_similarity() {
        let mut group = BSimResultGroup::new("libc".to_string(), "x86".to_string());
        group.add_result(make_result("a", 0.8, 0.7));
        group.add_result(make_result("b", 0.6, 0.5));
        let avg = group.average_similarity();
        assert!((avg - 0.7).abs() < 0.001);
    }

    #[test]
    fn test_result_group_empty_average() {
        let group = BSimResultGroup::new("empty".to_string(), "x86".to_string());
        assert_eq!(group.average_similarity(), 0.0);
    }

    #[test]
    fn test_result_group_pending() {
        let mut group = BSimResultGroup::new("libc".to_string(), "x86".to_string());
        group.add_result(make_result("a", 0.9, 0.8));
        group.add_result(make_result("b", 0.8, 0.7));
        assert_eq!(group.pending_results().len(), 2);

        group.results[0].status = BSimResultStatus::Applied;
        assert_eq!(group.pending_results().len(), 1);
        assert_eq!(group.applied_results().len(), 1);
    }

    #[test]
    fn test_result_group_toggle() {
        let mut group = BSimResultGroup::new("libc".to_string(), "x86".to_string());
        assert!(group.expanded);
        group.toggle();
        assert!(!group.expanded);
        group.toggle();
        assert!(group.expanded);
    }

    #[test]
    fn test_search_result_model_new() {
        let model = BSimSearchResultModel::new();
        assert_eq!(model.total_results(), 0);
        assert_eq!(model.total_pending(), 0);
        assert_eq!(model.total_applied(), 0);
        assert!(model.focused.is_none());
    }

    #[test]
    fn test_search_result_model_groups() {
        let mut model = BSimSearchResultModel::new();
        let mut g1 = BSimResultGroup::new("libc".to_string(), "x86".to_string());
        g1.add_result(make_result("malloc", 0.9, 0.8));
        g1.add_result(make_result("free", 0.85, 0.75));
        model.add_group(g1);

        let mut g2 = BSimResultGroup::new("libm".to_string(), "x86".to_string());
        g2.add_result(make_result("sin", 0.95, 0.9));
        model.add_group(g2);

        assert_eq!(model.total_results(), 3);
        assert_eq!(model.total_pending(), 3);
    }

    #[test]
    fn test_search_result_model_mark_applied() {
        let mut model = BSimSearchResultModel::new();
        let mut g = BSimResultGroup::new("libc".to_string(), "x86".to_string());
        g.add_result(make_result("malloc", 0.9, 0.8));
        model.add_group(g);

        model.mark_applied(0, 0);
        assert_eq!(model.total_applied(), 1);
        assert_eq!(model.total_pending(), 0);
    }

    #[test]
    fn test_search_result_model_focus() {
        let mut model = BSimSearchResultModel::new();
        let mut g = BSimResultGroup::new("libc".to_string(), "x86".to_string());
        g.add_result(make_result("malloc", 0.9, 0.8));
        model.add_group(g);

        model.focus(0, 0);
        let focused = model.focused_result().unwrap();
        assert_eq!(focused.matched_function_name, "malloc");
    }

    #[test]
    fn test_search_result_model_apply_all() {
        let mut model = BSimSearchResultModel::new();
        let mut g1 = BSimResultGroup::new("libc".to_string(), "x86".to_string());
        g1.add_result(make_result("malloc", 0.9, 0.8));
        g1.add_result(make_result("free", 0.85, 0.75));
        model.add_group(g1);

        model.mark_applied(0, 0);
        model.apply_all_pending();
        assert_eq!(model.total_applied(), 2);
        assert_eq!(model.total_pending(), 0);
    }

    #[test]
    fn test_search_result_model_sort_by_similarity() {
        let mut model = BSimSearchResultModel::new();
        let mut g = BSimResultGroup::new("libc".to_string(), "x86".to_string());
        g.add_result(make_result("low", 0.5, 0.5));
        g.add_result(make_result("high", 0.95, 0.9));
        g.add_result(make_result("mid", 0.7, 0.7));
        model.add_group(g);

        model.sort(ResultSortOrder::BySimilarity);
        let group = &model.groups[0];
        assert_eq!(group.results[0].matched_function_name, "high");
        assert_eq!(group.results[1].matched_function_name, "mid");
        assert_eq!(group.results[2].matched_function_name, "low");
    }

    #[test]
    fn test_search_result_model_sort_by_name() {
        let mut model = BSimSearchResultModel::new();
        let mut g = BSimResultGroup::new("libc".to_string(), "x86".to_string());
        g.add_result(make_result("zebra", 0.9, 0.9));
        g.add_result(make_result("alpha", 0.8, 0.8));
        model.add_group(g);

        model.sort(ResultSortOrder::ByName);
        let group = &model.groups[0];
        assert_eq!(group.results[0].matched_function_name, "alpha");
        assert_eq!(group.results[1].matched_function_name, "zebra");
    }

    #[test]
    fn test_search_result_model_clear() {
        let mut model = BSimSearchResultModel::new();
        let g = BSimResultGroup::new("libc".to_string(), "x86".to_string());
        model.add_group(g);
        assert_eq!(model.total_results(), 0);

        model.clear();
        assert!(model.groups.is_empty());
        assert!(model.focused.is_none());
    }

    #[test]
    fn test_result_sort_order_default() {
        assert_eq!(ResultSortOrder::default(), ResultSortOrder::BySimilarity);
    }

    #[test]
    fn test_apply_result_action() {
        let action = ApplyResultAction::new(0, 1, "malloc".to_string(), "0x2000".to_string())
            .with_namespace()
            .with_tags();
        assert!(action.apply_namespace);
        assert!(action.apply_tags);
        assert_eq!(action.source_name, "malloc");
        assert_eq!(action.target_address, "0x2000");
    }

    #[test]
    fn test_mark_ignored_and_rejected() {
        let mut model = BSimSearchResultModel::new();
        let mut g = BSimResultGroup::new("test".to_string(), "x86".to_string());
        g.add_result(make_result("func1", 0.8, 0.7));
        g.add_result(make_result("func2", 0.7, 0.6));
        model.add_group(g);

        model.mark_ignored(0, 0);
        model.mark_rejected(0, 1);
        assert_eq!(model.groups[0].results[0].status, BSimResultStatus::Ignored);
        assert_eq!(model.groups[0].results[1].status, BSimResultStatus::Rejected);
    }
}
