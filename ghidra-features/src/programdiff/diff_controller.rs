//! Diff controller for managing program comparison state.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.diff.DiffController` Java class.
//!
//! The DiffController controls a program Diff. It maintains address sets indicating
//! the differences between two programs. It can limit the determined differences
//! to an address set. It allows differences to be applied or ignored. It has a
//! diff filter that controls the differences being indicated. It has a merge
//! filter that controls the types of differences being applied. It allows
//! differences at particular addresses to be ignored.

use super::merge_filter::{MergeAction, MergeCategory, ProgramMergeFilter};
use super::{DiffResult, DiffType, ProgramDiffFilter, ProgramSnapshot};

/// A range of addresses [start, end] inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AddressRange {
    /// Start address (inclusive).
    pub start: u64,
    /// End address (inclusive).
    pub end: u64,
}

impl AddressRange {
    /// Create a new address range.
    pub fn new(start: u64, end: u64) -> Self {
        Self {
            start: start.min(end),
            end: start.max(end),
        }
    }

    /// Create a single-address range.
    pub fn single(address: u64) -> Self {
        Self {
            start: address,
            end: address,
        }
    }

    /// Check if this range contains an address.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.start && address <= self.end
    }

    /// Get the minimum address in this range.
    pub fn min_address(&self) -> u64 {
        self.start
    }

    /// Get the maximum address in this range.
    pub fn max_address(&self) -> u64 {
        self.end
    }

    /// Get the number of addresses in this range.
    pub fn length(&self) -> u64 {
        self.end - self.start + 1
    }
}

/// A set of address ranges.
#[derive(Debug, Clone, Default)]
pub struct AddressSet {
    ranges: Vec<AddressRange>,
}

impl AddressSet {
    /// Create an empty address set.
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Create an address set from a single range.
    pub fn from_range(start: u64, end: u64) -> Self {
        let mut set = Self::new();
        set.add_range(start, end);
        set
    }

    /// Create an address set from a single address.
    pub fn from_address(address: u64) -> Self {
        Self::from_range(address, address)
    }

    /// Add a range of addresses to the set.
    pub fn add_range(&mut self, start: u64, end: u64) {
        let new_range = AddressRange::new(start, end);
        self.ranges.push(new_range);
        self.normalize();
    }

    /// Add a single address to the set.
    pub fn add_address(&mut self, address: u64) {
        self.add_range(address, address);
    }

    /// Remove a range of addresses from the set.
    pub fn remove_range(&mut self, start: u64, end: u64) {
        let remove = AddressRange::new(start, end);
        let mut new_ranges = Vec::new();
        for range in &self.ranges {
            if range.end < remove.start || range.start > remove.end {
                // No overlap
                new_ranges.push(*range);
            } else {
                // Overlap - split if needed
                if range.start < remove.start {
                    new_ranges.push(AddressRange::new(range.start, remove.start - 1));
                }
                if range.end > remove.end {
                    new_ranges.push(AddressRange::new(remove.end + 1, range.end));
                }
            }
        }
        self.ranges = new_ranges;
    }

    /// Remove a single address from the set.
    pub fn remove_address(&mut self, address: u64) {
        self.remove_range(address, address);
    }

    /// Check if the set contains an address.
    pub fn contains(&self, address: u64) -> bool {
        self.ranges.iter().any(|r| r.contains(address))
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Get the number of ranges in the set.
    pub fn num_ranges(&self) -> usize {
        self.ranges.len()
    }

    /// Get the minimum address in the set.
    pub fn min_address(&self) -> Option<u64> {
        self.ranges.first().map(|r| r.start)
    }

    /// Get the maximum address in the set.
    pub fn max_address(&self) -> Option<u64> {
        self.ranges.last().map(|r| r.end)
    }

    /// Get the total number of addresses in the set.
    pub fn num_addresses(&self) -> u64 {
        self.ranges.iter().map(|r| r.length()).sum()
    }

    /// Get the intersection with another address set.
    pub fn intersect(&self, other: &AddressSet) -> AddressSet {
        let mut result = AddressSet::new();
        for r1 in &self.ranges {
            for r2 in &other.ranges {
                let start = r1.start.max(r2.start);
                let end = r1.end.min(r2.end);
                if start <= end {
                    result.add_range(start, end);
                }
            }
        }
        result
    }

    /// Get the union with another address set.
    pub fn union(&self, other: &AddressSet) -> AddressSet {
        let mut result = self.clone();
        for range in &other.ranges {
            result.add_range(range.start, range.end);
        }
        result
    }

    /// Get the difference (addresses in self but not in other).
    pub fn difference(&self, other: &AddressSet) -> AddressSet {
        let mut result = self.clone();
        for range in &other.ranges {
            result.remove_range(range.start, range.end);
        }
        result
    }

    /// Get all ranges in the set.
    pub fn ranges(&self) -> &[AddressRange] {
        &self.ranges
    }

    /// Normalize the ranges (merge overlapping/adjacent ranges).
    fn normalize(&mut self) {
        if self.ranges.len() <= 1 {
            return;
        }
        self.ranges.sort_by_key(|r| r.start);
        let mut merged = Vec::new();
        let mut current = self.ranges[0];
        for range in &self.ranges[1..] {
            if range.start <= current.end + 1 {
                current.end = current.end.max(range.end);
            } else {
                merged.push(current);
                current = *range;
            }
        }
        merged.push(current);
        self.ranges = merged;
    }
}

impl FromIterator<u64> for AddressSet {
    fn from_iter<I: IntoIterator<Item = u64>>(iter: I) -> Self {
        let mut set = Self::new();
        for addr in iter {
            set.add_address(addr);
        }
        set
    }
}

/// Listener for diff controller events.
///
/// Ported from Ghidra's `DiffControllerListener` Java interface.
pub trait DiffControllerListener {
    /// Called when the current diff location changes.
    fn diff_location_changed(&mut self, location: u64);

    /// Called when the set of differences changes.
    fn differences_changed(&mut self);
}

/// Controller for program diff operations.
///
/// Ported from Ghidra's `DiffController` Java class.
///
/// The DiffController maintains the state of a diff between two programs,
/// including the set of differences, the current location, and the filters
/// for controlling what is compared and what is applied.
pub struct DiffController {
    /// Program 1 (the "base" program).
    program1: ProgramSnapshot,
    /// Program 2 (the "other" program).
    program2: ProgramSnapshot,
    /// The set of addresses where differences were found (in program 1's address space).
    differences: AddressSet,
    /// The set of addresses to ignore.
    ignored: AddressSet,
    /// The set of addresses to restrict the diff to.
    restricted: AddressSet,
    /// The current address in the diff navigation.
    current_address: Option<u64>,
    /// The filter controlling which types of differences to detect.
    diff_filter: ProgramDiffFilter,
    /// The filter controlling which types of differences to apply.
    merge_filter: ProgramMergeFilter,
    /// Listeners for diff controller events.
    listeners: Vec<Box<dyn DiffControllerListener>>,
    /// Whether the differences have been computed.
    computed: bool,
}

impl DiffController {
    /// Create a new diff controller for two programs.
    ///
    /// # Arguments
    ///
    /// * `program1` - The first program (base).
    /// * `program2` - The second program (other).
    /// * `limit_set` - Optional address set to limit the diff to.
    /// * `diff_filter` - Filter controlling which types of differences to detect.
    /// * `merge_filter` - Filter controlling which types of differences to apply.
    pub fn new(
        program1: ProgramSnapshot,
        program2: ProgramSnapshot,
        limit_set: Option<AddressSet>,
        diff_filter: ProgramDiffFilter,
        merge_filter: ProgramMergeFilter,
    ) -> Self {
        let current_address = limit_set
            .as_ref()
            .and_then(|s| s.min_address())
            .or_else(|| {
                program1
                    .blocks
                    .values()
                    .map(|(start, _)| *start)
                    .min()
            });

        Self {
            program1,
            program2,
            differences: AddressSet::new(),
            ignored: AddressSet::new(),
            restricted: limit_set.unwrap_or_default(),
            current_address,
            diff_filter,
            merge_filter,
            listeners: Vec::new(),
            computed: false,
        }
    }

    /// Get the first program.
    pub fn program_one(&self) -> &ProgramSnapshot {
        &self.program1
    }

    /// Get the second program.
    pub fn program_two(&self) -> &ProgramSnapshot {
        &self.program2
    }

    /// Get the diff filter.
    pub fn diff_filter(&self) -> &ProgramDiffFilter {
        &self.diff_filter
    }

    /// Set the diff filter.
    pub fn set_diff_filter(&mut self, filter: ProgramDiffFilter) {
        self.diff_filter = filter;
    }

    /// Get the merge filter.
    pub fn merge_filter(&self) -> &ProgramMergeFilter {
        &self.merge_filter
    }

    /// Set the merge filter.
    pub fn set_merge_filter(&mut self, filter: ProgramMergeFilter) {
        self.merge_filter = filter;
    }

    /// Get the current address.
    pub fn current_address(&self) -> Option<u64> {
        self.current_address
    }

    /// Set the current address.
    pub fn set_location(&mut self, address: u64) {
        if self.current_address != Some(address) {
            self.current_address = Some(address);
            self.notify_location_changed(address);
        }
    }

    /// Get the set of differences.
    pub fn differences(&self) -> &AddressSet {
        &self.differences
    }

    /// Get the set of ignored addresses.
    pub fn ignored_addresses(&self) -> &AddressSet {
        &self.ignored
    }

    /// Get the restricted address set.
    pub fn restricted_addresses(&self) -> &AddressSet {
        &self.restricted
    }

    /// Compute the filtered differences between the two programs.
    ///
    /// This method compares the two programs according to the current diff filter
    /// and returns the set of addresses where differences were found.
    pub fn get_filtered_differences(&mut self) -> AddressSet {
        let results = super::diff_programs(&self.program1, &self.program2, self.diff_filter);

        let mut diff_set = AddressSet::new();
        for result in &results {
            diff_set.add_address(result.address);
        }

        // Remove ignored addresses
        let diff_set = diff_set.difference(&self.ignored);

        // Intersect with restricted set if non-empty
        let diff_set = if self.restricted.is_empty() {
            diff_set
        } else {
            diff_set.intersect(&self.restricted)
        };

        self.differences = diff_set.clone();
        self.computed = true;

        // Set current address to first difference if not set
        if self.current_address.is_none() {
            self.current_address = self.differences.min_address();
        }

        self.notify_differences_changed();
        diff_set
    }

    /// Restrict the diff results to the given address set.
    pub fn restrict_results(&mut self, address_set: AddressSet) {
        self.restricted = address_set;
        if self.computed {
            self.get_filtered_differences();
        } else {
            self.notify_differences_changed();
        }
    }

    /// Remove restrictions on the diff results.
    pub fn remove_result_restrictions(&mut self) {
        self.restricted = AddressSet::new();
        if self.computed {
            self.get_filtered_differences();
        } else {
            self.notify_differences_changed();
        }
    }

    /// Apply differences in the given address set from program 2 to program 1.
    ///
    /// Returns a list of diff results that were applied.
    pub fn apply(&self, address_set: &AddressSet) -> Vec<DiffResult> {
        let results = super::diff_programs(&self.program1, &self.program2, self.diff_filter);
        let mut applied = Vec::new();

        for result in &results {
            if address_set.contains(result.address) {
                // Check merge filter for this type of difference
                let category = Self::diff_type_to_merge_category(result.diff_type);
                let action = self.merge_filter.get_filter(category);
                if action != MergeAction::Ignore {
                    applied.push(result.clone());
                }
            }
        }

        applied
    }

    /// Ignore differences in the given address set.
    pub fn ignore(&mut self, address_set: &AddressSet) {
        self.ignored = self.ignored.union(address_set);
        self.differences = self.differences.difference(address_set);
        self.notify_differences_changed();
    }

    /// Check if there is a next difference.
    pub fn has_next(&self) -> bool {
        self.get_next_address().is_some()
    }

    /// Check if there is a previous difference.
    pub fn has_previous(&self) -> bool {
        self.get_previous_address().is_some()
    }

    /// Navigate to the first difference.
    pub fn first(&mut self) {
        if let Some(addr) = self.differences.min_address() {
            self.set_location(addr);
        }
    }

    /// Navigate to the next difference.
    pub fn next(&mut self) {
        if let Some(addr) = self.get_next_address() {
            self.set_location(addr);
        }
    }

    /// Navigate to the previous difference.
    pub fn previous(&mut self) {
        if let Some(addr) = self.get_previous_address() {
            self.set_location(addr);
        }
    }

    /// Get the next difference address after the current address.
    fn get_next_address(&self) -> Option<u64> {
        let current = self.current_address?;
        for range in self.differences.ranges() {
            if range.start > current {
                return Some(range.start);
            }
            if range.contains(current) && range.end > current {
                return Some(current + 1);
            }
        }
        None
    }

    /// Get the previous difference address before the current address.
    fn get_previous_address(&self) -> Option<u64> {
        let current = self.current_address?;
        for range in self.differences.ranges().iter().rev() {
            if range.end < current {
                return Some(range.end);
            }
            if range.contains(current) && range.start < current {
                return Some(current - 1);
            }
        }
        None
    }

    /// Add a listener for diff controller events.
    pub fn add_listener(&mut self, listener: Box<dyn DiffControllerListener>) {
        self.listeners.push(listener);
    }

    /// Refresh the differences (recompute from scratch).
    pub fn refresh(&mut self, keep_ignored: bool) {
        let ignored = if keep_ignored {
            self.ignored.clone()
        } else {
            AddressSet::new()
        };

        self.ignored = AddressSet::new();
        self.get_filtered_differences();

        if keep_ignored {
            self.ignored = ignored;
            self.differences = self.differences.difference(&self.ignored);
            self.notify_differences_changed();
        }
    }

    /// Convert a DiffType to a MergeCategory for filter checking.
    fn diff_type_to_merge_category(diff_type: DiffType) -> MergeCategory {
        match diff_type {
            DiffType::ByteChanged => MergeCategory::Bytes,
            DiffType::CodeUnitAdded | DiffType::CodeUnitRemoved | DiffType::CodeUnitChanged => {
                MergeCategory::CodeUnits
            }
            DiffType::SymbolAdded | DiffType::SymbolRemoved | DiffType::SymbolRenamed => {
                MergeCategory::Symbols
            }
            DiffType::DataTypeChanged => MergeCategory::Data,
            DiffType::CommentChanged => MergeCategory::Comments,
            DiffType::FunctionChanged => MergeCategory::Functions,
            DiffType::ReferenceChanged => MergeCategory::References,
            DiffType::BookmarkChanged => MergeCategory::Bookmarks,
            DiffType::MemoryBlockChanged => MergeCategory::Bytes,
            DiffType::EquateChanged => MergeCategory::Equates,
            DiffType::PropertyChanged => MergeCategory::Properties,
        }
    }

    fn notify_location_changed(&mut self, address: u64) {
        for listener in &mut self.listeners {
            listener.diff_location_changed(address);
        }
    }

    fn notify_differences_changed(&mut self) {
        for listener in &mut self.listeners {
            listener.differences_changed();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_range_basic() {
        let range = AddressRange::new(0x1000, 0x100F);
        assert_eq!(range.min_address(), 0x1000);
        assert_eq!(range.max_address(), 0x100F);
        assert_eq!(range.length(), 16);
        assert!(range.contains(0x1000));
        assert!(range.contains(0x100F));
        assert!(range.contains(0x1005));
        assert!(!range.contains(0x0FFF));
        assert!(!range.contains(0x1010));
    }

    #[test]
    fn test_address_range_single() {
        let range = AddressRange::single(0x1000);
        assert_eq!(range.min_address(), 0x1000);
        assert_eq!(range.max_address(), 0x1000);
        assert_eq!(range.length(), 1);
    }

    #[test]
    fn test_address_set_add_and_contains() {
        let mut set = AddressSet::new();
        assert!(set.is_empty());
        set.add_address(0x1000);
        assert!(!set.is_empty());
        assert!(set.contains(0x1000));
        assert!(!set.contains(0x1001));
    }

    #[test]
    fn test_address_set_range() {
        let mut set = AddressSet::new();
        set.add_range(0x1000, 0x100F);
        assert!(set.contains(0x1000));
        assert!(set.contains(0x100F));
        assert!(!set.contains(0x1010));
        assert_eq!(set.num_addresses(), 16);
    }

    #[test]
    fn test_address_set_merge_adjacent() {
        let mut set = AddressSet::new();
        set.add_range(0x1000, 0x100F);
        set.add_range(0x1010, 0x101F);
        assert_eq!(set.num_ranges(), 1); // merged
        assert_eq!(set.num_addresses(), 32);
    }

    #[test]
    fn test_address_set_remove() {
        let mut set = AddressSet::new();
        set.add_range(0x1000, 0x100F);
        set.remove_address(0x1005);
        assert!(!set.contains(0x1005));
        assert!(set.contains(0x1004));
        assert!(set.contains(0x1006));
        assert_eq!(set.num_ranges(), 2);
    }

    #[test]
    fn test_address_set_intersect() {
        let mut set1 = AddressSet::new();
        set1.add_range(0x1000, 0x100F);
        let mut set2 = AddressSet::new();
        set2.add_range(0x1005, 0x101F);
        let intersection = set1.intersect(&set2);
        assert!(intersection.contains(0x1005));
        assert!(intersection.contains(0x100F));
        assert!(!intersection.contains(0x1004));
        assert!(!intersection.contains(0x1010));
    }

    #[test]
    fn test_address_set_union() {
        let mut set1 = AddressSet::new();
        set1.add_range(0x1000, 0x100F);
        let mut set2 = AddressSet::new();
        set2.add_range(0x1010, 0x101F);
        let union = set1.union(&set2);
        assert!(union.contains(0x1000));
        assert!(union.contains(0x101F));
        assert_eq!(union.num_ranges(), 1); // merged
    }

    #[test]
    fn test_address_set_difference() {
        let mut set1 = AddressSet::new();
        set1.add_range(0x1000, 0x100F);
        let mut set2 = AddressSet::new();
        set2.add_range(0x1005, 0x100A);
        let diff = set1.difference(&set2);
        assert!(diff.contains(0x1000));
        assert!(diff.contains(0x1004));
        assert!(!diff.contains(0x1005));
        assert!(!diff.contains(0x100A));
        assert!(diff.contains(0x100B));
        assert!(diff.contains(0x100F));
    }

    #[test]
    fn test_diff_controller_basic() {
        let mut prog1 = ProgramSnapshot::new("p1");
        prog1.add_block(".text", 0x1000, vec![0x90, 0xC3, 0xCC]);
        let mut prog2 = ProgramSnapshot::new("p2");
        prog2.add_block(".text", 0x1000, vec![0x90, 0xCB, 0xCC]);

        let mut controller = DiffController::new(
            prog1,
            prog2,
            None,
            ProgramDiffFilter::BYTES,
            ProgramMergeFilter::defaults(),
        );

        let diffs = controller.get_filtered_differences();
        assert!(!diffs.is_empty());
        assert!(diffs.contains(0x1001));
    }

    #[test]
    fn test_diff_controller_navigation() {
        let mut prog1 = ProgramSnapshot::new("p1");
        prog1.add_block(".text", 0x1000, vec![0x00, 0x00, 0x00]);
        let mut prog2 = ProgramSnapshot::new("p2");
        prog2.add_block(".text", 0x1000, vec![0xFF, 0xFF, 0xFF]);

        let mut controller = DiffController::new(
            prog1,
            prog2,
            None,
            ProgramDiffFilter::BYTES,
            ProgramMergeFilter::defaults(),
        );

        controller.get_filtered_differences();
        assert!(controller.has_next());
        assert!(!controller.has_previous());

        controller.next();
        assert!(controller.has_previous());
    }

    #[test]
    fn test_diff_controller_ignore() {
        let mut prog1 = ProgramSnapshot::new("p1");
        prog1.add_block(".text", 0x1000, vec![0x00, 0x00, 0x00]);
        let mut prog2 = ProgramSnapshot::new("p2");
        prog2.add_block(".text", 0x1000, vec![0xFF, 0xFF, 0xFF]);

        let mut controller = DiffController::new(
            prog1,
            prog2,
            None,
            ProgramDiffFilter::BYTES,
            ProgramMergeFilter::defaults(),
        );

        controller.get_filtered_differences();
        let num_diffs = controller.differences().num_addresses();
        assert_eq!(num_diffs, 3);

        let mut ignore_set = AddressSet::new();
        ignore_set.add_address(0x1000);
        controller.ignore(&ignore_set);

        assert_eq!(controller.differences().num_addresses(), 2);
        assert!(controller.ignored_addresses().contains(0x1000));
    }

    #[test]
    fn test_diff_controller_apply() {
        let mut prog1 = ProgramSnapshot::new("p1");
        prog1.add_block(".text", 0x1000, vec![0x90, 0xC3]);
        let mut prog2 = ProgramSnapshot::new("p2");
        prog2.add_block(".text", 0x1000, vec![0x90, 0xCB]);

        let mut controller = DiffController::new(
            prog1,
            prog2,
            None,
            ProgramDiffFilter::BYTES,
            ProgramMergeFilter::defaults(),
        );

        controller.get_filtered_differences();

        let mut apply_set = AddressSet::new();
        apply_set.add_address(0x1001);
        let applied = controller.apply(&apply_set);
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].address, 0x1001);
    }

    #[test]
    fn test_diff_controller_restrict() {
        let mut prog1 = ProgramSnapshot::new("p1");
        prog1.add_block(".text", 0x1000, vec![0x00, 0x00, 0x00]);
        let mut prog2 = ProgramSnapshot::new("p2");
        prog2.add_block(".text", 0x1000, vec![0xFF, 0xFF, 0xFF]);

        let mut controller = DiffController::new(
            prog1,
            prog2,
            None,
            ProgramDiffFilter::BYTES,
            ProgramMergeFilter::defaults(),
        );

        controller.get_filtered_differences();
        assert_eq!(controller.differences().num_addresses(), 3);

        let mut restrict_set = AddressSet::new();
        restrict_set.add_range(0x1000, 0x1001);
        controller.restrict_results(restrict_set);
        assert_eq!(controller.differences().num_addresses(), 2);

        controller.remove_result_restrictions();
        assert_eq!(controller.differences().num_addresses(), 3);
    }

    #[test]
    fn test_address_set_from_iterator() {
        let set: AddressSet = vec![0x1000u64, 0x2000, 0x3000].into_iter().collect();
        assert!(set.contains(0x1000));
        assert!(set.contains(0x2000));
        assert!(set.contains(0x3000));
        assert!(!set.contains(0x1500));
    }
}
