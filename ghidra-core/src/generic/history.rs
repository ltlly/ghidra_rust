//! History list for navigation tracking.
//!
//! Ports Ghidra's `util.HistoryList` class. Maintains a bounded stack of
//! visited items with back/forward navigation, duplicate handling, and
//! optional null support.
//!
//! # Java source migrated
//!
//! | Java class         | Rust type       |
//! |--------------------|-----------------|
//! | `util.HistoryList` | [`HistoryList`] |

use std::collections::VecDeque;
use std::fmt;

// ============================================================================
// HistoryList
// ============================================================================

/// An object that tracks a list of items with the ability to go back and
/// forth within the list.
///
/// By default, duplicate entries are not allowed (re-adding an existing item
/// moves it to the front). By default, null values (represented as empty
/// strings since Rust cannot store `None` in a non-Option generic) are not
/// allowed.
///
/// The `max_size` parameter limits the number of items retained; oldest items
/// are dropped as the list grows.
///
/// # Examples
///
/// ```
/// use ghidra_core::generic::history::HistoryList;
///
/// let mut history = HistoryList::new(10);
/// history.push("page1".to_string());
/// history.push("page2".to_string());
/// history.push("page3".to_string());
///
/// assert_eq!(history.current(), Some(&"page3".to_string()));
/// history.go_back();
/// assert_eq!(history.current(), Some(&"page2".to_string()));
/// history.go_forward();
/// assert_eq!(history.current(), Some(&"page3".to_string()));
/// ```
pub struct HistoryList<T: Clone + PartialEq> {
    /// The bounded storage (newest items at the back).
    items: VecDeque<T>,
    /// Index of the current item (0-based).
    index: usize,
    /// Maximum number of items to retain.
    max_size: usize,
    /// Whether to allow duplicate entries.
    allow_duplicates: bool,
    /// Whether `go_back`/`go_forward` callbacks are being invoked
    /// (prevents re-entrant modification).
    broadcasting: bool,
}

impl<T: Clone + PartialEq> HistoryList<T> {
    /// Create a new history list with the given maximum capacity.
    ///
    /// # Panics
    ///
    /// Panics if `max_size` is 0.
    pub fn new(max_size: usize) -> Self {
        assert!(max_size >= 1, "max_size cannot be less than 1");
        Self {
            items: VecDeque::with_capacity(max_size),
            index: 0,
            max_size,
            allow_duplicates: false,
            broadcasting: false,
        }
    }

    /// Set whether duplicate entries are allowed.
    ///
    /// When duplicates are *not* allowed (the default), re-adding an existing
    /// item moves it to the end (most recent). When duplicates *are* allowed,
    /// every `push` creates a new entry.
    pub fn set_allow_duplicates(&mut self, allow: bool) {
        self.allow_duplicates = allow;
    }

    /// Returns `true` if duplicates are allowed.
    pub fn allows_duplicates(&self) -> bool {
        self.allow_duplicates
    }

    /// Push a new item onto the history list.
    ///
    /// After this call, the item becomes the current item. Any forward
    /// history is discarded.
    ///
    /// If the list is currently broadcasting (inside a `go_back`/`go_forward`
    /// callback), this call is a no-op.
    pub fn push(&mut self, item: T) {
        if self.broadcasting {
            return;
        }

        // Drop forward history
        while self.items.len() > self.index + 1 {
            self.items.pop_back();
        }

        // Handle duplicates
        if !self.allow_duplicates {
            if let Some(pos) = self.items.iter().position(|existing| *existing == item) {
                self.items.remove(pos);
                // Adjust index if needed
                if pos <= self.index {
                    self.index = self.index.saturating_sub(1);
                }
            }
        }

        // Enforce capacity
        while self.items.len() >= self.max_size {
            self.items.pop_front();
            if self.index > 0 {
                self.index -= 1;
            }
        }

        self.items.push_back(item);
        self.index = self.items.len() - 1;
    }

    /// Replace the most recent item and push a new one.
    ///
    /// This is equivalent to popping the last item and then pushing the new
    /// one. Useful for transient navigation entries.
    pub fn push_replace(&mut self, item: T) {
        if self.broadcasting {
            return;
        }
        if !self.items.is_empty() {
            self.items.pop_back();
            if self.index >= self.items.len() && self.index > 0 {
                self.index = self.items.len() - 1;
            }
        }
        self.push(item);
    }

    /// Returns `true` if there is a next item (forward history exists).
    pub fn has_next(&self) -> bool {
        self.index + 1 < self.items.len()
    }

    /// Returns `true` if there is a previous item (backward history exists).
    pub fn has_previous(&self) -> bool {
        self.index > 0
    }

    /// Move back one step in the history.
    ///
    /// Does nothing if already at the beginning.
    pub fn go_back(&mut self) {
        if self.index == 0 || self.items.is_empty() {
            return;
        }
        self.index -= 1;
    }

    /// Move forward one step in the history.
    ///
    /// Does nothing if already at the end.
    pub fn go_forward(&mut self) {
        if self.index + 1 >= self.items.len() {
            return;
        }
        self.index += 1;
    }

    /// Navigate backward until `target` is found.
    ///
    /// Does nothing if `target` is not in the backward history.
    pub fn go_back_to(&mut self, target: &T) {
        if self.index == 0 {
            return;
        }
        let mut i = self.index;
        while i > 0 {
            i -= 1;
            if self.items[i] == *target {
                self.index = i;
                return;
            }
        }
    }

    /// Navigate forward until `target` is found.
    ///
    /// Does nothing if `target` is not in the forward history.
    pub fn go_forward_to(&mut self, target: &T) {
        if self.index + 1 >= self.items.len() {
            return;
        }
        let mut i = self.index + 1;
        while i < self.items.len() {
            if self.items[i] == *target {
                self.index = i;
                return;
            }
            i += 1;
        }
    }

    /// Navigate to a specific index.
    pub fn go_to_index(&mut self, index: usize) {
        if index < self.items.len() {
            self.index = index;
        }
    }

    /// Returns a reference to the current item, or `None` if the list is empty.
    pub fn current(&self) -> Option<&T> {
        self.items.get(self.index)
    }

    /// Returns the current index.
    pub fn current_index(&self) -> usize {
        self.index
    }

    /// Get all items that come before the current item, in reverse
    /// navigation order (closest to current first).
    pub fn previous_items(&self) -> Vec<&T> {
        (0..self.index)
            .rev()
            .filter_map(|i| self.items.get(i))
            .collect()
    }

    /// Get all items that come after the current item, in forward
    /// navigation order (closest to current first).
    pub fn next_items(&self) -> Vec<&T> {
        ((self.index + 1)..self.items.len())
            .filter_map(|i| self.items.get(i))
            .collect()
    }

    /// Get all items in insertion order.
    pub fn all_items(&self) -> Vec<&T> {
        self.items.iter().collect()
    }

    /// Returns the number of items in the history.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns `true` if the history is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Returns the maximum capacity.
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Clear all history and reset the index.
    pub fn clear(&mut self) {
        self.items.clear();
        self.index = 0;
    }

    /// Returns `true` if the current item is at the end of the list.
    pub fn is_at_end(&self) -> bool {
        self.items.is_empty() || self.index == self.items.len() - 1
    }

    /// Returns `true` if the current item is at the beginning of the list.
    pub fn is_at_start(&self) -> bool {
        self.index == 0
    }
}

impl<T: Clone + PartialEq + fmt::Display> fmt::Display for HistoryList<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pad = "    items: ";
        let newline_pad = " ".repeat(pad.len());
        writeln!(f, "{{")?;
        write!(f, "{}", pad)?;
        for (i, item) in self.items.iter().enumerate() {
            if i == self.index {
                write!(f, "[{}]", item)?;
            } else {
                write!(f, "{}", item)?;
            }
            if i != self.items.len() - 1 {
                write!(f, ",\n{}", newline_pad)?;
            }
        }
        writeln!(f)?;
        write!(f, "}}")
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_history_list_new() {
        let h: HistoryList<String> = HistoryList::new(10);
        assert_eq!(h.len(), 0);
        assert!(h.is_empty());
        assert_eq!(h.max_size(), 10);
    }

    #[test]
    fn test_history_list_push_and_current() {
        let mut h = HistoryList::new(5);
        h.push("a".to_string());
        assert_eq!(h.current(), Some(&"a".to_string()));
        h.push("b".to_string());
        assert_eq!(h.current(), Some(&"b".to_string()));
        assert_eq!(h.len(), 2);
    }

    #[test]
    fn test_history_list_go_back_forward() {
        let mut h = HistoryList::new(5);
        h.push("a".to_string());
        h.push("b".to_string());
        h.push("c".to_string());
        assert_eq!(h.current(), Some(&"c".to_string()));

        h.go_back();
        assert_eq!(h.current(), Some(&"b".to_string()));
        assert!(h.has_next());
        assert!(h.has_previous());

        h.go_back();
        assert_eq!(h.current(), Some(&"a".to_string()));
        assert!(!h.has_previous());

        h.go_forward();
        assert_eq!(h.current(), Some(&"b".to_string()));
    }

    #[test]
    fn test_history_list_go_back_at_start() {
        let mut h = HistoryList::new(5);
        h.push("a".to_string());
        h.go_back(); // should be no-op
        assert_eq!(h.current(), Some(&"a".to_string()));
    }

    #[test]
    fn test_history_list_go_forward_at_end() {
        let mut h = HistoryList::new(5);
        h.push("a".to_string());
        h.go_forward(); // should be no-op
        assert_eq!(h.current(), Some(&"a".to_string()));
    }

    #[test]
    fn test_history_list_push_discards_forward() {
        let mut h = HistoryList::new(5);
        h.push("a".to_string());
        h.push("b".to_string());
        h.push("c".to_string());
        h.go_back();
        h.go_back();
        assert_eq!(h.current(), Some(&"a".to_string()));

        h.push("d".to_string());
        assert_eq!(h.current(), Some(&"d".to_string()));
        assert_eq!(h.len(), 2); // a, d
        assert!(!h.has_next());
    }

    #[test]
    fn test_history_list_no_duplicates() {
        let mut h = HistoryList::new(5);
        h.push("a".to_string());
        h.push("b".to_string());
        h.push("c".to_string());
        h.push("a".to_string()); // re-add "a"

        assert_eq!(h.current(), Some(&"a".to_string()));
        // "a" should have been moved, so order is b, c, a
        assert_eq!(h.len(), 3);
    }

    #[test]
    fn test_history_list_allow_duplicates() {
        let mut h = HistoryList::new(5);
        h.set_allow_duplicates(true);
        h.push("a".to_string());
        h.push("b".to_string());
        h.push("a".to_string()); // re-add "a"

        assert_eq!(h.len(), 3);
        assert_eq!(h.current(), Some(&"a".to_string()));
    }

    #[test]
    fn test_history_list_overflow() {
        let mut h = HistoryList::new(3);
        h.push("a".to_string());
        h.push("b".to_string());
        h.push("c".to_string());
        h.push("d".to_string()); // should evict "a"

        assert_eq!(h.len(), 3);
        assert_eq!(h.current(), Some(&"d".to_string()));
        h.go_back();
        h.go_back();
        assert_eq!(h.current(), Some(&"b".to_string()));
        assert!(!h.has_previous()); // "a" was evicted
    }

    #[test]
    fn test_history_list_previous_next_items() {
        let mut h = HistoryList::new(5);
        h.push("a".to_string());
        h.push("b".to_string());
        h.push("c".to_string());
        h.go_back();

        let prev = h.previous_items();
        assert_eq!(prev, vec![&"a".to_string()]);

        let next = h.next_items();
        assert_eq!(next, vec![&"c".to_string()]);
    }

    #[test]
    fn test_history_list_go_back_to() {
        let mut h = HistoryList::new(5);
        h.push("a".to_string());
        h.push("b".to_string());
        h.push("c".to_string());
        h.push("d".to_string());

        h.go_back_to(&"b".to_string());
        assert_eq!(h.current(), Some(&"b".to_string()));
    }

    #[test]
    fn test_history_list_go_forward_to() {
        let mut h = HistoryList::new(5);
        h.push("a".to_string());
        h.push("b".to_string());
        h.push("c".to_string());
        h.push("d".to_string());

        h.go_back();
        h.go_back();
        h.go_back();
        assert_eq!(h.current(), Some(&"a".to_string()));

        h.go_forward_to(&"c".to_string());
        assert_eq!(h.current(), Some(&"c".to_string()));
    }

    #[test]
    fn test_history_list_push_replace() {
        let mut h = HistoryList::new(5);
        h.push("a".to_string());
        h.push("b".to_string());
        h.push_replace("c".to_string());

        assert_eq!(h.len(), 2);
        assert_eq!(h.current(), Some(&"c".to_string()));
    }

    #[test]
    fn test_history_list_clear() {
        let mut h = HistoryList::new(5);
        h.push("a".to_string());
        h.push("b".to_string());
        h.clear();
        assert_eq!(h.len(), 0);
        assert!(h.is_empty());
        assert_eq!(h.current(), None);
    }

    #[test]
    fn test_history_list_is_at_start_end() {
        let mut h = HistoryList::new(5);
        h.push("a".to_string());
        h.push("b".to_string());

        assert!(h.is_at_end());
        assert!(!h.is_at_start());

        h.go_back();
        assert!(!h.is_at_end());
        assert!(h.is_at_start());
    }

    #[test]
    fn test_history_list_display() {
        let mut h = HistoryList::new(5);
        h.push("a".to_string());
        h.push("b".to_string());
        let s = format!("{}", h);
        assert!(s.contains("[b]"));
        assert!(s.contains("a"));
    }

    #[test]
    fn test_history_list_go_to_index() {
        let mut h = HistoryList::new(5);
        h.push("a".to_string());
        h.push("b".to_string());
        h.push("c".to_string());
        h.go_to_index(0);
        assert_eq!(h.current(), Some(&"a".to_string()));
    }
}
