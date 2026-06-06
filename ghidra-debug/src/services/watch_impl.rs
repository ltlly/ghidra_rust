//! Watch service implementation ported from DebuggerWatchesService.
//!
//! Provides watch expression evaluation and display.

/// A watch expression entry.
#[derive(Debug, Clone)]
pub struct WatchEntry {
    /// The expression text.
    pub expression: String,
    /// The evaluated value, if computed.
    pub value: Option<String>,
    /// Whether evaluation succeeded.
    pub valid: bool,
    /// Error message if evaluation failed.
    pub error: Option<String>,
}

impl WatchEntry {
    /// Create a new watch entry.
    pub fn new(expression: impl Into<String>) -> Self {
        Self {
            expression: expression.into(),
            value: None,
            valid: false,
            error: None,
        }
    }

    /// Set the evaluated value.
    pub fn set_value(&mut self, value: impl Into<String>) {
        self.value = Some(value.into());
        self.valid = true;
        self.error = None;
    }

    /// Set an error.
    pub fn set_error(&mut self, error: impl Into<String>) {
        self.value = None;
        self.valid = false;
        self.error = Some(error.into());
    }
}

/// A collection of watch entries.
#[derive(Debug, Default)]
pub struct WatchList {
    entries: Vec<WatchEntry>,
}

impl WatchList {
    /// Create a new empty watch list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a watch entry.
    pub fn add(&mut self, expression: impl Into<String>) {
        self.entries.push(WatchEntry::new(expression));
    }

    /// Remove a watch entry by index.
    pub fn remove(&mut self, index: usize) -> Option<WatchEntry> {
        if index < self.entries.len() {
            Some(self.entries.remove(index))
        } else {
            None
        }
    }

    /// Get all entries.
    pub fn entries(&self) -> &[WatchEntry] {
        &self.entries
    }

    /// Get a mutable reference to an entry.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut WatchEntry> {
        self.entries.get_mut(index)
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watch_list() {
        let mut list = WatchList::new();
        list.add("RAX");
        list.add("RBX");
        assert_eq!(list.len(), 2);

        list.get_mut(0).unwrap().set_value("0xDEAD");
        assert!(list.entries()[0].valid);
        assert_eq!(list.entries()[0].value.as_deref(), Some("0xDEAD"));

        let removed = list.remove(0);
        assert!(removed.is_some());
        assert_eq!(list.len(), 1);
    }
}
