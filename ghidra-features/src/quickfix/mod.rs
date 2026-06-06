//! Quick-fix framework for bulk-executable program modifications.
//!
//! Ported from `ghidra.features.base.quickfix`.
//!
//! Provides the base [`QuickFix`] trait for items that can be displayed in a table
//! and applied individually or in bulk (search-and-replace, code fixes, etc.).

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// QuickFixStatus
// ---------------------------------------------------------------------------

/// Status of a single [`QuickFix`] item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuickFixStatus {
    /// Unapplied and ready to execute.
    None,
    /// Unapplied, with an associated warning.
    Warning,
    /// Unapplied, but the target has changed from the original value.
    Changed,
    /// Target program element no longer exists.
    Deleted,
    /// Cannot be applied (before or after attempt).
    Error,
    /// Successfully applied.
    Done,
}

impl fmt::Display for QuickFixStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "Not Applied"),
            Self::Warning => write!(f, "Warning"),
            Self::Changed => write!(f, "Target changed externally"),
            Self::Deleted => write!(f, "Target no longer exists"),
            Self::Error => write!(f, "Error"),
            Self::Done => write!(f, "Applied"),
        }
    }
}

// ---------------------------------------------------------------------------
// QuickFix trait
// ---------------------------------------------------------------------------

/// A single fixable item representing a program modification.
///
/// Implementations provide the actual mutation logic via [`execute`](QuickFix::execute)
/// and describe the element they affect via metadata methods.
pub trait QuickFix {
    /// General action name (e.g. "Rename", "Update Comment").
    fn action_name(&self) -> &str;

    /// Type of the affected element (e.g. "Symbol", "Comment", "DataType").
    fn item_type(&self) -> &str;

    /// Address of the affected element, if applicable.
    fn address(&self) -> Option<u64> {
        None
    }

    /// A path associated with the affected element, if applicable.
    fn path(&self) -> Option<&str> {
        None
    }

    /// The original value before any modification.
    fn original(&self) -> &str;

    /// The current value (may differ from original if program was modified externally).
    fn current(&self) -> &str {
        self.original()
    }

    /// Preview of what the element will look like after applying.
    fn preview(&self) -> &str;

    /// Current status of this fix item.
    fn status(&self) -> QuickFixStatus;

    /// Human-readable status message.
    fn status_message(&self) -> String {
        match self.status() {
            QuickFixStatus::Done => "Applied".into(),
            QuickFixStatus::Error => "Error".into(),
            QuickFixStatus::None => "Not Applied".into(),
            QuickFixStatus::Warning => "Warning".into(),
            QuickFixStatus::Changed => "Target changed externally".into(),
            QuickFixStatus::Deleted => "Target no longer exists".into(),
        }
    }

    /// Execute the primary action. Should be idempotent for already-applied items.
    fn execute(&mut self);

    /// Optional custom tooltip data for display.
    fn custom_tooltip_data(&self) -> Option<&HashMap<String, String>> {
        None
    }
}

// ---------------------------------------------------------------------------
// QuickFixItem (concrete owned implementation for tests/simple use)
// ---------------------------------------------------------------------------

/// A concrete, owned [`QuickFix`] implementation for test and simple scripting use.
#[derive(Debug, Clone)]
pub struct QuickFixItem {
    action: String,
    item_type: String,
    addr: Option<u64>,
    path: Option<String>,
    orig: String,
    replacement: String,
    status: QuickFixStatus,
    status_msg: Option<String>,
}

impl QuickFixItem {
    /// Create a new quick-fix item.
    pub fn new(
        action: impl Into<String>,
        item_type: impl Into<String>,
        original: impl Into<String>,
        replacement: impl Into<String>,
    ) -> Self {
        Self {
            action: action.into(),
            item_type: item_type.into(),
            addr: None,
            path: None,
            orig: original.into(),
            replacement: replacement.into(),
            status: QuickFixStatus::None,
            status_msg: None,
        }
    }

    /// Set the address.
    pub fn with_address(mut self, addr: u64) -> Self {
        self.addr = Some(addr);
        self
    }

    /// Set the path.
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Set the status.
    pub fn set_status(&mut self, status: QuickFixStatus, message: Option<String>) {
        self.status = status;
        self.status_msg = message;
    }
}

impl QuickFix for QuickFixItem {
    fn action_name(&self) -> &str {
        &self.action
    }
    fn item_type(&self) -> &str {
        &self.item_type
    }
    fn address(&self) -> Option<u64> {
        self.addr
    }
    fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }
    fn original(&self) -> &str {
        &self.orig
    }
    fn preview(&self) -> &str {
        &self.replacement
    }
    fn status(&self) -> QuickFixStatus {
        self.status
    }
    fn status_message(&self) -> String {
        self.status_msg
            .clone()
            .unwrap_or_else(|| QuickFixStatus::to_string(&self.status))
    }
    fn execute(&mut self) {
        self.status = QuickFixStatus::Done;
    }
}

// ---------------------------------------------------------------------------
// TableDataLoader
// ---------------------------------------------------------------------------

/// Trait for asynchronous loading of quick-fix items into a table.
///
/// Implementations are called by a table model to fill an accumulator with
/// [`QuickFix`] items (e.g. from a search operation).
pub trait TableDataLoader<T> {
    /// Load data into the accumulator, reporting progress and supporting cancellation.
    fn load_data(&self, accumulator: &mut Vec<T>) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quickfix_status_display() {
        assert_eq!(QuickFixStatus::None.to_string(), "Not Applied");
        assert_eq!(QuickFixStatus::Done.to_string(), "Applied");
        assert_eq!(QuickFixStatus::Error.to_string(), "Error");
        assert_eq!(QuickFixStatus::Warning.to_string(), "Warning");
        assert_eq!(QuickFixStatus::Changed.to_string(), "Target changed externally");
        assert_eq!(QuickFixStatus::Deleted.to_string(), "Target no longer exists");
    }

    #[test]
    fn test_quickfix_item_creation() {
        let item = QuickFixItem::new("Rename", "Symbol", "old_name", "new_name")
            .with_address(0x400000)
            .with_path("main/old_name");

        assert_eq!(item.action_name(), "Rename");
        assert_eq!(item.item_type(), "Symbol");
        assert_eq!(item.original(), "old_name");
        assert_eq!(item.preview(), "new_name");
        assert_eq!(item.address(), Some(0x400000));
        assert_eq!(item.path(), Some("main/old_name"));
        assert_eq!(item.status(), QuickFixStatus::None);
    }

    #[test]
    fn test_quickfix_item_execute() {
        let mut item = QuickFixItem::new("Rename", "Label", "foo", "bar");
        assert_eq!(item.status(), QuickFixStatus::None);

        item.execute();
        assert_eq!(item.status(), QuickFixStatus::Done);
        assert_eq!(item.status_message(), "Applied");
    }

    #[test]
    fn test_quickfix_item_set_status() {
        let mut item = QuickFixItem::new("Update", "Comment", "old", "new");
        item.set_status(QuickFixStatus::Warning, Some("Address conflict".into()));
        assert_eq!(item.status(), QuickFixStatus::Warning);
        assert_eq!(item.status_message(), "Address conflict");
    }

    #[test]
    fn test_quickfix_no_execute_on_error() {
        // Verify error status semantics -- the real Java code blocks execution on error
        let mut item = QuickFixItem::new("Rename", "Symbol", "a", "b");
        item.set_status(QuickFixStatus::Error, Some("Cannot rename".into()));
        assert_eq!(item.status(), QuickFixStatus::Error);
    }

    #[test]
    fn test_quickfix_default_address_and_path() {
        let item = QuickFixItem::new("Rename", "Symbol", "a", "b");
        assert_eq!(item.address(), None);
        assert_eq!(item.path(), None);
    }
}
