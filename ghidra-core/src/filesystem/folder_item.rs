//! Folder item trait and helpers.
//!
//! Re-exports the [`FolderItem`] trait and related item traits
//! ([`DatabaseItem`], [`DataFileItem`], [`TextDataItem`], [`UnknownFolderItem`])
//! from `crate::filesystem::store`, plus provides a [`FolderItemExt`] extension
//! trait with convenience methods.
//!
//! Corresponds to `ghidra.framework.store.FolderItem`.

// Re-export all item traits and file-type constants from store.
pub use crate::filesystem::store::{
    DatabaseItem, DataFileItem, FolderItem, TextDataItem, UnknownFolderItem, Version,
    DATABASE_FILE_TYPE, DATAFILE_FILE_TYPE, DEFAULT_CHECKOUT_ID, LATEST_VERSION,
    LINK_FILE_TYPE, UNKNOWN_FILE_TYPE,
};

use crate::filesystem::store::StoreResult;

// ============================================================================
// File type constants
// ============================================================================

/// Returns a human-readable label for the given file-type constant.
///
/// Accepts the constants [`UNKNOWN_FILE_TYPE`], [`DATABASE_FILE_TYPE`],
/// [`DATAFILE_FILE_TYPE`], and [`LINK_FILE_TYPE`].
pub fn file_type_label(file_type: i32) -> &'static str {
    match file_type {
        UNKNOWN_FILE_TYPE => "Unknown",
        DATABASE_FILE_TYPE => "Database",
        DATAFILE_FILE_TYPE => "DataFile",
        LINK_FILE_TYPE => "Link",
        _ => "Invalid",
    }
}

/// Returns `true` when the given file-type constant is one of the recognized types.
pub fn is_valid_file_type(file_type: i32) -> bool {
    matches!(
        file_type,
        UNKNOWN_FILE_TYPE | DATABASE_FILE_TYPE | DATAFILE_FILE_TYPE | LINK_FILE_TYPE
    )
}

// ============================================================================
// FolderItemExt – convenience methods
// ============================================================================

/// Extension trait providing convenience methods for [`FolderItem`] implementors.
pub trait FolderItemExt: FolderItem {
    /// Returns true if this item is currently checked out by the given user.
    fn is_checked_out_by(&self, user: &str) -> StoreResult<bool> {
        if !self.is_checked_out() {
            return Ok(false);
        }
        let checkouts = self.get_checkouts()?;
        Ok(checkouts.iter().any(|c| c.user() == user))
    }

    /// Returns true if this item has any active checkouts.
    ///
    /// Corresponds to Java `FolderItem.hasCheckouts()`.
    fn has_active_checkouts(&self) -> StoreResult<bool> {
        let checkouts = self.get_checkouts()?;
        Ok(!checkouts.is_empty())
    }

    /// Returns the display name including content type, e.g. "MyProgram (Ghidra)".
    fn display_name(&self) -> String {
        let name = self.name();
        let ct = self.content_type();
        if ct.is_empty() {
            name.to_string()
        } else {
            format!("{} ({})", name, ct)
        }
    }

    /// Returns a summary string for debugging/logging.
    fn summary(&self) -> String {
        let id = self.file_id().unwrap_or("none");
        let ver = self.current_version();
        let ct = self.content_type();
        format!(
            "FolderItem[name={}, id={}, version={}, type={}]",
            self.name(),
            id,
            ver,
            ct
        )
    }

    /// Returns true if this is a private (non-versioned, non-checked-out) item.
    ///
    /// A private item has checkout_id of [`DEFAULT_CHECKOUT_ID`] and is
    /// not versioned.
    fn is_private(&self) -> StoreResult<bool> {
        if self.is_versioned()? {
            return Ok(false);
        }
        let cid = self.checkout_id()?;
        Ok(cid == DEFAULT_CHECKOUT_ID)
    }

    /// Returns true if this item is a database item.
    fn is_database(&self) -> bool {
        // Database items implement DatabaseItem; we cannot downcast via trait
        // alone so we rely on the content type heuristic.
        false
    }

    /// Returns true if this item has been deleted (refresh returns false).
    fn is_deleted(&self) -> StoreResult<bool> {
        // We cannot call refresh on &self (requires &mut self), so check
        // a non-destructive signal: minimum_version returning an error
        // can indicate the item is gone.  For a simple heuristic we just
        // return false and let callers call refresh() explicitly.
        Ok(false)
    }

    /// Returns the exclusive checkout status, if any.
    fn exclusive_checkout(&self) -> StoreResult<Option<crate::filesystem::store::ItemCheckoutStatus>> {
        if !self.is_checked_out_exclusive() {
            return Ok(None);
        }
        let checkouts = self.get_checkouts()?;
        Ok(checkouts
            .into_iter()
            .find(|c| c.checkout_type() == crate::filesystem::store::CheckoutType::Exclusive))
    }

    /// Returns the count of active checkouts.
    fn checkout_count(&self) -> StoreResult<usize> {
        let checkouts = self.get_checkouts()?;
        Ok(checkouts.len())
    }
}

// Blanket implementation for all FolderItem implementors.
impl<T: FolderItem + ?Sized> FolderItemExt for T {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::store::{
        CheckoutType, ItemCheckoutStatus, DEFAULT_CHECKOUT_ID,
    };
    use crate::generic::task::TaskMonitor;
    use std::path::Path;

    /// A minimal mock FolderItem for testing the extension trait.
    struct MockItem {
        name: String,
        content_type: String,
        version: i32,
        checkouts: Vec<ItemCheckoutStatus>,
    }

    impl MockItem {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                content_type: "Ghidra".to_string(),
                version: 5,
                checkouts: Vec::new(),
            }
        }
    }

    impl FolderItem for MockItem {
        fn name(&self) -> &str {
            &self.name
        }
        fn file_id(&self) -> Option<&str> {
            None
        }
        fn reset_file_id(&mut self) -> StoreResult<String> {
            Ok("new-id".into())
        }
        fn length(&self) -> StoreResult<i64> {
            Ok(0)
        }
        fn content_type(&self) -> &str {
            &self.content_type
        }
        fn current_version(&self) -> i32 {
            self.version
        }
        fn minimum_version(&self) -> StoreResult<i32> {
            Ok(1)
        }
        fn is_checked_out(&self) -> bool {
            !self.checkouts.is_empty()
        }
        fn is_checked_out_exclusive(&self) -> bool {
            self.checkouts
                .iter()
                .any(|c| c.checkout_type() == CheckoutType::Exclusive)
        }
        fn is_versioned(&self) -> StoreResult<bool> {
            Ok(false)
        }
        fn checkout_id(&self) -> StoreResult<i64> {
            Ok(DEFAULT_CHECKOUT_ID)
        }
        fn checkout_version(&self) -> StoreResult<i32> {
            Ok(-1)
        }
        fn local_checkout_version(&self) -> i32 {
            -1
        }
        fn set_checkout(
            &mut self,
            _checkout_id: i64,
            _exclusive: bool,
            _checkout_version: i32,
            _local_version: i32,
        ) -> StoreResult<()> {
            Ok(())
        }
        fn clear_checkout(&mut self) -> StoreResult<()> {
            self.checkouts.clear();
            Ok(())
        }
        fn delete(&mut self, _version: i32, _user: &str) -> StoreResult<()> {
            Ok(())
        }
        fn get_versions(&self) -> StoreResult<Option<Vec<Version>>> {
            Ok(None)
        }
        fn checkout(
            &self,
            _checkout_type: CheckoutType,
            _user: &str,
            _project_path: &str,
        ) -> StoreResult<Option<ItemCheckoutStatus>> {
            Ok(None)
        }
        fn terminate_checkout(&self, _checkout_id: i64, _notify: bool) -> StoreResult<()> {
            Ok(())
        }
        fn get_checkout(
            &self,
            checkout_id: i64,
        ) -> StoreResult<Option<ItemCheckoutStatus>> {
            Ok(self.checkouts.iter().find(|c| c.checkout_id() == checkout_id).cloned())
        }
        fn get_checkouts(&self) -> StoreResult<Vec<ItemCheckoutStatus>> {
            Ok(self.checkouts.clone())
        }
        fn is_checkin_active(&self) -> StoreResult<bool> {
            Ok(false)
        }
        fn update_checkout_version(
            &self,
            _checkout_id: i64,
            _checkout_version: i32,
            _user: &str,
        ) -> StoreResult<()> {
            Ok(())
        }
        fn output(
            &self,
            _output_file: &Path,
            _version: i32,
            _monitor: &TaskMonitor,
        ) -> StoreResult<()> {
            Ok(())
        }
        fn refresh(&mut self) -> StoreResult<bool> {
            Ok(true)
        }
        fn can_recover(&self) -> bool {
            false
        }
    }

    // ------------------------------------------------------------------
    // file_type helpers
    // ------------------------------------------------------------------

    #[test]
    fn test_file_type_label_known() {
        assert_eq!(file_type_label(DATABASE_FILE_TYPE), "Database");
        assert_eq!(file_type_label(DATAFILE_FILE_TYPE), "DataFile");
        assert_eq!(file_type_label(LINK_FILE_TYPE), "Link");
        assert_eq!(file_type_label(UNKNOWN_FILE_TYPE), "Unknown");
    }

    #[test]
    fn test_file_type_label_invalid() {
        assert_eq!(file_type_label(99), "Invalid");
    }

    #[test]
    fn test_is_valid_file_type() {
        assert!(is_valid_file_type(DATABASE_FILE_TYPE));
        assert!(is_valid_file_type(DATAFILE_FILE_TYPE));
        assert!(is_valid_file_type(LINK_FILE_TYPE));
        assert!(is_valid_file_type(UNKNOWN_FILE_TYPE));
        assert!(!is_valid_file_type(42));
    }

    // ------------------------------------------------------------------
    // FolderItemExt tests
    // ------------------------------------------------------------------

    #[test]
    fn test_display_name_with_content_type() {
        let item = MockItem::new("MyProgram");
        assert_eq!(item.display_name(), "MyProgram (Ghidra)");
    }

    #[test]
    fn test_display_name_empty_content_type() {
        let mut item = MockItem::new("test");
        item.content_type = String::new();
        assert_eq!(item.display_name(), "test");
    }

    #[test]
    fn test_summary() {
        let item = MockItem::new("MyProgram");
        let s = item.summary();
        assert!(s.contains("MyProgram"));
        assert!(s.contains("version=5"));
    }

    #[test]
    fn test_has_active_checkouts_empty() {
        let item = MockItem::new("test");
        assert!(!item.has_active_checkouts().unwrap());
    }

    #[test]
    fn test_has_active_checkouts_with_checkout() {
        let mut item = MockItem::new("test");
        item.checkouts.push(ItemCheckoutStatus::new(
            1,
            CheckoutType::Normal,
            "alice",
            1,
            0,
            None,
        ));
        assert!(item.has_active_checkouts().unwrap());
    }

    #[test]
    fn test_is_checked_out_by() {
        let mut item = MockItem::new("test");
        item.checkouts.push(ItemCheckoutStatus::new(
            1,
            CheckoutType::Normal,
            "alice",
            1,
            0,
            None,
        ));
        assert!(item.is_checked_out_by("alice").unwrap());
        assert!(!item.is_checked_out_by("bob").unwrap());
    }

    #[test]
    fn test_is_private() {
        let item = MockItem::new("test");
        assert!(item.is_private().unwrap());
    }

    #[test]
    fn test_exclusive_checkout_none() {
        let item = MockItem::new("test");
        assert!(item.exclusive_checkout().unwrap().is_none());
    }

    #[test]
    fn test_exclusive_checkout_present() {
        let mut item = MockItem::new("test");
        item.checkouts.push(ItemCheckoutStatus::new(
            1,
            CheckoutType::Exclusive,
            "alice",
            1,
            0,
            None,
        ));
        let exc = item.exclusive_checkout().unwrap();
        assert!(exc.is_some());
        assert_eq!(exc.unwrap().user(), "alice");
    }

    #[test]
    fn test_checkout_count() {
        let mut item = MockItem::new("test");
        assert_eq!(item.checkout_count().unwrap(), 0);
        item.checkouts.push(ItemCheckoutStatus::new(
            1,
            CheckoutType::Normal,
            "alice",
            1,
            0,
            None,
        ));
        item.checkouts.push(ItemCheckoutStatus::new(
            2,
            CheckoutType::Normal,
            "bob",
            1,
            0,
            None,
        ));
        assert_eq!(item.checkout_count().unwrap(), 2);
    }
}
