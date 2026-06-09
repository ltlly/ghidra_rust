//! Folder item trait and helpers.
//!
//! Re-exports the [`FolderItem`] trait and related item traits
//! ([`DatabaseItem`], [`DataFileItem`], [`TextDataItem`], [`UnknownFolderItem`])
//! from `crate::filesystem::store`, plus provides a [`FolderItemExt`] extension
//! trait with convenience methods.
//!
//! Corresponds to `ghidra.framework.store.FolderItem`.

// Re-export all item traits from store.
pub use crate::filesystem::store::{
    DatabaseItem, DataFileItem, FolderItem, TextDataItem, UnknownFolderItem, Version,
};

use crate::filesystem::store::StoreResult;

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
}
