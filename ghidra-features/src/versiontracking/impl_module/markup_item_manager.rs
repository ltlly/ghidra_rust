//! Markup item manager implementation.

use std::collections::HashMap;
use std::fmt;

use ghidra_core::addr::Address;
use crate::versiontracking::error::{VtError, VtResult};
use crate::versiontracking::impl_module::markup_item_impl::MarkupItemImpl;
use crate::versiontracking::markup::MarkupType;
use crate::versiontracking::types::{
    VtAssociationMarkupStatus, VtMarkupItemApplyActionType,
    VtMarkupItemConsideredStatus, VtMarkupItemStatus,
};

/// Manages markup items for an association.
///
/// Provides batch operations on markup items including applying,
/// unapplying, setting considered status, and computing the
/// overall markup status for an association.
///
/// Corresponds to Ghidra's `MarkupItemManagerImpl` Java class.
#[derive(Debug)]
pub struct MarkupItemManagerImpl {
    /// The association ID this manager is for
    association_id: u64,
    /// Markup items keyed by markup type
    items: HashMap<MarkupType, MarkupItemImpl>,
    /// All items in insertion order
    ordered_items: Vec<MarkupType>,
}

impl MarkupItemManagerImpl {
    /// Create a new markup item manager.
    pub fn new(association_id: u64) -> Self {
        Self {
            association_id,
            items: HashMap::new(),
            ordered_items: Vec::new(),
        }
    }

    /// Add a markup item.
    pub fn add_item(&mut self, item: MarkupItemImpl) {
        let mt = item.markup_type();
        if !self.items.contains_key(&mt) {
            self.ordered_items.push(mt);
        }
        self.items.insert(mt, item);
    }

    /// Get a markup item by type.
    pub fn get_item(&self, markup_type: MarkupType) -> Option<&MarkupItemImpl> {
        self.items.get(&markup_type)
    }

    /// Get a mutable markup item by type.
    pub fn get_item_mut(&mut self, markup_type: MarkupType) -> Option<&mut MarkupItemImpl> {
        self.items.get_mut(&markup_type)
    }

    /// Get all markup items.
    pub fn items(&self) -> Vec<&MarkupItemImpl> {
        self.ordered_items
            .iter()
            .filter_map(|mt| self.items.get(mt))
            .collect()
    }

    /// Get all mutable markup items (order not guaranteed).
    pub fn items_mut(&mut self) -> Vec<&mut MarkupItemImpl> {
        self.items.values_mut().collect()
    }

    /// Number of markup items.
    pub fn item_count(&self) -> usize {
        self.items.len()
    }

    /// Apply a markup item by type.
    pub fn apply_item(
        &mut self,
        markup_type: MarkupType,
        action: VtMarkupItemApplyActionType,
    ) -> VtResult<()> {
        let item = self
            .items
            .get_mut(&markup_type)
            .ok_or_else(|| VtError::ApplyError {
                message: format!("No markup item for type {:?}", markup_type),
            })?;
        item.apply(action)
    }

    /// Unapply a markup item by type.
    pub fn unapply_item(&mut self, markup_type: MarkupType) -> VtResult<()> {
        let item = self
            .items
            .get_mut(&markup_type)
            .ok_or_else(|| VtError::ApplyError {
                message: format!("No markup item for type {:?}", markup_type),
            })?;
        item.unapply()
    }

    /// Set considered status for a markup item.
    pub fn set_item_considered(
        &mut self,
        markup_type: MarkupType,
        status: VtMarkupItemConsideredStatus,
    ) -> VtResult<()> {
        let item = self
            .items
            .get_mut(&markup_type)
            .ok_or_else(|| VtError::ApplyError {
                message: format!("No markup item for type {:?}", markup_type),
            })?;
        item.set_considered(status)
    }

    /// Apply all items that can be applied.
    pub fn apply_all(
        &mut self,
        action: VtMarkupItemApplyActionType,
    ) -> VtResult<Vec<MarkupType>> {
        let mut applied = Vec::new();
        let keys: Vec<MarkupType> = self.ordered_items.clone();
        for key in keys {
            if let Some(item) = self.items.get_mut(&key) {
                if item.can_apply() && item.destination_address().is_some() {
                    item.apply(action)?;
                    applied.push(key);
                }
            }
        }
        Ok(applied)
    }

    /// Unapply all applied items.
    pub fn unapply_all(&mut self) -> VtResult<Vec<MarkupType>> {
        let mut unapplied = Vec::new();
        let keys: Vec<MarkupType> = self.ordered_items.clone();
        for key in keys {
            if let Some(item) = self.items.get_mut(&key) {
                if item.can_unapply() {
                    item.unapply()?;
                    unapplied.push(key);
                }
            }
        }
        Ok(unapplied)
    }

    /// Compute the overall markup status for this association.
    pub fn compute_markup_status(&self) -> VtAssociationMarkupStatus {
        let mut has_unexamined = false;
        let mut has_applied = false;
        let mut has_rejected = false;
        let mut has_dont_care = false;
        let mut has_dont_know = false;
        let mut has_errors = false;

        for item in self.items.values() {
            match item.status() {
                VtMarkupItemStatus::Unapplied => has_unexamined = true,
                VtMarkupItemStatus::Added | VtMarkupItemStatus::Replaced => has_applied = true,
                VtMarkupItemStatus::FailedApply => has_errors = true,
                VtMarkupItemStatus::DontCare => has_dont_care = true,
                VtMarkupItemStatus::DontKnow => has_dont_know = true,
                VtMarkupItemStatus::Rejected => has_rejected = true,
                VtMarkupItemStatus::Same => {} // not counted
                VtMarkupItemStatus::Conflict => {} // not counted
            }
        }

        VtAssociationMarkupStatus::new(has_unexamined, has_applied, has_rejected, has_dont_care, has_dont_know, has_errors)
    }

    /// Clear all markup items.
    pub fn clear(&mut self) {
        self.items.clear();
        self.ordered_items.clear();
    }

    /// Returns the association ID.
    pub fn association_id(&self) -> u64 {
        self.association_id
    }
}

impl fmt::Display for MarkupItemManagerImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MarkupItemManager(assoc={}, items={})",
            self.association_id,
            self.items.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;
    use crate::versiontracking::markup::{MarkupType, Stringable};

    fn make_manager_with_items() -> MarkupItemManagerImpl {
        let mut mgr = MarkupItemManagerImpl::new(1);
        let mut item1 = MarkupItemImpl::new(1, MarkupType::FunctionName, Address::new(0x1000));
        item1.set_destination_address(Address::new(0x2000));
        item1.set_source_value(Stringable::FunctionName("main".to_string()));
        mgr.add_item(item1);

        let mut item2 = MarkupItemImpl::new(2, MarkupType::Label, Address::new(0x1000));
        item2.set_destination_address(Address::new(0x2000));
        item2.set_source_value(Stringable::Label("my_label".to_string()));
        mgr.add_item(item2);

        mgr
    }

    #[test]
    fn test_manager_create() {
        let mgr = MarkupItemManagerImpl::new(1);
        assert_eq!(mgr.item_count(), 0);
        assert_eq!(mgr.association_id(), 1);
    }

    #[test]
    fn test_manager_add_and_get() {
        let mgr = make_manager_with_items();
        assert_eq!(mgr.item_count(), 2);
        assert!(mgr.get_item(MarkupType::FunctionName).is_some());
        assert!(mgr.get_item(MarkupType::EolComment).is_none());
    }

    #[test]
    fn test_manager_apply_item() {
        let mut mgr = make_manager_with_items();
        mgr.apply_item(MarkupType::FunctionName, VtMarkupItemApplyActionType::Replace)
            .unwrap();
        let item = mgr.get_item(MarkupType::FunctionName).unwrap();
        assert!(item.status() == VtMarkupItemStatus::Replaced);
    }

    #[test]
    fn test_manager_apply_all() {
        let mut mgr = make_manager_with_items();
        let applied = mgr.apply_all(VtMarkupItemApplyActionType::Add).unwrap();
        assert_eq!(applied.len(), 2);
    }

    #[test]
    fn test_manager_unapply_all() {
        let mut mgr = make_manager_with_items();
        let _ = mgr.apply_all(VtMarkupItemApplyActionType::Add);
        let unapplied = mgr.unapply_all().unwrap();
        assert_eq!(unapplied.len(), 2);
    }

    #[test]
    fn test_manager_markup_status() {
        let mgr = make_manager_with_items();
        let status = mgr.compute_markup_status();
        assert!(status.has_unexamined_markups());
    }

    #[test]
    fn test_manager_display() {
        let mgr = MarkupItemManagerImpl::new(1);
        let display = format!("{}", mgr);
        assert!(display.contains("MarkupItemManager"));
    }
}
