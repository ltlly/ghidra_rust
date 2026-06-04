//! Markup item implementation with full state management.

use std::fmt;

use ghidra_core::addr::Address;

use crate::versiontracking::markup::{MarkupType, Stringable, VtMarkupItem};
use crate::versiontracking::types::{
    VtMarkupItemApplyActionType, VtMarkupItemConsideredStatus,
    VtMarkupItemDestinationAddressEditStatus, VtMarkupItemStatus,
};
use crate::versiontracking::error::{VtError, VtResult};

/// Extended markup item implementation.
///
/// Wraps a `VtMarkupItem` with additional state management
/// for application to programs, change tracking, and options.
///
/// Corresponds to Ghidra's `MarkupItemImpl` and `MarkupItemStorage` Java classes.
#[derive(Debug, Clone)]
pub struct MarkupItemImpl {
    /// The underlying markup item
    item: VtMarkupItem,
    /// Whether this item has been examined by the user
    examined: bool,
    /// Whether the source value has been loaded
    source_loaded: bool,
    /// Whether the destination value has been loaded
    destination_loaded: bool,
    /// The apply options name
    options_name: String,
    /// Whether this item is read-only
    read_only: bool,
}

impl MarkupItemImpl {
    /// Create a new markup item implementation.
    pub fn new(id: u64, markup_type: MarkupType, source_address: Address) -> Self {
        Self {
            item: VtMarkupItem::new(id, markup_type, source_address),
            examined: false,
            source_loaded: false,
            destination_loaded: false,
            options_name: String::new(),
            read_only: false,
        }
    }

    /// Create from an existing VtMarkupItem.
    pub fn from_item(item: VtMarkupItem) -> Self {
        Self {
            item,
            examined: false,
            source_loaded: false,
            destination_loaded: false,
            options_name: String::new(),
            read_only: false,
        }
    }

    /// Returns a reference to the inner VtMarkupItem.
    pub fn inner(&self) -> &VtMarkupItem {
        &self.item
    }

    /// Returns a mutable reference to the inner VtMarkupItem.
    pub fn inner_mut(&mut self) -> &mut VtMarkupItem {
        &mut self.item
    }

    /// Whether this item has been examined.
    pub fn is_examined(&self) -> bool {
        self.examined
    }

    /// Mark as examined.
    pub fn set_examined(&mut self, examined: bool) {
        self.examined = examined;
    }

    /// Whether the source value has been loaded.
    pub fn is_source_loaded(&self) -> bool {
        self.source_loaded
    }

    /// Mark source as loaded.
    pub fn set_source_loaded(&mut self, loaded: bool) {
        self.source_loaded = loaded;
    }

    /// Whether the destination value has been loaded.
    pub fn is_destination_loaded(&self) -> bool {
        self.destination_loaded
    }

    /// Mark destination as loaded.
    pub fn set_destination_loaded(&mut self, loaded: bool) {
        self.destination_loaded = loaded;
    }

    /// Returns the options name.
    pub fn options_name(&self) -> &str {
        &self.options_name
    }

    /// Set the options name.
    pub fn set_options_name(&mut self, name: impl Into<String>) {
        self.options_name = name.into();
    }

    /// Whether this item is read-only.
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Set read-only.
    pub fn set_read_only(&mut self, read_only: bool) {
        self.read_only = read_only;
    }

    /// Apply the markup item with an action type.
    pub fn apply(&mut self, action: VtMarkupItemApplyActionType) -> VtResult<()> {
        if self.read_only {
            return Err(VtError::ApplyError {
                message: "Markup item is read-only".to_string(),
            });
        }
        self.item.apply(action).map_err(|e| VtError::ApplyError { message: e })
    }

    /// Unapply the markup item.
    pub fn unapply(&mut self) -> VtResult<()> {
        if self.read_only {
            return Err(VtError::ApplyError {
                message: "Markup item is read-only".to_string(),
            });
        }
        self.item.unapply().map_err(|e| VtError::ApplyError { message: e })
    }

    /// Set the considered status.
    pub fn set_considered(&mut self, status: VtMarkupItemConsideredStatus) -> VtResult<()> {
        self.item
            .set_considered(status)
            .map_err(|e| VtError::ApplyError { message: e })
    }

    /// Whether this item can be applied.
    pub fn can_apply(&self) -> bool {
        !self.read_only && self.item.can_apply()
    }

    /// Whether this item can be unapplied.
    pub fn can_unapply(&self) -> bool {
        !self.read_only && self.item.can_unapply()
    }

    /// Returns the markup type.
    pub fn markup_type(&self) -> MarkupType {
        self.item.markup_type()
    }

    /// Returns the source address.
    pub fn source_address(&self) -> Address {
        self.item.source_address()
    }

    /// Returns the destination address.
    pub fn destination_address(&self) -> Option<Address> {
        self.item.destination_address()
    }

    /// Returns the status.
    pub fn status(&self) -> VtMarkupItemStatus {
        self.item.status()
    }

    /// Returns the source value.
    pub fn source_value(&self) -> Option<&Stringable> {
        self.item.source_value()
    }

    /// Returns the current destination value.
    pub fn current_destination_value(&self) -> Option<&Stringable> {
        self.item.current_destination_value()
    }

    /// Returns the destination address edit status.
    pub fn destination_address_edit_status(&self) -> VtMarkupItemDestinationAddressEditStatus {
        self.item.destination_address_edit_status()
    }

    /// Whether source and destination values are the same.
    pub fn has_same_source_and_destination_values(&self) -> bool {
        self.item.has_same_source_and_destination_values()
    }

    /// Set the destination address.
    pub fn set_destination_address(&mut self, address: Address) {
        self.item.set_destination_address(address);
    }

    /// Set the default destination address.
    pub fn set_default_destination_address(&mut self, address: Address, source: impl Into<String>) {
        self.item.set_default_destination_address(address, source);
    }

    /// Set the source value.
    pub fn set_source_value(&mut self, value: Stringable) {
        self.item.set_source_value(value);
    }

    /// Set the current destination value.
    pub fn set_current_destination_value(&mut self, value: Stringable) {
        self.item.set_current_destination_value(value);
    }

    /// Set the original destination value.
    pub fn set_original_destination_value(&mut self, value: Stringable) {
        self.item.set_original_destination_value(value);
    }
}

impl fmt::Display for MarkupItemImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MarkupItemImpl({}, examined={})", self.item, self.examined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::versiontracking::markup::{MarkupType, Stringable};

    #[test]
    fn test_markup_item_impl_create() {
        let item = MarkupItemImpl::new(1, MarkupType::FunctionName, Address::new(0x1000));
        assert_eq!(item.markup_type(), MarkupType::FunctionName);
        assert!(!item.is_examined());
        assert!(!item.is_read_only());
    }

    #[test]
    fn test_markup_item_impl_lifecycle() {
        let mut item = MarkupItemImpl::new(1, MarkupType::Label, Address::new(0x1000));
        item.set_destination_address(Address::new(0x2000));
        item.set_source_value(Stringable::Label("test".to_string()));
        assert!(item.can_apply());
        item.apply(VtMarkupItemApplyActionType::Replace).unwrap();
        assert!(item.can_unapply());
        item.unapply().unwrap();
        assert!(item.can_apply());
    }

    #[test]
    fn test_markup_item_impl_read_only() {
        let mut item = MarkupItemImpl::new(1, MarkupType::Label, Address::new(0x1000));
        item.set_destination_address(Address::new(0x2000));
        item.set_read_only(true);
        assert!(!item.can_apply());
        assert!(item.apply(VtMarkupItemApplyActionType::Add).is_err());
    }

    #[test]
    fn test_markup_item_impl_examined() {
        let mut item = MarkupItemImpl::new(1, MarkupType::Label, Address::new(0x1000));
        assert!(!item.is_examined());
        item.set_examined(true);
        assert!(item.is_examined());
    }

    #[test]
    fn test_markup_item_impl_loaded() {
        let mut item = MarkupItemImpl::new(1, MarkupType::Label, Address::new(0x1000));
        item.set_source_loaded(true);
        item.set_destination_loaded(true);
        assert!(item.is_source_loaded());
        assert!(item.is_destination_loaded());
    }

    #[test]
    fn test_markup_item_impl_display() {
        let item = MarkupItemImpl::new(1, MarkupType::Label, Address::new(0x1000));
        let display = format!("{}", item);
        assert!(display.contains("MarkupItemImpl"));
        assert!(display.contains("examined=false"));
    }
}
