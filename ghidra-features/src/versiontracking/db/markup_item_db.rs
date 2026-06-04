//! Database-backed markup item storage.

use ghidra_core::addr::Address;

use crate::versiontracking::markup::{MarkupType, Stringable, VtMarkupItem};
use crate::versiontracking::types::{VtMarkupItemStatus};

/// Database-backed markup item storage.
///
/// Maps to a row in the markup item table.
#[derive(Debug, Clone)]
pub struct MarkupItemStorageDB {
    /// Database key
    pub key: i64,
    /// Association ID this item belongs to
    pub association_id: i64,
    /// Markup type ID
    pub markup_type_id: i32,
    /// Source address offset
    pub source_address: u64,
    /// Destination address offset (None if not set)
    pub destination_address: Option<u64>,
    /// Destination address source string
    pub destination_address_source: String,
    /// Source value as storage string
    pub source_value: Option<String>,
    /// Current destination value as storage string
    pub destination_value: Option<String>,
    /// Original destination value as storage string
    pub original_destination_value: Option<String>,
    /// Status code
    pub status: i32,
    /// Status description
    pub status_description: Option<String>,
}

impl MarkupItemStorageDB {
    /// Create a new markup item storage record.
    pub fn new(key: i64, association_id: i64, markup_type_id: i32, source_address: u64) -> Self {
        Self {
            key,
            association_id,
            markup_type_id,
            source_address,
            destination_address: None,
            destination_address_source: String::new(),
            source_value: None,
            destination_value: None,
            original_destination_value: None,
            status: 0,
            status_description: None,
        }
    }

    /// Create from a VtMarkupItem.
    pub fn from_markup_item(key: i64, association_id: i64, item: &VtMarkupItem) -> Self {
        Self {
            key,
            association_id,
            markup_type_id: item.markup_type().db_id(),
            source_address: item.source_address().get_offset(),
            destination_address: item.destination_address().map(|a| a.get_offset()),
            destination_address_source: item.destination_address_source().to_string(),
            source_value: item.source_value().map(|v| v.to_storage_string()),
            destination_value: item.current_destination_value().map(|v| v.to_storage_string()),
            original_destination_value: item.original_destination_value().map(|v| v.to_storage_string()),
            status: item.status() as i32,
            status_description: item.status_description().map(|s| s.to_string()),
        }
    }

    /// Convert to a VtMarkupItem.
    pub fn to_markup_item(&self) -> VtMarkupItem {
        let markup_type = MarkupType::from_db_id(self.markup_type_id)
            .unwrap_or(MarkupType::Label);
        let mut item = VtMarkupItem::new(
            self.key as u64,
            markup_type,
            Address::new(self.source_address),
        );
        if let Some(dst_addr) = self.destination_address {
            item.set_default_destination_address(
                Address::new(dst_addr),
                &self.destination_address_source,
            );
        }
        if let Some(ref sv) = self.source_value {
            if let Some(s) = Stringable::from_storage_string(sv) {
                item.set_source_value(s);
            }
        }
        if let Some(ref dv) = self.destination_value {
            if let Some(s) = Stringable::from_storage_string(dv) {
                item.set_current_destination_value(s);
            }
        }
        if let Some(ref ov) = self.original_destination_value {
            if let Some(s) = Stringable::from_storage_string(ov) {
                item.set_original_destination_value(s);
            }
        }
        // Restore status
        match self.status {
            1 => { let _ = item.apply(crate::versiontracking::types::VtMarkupItemApplyActionType::Add); }
            2 => { let _ = item.apply(crate::versiontracking::types::VtMarkupItemApplyActionType::Replace); }
            _ => {}
        }
        item
    }

    /// Returns the markup type.
    pub fn markup_type(&self) -> Option<MarkupType> {
        MarkupType::from_db_id(self.markup_type_id)
    }

    /// Returns the status.
    pub fn status_enum(&self) -> VtMarkupItemStatus {
        match self.status {
            0 => VtMarkupItemStatus::Unapplied,
            1 => VtMarkupItemStatus::Added,
            2 => VtMarkupItemStatus::Replaced,
            3 => VtMarkupItemStatus::FailedApply,
            4 => VtMarkupItemStatus::DontCare,
            5 => VtMarkupItemStatus::DontKnow,
            6 => VtMarkupItemStatus::Rejected,
            7 => VtMarkupItemStatus::Same,
            8 => VtMarkupItemStatus::Conflict,
            _ => VtMarkupItemStatus::Unapplied,
        }
    }

    /// Set status from enum.
    pub fn set_status_from_enum(&mut self, status: VtMarkupItemStatus) {
        self.status = match status {
            VtMarkupItemStatus::Unapplied => 0,
            VtMarkupItemStatus::Added => 1,
            VtMarkupItemStatus::Replaced => 2,
            VtMarkupItemStatus::FailedApply => 3,
            VtMarkupItemStatus::DontCare => 4,
            VtMarkupItemStatus::DontKnow => 5,
            VtMarkupItemStatus::Rejected => 6,
            VtMarkupItemStatus::Same => 7,
            VtMarkupItemStatus::Conflict => 8,
        };
    }
}

impl std::fmt::Display for MarkupItemStorageDB {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MarkupItemDB(key={}, assoc={}, type={}, src=0x{:x}, status={})",
            self.key, self.association_id, self.markup_type_id,
            self.source_address, self.status
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::versiontracking::markup::{MarkupType, VtMarkupItem, Stringable};

    #[test]
    fn test_markup_item_db_create() {
        let db = MarkupItemStorageDB::new(1, 10, 13, 0x1000);
        assert_eq!(db.key, 1);
        assert_eq!(db.association_id, 10);
        assert_eq!(db.markup_type_id, 13);
        assert_eq!(db.source_address, 0x1000);
        assert_eq!(db.markup_type(), Some(MarkupType::FunctionName));
    }

    #[test]
    fn test_markup_item_db_from_item() {
        let mut item = VtMarkupItem::new(1, MarkupType::Label, Address::new(0x1000));
        item.set_source_value(Stringable::Label("test_label".to_string()));
        let db = MarkupItemStorageDB::from_markup_item(1, 10, &item);
        assert_eq!(db.source_value, Some("LB:test_label".to_string()));
        assert_eq!(db.status, 0);
    }

    #[test]
    fn test_markup_item_db_status() {
        let mut db = MarkupItemStorageDB::new(1, 10, 13, 0x1000);
        db.set_status_from_enum(VtMarkupItemStatus::DontCare);
        assert_eq!(db.status, 4);
        assert_eq!(db.status_enum(), VtMarkupItemStatus::DontCare);
    }

    #[test]
    fn test_markup_item_db_display() {
        let db = MarkupItemStorageDB::new(1, 10, 13, 0x1000);
        let display = format!("{}", db);
        assert!(display.contains("MarkupItemDB"));
        assert!(display.contains("key=1"));
    }
}
