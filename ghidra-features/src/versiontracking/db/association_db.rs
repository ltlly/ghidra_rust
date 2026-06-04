//! Database-backed VTAssociation.

use ghidra_core::addr::Address;

use crate::versiontracking::association::VtAssociation;
use crate::versiontracking::types::{VtAssociationMarkupStatus, VtAssociationStatus, VtAssociationType};

/// Database-backed association record.
///
/// Maps to a row in the association table.
#[derive(Debug, Clone)]
pub struct VtAssociationDB {
    /// Database key
    pub key: i64,
    /// Association type (0=Function, 1=Data)
    pub association_type: i32,
    /// Source address offset
    pub source_address: u64,
    /// Destination address offset
    pub destination_address: u64,
    /// Status (0=Available, 1=Accepted, 2=Blocked, 3=Rejected)
    pub status: i32,
    /// Vote count
    pub vote_count: i32,
}

impl VtAssociationDB {
    /// Create a new association DB record.
    pub fn new(key: i64, association_type: i32, source: u64, destination: u64) -> Self {
        Self {
            key,
            association_type,
            source_address: source,
            destination_address: destination,
            status: 0,
            vote_count: 0,
        }
    }

    /// Create from a VtAssociation.
    pub fn from_association(assoc: &VtAssociation) -> Self {
        Self {
            key: assoc.id as i64,
            association_type: match assoc.association_type() {
                VtAssociationType::Function => 0,
                VtAssociationType::Data => 1,
            },
            source_address: assoc.source_address().offset(),
            destination_address: assoc.destination_address().offset(),
            status: match assoc.status() {
                VtAssociationStatus::Available => 0,
                VtAssociationStatus::Accepted => 1,
                VtAssociationStatus::Blocked => 2,
                VtAssociationStatus::Rejected => 3,
            },
            vote_count: assoc.vote_count(),
        }
    }

    /// Convert to VtAssociation.
    pub fn to_association(&self) -> VtAssociation {
        let mut assoc = VtAssociation::new(
            self.key as u64,
            if self.association_type == 0 {
                VtAssociationType::Function
            } else {
                VtAssociationType::Data
            },
            Address::new(self.source_address),
            Address::new(self.destination_address),
        );
        // Apply status
        match self.status {
            1 => { let _ = assoc.set_accepted(); }
            2 => { assoc.set_blocked(); }
            3 => { let _ = assoc.set_rejected(); }
            _ => {}
        }
        assoc.set_vote_count(self.vote_count);
        assoc
    }

    /// Returns the association type.
    pub fn association_type_enum(&self) -> VtAssociationType {
        if self.association_type == 0 {
            VtAssociationType::Function
        } else {
            VtAssociationType::Data
        }
    }

    /// Returns the status.
    pub fn status_enum(&self) -> VtAssociationStatus {
        match self.status {
            1 => VtAssociationStatus::Accepted,
            2 => VtAssociationStatus::Blocked,
            3 => VtAssociationStatus::Rejected,
            _ => VtAssociationStatus::Available,
        }
    }

    /// Set status from enum.
    pub fn set_status(&mut self, status: VtAssociationStatus) {
        self.status = match status {
            VtAssociationStatus::Available => 0,
            VtAssociationStatus::Accepted => 1,
            VtAssociationStatus::Blocked => 2,
            VtAssociationStatus::Rejected => 3,
        };
    }
}

impl std::fmt::Display for VtAssociationDB {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AssociationDB(key={}, type={}, src=0x{:x}, dst=0x{:x}, status={})",
            self.key, self.association_type, self.source_address,
            self.destination_address, self.status
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_association_db_create() {
        let db = VtAssociationDB::new(1, 0, 0x1000, 0x2000);
        assert_eq!(db.key, 1);
        assert_eq!(db.source_address, 0x1000);
        assert_eq!(db.destination_address, 0x2000);
        assert_eq!(db.status_enum(), VtAssociationStatus::Available);
    }

    #[test]
    fn test_association_db_from_vt() {
        let assoc = VtAssociation::new(5, VtAssociationType::Function, Address::new(0x1000), Address::new(0x2000));
        let db = VtAssociationDB::from_association(&assoc);
        assert_eq!(db.key, 5);
        assert_eq!(db.association_type, 0);
        assert_eq!(db.status, 0);
    }

    #[test]
    fn test_association_db_roundtrip() {
        let mut assoc = VtAssociation::new(5, VtAssociationType::Data, Address::new(0x1000), Address::new(0x2000));
        assoc.set_accepted().unwrap();
        assoc.set_vote_count(3);
        let db = VtAssociationDB::from_association(&assoc);
        let restored = db.to_association();
        assert_eq!(restored.status(), VtAssociationStatus::Accepted);
        assert_eq!(restored.vote_count(), 3);
    }

    #[test]
    fn test_association_db_status_conversion() {
        let mut db = VtAssociationDB::new(1, 0, 0x1000, 0x2000);
        db.set_status(VtAssociationStatus::Blocked);
        assert_eq!(db.status, 2);
        assert_eq!(db.status_enum(), VtAssociationStatus::Blocked);
    }
}
