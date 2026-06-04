//! Database-backed address correlator storage.

use ghidra_core::addr::Address;

use crate::versiontracking::correlator::address::AddressCorrelation;

/// Database-backed address correlator.
///
/// Stores the result of an address correlation between two functions
/// for persistence and reuse.
#[derive(Debug, Clone)]
pub struct AddressCorrelatorDB {
    /// Database key
    pub key: i64,
    /// Fully-qualified class name of the correlator
    pub correlator_class_name: String,
    /// Source function entry point
    pub source_entry: u64,
    /// Destination function entry point
    pub destination_entry: u64,
    /// Serialized mapping pairs (src_addr, dst_addr)
    pub mappings: Vec<(u64, u64)>,
    /// Correlation confidence
    pub confidence: f64,
}

impl AddressCorrelatorDB {
    /// Create a new address correlator DB record.
    pub fn new(
        key: i64,
        correlator_class_name: impl Into<String>,
        source_entry: u64,
        destination_entry: u64,
    ) -> Self {
        Self {
            key,
            correlator_class_name: correlator_class_name.into(),
            source_entry,
            destination_entry,
            mappings: Vec::new(),
            confidence: 0.0,
        }
    }

    /// Create from an AddressCorrelation.
    pub fn from_correlation(
        key: i64,
        correlator_class_name: impl Into<String>,
        correlation: &AddressCorrelation,
    ) -> Self {
        Self {
            key,
            correlator_class_name: correlator_class_name.into(),
            source_entry: correlation.source_entry.get_offset(),
            destination_entry: correlation.destination_entry.get_offset(),
            mappings: correlation
                .mappings
                .iter()
                .map(|m| (m.source.get_offset(), m.destination.get_offset()))
                .collect(),
            confidence: correlation.confidence,
        }
    }

    /// Convert to an AddressCorrelation.
    pub fn to_correlation(&self) -> AddressCorrelation {
        use crate::versiontracking::correlator::address::AddressMapping;
        AddressCorrelation {
            source_entry: Address::new(self.source_entry),
            destination_entry: Address::new(self.destination_entry),
            mappings: self
                .mappings
                .iter()
                .map(|(s, d)| AddressMapping {
                    source: Address::new(*s),
                    destination: Address::new(*d),
                })
                .collect(),
            confidence: self.confidence,
        }
    }

    /// Serialize mappings to a string for database storage.
    pub fn serialize_mappings(&self) -> String {
        self.mappings
            .iter()
            .map(|(s, d)| format!("0x{:x}:0x{:x}", s, d))
            .collect::<Vec<_>>()
            .join(";")
    }

    /// Deserialize mappings from a string.
    pub fn deserialize_mappings(s: &str) -> Vec<(u64, u64)> {
        if s.is_empty() {
            return Vec::new();
        }
        s.split(';')
            .filter_map(|pair| {
                let parts: Vec<&str> = pair.split(':').collect();
                if parts.len() == 2 {
                    let src = u64::from_str_radix(parts[0].strip_prefix("0x").unwrap_or(parts[0]), 16).ok()?;
                    let dst = u64::from_str_radix(parts[1].strip_prefix("0x").unwrap_or(parts[1]), 16).ok()?;
                    Some((src, dst))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Number of address mappings.
    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
    }
}

impl std::fmt::Display for AddressCorrelatorDB {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AddressCorrelatorDB(key={}, class={}, src=0x{:x}, dst=0x{:x}, mappings={}, conf={:.3})",
            self.key, self.correlator_class_name, self.source_entry,
            self.destination_entry, self.mappings.len(), self.confidence
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::versiontracking::correlator::address::AddressMapping;

    #[test]
    fn test_address_correlator_db_create() {
        let db = AddressCorrelatorDB::new(1, "ExactMatchAddressCorrelator", 0x1000, 0x2000);
        assert_eq!(db.key, 1);
        assert_eq!(db.correlator_class_name, "ExactMatchAddressCorrelator");
        assert_eq!(db.source_entry, 0x1000);
        assert_eq!(db.destination_entry, 0x2000);
    }

    #[test]
    fn test_address_correlator_db_from_correlation() {
        let corr = AddressCorrelation {
            source_entry: Address::new(0x1000),
            destination_entry: Address::new(0x2000),
            mappings: vec![
                AddressMapping { source: Address::new(0x1000), destination: Address::new(0x2000) },
                AddressMapping { source: Address::new(0x1001), destination: Address::new(0x2001) },
            ],
            confidence: 0.95,
        };
        let db = AddressCorrelatorDB::from_correlation(1, "TestCorrelator", &corr);
        assert_eq!(db.mapping_count(), 2);
        assert!((db.confidence - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn test_address_correlator_db_roundtrip() {
        let corr = AddressCorrelation {
            source_entry: Address::new(0x1000),
            destination_entry: Address::new(0x2000),
            mappings: vec![
                AddressMapping { source: Address::new(0x1000), destination: Address::new(0x2000) },
                AddressMapping { source: Address::new(0x1004), destination: Address::new(0x2008) },
            ],
            confidence: 0.85,
        };
        let db = AddressCorrelatorDB::from_correlation(1, "Test", &corr);
        let restored = db.to_correlation();
        assert_eq!(restored.mappings.len(), 2);
        assert_eq!(restored.source_entry.get_offset(), 0x1000);
        assert!((restored.confidence - 0.85).abs() < f64::EPSILON);
    }

    #[test]
    fn test_mapping_serialization() {
        let db = AddressCorrelatorDB {
            key: 1,
            correlator_class_name: "Test".to_string(),
            source_entry: 0x1000,
            destination_entry: 0x2000,
            mappings: vec![(0x1000, 0x2000), (0x1004, 0x2008)],
            confidence: 0.9,
        };
        let serialized = db.serialize_mappings();
        let deserialized = AddressCorrelatorDB::deserialize_mappings(&serialized);
        assert_eq!(deserialized, db.mappings);
    }

    #[test]
    fn test_empty_mappings_serialization() {
        let mappings = AddressCorrelatorDB::deserialize_mappings("");
        assert!(mappings.is_empty());
    }

    #[test]
    fn test_address_correlator_db_display() {
        let db = AddressCorrelatorDB::new(1, "Test", 0x1000, 0x2000);
        let display = format!("{}", db);
        assert!(display.contains("AddressCorrelatorDB"));
    }
}
