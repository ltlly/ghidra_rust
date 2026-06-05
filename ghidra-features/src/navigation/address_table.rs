//! Address table navigation types.
//!
//! Ported from `ghidra.app.plugin.core.navigation` table-related classes.
//!
//! Provides models for navigating through address tables (jump tables,
//! switch tables) commonly found in compiled binaries.

/// Entry in an address table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressTableEntry {
    /// Index in the table.
    pub index: usize,
    /// The address value.
    pub address: u64,
    /// Whether the address is valid (points to code or data).
    pub is_valid: bool,
    /// The label at the target address, if known.
    pub label: Option<String>,
    /// The type of target (code, data, etc.).
    pub target_type: AddressTableTargetType,
}

/// The type of target an address table entry points to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressTableTargetType {
    /// Points to code (a function or instruction).
    Code,
    /// Points to data.
    Data,
    /// Points to an external symbol.
    External,
    /// The target is unknown.
    Unknown,
    /// The address is invalid or null.
    Invalid,
}

/// Model for an address table discovered in a program.
///
/// This could be a jump table from a switch statement, a vtable,
/// or any other table of addresses.
#[derive(Debug, Clone)]
pub struct AddressTable {
    /// The base address of the table.
    pub base_address: u64,
    /// The address space name.
    pub space: String,
    /// Table entries.
    entries: Vec<AddressTableEntry>,
    /// Entry size in bytes (typically 4 for 32-bit, 8 for 64-bit).
    pub entry_size: usize,
    /// Whether the table is read-only.
    pub read_only: bool,
}

impl AddressTable {
    /// Create a new address table.
    pub fn new(base_address: u64, space: impl Into<String>, entry_size: usize) -> Self {
        Self {
            base_address,
            space: space.into(),
            entries: Vec::new(),
            entry_size,
            read_only: true,
        }
    }

    /// Add an entry to the table.
    pub fn add_entry(&mut self, entry: AddressTableEntry) {
        self.entries.push(entry);
    }

    /// Get all entries.
    pub fn entries(&self) -> &[AddressTableEntry] {
        &self.entries
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the byte size of the entire table.
    pub fn byte_size(&self) -> usize {
        self.entries.len() * self.entry_size
    }

    /// Get the end address (exclusive).
    pub fn end_address(&self) -> u64 {
        self.base_address + self.byte_size() as u64
    }

    /// Get entries pointing to code targets.
    pub fn code_entries(&self) -> Vec<&AddressTableEntry> {
        self.entries
            .iter()
            .filter(|e| e.target_type == AddressTableTargetType::Code)
            .collect()
    }

    /// Get entries pointing to external symbols.
    pub fn external_entries(&self) -> Vec<&AddressTableEntry> {
        self.entries
            .iter()
            .filter(|e| e.target_type == AddressTableTargetType::External)
            .collect()
    }

    /// Get invalid entries.
    pub fn invalid_entries(&self) -> Vec<&AddressTableEntry> {
        self.entries
            .iter()
            .filter(|e| e.target_type == AddressTableTargetType::Invalid)
            .collect()
    }

    /// Calculate the validity ratio (fraction of valid entries).
    pub fn validity_ratio(&self) -> f64 {
        if self.entries.is_empty() {
            return 0.0;
        }
        let valid = self.entries.iter().filter(|e| e.is_valid).count();
        valid as f64 / self.entries.len() as f64
    }

    /// Lookup an entry by index.
    pub fn get(&self, index: usize) -> Option<&AddressTableEntry> {
        self.entries.get(index)
    }

    /// Lookup an entry by target address.
    pub fn find_by_address(&self, addr: u64) -> Option<&AddressTableEntry> {
        self.entries.iter().find(|e| e.address == addr)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_table_entry() {
        let entry = AddressTableEntry {
            index: 0,
            address: 0x401000,
            is_valid: true,
            label: Some("main".to_string()),
            target_type: AddressTableTargetType::Code,
        };
        assert_eq!(entry.address, 0x401000);
        assert!(entry.is_valid);
    }

    #[test]
    fn test_address_table_lifecycle() {
        let mut table = AddressTable::new(0x1000, "ram", 8);
        assert!(table.is_empty());
        assert_eq!(table.byte_size(), 0);

        table.add_entry(AddressTableEntry {
            index: 0,
            address: 0x401000,
            is_valid: true,
            label: None,
            target_type: AddressTableTargetType::Code,
        });
        table.add_entry(AddressTableEntry {
            index: 1,
            address: 0x401100,
            is_valid: true,
            label: None,
            target_type: AddressTableTargetType::Code,
        });
        table.add_entry(AddressTableEntry {
            index: 2,
            address: 0,
            is_valid: false,
            label: None,
            target_type: AddressTableTargetType::Invalid,
        });

        assert_eq!(table.len(), 3);
        assert_eq!(table.byte_size(), 24);
        assert_eq!(table.end_address(), 0x1018);
    }

    #[test]
    fn test_address_table_filtering() {
        let mut table = AddressTable::new(0x1000, "ram", 4);
        table.add_entry(AddressTableEntry {
            index: 0,
            address: 0x401000,
            is_valid: true,
            label: None,
            target_type: AddressTableTargetType::Code,
        });
        table.add_entry(AddressTableEntry {
            index: 1,
            address: 0x402000,
            is_valid: true,
            label: None,
            target_type: AddressTableTargetType::External,
        });
        table.add_entry(AddressTableEntry {
            index: 2,
            address: 0,
            is_valid: false,
            label: None,
            target_type: AddressTableTargetType::Invalid,
        });

        assert_eq!(table.code_entries().len(), 1);
        assert_eq!(table.external_entries().len(), 1);
        assert_eq!(table.invalid_entries().len(), 1);
    }

    #[test]
    fn test_address_table_validity() {
        let mut table = AddressTable::new(0x1000, "ram", 4);
        table.add_entry(AddressTableEntry {
            index: 0,
            address: 0x401000,
            is_valid: true,
            label: None,
            target_type: AddressTableTargetType::Code,
        });
        table.add_entry(AddressTableEntry {
            index: 1,
            address: 0,
            is_valid: false,
            label: None,
            target_type: AddressTableTargetType::Invalid,
        });

        assert_eq!(table.validity_ratio(), 0.5);
    }

    #[test]
    fn test_address_table_lookup() {
        let mut table = AddressTable::new(0x1000, "ram", 4);
        table.add_entry(AddressTableEntry {
            index: 0,
            address: 0x401000,
            is_valid: true,
            label: None,
            target_type: AddressTableTargetType::Code,
        });

        assert!(table.get(0).is_some());
        assert!(table.get(1).is_none());
        assert!(table.find_by_address(0x401000).is_some());
        assert!(table.find_by_address(0x999).is_none());
    }

    #[test]
    fn test_address_table_empty_validity() {
        let table = AddressTable::new(0, "ram", 4);
        assert_eq!(table.validity_ratio(), 0.0);
    }
}
