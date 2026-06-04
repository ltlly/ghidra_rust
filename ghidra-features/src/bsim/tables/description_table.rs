//! Description table for BSim function descriptions.
//!
//! Ports Ghidra's `ghidra.features.bsim.query.client.tables.DescriptionTable`.
//! Stores function descriptions including name, address, signature text,
//! and basic statistics (instruction count, basic-block count, call count).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ============================================================================
// FunctionRecord
// ============================================================================

/// A record in the function description table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionRecord {
    /// Database function-id (primary key).
    pub function_id: i64,
    /// The executable hash-id this function belongs to.
    pub exe_hash_id: i64,
    /// Function address.
    pub address: u64,
    /// Function name.
    pub name: String,
    /// Function signature text.
    pub signature_text: String,
    /// Approximate number of machine instructions.
    pub num_instructions: u32,
    /// Approximate number of basic blocks.
    pub num_basic_blocks: u32,
    /// Number of call sites.
    pub num_calls: u32,
    /// MD5 hash of the function body (for identity).
    pub md5_hash: Option<[u8; 16]>,
}

impl FunctionRecord {
    /// Create a new function record.
    pub fn new(
        function_id: i64,
        exe_hash_id: i64,
        address: u64,
        name: impl Into<String>,
        signature_text: impl Into<String>,
    ) -> Self {
        Self {
            function_id,
            exe_hash_id,
            address,
            name: name.into(),
            signature_text: signature_text.into(),
            num_instructions: 0,
            num_basic_blocks: 0,
            num_calls: 0,
            md5_hash: None,
        }
    }

    /// Set instruction count.
    pub fn with_instructions(mut self, count: u32) -> Self {
        self.num_instructions = count;
        self
    }

    /// Set basic block count.
    pub fn with_basic_blocks(mut self, count: u32) -> Self {
        self.num_basic_blocks = count;
        self
    }

    /// Set call count.
    pub fn with_calls(mut self, count: u32) -> Self {
        self.num_calls = count;
        self
    }

    /// Set MD5 hash.
    pub fn with_md5(mut self, hash: [u8; 16]) -> Self {
        self.md5_hash = Some(hash);
        self
    }
}

// ============================================================================
// DescriptionTable
// ============================================================================

/// In-memory table of function descriptions.
///
/// Ported from `ghidra.features.bsim.query.client.tables.DescriptionTable`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DescriptionTable {
    /// Records indexed by function-id.
    by_id: HashMap<i64, FunctionRecord>,
    /// Index: exe_hash_id -> list of function-ids.
    by_exe: HashMap<i64, Vec<i64>>,
    /// Index: function name -> list of function-ids.
    by_name: HashMap<String, Vec<i64>>,
    /// Next function-id to assign.
    next_id: i64,
}

impl DescriptionTable {
    /// Create an empty description table.
    pub fn new() -> Self {
        Self {
            by_id: HashMap::new(),
            by_exe: HashMap::new(),
            by_name: HashMap::new(),
            next_id: 1,
        }
    }

    /// Insert a function record.  Returns the assigned function-id.
    ///
    /// If `record.function_id` is 0, the table auto-assigns an id.
    pub fn insert(&mut self, mut record: FunctionRecord) -> i64 {
        let id = if record.function_id == 0 {
            let id = self.next_id;
            self.next_id += 1;
            record.function_id = id;
            id
        } else {
            if record.function_id >= self.next_id {
                self.next_id = record.function_id + 1;
            }
            record.function_id
        };

        self.by_exe
            .entry(record.exe_hash_id)
            .or_default()
            .push(id);
        self.by_name
            .entry(record.name.clone())
            .or_default()
            .push(id);
        self.by_id.insert(id, record);
        id
    }

    /// Get a record by function-id.
    pub fn get(&self, function_id: i64) -> Option<&FunctionRecord> {
        self.by_id.get(&function_id)
    }

    /// Get all records for an executable.
    pub fn get_by_exe(&self, exe_hash_id: i64) -> Vec<&FunctionRecord> {
        self.by_exe
            .get(&exe_hash_id)
            .map(|ids| ids.iter().filter_map(|id| self.by_id.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get all records by function name.
    pub fn get_by_name(&self, name: &str) -> Vec<&FunctionRecord> {
        self.by_name
            .get(name)
            .map(|ids| ids.iter().filter_map(|id| self.by_id.get(id)).collect())
            .unwrap_or_default()
    }

    /// Remove a record by function-id.
    pub fn remove(&mut self, function_id: i64) -> bool {
        if let Some(record) = self.by_id.remove(&function_id) {
            if let Some(ids) = self.by_exe.get_mut(&record.exe_hash_id) {
                ids.retain(|id| *id != function_id);
            }
            if let Some(ids) = self.by_name.get_mut(&record.name) {
                ids.retain(|id| *id != function_id);
            }
            true
        } else {
            false
        }
    }

    /// Total number of records.
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Number of distinct executables.
    pub fn exe_count(&self) -> usize {
        self.by_exe.len()
    }

    /// Iterate over all records.
    pub fn iter(&self) -> impl Iterator<Item = &FunctionRecord> {
        self.by_id.values()
    }

    /// Remove all records for an executable.
    pub fn remove_by_exe(&mut self, exe_hash_id: i64) {
        if let Some(ids) = self.by_exe.remove(&exe_hash_id) {
            for id in ids {
                if let Some(record) = self.by_id.remove(&id) {
                    if let Some(name_ids) = self.by_name.get_mut(&record.name) {
                        name_ids.retain(|i| *i != id);
                    }
                }
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(id: i64, exe_id: i64, name: &str) -> FunctionRecord {
        FunctionRecord::new(id, exe_id, 0x1000, name, "void f() {}")
            .with_instructions(10)
            .with_basic_blocks(3)
            .with_calls(2)
    }

    #[test]
    fn description_table_insert_and_get() {
        let mut table = DescriptionTable::new();
        let id = table.insert(sample_record(0, 100, "main"));
        let record = table.get(id).unwrap();
        assert_eq!(record.name, "main");
        assert_eq!(record.exe_hash_id, 100);
    }

    #[test]
    fn description_table_auto_id() {
        let mut table = DescriptionTable::new();
        let id1 = table.insert(sample_record(0, 100, "a"));
        let id2 = table.insert(sample_record(0, 100, "b"));
        assert_ne!(id1, id2);
    }

    #[test]
    fn description_table_get_by_exe() {
        let mut table = DescriptionTable::new();
        table.insert(sample_record(0, 100, "a"));
        table.insert(sample_record(0, 100, "b"));
        table.insert(sample_record(0, 200, "c"));
        assert_eq!(table.get_by_exe(100).len(), 2);
        assert_eq!(table.get_by_exe(200).len(), 1);
    }

    #[test]
    fn description_table_get_by_name() {
        let mut table = DescriptionTable::new();
        table.insert(sample_record(0, 100, "malloc"));
        table.insert(sample_record(0, 200, "malloc"));
        assert_eq!(table.get_by_name("malloc").len(), 2);
    }

    #[test]
    fn description_table_remove() {
        let mut table = DescriptionTable::new();
        let id = table.insert(sample_record(0, 100, "f"));
        assert_eq!(table.len(), 1);
        assert!(table.remove(id));
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn description_table_remove_by_exe() {
        let mut table = DescriptionTable::new();
        table.insert(sample_record(0, 100, "a"));
        table.insert(sample_record(0, 100, "b"));
        table.insert(sample_record(0, 200, "c"));
        table.remove_by_exe(100);
        assert_eq!(table.len(), 1);
    }
}
