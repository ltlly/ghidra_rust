//! Database-backed instruction and data adapters for the trace listing.
//!
//! Ported from Ghidra's `ghidra.trace.database.listing` package. Provides
//! the database-layer types that manage instructions and data entries in
//! the trace listing, including:
//! - `DbTraceInstruction`: a stored instruction.
//! - `DbTraceData`: a stored data unit.
//! - `DbTraceCodeUnit`: a unified code unit.
//! - `DbTraceCodeSpace`: manages code units for a single address space.
//! - `DbTraceCodeManager`: top-level manager for all code spaces.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A database-backed instruction in the trace listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceInstruction {
    /// Database row key.
    pub key: i64,
    /// The address in the space.
    pub address: u64,
    /// The address space name.
    pub space: String,
    /// The lifespan (snap range).
    pub lifespan: Lifespan,
    /// The length in bytes.
    pub length: u32,
    /// The mnemonic string.
    pub mnemonic: String,
    /// The raw bytes.
    pub bytes: Vec<u8>,
    /// The prototype (encoding) identifier.
    pub prototype_id: u32,
    /// Thread key for register-space instructions.
    pub thread_key: Option<i64>,
    /// Frame level for register-space instructions.
    pub frame_level: Option<i32>,
}

impl DbTraceInstruction {
    /// Create a new instruction.
    pub fn new(
        key: i64,
        address: u64,
        space: impl Into<String>,
        lifespan: Lifespan,
        length: u32,
        mnemonic: impl Into<String>,
        bytes: Vec<u8>,
        prototype_id: u32,
    ) -> Self {
        Self {
            key,
            address,
            space: space.into(),
            lifespan,
            length,
            mnemonic: mnemonic.into(),
            bytes,
            prototype_id,
            thread_key: None,
            frame_level: None,
        }
    }

    /// Set the thread and frame for register-space instructions.
    pub fn with_register_context(mut self, thread_key: i64, frame_level: i32) -> Self {
        self.thread_key = Some(thread_key);
        self.frame_level = Some(frame_level);
        self
    }

    /// The maximum address (inclusive).
    pub fn max_address(&self) -> u64 {
        self.address + self.length as u64 - 1
    }

    /// Whether this instruction contains the given address.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.address && address <= self.max_address()
    }
}

/// A database-backed data entry in the trace listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceData {
    /// Database row key.
    pub key: i64,
    /// The address in the space.
    pub address: u64,
    /// The address space name.
    pub space: String,
    /// The lifespan (snap range).
    pub lifespan: Lifespan,
    /// The length in bytes.
    pub length: u32,
    /// The data type name.
    pub data_type: String,
    /// The raw bytes.
    pub bytes: Vec<u8>,
    /// Whether this is defined (vs. undefined) data.
    pub defined: bool,
    /// Thread key for register-space data.
    pub thread_key: Option<i64>,
    /// Frame level for register-space data.
    pub frame_level: Option<i32>,
    /// Comment text.
    pub comment: Option<String>,
}

impl DbTraceData {
    /// Create a new data entry.
    pub fn new(
        key: i64,
        address: u64,
        space: impl Into<String>,
        lifespan: Lifespan,
        length: u32,
        data_type: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            key,
            address,
            space: space.into(),
            lifespan,
            length,
            data_type: data_type.into(),
            bytes,
            defined: true,
            thread_key: None,
            frame_level: None,
            comment: None,
        }
    }

    /// Create an undefined data entry.
    pub fn undefined(
        key: i64,
        address: u64,
        space: impl Into<String>,
        lifespan: Lifespan,
        length: u32,
    ) -> Self {
        Self {
            key,
            address,
            space: space.into(),
            lifespan,
            length,
            data_type: "undefined".into(),
            bytes: Vec::new(),
            defined: false,
            thread_key: None,
            frame_level: None,
            comment: None,
        }
    }

    /// The maximum address (inclusive).
    pub fn max_address(&self) -> u64 {
        self.address + self.length as u64 - 1
    }

    /// Whether this data entry contains the given address.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.address && address <= self.max_address()
    }

    /// Set a comment.
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }
}

/// A unified code unit that is either an instruction or data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DbTraceCodeUnit {
    /// An instruction.
    Instruction(DbTraceInstruction),
    /// Defined data.
    Data(DbTraceData),
}

impl DbTraceCodeUnit {
    /// The database row key.
    pub fn key(&self) -> i64 {
        match self {
            Self::Instruction(i) => i.key,
            Self::Data(d) => d.key,
        }
    }

    /// The address.
    pub fn address(&self) -> u64 {
        match self {
            Self::Instruction(i) => i.address,
            Self::Data(d) => d.address,
        }
    }

    /// The space name.
    pub fn space(&self) -> &str {
        match self {
            Self::Instruction(i) => &i.space,
            Self::Data(d) => &d.space,
        }
    }

    /// The lifespan.
    pub fn lifespan(&self) -> &Lifespan {
        match self {
            Self::Instruction(i) => &i.lifespan,
            Self::Data(d) => &d.lifespan,
        }
    }

    /// The length in bytes.
    pub fn length(&self) -> u32 {
        match self {
            Self::Instruction(i) => i.length,
            Self::Data(d) => d.length,
        }
    }

    /// Whether this is an instruction.
    pub fn is_instruction(&self) -> bool {
        matches!(self, Self::Instruction(_))
    }

    /// Whether this is data.
    pub fn is_data(&self) -> bool {
        matches!(self, Self::Data(_))
    }

    /// The raw bytes.
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Instruction(i) => &i.bytes,
            Self::Data(d) => &d.bytes,
        }
    }

    /// Whether this code unit contains the given address.
    pub fn contains(&self, address: u64) -> bool {
        match self {
            Self::Instruction(i) => i.contains(address),
            Self::Data(d) => d.contains(address),
        }
    }

    /// A display string (mnemonic for instructions, type name for data).
    pub fn display(&self) -> &str {
        match self {
            Self::Instruction(i) => &i.mnemonic,
            Self::Data(d) => &d.data_type,
        }
    }
}

/// Manages code units for a single address space in the trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DbTraceCodeSpace {
    /// The space name.
    pub space: String,
    /// Instructions indexed by (address, key).
    pub instructions: Vec<DbTraceInstruction>,
    /// Data entries indexed by (address, key).
    pub data: Vec<DbTraceData>,
}

impl DbTraceCodeSpace {
    /// Create a new code space.
    pub fn new(space: impl Into<String>) -> Self {
        Self {
            space: space.into(),
            instructions: Vec::new(),
            data: Vec::new(),
        }
    }

    /// Add an instruction.
    pub fn add_instruction(&mut self, inst: DbTraceInstruction) {
        self.instructions.push(inst);
    }

    /// Add a data entry.
    pub fn add_data(&mut self, data: DbTraceData) {
        self.data.push(data);
    }

    /// Get the instruction at the given address at the given snap.
    pub fn get_instruction_at(&self, address: u64, snap: i64) -> Option<&DbTraceInstruction> {
        self.instructions
            .iter()
            .find(|i| i.address == address && i.lifespan.contains(snap))
    }

    /// Get the code unit containing the given address at the given snap.
    pub fn get_containing(&self, address: u64, snap: i64) -> Option<DbTraceCodeUnit> {
        // Check instructions first
        for inst in &self.instructions {
            if inst.contains(address) && inst.lifespan.contains(snap) {
                return Some(DbTraceCodeUnit::Instruction(inst.clone()));
            }
        }
        // Then data
        for d in &self.data {
            if d.contains(address) && d.lifespan.contains(snap) {
                return Some(DbTraceCodeUnit::Data(d.clone()));
            }
        }
        None
    }

    /// Get all instructions in a range.
    pub fn instructions_in_range(
        &self,
        min_addr: u64,
        max_addr: u64,
        snap: i64,
    ) -> Vec<&DbTraceInstruction> {
        self.instructions
            .iter()
            .filter(|i| {
                i.address >= min_addr && i.address <= max_addr && i.lifespan.contains(snap)
            })
            .collect()
    }

    /// Get all code units at a given snap.
    pub fn units_at_snap(&self, snap: i64) -> Vec<DbTraceCodeUnit> {
        let mut units = Vec::new();
        for inst in &self.instructions {
            if inst.lifespan.contains(snap) {
                units.push(DbTraceCodeUnit::Instruction(inst.clone()));
            }
        }
        for d in &self.data {
            if d.lifespan.contains(snap) {
                units.push(DbTraceCodeUnit::Data(d.clone()));
            }
        }
        units
    }

    /// The number of instructions.
    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    /// The number of data entries.
    pub fn data_count(&self) -> usize {
        self.data.len()
    }

    /// The total number of code units.
    pub fn total_count(&self) -> usize {
        self.instructions.len() + self.data.len()
    }
}

/// Top-level manager for all code spaces in the trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DbTraceCodeManager {
    /// The code spaces, keyed by space name.
    pub spaces: Vec<DbTraceCodeSpace>,
}

impl DbTraceCodeManager {
    /// Create a new code manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create a code space.
    pub fn get_or_create_space(&mut self, space_name: &str) -> &mut DbTraceCodeSpace {
        if let Some(pos) = self.spaces.iter().position(|s| s.space == space_name) {
            return &mut self.spaces[pos];
        }
        self.spaces.push(DbTraceCodeSpace::new(space_name));
        self.spaces.last_mut().unwrap()
    }

    /// Get a code space by name.
    pub fn get_space(&self, space_name: &str) -> Option<&DbTraceCodeSpace> {
        self.spaces.iter().find(|s| s.space == space_name)
    }

    /// Get the instruction at the given location.
    pub fn get_instruction_at(
        &self,
        space_name: &str,
        address: u64,
        snap: i64,
    ) -> Option<&DbTraceInstruction> {
        self.get_space(space_name)
            .and_then(|s| s.get_instruction_at(address, snap))
    }

    /// The total number of code units across all spaces.
    pub fn total_count(&self) -> usize {
        self.spaces.iter().map(|s| s.total_count()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_instruction() {
        let inst = DbTraceInstruction::new(
            1,
            0x400000,
            "ram",
            Lifespan::at(0),
            3,
            "NOP",
            vec![0x90, 0x90, 0x90],
            1,
        );
        assert!(inst.contains(0x400001));
        assert!(!inst.contains(0x400003));
        assert_eq!(inst.max_address(), 0x400002);
    }

    #[test]
    fn test_db_data() {
        let data = DbTraceData::new(
            2,
            0x500000,
            "ram",
            Lifespan::at(0),
            4,
            "DWORD",
            vec![0x01, 0x00, 0x00, 0x00],
        );
        assert!(data.contains(0x500002));
        assert!(!data.contains(0x500004));
        assert!(data.defined);
    }

    #[test]
    fn test_db_data_undefined() {
        let data = DbTraceData::undefined(3, 0x600000, "ram", Lifespan::at(0), 16);
        assert!(!data.defined);
        assert!(data.bytes.is_empty());
    }

    #[test]
    fn test_code_unit() {
        let inst = DbTraceCodeUnit::Instruction(DbTraceInstruction::new(
            1,
            0x400000,
            "ram",
            Lifespan::at(0),
            3,
            "NOP",
            vec![0x90; 3],
            1,
        ));
        assert!(inst.is_instruction());
        assert!(!inst.is_data());
        assert_eq!(inst.display(), "NOP");
    }

    #[test]
    fn test_code_space() {
        let mut space = DbTraceCodeSpace::new("ram");
        space.add_instruction(DbTraceInstruction::new(
            1,
            0x400000,
            "ram",
            Lifespan::at(0),
            3,
            "NOP",
            vec![0x90; 3],
            1,
        ));
        space.add_data(DbTraceData::new(
            2,
            0x500000,
            "ram",
            Lifespan::at(0),
            4,
            "DWORD",
            vec![0; 4],
        ));

        assert_eq!(space.instruction_count(), 1);
        assert_eq!(space.data_count(), 1);
        assert_eq!(space.total_count(), 2);

        let inst = space.get_instruction_at(0x400000, 0);
        assert!(inst.is_some());

        let containing = space.get_containing(0x400001, 0);
        assert!(containing.is_some());
        assert!(containing.unwrap().is_instruction());
    }

    #[test]
    fn test_code_manager() {
        let mut mgr = DbTraceCodeManager::new();
        mgr.get_or_create_space("ram").add_instruction(
            DbTraceInstruction::new(1, 0x400000, "ram", Lifespan::at(0), 3, "NOP", vec![0x90; 3], 1),
        );
        mgr.get_or_create_space("ram").add_data(
            DbTraceData::new(2, 0x500000, "ram", Lifespan::at(0), 4, "DWORD", vec![0; 4]),
        );

        assert_eq!(mgr.total_count(), 2);

        let inst = mgr.get_instruction_at("ram", 0x400000, 0);
        assert!(inst.is_some());
        assert_eq!(inst.unwrap().mnemonic, "NOP");

        assert!(mgr.get_instruction_at("register", 0, 0).is_none());
    }

    #[test]
    fn test_code_space_range_query() {
        let mut space = DbTraceCodeSpace::new("ram");
        for i in 0i64..10 {
            space.add_instruction(DbTraceInstruction::new(
                i,
                0x400000u64 + (i as u64) * 4,
                "ram",
                Lifespan::at(0),
                4,
                "NOP",
                vec![0x90; 4],
                1,
            ));
        }

        let in_range = space.instructions_in_range(0x400000, 0x40000F, 0);
        assert_eq!(in_range.len(), 4); // 0, 4, 8, 12 (0xC)
    }

    #[test]
    fn test_serde() {
        let inst = DbTraceInstruction::new(
            1,
            0x400000,
            "ram",
            Lifespan::at(0),
            3,
            "NOP",
            vec![0x90; 3],
            1,
        );
        let json = serde_json::to_string(&inst).unwrap();
        let back: DbTraceInstruction = serde_json::from_str(&json).unwrap();
        assert_eq!(back.mnemonic, "NOP");
    }
}
