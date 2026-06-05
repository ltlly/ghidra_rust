//! Miscellaneous Plugin Utilities.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.misc` Java package.
//!
//! Provides shared utility types used by multiple plugins.

/// Miscellaneous actions (memory map, program info, etc.).
///
/// Ported from `ghidra.app.plugin.core.misc` action classes.
pub mod actions;

/// The import type for binary files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportType {
    /// Auto-detect the file format.
    Auto,
    /// Raw binary.
    Raw,
    /// ELF binary.
    Elf,
    /// PE (Windows) binary.
    Pe,
    /// Mach-O binary.
    Macho,
    /// COFF object file.
    Coff,
    /// Intel HEX format.
    IntelHex,
    /// Motorola S-Record format.
    MotorolaSRecord,
    /// Java Class file.
    JavaClass,
    /// Dalvik DEX file.
    Dalvik,
    /// WebAssembly.
    Wasm,
}

impl ImportType {
    /// Get the display name of the import type.
    pub fn display_name(&self) -> &str {
        match self {
            Self::Auto => "Auto-detect",
            Self::Raw => "Raw Binary",
            Self::Elf => "ELF",
            Self::Pe => "PE",
            Self::Macho => "Mach-O",
            Self::Coff => "COFF",
            Self::IntelHex => "Intel HEX",
            Self::MotorolaSRecord => "Motorola S-Record",
            Self::JavaClass => "Java Class",
            Self::Dalvik => "Dalvik DEX",
            Self::Wasm => "WebAssembly",
        }
    }

    /// Whether this format is auto-detected.
    pub fn is_auto(&self) -> bool { matches!(self, Self::Auto) }

    /// File extension commonly associated with this format.
    pub fn file_extension(&self) -> Option<&str> {
        match self {
            Self::Elf => Some("elf"), Self::Pe => Some("exe"),
            Self::Macho => Some("macho"), Self::Coff => Some("o"),
            Self::IntelHex => Some("hex"), Self::MotorolaSRecord => Some("srec"),
            Self::JavaClass => Some("class"), Self::Dalvik => Some("dex"),
            Self::Wasm => Some("wasm"), _ => None,
        }
    }
}

impl std::fmt::Display for ImportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.display_name()) }
}

/// A display format option for addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressDisplayFormat {
    /// Hexadecimal (default).
    Hex,
    /// Decimal.
    Decimal,
    /// Octal.
    Octal,
    /// Binary.
    Binary,
}

impl AddressDisplayFormat {
    /// Format an address value according to this format.
    pub fn format(&self, value: u64) -> String {
        match self {
            Self::Hex => format!("0x{:X}", value),
            Self::Decimal => format!("{}", value),
            Self::Octal => format!("0o{:o}", value),
            Self::Binary => format!("0b{:b}", value),
        }
    }

    /// Format with a fixed width (zero-padded).
    pub fn format_padded(&self, value: u64, width: usize) -> String {
        match self {
            Self::Hex => format!("0x{:0width$X}", value, width = width),
            Self::Decimal => format!("{:0width$}", value, width = width),
            Self::Octal => format!("0o{:0width$o}", value, width = width),
            Self::Binary => format!("0b{:0width$b}", value, width = width),
        }
    }
}

impl Default for AddressDisplayFormat {
    fn default() -> Self { Self::Hex }
}

/// Byte order for multi-byte values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    /// Big-endian (most significant byte first).
    Big,
    /// Little-endian (least significant byte first).
    Little,
}

impl Endianness {
    /// Whether this is big-endian.
    pub fn is_big_endian(&self) -> bool { matches!(self, Self::Big) }
    /// Whether this is little-endian.
    pub fn is_little_endian(&self) -> bool { matches!(self, Self::Little) }
    /// Read a `u16` from a 2-byte slice.
    pub fn read_u16(&self, data: &[u8]) -> u16 {
        match self {
            Self::Big => u16::from_be_bytes([data[0], data[1]]),
            Self::Little => u16::from_le_bytes([data[0], data[1]]),
        }
    }
    /// Read a `u32` from a 4-byte slice.
    pub fn read_u32(&self, data: &[u8]) -> u32 {
        match self {
            Self::Big => u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            Self::Little => u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        }
    }
}

impl std::fmt::Display for Endianness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::Big => write!(f, "Big Endian"), Self::Little => write!(f, "Little Endian") }
    }
}

/// Formatting options for register values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterValueFormat {
    Hex, SignedDecimal, UnsignedDecimal, Octal, Binary,
}

impl RegisterValueFormat {
    /// Format a register value.
    pub fn format_value(&self, value: u64, size_bytes: usize) -> String {
        match self {
            Self::Hex => format!("0x{:0width$X}", value, width = size_bytes * 2),
            Self::SignedDecimal => {
                let signed = match size_bytes { 1 => value as i8 as i64, 2 => value as i16 as i64, 4 => value as i32 as i64, _ => value as i64 };
                format!("{}", signed)
            }
            Self::UnsignedDecimal => format!("{}", value),
            Self::Octal => format!("0o{:o}", value),
            Self::Binary => format!("0b{:b}", value),
        }
    }
}

impl Default for RegisterValueFormat {
    fn default() -> Self { Self::Hex }
}

/// Standard plugin categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginCategory { Common, Analysis, Processor, Debugger, Script, Data, Search }

impl PluginCategory {
    /// Display name.
    pub fn display_name(&self) -> &str {
        match self { Self::Common => "Common", Self::Analysis => "Analysis", Self::Processor => "Processor", Self::Debugger => "Debugger", Self::Script => "Script", Self::Data => "Data", Self::Search => "Search" }
    }
}

impl std::fmt::Display for PluginCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.display_name()) }
}

/// Plugin status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginStatus { Released, Beta, Development, Deprecated, Hidden }

impl PluginStatus {
    /// Whether the plugin is usable.
    pub fn is_usable(&self) -> bool { !matches!(self, Self::Deprecated | Self::Hidden) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_type_display() {
        assert_eq!(ImportType::Elf.display_name(), "ELF");
        assert_eq!(ImportType::Pe.display_name(), "PE");
        assert_eq!(ImportType::JavaClass.display_name(), "Java Class");
        assert_eq!(ImportType::Wasm.display_name(), "WebAssembly");
    }

    #[test]
    fn test_import_type_properties() {
        assert!(ImportType::Auto.is_auto());
        assert!(!ImportType::Elf.is_auto());
        assert_eq!(ImportType::Elf.file_extension(), Some("elf"));
        assert_eq!(ImportType::Auto.file_extension(), None);
    }

    #[test]
    fn test_import_type_display_trait() { assert_eq!(ImportType::Elf.to_string(), "ELF"); }

    #[test]
    fn test_address_display_format() {
        assert_eq!(AddressDisplayFormat::Hex.format(255), "0xFF");
        assert_eq!(AddressDisplayFormat::Decimal.format(255), "255");
        assert_eq!(AddressDisplayFormat::Octal.format(255), "0o377");
        assert_eq!(AddressDisplayFormat::Binary.format(8), "0b1000");
    }

    #[test]
    fn test_address_display_format_padded() {
        assert_eq!(AddressDisplayFormat::Hex.format_padded(0xFF, 4), "0x00FF");
    }

    #[test]
    fn test_address_display_format_default() {
        assert_eq!(AddressDisplayFormat::default(), AddressDisplayFormat::Hex);
    }

    #[test]
    fn test_endianness() {
        assert!(Endianness::Big.is_big_endian());
        assert!(!Endianness::Big.is_little_endian());
    }

    #[test]
    fn test_endianness_read_u16() {
        let data = [0x01, 0x02];
        assert_eq!(Endianness::Big.read_u16(&data), 0x0102);
        assert_eq!(Endianness::Little.read_u16(&data), 0x0201);
    }

    #[test]
    fn test_endianness_read_u32() {
        let data = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(Endianness::Big.read_u32(&data), 0x01020304);
        assert_eq!(Endianness::Little.read_u32(&data), 0x04030201);
    }

    #[test]
    fn test_endianness_display() {
        assert_eq!(Endianness::Big.to_string(), "Big Endian");
    }

    #[test]
    fn test_register_value_format() {
        let fmt = RegisterValueFormat::Hex;
        assert_eq!(fmt.format_value(255, 1), "0xFF");
        let fmt = RegisterValueFormat::SignedDecimal;
        assert_eq!(fmt.format_value(0xFF, 1), "-1");
    }

    #[test]
    fn test_plugin_category() {
        assert_eq!(PluginCategory::Common.display_name(), "Common");
        assert_eq!(PluginCategory::Analysis.to_string(), "Analysis");
    }

    #[test]
    fn test_plugin_status() {
        assert!(PluginStatus::Released.is_usable());
        assert!(!PluginStatus::Deprecated.is_usable());
    }
}

// ---------------------------------------------------------------------------
// RecoverySnapshotMgr -- program change tracking and recovery snapshots
//
// Ported from Ghidra's `RecoverySnapshotMgrPlugin.java`.
// ---------------------------------------------------------------------------

/// A recovery snapshot of a program's state.
///
/// Ported from `ghidra.app.plugin.core.misc.RecoverySnapshotMgrPlugin`.
///
/// Tracks changes to a program for recovery purposes. When the program
/// is modified, a snapshot is created capturing the changes, enabling
/// the user to recover from unintended modifications.
#[derive(Debug, Clone)]
pub struct RecoverySnapshot {
    /// Unique identifier for this snapshot.
    pub id: u64,
    /// Timestamp (epoch seconds) when the snapshot was created.
    pub timestamp: u64,
    /// Description of what changed.
    pub description: String,
    /// Whether this snapshot has been applied (recovery performed).
    pub applied: bool,
    /// The size of the snapshot data in bytes.
    pub data_size: u64,
    /// Addresses that were modified.
    pub modified_addresses: Vec<(u64, u64)>,  // (start, end) ranges
}

impl RecoverySnapshot {
    /// Create a new recovery snapshot.
    pub fn new(id: u64, timestamp: u64, description: impl Into<String>) -> Self {
        Self {
            id,
            timestamp,
            description: description.into(),
            applied: false,
            data_size: 0,
            modified_addresses: Vec::new(),
        }
    }

    /// Mark this snapshot as applied.
    pub fn mark_applied(&mut self) {
        self.applied = true;
    }

    /// Whether this snapshot can be recovered from.
    pub fn is_recoverable(&self) -> bool {
        !self.applied && self.data_size > 0
    }
}

/// Manager for recovery snapshots.
#[derive(Debug)]
pub struct RecoverySnapshotManager {
    /// Stored snapshots.
    snapshots: Vec<RecoverySnapshot>,
    /// Next snapshot ID.
    next_id: u64,
    /// Maximum number of snapshots to keep.
    max_snapshots: usize,
    /// Directory for storing snapshot data.
    storage_dir: Option<String>,
    /// Whether the manager is enabled.
    enabled: bool,
}

impl RecoverySnapshotManager {
    /// Create a new recovery snapshot manager.
    pub fn new() -> Self {
        Self {
            snapshots: Vec::new(),
            next_id: 1,
            max_snapshots: 50,
            storage_dir: None,
            enabled: true,
        }
    }

    /// Create a recovery snapshot manager with a custom limit.
    pub fn with_max_snapshots(max: usize) -> Self {
        Self {
            max_snapshots: max,
            ..Self::new()
        }
    }

    /// Create a new snapshot.
    pub fn create_snapshot(
        &mut self,
        description: impl Into<String>,
        data_size: u64,
        modified_addresses: Vec<(u64, u64)>,
    ) -> u64 {
        if !self.enabled {
            return 0;
        }

        let id = self.next_id;
        self.next_id += 1;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut snapshot = RecoverySnapshot::new(id, timestamp, description);
        snapshot.data_size = data_size;
        snapshot.modified_addresses = modified_addresses;

        self.snapshots.push(snapshot);

        // Trim old snapshots
        while self.snapshots.len() > self.max_snapshots {
            self.snapshots.remove(0);
        }

        id
    }

    /// Get a snapshot by ID.
    pub fn get_snapshot(&self, id: u64) -> Option<&RecoverySnapshot> {
        self.snapshots.iter().find(|s| s.id == id)
    }

    /// Get all snapshots.
    pub fn all_snapshots(&self) -> &[RecoverySnapshot] {
        &self.snapshots
    }

    /// Get the most recent snapshot.
    pub fn latest_snapshot(&self) -> Option<&RecoverySnapshot> {
        self.snapshots.last()
    }

    /// Get all recoverable snapshots.
    pub fn recoverable_snapshots(&self) -> Vec<&RecoverySnapshot> {
        self.snapshots.iter().filter(|s| s.is_recoverable()).collect()
    }

    /// Remove a snapshot by ID.
    pub fn remove_snapshot(&mut self, id: u64) -> bool {
        if let Some(idx) = self.snapshots.iter().position(|s| s.id == id) {
            self.snapshots.remove(idx);
            true
        } else {
            false
        }
    }

    /// Clear all snapshots.
    pub fn clear(&mut self) {
        self.snapshots.clear();
    }

    /// Get the number of snapshots.
    pub fn count(&self) -> usize {
        self.snapshots.len()
    }

    /// Enable or disable the manager.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether the manager is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set the storage directory.
    pub fn set_storage_dir(&mut self, dir: impl Into<String>) {
        self.storage_dir = Some(dir.into());
    }

    /// Get the storage directory.
    pub fn storage_dir(&self) -> Option<&str> {
        self.storage_dir.as_deref()
    }
}

impl Default for RecoverySnapshotManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MyProgramChangesDisplay -- display program changes
//
// Ported from `ghidra.app.plugin.core.misc.MyProgramChangesDisplayPlugin.java`.
// ---------------------------------------------------------------------------

/// Represents a program change entry for display.
///
/// Ported from `ghidra.app.plugin.core.misc.MyProgramChangesDisplayPlugin`.
#[derive(Debug, Clone)]
pub struct ProgramChangeEntry {
    /// The address where the change occurred.
    pub address: u64,
    /// The original bytes.
    pub original_bytes: Vec<u8>,
    /// The new bytes.
    pub new_bytes: Vec<u8>,
    /// Description of the change.
    pub description: String,
    /// The type of change.
    pub change_type: ChangeType,
}

/// The type of program change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeType {
    /// A memory byte was modified.
    MemoryEdit,
    /// A function was created or modified.
    FunctionChange,
    /// A label/symbol was added or changed.
    SymbolChange,
    /// A comment was added or changed.
    CommentChange,
    /// A data type was applied or changed.
    DataTypeChange,
    /// A bookmark was added or removed.
    BookmarkChange,
    /// An equate was added or removed.
    EquateChange,
}

impl ChangeType {
    /// Display name for this change type.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::MemoryEdit => "Memory Edit",
            Self::FunctionChange => "Function Change",
            Self::SymbolChange => "Symbol Change",
            Self::CommentChange => "Comment Change",
            Self::DataTypeChange => "Data Type Change",
            Self::BookmarkChange => "Bookmark Change",
            Self::EquateChange => "Equate Change",
        }
    }
}

/// Display model for program changes.
#[derive(Debug, Default)]
pub struct ProgramChangesDisplay {
    /// The list of changes.
    changes: Vec<ProgramChangeEntry>,
}

impl ProgramChangesDisplay {
    /// Create a new display model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a change entry.
    pub fn add_change(&mut self, entry: ProgramChangeEntry) {
        self.changes.push(entry);
    }

    /// Get all changes.
    pub fn changes(&self) -> &[ProgramChangeEntry] {
        &self.changes
    }

    /// Get changes of a specific type.
    pub fn changes_of_type(&self, change_type: ChangeType) -> Vec<&ProgramChangeEntry> {
        self.changes
            .iter()
            .filter(|e| e.change_type == change_type)
            .collect()
    }

    /// Get the total number of changes.
    pub fn count(&self) -> usize {
        self.changes.len()
    }

    /// Clear all changes.
    pub fn clear(&mut self) {
        self.changes.clear();
    }

    /// Whether there are any changes.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Total number of modified bytes across all changes.
    pub fn total_modified_bytes(&self) -> usize {
        self.changes
            .iter()
            .map(|e| {
                let orig_len = e.original_bytes.len();
                let new_len = e.new_bytes.len();
                orig_len.max(new_len)
            })
            .sum()
    }
}

#[cfg(test)]
mod extended_misc_tests {
    use super::*;

    #[test]
    fn test_recovery_snapshot() {
        let snap = RecoverySnapshot::new(1, 1000, "test change");
        assert_eq!(snap.id, 1);
        assert!(!snap.applied);
        assert!(!snap.is_recoverable());
    }

    #[test]
    fn test_recovery_snapshot_recoverable() {
        let mut snap = RecoverySnapshot::new(1, 1000, "test");
        snap.data_size = 100;
        assert!(snap.is_recoverable());
        snap.mark_applied();
        assert!(!snap.is_recoverable());
    }

    #[test]
    fn test_recovery_snapshot_manager() {
        let mut mgr = RecoverySnapshotManager::new();
        assert!(mgr.is_enabled());
        assert_eq!(mgr.count(), 0);

        let id = mgr.create_snapshot("test", 100, vec![]);
        assert_eq!(mgr.count(), 1);
        assert_eq!(id, 1);

        let snap = mgr.get_snapshot(id).unwrap();
        assert_eq!(snap.description, "test");
        assert_eq!(snap.data_size, 100);
    }

    #[test]
    fn test_recovery_snapshot_manager_max() {
        let mut mgr = RecoverySnapshotManager::with_max_snapshots(3);
        mgr.create_snapshot("a", 10, vec![]);
        mgr.create_snapshot("b", 20, vec![]);
        mgr.create_snapshot("c", 30, vec![]);
        mgr.create_snapshot("d", 40, vec![]);
        assert_eq!(mgr.count(), 3);
        // "a" should have been removed
        assert!(mgr.get_snapshot(1).is_none());
        assert!(mgr.get_snapshot(4).is_some());
    }

    #[test]
    fn test_recovery_snapshot_manager_recoverable() {
        let mut mgr = RecoverySnapshotManager::new();
        mgr.create_snapshot("no data", 0, vec![]);
        mgr.create_snapshot("with data", 50, vec![(0x1000, 0x1010)]);
        assert_eq!(mgr.recoverable_snapshots().len(), 1);
    }

    #[test]
    fn test_recovery_snapshot_manager_remove() {
        let mut mgr = RecoverySnapshotManager::new();
        let id = mgr.create_snapshot("test", 10, vec![]);
        assert!(mgr.remove_snapshot(id));
        assert_eq!(mgr.count(), 0);
        assert!(!mgr.remove_snapshot(id));
    }

    #[test]
    fn test_recovery_snapshot_manager_clear() {
        let mut mgr = RecoverySnapshotManager::new();
        mgr.create_snapshot("a", 10, vec![]);
        mgr.create_snapshot("b", 20, vec![]);
        mgr.clear();
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn test_recovery_snapshot_manager_disabled() {
        let mut mgr = RecoverySnapshotManager::new();
        mgr.set_enabled(false);
        let id = mgr.create_snapshot("test", 10, vec![]);
        assert_eq!(id, 0);
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn test_recovery_snapshot_manager_latest() {
        let mut mgr = RecoverySnapshotManager::new();
        assert!(mgr.latest_snapshot().is_none());
        mgr.create_snapshot("first", 10, vec![]);
        mgr.create_snapshot("second", 20, vec![]);
        assert_eq!(mgr.latest_snapshot().unwrap().description, "second");
    }

    #[test]
    fn test_recovery_snapshot_manager_storage_dir() {
        let mut mgr = RecoverySnapshotManager::new();
        assert!(mgr.storage_dir().is_none());
        mgr.set_storage_dir("/tmp/recovery");
        assert_eq!(mgr.storage_dir(), Some("/tmp/recovery"));
    }

    #[test]
    fn test_program_change_entry() {
        let entry = ProgramChangeEntry {
            address: 0x1000,
            original_bytes: vec![0x90],
            new_bytes: vec![0xCC],
            description: "NOP -> INT3".to_string(),
            change_type: ChangeType::MemoryEdit,
        };
        assert_eq!(entry.change_type, ChangeType::MemoryEdit);
        assert_eq!(entry.change_type.display_name(), "Memory Edit");
    }

    #[test]
    fn test_program_changes_display() {
        let mut display = ProgramChangesDisplay::new();
        assert!(display.is_empty());

        display.add_change(ProgramChangeEntry {
            address: 0x1000,
            original_bytes: vec![0x90],
            new_bytes: vec![0xCC],
            description: "edit".into(),
            change_type: ChangeType::MemoryEdit,
        });
        display.add_change(ProgramChangeEntry {
            address: 0x2000,
            original_bytes: vec![],
            new_bytes: vec![],
            description: "label".into(),
            change_type: ChangeType::SymbolChange,
        });
        assert_eq!(display.count(), 2);
        assert_eq!(display.changes_of_type(ChangeType::MemoryEdit).len(), 1);
        assert_eq!(display.changes_of_type(ChangeType::SymbolChange).len(), 1);
        assert_eq!(display.changes_of_type(ChangeType::BookmarkChange).len(), 0);
    }

    #[test]
    fn test_program_changes_display_total_bytes() {
        let mut display = ProgramChangesDisplay::new();
        display.add_change(ProgramChangeEntry {
            address: 0x1000,
            original_bytes: vec![0x00; 4],
            new_bytes: vec![0xFF; 8],
            description: "edit".into(),
            change_type: ChangeType::MemoryEdit,
        });
        assert_eq!(display.total_modified_bytes(), 8);
    }

    #[test]
    fn test_change_type_display_names() {
        assert_eq!(ChangeType::MemoryEdit.display_name(), "Memory Edit");
        assert_eq!(ChangeType::FunctionChange.display_name(), "Function Change");
        assert_eq!(ChangeType::SymbolChange.display_name(), "Symbol Change");
        assert_eq!(ChangeType::CommentChange.display_name(), "Comment Change");
        assert_eq!(ChangeType::DataTypeChange.display_name(), "Data Type Change");
        assert_eq!(ChangeType::BookmarkChange.display_name(), "Bookmark Change");
        assert_eq!(ChangeType::EquateChange.display_name(), "Equate Change");
    }
}
