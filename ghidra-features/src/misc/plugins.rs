//! Additional misc plugins: font adjust, program changes display, recovery snapshot.
//!
//! Ported from `ghidra.app.plugin.core.misc.FontAdjustPlugin`,
//! `MyProgramChangesDisplayPlugin`, `RecoverySnapshotMgrPlugin`,
//! `RegisterField`.

use ghidra_core::Address;

// ---------------------------------------------------------------------------
// FontAdjustPlugin
// ---------------------------------------------------------------------------

/// Plugin for adjusting the application font size.
///
/// Ported from `ghidra.app.plugin.core.misc.FontAdjustPlugin`.
#[derive(Debug)]
pub struct FontAdjustPlugin {
    /// Current font size in points.
    font_size: f32,
    /// Minimum font size.
    min_size: f32,
    /// Maximum font size.
    max_size: f32,
    /// The font family name.
    font_family: String,
}

impl FontAdjustPlugin {
    /// Default font size.
    pub const DEFAULT_FONT_SIZE: f32 = 12.0;
    /// Minimum font size.
    pub const MIN_FONT_SIZE: f32 = 6.0;
    /// Maximum font size.
    pub const MAX_FONT_SIZE: f32 = 72.0;

    /// Create a new font adjust plugin.
    pub fn new() -> Self {
        Self {
            font_size: Self::DEFAULT_FONT_SIZE,
            min_size: Self::MIN_FONT_SIZE,
            max_size: Self::MAX_FONT_SIZE,
            font_family: "Monospaced".to_string(),
        }
    }

    /// Get the current font size.
    pub fn font_size(&self) -> f32 {
        self.font_size
    }

    /// Set the font size (clamped to min/max).
    pub fn set_font_size(&mut self, size: f32) {
        self.font_size = size.clamp(self.min_size, self.max_size);
    }

    /// Increase the font size by 1 point.
    pub fn increase_font_size(&mut self) {
        self.set_font_size(self.font_size + 1.0);
    }

    /// Decrease the font size by 1 point.
    pub fn decrease_font_size(&mut self) {
        self.set_font_size(self.font_size - 1.0);
    }

    /// Reset to default font size.
    pub fn reset_font_size(&mut self) {
        self.font_size = Self::DEFAULT_FONT_SIZE;
    }

    /// Get the font family.
    pub fn font_family(&self) -> &str {
        &self.font_family
    }

    /// Set the font family.
    pub fn set_font_family(&mut self, family: impl Into<String>) {
        self.font_family = family.into();
    }
}

impl Default for FontAdjustPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ProgramChangesDisplayPlugin
// ---------------------------------------------------------------------------

/// Plugin that displays program changes made during the current session.
///
/// Ported from `ghidra.app.plugin.core.misc.MyProgramChangesDisplayPlugin`.
#[derive(Debug)]
pub struct ProgramChangesDisplayPlugin {
    /// The list of changes.
    changes: Vec<ProgramChange>,
    /// Maximum number of changes to track.
    max_changes: usize,
}

/// A single program change record.
#[derive(Debug, Clone)]
pub struct ProgramChange {
    /// The address where the change occurred.
    pub address: Address,
    /// A description of the change.
    pub description: String,
    /// The change type.
    pub change_type: ChangeType,
    /// Whether the change has been undone.
    pub undone: bool,
}

/// The type of program change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeType {
    /// Code unit was set.
    CodeSet,
    /// Data was set.
    DataSet,
    /// Symbol was added/modified.
    SymbolChange,
    /// Comment was added/modified.
    CommentChange,
    /// Function was created/modified.
    FunctionChange,
    /// Memory was changed.
    MemoryChange,
}

impl ProgramChangesDisplayPlugin {
    /// Create a new changes display plugin.
    pub fn new() -> Self {
        Self {
            changes: Vec::new(),
            max_changes: 10_000,
        }
    }

    /// Record a change.
    pub fn record_change(
        &mut self,
        address: Address,
        description: impl Into<String>,
        change_type: ChangeType,
    ) {
        self.changes.push(ProgramChange {
            address,
            description: description.into(),
            change_type,
            undone: false,
        });
        if self.changes.len() > self.max_changes {
            self.changes.remove(0);
        }
    }

    /// Mark the last change as undone.
    pub fn undo_last(&mut self) {
        if let Some(last) = self.changes.last_mut() {
            last.undone = true;
        }
    }

    /// Get all changes.
    pub fn changes(&self) -> &[ProgramChange] {
        &self.changes
    }

    /// Get the number of changes.
    pub fn change_count(&self) -> usize {
        self.changes.len()
    }

    /// Get the number of non-undone changes.
    pub fn active_change_count(&self) -> usize {
        self.changes.iter().filter(|c| !c.undone).count()
    }

    /// Clear all changes.
    pub fn clear(&mut self) {
        self.changes.clear();
    }

    /// Get changes of a specific type.
    pub fn changes_of_type(&self, change_type: ChangeType) -> Vec<&ProgramChange> {
        self.changes
            .iter()
            .filter(|c| c.change_type == change_type)
            .collect()
    }
}

impl Default for ProgramChangesDisplayPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RecoverySnapshotMgrPlugin
// ---------------------------------------------------------------------------

/// Plugin managing recovery snapshots of program state.
///
/// Ported from `ghidra.app.plugin.core.misc.RecoverySnapshotMgrPlugin`.
#[derive(Debug)]
pub struct RecoverySnapshotMgrPlugin {
    /// Stored snapshots.
    snapshots: Vec<RecoverySnapshot>,
    /// Maximum number of snapshots to keep.
    max_snapshots: usize,
    /// Auto-snapshot interval in seconds.
    auto_interval_secs: u64,
    /// Whether auto-snapshot is enabled.
    auto_enabled: bool,
}

/// A recovery snapshot.
#[derive(Debug, Clone)]
pub struct RecoverySnapshot {
    /// The snapshot ID.
    pub id: u64,
    /// A description.
    pub description: String,
    /// The number of bytes in the snapshot.
    pub size_bytes: u64,
    /// Whether the snapshot was auto-created.
    pub auto_created: bool,
}

impl RecoverySnapshotMgrPlugin {
    /// Create a new recovery snapshot manager.
    pub fn new() -> Self {
        Self {
            snapshots: Vec::new(),
            max_snapshots: 50,
            auto_interval_secs: 300, // 5 minutes
            auto_enabled: true,
        }
    }

    /// Create a new snapshot.
    pub fn create_snapshot(
        &mut self,
        id: u64,
        description: impl Into<String>,
        size_bytes: u64,
        auto_created: bool,
    ) {
        self.snapshots.push(RecoverySnapshot {
            id,
            description: description.into(),
            size_bytes,
            auto_created,
        });
        while self.snapshots.len() > self.max_snapshots {
            self.snapshots.remove(0);
        }
    }

    /// Get all snapshots.
    pub fn snapshots(&self) -> &[RecoverySnapshot] {
        &self.snapshots
    }

    /// Get the number of snapshots.
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Find a snapshot by ID.
    pub fn find_snapshot(&self, id: u64) -> Option<&RecoverySnapshot> {
        self.snapshots.iter().find(|s| s.id == id)
    }

    /// Remove a snapshot by ID.
    pub fn remove_snapshot(&mut self, id: u64) -> bool {
        let len_before = self.snapshots.len();
        self.snapshots.retain(|s| s.id != id);
        self.snapshots.len() < len_before
    }

    /// Set auto-snapshot enabled state.
    pub fn set_auto_enabled(&mut self, enabled: bool) {
        self.auto_enabled = enabled;
    }

    /// Whether auto-snapshot is enabled.
    pub fn is_auto_enabled(&self) -> bool {
        self.auto_enabled
    }

    /// Set the auto-snapshot interval.
    pub fn set_auto_interval(&mut self, secs: u64) {
        self.auto_interval_secs = secs;
    }

    /// Get the auto-snapshot interval.
    pub fn auto_interval_secs(&self) -> u64 {
        self.auto_interval_secs
    }
}

impl Default for RecoverySnapshotMgrPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RegisterField
// ---------------------------------------------------------------------------

/// A field representing a register value in the listing.
///
/// Ported from `ghidra.app.plugin.core.misc.RegisterField`.
#[derive(Debug, Clone)]
pub struct RegisterField {
    /// The register name.
    pub name: String,
    /// The register value.
    pub value: u64,
    /// The register size in bytes.
    pub size: usize,
    /// The address where this register value is set.
    pub address: Address,
    /// Whether the value has been explicitly set by the user.
    pub user_set: bool,
}

impl RegisterField {
    /// Create a new register field.
    pub fn new(
        name: impl Into<String>,
        value: u64,
        size: usize,
        address: Address,
    ) -> Self {
        Self {
            name: name.into(),
            value,
            size,
            address,
            user_set: false,
        }
    }

    /// Format the value as hex.
    pub fn hex_value(&self) -> String {
        match self.size {
            1 => format!("0x{:02X}", self.value & 0xFF),
            2 => format!("0x{:04X}", self.value & 0xFFFF),
            4 => format!("0x{:08X}", self.value & 0xFFFFFFFF),
            8 => format!("0x{:016X}", self.value),
            _ => format!("0x{:X}", self.value),
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_font_adjust_plugin() {
        let mut plugin = FontAdjustPlugin::new();
        assert_eq!(plugin.font_size(), 12.0);
        assert_eq!(plugin.font_family(), "Monospaced");

        plugin.increase_font_size();
        assert_eq!(plugin.font_size(), 13.0);

        plugin.decrease_font_size();
        plugin.decrease_font_size();
        assert_eq!(plugin.font_size(), 11.0);

        plugin.set_font_size(100.0);
        assert_eq!(plugin.font_size(), 72.0); // Clamped to max

        plugin.set_font_size(1.0);
        assert_eq!(plugin.font_size(), 6.0); // Clamped to min

        plugin.reset_font_size();
        assert_eq!(plugin.font_size(), 12.0);
    }

    #[test]
    fn test_program_changes_display() {
        let mut plugin = ProgramChangesDisplayPlugin::new();
        assert_eq!(plugin.change_count(), 0);

        plugin.record_change(Address::new(0x1000), "Set instruction", ChangeType::CodeSet);
        plugin.record_change(Address::new(0x2000), "Added symbol", ChangeType::SymbolChange);
        assert_eq!(plugin.change_count(), 2);
        assert_eq!(plugin.active_change_count(), 2);

        plugin.undo_last();
        assert_eq!(plugin.active_change_count(), 1);

        let symbol_changes = plugin.changes_of_type(ChangeType::SymbolChange);
        assert_eq!(symbol_changes.len(), 1);
        assert!(symbol_changes[0].undone);
    }

    #[test]
    fn test_program_changes_max() {
        let mut plugin = ProgramChangesDisplayPlugin::new();
        plugin.max_changes = 3;

        for i in 0..5 {
            plugin.record_change(
                Address::new(i * 0x1000),
                format!("Change {}", i),
                ChangeType::DataSet,
            );
        }
        assert_eq!(plugin.change_count(), 3);
        // Oldest two were removed
        assert_eq!(plugin.changes()[0].address.offset, 0x2000);
    }

    #[test]
    fn test_recovery_snapshot_mgr() {
        let mut mgr = RecoverySnapshotMgrPlugin::new();
        assert!(mgr.is_auto_enabled());
        assert_eq!(mgr.auto_interval_secs(), 300);

        mgr.create_snapshot(1, "Initial", 1024, false);
        mgr.create_snapshot(2, "Auto save", 512, true);
        assert_eq!(mgr.snapshot_count(), 2);

        let snap = mgr.find_snapshot(1);
        assert!(snap.is_some());
        assert_eq!(snap.unwrap().description, "Initial");

        assert!(mgr.remove_snapshot(1));
        assert_eq!(mgr.snapshot_count(), 1);
        assert!(!mgr.remove_snapshot(99));
    }

    #[test]
    fn test_recovery_snapshot_auto() {
        let mut mgr = RecoverySnapshotMgrPlugin::new();
        mgr.set_auto_enabled(false);
        assert!(!mgr.is_auto_enabled());

        mgr.set_auto_interval(600);
        assert_eq!(mgr.auto_interval_secs(), 600);
    }

    #[test]
    fn test_register_field() {
        let field = RegisterField::new("RAX", 0x12345678, 8, Address::new(0x1000));
        assert_eq!(field.name, "RAX");
        assert_eq!(field.hex_value(), "0x0000000012345678");

        let field8 = RegisterField::new("AL", 0xFF, 1, Address::new(0x1000));
        assert_eq!(field8.hex_value(), "0xFF");

        let field2 = RegisterField::new("AX", 0x1234, 2, Address::new(0x1000));
        assert_eq!(field2.hex_value(), "0x1234");

        let field4 = RegisterField::new("EAX", 0xDEADBEEF, 4, Address::new(0x1000));
        assert_eq!(field4.hex_value(), "0xDEADBEEF");
    }

    #[test]
    fn test_change_type_variants() {
        assert_ne!(ChangeType::CodeSet, ChangeType::DataSet);
        assert_eq!(ChangeType::CommentChange, ChangeType::CommentChange);
    }
}
