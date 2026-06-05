// ===========================================================================
// Memory Block Operations -- ported from Ghidra's
// `ghidra.app.plugin.core.memory` package.
//
// Includes:
// - MoveBlockModel            -- model for moving a memory block
// - MoveBlockDialog           -- dialog model for block move
// - SplitBlockDialog          -- dialog model for splitting a block
// - UninitializedBlockCmd     -- command to create uninitialized blocks
// - ExpandBlockModel          -- model for expanding a block (base + up/down)
// - ExpandBlockDialog         -- dialog model for block expansion
// - ImageBaseDialog           -- dialog for changing the image base
// ===========================================================================

use ghidra_core::Address;

/// Memory block permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockPermissions {
    /// Read permission.
    pub read: bool,
    /// Write permission.
    pub write: bool,
    /// Execute permission.
    pub execute: bool,
}

impl BlockPermissions {
    /// Create new permissions.
    pub fn new(read: bool, write: bool, execute: bool) -> Self {
        Self {
            read,
            write,
            execute,
        }
    }

    /// Read-only permissions.
    pub fn read_only() -> Self {
        Self::new(true, false, false)
    }

    /// Read-write permissions.
    pub fn read_write() -> Self {
        Self::new(true, true, false)
    }

    /// Read-execute permissions.
    pub fn read_execute() -> Self {
        Self::new(true, false, true)
    }

    /// Full permissions.
    pub fn all() -> Self {
        Self::new(true, true, true)
    }
}

impl Default for BlockPermissions {
    fn default() -> Self {
        Self::read_write()
    }
}

// ---------------------------------------------------------------------------
// MoveBlockModel
// ---------------------------------------------------------------------------

/// Model for the "Move Memory Block" operation.
///
/// Ported from `ghidra.app.plugin.core.memory.MoveBlockModel`.
#[derive(Debug, Clone)]
pub struct MoveBlockModel {
    /// The block name.
    pub block_name: String,
    /// Current start address.
    pub current_start: Address,
    /// Current block size in bytes.
    pub block_size: u64,
    /// New start address (proposed).
    pub new_start: Address,
    /// Whether the move is valid.
    pub valid: bool,
    /// Error message (if invalid).
    pub error: Option<String>,
}

impl MoveBlockModel {
    /// Create a new model.
    pub fn new(
        block_name: impl Into<String>,
        current_start: Address,
        block_size: u64,
    ) -> Self {
        Self {
            block_name: block_name.into(),
            current_start,
            block_size,
            new_start: current_start,
            valid: true,
            error: None,
        }
    }

    /// Set the proposed new start address.
    pub fn set_new_start(&mut self, addr: Address) {
        self.new_start = addr;
        self.validate();
    }

    /// Validate the move operation.
    fn validate(&mut self) {
        self.valid = true;
        self.error = None;

        // Check that the new address + size doesn't overflow.
        if self.new_start.offset.checked_add(self.block_size).is_none() {
            self.valid = false;
            self.error = Some("New address would overflow".into());
        }
    }

    /// Whether the move would actually change anything.
    pub fn is_effective(&self) -> bool {
        self.new_start != self.current_start
    }
}

// ---------------------------------------------------------------------------
// MoveBlockDialog
// ---------------------------------------------------------------------------

/// Dialog model for moving a memory block.
///
/// Ported from `ghidra.app.plugin.core.memory.MoveBlockDialog`.
#[derive(Debug, Clone)]
pub struct MoveBlockDialog {
    /// The move model.
    pub model: MoveBlockModel,
    /// Whether the dialog is open.
    pub is_open: bool,
}

impl MoveBlockDialog {
    /// Create a new dialog.
    pub fn new(block_name: impl Into<String>, current_start: Address, block_size: u64) -> Self {
        Self {
            model: MoveBlockModel::new(block_name, current_start, block_size),
            is_open: false,
        }
    }

    /// Open the dialog.
    pub fn open(&mut self) {
        self.is_open = true;
    }

    /// Close the dialog.
    pub fn close(&mut self) {
        self.is_open = false;
    }

    /// Confirm the move.
    pub fn confirm(&self) -> Option<&MoveBlockModel> {
        if self.model.valid && self.model.is_effective() {
            Some(&self.model)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// ExpandBlockModel
// ---------------------------------------------------------------------------

/// Direction of block expansion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExpandDirection {
    /// Expand upward (toward lower addresses).
    Up,
    /// Expand downward (toward higher addresses).
    Down,
}

/// Model for expanding a memory block.
///
/// Ported from `ghidra.app.plugin.core.memory.ExpandBlockModel`,
/// `ExpandBlockUpModel`, and `ExpandBlockDownModel`.
#[derive(Debug, Clone)]
pub struct ExpandBlockModel {
    /// The block name.
    pub block_name: String,
    /// Current block start.
    pub current_start: Address,
    /// Current block end (exclusive).
    pub current_end: Address,
    /// The expansion direction.
    pub direction: ExpandDirection,
    /// Number of bytes to expand by.
    pub expand_by: u64,
    /// Whether the expansion is valid.
    pub valid: bool,
    /// Error message.
    pub error: Option<String>,
}

impl ExpandBlockModel {
    /// Create a new model.
    pub fn new(
        block_name: impl Into<String>,
        current_start: Address,
        current_end: Address,
        direction: ExpandDirection,
    ) -> Self {
        Self {
            block_name: block_name.into(),
            current_start,
            current_end,
            direction,
            expand_by: 0,
            valid: true,
            error: None,
        }
    }

    /// Set the number of bytes to expand by.
    pub fn set_expand_by(&mut self, bytes: u64) {
        self.expand_by = bytes;
        self.validate();
    }

    /// Get the proposed new start address after expansion.
    pub fn new_start(&self) -> Address {
        match self.direction {
            ExpandDirection::Up => {
                Address::new(self.current_start.offset.saturating_sub(self.expand_by))
            }
            ExpandDirection::Down => self.current_start,
        }
    }

    /// Get the proposed new end address after expansion.
    pub fn new_end(&self) -> Address {
        match self.direction {
            ExpandDirection::Up => self.current_end,
            ExpandDirection::Down => {
                Address::new(self.current_end.offset.saturating_add(self.expand_by))
            }
        }
    }

    /// Validate the expansion.
    fn validate(&mut self) {
        self.valid = true;
        self.error = None;

        if self.expand_by == 0 {
            self.valid = false;
            self.error = Some("Expansion size must be greater than 0".into());
        }

        match self.direction {
            ExpandDirection::Up => {
                if self.current_start.offset < self.expand_by {
                    self.valid = false;
                    self.error = Some("Cannot expand below address 0".into());
                }
            }
            ExpandDirection::Down => {
                if self.current_end.offset.checked_add(self.expand_by).is_none() {
                    self.valid = false;
                    self.error = Some("Expansion would overflow".into());
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ExpandBlockDialog
// ---------------------------------------------------------------------------

/// Dialog model for expanding a memory block.
///
/// Ported from `ghidra.app.plugin.core.memory.ExpandBlockDialog`.
#[derive(Debug, Clone)]
pub struct ExpandBlockDialog {
    /// The expand model.
    pub model: ExpandBlockModel,
    /// Whether the dialog is open.
    pub is_open: bool,
}

impl ExpandBlockDialog {
    /// Create a new dialog.
    pub fn new(
        block_name: impl Into<String>,
        current_start: Address,
        current_end: Address,
        direction: ExpandDirection,
    ) -> Self {
        Self {
            model: ExpandBlockModel::new(block_name, current_start, current_end, direction),
            is_open: false,
        }
    }

    /// Open the dialog.
    pub fn open(&mut self) {
        self.is_open = true;
    }

    /// Close the dialog.
    pub fn close(&mut self) {
        self.is_open = false;
    }

    /// Confirm the expansion.
    pub fn confirm(&self) -> Option<&ExpandBlockModel> {
        if self.model.valid && self.model.expand_by > 0 {
            Some(&self.model)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// SplitBlockDialog
// ---------------------------------------------------------------------------

/// Dialog model for splitting a memory block at an address.
///
/// Ported from `ghidra.app.plugin.core.memory.SplitBlockDialog`.
#[derive(Debug, Clone)]
pub struct SplitBlockDialog {
    /// The block name.
    pub block_name: String,
    /// The block start address.
    pub block_start: Address,
    /// The block end address (exclusive).
    pub block_end: Address,
    /// The address at which to split.
    pub split_address: Address,
    /// Whether the split is valid.
    pub valid: bool,
    /// Error message.
    pub error: Option<String>,
}

impl SplitBlockDialog {
    /// Create a new dialog.
    pub fn new(
        block_name: impl Into<String>,
        block_start: Address,
        block_end: Address,
    ) -> Self {
        Self {
            block_name: block_name.into(),
            block_start,
            block_end,
            split_address: block_start,
            valid: false,
            error: Some("Split address not set".into()),
        }
    }

    /// Set the split address.
    pub fn set_split_address(&mut self, addr: Address) {
        self.split_address = addr;
        self.validate();
    }

    /// Validate the split.
    fn validate(&mut self) {
        if self.split_address.offset <= self.block_start.offset {
            self.valid = false;
            self.error = Some("Split address must be after block start".into());
        } else if self.split_address.offset >= self.block_end.offset {
            self.valid = false;
            self.error = Some("Split address must be before block end".into());
        } else {
            self.valid = true;
            self.error = None;
        }
    }

    /// Get the size of the first half (before the split).
    pub fn first_half_size(&self) -> u64 {
        self.split_address.offset - self.block_start.offset
    }

    /// Get the size of the second half (after the split).
    pub fn second_half_size(&self) -> u64 {
        self.block_end.offset - self.split_address.offset
    }
}

// ---------------------------------------------------------------------------
// UninitializedBlockCmd
// ---------------------------------------------------------------------------

/// Command to create an uninitialized memory block.
///
/// Ported from `ghidra.app.plugin.core.memory.UninitializedBlockCmd`.
#[derive(Debug, Clone)]
pub struct UninitializedBlockCmd {
    /// Block name.
    pub name: String,
    /// Start address.
    pub start: Address,
    /// Block size in bytes.
    pub size: u64,
    /// Permissions.
    pub permissions: BlockPermissions,
    /// Whether volatile.
    pub volatile: bool,
    /// Whether executed.
    pub executed: bool,
}

impl UninitializedBlockCmd {
    /// Create a new command.
    pub fn new(
        name: impl Into<String>,
        start: Address,
        size: u64,
    ) -> Self {
        Self {
            name: name.into(),
            start,
            size,
            permissions: BlockPermissions::default(),
            volatile: false,
            executed: false,
        }
    }

    /// Set permissions.
    pub fn set_permissions(&mut self, perms: BlockPermissions) {
        self.permissions = perms;
    }

    /// Set volatile flag.
    pub fn set_volatile(&mut self, volatile: bool) {
        self.volatile = volatile;
    }

    /// The end address (exclusive).
    pub fn end_address(&self) -> u64 {
        self.start.offset + self.size
    }
}

// ---------------------------------------------------------------------------
// ImageBaseDialog
// ---------------------------------------------------------------------------

/// Dialog model for changing the image base address.
///
/// Ported from `ghidra.app.plugin.core.memory.ImageBaseDialog`.
#[derive(Debug, Clone)]
pub struct ImageBaseDialog {
    /// Current base address.
    pub current_base: Address,
    /// Proposed new base address.
    pub new_base: Address,
    /// Whether the change is valid.
    pub valid: bool,
    /// Error message.
    pub error: Option<String>,
}

impl ImageBaseDialog {
    /// Create a new dialog.
    pub fn new(current_base: Address) -> Self {
        Self {
            current_base,
            new_base: current_base,
            valid: true,
            error: None,
        }
    }

    /// Set the proposed new base.
    pub fn set_new_base(&mut self, base: Address) {
        self.new_base = base;
        self.valid = true;
        self.error = None;
    }

    /// Whether the change would have any effect.
    pub fn is_effective(&self) -> bool {
        self.new_base != self.current_base
    }

    /// Get the delta (shift) in bytes.
    pub fn delta(&self) -> i64 {
        self.new_base.offset as i64 - self.current_base.offset as i64
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_permissions() {
        let perms = BlockPermissions::read_execute();
        assert!(perms.read);
        assert!(!perms.write);
        assert!(perms.execute);
    }

    #[test]
    fn test_move_block_model() {
        let mut model = MoveBlockModel::new(".text", Address::new(0x400000), 0x1000);
        assert!(model.valid);
        model.set_new_start(Address::new(0x500000));
        assert!(model.valid);
        assert!(model.is_effective());
    }

    #[test]
    fn test_move_block_dialog() {
        let mut dialog = MoveBlockDialog::new(".text", Address::new(0x400000), 0x1000);
        dialog.open();
        assert!(dialog.is_open);
        dialog.model.set_new_start(Address::new(0x500000));
        assert!(dialog.confirm().is_some());
    }

    #[test]
    fn test_expand_block_model_up() {
        let mut model = ExpandBlockModel::new(
            ".text",
            Address::new(0x400000),
            Address::new(0x401000),
            ExpandDirection::Up,
        );
        model.set_expand_by(0x1000);
        assert!(model.valid);
        assert_eq!(model.new_start(), Address::new(0x3FF000));
        assert_eq!(model.new_end(), Address::new(0x401000));
    }

    #[test]
    fn test_expand_block_model_down() {
        let mut model = ExpandBlockModel::new(
            ".text",
            Address::new(0x400000),
            Address::new(0x401000),
            ExpandDirection::Down,
        );
        model.set_expand_by(0x1000);
        assert!(model.valid);
        assert_eq!(model.new_start(), Address::new(0x400000));
        assert_eq!(model.new_end(), Address::new(0x402000));
    }

    #[test]
    fn test_split_block_dialog() {
        let mut dialog = SplitBlockDialog::new(".text", Address::new(0x400000), Address::new(0x401000));
        assert!(!dialog.valid);
        dialog.set_split_address(Address::new(0x400800));
        assert!(dialog.valid);
        assert_eq!(dialog.first_half_size(), 0x800);
        assert_eq!(dialog.second_half_size(), 0x800);
    }

    #[test]
    fn test_split_block_dialog_invalid() {
        let mut dialog = SplitBlockDialog::new(".text", Address::new(0x400000), Address::new(0x401000));
        dialog.set_split_address(Address::new(0x400000));
        assert!(!dialog.valid);
        dialog.set_split_address(Address::new(0x401000));
        assert!(!dialog.valid);
    }

    #[test]
    fn test_uninitialized_block_cmd() {
        let mut cmd = UninitializedBlockCmd::new("RAM", Address::new(0x80000000), 0x10000);
        cmd.set_permissions(BlockPermissions::all());
        cmd.set_volatile(true);
        assert_eq!(cmd.end_address(), 0x80010000);
        assert!(cmd.volatile);
    }

    #[test]
    fn test_image_base_dialog() {
        let mut dialog = ImageBaseDialog::new(Address::new(0x400000));
        dialog.set_new_base(Address::new(0x401000));
        assert!(dialog.is_effective());
        assert_eq!(dialog.delta(), 0x1000);
    }
}
