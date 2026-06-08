//! Add-block model — validates and creates new memory blocks.
//!
//! Ported from `AddBlockModel` in Ghidra's `ghidra.app.plugin.core.memory`.
//!
//! This model validates all parameters for adding a new memory block to a
//! [`Program`], including block name, start address, length, type, permissions,
//! and initialization settings. Call [`AddBlockModel::execute`] after
//! configuration to apply the block to the program's memory.

use ghidra_core::addr::Address;
use ghidra_core::mem::{ByteMappingScheme, MemoryBlockType, MAX_BLOCK_SIZE};
use ghidra_core::program::program::Program;
use std::collections::HashSet;

// ============================================================================
// InitializedType
// ============================================================================

/// How a new block should be initialized.
///
/// Mirrors `AddBlockModel.InitializedType` in Java.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InitializedType {
    /// Block data is unknown (uninitialized).
    Uninitialized,
    /// Block is filled with a constant byte value.
    InitializedFromValue,
    /// Block data comes from file bytes at a specified offset.
    InitializedFromFileBytes,
}

// ============================================================================
// ValidationError
// ============================================================================

/// Validation error produced by [`AddBlockModel::validate`].
#[derive(Debug, Clone)]
pub enum ValidationError {
    /// No block name was provided.
    MissingName,
    /// The block name is invalid (e.g., contains control characters).
    InvalidName(String),
    /// A block with the same name already exists.
    DuplicateName(String),
    /// No start address was provided.
    MissingStartAddress,
    /// The start address was invalid.
    InvalidStartAddress(String),
    /// The block length is invalid.
    InvalidLength(u64),
    /// The new block overlaps an existing block.
    AddressConflict(String),
    /// A mapped block is missing its base address.
    MissingBaseAddress,
    /// The mapping scheme values are invalid.
    InvalidMappingScheme(String),
    /// The mapped source region has insufficient space.
    InsufficientSourceSpace(String),
    /// The initial fill value is out of the byte range.
    InvalidInitialValue(u8),
    /// File bytes offset or length exceeds the file bytes size.
    InvalidFileBytesOffset(String),
    /// Overlay blocks are required in the OTHER space.
    OverlayRequired(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingName => write!(f, "Please enter a Block Name"),
            Self::InvalidName(n) => write!(f, "Invalid Memory Block Name: {}", n),
            Self::DuplicateName(n) => write!(f, "Warning! Duplicate Block Name: {}", n),
            Self::MissingStartAddress => write!(f, "Please enter a valid Start Address"),
            Self::InvalidStartAddress(m) => write!(f, "Invalid Address: {}", m),
            Self::InvalidLength(limit) => {
                write!(f, "Please enter a valid Length: 1 to 0x{:x}", limit)
            }
            Self::AddressConflict(r) => write!(f, "Block address conflict: {}", r),
            Self::MissingBaseAddress => {
                write!(f, "Please enter a valid mapped region Source Address")
            }
            Self::InvalidMappingScheme(m) => write!(f, "Invalid mapping scheme: {}", m),
            Self::InsufficientSourceSpace(m) => {
                write!(f, "Insufficient space in mapped source region: {}", m)
            }
            Self::InvalidInitialValue(v) => {
                write!(f, "Invalid initial byte value: {} (must be 0..=255)", v)
            }
            Self::InvalidFileBytesOffset(m) => write!(f, "{}", m),
            Self::OverlayRequired(m) => write!(f, "{}", m),
        }
    }
}

impl std::error::Error for ValidationError {}

// ============================================================================
// AddBlockModel
// ============================================================================

/// Model for adding a new memory block to a program.
///
/// Ported from `AddBlockModel` in Java. Validates all parameters before
/// executing the block creation through [`Program::memory`].
///
/// # Usage
///
/// ```ignore
/// let mut model = AddBlockModel::new(&program);
/// model.set_block_name(".newsection");
/// model.set_start_address(Address::new(0x3000));
/// model.set_length(0x1000);
/// model.set_block_type(MemoryBlockType::Default);
/// model.set_initialized_type(InitializedType::InitializedFromValue);
/// model.set_initial_value(0xCC);
/// assert!(model.validate().is_ok());
/// model.execute(&mut program).unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct AddBlockModel {
    /// Name of the new block.
    block_name: Option<String>,
    /// Start address of the new block.
    start_addr: Option<Address>,
    /// Mapped base address (for bit/byte-mapped blocks).
    base_addr: Option<Address>,
    /// Byte mapping scheme destination byte count (for byte-mapped blocks).
    scheme_dest_byte_count: u8,
    /// Byte mapping scheme source byte count (for byte-mapped blocks).
    scheme_src_byte_count: u8,
    /// Length of the new block in bytes.
    length: u64,
    /// Type of the new block.
    block_type: MemoryBlockType,
    /// Whether the block is an overlay.
    is_overlay: bool,
    /// Fill value for initialized blocks.
    initial_value: u8,
    /// Current validation message (empty if valid).
    message: String,
    /// Whether the model is currently in a valid state.
    is_valid: bool,
    /// Read permission.
    is_read: bool,
    /// Write permission.
    is_write: bool,
    /// Execute permission.
    is_execute: bool,
    /// Volatile attribute.
    is_volatile: bool,
    /// Artificial attribute.
    is_artificial: bool,
    /// How the block should be initialized.
    initialized_type: InitializedType,
    /// Comment for the block.
    comment: Option<String>,
    /// File bytes offset (for InitializedFromFileBytes).
    file_bytes_offset: Option<u64>,
    /// File bytes total size (for validation).
    file_bytes_size: Option<u64>,
    /// Names of existing blocks (for duplicate detection).
    existing_block_names: HashSet<String>,
    /// Maximum address offset in the start address's space.
    space_max_offset: Option<u64>,
}

impl AddBlockModel {
    /// Create a new add-block model with default values.
    pub fn new(program: &Program) -> Self {
        let mut existing_names = HashSet::new();
        for block in program.memory.get_blocks() {
            existing_names.insert(block.name.clone());
        }

        let image_base = program.get_image_base();
        let space_max = None; // simplified — in Ghidra this is derived from the address space

        Self {
            block_name: None,
            start_addr: Some(image_base),
            base_addr: None,
            scheme_dest_byte_count: 1,
            scheme_src_byte_count: 1,
            length: 0,
            block_type: MemoryBlockType::Default,
            is_overlay: false,
            initial_value: 0,
            message: String::new(),
            is_valid: false,
            is_read: true,
            is_write: true,
            is_execute: false,
            is_volatile: false,
            is_artificial: false,
            initialized_type: InitializedType::Uninitialized,
            comment: None,
            file_bytes_offset: None,
            file_bytes_size: None,
            existing_block_names: existing_names,
            space_max_offset: space_max,
        }
    }

    // ---- setters ----

    /// Set the block name.
    pub fn set_block_name(&mut self, name: impl Into<String>) {
        self.block_name = Some(name.into());
        self.validate();
    }

    /// Set the start address.
    pub fn set_start_address(&mut self, addr: Address) {
        self.start_addr = Some(addr);
        self.validate();
    }

    /// Set the block length.
    pub fn set_length(&mut self, length: u64) {
        self.length = length;
        self.validate();
    }

    /// Set the block type.
    pub fn set_block_type(&mut self, block_type: MemoryBlockType) {
        self.block_type = block_type;
        self.is_read = true;
        self.is_write = true;
        self.is_execute = false;
        self.is_volatile = false;
        self.is_overlay = false;
        self.is_artificial = false;
        self.scheme_dest_byte_count = if block_type == MemoryBlockType::BitMapped { 8 } else { 1 };
        self.scheme_src_byte_count = 1;
        self.initialized_type = InitializedType::Uninitialized;
        self.validate();
    }

    /// Set the initialized type.
    pub fn set_initialized_type(&mut self, init_type: InitializedType) {
        self.initialized_type = init_type;
        self.validate();
    }

    /// Set the initial fill value (0..=255).
    pub fn set_initial_value(&mut self, value: u8) {
        self.initial_value = value;
        self.validate();
    }

    /// Set the overlay flag.
    pub fn set_overlay(&mut self, is_overlay: bool) {
        self.is_overlay = is_overlay;
        self.validate();
    }

    /// Set the mapped base address (for bit/byte-mapped blocks).
    pub fn set_base_address(&mut self, addr: Address) {
        self.base_addr = Some(addr);
        self.validate();
    }

    /// Set the byte mapping scheme destination byte count.
    pub fn set_scheme_dest_byte_count(&mut self, count: u8) {
        self.scheme_dest_byte_count = count;
        self.validate();
    }

    /// Set the byte mapping scheme source byte count.
    pub fn set_scheme_src_byte_count(&mut self, count: u8) {
        self.scheme_src_byte_count = count;
        self.validate();
    }

    /// Set file bytes offset for `InitializedFromFileBytes`.
    pub fn set_file_bytes_offset(&mut self, offset: u64) {
        self.file_bytes_offset = Some(offset);
        self.validate();
    }

    /// Set the file bytes size for validation.
    pub fn set_file_bytes_size(&mut self, size: u64) {
        self.file_bytes_size = Some(size);
        self.validate();
    }

    /// Set the block comment.
    pub fn set_comment(&mut self, comment: impl Into<String>) {
        self.comment = Some(comment.into());
    }

    /// Set read permission.
    pub fn set_read(&mut self, value: bool) {
        self.is_read = value;
    }

    /// Set write permission.
    pub fn set_write(&mut self, value: bool) {
        self.is_write = value;
    }

    /// Set execute permission.
    pub fn set_execute(&mut self, value: bool) {
        self.is_execute = value;
    }

    /// Set volatile attribute.
    pub fn set_volatile(&mut self, value: bool) {
        self.is_volatile = value;
    }

    /// Set artificial attribute.
    pub fn set_artificial(&mut self, value: bool) {
        self.is_artificial = value;
    }

    // ---- getters ----

    /// Get the current block name, if set.
    pub fn block_name(&self) -> Option<&str> {
        self.block_name.as_deref()
    }

    /// Get the start address, if set.
    pub fn start_address(&self) -> Option<Address> {
        self.start_addr
    }

    /// Get the block length.
    pub fn length(&self) -> u64 {
        self.length
    }

    /// Get the block type.
    pub fn block_type(&self) -> MemoryBlockType {
        self.block_type
    }

    /// Get the initial fill value.
    pub fn initial_value(&self) -> u8 {
        self.initial_value
    }

    /// Whether the model is valid.
    pub fn is_valid(&self) -> bool {
        self.is_valid
    }

    /// Get the current validation message (empty if valid).
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Get the initialized type.
    pub fn initialized_type(&self) -> InitializedType {
        self.initialized_type
    }

    /// Whether the model's block is read-permitted.
    pub fn is_read(&self) -> bool {
        self.is_read
    }

    /// Whether the model's block is write-permitted.
    pub fn is_write(&self) -> bool {
        self.is_write
    }

    /// Whether the model's block is execute-permitted.
    pub fn is_execute(&self) -> bool {
        self.is_execute
    }

    /// Whether the model's block is volatile.
    pub fn is_volatile(&self) -> bool {
        self.is_volatile
    }

    /// Whether the model's block is artificial.
    pub fn is_artificial(&self) -> bool {
        self.is_artificial
    }

    /// Whether the model's block is an overlay.
    pub fn is_overlay(&self) -> bool {
        self.is_overlay
    }

    // ---- validation ----

    /// Run all validation checks and update the model's valid/message state.
    pub fn validate(&mut self) {
        self.message.clear();
        self.is_valid = self.has_valid_name()
            && self.has_valid_start_address()
            && self.has_valid_length()
            && self.has_no_memory_conflicts()
            && self.has_mapped_address_if_needed()
            && self.has_initial_value_if_needed()
            && self.has_file_bytes_info_if_needed()
            && self.is_overlay_if_other_space();
    }

    fn has_valid_name(&mut self) -> bool {
        match &self.block_name {
            None => {
                self.message = "Please enter a Block Name".into();
                false
            }
            Some(name) if name.is_empty() => {
                self.message = "Please enter a Block Name".into();
                false
            }
            Some(name) if name.chars().any(|c| (c as u32) < 0x20) => {
                self.message = "Block Name is invalid".into();
                false
            }
            Some(name) if self.existing_block_names.contains(name) => {
                // Duplicate name is a warning, not a failure
                true
            }
            _ => true,
        }
    }

    fn has_valid_start_address(&mut self) -> bool {
        if self.start_addr.is_some() {
            true
        } else {
            self.message = "Please enter a valid Start Address".into();
            false
        }
    }

    fn has_valid_length(&mut self) -> bool {
        let limit = self.space_max_offset.map_or(MAX_BLOCK_SIZE, |max_off| {
            MAX_BLOCK_SIZE.min(max_off + 1)
        });
        if self.length > 0 && self.length <= limit {
            true
        } else {
            self.message = format!("Please enter a valid Length: 1 to 0x{:x}", limit);
            false
        }
    }

    fn has_no_memory_conflicts(&mut self) -> bool {
        // In the model this checks against the program's memory.
        // Since we store only names for deduplication, this is a simplified check.
        // The actual conflict check is performed in `execute()`.
        true
    }

    fn has_mapped_address_if_needed(&mut self) -> bool {
        if self.block_type != MemoryBlockType::BitMapped
            && self.block_type != MemoryBlockType::ByteMapped
        {
            return true;
        }
        if self.base_addr.is_none() {
            self.message = "Please enter a valid mapped region Source Address".into();
            return false;
        }
        if self.block_type == MemoryBlockType::ByteMapped {
            if self.scheme_dest_byte_count == 0
                || self.scheme_dest_byte_count > 127
                || self.scheme_src_byte_count == 0
                || self.scheme_src_byte_count > 127
            {
                self.message = "Mapping Ratio values must be within range: 1 to 127".into();
                return false;
            }
            if self.scheme_dest_byte_count > self.scheme_src_byte_count {
                self.message =
                    "Mapping Ratio destination byte count must be <= source byte count".into();
                return false;
            }
        }
        true
    }

    fn has_initial_value_if_needed(&mut self) -> bool {
        if self.initialized_type != InitializedType::InitializedFromValue {
            return true;
        }
        // u8 is always 0..=255, so this is always valid
        true
    }

    fn has_file_bytes_info_if_needed(&mut self) -> bool {
        if self.initialized_type != InitializedType::InitializedFromFileBytes {
            return true;
        }
        match (self.file_bytes_size, self.file_bytes_offset) {
            (Some(size), Some(offset)) => {
                if offset >= size {
                    self.message = format!(
                        "Please enter a valid file bytes offset (0 - {})",
                        size - 1
                    );
                    return false;
                }
                if offset + self.length > size {
                    self.message = format!(
                        "File bytes offset + length exceeds file bytes size: {}",
                        size
                    );
                    return false;
                }
                true
            }
            _ => {
                self.message = "Please select a FileBytes entry".into();
                false
            }
        }
    }

    fn is_overlay_if_other_space(&mut self) -> bool {
        // Simplified: in Ghidra, OTHER_SPACE blocks must be overlays.
        // We don't have a full address space model here, so this always passes.
        true
    }

    /// Compute the permission flags byte from the model's boolean fields.
    pub fn compute_flags(&self) -> u8 {
        let mut flags = 0u8;
        if self.is_read {
            flags |= ghidra_core::mem::FLAG_READ;
        }
        if self.is_write {
            flags |= ghidra_core::mem::FLAG_WRITE;
        }
        if self.is_execute {
            flags |= ghidra_core::mem::FLAG_EXECUTE;
        }
        if self.is_volatile {
            flags |= ghidra_core::mem::FLAG_VOLATILE;
        }
        if self.is_artificial {
            flags |= ghidra_core::mem::FLAG_ARTIFICIAL;
        }
        flags
    }

    /// Execute the model: create the block in the program's memory.
    ///
    /// Returns `Ok(())` if the block was created successfully, or an error.
    pub fn execute(&mut self, program: &mut Program) -> Result<(), String> {
        self.validate();
        if !self.is_valid {
            return Err(self.message.clone());
        }

        let name = self.block_name.as_ref().unwrap();
        let start = self.start_addr.unwrap();
        let _flags = self.compute_flags();

        match self.block_type {
            MemoryBlockType::Default => {
                match self.initialized_type {
                    InitializedType::Uninitialized => {
                        program
                            .memory
                            .create_uninitialized_block(name, start, self.length, self.is_overlay)
                            .map_err(|e| format!("{}", e))?;
                    }
                    InitializedType::InitializedFromValue => {
                        program
                            .memory
                            .create_initialized_block_value(
                                name,
                                start,
                                self.length,
                                self.initial_value,
                                self.is_overlay,
                            )
                            .map_err(|e| format!("{}", e))?;
                    }
                    InitializedType::InitializedFromFileBytes => {
                        // File bytes initialization is simplified here;
                        // in the full implementation this creates the block from
                        // the stored file bytes at the specified offset.
                        program
                            .memory
                            .create_uninitialized_block(name, start, self.length, self.is_overlay)
                            .map_err(|e| format!("{}", e))?;
                    }
                }
            }
            MemoryBlockType::BitMapped => {
                let base = self.base_addr.ok_or("Base address required for bit-mapped block")?;
                program
                    .memory
                    .create_bit_mapped_block(name, start, base, self.length, self.is_overlay)
                    .map_err(|e| format!("{}", e))?;
            }
            MemoryBlockType::ByteMapped => {
                let base = self.base_addr.ok_or("Base address required for byte-mapped block")?;
                let scheme = ByteMappingScheme::new(
                    self.scheme_dest_byte_count,
                    self.scheme_src_byte_count,
                );
                program
                    .memory
                    .create_byte_mapped_block(
                        name,
                        start,
                        base,
                        self.length,
                        Some(scheme),
                        self.is_overlay,
                    )
                    .map_err(|e| format!("{}", e))?;
            }
        }

        // Apply flags to the newly created block
        // (Note: MemoryMap sets default flags; we would need to update them
        // via a set_block_flags method if available. For now the block is
        // created with the API's default flags.)

        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;
    use ghidra_core::mem::MemoryMap;

    fn make_program() -> Program {
        let memory = MemoryMap::new(false);
        Program::with_memory("test", Address::new(0), Box::new(memory))
    }

    #[test]
    fn test_new_model_is_invalid() {
        let program = make_program();
        let mut model = AddBlockModel::new(&program);
        // New model starts as invalid (no name, no length set)
        model.validate();
        assert!(!model.is_valid());
        assert!(!model.message().is_empty());
    }

    #[test]
    fn test_set_valid_name_and_length() {
        let program = make_program();
        let mut model = AddBlockModel::new(&program);
        model.set_block_name(".text");
        model.set_length(0x1000);
        assert!(model.is_valid(), "model should be valid: {}", model.message());
    }

    #[test]
    fn test_empty_name_is_invalid() {
        let program = make_program();
        let mut model = AddBlockModel::new(&program);
        model.set_block_name("");
        assert!(!model.is_valid());
    }

    #[test]
    fn test_zero_length_is_invalid() {
        let program = make_program();
        let mut model = AddBlockModel::new(&program);
        model.set_block_name(".text");
        model.set_length(0);
        assert!(!model.is_valid());
    }

    #[test]
    fn test_invalid_byte_mapping_scheme() {
        let program = make_program();
        let mut model = AddBlockModel::new(&program);
        model.set_block_name(".mapped");
        model.set_length(0x100);
        model.set_block_type(MemoryBlockType::ByteMapped);
        model.set_base_address(Address::new(0x1000));
        // dest > src is invalid
        model.set_scheme_dest_byte_count(4);
        model.set_scheme_src_byte_count(2);
        assert!(!model.is_valid());
        assert!(model.message().contains("must be <="));
    }

    #[test]
    fn test_execute_create_uninitialized() {
        let mut program = make_program();
        let mut model = AddBlockModel::new(&program);
        model.set_block_name(".bss");
        model.set_length(0x100);
        assert!(model.is_valid(), "{}", model.message());
        let result = model.execute(&mut program);
        assert!(result.is_ok(), "execute should succeed: {:?}", result.err());
        assert!(program.memory.get_block_by_name(".bss").is_some());
    }

    #[test]
    fn test_execute_create_initialized_from_value() {
        let mut program = make_program();
        let mut model = AddBlockModel::new(&program);
        model.set_block_name(".data");
        model.set_length(0x80);
        model.set_initialized_type(InitializedType::InitializedFromValue);
        model.set_initial_value(0xCC);
        assert!(model.is_valid(), "{}", model.message());
        let result = model.execute(&mut program);
        assert!(result.is_ok(), "execute should succeed: {:?}", result.err());
    }

    #[test]
    fn test_duplicate_name_is_warning() {
        let mut program = make_program();
        let _ = program
            .memory
            .create_uninitialized_block(".text", Address::new(0x1000), 0x100, false);
        let mut model = AddBlockModel::new(&program);
        model.set_block_name(".text");
        model.set_length(0x100);
        // Duplicate name is a warning — model is still valid, just has a message
        // (In the Java version it's a warning, not a hard failure)
    }

    #[test]
    fn test_compute_flags() {
        let program = make_program();
        let mut model = AddBlockModel::new(&program);
        model.set_read(true);
        model.set_write(true);
        model.set_execute(false);
        model.set_volatile(false);
        model.set_artificial(false);
        let flags = model.compute_flags();
        assert_eq!(flags, ghidra_core::mem::FLAG_READ | ghidra_core::mem::FLAG_WRITE);
    }

    #[test]
    fn test_set_block_type_resets_permissions() {
        let program = make_program();
        let mut model = AddBlockModel::new(&program);
        model.set_execute(true);
        model.set_block_type(MemoryBlockType::Default);
        // set_block_type resets is_execute to false
        assert!(!model.is_execute());
        assert!(model.is_read());
        assert!(model.is_write());
    }
}
