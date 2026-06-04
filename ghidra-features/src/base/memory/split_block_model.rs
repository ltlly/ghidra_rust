//! Split-block validation model — validates parameters for splitting a memory block.
//!
//! Ported from `SplitBlockDialog` in Ghidra's `ghidra.app.plugin.core.memory`.
//!
//! This model tracks the proposed split point, computes the resulting
//! sub-block boundaries and lengths, and validates that the split is
//! well-formed (split address inside the block, both halves non-empty).
//!
//! The GUI dialog uses this model's validation methods; the non-GUI
//! port exposes the same validation and address-computation logic
//! without any Swing dependency.

use ghidra_core::addr::Address;

/// Validation result from the split-block model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SplitValidationError {
    /// The split address is outside the block's address range.
    SplitAddressOutOfBounds,
    /// The split address equals the block start (first half would be empty).
    SplitAtStart,
    /// The split address is beyond the block end.
    SplitBeyondEnd,
    /// The resulting first-block length is zero or negative.
    InvalidFirstBlockLength,
    /// The resulting second-block length is zero or negative.
    InvalidSecondBlockLength,
    /// No block name for the new (second) block.
    MissingNewBlockName,
    /// The new block name is invalid (contains control characters).
    InvalidNewBlockName(String),
}

impl std::fmt::Display for SplitValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SplitAddressOutOfBounds => {
                write!(f, "Split address is outside the block's address range")
            }
            Self::SplitAtStart => {
                write!(f, "Split address must be greater than block start")
            }
            Self::SplitBeyondEnd => {
                write!(f, "Split address must not exceed block end")
            }
            Self::InvalidFirstBlockLength => {
                write!(f, "First block length must be greater than zero")
            }
            Self::InvalidSecondBlockLength => {
                write!(f, "Second block length must be greater than zero")
            }
            Self::MissingNewBlockName => {
                write!(f, "Please enter a name for the new block")
            }
            Self::InvalidNewBlockName(n) => {
                write!(f, "Invalid block name: {}", n)
            }
        }
    }
}

impl std::error::Error for SplitValidationError {}

/// Result of a validated split computation.
///
/// Contains all the address/length values needed to execute the split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitResult {
    /// Start address of the first (original) block (unchanged).
    pub first_start: Address,
    /// New end address of the first block (split point - 1).
    pub first_end: Address,
    /// Length of the first block in bytes.
    pub first_length: u64,
    /// Start address of the second (new) block (= split point).
    pub second_start: Address,
    /// End address of the second block (= original end).
    pub second_end: Address,
    /// Length of the second block in bytes.
    pub second_length: u64,
}

/// Model for validating memory-block split parameters.
///
/// Ported from `SplitBlockDialog` in Java. Provides the validation and
/// address-computation logic without any GUI dependencies.
///
/// # Usage
///
/// ```ignore
/// let mut model = SplitBlockModel::new(
///     Address::new(0x1000),
///     Address::new(0x3fff),
///     ".text".to_string(),
/// );
/// model.set_split_address(Address::new(0x2000));
/// model.set_new_block_name(".text.split");
/// let result = model.validate().unwrap();
/// // result.first_length == 0x1000, result.second_length == 0x2000
/// ```
#[derive(Debug, Clone)]
pub struct SplitBlockModel {
    /// Start address of the block being split.
    block_start: Address,
    /// End address of the block being split.
    block_end: Address,
    /// Name of the block being split.
    block_name: String,
    /// The proposed split address (start of the second block).
    split_address: Option<Address>,
    /// Name for the new (second) block.
    new_block_name: String,
    /// Current status message (empty if valid).
    message: String,
}

impl SplitBlockModel {
    /// Create a new split-block model for the given block.
    pub fn new(
        block_start: Address,
        block_end: Address,
        block_name: impl Into<String>,
    ) -> Self {
        let name = block_name.into();
        let default_split_name = format!("{}.split", name);
        Self {
            block_start,
            block_end,
            block_name: name,
            split_address: None,
            new_block_name: default_split_name,
            message: String::new(),
        }
    }

    /// Set the proposed split address.
    pub fn set_split_address(&mut self, addr: Address) {
        self.split_address = Some(addr);
    }

    /// Set the name for the new (second) block.
    pub fn set_new_block_name(&mut self, name: impl Into<String>) {
        self.new_block_name = name.into();
    }

    /// Get the block name.
    pub fn block_name(&self) -> &str {
        &self.block_name
    }

    /// Get the split address, if set.
    pub fn split_address(&self) -> Option<Address> {
        self.split_address
    }

    /// Get the new block name.
    pub fn new_block_name(&self) -> &str {
        &self.new_block_name
    }

    /// Get the current status message (empty if no issues).
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Get the block size in bytes.
    pub fn block_size(&self) -> u64 {
        self.block_end.offset - self.block_start.offset + 1
    }

    /// Compute the split result from the "first block length" parameter.
    ///
    /// When the user enters a desired length for the first block, this
    /// computes the resulting second-block start and lengths.
    ///
    /// Returns `Ok(SplitResult)` if the length is valid, or an error message.
    pub fn compute_from_first_length(&self, first_length: u64) -> Result<SplitResult, String> {
        let block_size = self.block_size();
        if first_length == 0 || first_length >= block_size {
            return Err(format!(
                "Length must be less than original block size (0x{:x})",
                block_size
            ));
        }

        let first_end = Address::new(self.block_start.offset + first_length - 1);
        let second_start = Address::new(first_end.offset + 1);
        let second_length = self.block_end.offset - second_start.offset + 1;

        Ok(SplitResult {
            first_start: self.block_start,
            first_end,
            first_length,
            second_start,
            second_end: self.block_end,
            second_length,
        })
    }

    /// Compute the split result from the "second block length" parameter.
    ///
    /// When the user enters a desired length for the second block, this
    /// computes the resulting split address and first-block length.
    pub fn compute_from_second_length(&self, second_length: u64) -> Result<SplitResult, String> {
        let block_size = self.block_size();
        if second_length == 0 || second_length >= block_size {
            return Err(format!(
                "Length must be less than original block size (0x{:x})",
                block_size
            ));
        }

        let second_start = Address::new(self.block_end.offset - second_length + 1);
        let first_end = Address::new(second_start.offset - 1);
        let first_length = first_end.offset - self.block_start.offset + 1;

        Ok(SplitResult {
            first_start: self.block_start,
            first_end,
            first_length,
            second_start,
            second_end: self.block_end,
            second_length,
        })
    }

    /// Compute the split result from the "first block end address" parameter.
    ///
    /// When the user enters a new end address for the first block.
    pub fn compute_from_first_end(&self, first_end: Address) -> Result<SplitResult, String> {
        if first_end.offset < self.block_start.offset {
            return Err("End address must be greater than start".into());
        }
        if first_end.offset >= self.block_end.offset {
            return Err(format!(
                "End address must be less than original block end ({})",
                self.block_end
            ));
        }

        let first_length = first_end.offset - self.block_start.offset + 1;
        let second_start = Address::new(first_end.offset + 1);
        let second_length = self.block_end.offset - second_start.offset + 1;

        Ok(SplitResult {
            first_start: self.block_start,
            first_end,
            first_length,
            second_start,
            second_end: self.block_end,
            second_length,
        })
    }

    /// Compute the split result from the "second block start address" parameter.
    ///
    /// When the user enters a start address for the second block.
    pub fn compute_from_second_start(&self, second_start: Address) -> Result<SplitResult, String> {
        if second_start.offset > self.block_end.offset {
            return Err("Start address must not be greater than end".into());
        }
        if second_start.offset <= self.block_start.offset {
            return Err(format!(
                "Start address must be greater than original block start ({})",
                self.block_start
            ));
        }

        let second_length = self.block_end.offset - second_start.offset + 1;
        let first_end = Address::new(second_start.offset - 1);
        let first_length = first_end.offset - self.block_start.offset + 1;

        Ok(SplitResult {
            first_start: self.block_start,
            first_end,
            first_length,
            second_start,
            second_end: self.block_end,
            second_length,
        })
    }

    /// Validate the model using the currently set split address.
    ///
    /// This is the primary validation entry point. Returns `Ok(SplitResult)`
    /// if the split is valid, or the specific validation error.
    pub fn validate(&mut self) -> Result<SplitResult, SplitValidationError> {
        let split_addr = match self.split_address {
            Some(a) => a,
            None => return Err(SplitValidationError::SplitAddressOutOfBounds),
        };

        // Validate split address is within block bounds
        if split_addr.offset <= self.block_start.offset {
            return Err(SplitValidationError::SplitAtStart);
        }
        if split_addr.offset > self.block_end.offset {
            return Err(SplitValidationError::SplitBeyondEnd);
        }

        // Validate new block name
        if self.new_block_name.is_empty() {
            return Err(SplitValidationError::MissingNewBlockName);
        }
        if self.new_block_name.chars().any(|c| (c as u32) < 0x20) {
            return Err(SplitValidationError::InvalidNewBlockName(
                self.new_block_name.clone(),
            ));
        }

        let first_end = Address::new(split_addr.offset - 1);
        let first_length = first_end.offset - self.block_start.offset + 1;
        let second_length = self.block_end.offset - split_addr.offset + 1;

        if first_length == 0 {
            return Err(SplitValidationError::InvalidFirstBlockLength);
        }
        if second_length == 0 {
            return Err(SplitValidationError::InvalidSecondBlockLength);
        }

        self.message.clear();

        Ok(SplitResult {
            first_start: self.block_start,
            first_end,
            first_length,
            second_start: split_addr,
            second_end: self.block_end,
            second_length,
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_new_model_defaults() {
        let model = SplitBlockModel::new(addr(0x1000), addr(0x3fff), ".text");
        assert_eq!(model.block_name(), ".text");
        assert_eq!(model.new_block_name(), ".text.split");
        assert_eq!(model.block_size(), 0x3000);
        assert!(model.split_address().is_none());
    }

    #[test]
    fn test_validate_with_valid_split() {
        let mut model = SplitBlockModel::new(addr(0x1000), addr(0x3fff), ".text");
        model.set_split_address(addr(0x2000));
        let result = model.validate();
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.first_start, addr(0x1000));
        assert_eq!(r.first_end, addr(0x1fff));
        assert_eq!(r.first_length, 0x1000);
        assert_eq!(r.second_start, addr(0x2000));
        assert_eq!(r.second_end, addr(0x3fff));
        assert_eq!(r.second_length, 0x2000);
    }

    #[test]
    fn test_validate_split_at_start_fails() {
        let mut model = SplitBlockModel::new(addr(0x1000), addr(0x3fff), ".text");
        model.set_split_address(addr(0x1000));
        let result = model.validate();
        assert_eq!(result.unwrap_err(), SplitValidationError::SplitAtStart);
    }

    #[test]
    fn test_validate_split_beyond_end_fails() {
        let mut model = SplitBlockModel::new(addr(0x1000), addr(0x3fff), ".text");
        model.set_split_address(addr(0x5000));
        let result = model.validate();
        assert_eq!(result.unwrap_err(), SplitValidationError::SplitBeyondEnd);
    }

    #[test]
    fn test_validate_empty_name_fails() {
        let mut model = SplitBlockModel::new(addr(0x1000), addr(0x3fff), ".text");
        model.set_split_address(addr(0x2000));
        model.set_new_block_name("");
        let result = model.validate();
        assert_eq!(
            result.unwrap_err(),
            SplitValidationError::MissingNewBlockName
        );
    }

    #[test]
    fn test_validate_control_char_name_fails() {
        let mut model = SplitBlockModel::new(addr(0x1000), addr(0x3fff), ".text");
        model.set_split_address(addr(0x2000));
        model.set_new_block_name("bad\x01name");
        let result = model.validate();
        assert!(matches!(
            result.unwrap_err(),
            SplitValidationError::InvalidNewBlockName(_)
        ));
    }

    #[test]
    fn test_validate_no_split_address_fails() {
        let mut model = SplitBlockModel::new(addr(0x1000), addr(0x3fff), ".text");
        let result = model.validate();
        assert_eq!(
            result.unwrap_err(),
            SplitValidationError::SplitAddressOutOfBounds
        );
    }

    #[test]
    fn test_compute_from_first_length() {
        let model = SplitBlockModel::new(addr(0x1000), addr(0x3fff), ".text");
        let result = model.compute_from_first_length(0x2000);
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.first_end, addr(0x2fff));
        assert_eq!(r.second_start, addr(0x3000));
        assert_eq!(r.second_length, 0x1000);
    }

    #[test]
    fn test_compute_from_first_length_zero_fails() {
        let model = SplitBlockModel::new(addr(0x1000), addr(0x3fff), ".text");
        assert!(model.compute_from_first_length(0).is_err());
    }

    #[test]
    fn test_compute_from_first_length_too_large_fails() {
        let model = SplitBlockModel::new(addr(0x1000), addr(0x3fff), ".text");
        assert!(model.compute_from_first_length(0x4000).is_err());
    }

    #[test]
    fn test_compute_from_second_length() {
        let model = SplitBlockModel::new(addr(0x1000), addr(0x3fff), ".text");
        let result = model.compute_from_second_length(0x1000);
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.second_start, addr(0x3000));
        assert_eq!(r.first_end, addr(0x2fff));
        assert_eq!(r.first_length, 0x2000);
    }

    #[test]
    fn test_compute_from_first_end() {
        let model = SplitBlockModel::new(addr(0x1000), addr(0x3fff), ".text");
        let result = model.compute_from_first_end(addr(0x27ff));
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.first_length, 0x1800);
        assert_eq!(r.second_start, addr(0x2800));
        assert_eq!(r.second_length, 0x1800);
    }

    #[test]
    fn test_compute_from_first_end_before_start_fails() {
        let model = SplitBlockModel::new(addr(0x1000), addr(0x3fff), ".text");
        assert!(model.compute_from_first_end(addr(0x500)).is_err());
    }

    #[test]
    fn test_compute_from_second_start() {
        let model = SplitBlockModel::new(addr(0x1000), addr(0x3fff), ".text");
        let result = model.compute_from_second_start(addr(0x2800));
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.first_end, addr(0x27ff));
        assert_eq!(r.second_length, 0x1800);
    }

    #[test]
    fn test_compute_from_second_start_at_block_start_fails() {
        let model = SplitBlockModel::new(addr(0x1000), addr(0x3fff), ".text");
        assert!(model.compute_from_second_start(addr(0x1000)).is_err());
    }

    #[test]
    fn test_compute_from_second_start_beyond_end_fails() {
        let model = SplitBlockModel::new(addr(0x1000), addr(0x3fff), ".text");
        assert!(model.compute_from_second_start(addr(0x5000)).is_err());
    }

    #[test]
    fn test_display_errors() {
        let err = SplitValidationError::SplitAtStart;
        assert!(!format!("{}", err).is_empty());

        let err = SplitValidationError::InvalidNewBlockName("bad".into());
        assert!(format!("{}", err).contains("bad"));
    }

    #[test]
    fn test_split_result_equality() {
        let r1 = SplitResult {
            first_start: addr(0x1000),
            first_end: addr(0x1fff),
            first_length: 0x1000,
            second_start: addr(0x2000),
            second_end: addr(0x3fff),
            second_length: 0x2000,
        };
        let r2 = r1.clone();
        assert_eq!(r1, r2);
    }
}
