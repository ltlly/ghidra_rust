//! Instruction search model types.
//!
//! Ported from `ghidra.app.plugin.core.instructionsearch.model`.

use ghidra_core::Address;

// ============================================================================
// MaskContainer -- mask/value byte arrays for a mnemonic or operand
// ============================================================================

/// Contains the mask/value byte pair for a single mnemonic or operand.
///
/// The mask array controls which bits are significant in the search: a bit
/// set to `1` in the mask means the corresponding bit in the value array
/// must match; a `0` means "don't care" (wildcard).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskContainer {
    /// Mask bytes -- `1` bits indicate must-match positions.
    pub mask: Vec<u8>,
    /// Value bytes -- the expected pattern.
    pub value: Vec<u8>,
}

impl MaskContainer {
    /// Create a new mask container.
    ///
    /// # Errors
    ///
    /// Returns an error if mask and value have different lengths or are empty.
    pub fn new(mask: Vec<u8>, value: Vec<u8>) -> Result<Self, String> {
        if mask.is_empty() || value.is_empty() {
            return Err("Mask container: mask and/or value arrays cannot be empty".into());
        }
        if mask.len() != value.len() {
            return Err(format!(
                "Mask container: mask ({}) and value ({}) arrays must be same size",
                mask.len(),
                value.len()
            ));
        }
        Ok(Self { mask, value })
    }

    /// Return the mask as a binary string (one '0'/'1' per bit).
    pub fn mask_as_binary_string(&self) -> String {
        self.mask
            .iter()
            .map(|b| format!("{:08b}", b))
            .collect::<String>()
    }

    /// Return the value as a binary string.
    pub fn value_as_binary_string(&self) -> String {
        self.value
            .iter()
            .map(|b| format!("{:08b}", b))
            .collect::<String>()
    }

    /// Combined binary representation with `.` for masked-out bits.
    pub fn to_binary_string(&self) -> String {
        let val_str = self.value_as_binary_string();
        let mask_str = self.mask_as_binary_string();
        super::utils::InstructionSearchUtils::format_search_string(&val_str, &mask_str)
            .unwrap_or_else(|_| val_str)
    }

    /// Return the byte length of this container.
    pub fn len(&self) -> usize {
        self.mask.len()
    }

    /// Return `true` if the container is empty.
    pub fn is_empty(&self) -> bool {
        self.mask.is_empty()
    }
}

// ============================================================================
// OperandMetadata -- metadata for a single operand
// ============================================================================

/// Holds information about a single operand in an instruction.
#[derive(Debug, Clone, Default)]
pub struct OperandMetadata {
    /// Text representation of the operand (e.g. `"RAX"`, `[RIP+0x10]`).
    pub text_rep: String,
    /// Operand type flags (architecture-specific integer encoding).
    pub op_type: u32,
    /// The mask/value pair for this operand.
    pub mask_container: Option<MaskContainer>,
    /// Whether this operand is masked (wildcard).
    pub masked: bool,
}

// ============================================================================
// InstructionMetadata -- metadata for a single instruction
// ============================================================================

/// Data container for all mask information about a single instruction.
#[derive(Debug, Clone)]
pub struct InstructionMetadata {
    /// Address of this instruction.
    pub addr: Address,
    /// Text representation (mnemonic).
    pub mnemonic: String,
    /// Whether this is a real instruction (vs. data element).
    pub is_instruction: bool,
    /// Whether the mnemonic portion is masked.
    pub mnemonic_masked: bool,
    /// The mask/value pair for the full instruction.
    pub mask_container: MaskContainer,
    /// Operand metadata list.
    pub operands: Vec<OperandMetadata>,
}

impl InstructionMetadata {
    /// Create a new instruction metadata with the given mask container.
    pub fn new(mask_container: MaskContainer) -> Self {
        Self {
            addr: Address::new(0),
            mnemonic: String::new(),
            is_instruction: true,
            mnemonic_masked: false,
            mask_container,
            operands: Vec::new(),
        }
    }

    /// Whether the mnemonic portion is masked.
    pub fn is_masked(&self) -> bool {
        self.mnemonic_masked
    }

    /// Compute the effective mask/value by combining the mnemonic mask
    /// and per-operand masks according to the current mask settings.
    pub fn get_effective_mask(&self) -> MaskContainer {
        let mut temp_mask = vec![0u8; self.mask_container.mask.len()];
        let mut temp_value = vec![0u8; self.mask_container.value.len()];

        // Mnemonic
        if !self.mnemonic_masked {
            temp_value.copy_from_slice(&self.mask_container.value);
            temp_mask.copy_from_slice(&self.mask_container.mask);
        }

        // Operands
        for operand in &self.operands {
            if operand.masked {
                continue;
            }
            if let Some(ref mc) = operand.mask_container {
                let op_mask = &mc.mask;
                let op_value = &mc.value;
                for i in 0..op_mask.len().min(temp_mask.len()) {
                    temp_mask[i] |= op_mask[i];
                    temp_value[i] |= op_value[i];
                }
            }
        }

        MaskContainer {
            mask: temp_mask,
            value: temp_value,
        }
    }
}

// ============================================================================
// MaskSettings -- which components to mask
// ============================================================================

/// Settings controlling which instruction components are masked during search.
#[derive(Debug, Clone)]
pub struct MaskSettings {
    /// Mask address operands.
    pub mask_addresses: bool,
    /// Mask register and other operands.
    pub mask_operands: bool,
    /// Mask scalar/immediate operands.
    pub mask_scalars: bool,
}

impl MaskSettings {
    /// Create new mask settings.
    pub fn new(mask_addresses: bool, mask_operands: bool, mask_scalars: bool) -> Self {
        Self {
            mask_addresses,
            mask_operands,
            mask_scalars,
        }
    }

    /// Reset all mask settings to false.
    pub fn clear(&mut self) {
        self.mask_addresses = false;
        self.mask_operands = false;
        self.mask_scalars = false;
    }
}

impl Default for MaskSettings {
    fn default() -> Self {
        Self {
            mask_addresses: false,
            mask_operands: false,
            mask_scalars: false,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_container_new() {
        let mc = MaskContainer::new(vec![0xFF, 0x00], vec![0xAB, 0xCD]);
        assert!(mc.is_ok());
        let mc = mc.unwrap();
        assert_eq!(mc.len(), 2);
    }

    #[test]
    fn test_mask_container_mismatched_lengths() {
        let mc = MaskContainer::new(vec![0xFF], vec![0xAB, 0xCD]);
        assert!(mc.is_err());
    }

    #[test]
    fn test_mask_container_empty() {
        let mc = MaskContainer::new(vec![], vec![]);
        assert!(mc.is_err());
    }

    #[test]
    fn test_mask_binary_string() {
        let mc = MaskContainer::new(vec![0b1010_1010], vec![0b1111_0000]).unwrap();
        assert_eq!(mc.mask_as_binary_string(), "10101010");
        assert_eq!(mc.value_as_binary_string(), "11110000");
    }

    #[test]
    fn test_to_binary_string_with_masking() {
        let mc = MaskContainer::new(vec![0b1111_0000], vec![0b1010_0000]).unwrap();
        let s = mc.to_binary_string();
        // bits 7-4 are value-matched, bits 3-0 are wildcards
        assert_eq!(s, "1010....");
    }

    #[test]
    fn test_instruction_metadata_effective_mask() {
        let mc = MaskContainer::new(vec![0xFF, 0xFF], vec![0x48, 0x89]).unwrap();
        let mut meta = InstructionMetadata::new(mc);
        meta.mnemonic_masked = false;
        // Operand that overrides byte 1
        let op_mc = MaskContainer::new(vec![0x00, 0xF0], vec![0x00, 0x50]).unwrap();
        meta.operands.push(OperandMetadata {
            text_rep: "RAX".into(),
            op_type: 1,
            mask_container: Some(op_mc),
            masked: false,
        });
        let effective = meta.get_effective_mask();
        assert_eq!(effective.mask, vec![0xFF, 0xFF]);
        assert_eq!(effective.value, vec![0x48, 0xD9]); // 0x89 | 0x50 = 0xD9
    }

    #[test]
    fn test_mask_settings_default() {
        let ms = MaskSettings::default();
        assert!(!ms.mask_addresses);
        assert!(!ms.mask_operands);
        assert!(!ms.mask_scalars);
    }

    #[test]
    fn test_mask_settings_clear() {
        let mut ms = MaskSettings::new(true, true, true);
        ms.clear();
        assert!(!ms.mask_addresses);
        assert!(!ms.mask_operands);
        assert!(!ms.mask_scalars);
    }
}
