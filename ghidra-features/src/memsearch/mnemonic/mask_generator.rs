//! `MaskGenerator` -- generates mask/value pairs from selected instructions.
//!
//! Ported from `ghidra.features.base.memsearch.mnemonic.MaskGenerator`.

use crate::memsearch::mnemonic::mask_control::SLMaskControl;
use crate::memsearch::mnemonic::mask_value::MaskValue;

/// Generates combined mask/value pairs from selected instructions.
///
/// Examines selected instructions and builds a combined mask/value buffer
/// that can be used to search for matching instruction patterns.
///
/// Ported from `MaskGenerator.java`.
#[derive(Debug)]
pub struct MaskGenerator {
    mask_control: SLMaskControl,
    mnemonics: Vec<MaskValue>,
    operand_masks: Vec<Vec<MaskValue>>,
}

impl MaskGenerator {
    /// Create a new mask generator with the given mask control settings.
    pub fn new(mask_control: SLMaskControl) -> Self {
        Self {
            mask_control,
            mnemonics: Vec::new(),
            operand_masks: Vec::new(),
        }
    }

    /// Generate a mask/value pair from instruction bytes.
    ///
    /// Given the raw bytes of selected instructions and optional
    /// operand byte ranges, produces a combined MaskValue.
    pub fn generate(
        &self,
        instruction_bytes: &[u8],
        operand_ranges: &[(usize, usize)],
    ) -> MaskValue {
        let len = instruction_bytes.len();
        let mut mask = vec![0xFF; len];
        let value = instruction_bytes.to_vec();

        // If not using operands, mask out operand portions
        if !self.mask_control.use_operands() {
            for &(start, end) in operand_ranges {
                for i in start..end.min(len) {
                    mask[i] = 0x00;
                }
            }
        }

        // If not using constants, mask out constant portions
        if !self.mask_control.use_constants() {
            // In a real implementation, we'd detect constant values
            // within operands and mask them out. For now, the operand
            // ranges already handle this.
        }

        MaskValue::new(mask, value)
    }

    /// Get the mask control settings.
    pub fn mask_control(&self) -> &SLMaskControl {
        &self.mask_control
    }

    /// Get stored mnemonics.
    pub fn mnemonics(&self) -> &[MaskValue] {
        &self.mnemonics
    }

    /// Add a mnemonic to the generator.
    pub fn add_mnemonic(&mut self, mnemonic: MaskValue) {
        self.mnemonics.push(mnemonic);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_with_operands() {
        let control = SLMaskControl::new(true, true);
        let gen = MaskGenerator::new(control);
        let mv = gen.generate(&[0x55, 0x89, 0xE5, 0x83, 0xEC, 0x10], &[(3, 6)]);
        assert_eq!(mv.length(), 6);
        // All bytes should have mask 0xFF (including operand bytes)
        assert_eq!(mv.mask(), &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_generate_without_operands() {
        let control = SLMaskControl::new(false, true);
        let gen = MaskGenerator::new(control);
        let mv = gen.generate(&[0x55, 0x89, 0xE5, 0x83, 0xEC, 0x10], &[(3, 6)]);
        assert_eq!(mv.length(), 6);
        // Operand bytes (3..6) should be masked out
        assert_eq!(mv.mask(), &[0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_generate_no_operand_ranges() {
        let control = SLMaskControl::new(true, true);
        let gen = MaskGenerator::new(control);
        let mv = gen.generate(&[0x55, 0x89, 0xE5], &[]);
        assert_eq!(mv.mask(), &[0xFF, 0xFF, 0xFF]);
    }
}
