//! `SLMaskControl` -- controls what portions of instructions are masked.
//!
//! Ported from `ghidra.features.base.memsearch.mnemonic.SLMaskControl`.

/// Represents a filter for a single instruction defining what portions
/// will be masked in the search.
///
/// Ported from `SLMaskControl.java`.
#[derive(Debug, Clone, Copy)]
pub struct SLMaskControl {
    use_operands: bool,
    use_constants: bool,
}

impl SLMaskControl {
    /// Create a new mask control.
    pub fn new(use_operands: bool, use_constants: bool) -> Self {
        Self {
            use_operands,
            use_constants,
        }
    }

    /// Returns true if operands should be included in the search mask.
    pub fn use_operands(&self) -> bool {
        self.use_operands
    }

    /// Returns true if constants should be included in the search mask.
    pub fn use_constants(&self) -> bool {
        self.use_constants
    }
}

impl Default for SLMaskControl {
    fn default() -> Self {
        Self {
            use_operands: false,
            use_constants: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_control_default() {
        let mc = SLMaskControl::default();
        assert!(!mc.use_operands());
        assert!(!mc.use_constants());
    }

    #[test]
    fn test_mask_control_custom() {
        let mc = SLMaskControl::new(true, true);
        assert!(mc.use_operands());
        assert!(mc.use_constants());
    }
}
