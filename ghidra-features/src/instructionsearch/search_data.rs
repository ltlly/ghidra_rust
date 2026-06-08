//! Instruction search data loader.
//!
//! Ported from `ghidra.app.plugin.core.instructionsearch.model.InstructionSearchData`.
//!
//! Responsible for loading instructions from a program's address range and
//! building the combined mask/value arrays used for pattern matching.

use super::model::{InstructionMetadata, MaskContainer, MaskSettings, OperandMetadata};
use super::utils::InstructionSearchUtils;

/// Represents the state of the instruction search data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchState {
    /// Initial state, no data loaded.
    Empty,
    /// Instructions have been loaded from a program.
    Loaded,
    /// A combined mask has been built from the loaded instructions.
    Masked,
    /// An error occurred during loading or masking.
    Error,
}

/// Loads instructions from a program address range and builds combined
/// mask/value arrays for pattern searching.
///
/// Ported from `ghidra.app.plugin.core.instructionsearch.model.InstructionSearchData`.
///
/// # Usage
///
/// ```ignore
/// use ghidra_features::instructionsearch::search_data::InstructionSearchData;
/// use ghidra_features::instructionsearch::model::MaskSettings;
///
/// let mut data = InstructionSearchData::new();
/// data.set_mask_settings(MaskSettings::new(true, true, false));
/// // Load instructions from program...
/// ```
#[derive(Debug, Clone)]
pub struct InstructionSearchData {
    /// The loaded instruction metadata.
    instructions: Vec<InstructionMetadata>,
    /// The combined mask container (union of all instruction masks).
    combined_mask: Option<MaskContainer>,
    /// Current state.
    state: SearchState,
    /// Mask settings controlling what parts of instructions to mask.
    mask_settings: MaskSettings,
    /// The address range start (inclusive).
    start_address: Option<u64>,
    /// The address range end (inclusive).
    end_address: Option<u64>,
}

impl InstructionSearchData {
    /// Create a new empty instruction search data.
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
            combined_mask: None,
            state: SearchState::Empty,
            mask_settings: MaskSettings::default(),
            start_address: None,
            end_address: None,
        }
    }

    /// Get the current search state.
    pub fn state(&self) -> SearchState {
        self.state
    }

    /// Get the mask settings.
    pub fn mask_settings(&self) -> &MaskSettings {
        &self.mask_settings
    }

    /// Set the mask settings.
    pub fn set_mask_settings(&mut self, settings: MaskSettings) {
        self.mask_settings = settings;
    }

    /// Set the address range for loading.
    pub fn set_address_range(&mut self, start: u64, end: u64) {
        self.start_address = Some(start);
        self.end_address = Some(end);
    }

    /// Get the address range as (start, end).
    pub fn address_range(&self) -> Option<(u64, u64)> {
        match (self.start_address, self.end_address) {
            (Some(s), Some(e)) => Some((s, e)),
            _ => None,
        }
    }

    /// Add a single instruction to the data set.
    pub fn add_instruction(&mut self, instr: InstructionMetadata) {
        self.instructions.push(instr);
        self.state = SearchState::Loaded;
        // Invalidate combined mask
        self.combined_mask = None;
    }

    /// Add multiple instructions at once.
    pub fn add_instructions(&mut self, instrs: Vec<InstructionMetadata>) {
        self.instructions.extend(instrs);
        if !self.instructions.is_empty() {
            self.state = SearchState::Loaded;
        }
        self.combined_mask = None;
    }

    /// Get a reference to the loaded instructions.
    pub fn instructions(&self) -> &[InstructionMetadata] {
        &self.instructions
    }

    /// Get the number of loaded instructions.
    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    /// Check if any instructions are loaded.
    pub fn has_instructions(&self) -> bool {
        !self.instructions.is_empty()
    }

    /// Get the combined mask container.
    pub fn combined_mask(&self) -> Option<&MaskContainer> {
        self.combined_mask.as_ref()
    }

    /// Build the combined mask from all loaded instructions.
    ///
    /// This performs a bitwise OR across all instruction masks and
    /// ANDs the corresponding values. The result represents the
    /// combined pattern for matching.
    ///
    /// Returns true if the combined mask was successfully built.
    pub fn build_combined_mask(&mut self) -> bool {
        if self.instructions.is_empty() {
            self.state = SearchState::Error;
            return false;
        }

        let max_len = self
            .instructions
            .iter()
            .map(|i| i.mask_container.mask.len())
            .max()
            .unwrap_or(0);

        if max_len == 0 {
            self.state = SearchState::Error;
            return false;
        }

        let mut combined_mask = vec![0u8; max_len];
        let mut combined_value = vec![0u8; max_len];

        for instr in &self.instructions {
            let mc = &instr.mask_container;
            let len = mc.mask.len().min(max_len);
            for i in 0..len {
                combined_mask[i] |= mc.mask[i];
                // Only keep value bits where mask is on
                combined_value[i] |= mc.value[i] & mc.mask[i];
            }
        }

        // Apply mask settings
        self.apply_mask_settings(&mut combined_mask, &mut combined_value);

        self.combined_mask = Some(MaskContainer {
            mask: combined_mask,
            value: combined_value,
        });
        self.state = SearchState::Masked;
        true
    }

    /// Apply the current mask settings to the combined arrays.
    fn apply_mask_settings(&self, mask: &mut [u8], value: &mut [u8]) {
        // If addresses are masked, clear address-specific bytes
        if self.mask_settings.mask_addresses {
            // In most architectures, the first few bytes contain
            // the opcode prefix which encodes the address mode
            // Clearing first 2 bytes as a conservative approach
            let prefix_len = 2.min(mask.len());
            for i in 0..prefix_len {
                mask[i] = 0;
                value[i] = 0;
            }
        }

        // If scalars are masked, clear scalar operand bytes
        // Scalar operands are identified by their op_type having the SCALAR flag
        if self.mask_settings.mask_scalars {
            for instr in &self.instructions {
                for op in &instr.operands {
                    if Self::is_scalar_operand(op) {
                        if let Some(ref mc) = op.mask_container {
                            for i in 0..mc.mask.len().min(mask.len()) {
                                mask[i] &= !mc.mask[i];
                                value[i] &= !mc.mask[i];
                            }
                        }
                    }
                }
            }
        }

        // If operands are masked, clear all operand bytes
        if self.mask_settings.mask_operands {
            for instr in &self.instructions {
                for op in &instr.operands {
                    if let Some(ref mc) = op.mask_container {
                        for i in 0..mc.mask.len().min(mask.len()) {
                            mask[i] &= !mc.mask[i];
                            value[i] &= !mc.mask[i];
                        }
                    }
                }
            }
        }
    }

    /// Check whether an operand represents a scalar/immediate value.
    ///
    /// This checks the op_type flags for the SCALAR indicator.
    /// The SCALAR flag is bit 0x02 in Ghidra's operand type encoding.
    fn is_scalar_operand(op: &OperandMetadata) -> bool {
        // SCALAR flag = 0x02 in Ghidra's VarnodeFlags
        (op.op_type & 0x02) != 0
    }

    /// Clear all loaded data.
    pub fn clear(&mut self) {
        self.instructions.clear();
        self.combined_mask = None;
        self.state = SearchState::Empty;
        self.start_address = None;
        self.end_address = None;
    }

    /// Get the mnemonic of the first instruction, if any.
    pub fn first_mnemonic(&self) -> Option<&str> {
        self.instructions.first().map(|i| i.mnemonic.as_str())
    }

    /// Get all unique mnemonics in the loaded set.
    pub fn unique_mnemonics(&self) -> Vec<&str> {
        let mut mnemonics: Vec<&str> = self
            .instructions
            .iter()
            .map(|i| i.mnemonic.as_str())
            .collect();
        mnemonics.sort();
        mnemonics.dedup();
        mnemonics
    }

    /// Get the total number of bytes across all instructions.
    pub fn total_bytes(&self) -> usize {
        self.instructions.iter().map(|i| i.mask_container.len()).sum()
    }

    /// Check whether the combined mask has any wildcard (on) bits.
    pub fn has_wildcards(&self) -> bool {
        self.combined_mask
            .as_ref()
            .map(|mc| InstructionSearchUtils::contains_on_bit(&mc.mask))
            .unwrap_or(false)
    }
}

impl Default for InstructionSearchData {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;
    use crate::instructionsearch::model::MaskContainer;

    fn make_instr(address: u64, mnemonic: &str, bytes: &[u8]) -> InstructionMetadata {
        let mask = vec![0u8; bytes.len()];
        let mc = MaskContainer {
            mask,
            value: bytes.to_vec(),
        };
        InstructionMetadata {
            addr: Address::new(address),
            mnemonic: mnemonic.to_string(),
            is_instruction: true,
            mnemonic_masked: false,
            mask_container: mc,
            operands: Vec::new(),
        }
    }

    #[test]
    fn test_new_empty() {
        let data = InstructionSearchData::new();
        assert_eq!(data.state(), SearchState::Empty);
        assert!(!data.has_instructions());
        assert_eq!(data.instruction_count(), 0);
    }

    #[test]
    fn test_add_instruction() {
        let mut data = InstructionSearchData::new();
        data.add_instruction(make_instr(0x1000, "NOP", &[0x90]));
        assert_eq!(data.state(), SearchState::Loaded);
        assert!(data.has_instructions());
        assert_eq!(data.instruction_count(), 1);
    }

    #[test]
    fn test_add_instructions() {
        let mut data = InstructionSearchData::new();
        let instrs = vec![
            make_instr(0x1000, "NOP", &[0x90]),
            make_instr(0x1001, "RET", &[0xC3]),
        ];
        data.add_instructions(instrs);
        assert_eq!(data.instruction_count(), 2);
    }

    #[test]
    fn test_build_combined_mask() {
        let mut data = InstructionSearchData::new();
        data.add_instruction(make_instr(0x1000, "NOP", &[0x90]));
        data.add_instruction(make_instr(0x1001, "RET", &[0xC3]));
        assert!(data.build_combined_mask());
        assert_eq!(data.state(), SearchState::Masked);
        assert!(data.combined_mask().is_some());
    }

    #[test]
    fn test_build_combined_mask_empty() {
        let mut data = InstructionSearchData::new();
        assert!(!data.build_combined_mask());
        assert_eq!(data.state(), SearchState::Error);
    }

    #[test]
    fn test_address_range() {
        let mut data = InstructionSearchData::new();
        data.set_address_range(0x1000, 0x2000);
        assert_eq!(data.address_range(), Some((0x1000, 0x2000)));
    }

    #[test]
    fn test_first_mnemonic() {
        let mut data = InstructionSearchData::new();
        assert!(data.first_mnemonic().is_none());
        data.add_instruction(make_instr(0x1000, "MOV", &[0x89]));
        assert_eq!(data.first_mnemonic(), Some("MOV"));
    }

    #[test]
    fn test_unique_mnemonics() {
        let mut data = InstructionSearchData::new();
        data.add_instruction(make_instr(0x1000, "MOV", &[0x89]));
        data.add_instruction(make_instr(0x1002, "NOP", &[0x90]));
        data.add_instruction(make_instr(0x1003, "MOV", &[0x8B]));
        let mnemonics = data.unique_mnemonics();
        assert_eq!(mnemonics, vec!["MOV", "NOP"]);
    }

    #[test]
    fn test_total_bytes() {
        let mut data = InstructionSearchData::new();
        data.add_instruction(make_instr(0x1000, "MOV", &[0x89, 0xC3]));
        data.add_instruction(make_instr(0x1002, "NOP", &[0x90]));
        assert_eq!(data.total_bytes(), 3);
    }

    #[test]
    fn test_clear() {
        let mut data = InstructionSearchData::new();
        data.add_instruction(make_instr(0x1000, "NOP", &[0x90]));
        data.set_address_range(0x1000, 0x2000);
        data.clear();
        assert_eq!(data.state(), SearchState::Empty);
        assert!(!data.has_instructions());
        assert!(data.address_range().is_none());
    }

    #[test]
    fn test_mask_settings_default() {
        let data = InstructionSearchData::new();
        let settings = data.mask_settings();
        assert!(!settings.mask_addresses);
        assert!(!settings.mask_operands);
        assert!(!settings.mask_scalars);
    }

    #[test]
    fn test_has_wildcards_no_mask() {
        let data = InstructionSearchData::new();
        assert!(!data.has_wildcards());
    }

    #[test]
    fn test_has_wildcards_with_mask() {
        let mut data = InstructionSearchData::new();
        let mc = MaskContainer {
            mask: vec![0xFF, 0x00],
            value: vec![0x90, 0x00],
        };
        let instr = InstructionMetadata {
            addr: Address::new(0x1000),
            mnemonic: "TEST".to_string(),
            is_instruction: true,
            mnemonic_masked: false,
            mask_container: mc,
            operands: Vec::new(),
        };
        data.add_instruction(instr);
        data.build_combined_mask();
        assert!(data.has_wildcards());
    }

    #[test]
    fn test_is_scalar_operand() {
        let scalar_op = OperandMetadata {
            text_rep: "42".to_string(),
            op_type: 0x02, // SCALAR flag
            mask_container: None,
            masked: false,
        };
        assert!(InstructionSearchData::is_scalar_operand(&scalar_op));

        let reg_op = OperandMetadata {
            text_rep: "RAX".to_string(),
            op_type: 0x01,
            mask_container: None,
            masked: false,
        };
        assert!(!InstructionSearchData::is_scalar_operand(&reg_op));
    }
}
