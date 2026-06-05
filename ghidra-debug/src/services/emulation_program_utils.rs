//! Program emulation utilities.
//!
//! Ported from Ghidra's `ProgramEmulationUtils`.

/// Known register context XML for emulation.
pub const EMU_CTX_XML: &str = "";
/// Address of emulation start.
pub const EMULATION_STARTED_AT: u64 = 0;
/// Stack block name.
pub const BLOCK_NAME_STACK: &str = "Stack";

/// Check if an address is in the stack region.
pub fn is_stack_address(address: u64, stack_base: u64, stack_size: u64) -> bool {
    address >= stack_base && address < stack_base + stack_size
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_is_stack_address() {
        assert!(is_stack_address(0x7FFF_FFF0, 0x7FFF_0000, 0x10000));
        assert!(!is_stack_address(0x400000, 0x7FFF_0000, 0x10000));
    }
}
