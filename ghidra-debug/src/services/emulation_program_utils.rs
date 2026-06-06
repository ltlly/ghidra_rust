//! Program emulation utilities.
//!
//! Ported from Ghidra's `ProgramEmulationUtils`.
//!
//! Provides utility functions for setting up and managing program emulation.

/// Known register context XML for emulation.
pub const EMU_CTX_XML: &str = "";
/// Address of emulation start.
pub const EMULATION_STARTED_AT: u64 = 0;
/// Stack block name.
pub const BLOCK_NAME_STACK: &str = "Stack";
/// Default stack size (1 MB).
pub const DEFAULT_STACK_SIZE: u64 = 0x100000;
/// Default stack base for x86-64.
pub const DEFAULT_STACK_BASE_X86_64: u64 = 0x7FFF_0000;

/// Check if an address is in the stack region.
pub fn is_stack_address(address: u64, stack_base: u64, stack_size: u64) -> bool {
    address >= stack_base && address < stack_base + stack_size
}

/// Check if an address is in the code region.
pub fn is_code_address(address: u64, code_base: u64, code_size: u64) -> bool {
    address >= code_base && address < code_base + code_size
}

/// Compute the initial stack pointer for a given stack base and size.
pub fn initial_stack_pointer(stack_base: u64, stack_size: u64) -> u64 {
    stack_base + stack_size - 8
}

/// Classify a memory region by name based on common conventions.
pub fn classify_region<'a>(address: u64, regions: &[(u64, u64, &'a str)]) -> Option<&'a str> {
    for &(base, size, name) in regions {
        if address >= base && address < base + size {
            return Some(name);
        }
    }
    None
}

/// Default memory region layout for a typical x86-64 program.
/// Regions are ordered most-specific-first so overlapping ranges
/// (e.g., stack within heap address space) are matched correctly.
pub fn default_x86_64_regions() -> Vec<(u64, u64, &'static str)> {
    vec![
        (DEFAULT_STACK_BASE_X86_64, DEFAULT_STACK_SIZE, "stack"),
        (0x400000, 0x100000, "code"),
        (0x600000, 0x100000, "data"),
        (0x7000_0000, 0x1000_0000, "heap"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_stack_address() {
        assert!(is_stack_address(0x7FFF_FFF0, 0x7FFF_0000, 0x10000));
        assert!(!is_stack_address(0x400000, 0x7FFF_0000, 0x10000));
        assert!(is_stack_address(0x7FFF_0000, 0x7FFF_0000, 0x10000));
        assert!(!is_stack_address(0x7FFF_0000 + 0x10000, 0x7FFF_0000, 0x10000));
    }

    #[test]
    fn test_is_code_address() {
        assert!(is_code_address(0x401000, 0x400000, 0x100000));
        assert!(!is_code_address(0x700000, 0x400000, 0x100000));
    }

    #[test]
    fn test_initial_stack_pointer() {
        let sp = initial_stack_pointer(0x7FFF_0000, 0x10000);
        assert_eq!(sp, 0x7FFF_0000 + 0x10000 - 8);
    }

    #[test]
    fn test_classify_region() {
        let regions = vec![
            (0x400000, 0x100000, "code"),
            (0x7FFF_0000, 0x10000, "stack"),
        ];
        assert_eq!(classify_region(0x401000, &regions), Some("code"));
        assert_eq!(classify_region(0x7FFF_5000, &regions), Some("stack"));
        assert_eq!(classify_region(0xDEADBEEF, &regions), None);
    }

    #[test]
    fn test_default_x86_64_regions() {
        let regions = default_x86_64_regions();
        assert_eq!(regions.len(), 4);
        assert_eq!(classify_region(0x401000, &regions), Some("code"));
        assert_eq!(classify_region(0x601000, &regions), Some("data"));
        // Stack is checked first, so it takes priority over overlapping heap range
        assert_eq!(classify_region(0x7FFF_5000, &regions), Some("stack"));
        // Address in heap but not in stack
        assert_eq!(classify_region(0x7000_1000, &regions), Some("heap"));
        // Address beyond all regions
        assert_eq!(classify_region(0x9000_0000, &regions), None);
    }
}
