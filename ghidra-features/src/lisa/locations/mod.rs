//! P-code location types.
//!
//! Ported from the `ghidra.lisa.pcode.locations` package in the
//! Lisa extension.
//!
//! Locations represent positions within the p-code IR: either
//! instruction-level or p-code-operation-level.

/// A p-code location within an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PcodeLocation {
    /// The address of the containing instruction.
    pub address: u64,
    /// The index of the p-code operation within the instruction.
    pub op_index: u32,
}

impl PcodeLocation {
    /// Create a new p-code location.
    pub fn new(address: u64, op_index: u32) -> Self {
        Self { address, op_index }
    }

    /// The first p-code operation at an address.
    pub fn at_address(address: u64) -> Self {
        Self {
            address,
            op_index: 0,
        }
    }
}

impl std::fmt::Display for PcodeLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}:{}", self.address, self.op_index)
    }
}

/// An instruction-level location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InstLocation {
    /// The instruction address.
    pub address: u64,
    /// The length of the instruction in bytes.
    pub length: u32,
}

impl InstLocation {
    /// Create a new instruction location.
    pub fn new(address: u64, length: u32) -> Self {
        Self { address, length }
    }

    /// The address immediately after this instruction.
    pub fn next_address(&self) -> u64 {
        self.address + self.length as u64
    }
}

impl std::fmt::Display for InstLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}+{}", self.address, self.length)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcode_location() {
        let loc = PcodeLocation::new(0x1000, 2);
        assert_eq!(loc.address, 0x1000);
        assert_eq!(loc.op_index, 2);
        assert_eq!(loc.to_string(), "0x1000:2");
    }

    #[test]
    fn test_pcode_location_at_address() {
        let loc = PcodeLocation::at_address(0x4000);
        assert_eq!(loc.op_index, 0);
    }

    #[test]
    fn test_inst_location() {
        let loc = InstLocation::new(0x1000, 3);
        assert_eq!(loc.next_address(), 0x1003);
    }
}
