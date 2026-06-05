//! TraceCodeOperations - operations for querying and manipulating code listing.
//!
//! Ported from Ghidra's `ghidra.trace.model.listing.TraceCodeOperations`.

use super::Lifespan;
use super::listing::TraceCodeUnit;

/// The set of operations available on the code listing.
///
/// This provides read-only queries over instructions and data units.
pub trait TraceCodeOperations {
    /// Get the space name this operates on.
    fn space_name(&self) -> &str;

    /// Get all instructions at a given snap.
    fn get_instructions(&self, snap: i64) -> Vec<&TraceCodeUnit>;

    /// Get all defined data at a given snap.
    fn get_defined_data(&self, snap: i64) -> Vec<&TraceCodeUnit>;

    /// Get a code unit at a specific address and snap.
    fn get_code_unit_at(&self, snap: i64, address: u64) -> Option<&TraceCodeUnit>;

    /// Get instructions in an address range.
    fn get_instructions_in_range(
        &self,
        snap: i64,
        min_addr: u64,
        max_addr: u64,
    ) -> Vec<&TraceCodeUnit>;

    /// Get defined data in an address range.
    fn get_defined_data_in_range(
        &self,
        snap: i64,
        min_addr: u64,
        max_addr: u64,
    ) -> Vec<&TraceCodeUnit>;

    /// Get the code unit containing a given address.
    fn get_code_unit_containing(&self, snap: i64, address: u64) -> Option<&TraceCodeUnit>;

    /// Count instructions at a snap.
    fn instruction_count(&self, snap: i64) -> usize {
        self.get_instructions(snap).len()
    }

    /// Count defined data units at a snap.
    fn defined_data_count(&self, snap: i64) -> usize {
        self.get_defined_data(snap).len()
    }

    /// Check if an address has an instruction at a snap.
    fn has_instruction_at(&self, snap: i64, address: u64) -> bool {
        self.get_code_unit_at(snap, address)
            .map_or(false, |u| {
                u.unit_type == super::listing::CodeUnitType::Instruction
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_operations_trait() {
        // Trait test - ensures the trait can be implemented
        struct MockCodeOps;
        impl TraceCodeOperations for MockCodeOps {
            fn space_name(&self) -> &str { "ram" }
            fn get_instructions(&self, _snap: i64) -> Vec<&TraceCodeUnit> { vec![] }
            fn get_defined_data(&self, _snap: i64) -> Vec<&TraceCodeUnit> { vec![] }
            fn get_code_unit_at(&self, _snap: i64, _addr: u64) -> Option<&TraceCodeUnit> { None }
            fn get_instructions_in_range(&self, _: i64, _: u64, _: u64) -> Vec<&TraceCodeUnit> { vec![] }
            fn get_defined_data_in_range(&self, _: i64, _: u64, _: u64) -> Vec<&TraceCodeUnit> { vec![] }
            fn get_code_unit_containing(&self, _snap: i64, _addr: u64) -> Option<&TraceCodeUnit> { None }
        }

        let ops = MockCodeOps;
        assert_eq!(ops.space_name(), "ram");
        assert_eq!(ops.instruction_count(0), 0);
        assert!(!ops.has_instruction_at(0, 0x1000));
    }
}
