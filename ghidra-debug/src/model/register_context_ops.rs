//! Register context space and operations.
//!
//! Ported from Ghidra's `ghidra.trace.model.context.TraceRegisterContextSpaceOps`
//! and `TraceRegisterContextSpace`.
//!
//! Provides the interface for managing register contexts (disassembly context)
//! in a trace, including context register values over address ranges and snaps.

use serde::{Deserialize, Serialize};

use super::Lifespan;

/// A context register value entry for a specific register with a mask.
///
/// This is distinct from `model::register_context::TraceRegisterValue`
/// which stores raw byte values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskedContextValue {
    /// The register name.
    pub register: String,
    /// The value.
    pub value: u64,
    /// The mask of valid bits.
    pub mask: u64,
}

impl MaskedContextValue {
    /// Create a new masked context value.
    pub fn new(register: impl Into<String>, value: u64, mask: u64) -> Self {
        Self {
            register: register.into(),
            value,
            mask,
        }
    }

    /// Get the effective value (value & mask).
    pub fn effective_value(&self) -> u64 {
        self.value & self.mask
    }

    /// Whether all bits are valid.
    pub fn is_fully_valid(&self) -> bool {
        self.mask == u64::MAX
    }
}

/// A context register value with its associated range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextMaskedRange {
    /// The address space name.
    pub space: String,
    /// The minimum address.
    pub min_address: u64,
    /// The maximum address.
    pub max_address: u64,
    /// The register name.
    pub register: String,
    /// The value.
    pub value: u64,
    /// The mask.
    pub mask: u64,
    /// The lifespan.
    pub lifespan: Lifespan,
}

impl ContextMaskedRange {
    /// Create a new context address range.
    pub fn new(
        space: impl Into<String>,
        min_address: u64,
        max_address: u64,
        register: impl Into<String>,
        value: u64,
        mask: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            space: space.into(),
            min_address,
            max_address,
            register: register.into(),
            value,
            mask,
            lifespan,
        }
    }

    /// Whether this range contains the given address.
    pub fn contains_address(&self, address: u64) -> bool {
        address >= self.min_address && address <= self.max_address
    }

    /// Get the effective value.
    pub fn effective_value(&self) -> u64 {
        self.value & self.mask
    }
}

/// Operations for managing register context in a trace.
///
/// Ported from Ghidra's `TraceRegisterContextSpaceOps` interface.
pub trait TraceRegisterContextSpaceOps {
    /// Get the value of a context register at a given address and snap.
    fn get_context_value(&self, snap: i64, address: u64, register: &str) -> Option<u64>;

    /// Set the value of a context register for a given address range and lifespan.
    fn set_context_value(
        &mut self,
        lifespan: &Lifespan,
        min_address: u64,
        max_address: u64,
        register: &str,
        value: u64,
        mask: u64,
    );

    /// Get all context register values at a given address and snap.
    fn get_context_register_values(
        &self,
        snap: i64,
        address: u64,
    ) -> Vec<MaskedContextValue>;

    /// Get all context register names.
    fn get_context_register_names(&self) -> Vec<String>;

    /// Clear a context register value for a given address range and lifespan.
    fn clear_context_value(
        &mut self,
        lifespan: &Lifespan,
        min_address: u64,
        max_address: u64,
        register: &str,
    );
}

/// A register context space that manages context values for a specific address space.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceRegisterContextSpace {
    /// The address space name.
    pub address_space: String,
    /// The context register values, each covering an address range.
    pub entries: Vec<ContextMaskedRange>,
}

impl TraceRegisterContextSpace {
    /// Create a new register context space.
    pub fn new(address_space: impl Into<String>) -> Self {
        Self {
            address_space: address_space.into(),
            entries: Vec::new(),
        }
    }

    /// Get the address space name.
    pub fn address_space(&self) -> &str {
        &self.address_space
    }

    /// Add a context register value for an address range.
    pub fn set_value(
        &mut self,
        lifespan: Lifespan,
        min_address: u64,
        max_address: u64,
        register: &str,
        value: u64,
        mask: u64,
    ) {
        self.entries.push(ContextMaskedRange::new(
            &self.address_space,
            min_address,
            max_address,
            register,
            value,
            mask,
            lifespan,
        ));
    }

    /// Get the value of a context register at a given address and snap.
    pub fn get_value(&self, snap: i64, address: u64, register: &str) -> Option<u64> {
        // Find the most specific entry (latest added wins)
        self.entries
            .iter()
            .rev()
            .find(|e| {
                e.register == register
                    && e.contains_address(address)
                    && e.lifespan.contains(snap)
            })
            .map(|e| e.effective_value())
    }

    /// Get all context register values at a given address and snap.
    pub fn get_all_values(&self, snap: i64, address: u64) -> Vec<MaskedContextValue> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        for entry in self.entries.iter().rev() {
            if entry.contains_address(address)
                && entry.lifespan.contains(snap)
                && seen.insert(entry.register.clone())
            {
                result.push(MaskedContextValue::new(
                    &entry.register,
                    entry.value,
                    entry.mask,
                ));
            }
        }
        result
    }

    /// Get all context register names.
    pub fn register_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .entries
            .iter()
            .map(|e| e.register.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        names.sort();
        names
    }

    /// Clear context register values matching the given parameters.
    pub fn clear_value(
        &mut self,
        lifespan: &Lifespan,
        min_address: u64,
        max_address: u64,
        register: &str,
    ) {
        self.entries.retain(|e| {
            !(e.register == register
                && e.lifespan.intersects(lifespan)
                && e.min_address <= max_address
                && e.max_address >= min_address)
        });
    }
}

impl TraceRegisterContextSpaceOps for TraceRegisterContextSpace {
    fn get_context_value(&self, snap: i64, address: u64, register: &str) -> Option<u64> {
        self.get_value(snap, address, register)
    }

    fn set_context_value(
        &mut self,
        lifespan: &Lifespan,
        min_address: u64,
        max_address: u64,
        register: &str,
        value: u64,
        mask: u64,
    ) {
        self.set_value(lifespan.clone(), min_address, max_address, register, value, mask);
    }

    fn get_context_register_values(
        &self,
        snap: i64,
        address: u64,
    ) -> Vec<MaskedContextValue> {
        self.get_all_values(snap, address)
    }

    fn get_context_register_names(&self) -> Vec<String> {
        self.register_names()
    }

    fn clear_context_value(
        &mut self,
        lifespan: &Lifespan,
        min_address: u64,
        max_address: u64,
        register: &str,
    ) {
        self.clear_value(lifespan, min_address, max_address, register);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_space_basic() {
        let space = TraceRegisterContextSpace::new("ram");
        assert_eq!(space.address_space(), "ram");
        assert!(space.entries.is_empty());
    }

    #[test]
    fn test_context_set_get() {
        let mut space = TraceRegisterContextSpace::new("ram");
        space.set_value(Lifespan::span(0, 10), 0x1000, 0x2000, "TMode", 1, 1);

        assert_eq!(space.get_value(5, 0x1500, "TMode"), Some(1));
        assert_eq!(space.get_value(15, 0x1500, "TMode"), None);
        assert_eq!(space.get_value(5, 0x3000, "TMode"), None);
    }

    #[test]
    fn test_context_multiple_registers() {
        let mut space = TraceRegisterContextSpace::new("ram");
        space.set_value(Lifespan::span(0, 10), 0x1000, 0x2000, "TMode", 1, 1);
        space.set_value(Lifespan::span(0, 10), 0x1000, 0x2000, "ISAMode", 0, 1);

        let values = space.get_all_values(5, 0x1500);
        assert_eq!(values.len(), 2);

        let mut names = space.register_names();
        names.sort();
        assert_eq!(names, vec!["ISAMode", "TMode"]);
    }

    #[test]
    fn test_context_clear() {
        let mut space = TraceRegisterContextSpace::new("ram");
        space.set_value(Lifespan::span(0, 10), 0x1000, 0x2000, "TMode", 1, 1);

        space.clear_value(&Lifespan::span(5, 8), 0x1500, 0x1800, "TMode");
        assert!(space.entries.is_empty());
    }

    #[test]
    fn test_context_register_value() {
        let val = MaskedContextValue::new("TMode", 0xFF, 0x0F);
        assert_eq!(val.effective_value(), 0x0F);
        assert!(!val.is_fully_valid());

        let full = MaskedContextValue::new("TMode", 1, u64::MAX);
        assert!(full.is_fully_valid());
    }

    #[test]
    fn test_context_address_range() {
        let range = ContextMaskedRange::new("ram", 0x1000, 0x2000, "TMode", 1, 1, Lifespan::span(0, 10));
        assert!(range.contains_address(0x1500));
        assert!(!range.contains_address(0x3000));
        assert_eq!(range.effective_value(), 1);
    }

    #[test]
    fn test_context_operations_trait() {
        let mut space = TraceRegisterContextSpace::new("ram");
        let ops: &mut dyn TraceRegisterContextSpaceOps = &mut space;

        ops.set_context_value(&Lifespan::span(0, 10), 0x1000, 0x2000, "TMode", 1, 1);
        assert_eq!(ops.get_context_value(5, 0x1500, "TMode"), Some(1));

        ops.clear_context_value(&Lifespan::span(5, 8), 0x1500, 0x1800, "TMode");
        assert!(ops.get_context_value(5, 0x1500, "TMode").is_none());
    }

    #[test]
    fn test_context_later_entry_wins() {
        let mut space = TraceRegisterContextSpace::new("ram");
        space.set_value(Lifespan::span(0, 10), 0x1000, 0x2000, "TMode", 0, 1);
        space.set_value(Lifespan::span(0, 10), 0x1000, 0x2000, "TMode", 1, 1);

        assert_eq!(space.get_value(5, 0x1500, "TMode"), Some(1));
    }
}
