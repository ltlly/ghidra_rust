//! Wildcard assembly semantic resolution.
//!
//! Ported from Ghidra's `ghidra.asm.wild.sem` Java package.

/// Resolved assembly patterns.
#[derive(Debug, Clone)]
pub struct WildAssemblyResolvedPatterns {
    /// The resolved instruction bytes.
    pub bytes: Vec<u8>,
    /// The resolved mask (which bits are fixed).
    pub mask: Vec<u8>,
    /// Context register changes.
    pub context_changes: Vec<ContextChange>,
}

impl WildAssemblyResolvedPatterns {
    pub fn new() -> Self {
        Self { bytes: Vec::new(), mask: Vec::new(), context_changes: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl Default for WildAssemblyResolvedPatterns {
    fn default() -> Self { Self::new() }
}

/// A change to a context register.
#[derive(Debug, Clone)]
pub struct ContextChange {
    /// Register name.
    pub register: String,
    /// Bit range start.
    pub bit_start: u32,
    /// Bit range end.
    pub bit_end: u32,
    /// New value.
    pub value: u64,
}

/// Resolution factory for creating resolved patterns.
#[derive(Debug)]
pub struct WildAssemblyResolutionFactory;

impl WildAssemblyResolutionFactory {
    pub fn create_resolved() -> WildAssemblyResolvedPatterns {
        WildAssemblyResolvedPatterns::new()
    }
}

/// Operand state for tree resolution.
#[derive(Debug, Clone)]
pub struct WildAssemblyOperandState {
    /// The operand index.
    pub index: usize,
    /// Resolved value (if any).
    pub value: Option<u64>,
    /// Whether this is a wildcard.
    pub is_wildcard: bool,
}

impl WildAssemblyOperandState {
    pub fn new(index: usize) -> Self {
        Self { index, value: None, is_wildcard: true }
    }

    pub fn with_value(mut self, value: u64) -> Self {
        self.value = Some(value);
        self.is_wildcard = false;
        self
    }
}

/// NOP state for empty/placeholder assembly operations.
#[derive(Debug, Clone, Default)]
pub struct WildAssemblyNopState;

impl WildAssemblyNopState {
    pub fn new() -> Self { Self }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolved_patterns() {
        let rp = WildAssemblyResolvedPatterns::new();
        assert!(rp.is_empty());
    }

    #[test]
    fn test_operand_state() {
        let os = WildAssemblyOperandState::new(0);
        assert!(os.is_wildcard);
        assert!(os.value.is_none());

        let os2 = os.with_value(0xFF);
        assert!(!os2.is_wildcard);
        assert_eq!(os2.value, Some(0xFF));
    }

    #[test]
    fn test_context_change() {
        let cc = ContextChange {
            register: "CS".into(),
            bit_start: 0,
            bit_end: 3,
            value: 1,
        };
        assert_eq!(cc.register, "CS");
    }

    #[test]
    fn test_resolution_factory() {
        let rp = WildAssemblyResolutionFactory::create_resolved();
        assert!(rp.is_empty());
    }

    #[test]
    fn test_nop_state() {
        let nop = WildAssemblyNopState::new();
        let _ = format!("{:?}", nop);
    }
}
