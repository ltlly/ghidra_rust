//! Varnode context types for p-code analysis.
//!
//! Ported from `VarnodeContext.java`, `SymbolVarnodeContext.java`, and
//! `MemLocContext.java` in the Lisa extension.

/// Context for a raw varnode (register or memory location).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarnodeContext {
    /// The address space name (e.g., "register", "ram", "unique").
    pub space: String,
    /// The offset within the address space.
    pub offset: u64,
    /// The size in bytes.
    pub size: u32,
}

impl VarnodeContext {
    /// Create a new varnode context.
    pub fn new(space: impl Into<String>, offset: u64, size: u32) -> Self {
        Self {
            space: space.into(),
            offset,
            size,
        }
    }

    /// Check if this varnode is a register.
    pub fn is_register(&self) -> bool {
        self.space == "register"
    }

    /// Check if this varnode is in the unique (temporary) space.
    pub fn is_unique(&self) -> bool {
        self.space == "unique"
    }
}

/// Context for a symbol-backed varnode (named variable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolVarnodeContext {
    /// The underlying varnode.
    pub varnode: VarnodeContext,
    /// The symbol name.
    pub symbol_name: String,
    /// Whether the symbol is a parameter.
    pub is_parameter: bool,
}

impl SymbolVarnodeContext {
    /// Create a new symbol varnode context.
    pub fn new(
        varnode: VarnodeContext,
        name: impl Into<String>,
        is_parameter: bool,
    ) -> Self {
        Self {
            varnode,
            symbol_name: name.into(),
            is_parameter,
        }
    }
}

/// Context for a memory location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemLocContext {
    /// The memory address.
    pub address: u64,
    /// The size in bytes.
    pub size: u32,
    /// Whether this is a stack-relative address.
    pub is_stack: bool,
}

impl MemLocContext {
    /// Create a new memory location context.
    pub fn new(address: u64, size: u32) -> Self {
        Self {
            address,
            size,
            is_stack: false,
        }
    }

    /// Create a stack-relative memory location.
    pub fn stack(address: u64, size: u32) -> Self {
        Self {
            address,
            size,
            is_stack: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varnode_context() {
        let vc = VarnodeContext::new("register", 0, 8);
        assert!(vc.is_register());
        assert!(!vc.is_unique());
    }

    #[test]
    fn test_varnode_unique() {
        let vc = VarnodeContext::new("unique", 0x100, 4);
        assert!(vc.is_unique());
        assert!(!vc.is_register());
    }

    #[test]
    fn test_symbol_varnode() {
        let vc = VarnodeContext::new("register", 0, 8);
        let sv = SymbolVarnodeContext::new(vc, "RAX", false);
        assert_eq!(sv.symbol_name, "RAX");
        assert!(!sv.is_parameter);
    }

    #[test]
    fn test_mem_loc() {
        let ml = MemLocContext::new(0x1000, 4);
        assert!(!ml.is_stack);

        let stack = MemLocContext::stack(0x7fff_fff0, 8);
        assert!(stack.is_stack);
    }
}
