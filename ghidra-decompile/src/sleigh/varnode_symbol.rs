//! SLEIGH varnode symbol: global register and memory definitions.
//!
//! A [`VarnodeSymbol`] represents a named global varnode -- a register or
//! memory location defined in the `.slaspec` file. For example:
//!
//! ```text
//! define register space register type=register_size=4;
//! define register hex offset=0 size=4 [ EAX EBX ECX EDX ];
//! ```
//!
//! Each of `EAX`, `EBX`, etc. becomes a `VarnodeSymbol` with a fixed
//! address space, offset, and size.
//!
//! # Key Types
//! - [`VarnodeSymbol`] -- a global varnode with fixed space/offset/size

use serde::{Deserialize, Serialize};
use std::fmt;

use super::sleigh_symbol::{Location, SymbolType};

// ---------------------------------------------------------------------------
// VarnodeSymbol
// ---------------------------------------------------------------------------

/// A global varnode symbol: a named register or memory location.
///
/// `VarnodeSymbol` is a `PatternlessSymbol` -- it has no pattern expression
/// and always resolves to a constant value of 0 in pattern contexts. Its
/// primary purpose is to define a named storage location that can be
/// referenced in P-code templates.
///
/// The varnode is defined by:
/// - `space_name` -- the address space (e.g., "register", "ram")
/// - `offset` -- the byte offset within the space
/// - `size` -- the size in bytes
///
/// # Example
///
/// In a `.slaspec` file:
/// ```text
/// define register space register type=register_size=4;
/// define register hex offset=0x0 size=4 [ EAX ];
/// ```
///
/// This creates a `VarnodeSymbol` for `EAX` with:
/// - `space_name = "register"`
/// - `offset = 0x0`
/// - `size = 4`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VarnodeSymbol {
    /// Symbol name (e.g., "EAX")
    pub name: String,
    /// Symbol id
    pub id: usize,
    /// Scope id
    pub scope_id: usize,
    /// Source location
    pub location: Location,
    /// Address space name
    pub space_name: String,
    /// Address space index (for compact encoding)
    pub space_index: u32,
    /// Byte offset within the address space
    pub offset: u64,
    /// Size in bytes
    pub size: usize,
    /// Whether this varnode is a context register
    pub is_context: bool,
}

impl VarnodeSymbol {
    /// Create a new varnode symbol.
    pub fn new(
        name: impl Into<String>,
        location: Location,
        space_name: impl Into<String>,
        space_index: u32,
        offset: u64,
        size: usize,
    ) -> Self {
        Self {
            name: name.into(),
            id: 0,
            scope_id: 0,
            location,
            space_name: space_name.into(),
            space_index,
            offset,
            size,
            is_context: false,
        }
    }

    /// Create a register varnode symbol.
    pub fn register(
        name: impl Into<String>,
        location: Location,
        offset: u64,
        size: usize,
    ) -> Self {
        Self::new(name, location, "register", 0, offset, size)
    }

    /// Create a RAM varnode symbol.
    pub fn ram(
        name: impl Into<String>,
        location: Location,
        offset: u64,
        size: usize,
    ) -> Self {
        Self::new(name, location, "ram", 1, offset, size)
    }

    /// Returns the symbol type.
    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::Varnode
    }

    /// Mark this varnode as a context register.
    pub fn mark_as_context(&mut self) {
        self.is_context = true;
    }

    /// Returns the end offset (offset + size - 1).
    pub fn end_offset(&self) -> u64 {
        self.offset + self.size as u64 - 1
    }

    /// Returns `true` if this varnode overlaps with another.
    pub fn overlaps_with(&self, other: &VarnodeSymbol) -> bool {
        if self.space_name != other.space_name {
            return false;
        }
        self.offset <= other.end_offset() && other.offset <= self.end_offset()
    }

    /// Collect local values (for internal spaces).
    pub fn collect_local_values(&self, space_is_internal: bool) -> Option<u64> {
        if space_is_internal {
            Some(self.offset)
        } else {
            None
        }
    }
}

impl fmt::Display for VarnodeSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}[{}:0x{:x},{}]",
            self.name, self.space_name, self.space_index, self.offset, self.size
        )
    }
}

impl PartialEq for VarnodeSymbol {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for VarnodeSymbol {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varnode_symbol_new() {
        let sym = VarnodeSymbol::new(
            "EAX",
            Location::unknown(),
            "register",
            0,
            0x0,
            4,
        );
        assert_eq!(sym.name, "EAX");
        assert_eq!(sym.space_name, "register");
        assert_eq!(sym.offset, 0x0);
        assert_eq!(sym.size, 4);
        assert!(!sym.is_context);
    }

    #[test]
    fn test_varnode_symbol_register() {
        let sym = VarnodeSymbol::register("ESP", Location::unknown(), 0x4, 4);
        assert_eq!(sym.space_name, "register");
        assert_eq!(sym.offset, 0x4);
        assert_eq!(sym.size, 4);
    }

    #[test]
    fn test_varnode_symbol_ram() {
        let sym = VarnodeSymbol::ram("mem", Location::unknown(), 0x1000, 8);
        assert_eq!(sym.space_name, "ram");
        assert_eq!(sym.offset, 0x1000);
        assert_eq!(sym.size, 8);
    }

    #[test]
    fn test_varnode_symbol_type() {
        let sym = VarnodeSymbol::register("EAX", Location::unknown(), 0, 4);
        assert_eq!(sym.symbol_type(), SymbolType::Varnode);
    }

    #[test]
    fn test_varnode_mark_as_context() {
        let mut sym = VarnodeSymbol::register("ctx", Location::unknown(), 0, 4);
        assert!(!sym.is_context);
        sym.mark_as_context();
        assert!(sym.is_context);
    }

    #[test]
    fn test_varnode_end_offset() {
        let sym = VarnodeSymbol::register("EAX", Location::unknown(), 0x10, 4);
        assert_eq!(sym.end_offset(), 0x13);
    }

    #[test]
    fn test_varnode_overlaps() {
        let a = VarnodeSymbol::register("A", Location::unknown(), 0x0, 4);
        let b = VarnodeSymbol::register("B", Location::unknown(), 0x2, 4);
        let c = VarnodeSymbol::register("C", Location::unknown(), 0x4, 4);

        assert!(a.overlaps_with(&b)); // [0..3] overlaps [2..5]
        assert!(!a.overlaps_with(&c)); // [0..3] does not overlap [4..7]
        assert!(b.overlaps_with(&c)); // [2..5] overlaps [4..7]
    }

    #[test]
    fn test_varnode_overlaps_different_space() {
        let a = VarnodeSymbol::register("A", Location::unknown(), 0x0, 4);
        let b = VarnodeSymbol::ram("B", Location::unknown(), 0x0, 4);
        assert!(!a.overlaps_with(&b));
    }

    #[test]
    fn test_varnode_display() {
        let sym = VarnodeSymbol::register("EAX", Location::unknown(), 0x0, 4);
        let s = format!("{}", sym);
        assert!(s.contains("EAX"));
        assert!(s.contains("register"));
        assert!(s.contains("0x0"));
        assert!(s.contains("4"));
    }

    #[test]
    fn test_varnode_equality() {
        let a = VarnodeSymbol::register("EAX", Location::unknown(), 0x0, 4);
        let b = VarnodeSymbol::register("EAX", Location::unknown(), 0x4, 4);
        let c = VarnodeSymbol::register("EBX", Location::unknown(), 0x0, 4);

        assert_eq!(a, b); // Same name
        assert_ne!(a, c); // Different name
    }
}
