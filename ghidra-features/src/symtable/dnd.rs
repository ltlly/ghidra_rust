//! Symbol drag-and-drop support -- ported from `SymbolDataFlavor`,
//! `SymbolTransferable`, and `SymbolTransferData`.
//!
//! Provides the data transfer types for dragging symbols between
//! the symbol table and other Ghidra components.

use std::fmt;

/// The data flavor for symbol transfers.
///
/// Ported from `SymbolDataFlavor.java`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolDataFlavor {
    /// A single symbol reference.
    SymbolReference,
    /// Multiple symbol references.
    SymbolReferenceList,
    /// A symbol name.
    SymbolName,
    /// A symbol address.
    SymbolAddress,
}

impl fmt::Display for SymbolDataFlavor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SymbolReference => write!(f, "SymbolReference"),
            Self::SymbolReferenceList => write!(f, "SymbolReferenceList"),
            Self::SymbolName => write!(f, "SymbolName"),
            Self::SymbolAddress => write!(f, "SymbolAddress"),
        }
    }
}

/// Transfer data for a single symbol.
///
/// Ported from `SymbolTransferData.java`.
#[derive(Debug, Clone)]
pub struct SymbolTransferData {
    /// The symbol name.
    name: String,
    /// The symbol address.
    address: u64,
    /// The symbol ID.
    id: u64,
    /// The namespace.
    namespace: String,
}

impl SymbolTransferData {
    /// Creates new symbol transfer data.
    pub fn new(
        name: impl Into<String>,
        address: u64,
        id: u64,
        namespace: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            address,
            id,
            namespace: namespace.into(),
        }
    }

    /// Returns the symbol name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the symbol address.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Returns the symbol ID.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Returns the namespace.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
}

/// A transferable container for symbol data.
///
/// Ported from `SymbolTransferable.java`.
#[derive(Debug, Clone)]
pub struct SymbolTransferable {
    /// The flavor of this transfer.
    flavor: SymbolDataFlavor,
    /// The symbols being transferred.
    symbols: Vec<SymbolTransferData>,
}

impl SymbolTransferable {
    /// Creates a new transferable with a single symbol.
    pub fn single(data: SymbolTransferData) -> Self {
        Self {
            flavor: SymbolDataFlavor::SymbolReference,
            symbols: vec![data],
        }
    }

    /// Creates a new transferable with multiple symbols.
    pub fn multiple(data: Vec<SymbolTransferData>) -> Self {
        Self {
            flavor: if data.len() == 1 {
                SymbolDataFlavor::SymbolReference
            } else {
                SymbolDataFlavor::SymbolReferenceList
            },
            symbols: data,
        }
    }

    /// Returns the flavor.
    pub fn flavor(&self) -> SymbolDataFlavor {
        self.flavor
    }

    /// Returns the symbols.
    pub fn symbols(&self) -> &[SymbolTransferData] {
        &self.symbols
    }

    /// Returns the number of symbols.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Returns whether the transferable is empty.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_flavor_display() {
        assert_eq!(
            SymbolDataFlavor::SymbolReference.to_string(),
            "SymbolReference"
        );
        assert_eq!(SymbolDataFlavor::SymbolName.to_string(), "SymbolName");
    }

    #[test]
    fn test_transfer_data() {
        let data = SymbolTransferData::new("main", 0x401000, 1, "Global");
        assert_eq!(data.name(), "main");
        assert_eq!(data.address(), 0x401000);
        assert_eq!(data.namespace(), "Global");
    }

    #[test]
    fn test_transferable_single() {
        let data = SymbolTransferData::new("main", 0x401000, 1, "Global");
        let transfer = SymbolTransferable::single(data);
        assert_eq!(transfer.flavor(), SymbolDataFlavor::SymbolReference);
        assert_eq!(transfer.len(), 1);
    }

    #[test]
    fn test_transferable_multiple() {
        let data = vec![
            SymbolTransferData::new("a", 0x1000, 1, "Global"),
            SymbolTransferData::new("b", 0x2000, 2, "Global"),
        ];
        let transfer = SymbolTransferable::multiple(data);
        assert_eq!(transfer.flavor(), SymbolDataFlavor::SymbolReferenceList);
        assert_eq!(transfer.len(), 2);
        assert!(!transfer.is_empty());
    }
}
