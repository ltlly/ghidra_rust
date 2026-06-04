//! Decompiler location types.
//!
//! Port of Ghidra's `ghidra.app.decompiler.location` package.

use ghidra_core::addr::Address;

/// Information about a cursor position in the decompiler output.
#[derive(Debug, Clone)]
pub struct DecompilerLocationInfo {
    /// Entry point of the function.
    pub function_entry: Address,
    /// The token text at the cursor position.
    pub token_text: Option<String>,
    /// The ClangNodeId at the cursor position.
    pub node_id: Option<usize>,
    /// The line number.
    pub line_number: usize,
    /// The column number within the line.
    pub column: usize,
}

impl DecompilerLocationInfo {
    /// Create a new DecompilerLocationInfo.
    pub fn new(function_entry: Address) -> Self {
        Self {
            function_entry,
            token_text: None,
            node_id: None,
            line_number: 0,
            column: 0,
        }
    }
}

/// Represents a location in the Decompiler.
///
/// This interface allows the Decompiler to subclass more general
/// ProgramLocations while adding more detailed Decompiler information.
#[derive(Debug, Clone)]
pub struct DecompilerLocation {
    /// Entry point of the function.
    pub function_entry: Address,
    /// C code markup root (ClangNodeId).
    pub markup_root: Option<usize>,
    /// The token text at the cursor.
    pub token_text: Option<String>,
    /// The address represented by this location.
    pub address: Address,
    /// Location info.
    pub info: DecompilerLocationInfo,
}

impl DecompilerLocation {
    /// Create a new DecompilerLocation.
    pub fn new(function_entry: Address, address: Address) -> Self {
        Self {
            function_entry,
            markup_root: None,
            token_text: None,
            address,
            info: DecompilerLocationInfo::new(function_entry),
        }
    }

    /// Get the function entry point.
    pub fn function_entry_point(&self) -> Address {
        self.function_entry
    }

    /// Get the address.
    pub fn get_address(&self) -> Address {
        self.address
    }
}

/// A default implementation of DecompilerLocation.
#[derive(Debug, Clone)]
pub struct DefaultDecompilerLocation {
    /// Base location data.
    pub location: DecompilerLocation,
}

impl DefaultDecompilerLocation {
    /// Create a new DefaultDecompilerLocation.
    pub fn new(function_entry: Address, address: Address) -> Self {
        Self {
            location: DecompilerLocation::new(function_entry, address),
        }
    }
}

/// A location for a function name token in the decompiler.
#[derive(Debug, Clone)]
pub struct FunctionNameDecompilerLocation {
    /// Base location data.
    pub location: DecompilerLocation,
    /// The function name at this location.
    pub function_name: String,
}

impl FunctionNameDecompilerLocation {
    /// Create a new FunctionNameDecompilerLocation.
    pub fn new(function_entry: Address, address: Address, function_name: String) -> Self {
        Self {
            location: DecompilerLocation::new(function_entry, address),
            function_name,
        }
    }
}

/// A location for a variable token in the decompiler.
#[derive(Debug, Clone)]
pub struct VariableDecompilerLocation {
    /// Base location data.
    pub location: DecompilerLocation,
    /// Variable name.
    pub variable_name: String,
    /// Variable storage address.
    pub storage_address: Address,
}

impl VariableDecompilerLocation {
    /// Create a new VariableDecompilerLocation.
    pub fn new(
        function_entry: Address,
        address: Address,
        variable_name: String,
        storage_address: Address,
    ) -> Self {
        Self {
            location: DecompilerLocation::new(function_entry, address),
            variable_name,
            storage_address,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompiler_location() {
        let loc = DecompilerLocation::new(Address::new(0x1000), Address::new(0x1010));
        assert_eq!(loc.function_entry_point(), Address::new(0x1000));
        assert_eq!(loc.get_address(), Address::new(0x1010));
    }

    #[test]
    fn test_default_location() {
        let loc = DefaultDecompilerLocation::new(Address::new(0x1000), Address::new(0x1020));
        assert_eq!(loc.location.function_entry, Address::new(0x1000));
    }

    #[test]
    fn test_function_name_location() {
        let loc = FunctionNameDecompilerLocation::new(
            Address::new(0x1000),
            Address::new(0x1000),
            "main".to_string(),
        );
        assert_eq!(loc.function_name, "main");
    }

    #[test]
    fn test_variable_location() {
        let loc = VariableDecompilerLocation::new(
            Address::new(0x1000),
            Address::new(0x1010),
            "x".to_string(),
            Address::new(0x8),
        );
        assert_eq!(loc.variable_name, "x");
        assert_eq!(loc.storage_address, Address::new(0x8));
    }

    #[test]
    fn test_location_info() {
        let info = DecompilerLocationInfo::new(Address::new(0x1000));
        assert_eq!(info.function_entry, Address::new(0x1000));
        assert_eq!(info.line_number, 0);
        assert_eq!(info.column, 0);
    }
}
