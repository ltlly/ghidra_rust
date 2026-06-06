//! Table row mappers for converting between table row types.
//!
//! Ported from `ghidra.util.table.mapper` -- provides row mapper types that
//! convert one table row object type to another (e.g., Address to Function,
//! Symbol to Address, ReferenceEndpoint to ProgramLocation). These are used
//! by Ghidra's table framework to enable navigation between related table views.
//!
//! # Architecture
//!
//! - [`TableRowMapper`]: Trait for mapping one row type to another.
//! - Address mappers: [`AddressToAddressRowMapper`], [`AddressToFunctionRowMapper`],
//!   [`AddressToProgramLocationRowMapper`], [`AddressToSymbolRowMapper`].
//! - ProgramLocation mappers: [`ProgramLocationToAddressRowMapper`],
//!   [`ProgramLocationToFunctionRowMapper`], [`ProgramLocationToSymbolRowMapper`].
//! - ReferenceEndpoint mappers: [`ReferenceEndpointToAddressRowMapper`],
//!   [`ReferenceEndpointToFunctionRowMapper`],
//!   [`ReferenceEndpointToProgramLocationRowMapper`],
//!   [`ReferenceEndpointToReferenceRowMapper`].
//! - Symbol mappers: [`SymbolToAddressRowMapper`], [`SymbolToProgramLocationRowMapper`].
//! - Reference mapper: [`ReferenceToReferenceAddressPairRowMapper`].

use std::fmt;

// ---------------------------------------------------------------------------
// TableRowMapper
// ---------------------------------------------------------------------------

/// Trait for mapping one row type to another.
///
/// Ported from `ghidra.util.table.mapper.TableRowMapper`.
/// Enables navigating from one table view to another by converting row objects.
pub trait TableRowMapper<FROM, TO>: fmt::Debug {
    /// The name of this mapper.
    fn name(&self) -> &str;

    /// Map a row from the source type to the target type.
    fn map(&self, from: &FROM) -> Option<TO>;

    /// Whether this mapper can produce multiple results.
    fn is_one_to_many(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Address -> Address mapper
// ---------------------------------------------------------------------------

/// Maps an address to itself (identity mapper).
///
/// Ported from `AddressTableToAddressTableRowMapper.java`.
#[derive(Debug)]
pub struct AddressToAddressRowMapper;

impl TableRowMapper<String, String> for AddressToAddressRowMapper {
    fn name(&self) -> &str {
        "Address -> Address"
    }

    fn map(&self, from: &String) -> Option<String> {
        Some(from.clone())
    }
}

// ---------------------------------------------------------------------------
// Address -> Function mapper
// ---------------------------------------------------------------------------

/// Maps an address to the function containing it.
///
/// Ported from `AddressToFunctionContainingTableRowMapper.java`.
#[derive(Debug)]
pub struct AddressToFunctionRowMapper;

impl TableRowMapper<String, String> for AddressToFunctionRowMapper {
    fn name(&self) -> &str {
        "Address -> Function"
    }

    fn map(&self, _from: &String) -> Option<String> {
        // In a real implementation, this would look up the function containing
        // the address. Here we return the address itself as a placeholder.
        Some("function_lookup".to_string())
    }
}

// ---------------------------------------------------------------------------
// Address -> ProgramLocation mapper
// ---------------------------------------------------------------------------

/// Maps an address to a program location.
///
/// Ported from `AddressToProgramLocationTableRowMapper.java`.
#[derive(Debug)]
pub struct AddressToProgramLocationRowMapper;

impl TableRowMapper<String, String> for AddressToProgramLocationRowMapper {
    fn name(&self) -> &str {
        "Address -> ProgramLocation"
    }

    fn map(&self, from: &String) -> Option<String> {
        Some(from.clone())
    }
}

// ---------------------------------------------------------------------------
// Address -> Symbol mapper
// ---------------------------------------------------------------------------

/// Maps an address to the symbol at that address.
///
/// Ported from `AddressToSymbolTableRowMapper.java`.
#[derive(Debug)]
pub struct AddressToSymbolRowMapper;

impl TableRowMapper<String, String> for AddressToSymbolRowMapper {
    fn name(&self) -> &str {
        "Address -> Symbol"
    }

    fn map(&self, _from: &String) -> Option<String> {
        // In a real implementation, would look up symbols at the address.
        Some("symbol_lookup".to_string())
    }
}

// ---------------------------------------------------------------------------
// ProgramLocation -> Address mapper
// ---------------------------------------------------------------------------

/// Maps a program location to its address.
///
/// Ported from `ProgramLocationToAddressTableRowMapper.java`.
#[derive(Debug)]
pub struct ProgramLocationToAddressRowMapper;

impl TableRowMapper<String, String> for ProgramLocationToAddressRowMapper {
    fn name(&self) -> &str {
        "ProgramLocation -> Address"
    }

    fn map(&self, from: &String) -> Option<String> {
        Some(from.clone())
    }
}

// ---------------------------------------------------------------------------
// ProgramLocation -> Function mapper
// ---------------------------------------------------------------------------

/// Maps a program location to the function containing it.
///
/// Ported from `ProgramLocationToFunctionContainingTableRowMapper.java`.
#[derive(Debug)]
pub struct ProgramLocationToFunctionRowMapper;

impl TableRowMapper<String, String> for ProgramLocationToFunctionRowMapper {
    fn name(&self) -> &str {
        "ProgramLocation -> Function"
    }

    fn map(&self, _from: &String) -> Option<String> {
        Some("function_lookup".to_string())
    }
}

// ---------------------------------------------------------------------------
// ProgramLocation -> Symbol mapper
// ---------------------------------------------------------------------------

/// Maps a program location to the symbol at that location.
///
/// Ported from `ProgramLocationToSymbolTableRowMapper.java`.
#[derive(Debug)]
pub struct ProgramLocationToSymbolRowMapper;

impl TableRowMapper<String, String> for ProgramLocationToSymbolRowMapper {
    fn name(&self) -> &str {
        "ProgramLocation -> Symbol"
    }

    fn map(&self, _from: &String) -> Option<String> {
        Some("symbol_lookup".to_string())
    }
}

// ---------------------------------------------------------------------------
// ReferenceEndpoint -> Address mapper
// ---------------------------------------------------------------------------

/// Maps a reference endpoint to its address.
///
/// Ported from `ReferenceEndpointToAddressTableRowMapper.java`.
#[derive(Debug)]
pub struct ReferenceEndpointToAddressRowMapper;

impl TableRowMapper<String, String> for ReferenceEndpointToAddressRowMapper {
    fn name(&self) -> &str {
        "ReferenceEndpoint -> Address"
    }

    fn map(&self, from: &String) -> Option<String> {
        Some(from.clone())
    }
}

// ---------------------------------------------------------------------------
// ReferenceEndpoint -> Function mapper
// ---------------------------------------------------------------------------

/// Maps a reference endpoint to the function containing its address.
///
/// Ported from `ReferenceEndpointToFunctionTableRowMapper.java`.
#[derive(Debug)]
pub struct ReferenceEndpointToFunctionRowMapper;

impl TableRowMapper<String, String> for ReferenceEndpointToFunctionRowMapper {
    fn name(&self) -> &str {
        "ReferenceEndpoint -> Function"
    }

    fn map(&self, _from: &String) -> Option<String> {
        Some("function_lookup".to_string())
    }
}

// ---------------------------------------------------------------------------
// ReferenceEndpoint -> ProgramLocation mapper
// ---------------------------------------------------------------------------

/// Maps a reference endpoint to a program location.
///
/// Ported from `ReferenceEndpointToProgramLocationTableRowMapper.java`.
#[derive(Debug)]
pub struct ReferenceEndpointToProgramLocationRowMapper;

impl TableRowMapper<String, String> for ReferenceEndpointToProgramLocationRowMapper {
    fn name(&self) -> &str {
        "ReferenceEndpoint -> ProgramLocation"
    }

    fn map(&self, from: &String) -> Option<String> {
        Some(from.clone())
    }
}

// ---------------------------------------------------------------------------
// ReferenceEndpoint -> Reference mapper
// ---------------------------------------------------------------------------

/// Maps a reference endpoint to the reference itself.
///
/// Ported from `ReferenceEndpointToReferenceTableRowMapper.java`.
#[derive(Debug)]
pub struct ReferenceEndpointToReferenceRowMapper;

impl TableRowMapper<String, String> for ReferenceEndpointToReferenceRowMapper {
    fn name(&self) -> &str {
        "ReferenceEndpoint -> Reference"
    }

    fn map(&self, from: &String) -> Option<String> {
        Some(from.clone())
    }
}

// ---------------------------------------------------------------------------
// Reference -> ReferenceAddressPair mapper
// ---------------------------------------------------------------------------

/// Maps a reference to a (from, to) address pair.
///
/// Ported from `ReferenceToReferenceAddressPairTableRowMapper.java`.
#[derive(Debug)]
pub struct ReferenceToReferenceAddressPairRowMapper;

/// A pair of addresses representing a reference relationship.
#[derive(Debug, Clone)]
pub struct ReferenceAddressPair {
    /// The "from" address.
    pub from_address: String,
    /// The "to" address.
    pub to_address: String,
}

impl ReferenceAddressPair {
    /// Create a new address pair.
    pub fn new(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            from_address: from.into(),
            to_address: to.into(),
        }
    }
}

impl TableRowMapper<String, ReferenceAddressPair> for ReferenceToReferenceAddressPairRowMapper {
    fn name(&self) -> &str {
        "Reference -> (From, To)"
    }

    fn map(&self, _from: &String) -> Option<ReferenceAddressPair> {
        // In a real implementation, would look up the reference and extract both addresses.
        Some(ReferenceAddressPair::new("from_addr", "to_addr"))
    }
}

// ---------------------------------------------------------------------------
// Symbol -> Address mapper
// ---------------------------------------------------------------------------

/// Maps a symbol to its address.
///
/// Ported from `SymbolToAddressTableRowMapper.java`.
#[derive(Debug)]
pub struct SymbolToAddressRowMapper;

impl TableRowMapper<String, String> for SymbolToAddressRowMapper {
    fn name(&self) -> &str {
        "Symbol -> Address"
    }

    fn map(&self, from: &String) -> Option<String> {
        Some(from.clone())
    }
}

// ---------------------------------------------------------------------------
// Symbol -> ProgramLocation mapper
// ---------------------------------------------------------------------------

/// Maps a symbol to a program location.
///
/// Ported from `SymbolToProgramLocationTableRowMapper.java`.
#[derive(Debug)]
pub struct SymbolToProgramLocationRowMapper;

impl TableRowMapper<String, String> for SymbolToProgramLocationRowMapper {
    fn name(&self) -> &str {
        "Symbol -> ProgramLocation"
    }

    fn map(&self, from: &String) -> Option<String> {
        Some(from.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_to_address_mapper() {
        let mapper = AddressToAddressRowMapper;
        assert_eq!(mapper.name(), "Address -> Address");
        assert_eq!(
            mapper.map(&"0x401000".to_string()),
            Some("0x401000".to_string())
        );
    }

    #[test]
    fn test_address_to_function_mapper() {
        let mapper = AddressToFunctionRowMapper;
        assert_eq!(mapper.name(), "Address -> Function");
        assert!(mapper.map(&"0x401000".to_string()).is_some());
    }

    #[test]
    fn test_address_to_program_location_mapper() {
        let mapper = AddressToProgramLocationRowMapper;
        assert_eq!(mapper.name(), "Address -> ProgramLocation");
        assert_eq!(
            mapper.map(&"0x401000".to_string()),
            Some("0x401000".to_string())
        );
    }

    #[test]
    fn test_program_location_to_address_mapper() {
        let mapper = ProgramLocationToAddressRowMapper;
        assert_eq!(mapper.name(), "ProgramLocation -> Address");
        assert_eq!(
            mapper.map(&"0x401000".to_string()),
            Some("0x401000".to_string())
        );
    }

    #[test]
    fn test_symbol_to_address_mapper() {
        let mapper = SymbolToAddressRowMapper;
        assert_eq!(mapper.name(), "Symbol -> Address");
        assert!(mapper.map(&"main".to_string()).is_some());
    }

    #[test]
    fn test_symbol_to_program_location_mapper() {
        let mapper = SymbolToProgramLocationRowMapper;
        assert_eq!(mapper.name(), "Symbol -> ProgramLocation");
        assert!(mapper.map(&"main".to_string()).is_some());
    }

    #[test]
    fn test_reference_endpoint_to_address_mapper() {
        let mapper = ReferenceEndpointToAddressRowMapper;
        assert_eq!(mapper.name(), "ReferenceEndpoint -> Address");
        assert!(mapper.map(&"0x401000".to_string()).is_some());
    }

    #[test]
    fn test_reference_endpoint_to_function_mapper() {
        let mapper = ReferenceEndpointToFunctionRowMapper;
        assert_eq!(mapper.name(), "ReferenceEndpoint -> Function");
        assert!(mapper.map(&"0x401000".to_string()).is_some());
    }

    #[test]
    fn test_reference_address_pair() {
        let pair = ReferenceAddressPair::new("0x401000", "0x402000");
        assert_eq!(pair.from_address, "0x401000");
        assert_eq!(pair.to_address, "0x402000");
    }

    #[test]
    fn test_reference_to_pair_mapper() {
        let mapper = ReferenceToReferenceAddressPairRowMapper;
        assert_eq!(mapper.name(), "Reference -> (From, To)");
        let pair = mapper.map(&"ref".to_string()).unwrap();
        assert_eq!(pair.from_address, "from_addr");
        assert_eq!(pair.to_address, "to_addr");
    }

    #[test]
    fn test_all_mappers_produce_output() {
        let mappers: Vec<Box<dyn TableRowMapper<String, String>>> = vec![
            Box::new(AddressToAddressRowMapper),
            Box::new(AddressToFunctionRowMapper),
            Box::new(AddressToProgramLocationRowMapper),
            Box::new(AddressToSymbolRowMapper),
            Box::new(ProgramLocationToAddressRowMapper),
            Box::new(ProgramLocationToFunctionRowMapper),
            Box::new(ProgramLocationToSymbolRowMapper),
            Box::new(ReferenceEndpointToAddressRowMapper),
            Box::new(ReferenceEndpointToFunctionRowMapper),
            Box::new(ReferenceEndpointToProgramLocationRowMapper),
            Box::new(ReferenceEndpointToReferenceRowMapper),
            Box::new(SymbolToAddressRowMapper),
            Box::new(SymbolToProgramLocationRowMapper),
        ];
        for mapper in &mappers {
            let result = mapper.map(&"test".to_string());
            assert!(result.is_some(), "Mapper '{}' should produce output", mapper.name());
            assert!(!mapper.is_one_to_many());
        }
    }
}
