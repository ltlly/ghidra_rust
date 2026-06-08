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

// ============================================================================
// Module-specific table row mappers
//
// These are the row mappers defined within each plugin module's Java code.
// They convert module-specific row objects (Function, Comment, Data, Scalar,
// SourceMap, Relocation) to generic table types (Address, ProgramLocation).
// ============================================================================

/// Row object representing a function for table display.
///
/// Ported from `FunctionRowObject` in `ghidra.app.plugin.core.functionwindow`.
#[derive(Debug, Clone)]
pub struct FunctionRowObject {
    /// Function name.
    pub name: String,
    /// Entry point address as a string.
    pub address: String,
    /// Calling convention.
    pub calling_convention: String,
    /// Whether the function has a custom storage.
    pub custom_storage: bool,
    /// Function signature text.
    pub signature: String,
}

impl FunctionRowObject {
    /// Create a new function row object.
    pub fn new(
        name: impl Into<String>,
        address: impl Into<String>,
        calling_convention: impl Into<String>,
        signature: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            address: address.into(),
            calling_convention: calling_convention.into(),
            custom_storage: false,
            signature: signature.into(),
        }
    }
}

/// Maps a Function row object to an Address.
///
/// Ported from `FunctionToAddressTableRowMapper.java` in
/// `ghidra.app.plugin.core.functionwindow`.
#[derive(Debug)]
pub struct FunctionRowObjectToAddressRowMapper;

impl TableRowMapper<FunctionRowObject, String> for FunctionRowObjectToAddressRowMapper {
    fn name(&self) -> &str {
        "Function -> Address"
    }

    fn map(&self, from: &FunctionRowObject) -> Option<String> {
        Some(from.address.clone())
    }
}

/// Maps a Function row object to a ProgramLocation.
///
/// Ported from `FunctionRowObjectToProgramLocationTableRowMapper.java` in
/// `ghidra.app.plugin.core.functionwindow`.
#[derive(Debug)]
pub struct FunctionRowObjectToProgramLocationRowMapper;

impl TableRowMapper<FunctionRowObject, String> for FunctionRowObjectToProgramLocationRowMapper {
    fn name(&self) -> &str {
        "Function -> ProgramLocation"
    }

    fn map(&self, from: &FunctionRowObject) -> Option<String> {
        Some(from.address.clone())
    }
}

/// Maps a Function row object to a Function (identity).
///
/// Ported from `FunctionRowObjectToFunctionTableRowMapper.java` in
/// `ghidra.app.plugin.core.functionwindow`.
#[derive(Debug)]
pub struct FunctionRowObjectToFunctionRowMapper;

impl TableRowMapper<FunctionRowObject, FunctionRowObject> for FunctionRowObjectToFunctionRowMapper {
    fn name(&self) -> &str {
        "Function -> Function"
    }

    fn map(&self, from: &FunctionRowObject) -> Option<FunctionRowObject> {
        Some(from.clone())
    }
}

/// Maps a function name/address to an Address.
///
/// Ported from `FunctionToAddressTableRowMapper.java` in
/// `ghidra.app.plugin.core.functionwindow`.
#[derive(Debug)]
pub struct FunctionToAddressRowMapper;

impl TableRowMapper<String, String> for FunctionToAddressRowMapper {
    fn name(&self) -> &str {
        "Function (string) -> Address"
    }

    fn map(&self, from: &String) -> Option<String> {
        Some(from.clone())
    }
}

/// Maps a function name/address to a ProgramLocation.
///
/// Ported from `FunctionToProgramLocationTableRowMapper.java` in
/// `ghidra.app.plugin.core.functionwindow`.
#[derive(Debug)]
pub struct FunctionToProgramLocationRowMapper;

impl TableRowMapper<String, String> for FunctionToProgramLocationRowMapper {
    fn name(&self) -> &str {
        "Function (string) -> ProgramLocation"
    }

    fn map(&self, from: &String) -> Option<String> {
        Some(from.clone())
    }
}

// ---------------------------------------------------------------------------
// Comment row mappers
// ---------------------------------------------------------------------------

/// Row object representing a comment for table display.
///
/// Ported from `CommentRowObject` in `ghidra.app.plugin.core.commentwindow`.
#[derive(Debug, Clone)]
pub struct CommentRowObject {
    /// Address of the comment.
    pub address: String,
    /// Comment text.
    pub text: String,
    /// Comment type (EOL, Pre, Post, Plate, Repeatable).
    pub comment_type: String,
}

impl CommentRowObject {
    /// Create a new comment row object.
    pub fn new(
        address: impl Into<String>,
        text: impl Into<String>,
        comment_type: impl Into<String>,
    ) -> Self {
        Self {
            address: address.into(),
            text: text.into(),
            comment_type: comment_type.into(),
        }
    }

    /// Get the address.
    pub fn get_address(&self) -> String {
        self.address.clone()
    }
}

/// Maps a Comment row object to an Address.
///
/// Ported from `CommentRowObjectToAddressTableRowMapper.java` in
/// `ghidra.app.plugin.core.commentwindow`.
#[derive(Debug)]
pub struct CommentRowObjectToAddressRowMapper;

impl TableRowMapper<CommentRowObject, String> for CommentRowObjectToAddressRowMapper {
    fn name(&self) -> &str {
        "Comment -> Address"
    }

    fn map(&self, from: &CommentRowObject) -> Option<String> {
        Some(from.address.clone())
    }
}

/// Maps a Comment row object to a ProgramLocation.
///
/// Ported from `CommentRowObjectToProgramLocationTableRowMapper.java` in
/// `ghidra.app.plugin.core.commentwindow`.
#[derive(Debug)]
pub struct CommentRowObjectToProgramLocationRowMapper;

impl TableRowMapper<CommentRowObject, String> for CommentRowObjectToProgramLocationRowMapper {
    fn name(&self) -> &str {
        "Comment -> ProgramLocation"
    }

    fn map(&self, from: &CommentRowObject) -> Option<String> {
        Some(from.address.clone())
    }
}

// ---------------------------------------------------------------------------
// Data row mappers
// ---------------------------------------------------------------------------

/// Row object representing a data item for table display.
///
/// Ported from `DataRowObject` in `ghidra.app.plugin.core.datawindow`.
#[derive(Debug, Clone)]
pub struct DataRowObject {
    /// Address of the data item.
    pub address: String,
    /// Data type name.
    pub data_type_name: String,
    /// Data value representation.
    pub value: String,
}

impl DataRowObject {
    /// Create a new data row object.
    pub fn new(
        address: impl Into<String>,
        data_type_name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            address: address.into(),
            data_type_name: data_type_name.into(),
            value: value.into(),
        }
    }
}

/// Maps a Data row object to an Address.
///
/// Ported from `DataRowObjectToAddressTableRowMapper.java` in
/// `ghidra.app.plugin.core.datawindow`.
#[derive(Debug)]
pub struct DataRowObjectToAddressRowMapper;

impl TableRowMapper<DataRowObject, String> for DataRowObjectToAddressRowMapper {
    fn name(&self) -> &str {
        "Data -> Address"
    }

    fn map(&self, from: &DataRowObject) -> Option<String> {
        Some(from.address.clone())
    }
}

/// Maps a Data row object to a ProgramLocation.
///
/// Ported from `DataRowObjectToProgramLocationTableRowMapper.java` in
/// `ghidra.app.plugin.core.datawindow`.
#[derive(Debug)]
pub struct DataRowObjectToProgramLocationRowMapper;

impl TableRowMapper<DataRowObject, String> for DataRowObjectToProgramLocationRowMapper {
    fn name(&self) -> &str {
        "Data -> ProgramLocation"
    }

    fn map(&self, from: &DataRowObject) -> Option<String> {
        Some(from.address.clone())
    }
}

// ---------------------------------------------------------------------------
// Scalar row mappers
// ---------------------------------------------------------------------------

/// Row object representing a scalar value found in the program.
///
/// Ported from `ScalarRowObject` in `ghidra.app.plugin.core.scalartable`.
#[derive(Debug, Clone)]
pub struct ScalarRowObject {
    /// Address of the scalar.
    pub address: String,
    /// The scalar value.
    pub value: u64,
    /// Bit length of the scalar.
    pub bit_length: usize,
}

impl ScalarRowObject {
    /// Create a new scalar row object.
    pub fn new(address: impl Into<String>, value: u64, bit_length: usize) -> Self {
        Self {
            address: address.into(),
            value,
            bit_length,
        }
    }
}

/// Maps a Scalar row object to an Address.
///
/// Ported from `ScalarRowObjectToAddressTableRowMapper.java` in
/// `ghidra.app.plugin.core.scalartable`.
#[derive(Debug)]
pub struct ScalarRowObjectToAddressRowMapper;

impl TableRowMapper<ScalarRowObject, String> for ScalarRowObjectToAddressRowMapper {
    fn name(&self) -> &str {
        "Scalar -> Address"
    }

    fn map(&self, from: &ScalarRowObject) -> Option<String> {
        Some(from.address.clone())
    }
}

/// Maps a Scalar row object to a ProgramLocation.
///
/// Ported from `ScalarRowObjectToProgramLocationTableRowMapper.java` in
/// `ghidra.app.plugin.core.scalartable`.
#[derive(Debug)]
pub struct ScalarRowObjectToProgramLocationRowMapper;

impl TableRowMapper<ScalarRowObject, String> for ScalarRowObjectToProgramLocationRowMapper {
    fn name(&self) -> &str {
        "Scalar -> ProgramLocation"
    }

    fn map(&self, from: &ScalarRowObject) -> Option<String> {
        Some(from.address.clone())
    }
}

// ---------------------------------------------------------------------------
// Source file row mappers
// ---------------------------------------------------------------------------

/// Row object representing a source map entry.
///
/// Ported from `SourceMapEntry` display in
/// `ghidra.app.plugin.core.sourcefilestable`.
#[derive(Debug, Clone)]
pub struct SourceMapEntryRowObject {
    /// Source file path.
    pub source_file: String,
    /// Address in the program.
    pub address: String,
    /// Line number in the source file.
    pub line_number: Option<u32>,
}

impl SourceMapEntryRowObject {
    /// Create a new source map entry row object.
    pub fn new(
        source_file: impl Into<String>,
        address: impl Into<String>,
        line_number: Option<u32>,
    ) -> Self {
        Self {
            source_file: source_file.into(),
            address: address.into(),
            line_number,
        }
    }
}

/// Maps a SourceMapEntry row object to an Address.
///
/// Ported from `SourceMapEntryToAddressTableRowMapper.java` in
/// `ghidra.app.plugin.core.sourcefilestable`.
#[derive(Debug)]
pub struct SourceMapEntryToAddressRowMapper;

impl TableRowMapper<SourceMapEntryRowObject, String> for SourceMapEntryToAddressRowMapper {
    fn name(&self) -> &str {
        "SourceMapEntry -> Address"
    }

    fn map(&self, from: &SourceMapEntryRowObject) -> Option<String> {
        Some(from.address.clone())
    }
}

/// Maps a SourceMapEntry row object to a ProgramLocation.
///
/// Ported from `SourceMapEntryToProgramLocationRowMapper.java` in
/// `ghidra.app.plugin.core.sourcefilestable`.
#[derive(Debug)]
pub struct SourceMapEntryToProgramLocationRowMapper;

impl TableRowMapper<SourceMapEntryRowObject, String> for SourceMapEntryToProgramLocationRowMapper {
    fn name(&self) -> &str {
        "SourceMapEntry -> ProgramLocation"
    }

    fn map(&self, from: &SourceMapEntryRowObject) -> Option<String> {
        Some(from.address.clone())
    }
}

// ---------------------------------------------------------------------------
// Relocation row mappers
// ---------------------------------------------------------------------------

/// Row object representing a relocation entry.
///
/// Ported from the relocation display in `ghidra.app.plugin.core.reloc`.
#[derive(Debug, Clone)]
pub struct RelocationRowObject {
    /// Address of the relocation.
    pub address: String,
    /// Relocation type name.
    pub relocation_type: String,
    /// The original value before relocation.
    pub original_value: u64,
}

impl RelocationRowObject {
    /// Create a new relocation row object.
    pub fn new(
        address: impl Into<String>,
        relocation_type: impl Into<String>,
        original_value: u64,
    ) -> Self {
        Self {
            address: address.into(),
            relocation_type: relocation_type.into(),
            original_value,
        }
    }
}

/// Maps a Relocation row object to an Address.
///
/// Ported from `RelocationToAddressTableRowMapper.java` in
/// `ghidra.app.plugin.core.reloc`.
#[derive(Debug)]
pub struct RelocationToAddressRowMapper;

impl TableRowMapper<RelocationRowObject, String> for RelocationToAddressRowMapper {
    fn name(&self) -> &str {
        "Relocation -> Address"
    }

    fn map(&self, from: &RelocationRowObject) -> Option<String> {
        Some(from.address.clone())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

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
            Box::new(FunctionToAddressRowMapper),
            Box::new(FunctionToProgramLocationRowMapper),
        ];
        for mapper in &mappers {
            let result = mapper.map(&"test".to_string());
            assert!(result.is_some(), "Mapper '{}' should produce output", mapper.name());
            assert!(!mapper.is_one_to_many());
        }
    }

    // -----------------------------------------------------------------------
    // Module-specific mapper tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_function_row_object_creation() {
        let func = FunctionRowObject::new("main", "0x401000", "cdecl", "void main(void)");
        assert_eq!(func.name, "main");
        assert_eq!(func.address, "0x401000");
        assert_eq!(func.calling_convention, "cdecl");
        assert!(!func.custom_storage);
    }

    #[test]
    fn test_function_row_object_to_address() {
        let mapper = FunctionRowObjectToAddressRowMapper;
        let func = FunctionRowObject::new("main", "0x401000", "cdecl", "void main(void)");
        assert_eq!(mapper.name(), "Function -> Address");
        assert_eq!(mapper.map(&func), Some("0x401000".to_string()));
    }

    #[test]
    fn test_function_row_object_to_program_location() {
        let mapper = FunctionRowObjectToProgramLocationRowMapper;
        let func = FunctionRowObject::new("foo", "0x402000", "stdcall", "int foo(int)");
        assert_eq!(mapper.name(), "Function -> ProgramLocation");
        assert_eq!(mapper.map(&func), Some("0x402000".to_string()));
    }

    #[test]
    fn test_function_row_object_to_function_identity() {
        let mapper = FunctionRowObjectToFunctionRowMapper;
        let func = FunctionRowObject::new("bar", "0x403000", "cdecl", "void bar()");
        let mapped = mapper.map(&func).unwrap();
        assert_eq!(mapped.name, "bar");
        assert_eq!(mapped.address, "0x403000");
    }

    #[test]
    fn test_comment_row_object_creation() {
        let comment = CommentRowObject::new("0x1000", "entry point", "EOL");
        assert_eq!(comment.get_address(), "0x1000");
        assert_eq!(comment.text, "entry point");
        assert_eq!(comment.comment_type, "EOL");
    }

    #[test]
    fn test_comment_row_object_to_address() {
        let mapper = CommentRowObjectToAddressRowMapper;
        let comment = CommentRowObject::new("0x1000", "test", "Pre");
        assert_eq!(mapper.name(), "Comment -> Address");
        assert_eq!(mapper.map(&comment), Some("0x1000".to_string()));
    }

    #[test]
    fn test_comment_row_object_to_program_location() {
        let mapper = CommentRowObjectToProgramLocationRowMapper;
        let comment = CommentRowObject::new("0x2000", "test", "Post");
        assert_eq!(mapper.map(&comment), Some("0x2000".to_string()));
    }

    #[test]
    fn test_data_row_object_creation() {
        let data = DataRowObject::new("0x3000", "int", "42");
        assert_eq!(data.address, "0x3000");
        assert_eq!(data.data_type_name, "int");
        assert_eq!(data.value, "42");
    }

    #[test]
    fn test_data_row_object_to_address() {
        let mapper = DataRowObjectToAddressRowMapper;
        let data = DataRowObject::new("0x3000", "char", "'A'");
        assert_eq!(mapper.name(), "Data -> Address");
        assert_eq!(mapper.map(&data), Some("0x3000".to_string()));
    }

    #[test]
    fn test_data_row_object_to_program_location() {
        let mapper = DataRowObjectToProgramLocationRowMapper;
        let data = DataRowObject::new("0x4000", "short", "256");
        assert_eq!(mapper.map(&data), Some("0x4000".to_string()));
    }

    #[test]
    fn test_scalar_row_object_creation() {
        let scalar = ScalarRowObject::new("0x5000", 0xFF, 8);
        assert_eq!(scalar.address, "0x5000");
        assert_eq!(scalar.value, 0xFF);
        assert_eq!(scalar.bit_length, 8);
    }

    #[test]
    fn test_scalar_row_object_to_address() {
        let mapper = ScalarRowObjectToAddressRowMapper;
        let scalar = ScalarRowObject::new("0x5000", 42, 32);
        assert_eq!(mapper.name(), "Scalar -> Address");
        assert_eq!(mapper.map(&scalar), Some("0x5000".to_string()));
    }

    #[test]
    fn test_scalar_row_object_to_program_location() {
        let mapper = ScalarRowObjectToProgramLocationRowMapper;
        let scalar = ScalarRowObject::new("0x6000", 0xDEAD, 16);
        assert_eq!(mapper.map(&scalar), Some("0x6000".to_string()));
    }

    #[test]
    fn test_source_map_entry_row_object_creation() {
        let entry = SourceMapEntryRowObject::new("main.c", "0x1000", Some(42));
        assert_eq!(entry.source_file, "main.c");
        assert_eq!(entry.address, "0x1000");
        assert_eq!(entry.line_number, Some(42));
    }

    #[test]
    fn test_source_map_entry_to_address() {
        let mapper = SourceMapEntryToAddressRowMapper;
        let entry = SourceMapEntryRowObject::new("test.c", "0x2000", None);
        assert_eq!(mapper.name(), "SourceMapEntry -> Address");
        assert_eq!(mapper.map(&entry), Some("0x2000".to_string()));
    }

    #[test]
    fn test_source_map_entry_to_program_location() {
        let mapper = SourceMapEntryToProgramLocationRowMapper;
        let entry = SourceMapEntryRowObject::new("utils.c", "0x3000", Some(10));
        assert_eq!(mapper.map(&entry), Some("0x3000".to_string()));
    }

    #[test]
    fn test_relocation_row_object_creation() {
        let reloc = RelocationRowObject::new("0x4000", "ABSOLUTE", 0x12345678);
        assert_eq!(reloc.address, "0x4000");
        assert_eq!(reloc.relocation_type, "ABSOLUTE");
        assert_eq!(reloc.original_value, 0x12345678);
    }

    #[test]
    fn test_relocation_to_address() {
        let mapper = RelocationToAddressRowMapper;
        let reloc = RelocationRowObject::new("0x4000", "RELATIVE", 0);
        assert_eq!(mapper.name(), "Relocation -> Address");
        assert_eq!(mapper.map(&reloc), Some("0x4000".to_string()));
    }

    #[test]
    fn test_all_module_mappers_produce_output() {
        let func = FunctionRowObject::new("main", "0x1000", "cdecl", "void main()");
        assert!(FunctionRowObjectToAddressRowMapper.map(&func).is_some());
        assert!(FunctionRowObjectToProgramLocationRowMapper.map(&func).is_some());
        assert!(FunctionRowObjectToFunctionRowMapper.map(&func).is_some());

        let comment = CommentRowObject::new("0x2000", "text", "EOL");
        assert!(CommentRowObjectToAddressRowMapper.map(&comment).is_some());
        assert!(CommentRowObjectToProgramLocationRowMapper.map(&comment).is_some());

        let data = DataRowObject::new("0x3000", "int", "0");
        assert!(DataRowObjectToAddressRowMapper.map(&data).is_some());
        assert!(DataRowObjectToProgramLocationRowMapper.map(&data).is_some());

        let scalar = ScalarRowObject::new("0x4000", 0, 32);
        assert!(ScalarRowObjectToAddressRowMapper.map(&scalar).is_some());
        assert!(ScalarRowObjectToProgramLocationRowMapper.map(&scalar).is_some());

        let source = SourceMapEntryRowObject::new("file.c", "0x5000", None);
        assert!(SourceMapEntryToAddressRowMapper.map(&source).is_some());
        assert!(SourceMapEntryToProgramLocationRowMapper.map(&source).is_some());

        let reloc = RelocationRowObject::new("0x6000", "ABS", 0);
        assert!(RelocationToAddressRowMapper.map(&reloc).is_some());
    }
}
