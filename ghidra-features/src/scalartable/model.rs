//! Scalar value search model, row objects, and plugin.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.scalartable` Java package:
//! `ScalarSearchModel`, `ScalarRowObject`, `ScalarSearchPlugin`,
//! `ScalarSearchProvider`, `ScalarSearchContext`, `ScalarSearchDialog`,
//! `ScalarColumnConstraintProvider`, `RangeFilterTextField`,
//! `ScalarRowObjectToAddressTableRowMapper`,
//! `ScalarRowObjectToProgramLocationTableRowMapper`.

use ghidra_core::Address;

// ============================================================================
// ScalarRowObject -- a scalar value found in the program
// ============================================================================

/// A scalar value found at an address in the program.
///
/// Ported from `ghidra.app.plugin.core.scalartable.ScalarRowObject`.
#[derive(Debug, Clone)]
pub struct ScalarRowObject {
    /// The address where the scalar was found.
    pub address: Address,
    /// The scalar value.
    pub value: i64,
    /// The size of the scalar in bytes.
    pub size: u8,
    /// The instruction mnemonic (if at an instruction).
    pub mnemonic: Option<String>,
    /// The operand index where the scalar appears.
    pub operand_index: Option<u8>,
}

impl ScalarRowObject {
    /// Create a new scalar row object.
    pub fn new(address: Address, value: i64, size: u8) -> Self {
        Self {
            address,
            value,
            size,
            mnemonic: None,
            operand_index: None,
        }
    }

    /// Create with instruction context.
    pub fn with_context(
        address: Address,
        value: i64,
        size: u8,
        mnemonic: impl Into<String>,
        operand_index: u8,
    ) -> Self {
        Self {
            address,
            value,
            size,
            mnemonic: Some(mnemonic.into()),
            operand_index: Some(operand_index),
        }
    }

    /// The hex representation of the value.
    pub fn hex_value(&self) -> String {
        match self.size {
            1 => format!("0x{:02x}", self.value as u8),
            2 => format!("0x{:04x}", self.value as u16),
            4 => format!("0x{:08x}", self.value as u32),
            8 => format!("0x{:016x}", self.value as u64),
            _ => format!("0x{:x}", self.value),
        }
    }
}

// ============================================================================
// ScalarSearchContext -- search context/configuration
// ============================================================================

/// Configuration for scalar value searching.
///
/// Ported from `ghidra.app.plugin.core.scalartable.ScalarSearchContext`.
#[derive(Debug, Clone)]
pub struct ScalarSearchContext {
    /// The value to search for.
    pub value: Option<i64>,
    /// Minimum value (inclusive).
    pub min_value: Option<i64>,
    /// Maximum value (inclusive).
    pub max_value: Option<i64>,
    /// The byte size to search for (1, 2, 4, 8, or 0 for any).
    pub byte_size: u8,
    /// Whether to treat the value as signed.
    pub signed: bool,
    /// Maximum number of results.
    pub max_results: Option<usize>,
}

impl ScalarSearchContext {
    /// Create a new search context.
    pub fn new() -> Self {
        Self {
            value: None,
            min_value: None,
            max_value: None,
            byte_size: 0,
            signed: false,
            max_results: None,
        }
    }

    /// Search for an exact value.
    pub fn exact(value: i64) -> Self {
        Self {
            value: Some(value),
            ..Self::new()
        }
    }

    /// Search for values in a range.
    pub fn range(min: i64, max: i64) -> Self {
        Self {
            min_value: Some(min),
            max_value: Some(max),
            ..Self::new()
        }
    }

    /// Set the byte size filter.
    pub fn with_byte_size(mut self, size: u8) -> Self {
        self.byte_size = size;
        self
    }

    /// Set signed mode.
    pub fn with_signed(mut self, signed: bool) -> Self {
        self.signed = signed;
        self
    }

    /// Set maximum results.
    pub fn with_max_results(mut self, max: usize) -> Self {
        self.max_results = Some(max);
        self
    }

    /// Check whether a scalar row matches this search context.
    pub fn matches(&self, row: &ScalarRowObject) -> bool {
        if self.byte_size != 0 && row.size != self.byte_size {
            return false;
        }

        if let Some(exact) = self.value {
            if row.value != exact {
                return false;
            }
        }

        if let Some(min) = self.min_value {
            if row.value < min {
                return false;
            }
        }

        if let Some(max) = self.max_value {
            if row.value > max {
                return false;
            }
        }

        true
    }
}

impl Default for ScalarSearchContext {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ScalarSearchModel -- table model for scalar search results
// ============================================================================

/// Column definitions for the scalar search table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScalarColumn {
    /// Address column.
    Address,
    /// Value column.
    Value,
    /// Hex value column.
    HexValue,
    /// Size column.
    Size,
    /// Mnemonic column.
    Mnemonic,
}

impl ScalarColumn {
    /// All columns in display order.
    pub fn all() -> &'static [ScalarColumn] {
        &[
            Self::Address,
            Self::Value,
            Self::HexValue,
            Self::Size,
            Self::Mnemonic,
        ]
    }

    /// Column header.
    pub fn header(&self) -> &'static str {
        match self {
            Self::Address => "Address",
            Self::Value => "Value",
            Self::HexValue => "Hex",
            Self::Size => "Size",
            Self::Mnemonic => "Mnemonic",
        }
    }
}

/// Table model for displaying scalar search results.
///
/// Ported from `ghidra.app.plugin.core.scalartable.ScalarSearchModel`.
#[derive(Debug, Default)]
pub struct ScalarSearchModel {
    /// All scalar results.
    results: Vec<ScalarRowObject>,
    /// Whether the results were truncated.
    truncated: bool,
}

impl ScalarSearchModel {
    /// Create a new model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a result.
    pub fn add_result(&mut self, row: ScalarRowObject) {
        self.results.push(row);
    }

    /// Set whether the results were truncated.
    pub fn set_truncated(&mut self, truncated: bool) {
        self.truncated = truncated;
    }

    /// Whether results were truncated.
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Result count.
    pub fn result_count(&self) -> usize {
        self.results.len()
    }

    /// Get a result by index.
    pub fn get_result(&self, index: usize) -> Option<&ScalarRowObject> {
        self.results.get(index)
    }

    /// Get all results.
    pub fn all_results(&self) -> &[ScalarRowObject] {
        &self.results
    }

    /// Filter results by the search context.
    pub fn filter(&self, ctx: &ScalarSearchContext) -> Vec<&ScalarRowObject> {
        self.results.iter().filter(|r| ctx.matches(r)).collect()
    }

    /// Sort results by column.
    pub fn sort_by(&mut self, column: ScalarColumn, ascending: bool) {
        match column {
            ScalarColumn::Address => {
                self.results.sort_by_key(|r| r.address.offset);
            }
            ScalarColumn::Value => {
                self.results.sort_by_key(|r| r.value);
            }
            ScalarColumn::HexValue => {
                self.results.sort_by_key(|r| r.value);
            }
            ScalarColumn::Size => {
                self.results.sort_by_key(|r| r.size);
            }
            ScalarColumn::Mnemonic => {
                self.results.sort_by(|a, b| {
                    a.mnemonic
                        .as_deref()
                        .unwrap_or("")
                        .cmp(b.mnemonic.as_deref().unwrap_or(""))
                });
            }
        }
        if !ascending {
            self.results.reverse();
        }
    }

    /// Clear all results.
    pub fn clear(&mut self) {
        self.results.clear();
        self.truncated = false;
    }
}

// ============================================================================
// ScalarSearchPlugin -- plugin for scalar value searching
// ============================================================================

/// Plugin for searching scalar values in a program.
///
/// Ported from `ghidra.app.plugin.core.scalartable.ScalarSearchPlugin`.
#[derive(Debug)]
pub struct ScalarSearchPlugin {
    /// The search model.
    pub model: ScalarSearchModel,
    /// The last search context.
    pub last_context: Option<ScalarSearchContext>,
    /// Whether the plugin is disposed.
    disposed: bool,
}

impl ScalarSearchPlugin {
    /// Create a new scalar search plugin.
    pub fn new() -> Self {
        Self {
            model: ScalarSearchModel::new(),
            last_context: None,
            disposed: false,
        }
    }

    /// Execute a search (populates the model with matching scalars).
    pub fn search(&mut self, ctx: &ScalarSearchContext, scalars: &[ScalarRowObject]) {
        self.model.clear();
        let max = ctx.max_results.unwrap_or(usize::MAX);
        let mut count = 0;
        for scalar in scalars {
            if ctx.matches(scalar) {
                self.model.add_result(scalar.clone());
                count += 1;
                if count >= max {
                    self.model.set_truncated(true);
                    break;
                }
            }
        }
        self.last_context = Some(ctx.clone());
    }

    /// Dispose the plugin.
    pub fn dispose(&mut self) {
        self.disposed = true;
    }

    /// Whether the plugin is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }
}

impl Default for ScalarSearchPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Mappers
// ============================================================================

/// Maps a scalar row to an address.
///
/// Ported from
/// `ghidra.app.plugin.core.scalartable.ScalarRowObjectToAddressTableRowMapper`.
pub struct ScalarRowObjectToAddressMapper;

impl ScalarRowObjectToAddressMapper {
    /// Map a scalar row to its address.
    pub fn map(row: &ScalarRowObject) -> Address {
        row.address
    }
}

/// Maps a scalar row to a program location.
///
/// Ported from
/// `ghidra.app.plugin.core.scalartable.ScalarRowObjectToProgramLocationTableRowMapper`.
pub struct ScalarRowObjectToProgramLocationMapper;

impl ScalarRowObjectToProgramLocationMapper {
    /// Map a scalar row to a (address, value, mnemonic) tuple.
    pub fn map(row: &ScalarRowObject) -> (Address, i64, Option<&str>) {
        (row.address, row.value, row.mnemonic.as_deref())
    }
}

// ============================================================================
// Signedness -- whether a scalar is signed or unsigned
// ============================================================================

/// Whether a scalar value is interpreted as signed or unsigned.
///
/// Ported from `ScalarSearchModel.Signedness`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Signedness {
    /// Signed interpretation.
    Signed,
    /// Unsigned interpretation.
    Unsigned,
}

impl std::fmt::Display for Signedness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Signed => write!(f, "Signed"),
            Self::Unsigned => write!(f, "Unsigned"),
        }
    }
}

// ============================================================================
// ScalarFunctionNameColumn -- function name at scalar address
// ============================================================================

/// Information about the function containing a scalar value.
///
/// Ported from `ScalarSearchModel.ScalarFunctionNameTableColumn`.
#[derive(Debug, Clone)]
pub struct ScalarFunctionInfo {
    /// The function name.
    pub function_name: String,
    /// The function entry address.
    pub function_entry: Address,
    /// Whether the scalar is in the function prologue.
    pub in_prologue: bool,
    /// Whether the scalar is in the function epilogue.
    pub in_epilogue: bool,
}

impl ScalarFunctionInfo {
    /// Create a new function info.
    pub fn new(function_name: impl Into<String>, function_entry: Address) -> Self {
        Self {
            function_name: function_name.into(),
            function_entry,
            in_prologue: false,
            in_epilogue: false,
        }
    }
}

// ============================================================================
// ScalarPreviewColumn -- preview of instruction context
// ============================================================================

/// A preview of the instruction context around a scalar.
///
/// Ported from `ScalarSearchModel.PreviewTableColumn`.
#[derive(Debug, Clone)]
pub struct ScalarPreview {
    /// The instruction mnemonic.
    pub mnemonic: String,
    /// The operand representation containing the scalar.
    pub operand_repr: String,
    /// The full instruction representation.
    pub full_repr: String,
    /// The byte length of the instruction.
    pub instruction_length: usize,
}

impl ScalarPreview {
    /// Create a new preview.
    pub fn new(mnemonic: impl Into<String>, operand_repr: impl Into<String>) -> Self {
        let m = mnemonic.into();
        let o = operand_repr.into();
        Self {
            full_repr: format!("{} {}", m, o),
            mnemonic: m,
            operand_repr: o,
            instruction_length: 0,
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_row_object() {
        let row = ScalarRowObject::new(Address::new(0x1000), 42, 4);
        assert_eq!(row.value, 42);
        assert_eq!(row.size, 4);
        assert_eq!(row.hex_value(), "0x0000002a");
    }

    #[test]
    fn test_scalar_row_hex_sizes() {
        assert_eq!(ScalarRowObject::new(Address::new(0), 0xFF, 1).hex_value(), "0xff");
        assert_eq!(ScalarRowObject::new(Address::new(0), 0xFFFF, 2).hex_value(), "0xffff");
        assert_eq!(ScalarRowObject::new(Address::new(0), 0x12345678, 4).hex_value(), "0x12345678");
    }

    #[test]
    fn test_scalar_row_with_context() {
        let row = ScalarRowObject::with_context(
            Address::new(0x1000),
            100,
            4,
            "MOV",
            1,
        );
        assert_eq!(row.mnemonic.as_deref(), Some("MOV"));
        assert_eq!(row.operand_index, Some(1));
    }

    #[test]
    fn test_scalar_search_context_exact() {
        let ctx = ScalarSearchContext::exact(42);
        let matching = ScalarRowObject::new(Address::new(0x1000), 42, 4);
        let non_matching = ScalarRowObject::new(Address::new(0x2000), 99, 4);
        assert!(ctx.matches(&matching));
        assert!(!ctx.matches(&non_matching));
    }

    #[test]
    fn test_scalar_search_context_range() {
        let ctx = ScalarSearchContext::range(10, 20);
        let in_range = ScalarRowObject::new(Address::new(0x1000), 15, 4);
        let below = ScalarRowObject::new(Address::new(0x2000), 5, 4);
        let above = ScalarRowObject::new(Address::new(0x3000), 25, 4);
        assert!(ctx.matches(&in_range));
        assert!(!ctx.matches(&below));
        assert!(!ctx.matches(&above));
    }

    #[test]
    fn test_scalar_search_context_byte_size() {
        let ctx = ScalarSearchContext::exact(42).with_byte_size(4);
        let size4 = ScalarRowObject::new(Address::new(0x1000), 42, 4);
        let size2 = ScalarRowObject::new(Address::new(0x2000), 42, 2);
        assert!(ctx.matches(&size4));
        assert!(!ctx.matches(&size2));
    }

    #[test]
    fn test_scalar_search_model() {
        let mut model = ScalarSearchModel::new();
        model.add_result(ScalarRowObject::new(Address::new(0x1000), 42, 4));
        model.add_result(ScalarRowObject::new(Address::new(0x2000), 99, 4));
        assert_eq!(model.result_count(), 2);
        assert!(!model.is_truncated());
    }

    #[test]
    fn test_scalar_search_model_filter() {
        let mut model = ScalarSearchModel::new();
        model.add_result(ScalarRowObject::new(Address::new(0x1000), 42, 4));
        model.add_result(ScalarRowObject::new(Address::new(0x2000), 99, 2));
        model.add_result(ScalarRowObject::new(Address::new(0x3000), 42, 2));

        let ctx = ScalarSearchContext::exact(42);
        let filtered = model.filter(&ctx);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_scalar_search_model_sort() {
        let mut model = ScalarSearchModel::new();
        model.add_result(ScalarRowObject::new(Address::new(0x3000), 10, 4));
        model.add_result(ScalarRowObject::new(Address::new(0x1000), 30, 4));
        model.add_result(ScalarRowObject::new(Address::new(0x2000), 20, 4));

        model.sort_by(ScalarColumn::Value, true);
        assert_eq!(model.get_result(0).unwrap().value, 10);
        assert_eq!(model.get_result(2).unwrap().value, 30);

        model.sort_by(ScalarColumn::Address, true);
        assert_eq!(model.get_result(0).unwrap().address, Address::new(0x1000));
    }

    #[test]
    fn test_scalar_search_model_sort_descending() {
        let mut model = ScalarSearchModel::new();
        model.add_result(ScalarRowObject::new(Address::new(0x1000), 10, 4));
        model.add_result(ScalarRowObject::new(Address::new(0x2000), 20, 4));
        model.sort_by(ScalarColumn::Value, false);
        assert_eq!(model.get_result(0).unwrap().value, 20);
    }

    #[test]
    fn test_scalar_search_plugin() {
        let mut plugin = ScalarSearchPlugin::new();
        assert!(!plugin.is_disposed());

        let scalars = vec![
            ScalarRowObject::new(Address::new(0x1000), 42, 4),
            ScalarRowObject::new(Address::new(0x2000), 99, 4),
            ScalarRowObject::new(Address::new(0x3000), 42, 2),
        ];

        let ctx = ScalarSearchContext::exact(42);
        plugin.search(&ctx, &scalars);
        assert_eq!(plugin.model.result_count(), 2);
        assert!(plugin.last_context.is_some());
    }

    #[test]
    fn test_scalar_search_plugin_max_results() {
        let mut plugin = ScalarSearchPlugin::new();
        let scalars: Vec<ScalarRowObject> = (0..100)
            .map(|i| ScalarRowObject::new(Address::new(0x1000 + i * 0x10), 42, 4))
            .collect();

        let ctx = ScalarSearchContext::exact(42).with_max_results(10);
        plugin.search(&ctx, &scalars);
        assert_eq!(plugin.model.result_count(), 10);
        assert!(plugin.model.is_truncated());
    }

    #[test]
    fn test_scalar_search_plugin_dispose() {
        let mut plugin = ScalarSearchPlugin::new();
        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_scalar_column_headers() {
        assert_eq!(ScalarColumn::Address.header(), "Address");
        assert_eq!(ScalarColumn::Value.header(), "Value");
        assert_eq!(ScalarColumn::HexValue.header(), "Hex");
        assert_eq!(ScalarColumn::Size.header(), "Size");
        assert_eq!(ScalarColumn::Mnemonic.header(), "Mnemonic");
        assert_eq!(ScalarColumn::all().len(), 5);
    }

    #[test]
    fn test_address_mapper() {
        let row = ScalarRowObject::new(Address::new(0x4000), 42, 4);
        assert_eq!(ScalarRowObjectToAddressMapper::map(&row), Address::new(0x4000));
    }

    #[test]
    fn test_program_location_mapper() {
        let row = ScalarRowObject::with_context(
            Address::new(0x4000),
            42,
            4,
            "MOV",
            1,
        );
        let (addr, val, mnem) = ScalarRowObjectToProgramLocationMapper::map(&row);
        assert_eq!(addr, Address::new(0x4000));
        assert_eq!(val, 42);
        assert_eq!(mnem, Some("MOV"));
    }

    #[test]
    fn test_scalar_search_model_clear() {
        let mut model = ScalarSearchModel::new();
        model.add_result(ScalarRowObject::new(Address::new(0x1000), 42, 4));
        model.set_truncated(true);
        model.clear();
        assert_eq!(model.result_count(), 0);
        assert!(!model.is_truncated());
    }
}
