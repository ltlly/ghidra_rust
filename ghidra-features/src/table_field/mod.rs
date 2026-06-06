//! Program-based table column definitions.
//!
//! Ported from `ghidra.util.table.field` -- provides table column types used
//! by Ghidra's various table views to display program data such as addresses,
//! function names, bytes, references, labels, namespaces, source types, and
//! code units.
//!
//! # Architecture
//!
//! - **Traits**: [`ProgramBasedDynamicTableColumn`], [`ProgramLocationTableColumn`]
//!   define the extension-point interfaces.
//! - **Abstract bases**: [`AbstractProgramBasedDynamicTableColumn`],
//!   [`AbstractProgramLocationTableColumn`], [`AbstractReferenceBytesTableColumn`],
//!   [`AbstractReferencePreviewTableColumn`].
//! - **Concrete columns**: [`AddressTableColumn`], [`FunctionNameTableColumn`],
//!   [`BytesTableColumn`], [`CodeUnitTableColumn`], [`LabelTableColumn`],
//!   [`NamespaceTableColumn`], [`EolCommentTableColumn`], and many more.
//! - **Settings**: [`ByteCountSettingsDefinition`], [`CodeUnitCountSettingsDefinition`],
//!   [`CodeUnitOffsetSettingsDefinition`], [`MemoryOffsetSettingsDefinition`],
//!   [`AddressRangeEndpointSettingsDefinition`], function property settings.
//! - **Location types**: [`AddressBasedLocation`], [`ReferenceEndpoint`],
//!   [`IncomingReferenceEndpoint`], [`OutgoingReferenceEndpoint`],
//!   [`CodeUnitTableCellData`].
//!
//! # Example
//!
//! ```rust
//! use ghidra_features::table_field::*;
//!
//! let col = AddressTableColumn::new();
//! assert_eq!(col.column_name(), "Location");
//! assert_eq!(col.preferred_width(), 200);
//!
//! let col = FunctionNameTableColumn::new();
//! assert_eq!(col.column_name(), "Function Name");
//!
//! let settings = ByteCountSettingsDefinition::new();
//! assert_eq!(settings.name(), "Byte count");
//! assert_eq!(settings.default_choice(), 0);
//! ```

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Settings trait and definitions
// ---------------------------------------------------------------------------

/// A setting definition that controls table column display options.
///
/// Ported from `ghidra.docking.settings.SettingsDefinition`.
pub trait SettingsDefinition: std::fmt::Debug {
    /// The setting name.
    fn name(&self) -> &str;
    /// The storage key.
    fn storage_key(&self) -> &str;
    /// Human-readable description.
    fn description(&self) -> &str;
}

/// An enum-based setting definition.
///
/// Ported from `ghidra.docking.settings.EnumSettingsDefinition`.
pub trait EnumSettingsDefinition: SettingsDefinition {
    /// Get the currently selected choice index.
    fn get_choice(&self, settings: &Settings) -> usize;
    /// Set the choice.
    fn set_choice(&self, settings: &mut Settings, value: usize);
    /// Get the display string for the current choice.
    fn get_value_string(&self, settings: &Settings) -> String;
    /// Get the available display choices.
    fn display_choices(&self) -> &[&str];
    /// Get the display name for a specific choice value.
    fn display_choice(&self, value: usize) -> &str;
    /// Clear the setting.
    fn clear(&self, settings: &mut Settings);
    /// Check if a value is set.
    fn has_value(&self, settings: &Settings) -> bool;
}

/// A simple settings container.
///
/// Ported from `ghidra.docking.settings.Settings`.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    values: HashMap<String, SettingValue>,
}

/// A value stored in settings.
#[derive(Debug, Clone)]
pub enum SettingValue {
    /// Long (integer) value.
    Long(i64),
    /// String value.
    String(String),
    /// Boolean value.
    Bool(bool),
}

impl Settings {
    /// Create empty settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a long value.
    pub fn get_long(&self, key: &str) -> Option<i64> {
        match self.values.get(key) {
            Some(SettingValue::Long(v)) => Some(*v),
            _ => None,
        }
    }

    /// Set a long value.
    pub fn set_long(&mut self, key: &str, value: i64) {
        self.values.insert(key.to_string(), SettingValue::Long(value));
    }

    /// Get a string value.
    pub fn get_string(&self, key: &str) -> Option<&str> {
        match self.values.get(key) {
            Some(SettingValue::String(v)) => Some(v.as_str()),
            _ => None,
        }
    }

    /// Set a string value.
    pub fn set_string(&mut self, key: &str, value: &str) {
        self.values
            .insert(key.to_string(), SettingValue::String(value.to_string()));
    }

    /// Clear a setting.
    pub fn clear_setting(&mut self, key: &str) {
        self.values.remove(key);
    }

    /// Get the raw value.
    pub fn get_value(&self, key: &str) -> Option<&SettingValue> {
        self.values.get(key)
    }
}

// ---------------------------------------------------------------------------
// ByteCountSettingsDefinition
// ---------------------------------------------------------------------------

/// Setting definition controlling the number of bytes to display.
///
/// Ported from `ByteCountSettingsDefinition.java`.
#[derive(Debug)]
pub struct ByteCountSettingsDefinition {
    choices: Vec<&'static str>,
}

impl ByteCountSettingsDefinition {
    /// Default byte count.
    pub const DEFAULT: usize = 0;
    /// Maximum byte count.
    pub const MAX_BYTE_COUNT: usize = 8;
    /// Setting key.
    pub const KEY: &'static str = "Byte count";

    /// Create a new definition.
    pub fn new() -> Self {
        Self {
            choices: vec!["default", "1", "2", "3", "4", "5", "6", "7", "8"],
        }
    }

    /// Get the default byte count choice index.
    pub fn default_choice(&self) -> usize {
        Self::DEFAULT
    }
}

impl Default for ByteCountSettingsDefinition {
    fn default() -> Self {
        Self::new()
    }
}

impl SettingsDefinition for ByteCountSettingsDefinition {
    fn name(&self) -> &str {
        Self::KEY
    }
    fn storage_key(&self) -> &str {
        Self::KEY
    }
    fn description(&self) -> &str {
        "Selects the number of bytes to display"
    }
}

impl EnumSettingsDefinition for ByteCountSettingsDefinition {
    fn get_choice(&self, settings: &Settings) -> usize {
        match settings.get_long(Self::KEY) {
            Some(v) if v >= 0 && (v as usize) < self.choices.len() => v as usize,
            _ => Self::DEFAULT,
        }
    }

    fn set_choice(&self, settings: &mut Settings, value: usize) {
        if value == Self::DEFAULT {
            settings.clear_setting(Self::KEY);
        } else {
            let v = value.min(Self::MAX_BYTE_COUNT);
            settings.set_long(Self::KEY, v as i64);
        }
    }

    fn get_value_string(&self, settings: &Settings) -> String {
        let idx = self.get_choice(settings);
        self.choices[idx].to_string()
    }

    fn display_choices(&self) -> &[&str] {
        &self.choices
    }

    fn display_choice(&self, value: usize) -> &str {
        self.choices.get(value).copied().unwrap_or("???")
    }

    fn clear(&self, settings: &mut Settings) {
        settings.clear_setting(Self::KEY);
    }

    fn has_value(&self, settings: &Settings) -> bool {
        settings.get_value(Self::KEY).is_some()
    }
}

// ---------------------------------------------------------------------------
// CodeUnitCountSettingsDefinition
// ---------------------------------------------------------------------------

/// Setting definition for the number of code units to display.
///
/// Ported from `CodeUnitCountSettingsDefinition.java`.
#[derive(Debug)]
pub struct CodeUnitCountSettingsDefinition {
    choices: Vec<&'static str>,
}

impl CodeUnitCountSettingsDefinition {
    /// Default code unit count.
    pub const DEFAULT: usize = 0;
    /// Maximum code unit count.
    pub const MAX: usize = 8;
    /// Setting key.
    pub const KEY: &'static str = "Code unit count";

    /// Create a new definition.
    pub fn new() -> Self {
        Self {
            choices: vec!["default", "1", "2", "3", "4", "5", "6", "7", "8"],
        }
    }

    /// Get the current count (1 if default).
    pub fn get_count(&self, settings: &Settings) -> usize {
        let choice = self.get_choice_from_settings(settings);
        if choice == 0 {
            1
        } else {
            choice
        }
    }

    fn get_choice_from_settings(&self, settings: &Settings) -> usize {
        match settings.get_long(Self::KEY) {
            Some(v) if v >= 0 && (v as usize) < self.choices.len() => v as usize,
            _ => Self::DEFAULT,
        }
    }
}

impl Default for CodeUnitCountSettingsDefinition {
    fn default() -> Self {
        Self::new()
    }
}

impl SettingsDefinition for CodeUnitCountSettingsDefinition {
    fn name(&self) -> &str {
        Self::KEY
    }
    fn storage_key(&self) -> &str {
        Self::KEY
    }
    fn description(&self) -> &str {
        "Selects the number of code units to display"
    }
}

impl EnumSettingsDefinition for CodeUnitCountSettingsDefinition {
    fn get_choice(&self, settings: &Settings) -> usize {
        self.get_choice_from_settings(settings)
    }

    fn set_choice(&self, settings: &mut Settings, value: usize) {
        if value == Self::DEFAULT {
            settings.clear_setting(Self::KEY);
        } else {
            let v = value.min(Self::MAX);
            settings.set_long(Self::KEY, v as i64);
        }
    }

    fn get_value_string(&self, settings: &Settings) -> String {
        let idx = self.get_choice(settings);
        self.choices[idx].to_string()
    }

    fn display_choices(&self) -> &[&str] {
        &self.choices
    }

    fn display_choice(&self, value: usize) -> &str {
        self.choices.get(value).copied().unwrap_or("???")
    }

    fn clear(&self, settings: &mut Settings) {
        settings.clear_setting(Self::KEY);
    }

    fn has_value(&self, settings: &Settings) -> bool {
        settings.get_value(Self::KEY).is_some()
    }
}

// ---------------------------------------------------------------------------
// CodeUnitOffsetSettingsDefinition
// ---------------------------------------------------------------------------

/// Setting definition for the code unit offset to display.
///
/// Ported from `CodeUnitOffsetSettingsDefinition.java`.
#[derive(Debug)]
pub struct CodeUnitOffsetSettingsDefinition {
    choices: Vec<&'static str>,
}

impl CodeUnitOffsetSettingsDefinition {
    /// Setting key.
    pub const KEY: &'static str = "Code unit offset";

    /// Create a new definition.
    pub fn new() -> Self {
        Self {
            choices: vec![
                "0", "+1", "+2", "+3", "+4", "+5", "+6", "+7",
            ],
        }
    }

    /// Get the offset value.
    pub fn get_offset(&self, settings: &Settings) -> usize {
        match settings.get_long(Self::KEY) {
            Some(v) if v >= 0 => v as usize,
            _ => 0,
        }
    }

    /// Get the display value string.
    pub fn get_display_value(&self, settings: &Settings) -> String {
        let idx = self.get_offset(settings);
        self.choices.get(idx).copied().unwrap_or("0").to_string()
    }
}

impl Default for CodeUnitOffsetSettingsDefinition {
    fn default() -> Self {
        Self::new()
    }
}

impl SettingsDefinition for CodeUnitOffsetSettingsDefinition {
    fn name(&self) -> &str {
        Self::KEY
    }
    fn storage_key(&self) -> &str {
        Self::KEY
    }
    fn description(&self) -> &str {
        "Selects the byte offset within the code unit"
    }
}

// ---------------------------------------------------------------------------
// MemoryOffsetSettingsDefinition
// ---------------------------------------------------------------------------

/// Setting definition for memory offset display.
///
/// Ported from `MemoryOffsetSettingsDefinition.java`.
#[derive(Debug)]
pub struct MemoryOffsetSettingsDefinition {
    choices: Vec<&'static str>,
}

impl MemoryOffsetSettingsDefinition {
    /// Setting key.
    pub const KEY: &'static str = "Memory offset";

    /// Create a new definition.
    pub fn new() -> Self {
        Self {
            choices: vec![
                "0", "+1", "+2", "+3", "+4", "+5", "+6", "+7",
            ],
        }
    }

    /// Get the offset value.
    pub fn get_offset(&self, settings: &Settings) -> usize {
        match settings.get_long(Self::KEY) {
            Some(v) if v >= 0 => v as usize,
            _ => 0,
        }
    }

    /// Get the display value string.
    pub fn get_display_value(&self, settings: &Settings) -> String {
        let idx = self.get_offset(settings);
        self.choices.get(idx).copied().unwrap_or("0").to_string()
    }
}

impl Default for MemoryOffsetSettingsDefinition {
    fn default() -> Self {
        Self::new()
    }
}

impl SettingsDefinition for MemoryOffsetSettingsDefinition {
    fn name(&self) -> &str {
        Self::KEY
    }
    fn storage_key(&self) -> &str {
        Self::KEY
    }
    fn description(&self) -> &str {
        "Selects the memory address offset"
    }
}

// ---------------------------------------------------------------------------
// AddressRangeEndpointSettingsDefinition
// ---------------------------------------------------------------------------

/// Setting definition for the address range endpoint.
///
/// Ported from `AddressRangeEndpointSettingsDefinition.java`.
#[derive(Debug)]
pub struct AddressRangeEndpointSettingsDefinition {
    choices: Vec<&'static str>,
}

impl AddressRangeEndpointSettingsDefinition {
    /// Use the start of the address range.
    pub const START: usize = 0;
    /// Use the end of the address range.
    pub const END: usize = 1;
    /// Setting key.
    pub const KEY: &'static str = "Address range endpoint";

    /// Create a new definition.
    pub fn new() -> Self {
        Self {
            choices: vec!["Start", "End"],
        }
    }

    /// Get the endpoint choice (START or END).
    pub fn get_endpoint(&self, settings: &Settings) -> usize {
        match settings.get_long(Self::KEY) {
            Some(1) => Self::END,
            _ => Self::START,
        }
    }
}

impl Default for AddressRangeEndpointSettingsDefinition {
    fn default() -> Self {
        Self::new()
    }
}

impl SettingsDefinition for AddressRangeEndpointSettingsDefinition {
    fn name(&self) -> &str {
        Self::KEY
    }
    fn storage_key(&self) -> &str {
        Self::KEY
    }
    fn description(&self) -> &str {
        "Selects whether to use the start or end of an address range"
    }
}

// ---------------------------------------------------------------------------
// FunctionInlineSettingsDefinition
// ---------------------------------------------------------------------------

/// Setting definition for function inline display.
#[derive(Debug)]
pub struct FunctionInlineSettingsDefinition;
impl SettingsDefinition for FunctionInlineSettingsDefinition {
    fn name(&self) -> &str { "Function Inline" }
    fn storage_key(&self) -> &str { "Function Inline" }
    fn description(&self) -> &str { "Displays whether a function is inline" }
}

// ---------------------------------------------------------------------------
// FunctionNoReturnSettingsDefinition
// ---------------------------------------------------------------------------

/// Setting definition for function no-return display.
#[derive(Debug)]
pub struct FunctionNoReturnSettingsDefinition;
impl SettingsDefinition for FunctionNoReturnSettingsDefinition {
    fn name(&self) -> &str { "Function No Return" }
    fn storage_key(&self) -> &str { "Function No Return" }
    fn description(&self) -> &str { "Displays whether a function does not return" }
}

// ---------------------------------------------------------------------------
// FunctionThunkSettingsDefinition
// ---------------------------------------------------------------------------

/// Setting definition for function thunk display.
#[derive(Debug)]
pub struct FunctionThunkSettingsDefinition;
impl SettingsDefinition for FunctionThunkSettingsDefinition {
    fn name(&self) -> &str { "Function Thunk" }
    fn storage_key(&self) -> &str { "Function Thunk" }
    fn description(&self) -> &str { "Displays whether a function is a thunk" }
}

// ---------------------------------------------------------------------------
// ProgramBasedDynamicTableColumn trait
// ---------------------------------------------------------------------------

/// Trait for table columns that are program-data-source-aware.
///
/// Ported from `ProgramBasedDynamicTableColumn.java`.  This is the
/// extension point interface for program-based table columns.
pub trait ProgramBasedDynamicTableColumn: std::fmt::Debug {
    /// The column's internal name.
    fn column_name(&self) -> &str;

    /// The column's display name (may depend on settings).
    fn column_display_name(&self, _settings: &Settings) -> String {
        self.column_name().to_string()
    }

    /// Preferred width in pixels.
    fn preferred_width(&self) -> usize {
        100
    }

    /// Maximum display lines.
    fn max_lines(&self, _settings: &Settings) -> usize {
        1
    }

    /// Settings definitions applicable to this column.
    fn settings_definitions(&self) -> &[&dyn SettingsDefinition] {
        &[]
    }
}

/// Trait for table columns that map from a ProgramLocation.
///
/// Ported from `ProgramLocationTableColumn.java`.
pub trait ProgramLocationTableColumn: ProgramBasedDynamicTableColumn {
    /// Get the program location for a given row.
    fn get_program_location(&self, row_address: &str) -> Option<String>;
}

// ---------------------------------------------------------------------------
// AddressBasedLocation
// ---------------------------------------------------------------------------

/// A renderable and comparable address-based location.
///
/// Ported from `AddressBasedLocation.java`. Provides the ability to render
/// and compare addresses across different address space types (memory, stack,
/// register, external, variable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressBasedLocation {
    /// The address string representation.
    address: Option<String>,
    /// The rendered string.
    representation: String,
    /// Reference class tag (affects sort order).
    reference_kind: ReferenceKind,
}

/// The kind of reference for sorting purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceKind {
    /// Not a reference.
    None,
    /// A shifted reference.
    Shifted,
    /// An offset reference.
    Offset,
}

impl AddressBasedLocation {
    /// Create a null/bad location.
    pub fn null() -> Self {
        Self {
            address: None,
            representation: "<NULL>".to_string(),
            reference_kind: ReferenceKind::None,
        }
    }

    /// Create a location from a simple memory address.
    pub fn from_address(address: impl Into<String>) -> Self {
        let addr = address.into();
        Self {
            representation: addr.clone(),
            address: Some(addr),
            reference_kind: ReferenceKind::None,
        }
    }

    /// Create a location for an external address.
    pub fn external(symbol: impl Into<String>) -> Self {
        let sym = symbol.into();
        Self {
            address: None,
            representation: format!("External[ {} ]", sym),
            reference_kind: ReferenceKind::None,
        }
    }

    /// Create a location for a stack address.
    pub fn stack(offset: i64) -> Self {
        let neg = offset < 0;
        let abs = if neg { -offset } else { offset };
        let sign = if neg { "-" } else { "+" };
        Self {
            address: None,
            representation: format!("Stack[{}0x{:x}]", sign, abs),
            reference_kind: ReferenceKind::None,
        }
    }

    /// Create a location for a register address.
    pub fn register(name: impl Into<String>) -> Self {
        let n = name.into();
        Self {
            address: None,
            representation: format!("Register[{}]", n),
            reference_kind: ReferenceKind::None,
        }
    }

    /// Create a location for a constant address.
    pub fn constant(offset: i64) -> Self {
        let neg = offset < 0;
        let abs = if neg { -offset } else { offset };
        let sign = if neg { "-" } else { "+" };
        Self {
            address: None,
            representation: format!("Constant[{}0x{:x}]", sign, abs),
            reference_kind: ReferenceKind::None,
        }
    }

    /// Create a location for an offset reference.
    pub fn offset_ref(base: impl Into<String>, offset: i64) -> Self {
        let b = base.into();
        let neg = offset < 0;
        let abs = if neg { -offset } else { offset };
        let sign = if neg { "-" } else { "+" };
        Self {
            address: Some(b.clone()),
            representation: format!("{}{}0x{:x}", b, sign, abs),
            reference_kind: ReferenceKind::Offset,
        }
    }

    /// Create a location for a shifted reference.
    pub fn shifted_ref(address: impl Into<String>, value: u64, shift: u32) -> Self {
        let a = address.into();
        Self {
            address: Some(a.clone()),
            representation: format!("{}(0x{:x}<<{})", a, value, shift),
            reference_kind: ReferenceKind::Shifted,
        }
    }

    /// Whether this corresponds to a memory address.
    pub fn is_memory_location(&self) -> bool {
        self.address.is_some() && self.reference_kind == ReferenceKind::None
    }

    /// Whether this is a reference destination.
    pub fn is_reference_destination(&self) -> bool {
        self.reference_kind != ReferenceKind::None
    }

    /// Whether this is a shifted reference.
    pub fn is_shifted_address(&self) -> bool {
        self.reference_kind == ReferenceKind::Shifted
    }

    /// Whether this is an offset reference.
    pub fn is_offset_address(&self) -> bool {
        self.reference_kind == ReferenceKind::Offset
    }

    /// Get the address string (if any).
    pub fn address(&self) -> Option<&str> {
        self.address.as_deref()
    }
}

impl fmt::Display for AddressBasedLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.representation)
    }
}

impl PartialOrd for AddressBasedLocation {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AddressBasedLocation {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Null addresses sort first.
        match (&self.address, &other.address) {
            (None, None) => self.representation.cmp(&other.representation),
            (None, Some(_)) => std::cmp::Ordering::Less,
            (Some(_), None) => std::cmp::Ordering::Greater,
            (Some(a), Some(b)) => {
                let rc = a.cmp(b);
                if rc != std::cmp::Ordering::Equal {
                    return rc;
                }
                // Same address: sort by reference kind.
                self.representation.cmp(&other.representation)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ReferenceEndpoint
// ---------------------------------------------------------------------------

/// The reference type enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefType {
    /// Read reference.
    Read,
    /// Write reference.
    Write,
    /// Flow/reference from instruction.
    Flow,
    /// Data reference.
    Data,
    /// Parameter reference.
    Parameter,
    /// Other/unknown.
    Other,
}

/// Source type for a reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceType {
    /// User-defined.
    UserDefined,
    /// Analysis-derived.
    Analysis,
    /// Default.
    Default,
    /// Library.
    Library,
    /// Imported.
    Imported,
}

/// An abstract endpoint of a reference.
///
/// Ported from `ReferenceEndpoint.java`. Used by table models showing
/// reference-to or reference-from data.
#[derive(Debug, Clone)]
pub struct ReferenceEndpoint {
    /// The address of this endpoint.
    pub address: String,
    /// The reference type.
    pub ref_type: RefType,
    /// Whether this is an offcut reference.
    pub is_offcut: bool,
    /// Source of the reference.
    pub source: SourceType,
}

impl ReferenceEndpoint {
    /// Create a new reference endpoint.
    pub fn new(
        address: impl Into<String>,
        ref_type: RefType,
        is_offcut: bool,
        source: SourceType,
    ) -> Self {
        Self {
            address: address.into(),
            ref_type,
            is_offcut,
            source,
        }
    }

    /// Get the address.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Whether this is an offcut reference.
    pub fn is_offcut(&self) -> bool {
        self.is_offcut
    }

    /// Get the reference type.
    pub fn reference_type(&self) -> RefType {
        self.ref_type
    }

    /// Get the source type.
    pub fn source(&self) -> SourceType {
        self.source
    }
}

/// An incoming reference endpoint (reference TO this address).
#[derive(Debug, Clone)]
pub struct IncomingReferenceEndpoint {
    /// Base endpoint data.
    pub endpoint: ReferenceEndpoint,
    /// The source function name (if any).
    pub from_function: Option<String>,
    /// The source label (if any).
    pub from_label: Option<String>,
}

impl IncomingReferenceEndpoint {
    /// Create a new incoming reference endpoint.
    pub fn new(endpoint: ReferenceEndpoint) -> Self {
        Self {
            endpoint,
            from_function: None,
            from_label: None,
        }
    }
}

impl std::ops::Deref for IncomingReferenceEndpoint {
    type Target = ReferenceEndpoint;
    fn deref(&self) -> &Self::Target {
        &self.endpoint
    }
}

/// An outgoing reference endpoint (reference FROM this address).
#[derive(Debug, Clone)]
pub struct OutgoingReferenceEndpoint {
    /// Base endpoint data.
    pub endpoint: ReferenceEndpoint,
    /// Whether the destination is offcut.
    pub to_offcut: bool,
}

impl OutgoingReferenceEndpoint {
    /// Create a new outgoing reference endpoint.
    pub fn new(endpoint: ReferenceEndpoint) -> Self {
        let to_offcut = endpoint.is_offcut;
        Self {
            endpoint,
            to_offcut,
        }
    }
}

impl std::ops::Deref for OutgoingReferenceEndpoint {
    type Target = ReferenceEndpoint;
    fn deref(&self) -> &Self::Target {
        &self.endpoint
    }
}

// ---------------------------------------------------------------------------
// CodeUnitTableCellData
// ---------------------------------------------------------------------------

/// Data for rendering a code unit cell in a table.
///
/// Ported from `CodeUnitTableCellData.java`.
#[derive(Debug, Clone)]
pub struct CodeUnitTableCellData {
    /// The address string.
    pub address: String,
    /// Code unit text lines.
    pub lines: Vec<String>,
    /// Byte offset within the code unit.
    pub byte_offset: usize,
    /// Number of code units to show.
    pub code_unit_count: usize,
}

impl CodeUnitTableCellData {
    /// Create new cell data.
    pub fn new(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            lines: Vec::new(),
            byte_offset: 0,
            code_unit_count: 1,
        }
    }

    /// Set the display lines.
    pub fn with_lines(mut self, lines: Vec<String>) -> Self {
        self.lines = lines;
        self
    }

    /// Get the number of display lines.
    pub fn line_count(&self) -> usize {
        self.lines.len().max(1)
    }
}

// ---------------------------------------------------------------------------
// Concrete table columns
// ---------------------------------------------------------------------------

/// Table column for displaying addresses.
///
/// Ported from `AddressTableColumn.java`.
#[derive(Debug)]
pub struct AddressTableColumn;

impl AddressTableColumn {
    /// Column name constant.
    pub const NAME: &'static str = "Location";

    /// Create a new column.
    pub fn new() -> Self {
        Self
    }
}

impl Default for AddressTableColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgramBasedDynamicTableColumn for AddressTableColumn {
    fn column_name(&self) -> &str {
        Self::NAME
    }

    fn preferred_width(&self) -> usize {
        200
    }
}

/// Table column for displaying function names.
///
/// Ported from `FunctionNameTableColumn.java`.
#[derive(Debug)]
pub struct FunctionNameTableColumn;

impl FunctionNameTableColumn {
    /// Create a new column.
    pub fn new() -> Self {
        Self
    }
}

impl Default for FunctionNameTableColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgramBasedDynamicTableColumn for FunctionNameTableColumn {
    fn column_name(&self) -> &str {
        "Function Name"
    }
}

/// Table column for displaying bytes.
///
/// Ported from `BytesTableColumn.java`.
#[derive(Debug)]
pub struct BytesTableColumn;

impl BytesTableColumn {
    /// Byte limit for display.
    pub const BYTE_LIMIT: usize = 20;

    /// Create a new column.
    pub fn new() -> Self {
        Self
    }
}

impl Default for BytesTableColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgramBasedDynamicTableColumn for BytesTableColumn {
    fn column_name(&self) -> &str {
        "Bytes"
    }

    fn column_display_name(&self, settings: &Settings) -> String {
        let bc = ByteCountSettingsDefinition::new();
        let mo = MemoryOffsetSettingsDefinition::new();

        let mut name = self.column_name().to_string();
        let byte_cnt = bc.get_choice(settings);
        if byte_cnt != 0 {
            name += &format!("[{}]", byte_cnt);
        }
        let offset = mo.get_display_value(settings);
        if offset != "0" {
            name += &offset;
        }
        name
    }

    fn settings_definitions(&self) -> &[&dyn SettingsDefinition] {
        // Would return &[&BYTE_COUNT, &MEMORY_OFFSET, &ENDIANNESS, &FORMAT]
        &[]
    }
}

/// Table column for displaying code units.
///
/// Ported from `CodeUnitTableColumn.java`.
#[derive(Debug)]
pub struct CodeUnitTableColumn;

impl CodeUnitTableColumn {
    /// Create a new column.
    pub fn new() -> Self {
        Self
    }
}

impl Default for CodeUnitTableColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgramBasedDynamicTableColumn for CodeUnitTableColumn {
    fn column_name(&self) -> &str {
        "Code Unit"
    }

    fn column_display_name(&self, settings: &Settings) -> String {
        let cuc = CodeUnitCountSettingsDefinition::new();
        let cuo = CodeUnitOffsetSettingsDefinition::new();

        let mut name = self.column_name().to_string();
        let count = cuc.get_count(settings);
        if count != 1 {
            name += &format!("[{}]", count);
        }
        let offset = cuo.get_display_value(settings);
        if offset != "0" {
            name += &offset;
        }
        name
    }

    fn max_lines(&self, settings: &Settings) -> usize {
        let cuc = CodeUnitCountSettingsDefinition::new();
        cuc.get_count(settings)
    }
}

/// Table column for displaying labels.
///
/// Ported from `LabelTableColumn.java`.
#[derive(Debug)]
pub struct LabelTableColumn;

impl LabelTableColumn {
    /// Create a new column.
    pub fn new() -> Self {
        Self
    }
}

impl Default for LabelTableColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgramBasedDynamicTableColumn for LabelTableColumn {
    fn column_name(&self) -> &str {
        "Label"
    }
}

/// Table column for displaying namespaces.
///
/// Ported from `NamespaceTableColumn.java`.
#[derive(Debug)]
pub struct NamespaceTableColumn;

impl NamespaceTableColumn {
    /// Create a new column.
    pub fn new() -> Self {
        Self
    }
}

impl Default for NamespaceTableColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgramBasedDynamicTableColumn for NamespaceTableColumn {
    fn column_name(&self) -> &str {
        "Namespace"
    }
}

/// Table column for displaying end-of-line comments.
///
/// Ported from `EOLCommentTableColumn.java`.
#[derive(Debug)]
pub struct EolCommentTableColumn;

impl EolCommentTableColumn {
    /// Create a new column.
    pub fn new() -> Self {
        Self
    }
}

impl Default for EolCommentTableColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgramBasedDynamicTableColumn for EolCommentTableColumn {
    fn column_name(&self) -> &str {
        "EOL Comment"
    }
}

/// Table column for displaying source types.
///
/// Ported from `SourceTypeTableColumn.java`.
#[derive(Debug)]
pub struct SourceTypeTableColumn;

impl SourceTypeTableColumn {
    /// Create a new column.
    pub fn new() -> Self {
        Self
    }
}

impl Default for SourceTypeTableColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgramBasedDynamicTableColumn for SourceTypeTableColumn {
    fn column_name(&self) -> &str {
        "Source"
    }
}

/// Table column for displaying symbol types.
///
/// Ported from `SymbolTypeTableColumn.java`.
#[derive(Debug)]
pub struct SymbolTypeTableColumn;

impl SymbolTypeTableColumn {
    /// Create a new column.
    pub fn new() -> Self {
        Self
    }
}

impl Default for SymbolTypeTableColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgramBasedDynamicTableColumn for SymbolTypeTableColumn {
    fn column_name(&self) -> &str {
        "Symbol Type"
    }
}

/// Table column for displaying reference types.
///
/// Ported from `ReferenceTypeTableColumn.java`.
#[derive(Debug)]
pub struct ReferenceTypeTableColumn;

impl ReferenceTypeTableColumn {
    /// Create a new column.
    pub fn new() -> Self {
        Self
    }
}

impl Default for ReferenceTypeTableColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgramBasedDynamicTableColumn for ReferenceTypeTableColumn {
    fn column_name(&self) -> &str {
        "Ref Type"
    }
}

/// Table column for displaying the "from" address of a reference.
#[derive(Debug)]
pub struct ReferenceFromAddressTableColumn;
impl ProgramBasedDynamicTableColumn for ReferenceFromAddressTableColumn {
    fn column_name(&self) -> &str { "From Address" }
}

/// Table column for displaying the "to" address of a reference.
#[derive(Debug)]
pub struct ReferenceToAddressTableColumn;
impl ProgramBasedDynamicTableColumn for ReferenceToAddressTableColumn {
    fn column_name(&self) -> &str { "To Address" }
}

/// Table column for displaying reference bytes.
#[derive(Debug)]
pub struct ReferenceFromBytesTableColumn;
impl ProgramBasedDynamicTableColumn for ReferenceFromBytesTableColumn {
    fn column_name(&self) -> &str { "From Bytes" }
}

/// Table column for displaying reference to-bytes.
#[derive(Debug)]
pub struct ReferenceToBytesTableColumn;
impl ProgramBasedDynamicTableColumn for ReferenceToBytesTableColumn {
    fn column_name(&self) -> &str { "To Bytes" }
}

/// Table column for displaying a reference preview.
#[derive(Debug)]
pub struct ReferenceFromPreviewTableColumn;
impl ProgramBasedDynamicTableColumn for ReferenceFromPreviewTableColumn {
    fn column_name(&self) -> &str { "From Preview" }
}

/// Table column for displaying a reference-to preview.
#[derive(Debug)]
pub struct ReferenceToPreviewTableColumn;
impl ProgramBasedDynamicTableColumn for ReferenceToPreviewTableColumn {
    fn column_name(&self) -> &str { "To Preview" }
}

/// Table column for displaying the function containing the reference source.
#[derive(Debug)]
pub struct ReferenceFromFunctionTableColumn;
impl ProgramBasedDynamicTableColumn for ReferenceFromFunctionTableColumn {
    fn column_name(&self) -> &str { "From Function" }
}

/// Table column for displaying the label at the reference source.
#[derive(Debug)]
pub struct ReferenceFromLabelTableColumn;
impl ProgramBasedDynamicTableColumn for ReferenceFromLabelTableColumn {
    fn column_name(&self) -> &str { "From Label" }
}

/// Table column for reference count to an address.
#[derive(Debug)]
pub struct ReferenceCountToAddressTableColumn;
impl ProgramBasedDynamicTableColumn for ReferenceCountToAddressTableColumn {
    fn column_name(&self) -> &str { "Ref Count" }
}

/// Table column for offcut reference count to an address.
#[derive(Debug)]
pub struct OffcutReferenceCountToAddressTableColumn;
impl ProgramBasedDynamicTableColumn for OffcutReferenceCountToAddressTableColumn {
    fn column_name(&self) -> &str { "Offcut Refs" }
}

/// Table column for the preview of code at an address.
#[derive(Debug)]
pub struct PreviewTableColumn;
impl ProgramBasedDynamicTableColumn for PreviewTableColumn {
    fn column_name(&self) -> &str { "Preview" }
}

/// Table column for displaying function body size.
#[derive(Debug)]
pub struct FunctionBodySizeTableColumn;
impl ProgramBasedDynamicTableColumn for FunctionBodySizeTableColumn {
    fn column_name(&self) -> &str { "Body Size" }
}

/// Table column for displaying function calling convention.
#[derive(Debug)]
pub struct FunctionCallingConventionTableColumn;
impl ProgramBasedDynamicTableColumn for FunctionCallingConventionTableColumn {
    fn column_name(&self) -> &str { "Calling Convention" }
}

/// Table column for displaying function parameter count.
#[derive(Debug)]
pub struct FunctionParameterCountTableColumn;
impl ProgramBasedDynamicTableColumn for FunctionParameterCountTableColumn {
    fn column_name(&self) -> &str { "Param Count" }
}

/// Table column for displaying function purge.
#[derive(Debug)]
pub struct FunctionPurgeTableColumn;
impl ProgramBasedDynamicTableColumn for FunctionPurgeTableColumn {
    fn column_name(&self) -> &str { "Purge" }
}

/// Table column for displaying function signature.
#[derive(Debug)]
pub struct FunctionSignatureTableColumn;
impl ProgramBasedDynamicTableColumn for FunctionSignatureTableColumn {
    fn column_name(&self) -> &str { "Signature" }
}

/// Table column for displaying function tag.
#[derive(Debug)]
pub struct FunctionTagTableColumn;
impl ProgramBasedDynamicTableColumn for FunctionTagTableColumn {
    fn column_name(&self) -> &str { "Tag" }
}

/// Table column for displaying function local stack size.
#[derive(Debug)]
pub struct FunctionLocalStackSizeColumn;
impl ProgramBasedDynamicTableColumn for FunctionLocalStackSizeColumn {
    fn column_name(&self) -> &str { "Local Stack Size" }
}

/// Table column for displaying function parameter stack size.
#[derive(Debug)]
pub struct FunctionParameterStackSizeColumn;
impl ProgramBasedDynamicTableColumn for FunctionParameterStackSizeColumn {
    fn column_name(&self) -> &str { "Param Stack Size" }
}

/// Table column for "is function inline".
#[derive(Debug)]
pub struct IsFunctionInlineTableColumn;
impl ProgramBasedDynamicTableColumn for IsFunctionInlineTableColumn {
    fn column_name(&self) -> &str { "Inline" }
}

/// Table column for "is function non-returning".
#[derive(Debug)]
pub struct IsFunctionNonReturningTableColumn;
impl ProgramBasedDynamicTableColumn for IsFunctionNonReturningTableColumn {
    fn column_name(&self) -> &str { "No Return" }
}

/// Table column for "is function thunk".
#[derive(Debug)]
pub struct IsFunctionThunkTableColumn;
impl ProgramBasedDynamicTableColumn for IsFunctionThunkTableColumn {
    fn column_name(&self) -> &str { "Thunk" }
}

/// Table column for "is function varargs".
#[derive(Debug)]
pub struct IsFunctionVarargsTableColumn;
impl ProgramBasedDynamicTableColumn for IsFunctionVarargsTableColumn {
    fn column_name(&self) -> &str { "Varargs" }
}

/// Table column for "is function custom storage".
#[derive(Debug)]
pub struct IsFunctionCustomStorageTableColumn;
impl ProgramBasedDynamicTableColumn for IsFunctionCustomStorageTableColumn {
    fn column_name(&self) -> &str { "Custom Storage" }
}

/// Table column for the address table data column.
#[derive(Debug)]
pub struct AddressTableDataTableColumn;
impl ProgramBasedDynamicTableColumn for AddressTableDataTableColumn {
    fn column_name(&self) -> &str { "Data" }
}

/// Table column for the address table length column.
#[derive(Debug)]
pub struct AddressTableLengthTableColumn;
impl ProgramBasedDynamicTableColumn for AddressTableLengthTableColumn {
    fn column_name(&self) -> &str { "Length" }
}

/// Table column for memory section display.
#[derive(Debug)]
pub struct MemorySectionProgramLocationBasedTableColumn;
impl ProgramBasedDynamicTableColumn for MemorySectionProgramLocationBasedTableColumn {
    fn column_name(&self) -> &str { "Section" }
}

/// Table column for memory source program display.
#[derive(Debug)]
pub struct MemorySourceProgramLocationBasedTableColumn;
impl ProgramBasedDynamicTableColumn for MemorySourceProgramLocationBasedTableColumn {
    fn column_name(&self) -> &str { "Source Program" }
}

/// Table column for memory type display.
#[derive(Debug)]
pub struct MemoryTypeProgramLocationBasedTableColumn;
impl ProgramBasedDynamicTableColumn for MemoryTypeProgramLocationBasedTableColumn {
    fn column_name(&self) -> &str { "Memory Type" }
}

/// Table column for byte count based on program location.
#[derive(Debug)]
pub struct ByteCountProgramLocationBasedTableColumn;
impl ProgramBasedDynamicTableColumn for ByteCountProgramLocationBasedTableColumn {
    fn column_name(&self) -> &str { "Byte Count" }
}

// ---------------------------------------------------------------------------
// MonospacedByteRenderer
// ---------------------------------------------------------------------------

/// A renderer that displays bytes in monospaced format.
///
/// Ported from `MonospacedByteRenderer.java`.
#[derive(Debug)]
pub struct MonospacedByteRenderer {
    /// Separator between bytes.
    pub separator: String,
    /// Whether to use uppercase hex.
    pub uppercase: bool,
}

impl MonospacedByteRenderer {
    /// Create a new renderer with space-separated uppercase hex.
    pub fn new() -> Self {
        Self {
            separator: " ".to_string(),
            uppercase: true,
        }
    }

    /// Render bytes as a hex string.
    pub fn render(&self, bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|b| {
                if self.uppercase {
                    format!("{:02X}", b)
                } else {
                    format!("{:02x}", b)
                }
            })
            .collect::<Vec<_>>()
            .join(&self.separator)
    }
}

impl Default for MonospacedByteRenderer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Extension point interfaces
// ---------------------------------------------------------------------------

/// Extension point trait for program-based dynamic table columns.
///
/// Ported from `ProgramBasedDynamicTableColumnExtensionPoint.java`.
pub trait ProgramBasedDynamicTableColumnExtensionPoint:
    ProgramBasedDynamicTableColumn
{
    /// Return the column's unique ID.
    fn unique_id(&self) -> String {
        self.column_name().to_string()
    }
}

/// Extension point trait for program-location-based table columns.
///
/// Ported from `ProgramLocationTableColumnExtensionPoint.java`.
pub trait ProgramLocationTableColumnExtensionPoint: ProgramLocationTableColumn {
    /// Return the column's unique ID.
    fn unique_id(&self) -> String {
        self.column_name().to_string()
    }
}

// ---------------------------------------------------------------------------
// Abstract table column bases
// ---------------------------------------------------------------------------

/// Abstract base for program-based dynamic table columns.
///
/// Ported from `AbstractProgramBasedDynamicTableColumn.java`.
#[derive(Debug)]
pub struct AbstractProgramBasedDynamicTableColumn {
    unique_id: String,
}

impl AbstractProgramBasedDynamicTableColumn {
    /// Create with the default unique ID.
    pub fn new(unique_id: impl Into<String>) -> Self {
        Self {
            unique_id: unique_id.into(),
        }
    }

    /// Get the unique ID.
    pub fn unique_id(&self) -> &str {
        &self.unique_id
    }
}

/// Abstract base for program-location-based table columns.
///
/// Ported from `AbstractProgramLocationTableColumn.java`.
#[derive(Debug)]
pub struct AbstractProgramLocationTableColumn {
    unique_id: String,
}

impl AbstractProgramLocationTableColumn {
    /// Create with a unique ID.
    pub fn new(unique_id: impl Into<String>) -> Self {
        Self {
            unique_id: unique_id.into(),
        }
    }

    /// Get the unique ID.
    pub fn unique_id(&self) -> &str {
        &self.unique_id
    }
}

/// Abstract base for reference-bytes table columns.
///
/// Ported from `AbstractReferenceBytesTableColumn.java`.
#[derive(Debug)]
pub struct AbstractReferenceBytesTableColumn {
    column_name: String,
}

impl AbstractReferenceBytesTableColumn {
    /// Create a new column.
    pub fn new(column_name: impl Into<String>) -> Self {
        Self {
            column_name: column_name.into(),
        }
    }
}

impl ProgramBasedDynamicTableColumn for AbstractReferenceBytesTableColumn {
    fn column_name(&self) -> &str {
        &self.column_name
    }
}

/// Abstract base for reference preview table columns.
///
/// Ported from `AbstractReferencePreviewTableColumn.java`.
#[derive(Debug)]
pub struct AbstractReferencePreviewTableColumn {
    column_name: String,
}

impl AbstractReferencePreviewTableColumn {
    /// Create a new column.
    pub fn new(column_name: impl Into<String>) -> Self {
        Self {
            column_name: column_name.into(),
        }
    }
}

impl ProgramBasedDynamicTableColumn for AbstractReferencePreviewTableColumn {
    fn column_name(&self) -> &str {
        &self.column_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Settings tests
    // ========================================================================

    #[test]
    fn test_settings_long() {
        let mut s = Settings::new();
        assert!(s.get_long("key").is_none());
        s.set_long("key", 42);
        assert_eq!(s.get_long("key"), Some(42));
        s.clear_setting("key");
        assert!(s.get_long("key").is_none());
    }

    #[test]
    fn test_settings_string() {
        let mut s = Settings::new();
        s.set_string("key", "value");
        assert_eq!(s.get_string("key"), Some("value"));
    }

    // ========================================================================
    // ByteCountSettingsDefinition tests
    // ========================================================================

    #[test]
    fn test_byte_count_default() {
        let def = ByteCountSettingsDefinition::new();
        let s = Settings::new();
        assert_eq!(def.get_choice(&s), 0);
        assert_eq!(def.get_value_string(&s), "default");
    }

    #[test]
    fn test_byte_count_set() {
        let def = ByteCountSettingsDefinition::new();
        let mut s = Settings::new();
        def.set_choice(&mut s, 4);
        assert_eq!(def.get_choice(&s), 4);
        assert_eq!(def.get_value_string(&s), "4");
    }

    #[test]
    fn test_byte_count_clamp() {
        let def = ByteCountSettingsDefinition::new();
        let mut s = Settings::new();
        def.set_choice(&mut s, 99);
        assert_eq!(def.get_choice(&s), 8); // clamped to MAX
    }

    #[test]
    fn test_byte_count_clear() {
        let def = ByteCountSettingsDefinition::new();
        let mut s = Settings::new();
        def.set_choice(&mut s, 3);
        def.clear(&mut s);
        assert_eq!(def.get_choice(&s), 0);
        assert!(!def.has_value(&s));
    }

    #[test]
    fn test_byte_count_display_choices() {
        let def = ByteCountSettingsDefinition::new();
        assert_eq!(def.display_choices().len(), 9);
        assert_eq!(def.display_choice(0), "default");
        assert_eq!(def.display_choice(1), "1");
    }

    // ========================================================================
    // CodeUnitCountSettingsDefinition tests
    // ========================================================================

    #[test]
    fn test_code_unit_count_default() {
        let def = CodeUnitCountSettingsDefinition::new();
        let s = Settings::new();
        assert_eq!(def.get_count(&s), 1); // default maps to 1
    }

    #[test]
    fn test_code_unit_count_set() {
        let def = CodeUnitCountSettingsDefinition::new();
        let mut s = Settings::new();
        def.set_choice(&mut s, 3);
        assert_eq!(def.get_count(&s), 3);
    }

    // ========================================================================
    // MemoryOffsetSettingsDefinition tests
    // ========================================================================

    #[test]
    fn test_memory_offset_default() {
        let def = MemoryOffsetSettingsDefinition::new();
        let s = Settings::new();
        assert_eq!(def.get_offset(&s), 0);
        assert_eq!(def.get_display_value(&s), "0");
    }

    #[test]
    fn test_memory_offset_set() {
        let def = MemoryOffsetSettingsDefinition::new();
        let mut s = Settings::new();
        s.set_long(MemoryOffsetSettingsDefinition::KEY, 3);
        assert_eq!(def.get_offset(&s), 3);
        assert_eq!(def.get_display_value(&s), "+3");
    }

    // ========================================================================
    // AddressRangeEndpointSettingsDefinition tests
    // ========================================================================

    #[test]
    fn test_address_range_endpoint() {
        let def = AddressRangeEndpointSettingsDefinition::new();
        let mut s = Settings::new();
        assert_eq!(def.get_endpoint(&s), AddressRangeEndpointSettingsDefinition::START);
        s.set_long(AddressRangeEndpointSettingsDefinition::KEY, 1);
        assert_eq!(def.get_endpoint(&s), AddressRangeEndpointSettingsDefinition::END);
    }

    // ========================================================================
    // AddressBasedLocation tests
    // ========================================================================

    #[test]
    fn test_address_based_location_null() {
        let loc = AddressBasedLocation::null();
        assert_eq!(loc.to_string(), "<NULL>");
        assert!(!loc.is_memory_location());
    }

    #[test]
    fn test_address_based_location_memory() {
        let loc = AddressBasedLocation::from_address("ram:00401000");
        assert!(loc.is_memory_location());
        assert!(!loc.is_reference_destination());
        assert_eq!(loc.to_string(), "ram:00401000");
    }

    #[test]
    fn test_address_based_location_external() {
        let loc = AddressBasedLocation::external("printf");
        assert_eq!(loc.to_string(), "External[ printf ]");
        assert!(!loc.is_memory_location());
    }

    #[test]
    fn test_address_based_location_stack() {
        let loc = AddressBasedLocation::stack(-8);
        assert_eq!(loc.to_string(), "Stack[-0x8]");
    }

    #[test]
    fn test_address_based_location_register() {
        let loc = AddressBasedLocation::register("EAX");
        assert_eq!(loc.to_string(), "Register[EAX]");
    }

    #[test]
    fn test_address_based_location_constant() {
        let loc = AddressBasedLocation::constant(255);
        assert_eq!(loc.to_string(), "Constant[+0xff]");
    }

    #[test]
    fn test_address_based_location_offset_ref() {
        let loc = AddressBasedLocation::offset_ref("ram:00401000", 16);
        assert!(loc.is_offset_address());
        assert!(loc.is_reference_destination());
        assert_eq!(loc.to_string(), "ram:00401000+0x10");
    }

    #[test]
    fn test_address_based_location_shifted_ref() {
        let loc = AddressBasedLocation::shifted_ref("ram:00401000", 0x1234, 2);
        assert!(loc.is_shifted_address());
        assert!(loc.is_reference_destination());
        assert!(loc.to_string().contains("<<2"));
    }

    #[test]
    fn test_address_based_location_ordering() {
        let null = AddressBasedLocation::null();
        let mem = AddressBasedLocation::from_address("ram:00401000");
        assert!(null < mem);

        let a = AddressBasedLocation::from_address("ram:00400000");
        let b = AddressBasedLocation::from_address("ram:00401000");
        assert!(a < b);
    }

    // ========================================================================
    // ReferenceEndpoint tests
    // ========================================================================

    #[test]
    fn test_reference_endpoint() {
        let ep = ReferenceEndpoint::new("ram:00401000", RefType::Read, false, SourceType::Analysis);
        assert_eq!(ep.address(), "ram:00401000");
        assert!(!ep.is_offcut());
        assert_eq!(ep.reference_type(), RefType::Read);
        assert_eq!(ep.source(), SourceType::Analysis);
    }

    #[test]
    fn test_incoming_reference_endpoint() {
        let ep = ReferenceEndpoint::new("ram:00402000", RefType::Flow, false, SourceType::UserDefined);
        let incoming = IncomingReferenceEndpoint::new(ep);
        assert_eq!(incoming.address(), "ram:00402000");
        assert!(incoming.from_function.is_none());
    }

    #[test]
    fn test_outgoing_reference_endpoint() {
        let ep = ReferenceEndpoint::new("ram:00403000", RefType::Data, true, SourceType::Analysis);
        let outgoing = OutgoingReferenceEndpoint::new(ep);
        assert!(outgoing.to_offcut);
    }

    // ========================================================================
    // Table column tests
    // ========================================================================

    #[test]
    fn test_address_table_column() {
        let col = AddressTableColumn::new();
        assert_eq!(col.column_name(), "Location");
        assert_eq!(col.preferred_width(), 200);
    }

    #[test]
    fn test_function_name_table_column() {
        let col = FunctionNameTableColumn::new();
        assert_eq!(col.column_name(), "Function Name");
    }

    #[test]
    fn test_bytes_table_column() {
        let col = BytesTableColumn::new();
        assert_eq!(col.column_name(), "Bytes");

        let s = Settings::new();
        assert_eq!(col.column_display_name(&s), "Bytes");
    }

    #[test]
    fn test_code_unit_table_column() {
        let col = CodeUnitTableColumn::new();
        assert_eq!(col.column_name(), "Code Unit");

        let s = Settings::new();
        assert_eq!(col.max_lines(&s), 1); // default maps to 1
    }

    #[test]
    fn test_label_table_column() {
        let col = LabelTableColumn::new();
        assert_eq!(col.column_name(), "Label");
    }

    #[test]
    fn test_namespace_table_column() {
        let col = NamespaceTableColumn::new();
        assert_eq!(col.column_name(), "Namespace");
    }

    #[test]
    fn test_eol_comment_table_column() {
        let col = EolCommentTableColumn::new();
        assert_eq!(col.column_name(), "EOL Comment");
    }

    #[test]
    fn test_source_type_table_column() {
        let col = SourceTypeTableColumn::new();
        assert_eq!(col.column_name(), "Source");
    }

    #[test]
    fn test_symbol_type_table_column() {
        let col = SymbolTypeTableColumn::new();
        assert_eq!(col.column_name(), "Symbol Type");
    }

    #[test]
    fn test_function_columns() {
        assert_eq!(FunctionBodySizeTableColumn.column_name(), "Body Size");
        assert_eq!(FunctionCallingConventionTableColumn.column_name(), "Calling Convention");
        assert_eq!(FunctionParameterCountTableColumn.column_name(), "Param Count");
        assert_eq!(FunctionPurgeTableColumn.column_name(), "Purge");
        assert_eq!(FunctionSignatureTableColumn.column_name(), "Signature");
        assert_eq!(FunctionTagTableColumn.column_name(), "Tag");
        assert_eq!(FunctionLocalStackSizeColumn.column_name(), "Local Stack Size");
        assert_eq!(FunctionParameterStackSizeColumn.column_name(), "Param Stack Size");
    }

    #[test]
    fn test_function_bool_columns() {
        assert_eq!(IsFunctionInlineTableColumn.column_name(), "Inline");
        assert_eq!(IsFunctionNonReturningTableColumn.column_name(), "No Return");
        assert_eq!(IsFunctionThunkTableColumn.column_name(), "Thunk");
        assert_eq!(IsFunctionVarargsTableColumn.column_name(), "Varargs");
        assert_eq!(IsFunctionCustomStorageTableColumn.column_name(), "Custom Storage");
    }

    #[test]
    fn test_reference_columns() {
        assert_eq!(ReferenceTypeTableColumn.column_name(), "Ref Type");
        assert_eq!(ReferenceFromAddressTableColumn.column_name(), "From Address");
        assert_eq!(ReferenceToAddressTableColumn.column_name(), "To Address");
        assert_eq!(ReferenceCountToAddressTableColumn.column_name(), "Ref Count");
        assert_eq!(OffcutReferenceCountToAddressTableColumn.column_name(), "Offcut Refs");
    }

    #[test]
    fn test_memory_columns() {
        assert_eq!(MemorySectionProgramLocationBasedTableColumn.column_name(), "Section");
        assert_eq!(MemorySourceProgramLocationBasedTableColumn.column_name(), "Source Program");
        assert_eq!(MemoryTypeProgramLocationBasedTableColumn.column_name(), "Memory Type");
        assert_eq!(ByteCountProgramLocationBasedTableColumn.column_name(), "Byte Count");
    }

    // ========================================================================
    // MonospacedByteRenderer tests
    // ========================================================================

    #[test]
    fn test_monospaced_byte_renderer() {
        let renderer = MonospacedByteRenderer::new();
        assert_eq!(renderer.render(&[0x48, 0x65, 0x6C]), "48 65 6C");
    }

    #[test]
    fn test_monospaced_byte_renderer_lowercase() {
        let mut renderer = MonospacedByteRenderer::new();
        renderer.uppercase = false;
        assert_eq!(renderer.render(&[0xFF, 0xAB]), "ff ab");
    }

    #[test]
    fn test_monospaced_byte_renderer_custom_separator() {
        let mut renderer = MonospacedByteRenderer::new();
        renderer.separator = ":".to_string();
        assert_eq!(renderer.render(&[0x01, 0x02, 0x03]), "01:02:03");
    }

    // ========================================================================
    // CodeUnitTableCellData tests
    // ========================================================================

    #[test]
    fn test_code_unit_table_cell_data() {
        let data = CodeUnitTableCellData::new("0x401000");
        assert_eq!(data.address, "0x401000");
        assert_eq!(data.line_count(), 1);
        assert!(data.lines.is_empty());
    }

    #[test]
    fn test_code_unit_table_cell_data_with_lines() {
        let data = CodeUnitTableCellData::new("0x401000")
            .with_lines(vec!["MOV EAX, 1".to_string(), "RET".to_string()]);
        assert_eq!(data.line_count(), 2);
    }
}
