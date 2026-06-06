//! Core traits for program-location-based table columns.
//!
//! Ported from `ghidra.util.table.field`:
//! - `ProgramBasedDynamicTableColumn` -- column whose data source is a `Program`.
//! - `ProgramLocationTableColumn` -- column that can produce a `ProgramLocation`.
//! - Extension-point marker traits for discoverable columns.

use ghidra_core::addr::Address;

use super::super::mapper::ProgramLocation;

// ---------------------------------------------------------------------------
// Settings (lightweight stand-in for the full Settings framework)
// ---------------------------------------------------------------------------

/// A set of key/value settings for table column configuration.
///
/// This is the Rust equivalent of `ghidra.docking.settings.Settings`.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    values: std::collections::HashMap<String, SettingsValue>,
}

/// A value stored in a [`Settings`] map.
#[derive(Debug, Clone)]
pub enum SettingsValue {
    /// A long integer value.
    Long(i64),
    /// A string value.
    String(String),
    /// A boolean value.
    Bool(bool),
}

impl Settings {
    /// Create empty settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a long value by key.
    pub fn get_long(&self, key: &str) -> Option<i64> {
        match self.values.get(key) {
            Some(SettingsValue::Long(v)) => Some(*v),
            _ => None,
        }
    }

    /// Set a long value.
    pub fn set_long(&mut self, key: impl Into<String>, value: i64) {
        self.values.insert(key.into(), SettingsValue::Long(value));
    }

    /// Get a string value by key.
    pub fn get_string(&self, key: &str) -> Option<&str> {
        match self.values.get(key) {
            Some(SettingsValue::String(v)) => Some(v.as_str()),
            _ => None,
        }
    }

    /// Set a string value.
    pub fn set_string(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.values.insert(key.into(), SettingsValue::String(value.into()));
    }

    /// Get a boolean value by key.
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        match self.values.get(key) {
            Some(SettingsValue::Bool(v)) => Some(*v),
            _ => None,
        }
    }

    /// Check if a value exists for the given key.
    pub fn has_value(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }

    /// Clear a setting by key.
    pub fn clear_setting(&mut self, key: &str) {
        self.values.remove(key);
    }
}

// ---------------------------------------------------------------------------
// ServiceProvider (lightweight stand-in)
// ---------------------------------------------------------------------------

/// A service provider for resolving plugin tool services.
///
/// This is the Rust equivalent of `ghidra.framework.plugintool.ServiceProvider`.
#[derive(Debug, Clone, Default)]
pub struct ServiceProvider {
    /// Name of the associated plugin tool.
    pub tool_name: String,
}

impl ServiceProvider {
    /// Create a new service provider.
    pub fn new(tool_name: impl Into<String>) -> Self {
        Self { tool_name: tool_name.into() }
    }
}

// ---------------------------------------------------------------------------
// Program (lightweight stand-in for program model)
// ---------------------------------------------------------------------------

/// Lightweight program representation for table column context.
///
/// This is a minimal stand-in for `ghidra.program.model.listing.Program`
/// used by the table column framework.
#[derive(Debug, Clone)]
pub struct ProgramInfo {
    /// Program name.
    pub name: String,
    /// Program language ID.
    pub language_id: String,
}

impl ProgramInfo {
    /// Create a new program info.
    pub fn new(name: impl Into<String>, language_id: impl Into<String>) -> Self {
        Self { name: name.into(), language_id: language_id.into() }
    }
}

// ---------------------------------------------------------------------------
// SymbolType
// ---------------------------------------------------------------------------

/// Type of symbol in a program's symbol table.
///
/// Ported from `ghidra.program.model.symbol.SymbolType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolType {
    /// A label at an address.
    Label,
    /// A function symbol.
    Function,
    /// A library symbol.
    Library,
    /// A namespace.
    Namespace,
    /// A class symbol.
    Class,
    /// A parameter symbol.
    Parameter,
    /// A local variable.
    LocalVar,
    /// A global variable.
    GlobalVar,
    /// An external reference.
    External,
    /// A generic symbol.
    Generic,
}

impl SymbolType {
    /// Returns a human-readable display name for the symbol type.
    pub fn display_name(&self) -> &str {
        match self {
            SymbolType::Label => "Label",
            SymbolType::Function => "Function",
            SymbolType::Library => "Library",
            SymbolType::Namespace => "Namespace",
            SymbolType::Class => "Class",
            SymbolType::Parameter => "Parameter",
            SymbolType::LocalVar => "Local Variable",
            SymbolType::GlobalVar => "Global Variable",
            SymbolType::External => "External",
            SymbolType::Generic => "Generic",
        }
    }
}

impl std::fmt::Display for SymbolType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.display_name())
    }
}

// ---------------------------------------------------------------------------
// RefType
// ---------------------------------------------------------------------------

/// Type of reference (xref) between code/data locations.
///
/// Ported from `ghidra.program.model.symbol.RefType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefType {
    /// Unconditional jump/call flow.
    Unconditional,
    /// Conditional jump flow.
    Conditional,
    /// Call flow.
    Call,
    /// Fall-through flow.
    FallThrough,
    /// Data read reference.
    Read,
    /// Data write reference.
    Write,
    /// Data read/write reference.
    ReadWrite,
    /// Indirection reference.
    Indirection,
    /// Computed jump.
    ComputedJump,
    /// Computed call.
    ComputedCall,
    /// Other/miscellaneous reference.
    Other,
}

impl RefType {
    /// Returns a short display string for this reference type.
    pub fn display_string(&self) -> &str {
        match self {
            RefType::Unconditional => "Unconditional",
            RefType::Conditional => "Conditional",
            RefType::Call => "Call",
            RefType::FallThrough => "Fallthrough",
            RefType::Read => "Read",
            RefType::Write => "Write",
            RefType::ReadWrite => "Read/Write",
            RefType::Indirection => "Indirection",
            RefType::ComputedJump => "Computed Jump",
            RefType::ComputedCall => "Computed Call",
            RefType::Other => "Other",
        }
    }

    /// Returns true if this is a flow-type reference (jump/call/fall-through).
    pub fn is_flow(&self) -> bool {
        matches!(self, RefType::Unconditional | RefType::Conditional
                 | RefType::Call | RefType::FallThrough
                 | RefType::ComputedJump | RefType::ComputedCall)
    }
}

impl std::fmt::Display for RefType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.display_string())
    }
}

// ---------------------------------------------------------------------------
// SourceType
// ---------------------------------------------------------------------------

/// Source of a symbol or reference.
///
/// Ported from `ghidra.program.model.symbol.SourceType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceType {
    /// User-defined (default).
    Default,
    /// User-specified.
    UserDefined,
    /// Analysis-generated.
    Analysis,
    /// Imported.
    Import,
}

impl std::fmt::Display for SourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceType::Default => f.write_str("Default"),
            SourceType::UserDefined => f.write_str("User Defined"),
            SourceType::Analysis => f.write_str("Analysis"),
            SourceType::Import => f.write_str("Import"),
        }
    }
}

// ---------------------------------------------------------------------------
// ProgramBasedDynamicTableColumn
// ---------------------------------------------------------------------------

/// A table column whose data source is a [`ProgramInfo`].
///
/// This is the Rust equivalent of
/// `ghidra.util.table.field.ProgramBasedDynamicTableColumn<ROW, COL>`.
pub trait ProgramBasedDynamicTableColumn<ROW>: Send + Sync {
    /// Returns the column header name.
    fn column_name(&self) -> &str;

    /// Returns the column display name, optionally incorporating settings.
    fn column_display_name(&self, settings: &Settings) -> String {
        self.column_name().to_string()
    }

    /// Extracts the column value from a row object.
    fn get_value(&self, row: &ROW, settings: &Settings, program: &ProgramInfo,
                 service_provider: &ServiceProvider) -> Option<String>;

    /// Returns the preferred column width in pixels.
    fn preferred_width(&self) -> usize {
        100
    }
}

// ---------------------------------------------------------------------------
// ProgramLocationTableColumn
// ---------------------------------------------------------------------------

/// A table column that can produce a [`ProgramLocation`] for navigation.
///
/// This is the Rust equivalent of
/// `ghidra.util.table.field.ProgramLocationTableColumn<ROW, COL>`.
pub trait ProgramLocationTableColumn<ROW>: ProgramBasedDynamicTableColumn<ROW> {
    /// Produces a program location for the given row, suitable for navigation.
    fn get_program_location(&self, row: &ROW, settings: &Settings,
                            program: &ProgramInfo, service_provider: &ServiceProvider)
        -> Option<ProgramLocation>;
}

// ---------------------------------------------------------------------------
// Extension-point marker traits
// ---------------------------------------------------------------------------

/// Marker trait for program-location table columns that are discoverable.
///
/// Ported from `ProgramLocationTableColumnExtensionPoint`.
pub trait ProgramLocationTableColumnExt<ROW>: ProgramLocationTableColumn<ROW> {}

/// Marker trait for program-based dynamic table columns that are discoverable.
///
/// Ported from `ProgramBasedDynamicTableColumnExtensionPoint`.
pub trait ProgramBasedDynamicTableColumnExt<ROW>: ProgramBasedDynamicTableColumn<ROW> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settings_long() {
        let mut s = Settings::new();
        assert!(!s.has_value("key"));
        s.set_long("key", 42);
        assert!(s.has_value("key"));
        assert_eq!(s.get_long("key"), Some(42));
        s.clear_setting("key");
        assert!(!s.has_value("key"));
    }

    #[test]
    fn test_settings_string() {
        let mut s = Settings::new();
        s.set_string("name", "test");
        assert_eq!(s.get_string("name"), Some("test"));
    }

    #[test]
    fn test_symbol_type_display() {
        assert_eq!(SymbolType::Function.to_string(), "Function");
        assert_eq!(SymbolType::Label.to_string(), "Label");
        assert_eq!(SymbolType::Parameter.display_name(), "Parameter");
    }

    #[test]
    fn test_ref_type_display() {
        assert_eq!(RefType::Call.display_string(), "Call");
        assert!(RefType::Unconditional.is_flow());
        assert!(RefType::Call.is_flow());
        assert!(!RefType::Read.is_flow());
    }

    #[test]
    fn test_source_type_display() {
        assert_eq!(SourceType::Analysis.to_string(), "Analysis");
        assert_eq!(SourceType::UserDefined.to_string(), "User Defined");
    }
}
