//! ExternalLocationDB -- database-backed external location.
//!
//! Ported from `ghidra.program.database.external.ExternalLocationDB`.
//!
//! An external location represents a reference to a symbol (function or
//! data) in an external library.  Each location has:
//! - a label (the symbol name)
//! - an optional address in the external program
//! - a source type (user-defined, imported, analysis, default)
//! - an optional original imported name (for mangled names)
//! - a parent namespace (usually a Library)
//!
//! This implementation uses in-memory storage rather than a database
//! handle, but preserves the same API.

use std::fmt;

use ghidra_core::addr::Address;
use ghidra_core::symbol::SourceType;

/// Errors that can occur with external locations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalLocationError {
    /// The label or address is invalid.
    InvalidInput(String),
    /// A duplicate name exists in the namespace.
    DuplicateName(String),
    /// The namespace is not external.
    NotExternal(String),
    /// The address is not a valid memory address.
    InvalidAddress(String),
    /// General error.
    Other(String),
}

impl fmt::Display for ExternalLocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExternalLocationError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            ExternalLocationError::DuplicateName(name) => {
                write!(f, "Duplicate name: {}", name)
            }
            ExternalLocationError::NotExternal(ns) => {
                write!(f, "Not an external namespace: {}", ns)
            }
            ExternalLocationError::InvalidAddress(addr) => {
                write!(f, "Invalid address: {}", addr)
            }
            ExternalLocationError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ExternalLocationError {}

/// Result type for external location operations.
pub type ExtResult<T> = Result<T, ExternalLocationError>;

/// A database-backed external location.
///
/// Represents a reference to a symbol in an external library.  This is
/// the Rust port of Ghidra's `ExternalLocationDB`.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::ExternalLocationDB;
/// use ghidra_core::symbol::SourceType;
/// use ghidra_core::Address;
///
/// let mut loc = ExternalLocationDB::new_function(
///     "libc",
///     "printf",
///     Some(Address::new(0x1234)),
///     SourceType::Imported,
/// );
///
/// assert_eq!(loc.label(), Some("printf"));
/// assert!(loc.is_function());
/// assert_eq!(loc.library_name(), "libc");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalLocationDB {
    /// The library name this location belongs to.
    library_name: String,
    /// The namespace path within the library (e.g., "std::io").
    namespace_path: Vec<String>,
    /// The label (symbol name).
    label: Option<String>,
    /// The original imported name (before demangling, etc.).
    original_imported_name: Option<String>,
    /// The address in the external program.
    external_program_address: Option<Address>,
    /// The address in the external (special) address space.
    external_space_address: Option<Address>,
    /// Whether this location represents a function.
    is_function: bool,
    /// The source of this location.
    source: SourceType,
    /// The data type ID (for data locations).
    data_type_id: Option<i64>,
    /// The symbol ID in the symbol table.
    symbol_id: Option<u64>,
}

impl ExternalLocationDB {
    // ------------------------------------------------------------------
    // Constructors
    // ------------------------------------------------------------------

    /// Create a new external function location.
    pub fn new_function(
        library_name: impl Into<String>,
        label: impl Into<String>,
        external_program_address: Option<Address>,
        source: SourceType,
    ) -> Self {
        Self {
            library_name: library_name.into(),
            namespace_path: Vec::new(),
            label: Some(label.into()),
            original_imported_name: None,
            external_program_address,
            external_space_address: None,
            is_function: true,
            source,
            data_type_id: None,
            symbol_id: None,
        }
    }

    /// Create a new external data location.
    pub fn new_data(
        library_name: impl Into<String>,
        label: impl Into<String>,
        external_program_address: Option<Address>,
        source: SourceType,
    ) -> Self {
        Self {
            library_name: library_name.into(),
            namespace_path: Vec::new(),
            label: Some(label.into()),
            original_imported_name: None,
            external_program_address,
            external_space_address: None,
            is_function: false,
            source,
            data_type_id: None,
            symbol_id: None,
        }
    }

    /// Create an external location with only an address (default source).
    pub fn new_address_only(
        library_name: impl Into<String>,
        external_program_address: Address,
    ) -> Self {
        Self {
            library_name: library_name.into(),
            namespace_path: Vec::new(),
            label: None,
            original_imported_name: None,
            external_program_address: Some(external_program_address),
            external_space_address: None,
            is_function: false,
            source: SourceType::Default,
            data_type_id: None,
            symbol_id: None,
        }
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    /// Returns the library name.
    pub fn library_name(&self) -> &str {
        &self.library_name
    }

    /// Returns the namespace path.
    pub fn namespace_path(&self) -> &[String] {
        &self.namespace_path
    }

    /// Returns the label (symbol name).
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Returns the original imported name.
    pub fn original_imported_name(&self) -> Option<&str> {
        self.original_imported_name.as_deref()
    }

    /// Returns the external program address.
    pub fn external_program_address(&self) -> Option<Address> {
        self.external_program_address
    }

    /// Returns the external program address (alias).
    pub fn external_address(&self) -> Option<Address> {
        self.external_program_address
    }

    /// Returns the external space address.
    pub fn external_space_address(&self) -> Option<Address> {
        self.external_space_address
    }

    /// Returns `true` if this location represents a function.
    pub fn is_function(&self) -> bool {
        self.is_function
    }

    /// Returns the source type.
    pub fn source(&self) -> SourceType {
        self.source
    }

    /// Returns the data type ID.
    pub fn data_type_id(&self) -> Option<i64> {
        self.data_type_id
    }

    /// Returns the symbol ID.
    pub fn symbol_id(&self) -> Option<u64> {
        self.symbol_id
    }

    /// Returns the fully qualified name (library::label or library::ns::label).
    pub fn qualified_name(&self) -> String {
        let mut parts = Vec::new();
        parts.push(self.library_name.clone());
        parts.extend(self.namespace_path.clone());
        if let Some(label) = &self.label {
            parts.push(label.clone());
        }
        parts.join("::")
    }

    /// Returns the display name (for toString in Java).
    pub fn display_name(&self) -> String {
        let mut result = self
            .label
            .clone()
            .unwrap_or_else(|| "<default>".to_string());

        if let Some(orig) = &self.original_imported_name {
            if Some(orig.as_str()) != self.label.as_deref() {
                result = format!("{} ({})", result, orig);
            }
        }
        result
    }

    // ------------------------------------------------------------------
    // Mutators
    // ------------------------------------------------------------------

    /// Set the label and optionally address.
    pub fn set_location(
        &mut self,
        label: Option<&str>,
        addr: Option<Address>,
        source: SourceType,
    ) -> ExtResult<()> {
        if label.is_none() && addr.is_none() {
            return Err(ExternalLocationError::InvalidInput(
                "Either an external label or address is required".into(),
            ));
        }
        if let Some(l) = label {
            if l.is_empty() {
                self.label = None;
            } else {
                self.label = Some(l.to_string());
            }
        }
        if let Some(a) = addr {
            self.external_program_address = Some(a);
        }
        self.source = source;
        Ok(())
    }

    /// Set the address.
    pub fn set_address(&mut self, address: Option<Address>) -> ExtResult<()> {
        if address.is_none() && self.source == SourceType::Default && self.label.is_none() {
            return Err(ExternalLocationError::InvalidInput(
                "Either an external label or address is required".into(),
            ));
        }
        self.external_program_address = address;
        Ok(())
    }

    /// Set the label.
    pub fn set_label(&mut self, label: Option<&str>, source: SourceType) {
        if let Some(l) = label {
            if l.is_empty() {
                self.label = None;
            } else {
                self.label = Some(l.to_string());
            }
        } else {
            self.label = None;
        }
        self.source = source;
    }

    /// Set the original imported name.
    pub fn set_original_imported_name(&mut self, name: impl Into<Option<String>>) {
        self.original_imported_name = name.into();
    }

    /// Set the data type ID.
    pub fn set_data_type_id(&mut self, id: Option<i64>) {
        self.data_type_id = id;
    }

    /// Set the symbol ID.
    pub fn set_symbol_id(&mut self, id: Option<u64>) {
        self.symbol_id = id;
    }

    /// Set the namespace path.
    pub fn set_namespace_path(&mut self, path: Vec<String>) {
        self.namespace_path = path;
    }

    /// Save the original imported name if needed (before renaming).
    pub fn save_original_name_if_needed(
        &mut self,
        old_source: SourceType,
    ) {
        // If the current label matches the original, clear it
        if self.label.as_deref() == self.original_imported_name.as_deref() {
            self.original_imported_name = None;
        }
        // If this is an imported symbol being renamed for the first time, save the original
        else if self.original_imported_name.is_none()
            && self.source != SourceType::Default
            && old_source == SourceType::Imported
        {
            if let Some(label) = &self.label {
                self.original_imported_name = Some(label.clone());
            }
        }
    }

    /// Restore the original imported name.
    pub fn restore_original_name(&mut self) -> ExtResult<()> {
        if let Some(original) = self.original_imported_name.clone() {
            self.label = Some(original);
            self.original_imported_name = None;
            self.source = SourceType::Imported;
        }
        Ok(())
    }

    /// Convert this location to a function location.
    pub fn convert_to_function(&mut self) {
        self.is_function = true;
    }

    /// Check if this location is equivalent to another.
    pub fn is_equivalent(&self, other: &ExternalLocationDB) -> bool {
        // Must be the same type
        if self.is_function != other.is_function {
            return false;
        }

        // If original import names match, they are equivalent
        if self.original_imported_name.is_some()
            && self.original_imported_name == other.original_imported_name
        {
            return true;
        }

        // If the name of one matches the original import name of the other
        if self.label.is_some() && self.label == other.original_imported_name {
            return true;
        }
        if other.label.is_some() && other.label == self.original_imported_name {
            return true;
        }

        // If both have originals but they don't match, not equivalent
        if self.original_imported_name.is_some() || other.original_imported_name.is_some() {
            return false;
        }

        // Compare label and address
        self.label == other.label && self.external_program_address == other.external_program_address
    }
}

impl fmt::Display for ExternalLocationDB {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_location() {
        let loc = ExternalLocationDB::new_function(
            "libc",
            "printf",
            Some(Address::new(0x1000)),
            SourceType::Imported,
        );

        assert!(loc.is_function());
        assert_eq!(loc.label(), Some("printf"));
        assert_eq!(loc.library_name(), "libc");
        assert_eq!(loc.source(), SourceType::Imported);
        assert_eq!(loc.external_program_address(), Some(Address::new(0x1000)));
    }

    #[test]
    fn test_data_location() {
        let loc = ExternalLocationDB::new_data(
            "kernel32.dll",
            "GetLastError",
            None,
            SourceType::Analysis,
        );

        assert!(!loc.is_function());
        assert_eq!(loc.label(), Some("GetLastError"));
    }

    #[test]
    fn test_address_only() {
        let loc = ExternalLocationDB::new_address_only("libc", Address::new(0x2000));

        assert!(loc.label().is_none());
        assert_eq!(loc.source(), SourceType::Default);
        assert_eq!(loc.external_program_address(), Some(Address::new(0x2000)));
    }

    #[test]
    fn test_set_location() {
        let mut loc = ExternalLocationDB::new_function("libc", "old", None, SourceType::Analysis);
        loc.set_location(Some("new"), Some(Address::new(0x3000)), SourceType::UserDefined)
            .unwrap();

        assert_eq!(loc.label(), Some("new"));
        assert_eq!(loc.external_program_address(), Some(Address::new(0x3000)));
        assert_eq!(loc.source(), SourceType::UserDefined);
    }

    #[test]
    fn test_set_location_no_label_no_address() {
        let mut loc = ExternalLocationDB::new_function("libc", "func", None, SourceType::Analysis);
        assert!(loc.set_location(None, None, SourceType::Default).is_err());
    }

    #[test]
    fn test_qualified_name() {
        let mut loc = ExternalLocationDB::new_function("libc", "printf", None, SourceType::Imported);
        loc.set_namespace_path(vec!["std".into()]);
        assert_eq!(loc.qualified_name(), "libc::std::printf");
    }

    #[test]
    fn test_display_name_with_original() {
        let mut loc = ExternalLocationDB::new_function("libc", "printf", None, SourceType::Imported);
        loc.set_original_imported_name(Some("_printf".into()));
        assert_eq!(loc.display_name(), "printf (_printf)");
    }

    #[test]
    fn test_equivalence() {
        let loc1 = ExternalLocationDB::new_function("libc", "printf", None, SourceType::Imported);
        let loc2 = ExternalLocationDB::new_function("libc", "printf", None, SourceType::Imported);
        assert!(loc1.is_equivalent(&loc2));

        let loc3 = ExternalLocationDB::new_data("libc", "printf", None, SourceType::Imported);
        assert!(!loc1.is_equivalent(&loc3)); // different type
    }

    #[test]
    fn test_equivalence_original_import() {
        let mut loc1 =
            ExternalLocationDB::new_function("libc", "printf", None, SourceType::Imported);
        loc1.set_original_imported_name(Some("_printf".into()));

        let mut loc2 =
            ExternalLocationDB::new_function("libc", "puts", None, SourceType::Imported);
        loc2.set_original_imported_name(Some("_printf".into()));

        // Same original import name
        assert!(loc1.is_equivalent(&loc2));
    }

    #[test]
    fn test_restore_original() {
        let mut loc = ExternalLocationDB::new_function("libc", "func", None, SourceType::Imported);
        loc.set_original_imported_name(Some("_original_func".into()));

        loc.label = Some("demangled_func".to_string());
        loc.restore_original_name().unwrap();

        assert_eq!(loc.label(), Some("_original_func"));
        assert!(loc.original_imported_name().is_none());
        assert_eq!(loc.source(), SourceType::Imported);
    }

    #[test]
    fn test_convert_to_function() {
        let mut loc = ExternalLocationDB::new_data("libc", "global_var", None, SourceType::Analysis);
        assert!(!loc.is_function());
        loc.convert_to_function();
        assert!(loc.is_function());
    }

    #[test]
    fn test_display() {
        let loc = ExternalLocationDB::new_function("libc", "printf", None, SourceType::Imported);
        assert_eq!(loc.to_string(), "printf");
    }
}
