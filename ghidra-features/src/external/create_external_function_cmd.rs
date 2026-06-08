//! CreateExternalFunctionCmd -- command for creating external functions.
//!
//! Ported from `ghidra.app.cmd.function.CreateExternalFunctionCmd`.
//!
//! This command creates a new external function entry or converts an
//! existing external label symbol into a function.  It supports three
//! modes of construction:
//!
//! 1. From an existing external symbol (convert label to function)
//! 2. By library name and function name
//! 3. By parent namespace and function name
//!
//! # Examples
//!
//! ```rust
//! use ghidra_features::external::{
//!     CreateExternalFunctionCmd, ExternalManagerDB, ExternalLocationDB,
//! };
//! use ghidra_core::symbol::SourceType;
//! use ghidra_core::addr::Address;
//!
//! // Create by library name
//! let cmd = CreateExternalFunctionCmd::by_library(
//!     "libc",
//!     "printf",
//!     Some(Address::new(0x1000)),
//!     SourceType::Imported,
//! );
//!
//! assert_eq!(cmd.name(), "Create External Function");
//! ```

use std::fmt;

use ghidra_core::addr::Address;
use ghidra_core::symbol::SourceType;

use super::external_location_db::{ExternalLocationDB, ExternalLocationError, ExtResult};
use super::external_manager_db::ExternalManagerDB;
use super::UNKNOWN_LIBRARY;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors that can occur when creating an external function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateExternalFunctionError {
    /// The external symbol was null or invalid.
    InvalidSymbol(String),
    /// A duplicate name was found.
    DuplicateName(String),
    /// Invalid input was provided.
    InvalidInput(String),
    /// The namespace is not external.
    NotExternal(String),
    /// General error.
    Other(String),
}

impl fmt::Display for CreateExternalFunctionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CreateExternalFunctionError::InvalidSymbol(msg) => {
                write!(f, "Invalid symbol: {}", msg)
            }
            CreateExternalFunctionError::DuplicateName(name) => {
                write!(f, "Duplicate name: {}", name)
            }
            CreateExternalFunctionError::InvalidInput(msg) => {
                write!(f, "Invalid input: {}", msg)
            }
            CreateExternalFunctionError::NotExternal(ns) => {
                write!(f, "Not an external namespace: {}", ns)
            }
            CreateExternalFunctionError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for CreateExternalFunctionError {}

impl From<ExternalLocationError> for CreateExternalFunctionError {
    fn from(e: ExternalLocationError) -> Self {
        match e {
            ExternalLocationError::InvalidInput(msg) => {
                CreateExternalFunctionError::InvalidInput(msg)
            }
            ExternalLocationError::DuplicateName(name) => {
                CreateExternalFunctionError::DuplicateName(name)
            }
            ExternalLocationError::NotExternal(ns) => {
                CreateExternalFunctionError::NotExternal(ns)
            }
            _ => CreateExternalFunctionError::Other(e.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Construction mode
// ---------------------------------------------------------------------------

/// Internal representation of how the command was constructed.
#[derive(Debug, Clone)]
enum ConstructionMode {
    /// Convert an existing external label symbol to a function.
    FromSymbol(ExternalLocationDB),
    /// Create by library name, function name, optional address, and source.
    ByLibrary {
        library_name: String,
        name: String,
        address: Option<Address>,
        source: SourceType,
    },
    /// Create by parent namespace (library), function name, optional address, and source.
    ByNamespace {
        parent_library: String,
        name: String,
        address: Option<Address>,
        source: SourceType,
    },
}

// ---------------------------------------------------------------------------
// CreateExternalFunctionCmd
// ---------------------------------------------------------------------------

/// Command for creating an external function.
///
/// This is the Rust port of Ghidra's `CreateExternalFunctionCmd`.  It
/// either converts an existing external label symbol to a function or
/// creates a new external function entry in the external manager.
///
/// # Modes
///
/// - [`CreateExternalFunctionCmd::from_symbol`] -- convert existing symbol
/// - [`CreateExternalFunctionCmd::by_library`] -- create by library name
/// - [`CreateExternalFunctionCmd::by_namespace`] -- create by namespace
#[derive(Debug, Clone)]
pub struct CreateExternalFunctionCmd {
    mode: ConstructionMode,
    /// The resulting external location after successful execution.
    result: Option<ExternalLocationDB>,
    /// Error message from the last execution.
    status: Option<String>,
}

impl CreateExternalFunctionCmd {
    // ------------------------------------------------------------------
    // Constructors
    // ------------------------------------------------------------------

    /// Create a command that converts an existing external label symbol
    /// to a function.
    ///
    /// # Arguments
    ///
    /// * `ext_location` -- the existing external location (must be a label,
    ///   not already a function).
    pub fn from_symbol(ext_location: ExternalLocationDB) -> Self {
        Self {
            mode: ConstructionMode::FromSymbol(ext_location),
            result: None,
            status: None,
        }
    }

    /// Create a command that adds a new external function by library name.
    ///
    /// # Arguments
    ///
    /// * `library_name` -- the external library name.  If `None` or empty,
    ///   `UNKNOWN_LIBRARY` is used.
    /// * `name` -- the function name (required).
    /// * `address` -- optional address of the function's entry point in
    ///   the external library.
    /// * `source` -- the source type for this external function.
    ///
    /// # Panics
    ///
    /// Panics if `name` is `None` or empty, or if `source` is not provided.
    pub fn by_library(
        library_name: impl Into<String>,
        name: impl Into<String>,
        address: Option<Address>,
        source: SourceType,
    ) -> Self {
        let lib = library_name.into();
        let lib = if lib.is_empty() {
            UNKNOWN_LIBRARY.to_string()
        } else {
            lib
        };
        let n = name.into();
        assert!(!n.is_empty(), "External function name must be specified");

        Self {
            mode: ConstructionMode::ByLibrary {
                library_name: lib,
                name: n,
                address,
                source,
            },
            result: None,
            status: None,
        }
    }

    /// Create a command that adds a new external function by parent namespace.
    ///
    /// # Arguments
    ///
    /// * `parent_library` -- the external library (namespace) name.
    /// * `name` -- the function name (required).
    /// * `address` -- optional address of the function's entry point.
    /// * `source` -- the source type.
    ///
    /// # Panics
    ///
    /// Panics if `parent_library` or `name` is empty.
    pub fn by_namespace(
        parent_library: impl Into<String>,
        name: impl Into<String>,
        address: Option<Address>,
        source: SourceType,
    ) -> Self {
        let ns = parent_library.into();
        assert!(!ns.is_empty(), "A parent namespace must be specified.");
        let n = name.into();
        assert!(!n.is_empty(), "Function name must be specified.");

        Self {
            mode: ConstructionMode::ByNamespace {
                parent_library: ns,
                name: n,
                address,
                source,
            },
            result: None,
            status: None,
        }
    }

    // ------------------------------------------------------------------
    // Execution
    // ------------------------------------------------------------------

    /// Execute the command against the given external manager.
    ///
    /// Returns `true` if the command succeeded, `false` otherwise.
    /// After a successful call, [`result`](Self::result) contains the
    /// created or converted external location.
    pub fn apply_to(&mut self, ext_mgr: &mut ExternalManagerDB) -> bool {
        self.status = None;

        match &self.mode {
            ConstructionMode::FromSymbol(ext_loc) => {
                // Convert an existing label to a function
                if ext_loc.is_function() {
                    // Already a function, nothing to do
                    self.result = Some(ext_loc.clone());
                    return true;
                }
                let mut converted = ext_loc.clone();
                converted.convert_to_function();
                self.result = Some(converted);
                true
            }
            ConstructionMode::ByLibrary {
                library_name,
                name,
                address,
                source,
            } => {
                let lib = library_name.clone();
                let n = name.clone();
                let addr = *address;
                let src = *source;
                match self.create_function_by_library(ext_mgr, &lib, &n, addr, src) {
                    Ok(loc) => {
                        self.result = Some(loc);
                        true
                    }
                    Err(e) => {
                        self.status = Some(e.to_string());
                        false
                    }
                }
            }
            ConstructionMode::ByNamespace {
                parent_library,
                name,
                address,
                source,
            } => {
                let ns = parent_library.clone();
                let n = name.clone();
                let addr = *address;
                let src = *source;
                match self.create_function_by_namespace(ext_mgr, &ns, &n, addr, src) {
                    Ok(loc) => {
                        self.result = Some(loc);
                        true
                    }
                    Err(e) => {
                        self.status = Some(e.to_string());
                        false
                    }
                }
            }
        }
    }

    fn create_function_by_library(
        &self,
        ext_mgr: &mut ExternalManagerDB,
        library_name: &str,
        name: &str,
        address: Option<Address>,
        source: SourceType,
    ) -> Result<ExternalLocationDB, CreateExternalFunctionError> {
        let mut loc = ExternalLocationDB::new_function(library_name, name, address, source);
        ext_mgr
            .add_external_location(loc.clone())
            .map_err(CreateExternalFunctionError::from)?;
        Ok(loc)
    }

    fn create_function_by_namespace(
        &self,
        ext_mgr: &mut ExternalManagerDB,
        parent_library: &str,
        name: &str,
        address: Option<Address>,
        source: SourceType,
    ) -> Result<ExternalLocationDB, CreateExternalFunctionError> {
        // Ensure the library exists
        if ext_mgr.get_external_library(parent_library).is_none() {
            ext_mgr
                .add_external_library_name(parent_library, source)
                .map_err(|e| CreateExternalFunctionError::Other(e.to_string()))?;
        }
        let mut loc = ExternalLocationDB::new_function(parent_library, name, address, source);
        ext_mgr
            .add_external_location(loc.clone())
            .map_err(CreateExternalFunctionError::from)?;
        Ok(loc)
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    /// Returns the command name.
    pub fn name(&self) -> &str {
        "Create External Function"
    }

    /// Returns the status message from the last execution, if any.
    pub fn status_msg(&self) -> Option<&str> {
        self.status.as_deref()
    }

    /// Returns the resulting external location, if the command succeeded.
    pub fn result(&self) -> Option<&ExternalLocationDB> {
        self.result.as_ref()
    }

    /// Consumes the command and returns the resulting external location.
    pub fn into_result(self) -> Option<ExternalLocationDB> {
        self.result
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_by_library() {
        let cmd = CreateExternalFunctionCmd::by_library(
            "libc",
            "printf",
            Some(Address::new(0x1000)),
            SourceType::Imported,
        );
        assert_eq!(cmd.name(), "Create External Function");
        assert!(cmd.result().is_none());
        assert!(cmd.status_msg().is_none());
    }

    #[test]
    fn test_create_by_library_unknown() {
        let cmd = CreateExternalFunctionCmd::by_library(
            "",
            "func",
            None,
            SourceType::Analysis,
        );
        // Empty library name should default to UNKNOWN
        match &cmd.mode {
            ConstructionMode::ByLibrary { library_name, .. } => {
                assert_eq!(library_name, UNKNOWN_LIBRARY);
            }
            _ => panic!("Expected ByLibrary mode"),
        }
    }

    #[test]
    fn test_create_by_namespace() {
        let cmd = CreateExternalFunctionCmd::by_namespace(
            "kernel32.dll",
            "GetLastError",
            None,
            SourceType::Imported,
        );
        assert_eq!(cmd.name(), "Create External Function");
    }

    #[test]
    fn test_apply_by_library() {
        let mut ext_mgr = ExternalManagerDB::new();
        let mut cmd = CreateExternalFunctionCmd::by_library(
            "libc",
            "printf",
            Some(Address::new(0x1000)),
            SourceType::Imported,
        );

        assert!(cmd.apply_to(&mut ext_mgr));
        assert!(cmd.result().is_some());
        let loc = cmd.result().unwrap();
        assert!(loc.is_function());
        assert_eq!(loc.label(), Some("printf"));
        assert_eq!(loc.library_name(), "libc");
    }

    #[test]
    fn test_convert_label_to_function() {
        let label = ExternalLocationDB::new_data("libc", "my_func", None, SourceType::Imported);
        assert!(!label.is_function());

        let mut ext_mgr = ExternalManagerDB::new();
        let mut cmd = CreateExternalFunctionCmd::from_symbol(label);

        assert!(cmd.apply_to(&mut ext_mgr));
        let result = cmd.result().unwrap();
        assert!(result.is_function());
        assert_eq!(result.label(), Some("my_func"));
    }

    #[test]
    fn test_convert_already_function() {
        let func = ExternalLocationDB::new_function("libc", "printf", None, SourceType::Imported);
        assert!(func.is_function());

        let mut ext_mgr = ExternalManagerDB::new();
        let mut cmd = CreateExternalFunctionCmd::from_symbol(func);

        assert!(cmd.apply_to(&mut ext_mgr));
        assert!(cmd.result().unwrap().is_function());
    }

    #[test]
    fn test_apply_by_namespace_creates_library() {
        let mut ext_mgr = ExternalManagerDB::new();
        assert!(ext_mgr.get_external_library("newlib").is_none());

        let mut cmd = CreateExternalFunctionCmd::by_namespace(
            "newlib",
            "malloc",
            Some(Address::new(0x2000)),
            SourceType::Imported,
        );

        assert!(cmd.apply_to(&mut ext_mgr));
        // Library should have been created
        assert!(ext_mgr.get_external_library("newlib").is_some());
    }

    #[test]
    #[should_panic(expected = "External function name must be specified")]
    fn test_panic_on_empty_name() {
        CreateExternalFunctionCmd::by_library("libc", "", None, SourceType::Default);
    }

    #[test]
    #[should_panic(expected = "A parent namespace must be specified.")]
    fn test_panic_on_empty_namespace() {
        CreateExternalFunctionCmd::by_namespace("", "func", None, SourceType::Default);
    }

    #[test]
    fn test_into_result() {
        let mut ext_mgr = ExternalManagerDB::new();
        let mut cmd = CreateExternalFunctionCmd::by_library(
            "libc",
            "puts",
            None,
            SourceType::Analysis,
        );
        assert!(cmd.apply_to(&mut ext_mgr));

        let loc = cmd.into_result();
        assert!(loc.is_some());
        assert_eq!(loc.unwrap().label(), Some("puts"));
    }
}
