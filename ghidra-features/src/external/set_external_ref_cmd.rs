//! SetExternalRefCmd -- command for adding external references.
//!
//! Ported from `ghidra.app.cmd.refs.SetExternalRefCmd`.
//!
//! This command adds an external reference from a source address in
//! the current program to an external location (function or data) in
//! an external library.  In Ghidra's Java implementation this calls
//! `ReferenceManager.addExternalReference()`; here we adapt it to
//! work with [`ExternalManagerDB`] by adding or retrieving an
//! external location.

use std::fmt;

use ghidra_core::addr::Address;
use ghidra_core::symbol::SourceType;

use super::external_location_db::{ExternalLocationDB, ExternalLocationError, ExtResult};
use super::external_manager_db::ExternalManagerDB;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors that can occur when setting an external reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetExternalRefError {
    /// A duplicate name was found in the namespace.
    DuplicateName(String),
    /// Invalid input was provided.
    InvalidInput(String),
    /// General error.
    Other(String),
}

impl fmt::Display for SetExternalRefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SetExternalRefError::DuplicateName(name) => {
                write!(f, "{} already exists", name)
            }
            SetExternalRefError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            SetExternalRefError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for SetExternalRefError {}

impl From<ExternalLocationError> for SetExternalRefError {
    fn from(e: ExternalLocationError) -> Self {
        match e {
            ExternalLocationError::DuplicateName(name) => {
                SetExternalRefError::DuplicateName(name)
            }
            ExternalLocationError::InvalidInput(msg) => {
                SetExternalRefError::InvalidInput(msg)
            }
            _ => SetExternalRefError::Other(e.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// RefType
// ---------------------------------------------------------------------------

/// The type of external reference.
///
/// This corresponds to Ghidra's `RefType` enum, simplified for the
/// external reference use case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExternalRefType {
    /// A data/pointer reference (e.g., address table pointer).
    Data,
    /// A call/reference to an external function.
    Call,
    /// A generic read reference.
    Read,
    /// A generic write reference.
    Write,
    /// An unconditional jump reference.
    Jump,
}

impl Default for ExternalRefType {
    fn default() -> Self {
        ExternalRefType::Data
    }
}

impl fmt::Display for ExternalRefType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExternalRefType::Data => write!(f, "DATA"),
            ExternalRefType::Call => write!(f, "CALL"),
            ExternalRefType::Read => write!(f, "READ"),
            ExternalRefType::Write => write!(f, "WRITE"),
            ExternalRefType::Jump => write!(f, "JUMP"),
        }
    }
}

// ---------------------------------------------------------------------------
// SetExternalRefCmd
// ---------------------------------------------------------------------------

/// Command for adding external references.
///
/// This is the Rust port of Ghidra's `SetExternalRefCmd`.  It adds an
/// external reference from a source address in the current program to
/// an external location in an external library.  The external
/// location is created or retrieved from the
/// [`ExternalManagerDB`].
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::{
///     SetExternalRefCmd, ExternalRefType, ExternalManagerDB,
/// };
/// use ghidra_core::addr::Address;
/// use ghidra_core::symbol::SourceType;
///
/// let mut mgr = ExternalManagerDB::new();
/// let mut cmd = SetExternalRefCmd::new(
///     Address::new(0x401000),  // from address
///     0,                        // operand index
///     "libc",                   // external library name
///     Some("printf"),           // external label
///     None,                     // external address
///     ExternalRefType::Call,    // reference type
///     SourceType::Imported,
/// );
///
/// assert!(cmd.apply_to(&mut mgr));
/// assert!(mgr.contains_library("libc"));
/// ```
#[derive(Debug, Clone)]
pub struct SetExternalRefCmd {
    /// The address of the codeunit making the external reference.
    from_addr: Address,
    /// The operand index.
    op_index: i32,
    /// The name of the external program (library).
    ext_name: String,
    /// The label within the external program (may be None if
    /// ext_addr is set).
    ext_label: Option<String>,
    /// The address within the external program (optional).
    ext_addr: Option<Address>,
    /// The reference type.
    ref_type: ExternalRefType,
    /// The source of this reference.
    source: SourceType,
    /// Error message from the last execution, if any.
    status: Option<String>,
}

impl SetExternalRefCmd {
    /// Create a new command for adding an external reference.
    ///
    /// # Arguments
    ///
    /// * `from_addr` -- from address (source of the reference).
    /// * `op_index` -- operand index.
    /// * `ext_name` -- name of external program.
    /// * `ext_label` -- label within the external program, may be
    ///   `None` if `ext_addr` is not `None`.
    /// * `ext_addr` -- address within the external program, may be
    ///   `None`.
    /// * `ref_type` -- the reference type.
    /// * `source` -- the source of this reference.
    pub fn new(
        from_addr: Address,
        op_index: i32,
        ext_name: impl Into<String>,
        ext_label: Option<&str>,
        ext_addr: Option<Address>,
        ref_type: ExternalRefType,
        source: SourceType,
    ) -> Self {
        Self {
            from_addr,
            op_index,
            ext_name: ext_name.into(),
            ext_label: ext_label.map(|s| s.to_string()),
            ext_addr,
            ref_type,
            source,
            status: None,
        }
    }

    /// Create a new command for adding an external reference from
    /// data using `ExternalRefType::Data`.
    ///
    /// This is the convenience constructor for data/pointer
    /// references (e.g., address table pointer references).
    ///
    /// # Arguments
    ///
    /// * `from_addr` -- from address (source of the reference).
    /// * `op_index` -- operand index.
    /// * `ext_name` -- name of external program.
    /// * `ext_label` -- label within the external program, may be
    ///   `None` if `ext_addr` is not `None`.
    /// * `ext_addr` -- address within the external program, may be
    ///   `None`.
    /// * `source` -- the source of this reference.
    pub fn new_data(
        from_addr: Address,
        op_index: i32,
        ext_name: impl Into<String>,
        ext_label: Option<&str>,
        ext_addr: Option<Address>,
        source: SourceType,
    ) -> Self {
        Self::new(
            from_addr,
            op_index,
            ext_name,
            ext_label,
            ext_addr,
            ExternalRefType::Data,
            source,
        )
    }

    /// Execute the command against the given external manager.
    ///
    /// Returns `true` if the reference was successfully set, `false`
    /// otherwise.  On failure, [`status_msg`](Self::status_msg)
    /// contains a description of the error.
    pub fn apply_to(&mut self, ext_mgr: &mut ExternalManagerDB) -> bool {
        self.status = None;

        // Determine if this should be a function or data reference
        let result = if self.ref_type == ExternalRefType::Call {
            ext_mgr.add_ext_function(
                &self.ext_name,
                self.ext_label.as_deref().unwrap_or(""),
                self.ext_addr,
                self.source,
            )
        } else {
            ext_mgr.add_ext_location(
                &self.ext_name,
                self.ext_label.as_deref().unwrap_or(""),
                self.ext_addr,
                self.source,
            )
        };

        match result {
            Ok(_idx) => true,
            Err(e) => {
                self.status = Some(e.to_string());
                false
            }
        }
    }

    /// Returns the command name.
    pub fn name(&self) -> &str {
        "Set External Reference"
    }

    /// Returns the status message from the last execution, if any.
    pub fn status_msg(&self) -> Option<&str> {
        self.status.as_deref()
    }

    /// Returns the source address.
    pub fn from_addr(&self) -> Address {
        self.from_addr
    }

    /// Returns the operand index.
    pub fn op_index(&self) -> i32 {
        self.op_index
    }

    /// Returns the external program name.
    pub fn ext_name(&self) -> &str {
        &self.ext_name
    }

    /// Returns the external label.
    pub fn ext_label(&self) -> Option<&str> {
        self.ext_label.as_deref()
    }

    /// Returns the external address.
    pub fn ext_addr(&self) -> Option<Address> {
        self.ext_addr
    }

    /// Returns the reference type.
    pub fn ref_type(&self) -> ExternalRefType {
        self.ref_type
    }

    /// Returns the source type.
    pub fn source(&self) -> SourceType {
        self.source
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_external_ref_data() {
        let mut mgr = ExternalManagerDB::new();
        let mut cmd = SetExternalRefCmd::new(
            Address::new(0x401000),
            0,
            "libc",
            Some("errno"),
            None,
            ExternalRefType::Data,
            SourceType::Imported,
        );

        assert!(cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_none());
        assert!(mgr.contains_library("libc"));
        assert_eq!(mgr.location_count(), 1);
    }

    #[test]
    fn test_set_external_ref_call() {
        let mut mgr = ExternalManagerDB::new();
        let mut cmd = SetExternalRefCmd::new(
            Address::new(0x401000),
            0,
            "libc",
            Some("printf"),
            Some(Address::new(0x1000)),
            ExternalRefType::Call,
            SourceType::Imported,
        );

        assert!(cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_none());

        // Should have created a function location
        let locs = mgr.get_external_locations_by_lib_and_label("libc", "printf");
        assert_eq!(locs.len(), 1);
        assert!(locs[0].is_function());
    }

    #[test]
    fn test_set_external_ref_with_address() {
        let mut mgr = ExternalManagerDB::new();
        let mut cmd = SetExternalRefCmd::new(
            Address::new(0x401000),
            0,
            "libc",
            Some("printf"),
            Some(Address::new(0x2000)),
            ExternalRefType::Call,
            SourceType::Imported,
        );

        assert!(cmd.apply_to(&mut mgr));

        let locs = mgr.get_external_locations_by_lib_and_label("libc", "printf");
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].external_program_address(), Some(Address::new(0x2000)));
    }

    #[test]
    fn test_set_external_ref_new_data_convenience() {
        let mut mgr = ExternalManagerDB::new();
        let mut cmd = SetExternalRefCmd::new_data(
            Address::new(0x401000),
            0,
            "libc",
            Some("errno"),
            None,
            SourceType::Imported,
        );

        assert!(cmd.apply_to(&mut mgr));
        assert_eq!(cmd.ref_type(), ExternalRefType::Data);
    }

    #[test]
    fn test_set_external_ref_no_label() {
        let mut mgr = ExternalManagerDB::new();
        let mut cmd = SetExternalRefCmd::new(
            Address::new(0x401000),
            0,
            "libc",
            None,
            Some(Address::new(0x3000)),
            ExternalRefType::Data,
            SourceType::Imported,
        );

        assert!(cmd.apply_to(&mut mgr));
    }

    #[test]
    fn test_command_name() {
        let cmd = SetExternalRefCmd::new(
            Address::new(0x401000),
            0,
            "libc",
            Some("printf"),
            None,
            ExternalRefType::Call,
            SourceType::Imported,
        );
        assert_eq!(cmd.name(), "Set External Reference");
    }

    #[test]
    fn test_accessors() {
        let cmd = SetExternalRefCmd::new(
            Address::new(0x401000),
            2,
            "kernel32.dll",
            Some("GetLastError"),
            Some(Address::new(0x5000)),
            ExternalRefType::Call,
            SourceType::UserDefined,
        );

        assert_eq!(cmd.from_addr(), Address::new(0x401000));
        assert_eq!(cmd.op_index(), 2);
        assert_eq!(cmd.ext_name(), "kernel32.dll");
        assert_eq!(cmd.ext_label(), Some("GetLastError"));
        assert_eq!(cmd.ext_addr(), Some(Address::new(0x5000)));
        assert_eq!(cmd.ref_type(), ExternalRefType::Call);
        assert_eq!(cmd.source(), SourceType::UserDefined);
    }

    #[test]
    fn test_initial_status_is_none() {
        let cmd = SetExternalRefCmd::new(
            Address::new(0x401000),
            0,
            "libc",
            Some("printf"),
            None,
            ExternalRefType::Call,
            SourceType::Imported,
        );
        assert!(cmd.status_msg().is_none());
    }

    #[test]
    fn test_clone() {
        let cmd = SetExternalRefCmd::new(
            Address::new(0x401000),
            0,
            "libc",
            Some("printf"),
            None,
            ExternalRefType::Call,
            SourceType::Imported,
        );
        let cloned = cmd.clone();
        assert_eq!(cloned.ext_name(), "libc");
        assert_eq!(cloned.ext_label(), Some("printf"));
    }

    #[test]
    fn test_ref_type_display() {
        assert_eq!(ExternalRefType::Data.to_string(), "DATA");
        assert_eq!(ExternalRefType::Call.to_string(), "CALL");
        assert_eq!(ExternalRefType::Read.to_string(), "READ");
        assert_eq!(ExternalRefType::Write.to_string(), "WRITE");
        assert_eq!(ExternalRefType::Jump.to_string(), "JUMP");
    }

    #[test]
    fn test_ref_type_default() {
        assert_eq!(ExternalRefType::default(), ExternalRefType::Data);
    }

    #[test]
    fn test_multiple_refs_to_same_library() {
        let mut mgr = ExternalManagerDB::new();

        let mut cmd1 = SetExternalRefCmd::new(
            Address::new(0x401000),
            0,
            "libc",
            Some("printf"),
            None,
            ExternalRefType::Call,
            SourceType::Imported,
        );
        assert!(cmd1.apply_to(&mut mgr));

        let mut cmd2 = SetExternalRefCmd::new(
            Address::new(0x401004),
            0,
            "libc",
            Some("puts"),
            None,
            ExternalRefType::Call,
            SourceType::Imported,
        );
        assert!(cmd2.apply_to(&mut mgr));

        assert_eq!(mgr.location_count(), 2);
        assert_eq!(mgr.library_count(), 1);
    }

    #[test]
    fn test_refs_to_different_libraries() {
        let mut mgr = ExternalManagerDB::new();

        let mut cmd1 = SetExternalRefCmd::new(
            Address::new(0x401000),
            0,
            "libc",
            Some("printf"),
            None,
            ExternalRefType::Call,
            SourceType::Imported,
        );
        assert!(cmd1.apply_to(&mut mgr));

        let mut cmd2 = SetExternalRefCmd::new(
            Address::new(0x401004),
            0,
            "kernel32.dll",
            Some("GetLastError"),
            None,
            ExternalRefType::Call,
            SourceType::Imported,
        );
        assert!(cmd2.apply_to(&mut mgr));

        assert_eq!(mgr.library_count(), 2);
    }

    #[test]
    fn test_set_ref_creates_library() {
        let mut mgr = ExternalManagerDB::new();
        assert!(!mgr.contains_library("libc"));

        let mut cmd = SetExternalRefCmd::new(
            Address::new(0x401000),
            0,
            "libc",
            Some("printf"),
            None,
            ExternalRefType::Call,
            SourceType::Imported,
        );
        assert!(cmd.apply_to(&mut mgr));

        // Library should have been auto-created
        assert!(mgr.contains_library("libc"));
    }

    #[test]
    fn test_status_resets_on_reapply() {
        let mut mgr = ExternalManagerDB::new();

        // First call should succeed
        let mut cmd = SetExternalRefCmd::new(
            Address::new(0x401000),
            0,
            "libc",
            Some("printf"),
            None,
            ExternalRefType::Call,
            SourceType::Imported,
        );
        assert!(cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_none());

        // Second call with same params should also succeed
        // (returns existing location)
        assert!(cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_none());
    }

    #[test]
    fn test_set_ref_with_analysis_source() {
        let mut mgr = ExternalManagerDB::new();
        let mut cmd = SetExternalRefCmd::new(
            Address::new(0x401000),
            0,
            "libm",
            Some("sin"),
            None,
            ExternalRefType::Call,
            SourceType::Analysis,
        );

        assert!(cmd.apply_to(&mut mgr));
        let locs = mgr.get_external_locations_by_lib_and_label("libm", "sin");
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].source(), SourceType::Analysis);
    }
}
