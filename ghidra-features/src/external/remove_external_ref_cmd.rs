//! RemoveExternalRefCmd -- command for removing external references.
//!
//! Ported from `ghidra.app.cmd.refs.RemoveExternalRefCmd`.
//!
//! This command removes external references from a given source
//! address and operand index.  In Ghidra's Java implementation this
//! operates on the `ReferenceManager`; here we adapt it to work with
//! the [`ExternalManagerDB`] by removing external locations that
//! correspond to the given source address.

use std::fmt;

use ghidra_core::addr::Address;

use super::external_manager_db::ExternalManagerDB;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors that can occur when removing an external reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoveExternalRefError {
    /// No external references found at the given address.
    NoReferences(String),
    /// General error.
    Other(String),
}

impl fmt::Display for RemoveExternalRefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RemoveExternalRefError::NoReferences(msg) => {
                write!(f, "No external references: {}", msg)
            }
            RemoveExternalRefError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for RemoveExternalRefError {}

// ---------------------------------------------------------------------------
// RemoveExternalRefCmd
// ---------------------------------------------------------------------------

/// Command for removing external references.
///
/// This is the Rust port of Ghidra's `RemoveExternalRefCmd`.  It
/// removes external references from a given source address and
/// operand index.  In the original Java implementation this iterates
/// over references from the address and deletes those that are
/// external references.  Here we adapt the semantics to work with
/// [`ExternalManagerDB`]: we remove external locations whose
/// external-space address matches the source address.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::{RemoveExternalRefCmd, ExternalManagerDB};
/// use ghidra_core::addr::Address;
///
/// let mut mgr = ExternalManagerDB::new();
/// let mut cmd = RemoveExternalRefCmd::new(Address::new(0x401000), 0);
/// assert!(cmd.apply_to(&mut mgr));
/// ```
#[derive(Debug, Clone)]
pub struct RemoveExternalRefCmd {
    /// The address of the codeunit making the external reference.
    from_addr: Address,
    /// The operand index.
    op_index: i32,
    /// Error message from the last execution, if any.
    status: Option<String>,
}

impl RemoveExternalRefCmd {
    /// Create a new command for removing an external reference.
    ///
    /// # Arguments
    ///
    /// * `from_addr` -- the address of the codeunit making the
    ///   external reference.
    /// * `op_index` -- the operand index.
    pub fn new(from_addr: Address, op_index: i32) -> Self {
        Self {
            from_addr,
            op_index,
            status: None,
        }
    }

    /// Execute the command against the given external manager.
    ///
    /// Returns `true` if the command succeeded (even if no references
    /// were found), `false` on error.  On failure,
    /// [`status_msg`](Self::status_msg) contains a description of the
    /// error.
    pub fn apply_to(&mut self, ext_mgr: &mut ExternalManagerDB) -> bool {
        self.status = None;

        // In the Java implementation, this iterates over references
        // from (from_addr, opIndex) and deletes external references.
        // Here we remove external locations whose external-space
        // address matches from_addr.
        ext_mgr.remove_external_location(self.from_addr);

        // The Java implementation always returns true
        true
    }

    /// Returns the command name.
    pub fn name(&self) -> &str {
        "Remove External Reference"
    }

    /// Returns the status message from the last execution, if any.
    pub fn status_msg(&self) -> Option<&str> {
        self.status.as_deref()
    }

    /// Returns the source address of the reference.
    pub fn from_addr(&self) -> Address {
        self.from_addr
    }

    /// Returns the operand index.
    pub fn op_index(&self) -> i32 {
        self.op_index
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::symbol::SourceType;

    #[test]
    fn test_remove_external_ref() {
        let mut mgr = ExternalManagerDB::new();
        let mut cmd = RemoveExternalRefCmd::new(Address::new(0x401000), 0);

        assert!(cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_none());
    }

    #[test]
    fn test_remove_ref_with_existing_locations() {
        let mut mgr = ExternalManagerDB::new();
        // Add some external locations
        mgr.add_ext_function("libc", "printf", None, SourceType::Imported)
            .unwrap();
        mgr.add_ext_function("libc", "puts", None, SourceType::Imported)
            .unwrap();

        let mut cmd = RemoveExternalRefCmd::new(Address::new(0x401000), 0);
        assert!(cmd.apply_to(&mut mgr));

        // Locations still exist (not matching the from_addr)
        assert_eq!(mgr.location_count(), 2);
    }

    #[test]
    fn test_command_name() {
        let cmd = RemoveExternalRefCmd::new(Address::new(0x401000), 0);
        assert_eq!(cmd.name(), "Remove External Reference");
    }

    #[test]
    fn test_accessors() {
        let cmd = RemoveExternalRefCmd::new(Address::new(0x401000), 2);
        assert_eq!(cmd.from_addr(), Address::new(0x401000));
        assert_eq!(cmd.op_index(), 2);
    }

    #[test]
    fn test_initial_status_is_none() {
        let cmd = RemoveExternalRefCmd::new(Address::new(0x401000), 0);
        assert!(cmd.status_msg().is_none());
    }

    #[test]
    fn test_clone() {
        let cmd = RemoveExternalRefCmd::new(Address::new(0x401000), 1);
        let cloned = cmd.clone();
        assert_eq!(cloned.from_addr(), Address::new(0x401000));
        assert_eq!(cloned.op_index(), 1);
    }

    #[test]
    fn test_always_returns_true() {
        let mut mgr = ExternalManagerDB::new();
        let mut cmd = RemoveExternalRefCmd::new(Address::new(0x0), 0);
        assert!(cmd.apply_to(&mut mgr));
    }

    #[test]
    fn test_remove_with_different_op_indices() {
        let mut mgr = ExternalManagerDB::new();

        let mut cmd0 = RemoveExternalRefCmd::new(Address::new(0x401000), 0);
        assert!(cmd0.apply_to(&mut mgr));

        let mut cmd1 = RemoveExternalRefCmd::new(Address::new(0x401000), 1);
        assert!(cmd1.apply_to(&mut mgr));

        let mut cmd2 = RemoveExternalRefCmd::new(Address::new(0x401000), 2);
        assert!(cmd2.apply_to(&mut mgr));
    }

    #[test]
    fn test_remove_from_zero_address() {
        let mut mgr = ExternalManagerDB::new();
        let mut cmd = RemoveExternalRefCmd::new(Address::new(0x0), 0);
        assert!(cmd.apply_to(&mut mgr));
    }

    #[test]
    fn test_remove_from_max_address() {
        let mut mgr = ExternalManagerDB::new();
        let mut cmd = RemoveExternalRefCmd::new(Address::new(u64::MAX), 0);
        assert!(cmd.apply_to(&mut mgr));
    }

    #[test]
    fn test_apply_twice() {
        let mut mgr = ExternalManagerDB::new();
        let mut cmd = RemoveExternalRefCmd::new(Address::new(0x401000), 0);

        assert!(cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_none());

        // Second call should also succeed
        assert!(cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_none());
    }

    #[test]
    fn test_remove_preserves_other_locations() {
        let mut mgr = ExternalManagerDB::new();
        mgr.add_ext_function("libc", "printf", Some(Address::new(0x1000)), SourceType::Imported)
            .unwrap();
        mgr.add_ext_function("libc", "puts", Some(Address::new(0x2000)), SourceType::Imported)
            .unwrap();

        let initial_count = mgr.location_count();

        // Remove from a different address
        let mut cmd = RemoveExternalRefCmd::new(Address::new(0x401000), 0);
        assert!(cmd.apply_to(&mut mgr));

        // All locations preserved
        assert_eq!(mgr.location_count(), initial_count);
    }
}
