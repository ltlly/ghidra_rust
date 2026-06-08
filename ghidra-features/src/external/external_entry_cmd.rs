//! ExternalEntryCmd -- command for setting/unsetting external entry points.
//!
//! Ported from `ghidra.app.cmd.label.ExternalEntryCmd`.
//!
//! This command adds or removes an address from the program's set of
//! external entry points.  External entry points are addresses in the
//! current program that are known to be called from external code (e.g.,
//! exported library functions).
//!
//! # Examples
//!
//! ```rust
//! use ghidra_features::external::ExternalEntryCmd;
//! use ghidra_core::addr::Address;
//!
//! // Create a command to mark address 0x401000 as an external entry
//! let mut cmd = ExternalEntryCmd::new(Address::new(0x401000), true);
//! assert_eq!(cmd.name(), "Set External Entry Point");
//!
//! // Create a command to unmark address 0x401000
//! let mut cmd = ExternalEntryCmd::new(Address::new(0x401000), false);
//! assert_eq!(cmd.name(), "Unset External Entry Point");
//! ```

use std::collections::BTreeSet;
use std::fmt;

use ghidra_core::addr::Address;

// ---------------------------------------------------------------------------
// ExternalEntryPointTable
// ---------------------------------------------------------------------------

/// Manages the set of external entry point addresses.
///
/// This is a simplified in-memory representation of Ghidra's symbol table
/// external entry point tracking.  In the Java implementation this is
/// handled by `SymbolTable.addExternalEntryPoint()` and
/// `SymbolTable.removeExternalEntryPoint()`.
#[derive(Debug, Clone, Default)]
pub struct ExternalEntryPointTable {
    /// The set of addresses that are external entry points.
    entry_points: BTreeSet<u64>,
}

/// Type alias for `ExternalEntryPointTable`, used by the
/// [`ExternalEntryFunctionAnalyzer`](super::external_entry_function_analyzer::ExternalEntryFunctionAnalyzer).
pub type ExternalEntryPointManager = ExternalEntryPointTable;

impl ExternalEntryPointTable {
    /// Create a new empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an address as an external entry point.
    ///
    /// Returns `true` if the address was newly inserted, `false` if it
    /// was already present.
    pub fn add_external_entry_point(&mut self, addr: Address) -> bool {
        self.entry_points.insert(addr.offset)
    }

    /// Remove an address from the external entry point set.
    ///
    /// Returns `true` if the address was present and removed, `false`
    /// if it was not found.
    pub fn remove_external_entry_point(&mut self, addr: Address) -> bool {
        self.entry_points.remove(&addr.offset)
    }

    /// Check if an address is an external entry point.
    pub fn is_external_entry_point(&self, addr: &Address) -> bool {
        self.entry_points.contains(&addr.offset)
    }

    /// Returns the number of external entry points.
    pub fn count(&self) -> usize {
        self.entry_points.len()
    }

    /// Returns `true` if there are no external entry points.
    pub fn is_empty(&self) -> bool {
        self.entry_points.is_empty()
    }

    /// Returns an iterator over all external entry point addresses,
    /// sorted in ascending order.
    pub fn addresses(&self) -> impl Iterator<Item = Address> + '_ {
        self.entry_points.iter().map(|&offset| Address::new(offset))
    }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors that can occur when executing an external entry point command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalEntryError {
    /// The address is invalid (e.g., null address).
    InvalidAddress(String),
    /// General error.
    Other(String),
}

impl fmt::Display for ExternalEntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExternalEntryError::InvalidAddress(msg) => write!(f, "Invalid address: {}", msg),
            ExternalEntryError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ExternalEntryError {}

// ---------------------------------------------------------------------------
// ExternalEntryCmd
// ---------------------------------------------------------------------------

/// Command for setting or unsetting an external entry point.
///
/// This is the Rust port of Ghidra's `ExternalEntryCmd`.  When
/// `is_entry` is `true`, the command adds the address to the set of
/// external entry points; when `false`, it removes it.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::{ExternalEntryCmd, ExternalEntryPointTable};
/// use ghidra_core::addr::Address;
///
/// let mut mgr = ExternalEntryPointTable::new();
///
/// // Mark 0x401000 as an external entry point
/// let mut cmd = ExternalEntryCmd::new(Address::new(0x401000), true);
/// assert!(cmd.apply_to(&mut mgr));
/// assert!(mgr.is_external_entry_point(&Address::new(0x401000)));
///
/// // Unmark it
/// let mut cmd = ExternalEntryCmd::new(Address::new(0x401000), false);
/// assert!(cmd.apply_to(&mut mgr));
/// assert!(!mgr.is_external_entry_point(&Address::new(0x401000)));
/// ```
#[derive(Debug, Clone)]
pub struct ExternalEntryCmd {
    /// The address to set or unset as an external entry point.
    addr: Address,
    /// Whether to add (`true`) or remove (`false`) the entry point.
    is_entry: bool,
    /// Error message from the last execution, if any.
    status: Option<String>,
}

impl ExternalEntryCmd {
    /// Create a new command for setting/unsetting an external entry point.
    ///
    /// # Arguments
    ///
    /// * `addr` -- the address to set or unset as an external entry point.
    /// * `is_entry` -- `true` to mark the address as an entry point,
    ///   `false` to unmark it.
    pub fn new(addr: Address, is_entry: bool) -> Self {
        Self {
            addr,
            is_entry,
            status: None,
        }
    }

    /// Execute the command against the given entry point manager.
    ///
    /// Returns `true` if the command succeeded, `false` otherwise.
    /// On failure, [`status_msg`](Self::status_msg) contains a
    /// description of the error.
    pub fn apply_to(&mut self, mgr: &mut ExternalEntryPointTable) -> bool {
        self.status = None;

        if self.is_entry {
            mgr.add_external_entry_point(self.addr);
        } else {
            mgr.remove_external_entry_point(self.addr);
        }
        true
    }

    /// Returns the command name.
    pub fn name(&self) -> &str {
        if self.is_entry {
            "Set External Entry Point"
        } else {
            "Unset External Entry Point"
        }
    }

    /// Returns the status message from the last execution, if any.
    pub fn status_msg(&self) -> Option<&str> {
        self.status.as_deref()
    }

    /// Returns the address this command operates on.
    pub fn addr(&self) -> Address {
        self.addr
    }

    /// Returns whether this command sets (`true`) or unsets (`false`)
    /// the entry point.
    pub fn is_entry(&self) -> bool {
        self.is_entry
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_external_entry_point() {
        let mut mgr = ExternalEntryPointTable::new();
        let mut cmd = ExternalEntryCmd::new(Address::new(0x401000), true);

        assert!(cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_none());
        assert!(mgr.is_external_entry_point(&Address::new(0x401000)));
    }

    #[test]
    fn test_unset_external_entry_point() {
        let mut mgr = ExternalEntryPointTable::new();
        mgr.add_external_entry_point(Address::new(0x401000));

        let mut cmd = ExternalEntryCmd::new(Address::new(0x401000), false);
        assert!(cmd.apply_to(&mut mgr));
        assert!(!mgr.is_external_entry_point(&Address::new(0x401000)));
    }

    #[test]
    fn test_set_entry_point_already_exists() {
        let mut mgr = ExternalEntryPointTable::new();
        mgr.add_external_entry_point(Address::new(0x401000));

        let mut cmd = ExternalEntryCmd::new(Address::new(0x401000), true);
        // Should still succeed (idempotent)
        assert!(cmd.apply_to(&mut mgr));
        assert!(mgr.is_external_entry_point(&Address::new(0x401000)));
    }

    #[test]
    fn test_unset_entry_point_not_present() {
        let mut mgr = ExternalEntryPointTable::new();

        let mut cmd = ExternalEntryCmd::new(Address::new(0x401000), false);
        // Should still succeed (idempotent)
        assert!(cmd.apply_to(&mut mgr));
        assert!(!mgr.is_external_entry_point(&Address::new(0x401000)));
    }

    #[test]
    fn test_command_name_set() {
        let cmd = ExternalEntryCmd::new(Address::new(0x401000), true);
        assert_eq!(cmd.name(), "Set External Entry Point");
    }

    #[test]
    fn test_command_name_unset() {
        let cmd = ExternalEntryCmd::new(Address::new(0x401000), false);
        assert_eq!(cmd.name(), "Unset External Entry Point");
    }

    #[test]
    fn test_accessors() {
        let cmd = ExternalEntryCmd::new(Address::new(0x401000), true);
        assert_eq!(cmd.addr(), Address::new(0x401000));
        assert!(cmd.is_entry());
    }

    #[test]
    fn test_initial_status_is_none() {
        let cmd = ExternalEntryCmd::new(Address::new(0x401000), true);
        assert!(cmd.status_msg().is_none());
    }

    #[test]
    fn test_clone() {
        let cmd = ExternalEntryCmd::new(Address::new(0x401000), true);
        let cloned = cmd.clone();
        assert_eq!(cloned.addr(), Address::new(0x401000));
        assert!(cloned.is_entry());
    }

    #[test]
    fn test_multiple_entry_points() {
        let mut mgr = ExternalEntryPointTable::new();

        let mut cmd1 = ExternalEntryCmd::new(Address::new(0x401000), true);
        assert!(cmd1.apply_to(&mut mgr));

        let mut cmd2 = ExternalEntryCmd::new(Address::new(0x402000), true);
        assert!(cmd2.apply_to(&mut mgr));

        let mut cmd3 = ExternalEntryCmd::new(Address::new(0x403000), true);
        assert!(cmd3.apply_to(&mut mgr));

        assert_eq!(mgr.count(), 3);
        assert!(mgr.is_external_entry_point(&Address::new(0x401000)));
        assert!(mgr.is_external_entry_point(&Address::new(0x402000)));
        assert!(mgr.is_external_entry_point(&Address::new(0x403000)));
    }

    #[test]
    fn test_set_and_unset_cycle() {
        let mut mgr = ExternalEntryPointTable::new();

        // Set
        let mut cmd = ExternalEntryCmd::new(Address::new(0x401000), true);
        assert!(cmd.apply_to(&mut mgr));
        assert!(mgr.is_external_entry_point(&Address::new(0x401000)));

        // Unset
        let mut cmd = ExternalEntryCmd::new(Address::new(0x401000), false);
        assert!(cmd.apply_to(&mut mgr));
        assert!(!mgr.is_external_entry_point(&Address::new(0x401000)));
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn test_entry_point_manager_iterator() {
        let mut mgr = ExternalEntryPointTable::new();
        mgr.add_external_entry_point(Address::new(0x401000));
        mgr.add_external_entry_point(Address::new(0x402000));
        mgr.add_external_entry_point(Address::new(0x403000));

        let addrs: Vec<Address> = mgr.addresses().collect();
        assert_eq!(addrs.len(), 3);
        assert_eq!(addrs[0], Address::new(0x401000));
        assert_eq!(addrs[1], Address::new(0x402000));
        assert_eq!(addrs[2], Address::new(0x403000));
    }

    #[test]
    fn test_entry_point_manager_empty() {
        let mgr = ExternalEntryPointTable::new();
        assert!(mgr.is_empty());
        assert_eq!(mgr.count(), 0);
        assert!(!mgr.is_external_entry_point(&Address::new(0x401000)));
    }

    #[test]
    fn test_error_display() {
        let e = ExternalEntryError::InvalidAddress("null address".into());
        assert!(e.to_string().contains("Invalid address"));

        let e = ExternalEntryError::Other("details".into());
        assert!(e.to_string().contains("details"));
    }

    #[test]
    fn test_status_resets_on_reapply() {
        let mut mgr = ExternalEntryPointTable::new();

        let mut cmd = ExternalEntryCmd::new(Address::new(0x401000), true);
        assert!(cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_none());

        // Apply again -- should still succeed
        assert!(cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_none());
    }
}
