//! ExternalReferencePluginEvent -- plugin event for external references.
//!
//! Ported from `ghidra.app.events.ExternalReferencePluginEvent`.
//!
//! This event is generated when a tool needs to navigate to a location
//! in another program when following an external reference.  It carries
//! the external location information and the target program path.
//!
//! # Examples
//!
//! ```rust
//! use ghidra_features::external::{
//!     ExternalReferencePluginEvent, ExternalLocationDB,
//! };
//! use ghidra_core::addr::Address;
//! use ghidra_core::symbol::SourceType;
//!
//! let ext_loc = ExternalLocationDB::new_function(
//!     "libc", "printf", Some(Address::new(0x1000)), SourceType::Imported,
//! );
//!
//! let event = ExternalReferencePluginEvent::new(
//!     "ReferencesPlugin",
//!     ext_loc,
//!     "/project/program.exe".to_string(),
//! );
//!
//! assert_eq!(event.source(), "ReferencesPlugin");
//! assert_eq!(event.program_path(), "/project/program.exe");
//! ```

use std::fmt;

use ghidra_core::addr::Address;
use ghidra_core::symbol::SourceType;

use super::external_location_db::ExternalLocationDB;

// ---------------------------------------------------------------------------
// ExternalReferencePluginEvent
// ---------------------------------------------------------------------------

/// Plugin event used to navigate to a location in another program when
/// following an external reference.
///
/// This is the Rust port of Ghidra's `ExternalReferencePluginEvent`.
/// When a user follows an external reference (e.g., double-clicking on
/// an imported function), this event is fired to tell the tool to
/// navigate to the referenced location in the external program.
///
/// # Fields
///
/// * `source` -- the name of the plugin that generated this event.
/// * `external_location` -- the external location to follow.
/// * `program_path` -- the Ghidra project path of the target program.
#[derive(Debug, Clone)]
pub struct ExternalReferencePluginEvent {
    /// The name of the source plugin that generated this event.
    source: String,
    /// The external location to follow.
    external_location: ExternalLocationDB,
    /// The Ghidra project path of the target program.
    program_path: String,
}

impl ExternalReferencePluginEvent {
    /// The event name constant, matching Ghidra's event name.
    pub const NAME: &'static str = "ExternalReference";

    /// Create a new external reference plugin event.
    ///
    /// # Arguments
    ///
    /// * `source` -- the name of the plugin that generated this event.
    /// * `external_location` -- the external location to follow.
    /// * `program_path` -- the Ghidra project path of the target program.
    pub fn new(
        source: impl Into<String>,
        external_location: ExternalLocationDB,
        program_path: impl Into<String>,
    ) -> Self {
        Self {
            source: source.into(),
            external_location,
            program_path: program_path.into(),
        }
    }

    /// Returns the event name.
    pub fn event_name(&self) -> &str {
        Self::NAME
    }

    /// Returns the source plugin name.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns the external location for this event.
    pub fn external_location(&self) -> &ExternalLocationDB {
        &self.external_location
    }

    /// Returns the program path name.
    pub fn program_path(&self) -> &str {
        &self.program_path
    }

    /// Returns the external library name.
    pub fn library_name(&self) -> &str {
        self.external_location.library_name()
    }

    /// Returns the external label (function/data name).
    pub fn label(&self) -> Option<&str> {
        self.external_location.label()
    }

    /// Returns the external address, if any.
    pub fn external_address(&self) -> Option<Address> {
        self.external_location.external_program_address()
    }

    /// Returns whether this external location is a function.
    pub fn is_function(&self) -> bool {
        self.external_location.is_function()
    }

    /// Returns the source type of the external location.
    pub fn source_type(&self) -> SourceType {
        self.external_location.source()
    }
}

impl fmt::Display for ExternalReferencePluginEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ExternalReferenceEvent[{} -> {}:{}]",
            self.source,
            self.program_path,
            self.external_location
                .label()
                .unwrap_or("<unknown>")
        )
    }
}

// ---------------------------------------------------------------------------
// ExternalProgramLocationPluginEvent
// ---------------------------------------------------------------------------

/// Plugin event generated when a tool receives an external program
/// location change.
///
/// This is the Rust port of Ghidra's
/// `ExternalProgramLocationPluginEvent`.  It carries a program location
/// and a weak reference to the program, allowing tools to navigate to
/// a specific location in an external program.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::ExternalProgramLocationPluginEvent;
/// use ghidra_core::addr::Address;
///
/// let event = ExternalProgramLocationPluginEvent::new(
///     "ExternalReferencesPlugin",
///     Address::new(0x401000),
///     "libc".to_string(),
/// );
///
/// assert_eq!(event.source(), "ExternalReferencesPlugin");
/// assert_eq!(event.address(), Address::new(0x401000));
/// ```
#[derive(Debug, Clone)]
pub struct ExternalProgramLocationPluginEvent {
    /// The name of the source plugin.
    source: String,
    /// The address in the external program.
    address: Address,
    /// The program path (weak reference equivalent).
    program_path: String,
}

impl ExternalProgramLocationPluginEvent {
    /// The event name constant.
    pub const NAME: &'static str = "External Program Location Change";

    /// The tool event name for cross-tool connections.
    pub const TOOL_EVENT_NAME: &'static str = "Program Location Change";

    /// Create a new external program location plugin event.
    ///
    /// # Arguments
    ///
    /// * `source` -- the name of the plugin that generated this event.
    /// * `address` -- the address in the external program.
    /// * `program_path` -- the path of the external program.
    pub fn new(
        source: impl Into<String>,
        address: Address,
        program_path: impl Into<String>,
    ) -> Self {
        Self {
            source: source.into(),
            address,
            program_path: program_path.into(),
        }
    }

    /// Returns the event name.
    pub fn event_name(&self) -> &str {
        Self::NAME
    }

    /// Returns the tool event name.
    pub fn tool_event_name(&self) -> &str {
        Self::TOOL_EVENT_NAME
    }

    /// Returns the source plugin name.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns the address in the external program.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Returns the program path.
    pub fn program_path(&self) -> &str {
        &self.program_path
    }
}

impl fmt::Display for ExternalProgramLocationPluginEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ExternalProgramLocationEvent[{} @ {}]",
            self.program_path, self.address
        )
    }
}

// ---------------------------------------------------------------------------
// ExternalProgramSelectionPluginEvent
// ---------------------------------------------------------------------------

/// Plugin event generated when a tool receives an external program
/// selection change.
///
/// This is the Rust port of Ghidra's
/// `ExternalProgramSelectionPluginEvent`.  It carries a set of
/// selected addresses and a reference to the program, allowing tools
/// to display or highlight a selection in an external program.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::ExternalProgramSelectionPluginEvent;
/// use ghidra_core::addr::Address;
///
/// let event = ExternalProgramSelectionPluginEvent::new(
///     "ExternalReferencesPlugin",
///     vec![Address::new(0x401000), Address::new(0x402000)],
///     "libc".to_string(),
/// );
///
/// assert_eq!(event.source(), "ExternalReferencesPlugin");
/// assert_eq!(event.selection().len(), 2);
/// ```
#[derive(Debug, Clone)]
pub struct ExternalProgramSelectionPluginEvent {
    /// The name of the source plugin.
    source: String,
    /// The set of selected addresses.
    selection: Vec<Address>,
    /// The program path (weak reference equivalent).
    program_path: String,
}

impl ExternalProgramSelectionPluginEvent {
    /// The event name constant.
    pub const NAME: &'static str = "ExternalProgramSelection";

    /// The tool event name for cross-tool connections.
    pub const TOOL_EVENT_NAME: &'static str = "Program Selection";

    /// Create a new external program selection plugin event.
    ///
    /// # Arguments
    ///
    /// * `source` -- the name of the plugin that generated this event.
    /// * `selection` -- the set of selected addresses.
    /// * `program_path` -- the path of the external program.
    pub fn new(
        source: impl Into<String>,
        selection: Vec<Address>,
        program_path: impl Into<String>,
    ) -> Self {
        Self {
            source: source.into(),
            selection,
            program_path: program_path.into(),
        }
    }

    /// Returns the event name.
    pub fn event_name(&self) -> &str {
        Self::NAME
    }

    /// Returns the tool event name.
    pub fn tool_event_name(&self) -> &str {
        Self::TOOL_EVENT_NAME
    }

    /// Returns the source plugin name.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns the selection.
    pub fn selection(&self) -> &[Address] {
        &self.selection
    }

    /// Returns the program path.
    pub fn program_path(&self) -> &str {
        &self.program_path
    }

    /// Returns the number of selected addresses.
    pub fn selection_count(&self) -> usize {
        self.selection.len()
    }

    /// Returns true if the selection is empty.
    pub fn is_empty(&self) -> bool {
        self.selection.is_empty()
    }
}

impl fmt::Display for ExternalProgramSelectionPluginEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ExternalProgramSelectionEvent[{} ({} addresses)]",
            self.program_path,
            self.selection.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- ExternalReferencePluginEvent tests --

    #[test]
    fn test_external_reference_event_creation() {
        let ext_loc = ExternalLocationDB::new_function(
            "libc",
            "printf",
            Some(Address::new(0x1000)),
            SourceType::Imported,
        );

        let event = ExternalReferencePluginEvent::new(
            "ReferencesPlugin",
            ext_loc,
            "/project/program.exe",
        );

        assert_eq!(event.source(), "ReferencesPlugin");
        assert_eq!(event.program_path(), "/project/program.exe");
        assert_eq!(event.library_name(), "libc");
        assert_eq!(event.label(), Some("printf"));
        assert!(event.is_function());
    }

    #[test]
    fn test_external_reference_event_name() {
        let ext_loc = ExternalLocationDB::new_data(
            "libc",
            "errno",
            None,
            SourceType::Imported,
        );

        let event = ExternalReferencePluginEvent::new(
            "ReferencesPlugin",
            ext_loc,
            "/project/program.exe",
        );

        assert_eq!(event.event_name(), "ExternalReference");
    }

    #[test]
    fn test_external_reference_event_display() {
        let ext_loc = ExternalLocationDB::new_function(
            "libc",
            "printf",
            Some(Address::new(0x1000)),
            SourceType::Imported,
        );

        let event = ExternalReferencePluginEvent::new(
            "ReferencesPlugin",
            ext_loc,
            "/project/program.exe",
        );

        let display = format!("{}", event);
        assert!(display.contains("ExternalReferenceEvent"));
        assert!(display.contains("ReferencesPlugin"));
        assert!(display.contains("/project/program.exe"));
        assert!(display.contains("printf"));
    }

    #[test]
    fn test_external_reference_event_clone() {
        let ext_loc = ExternalLocationDB::new_function(
            "libc",
            "printf",
            Some(Address::new(0x1000)),
            SourceType::Imported,
        );

        let event = ExternalReferencePluginEvent::new(
            "ReferencesPlugin",
            ext_loc,
            "/project/program.exe",
        );

        let cloned = event.clone();
        assert_eq!(cloned.source(), event.source());
        assert_eq!(cloned.program_path(), event.program_path());
        assert_eq!(cloned.library_name(), event.library_name());
        assert_eq!(cloned.label(), event.label());
    }

    #[test]
    fn test_external_reference_event_external_address() {
        let ext_loc = ExternalLocationDB::new_function(
            "libc",
            "printf",
            Some(Address::new(0x1000)),
            SourceType::Imported,
        );

        let event = ExternalReferencePluginEvent::new(
            "ReferencesPlugin",
            ext_loc,
            "/project/program.exe",
        );

        assert_eq!(event.external_address(), Some(Address::new(0x1000)));
    }

    #[test]
    fn test_external_reference_event_no_address() {
        let ext_loc = ExternalLocationDB::new_function(
            "libc",
            "printf",
            None,
            SourceType::Imported,
        );

        let event = ExternalReferencePluginEvent::new(
            "ReferencesPlugin",
            ext_loc,
            "/project/program.exe",
        );

        assert_eq!(event.external_address(), None);
    }

    #[test]
    fn test_external_reference_event_source_type() {
        let ext_loc = ExternalLocationDB::new_function(
            "libc",
            "printf",
            None,
            SourceType::Analysis,
        );

        let event = ExternalReferencePluginEvent::new(
            "ReferencesPlugin",
            ext_loc,
            "/project/program.exe",
        );

        assert_eq!(event.source_type(), SourceType::Analysis);
    }

    // -- ExternalProgramLocationPluginEvent tests --

    #[test]
    fn test_program_location_event_creation() {
        let event = ExternalProgramLocationPluginEvent::new(
            "ExternalReferencesPlugin",
            Address::new(0x401000),
            "libc",
        );

        assert_eq!(event.source(), "ExternalReferencesPlugin");
        assert_eq!(event.address(), Address::new(0x401000));
        assert_eq!(event.program_path(), "libc");
    }

    #[test]
    fn test_program_location_event_names() {
        let event = ExternalProgramLocationPluginEvent::new(
            "ExternalReferencesPlugin",
            Address::new(0x401000),
            "libc",
        );

        assert_eq!(
            event.event_name(),
            "External Program Location Change"
        );
        assert_eq!(
            event.tool_event_name(),
            "Program Location Change"
        );
    }

    #[test]
    fn test_program_location_event_display() {
        let event = ExternalProgramLocationPluginEvent::new(
            "ExternalReferencesPlugin",
            Address::new(0x401000),
            "libc",
        );

        let display = format!("{}", event);
        assert!(display.contains("ExternalProgramLocationEvent"));
        assert!(display.contains("libc"));
        assert!(display.contains("401000"));
    }

    #[test]
    fn test_program_location_event_clone() {
        let event = ExternalProgramLocationPluginEvent::new(
            "ExternalReferencesPlugin",
            Address::new(0x401000),
            "libc",
        );

        let cloned = event.clone();
        assert_eq!(cloned.source(), event.source());
        assert_eq!(cloned.address(), event.address());
        assert_eq!(cloned.program_path(), event.program_path());
    }

    // -- ExternalProgramSelectionPluginEvent tests --

    #[test]
    fn test_program_selection_event_creation() {
        let event = ExternalProgramSelectionPluginEvent::new(
            "ExternalReferencesPlugin",
            vec![Address::new(0x401000), Address::new(0x402000)],
            "libc",
        );

        assert_eq!(event.source(), "ExternalReferencesPlugin");
        assert_eq!(event.selection().len(), 2);
        assert_eq!(event.program_path(), "libc");
    }

    #[test]
    fn test_program_selection_event_names() {
        let event = ExternalProgramSelectionPluginEvent::new(
            "ExternalReferencesPlugin",
            vec![],
            "libc",
        );

        assert_eq!(
            event.event_name(),
            "ExternalProgramSelection"
        );
        assert_eq!(
            event.tool_event_name(),
            "Program Selection"
        );
    }

    #[test]
    fn test_program_selection_event_display() {
        let event = ExternalProgramSelectionPluginEvent::new(
            "ExternalReferencesPlugin",
            vec![Address::new(0x401000), Address::new(0x402000)],
            "libc",
        );

        let display = format!("{}", event);
        assert!(display.contains("ExternalProgramSelectionEvent"));
        assert!(display.contains("libc"));
        assert!(display.contains("2 addresses"));
    }

    #[test]
    fn test_program_selection_event_clone() {
        let event = ExternalProgramSelectionPluginEvent::new(
            "ExternalReferencesPlugin",
            vec![Address::new(0x401000), Address::new(0x402000)],
            "libc",
        );

        let cloned = event.clone();
        assert_eq!(cloned.source(), event.source());
        assert_eq!(cloned.selection(), event.selection());
        assert_eq!(cloned.program_path(), event.program_path());
    }

    #[test]
    fn test_program_selection_event_empty() {
        let event = ExternalProgramSelectionPluginEvent::new(
            "ExternalReferencesPlugin",
            vec![],
            "libc",
        );

        assert!(event.is_empty());
        assert_eq!(event.selection_count(), 0);
    }

    #[test]
    fn test_program_selection_event_non_empty() {
        let event = ExternalProgramSelectionPluginEvent::new(
            "ExternalReferencesPlugin",
            vec![Address::new(0x401000), Address::new(0x402000)],
            "libc",
        );

        assert!(!event.is_empty());
        assert_eq!(event.selection_count(), 2);
    }

    #[test]
    fn test_program_selection_event_single_address() {
        let event = ExternalProgramSelectionPluginEvent::new(
            "ExternalReferencesPlugin",
            vec![Address::new(0x401000)],
            "libc",
        );

        assert_eq!(event.selection_count(), 1);
        assert_eq!(event.selection()[0], Address::new(0x401000));
    }

    #[test]
    fn test_program_selection_event_multiple_addresses() {
        let addrs = vec![
            Address::new(0x401000),
            Address::new(0x402000),
            Address::new(0x403000),
            Address::new(0x404000),
        ];

        let event = ExternalProgramSelectionPluginEvent::new(
            "ExternalReferencesPlugin",
            addrs.clone(),
            "libc",
        );

        assert_eq!(event.selection_count(), 4);
        for (i, addr) in addrs.iter().enumerate() {
            assert_eq!(event.selection()[i], *addr);
        }
    }
}
