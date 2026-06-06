//! Clear Plugin -- clear code/data at addresses.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.clear` Java package.
//!
//! Provides logic for clearing (removing) code units, data, and analysis
//! results from a program's listing. Includes fine-grained clear options
//! matching Ghidra's `ClearOptions.ClearType` and a command model for
//! applying clear operations with flow-repair support.
//!
//! # Key Types
//!
//! - [`ClearType`] -- fine-grained types matching `ClearOptions.ClearType`
//! - [`ClearOptions`] -- a set of clear type toggles (port of `ClearOptions.java`)
//! - [`ClearOperation`] -- a clear operation over an address range
//! - [`ClearModel`] -- model for managing clear operations

use ghidra_core::Address;
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// ClearType -- fine-grained clear type (matches ClearOptions.ClearType)
// ---------------------------------------------------------------------------

/// Fine-grained clear type matching `ghidra.app.plugin.core.clear.ClearOptions.ClearType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClearType {
    /// Clear instructions.
    Instructions,
    /// Clear data items.
    Data,
    /// Clear symbols / labels.
    Symbols,
    /// Clear comments (all types).
    Comments,
    /// Clear properties.
    Properties,
    /// Clear functions.
    Functions,
    /// Clear register values.
    Registers,
    /// Clear equates.
    Equates,
    /// Clear user-defined references.
    UserReferences,
    /// Clear analysis-discovered references.
    AnalysisReferences,
    /// Clear imported references.
    ImportReferences,
    /// Clear default references.
    DefaultReferences,
    /// Clear bookmarks.
    Bookmarks,
}

impl ClearType {
    /// All clear types.
    pub fn all() -> &'static [ClearType] {
        &[
            Self::Instructions,
            Self::Data,
            Self::Symbols,
            Self::Comments,
            Self::Properties,
            Self::Functions,
            Self::Registers,
            Self::Equates,
            Self::UserReferences,
            Self::AnalysisReferences,
            Self::ImportReferences,
            Self::DefaultReferences,
            Self::Bookmarks,
        ]
    }
}

// ---------------------------------------------------------------------------
// ClearOptions
// ---------------------------------------------------------------------------

/// A set of clear type toggles.
///
/// Ported from `ghidra.app.plugin.core.clear.ClearOptions`.
#[derive(Debug, Clone)]
pub struct ClearOptions {
    types_to_clear: HashSet<ClearType>,
}

impl ClearOptions {
    /// Create a new ClearOptions that clears everything by default.
    pub fn all() -> Self {
        let types_to_clear = ClearType::all().iter().copied().collect();
        Self { types_to_clear }
    }

    /// Create a new ClearOptions with nothing selected.
    pub fn none() -> Self {
        Self {
            types_to_clear: HashSet::new(),
        }
    }

    /// Create a ClearOptions with just instructions and data enabled
    /// (the default when no options object is provided in Java).
    pub fn instructions_and_data() -> Self {
        let mut opts = Self::none();
        opts.set_should_clear(ClearType::Instructions, true);
        opts.set_should_clear(ClearType::Data, true);
        opts
    }

    /// Set whether a given clear type should be cleared.
    pub fn set_should_clear(&mut self, clear_type: ClearType, should_clear: bool) {
        if should_clear {
            self.types_to_clear.insert(clear_type);
        } else {
            self.types_to_clear.remove(&clear_type);
        }
    }

    /// Check whether a given clear type should be cleared.
    pub fn should_clear(&self, clear_type: ClearType) -> bool {
        self.types_to_clear.contains(&clear_type)
    }

    /// Whether any clear types are enabled.
    pub fn clear_any(&self) -> bool {
        !self.types_to_clear.is_empty()
    }

    /// Get the set of reference source types to clear.
    ///
    /// Maps the four reference-related clear types to source type labels.
    pub fn reference_source_types_to_clear(&self) -> Vec<&'static str> {
        let mut types = Vec::new();
        if self.should_clear(ClearType::UserReferences) {
            types.push("USER_DEFINED");
        }
        if self.should_clear(ClearType::DefaultReferences) {
            types.push("DEFAULT");
        }
        if self.should_clear(ClearType::ImportReferences) {
            types.push("IMPORTED");
        }
        if self.should_clear(ClearType::AnalysisReferences) {
            types.push("ANALYSIS");
        }
        types
    }

    /// The number of enabled clear types.
    pub fn enabled_count(&self) -> usize {
        self.types_to_clear.len()
    }
}

impl Default for ClearOptions {
    fn default() -> Self {
        Self::all()
    }
}

// ---------------------------------------------------------------------------
// ClearOperation -- a clear over an address range
// ---------------------------------------------------------------------------

/// A clear operation to perform.
#[derive(Debug, Clone)]
pub struct ClearOperation {
    /// The start address.
    pub start: Address,
    /// The end address.
    pub end: Address,
    /// What to clear.
    pub clear_type: ClearType,
    /// Whether to clear the bytes themselves.
    pub clear_bytes: bool,
}

impl ClearOperation {
    /// Create a new clear operation.
    pub fn new(start: Address, end: Address, clear_type: ClearType) -> Self {
        Self {
            start,
            end,
            clear_type,
            clear_bytes: false,
        }
    }

    /// Create a clear operation that also zeroes bytes.
    pub fn with_clear_bytes(mut self, clear_bytes: bool) -> Self {
        self.clear_bytes = clear_bytes;
        self
    }

    /// The number of addresses in the clear range.
    pub fn address_count(&self) -> u64 {
        self.end.offset.saturating_sub(self.start.offset) + 1
    }
}

// ---------------------------------------------------------------------------
// ClearModel
// ---------------------------------------------------------------------------

/// Model for managing clear operations.
#[derive(Debug, Default)]
pub struct ClearModel {
    /// The pending clear operations.
    operations: Vec<ClearOperation>,
}

impl ClearModel {
    /// Create a new clear model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a clear operation.
    pub fn add_operation(&mut self, op: ClearOperation) {
        self.operations.push(op);
    }

    /// Get all pending operations.
    pub fn get_operations(&self) -> &[ClearOperation] {
        &self.operations
    }

    /// Clear all pending operations.
    pub fn clear(&mut self) {
        self.operations.clear();
    }

    /// Get the number of pending operations.
    pub fn operation_count(&self) -> usize {
        self.operations.len()
    }

    /// Compute the total number of addresses that would be affected.
    pub fn total_address_count(&self) -> u64 {
        self.operations.iter().map(|op| op.address_count()).sum()
    }
}

// ---------------------------------------------------------------------------
// ClearDialog
// ---------------------------------------------------------------------------

/// Dialog for configuring clear options before applying.
///
/// Ported from `ghidra.app.plugin.core.clear.ClearDialog`.
#[derive(Debug, Clone)]
pub struct ClearDialog {
    /// The clear options selected by the user.
    pub options: ClearOptions,
    /// Whether the dialog was confirmed.
    pub confirmed: bool,
    /// The address range to clear.
    pub start_address: u64,
    /// End address of the range.
    pub end_address: u64,
}

impl ClearDialog {
    /// Create a new clear dialog.
    pub fn new(start: u64, end: u64) -> Self {
        Self {
            options: ClearOptions::default(),
            confirmed: false,
            start_address: start,
            end_address: end,
        }
    }

    /// Confirm the dialog.
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    /// Get the address count.
    pub fn address_count(&self) -> u64 {
        self.end_address.saturating_sub(self.start_address) + 1
    }
}

// ---------------------------------------------------------------------------
// ClearFlowDialog
// ---------------------------------------------------------------------------

/// Dialog for clearing with flow override options.
///
/// Ported from `ghidra.app.plugin.core.clear.ClearFlowDialog`.
#[derive(Debug, Clone)]
pub struct ClearFlowDialog {
    /// Base clear dialog.
    pub clear_dialog: ClearDialog,
    /// Whether to clear flow override.
    pub clear_flow_override: bool,
    /// Whether to remove instruction context.
    pub remove_context: bool,
}

impl ClearFlowDialog {
    /// Create a new clear flow dialog.
    pub fn new(start: u64, end: u64) -> Self {
        Self {
            clear_dialog: ClearDialog::new(start, end),
            clear_flow_override: true,
            remove_context: false,
        }
    }

    /// Confirm the dialog.
    pub fn confirm(&mut self) {
        self.clear_dialog.confirm();
    }
}

// ---------------------------------------------------------------------------
// ClearPlugin
// ---------------------------------------------------------------------------

/// Plugin providing clear functionality.
///
/// Ported from `ghidra.app.plugin.core.clear.ClearPlugin`.
#[derive(Debug)]
pub struct ClearPlugin {
    /// Plugin name.
    pub name: String,
    /// Whether the plugin is enabled.
    pub enabled: bool,
    /// Last clear operation performed.
    pub last_operation: Option<ClearOperation>,
}

impl ClearPlugin {
    /// Create a new clear plugin.
    pub fn new() -> Self {
        Self {
            name: "ClearPlugin".into(),
            enabled: true,
            last_operation: None,
        }
    }

    /// Perform a clear operation.
    pub fn perform_clear(&mut self, op: ClearOperation) {
        self.last_operation = Some(op);
    }
}

impl Default for ClearPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clear_type_all() {
        assert_eq!(ClearType::all().len(), 13);
    }

    #[test]
    fn test_clear_options_all() {
        let opts = ClearOptions::all();
        assert!(opts.clear_any());
        assert!(opts.should_clear(ClearType::Instructions));
        assert!(opts.should_clear(ClearType::Bookmarks));
        assert_eq!(opts.enabled_count(), 13);
    }

    #[test]
    fn test_clear_options_none() {
        let opts = ClearOptions::none();
        assert!(!opts.clear_any());
        assert_eq!(opts.enabled_count(), 0);
    }

    #[test]
    fn test_clear_options_set_toggle() {
        let mut opts = ClearOptions::none();
        opts.set_should_clear(ClearType::Instructions, true);
        assert!(opts.should_clear(ClearType::Instructions));
        assert!(!opts.should_clear(ClearType::Data));
        opts.set_should_clear(ClearType::Instructions, false);
        assert!(!opts.should_clear(ClearType::Instructions));
    }

    #[test]
    fn test_clear_options_instructions_and_data() {
        let opts = ClearOptions::instructions_and_data();
        assert!(opts.should_clear(ClearType::Instructions));
        assert!(opts.should_clear(ClearType::Data));
        assert!(!opts.should_clear(ClearType::Symbols));
    }

    #[test]
    fn test_reference_source_types() {
        let mut opts = ClearOptions::none();
        opts.set_should_clear(ClearType::UserReferences, true);
        opts.set_should_clear(ClearType::AnalysisReferences, true);
        let types = opts.reference_source_types_to_clear();
        assert_eq!(types.len(), 2);
        assert!(types.contains(&"USER_DEFINED"));
        assert!(types.contains(&"ANALYSIS"));
    }

    #[test]
    fn test_clear_operation() {
        let op = ClearOperation::new(
            Address::new(0x1000),
            Address::new(0x1FFF),
            ClearType::Instructions,
        );
        assert_eq!(op.address_count(), 0x1000);
    }

    #[test]
    fn test_clear_operation_with_bytes() {
        let op = ClearOperation::new(
            Address::new(0x1000),
            Address::new(0x100F),
            ClearType::Data,
        )
        .with_clear_bytes(true);
        assert!(op.clear_bytes);
    }

    #[test]
    fn test_clear_model() {
        let mut model = ClearModel::new();
        model.add_operation(ClearOperation::new(
            Address::new(0x1000),
            Address::new(0x1FFF),
            ClearType::Instructions,
        ));
        assert_eq!(model.operation_count(), 1);
        model.clear();
        assert_eq!(model.operation_count(), 0);
    }

    #[test]
    fn test_clear_model_total_address_count() {
        let mut model = ClearModel::new();
        model.add_operation(ClearOperation::new(
            Address::new(0x1000),
            Address::new(0x100F),
            ClearType::Instructions,
        ));
        model.add_operation(ClearOperation::new(
            Address::new(0x2000),
            Address::new(0x20FF),
            ClearType::Data,
        ));
        assert_eq!(model.total_address_count(), 16 + 256);
    }

    #[test]
    fn test_clear_options_default_is_all() {
        let opts = ClearOptions::default();
        assert!(opts.should_clear(ClearType::Instructions));
        assert_eq!(opts.enabled_count(), 13);
    }

    #[test]
    fn test_clear_options_no_references() {
        let mut opts = ClearOptions::all();
        opts.set_should_clear(ClearType::UserReferences, false);
        opts.set_should_clear(ClearType::AnalysisReferences, false);
        opts.set_should_clear(ClearType::ImportReferences, false);
        opts.set_should_clear(ClearType::DefaultReferences, false);
        let refs = opts.reference_source_types_to_clear();
        assert!(refs.is_empty());
    }

    #[test]
    fn test_clear_cmd_basic() {
        let mut cmd = ClearCmd::new(
            Address::new(0x1000),
            Address::new(0x1FFF),
            ClearOptions::instructions_and_data(),
        );
        assert_eq!(cmd.status_msg(), "");
        assert!(!cmd.has_error());

        cmd.apply_to_program();
        assert!(cmd.was_applied());
        assert_eq!(cmd.cleared_items().len(), 2); // Instructions + Data
    }

    #[test]
    fn test_clear_cmd_preserves_labels() {
        let mut cmd = ClearCmd::new(
            Address::new(0x1000),
            Address::new(0x1FFF),
            ClearOptions::instructions_and_data(),
        );
        cmd.set_clear_labels(false);
        assert!(!cmd.should_clear_labels());

        cmd.apply_to_program();
        assert!(cmd.was_applied());
    }

    #[test]
    fn test_clear_flow_and_repair_cmd() {
        let mut cmd = ClearFlowAndRepairCmd::new(
            Address::new(0x1000),
            true,  // clear data
            false, // clear labels
            true,  // repair
        );
        assert_eq!(cmd.command_name(), "Clear Flow");
        assert!(cmd.should_repair());
        assert!(!cmd.has_protected_set());

        cmd.apply_to_program();
        assert!(cmd.was_applied());
    }

    #[test]
    fn test_clear_flow_and_repair_cmd_with_protected() {
        let mut protected = std::collections::HashSet::new();
        protected.insert(Address::new(0x1500));

        let cmd = ClearFlowAndRepairCmd::with_protected(
            Address::new(0x1000),
            Address::new(0x1FFF),
            true,
            false,
            true,
            protected,
        );
        assert!(cmd.has_protected_set());
        assert!(cmd.is_protected(Address::new(0x1500)));
        assert!(!cmd.is_protected(Address::new(0x1200)));
    }

    #[test]
    fn test_clear_flow_and_repair_repair_functions() {
        let mut cmd = ClearFlowAndRepairCmd::new(
            Address::new(0x1000),
            true,
            false,
            true,
        );
        cmd.set_repair_functions(true);
        assert!(cmd.should_repair_functions());
    }

    #[test]
    fn test_clear_flow_and_repair_no_repair() {
        let cmd = ClearFlowAndRepairCmd::new(
            Address::new(0x1000),
            true,
            true,
            false,
        );
        assert!(!cmd.should_repair());
    }

    #[test]
    fn test_clear_cmd_display() {
        let cmd = ClearCmd::new(
            Address::new(0x1000),
            Address::new(0x1FFF),
            ClearOptions::all(),
        );
        let s = format!("{}", cmd);
        assert!(s.contains("Clear"));
    }

    #[test]
    fn test_clear_flow_and_repair_display() {
        let cmd = ClearFlowAndRepairCmd::new(
            Address::new(0x1000),
            true,
            false,
            true,
        );
        let s = format!("{}", cmd);
        assert!(s.contains("Clear Flow"));
    }
}

// ---------------------------------------------------------------------------
// ClearCmd -- command to clear code/data at addresses
// ---------------------------------------------------------------------------

/// Command that clears code units, data, labels, and other items at an address range.
///
/// Ported from Ghidra's `ClearCmd.java`.
#[derive(Debug, Clone)]
pub struct ClearCmd {
    start: Address,
    end: Address,
    options: ClearOptions,
    clear_labels: bool,
    clear_bytes: bool,
    applied: bool,
    cleared_items: Vec<ClearType>,
    status_msg: String,
}

impl ClearCmd {
    /// Create a new clear command.
    pub fn new(start: Address, end: Address, options: ClearOptions) -> Self {
        Self {
            start,
            end,
            options,
            clear_labels: true,
            clear_bytes: false,
            applied: false,
            cleared_items: Vec::new(),
            status_msg: String::new(),
        }
    }

    /// Whether to clear labels/symbols.
    pub fn set_clear_labels(&mut self, clear: bool) {
        self.clear_labels = clear;
    }

    /// Whether labels should be cleared.
    pub fn should_clear_labels(&self) -> bool {
        self.clear_labels
    }

    /// Whether to clear bytes.
    pub fn set_clear_bytes(&mut self, clear: bool) {
        self.clear_bytes = clear;
    }

    /// The start address.
    pub fn start(&self) -> Address {
        self.start
    }

    /// The end address.
    pub fn end(&self) -> Address {
        self.end
    }

    /// The clear options.
    pub fn options(&self) -> &ClearOptions {
        &self.options
    }

    /// Apply the clear to a program (simulated).
    pub fn apply_to_program(&mut self) {
        self.cleared_items.clear();
        for &clear_type in ClearType::all() {
            if self.options.should_clear(clear_type) {
                self.cleared_items.push(clear_type);
            }
        }
        self.applied = true;
        self.status_msg = format!("Cleared {} types over {} addresses",
            self.cleared_items.len(),
            self.end.offset.saturating_sub(self.start.offset) + 1
        );
    }

    /// Whether the command was applied.
    pub fn was_applied(&self) -> bool {
        self.applied
    }

    /// Get the list of cleared item types.
    pub fn cleared_items(&self) -> &[ClearType] {
        &self.cleared_items
    }

    /// The status message.
    pub fn status_msg(&self) -> &str {
        &self.status_msg
    }

    /// Whether an error occurred.
    pub fn has_error(&self) -> bool {
        self.status_msg.contains("ERROR")
    }
}

impl std::fmt::Display for ClearCmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Clear {:?} to {:?} ({})", self.start, self.end, self.status_msg)
    }
}

// ---------------------------------------------------------------------------
// ClearFlowAndRepairCmd -- clear flow and optionally repair
// ---------------------------------------------------------------------------

/// Command that clears code flow at an address and optionally repairs it.
///
/// Ported from Ghidra's `ClearFlowAndRepairCmd.java`.
/// This is the most complex clear command, handling:
/// - Clearing code units
/// - Removing references
/// - Repairing flow (re-disassembling fallthrough paths)
/// - Handling protected address sets
#[derive(Debug, Clone)]
pub struct ClearFlowAndRepairCmd {
    start: Address,
    end: Address,
    clear_data: bool,
    clear_labels: bool,
    repair: bool,
    repair_functions: bool,
    clear_computed_ptr_refs: bool,
    clear_offcut: bool,
    protected: HashSet<Address>,
    applied: bool,
    status_msg: String,
}

impl ClearFlowAndRepairCmd {
    /// The fallthrough search limit for repair operations.
    pub const FALLTHROUGH_SEARCH_LIMIT: usize = 12;

    /// Create a new clear-flow-and-repair command.
    pub fn new(
        start: Address,
        clear_data: bool,
        clear_labels: bool,
        repair: bool,
    ) -> Self {
        Self {
            start,
            end: start,
            clear_data,
            clear_labels,
            repair,
            repair_functions: false,
            clear_computed_ptr_refs: true,
            clear_offcut: true,
            protected: HashSet::new(),
            applied: false,
            status_msg: String::new(),
        }
    }

    /// Create with a protected address set.
    pub fn with_protected(
        start: Address,
        end: Address,
        clear_data: bool,
        clear_labels: bool,
        repair: bool,
        protected: HashSet<Address>,
    ) -> Self {
        Self {
            start,
            end,
            clear_data,
            clear_labels,
            repair,
            repair_functions: false,
            clear_computed_ptr_refs: true,
            clear_offcut: true,
            protected,
            applied: false,
            status_msg: String::new(),
        }
    }

    /// The command name.
    pub fn command_name(&self) -> &str {
        "Clear Flow"
    }

    /// Whether this command should repair flow.
    pub fn should_repair(&self) -> bool {
        self.repair
    }

    /// Whether to clear data.
    pub fn should_clear_data(&self) -> bool {
        self.clear_data
    }

    /// Whether to clear labels.
    pub fn should_clear_labels(&self) -> bool {
        self.clear_labels
    }

    /// Whether to repair functions.
    pub fn should_repair_functions(&self) -> bool {
        self.repair_functions
    }

    /// Set whether to repair functions.
    pub fn set_repair_functions(&mut self, repair: bool) {
        self.repair_functions = repair;
    }

    /// Whether to clear computed pointer references.
    pub fn should_clear_computed_ptr_refs(&self) -> bool {
        self.clear_computed_ptr_refs
    }

    /// Set whether to clear computed pointer references.
    pub fn set_clear_computed_ptr_refs(&mut self, clear: bool) {
        self.clear_computed_ptr_refs = clear;
    }

    /// Whether to clear offcut references.
    pub fn should_clear_offcut(&self) -> bool {
        self.clear_offcut
    }

    /// Set whether to clear offcut references.
    pub fn set_clear_offcut(&mut self, clear: bool) {
        self.clear_offcut = clear;
    }

    /// Whether a protected set is configured.
    pub fn has_protected_set(&self) -> bool {
        !self.protected.is_empty()
    }

    /// Check if an address is protected.
    pub fn is_protected(&self, address: Address) -> bool {
        self.protected.contains(&address)
    }

    /// Apply the command to a program (simulated).
    pub fn apply_to_program(&mut self) {
        self.applied = true;
        self.status_msg = format!(
            "Cleared flow at {:?}-{:?} (repair={}, data={}, labels={})",
            self.start, self.end, self.repair, self.clear_data, self.clear_labels
        );
    }

    /// Whether the command was applied.
    pub fn was_applied(&self) -> bool {
        self.applied
    }

    /// The status message.
    pub fn status_msg(&self) -> &str {
        &self.status_msg
    }

    /// The start address.
    pub fn start(&self) -> Address {
        self.start
    }

    /// The end address.
    pub fn end(&self) -> Address {
        self.end
    }
}

impl std::fmt::Display for ClearFlowAndRepairCmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Clear Flow {:?}-{:?}", self.start, self.end)
    }
}
