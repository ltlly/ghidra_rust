//! Clear flow and repair command -- clears code flow and optionally repairs disassembly.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd`.
//!
//! The `ClearFlowAndRepairCmd` follows instruction flow from a set of start
//! addresses, identifies all reachable code blocks, and clears them. It
//! optionally repairs disassembly around the cleared area by re-disassembling
//! from reference points.

use super::options::{ClearOptions, ClearType};
use ghidra_core::addr::{Address, AddressSet};
use serde::{Deserialize, Serialize};

/// Maximum number of backward addresses to search for fallthrough repair.
///
/// When repairing, the command searches backward from each cleared range
/// boundary for an instruction whose fallthrough falls into the cleared
/// region.
pub const FALLTHROUGH_SEARCH_LIMIT: u32 = 12;

/// A command that follows code flow from selected addresses, clears the
/// identified flow, and optionally repairs the surrounding disassembly.
///
/// This is the Rust equivalent of Ghidra's `ClearFlowAndRepairCmd`. The
/// command:
///
/// 1. Identifies all instruction flow from the start addresses
/// 2. Optionally follows data references to find additional code to clear
/// 3. Builds an address set of all code to clear
/// 4. Executes a [`ClearCmd`](super::cmd::ClearCmd) with the computed set
/// 5. Optionally repairs fallthroughs and functions around the cleared area
///
/// # Construction
///
/// ```rust
/// use ghidra_features::base::clear::ClearFlowAndRepairCmd;
/// use ghidra_core::addr::{Address, AddressSet};
///
/// // From a single address
/// let cmd = ClearFlowAndRepairCmd::from_address(
///     Address::new(0x401000), true, false, true,
/// );
///
/// // From an address set
/// let mut addrs = AddressSet::new();
/// addrs.add_range(Address::new(0x401000), Address::new(0x401100));
/// let cmd = ClearFlowAndRepairCmd::new(addrs, None, true, false, true);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearFlowAndRepairCmd {
    /// The initial addresses from which to follow flow.
    start_addrs: AddressSet,
    /// Addresses that should not be cleared (protected regions).
    protected_set: AddressSet,
    /// Whether to clear data encountered during flow analysis.
    clear_data: bool,
    /// Whether to clear labels (symbols) in the cleared region.
    clear_labels: bool,
    /// Whether to clear computed pointer references.
    clear_computed_ptr_refs: bool,
    /// Whether to clear offcut (misaligned) instruction flows.
    clear_offcut: bool,
    /// Whether to repair disassembly around the cleared area.
    repair: bool,
    /// Whether to repair function boundaries after clearing.
    repair_functions: bool,
}

impl ClearFlowAndRepairCmd {
    /// Creates a command from a single address.
    pub fn from_address(
        addr: Address,
        clear_data: bool,
        clear_labels: bool,
        repair: bool,
    ) -> Self {
        Self::new(
            AddressSet::from_range(addr, addr),
            None,
            clear_data,
            clear_labels,
            repair,
        )
    }

    /// Creates a command from an address set with optional protection.
    ///
    /// # Parameters
    ///
    /// * `start_addrs` - Addresses from which to follow flow.
    /// * `protected_set` - Optional addresses that should not be cleared.
    /// * `clear_data` - Whether to clear defined data in the flow.
    /// * `clear_labels` - Whether to clear label symbols.
    /// * `repair` - Whether to repair disassembly after clearing.
    pub fn new(
        start_addrs: AddressSet,
        protected_set: Option<AddressSet>,
        clear_data: bool,
        clear_labels: bool,
        repair: bool,
    ) -> Self {
        Self {
            start_addrs,
            protected_set: protected_set.unwrap_or_default(),
            clear_data,
            clear_labels,
            clear_computed_ptr_refs: true,
            clear_offcut: true,
            repair,
            repair_functions: repair,
        }
    }

    // -- Accessors --

    /// Returns the command name for display.
    pub fn name(&self) -> &str {
        "Clear Flow"
    }

    /// Returns a reference to the start address set.
    pub fn start_addrs(&self) -> &AddressSet {
        &self.start_addrs
    }

    /// Returns a reference to the protected address set.
    pub fn protected_set(&self) -> &AddressSet {
        &self.protected_set
    }

    /// Returns whether data will be cleared.
    pub fn clears_data(&self) -> bool {
        self.clear_data
    }

    /// Returns whether labels will be cleared.
    pub fn clears_labels(&self) -> bool {
        self.clear_labels
    }

    /// Returns whether computed pointer references will be cleared.
    pub fn clears_computed_ptr_refs(&self) -> bool {
        self.clear_computed_ptr_refs
    }

    /// Returns whether offcut instruction flows will be cleared.
    pub fn clears_offcut(&self) -> bool {
        self.clear_offcut
    }

    /// Returns whether disassembly repair will be performed.
    pub fn repairs(&self) -> bool {
        self.repair
    }

    /// Returns whether function repair will be performed.
    pub fn repairs_functions(&self) -> bool {
        self.repair_functions
    }

    /// Builds a [`ClearOptions`] suitable for clearing the identified flow.
    ///
    /// This creates options with instructions, data (if `clear_data`),
    /// symbols (if `clear_labels`), and all reference types enabled.
    pub fn build_clear_options(&self) -> ClearOptions {
        let mut opts = ClearOptions::new(false);
        opts.set_should_clear(ClearType::Instructions, true);
        opts.set_should_clear(ClearType::Data, self.clear_data);
        opts.set_should_clear(ClearType::Symbols, self.clear_labels);
        opts.set_should_clear(ClearType::Comments, true);
        opts.set_should_clear(ClearType::Properties, true);
        opts.set_should_clear(ClearType::Functions, true);
        opts.set_should_clear(ClearType::Registers, true);
        opts.set_should_clear(ClearType::Equates, true);
        opts.set_should_clear(ClearType::Bookmarks, true);
        opts.set_should_clear(ClearType::UserReferences, true);
        opts.set_should_clear(ClearType::AnalysisReferences, true);
        opts.set_should_clear(ClearType::ImportReferences, true);
        opts.set_should_clear(ClearType::DefaultReferences, true);
        opts
    }
}

/// Describes the steps the flow-clear command would perform.
///
/// This is used for progress display and debugging. It mirrors the
/// high-level phases of `ClearFlowAndRepairCmd.applyTo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowClearPhase {
    /// Examining code flow from start addresses.
    ExaminingFlow,
    /// Building the address set of code to clear.
    BuildingClearSet,
    /// Clearing the identified code.
    ClearingCode,
    /// Clearing dereferenced symbols.
    ClearingDereferencedSymbols,
    /// Repairing fallthrough flows.
    RepairingFallthroughs,
    /// Repairing function boundaries.
    RepairingFunctions,
    /// Complete.
    Complete,
}

/// Result of analyzing which code flow to clear.
///
/// Contains the computed address set that would be cleared, the phases
/// that would be executed, and any warnings generated during analysis.
#[derive(Debug, Clone)]
pub struct FlowAnalysisResult {
    /// The computed set of addresses to be cleared.
    pub clear_set: AddressSet,
    /// The phases that would be executed (in order).
    pub phases: Vec<FlowClearPhase>,
    /// Warnings generated during analysis (e.g., overlapping functions).
    pub warnings: Vec<String>,
    /// The number of blocks analyzed.
    pub block_count: usize,
    /// The number of data reference destinations found.
    pub data_ref_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_address_creates_singleton_set() {
        let cmd = ClearFlowAndRepairCmd::from_address(
            Address::new(0x401000),
            true,
            false,
            true,
        );
        assert_eq!(cmd.start_addrs().num_addresses(), 1);
        assert!(cmd.start_addrs().contains(&Address::new(0x401000)));
    }

    #[test]
    fn test_default_flags() {
        let cmd = ClearFlowAndRepairCmd::from_address(
            Address::new(0x401000),
            false,
            false,
            false,
        );
        assert!(!cmd.clears_data());
        assert!(!cmd.clears_labels());
        assert!(!cmd.repairs());
        assert!(!cmd.repairs_functions());
        assert!(cmd.clears_computed_ptr_refs());
        assert!(cmd.clears_offcut());
    }

    #[test]
    fn test_repair_implies_repair_functions() {
        let cmd = ClearFlowAndRepairCmd::from_address(
            Address::new(0x401000),
            true,
            false,
            true,
        );
        assert!(cmd.repairs());
        assert!(cmd.repairs_functions());
    }

    #[test]
    fn test_no_repair_implies_no_function_repair() {
        let cmd = ClearFlowAndRepairCmd::from_address(
            Address::new(0x401000),
            true,
            false,
            false,
        );
        assert!(!cmd.repairs());
        assert!(!cmd.repairs_functions());
    }

    #[test]
    fn test_protected_set() {
        let mut protected = AddressSet::new();
        protected.add_range(Address::new(0x402000), Address::new(0x402FFF));

        let cmd = ClearFlowAndRepairCmd::new(
            AddressSet::from_range(Address::new(0x401000), Address::new(0x403000)),
            Some(protected),
            true,
            false,
            true,
        );
        assert!(!cmd.protected_set().is_empty());
        assert!(cmd.protected_set().contains(&Address::new(0x402500)));
    }

    #[test]
    fn test_build_clear_options_data_and_labels() {
        let cmd = ClearFlowAndRepairCmd::from_address(
            Address::new(0x401000),
            true,
            true,
            true,
        );
        let opts = cmd.build_clear_options();
        assert!(opts.should_clear(ClearType::Instructions));
        assert!(opts.should_clear(ClearType::Data));
        assert!(opts.should_clear(ClearType::Symbols));
        assert!(opts.should_clear(ClearType::Comments));
        assert!(opts.should_clear(ClearType::Functions));
        assert!(opts.should_clear(ClearType::Bookmarks));
    }

    #[test]
    fn test_build_clear_options_no_data_no_labels() {
        let cmd = ClearFlowAndRepairCmd::from_address(
            Address::new(0x401000),
            false,
            false,
            true,
        );
        let opts = cmd.build_clear_options();
        assert!(opts.should_clear(ClearType::Instructions));
        assert!(!opts.should_clear(ClearType::Data));
        assert!(!opts.should_clear(ClearType::Symbols));
    }

    #[test]
    fn test_name() {
        let cmd = ClearFlowAndRepairCmd::from_address(
            Address::new(0x401000),
            true,
            false,
            true,
        );
        assert_eq!(cmd.name(), "Clear Flow");
    }

    #[test]
    fn test_flow_clear_phase_ordering() {
        let phases = vec![
            FlowClearPhase::ExaminingFlow,
            FlowClearPhase::BuildingClearSet,
            FlowClearPhase::ClearingCode,
            FlowClearPhase::ClearingDereferencedSymbols,
            FlowClearPhase::RepairingFallthroughs,
            FlowClearPhase::RepairingFunctions,
            FlowClearPhase::Complete,
        ];
        assert_eq!(phases.len(), 7);
        assert_eq!(phases[0], FlowClearPhase::ExaminingFlow);
        assert_eq!(phases[6], FlowClearPhase::Complete);
    }
}
