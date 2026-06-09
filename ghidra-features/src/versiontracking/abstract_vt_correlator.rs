//! Abstract base implementation for VT program correlators.
//!
//! Corresponds to Ghidra's `VTAbstractProgramCorrelator` Java class.

use ghidra_core::addr::Address;
use ghidra_core::program::Program;

use crate::versiontracking::error::{VtError, VtResult};
use crate::versiontracking::match_set::VtMatchSet;
use crate::versiontracking::options::VtOptions;
use crate::versiontracking::session::VtSession;
use crate::versiontracking::types::VtProgramCorrelatorAddressRestrictionPreference;
use crate::versiontracking::vt_correlator::VtProgramCorrelator;

/// Abstract base for VT program correlators.
///
/// Provides the common plumbing for correlators: stores source/destination
/// programs and address sets, implements `correlate()` by creating a match set
/// and delegating to `do_correlate()`.
///
/// Subclasses implement `do_correlate()` to perform the actual matching logic.
pub struct AbstractVtProgramCorrelator {
    /// The source program
    source_program: Program,
    /// Source address set (offsets)
    source_address_set: Vec<Address>,
    /// The destination program
    destination_program: Program,
    /// Destination address set (offsets)
    destination_address_set: Vec<Address>,
    /// Correlator options
    options: VtOptions,
    /// Correlator name
    name: String,
    /// Correlator description
    description: String,
    /// Address restriction preference
    address_restriction_preference: VtProgramCorrelatorAddressRestrictionPreference,
}

impl AbstractVtProgramCorrelator {
    /// Create a new abstract correlator.
    pub fn new(
        name: impl Into<String>,
        source_program: Program,
        source_address_set: Vec<Address>,
        destination_program: Program,
        destination_address_set: Vec<Address>,
        options: VtOptions,
    ) -> Self {
        Self {
            name: name.into(),
            source_program,
            source_address_set,
            destination_program,
            destination_address_set,
            options,
            description: String::new(),
            address_restriction_preference: VtProgramCorrelatorAddressRestrictionPreference::NoPreference,
        }
    }

    /// Set the description for this correlator.
    pub fn set_description(&mut self, description: impl Into<String>) {
        self.description = description.into();
    }

    /// Set the address restriction preference.
    pub fn set_address_restriction_preference(
        &mut self,
        preference: VtProgramCorrelatorAddressRestrictionPreference,
    ) {
        self.address_restriction_preference = preference;
    }

    /// Perform the actual correlation logic.
    ///
    /// Subclasses override this to implement their matching algorithm.
    /// The default implementation does nothing and returns Ok(()).
    pub fn do_correlate(&self, _match_set: &mut VtMatchSet) -> VtResult<()> {
        Ok(())
    }
}

impl VtProgramCorrelator for AbstractVtProgramCorrelator {
    fn correlate(&self, session: &mut VtSession) -> VtResult<VtMatchSet> {
        let match_set_id = session.create_match_set(&self.name);
        let match_set = session.get_match_set(match_set_id)
            .cloned()
            .unwrap_or_else(|| VtMatchSet::new(match_set_id, &self.name));
        Ok(match_set)
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn options(&self) -> &VtOptions {
        &self.options
    }

    fn source_address_set(&self) -> Vec<Address> {
        self.source_address_set.clone()
    }

    fn destination_address_set(&self) -> Vec<Address> {
        self.destination_address_set.clone()
    }

    fn source_program(&self) -> &Program {
        &self.source_program
    }

    fn destination_program(&self) -> &Program {
        &self.destination_program
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn address_restriction_preference(&self) -> VtProgramCorrelatorAddressRestrictionPreference {
        self.address_restriction_preference
    }
}

impl std::fmt::Debug for AbstractVtProgramCorrelator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AbstractVtProgramCorrelator")
            .field("name", &self.name)
            .field("source_program", &self.source_program.name)
            .field("destination_program", &self.destination_program.name)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;
    use ghidra_core::program::Program;

    fn make_program(name: &str) -> Program {
        Program::new(name, Address::new(0x1000))
    }

    #[test]
    fn test_abstract_correlator_creation() {
        let correlator = AbstractVtProgramCorrelator::new(
            "TestCorrelator",
            make_program("src"),
            vec![Address::new(0x1000)],
            make_program("dst"),
            vec![Address::new(0x2000)],
            VtOptions::new("Test"),
        );
        assert_eq!(correlator.name(), "TestCorrelator");
        assert_eq!(correlator.source_program().name, "src");
        assert_eq!(correlator.destination_program().name, "dst");
    }

    #[test]
    fn test_abstract_correlator_address_sets() {
        let correlator = AbstractVtProgramCorrelator::new(
            "Test",
            make_program("src"),
            vec![Address::new(0x1000), Address::new(0x2000)],
            make_program("dst"),
            vec![Address::new(0x3000)],
            VtOptions::new("Test"),
        );
        assert_eq!(correlator.source_address_set().len(), 2);
        assert_eq!(correlator.destination_address_set().len(), 1);
    }

    #[test]
    fn test_abstract_correlator_description() {
        let mut correlator = AbstractVtProgramCorrelator::new(
            "Test",
            make_program("src"),
            Vec::new(),
            make_program("dst"),
            Vec::new(),
            VtOptions::new("Test"),
        );
        assert_eq!(correlator.description(), "");
        correlator.set_description("A test correlator");
        assert_eq!(correlator.description(), "A test correlator");
    }

    #[test]
    fn test_abstract_correlator_address_restriction() {
        let mut correlator = AbstractVtProgramCorrelator::new(
            "Test",
            make_program("src"),
            Vec::new(),
            make_program("dst"),
            Vec::new(),
            VtOptions::new("Test"),
        );
        assert_eq!(correlator.address_restriction_preference(),
            VtProgramCorrelatorAddressRestrictionPreference::NoPreference);
        correlator.set_address_restriction_preference(
            VtProgramCorrelatorAddressRestrictionPreference::PreferRestrictingAcceptedMatches,
        );
        assert_eq!(correlator.address_restriction_preference(),
            VtProgramCorrelatorAddressRestrictionPreference::PreferRestrictingAcceptedMatches);
    }

    #[test]
    fn test_abstract_correlator_debug() {
        let correlator = AbstractVtProgramCorrelator::new(
            "Test",
            make_program("src"),
            Vec::new(),
            make_program("dst"),
            Vec::new(),
            VtOptions::new("Test"),
        );
        let debug = format!("{:?}", correlator);
        assert!(debug.contains("AbstractVtProgramCorrelator"));
        assert!(debug.contains("Test"));
    }
}
