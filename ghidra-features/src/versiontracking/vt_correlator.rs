//! VTProgramCorrelator trait -- the core interface for version tracking correlators.
//!
//! Corresponds to Ghidra's `VTProgramCorrelator` Java interface.

use ghidra_core::addr::Address;
use ghidra_core::program::Program;

use crate::versiontracking::error::VtResult;
use crate::versiontracking::match_set::VtMatchSet;
use crate::versiontracking::options::VtOptions;
use crate::versiontracking::session::VtSession;
use crate::versiontracking::types::VtProgramCorrelatorAddressRestrictionPreference;

/// Trait for algorithms that correlate items (primarily functions) from one
/// program to another, typically for purposes of version tracking.
///
/// This is the Rust equivalent of Ghidra's `VTProgramCorrelator` Java interface.
pub trait VtProgramCorrelator: Send + Sync {
    /// Performs the correlation between two programs.
    ///
    /// Creates a new match set in the session and populates it with matches
    /// discovered by this correlator's algorithm.
    fn correlate(&self, session: &mut VtSession) -> VtResult<VtMatchSet>;

    /// Returns the name of this correlator.
    fn name(&self) -> &str;

    /// Returns the options for this correlator.
    fn options(&self) -> &VtOptions;

    /// Returns the source address set to use in the correlation.
    fn source_address_set(&self) -> Vec<Address>;

    /// Returns the destination address set to search within.
    fn destination_address_set(&self) -> Vec<Address>;

    /// Returns the source program.
    fn source_program(&self) -> &Program;

    /// Returns the destination program.
    fn destination_program(&self) -> &Program;

    /// Returns a description of this correlator.
    fn description(&self) -> &str {
        ""
    }

    /// Returns the address restriction preference for this correlator.
    fn address_restriction_preference(&self) -> VtProgramCorrelatorAddressRestrictionPreference {
        VtProgramCorrelatorAddressRestrictionPreference::NoPreference
    }
}

/// Trait for creating VTProgramCorrelator instances.
///
/// Corresponds to Ghidra's `VTProgramCorrelatorFactory` Java interface.
pub trait VtProgramCorrelatorFactory: Send + Sync {
    /// Returns the name of this correlator factory.
    fn name(&self) -> &str;

    /// Returns a description of this correlator.
    fn description(&self) -> &str;

    /// Returns the priority of this correlator. Lower numbers run first.
    fn priority(&self) -> i32;

    /// Returns the address restriction preference.
    fn address_restriction_preference(&self) -> VtProgramCorrelatorAddressRestrictionPreference {
        VtProgramCorrelatorAddressRestrictionPreference::NoPreference
    }

    /// Creates default options for this correlator.
    fn create_default_options(&self) -> VtOptions;

    /// Creates a new correlator instance with the given parameters.
    fn create_correlator(
        &self,
        source_program: &Program,
        source_address_set: &[Address],
        destination_program: &Program,
        destination_address_set: &[Address],
        options: &VtOptions,
    ) -> Box<dyn VtProgramCorrelator>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;
    use ghidra_core::program::Program;

    struct TestCorrelator {
        name: String,
        options: VtOptions,
    }

    impl VtProgramCorrelator for TestCorrelator {
        fn correlate(&self, _session: &mut VtSession) -> VtResult<VtMatchSet> {
            Ok(VtMatchSet::new(1, &self.name))
        }
        fn name(&self) -> &str { &self.name }
        fn options(&self) -> &VtOptions { &self.options }
        fn source_address_set(&self) -> Vec<Address> { Vec::new() }
        fn destination_address_set(&self) -> Vec<Address> { Vec::new() }
        fn source_program(&self) -> &Program { unimplemented!() }
        fn destination_program(&self) -> &Program { unimplemented!() }
    }

    #[test]
    fn test_correlator_trait() {
        let correlator = TestCorrelator {
            name: "TestCorrelator".to_string(),
            options: VtOptions::new("Test"),
        };
        assert_eq!(correlator.name(), "TestCorrelator");
        assert_eq!(correlator.address_restriction_preference(),
            VtProgramCorrelatorAddressRestrictionPreference::NoPreference);
    }
}
