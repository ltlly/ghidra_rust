//! Program correlators and factories.

use ghidra_core::addr::Address;
use ghidra_core::program::Program;
use crate::versiontracking::error::VtResult;
use crate::versiontracking::match_set::VtMatchSet;
use crate::versiontracking::options::VtOptions;
use crate::versiontracking::types::{VtAssociationType, VtProgramCorrelatorAddressRestrictionPreference, VtScore};

pub trait VtProgramCorrelator: Send + Sync {
    fn correlate(&self, session: &mut crate::versiontracking::session::VtSession) -> VtResult<VtMatchSet>;
    fn name(&self) -> &str;
    fn options(&self) -> &VtOptions;
    fn source_address_set(&self) -> Vec<Address>;
    fn destination_address_set(&self) -> Vec<Address>;
}

pub trait VtProgramCorrelatorFactory: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn priority(&self) -> i32;
    fn address_restriction_preference(&self) -> VtProgramCorrelatorAddressRestrictionPreference { VtProgramCorrelatorAddressRestrictionPreference::NoPreference }
    fn create_default_options(&self) -> VtOptions;
    fn create_correlator(&self, source_program: &Program, source_address_set: &[Address],
        destination_program: &Program, destination_address_set: &[Address], options: &VtOptions) -> Box<dyn VtProgramCorrelator>;
}

// -- Factory implementations --

pub struct ExactMatchBytesCorrelatorFactory;
impl ExactMatchBytesCorrelatorFactory { pub const NAME: &'static str = "Exact Function Bytes Match"; pub const FUNCTION_MINIMUM_SIZE: &'static str = "Function Minimum Size"; pub const FUNCTION_MINIMUM_SIZE_DEFAULT: i64 = 10; }
impl VtProgramCorrelatorFactory for ExactMatchBytesCorrelatorFactory {
    fn name(&self) -> &str { Self::NAME }
    fn description(&self) -> &str { "Compares code by hashing bytes, looking for identical functions." }
    fn priority(&self) -> i32 { 20 }
    fn create_default_options(&self) -> VtOptions { let mut opts = VtOptions::new(Self::NAME); opts.set_int(Self::FUNCTION_MINIMUM_SIZE, Self::FUNCTION_MINIMUM_SIZE_DEFAULT); opts }
    fn create_correlator(&self, sp: &Program, sa: &[Address], dp: &Program, da: &[Address], opts: &VtOptions) -> Box<dyn VtProgramCorrelator> {
        Box::new(StubCorrelator { name: Self::NAME.to_string(), options: opts.clone(), source_address_set: sa.to_vec(), dest_address_set: da.to_vec() })
    }
}

pub struct ExactMatchInstructionsCorrelatorFactory;
impl ExactMatchInstructionsCorrelatorFactory { pub const NAME: &'static str = "Exact Function Instructions Match"; }
impl VtProgramCorrelatorFactory for ExactMatchInstructionsCorrelatorFactory {
    fn name(&self) -> &str { Self::NAME }
    fn description(&self) -> &str { "Compares code by hashing instructions, looking for identical functions." }
    fn priority(&self) -> i32 { 30 }
    fn create_default_options(&self) -> VtOptions { VtOptions::new(Self::NAME) }
    fn create_correlator(&self, _: &Program, sa: &[Address], _: &Program, da: &[Address], opts: &VtOptions) -> Box<dyn VtProgramCorrelator> {
        Box::new(StubCorrelator { name: Self::NAME.to_string(), options: opts.clone(), source_address_set: sa.to_vec(), dest_address_set: da.to_vec() })
    }
}

pub struct ExactMatchMnemonicsCorrelatorFactory;
impl ExactMatchMnemonicsCorrelatorFactory { pub const NAME: &'static str = "Exact Function Mnemonics Match"; }
impl VtProgramCorrelatorFactory for ExactMatchMnemonicsCorrelatorFactory {
    fn name(&self) -> &str { Self::NAME }
    fn description(&self) -> &str { "Compares code by hashing mnemonics, looking for identical mnemonic sequences." }
    fn priority(&self) -> i32 { 40 }
    fn create_default_options(&self) -> VtOptions { VtOptions::new(Self::NAME) }
    fn create_correlator(&self, _: &Program, sa: &[Address], _: &Program, da: &[Address], opts: &VtOptions) -> Box<dyn VtProgramCorrelator> {
        Box::new(StubCorrelator { name: Self::NAME.to_string(), options: opts.clone(), source_address_set: sa.to_vec(), dest_address_set: da.to_vec() })
    }
}

pub struct SymbolNameCorrelatorFactory;
impl SymbolNameCorrelatorFactory { pub const NAME: &'static str = "Symbol Name Match"; }
impl VtProgramCorrelatorFactory for SymbolNameCorrelatorFactory {
    fn name(&self) -> &str { Self::NAME }
    fn description(&self) -> &str { "Matches functions and data items that have the same symbol name in both programs." }
    fn priority(&self) -> i32 { 10 }
    fn address_restriction_preference(&self) -> VtProgramCorrelatorAddressRestrictionPreference { VtProgramCorrelatorAddressRestrictionPreference::PreferRestrictingAcceptedMatches }
    fn create_default_options(&self) -> VtOptions { VtOptions::new(Self::NAME) }
    fn create_correlator(&self, _: &Program, sa: &[Address], _: &Program, da: &[Address], opts: &VtOptions) -> Box<dyn VtProgramCorrelator> {
        Box::new(StubCorrelator { name: Self::NAME.to_string(), options: opts.clone(), source_address_set: sa.to_vec(), dest_address_set: da.to_vec() })
    }
}

pub struct SimilarSymbolNameCorrelatorFactory;
impl SimilarSymbolNameCorrelatorFactory { pub const NAME: &'static str = "Similar Symbol Name Match"; }
impl VtProgramCorrelatorFactory for SimilarSymbolNameCorrelatorFactory {
    fn name(&self) -> &str { Self::NAME }
    fn description(&self) -> &str { "Matches functions and data items that have similar symbol names." }
    fn priority(&self) -> i32 { 15 }
    fn create_default_options(&self) -> VtOptions { VtOptions::new(Self::NAME) }
    fn create_correlator(&self, _: &Program, sa: &[Address], _: &Program, da: &[Address], opts: &VtOptions) -> Box<dyn VtProgramCorrelator> {
        Box::new(StubCorrelator { name: Self::NAME.to_string(), options: opts.clone(), source_address_set: sa.to_vec(), dest_address_set: da.to_vec() })
    }
}

pub struct DataMatchCorrelatorFactory;
impl DataMatchCorrelatorFactory { pub const NAME: &'static str = "Data Match"; }
impl VtProgramCorrelatorFactory for DataMatchCorrelatorFactory {
    fn name(&self) -> &str { Self::NAME }
    fn description(&self) -> &str { "Matches data items by comparing type name, size, and byte content." }
    fn priority(&self) -> i32 { 50 }
    fn create_default_options(&self) -> VtOptions { VtOptions::new(Self::NAME) }
    fn create_correlator(&self, _: &Program, sa: &[Address], _: &Program, da: &[Address], opts: &VtOptions) -> Box<dyn VtProgramCorrelator> {
        Box::new(StubCorrelator { name: Self::NAME.to_string(), options: opts.clone(), source_address_set: sa.to_vec(), dest_address_set: da.to_vec() })
    }
}

pub struct SimilarDataCorrelatorFactory;
impl SimilarDataCorrelatorFactory { pub const NAME: &'static str = "Similar Data Match"; }
impl VtProgramCorrelatorFactory for SimilarDataCorrelatorFactory {
    fn name(&self) -> &str { Self::NAME }
    fn description(&self) -> &str { "Matches data items that are similar but not identical." }
    fn priority(&self) -> i32 { 55 }
    fn create_default_options(&self) -> VtOptions { VtOptions::new(Self::NAME) }
    fn create_correlator(&self, _: &Program, sa: &[Address], _: &Program, da: &[Address], opts: &VtOptions) -> Box<dyn VtProgramCorrelator> {
        Box::new(StubCorrelator { name: Self::NAME.to_string(), options: opts.clone(), source_address_set: sa.to_vec(), dest_address_set: da.to_vec() })
    }
}

pub struct FunctionReferenceCorrelatorFactory;
impl FunctionReferenceCorrelatorFactory { pub const NAME: &'static str = "Function Reference Match"; }
impl VtProgramCorrelatorFactory for FunctionReferenceCorrelatorFactory {
    fn name(&self) -> &str { Self::NAME }
    fn description(&self) -> &str { "Matches functions based on their call references." }
    fn priority(&self) -> i32 { 60 }
    fn create_default_options(&self) -> VtOptions { VtOptions::new(Self::NAME) }
    fn create_correlator(&self, _: &Program, sa: &[Address], _: &Program, da: &[Address], opts: &VtOptions) -> Box<dyn VtProgramCorrelator> {
        Box::new(StubCorrelator { name: Self::NAME.to_string(), options: opts.clone(), source_address_set: sa.to_vec(), dest_address_set: da.to_vec() })
    }
}

pub struct DataReferenceCorrelatorFactory;
impl DataReferenceCorrelatorFactory { pub const NAME: &'static str = "Data Reference Match"; }
impl VtProgramCorrelatorFactory for DataReferenceCorrelatorFactory {
    fn name(&self) -> &str { Self::NAME }
    fn description(&self) -> &str { "Matches data items based on their cross-references." }
    fn priority(&self) -> i32 { 70 }
    fn create_default_options(&self) -> VtOptions { VtOptions::new(Self::NAME) }
    fn create_correlator(&self, _: &Program, sa: &[Address], _: &Program, da: &[Address], opts: &VtOptions) -> Box<dyn VtProgramCorrelator> {
        Box::new(StubCorrelator { name: Self::NAME.to_string(), options: opts.clone(), source_address_set: sa.to_vec(), dest_address_set: da.to_vec() })
    }
}

pub struct CombinedReferenceCorrelatorFactory;
impl CombinedReferenceCorrelatorFactory { pub const NAME: &'static str = "Combined Function and Data Reference Match"; }
impl VtProgramCorrelatorFactory for CombinedReferenceCorrelatorFactory {
    fn name(&self) -> &str { Self::NAME }
    fn description(&self) -> &str { "Combines function and data reference matching." }
    fn priority(&self) -> i32 { 80 }
    fn create_default_options(&self) -> VtOptions { VtOptions::new(Self::NAME) }
    fn create_correlator(&self, _: &Program, sa: &[Address], _: &Program, da: &[Address], opts: &VtOptions) -> Box<dyn VtProgramCorrelator> {
        Box::new(StubCorrelator { name: Self::NAME.to_string(), options: opts.clone(), source_address_set: sa.to_vec(), dest_address_set: da.to_vec() })
    }
}

pub struct DuplicateFunctionCorrelatorFactory;
impl DuplicateFunctionCorrelatorFactory { pub const NAME: &'static str = "Duplicate Function Match"; }
impl VtProgramCorrelatorFactory for DuplicateFunctionCorrelatorFactory {
    fn name(&self) -> &str { Self::NAME }
    fn description(&self) -> &str { "Finds functions that are duplicates of already matched functions." }
    fn priority(&self) -> i32 { 90 }
    fn create_default_options(&self) -> VtOptions { VtOptions::new(Self::NAME) }
    fn create_correlator(&self, _: &Program, sa: &[Address], _: &Program, da: &[Address], opts: &VtOptions) -> Box<dyn VtProgramCorrelator> {
        Box::new(StubCorrelator { name: Self::NAME.to_string(), options: opts.clone(), source_address_set: sa.to_vec(), dest_address_set: da.to_vec() })
    }
}

pub struct DuplicateDataCorrelatorFactory;
impl DuplicateDataCorrelatorFactory { pub const NAME: &'static str = "Duplicate Data Match"; }
impl VtProgramCorrelatorFactory for DuplicateDataCorrelatorFactory {
    fn name(&self) -> &str { Self::NAME }
    fn description(&self) -> &str { "Finds data items that are duplicates of already matched data." }
    fn priority(&self) -> i32 { 95 }
    fn create_default_options(&self) -> VtOptions { VtOptions::new(Self::NAME) }
    fn create_correlator(&self, _: &Program, sa: &[Address], _: &Program, da: &[Address], opts: &VtOptions) -> Box<dyn VtProgramCorrelator> {
        Box::new(StubCorrelator { name: Self::NAME.to_string(), options: opts.clone(), source_address_set: sa.to_vec(), dest_address_set: da.to_vec() })
    }
}

pub struct DuplicateSymbolNameCorrelatorFactory;
impl DuplicateSymbolNameCorrelatorFactory { pub const NAME: &'static str = "Duplicate Symbol Name Match"; }
impl VtProgramCorrelatorFactory for DuplicateSymbolNameCorrelatorFactory {
    fn name(&self) -> &str { Self::NAME }
    fn description(&self) -> &str { "Matches entities with duplicate symbol names." }
    fn priority(&self) -> i32 { 92 }
    fn create_default_options(&self) -> VtOptions { VtOptions::new(Self::NAME) }
    fn create_correlator(&self, _: &Program, sa: &[Address], _: &Program, da: &[Address], opts: &VtOptions) -> Box<dyn VtProgramCorrelator> {
        Box::new(StubCorrelator { name: Self::NAME.to_string(), options: opts.clone(), source_address_set: sa.to_vec(), dest_address_set: da.to_vec() })
    }
}

pub struct ManualMatchCorrelatorFactory;
impl ManualMatchCorrelatorFactory { pub const NAME: &'static str = "Manual Match"; }
impl VtProgramCorrelatorFactory for ManualMatchCorrelatorFactory {
    fn name(&self) -> &str { Self::NAME }
    fn description(&self) -> &str { "Used to store manually created matches." }
    fn priority(&self) -> i32 { i32::MAX }
    fn create_default_options(&self) -> VtOptions { VtOptions::new(Self::NAME) }
    fn create_correlator(&self, _: &Program, _: &[Address], _: &Program, _: &[Address], opts: &VtOptions) -> Box<dyn VtProgramCorrelator> {
        Box::new(StubCorrelator { name: Self::NAME.to_string(), options: opts.clone(), source_address_set: vec![], dest_address_set: vec![] })
    }
}

pub struct ImpliedMatchCorrelatorFactory;
impl ImpliedMatchCorrelatorFactory { pub const NAME: &'static str = "Implied Match"; }
impl VtProgramCorrelatorFactory for ImpliedMatchCorrelatorFactory {
    fn name(&self) -> &str { Self::NAME }
    fn description(&self) -> &str { "Generates implied matches based on call references from accepted associations." }
    fn priority(&self) -> i32 { 100 }
    fn create_default_options(&self) -> VtOptions { VtOptions::new(Self::NAME) }
    fn create_correlator(&self, _: &Program, sa: &[Address], _: &Program, da: &[Address], opts: &VtOptions) -> Box<dyn VtProgramCorrelator> {
        Box::new(StubCorrelator { name: Self::NAME.to_string(), options: opts.clone(), source_address_set: sa.to_vec(), dest_address_set: da.to_vec() })
    }
}

// -- Stub correlator implementation --

struct StubCorrelator { name: String, options: VtOptions, source_address_set: Vec<Address>, dest_address_set: Vec<Address> }

impl VtProgramCorrelator for StubCorrelator {
    fn correlate(&self, _session: &mut crate::versiontracking::session::VtSession) -> VtResult<VtMatchSet> { Ok(VtMatchSet::new(0, &self.name)) }
    fn name(&self) -> &str { &self.name }
    fn options(&self) -> &VtOptions { &self.options }
    fn source_address_set(&self) -> Vec<Address> { self.source_address_set.clone() }
    fn destination_address_set(&self) -> Vec<Address> { self.dest_address_set.clone() }
}

/// Get all built-in correlator factories in priority order.
pub fn all_correlator_factories() -> Vec<Box<dyn VtProgramCorrelatorFactory>> {
    let mut factories: Vec<Box<dyn VtProgramCorrelatorFactory>> = vec![
        Box::new(SymbolNameCorrelatorFactory), Box::new(SimilarSymbolNameCorrelatorFactory),
        Box::new(ExactMatchBytesCorrelatorFactory), Box::new(ExactMatchInstructionsCorrelatorFactory),
        Box::new(ExactMatchMnemonicsCorrelatorFactory), Box::new(DataMatchCorrelatorFactory),
        Box::new(SimilarDataCorrelatorFactory), Box::new(FunctionReferenceCorrelatorFactory),
        Box::new(DataReferenceCorrelatorFactory), Box::new(CombinedReferenceCorrelatorFactory),
        Box::new(DuplicateFunctionCorrelatorFactory), Box::new(DuplicateSymbolNameCorrelatorFactory),
        Box::new(DuplicateDataCorrelatorFactory), Box::new(ManualMatchCorrelatorFactory),
        Box::new(ImpliedMatchCorrelatorFactory),
    ];
    factories.sort_by_key(|f| f.priority());
    factories
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correlator_factory_names() {
        assert_eq!(ExactMatchBytesCorrelatorFactory::NAME, "Exact Function Bytes Match");
        assert_eq!(ExactMatchInstructionsCorrelatorFactory::NAME, "Exact Function Instructions Match");
        assert_eq!(ExactMatchMnemonicsCorrelatorFactory::NAME, "Exact Function Mnemonics Match");
        assert_eq!(SymbolNameCorrelatorFactory::NAME, "Symbol Name Match");
    }

    #[test]
    fn test_correlator_factory_priorities() {
        assert!(SymbolNameCorrelatorFactory.priority() < ExactMatchBytesCorrelatorFactory.priority());
        assert!(ExactMatchBytesCorrelatorFactory.priority() < ExactMatchInstructionsCorrelatorFactory.priority());
    }

    #[test]
    fn test_default_options() {
        let opts = ExactMatchBytesCorrelatorFactory.create_default_options();
        assert_eq!(opts.get_int(ExactMatchBytesCorrelatorFactory::FUNCTION_MINIMUM_SIZE, 0), ExactMatchBytesCorrelatorFactory::FUNCTION_MINIMUM_SIZE_DEFAULT);
    }

    #[test]
    fn test_all_factories() {
        let factories = all_correlator_factories();
        assert_eq!(factories.len(), 15);
        for i in 1..factories.len() { assert!(factories[i - 1].priority() <= factories[i].priority()); }
    }

    #[test]
    fn test_factory_descriptions() {
        for f in &all_correlator_factories() {
            assert!(!f.description().is_empty());
            assert!(!f.name().is_empty());
        }
    }
}
