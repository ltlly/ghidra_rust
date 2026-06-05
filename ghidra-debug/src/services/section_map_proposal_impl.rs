//! Section map proposal implementation.
//!
//! Ported from Ghidra's `DefaultSectionMapProposal`.
pub use super::mapping_proposals_impl::SectionMapProposal;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_re_export() {
        let p = SectionMapProposal::new(".text");
        assert_eq!(p.section_name, ".text");
    }
}
