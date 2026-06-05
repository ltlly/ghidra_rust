//! Region map proposal implementation.
//!
//! Ported from Ghidra's `DefaultRegionMapProposal`.
pub use super::mapping_proposals_impl::RegionMapProposal;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_re_export() {
        let p = RegionMapProposal::new("test");
        assert_eq!(p.region_name, "test");
    }
}
