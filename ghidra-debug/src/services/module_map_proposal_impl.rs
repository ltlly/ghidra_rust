//! Module map proposal implementation.
//!
//! Ported from Ghidra's `DefaultModuleMapProposal`.
pub use super::mapping_proposals_impl::ModuleMapProposal;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_re_export() {
        let p = ModuleMapProposal::new("libc", "libc");
        assert_eq!(p.module_name, "libc");
    }
}
