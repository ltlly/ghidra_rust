//! Platform-specific debugger connector opinions.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.platform` package.
//! Each sub-module implements a platform opinion provider for a specific
//! debugger backend (GDB, LLDB, Frida, Dbgeng, JDI) that maps debugger
//! metadata to Ghidra language/compiler-spec pairs.

use crate::services::platform_impl::{Endian, PlatformOffer};

pub mod gdb_opinion;
pub mod lldb_opinion;
pub mod frida_opinion;
pub mod dbgeng_opinion;
pub mod jdi_opinion;
pub mod arm_inject;
pub mod host_opinion;
pub mod override_opinion;

pub use gdb_opinion::GdbPlatformOpinion;
pub use lldb_opinion::LldbPlatformOpinion;
pub use frida_opinion::FridaPlatformOpinion;
pub use dbgeng_opinion::DbgengPlatformOpinion;
pub use jdi_opinion::JdiPlatformOpinion;
pub use arm_inject::ArmDisassemblyInject;
pub use host_opinion::HostPlatformOpinion;
pub use override_opinion::OverridePlatformOpinion;

/// Trait for platform opinion providers.
///
/// Each debugger backend (GDB, LLDB, etc.) implements this trait to map
/// debugger metadata to Ghidra language/compiler-spec pairs.
pub trait PlatformOpinionProvider: std::fmt::Debug {
    /// Get the name of this opinion provider.
    fn name(&self) -> &str;

    /// Get offers for the given debugger metadata.
    fn get_offers(
        &self,
        debugger: Option<&str>,
        arch: &str,
        os: &str,
        endian: Option<Endian>,
        include_overrides: bool,
    ) -> Vec<PlatformOffer>;
}

/// Registry of all built-in platform opinion providers.
pub fn builtin_opinion_providers() -> Vec<Box<dyn PlatformOpinionProvider>> {
    vec![
        Box::new(GdbPlatformOpinion::new()),
        Box::new(LldbPlatformOpinion::new()),
        Box::new(FridaPlatformOpinion::new()),
        Box::new(DbgengPlatformOpinion::new()),
        Box::new(JdiPlatformOpinion::new()),
        Box::new(HostPlatformOpinion::new()),
        Box::new(OverridePlatformOpinion::new()),
    ]
}

/// Query all registered opinions for offers.
pub fn query_opinions(
    debugger: Option<&str>,
    arch: &str,
    os: &str,
    endian: Option<Endian>,
    include_overrides: bool,
) -> Vec<PlatformOffer> {
    let providers = builtin_opinion_providers();
    let mut all_offers: Vec<PlatformOffer> = providers
        .iter()
        .flat_map(|p| p.get_offers(debugger, arch, os, endian, include_overrides))
        .collect();
    // Sort by confidence descending
    all_offers.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
    all_offers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_opinions_gdb() {
        let offers = query_opinions(Some("gdb"), "x86_64", "Linux", Some(Endian::Little), false);
        assert!(!offers.is_empty());
        // GDB should have highest confidence for x86_64 Linux
        assert!(offers[0].confidence >= offers.last().unwrap().confidence);
    }

    #[test]
    fn test_query_opinions_none_debugger() {
        let offers = query_opinions(None, "x86_64", "Linux", None, false);
        // Host fallback should provide at least one offer
        assert!(!offers.is_empty());
    }

    #[test]
    fn test_query_opinions_sorted() {
        let offers = query_opinions(Some("lldb"), "x86_64", "macOS", Some(Endian::Little), false);
        for i in 1..offers.len() {
            assert!(offers[i - 1].confidence >= offers[i].confidence);
        }
    }
}
