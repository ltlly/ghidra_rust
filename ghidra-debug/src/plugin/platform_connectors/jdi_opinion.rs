//! JDI (Java Debug Interface) platform opinion.
//!
//! Ported from Ghidra's `JdiDebuggerPlatformOpinion`.
//! Maps JDI (Java debugger) metadata to Ghidra language/compiler-spec pairs.
//! Java targets are typically JVM-based and use a single language ID.

use crate::services::platform_impl::{Endian, LanguageCompilerSpecId, PlatformOffer};
use super::PlatformOpinionProvider;

/// JVM language ID for Java bytecode.
pub const LANG_ID_JVM: &str = "JVM:BE:64:default";

/// JDI platform opinion implementation.
#[derive(Debug, Clone, Default)]
pub struct JdiPlatformOpinion;

impl JdiPlatformOpinion {
    /// Create a new JDI platform opinion.
    pub fn new() -> Self {
        Self
    }
}

impl PlatformOpinionProvider for JdiPlatformOpinion {
    fn name(&self) -> &str {
        "JDI"
    }

    fn get_offers(
        &self,
        debugger: Option<&str>,
        arch: &str,
        _os: &str,
        _endian: Option<Endian>,
        _include_overrides: bool,
    ) -> Vec<PlatformOffer> {
        match debugger {
            Some(dbg) if dbg.to_lowercase() == "jdi" => {}
            _ => return Vec::new(),
        }

        vec![PlatformOffer::new(
            LanguageCompilerSpecId::new(LANG_ID_JVM, "default"),
            0.9,
            format!("JDI: Java debugger ({})", arch),
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jdi_name() {
        assert_eq!(JdiPlatformOpinion::new().name(), "JDI");
    }

    #[test]
    fn test_jdi_ignores_non_jdi() {
        let opinion = JdiPlatformOpinion::new();
        assert!(opinion.get_offers(Some("gdb"), "x86_64", "Linux", Some(Endian::Little), false).is_empty());
    }

    #[test]
    fn test_jdi_offer() {
        let opinion = JdiPlatformOpinion::new();
        let offers = opinion.get_offers(Some("jdi"), "jvm", "Linux", Some(Endian::Big), false);
        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0].lcsp.language_id, LANG_ID_JVM);
    }
}
