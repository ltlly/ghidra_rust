//! Frida platform opinion.
//!
//! Ported from Ghidra's `FridaDebuggerPlatformOpinion`.
//! Maps Frida debugger metadata to Ghidra language/compiler-spec pairs.
//! Frida typically targets mobile and desktop platforms with x86, x86_64,
//! ARM, and AArch64 architectures.

use crate::services::platform_impl::{Endian, LanguageCompilerSpecId, PlatformOffer};
use super::PlatformOpinionProvider;

/// Frida platform opinion implementation.
#[derive(Debug, Clone, Default)]
pub struct FridaPlatformOpinion;

static FRIDA_MAPPINGS: &[(&str, &str, &str, f64)] = &[
    // (arch, lang_id, cspec_id, confidence)
    ("aarch64", "AARCH64:LE:64:v8A", "default", 0.85),
    ("arm64", "AARCH64:LE:64:v8A", "default", 0.85),
    ("arm", "ARM:LE:32:v8", "default", 0.8),
    ("armv7", "ARM:LE:32:v8", "default", 0.8),
    ("armv7l", "ARM:LE:32:v8", "default", 0.8),
    ("armv7s", "ARM:LE:32:v8", "default", 0.8),
    ("x86", "x86:LE:32:default", "default", 0.8),
    ("i686", "x86:LE:32:default", "default", 0.8),
    ("x86_64", "x86:LE:64:default", "default", 0.85),
    ("amd64", "x86:LE:64:default", "default", 0.85),
    ("mips", "MIPS:BE:32:default", "default", 0.7),
    ("mipsel", "MIPS:LE:32:default", "default", 0.7),
];

impl FridaPlatformOpinion {
    /// Create a new Frida platform opinion.
    pub fn new() -> Self {
        Self
    }
}

impl PlatformOpinionProvider for FridaPlatformOpinion {
    fn name(&self) -> &str {
        "Frida"
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
            Some(dbg) if dbg.to_lowercase() == "frida" => {}
            _ => return Vec::new(),
        }

        let arch_lower = arch.to_lowercase();
        FRIDA_MAPPINGS
            .iter()
            .filter(|(a, _, _, _)| *a == arch_lower)
            .map(|(_, lang_id, cspec_id, confidence)| {
                let reason = format!("Frida: {} architecture", arch);
                PlatformOffer::new(
                    LanguageCompilerSpecId::new(*lang_id, *cspec_id),
                    *confidence,
                    reason,
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frida_name() {
        assert_eq!(FridaPlatformOpinion::new().name(), "Frida");
    }

    #[test]
    fn test_frida_ignores_non_frida() {
        let opinion = FridaPlatformOpinion::new();
        assert!(opinion.get_offers(Some("gdb"), "aarch64", "Linux", Some(Endian::Little), false).is_empty());
    }

    #[test]
    fn test_frida_aarch64() {
        let opinion = FridaPlatformOpinion::new();
        let offers = opinion.get_offers(Some("frida"), "aarch64", "Android", Some(Endian::Little), false);
        assert!(!offers.is_empty());
        assert_eq!(offers[0].lcsp.language_id, "AARCH64:LE:64:v8A");
    }

    #[test]
    fn test_frida_x86_64() {
        let opinion = FridaPlatformOpinion::new();
        let offers = opinion.get_offers(Some("frida"), "x86_64", "Linux", Some(Endian::Little), false);
        assert!(!offers.is_empty());
        assert_eq!(offers[0].lcsp.language_id, "x86:LE:64:default");
    }

    #[test]
    fn test_frida_arm() {
        let opinion = FridaPlatformOpinion::new();
        let offers = opinion.get_offers(Some("Frida"), "arm", "Android", Some(Endian::Little), false);
        assert!(!offers.is_empty());
        assert_eq!(offers[0].lcsp.language_id, "ARM:LE:32:v8");
    }
}
