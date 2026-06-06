//! LLDB platform opinion.
//!
//! Ported from Ghidra's `LldbDebuggerPlatformOpinion`.
//! Maps LLDB debugger metadata to Ghidra language/compiler-spec pairs.
//! Supports macOS, Linux, and iOS targets with AArch64, x86, and x86_64.

use crate::services::platform_impl::{Endian, LanguageCompilerSpecId, PlatformOffer};
use super::PlatformOpinionProvider;

/// LLDB platform opinion implementation.
#[derive(Debug, Clone, Default)]
pub struct LldbPlatformOpinion;

/// Architecture mapping for LLDB.
#[derive(Debug, Clone, PartialEq)]
pub struct LldbArchMapping {
    /// Architecture string.
    pub arch: &'static str,
    /// OS string (or "default" for any).
    pub os: &'static str,
    /// Language ID.
    pub lang_id: &'static str,
    /// Compiler spec ID.
    pub cspec_id: &'static str,
    /// Confidence when matching OS.
    pub confidence_os_match: f64,
    /// Confidence for generic match.
    pub confidence_generic: f64,
}

static LLDB_MAPPINGS: &[LldbArchMapping] = &[
    LldbArchMapping { arch: "x86_64", os: "macOS", lang_id: "x86:LE:64:default", cspec_id: "clang", confidence_os_match: 0.95, confidence_generic: 0.8 },
    LldbArchMapping { arch: "x86_64", os: "Linux", lang_id: "x86:LE:64:default", cspec_id: "gcc", confidence_os_match: 0.9, confidence_generic: 0.8 },
    LldbArchMapping { arch: "x86_64", os: "default", lang_id: "x86:LE:64:default", cspec_id: "default", confidence_os_match: 0.7, confidence_generic: 0.7 },
    LldbArchMapping { arch: "aarch64", os: "macOS", lang_id: "AARCH64:LE:64:v8A", cspec_id: "clang", confidence_os_match: 0.95, confidence_generic: 0.8 },
    LldbArchMapping { arch: "aarch64", os: "Linux", lang_id: "AARCH64:LE:64:v8A", cspec_id: "default", confidence_os_match: 0.9, confidence_generic: 0.8 },
    LldbArchMapping { arch: "aarch64", os: "default", lang_id: "AARCH64:LE:64:v8A", cspec_id: "default", confidence_os_match: 0.7, confidence_generic: 0.7 },
    LldbArchMapping { arch: "arm", os: "default", lang_id: "ARM:LE:32:v8", cspec_id: "default", confidence_os_match: 0.7, confidence_generic: 0.7 },
    LldbArchMapping { arch: "armv7", os: "default", lang_id: "ARM:LE:32:v8", cspec_id: "default", confidence_os_match: 0.7, confidence_generic: 0.7 },
    LldbArchMapping { arch: "arm64", os: "macOS", lang_id: "AARCH64:LE:64:v8A", cspec_id: "clang", confidence_os_match: 0.95, confidence_generic: 0.8 },
    LldbArchMapping { arch: "arm64", os: "default", lang_id: "AARCH64:LE:64:v8A", cspec_id: "default", confidence_os_match: 0.7, confidence_generic: 0.7 },
    LldbArchMapping { arch: "i386", os: "default", lang_id: "x86:LE:32:default", cspec_id: "clang", confidence_os_match: 0.8, confidence_generic: 0.7 },
];

impl LldbPlatformOpinion {
    /// Create a new LLDB platform opinion.
    pub fn new() -> Self {
        Self
    }
}

impl PlatformOpinionProvider for LldbPlatformOpinion {
    fn name(&self) -> &str {
        "LLDB"
    }

    fn get_offers(
        &self,
        debugger: Option<&str>,
        arch: &str,
        os: &str,
        _endian: Option<Endian>,
        _include_overrides: bool,
    ) -> Vec<PlatformOffer> {
        match debugger {
            Some(dbg) if dbg.to_lowercase() == "lldb" => {}
            _ => return Vec::new(),
        }

        let arch_lower = arch.to_lowercase();
        let os_lower = os.to_lowercase();

        LLDB_MAPPINGS
            .iter()
            .filter(|m| m.arch == arch_lower)
            .map(|m| {
                let is_os_match = m.os.to_lowercase() == os_lower;
                let confidence = if is_os_match {
                    m.confidence_os_match
                } else {
                    m.confidence_generic
                };
                let reason = format!("LLDB: {} on {} ({})", arch, os, m.lang_id);
                PlatformOffer::new(
                    LanguageCompilerSpecId::new(m.lang_id, m.cspec_id),
                    confidence,
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
    fn test_lldb_name() {
        let opinion = LldbPlatformOpinion::new();
        assert_eq!(opinion.name(), "LLDB");
    }

    #[test]
    fn test_lldb_ignores_non_lldb() {
        let opinion = LldbPlatformOpinion::new();
        let offers = opinion.get_offers(Some("gdb"), "x86_64", "Linux", Some(Endian::Little), false);
        assert!(offers.is_empty());
    }

    #[test]
    fn test_lldb_x86_64_macos() {
        let opinion = LldbPlatformOpinion::new();
        let offers = opinion.get_offers(Some("lldb"), "x86_64", "macOS", Some(Endian::Little), false);
        assert!(!offers.is_empty());
        let clang_offer = offers.iter().find(|o| o.lcsp.compiler_spec_id == "clang");
        assert!(clang_offer.is_some());
        assert!(clang_offer.unwrap().confidence > 0.9);
    }

    #[test]
    fn test_lldb_aarch64_macos() {
        let opinion = LldbPlatformOpinion::new();
        let offers = opinion.get_offers(Some("lldb"), "aarch64", "macOS", Some(Endian::Little), false);
        assert!(!offers.is_empty());
    }

    #[test]
    fn test_lldb_arm64_macos() {
        let opinion = LldbPlatformOpinion::new();
        let offers = opinion.get_offers(Some("lldb"), "arm64", "macOS", Some(Endian::Little), false);
        assert!(!offers.is_empty());
        assert_eq!(offers[0].lcsp.language_id, "AARCH64:LE:64:v8A");
    }

    #[test]
    fn test_lldb_empty_arch() {
        let opinion = LldbPlatformOpinion::new();
        let offers = opinion.get_offers(Some("lldb"), "unknown_arch", "Linux", Some(Endian::Little), false);
        assert!(offers.is_empty());
    }
}
