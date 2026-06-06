//! DbgEng (Windows Debugger Engine) platform opinion.
//!
//! Ported from Ghidra's `DbgengDebuggerPlatformOpinion`.
//! Maps Windows debugger metadata to Ghidra language/compiler-spec pairs.
//! Supports x86, x86_64, and x86_64-32 (WoW64) targets.

use crate::services::platform_impl::{Endian, LanguageCompilerSpecId, PlatformOffer};
use super::PlatformOpinionProvider;

/// Windows x86_64 language ID.
pub const LANG_ID_X86_64: &str = "x86:LE:64:default";
/// Windows x86_64-32 (WoW64) language ID.
pub const LANG_ID_X86_64_32: &str = "x86:LE:64:compat32";
/// Windows x86 language ID.
pub const LANG_ID_X86: &str = "x86:LE:32:default";
/// Windows compiler spec ID.
pub const COMP_ID_WINDOWS: &str = "windows";

/// DbgEng platform opinion implementation.
///
/// Examines the trace environment's debugger field and, if it matches "dbgeng"
/// or "gdb" on Windows, maps architecture to appropriate Ghidra language IDs.
#[derive(Debug, Clone, Default)]
pub struct DbgengPlatformOpinion;

impl DbgengPlatformOpinion {
    /// Create a new DbgEng platform opinion.
    pub fn new() -> Self {
        Self
    }

    /// Detect WoW64 by examining the address size of the trace.
    pub fn is_wow64(arch: &str, os: &str) -> bool {
        arch.to_lowercase().contains("x86_64") && os.to_lowercase().contains("windows")
    }
}

impl PlatformOpinionProvider for DbgengPlatformOpinion {
    fn name(&self) -> &str {
        "DbgEng"
    }

    fn get_offers(
        &self,
        debugger: Option<&str>,
        arch: &str,
        os: &str,
        _endian: Option<Endian>,
        _include_overrides: bool,
    ) -> Vec<PlatformOffer> {
        let dbg = match debugger {
            Some(d) => d.to_lowercase(),
            None => return Vec::new(),
        };

        if dbg != "dbgeng" && dbg != "gdb" {
            return Vec::new();
        }

        let arch_lower = arch.to_lowercase();
        let os_lower = os.to_lowercase();

        let mut offers = Vec::new();

        if arch_lower == "x86_64" || arch_lower == "amd64" {
            offers.push(PlatformOffer::new(
                LanguageCompilerSpecId::new(LANG_ID_X86_64, COMP_ID_WINDOWS),
                0.95,
                format!("DbgEng: {} on Windows x86_64", arch),
            ));
            // Also offer WoW64 compat mode
            if os_lower.contains("windows") {
                offers.push(PlatformOffer::new(
                    LanguageCompilerSpecId::new(LANG_ID_X86_64_32, COMP_ID_WINDOWS),
                    0.5,
                    "DbgEng: WoW64 compat32 mode".to_string(),
                ));
            }
        } else if arch_lower == "x86" || arch_lower == "i386" || arch_lower == "i686" {
            offers.push(PlatformOffer::new(
                LanguageCompilerSpecId::new(LANG_ID_X86, COMP_ID_WINDOWS),
                0.9,
                format!("DbgEng: {} on Windows x86", arch),
            ));
        } else if arch_lower == "aarch64" || arch_lower == "arm64" {
            offers.push(PlatformOffer::new(
                LanguageCompilerSpecId::new("AARCH64:LE:64:v8A", "windows"),
                0.85,
                format!("DbgEng: {} on Windows AArch64", arch),
            ));
        }

        offers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dbgeng_name() {
        assert_eq!(DbgengPlatformOpinion::new().name(), "DbgEng");
    }

    #[test]
    fn test_dbgeng_ignores_non_dbgeng() {
        let opinion = DbgengPlatformOpinion::new();
        assert!(opinion.get_offers(Some("lldb"), "x86_64", "Windows", None, false).is_empty());
    }

    #[test]
    fn test_dbgeng_x86_64_windows() {
        let opinion = DbgengPlatformOpinion::new();
        let offers = opinion.get_offers(Some("dbgeng"), "x86_64", "Windows", Some(Endian::Little), false);
        assert!(!offers.is_empty());
        assert_eq!(offers[0].lcsp.language_id, LANG_ID_X86_64);
        // Should also have WoW64 offer
        assert!(offers.len() >= 2);
    }

    #[test]
    fn test_dbgeng_x86_windows() {
        let opinion = DbgengPlatformOpinion::new();
        let offers = opinion.get_offers(Some("dbgeng"), "x86", "Windows", Some(Endian::Little), false);
        assert!(!offers.is_empty());
        assert_eq!(offers[0].lcsp.language_id, LANG_ID_X86);
    }

    #[test]
    fn test_dbgeng_none_debugger() {
        let opinion = DbgengPlatformOpinion::new();
        assert!(opinion.get_offers(None, "x86_64", "Windows", None, false).is_empty());
    }

    #[test]
    fn test_wow64_detection() {
        assert!(DbgengPlatformOpinion::is_wow64("x86_64", "Windows"));
        assert!(!DbgengPlatformOpinion::is_wow64("x86", "Windows"));
    }
}
