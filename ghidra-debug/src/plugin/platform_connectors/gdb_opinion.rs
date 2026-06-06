//! GDB platform opinion.
//!
//! Ported from Ghidra's `GdbDebuggerPlatformOpinion`.
//! Maps GDB debugger metadata (arch/os/endian) to Ghidra language/compiler-spec
//! pairs. Uses the "gnu" external tool identifier and supports GCC and Windows
//! compiler specs.

use crate::services::platform_impl::{Endian, LanguageCompilerSpecId, PlatformOffer};
use super::PlatformOpinionProvider;

/// The external tool name for GDB-based debuggers.
pub const EXTERNAL_TOOL: &str = "gnu";

/// GCC compiler spec identifier.
pub const GCC_CSPEC_ID: &str = "gcc";
/// Windows compiler spec identifier.
pub const WINDOWS_CSPEC_ID: &str = "windows";

/// Architecture-to-language-id mapping for GNU toolchains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchLangMapping {
    /// Architecture identifier (e.g., "x86", "x86_64", "AARCH64").
    pub arch: &'static str,
    /// Operating system identifier (e.g., "Linux", "Windows").
    pub os: &'static str,
    /// Target language-compiler-spec pair.
    pub lcsp: (&'static str, &'static str),
}

/// Built-in architecture-to-language mappings for GDB.
pub static GDB_ARCH_MAPPINGS: &[ArchLangMapping] = &[
    ArchLangMapping { arch: "x86", os: "default", lcsp: ("x86:LE:32:default", "gcc") },
    ArchLangMapping { arch: "x86_64", os: "default", lcsp: ("x86:LE:64:default", "gcc") },
    ArchLangMapping { arch: "i386", os: "default", lcsp: ("x86:LE:32:default", "gcc") },
    ArchLangMapping { arch: "i686", os: "default", lcsp: ("x86:LE:32:default", "gcc") },
    ArchLangMapping { arch: "amd64", os: "default", lcsp: ("x86:LE:64:default", "gcc") },
    ArchLangMapping { arch: "aarch64", os: "default", lcsp: ("AARCH64:LE:64:v8A", "default") },
    ArchLangMapping { arch: "arm", os: "default", lcsp: ("ARM:LE:32:v8", "default") },
    ArchLangMapping { arch: "armeb", os: "default", lcsp: ("ARM:BE:32:v8", "default") },
    ArchLangMapping { arch: "powerpc", os: "default", lcsp: ("PowerPC:BE:32:default", "gcc") },
    ArchLangMapping { arch: "powerpc64", os: "default", lcsp: ("PowerPC:BE:64:64-47addr", "gcc") },
    ArchLangMapping { arch: "powerpc64le", os: "default", lcsp: ("PowerPC:LE:64:64-47addr", "default") },
    ArchLangMapping { arch: "mips", os: "default", lcsp: ("MIPS:BE:32:default", "default") },
    ArchLangMapping { arch: "mipsel", os: "default", lcsp: ("MIPS:LE:32:default", "default") },
    ArchLangMapping { arch: "mips64", os: "default", lcsp: ("MIPS:BE:64:64-addr", "default") },
    ArchLangMapping { arch: "riscv64", os: "default", lcsp: ("RISCV:LE:64:default", "default") },
    ArchLangMapping { arch: "sparc", os: "default", lcsp: ("sparc:BE:32:default", "default") },
    ArchLangMapping { arch: "sparc64", os: "default", lcsp: ("sparc:BE:64:default", "default") },
];

/// GDB platform opinion implementation.
///
/// Examines the trace environment's debugger field and, if it matches "gdb",
/// maps architecture/OS/endian to appropriate Ghidra language/compiler-spec pairs.
#[derive(Debug, Clone, Default)]
pub struct GdbPlatformOpinion;

impl GdbPlatformOpinion {
    /// Create a new GDB platform opinion.
    pub fn new() -> Self {
        Self
    }

    /// Get compiler specs for GNU toolchain based on arch, os, and endian.
    pub fn get_compiler_specs_for_gnu(
        arch: &str,
        os: &str,
        endian: Option<Endian>,
    ) -> Vec<LanguageCompilerSpecId> {
        let arch_lower = arch.to_lowercase();
        GDB_ARCH_MAPPINGS
            .iter()
            .filter(|m| m.arch == arch_lower)
            .map(|m| LanguageCompilerSpecId::new(m.lcsp.0, m.lcsp.1))
            .collect()
    }

    /// Create offers for a given language and compiler spec.
    pub fn offers_for_language_and_cspec(
        arch: &str,
        endian: Option<Endian>,
        lcsp: &LanguageCompilerSpecId,
    ) -> Vec<PlatformOffer> {
        let endian_str = match endian {
            Some(Endian::Little) => "Little Endian",
            Some(Endian::Big) => "Big Endian",
            None => "Unknown Endian",
        };
        let desc = format!("GDB: {} ({})", arch, endian_str);
        let confidence = if arch.to_lowercase() == "x86_64" || arch.to_lowercase() == "aarch64" {
            0.9
        } else {
            0.8
        };
        vec![PlatformOffer::new(lcsp.clone(), confidence, desc)]
    }
}

impl PlatformOpinionProvider for GdbPlatformOpinion {
    fn name(&self) -> &str {
        "GDB"
    }

    fn get_offers(
        &self,
        debugger: Option<&str>,
        arch: &str,
        os: &str,
        endian: Option<Endian>,
        _include_overrides: bool,
    ) -> Vec<PlatformOffer> {
        match debugger {
            Some(dbg) if dbg.to_lowercase() == "gdb" => {}
            _ => return Vec::new(),
        }

        let lcsp_list = Self::get_compiler_specs_for_gnu(arch, os, endian);
        lcsp_list
            .iter()
            .flat_map(|lcsp| Self::offers_for_language_and_cspec(arch, endian, lcsp))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gdb_opinion_name() {
        let opinion = GdbPlatformOpinion::new();
        assert_eq!(opinion.name(), "GDB");
    }

    #[test]
    fn test_gdb_opinion_ignores_non_gdb() {
        let opinion = GdbPlatformOpinion::new();
        let offers = opinion.get_offers(Some("lldb"), "x86_64", "Linux", Some(Endian::Little), false);
        assert!(offers.is_empty());
    }

    #[test]
    fn test_gdb_opinion_x86_64() {
        let opinion = GdbPlatformOpinion::new();
        let offers = opinion.get_offers(Some("gdb"), "x86_64", "Linux", Some(Endian::Little), false);
        assert!(!offers.is_empty());
        assert!(offers[0].confidence > 0.0);
    }

    #[test]
    fn test_gdb_opinion_aarch64() {
        let opinion = GdbPlatformOpinion::new();
        let offers = opinion.get_offers(Some("GDB"), "aarch64", "Linux", Some(Endian::Little), false);
        assert!(!offers.is_empty());
        assert_eq!(offers[0].lcsp.language_id, "AARCH64:LE:64:v8A");
    }

    #[test]
    fn test_gdb_compiler_specs_gnu() {
        let specs = GdbPlatformOpinion::get_compiler_specs_for_gnu("x86", "Linux", Some(Endian::Little));
        assert!(!specs.is_empty());
        assert_eq!(specs[0].language_id, "x86:LE:32:default");
    }

    #[test]
    fn test_gdb_opinion_none_debugger() {
        let opinion = GdbPlatformOpinion::new();
        let offers = opinion.get_offers(None, "x86_64", "Linux", Some(Endian::Little), false);
        assert!(offers.is_empty());
    }

    #[test]
    fn test_gdb_arch_mappings_not_empty() {
        assert!(!GDB_ARCH_MAPPINGS.is_empty());
    }

    #[test]
    fn test_gdb_arm_arch() {
        let opinion = GdbPlatformOpinion::new();
        let offers = opinion.get_offers(Some("gdb"), "arm", "Linux", Some(Endian::Little), false);
        assert!(!offers.is_empty());
    }
}
