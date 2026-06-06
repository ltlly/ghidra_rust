//! Host platform opinion.
//!
//! Ported from Ghidra's `HostDebuggerPlatformOpinion`.
//! Provides platform offers based on the host system's architecture and
//! operating system. Used as a fallback when no debugger-specific opinion
//! matches.

use crate::services::platform_impl::{Endian, LanguageCompilerSpecId, PlatformOffer};
use super::PlatformOpinionProvider;

/// Confidence for host-known platform mapping.
pub const CONFIDENCE_HOST_KNOWN: f64 = 0.5;

/// Host platform opinion implementation.
///
/// Detects the host platform and returns a single low-confidence offer
/// based on the detected architecture and OS.
#[derive(Debug, Clone, Default)]
pub struct HostPlatformOpinion;

impl HostPlatformOpinion {
    /// Create a new host platform opinion.
    pub fn new() -> Self {
        Self
    }

    /// Detect the host platform architecture.
    pub fn host_arch() -> &'static str {
        if cfg!(target_arch = "x86_64") {
            "x86_64"
        } else if cfg!(target_arch = "x86") {
            "x86"
        } else if cfg!(target_arch = "aarch64") {
            "aarch64"
        } else if cfg!(target_arch = "arm") {
            "arm"
        } else {
            "unknown"
        }
    }

    /// Detect the host operating system.
    pub fn host_os() -> &'static str {
        if cfg!(target_os = "linux") {
            "Linux"
        } else if cfg!(target_os = "macos") {
            "macOS"
        } else if cfg!(target_os = "windows") {
            "Windows"
        } else {
            "Unknown"
        }
    }
}

impl PlatformOpinionProvider for HostPlatformOpinion {
    fn name(&self) -> &str {
        "Host"
    }

    fn get_offers(
        &self,
        debugger: Option<&str>,
        _arch: &str,
        _os: &str,
        _endian: Option<Endian>,
        _include_overrides: bool,
    ) -> Vec<PlatformOffer> {
        // Only provide as a fallback when no debugger is specified
        if debugger.is_some() {
            return Vec::new();
        }

        let host_arch = Self::host_arch();
        let host_os = Self::host_os();

        let (lang_id, cspec_id) = match (host_arch, host_os) {
            ("x86_64", "Windows") => ("x86:LE:64:default", "windows"),
            ("x86_64", _) => ("x86:LE:64:default", "gcc"),
            ("x86", "Windows") => ("x86:LE:32:default", "windows"),
            ("x86", _) => ("x86:LE:32:default", "gcc"),
            ("aarch64", _) => ("AARCH64:LE:64:v8A", "default"),
            ("arm", _) => ("ARM:LE:32:v8", "default"),
            _ => return Vec::new(),
        };

        vec![PlatformOffer::new(
            LanguageCompilerSpecId::new(lang_id, cspec_id),
            CONFIDENCE_HOST_KNOWN,
            format!("Host platform: {} on {}", host_arch, host_os),
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_name() {
        assert_eq!(HostPlatformOpinion::new().name(), "Host");
    }

    #[test]
    fn test_host_ignores_when_debugger_specified() {
        let opinion = HostPlatformOpinion::new();
        assert!(opinion.get_offers(Some("gdb"), "x86_64", "Linux", None, false).is_empty());
    }

    #[test]
    fn test_host_provides_fallback() {
        let opinion = HostPlatformOpinion::new();
        let offers = opinion.get_offers(None, "", "", None, false);
        // Should produce at least one offer based on current host
        assert!(!offers.is_empty());
        assert!(offers[0].confidence <= 0.6);
    }
}
