//! Frida platform opinion implementation.
//!
//! Ported from Ghidra's `FridaDebuggerPlatformOpinion`. Maps Frida
//! architecture information to Ghidra language and compiler specifications.

use super::platform_opinion::{OpinionContext, PlatformOpinion, PlatformOpinionProvider};

/// The Frida tool identifier.
pub const FRIDA_TOOL: &str = "frida";

/// Frida platform opinion provider.
///
/// Examines the Frida target process to suggest appropriate Ghidra platform.
/// Frida typically injects into running processes, so the architecture
/// is determined from the host process.
#[derive(Debug, Clone)]
pub struct FridaPlatformOpinion;

impl PlatformOpinionProvider for FridaPlatformOpinion {
    fn name(&self) -> &str {
        "Frida"
    }

    fn debugger_types(&self) -> &[&str] {
        &["frida"]
    }

    fn get_opinions(&self, context: &OpinionContext) -> Vec<PlatformOpinion> {
        if context.debugger_type != "frida" {
            return Vec::new();
        }

        let endian = if context.big_endian { "BE" } else { "LE" };
        let arch = context.architecture.to_lowercase();

        let mut opinions = Vec::new();

        // Frida commonly targets mobile and desktop platforms
        if arch.contains("x86_64") || arch.contains("amd64") {
            opinions.push(PlatformOpinion::new(
                "frida",
                &format!("x86:{}:64:default", endian),
                "gcc",
                "x86-64",
                0.8,
            ));
        } else if arch.contains("i386") || arch.contains("i686") || arch == "x86" {
            opinions.push(PlatformOpinion::new(
                "frida",
                &format!("x86:{}:32:default", endian),
                "gcc",
                "x86",
                0.8,
            ));
        } else if arch.contains("aarch64") || arch.contains("arm64") {
            opinions.push(PlatformOpinion::new(
                "frida",
                &format!("AARCH64:{}:64:v8A", endian),
                "gcc",
                "AARCH64",
                0.8,
            ));
        } else if arch.contains("arm") {
            opinions.push(PlatformOpinion::new(
                "frida",
                &format!("ARM:{}:32:v7", endian),
                "gcc",
                "ARM",
                0.8,
            ));
        }

        opinions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frida_opinion_aarch64() {
        let provider = FridaPlatformOpinion;
        let context = OpinionContext::new()
            .with_debugger_type("frida")
            .with_architecture("arm64")
            .with_os("linux")
            .with_big_endian(false);

        let opinions = provider.get_opinions(&context);
        assert_eq!(opinions.len(), 1);
        assert!(opinions[0].language_id.contains("AARCH64"));
    }

    #[test]
    fn test_frida_opinion_arm() {
        let provider = FridaPlatformOpinion;
        let context = OpinionContext::new()
            .with_debugger_type("frida")
            .with_architecture("arm")
            .with_os("linux")
            .with_big_endian(false);

        let opinions = provider.get_opinions(&context);
        assert_eq!(opinions.len(), 1);
        assert!(opinions[0].language_id.contains("ARM"));
    }

    #[test]
    fn test_frida_opinion_wrong_debugger() {
        let provider = FridaPlatformOpinion;
        let context = OpinionContext::new()
            .with_debugger_type("gdb")
            .with_architecture("arm64")
            .with_os("linux");

        let opinions = provider.get_opinions(&context);
        assert!(opinions.is_empty());
    }

    #[test]
    fn test_frida_opinion_x86_64() {
        let provider = FridaPlatformOpinion;
        let context = OpinionContext::new()
            .with_debugger_type("frida")
            .with_architecture("x86_64")
            .with_os("windows")
            .with_big_endian(false);

        let opinions = provider.get_opinions(&context);
        assert_eq!(opinions.len(), 1);
        assert!(opinions[0].language_id.contains("x86"));
        assert!(opinions[0].language_id.contains(":64:"));
    }

    #[test]
    fn test_frida_opinion_unknown() {
        let provider = FridaPlatformOpinion;
        let context = OpinionContext::new()
            .with_debugger_type("frida")
            .with_architecture("mips")
            .with_os("linux");

        let opinions = provider.get_opinions(&context);
        assert!(opinions.is_empty());
    }
}
