//! JDI (Java Debug Interface) platform opinion implementation.
//!
//! Ported from Ghidra's `JdiDebuggerPlatformOpinion`. Maps JDI (JVM)
//! architecture information to Ghidra language and compiler specifications.
//! JDI debugs Java bytecode, which runs on the JVM.

use super::platform_opinion::{OpinionContext, PlatformOpinion, PlatformOpinionProvider};

/// The JDI tool identifier.
pub const JDI_TOOL: &str = "jdi";

/// JDI platform opinion provider.
///
/// JDI targets are Java Virtual Machines. The architecture is always
/// a Java bytecode model.
#[derive(Debug, Clone)]
pub struct JdiPlatformOpinion;

impl PlatformOpinionProvider for JdiPlatformOpinion {
    fn name(&self) -> &str {
        "JDI"
    }

    fn debugger_types(&self) -> &[&str] {
        &["jdi", "jdb"]
    }

    fn get_opinions(&self, context: &OpinionContext) -> Vec<PlatformOpinion> {
        if context.debugger_type != "jdi" && context.debugger_type != "jdb" {
            return Vec::new();
        }

        let arch = context.architecture.to_lowercase();

        let mut opinions = Vec::new();

        // JDI targets are always JVM-based
        if arch.contains("jvm") || arch.contains("java") || arch.is_empty() {
            opinions.push(PlatformOpinion::new(
                "jdi",
                "JVM:BE:32:default",
                "default",
                "JVM",
                0.95,
            ));
        }

        opinions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jdi_opinion_jvm() {
        let provider = JdiPlatformOpinion;
        let context = OpinionContext::new()
            .with_debugger_type("jdi")
            .with_architecture("jvm")
            .with_os("linux");

        let opinions = provider.get_opinions(&context);
        assert_eq!(opinions.len(), 1);
        assert_eq!(opinions[0].language_id, "JVM:BE:32:default");
        assert_eq!(opinions[0].architecture, "JVM");
    }

    #[test]
    fn test_jdi_opinion_empty_arch() {
        let provider = JdiPlatformOpinion;
        let context = OpinionContext::new()
            .with_debugger_type("jdi")
            .with_architecture("")
            .with_os("windows");

        let opinions = provider.get_opinions(&context);
        assert_eq!(opinions.len(), 1);
    }

    #[test]
    fn test_jdi_opinion_wrong_debugger() {
        let provider = JdiPlatformOpinion;
        let context = OpinionContext::new()
            .with_debugger_type("gdb")
            .with_architecture("jvm")
            .with_os("linux");

        let opinions = provider.get_opinions(&context);
        assert!(opinions.is_empty());
    }

    #[test]
    fn test_jdi_opinion_jdb() {
        let provider = JdiPlatformOpinion;
        let context = OpinionContext::new()
            .with_debugger_type("jdb")
            .with_architecture("java")
            .with_os("linux");

        let opinions = provider.get_opinions(&context);
        assert_eq!(opinions.len(), 1);
    }
}
