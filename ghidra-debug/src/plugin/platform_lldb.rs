//! LLDB platform opinion implementation.
//!
//! Ported from Ghidra's `LldbDebuggerPlatformOpinion`. Maps LLDB architecture
//! and OS information to Ghidra language and compiler specifications.

use super::platform_opinion::{OpinionContext, PlatformOpinion, PlatformOpinionProvider};

/// The LLDB tool identifier.
pub const LLDB_TOOL: &str = "llvm";

/// LLDB platform opinion provider.
///
/// Examines the target process to suggest appropriate Ghidra platform.
#[derive(Debug, Clone)]
pub struct LldbPlatformOpinion;

impl PlatformOpinionProvider for LldbPlatformOpinion {
    fn name(&self) -> &str {
        "LLDB"
    }

    fn debugger_types(&self) -> &[&str] {
        &["lldb", "lldb-server", "lldb-remote"]
    }

    fn get_opinions(&self, context: &OpinionContext) -> Vec<PlatformOpinion> {
        if context.debugger_type != "lldb"
            && context.debugger_type != "lldb-server"
            && context.debugger_type != "lldb-remote"
        {
            return Vec::new();
        }

        let endian = if context.big_endian { "BE" } else { "LE" };
        let arch = context.architecture.to_lowercase();
        let os = context.os.to_lowercase();
        let cspec = compute_lldb_preferred_spec_id(&os);

        let mut opinions = Vec::new();

        if arch.contains("x86_64") || arch.contains("amd64") {
            opinions.push(PlatformOpinion::new(
                "lldb",
                &format!("x86:{}:64:default", endian),
                cspec,
                "x86-64",
                0.85,
            ));
        } else if arch.contains("i386") || arch.contains("i686") || arch == "x86" {
            opinions.push(PlatformOpinion::new(
                "lldb",
                &format!("x86:{}:32:default", endian),
                cspec,
                "x86",
                0.85,
            ));
        } else if arch.contains("aarch64") || arch.contains("arm64") {
            opinions.push(PlatformOpinion::new(
                "lldb",
                &format!("AARCH64:{}:64:v8A", endian),
                cspec,
                "AARCH64",
                0.85,
            ));
        } else if arch.contains("arm") || arch.starts_with("armv") {
            let variant = if arch.contains("v7") || arch.contains("v7l") {
                "v7"
            } else if arch.contains("v6") {
                "v6"
            } else {
                "v8"
            };
            opinions.push(PlatformOpinion::new(
                "lldb",
                &format!("ARM:{}:32:{}", endian, variant),
                cspec,
                "ARM",
                0.85,
            ));
        } else if arch.contains("mips64") {
            opinions.push(PlatformOpinion::new(
                "lldb",
                &format!("MIPS:{}:64:64-{}", endian, endian.to_lowercase()),
                cspec,
                "MIPS",
                0.85,
            ));
        } else if arch.contains("mips") {
            opinions.push(PlatformOpinion::new(
                "lldb",
                &format!("MIPS:{}:32:default", endian),
                cspec,
                "MIPS",
                0.85,
            ));
        } else if arch.contains("powerpc64") || arch.contains("ppc64") {
            opinions.push(PlatformOpinion::new(
                "lldb",
                &format!("PowerPC:{}:64:default", endian),
                cspec,
                "PowerPC",
                0.85,
            ));
        } else if arch.contains("powerpc") || arch.contains("ppc") {
            opinions.push(PlatformOpinion::new(
                "lldb",
                &format!("PowerPC:{}:32:default", endian),
                cspec,
                "PowerPC",
                0.85,
            ));
        } else if arch.contains("riscv64") {
            opinions.push(PlatformOpinion::new(
                "lldb",
                &format!("RISCV:{}:64:default", endian),
                cspec,
                "RISC-V",
                0.85,
            ));
        } else if arch.contains("riscv") {
            opinions.push(PlatformOpinion::new(
                "lldb",
                &format!("RISCV:{}:32:default", endian),
                cspec,
                "RISC-V",
                0.85,
            ));
        } else if arch.contains("sparc64") {
            opinions.push(PlatformOpinion::new(
                "lldb",
                &format!("SPARC:{}:64:default", endian),
                cspec,
                "SPARC",
                0.85,
            ));
        } else if arch.contains("sparc") {
            opinions.push(PlatformOpinion::new(
                "lldb",
                &format!("SPARC:{}:32:default", endian),
                cspec,
                "SPARC",
                0.85,
            ));
        }

        opinions
    }
}

/// Compute the preferred compiler spec ID for LLDB targets.
fn compute_lldb_preferred_spec_id(os: &str) -> &'static str {
    let lower = os.to_lowercase();
    if lower.contains("windows") {
        "windows"
    } else if lower.contains("macos") || lower.contains("darwin") {
        // LLDB on macOS typically uses clang conventions
        "clang"
    } else {
        // Default to GCC
        "gcc"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lldb_opinion_x86_64_linux() {
        let provider = LldbPlatformOpinion;
        let context = OpinionContext::new()
            .with_debugger_type("lldb")
            .with_architecture("x86_64")
            .with_os("linux-gnu")
            .with_big_endian(false);

        let opinions = provider.get_opinions(&context);
        assert_eq!(opinions.len(), 1);
        assert_eq!(opinions[0].language_id, "x86:LE:64:default");
        assert_eq!(opinions[0].compiler_spec_id, "gcc");
    }

    #[test]
    fn test_lldb_opinion_arm64_macos() {
        let provider = LldbPlatformOpinion;
        let context = OpinionContext::new()
            .with_debugger_type("lldb")
            .with_architecture("arm64")
            .with_os("macos")
            .with_big_endian(false);

        let opinions = provider.get_opinions(&context);
        assert_eq!(opinions.len(), 1);
        assert!(opinions[0].language_id.contains("AARCH64"));
        assert_eq!(opinions[0].compiler_spec_id, "clang");
    }

    #[test]
    fn test_lldb_opinion_wrong_debugger() {
        let provider = LldbPlatformOpinion;
        let context = OpinionContext::new()
            .with_debugger_type("gdb")
            .with_architecture("x86_64")
            .with_os("linux-gnu");

        let opinions = provider.get_opinions(&context);
        assert!(opinions.is_empty());
    }

    #[test]
    fn test_lldb_opinion_arm() {
        let provider = LldbPlatformOpinion;
        let context = OpinionContext::new()
            .with_debugger_type("lldb")
            .with_architecture("armv8")
            .with_os("linux-gnu")
            .with_big_endian(false);

        let opinions = provider.get_opinions(&context);
        assert_eq!(opinions.len(), 1);
        assert!(opinions[0].language_id.contains("ARM"));
    }

    #[test]
    fn test_lldb_opinion_i386() {
        let provider = LldbPlatformOpinion;
        let context = OpinionContext::new()
            .with_debugger_type("lldb-server")
            .with_architecture("i386")
            .with_os("linux-gnu")
            .with_big_endian(false);

        let opinions = provider.get_opinions(&context);
        assert_eq!(opinions.len(), 1);
        assert!(opinions[0].language_id.contains("x86"));
        assert!(opinions[0].language_id.contains(":32:"));
    }
}
