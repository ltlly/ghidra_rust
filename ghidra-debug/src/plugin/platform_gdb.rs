//! GDB platform opinion implementation.
//!
//! Ported from Ghidra's `GdbDebuggerPlatformOpinion`. Maps GDB architecture
//! and OS information to Ghidra language and compiler specifications.


use super::platform_opinion::{OpinionContext, PlatformOpinion, PlatformOpinionProvider};

/// The GDB tool identifier.
pub const GDB_TOOL: &str = "gnu";

/// The default GCC compiler spec ID.
pub const GCC_CSPEC_ID: &str = "gcc";

/// The Windows compiler spec ID.
pub const WINDOWS_CSPEC_ID: &str = "windows";

/// GDB platform opinion provider.
///
/// Examines the target process to suggest appropriate Ghidra platform.
#[derive(Debug, Clone)]
pub struct GdbPlatformOpinion;

impl PlatformOpinionProvider for GdbPlatformOpinion {
    fn name(&self) -> &str {
        "GDB"
    }

    fn debugger_types(&self) -> &[&str] {
        &["gdb", "gdbserver", "gdb-remote"]
    }

    fn get_opinions(&self, context: &OpinionContext) -> Vec<PlatformOpinion> {
        if context.debugger_type != "gdb"
            && context.debugger_type != "gdbserver"
            && context.debugger_type != "gdb-remote"
        {
            return Vec::new();
        }

        let endian = if context.big_endian { "BE" } else { "LE" };
        let arch = context.architecture.to_lowercase();
        let os = context.os.to_lowercase();
        let cspec = compute_preferred_spec_id(&os);

        let mut opinions = Vec::new();

        // Match architecture to language ID
        if arch.contains("x86_64") || arch.contains("amd64") {
            opinions.push(PlatformOpinion::new(
                "gdb",
                &format!("x86:{}:64:default", endian),
                cspec,
                "x86-64",
                0.9,
            ));
        } else if arch.contains("i386") || arch.contains("i686") || arch == "x86" {
            opinions.push(PlatformOpinion::new(
                "gdb",
                &format!("x86:{}:32:default", endian),
                cspec,
                "x86",
                0.9,
            ));
        } else if arch.contains("aarch64") || arch.contains("arm64") {
            opinions.push(PlatformOpinion::new(
                "gdb",
                &format!("AARCH64:{}:64:v8A", endian),
                cspec,
                "AARCH64",
                0.9,
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
                "gdb",
                &format!("ARM:{}:32:{}", endian, variant),
                cspec,
                "ARM",
                0.9,
            ));
        } else if arch.contains("mips64") {
            opinions.push(PlatformOpinion::new(
                "gdb",
                &format!("MIPS:{}:64:64-{}", endian, endian.to_lowercase()),
                cspec,
                "MIPS",
                0.9,
            ));
        } else if arch.contains("mips") {
            opinions.push(PlatformOpinion::new(
                "gdb",
                &format!("MIPS:{}:32:default", endian),
                cspec,
                "MIPS",
                0.9,
            ));
        } else if arch.contains("powerpc64") || arch.contains("ppc64") {
            opinions.push(PlatformOpinion::new(
                "gdb",
                &format!("PowerPC:{}:64:default", endian),
                cspec,
                "PowerPC",
                0.9,
            ));
        } else if arch.contains("powerpc") || arch.contains("ppc") {
            opinions.push(PlatformOpinion::new(
                "gdb",
                &format!("PowerPC:{}:32:default", endian),
                cspec,
                "PowerPC",
                0.9,
            ));
        } else if arch.contains("riscv64") {
            opinions.push(PlatformOpinion::new(
                "gdb",
                &format!("RISCV:{}:64:default", endian),
                cspec,
                "RISC-V",
                0.9,
            ));
        } else if arch.contains("riscv") {
            opinions.push(PlatformOpinion::new(
                "gdb",
                &format!("RISCV:{}:32:default", endian),
                cspec,
                "RISC-V",
                0.9,
            ));
        } else if arch.contains("sparc64") {
            opinions.push(PlatformOpinion::new(
                "gdb",
                &format!("SPARC:{}:64:default", endian),
                cspec,
                "SPARC",
                0.9,
            ));
        } else if arch.contains("sparc") {
            opinions.push(PlatformOpinion::new(
                "gdb",
                &format!("SPARC:{}:32:default", endian),
                cspec,
                "SPARC",
                0.9,
            ));
        }

        opinions
    }
}

/// Compute the preferred compiler spec ID based on the target OS.
pub fn compute_preferred_spec_id(os: &str) -> &'static str {
    let lower = os.to_lowercase();
    if lower.contains("windows") {
        WINDOWS_CSPEC_ID
    } else {
        // Default to GCC (covers Linux, macOS, etc.)
        GCC_CSPEC_ID
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gdb_opinion_x86_64_linux() {
        let provider = GdbPlatformOpinion;
        let context = OpinionContext::new()
            .with_debugger_type("gdb")
            .with_architecture("x86_64")
            .with_os("linux-gnu")
            .with_big_endian(false);

        let opinions = provider.get_opinions(&context);
        assert_eq!(opinions.len(), 1);
        assert_eq!(opinions[0].language_id, "x86:LE:64:default");
        assert_eq!(opinions[0].compiler_spec_id, "gcc");
    }

    #[test]
    fn test_gdb_opinion_arm() {
        let provider = GdbPlatformOpinion;
        let context = OpinionContext::new()
            .with_debugger_type("gdb")
            .with_architecture("armv7l")
            .with_os("linux-gnueabihf")
            .with_big_endian(false);

        let opinions = provider.get_opinions(&context);
        assert_eq!(opinions.len(), 1);
        assert!(opinions[0].language_id.contains("ARM"));
        assert!(opinions[0].language_id.contains("v7"));
    }

    #[test]
    fn test_gdb_opinion_aarch64() {
        let provider = GdbPlatformOpinion;
        let context = OpinionContext::new()
            .with_debugger_type("gdb")
            .with_architecture("aarch64")
            .with_os("linux-gnu")
            .with_big_endian(false);

        let opinions = provider.get_opinions(&context);
        assert_eq!(opinions.len(), 1);
        assert!(opinions[0].language_id.contains("AARCH64"));
    }

    #[test]
    fn test_gdb_opinion_windows() {
        let provider = GdbPlatformOpinion;
        let context = OpinionContext::new()
            .with_debugger_type("gdb")
            .with_architecture("x86_64")
            .with_os("windows")
            .with_big_endian(false);

        let opinions = provider.get_opinions(&context);
        assert_eq!(opinions.len(), 1);
        assert_eq!(opinions[0].compiler_spec_id, "windows");
    }

    #[test]
    fn test_gdb_opinion_wrong_debugger() {
        let provider = GdbPlatformOpinion;
        let context = OpinionContext::new()
            .with_debugger_type("lldb")
            .with_architecture("x86_64")
            .with_os("linux-gnu");

        let opinions = provider.get_opinions(&context);
        assert!(opinions.is_empty());
    }

    #[test]
    fn test_gdb_opinion_unknown_arch() {
        let provider = GdbPlatformOpinion;
        let context = OpinionContext::new()
            .with_debugger_type("gdb")
            .with_architecture("unknown_arch")
            .with_os("linux-gnu");

        let opinions = provider.get_opinions(&context);
        assert!(opinions.is_empty());
    }

    #[test]
    fn test_compute_preferred_spec_id() {
        assert_eq!(compute_preferred_spec_id("windows"), WINDOWS_CSPEC_ID);
        assert_eq!(compute_preferred_spec_id("linux-gnu"), GCC_CSPEC_ID);
        assert_eq!(compute_preferred_spec_id("macos"), GCC_CSPEC_ID);
    }

    #[test]
    fn test_gdb_opinion_mips() {
        let provider = GdbPlatformOpinion;
        let context = OpinionContext::new()
            .with_debugger_type("gdb")
            .with_architecture("mips")
            .with_os("linux-gnu")
            .with_big_endian(true);

        let opinions = provider.get_opinions(&context);
        assert_eq!(opinions.len(), 1);
        assert!(opinions[0].language_id.contains("MIPS"));
        assert!(opinions[0].language_id.contains("BE"));
    }

    #[test]
    fn test_gdb_opinion_riscv() {
        let provider = GdbPlatformOpinion;
        let context = OpinionContext::new()
            .with_debugger_type("gdb")
            .with_architecture("riscv64")
            .with_os("linux-gnu")
            .with_big_endian(false);

        let opinions = provider.get_opinions(&context);
        assert_eq!(opinions.len(), 1);
        assert!(opinions[0].language_id.contains("RISCV"));
    }
}
