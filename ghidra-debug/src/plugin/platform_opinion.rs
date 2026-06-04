//! Debugger platform opinion framework.
//!
//! Ported from Ghidra's `DebuggerPlatformOpinion` and platform-specific
//! implementations (GDB, LLDB, Frida, JDI, dbgeng). These opinions
//! suggest appropriate language and compiler specifications for a given
//! debugger connection.

use std::collections::HashMap;

/// An opinion about which platform (language/compiler) to use for a debug session.
///
/// Platform opinions examine the target process and environment to suggest
/// the most appropriate Ghidra language and compiler specification.
#[derive(Debug, Clone)]
pub struct PlatformOpinion {
    /// The debugger type this opinion applies to (e.g., "gdb", "lldb").
    pub debugger_type: String,
    /// The suggested language ID.
    pub language_id: String,
    /// The suggested compiler spec ID.
    pub compiler_spec_id: String,
    /// Confidence level (0.0 - 1.0).
    pub confidence: f64,
    /// The architecture this opinion matches (e.g., "x86", "ARM").
    pub architecture: String,
}

impl PlatformOpinion {
    /// Create a new platform opinion.
    pub fn new(
        debugger_type: impl Into<String>,
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
        architecture: impl Into<String>,
        confidence: f64,
    ) -> Self {
        Self {
            debugger_type: debugger_type.into(),
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
            confidence,
            architecture: architecture.into(),
        }
    }
}

/// A platform opinion provider (extension point).
///
/// Each debugger backend provides an opinion that maps target characteristics
/// to Ghidra language/compiler specifications.
pub trait PlatformOpinionProvider: std::fmt::Debug {
    /// The name of this provider.
    fn name(&self) -> &str;

    /// The debugger types this provider handles.
    fn debugger_types(&self) -> &[&str];

    /// Compute opinions for the given context.
    fn get_opinions(&self, context: &OpinionContext) -> Vec<PlatformOpinion>;
}

/// Context information for computing platform opinions.
#[derive(Debug, Clone, Default)]
pub struct OpinionContext {
    /// The debugger type.
    pub debugger_type: String,
    /// The target architecture string.
    pub architecture: String,
    /// The target OS.
    pub os: String,
    /// The target pointer size in bytes.
    pub pointer_size: usize,
    /// Whether the target is big-endian.
    pub big_endian: bool,
    /// Additional properties from the debugger.
    pub properties: HashMap<String, String>,
}

impl OpinionContext {
    /// Create a new opinion context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the debugger type.
    pub fn with_debugger_type(mut self, t: impl Into<String>) -> Self {
        self.debugger_type = t.into();
        self
    }

    /// Set the architecture.
    pub fn with_architecture(mut self, arch: impl Into<String>) -> Self {
        self.architecture = arch.into();
        self
    }

    /// Set the OS.
    pub fn with_os(mut self, os: impl Into<String>) -> Self {
        self.os = os.into();
        self
    }

    /// Set pointer size.
    pub fn with_pointer_size(mut self, size: usize) -> Self {
        self.pointer_size = size;
        self
    }

    /// Set endianness.
    pub fn with_big_endian(mut self, big_endian: bool) -> Self {
        self.big_endian = big_endian;
        self
    }
}

/// Registry of platform opinion providers.
#[derive(Debug, Default)]
pub struct PlatformOpinionRegistry {
    providers: Vec<Box<dyn PlatformOpinionProvider>>,
}

impl PlatformOpinionRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Register a provider.
    pub fn register(&mut self, provider: Box<dyn PlatformOpinionProvider>) {
        self.providers.push(provider);
    }

    /// Get opinions for the given context.
    pub fn get_opinions(&self, context: &OpinionContext) -> Vec<PlatformOpinion> {
        self.providers
            .iter()
            .flat_map(|p| {
                if p.debugger_types().contains(&context.debugger_type.as_str())
                    || p.debugger_types().is_empty()
                {
                    p.get_opinions(context)
                } else {
                    Vec::new()
                }
            })
            .collect()
    }

    /// Get the best opinion (highest confidence).
    pub fn best_opinion(&self, context: &OpinionContext) -> Option<PlatformOpinion> {
        self.get_opinions(context)
            .into_iter()
            .max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap())
    }

    /// Number of registered providers.
    pub fn len(&self) -> usize {
        self.providers.len()
    }

    /// Whether no providers are registered.
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }
}

/// Built-in GDB platform opinion provider.
#[derive(Debug)]
pub struct GdbPlatformOpinion;

impl PlatformOpinionProvider for GdbPlatformOpinion {
    fn name(&self) -> &str {
        "GDB Platform Opinion"
    }

    fn debugger_types(&self) -> &[&str] {
        &["gdb"]
    }

    fn get_opinions(&self, context: &OpinionContext) -> Vec<PlatformOpinion> {
        let mut opinions = Vec::new();

        match context.architecture.as_str() {
            arch if arch.contains("x86-64") || arch.contains("amd64") => {
                opinions.push(PlatformOpinion::new(
                    "gdb",
                    "x86:LE:64:default",
                    "default",
                    "x86-64",
                    0.9,
                ));
            }
            arch if arch.contains("x86") || arch.contains("i386") || arch.contains("i686") => {
                opinions.push(PlatformOpinion::new(
                    "gdb",
                    "x86:LE:32:default",
                    "default",
                    "x86",
                    0.9,
                ));
            }
            arch if arch.contains("aarch64") || arch.contains("arm64") => {
                opinions.push(PlatformOpinion::new(
                    "gdb",
                    "AARCH64:LE:64:v8A",
                    "default",
                    "aarch64",
                    0.9,
                ));
            }
            arch if arch.contains("arm") => {
                opinions.push(PlatformOpinion::new(
                    "gdb",
                    "ARM:LE:32:v8",
                    "default",
                    "arm",
                    0.9,
                ));
            }
            arch if arch.contains("mips") && context.big_endian => {
                opinions.push(PlatformOpinion::new(
                    "gdb",
                    "MIPS:BE:32:default",
                    "default",
                    "mips",
                    0.9,
                ));
            }
            arch if arch.contains("mips") => {
                opinions.push(PlatformOpinion::new(
                    "gdb",
                    "MIPS:LE:32:default",
                    "default",
                    "mips",
                    0.9,
                ));
            }
            arch if arch.contains("riscv") && context.pointer_size == 8 => {
                opinions.push(PlatformOpinion::new(
                    "gdb",
                    "RISCV:LE:64:default",
                    "default",
                    "riscv64",
                    0.9,
                ));
            }
            arch if arch.contains("riscv") => {
                opinions.push(PlatformOpinion::new(
                    "gdb",
                    "RISCV:LE:32:default",
                    "default",
                    "riscv32",
                    0.9,
                ));
            }
            arch if arch.contains("powerpc") && context.big_endian => {
                opinions.push(PlatformOpinion::new(
                    "gdb",
                    "PowerPC:BE:32:default",
                    "default",
                    "powerpc",
                    0.9,
                ));
            }
            arch if arch.contains("sparc") && context.big_endian => {
                opinions.push(PlatformOpinion::new(
                    "gdb",
                    "SPARC:BE:32:default",
                    "default",
                    "sparc",
                    0.9,
                ));
            }
            _ => {
                // Default fallback for unknown architectures
                if context.pointer_size == 8 {
                    opinions.push(PlatformOpinion::new(
                        "gdb",
                        "x86:LE:64:default",
                        "default",
                        "unknown",
                        0.3,
                    ));
                }
            }
        }

        opinions
    }
}

/// Built-in LLDB platform opinion provider.
#[derive(Debug)]
pub struct LldbPlatformOpinion;

impl PlatformOpinionProvider for LldbPlatformOpinion {
    fn name(&self) -> &str {
        "LLDB Platform Opinion"
    }

    fn debugger_types(&self) -> &[&str] {
        &["lldb"]
    }

    fn get_opinions(&self, context: &OpinionContext) -> Vec<PlatformOpinion> {
        // LLDB shares the same architecture mappings as GDB
        let gdb = GdbPlatformOpinion;
        gdb.get_opinions(context)
    }
}

/// Built-in Frida platform opinion provider.
#[derive(Debug)]
pub struct FridaPlatformOpinion;

impl PlatformOpinionProvider for FridaPlatformOpinion {
    fn name(&self) -> &str {
        "Frida Platform Opinion"
    }

    fn debugger_types(&self) -> &[&str] {
        &["frida"]
    }

    fn get_opinions(&self, context: &OpinionContext) -> Vec<PlatformOpinion> {
        let gdb = GdbPlatformOpinion;
        gdb.get_opinions(context)
    }
}

/// Create a registry with all built-in providers.
pub fn create_default_registry() -> PlatformOpinionRegistry {
    let mut registry = PlatformOpinionRegistry::new();
    registry.register(Box::new(GdbPlatformOpinion));
    registry.register(Box::new(LldbPlatformOpinion));
    registry.register(Box::new(FridaPlatformOpinion));
    registry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gdb_x86_64() {
        let ctx = OpinionContext::new()
            .with_debugger_type("gdb")
            .with_architecture("x86-64")
            .with_pointer_size(8);
        let opinions = GdbPlatformOpinion.get_opinions(&ctx);
        assert!(!opinions.is_empty());
        assert_eq!(opinions[0].language_id, "x86:LE:64:default");
    }

    #[test]
    fn test_gdb_arm() {
        let ctx = OpinionContext::new()
            .with_debugger_type("gdb")
            .with_architecture("arm")
            .with_pointer_size(4);
        let opinions = GdbPlatformOpinion.get_opinions(&ctx);
        assert!(!opinions.is_empty());
        assert_eq!(opinions[0].language_id, "ARM:LE:32:v8");
    }

    #[test]
    fn test_gdb_aarch64() {
        let ctx = OpinionContext::new()
            .with_debugger_type("gdb")
            .with_architecture("aarch64")
            .with_pointer_size(8);
        let opinions = GdbPlatformOpinion.get_opinions(&ctx);
        assert!(!opinions.is_empty());
        assert_eq!(opinions[0].language_id, "AARCH64:LE:64:v8A");
    }

    #[test]
    fn test_lldb_uses_gdb_mappings() {
        let ctx = OpinionContext::new()
            .with_debugger_type("lldb")
            .with_architecture("x86-64")
            .with_pointer_size(8);
        let opinions = LldbPlatformOpinion.get_opinions(&ctx);
        assert!(!opinions.is_empty());
    }

    #[test]
    fn test_registry_best_opinion() {
        let registry = create_default_registry();
        let ctx = OpinionContext::new()
            .with_debugger_type("gdb")
            .with_architecture("x86-64")
            .with_pointer_size(8);
        let best = registry.best_opinion(&ctx);
        assert!(best.is_some());
        assert_eq!(best.unwrap().language_id, "x86:LE:64:default");
    }

    #[test]
    fn test_registry_no_match() {
        let registry = create_default_registry();
        let ctx = OpinionContext::new()
            .with_debugger_type("unknown_debugger")
            .with_architecture("unknown_arch");
        let opinions = registry.get_opinions(&ctx);
        assert!(opinions.is_empty());
    }

    #[test]
    fn test_opinion_context_builder() {
        let ctx = OpinionContext::new()
            .with_debugger_type("gdb")
            .with_architecture("mips")
            .with_os("linux")
            .with_pointer_size(4)
            .with_big_endian(true);
        assert_eq!(ctx.debugger_type, "gdb");
        assert_eq!(ctx.architecture, "mips");
        assert!(ctx.big_endian);
        assert_eq!(ctx.pointer_size, 4);
    }
}
