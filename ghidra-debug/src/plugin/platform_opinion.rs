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

/// Create a registry with all built-in providers from the individual platform modules.
///
/// This function imports the platform-specific opinion providers from their
/// respective modules to avoid ambiguous glob re-exports.
pub fn create_default_registry() -> PlatformOpinionRegistry {
    use super::platform_frida::FridaPlatformOpinion;
    use super::platform_gdb::GdbPlatformOpinion;
    use super::platform_lldb::LldbPlatformOpinion;

    let mut registry = PlatformOpinionRegistry::new();
    registry.register(Box::new(GdbPlatformOpinion));
    registry.register(Box::new(LldbPlatformOpinion));
    registry.register(Box::new(FridaPlatformOpinion));
    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::platform_gdb::GdbPlatformOpinion;
    use super::super::platform_lldb::LldbPlatformOpinion;

    #[test]
    fn test_platform_opinion_creation() {
        let opinion = PlatformOpinion::new("gdb", "x86:LE:64:default", "gcc", "x86-64", 0.9);
        assert_eq!(opinion.debugger_type, "gdb");
        assert_eq!(opinion.language_id, "x86:LE:64:default");
        assert_eq!(opinion.compiler_spec_id, "gcc");
        assert_eq!(opinion.architecture, "x86-64");
        assert_eq!(opinion.confidence, 0.9);
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
        assert_eq!(ctx.os, "linux");
        assert!(ctx.big_endian);
        assert_eq!(ctx.pointer_size, 4);
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
    fn test_registry_len() {
        let registry = create_default_registry();
        assert_eq!(registry.len(), 3);
        assert!(!registry.is_empty());
    }

    #[test]
    fn test_empty_registry() {
        let registry = PlatformOpinionRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_registry_lldb() {
        let registry = create_default_registry();
        let ctx = OpinionContext::new()
            .with_debugger_type("lldb")
            .with_architecture("x86-64")
            .with_pointer_size(8);
        let opinions = registry.get_opinions(&ctx);
        assert!(!opinions.is_empty());
    }

    #[test]
    fn test_registry_frida() {
        let registry = create_default_registry();
        let ctx = OpinionContext::new()
            .with_debugger_type("frida")
            .with_architecture("arm64")
            .with_pointer_size(8);
        let opinions = registry.get_opinions(&ctx);
        assert!(!opinions.is_empty());
    }

    #[test]
    fn test_provider_name() {
        let provider = GdbPlatformOpinion;
        assert_eq!(provider.name(), "GDB");
    }
}
