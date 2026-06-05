//! Extended platform mapper types ported from Java.
//!
//! Ported from the Debugger module's `mapping` package. Provides
//! the platform mapper infrastructure for mapping debug targets
//! to Ghidra's program model, including default and host platform
//! mapper implementations.

use std::collections::HashMap;

/// A platform offer represents a suggestion for how to interpret
/// a debug target's architecture.
#[derive(Debug, Clone)]
pub struct PlatformOffer {
    /// The language ID for this offer.
    pub language_id: String,
    /// The compiler spec ID.
    pub compiler_spec_id: String,
    /// Human-readable description of the offer.
    pub description: String,
    /// Confidence score (0.0 to 1.0).
    pub confidence: f64,
    /// Whether this offer is the default.
    pub is_default: bool,
}

impl PlatformOffer {
    /// Create a new platform offer.
    pub fn new(
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
            description: description.into(),
            confidence: 0.5,
            is_default: false,
        }
    }

    /// Set the confidence score.
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence;
        self
    }

    /// Mark this as the default offer.
    pub fn as_default(mut self) -> Self {
        self.is_default = true;
        self
    }
}

/// Trait for platform opinions - extension points that suggest
/// how to interpret debug targets.
pub trait PlatformOpinion: Send + Sync {
    /// Get the name of this opinion provider.
    fn name(&self) -> &str;

    /// Evaluate offers for a given trace target.
    fn offers(&self, trace_info: &TracePlatformInfo) -> Vec<PlatformOffer>;
}

/// Information about a trace's platform for opinion evaluation.
#[derive(Debug, Clone)]
pub struct TracePlatformInfo {
    /// The trace's target type (e.g., "gdb", "lldb", "dbgeng").
    pub target_type: String,
    /// Processor family reported by the debugger.
    pub processor: String,
    /// Address size in bits.
    pub address_size: u32,
    /// Endianness ("little" or "big").
    pub endianness: String,
    /// OS reported by the debugger.
    pub os: String,
    /// Architecture string (e.g., "x86_64", "aarch64").
    pub architecture: String,
    /// Additional metadata from the debugger.
    pub metadata: HashMap<String, String>,
}

impl TracePlatformInfo {
    /// Create a new trace platform info.
    pub fn new(target_type: impl Into<String>) -> Self {
        Self {
            target_type: target_type.into(),
            processor: String::new(),
            address_size: 0,
            endianness: "little".into(),
            os: String::new(),
            architecture: String::new(),
            metadata: HashMap::new(),
        }
    }
}

/// The default platform mapper that maps debug target platforms
/// to Ghidra language/compiler-spec pairs.
///
/// Ported from `DefaultDebuggerPlatformMapper`.
pub struct DefaultPlatformMapper {
    /// Known platform mappings: (processor, address_size) -> (lang_id, cspec_id)
    known_mappings: HashMap<(String, u32), (String, String)>,
}

impl DefaultPlatformMapper {
    /// Create a new default mapper with built-in platform mappings.
    pub fn new() -> Self {
        let mut known_mappings = HashMap::new();
        // Common x86 mappings
        known_mappings.insert(
            ("x86".into(), 32),
            ("x86:LE:32:default".into(), "default".into()),
        );
        known_mappings.insert(
            ("x86".into(), 64),
            ("x86:LE:64:default".into(), "default".into()),
        );
        // ARM mappings
        known_mappings.insert(
            ("ARM".into(), 32),
            ("ARM:LE:32:v8".into(), "default".into()),
        );
        known_mappings.insert(
            ("AARCH64".into(), 64),
            ("AARCH64:LE:64:v8A".into(), "default".into()),
        );
        // MIPS mappings
        known_mappings.insert(
            ("MIPS".into(), 32),
            ("MIPS:LE:32:default".into(), "default".into()),
        );
        known_mappings.insert(
            ("MIPS".into(), 64),
            ("MIPS:LE:64:64-32addr".into(), "default".into()),
        );
        // PowerPC mappings
        known_mappings.insert(
            ("PowerPC".into(), 32),
            ("PowerPC:BE:32:default".into(), "default".into()),
        );
        known_mappings.insert(
            ("PowerPC".into(), 64),
            ("PowerPC:BE:64:64-32addr".into(), "default".into()),
        );
        // RISC-V mappings
        known_mappings.insert(
            ("RISC-V".into(), 32),
            ("RISCV:LE:32:default".into(), "default".into()),
        );
        known_mappings.insert(
            ("RISC-V".into(), 64),
            ("RISCV:LE:64:default".into(), "default".into()),
        );

        Self { known_mappings }
    }

    /// Map a trace platform info to a platform offer.
    pub fn map(&self, info: &TracePlatformInfo) -> Option<PlatformOffer> {
        let key = (info.processor.clone(), info.address_size);
        self.known_mappings.get(&key).map(|(lang_id, cspec_id)| {
            PlatformOffer::new(lang_id, cspec_id, format!("{}-bit {}", info.address_size, info.processor))
                .with_confidence(0.8)
                .as_default()
        })
    }

    /// Check if this mapper supports a given processor.
    pub fn supports(&self, processor: &str, address_size: u32) -> bool {
        self.known_mappings.contains_key(&(processor.to_string(), address_size))
    }
}

impl Default for DefaultPlatformMapper {
    fn default() -> Self {
        Self::new()
    }
}

/// Host platform opinion that uses the trace's host language directly.
///
/// Ported from `HostDebuggerPlatformOpinion`. This opinion assumes the
/// trace was created with the correct host language by the debugger backend.
pub struct HostPlatformOpinion;

impl PlatformOpinion for HostPlatformOpinion {
    fn name(&self) -> &str {
        "Host Platform"
    }

    fn offers(&self, info: &TracePlatformInfo) -> Vec<PlatformOffer> {
        // The host opinion simply passes through the trace's own language
        if !info.processor.is_empty() {
            let mapper = DefaultPlatformMapper::new();
            if let Some(offer) = mapper.map(info) {
                return vec![offer];
            }
        }
        Vec::new()
    }
}

/// Abstract platform mapper that maps debugger memory/register spaces
/// to Ghidra address spaces.
///
/// Ported from `AbstractDebuggerPlatformMapper`.
pub struct AbstractPlatformMapper {
    /// The source language ID.
    pub source_language_id: String,
    /// The target language ID.
    pub target_language_id: String,
    /// Address space mappings: source_space -> target_space
    space_mappings: HashMap<String, String>,
    /// Register mappings: source_register -> target_register
    register_mappings: HashMap<String, String>,
}

impl AbstractPlatformMapper {
    /// Create a new abstract platform mapper.
    pub fn new(source_language_id: impl Into<String>, target_language_id: impl Into<String>) -> Self {
        Self {
            source_language_id: source_language_id.into(),
            target_language_id: target_language_id.into(),
            space_mappings: HashMap::new(),
            register_mappings: HashMap::new(),
        }
    }

    /// Add an address space mapping.
    pub fn add_space_mapping(&mut self, source: impl Into<String>, target: impl Into<String>) {
        self.space_mappings.insert(source.into(), target.into());
    }

    /// Add a register mapping.
    pub fn add_register_mapping(&mut self, source: impl Into<String>, target: impl Into<String>) {
        self.register_mappings.insert(source.into(), target.into());
    }

    /// Translate an address space name from source to target.
    pub fn translate_space(&self, source_space: &str) -> Option<&str> {
        self.space_mappings.get(source_space).map(|s| s.as_str())
    }

    /// Translate a register name from source to target.
    pub fn translate_register(&self, source_register: &str) -> Option<&str> {
        self.register_mappings.get(source_register).map(|s| s.as_str())
    }

    /// Check if this is a Harvard architecture mapping.
    /// Harvard architectures have separate code and data address spaces.
    pub fn is_harvard(&self) -> bool {
        let non_register_spaces: Vec<_> = self.space_mappings.keys()
            .filter(|s| s.as_str() != "register" && s.as_str() != "ram")
            .collect();
        non_register_spaces.len() > 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_offer() {
        let offer = PlatformOffer::new("x86:LE:64:default", "default", "x86-64")
            .with_confidence(0.9)
            .as_default();
        assert!(offer.is_default);
        assert_eq!(offer.confidence, 0.9);
    }

    #[test]
    fn test_default_mapper_x86_64() {
        let mapper = DefaultPlatformMapper::new();
        assert!(mapper.supports("x86", 64));
        assert!(mapper.supports("ARM", 32));
        assert!(!mapper.supports("UNKNOWN", 32));

        let info = TracePlatformInfo {
            target_type: "gdb".into(),
            processor: "x86".into(),
            address_size: 64,
            endianness: "little".into(),
            os: "linux".into(),
            architecture: "x86_64".into(),
            metadata: HashMap::new(),
        };
        let offer = mapper.map(&info).unwrap();
        assert_eq!(offer.language_id, "x86:LE:64:default");
    }

    #[test]
    fn test_host_platform_opinion() {
        let opinion = HostPlatformOpinion;
        let info = TracePlatformInfo {
            target_type: "gdb".into(),
            processor: "x86".into(),
            address_size: 64,
            endianness: "little".into(),
            os: "linux".into(),
            architecture: "x86_64".into(),
            metadata: HashMap::new(),
        };
        let offers = opinion.offers(&info);
        assert!(!offers.is_empty());
    }

    #[test]
    fn test_abstract_mapper() {
        let mut mapper = AbstractPlatformMapper::new("x86:LE:64:default", "x86:LE:64:default");
        mapper.add_space_mapping("ram", "ram");
        mapper.add_space_mapping("register", "register");
        mapper.add_register_mapping("RAX", "RAX");
        mapper.add_register_mapping("RBX", "RBX");

        assert_eq!(mapper.translate_space("ram"), Some("ram"));
        assert_eq!(mapper.translate_space("unknown"), None);
        assert_eq!(mapper.translate_register("RAX"), Some("RAX"));
        assert!(!mapper.is_harvard());

        // Harvard: multiple distinct spaces
        let mut harvard = AbstractPlatformMapper::new("AVR8:BE:24:atmega256", "AVR8:BE:24:atmega256");
        harvard.add_space_mapping("code", "code");
        harvard.add_space_mapping("data", "data");
        assert!(harvard.is_harvard());
    }

    #[test]
    fn test_trace_platform_info() {
        let info = TracePlatformInfo::new("gdb");
        assert_eq!(info.target_type, "gdb");
        assert_eq!(info.endianness, "little");
    }
}
