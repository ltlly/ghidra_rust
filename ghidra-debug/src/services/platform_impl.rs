//! Platform service implementation: platform opinions, offers, and connectors.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.platform` package.
//! Provides the platform opinion system that maps debugger metadata to
//! Ghidra language/compiler specs.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// An endianness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Endian {
    /// Little-endian.
    Little,
    /// Big-endian.
    Big,
}

impl std::fmt::Display for Endian {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Little => write!(f, "Little"),
            Self::Big => write!(f, "Big"),
        }
    }
}

/// A language-compiler-spec pair identifying a Ghidra processor module config.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LanguageCompilerSpecId {
    /// The language ID (e.g., "x86:LE:64:default").
    pub language_id: String,
    /// The compiler spec ID (e.g., "default", "gcc").
    pub compiler_spec_id: String,
}

impl LanguageCompilerSpecId {
    /// Create a new LCSP.
    pub fn new(
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
    ) -> Self {
        Self {
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
        }
    }
}

impl std::fmt::Display for LanguageCompilerSpecId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} [{}]", self.language_id, self.compiler_spec_id)
    }
}

/// An offer from a platform opinion to map a debugger's metadata to a Ghidra language.
///
/// Ported from Ghidra's `DebuggerPlatformOffer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformOffer {
    /// The language-compiler-spec pair.
    pub lcsp: LanguageCompilerSpecId,
    /// A confidence score (0.0 = low, 1.0 = high).
    pub confidence: f64,
    /// An explanation of why this offer was made.
    pub reason: String,
    /// Whether this offer is an override (manually selected).
    pub is_override: bool,
}

impl PlatformOffer {
    /// Create a new offer.
    pub fn new(
        lcsp: LanguageCompilerSpecId,
        confidence: f64,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            lcsp,
            confidence,
            reason: reason.into(),
            is_override: false,
        }
    }

    /// Create an override offer (always chosen over auto-detected).
    pub fn with_override(mut self) -> Self {
        self.is_override = true;
        self
    }
}

/// A platform opinion that maps debugger metadata to Ghidra language/compiler specs.
///
/// Ported from Ghidra's `DebuggerPlatformOpinion` abstract class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformOpinion {
    /// The debugger name this opinion applies to (e.g., "gdb", "lldb", "dbgeng").
    pub debugger: String,
    /// The priority of this opinion (higher = preferred).
    pub priority: i32,
}

impl PlatformOpinion {
    /// Create a new opinion.
    pub fn new(debugger: impl Into<String>, priority: i32) -> Self {
        Self {
            debugger: debugger.into(),
            priority,
        }
    }
}

/// The registry of platform opinions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlatformOpinionRegistry {
    opinions: Vec<PlatformOpinion>,
    /// Pre-built offers indexed by debugger name.
    offers: BTreeMap<String, Vec<PlatformOffer>>,
}

impl PlatformOpinionRegistry {
    /// Create a new registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a platform opinion.
    pub fn register(&mut self, opinion: PlatformOpinion) {
        self.opinions.push(opinion);
    }

    /// Add a pre-built offer for a debugger.
    pub fn add_offer(&mut self, debugger: &str, offer: PlatformOffer) {
        self.offers
            .entry(debugger.to_string())
            .or_default()
            .push(offer);
    }

    /// Get offers for a given debugger.
    pub fn offers_for(&self, debugger: &str) -> Vec<&PlatformOffer> {
        self.offers
            .get(debugger)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Get all known debugger names.
    pub fn known_debuggers(&self) -> BTreeSet<&str> {
        let mut set = BTreeSet::new();
        for o in &self.opinions {
            set.insert(o.debugger.as_str());
        }
        set
    }
}

// ── Platform Mapper ───────────────────────────────────────────────────────

/// The result of a disassembly attempt on a trace.
///
/// Ported from Ghidra's `DisassemblyResult`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyResult {
    /// Whether the disassembly was successful.
    pub success: bool,
    /// The disassembled instruction length (in bytes).
    pub length: usize,
    /// The disassembly text.
    pub text: String,
    /// An error message if disassembly failed.
    pub error: Option<String>,
}

impl DisassemblyResult {
    /// Create a successful result.
    pub fn success(length: usize, text: impl Into<String>) -> Self {
        Self {
            success: true,
            length,
            text: text.into(),
            error: None,
        }
    }

    /// Create a failed result.
    pub fn error(error: impl Into<String>) -> Self {
        Self {
            success: false,
            length: 0,
            text: String::new(),
            error: Some(error.into()),
        }
    }
}

/// A mapper that translates between trace and program coordinates,
/// handling language and register mapping.
///
/// Ported from Ghidra's `DebuggerPlatformMapper` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformMapper {
    /// The language ID used by this mapper.
    pub language_id: String,
    /// The compiler spec ID.
    pub compiler_spec_id: String,
    /// The register name mappings (trace register -> Ghidra register).
    pub register_mappings: BTreeMap<String, String>,
    /// The address space name mappings (trace space -> Ghidra space).
    pub space_mappings: BTreeMap<String, String>,
}

impl PlatformMapper {
    /// Create a new mapper.
    pub fn new(
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
    ) -> Self {
        Self {
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
            register_mappings: BTreeMap::new(),
            space_mappings: BTreeMap::new(),
        }
    }

    /// Add a register name mapping.
    pub fn with_register_mapping(
        mut self,
        trace_name: impl Into<String>,
        ghidra_name: impl Into<String>,
    ) -> Self {
        self.register_mappings
            .insert(trace_name.into(), ghidra_name.into());
        self
    }

    /// Add an address space mapping.
    pub fn with_space_mapping(
        mut self,
        trace_space: impl Into<String>,
        ghidra_space: impl Into<String>,
    ) -> Self {
        self.space_mappings
            .insert(trace_space.into(), ghidra_space.into());
        self
    }

    /// Map a trace register name to a Ghidra register name.
    pub fn map_register(&self, trace_name: &str) -> Option<&str> {
        self.register_mappings
            .get(trace_name)
            .map(|s| s.as_str())
    }

    /// Map a trace address space to a Ghidra space.
    pub fn map_space(&self, trace_space: &str) -> Option<&str> {
        self.space_mappings
            .get(trace_space)
            .map(|s| s.as_str())
    }
}

// ── Built-in platform connectors ──────────────────────────────────────────

/// GDB platform connector metadata.
///
/// Ported from Ghidra's `GdbDebuggerPlatformOpinion`.
pub fn gdb_opinion() -> PlatformOpinion {
    PlatformOpinion::new("gdb", 100)
}

/// LLDB platform connector metadata.
///
/// Ported from Ghidra's `LldbDebuggerPlatformOpinion`.
pub fn lldb_opinion() -> PlatformOpinion {
    PlatformOpinion::new("lldb", 100)
}

/// Windows Debugger Engine (dbgeng) platform connector metadata.
///
/// Ported from Ghidra's `DbgEngDebuggerPlatformOpinion`.
pub fn dbgeng_opinion() -> PlatformOpinion {
    PlatformOpinion::new("dbgeng", 100)
}

/// Frida platform connector metadata.
///
/// Ported from Ghidra's `FridaDebuggerPlatformOpinion`.
pub fn frida_opinion() -> PlatformOpinion {
    PlatformOpinion::new("frida", 100)
}

/// JDI (Java Debug Interface) platform connector metadata.
///
/// Ported from Ghidra's `JdiDebuggerPlatformOpinion`.
pub fn jdi_opinion() -> PlatformOpinion {
    PlatformOpinion::new("jdi", 50)
}

/// Create a default GDB mapper for x86_64 Linux.
pub fn gdb_x86_64_linux_mapper() -> PlatformMapper {
    PlatformMapper::new("x86:LE:64:default", "default")
        .with_register_mapping("rip", "RIP")
        .with_register_mapping("rsp", "RSP")
        .with_register_mapping("rbp", "RBP")
        .with_register_mapping("rax", "RAX")
        .with_register_mapping("rbx", "RBX")
        .with_register_mapping("rcx", "RCX")
        .with_register_mapping("rdx", "RDX")
        .with_space_mapping("ram", "ram")
        .with_space_mapping("register", "register")
}

/// Create a default GDB mapper for ARM (32-bit).
pub fn gdb_arm32_mapper() -> PlatformMapper {
    PlatformMapper::new("ARM:LE:32:v8", "default")
        .with_register_mapping("pc", "PC")
        .with_register_mapping("sp", "SP")
        .with_register_mapping("lr", "LR")
        .with_register_mapping("r0", "R0")
        .with_register_mapping("r1", "R1")
}

/// Create a default GDB mapper for AArch64.
pub fn gdb_aarch64_mapper() -> PlatformMapper {
    PlatformMapper::new("AARCH64:LE:64:v8A", "default")
        .with_register_mapping("pc", "PC")
        .with_register_mapping("sp", "SP")
        .with_register_mapping("x0", "X0")
        .with_register_mapping("x1", "X1")
}

/// Helper to resolve architecture strings from GDB to Ghidra language IDs.
pub fn arch_to_languages(arch: &str, os: &str, endian: Endian) -> Vec<LanguageCompilerSpecId> {
    match (arch, endian) {
        ("i386" | "i686" | "x86", Endian::Little) => {
            vec![LanguageCompilerSpecId::new("x86:LE:32:default", "default")]
        }
        ("x86-64" | "x86_64" | "amd64", Endian::Little) => {
            vec![LanguageCompilerSpecId::new("x86:LE:64:default", "default")]
        }
        ("arm" | "armv7" | "armv7l", Endian::Little) => {
            vec![LanguageCompilerSpecId::new("ARM:LE:32:v8", "default")]
        }
        ("aarch64" | "arm64", Endian::Little) => {
            vec![LanguageCompilerSpecId::new("AARCH64:LE:64:v8A", "default")]
        }
        ("mips" | "mipsel", Endian::Little) => {
            vec![LanguageCompilerSpecId::new("MIPS:LE:32:default", "default")]
        }
        ("mips" | "mipseb", Endian::Big) => {
            vec![LanguageCompilerSpecId::new("MIPS:BE:32:default", "default")]
        }
        ("powerpc" | "ppc", Endian::Big) => {
            vec![LanguageCompilerSpecId::new("PowerPC:BE:32:default", "default")]
        }
        ("powerpc64" | "ppc64", Endian::Big) => {
            vec![LanguageCompilerSpecId::new("PowerPC:BE:64:64-32addr", "default")]
        }
        ("riscv64" | "riscv64gc", _) => {
            vec![LanguageCompilerSpecId::new(
                "RISCV:LE:64:default",
                "default",
            )]
        }
        ("sparc", Endian::Big) => {
            vec![LanguageCompilerSpecId::new("sparc:BE:32:default", "default")]
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_offer() {
        let offer = PlatformOffer::new(
            LanguageCompilerSpecId::new("x86:LE:64:default", "default"),
            0.9,
            "arch=x86_64",
        );
        assert!((offer.confidence - 0.9).abs() < f64::EPSILON);
        assert!(!offer.is_override);
    }

    #[test]
    fn test_platform_opinion_registry() {
        let mut reg = PlatformOpinionRegistry::new();
        reg.register(gdb_opinion());
        reg.register(lldb_opinion());
        reg.register(dbgeng_opinion());

        let debuggers = reg.known_debuggers();
        assert!(debuggers.contains("gdb"));
        assert!(debuggers.contains("lldb"));
    }

    #[test]
    fn test_platform_mapper() {
        let mapper = gdb_x86_64_linux_mapper();
        assert_eq!(mapper.language_id, "x86:LE:64:default");
        assert_eq!(mapper.map_register("rip"), Some("RIP"));
        assert_eq!(mapper.map_register("unknown"), None);
        assert_eq!(mapper.map_space("ram"), Some("ram"));
    }

    #[test]
    fn test_arch_to_languages() {
        let langs = arch_to_languages("x86_64", "linux", Endian::Little);
        assert_eq!(langs.len(), 1);
        assert_eq!(langs[0].language_id, "x86:LE:64:default");

        let langs = arch_to_languages("aarch64", "linux", Endian::Little);
        assert_eq!(langs.len(), 1);

        let langs = arch_to_languages("unknown_arch", "linux", Endian::Little);
        assert!(langs.is_empty());
    }

    #[test]
    fn test_disassembly_result() {
        let result = DisassemblyResult::success(3, "mov eax, ebx");
        assert!(result.success);
        assert_eq!(result.length, 3);

        let result = DisassemblyResult::error("invalid instruction");
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_endian_display() {
        assert_eq!(Endian::Little.to_string(), "Little");
        assert_eq!(Endian::Big.to_string(), "Big");
    }

    #[test]
    fn test_gdb_arm_mapper() {
        let mapper = gdb_arm32_mapper();
        assert_eq!(mapper.language_id, "ARM:LE:32:v8");
        assert_eq!(mapper.map_register("pc"), Some("PC"));
        assert_eq!(mapper.map_register("sp"), Some("SP"));
    }

    #[test]
    fn test_gdb_aarch64_mapper() {
        let mapper = gdb_aarch64_mapper();
        assert_eq!(mapper.language_id, "AARCH64:LE:64:v8A");
        assert_eq!(mapper.map_register("x0"), Some("X0"));
    }

    #[test]
    fn test_platform_opinions() {
        assert_eq!(gdb_opinion().debugger, "gdb");
        assert_eq!(lldb_opinion().debugger, "lldb");
        assert_eq!(dbgeng_opinion().debugger, "dbgeng");
        assert_eq!(frida_opinion().debugger, "frida");
        assert_eq!(jdi_opinion().debugger, "jdi");
    }

    #[test]
    fn test_offers_for() {
        let mut reg = PlatformOpinionRegistry::new();
        reg.add_offer(
            "gdb",
            PlatformOffer::new(
                LanguageCompilerSpecId::new("x86:LE:64:default", "default"),
                0.95,
                "x86_64 detected",
            ),
        );
        let offers = reg.offers_for("gdb");
        assert_eq!(offers.len(), 1);
        assert!(reg.offers_for("lldb").is_empty());
    }

    #[test]
    fn test_language_compiler_spec_id_display() {
        let lcsp = LanguageCompilerSpecId::new("x86:LE:64:default", "default");
        assert!(lcsp.to_string().contains("x86:LE:64:default"));
    }

    #[test]
    fn test_mips_endian() {
        let le = arch_to_languages("mipsel", "linux", Endian::Little);
        assert_eq!(le[0].language_id, "MIPS:LE:32:default");
        let be = arch_to_languages("mips", "linux", Endian::Big);
        assert_eq!(be[0].language_id, "MIPS:BE:32:default");
    }
}
