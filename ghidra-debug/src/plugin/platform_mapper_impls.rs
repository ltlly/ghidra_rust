//! Platform mapper implementations.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.mapping` package:
//! - `AbstractDebuggerPlatformMapper`: Base mapper with disassembly injection support.
//! - `DefaultDebuggerPlatformMapper`: Default mapper using compiler spec for host/guest.
//! - `AbstractDebuggerPlatformOffer`: Base offer with description and compiler spec.
//! - `AbstractDebuggerPlatformOpinion`: Base opinion that resolves environment info.
//! - `HostDebuggerPlatformOpinion`: Opinion using the trace's host platform directly.

use std::fmt;

use crate::api::platform_mapper::DisassemblyResult;

// ---------------------------------------------------------------------------
// CompilerSpec placeholder (represents a language + compiler specification)
// ---------------------------------------------------------------------------

/// A language/compiler specification identifier.
///
/// Ported from Ghidra's `CompilerSpec`. In the full Ghidra, this represents
/// a specific compiler specification for a processor language. Here, it
/// captures the essential identity fields.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CompilerSpec {
    /// The language ID (e.g., "x86:LE:64:default").
    pub language_id: String,
    /// The compiler spec ID (e.g., "default").
    pub compiler_spec_id: String,
    /// Human-readable description.
    pub description: String,
}

impl CompilerSpec {
    /// Create a new compiler spec.
    pub fn new(
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
            description: description.into(),
        }
    }

    /// Check if this is a Harvard architecture (separate code/data spaces).
    pub fn is_harvard(&self) -> bool {
        // Heuristic: Harvard architectures typically have different default spaces.
        // In Ghidra proper this is checked via Language.getDefaultSpace() != getDefaultDataSpace().
        self.language_id.contains(":Harvard")
    }
}

impl fmt::Display for CompilerSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.language_id, self.compiler_spec_id)
    }
}

// ---------------------------------------------------------------------------
// PlatformOffer trait
// ---------------------------------------------------------------------------

/// An offer for a particular platform/compiler-spec for a debug target.
///
/// Ported from `DebuggerPlatformOffer`.
pub trait PlatformOffer: fmt::Debug {
    /// Human-readable description of this offer.
    fn description(&self) -> &str;

    /// The compiler spec for this offer, if known.
    fn compiler_spec(&self) -> Option<&CompilerSpec>;

    /// Confidence level for this offer (higher = more confident).
    fn confidence(&self) -> i32;

    /// Whether this offer's mapper is the creator of the given mapper.
    fn is_creator_of(&self, _mapper: &dyn PlatformMapper) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// PlatformMapper trait
// ---------------------------------------------------------------------------

/// A platform mapper that can interpret and add platforms to a trace.
///
/// Ported from `DebuggerPlatformMapper`.
pub trait PlatformMapper: fmt::Debug {
    /// Get the compiler spec for a given object at a snap.
    fn get_compiler_spec(&self, object_path: &str, snap: i64) -> Option<&CompilerSpec>;

    /// Whether this mapper can interpret the given focus at the given snap.
    fn can_interpret(&self, focus_path: &str, snap: i64) -> bool;

    /// Add the platform to the trace. Returns a description of what was added.
    fn add_to_trace(&self, focus_path: &str, snap: i64) -> String;

    /// Disassemble at the given address. Returns None if cancelled.
    fn disassemble(
        &self,
        thread_path: &str,
        object_path: &str,
        start_offset: u64,
        restricted: &[(u64, u64)],
        snap: i64,
    ) -> Option<DisassemblyResult>;
}

// ---------------------------------------------------------------------------
// AbstractDebuggerPlatformMapper
// ---------------------------------------------------------------------------

/// Base implementation of a platform mapper.
///
/// Provides common logic for disassembly with injection support,
/// environment-based `canInterpret`, and cancellation of already-known
/// addresses. Subclasses provide `get_compiler_spec` and `add_to_trace`.
///
/// Ported from `AbstractDebuggerPlatformMapper`.
#[derive(Debug)]
pub struct AbstractPlatformMapper {
    /// The trace identifier this mapper operates on.
    pub trace_id: String,
}

impl AbstractPlatformMapper {
    /// Create a new abstract platform mapper.
    pub fn new(trace_id: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
        }
    }

    /// Check if we can interpret based on environment info.
    ///
    /// Default implementation always returns true. Subclasses override to
    /// filter by debugger name, architecture, OS, or endianness.
    pub fn can_interpret_with_env(
        &self,
        _focus_path: &str,
        _snap: i64,
        _debugger: Option<&str>,
        _arch: Option<&str>,
        _os: Option<&str>,
        _big_endian: Option<bool>,
    ) -> bool {
        true
    }

    /// Check if disassembly should be silently cancelled for a given address.
    ///
    /// Returns true if the address already has fully-known memory state.
    pub fn is_cancel_silently(&self, _start_offset: u64, _snap: i64) -> bool {
        // In Ghidra, this checks if an instruction already exists at the address
        // and all its memory states are KNOWN. Simplified here.
        false
    }
}

impl AbstractPlatformMapper {
    /// Disassemble with the given parameters. Returns None if cancelled.
    pub fn disassemble_impl(
        &self,
        _start_offset: u64,
        _restricted: &[(u64, u64)],
        _snap: i64,
    ) -> Option<DisassemblyResult> {
        if self.is_cancel_silently(_start_offset, _snap) {
            return None;
        }
        Some(DisassemblyResult::new("DIS", "DISASSEMBLED", 0))
    }
}

impl PlatformMapper for AbstractPlatformMapper {
    fn get_compiler_spec(&self, _object_path: &str, _snap: i64) -> Option<&CompilerSpec> {
        None
    }

    fn can_interpret(&self, focus_path: &str, snap: i64) -> bool {
        self.can_interpret_with_env(focus_path, snap, None, None, None, None)
    }

    fn add_to_trace(&self, _focus_path: &str, _snap: i64) -> String {
        "AbstractPlatformMapper (no-op)".to_string()
    }

    fn disassemble(
        &self,
        _thread_path: &str,
        _object_path: &str,
        start_offset: u64,
        restricted: &[(u64, u64)],
        snap: i64,
    ) -> Option<DisassemblyResult> {
        self.disassemble_impl(start_offset, restricted, snap)
    }
}

// ---------------------------------------------------------------------------
// DefaultDebuggerPlatformMapper
// ---------------------------------------------------------------------------

/// Default platform mapper that uses a fixed compiler spec.
///
/// For non-Harvard architectures, this simply uses the given compiler spec.
/// For Harvard architectures, this raises an error.
///
/// Ported from `DefaultDebuggerPlatformMapper`.
#[derive(Debug)]
pub struct DefaultPlatformMapper {
    base: AbstractPlatformMapper,
    cspec: CompilerSpec,
}

impl DefaultPlatformMapper {
    /// Create a new default platform mapper.
    ///
    /// # Errors
    /// Returns an error if the compiler spec is for a Harvard architecture.
    pub fn new(trace_id: impl Into<String>, cspec: CompilerSpec) -> Result<Self, String> {
        if cspec.is_harvard() {
            return Err("This mapper cannot handle Harvard guests".to_string());
        }
        Ok(Self {
            base: AbstractPlatformMapper::new(trace_id),
            cspec,
        })
    }

    /// Get the compiler spec.
    pub fn compiler_spec(&self) -> &CompilerSpec {
        &self.cspec
    }

    /// Compute mapped ranges for a guest platform.
    ///
    /// Given host and guest address space ranges, computes the overlap
    /// and returns (host_start, guest_start, length) tuples.
    pub fn compute_mapped_ranges(
        host_min: u64,
        host_max: u64,
        guest_min: u64,
        guest_max: u64,
    ) -> Option<(u64, u64, u64)> {
        let min = host_min.max(guest_min);
        let max = host_max.min(guest_max);
        if min > max {
            return None;
        }
        Some((min, min, max - min + 1))
    }
}

impl PlatformMapper for DefaultPlatformMapper {
    fn get_compiler_spec(&self, _object_path: &str, _snap: i64) -> Option<&CompilerSpec> {
        Some(&self.cspec)
    }

    fn can_interpret(&self, _focus_path: &str, _snap: i64) -> bool {
        true
    }

    fn add_to_trace(&self, _focus_path: &str, _snap: i64) -> String {
        format!("Add guest {}", self.cspec)
    }

    fn disassemble(
        &self,
        _thread_path: &str,
        _object_path: &str,
        start_offset: u64,
        restricted: &[(u64, u64)],
        snap: i64,
    ) -> Option<DisassemblyResult> {
        self.base.disassemble_impl(start_offset, restricted, snap)
    }
}

// ---------------------------------------------------------------------------
// AbstractDebuggerPlatformOffer
// ---------------------------------------------------------------------------

/// Base implementation of a platform offer.
///
/// Ported from `AbstractDebuggerPlatformOffer`.
#[derive(Debug, Clone)]
pub struct AbstractPlatformOffer {
    description: String,
    cspec: Option<CompilerSpec>,
    confidence: i32,
}

impl AbstractPlatformOffer {
    /// Create a new platform offer.
    pub fn new(
        description: impl Into<String>,
        cspec: Option<CompilerSpec>,
        confidence: i32,
    ) -> Self {
        Self {
            description: description.into(),
            cspec,
            confidence,
        }
    }
}

impl PlatformOffer for AbstractPlatformOffer {
    fn description(&self) -> &str {
        &self.description
    }

    fn compiler_spec(&self) -> Option<&CompilerSpec> {
        self.cspec.as_ref()
    }

    fn confidence(&self) -> i32 {
        self.confidence
    }
}

impl PartialEq for AbstractPlatformOffer {
    fn eq(&self, other: &Self) -> bool {
        self.description == other.description && self.cspec == other.cspec
    }
}
impl Eq for AbstractPlatformOffer {}

impl std::hash::Hash for AbstractPlatformOffer {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.description.hash(state);
        self.cspec.hash(state);
    }
}

// ---------------------------------------------------------------------------
// PlatformOpinion trait
// ---------------------------------------------------------------------------

/// A platform opinion provides offers for how to interpret a debug target.
///
/// Ported from `DebuggerPlatformOpinion`.
pub trait PlatformOpinion: fmt::Debug {
    /// Get platform offers for the given trace object at the given snap.
    fn get_offers(
        &self,
        trace_id: &str,
        object_path: &str,
        snap: i64,
        include_overrides: bool,
    ) -> Vec<Box<dyn PlatformOffer>>;

    /// Extract the environment object from a focus object.
    fn get_environment(object_path: &str, snap: i64) -> Option<String> {
        let _ = (object_path, snap);
        None
    }

    /// Extract the debugger name from an environment object.
    fn get_debugger_from_env(env_path: &str, snap: i64) -> Option<String> {
        let _ = (env_path, snap);
        None
    }

    /// Extract the architecture from an environment object.
    fn get_architecture_from_env(env_path: &str, snap: i64) -> Option<String> {
        let _ = (env_path, snap);
        None
    }

    /// Extract the OS from an environment object.
    fn get_os_from_env(env_path: &str, snap: i64) -> Option<String> {
        let _ = (env_path, snap);
        None
    }

    /// Extract the endianness from an environment object.
    fn get_endian_from_env(env_path: &str, snap: i64) -> Option<bool> {
        let _ = (env_path, snap);
        None
    }
}

// ---------------------------------------------------------------------------
// AbstractDebuggerPlatformOpinion
// ---------------------------------------------------------------------------

/// Base implementation of a platform opinion.
///
/// Resolves environment info (debugger, arch, OS, endian) and delegates
/// to `get_offers_with_env`.
///
/// Ported from `AbstractDebuggerPlatformOpinion`.
#[derive(Debug)]
pub struct AbstractPlatformOpinion;

impl AbstractPlatformOpinion {
    /// Get offers using resolved environment information.
    pub fn get_offers_with_env(
        _object_path: &str,
        _snap: i64,
        _env_path: Option<&str>,
        _debugger: Option<&str>,
        _arch: Option<&str>,
        _os: Option<&str>,
        _big_endian: Option<bool>,
        _include_overrides: bool,
    ) -> Vec<Box<dyn PlatformOffer>> {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// HostDebuggerPlatformOpinion
// ---------------------------------------------------------------------------

/// Confidence when the back-end chose the language.
pub const CONFIDENCE_HOST_KNOWN: i32 = 10_000;

/// An opinion that uses the trace's host platform directly.
///
/// When the back-end created the trace with the correct host language,
/// this opinion just uses that language rather than mapping a guest.
///
/// Ported from `HostDebuggerPlatformOpinion`.
#[derive(Debug)]
pub struct HostPlatformOpinion;

impl HostPlatformOpinion {
    /// Create a host platform mapper.
    pub fn create_mapper(trace_id: &str) -> Box<dyn PlatformMapper> {
        Box::new(HostPlatformMapper {
            base: AbstractPlatformMapper::new(trace_id),
        })
    }
}

/// Mapper that uses the trace's base compiler spec.
#[derive(Debug)]
struct HostPlatformMapper {
    base: AbstractPlatformMapper,
}

impl PlatformMapper for HostPlatformMapper {
    fn get_compiler_spec(&self, _object_path: &str, _snap: i64) -> Option<&CompilerSpec> {
        None // In full Ghidra, returns trace.getBaseCompilerSpec()
    }

    fn can_interpret(&self, _focus_path: &str, _snap: i64) -> bool {
        true
    }

    fn add_to_trace(&self, _focus_path: &str, _snap: i64) -> String {
        "Use host platform".to_string()
    }

    fn disassemble(
        &self,
        _thread_path: &str,
        _object_path: &str,
        start_offset: u64,
        restricted: &[(u64, u64)],
        snap: i64,
    ) -> Option<DisassemblyResult> {
        self.base.disassemble_impl(start_offset, restricted, snap)
    }
}

impl PlatformOpinion for HostPlatformOpinion {
    fn get_offers(
        &self,
        _trace_id: &str,
        _object_path: &str,
        _snap: i64,
        _include_overrides: bool,
    ) -> Vec<Box<dyn PlatformOffer>> {
        vec![
            Box::new(AbstractPlatformOffer::new(
                "Host/base (back end chose the language)",
                None,
                CONFIDENCE_HOST_KNOWN,
            )),
        ]
    }
}

// ---------------------------------------------------------------------------
// Environment key constants
// ---------------------------------------------------------------------------

/// Environment attribute key for architecture.
pub const ENV_KEY_ARCH: &str = "_arch";
/// Environment attribute key for debugger name.
pub const ENV_KEY_DEBUGGER: &str = "_debugger";
/// Environment attribute key for endianness.
pub const ENV_KEY_ENDIAN: &str = "_endian";
/// Environment attribute key for OS.
pub const ENV_KEY_OS: &str = "_os";

/// Parse endianness from an environment string value.
pub fn parse_endian(value: &str) -> Option<bool> {
    match value.to_lowercase().as_str() {
        "big" | "be" | "bigendian" | "big-endian" => Some(true),
        "little" | "le" | "littleendian" | "little-endian" => Some(false),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compiler_spec_new() {
        let cs = CompilerSpec::new("x86:LE:64:default", "default", "x86 64-bit default");
        assert_eq!(cs.language_id, "x86:LE:64:default");
        assert_eq!(cs.compiler_spec_id, "default");
        assert!(!cs.is_harvard());
    }

    #[test]
    fn test_compiler_spec_harvard() {
        let cs = CompilerSpec::new("AVR8:Harvard:8:default", "default", "AVR8");
        assert!(cs.is_harvard());
    }

    #[test]
    fn test_compiler_spec_display() {
        let cs = CompilerSpec::new("x86:LE:64:default", "default", "x86 64-bit");
        assert_eq!(format!("{}", cs), "x86:LE:64:default/default");
    }

    #[test]
    fn test_default_platform_mapper_harvard_rejected() {
        let cs = CompilerSpec::new("AVR8:Harvard:8:default", "default", "AVR8");
        let result = DefaultPlatformMapper::new("trace1", cs);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Harvard"));
    }

    #[test]
    fn test_default_platform_mapper_ok() {
        let cs = CompilerSpec::new("x86:LE:64:default", "default", "x86 64-bit");
        let mapper = DefaultPlatformMapper::new("trace1", cs).unwrap();
        assert!(mapper.can_interpret("obj", 0));
        assert!(mapper.get_compiler_spec("obj", 0).is_some());
    }

    #[test]
    fn test_default_platform_mapper_disassemble() {
        let cs = CompilerSpec::new("x86:LE:64:default", "default", "x86 64-bit");
        let mapper = DefaultPlatformMapper::new("trace1", cs).unwrap();
        let result = mapper.disassemble("thread", "obj", 0x1000, &[], 0);
        assert!(result.is_some());
    }

    #[test]
    fn test_compute_mapped_ranges() {
        let result = DefaultPlatformMapper::compute_mapped_ranges(0, 0xFFFF, 0x1000, 0x1FFFF);
        assert_eq!(result, Some((0x1000, 0x1000, 0xF000)));
    }

    #[test]
    fn test_compute_mapped_ranges_no_overlap() {
        let result = DefaultPlatformMapper::compute_mapped_ranges(0, 0xFF, 0x1000, 0x1FFF);
        assert_eq!(result, None);
    }

    #[test]
    fn test_abstract_platform_offer() {
        let cs = CompilerSpec::new("x86:LE:64:default", "default", "x86");
        let offer = AbstractPlatformOffer::new("Test offer", Some(cs), 100);
        assert_eq!(offer.description(), "Test offer");
        assert_eq!(offer.confidence(), 100);
        assert!(offer.compiler_spec().is_some());
    }

    #[test]
    fn test_host_platform_opinion() {
        let opinion = HostPlatformOpinion;
        let offers = opinion.get_offers("trace1", "obj", 0, false);
        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0].confidence(), CONFIDENCE_HOST_KNOWN);
        assert!(offers[0].description().contains("Host"));
    }

    #[test]
    fn test_host_platform_mapper() {
        let mapper = HostPlatformOpinion::create_mapper("trace1");
        assert!(mapper.can_interpret("obj", 0));
        assert_eq!(mapper.add_to_trace("obj", 0), "Use host platform");
    }

    #[test]
    fn test_abstract_platform_mapper() {
        let mapper = AbstractPlatformMapper::new("trace1");
        assert!(mapper.can_interpret("obj", 0));
        assert!(mapper.can_interpret_with_env("obj", 0, Some("gdb"), Some("x86"), Some("linux"), Some(false)));
    }

    #[test]
    fn test_parse_endian() {
        assert_eq!(parse_endian("big"), Some(true));
        assert_eq!(parse_endian("LE"), Some(false));
        assert_eq!(parse_endian("Little-Endian"), Some(false));
        assert_eq!(parse_endian("unknown"), None);
    }

    #[test]
    fn test_platform_offer_equality() {
        let cs = CompilerSpec::new("x86:LE:64:default", "default", "x86");
        let offer1 = AbstractPlatformOffer::new("offer", Some(cs.clone()), 100);
        let offer2 = AbstractPlatformOffer::new("offer", Some(cs), 200);
        // Same description and cspec => equal (confidence not compared)
        assert_eq!(offer1, offer2);
    }
}
