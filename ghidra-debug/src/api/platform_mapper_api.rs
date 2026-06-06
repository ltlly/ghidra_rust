//! Platform mapper and platform opinion API types.
//!
//! Ported from Ghidra's `ghidra.debug.api.platform` package:
//! - `DebuggerPlatformMapper`: Interface for interpreting a trace according to
//!   a chosen platform (language, compiler spec, data organization).
//! - `DisassemblyResult`: Result of a disassembly operation.
//! - `DebuggerPlatformOpinion`: Extension point for back-end debugger platform
//!   opinions (already in platform_opinion but API-level types are here).
//! - `DebuggerPlatformOffer`: A platform mapping offer.
//!
//! Platform selection determines the language, compiler spec, and data organization
//! used for disassembly and data interpretation in the trace.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// An object for interpreting a trace according to a chosen platform.
///
/// Ported from `DebuggerPlatformMapper`. Platform selection allows the mapper
/// to choose relevant languages, compiler specifications, data organization, etc.,
/// based on the current debugger context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformMapperConfig {
    /// The language ID for this platform.
    pub language_id: String,
    /// The compiler spec ID.
    pub compiler_spec_id: String,
    /// Whether this is a host (default) platform.
    pub is_host: bool,
    /// The display name for this platform.
    pub display_name: String,
    /// The processor name.
    pub processor: String,
    /// The endianness.
    pub endianness: Endianness,
    /// The pointer size in bytes.
    pub pointer_size: u32,
    /// Address space descriptions.
    pub address_spaces: Vec<AddressSpaceDesc>,
    /// Register mappings from back-end register names to Ghidra register names.
    pub register_mappings: BTreeMap<String, String>,
}

/// Endianness of a platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endianness {
    /// Little-endian byte order.
    Little,
    /// Big-endian byte order.
    Big,
}

/// Description of an address space in a platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressSpaceDesc {
    /// The space name (e.g., "ram", "register").
    pub name: String,
    /// The address size in bytes.
    pub size: u32,
    /// Whether this space is memory-mapped.
    pub is_memory: bool,
    /// Whether this is a register space.
    pub is_register: bool,
}

/// Result of a disassembly operation.
///
/// Ported from `DisassemblyResult`. Captures the result of attempting to
/// disassemble bytes at an address in a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyResult {
    /// The address at which disassembly was attempted.
    pub address: u64,
    /// The disassembled mnemonic.
    pub mnemonic: Option<String>,
    /// The full disassembly text.
    pub full_text: Option<String>,
    /// The length of the disassembled instruction in bytes.
    pub length: Option<u32>,
    /// Whether disassembly was successful.
    pub success: bool,
    /// An error message, if disassembly failed.
    pub error: Option<String>,
    /// The language ID used for disassembly.
    pub language_id: String,
    /// Operands extracted from the instruction.
    pub operands: Vec<String>,
    /// Flow type (call, jump, return, etc.).
    pub flow_type: FlowType,
}

/// Types of instruction flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowType {
    /// Fall-through to next instruction.
    FallThrough,
    /// Unconditional branch/jump.
    Jump,
    /// Conditional branch.
    ConditionalJump,
    /// Function call.
    Call,
    /// Return from function.
    Return,
    /// Call that returns (call + fall-through).
    CallFallThrough,
    /// Indirect jump.
    IndirectJump,
    /// Indirect call.
    IndirectCall,
    /// Other/unknown flow.
    Other,
}

impl FlowType {
    /// Check if this flow type is a branch (jump).
    pub fn is_jump(&self) -> bool {
        matches!(self, Self::Jump | Self::ConditionalJump | Self::IndirectJump)
    }

    /// Check if this flow type is a call.
    pub fn is_call(&self) -> bool {
        matches!(self, Self::Call | Self::CallFallThrough | Self::IndirectCall)
    }

    /// Check if this flow type is a return.
    pub fn is_return(&self) -> bool {
        matches!(self, Self::Return)
    }
}

impl DisassemblyResult {
    /// Create a successful disassembly result.
    pub fn success(
        address: u64,
        mnemonic: &str,
        full_text: &str,
        length: u32,
        language_id: &str,
    ) -> Self {
        Self {
            address,
            mnemonic: Some(mnemonic.to_string()),
            full_text: Some(full_text.to_string()),
            length: Some(length),
            success: true,
            error: None,
            language_id: language_id.to_string(),
            operands: Vec::new(),
            flow_type: FlowType::FallThrough,
        }
    }

    /// Create a failed disassembly result.
    pub fn error(address: u64, error: &str, language_id: &str) -> Self {
        Self {
            address,
            mnemonic: None,
            full_text: None,
            length: None,
            success: false,
            error: Some(error.to_string()),
            language_id: language_id.to_string(),
            operands: Vec::new(),
            flow_type: FlowType::Other,
        }
    }
}

/// A platform mapping offer from a platform opinion.
///
/// Ported from `DebuggerPlatformOffer`. Represents a suggestion for how
/// to map a debug target's platform to Ghidra's language/compiler spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformOffer {
    /// The language ID.
    pub language_id: String,
    /// The compiler spec ID.
    pub compiler_spec_id: String,
    /// A confidence score (0.0 to 1.0).
    pub confidence: f64,
    /// The source of this offer (e.g., the opinion provider).
    pub source: String,
    /// A description of why this offer was made.
    pub reason: Option<String>,
    /// Whether this is the recommended offer.
    pub is_recommended: bool,
}

impl PlatformOffer {
    /// Create a new platform offer.
    pub fn new(language_id: &str, compiler_spec_id: &str, confidence: f64, source: &str) -> Self {
        Self {
            language_id: language_id.to_string(),
            compiler_spec_id: compiler_spec_id.to_string(),
            confidence,
            source: source.to_string(),
            reason: None,
            is_recommended: false,
        }
    }

    /// Set the reason.
    pub fn with_reason(mut self, reason: &str) -> Self {
        self.reason = Some(reason.to_string());
        self
    }

    /// Mark as recommended.
    pub fn as_recommended(mut self) -> Self {
        self.is_recommended = true;
        self
    }
}

/// A platform opinion from a back-end debugger.
///
/// Ported from `DebuggerPlatformOpinion`. Platform opinions are extension
/// points that allow different debug backends to suggest platform mappings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformOpinionConfig {
    /// The opinion name.
    pub name: String,
    /// The back-end debugger type this opinion applies to (e.g., "gdb", "lldb").
    pub debugger_type: String,
    /// A description of what this opinion does.
    pub description: Option<String>,
    /// The offers this opinion can make.
    pub offers: Vec<PlatformOffer>,
}

impl PlatformOpinionConfig {
    /// Create a new platform opinion.
    pub fn new(name: &str, debugger_type: &str) -> Self {
        Self {
            name: name.to_string(),
            debugger_type: debugger_type.to_string(),
            description: None,
            offers: Vec::new(),
        }
    }

    /// Add an offer.
    pub fn with_offer(mut self, offer: PlatformOffer) -> Self {
        self.offers.push(offer);
        self
    }

    /// Get the recommended offer, if any.
    pub fn recommended_offer(&self) -> Option<&PlatformOffer> {
        self.offers.iter().find(|o| o.is_recommended)
    }

    /// Get the best offer (highest confidence).
    pub fn best_offer(&self) -> Option<&PlatformOffer> {
        self.offers
            .iter()
            .max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap_or(std::cmp::Ordering::Equal))
    }
}

/// Register mapping entry for a platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterMappingEntry {
    /// The back-end register name.
    pub backend_name: String,
    /// The Ghidra register name.
    pub ghidra_name: String,
    /// The bit offset within the register.
    pub bit_offset: u32,
    /// The bit length.
    pub bit_length: u32,
}

impl RegisterMappingEntry {
    /// Create a new register mapping.
    pub fn new(backend: &str, ghidra: &str, bit_offset: u32, bit_length: u32) -> Self {
        Self {
            backend_name: backend.to_string(),
            ghidra_name: ghidra.to_string(),
            bit_offset,
            bit_length,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_mapper_config() {
        let config = PlatformMapperConfig {
            language_id: "x86:LE:64:default".to_string(),
            compiler_spec_id: "default".to_string(),
            is_host: true,
            display_name: "x86-64".to_string(),
            processor: "x86".to_string(),
            endianness: Endianness::Little,
            pointer_size: 8,
            address_spaces: vec![],
            register_mappings: BTreeMap::new(),
        };

        assert_eq!(config.pointer_size, 8);
        assert_eq!(config.endianness, Endianness::Little);
    }

    #[test]
    fn test_disassembly_result_success() {
        let result = DisassemblyResult::success(
            0x401000,
            "MOV",
            "MOV EAX, EBX",
            2,
            "x86:LE:32:default",
        );

        assert!(result.success);
        assert_eq!(result.mnemonic.as_deref(), Some("MOV"));
        assert_eq!(result.length, Some(2));
    }

    #[test]
    fn test_disassembly_result_error() {
        let result = DisassemblyResult::error(0x401000, "bad bytes", "x86:LE:32:default");
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_flow_type() {
        assert!(FlowType::Jump.is_jump());
        assert!(!FlowType::Jump.is_call());
        assert!(FlowType::Call.is_call());
        assert!(!FlowType::Call.is_return());
        assert!(FlowType::Return.is_return());
    }

    #[test]
    fn test_platform_offer() {
        let offer = PlatformOffer::new("x86:LE:64:default", "default", 0.9, "gdb-opinion")
            .with_reason("detected x86-64 target")
            .as_recommended();

        assert!(offer.is_recommended);
        assert_eq!(offer.confidence, 0.9);
        assert!(offer.reason.is_some());
    }

    #[test]
    fn test_platform_opinion_config() {
        let opinion = PlatformOpinionConfig::new("GDB x86", "gdb")
            .with_offer(PlatformOffer::new("x86:LE:32:default", "default", 0.8, "gdb"))
            .with_offer(
                PlatformOffer::new("x86:LE:64:default", "default", 0.9, "gdb")
                    .as_recommended(),
            );

        assert_eq!(opinion.offers.len(), 2);
        let best = opinion.best_offer();
        assert!(best.is_some());
        assert_eq!(best.unwrap().language_id, "x86:LE:64:default");

        let rec = opinion.recommended_offer();
        assert!(rec.is_some());
    }

    #[test]
    fn test_register_mapping() {
        let entry = RegisterMappingEntry::new("rax", "RAX", 0, 64);
        assert_eq!(entry.backend_name, "rax");
        assert_eq!(entry.ghidra_name, "RAX");
        assert_eq!(entry.bit_length, 64);
    }

    #[test]
    fn test_address_space_desc() {
        let desc = AddressSpaceDesc {
            name: "ram".to_string(),
            size: 8,
            is_memory: true,
            is_register: false,
        };
        assert!(desc.is_memory);
        assert!(!desc.is_register);
    }
}
