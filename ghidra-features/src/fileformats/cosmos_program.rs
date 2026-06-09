//! Cosmos SDK program format parser.
//!
//! This module provides support for parsing Solana BPF/SBF programs
//! compiled with the Cosmos SDK toolchain, as well as generic ELF-based
//! on-chain program formats used by Cosmos-ecosystem blockchains.
//!
//! Cosmos programs are typically shared-object ELF files deployed to
//! on-chain virtual machines.  This module provides structures and
//! helpers for identifying and analysing such programs.
//!
//! # References
//!
//! - [Cosmos SDK documentation](https://docs.cosmos.network/)
//! - [Solana BPF/SBF loader](https://docs.solana.com/developing/on-chain-programs/overview)
//! - Ghidra's analysis of ELF-based on-chain programs

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// BPF/SBF ELF machine type (EM_BPF).
pub const EM_BPF: u16 = 0x00F7;

/// Solana SBF v2 magic (first 4 bytes of a deployed Solana program).
pub const SOLANA_MAGIC: [u8; 4] = [0x7F, 0x42, 0x50, 0x46]; // "\x7FBPF"

/// Solana SBF v2 ELF machine type.
pub const EM_SBF: u16 = 0x0100;

/// Cosmos WASM magic ("\0asm").
pub const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D];

/// WASM version (1).
pub const WASM_VERSION: u32 = 1;

// ═══════════════════════════════════════════════════════════════════════════════════
// Cosmos Program Type
// ═══════════════════════════════════════════════════════════════════════════════════

/// The type of Cosmos/Solana program detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CosmosProgramType {
    /// Solana BPF/SBF ELF program.
    SolanaBpf,
    /// Solana SBF v2 ELF program.
    SolanaSbf,
    /// Cosmos WASM (WebAssembly) smart contract.
    CosmosWasm,
    /// Generic on-chain ELF program (e.g., NEAR, CosmWasm native).
    GenericElf,
    /// Unknown or not a Cosmos program.
    Unknown,
}

impl std::fmt::Display for CosmosProgramType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SolanaBpf => write!(f, "Solana BPF"),
            Self::SolanaSbf => write!(f, "Solana SBF"),
            Self::CosmosWasm => write!(f, "Cosmos WASM"),
            Self::GenericElf => write!(f, "Generic ELF"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Cosmos Program Info
// ═══════════════════════════════════════════════════════════════════════════════════

/// Metadata about a detected Cosmos/Solana program.
#[derive(Debug, Clone)]
pub struct CosmosProgramInfo {
    /// The detected program type.
    pub program_type: CosmosProgramType,
    /// ELF machine type (if applicable).
    pub elf_machine: Option<u16>,
    /// ELF entry point address (if applicable).
    pub entry_point: Option<u64>,
    /// ELF class (32 or 64 bit).
    pub elf_class: Option<u8>,
    /// ELF data encoding (1 = little-endian, 2 = big-endian).
    pub elf_data: Option<u8>,
    /// WASM version (if applicable).
    pub wasm_version: Option<u32>,
    /// Program size in bytes.
    pub size: u64,
}

impl CosmosProgramInfo {
    /// Detect the program type from raw bytes.
    pub fn detect(data: &[u8]) -> Self {
        if data.is_empty() {
            return CosmosProgramInfo {
                program_type: CosmosProgramType::Unknown,
                elf_machine: None,
                entry_point: None,
                elf_class: None,
                elf_data: None,
                wasm_version: None,
                size: 0,
            };
        }

        // Check for WASM magic
        if data.len() >= 8 && data[0..4] == WASM_MAGIC {
            let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
            if version == WASM_VERSION {
                return CosmosProgramInfo {
                    program_type: CosmosProgramType::CosmosWasm,
                    elf_machine: None,
                    entry_point: None,
                    elf_class: None,
                    elf_data: None,
                    wasm_version: Some(version),
                    size: data.len() as u64,
                };
            }
        }

        // Check for ELF magic
        if data.len() >= 16 && data[0..4] == [0x7F, b'E', b'L', b'F'] {
            let elf_class = data[4];
            let elf_data = data[5];
            let elf_machine = u16::from_le_bytes(data[18..20].try_into().unwrap());

            // Read entry point (offset 24 for ELF64, offset 24 for ELF32 as well)
            let entry_point = if elf_class == 2 {
                // 64-bit
                Some(u64::from_le_bytes(data[24..32].try_into().unwrap()))
            } else {
                // 32-bit
                Some(u32::from_le_bytes(data[24..28].try_into().unwrap()) as u64)
            };

            let program_type = match elf_machine {
                EM_BPF => CosmosProgramType::SolanaBpf,
                EM_SBF => CosmosProgramType::SolanaSbf,
                _ => CosmosProgramType::GenericElf,
            };

            return CosmosProgramInfo {
                program_type,
                elf_machine: Some(elf_machine),
                entry_point,
                elf_class: Some(elf_class),
                elf_data: Some(elf_data),
                wasm_version: None,
                size: data.len() as u64,
            };
        }

        CosmosProgramInfo {
            program_type: CosmosProgramType::Unknown,
            elf_machine: None,
            entry_point: None,
            elf_class: None,
            elf_data: None,
            wasm_version: None,
            size: data.len() as u64,
        }
    }

    /// Returns true if the program was detected as a known Cosmos/Solana format.
    pub fn is_known(&self) -> bool {
        self.program_type != CosmosProgramType::Unknown
    }

    /// Returns true if the program is an ELF binary.
    pub fn is_elf(&self) -> bool {
        self.elf_class.is_some()
    }

    /// Returns true if the program is a 64-bit ELF.
    pub fn is_64bit(&self) -> bool {
        self.elf_class == Some(2)
    }

    /// Returns true if the program is little-endian.
    pub fn is_little_endian(&self) -> bool {
        self.elf_data == Some(1)
    }

    /// Returns a human-readable description of the detected program.
    pub fn description(&self) -> String {
        match self.program_type {
            CosmosProgramType::SolanaBpf => {
                format!("Solana BPF program ({} bytes)", self.size)
            }
            CosmosProgramType::SolanaSbf => {
                format!("Solana SBF program ({} bytes)", self.size)
            }
            CosmosProgramType::CosmosWasm => {
                format!(
                    "Cosmos WASM contract v{} ({} bytes)",
                    self.wasm_version.unwrap_or(0),
                    self.size
                )
            }
            CosmosProgramType::GenericElf => {
                let bits = if self.is_64bit() { "64" } else { "32" };
                format!(
                    "Generic {}-bit ELF program, machine 0x{:04x} ({} bytes)",
                    bits,
                    self.elf_machine.unwrap_or(0),
                    self.size
                )
            }
            CosmosProgramType::Unknown => "Unknown format".to_string(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// WASM Section Types (for Cosmos WASM contracts)
// ═══════════════════════════════════════════════════════════════════════════════════

/// WASM section IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WasmSectionType {
    /// Custom section (name, data).
    Custom = 0,
    /// Function type signatures.
    Type = 1,
    /// Import declarations.
    Import = 2,
    /// Function declarations.
    Function = 3,
    /// Table declarations.
    Table = 4,
    /// Memory declarations.
    Memory = 5,
    /// Global declarations.
    Global = 6,
    /// Export declarations.
    Export = 7,
    /// Start function declaration.
    Start = 8,
    /// Element declarations.
    Element = 9,
    /// Code section (function bodies).
    Code = 10,
    /// Data section.
    Data = 11,
    /// Data count section.
    DataCount = 12,
    /// Unknown section type.
    Unknown(u8),
}

impl WasmSectionType {
    /// Convert a raw byte to a `WasmSectionType`.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::Custom,
            1 => Self::Type,
            2 => Self::Import,
            3 => Self::Function,
            4 => Self::Table,
            5 => Self::Memory,
            6 => Self::Global,
            7 => Self::Export,
            8 => Self::Start,
            9 => Self::Element,
            10 => Self::Code,
            11 => Self::Data,
            12 => Self::DataCount,
            other => Self::Unknown(other),
        }
    }

    /// Returns a human-readable name for the section type.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Custom => "custom",
            Self::Type => "type",
            Self::Import => "import",
            Self::Function => "function",
            Self::Table => "table",
            Self::Memory => "memory",
            Self::Global => "global",
            Self::Export => "export",
            Self::Start => "start",
            Self::Element => "element",
            Self::Code => "code",
            Self::Data => "data",
            Self::DataCount => "data_count",
            Self::Unknown(_) => "unknown",
        }
    }
}

/// A WASM section descriptor.
#[derive(Debug, Clone)]
pub struct WasmSection {
    /// The section type.
    pub section_type: WasmSectionType,
    /// Section payload size in bytes.
    pub size: u32,
    /// File offset of the section payload.
    pub offset: u64,
}

// ═══════════════════════════════════════════════════════════════════════════════════
// WASM Parser
// ═══════════════════════════════════════════════════════════════════════════════════

/// Parse WASM sections from a byte slice.
///
/// Returns a list of section descriptors.  This is a minimal parser
/// that reads section headers but does not parse section payloads.
pub fn parse_wasm_sections(data: &[u8]) -> Result<Vec<WasmSection>, String> {
    if data.len() < 8 {
        return Err("Data too short for WASM header".to_string());
    }

    if data[0..4] != WASM_MAGIC {
        return Err("Invalid WASM magic".to_string());
    }

    let _version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let mut sections = Vec::new();
    let mut pos = 8;

    while pos < data.len() {
        let section_id = data[pos];
        pos += 1;

        // Read LEB128-encoded section size
        let (section_size, new_pos) = read_leb128_u32(data, pos)?;
        pos = new_pos;

        let section_type = WasmSectionType::from_byte(section_id);
        sections.push(WasmSection {
            section_type,
            size: section_size,
            offset: pos as u64,
        });

        // Skip to the next section
        pos = pos.saturating_add(section_size as usize);
    }

    Ok(sections)
}

/// Read an unsigned LEB128-encoded u32 from `data` at `pos`.
fn read_leb128_u32(data: &[u8], mut pos: usize) -> Result<(u32, usize), String> {
    let mut result: u32 = 0;
    let mut shift = 0;

    loop {
        if pos >= data.len() {
            return Err("LEB128: unexpected end of data".to_string());
        }
        let byte = data[pos];
        pos += 1;
        result |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 {
            return Ok((result, pos));
        }
        shift += 7;
        if shift >= 32 {
            return Err("LEB128: too many bytes for u32".to_string());
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_wasm() {
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(&WASM_MAGIC);
        data[4..8].copy_from_slice(&1u32.to_le_bytes());

        let info = CosmosProgramInfo::detect(&data);
        assert_eq!(info.program_type, CosmosProgramType::CosmosWasm);
        assert!(info.is_known());
        assert!(!info.is_elf());
    }

    #[test]
    fn test_detect_solana_bpf_elf() {
        let mut data = vec![0u8; 64];
        // ELF magic
        data[0] = 0x7F;
        data[1] = b'E';
        data[2] = b'L';
        data[3] = b'F';
        // 64-bit, little-endian
        data[4] = 2; // ELFCLASS64
        data[5] = 1; // ELFDATA2LSB
        // e_machine at offset 18
        data[18..20].copy_from_slice(&EM_BPF.to_le_bytes());

        let info = CosmosProgramInfo::detect(&data);
        assert_eq!(info.program_type, CosmosProgramType::SolanaBpf);
        assert!(info.is_elf());
        assert!(info.is_64bit());
        assert!(info.is_little_endian());
    }

    #[test]
    fn test_detect_solana_sbf_elf() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        data[4] = 2;
        data[5] = 1;
        data[18..20].copy_from_slice(&EM_SBF.to_le_bytes());

        let info = CosmosProgramInfo::detect(&data);
        assert_eq!(info.program_type, CosmosProgramType::SolanaSbf);
    }

    #[test]
    fn test_detect_generic_elf() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        data[4] = 1; // 32-bit
        data[5] = 1;
        data[18..20].copy_from_slice(&3u16.to_le_bytes()); // EM_386

        let info = CosmosProgramInfo::detect(&data);
        assert_eq!(info.program_type, CosmosProgramType::GenericElf);
        assert!(info.is_elf());
        assert!(!info.is_64bit());
    }

    #[test]
    fn test_detect_unknown() {
        let data = b"this is not a program";
        let info = CosmosProgramInfo::detect(data);
        assert_eq!(info.program_type, CosmosProgramType::Unknown);
        assert!(!info.is_known());
    }

    #[test]
    fn test_detect_empty() {
        let data = &[];
        let info = CosmosProgramInfo::detect(data);
        assert_eq!(info.program_type, CosmosProgramType::Unknown);
    }

    #[test]
    fn test_program_description() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&WASM_MAGIC);
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        let info = CosmosProgramInfo::detect(&data);
        assert!(info.description().contains("WASM"));
    }

    #[test]
    fn test_wasm_section_type_from_byte() {
        assert_eq!(WasmSectionType::from_byte(0), WasmSectionType::Custom);
        assert_eq!(WasmSectionType::from_byte(10), WasmSectionType::Code);
        assert_eq!(WasmSectionType::from_byte(255), WasmSectionType::Unknown(255));
    }

    #[test]
    fn test_wasm_section_type_name() {
        assert_eq!(WasmSectionType::Code.name(), "code");
        assert_eq!(WasmSectionType::Data.name(), "data");
        assert_eq!(WasmSectionType::Unknown(99).name(), "unknown");
    }

    #[test]
    fn test_parse_wasm_sections() {
        // Minimal WASM binary: magic + version + one empty code section
        let mut data = Vec::new();
        data.extend_from_slice(&WASM_MAGIC);
        data.extend_from_slice(&1u32.to_le_bytes());
        // Section: type=10 (code), size=0
        data.push(10); // code section
        data.push(0); // size = 0

        let sections = parse_wasm_sections(&data).unwrap();
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].section_type, WasmSectionType::Code);
        assert_eq!(sections[0].size, 0);
    }

    #[test]
    fn test_parse_wasm_sections_invalid_magic() {
        let data = vec![0u8; 16];
        assert!(parse_wasm_sections(&data).is_err());
    }
}
