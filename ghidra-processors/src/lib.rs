//! Ghidra Rust - Processor definitions.
//!
//! This crate provides processor-specific definitions including:
//! - Register definitions for each architecture
//! - Instruction mnemonics and encoding helpers
//! - Processor module trait for architecture plug-ins
//! - A centralized [`ProcessorRegistry`] for runtime processor lookup

pub mod aarch64;
pub mod arm;
pub mod avr;
pub mod common;

pub mod m68000;

#[path = "mcs51/mod.rs"]
pub mod m8051;

pub mod cp1600;
pub mod ebpf;
pub mod hcs12;
pub mod hexagon;
pub mod jvm;
pub mod loongarch;
pub mod mips;
pub mod msp430;
pub mod nds32;
pub mod pa_risc;
pub mod pic;
pub mod powerpc;
pub mod riscv;
pub mod sparc;
pub mod superh;
pub mod toy;
pub mod tricore;
pub mod v850;
pub mod x86;
pub mod xtensa;
pub mod z80;

use crate::common::{Language, ProcessorModule, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Processor entry — concrete data extracted from each module
// ---------------------------------------------------------------------------

/// A concrete snapshot of a registered processor's static metadata.
///
/// Populated from the [`ProcessorModule`] trait at registration time so that
/// the registry can hand out references without requiring trait objects
/// (noting that the [`ProcessorModule`] trait uses associated functions, not
/// instance methods, and is therefore not object-safe).
#[derive(Debug, Clone)]
pub struct ProcessorEntry {
    /// Human-readable processor name.
    pub name: String,
    /// The processor's register bank.
    pub registers: RegisterBank,
    /// Supported language/compiler variants.
    pub languages: Vec<Language>,
    /// Supported instruction mnemonics.
    pub instructions: Vec<InstructionMnemonic>,
}

impl ProcessorEntry {
    /// Create a new entry from any type implementing [`ProcessorModule`].
    pub fn from_module<T: ProcessorModule>() -> Self {
        Self {
            name: T::name().to_string(),
            registers: T::registers(),
            languages: T::languages(),
            instructions: T::instructions(),
        }
    }
}

// ---------------------------------------------------------------------------
// Processor registry
// ---------------------------------------------------------------------------

/// A centralized registry of all processor modules.
///
/// Provides runtime lookup of processors by name, listing of all registered
/// processors, and architecture detection from binary data.
pub struct ProcessorRegistry {
    processors: HashMap<String, ProcessorEntry>,
}

impl ProcessorRegistry {
    /// Create a new, empty processor registry.
    pub fn new() -> Self {
        Self {
            processors: HashMap::new(),
        }
    }

    /// Register a single processor by extracting its metadata from its
    /// [`ProcessorModule`] implementation.
    fn register<T: ProcessorModule + 'static>(&mut self) {
        let entry = ProcessorEntry::from_module::<T>();
        self.processors.insert(entry.name.clone(), entry);
    }

    /// Register all known processor modules.
    #[allow(unused_mut)]
    pub fn register_all(&mut self) {
        self.register::<aarch64::Aarch64Module>();
        self.register::<arm::ArmModule>();
        self.register::<avr::AvrProcessor>();
        self.register::<cp1600::Cp1600Processor>();
        self.register::<ebpf::EbpfProcessor>();
        self.register::<hcs12::Hcs12Processor>();
        self.register::<hexagon::HexagonProcessor>();
        self.register::<jvm::JvmModule>();
        self.register::<loongarch::LoongArchProcessor>();
        self.register::<m68000::M68000Module>();
        self.register::<m8051::M8051Processor>();
        self.register::<mips::MipsModule>();
        self.register::<msp430::Msp430Processor>();
        self.register::<nds32::Nds32Processor>();
        self.register::<pa_risc::PaRiscProcessor>();
        self.register::<pic::PicProcessor>();
        self.register::<powerpc::PowerPcModule>();
        self.register::<riscv::RiscVModule>();
        self.register::<sparc::SparcModule>();
        self.register::<superh::SuperHProcessor>();
        self.register::<toy::ToyProcessor>();
        self.register::<tricore::TricoreProcessor>();
        self.register::<v850::V850Processor>();
        self.register::<xtensa::XtensaProcessor>();
        self.register::<z80::Z80Processor>();
        // NOTE: x86 uses a different module organisation and is registered
        // via its own ProcessorModule adapter (see x86 module).
    }

    /// Look up a processor by its name (case-sensitive).
    pub fn get(&self, name: &str) -> Option<&ProcessorEntry> {
        self.processors.get(name)
    }

    /// Return a sorted list of all registered processor names.
    pub fn list(&self) -> Vec<String> {
        let mut names: Vec<String> = self.processors.keys().cloned().collect();
        names.sort();
        names
    }

    /// Attempt to detect the architecture of a binary from its header bytes.
    ///
    /// Returns the name of the best-matching processor, or `None` if the
    /// architecture could not be determined.
    pub fn detect_arch(data: &[u8]) -> Option<String> {
        if data.len() < 4 {
            return None;
        }

        // ELF magic
        if &data[0..4] == b"\x7fELF" {
            return Self::detect_elf_arch(data);
        }

        // PE magic
        if &data[0..2] == b"MZ" {
            return Self::detect_pe_arch(data);
        }

        // Mach-O magic
        if data.len() >= 4 {
            let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            match magic {
                0xFEEDFACE | 0xFEEDFACF | 0xCEFAEDFE | 0xCFFAEDFE => {
                    return Self::detect_macho_arch(data);
                }
                _ => {}
            }
        }

        // Java class file
        if data.len() >= 4 && &data[0..4] == b"\xCA\xFE\xBA\xBE" {
            return Some("JVM (Java Virtual Machine)".to_string());
        }

        None
    }

    /// Attempt to detect architecture from an ELF header.
    fn detect_elf_arch(data: &[u8]) -> Option<String> {
        if data.len() < 20 {
            return None;
        }
        let _class = data[4];
        let _endian = data[5];
        let machine = if data[5] == 1 {
            u16::from_le_bytes([data[18], data[19]])
        } else {
            u16::from_be_bytes([data[18], data[19]])
        };

        match machine {
            0x03 => Some("x86".to_string()),
            0x3E => Some("x86".to_string()),
            0x28 => Some("ARM".to_string()),
            0xB7 => Some("AARCH64".to_string()),
            0x08 => Some("MIPS".to_string()),
            0x14 => Some("PowerPC".to_string()),
            0x15 => Some("PowerPC".to_string()),
            0xF3 => Some("RISC-V".to_string()),
            0x02 => Some("SPARC".to_string()),
            0x2B => Some("SPARC".to_string()),
            0x2A => Some("SuperH".to_string()),
            0x87 => Some("Renesas V850".to_string()),
            0x4C => Some("Andes NDS32 (AndeStar V3)".to_string()),
            0x102 => Some("LoongArch".to_string()),
            0xF7 => Some("eBPF (extended Berkeley Packet Filter)".to_string()),
            0x4B => Some("M68000".to_string()),
            0xDC => Some("Z80".to_string()),
            0x69 => Some("AVR".to_string()),
            0x6A => Some("MSP430".to_string()),
            0xA5 => Some("Hexagon".to_string()),
            0xBC => Some("Xtensa".to_string()),
            0x2C => Some("Tricore".to_string()),
            _ => None,
        }
    }

    /// Attempt to detect architecture from a PE header.
    fn detect_pe_arch(data: &[u8]) -> Option<String> {
        if data.len() < 64 {
            return None;
        }
        let pe_offset =
            u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
        if data.len() < pe_offset + 6 {
            return None;
        }
        if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return None;
        }
        let machine =
            u16::from_le_bytes([data[pe_offset + 4], data[pe_offset + 5]]);

        match machine {
            0x014C => Some("x86".to_string()),
            0x0200 => Some("x86".to_string()),
            0x8664 => Some("x86".to_string()),
            0x01C0 => Some("ARM".to_string()),
            0x01C4 => Some("ARM".to_string()),
            0xAA64 => Some("AARCH64".to_string()),
            0x0166 => Some("MIPS".to_string()),
            0x0168 => Some("MIPS".to_string()),
            0x01F0 => Some("PowerPC".to_string()),
            0x01F1 => Some("PowerPC".to_string()),
            0x5064 => Some("RISC-V".to_string()),
            0x5032 => Some("RISC-V".to_string()),
            0x9041 => Some("M68000".to_string()),
            0x01C2 => Some("SuperH".to_string()),
            0x01A2 => Some("SuperH".to_string()),
            0x01A6 => Some("SuperH".to_string()),
            _ => None,
        }
    }

    /// Attempt to detect architecture from a Mach-O header.
    fn detect_macho_arch(data: &[u8]) -> Option<String> {
        if data.len() < 8 {
            return None;
        }
        let cputype = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let base_type = cputype & 0x00FF_FFFF;

        match base_type {
            0x07 => Some("x86".to_string()),
            0x0C => Some("ARM".to_string()),
            0x12 => Some("PowerPC".to_string()),
            _ => {
                // Check for 64-bit variants
                match cputype {
                    0x0100_0007 => Some("x86".to_string()),
                    0x0100_000C => Some("AARCH64".to_string()),
                    0x0100_0012 => Some("PowerPC".to_string()),
                    _ => None,
                }
            }
        }
    }
}

impl Default for ProcessorRegistry {
    fn default() -> Self {
        let mut registry = Self::new();
        registry.register_all();
        registry
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_new() {
        let registry = ProcessorRegistry::new();
        assert!(registry.list().is_empty());
    }

    #[test]
    fn test_registry_register_all() {
        let mut registry = ProcessorRegistry::new();
        registry.register_all();
        let names = registry.list();
        assert!(
            names.len() >= 20,
            "Expected at least 20 processors, got {}: {:?}",
            names.len(),
            names
        );
    }

    #[test]
    fn test_registry_get() {
        let mut registry = ProcessorRegistry::new();
        registry.register_all();
        assert!(registry.get("RISC-V").is_some());
        assert!(registry
            .get("eBPF (extended Berkeley Packet Filter)")
            .is_some());
        assert!(registry.get("LoongArch").is_some());
        assert!(registry.get("SPARC").is_some());
        assert!(registry.get("JVM").is_some());
        assert!(registry.get("Toy BISA (Basic Instruction Set Architecture)").is_some());
        assert!(registry.get("NonexistentProcessor").is_none());
    }

    #[test]
    fn test_registry_list_sorted() {
        let mut registry = ProcessorRegistry::new();
        registry.register_all();
        let names = registry.list();
        for window in names.windows(2) {
            assert!(window[0] <= window[1], "Names not sorted: {:?}", window);
        }
    }

    #[test]
    fn test_registry_default() {
        let registry = ProcessorRegistry::default();
        let names = registry.list();
        assert!(!names.is_empty());
    }

    #[test]
    fn test_registry_entry_content() {
        let mut registry = ProcessorRegistry::new();
        registry.register_all();

        // Verify eBPF processor entry has correct data
        let ebpf = registry
            .get("eBPF (extended Berkeley Packet Filter)")
            .unwrap();
        assert!(ebpf.registers.len() > 10);
        assert_eq!(ebpf.languages.len(), 1);
        assert!(!ebpf.instructions.is_empty());

        // Verify LoongArch
        let la = registry.get("LoongArch").unwrap();
        assert!(la.registers.len() > 50);
        assert!(la.languages.len() >= 2);

        // Verify Toy
        let toy = registry
            .get("Toy BISA (Basic Instruction Set Architecture)")
            .unwrap();
        assert!(!toy.registers.is_empty());
        assert!(toy.languages.len() >= 2);
    }

    #[test]
    fn test_detect_elf_x86_64() {
        let elf: Vec<u8> = vec![
            0x7F, b'E', b'L', b'F',
            2,      1,      1,
            0, 0,   0, 0, 0, 0, 0, 0, 0,
            0, 0,   0x3E, 0x00,
            0, 0, 0, 0,
        ];
        let arch = ProcessorRegistry::detect_arch(&elf);
        assert_eq!(arch, Some("x86".to_string()));
    }

    #[test]
    fn test_detect_pe_x86() {
        let mut pe: Vec<u8> = vec![0; 128];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[60] = 64;
        pe[64] = b'P';
        pe[65] = b'E';
        pe[66] = 0;
        pe[67] = 0;
        pe[68] = 0x4C;
        pe[69] = 0x01;
        let arch = ProcessorRegistry::detect_arch(&pe);
        assert_eq!(arch, Some("x86".to_string()));
    }

    #[test]
    fn test_detect_java_class() {
        let class: Vec<u8> =
            vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34];
        let arch = ProcessorRegistry::detect_arch(&class);
        assert_eq!(arch, Some("JVM".to_string()));
    }

    #[test]
    fn test_detect_unknown() {
        let data: Vec<u8> = vec![0x00, 0x01, 0x02, 0x03];
        let arch = ProcessorRegistry::detect_arch(&data);
        assert_eq!(arch, None);
    }

    #[test]
    fn test_detect_short_data() {
        let data: Vec<u8> = vec![0x00];
        let arch = ProcessorRegistry::detect_arch(&data);
        assert_eq!(arch, None);
    }
}
