//! Ghidra Rust - Processor definitions.
//!
//! This crate provides processor-specific definitions including:
//! - Register definitions for each architecture
//! - Instruction mnemonics and encoding helpers
//! - Processor module trait for architecture plug-ins
//! - A centralized [`ProcessorRegistry`] for runtime processor lookup
//! - Architecture detection from ELF/PE/Mach-O/Java headers

pub mod aarch64;
pub mod arm;
pub mod avr;
pub mod bpf;
pub mod common;
pub mod cr16;
pub mod dalvik;
pub mod hcs08;

pub mod m68000;
pub mod mc6800;

#[path = "mcs51/mod.rs"]
pub mod m8051;

pub mod mos6502;
pub mod i8085;

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
pub mod superh4;
pub mod toy;
pub mod tricore;
pub mod v850;
pub mod x86;
pub mod xtensa;
pub mod z80;

use crate::common::{Endian, Language, LanguageDescription, Processor, ProcessorModule, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Processor entry
// ---------------------------------------------------------------------------

/// A concrete snapshot of a registered processor's static metadata.
#[derive(Debug, Clone)]
pub struct ProcessorEntry {
    pub name: String,
    pub registers: RegisterBank,
    pub languages: Vec<Language>,
    pub instructions: Vec<InstructionMnemonic>,
    pub description: String,
    pub family: String,
    pub pointer_size: u32,
    pub endian: Endian,
}

impl ProcessorEntry {
    pub fn from_module<T: ProcessorModule>() -> Self {
        Self {
            name: T::name().to_string(),
            registers: T::registers(),
            languages: T::languages(),
            instructions: T::instructions(),
            description: T::description().to_string(),
            family: T::family().to_string(),
            pointer_size: T::default_pointer_size(),
            endian: T::default_endian(),
        }
    }

    pub fn processor(&self) -> Processor {
        Processor::new(&self.name, &self.description, &self.family)
    }

    pub fn language_description(&self) -> LanguageDescription {
        let first = self.languages.first();
        LanguageDescription::new(
            common::LanguageID::new(
                first.map(|l| l.id.clone()).unwrap_or_else(|| "unknown:LE:32:default".to_string()),
            ),
            self.processor(),
            first.map(|l| l.endian).unwrap_or(Endian::Little),
            first.map(|l| l.pointer_size).unwrap_or(32),
            first.map(|l| l.version.clone()).unwrap_or_else(|| "default".to_string()),
            &self.description,
        )
    }
}

// ---------------------------------------------------------------------------
// Processor registry
// ---------------------------------------------------------------------------

/// A centralized registry of all processor modules.
pub struct ProcessorRegistry {
    processors: HashMap<String, ProcessorEntry>,
    lowercase_index: HashMap<String, String>,
    language_id_index: HashMap<String, String>,
}

impl ProcessorRegistry {
    pub fn new() -> Self {
        Self {
            processors: HashMap::new(),
            lowercase_index: HashMap::new(),
            language_id_index: HashMap::new(),
        }
    }

    fn register<T: ProcessorModule + 'static>(&mut self) {
        let entry = ProcessorEntry::from_module::<T>();
        let name = entry.name.clone();
        for lang in &entry.languages {
            self.language_id_index.insert(lang.id.clone(), name.clone());
        }
        self.lowercase_index.insert(entry.name.to_lowercase(), entry.name.clone());
        self.processors.insert(name, entry);
    }

    /// Register all known processor modules (34 processors).
    #[allow(unused_mut)]
    pub fn register_all(&mut self) {
        self.register::<aarch64::Aarch64Module>();
        self.register::<arm::ArmModule>();
        self.register::<avr::AvrProcessor>();
        self.register::<bpf::BpfProcessor>();
        self.register::<cp1600::Cp1600Processor>();
        self.register::<cr16::Cr16cProcessor>();
        self.register::<dalvik::DalvikProcessor>();
        self.register::<ebpf::EbpfProcessor>();
        self.register::<hcs08::Hcs08Processor>();
        self.register::<hcs12::Hcs12Processor>();
        self.register::<hexagon::HexagonProcessor>();
        self.register::<i8085::I8085Processor>();
        self.register::<jvm::JvmModule>();
        self.register::<loongarch::LoongArchProcessor>();
        self.register::<m68000::M68000Module>();
        self.register::<m8051::M8051Processor>();
        self.register::<mc6800::Mc6800Processor>();
        self.register::<mips::MipsModule>();
        self.register::<mos6502::Mos6502Processor>();
        self.register::<msp430::Msp430Processor>();
        self.register::<nds32::Nds32Processor>();
        self.register::<pa_risc::PaRiscProcessor>();
        self.register::<pic::PicProcessor>();
        self.register::<powerpc::PowerPcModule>();
        self.register::<riscv::RiscVModule>();
        self.register::<sparc::SparcModule>();
        self.register::<superh::SuperHProcessor>();
        self.register::<superh4::SuperH4Processor>();
        self.register::<toy::ToyProcessor>();
        self.register::<tricore::TricoreProcessor>();
        self.register::<v850::V850Processor>();
        self.register::<x86::X86Module>();
        self.register::<xtensa::XtensaProcessor>();
        self.register::<z80::Z80Processor>();
    }

    pub fn get(&self, name: &str) -> Option<&ProcessorEntry> { self.processors.get(name) }

    pub fn get_case_insensitive(&self, name: &str) -> Option<&ProcessorEntry> {
        self.lowercase_index.get(&name.to_lowercase()).and_then(|canonical| self.processors.get(canonical))
    }

    pub fn get_by_language_id(&self, lang_id: &str) -> Option<&ProcessorEntry> {
        self.language_id_index.get(lang_id).and_then(|name| self.processors.get(name))
    }

    pub fn list(&self) -> Vec<String> {
        let mut names: Vec<String> = self.processors.keys().cloned().collect();
        names.sort();
        names
    }

    pub fn len(&self) -> usize { self.processors.len() }
    pub fn is_empty(&self) -> bool { self.processors.is_empty() }
    pub fn iter(&self) -> impl Iterator<Item = (&String, &ProcessorEntry)> { self.processors.iter() }

    pub fn processors_in_family(&self, family: &str) -> Vec<&ProcessorEntry> {
        self.processors.values().filter(|e| e.family.eq_ignore_ascii_case(family)).collect()
    }

    pub fn search(&self, query: &str) -> Vec<&ProcessorEntry> {
        let query_lower = query.to_lowercase();
        self.processors.values().filter(|e| {
            e.name.to_lowercase().contains(&query_lower)
                || e.description.to_lowercase().contains(&query_lower)
                || e.family.to_lowercase().contains(&query_lower)
        }).collect()
    }

    // -----------------------------------------------------------------------
    // Architecture detection from binary headers
    // -----------------------------------------------------------------------

    pub fn detect_arch(data: &[u8]) -> Option<String> {
        if data.len() < 4 { return None; }

        if &data[0..4] == b"\x7fELF" { return Self::detect_elf_arch(data); }
        if &data[0..2] == b"MZ" { return Self::detect_pe_arch(data); }

        if data.len() >= 4 {
            let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            match magic {
                0xFEEDFACE | 0xFEEDFACF | 0xCEFAEDFE | 0xCFFAEDFE => {
                    return Self::detect_macho_arch(data);
                }
                _ => {}
            }
        }

        // Java class file (0xCAFEBABE)
        if data.len() >= 4 && &data[0..4] == b"\xCA\xFE\xBA\xBE" { return Some("JVM".to_string()); }

        // Dalvik DEX file
        if data.len() >= 4 && &data[0..4] == b"dex\n" { return Some("Dalvik".to_string()); }

        // Game Boy ROM (Nintendo logo at 0x104)
        if data.len() >= 0x104 + 48 {
            let gb_logo: [u8; 4] = [0xCE, 0xED, 0x66, 0x66];
            if data[0x104..0x108] == gb_logo { return Some("Zilog Z80 / Game Boy LR35902".to_string()); }
        }

        None
    }

    fn detect_elf_arch(data: &[u8]) -> Option<String> {
        if data.len() < 20 { return None; }
        let _class = data[4];
        let _endian = data[5];
        let machine = if data[5] == 1 { u16::from_le_bytes([data[18], data[19]]) } else { u16::from_be_bytes([data[18], data[19]]) };

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
            0x53 => Some("Atmel".to_string()),
            0x6D => Some("PIC".to_string()),
            _ => None,
        }
    }

    fn detect_pe_arch(data: &[u8]) -> Option<String> {
        if data.len() < 64 { return None; }
        let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
        if data.len() < pe_offset + 6 { return None; }
        if &data[pe_offset..pe_offset + 4] != b"PE\0\0" { return None; }
        let machine = u16::from_le_bytes([data[pe_offset + 4], data[pe_offset + 5]]);

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
            0x01A8 => Some("SuperH".to_string()),
            _ => None,
        }
    }

    fn detect_macho_arch(data: &[u8]) -> Option<String> {
        if data.len() < 8 { return None; }
        let magic_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        // Determine endianness from the magic number:
        // LE Mach-O: magic_le == 0xFEEDFACE (32-bit) or 0xFEEDFACF (64-bit)
        // BE Mach-O: magic_be == 0xFEEDFACE (32-bit) or 0xFEEDFACF (64-bit)
        let is_little_endian = matches!(magic_le, 0xFEEDFACE | 0xFEEDFACF);
        let is_big_endian = matches!(magic_le, 0xCEFAEDFE | 0xCFFAEDFE);
        if !is_big_endian && !is_little_endian { return None; }

        let cputype = if is_big_endian {
            u32::from_be_bytes([data[4], data[5], data[6], data[7]])
        } else {
            u32::from_le_bytes([data[4], data[5], data[6], data[7]])
        };
        let base_type_ne = cputype & 0x00FF_FFFF;

        // Check full cputype first for 64-bit variants, then base type.
        match cputype {
            0x0100_0007 => Some("x86".to_string()),     // CPU_TYPE_X86_64
            0x0100_000C => Some("AARCH64".to_string()), // CPU_TYPE_ARM64
            0x0100_0012 => Some("PowerPC".to_string()), // CPU_TYPE_POWERPC64
            _ => {
                match base_type_ne {
                    0x07 => Some("x86".to_string()),
                    0x06 => Some("M68000".to_string()),
                    0x0C => Some("ARM".to_string()),
                    0x12 => Some("PowerPC".to_string()),
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
        assert!(names.len() >= 30, "Expected at least 30 processors, got {}: {:?}", names.len(), names);
    }

    #[test]
    fn test_registry_get() {
        let mut registry = ProcessorRegistry::new();
        registry.register_all();
        assert!(registry.get("RISC-V").is_some());
        assert!(registry.get("eBPF (extended Berkeley Packet Filter)").is_some());
        assert!(registry.get("LoongArch").is_some());
        assert!(registry.get("SPARC").is_some());
        assert!(registry.get("JVM").is_some());
        assert!(registry.get("Toy BISA (Basic Instruction Set Architecture)").is_some());
        assert!(registry.get("x86").is_some());
        assert!(registry.get("AARCH64").is_some());
        assert!(registry.get("ARM").is_some());
        assert!(registry.get("MIPS").is_some());
        assert!(registry.get("PowerPC").is_some());
        assert!(registry.get("NonexistentProcessor").is_none());
    }

    #[test]
    fn test_registry_get_case_insensitive() {
        let mut registry = ProcessorRegistry::new();
        registry.register_all();
        assert!(registry.get_case_insensitive("risc-v").is_some());
        assert!(registry.get_case_insensitive("RISC-V").is_some());
        assert!(registry.get_case_insensitive("X86").is_some());
        assert!(registry.get_case_insensitive("nonexistent").is_none());
    }

    #[test]
    fn test_registry_get_by_language_id() {
        let mut registry = ProcessorRegistry::new();
        registry.register_all();
        assert!(registry.get_by_language_id("x86:LE:64:default").is_some());
        assert!(registry.get_by_language_id("RISCV:LE:64:RV64GC").is_some());
        assert!(registry.get_by_language_id("nonexistent:LE:32:default").is_none());
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
        assert!(!registry.list().is_empty());
    }

    #[test]
    fn test_registry_len() {
        let registry = ProcessorRegistry::default();
        assert!(registry.len() >= 30);
        assert!(!registry.is_empty());
    }

    #[test]
    fn test_registry_entry_content() {
        let mut registry = ProcessorRegistry::new();
        registry.register_all();

        let ebpf = registry.get("eBPF (extended Berkeley Packet Filter)").unwrap();
        assert!(ebpf.registers.len() > 10);
        assert!(ebpf.languages.len() >= 1);
        assert!(!ebpf.instructions.is_empty());
        assert_eq!(ebpf.family, "Unknown");

        let la = registry.get("LoongArch").unwrap();
        assert!(la.registers.len() > 50);
        assert!(la.languages.len() >= 2);

        let toy = registry.get("Toy BISA (Basic Instruction Set Architecture)").unwrap();
        assert!(!toy.registers.is_empty());
        assert!(toy.languages.len() >= 2);

        let x86_entry = registry.get("x86").unwrap();
        assert!(x86_entry.registers.len() > 10);
        assert!(x86_entry.languages.len() >= 3);
        assert!(!x86_entry.instructions.is_empty());
    }

    #[test]
    fn test_registry_search() {
        let mut registry = ProcessorRegistry::new();
        registry.register_all();
        let results = registry.search("RISC");
        assert!(!results.is_empty());
        let names: Vec<&str> = results.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"RISC-V"));
    }

    #[test]
    fn test_registry_families() {
        let registry = ProcessorRegistry::default();
        let x86_family = registry.processors_in_family("Unknown");
        assert!(!x86_family.is_empty());
    }

    #[test]
    fn test_detect_elf_x86_64() {
        let elf: Vec<u8> = vec![0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x3E, 0x00, 0, 0, 0, 0];
        assert_eq!(ProcessorRegistry::detect_arch(&elf), Some("x86".to_string()));
    }

    #[test]
    fn test_detect_elf_arm() {
        let elf: Vec<u8> = vec![0x7F, b'E', b'L', b'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x28, 0x00, 0, 0, 0, 0];
        assert_eq!(ProcessorRegistry::detect_arch(&elf), Some("ARM".to_string()));
    }

    #[test]
    fn test_detect_elf_aarch64() {
        let elf: Vec<u8> = vec![0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xB7, 0x00, 0, 0, 0, 0];
        assert_eq!(ProcessorRegistry::detect_arch(&elf), Some("AARCH64".to_string()));
    }

    #[test]
    fn test_detect_elf_riscv() {
        let elf: Vec<u8> = vec![0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xF3, 0x00, 0, 0, 0, 0];
        assert_eq!(ProcessorRegistry::detect_arch(&elf), Some("RISC-V".to_string()));
    }

    #[test]
    fn test_detect_pe_x86() {
        let mut pe: Vec<u8> = vec![0; 128];
        pe[0] = b'M'; pe[1] = b'Z';
        pe[60] = 64;
        pe[64] = b'P'; pe[65] = b'E'; pe[66] = 0; pe[67] = 0;
        pe[68] = 0x4C; pe[69] = 0x01;
        assert_eq!(ProcessorRegistry::detect_arch(&pe), Some("x86".to_string()));
    }

    #[test]
    fn test_detect_pe_arm64() {
        let mut pe: Vec<u8> = vec![0; 128];
        pe[0] = b'M'; pe[1] = b'Z';
        pe[60] = 64;
        pe[64] = b'P'; pe[65] = b'E'; pe[66] = 0; pe[67] = 0;
        pe[68] = 0x64; pe[69] = 0xAA;
        assert_eq!(ProcessorRegistry::detect_arch(&pe), Some("AARCH64".to_string()));
    }

    #[test]
    fn test_detect_macho_x86() {
        let mut data: Vec<u8> = vec![0; 32];
        // Big-endian Mach-O: 32-bit x86. Magic = 0xFEEDFACE, stored as BE.
        data[0] = 0xFE; data[1] = 0xED; data[2] = 0xFA; data[3] = 0xCE;
        // CPU_TYPE_X86 = 0x07, stored as BE.
        data[4] = 0x00; data[5] = 0x00; data[6] = 0x00; data[7] = 0x07;
        assert_eq!(ProcessorRegistry::detect_arch(&data), Some("x86".to_string()));
    }

    #[test]
    fn test_detect_macho_arm64() {
        let mut data: Vec<u8> = vec![0; 32];
        // Little-endian Mach-O: 64-bit ARM64. Magic = 0xFEEDFACF, stored as LE.
        data[0] = 0xCF; data[1] = 0xFA; data[2] = 0xED; data[3] = 0xFE;
        // CPU_TYPE_ARM64 = 0x0100000C, stored as LE.
        data[4] = 0x0C; data[5] = 0x00; data[6] = 0x00; data[7] = 0x01;
        assert_eq!(ProcessorRegistry::detect_arch(&data), Some("AARCH64".to_string()));
    }

    #[test]
    fn test_detect_java_class() {
        let class: Vec<u8> = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34];
        assert_eq!(ProcessorRegistry::detect_arch(&class), Some("JVM".to_string()));
    }

    #[test]
    fn test_detect_dalvik() {
        let dex: Vec<u8> = b"dex\n035\x00".to_vec();
        assert_eq!(ProcessorRegistry::detect_arch(&dex), Some("Dalvik".to_string()));
    }

    #[test]
    fn test_detect_unknown() {
        let data: Vec<u8> = vec![0x00, 0x01, 0x02, 0x03];
        assert_eq!(ProcessorRegistry::detect_arch(&data), None);
    }

    #[test]
    fn test_detect_short_data() {
        let data: Vec<u8> = vec![0x00];
        assert_eq!(ProcessorRegistry::detect_arch(&data), None);
    }

    #[test]
    fn test_common_types() {
        let lang_id = common::LanguageID::new("x86:LE:64:default");
        assert_eq!(lang_id.as_str(), "x86:LE:64:default");
        assert_eq!(lang_id.processor(), "x86");
        assert_eq!(lang_id.endian_str(), "LE");
        assert_eq!(lang_id.size_str(), "64");
        assert_eq!(lang_id.variant(), "default");

        let cs_id = common::CompilerSpecID::new("gcc");
        assert_eq!(cs_id.as_str(), "gcc");
        assert_eq!(common::CompilerSpecID::default_id().as_str(), "default");

        let proc = common::Processor::new("x86", "Intel/AMD x86", "x86");
        assert_eq!(proc.name(), "x86");
        assert_eq!(proc.family(), "x86");

        let flags = common::RegisterType::PC.union(common::RegisterType::SP);
        assert!(flags.is_pc());
        assert!(flags.is_sp());
        assert!(!flags.is_fp());

        let reg = common::Register::new("RAX", 64, 0)
            .with_type(common::RegisterType::NONE)
            .with_description("Accumulator register")
            .with_group("General Purpose");
        assert_eq!(reg.name, "RAX");
        assert_eq!(reg.bit_size, 64);
        assert_eq!(reg.byte_size(), 8);
        assert!(reg.is_base_register());

        let mut bank = common::RegisterBank::new();
        bank.add(reg.clone());
        assert_eq!(bank.len(), 1);
        assert!(bank.get("RAX").is_some());
        assert!(bank.get("RBX").is_none());
    }

    #[test]
    fn test_register_manager() {
        let mut bank = common::RegisterBank::new();
        bank.add(common::Register::new("RAX", 64, 0).with_group("General Purpose"));
        bank.add(common::Register::new("RIP", 64, 0x1000).with_type(common::RegisterType::PC));
        bank.add(common::Register::new("XMM0", 128, 0x2000).with_type(common::RegisterType::VECTOR).with_group("Vector"));

        let mgr = common::RegisterManager::new(&bank);
        assert_eq!(mgr.len(), 3);
        assert!(mgr.get_register("rax").is_some()); // case-insensitive
        assert!(mgr.get_register("RAX").is_some());
        assert!(mgr.get_register("nonexistent").is_none());
        assert_eq!(mgr.sorted_vector_registers().len(), 1);
        assert_eq!(mgr.sorted_vector_registers()[0].name, "XMM0");
        assert!(mgr.group_names().len() >= 2);
    }

    #[test]
    fn test_language_builder() {
        let lang = common::Language::new("x86:LE:64:default", "x86-64", "x86-64", common::Endian::Little, 64)
            .with_pc_register("RIP")
            .with_instruction_alignment(1);
        assert_eq!(lang.program_counter, "RIP");
        assert_eq!(lang.instruction_alignment, 1);
        assert!(lang.supports_pcode);
        assert_eq!(lang.pointer_size, 64);
    }
}
