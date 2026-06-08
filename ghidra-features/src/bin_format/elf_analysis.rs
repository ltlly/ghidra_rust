//! ELF binary analysis command ported from Ghidra's
//! `ghidra.app.cmd.formats.ElfBinaryAnalysisCommand`.
//!
//! Provides [`ElfAnalysisCommand`] which analyzes an ELF binary and produces
//! [`ProgramMarkup`] entries for:
//! - ELF header
//! - Program headers (PT_LOAD, PT_INTERP, PT_DYNAMIC, etc.)
//! - Section headers (with data regions and labels)
//! - Symbol tables (SYMTAB, DYNSYM)
//! - Relocation tables (REL, RELA)
//! - String tables (STRTAB)
//! - Dynamic section entries with cross-references
//!
//! This implementation works on raw binary data (e.g., a flat binary loaded at
//! address 0) and generates markup descriptors rather than directly mutating a
//! Ghidra Program.

use super::analysis_command::{
    BinaryAnalysisCommand, BinaryFormat, CommentEntry, CommentType, FragmentEntry, LabelEntry,
    MarkupEntry, MessageLog, ProgramMarkup, ReferenceEntry, SourceType,
};
use super::binary_reader::BinaryReader;
use super::types::DataTypeDescription;

use crate::fileformats::elf::{
    ElfClass, ElfDataEncoding, ELF_MAGIC, SHT_DYNSYM, SHT_DYNAMIC, SHT_NOBITS, SHT_REL,
    SHT_RELA, SHT_STRTAB, SHT_SYMTAB, PT_DYNAMIC, PT_INTERP, PT_LOAD, PT_NOTE, PT_NULL,
};

// ---------------------------------------------------------------------------
// ELF constants used for analysis
// ---------------------------------------------------------------------------

/// ELF64 header size.
const ELF64_EHDR_SIZE: u64 = 64;
/// ELF32 header size.
const ELF32_EHDR_SIZE: u64 = 52;

/// Size of an ELF64 program header entry.
const ELF64_PHDR_SIZE: u64 = 56;
/// Size of an ELF32 program header entry.
const ELF32_PHDR_SIZE: u64 = 32;

/// Size of an ELF64 section header entry.
const ELF64_SHDR_SIZE: u64 = 64;
/// Size of an ELF32 section header entry.
const ELF32_SHDR_SIZE: u64 = 40;

/// Size of an ELF64 symbol table entry.
const ELF64_SYM_SIZE: u64 = 24;
/// Size of an ELF32 symbol table entry.
const ELF32_SYM_SIZE: u64 = 16;

/// Size of an ELF64 relocation entry (REL).
const ELF64_REL_SIZE: u64 = 16;
/// Size of an ELF32 relocation entry (REL).
const ELF32_REL_SIZE: u64 = 8;

/// Size of an ELF64 relocation entry with addend (RELA).
const ELF64_RELA_SIZE: u64 = 24;
/// Size of an ELF32 relocation entry with addend (RELA).
const ELF32_RELA_SIZE: u64 = 12;

/// Size of an ELF64 dynamic entry.
const ELF64_DYN_SIZE: u64 = 16;
/// Size of an ELF32 dynamic entry.
const ELF32_DYN_SIZE: u64 = 8;

// ---------------------------------------------------------------------------
// Parsed ELF structures (lightweight, used for markup generation)
// ---------------------------------------------------------------------------

/// Parsed ELF header information.
#[derive(Debug, Clone)]
struct ElfHeaderInfo {
    class: ElfClass,
    data_encoding: ElfDataEncoding,
    is_64: bool,
    is_le: bool,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

/// Parsed ELF program header.
#[derive(Debug, Clone)]
struct ParsedPhdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
    /// Index in the program header table.
    index: usize,
}

/// Parsed ELF section header.
#[derive(Debug, Clone)]
struct ParsedShdr {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
    /// Index in the section header table.
    index: usize,
    /// Resolved section name (from string table).
    name: String,
}

// ---------------------------------------------------------------------------
// ElfAnalysisCommand
// ---------------------------------------------------------------------------

/// ELF binary analysis command.
///
/// Ported from `ghidra.app.cmd.formats.ElfBinaryAnalysisCommand`. Parses the
/// ELF header, program headers, section headers, symbol tables, relocations,
/// string tables, and dynamic section, and produces a [`ProgramMarkup`].
pub struct ElfAnalysisCommand {
    messages: MessageLog,
}

impl ElfAnalysisCommand {
    /// Create a new ELF analysis command.
    pub fn new() -> Self {
        Self {
            messages: MessageLog::new(),
        }
    }

    /// Parse the ELF header from the data.
    fn parse_elf_header(&self, data: &[u8]) -> Result<ElfHeaderInfo, String> {
        if data.len() < 16 {
            return Err("Data too short for ELF header".into());
        }

        // Verify magic
        if data[0] != 0x7f || data[1] != b'E' || data[2] != b'L' || data[3] != b'F' {
            return Err("Not an ELF file: invalid magic bytes".into());
        }

        let class = match data[4] {
            1 => ElfClass::ELF32,
            2 => ElfClass::ELF64,
            _ => return Err(format!("Unsupported ELF class: {}", data[4])),
        };

        let data_encoding = match data[5] {
            1 => ElfDataEncoding::LittleEndian,
            2 => ElfDataEncoding::BigEndian,
            _ => return Err(format!("Unsupported ELF data encoding: {}", data[5])),
        };

        let is_64 = class == ElfClass::ELF64;
        let is_le = data_encoding == ElfDataEncoding::LittleEndian;

        let mut reader = BinaryReader::from_bytes(data, is_le);
        reader.set_cursor(0);

        // Skip e_ident[16]
        reader.advance(16);

        let e_type = reader.read_next_u16().map_err(|e| format!("e_type: {}", e))?;
        let e_machine = reader.read_next_u16().map_err(|e| format!("e_machine: {}", e))?;
        let e_version = reader.read_next_u32().map_err(|e| format!("e_version: {}", e))?;

        let (e_entry, e_phoff, e_shoff) = if is_64 {
            let entry = reader.read_next_u64().map_err(|e| format!("e_entry: {}", e))?;
            let phoff = reader.read_next_u64().map_err(|e| format!("e_phoff: {}", e))?;
            let shoff = reader.read_next_u64().map_err(|e| format!("e_shoff: {}", e))?;
            (entry, phoff, shoff)
        } else {
            let entry = reader.read_next_u32().map_err(|e| format!("e_entry: {}", e))? as u64;
            let phoff = reader.read_next_u32().map_err(|e| format!("e_phoff: {}", e))? as u64;
            let shoff = reader.read_next_u32().map_err(|e| format!("e_shoff: {}", e))? as u64;
            (entry, phoff, shoff)
        };

        let e_flags = reader.read_next_u32().map_err(|e| format!("e_flags: {}", e))?;
        let e_ehsize = reader.read_next_u16().map_err(|e| format!("e_ehsize: {}", e))?;
        let e_phentsize = reader.read_next_u16().map_err(|e| format!("e_phentsize: {}", e))?;
        let e_phnum = reader.read_next_u16().map_err(|e| format!("e_phnum: {}", e))?;
        let e_shentsize = reader.read_next_u16().map_err(|e| format!("e_shentsize: {}", e))?;
        let e_shnum = reader.read_next_u16().map_err(|e| format!("e_shnum: {}", e))?;
        let e_shstrndx = reader.read_next_u16().map_err(|e| format!("e_shstrndx: {}", e))?;

        Ok(ElfHeaderInfo {
            class,
            data_encoding,
            is_64,
            is_le,
            e_type,
            e_machine,
            e_version,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        })
    }

    /// Parse program headers.
    fn parse_program_headers(
        &self,
        data: &[u8],
        hdr: &ElfHeaderInfo,
    ) -> Result<Vec<ParsedPhdr>, String> {
        let mut phdrs = Vec::new();
        let phdr_size = if hdr.is_64 { ELF64_PHDR_SIZE } else { ELF32_PHDR_SIZE } as usize;

        for i in 0..hdr.e_phnum as usize {
            let offset = hdr.e_phoff as usize + i * hdr.e_phentsize as usize;
            if offset + phdr_size > data.len() {
                return Err(format!("Program header {} extends beyond data", i));
            }

            let mut reader = BinaryReader::from_bytes(&data[offset..], hdr.is_le);

            let p_type = reader.read_next_u32().map_err(|e| format!("p_type[{}]: {}", i, e))?;

            let (p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align) = if hdr.is_64 {
                let flags = reader.read_next_u32().map_err(|e| format!("p_flags[{}]: {}", i, e))?;
                let off = reader.read_next_u64().map_err(|e| format!("p_offset[{}]: {}", i, e))?;
                let vaddr = reader.read_next_u64().map_err(|e| format!("p_vaddr[{}]: {}", i, e))?;
                let paddr = reader.read_next_u64().map_err(|e| format!("p_paddr[{}]: {}", i, e))?;
                let filesz = reader.read_next_u64().map_err(|e| format!("p_filesz[{}]: {}", i, e))?;
                let memsz = reader.read_next_u64().map_err(|e| format!("p_memsz[{}]: {}", i, e))?;
                let align = reader.read_next_u64().map_err(|e| format!("p_align[{}]: {}", i, e))?;
                (flags, off, vaddr, paddr, filesz, memsz, align)
            } else {
                let off = reader.read_next_u32().map_err(|e| format!("p_offset[{}]: {}", i, e))? as u64;
                let vaddr = reader.read_next_u32().map_err(|e| format!("p_vaddr[{}]: {}", i, e))? as u64;
                let paddr = reader.read_next_u32().map_err(|e| format!("p_paddr[{}]: {}", i, e))? as u64;
                let filesz = reader.read_next_u32().map_err(|e| format!("p_filesz[{}]: {}", i, e))? as u64;
                let memsz = reader.read_next_u32().map_err(|e| format!("p_memsz[{}]: {}", i, e))? as u64;
                let flags = reader.read_next_u32().map_err(|e| format!("p_flags[{}]: {}", i, e))?;
                let align = reader.read_next_u32().map_err(|e| format!("p_align[{}]: {}", i, e))? as u64;
                (flags, off, vaddr, paddr, filesz, memsz, align)
            };

            phdrs.push(ParsedPhdr {
                p_type,
                p_flags,
                p_offset,
                p_vaddr,
                p_paddr,
                p_filesz,
                p_memsz,
                p_align,
                index: i,
            });
        }

        Ok(phdrs)
    }

    /// Parse section headers.
    fn parse_section_headers(
        &self,
        data: &[u8],
        hdr: &ElfHeaderInfo,
    ) -> Result<Vec<ParsedShdr>, String> {
        let mut shdrs = Vec::new();
        let shdr_size = if hdr.is_64 { ELF64_SHDR_SIZE } else { ELF32_SHDR_SIZE } as usize;

        // First pass: parse raw section headers
        for i in 0..hdr.e_shnum as usize {
            let offset = hdr.e_shoff as usize + i * hdr.e_shentsize as usize;
            if offset + shdr_size > data.len() {
                return Err(format!("Section header {} extends beyond data", i));
            }

            let mut reader = BinaryReader::from_bytes(&data[offset..], hdr.is_le);

            let sh_name = reader.read_next_u32().map_err(|e| format!("sh_name[{}]: {}", i, e))?;
            let sh_type = reader.read_next_u32().map_err(|e| format!("sh_type[{}]: {}", i, e))?;

            let (sh_flags, sh_addr, sh_offset, sh_size) = if hdr.is_64 {
                let flags = reader.read_next_u64().map_err(|e| format!("sh_flags[{}]: {}", i, e))?;
                let addr = reader.read_next_u64().map_err(|e| format!("sh_addr[{}]: {}", i, e))?;
                let off = reader.read_next_u64().map_err(|e| format!("sh_offset[{}]: {}", i, e))?;
                let size = reader.read_next_u64().map_err(|e| format!("sh_size[{}]: {}", i, e))?;
                (flags, addr, off, size)
            } else {
                let flags = reader.read_next_u32().map_err(|e| format!("sh_flags[{}]: {}", i, e))? as u64;
                let addr = reader.read_next_u32().map_err(|e| format!("sh_addr[{}]: {}", i, e))? as u64;
                let off = reader.read_next_u32().map_err(|e| format!("sh_offset[{}]: {}", i, e))? as u64;
                let size = reader.read_next_u32().map_err(|e| format!("sh_size[{}]: {}", i, e))? as u64;
                (flags, addr, off, size)
            };

            let sh_link = reader.read_next_u32().map_err(|e| format!("sh_link[{}]: {}", i, e))?;
            let sh_info = reader.read_next_u32().map_err(|e| format!("sh_info[{}]: {}", i, e))?;
            let sh_addralign = if hdr.is_64 {
                reader.read_next_u64().map_err(|e| format!("sh_addralign[{}]: {}", i, e))?
            } else {
                reader.read_next_u32().map_err(|e| format!("sh_addralign[{}]: {}", i, e))? as u64
            };
            let sh_entsize = if hdr.is_64 {
                reader.read_next_u64().map_err(|e| format!("sh_entsize[{}]: {}", i, e))?
            } else {
                reader.read_next_u32().map_err(|e| format!("sh_entsize[{}]: {}", i, e))? as u64
            };

            shdrs.push(ParsedShdr {
                sh_name,
                sh_type,
                sh_flags,
                sh_addr,
                sh_offset,
                sh_size,
                sh_link,
                sh_info,
                sh_addralign,
                sh_entsize,
                index: i,
                name: String::new(),
            });
        }

        // Second pass: resolve section names from the section header string table
        if (hdr.e_shstrndx as usize) < shdrs.len() {
            let strtab_offset = shdrs[hdr.e_shstrndx as usize].sh_offset;
            for sh in shdrs.iter_mut() {
                let name_off = strtab_offset as usize + sh.sh_name as usize;
                if name_off < data.len() {
                    sh.name = read_null_terminated(data, name_off);
                }
            }
        }

        Ok(shdrs)
    }

    /// Read a null-terminated string from data at the given offset.
    fn read_string(&self, data: &[u8], offset: u64) -> String {
        read_null_terminated(data, offset as usize)
    }

    /// Get the string table and read a string from it.
    fn read_string_from_table(&self, data: &[u8], strtab_offset: u64, str_index: u64) -> String {
        read_null_terminated(data, (strtab_offset + str_index) as usize)
    }

    /// Process the ELF header markup.
    fn process_elf_header(
        &self,
        hdr: &ElfHeaderInfo,
        markup: &mut ProgramMarkup,
    ) {
        let ehdr_size = if hdr.is_64 { ELF64_EHDR_SIZE } else { ELF32_EHDR_SIZE };

        // Create the ELF header struct data type
        let elf_header_dt = if hdr.is_64 {
            DataTypeDescription::Struct {
                name: "Elf64_Ehdr".into(),
                size: ELF64_EHDR_SIZE as u32,
                fields: vec![
                    ("e_ident".into(), DataTypeDescription::Array {
                        element: Box::new(DataTypeDescription::Byte),
                        count: 16,
                    }),
                    ("e_type".into(), DataTypeDescription::Word),
                    ("e_machine".into(), DataTypeDescription::Word),
                    ("e_version".into(), DataTypeDescription::DWord),
                    ("e_entry".into(), DataTypeDescription::QWord),
                    ("e_phoff".into(), DataTypeDescription::QWord),
                    ("e_shoff".into(), DataTypeDescription::QWord),
                    ("e_flags".into(), DataTypeDescription::DWord),
                    ("e_ehsize".into(), DataTypeDescription::Word),
                    ("e_phentsize".into(), DataTypeDescription::Word),
                    ("e_phnum".into(), DataTypeDescription::Word),
                    ("e_shentsize".into(), DataTypeDescription::Word),
                    ("e_shnum".into(), DataTypeDescription::Word),
                    ("e_shstrndx".into(), DataTypeDescription::Word),
                ],
            }
        } else {
            DataTypeDescription::Struct {
                name: "Elf32_Ehdr".into(),
                size: ELF32_EHDR_SIZE as u32,
                fields: vec![
                    ("e_ident".into(), DataTypeDescription::Array {
                        element: Box::new(DataTypeDescription::Byte),
                        count: 16,
                    }),
                    ("e_type".into(), DataTypeDescription::Word),
                    ("e_machine".into(), DataTypeDescription::Word),
                    ("e_version".into(), DataTypeDescription::DWord),
                    ("e_entry".into(), DataTypeDescription::DWord),
                    ("e_phoff".into(), DataTypeDescription::DWord),
                    ("e_shoff".into(), DataTypeDescription::DWord),
                    ("e_flags".into(), DataTypeDescription::DWord),
                    ("e_ehsize".into(), DataTypeDescription::Word),
                    ("e_phentsize".into(), DataTypeDescription::Word),
                    ("e_phnum".into(), DataTypeDescription::Word),
                    ("e_shentsize".into(), DataTypeDescription::Word),
                    ("e_shnum".into(), DataTypeDescription::Word),
                    ("e_shstrndx".into(), DataTypeDescription::Word),
                ],
            }
        };

        let elf_type_name = match hdr.e_type {
            0 => "ET_NONE",
            1 => "ET_REL",
            2 => "ET_EXEC",
            3 => "ET_DYN",
            4 => "ET_CORE",
            _ => "ET_UNKNOWN",
        };

        let machine_name = elf_machine_name(hdr.e_machine);

        let comment = format!(
            "ELF Header: {} {} {} Entry={:#x}",
            elf_type_name, machine_name,
            if hdr.is_64 { "ELF64" } else { "ELF32" },
            hdr.e_entry
        );

        markup.add_markup(
            MarkupEntry::new(0, elf_header_dt.clone())
                .with_name(elf_header_dt.to_string())
                .with_comment(comment, CommentType::Plate),
        );
        markup.add_fragment(FragmentEntry::new("ELF Header", 0, ehdr_size));
    }

    /// Process program headers markup.
    fn process_program_headers(
        &self,
        data: &[u8],
        hdr: &ElfHeaderInfo,
        phdrs: &[ParsedPhdr],
        markup: &mut ProgramMarkup,
    ) {
        if phdrs.is_empty() {
            return;
        }

        let phdr_size = if hdr.is_64 { ELF64_PHDR_SIZE } else { ELF32_PHDR_SIZE };

        // Create array of program headers
        let phdr_dt = if hdr.is_64 {
            DataTypeDescription::Struct {
                name: "Elf64_Phdr".into(),
                size: ELF64_PHDR_SIZE as u32,
                fields: vec![
                    ("p_type".into(), DataTypeDescription::DWord),
                    ("p_flags".into(), DataTypeDescription::DWord),
                    ("p_offset".into(), DataTypeDescription::QWord),
                    ("p_vaddr".into(), DataTypeDescription::QWord),
                    ("p_paddr".into(), DataTypeDescription::QWord),
                    ("p_filesz".into(), DataTypeDescription::QWord),
                    ("p_memsz".into(), DataTypeDescription::QWord),
                    ("p_align".into(), DataTypeDescription::QWord),
                ],
            }
        } else {
            DataTypeDescription::Struct {
                name: "Elf32_Phdr".into(),
                size: ELF32_PHDR_SIZE as u32,
                fields: vec![
                    ("p_type".into(), DataTypeDescription::DWord),
                    ("p_offset".into(), DataTypeDescription::DWord),
                    ("p_vaddr".into(), DataTypeDescription::DWord),
                    ("p_paddr".into(), DataTypeDescription::DWord),
                    ("p_filesz".into(), DataTypeDescription::DWord),
                    ("p_memsz".into(), DataTypeDescription::DWord),
                    ("p_flags".into(), DataTypeDescription::DWord),
                    ("p_align".into(), DataTypeDescription::DWord),
                ],
            }
        };

        let total_size = phdr_size * phdrs.len() as u64;
        let array_dt = DataTypeDescription::Array {
            element: Box::new(phdr_dt.clone()),
            count: phdrs.len(),
        };

        markup.add_markup(
            MarkupEntry::new(hdr.e_phoff, array_dt)
                .with_name(phdr_dt.to_string()),
        );
        markup.add_fragment(FragmentEntry::new(
            phdr_dt.to_string(),
            hdr.e_phoff,
            total_size,
        ));

        // Add individual program header comments and labels
        for phdr in phdrs {
            let addr = hdr.e_phoff + phdr.index as u64 * hdr.e_phentsize as u64;
            let type_name = elf_phdr_type_name(phdr.p_type);
            let comment = format!(
                "Type={} Offset={:#x} VAddr={:#x} FileSz={:#x} MemSz={:#x} Flags={:#x}",
                type_name, phdr.p_offset, phdr.p_vaddr, phdr.p_filesz, phdr.p_memsz, phdr.p_flags
            );

            markup.add_comment(CommentEntry::new(addr, comment, CommentType::Eol));

            // Create labels for PT_LOAD segments at their file offset
            if phdr.p_type == PT_LOAD && phdr.p_filesz > 0 {
                let label_name = format!("LOAD_{:#x}", phdr.p_vaddr);
                markup.add_label(LabelEntry::new(phdr.p_offset, label_name));
            }
        }
    }

    /// Process section headers markup.
    fn process_section_headers(
        &self,
        data: &[u8],
        hdr: &ElfHeaderInfo,
        shdrs: &[ParsedShdr],
        markup: &mut ProgramMarkup,
    ) {
        for shdr in shdrs {
            let shdr_addr = hdr.e_shoff + shdr.index as u64 * hdr.e_shentsize as u64;

            let shdr_dt = if hdr.is_64 {
                DataTypeDescription::Struct {
                    name: "Elf64_Shdr".into(),
                size: ELF64_SHDR_SIZE as u32,
                    fields: vec![
                        ("sh_name".into(), DataTypeDescription::DWord),
                        ("sh_type".into(), DataTypeDescription::DWord),
                        ("sh_flags".into(), DataTypeDescription::QWord),
                        ("sh_addr".into(), DataTypeDescription::QWord),
                        ("sh_offset".into(), DataTypeDescription::QWord),
                        ("sh_size".into(), DataTypeDescription::QWord),
                        ("sh_link".into(), DataTypeDescription::DWord),
                        ("sh_info".into(), DataTypeDescription::DWord),
                        ("sh_addralign".into(), DataTypeDescription::QWord),
                        ("sh_entsize".into(), DataTypeDescription::QWord),
                    ],
                }
            } else {
                DataTypeDescription::Struct {
                    name: "Elf32_Shdr".into(),
                size: ELF32_SHDR_SIZE as u32,
                    fields: vec![
                        ("sh_name".into(), DataTypeDescription::DWord),
                        ("sh_type".into(), DataTypeDescription::DWord),
                        ("sh_flags".into(), DataTypeDescription::DWord),
                        ("sh_addr".into(), DataTypeDescription::DWord),
                        ("sh_offset".into(), DataTypeDescription::DWord),
                        ("sh_size".into(), DataTypeDescription::DWord),
                        ("sh_link".into(), DataTypeDescription::DWord),
                        ("sh_info".into(), DataTypeDescription::DWord),
                        ("sh_addralign".into(), DataTypeDescription::DWord),
                        ("sh_entsize".into(), DataTypeDescription::DWord),
                    ],
                }
            };

            let comment = format!(
                "#{}) {} at {:#x}",
                shdr.index, shdr.name, shdr.sh_addr
            );

            markup.add_markup(
                MarkupEntry::new(shdr_addr, shdr_dt.clone())
                    .with_name(shdr_dt.to_string())
                    .with_comment(comment, CommentType::Plate),
            );
            markup.add_fragment(FragmentEntry::new(
                shdr_dt.to_string(),
                shdr_addr,
                shdr_dt.size().unwrap_or(0) as u64,
            ));

            // Skip NOBITS sections (like .bss) and sections with no data
            if shdr.sh_type == SHT_NOBITS || shdr.sh_size == 0 {
                continue;
            }

            // Create a data fragment for the section contents
            if shdr.sh_offset + shdr.sh_size <= data.len() as u64 {
                let frag_name = format!("{}_DATA", shdr.name);
                markup.add_fragment(FragmentEntry::new(&frag_name, shdr.sh_offset, shdr.sh_size));
                markup.add_label(LabelEntry::new(shdr.sh_offset, &shdr.name));
                markup.add_comment(CommentEntry::new(
                    shdr.sh_offset,
                    format!("{} Size: {:#x}", shdr.name, shdr.sh_size),
                    CommentType::Pre,
                ));
            }
        }
    }

    /// Process symbol tables markup.
    fn process_symbol_tables(
        &self,
        data: &[u8],
        hdr: &ElfHeaderInfo,
        shdrs: &[ParsedShdr],
        markup: &mut ProgramMarkup,
    ) {
        let sym_size = if hdr.is_64 { ELF64_SYM_SIZE } else { ELF32_SYM_SIZE };

        for shdr in shdrs {
            if shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM {
                continue;
            }

            let table_type = if shdr.sh_type == SHT_SYMTAB {
                "SYMTAB"
            } else {
                "DYNSYM"
            };

            // Get the associated string table
            let strtab_shdr = if (shdr.sh_link as usize) < shdrs.len() {
                &shdrs[shdr.sh_link as usize]
            } else {
                self.messages.append_warning(format!(
                    "Symbol table '{}' has invalid sh_link: {}",
                    shdr.name, shdr.sh_link
                ));
                continue;
            };

            if shdr.sh_entsize == 0 || shdr.sh_size == 0 {
                continue;
            }

            let num_symbols = shdr.sh_size / shdr.sh_entsize;

            // Create a fragment for the entire symbol table
            let sym_dt = if hdr.is_64 {
                DataTypeDescription::Struct {
                    name: "Elf64_Sym".into(),
                size: ELF64_SYM_SIZE as u32,
                    fields: vec![
                        ("st_name".into(), DataTypeDescription::DWord),
                        ("st_info".into(), DataTypeDescription::Byte),
                        ("st_other".into(), DataTypeDescription::Byte),
                        ("st_shndx".into(), DataTypeDescription::Word),
                        ("st_value".into(), DataTypeDescription::QWord),
                        ("st_size".into(), DataTypeDescription::QWord),
                    ],
                }
            } else {
                DataTypeDescription::Struct {
                    name: "Elf32_Sym".into(),
                size: ELF32_SYM_SIZE as u32,
                    fields: vec![
                        ("st_name".into(), DataTypeDescription::DWord),
                        ("st_value".into(), DataTypeDescription::DWord),
                        ("st_size".into(), DataTypeDescription::DWord),
                        ("st_info".into(), DataTypeDescription::Byte),
                        ("st_other".into(), DataTypeDescription::Byte),
                        ("st_shndx".into(), DataTypeDescription::Word),
                    ],
                }
            };

            let sym_table_dt = DataTypeDescription::Array {
                element: Box::new(sym_dt.clone()),
                count: num_symbols as usize,
            };

            markup.add_markup(
                MarkupEntry::new(shdr.sh_offset, sym_table_dt)
                    .with_name(format!("{}_{}", table_type, shdr.name)),
            );
            markup.add_fragment(FragmentEntry::new(
                format!("{}_{}", table_type, shdr.name),
                shdr.sh_offset,
                shdr.sh_size,
            ));

            // Process individual symbols: add comments with symbol names
            for i in 0..num_symbols as usize {
                let sym_offset = shdr.sh_offset + i as u64 * shdr.sh_entsize;
                if sym_offset + shdr.sh_entsize > data.len() as u64 {
                    break;
                }

                let sym_name = if hdr.is_64 {
                    self.read_elf64_symbol_name(data, sym_offset, strtab_shdr)
                } else {
                    self.read_elf32_symbol_name(data, sym_offset, strtab_shdr)
                };

                if !sym_name.is_empty() {
                    let sym_value = if hdr.is_64 {
                        self.read_u64_at(data, sym_offset + 8, hdr.is_le)
                    } else {
                        self.read_u32_at(data, sym_offset + 4, hdr.is_le) as u64
                    };

                    markup.add_comment(CommentEntry::new(
                        sym_offset,
                        format!("{} at {:#x}", sym_name, sym_value),
                        CommentType::Eol,
                    ));
                }
            }
        }
    }

    /// Read the symbol name for an ELF64 symbol.
    fn read_elf64_symbol_name(
        &self,
        data: &[u8],
        sym_offset: u64,
        strtab: &ParsedShdr,
    ) -> String {
        let st_name = self.read_u32_at(data, sym_offset, true) as u64; // always at offset 0
        if st_name == 0 {
            return String::new();
        }
        self.read_string_from_table(data, strtab.sh_offset, st_name)
    }

    /// Read the symbol name for an ELF32 symbol.
    fn read_elf32_symbol_name(
        &self,
        data: &[u8],
        sym_offset: u64,
        strtab: &ParsedShdr,
    ) -> String {
        let st_name = self.read_u32_at(data, sym_offset, true) as u64;
        if st_name == 0 {
            return String::new();
        }
        self.read_string_from_table(data, strtab.sh_offset, st_name)
    }

    /// Process string tables markup.
    fn process_string_tables(
        &self,
        data: &[u8],
        hdr: &ElfHeaderInfo,
        shdrs: &[ParsedShdr],
        markup: &mut ProgramMarkup,
    ) {
        for shdr in shdrs {
            if shdr.sh_type != SHT_STRTAB {
                continue;
            }

            if shdr.sh_size == 0 || shdr.sh_offset + shdr.sh_size > data.len() as u64 {
                continue;
            }

            // The section header string table is already used for section names;
            // we mark up all string tables as data regions.
            markup.add_fragment(FragmentEntry::new(
                format!("STRTAB_{}", shdr.name),
                shdr.sh_offset,
                shdr.sh_size,
            ));

            // Parse individual strings in the string table
            let mut pos = shdr.sh_offset as usize;
            let end = (shdr.sh_offset + shdr.sh_size) as usize;
            while pos < end && pos < data.len() {
                let s = read_null_terminated(data, pos);
                if !s.is_empty() {
                    markup.add_comment(CommentEntry::new(
                        pos as u64,
                        s.clone(),
                        CommentType::Eol,
                    ));
                }
                pos += s.len() + 1; // +1 for null terminator
                if s.is_empty() && pos > shdr.sh_offset as usize + 1 {
                    // Empty string not at start -- likely padding
                    break;
                }
            }
        }
    }

    /// Process relocation tables markup.
    fn process_relocation_tables(
        &self,
        data: &[u8],
        hdr: &ElfHeaderInfo,
        shdrs: &[ParsedShdr],
        markup: &mut ProgramMarkup,
    ) {
        for shdr in shdrs {
            if shdr.sh_type != SHT_REL && shdr.sh_type != SHT_RELA {
                continue;
            }

            if shdr.sh_size == 0 {
                continue;
            }

            let rel_dt_name = if shdr.sh_type == SHT_RELA {
                if hdr.is_64 { "Elf64_Rela" } else { "Elf32_Rela" }
            } else {
                if hdr.is_64 { "Elf64_Rel" } else { "Elf32_Rel" }
            };

            let rel_dt = if hdr.is_64 && shdr.sh_type == SHT_RELA {
                DataTypeDescription::Struct {
                    name: "Elf64_Rela".into(),
                size: ELF64_RELA_SIZE as u32,
                    fields: vec![
                        ("r_offset".into(), DataTypeDescription::QWord),
                        ("r_info".into(), DataTypeDescription::QWord),
                        ("r_addend".into(), DataTypeDescription::QWord),
                    ],
                }
            } else if hdr.is_64 {
                DataTypeDescription::Struct {
                    name: "Elf64_Rel".into(),
                size: ELF64_REL_SIZE as u32,
                    fields: vec![
                        ("r_offset".into(), DataTypeDescription::QWord),
                        ("r_info".into(), DataTypeDescription::QWord),
                    ],
                }
            } else if shdr.sh_type == SHT_RELA {
                DataTypeDescription::Struct {
                    name: "Elf32_Rela".into(),
                size: ELF32_RELA_SIZE as u32,
                    fields: vec![
                        ("r_offset".into(), DataTypeDescription::DWord),
                        ("r_info".into(), DataTypeDescription::DWord),
                        ("r_addend".into(), DataTypeDescription::DWord),
                    ],
                }
            } else {
                DataTypeDescription::Struct {
                    name: "Elf32_Rel".into(),
                size: ELF32_REL_SIZE as u32,
                    fields: vec![
                        ("r_offset".into(), DataTypeDescription::DWord),
                        ("r_info".into(), DataTypeDescription::DWord),
                    ],
                }
            };

            let rel_size = rel_dt.size().unwrap_or(0) as u64;
            if rel_size == 0 {
                continue;
            }

            let num_entries = shdr.sh_size / rel_size;
            let array_dt = DataTypeDescription::Array {
                element: Box::new(rel_dt.clone()),
                count: num_entries as usize,
            };

            markup.add_markup(
                MarkupEntry::new(shdr.sh_offset, array_dt)
                    .with_name(format!("{}_{}", rel_dt_name, shdr.name)),
            );
            markup.add_fragment(FragmentEntry::new(
                format!("{}_{}", rel_dt_name, shdr.name),
                shdr.sh_offset,
                shdr.sh_size,
            ));
        }
    }

    /// Process the dynamic section markup.
    fn process_dynamic_section(
        &self,
        data: &[u8],
        hdr: &ElfHeaderInfo,
        shdrs: &[ParsedShdr],
        phdrs: &[ParsedPhdr],
        markup: &mut ProgramMarkup,
    ) {
        // Find dynamic section via section header or program header
        let dyn_shdr = shdrs.iter().find(|s| s.sh_type == SHT_DYNAMIC);
        let dyn_phdr = phdrs.iter().find(|p| p.p_type == PT_DYNAMIC);

        let (dyn_offset, dyn_size) = match (dyn_shdr, dyn_phdr) {
            (Some(shdr), _) if shdr.sh_size > 0 => (shdr.sh_offset, shdr.sh_size),
            (_, Some(phdr)) if phdr.p_filesz > 0 => (phdr.p_offset, phdr.p_filesz),
            _ => return,
        };

        let dyn_entry_size = if hdr.is_64 { ELF64_DYN_SIZE } else { ELF32_DYN_SIZE };
        if dyn_entry_size == 0 {
            return;
        }

        let num_entries = dyn_size / dyn_entry_size;

        // Find the dynamic string table for resolving dynamic strings
        let dynstr_offset = shdrs
            .iter()
            .find(|s| s.sh_type == SHT_STRTAB && s.name == ".dynstr")
            .map(|s| s.sh_offset);

        let dyn_dt = if hdr.is_64 {
            DataTypeDescription::Struct {
                name: "Elf64_Dyn".into(),
                size: ELF64_DYN_SIZE as u32,
                fields: vec![
                    ("d_tag".into(), DataTypeDescription::QWord),
                    ("d_val".into(), DataTypeDescription::QWord),
                ],
            }
        } else {
            DataTypeDescription::Struct {
                name: "Elf32_Dyn".into(),
                size: ELF32_DYN_SIZE as u32,
                fields: vec![
                    ("d_tag".into(), DataTypeDescription::DWord),
                    ("d_val".into(), DataTypeDescription::DWord),
                ],
            }
        };

        let array_dt = DataTypeDescription::Array {
            element: Box::new(dyn_dt.clone()),
            count: num_entries as usize,
        };

        markup.add_markup(
            MarkupEntry::new(dyn_offset, array_dt)
                .with_name("_DYNAMIC"),
        );
        markup.add_label(LabelEntry::new(dyn_offset, "_DYNAMIC"));
        markup.add_fragment(FragmentEntry::new("Dynamic", dyn_offset, dyn_size));

        // Process individual dynamic entries
        for i in 0..num_entries as usize {
            let entry_offset = dyn_offset + i as u64 * dyn_entry_size;
            if entry_offset + dyn_entry_size > data.len() as u64 {
                break;
            }

            let (d_tag, d_val) = if hdr.is_64 {
                (
                    self.read_u64_at(data, entry_offset, hdr.is_le) as i64,
                    self.read_u64_at(data, entry_offset + 8, hdr.is_le),
                )
            } else {
                (
                    self.read_u32_at(data, entry_offset, hdr.is_le) as i32 as i64,
                    self.read_u32_at(data, entry_offset + 4, hdr.is_le) as u64,
                )
            };

            // DT_NULL marks end of dynamic section
            if d_tag == 0 {
                break;
            }

            let tag_name = elf_dynamic_tag_name(d_tag);
            let comment = if let Some(str_off) = dynstr_offset {
                if is_string_dynamic_tag(d_tag) {
                    let s = self.read_string_from_table(data, str_off, d_val);
                    format!("{} ({}) - {}", tag_name, d_tag, s)
                } else {
                    format!("{} ({}) = {:#x}", tag_name, d_tag, d_val)
                }
            } else {
                format!("{} ({}) = {:#x}", tag_name, d_tag, d_val)
            };

            let value_offset = entry_offset + if hdr.is_64 { 8 } else { 4 };
            markup.add_comment(CommentEntry::new(entry_offset, comment, CommentType::Eol));

            // Add cross-references for address-type dynamic entries
            if is_address_dynamic_tag(d_tag) && d_val > 0 {
                markup.add_reference(ReferenceEntry::new(value_offset, d_val, "DATA"));
            }
        }
    }

    /// Helper: read a u32 at an arbitrary offset.
    fn read_u32_at(&self, data: &[u8], offset: u64, is_le: bool) -> u32 {
        let off = offset as usize;
        if off + 4 > data.len() {
            return 0;
        }
        let bytes = [data[off], data[off + 1], data[off + 2], data[off + 3]];
        if is_le {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        }
    }

    /// Helper: read a u64 at an arbitrary offset.
    fn read_u64_at(&self, data: &[u8], offset: u64, is_le: bool) -> u64 {
        let off = offset as usize;
        if off + 8 > data.len() {
            return 0;
        }
        let bytes = [
            data[off],
            data[off + 1],
            data[off + 2],
            data[off + 3],
            data[off + 4],
            data[off + 5],
            data[off + 6],
            data[off + 7],
        ];
        if is_le {
            u64::from_le_bytes(bytes)
        } else {
            u64::from_be_bytes(bytes)
        }
    }
}

impl Default for ElfAnalysisCommand {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryAnalysisCommand for ElfAnalysisCommand {
    fn name(&self) -> &str {
        "ELF Header Annotation"
    }

    fn can_apply(&self, data: &[u8]) -> bool {
        data.len() >= 16
            && data[0] == 0x7f
            && data[1] == b'E'
            && data[2] == b'L'
            && data[3] == b'F'
    }

    fn apply(&self, data: &[u8], is_little_endian: bool) -> Result<ProgramMarkup, String> {
        self.messages.clear();
        let mut markup = ProgramMarkup::new();

        // Parse ELF header
        let hdr = self.parse_elf_header(data)?;

        // Verify endianness matches expectation
        let expected_le = hdr.data_encoding == ElfDataEncoding::LittleEndian;
        if expected_le != is_little_endian {
            self.messages.append_warning(format!(
                "Endianness mismatch: ELF says {} but caller specified {}",
                if expected_le { "LE" } else { "BE" },
                if is_little_endian { "LE" } else { "BE" },
            ));
        }

        // Process ELF header
        self.process_elf_header(&hdr, &mut markup);

        // Parse and process program headers
        let phdrs = self.parse_program_headers(data, &hdr).unwrap_or_else(|e| {
            self.messages.append_warning(format!("Failed to parse program headers: {}", e));
            Vec::new()
        });
        self.process_program_headers(data, &hdr, &phdrs, &mut markup);

        // Parse and process section headers
        let shdrs = self.parse_section_headers(data, &hdr).unwrap_or_else(|e| {
            self.messages.append_warning(format!("Failed to parse section headers: {}", e));
            Vec::new()
        });
        self.process_section_headers(data, &hdr, &shdrs, &mut markup);

        // Process string tables
        self.process_string_tables(data, &hdr, &shdrs, &mut markup);

        // Process symbol tables
        self.process_symbol_tables(data, &hdr, &shdrs, &mut markup);

        // Process relocation tables
        self.process_relocation_tables(data, &hdr, &shdrs, &mut markup);

        // Process dynamic section
        self.process_dynamic_section(data, &hdr, &shdrs, &phdrs, &mut markup);

        // Log summary
        self.messages.append_msg(format!(
            "ELF analysis complete: {} markups, {} fragments, {} labels, {} comments",
            markup.data_markups.len(),
            markup.fragments.len(),
            markup.labels.len(),
            markup.comments.len(),
        ));

        Ok(markup)
    }

    fn messages(&self) -> &MessageLog {
        &self.messages
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Read a null-terminated string from data at the given offset.
fn read_null_terminated(data: &[u8], offset: usize) -> String {
    let mut end = offset;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    if end == offset {
        return String::new();
    }
    String::from_utf8_lossy(&data[offset..end]).into_owned()
}

/// Get a human-readable name for an ELF machine type.
fn elf_machine_name(machine: u16) -> &'static str {
    match machine {
        0 => "EM_NONE",
        1 => "EM_M32",
        2 => "EM_SPARC",
        3 => "EM_386",
        4 => "EM_68K",
        5 => "EM_88K",
        6 => "EM_486",
        7 => "EM_860",
        8 => "EM_MIPS",
        9 => "EM_S370",
        10 => "EM_MIPS_RS3_LE",
        15 => "EM_PARISC",
        17 => "EM_VPP500",
        18 => "EM_SPARC32PLUS",
        19 => "EM_960",
        20 => "EM_PPC",
        21 => "EM_PPC64",
        22 => "EM_S390",
        36 => "EM_V800",
        37 => "EM_FR20",
        38 => "EM_RH32",
        39 => "EM_RCE",
        40 => "EM_ARM",
        41 => "EM_FAKE_ALPHA",
        42 => "EM_SH",
        43 => "EM_SPARCV9",
        44 => "EM_TRICORE",
        45 => "EM_ARC",
        46 => "EM_H8_300",
        47 => "EM_H8_300H",
        48 => "EM_H8S",
        49 => "EM_H8_500",
        50 => "EM_IA_64",
        51 => "EM_MIPS_X",
        52 => "EM_COLDFIRE",
        53 => "EM_68HC12",
        54 => "EM_MMA",
        55 => "EM_PCP",
        56 => "EM_NCPU",
        57 => "EM_NDR1",
        58 => "EM_STARCORE",
        59 => "EM_ME16",
        60 => "EM_ST100",
        61 => "EM_TINYJ",
        62 => "EM_X86_64",
        63 => "EM_PDSP",
        66 => "EM_FX66",
        67 => "EM_ST9PLUS",
        68 => "EM_ST7",
        69 => "EM_68HC16",
        70 => "EM_68HC11",
        71 => "EM_68HC08",
        72 => "EM_68HC05",
        73 => "EM_SVX",
        74 => "EM_ST19",
        75 => "EM_VAX",
        76 => "EM_CRIS",
        77 => "EM_JAVELIN",
        78 => "EM_FIREPATH",
        79 => "EM_ZSP",
        80 => "EM_MMIX",
        81 => "EM_HUANY",
        82 => "EM_PRISM",
        83 => "EM_AVR",
        84 => "EM_FR30",
        85 => "EM_D10V",
        86 => "EM_D30V",
        87 => "EM_V850",
        88 => "EM_M32R",
        89 => "EM_MN10300",
        90 => "EM_MN10200",
        91 => "EM_PJ",
        92 => "EM_OPENRISC",
        93 => "EM_ARC_A5",
        94 => "EM_XTENSA",
        95 => "EM_VIDEOCORE",
        96 => "EM_TMM_GPP",
        97 => "EM_NS32K",
        98 => "EM_TPC",
        99 => "EM_SNP1K",
        100 => "EM_ST200",
        101 => "EM_IP2K",
        102 => "EM_MAX",
        103 => "EM_CR",
        104 => "EM_F2MC16",
        105 => "EM_MSP430",
        106 => "EM_BLACKFIN",
        107 => "EM_SE_C33",
        108 => "EM_SEP",
        109 => "EM_ARCA",
        110 => "EM_UNICORE",
        183 => "EM_AARCH64",
        167 => "EM_RISCV",
        243 => "EM_BPF",
        247 => "EM_LOONGARCH",
        _ => "EM_UNKNOWN",
    }
}

/// Get a human-readable name for an ELF program header type.
fn elf_phdr_type_name(p_type: u32) -> &'static str {
    match p_type {
        0 => "PT_NULL",
        1 => "PT_LOAD",
        2 => "PT_DYNAMIC",
        3 => "PT_INTERP",
        4 => "PT_NOTE",
        5 => "PT_SHLIB",
        6 => "PT_PHDR",
        7 => "PT_TLS",
        0x6474e550 => "PT_GNU_EH_FRAME",
        0x6474e551 => "PT_GNU_STACK",
        0x6474e552 => "PT_GNU_RELRO",
        _ => "PT_UNKNOWN",
    }
}

/// Get a human-readable name for an ELF dynamic tag.
fn elf_dynamic_tag_name(tag: i64) -> &'static str {
    match tag {
        0 => "DT_NULL",
        1 => "DT_NEEDED",
        2 => "DT_PLTRELSZ",
        3 => "DT_PLTGOT",
        4 => "DT_HASH",
        5 => "DT_STRTAB",
        6 => "DT_SYMTAB",
        7 => "DT_RELA",
        8 => "DT_RELASZ",
        9 => "DT_RELAENT",
        10 => "DT_STRSZ",
        11 => "DT_SYMENT",
        12 => "DT_INIT",
        13 => "DT_FINI",
        14 => "DT_SONAME",
        15 => "DT_RPATH",
        16 => "DT_SYMBOLIC",
        17 => "DT_REL",
        18 => "DT_RELSZ",
        19 => "DT_RELENT",
        20 => "DT_PLTREL",
        22 => "DT_INIT_ARRAY",
        23 => "DT_FINI_ARRAY",
        24 => "DT_INIT_ARRAYSZ",
        25 => "DT_FINI_ARRAYSZ",
        26 => "DT_FLAGS",
        30 => "DT_FLAGS_1",
        0x6ffffef5 => "DT_GNU_HASH",
        0x6ffffffe => "DT_VERNEED",
        0x6fffffff => "DT_VERNEEDNUM",
        0x6ffffff0 => "DT_VERSYM",
        _ => "DT_UNKNOWN",
    }
}

/// Check if a dynamic tag points to a string.
fn is_string_dynamic_tag(tag: i64) -> bool {
    matches!(tag, 1 | 14 | 15 | 29) // DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH
}

/// Check if a dynamic tag points to an address.
fn is_address_dynamic_tag(tag: i64) -> bool {
    matches!(tag, 3 | 12 | 13 | 22 | 23) // DT_PLTGOT, DT_INIT, DT_FINI, DT_INIT_ARRAY, DT_FINI_ARRAY
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid ELF64 LE binary.
    fn make_elf64_le() -> Vec<u8> {
        let mut data = vec![0u8; 512];

        // e_ident
        data[0] = 0x7f;
        data[1] = b'E';
        data[2] = b'L';
        data[3] = b'F';
        data[4] = 2; // ELFCLASS64
        data[5] = 1; // ELFDATA2LSB (LE)
        data[6] = 1; // EV_CURRENT
        data[7] = 0; // ELFOSABI_NONE

        // e_type = ET_EXEC (2)
        data[16] = 0x02;
        data[17] = 0x00;
        // e_machine = EM_X86_64 (62)
        data[18] = 0x3E;
        data[19] = 0x00;
        // e_version = 1
        data[20] = 0x01;
        // e_entry = 0x400000
        data[24] = 0x00;
        data[25] = 0x00;
        data[26] = 0x40;
        data[27] = 0x00;
        // e_phoff = 64 (right after header)
        data[32] = 64;
        // e_shoff = 256
        data[40] = 0x00;
        data[41] = 0x01;
        // e_ehsize = 64
        data[52] = 64;
        // e_phentsize = 56
        data[54] = 56;
        // e_phnum = 1
        data[56] = 1;
        // e_shentsize = 64
        data[58] = 64;
        // e_shnum = 3 (NULL + .text + .shstrtab)
        data[60] = 3;
        // e_shstrndx = 2
        data[62] = 2;

        // Program header (at offset 64): PT_LOAD
        let phdr_off = 64;
        data[phdr_off] = 1; // p_type = PT_LOAD
        // p_flags = 5 (PF_R | PF_X)
        data[phdr_off + 4] = 0x05;
        // p_offset = 0
        // p_vaddr = 0x400000
        data[phdr_off + 16] = 0x00;
        data[phdr_off + 17] = 0x00;
        data[phdr_off + 18] = 0x40;
        data[phdr_off + 19] = 0x00;
        // p_filesz = 512
        data[phdr_off + 32] = 0x00;
        data[phdr_off + 33] = 0x02;
        // p_memsz = 512
        data[phdr_off + 40] = 0x00;
        data[phdr_off + 41] = 0x02;

        // Section headers at offset 256 (3 headers * 64 bytes = 192 bytes)
        // shstrtab content at offset 448
        let shstrtab_off = 448;
        data[shstrtab_off] = 0; // empty string at index 0
        let s1 = b".text\0.shstrtab\0";
        data[shstrtab_off + 1..shstrtab_off + 1 + s1.len()].copy_from_slice(s1);

        // Section header 0: NULL
        // (all zeros, already)

        // Section header 1: .text
        let sh1_off = 256 + 64; // offset 320
        // sh_name = 1 (index into shstrtab)
        data[sh1_off] = 1;
        // sh_type = SHT_PROGBITS (1)
        data[sh1_off + 4] = 1;
        // sh_offset = 0
        // sh_size = 256
        data[sh1_off + 40] = 0x00;
        data[sh1_off + 41] = 0x01;

        // Section header 2: .shstrtab
        let sh2_off = 256 + 128; // offset 384
        // sh_name = 7
        data[sh2_off] = 7;
        // sh_type = SHT_STRTAB (3)
        data[sh2_off + 4] = 3;
        // sh_offset = 448
        data[sh2_off + 24] = 0xC0;
        data[sh2_off + 25] = 0x01;
        // sh_size = 20
        data[sh2_off + 32] = 20;

        data
    }

    #[test]
    fn test_elf_can_apply() {
        let cmd = ElfAnalysisCommand::new();
        let data = make_elf64_le();
        assert!(cmd.can_apply(&data));
    }

    #[test]
    fn test_elf_cannot_apply_non_elf() {
        let cmd = ElfAnalysisCommand::new();
        assert!(!cmd.can_apply(&[0x7f, 0x00, 0x00, 0x00]));
        assert!(!cmd.can_apply(&[0x00, 0x00, 0x00, 0x00]));
        assert!(!cmd.can_apply(&[]));
    }

    #[test]
    fn test_elf_apply_basic() {
        let cmd = ElfAnalysisCommand::new();
        let data = make_elf64_le();
        let result = cmd.apply(&data, true);
        assert!(result.is_ok(), "ELF analysis failed: {:?}", result.err());

        let markup = result.unwrap();
        // Should have at least ELF header markup
        assert!(!markup.data_markups.is_empty(), "Expected at least 1 markup");
        assert!(!markup.fragments.is_empty(), "Expected at least 1 fragment");

        // First markup should be at address 0 (ELF header)
        assert_eq!(markup.data_markups[0].address, 0);

        // Should have at least the ELF Header fragment
        let has_elf_header = markup.fragments.iter().any(|f| f.name == "ELF Header");
        assert!(has_elf_header, "Expected 'ELF Header' fragment");
    }

    #[test]
    fn test_elf_parse_header() {
        let cmd = ElfAnalysisCommand::new();
        let data = make_elf64_le();
        let hdr = cmd.parse_elf_header(&data).unwrap();
        assert_eq!(hdr.class, ElfClass::ELF64);
        assert!(hdr.is_64);
        assert!(hdr.is_le);
        assert_eq!(hdr.e_type, 2); // ET_EXEC
        assert_eq!(hdr.e_machine, 62); // EM_X86_64
        assert_eq!(hdr.e_entry, 0x400000);
        assert_eq!(hdr.e_phoff, 64);
        assert_eq!(hdr.e_phnum, 1);
        assert_eq!(hdr.e_shnum, 3);
    }

    #[test]
    fn test_elf_parse_program_headers() {
        let cmd = ElfAnalysisCommand::new();
        let data = make_elf64_le();
        let hdr = cmd.parse_elf_header(&data).unwrap();
        let phdrs = cmd.parse_program_headers(&data, &hdr).unwrap();
        assert_eq!(phdrs.len(), 1);
        assert_eq!(phdrs[0].p_type, 1); // PT_LOAD
    }

    #[test]
    fn test_elf_parse_section_headers() {
        let cmd = ElfAnalysisCommand::new();
        let data = make_elf64_le();
        let hdr = cmd.parse_elf_header(&data).unwrap();
        let shdrs = cmd.parse_section_headers(&data, &hdr).unwrap();
        assert_eq!(shdrs.len(), 3);
        // Names should be resolved from shstrtab
        assert_eq!(shdrs[0].name, ""); // NULL section
        assert_eq!(shdrs[1].name, ".text");
        assert_eq!(shdrs[2].name, ".shstrtab");
    }

    #[test]
    fn test_elf_machine_names() {
        assert_eq!(elf_machine_name(3), "EM_386");
        assert_eq!(elf_machine_name(62), "EM_X86_64");
        assert_eq!(elf_machine_name(40), "EM_ARM");
        assert_eq!(elf_machine_name(183), "EM_AARCH64");
    }

    #[test]
    fn test_elf_phdr_type_names() {
        assert_eq!(elf_phdr_type_name(0), "PT_NULL");
        assert_eq!(elf_phdr_type_name(1), "PT_LOAD");
        assert_eq!(elf_phdr_type_name(2), "PT_DYNAMIC");
        assert_eq!(elf_phdr_type_name(3), "PT_INTERP");
    }

    #[test]
    fn test_elf_dynamic_tag_names() {
        assert_eq!(elf_dynamic_tag_name(0), "DT_NULL");
        assert_eq!(elf_dynamic_tag_name(1), "DT_NEEDED");
        assert_eq!(elf_dynamic_tag_name(5), "DT_STRTAB");
    }

    #[test]
    fn test_elf_is_string_dynamic_tag() {
        assert!(is_string_dynamic_tag(1)); // DT_NEEDED
        assert!(is_string_dynamic_tag(14)); // DT_SONAME
        assert!(!is_string_dynamic_tag(3)); // DT_PLTGOT
    }

    #[test]
    fn test_elf_is_address_dynamic_tag() {
        assert!(is_address_dynamic_tag(3)); // DT_PLTGOT
        assert!(is_address_dynamic_tag(12)); // DT_INIT
        assert!(!is_address_dynamic_tag(1)); // DT_NEEDED
    }

    #[test]
    fn test_elf_read_null_terminated() {
        let data = b"hello\0world\0";
        assert_eq!(read_null_terminated(data, 0), "hello");
        assert_eq!(read_null_terminated(data, 6), "world");
        assert_eq!(read_null_terminated(data, 5), "");
    }

    #[test]
    fn test_elf_name() {
        let cmd = ElfAnalysisCommand::new();
        assert_eq!(cmd.name(), "ELF Header Annotation");
    }

    #[test]
    fn test_elf_messages() {
        let cmd = ElfAnalysisCommand::new();
        let data = make_elf64_le();
        let _ = cmd.apply(&data, true);
        // Messages should contain the summary
        let summary = cmd.messages().to_string_lossy();
        assert!(summary.contains("ELF analysis complete"));
    }
}
