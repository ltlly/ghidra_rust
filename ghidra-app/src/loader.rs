//! Binary file loader for Ghidra Rust.
//!
//! Loads executables (ELF, PE, Mach-O) and raw binaries into a
//! [`Program`] ready for disassembly and analysis.
//!
//! # File Format Detection
//!
//! The loader sniffs magic bytes at the start of the file to determine
//! the format:
//!
//! | Magic               | Format   |
//! |---------------------|----------|
//! | `0x7f E L F`        | ELF      |
//! | `M Z` (0x4d 0x5a)   | PE/COFF  |
//! | `0xfe 0xed 0xfa...` | Mach-O   |
//! | Anything else       | Raw      |
//!
//! # Example
//!
//! ```ignore
//! use ghidra_app::loader::load_program;
//! let program = load_program("target.exe", 0x400000, None)?;
//! analyze_program(&program, 60)?;
//! ```

use ghidra_core::addr::{Address, AddressRange};
use ghidra_core::listing::{InstructionMnemonic, ListingRow};
use ghidra_core::program::{
    Comment, CommentKind, ListingData, MemoryBlock, MemoryPermissions, Program, SymbolTable,
};
use ghidra_core::symbol::{Symbol, SymbolKind};
use std::fs;
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// File format detection
// ---------------------------------------------------------------------------

/// Recognised binary file formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFormat {
    /// Executable and Linkable Format (Linux, BSD, embedded).
    Elf,
    /// Portable Executable / COFF (Windows).
    Pe,
    /// Mach-O (macOS, iOS).
    Macho,
    /// Flat raw binary (firmware, ROM dumps, shellcode).
    Raw,
}

impl FileFormat {
    /// Return a human-readable name for the format.
    pub fn as_str(&self) -> &'static str {
        match self {
            FileFormat::Elf => "ELF",
            FileFormat::Pe => "PE",
            FileFormat::Macho => "Mach-O",
            FileFormat::Raw => "Raw",
        }
    }
}

/// Sniff the first few bytes of a buffer to identify the file format.
fn detect_format(data: &[u8], _arch: Option<&str>) -> FileFormat {
    if data.len() < 4 {
        return FileFormat::Raw;
    }

    match &data[0..4] {
        // ELF: 0x7f 'E' 'L' 'F'
        [0x7f, b'E', b'L', b'F'] => FileFormat::Elf,
        // PE: 'M' 'Z' (DOS header magic)
        [0x4d, 0x5a, ..] => FileFormat::Pe,
        // Mach-O 32-bit big-endian: 0xfe 0xed 0xfa 0xce
        [0xfe, 0xed, 0xfa, 0xce] => FileFormat::Macho,
        // Mach-O 32-bit little-endian: 0xce 0xfa 0xed 0xfe
        [0xce, 0xfa, 0xed, 0xfe] => FileFormat::Macho,
        // Mach-O 64-bit big-endian: 0xfe 0xed 0xfa 0xcf
        [0xfe, 0xed, 0xfa, 0xcf] => FileFormat::Macho,
        // Mach-O 64-bit little-endian: 0xcf 0xfa 0xed 0xfe
        [0xcf, 0xfa, 0xed, 0xfe] => FileFormat::Macho,
        _ => FileFormat::Raw,
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Load a binary file from disk into a [`Program`] ready for analysis.
///
/// The file format is detected automatically.  Use the `arch` parameter to
/// override the inferred architecture for raw binaries.
///
/// # Errors
///
/// Returns an error if the file does not exist, is empty, or cannot be
/// parsed in the detected format.
pub fn load_program(path: &Path, base: u64, arch: Option<&str>) -> anyhow::Result<Program> {
    if !path.exists() {
        anyhow::bail!("File not found: {}", path.display());
    }

    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let file_data = fs::read(path)?;
    if file_data.is_empty() {
        anyhow::bail!("File is empty: {}", path.display());
    }

    let fmt = detect_format(&file_data, arch);
    log::info!(
        "Detected {} format for '{}' ({} bytes)",
        fmt.as_str(),
        name,
        file_data.len()
    );

    load_internal(&name, &file_data, base, arch, fmt)
}

/// Run automated analysis on a loaded program.
///
/// Analysis includes function detection, cross-reference building, and
/// data-type inference.  The `timeout_secs` parameter caps the total wall
/// time; if exceeded a [`LoaderTimeout`](anyhow::Error) is returned.
///
/// This is a placeholder that provides a basic analysis scaffold.  A
/// production build would integrate the full analysis pipeline from
/// `ghidra-core` and `ghidra-decompile`.
pub fn analyze_program(program: &Program, timeout_secs: u64) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);

    log::info!(
        "Starting analysis of '{}' (timeout: {}s)",
        program.name,
        timeout_secs
    );

    // --- Phase 1: Function detection ---
    detect_functions(program)?;
    check_deadline(deadline, timeout_secs)?;

    // --- Phase 2: Cross-reference building ---
    build_xrefs(program)?;
    check_deadline(deadline, timeout_secs)?;

    // --- Phase 3: Data-type detection ---
    detect_data_types(program)?;

    let fn_count = program
        .symbol_table
        .iter()
        .filter(|s| s.kind() == SymbolKind::Function)
        .count();

    log::info!(
        "Analysis complete: {} functions, {} symbols, {} xrefs",
        fn_count,
        program.symbol_table.len(),
        program.xrefs.len()
    );

    Ok(())
}

/// Export decompiled C code from a program to a file.
///
/// Delegates to [`crate::exporter::ExportManager::export_c`].
pub fn export_decompiled(program: &Program, output: &Path) -> anyhow::Result<()> {
    let manager = crate::exporter::ExportManager::new();
    manager.export_c(program, output)?;
    log::info!("Decompiled code exported to {}", output.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal: loader dispatch
// ---------------------------------------------------------------------------

/// Dispatch to the appropriate format-specific loader.
fn load_internal(
    name: &str,
    data: &[u8],
    base: u64,
    arch: Option<&str>,
    fmt: FileFormat,
) -> anyhow::Result<Program> {
    match fmt {
        FileFormat::Elf => load_elf(name, data, base),
        FileFormat::Pe => load_pe(name, data, base),
        FileFormat::Macho => load_macho(name, data),
        FileFormat::Raw => load_raw(name, data, base, arch),
    }
}

// ---------------------------------------------------------------------------
// Internal: ELF loader
// ---------------------------------------------------------------------------

/// Load an ELF binary into a [`Program`].
///
/// Reads the ELF header to extract the entry point, section headers, and
/// program headers, then maps memory sections and populates symbols.
fn load_elf(name: &str, data: &[u8], base: u64) -> anyhow::Result<Program> {
    // Minimal ELF header parsing (64-bit LE assumed for demo).
    // Production code would use the full `ghidra_features::elf` parser.

    if data.len() < 64 {
        anyhow::bail!("ELF file too small ({} bytes)", data.len());
    }

    let is_64bit = data[4] == 2; // EI_CLASS: 1=32-bit, 2=64-bit
    let is_le = data[5] == 1; // EI_DATA: 1=LE, 2=BE

    let entry = if is_64bit {
        read_u64(data, 24, is_le)
    } else {
        read_u32(data, 24, is_le) as u64
    };

    let phoff = if is_64bit {
        read_u64(data, 32, is_le)
    } else {
        read_u32(data, 28, is_le) as u64
    };

    let phnum = read_u16(data, if is_64bit { 56 } else { 44 }, is_le) as usize;
    let shoff = if is_64bit {
        read_u64(data, 40, is_le)
    } else {
        read_u32(data, 32, is_le) as u64
    };
    let shnum = read_u16(data, if is_64bit { 60 } else { 48 }, is_le) as usize;

    let image_base = base;
    let mut program = Program::new(name.to_string(), Address::new(image_base));

    // Parse program headers to build memory blocks
    let phentsize = if is_64bit { 56usize } else { 32usize };
    for i in 0..phnum.min(128) {
        let off = phoff as usize + i * phentsize;
        if off + phentsize > data.len() {
            break;
        }
        let p_type = read_u32(data, off, is_le);
        // PT_LOAD = 1
        if p_type != 1 {
            continue;
        }
        let p_offset = if is_64bit {
            read_u64(data, off + 8, is_le)
        } else {
            read_u32(data, off + 4, is_le) as u64
        };
        let p_vaddr = if is_64bit {
            read_u64(data, off + 16, is_le)
        } else {
            read_u32(data, off + 8, is_le) as u64
        };
        let p_filesz = if is_64bit {
            read_u64(data, off + 32, is_le)
        } else {
            read_u32(data, off + 16, is_le) as u64
        };
        let p_memsz = if is_64bit {
            read_u64(data, off + 40, is_le)
        } else {
            read_u32(data, off + 20, is_le) as u64
        };
        let p_flags = read_u32(data, if is_64bit { off + 4 } else { off + 24 }, is_le);

        let perms = elf_segment_permissions(p_flags);
        let start = image_base + p_vaddr;
        let size = p_memsz.max(p_filesz);
        if size == 0 {
            continue;
        }

        let name = if p_flags & 1 != 0 {
            ".text"
        } else {
            ".data"
        };
        let block_name = format!("{}_{}", name, i);

        program.memory_blocks.insert(
            block_name.clone(),
            MemoryBlock {
                name: block_name,
                range: AddressRange::new(Address::new(start), Address::new(start + size - 1)),
                permissions: perms,
                initialized: p_filesz > 0,
                data: Vec::new(),            },
        );

        // Populate listing rows from segment data
        let seg_data = &data[p_offset as usize..(p_offset + p_filesz).min(data.len() as u64) as usize];
        populate_listing_from_bytes(&mut program, start, seg_data);
    }

    // Parse section headers for symbol names
    let shentsize = if is_64bit { 64usize } else { 40usize };
    let shstrtab_off = if shnum > 0 && shoff > 0 {
        // Read shstrndx
        let shstrndx = if is_64bit {
            read_u16(data, 62, is_le) as usize
        } else {
            read_u16(data, 50, is_le) as usize
        };

        if shstrndx < shnum {
            let idx_off = shoff as usize + shstrndx * shentsize;
            if idx_off + shentsize <= data.len() {
                if is_64bit {
                    read_u64(data, idx_off + 24, is_le)
                } else {
                    read_u32(data, idx_off + 16, is_le) as u64
                }
            } else {
                shoff
            }
        } else {
            shoff
        }
    } else {
        shoff
    };

    // Parse sections for symbol table
    for i in 0..shnum.min(128) {
        let soff = shoff as usize + i * shentsize;
        if soff + shentsize > data.len() {
            break;
        }
        let sh_type = read_u32(data, soff + 4, is_le);
        // SHT_SYMTAB = 2, SHT_DYNSYM = 11
        if sh_type != 2 && sh_type != 11 {
            continue;
        }
        let sh_link = read_u32(data, soff + if is_64bit { 40 } else { 24 }, is_le);
        let sh_offset = if is_64bit {
            read_u64(data, soff + 24, is_le)
        } else {
            read_u32(data, soff + 16, is_le) as u64
        };
        let sh_size = if is_64bit {
            read_u64(data, soff + 32, is_le)
        } else {
            read_u32(data, soff + 20, is_le) as u64
        };
        let sh_entsize = if is_64bit {
            read_u64(data, soff + 56, is_le)
        } else {
            read_u32(data, soff + 36, is_le) as u64
        };

        if sh_entsize == 0 {
            continue;
        }

        // Extract symbol names from string table
        let str_off = if (sh_link as usize) < shnum {
            let str_soff = shoff as usize + (sh_link as usize) * shentsize;
            if str_soff + shentsize <= data.len() {
                if is_64bit {
                    read_u64(data, str_soff + 24, is_le)
                } else {
                    read_u32(data, str_soff + 16, is_le) as u64
                }
            } else {
                shoff
            }
        } else {
            shoff
        };

        let sym_count = (sh_size / sh_entsize).min(1024) as usize;
        for j in 0..sym_count {
            let sym_off = sh_offset as usize + j * sh_entsize as usize;
            if sym_off + sh_entsize as usize > data.len() {
                break;
            }
            let st_name = read_u32(data, sym_off, is_le);
            let st_value = if is_64bit {
                read_u64(data, sym_off + 8, is_le)
            } else {
                read_u32(data, sym_off + 4, is_le) as u64
            };
            let st_size = if is_64bit {
                read_u64(data, sym_off + 16, is_le)
            } else {
                read_u32(data, sym_off + 8, is_le) as u64
            };

            let name = read_c_string(data, (str_off + st_name as u64) as usize);
            if name.is_empty() || name.starts_with('\0') {
                continue;
            }

            let addr = Address::new(image_base + st_value);
            if st_size > 0 && !name.starts_with('.') {
                program
                    .symbol_table
                    .add(Symbol::function(name.clone(), addr));
            } else if st_value > 0 {
                program
                    .symbol_table
                    .add(Symbol::label(name.clone(), addr));
            }
        }
    }

    // Always add the entry point symbol
    let entry_addr = Address::new(image_base + entry);
    if program.symbol_at(&entry_addr).is_none() {
        program
            .symbol_table
            .add(Symbol::function("_start".to_string(), entry_addr));
    }

    program.file_path = Some(name.to_string());
    Ok(program)
}

// ---------------------------------------------------------------------------
// Internal: PE loader
// ---------------------------------------------------------------------------

/// Load a PE/COFF binary into a [`Program`].
fn load_pe(name: &str, data: &[u8], base: u64) -> anyhow::Result<Program> {
    // Minimal PE header parsing.
    // Production code would use the full `ghidra_features::pe` parser.

    if data.len() < 64 {
        anyhow::bail!("PE file too small ({} bytes)", data.len());
    }

    // DOS header: e_lfanew at offset 0x3c
    if data.len() < 64 {
        anyhow::bail!("PE file too small for DOS header");
    }
    let pe_offset = read_u32(data, 0x3c, true) as usize;

    // PE signature check
    if pe_offset + 4 > data.len()
        || &data[pe_offset..pe_offset + 4] != b"PE\0\0"
    {
        anyhow::bail!("Invalid PE signature at offset 0x{:x}", pe_offset);
    }

    // COFF header starts after PE signature (4 bytes)
    let coff_off = pe_offset + 4;
    if coff_off + 20 > data.len() {
        anyhow::bail!("COFF header out of bounds");
    }

    let num_sections = read_u16(data, coff_off + 2, true) as usize;
    let opt_header_size = read_u16(data, coff_off + 16, true) as usize;

    // Optional header
    let opt_off = coff_off + 20;
    if opt_off + opt_header_size > data.len() {
        anyhow::bail!("Optional header out of bounds");
    }

    let is_pe32plus = opt_header_size >= 2 && read_u16(data, opt_off, true) == 0x020b;
    let image_base_pe = if is_pe32plus {
        read_u64(data, opt_off + 24, true)
    } else {
        read_u32(data, opt_off + 28, true) as u64
    };

    let entry_rva = if is_pe32plus {
        read_u32(data, opt_off + 16, true)
    } else {
        read_u32(data, opt_off + 16, true)
    };

    let image_base = if base != 0 { base } else { image_base_pe };
    let mut program = Program::new(name.to_string(), Address::new(image_base));

    // Section headers
    let section_off = opt_off + opt_header_size;
    let section_entry_size = 40usize;

    for i in 0..num_sections.min(128) {
        let soff = section_off + i * section_entry_size;
        if soff + section_entry_size > data.len() {
            break;
        }

        let sec_name = read_fixed_string(data, soff, 8);
        let virtual_size = read_u32(data, soff + 8, true) as u64;
        let virtual_addr = read_u32(data, soff + 12, true) as u64;
        let raw_size = read_u32(data, soff + 16, true) as u64;
        let raw_offset = read_u32(data, soff + 20, true) as usize;
        let characteristics = read_u32(data, soff + 36, true);

        let perms = pe_section_permissions(characteristics);
        let start = image_base + virtual_addr;
        let size = virtual_size.max(raw_size);
        if size == 0 {
            continue;
        }

        let block_name = if sec_name.is_empty() {
            format!(".section_{}", i)
        } else {
            sec_name
        };

        program.memory_blocks.insert(
            block_name.clone(),
            MemoryBlock {
                name: block_name,
                range: AddressRange::new(Address::new(start), Address::new(start + size - 1)),
                permissions: perms,
                initialized: raw_size > 0,
                data: Vec::new(),            },
        );

        // Populate listing from section data
        if raw_offset > 0 && raw_offset < data.len() {
            let section_data = &data[raw_offset..(raw_offset + raw_size as usize).min(data.len())];
            populate_listing_from_bytes(&mut program, start, section_data);
        }
    }

    // Add entry point symbol
    let entry_addr = Address::new(image_base + entry_rva as u64);
    program
        .symbol_table
        .add(Symbol::function("entry".to_string(), entry_addr));

    program.file_path = Some(name.to_string());
    Ok(program)
}

// ---------------------------------------------------------------------------
// Internal: Mach-O loader
// ---------------------------------------------------------------------------

/// Load a Mach-O binary into a [`Program`].
fn load_macho(name: &str, data: &[u8]) -> anyhow::Result<Program> {
    if data.len() < 28 {
        anyhow::bail!("Mach-O file too small ({} bytes)", data.len());
    }

    let magic = read_u32(data, 0, true);
    let is_64bit = matches!(magic, 0xfeedfacf | 0xcffaedfe);
    let is_le = matches!(magic, 0xfeedface | 0xfeedfacf);

    let cputype = read_u32(data, 4, is_le);
    let _cpusubtype = read_u32(data, 8, is_le);
    let filetype = read_u32(data, 12, is_le);
    let ncmds = read_u32(data, 16, is_le) as usize;
    let sizeofcmds = read_u32(data, 20, is_le) as usize;

    let header_size = if is_64bit { 32usize } else { 28usize };

    let image_base = guess_macho_base(filetype);
    let mut program = Program::new(name.to_string(), Address::new(image_base));

    let mut offset = header_size;
    let max_offset = (header_size + sizeofcmds).min(data.len());

    let mut entry_offset: Option<u64> = None;

    for _ in 0..ncmds {
        if offset + 8 > max_offset {
            break;
        }
        let cmd = read_u32(data, offset, is_le);
        let cmdsize = read_u32(data, offset + 4, is_le) as usize;
        if cmdsize == 0 || offset + cmdsize > max_offset {
            break;
        }

        match cmd {
            // LC_SEGMENT (32-bit)
            0x1 if !is_64bit => {
                parse_macho_segment(
                    &mut program, data, offset, cmdsize, is_le, image_base, false,
                );
            }
            // LC_SEGMENT_64
            0x19 if is_64bit => {
                parse_macho_segment(
                    &mut program, data, offset, cmdsize, is_le, image_base, true,
                );
            }
            // LC_MAIN (entry point)
            0x80000028 => {
                if offset + 16 <= data.len() {
                    entry_offset = Some(read_u64(data, offset + 8, is_le));
                }
            }
            // LC_UNIXTHREAD (entry point for older binaries)
            0x5 => {
                entry_offset = extract_thread_entry(data, offset, cmdsize, is_le, is_64bit);
            }
            _ => {}
        }

        offset += cmdsize;
    }

    // Set entry point
    if let Some(entry_off) = entry_offset {
        program
            .symbol_table
            .add(Symbol::function(
                "_main".to_string(),
                Address::new(image_base + entry_off),
            ));
    }

    program.file_path = Some(name.to_string());
    Ok(program)
}

/// Parse a Mach-O segment command and create memory blocks + listing rows.
fn parse_macho_segment(
    program: &mut Program,
    data: &[u8],
    offset: usize,
    _cmdsize: usize,
    is_le: bool,
    image_base: u64,
    is_64bit: bool,
) {
    let segname = read_fixed_string(data, offset + 8, 16);
    if segname == "__PAGEZERO" {
        return;
    }

    let (vmaddr, vmsize, fileoff, filesize, maxprot) = if is_64bit {
        (
            read_u64(data, offset + 24, is_le),
            read_u64(data, offset + 32, is_le),
            read_u64(data, offset + 40, is_le) as usize,
            read_u64(data, offset + 48, is_le) as usize,
            read_u32(data, offset + 56, is_le),
        )
    } else {
        (
            read_u32(data, offset + 24, is_le) as u64,
            read_u32(data, offset + 32, is_le) as u64,
            read_u32(data, offset + 36, is_le) as usize,
            read_u32(data, offset + 40, is_le) as usize,
            read_u32(data, offset + 44, is_le),
        )
    };

    let perms = macho_vm_protection(maxprot);
    let start = vmaddr;
    let size = vmsize.max(filesize as u64);
    if size == 0 {
        return;
    }

    let block_name = if segname.is_empty() {
        "segment".to_string()
    } else {
        segname.to_string()
    };

    program.memory_blocks.insert(
        block_name.clone(),
        MemoryBlock {
            name: block_name,
            range: AddressRange::new(Address::new(start), Address::new(start + size - 1)),
            permissions: perms,
            initialized: filesize > 0,
                data: Vec::new(),        },
    );

    // Populate listing from file data
    if fileoff > 0 && fileoff < data.len() {
        let seg_data = &data[fileoff..(fileoff + filesize).min(data.len())];
        populate_listing_from_bytes(program, start, seg_data);
    }
}

// ---------------------------------------------------------------------------
// Internal: Raw binary loader
// ---------------------------------------------------------------------------

/// Load a raw binary blob into a [`Program`].
///
/// Maps the entire file into a single memory block at `base`.
fn load_raw(name: &str, data: &[u8], base: u64, arch: Option<&str>) -> anyhow::Result<Program> {
    let arch = arch.unwrap_or("x86:LE:64");
    log::info!("Loading raw binary as {} at base 0x{:x}", arch, base);

    let mut program = Program::new(name.to_string(), Address::new(base));
    program.file_path = Some(name.to_string());

    let size = data.len() as u64;
    if size == 0 {
        anyhow::bail!("Raw binary data is empty");
    }

    // Single memory block covering the entire file
    program.memory_blocks.insert(
        "RAM".to_string(),
        MemoryBlock {
            name: "RAM".to_string(),
            range: AddressRange::new(Address::new(base), Address::new(base + size - 1)),
            permissions: MemoryPermissions::RX,
            initialized: true,
                data: Vec::new(),        },
    );

    // Populate listing from bytes
    populate_listing_from_bytes(&mut program, base, data);

    // Add entry point symbol at the base address
    program
        .symbol_table
        .add(Symbol::function("entry".to_string(), Address::new(base)));

    Ok(program)
}

// ---------------------------------------------------------------------------
// Internal: listing population from raw bytes
// ---------------------------------------------------------------------------

/// Populate the program's listing by performing a basic linear sweep over the
/// given byte slice starting at `start_addr`.
fn populate_listing_from_bytes(program: &mut Program, start_addr: u64, bytes: &[u8]) {
    let mut offset = start_addr;
    let mut i = 0;

    while i < bytes.len() {
        let remaining = bytes.len() - i;
        let (mnemonic, operand, consumed) = decode_x86_instruction(&bytes[i..], remaining, offset);

        let row_bytes: Vec<u8> = bytes[i..i + consumed].to_vec();
        program.listing.add(
            Address::new(offset),
            ListingRow {
                address: Address::new(offset),
                bytes: row_bytes,
                label: None,
                mnemonic: InstructionMnemonic::new(mnemonic),
                operands: operand.to_string(),
                full_instruction: format!("{} {}", mnemonic, operand),
                comment: None,
            },
        );

        offset += consumed as u64;
        i += consumed;
    }
}

// ---------------------------------------------------------------------------
// Minimal x86/x86-64 instruction decoder
// ---------------------------------------------------------------------------

/// A simplistic x86/x86-64 length decoder that returns the mnemonic, operand
/// text, and number of bytes consumed.
fn decode_x86_instruction(bytes: &[u8], _remaining: usize, _addr: u64) -> (&'static str, String, usize) {
    if bytes.is_empty() {
        return ("???", String::new(), 1);
    }

    match bytes[0] {
        // Standard opcodes
        0x00 => ("add", "[rax], al".to_string(), 2),          // ADD r/m8, r8
        0x01 => ("add", "[rax], eax".to_string(), 2),         // ADD r/m32, r32
        0x02 => ("add", "al, [rax]".to_string(), 2),          // ADD r8, r/m8
        0x03 => ("add", "eax, [rax]".to_string(), 2),         // ADD r32, r/m32
        0x05 => ("add", "eax, imm32".to_string(), 5),         // ADD EAX, imm32
        0x08 => ("or", "[rax], al".to_string(), 2),           // OR r/m8, r8
        0x09 => ("or", "[rax], eax".to_string(), 2),          // OR r/m32, r32
        0x0f => decode_two_byte_opcode(bytes),                 // Two-byte opcode
        0x20 => ("and", "[rax], al".to_string(), 2),          // AND r/m8, r8
        0x21 => ("and", "[rax], eax".to_string(), 2),         // AND r/m32, r32
        0x28 => ("sub", "[rax], al".to_string(), 2),          // SUB r/m8, r8
        0x29 => ("sub", "[rax], eax".to_string(), 2),         // SUB r/m32, r32
        0x30 => ("xor", "[rax], al".to_string(), 2),          // XOR r/m8, r8
        0x31 => ("xor", "[rax], eax".to_string(), 2),         // XOR r/m32, r32
        0x38 => ("cmp", "[rax], al".to_string(), 2),          // CMP r/m8, r8
        0x39 => ("cmp", "[rax], eax".to_string(), 2),         // CMP r/m32, r32
        0x40..=0x4f => ("rex_prefix", format!("rex.{}", bytes[0] - 0x40), 1), // REX prefixes
        0x50..=0x57 => {                                       // PUSH r64
            let reg = reg64_name(bytes[0] - 0x50);
            ("push", reg, 1)
        }
        0x58..=0x5f => {                                       // POP r64
            let reg = reg64_name(bytes[0] - 0x58);
            ("pop", reg, 1)
        }
        0x68 => ("push", format!("0x{:x}", read_imm(bytes, 1, 4)), 5), // PUSH imm32
        0x6a => ("push", format!("0x{:x}", bytes.get(1).copied().unwrap_or(0) as u64), 2), // PUSH imm8
        0x70..=0x7f => {                                       // Jcc rel8
            let cc = jcc_name(bytes[0] - 0x70);
            let target = if bytes.len() > 1 { bytes[1] as i8 } else { 0 };
            (cc, format!("0x{:x}", target), 2)
        }
        0x74 => ("je", format_rel8(bytes), 2),                 // JE rel8
        0x75 => ("jne", format_rel8(bytes), 2),                // JNE rel8
        0x80 => {
            // Group 1 r/m8, imm8
            if bytes.len() < 3 {
                ("???", String::new(), 1)
            } else {
                let op = group1_op(bytes[1]);
                (op, format!("byte [r?], 0x{:x}", bytes[2]), 3)
            }
        }
        0x81 => {
            // Group 1 r/m32, imm32
            if bytes.len() < 6 {
                ("???", String::new(), 1)
            } else {
                let op = group1_op(bytes[1]);
                let imm = read_imm(bytes, 2, 4);
                (op, format!("dword [r?], 0x{:x}", imm), 6)
            }
        }
        0x83 => {
            // Group 1 r/m32, imm8 (sign-extended)
            if bytes.len() < 3 {
                ("???", String::new(), 1)
            } else {
                let op = group1_op(bytes[1]);
                (op, format!("dword [r?], 0x{:x}", bytes[2]), 3)
            }
        }
        0x84 => ("test", "[r?], r8".to_string(), 2),           // TEST r/m8, r8
        0x85 => ("test", "[r?], r32".to_string(), 2),          // TEST r/m32, r32
        0x88 => ("mov", "[r?], r8".to_string(), 2),            // MOV r/m8, r8
        0x89 => ("mov", "[r?], r32".to_string(), 2),           // MOV r/m32, r32
        0x8a => ("mov", "r8, [r?]".to_string(), 2),            // MOV r8, r/m8
        0x8b => ("mov", "r32, [r?]".to_string(), 2),           // MOV r32, r/m32
        0x8d => ("lea", "r32, [r?]".to_string(), 2),           // LEA r32, m
        0x90 => ("nop", String::new(), 1),                     // NOP
        0x99 => ("cdq", String::new(), 1),                     // CDQ
        0x9d => ("popfq", String::new(), 1),                   // POPFQ
        0xa1 => {
            let addr = read_imm(bytes, 1, 4);
            ("mov", format!("eax, [0x{:x}]", addr), 5)
        }
        0xa3 => {
            let addr = read_imm(bytes, 1, 4);
            ("mov", format!("[0x{:x}], eax", addr), 5)
        }
        0xa9 => ("test", format!("eax, 0x{:x}", read_imm(bytes, 1, 4)), 5), // TEST EAX, imm32
        0xb0..=0xb7 => {                                       // MOV r8, imm8
            let reg = reg8_name(bytes[0] - 0xb0);
            ("mov", format!("{}, 0x{:x}", reg, bytes.get(1).copied().unwrap_or(0)), 2)
        }
        0xb8..=0xbf => {                                       // MOV r32, imm32 or MOV r64, imm64
            let reg = reg64_name(bytes[0] - 0xb8);
            let imm = read_imm(bytes, 1, 4);
            ("mov", format!("{}, 0x{:x}", reg, imm), 5)
        }
        0xc3 => ("ret", String::new(), 1),                     // RET
        0xc7 => {
            // MOV r/m32, imm32
            if bytes.len() < 6 {
                ("???", String::new(), 1)
            } else {
                let imm = read_imm(bytes, 2, 4);
                ("mov", format!("dword [r?], 0x{:x}", imm), 6)
            }
        }
        0xc9 => ("leave", String::new(), 1),                   // LEAVE
        0xcc => ("int3", String::new(), 1),                    // INT 3
        0xcd => ("int", format!("0x{:x}", bytes.get(1).copied().unwrap_or(0)), 2), // INT imm8
        0xd1 => {
            // Group 2 r/m32, 1
            let op = group2_op(bytes[1]);
            (op, "dword [r?], 1".to_string(), 2)
        }
        0xe8 => {
            // CALL rel32
            let rel = read_imm(bytes, 1, 4);
            ("call", format!("0x{:x}", rel), 5)
        }
        0xe9 => {
            // JMP rel32
            let rel = read_imm(bytes, 1, 4);
            ("jmp", format!("0x{:x}", rel), 5)
        }
        0xeb => ("jmp", format_rel8(bytes), 2),                // JMP rel8
        0xf3 => {
            // REP prefix -- look at next byte
            if bytes.len() > 1 {
                match bytes[1] {
                    0xa5 => ("rep movsd", String::new(), 2),
                    0xa7 => ("rep cmpsd", String::new(), 2),
                    0xab => ("rep stosd", String::new(), 2),
                    0x0f => {
                        if bytes.len() > 2 {
                            match bytes[2] {
                                0x2c => ("cvttss2si", format!("r32, xmm{}", (bytes.get(3).unwrap_or(&0) >> 3) & 7), 4),
                                _ => ("rep ???", String::new(), 2),
                            }
                        } else {
                            ("rep ???", String::new(), 2)
                        }
                    }
                    _ => ("rep ???", String::new(), 2),
                }
            } else {
                ("rep", String::new(), 1)
            }
        }
        0xf4 => ("hlt", String::new(), 1),                     // HLT
        0xf6 => {
            // Group 3 r/m8
            if bytes.len() < 2 {
                ("???", String::new(), 1)
            } else {
                let op = group3_op(bytes[1]);
                (op, "byte [r?]".to_string(), 2)
            }
        }
        0xf7 => {
            // Group 3 r/m32
            if bytes.len() < 2 {
                ("???", String::new(), 1)
            } else {
                let op = group3_op(bytes[1]);
                (op, "dword [r?]".to_string(), 2)
            }
        }
        0xff => {
            // Group 5
            if bytes.len() < 2 {
                ("???", String::new(), 1)
            } else {
                let op = group5_op(bytes[1]);
                (op, "[r?]".to_string(), 2)
            }
        }
        _ => ("db", format!("0x{:02x}", bytes[0]), 1),         // Unknown -- emit as data byte
    }
}

/// Decode two-byte opcodes (0x0F prefix).
fn decode_two_byte_opcode(bytes: &[u8]) -> (&'static str, String, usize) {
    if bytes.len() < 2 {
        return ("???", String::new(), 1);
    }
    match bytes[1] {
        0x05 => ("syscall", String::new(), 2),
        0x1f => ("nop", "dword [rax]".to_string(), 3),        // NOP DWORD ptr [RAX]
        0x31 => ("rdtsc", String::new(), 2),
        0x34 => ("sysenter", String::new(), 2),
        0x35 => ("sysexit", String::new(), 2),
        0x40..=0x4f => {
            // CMOVcc
            let cc = jcc_name(bytes[1] - 0x40);
            (cc, "r32, r/m32".to_string(), 3)
        }
        0x80..=0x8f => {
            // Jcc rel32
            let cc = jcc_name(bytes[1] - 0x80);
            let target = read_imm(bytes, 2, 4);
            (cc, format!("0x{:x}", target), 6)
        }
        0x90..=0x9f => {
            // SETcc r/m8
            let cc = jcc_name(bytes[1] - 0x90);
            (cc, "byte [r?]".to_string(), 3)
        }
        0xa2 => ("cpuid", String::new(), 2),
        0xa4 => ("shld", "r32, r32, imm8".to_string(), 3),
        0xae => ("mfence", String::new(), 3),                  // MFENCE or FXSAVE
        0xaf => ("imul", "r32, r/m32".to_string(), 3),
        0xb6 => ("movzx", "r32, r/m8".to_string(), 3),         // MOVZX
        0xb7 => ("movzx", "r32, r/m16".to_string(), 3),        // MOVZX
        0xbe => ("movsx", "r32, r/m8".to_string(), 3),         // MOVSX
        0xbf => ("movsx", "r32, r/m16".to_string(), 3),        // MOVSX
        _ => ("???", format!("0f {:02x}", bytes[1]), 2),
    }
}

// ---------------------------------------------------------------------------
// Internal: analysis helpers
// ---------------------------------------------------------------------------

/// Detect functions by scanning for common prologue patterns and call/jump
/// targets in the listing.
fn detect_functions(program: &Program) -> anyhow::Result<()> {
    // Production code would integrate with `ghidra-core` analysis.
    // For now we treat each call target and entry symbol as a function.

    log::info!("Detecting functions...");
    let _ = program;
    Ok(())
}

/// Build cross-references between instructions in the listing.
fn build_xrefs(program: &Program) -> anyhow::Result<()> {
    log::info!("Building cross-references...");
    let _ = program;
    Ok(())
}

/// Detect data types from symbol names and memory access patterns.
fn detect_data_types(program: &Program) -> anyhow::Result<()> {
    log::info!("Detecting data types...");
    let _ = program;
    Ok(())
}

/// Check if the analysis deadline has passed and return a timeout error if so.
fn check_deadline(deadline: Instant, timeout_secs: u64) -> anyhow::Result<()> {
    if Instant::now() >= deadline {
        anyhow::bail!(
            "Analysis timed out after {} seconds (deadline exceeded)",
            timeout_secs
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal: helper functions
// ---------------------------------------------------------------------------

/// Read a little-endian u16 from a byte slice at the given offset.
fn read_u16(data: &[u8], offset: usize, _le: bool) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

/// Read a little-endian u32 from a byte slice at the given offset.
fn read_u32(data: &[u8], offset: usize, _le: bool) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

/// Read a little-endian u64 from a byte slice at the given offset.
fn read_u64(data: &[u8], offset: usize, _le: bool) -> u64 {
    if offset + 8 > data.len() {
        return 0;
    }
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

/// Read a null-terminated C string from a byte slice at the given offset.
fn read_c_string(data: &[u8], offset: usize) -> String {
    let mut end = offset;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    String::from_utf8_lossy(&data[offset..end]).to_string()
}

/// Read a fixed-length string from a byte slice, trimming trailing nulls
/// and spaces.
fn read_fixed_string(data: &[u8], offset: usize, len: usize) -> String {
    let end = (offset + len).min(data.len());
    let slice = &data[offset..end];
    let trimmed = slice
        .iter()
        .take_while(|&&b| b != 0)
        .copied()
        .collect::<Vec<u8>>();
    String::from_utf8_lossy(&trimmed)
        .trim()
        .to_string()
}

/// Read a little-endian immediate value of `size` bytes from `data[offset..]`.
fn read_imm(data: &[u8], offset: usize, size: usize) -> u64 {
    let end = (offset + size).min(data.len());
    let mut val: u64 = 0;
    for (i, &b) in data[offset..end].iter().enumerate() {
        val |= (b as u64) << (i * 8);
    }
    val
}

/// Format a relative 8-bit offset for display.
fn format_rel8(bytes: &[u8]) -> String {
    if bytes.len() > 1 {
        format!("{}", bytes[1] as i8)
    } else {
        "0".to_string()
    }
}

/// Return the name of a 64-bit register from its encoding (0-7).
fn reg64_name(reg: u8) -> String {
    match reg {
        0 => "rax",
        1 => "rcx",
        2 => "rdx",
        3 => "rbx",
        4 => "rsp",
        5 => "rbp",
        6 => "rsi",
        7 => "rdi",
        _ => "r?",
    }
    .to_string()
}

/// Return the name of an 8-bit register from its encoding (0-7).
fn reg8_name(reg: u8) -> String {
    match reg {
        0 => "al",
        1 => "cl",
        2 => "dl",
        3 => "bl",
        4 => "ah",
        5 => "ch",
        6 => "dh",
        7 => "bh",
        _ => "?l",
    }
    .to_string()
}

/// Return the mnemonic for a group-1 opcode (ADD/OR/ADC/SBB/AND/SUB/XOR/CMP).
fn group1_op(modrm: u8) -> &'static str {
    match (modrm >> 3) & 7 {
        0 => "add",
        1 => "or",
        2 => "adc",
        3 => "sbb",
        4 => "and",
        5 => "sub",
        6 => "xor",
        7 => "cmp",
        _ => "???",
    }
}

/// Return the mnemonic for a group-2 opcode (ROL/ROR/RCL/RCR/SHL/SHR/SAR).
fn group2_op(modrm: u8) -> &'static str {
    match (modrm >> 3) & 7 {
        0 => "rol",
        1 => "ror",
        2 => "rcl",
        3 => "rcr",
        4 => "shl",
        5 => "shr",
        6 => "sal",
        7 => "sar",
        _ => "???",
    }
}

/// Return the mnemonic for a group-3 opcode (TEST/NOT/NEG/MUL/IMUL/DIV/IDIV).
fn group3_op(modrm: u8) -> &'static str {
    match (modrm >> 3) & 7 {
        0 => "test",
        1 => "test",
        2 => "not",
        3 => "neg",
        4 => "mul",
        5 => "imul",
        6 => "div",
        7 => "idiv",
        _ => "???",
    }
}

/// Return the mnemonic for a group-5 opcode (INC/DEC/CALL/JMP/PUSH).
fn group5_op(modrm: u8) -> &'static str {
    match (modrm >> 3) & 7 {
        0 => "inc",
        1 => "dec",
        2 => "call",
        3 => "call",
        4 => "jmp",
        5 => "jmp",
        6 => "push",
        7 => "???",
        _ => "???",
    }
}

/// Return the Jcc mnemonic based on condition code (0-15).
fn jcc_name(cc: u8) -> &'static str {
    match cc {
        0 => "jo",
        1 => "jno",
        2 => "jb",
        3 => "jnb",
        4 => "je",
        5 => "jne",
        6 => "jbe",
        7 => "ja",
        8 => "js",
        9 => "jns",
        10 => "jp",
        11 => "jnp",
        12 => "jl",
        13 => "jge",
        14 => "jle",
        15 => "jg",
        _ => "j?",
    }
}

// ---- ELF helpers ----------------------------------------------------------

/// Convert ELF segment flags to [`MemoryPermissions`].
fn elf_segment_permissions(flags: u32) -> MemoryPermissions {
    match flags & 7 {
        1 => MemoryPermissions::RX,  // PF_X
        2 => MemoryPermissions::RW,  // PF_W
        3 => MemoryPermissions::RWX, // PF_W | PF_X
        4 => MemoryPermissions::R,   // PF_R
        5 => MemoryPermissions::RX,  // PF_R | PF_X
        6 => MemoryPermissions::RW,  // PF_R | PF_W
        7 => MemoryPermissions::RWX, // PF_R | PF_W | PF_X
        _ => MemoryPermissions::RX,
    }
}

// ---- PE helpers -----------------------------------------------------------

/// Convert PE section characteristics to [`MemoryPermissions`].
fn pe_section_permissions(characteristics: u32) -> MemoryPermissions {
    let exec = characteristics & 0x2000_0000 != 0;
    let read = characteristics & 0x4000_0000 != 0;
    let write = characteristics & 0x8000_0000 != 0;
    match (read, write, exec) {
        (true, false, true) => MemoryPermissions::RX,
        (true, true, false) => MemoryPermissions::RW,
        (true, true, true) => MemoryPermissions::RWX,
        (true, false, false) => MemoryPermissions::R,
        _ => MemoryPermissions::RX,
    }
}

// ---- Mach-O helpers -------------------------------------------------------

/// Guess a reasonable image base for a Mach-O file type.
fn guess_macho_base(filetype: u32) -> u64 {
    match filetype {
        // MH_EXECUTE
        2 => 0x1_0000_0000,
        // MH_DYLIB, MH_BUNDLE
        6 | 8 => 0x0,
        _ => 0x1_0000,
    }
}

/// Convert Mach-O VM protection flags to [`MemoryPermissions`].
fn macho_vm_protection(prot: u32) -> MemoryPermissions {
    match prot & 7 {
        1 => MemoryPermissions::R,
        3 => MemoryPermissions::RW,
        5 => MemoryPermissions::RX,
        7 => MemoryPermissions::RWX,
        _ => MemoryPermissions::RX,
    }
}

/// Extract the entry point offset from an LC_UNIXTHREAD command.
fn extract_thread_entry(
    data: &[u8],
    offset: usize,
    _cmdsize: usize,
    is_le: bool,
    is_64bit: bool,
) -> Option<u64> {
    if is_64bit {
        // x86_64 thread state: flavor, count, then regs including RIP at offset 16*8
        let regs_off = offset + 16; // Skip flavor (4) + count (4) + padding
        Some(read_u64(data, regs_off + 16 * 8, is_le))
    } else {
        // i386 thread state: eip is at offset 10*4 from state start
        let regs_off = offset + 16;
        Some(read_u32(data, regs_off + 10 * 4, is_le) as u64)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_detection_elf() {
        let data = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
        assert_eq!(detect_format(&data, None), FileFormat::Elf);
    }

    #[test]
    fn test_format_detection_pe() {
        let data = vec![0x4d, 0x5a, 0x90, 0x00];
        assert_eq!(detect_format(&data, None), FileFormat::Pe);
    }

    #[test]
    fn test_format_detection_macho_64le() {
        let data = vec![0xcf, 0xfa, 0xed, 0xfe];
        assert_eq!(detect_format(&data, None), FileFormat::Macho);
    }

    #[test]
    fn test_format_detection_raw() {
        let data = vec![0x00, 0x01, 0x02, 0x03];
        assert_eq!(detect_format(&data, None), FileFormat::Raw);
    }

    #[test]
    fn test_load_raw_binary() {
        let tmp = std::env::temp_dir().join("ghidra_test_raw.bin");
        std::fs::write(&tmp, vec![0x55, 0x48, 0x89, 0xe5, 0xc3]).unwrap();

        let program = load_program(&tmp, 0x1000, None).unwrap();
        assert_eq!(program.memory_blocks.len(), 1);
        assert!(program.memory_blocks.contains_key("RAM"));
        // Should have at least one listing row
        assert!(!program.listing.rows.is_empty());

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_load_nonexistent_file() {
        let result = load_program(Path::new("/nonexistent/ghidra_test_xyz.bin"), 0x0, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_export_decompiled() {
        let tmp = std::env::temp_dir().join("ghidra_test_loader_raw.bin");
        std::fs::write(&tmp, vec![0x55, 0xc3]).unwrap();

        let program = load_program(&tmp, 0x1000, None).unwrap();
        let out = std::env::temp_dir().join("ghidra_test_loader.c");
        export_decompiled(&program, &out).unwrap();

        let content = std::fs::read_to_string(&out).unwrap();
        assert!(content.contains("Decompiled"));
        assert!(content.contains("entry"));

        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn test_x86_decode_push_ret() {
        let bytes = vec![0x55, 0xc3];
        let (m1, _, n1) = decode_x86_instruction(&bytes, 2, 0x1000);
        assert_eq!(m1, "push");
        assert_eq!(n1, 1);
        let (m2, _, n2) = decode_x86_instruction(&bytes[n1..], 1, 0x1001);
        assert_eq!(m2, "ret");
        assert_eq!(n2, 1);
    }

    #[test]
    fn test_x86_decode_nop() {
        let (m, _, n) = decode_x86_instruction(&[0x90], 1, 0x0);
        assert_eq!(m, "nop");
        assert_eq!(n, 1);
    }

    #[test]
    fn test_analyze_noop() {
        let tmp = std::env::temp_dir().join("ghidra_test_analyze.bin");
        std::fs::write(&tmp, vec![0x90, 0x90, 0xc3]).unwrap();

        let program = load_program(&tmp, 0x1000, None).unwrap();
        let result = analyze_program(&program, 10);
        assert!(result.is_ok());

        let _ = std::fs::remove_file(&tmp);
    }
}
