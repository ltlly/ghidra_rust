//! Raw binary loader.
//!
//! Loads a raw binary blob as a flat memory image — useful for firmware,
//! bootloaders, ROM dumps, and other blobs that have no standard file header.
//!
//! Ported from Ghidra's `ghidra.app.util.bin.format.raw` package.

use serde::{Deserialize, Serialize};
use std::fmt;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Error Type
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone)]
pub enum RawError {
    EmptyData,
    InvalidArchitecture(String),
    InvalidBaseAddress,
}

impl fmt::Display for RawError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RawError::EmptyData => write!(f, "Raw binary data is empty"),
            RawError::InvalidArchitecture(a) => write!(f, "Invalid architecture: {}", a),
            RawError::InvalidBaseAddress => write!(f, "Invalid base address"),
        }
    }
}

impl std::error::Error for RawError {}

/// Type alias for raw binary results.
pub type RawResult<T> = Result<T, RawError>;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Architecture
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Supported target architectures for raw binary loading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Architecture {
    X86,
    X86_64,
    ARM,
    ARM_Thumb,
    AArch64,
    PowerPC,
    PowerPC64,
    MIPS,
    MIPS64,
    RISCV32,
    RISCV64,
    SPARC,
    M68K,
    Unknown(String),
}

impl Architecture {
    /// Parse an architecture string (case-insensitive).
    ///
    /// Supported names:
    /// - `x86`, `i386`, `i686`
    /// - `x86_64`, `amd64`, `x64`
    /// - `arm`, `armle`, `armeb`, `arm_le`, `arm_be`
    /// - `thumb`, `thumb_le`, `thumb_be`
    /// - `aarch64`, `arm64`
    /// - `ppc`, `powerpc`, `ppc32`, `ppc_be`, `ppc_le`
    /// - `ppc64`, `powerpc64`, `ppc64_be`, `ppc64_le`
    /// - `mips`, `mips32`, `mips_be`, `mips_le`
    /// - `mips64`, `mips64_be`, `mips64_le`
    /// - `riscv32`
    /// - `riscv64`
    /// - `sparc`
    /// - `m68k`, `68000`
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "x86" | "i386" | "i486" | "i586" | "i686" | "x86-32" => Some(Architecture::X86),
            "x86_64" | "x86-64" | "amd64" | "x64" => Some(Architecture::X86_64),
            "arm" | "armle" | "arm_le" | "armeb" | "arm_be" | "armv7" | "armv7le" | "arm32" => {
                Some(Architecture::ARM)
            }
            "thumb" | "thumb_le" | "thumb_be" | "thumb2" => Some(Architecture::ARM_Thumb),
            "aarch64" | "arm64" | "armv8" | "armv8-a" | "arm64e" => Some(Architecture::AArch64),
            "ppc" | "powerpc" | "ppc32" | "ppc_be" | "ppc_le" | "ppc750" => {
                Some(Architecture::PowerPC)
            }
            "ppc64" | "powerpc64" | "ppc64_be" | "ppc64_le" => Some(Architecture::PowerPC64),
            "mips" | "mips32" | "mips_be" | "mips_le" | "mipsel" | "mipseb" => {
                Some(Architecture::MIPS)
            }
            "mips64" | "mips64_be" | "mips64_le" | "mips64el" | "mips64eb" => {
                Some(Architecture::MIPS64)
            }
            "riscv32" | "rv32" | "riscv32i" => Some(Architecture::RISCV32),
            "riscv64" | "rv64" | "riscv64i" | "riscv" => Some(Architecture::RISCV64),
            "sparc" | "sparcv8" | "sparc32" => Some(Architecture::SPARC),
            "m68k" | "68000" | "68020" | "68030" | "68040" | "68060" | "coldfire" => {
                Some(Architecture::M68K)
            }
            other => Some(Architecture::Unknown(other.to_string())),
        }
    }

    /// Return the default endianness for this architecture.
    pub fn default_endian(&self) -> Endian {
        match self {
            Architecture::X86 | Architecture::X86_64 => Endian::Little,
            Architecture::ARM | Architecture::ARM_Thumb => Endian::Little,
            Architecture::AArch64 => Endian::Little,
            Architecture::PowerPC | Architecture::PowerPC64 => Endian::Big,
            Architecture::MIPS | Architecture::MIPS64 => Endian::Big,
            Architecture::RISCV32 | Architecture::RISCV64 => Endian::Little,
            Architecture::SPARC => Endian::Big,
            Architecture::M68K => Endian::Big,
            Architecture::Unknown(_) => Endian::Little,
        }
    }

    /// Return the default word size in bytes.
    pub fn word_size(&self) -> u8 {
        match self {
            Architecture::X86 => 4,
            Architecture::X86_64 => 8,
            Architecture::ARM => 4,
            Architecture::ARM_Thumb => 4, // Thumb uses 2-byte instructions but 4-byte addressing
            Architecture::AArch64 => 8,
            Architecture::PowerPC => 4,
            Architecture::PowerPC64 => 8,
            Architecture::MIPS => 4,
            Architecture::MIPS64 => 8,
            Architecture::RISCV32 => 4,
            Architecture::RISCV64 => 8,
            Architecture::SPARC => 4,
            Architecture::M68K => 4,
            Architecture::Unknown(_) => 4,
        }
    }
}

impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Architecture::X86 => write!(f, "x86"),
            Architecture::X86_64 => write!(f, "x86-64"),
            Architecture::ARM => write!(f, "ARM"),
            Architecture::ARM_Thumb => write!(f, "ARM Thumb"),
            Architecture::AArch64 => write!(f, "AArch64"),
            Architecture::PowerPC => write!(f, "PowerPC"),
            Architecture::PowerPC64 => write!(f, "PowerPC-64"),
            Architecture::MIPS => write!(f, "MIPS"),
            Architecture::MIPS64 => write!(f, "MIPS-64"),
            Architecture::RISCV32 => write!(f, "RISC-V 32"),
            Architecture::RISCV64 => write!(f, "RISC-V 64"),
            Architecture::SPARC => write!(f, "SPARC"),
            Architecture::M68K => write!(f, "M68K"),
            Architecture::Unknown(s) => write!(f, "{}", s),
        }
    }
}

/// Endianness for raw binary loading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endian {
    Little,
    Big,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Memory Region
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// A contiguous memory region in the loaded program.
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub name: String,
    pub start: u64,
    pub size: u64,
    pub permissions: u8,
    pub data_offset: usize,
    pub data_size: usize,
}

impl MemoryRegion {
    /// Create a new memory region.
    pub fn new(
        name: &str,
        start: u64,
        size: u64,
        permissions: u8,
        data_offset: usize,
        data_size: usize,
    ) -> Self {
        MemoryRegion {
            name: name.to_string(),
            start,
            size,
            permissions,
            data_offset,
            data_size,
        }
    }

    /// Check if the region is readable.
    pub fn is_readable(&self) -> bool {
        (self.permissions & 0x4) != 0
    }

    /// Check if the region is writable.
    pub fn is_writable(&self) -> bool {
        (self.permissions & 0x2) != 0
    }

    /// Check if the region is executable.
    pub fn is_executable(&self) -> bool {
        (self.permissions & 0x1) != 0
    }

    /// Return the end address (exclusive).
    pub fn end(&self) -> u64 {
        self.start + self.size
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Program
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// The loaded raw binary program.
#[derive(Debug, Clone)]
pub struct Program {
    /// Data buffer (the raw binary contents).
    pub data: Vec<u8>,
    /// Target architecture.
    pub arch: Architecture,
    /// Endianness used for interpretation.
    pub endian: Endian,
    /// Base load address.
    pub base_addr: u64,
    /// Size of the program image in bytes.
    pub size: u64,
    /// Memory regions mapped in this program.
    pub regions: Vec<MemoryRegion>,
    /// Entry point address (defaults to base_addr).
    pub entry_point: u64,
}

impl Program {
    /// Read a byte at the given virtual address.
    pub fn read_u8(&self, addr: u64) -> Option<u8> {
        let off = addr.checked_sub(self.base_addr)? as usize;
        self.data.get(off).copied()
    }

    /// Read a 16-bit value at the given virtual address.
    pub fn read_u16(&self, addr: u64) -> Option<u16> {
        let off = addr.checked_sub(self.base_addr)? as usize;
        if off + 2 > self.data.len() {
            return None;
        }
        let bytes = self.data[off..off + 2].try_into().ok()?;
        Some(match self.endian {
            Endian::Little => u16::from_le_bytes(bytes),
            Endian::Big => u16::from_be_bytes(bytes),
        })
    }

    /// Read a 32-bit value at the given virtual address.
    pub fn read_u32(&self, addr: u64) -> Option<u32> {
        let off = addr.checked_sub(self.base_addr)? as usize;
        if off + 4 > self.data.len() {
            return None;
        }
        let bytes = self.data[off..off + 4].try_into().ok()?;
        Some(match self.endian {
            Endian::Little => u32::from_le_bytes(bytes),
            Endian::Big => u32::from_be_bytes(bytes),
        })
    }

    /// Read a 64-bit value at the given virtual address.
    pub fn read_u64(&self, addr: u64) -> Option<u64> {
        let off = addr.checked_sub(self.base_addr)? as usize;
        if off + 8 > self.data.len() {
            return None;
        }
        let bytes = self.data[off..off + 8].try_into().ok()?;
        Some(match self.endian {
            Endian::Little => u64::from_le_bytes(bytes),
            Endian::Big => u64::from_be_bytes(bytes),
        })
    }

    /// Read a slice at the given virtual address.
    pub fn read_bytes(&self, addr: u64, len: usize) -> Option<&[u8]> {
        let off = addr.checked_sub(self.base_addr)? as usize;
        self.data.get(off..off + len)
    }

    /// Return the size of the program in bytes.
    pub fn data_len(&self) -> usize {
        self.data.len()
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Loader Functions
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Load a raw binary blob as a program.
///
/// # Arguments
/// * `data` - The raw binary data
/// * `arch` - Architecture name string (e.g., "x86_64", "arm")
/// * `base_addr` - Base load address
///
/// # Errors
/// Returns `RawError::EmptyData` if the data slice is empty.
/// Returns `RawError::InvalidArchitecture` if the architecture cannot be parsed.
pub fn load_raw(data: &[u8], arch: &str, base_addr: u64) -> RawResult<Program> {
    if data.is_empty() {
        return Err(RawError::EmptyData);
    }

    let architecture =
        Architecture::parse(arch).ok_or_else(|| RawError::InvalidArchitecture(arch.to_string()))?;

    let size = data.len() as u64;
    let endian = architecture.default_endian();

    let region = MemoryRegion::new(
        "RAW",
        base_addr,
        size,
        0x7, // R/W/X
        0,
        data.len(),
    );

    Ok(Program {
        data: data.to_vec(),
        arch: architecture,
        endian,
        base_addr,
        size,
        regions: vec![region],
        entry_point: base_addr,
    })
}

/// Load a raw binary blob with explicit endianness override.
///
/// Use this when the default endianness of the architecture is wrong
/// for your particular binary (e.g., a little-endian PPC variant).
pub fn load_raw_with_endian(
    data: &[u8],
    arch: &str,
    base_addr: u64,
    endian: Endian,
) -> RawResult<Program> {
    let mut program = load_raw(data, arch, base_addr)?;
    program.endian = endian;
    Ok(program)
}

/// Load a raw binary blob at a specific offset within a larger address space.
///
/// The `entry_point` specifies where execution starts.
pub fn load_raw_with_entry(
    data: &[u8],
    arch: &str,
    base_addr: u64,
    entry_point: u64,
) -> RawResult<Program> {
    let mut program = load_raw(data, arch, base_addr)?;
    program.entry_point = entry_point;
    Ok(program)
}

/// Split a loaded program into multiple named regions.
///
/// Region sizes are given as (name, size) pairs. The total must not exceed
/// the program size. The regions are laid out sequentially starting from
/// `base_addr`.
pub fn load_raw_regions(
    data: &[u8],
    arch: &str,
    base_addr: u64,
    regions: &[(&str, u64)],
    perms: &[u8],
) -> RawResult<Program> {
    let mut program = load_raw(data, arch, base_addr)?;
    let total_size: u64 = regions.iter().map(|(_, s)| s).sum();

    if total_size > data.len() as u64 {
        return Err(RawError::EmptyData); // regions exceed data
    }

    let mut mem_regions = Vec::new();
    let mut offset = 0usize;
    let mut addr = base_addr;

    for (i, (name, size)) in regions.iter().enumerate() {
        let perm = perms.get(i).copied().unwrap_or(0x7);
        mem_regions.push(MemoryRegion::new(
            name,
            addr,
            *size,
            perm,
            offset,
            *size as usize,
        ));
        offset += *size as usize;
        addr += *size;
    }

    program.regions = mem_regions;
    Ok(program)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_raw_x86_64() {
        let data = vec![0x48, 0x89, 0xe5, 0x90]; // mov rbp, rsp; nop
        let prog = load_raw(&data, "x86_64", 0x400000).expect("load raw");
        assert_eq!(prog.arch, Architecture::X86_64);
        assert_eq!(prog.endian, Endian::Little);
        assert_eq!(prog.base_addr, 0x400000);
        assert_eq!(prog.size, 4);
        assert_eq!(prog.arch.word_size(), 8);
        assert_eq!(prog.regions.len(), 1);
        assert_eq!(prog.regions[0].name, "RAW");
        assert_eq!(prog.regions[0].is_readable(), true);
        assert_eq!(prog.regions[0].is_executable(), true);
    }

    #[test]
    fn test_load_raw_arm_thumb() {
        let data = vec![0x70, 0x47]; // bx lr (Thumb)
        let prog = load_raw(&data, "thumb", 0x08000000).expect("load raw");
        assert_eq!(prog.arch, Architecture::ARM_Thumb);
        assert_eq!(prog.endian, Endian::Little);
    }

    #[test]
    fn test_load_raw_ppc() {
        let data = vec![0x4e, 0x80, 0x00, 0x20]; // blr (PowerPC)
        let prog = load_raw(&data, "ppc", 0x10000000).expect("load raw");
        assert_eq!(prog.arch, Architecture::PowerPC);
        assert_eq!(prog.endian, Endian::Big);
    }

    #[test]
    fn test_load_raw_with_entry() {
        let data = vec![0x90u8; 256];
        let prog = load_raw_with_entry(&data, "arm64", 0x0, 0x100).expect("load raw");
        assert_eq!(prog.entry_point, 0x100);
        assert_eq!(prog.base_addr, 0x0);
    }

    #[test]
    fn test_load_raw_with_endian() {
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        let prog =
            load_raw_with_endian(&data, "mips", 0x80000000, Endian::Little).expect("load raw");
        assert_eq!(prog.arch, Architecture::MIPS);
        assert_eq!(prog.endian, Endian::Little); // overridden from Big
    }

    #[test]
    fn test_empty_data() {
        let data: Vec<u8> = vec![];
        assert!(matches!(
            load_raw(&data, "x86_64", 0x0),
            Err(RawError::EmptyData)
        ));
    }

    #[test]
    fn test_invalid_arch() {
        let data = vec![0u8; 4];
        assert!(matches!(
            load_raw(&data, "__bogus_arch__", 0x0),
            Err(RawError::InvalidArchitecture(_))
        ));
    }

    #[test]
    fn test_arch_parse_variants() {
        assert_eq!(Architecture::parse("amd64"), Some(Architecture::X86_64));
        assert_eq!(Architecture::parse("x64"), Some(Architecture::X86_64));
        assert_eq!(Architecture::parse("i386"), Some(Architecture::X86));
        assert_eq!(Architecture::parse("armv7"), Some(Architecture::ARM));
        assert_eq!(Architecture::parse("arm64"), Some(Architecture::AArch64));
        assert_eq!(Architecture::parse("riscv"), Some(Architecture::RISCV64));
        assert_eq!(Architecture::parse("coldfire"), Some(Architecture::M68K));
        assert_eq!(Architecture::parse("ppc_be"), Some(Architecture::PowerPC));
    }

    #[test]
    fn test_program_read_vaddr() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a];
        let prog = load_raw(&data, "x86_64", 0x1000).expect("load raw");
        assert_eq!(prog.read_u8(0x1000), Some(0x01));
        assert_eq!(prog.read_u16(0x1001), Some(0x0302));
        assert_eq!(prog.read_u32(0x1002), Some(0x06050403));
        assert_eq!(prog.read_u64(0x1002), Some(0x0a09080706050403));
        assert_eq!(prog.read_u8(0x2000), None); // out of range
    }

    #[test]
    fn test_load_raw_regions() {
        let data = vec![0u8; 512];
        let regions = &[("CODE", 256), ("DATA", 256)];
        let perms = &[0x5u8, 0x7u8]; // CODE: R+X, DATA: R+W+X
        let prog = load_raw_regions(&data, "arm", 0x8000, regions, perms).expect("load");
        assert_eq!(prog.regions.len(), 2);
        assert_eq!(prog.regions[0].name, "CODE");
        assert_eq!(prog.regions[0].start, 0x8000);
        assert_eq!(prog.regions[0].size, 256);
        assert_eq!(prog.regions[1].name, "DATA");
        assert_eq!(prog.regions[1].start, 0x8100);
        assert_eq!(prog.regions[1].size, 256);
    }

    #[test]
    fn test_arch_defaults() {
        let arm = Architecture::ARM;
        assert_eq!(arm.default_endian(), Endian::Little);
        assert_eq!(arm.word_size(), 4);

        let ppc = Architecture::PowerPC;
        assert_eq!(ppc.default_endian(), Endian::Big);
        assert_eq!(ppc.word_size(), 4);

        let x64 = Architecture::X86_64;
        assert_eq!(x64.default_endian(), Endian::Little);
        assert_eq!(x64.word_size(), 8);
    }
}
