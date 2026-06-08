//! Mach-O relocation info ported from Ghidra's
//! `ghidra.app.util.bin.format.macho.RelocationInfo`.
//!
//! Represents both `relocation_info` and `scattered_relocation_info` structures.
//!
//! Reference: <https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/reloc.h>

use super::mach_exception::MachException;

/// Mask applied to r_address of a `relocation_info` to detect a scattered relocation (LE).
const R_SCATTERED_LE: u32 = 0x8000_0000;

/// Mask applied to r_address of a `relocation_info` to detect a scattered relocation (BE).
const R_SCATTERED_BE: u32 = 0x0000_0001;

/// Represents a Mach-O relocation entry (`relocation_info` or `scattered_relocation_info`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocationInfo {
    /// 1 if scattered, 0 if non-scattered.
    r_scattered: u32,
    /// Offset in the section to what is being relocated.
    r_address: u32,
    /// Symbol index if r_extern == 1, or section ordinal if r_extern == 0.
    r_value: u32,
    /// Was relocated PC-relative already.
    r_pcrel: u32,
    /// 0=byte, 1=word, 2=long, 3=quad.
    r_length: u32,
    /// If 0 then r_symbolnum is a segment ordinal; if 1 then r_value is a symbol index.
    r_extern: u32,
    /// Machine-specific relocation type (if not 0).
    r_type: u32,
}

impl RelocationInfo {
    /// Parses a relocation entry from two 32-bit words.
    ///
    /// `is_big_endian` indicates the byte order of the source data.
    pub fn new(i1: u32, i2: u32, is_big_endian: bool) -> Self {
        if is_big_endian && (i1 & R_SCATTERED_BE) != 0 {
            // Big-endian scattered relocation
            RelocationInfo {
                r_scattered: 1,
                r_pcrel: (i1 >> 1) & 0x1,
                r_length: (i1 >> 2) & 0x3,
                r_type: (i1 >> 4) & 0xf,
                r_address: (i1 >> 8) & 0xff_ff_ff,
                r_extern: 1,
                r_value: i2,
            }
        } else if (i1 & R_SCATTERED_LE) != 0 {
            // Little-endian scattered relocation
            RelocationInfo {
                r_scattered: 1,
                r_extern: 1,
                r_address: i1 & 0xff_ff_ff,
                r_type: (i1 >> 24) & 0xf,
                r_length: (i1 >> 28) & 0x3,
                r_pcrel: (i1 >> 30) & 0x1,
                r_value: i2,
            }
        } else {
            // Non-scattered relocation
            RelocationInfo {
                r_scattered: 0,
                r_address: i1,
                r_value: i2 & 0xff_ff_ff,
                r_pcrel: (i2 >> 24) & 0x1,
                r_length: (i2 >> 25) & 0x3,
                r_extern: (i2 >> 27) & 0x1,
                r_type: (i2 >> 28) & 0xf,
            }
        }
    }

    /// Returns the address/offset in the section to what is being relocated.
    pub fn address(&self) -> u32 {
        self.r_address
    }

    /// Returns the symbol index (if external) or section ordinal (if internal).
    pub fn value(&self) -> u32 {
        self.r_value
    }

    /// Returns `true` if the relocation is PC-relative.
    pub fn is_pcrel(&self) -> bool {
        self.r_pcrel == 1
    }

    /// Returns the relocation length: 0=byte, 1=word, 2=long, 3=quad.
    pub fn length(&self) -> u32 {
        self.r_length
    }

    /// Returns the byte size of the relocation length (1, 2, 4, or 8).
    pub fn length_bytes(&self) -> u32 {
        1u32 << self.r_length
    }

    /// Returns `true` if the relocation references an external symbol.
    pub fn is_external(&self) -> bool {
        self.r_extern == 1
    }

    /// Returns `true` if this is a scattered relocation.
    pub fn is_scattered(&self) -> bool {
        self.r_scattered == 1
    }

    /// Returns the relocation type.
    pub fn reloc_type(&self) -> u32 {
        self.r_type
    }

    /// Converts to the values array for storage into a program's relocation table.
    ///
    /// Format: `[scattered_flag, address, value, pcrel, length, extern, type]`
    pub fn to_values(&self) -> [u64; 7] {
        [
            self.r_scattered as u64,
            self.r_address as u64,
            self.r_value as u64,
            self.r_pcrel as u64,
            self.r_length as u64,
            self.r_extern as u64,
            self.r_type as u64,
        ]
    }
}

impl std::fmt::Display for RelocationInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Address:      {:x}", self.r_address)?;
        writeln!(f, "Value:        {:x}", self.r_value)?;
        writeln!(f, "Scattered:    {}", self.is_scattered())?;
        writeln!(f, "PC Relocated: {}", self.is_pcrel())?;
        writeln!(
            f,
            "Length:       {:x} ({})",
            self.r_length,
            match self.r_length {
                0 => "1 byte",
                1 => "2 bytes",
                2 => "4 bytes",
                3 => "8 bytes",
                _ => "unknown",
            }
        )?;
        writeln!(f, "External:     {}", self.is_external())?;
        writeln!(f, "Type:         {:x}", self.r_type)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_scattered_relocation() {
        // Non-scattered: i1 = address, i2 encodes symbolnum/pcrel/length/extern/type
        let r = RelocationInfo::new(0x100, 0x00000002, false); // type=0, extern=0, length=0, pcrel=0, symnum=2
        assert!(!r.is_scattered());
        assert_eq!(r.address(), 0x100);
        assert_eq!(r.value(), 2);
        assert!(!r.is_pcrel());
        assert_eq!(r.length(), 0);
        assert!(!r.is_external());
        assert_eq!(r.reloc_type(), 0);
    }

    #[test]
    fn test_non_scattered_with_flags() {
        // extern=1, pcrel=1, length=2, type=2
        let i2: u32 = 0x05 | (1 << 24) | (2 << 25) | (1 << 27) | (2 << 28);
        let r = RelocationInfo::new(0x200, i2, false);
        assert!(!r.is_scattered());
        assert_eq!(r.address(), 0x200);
        assert!(r.is_pcrel());
        assert_eq!(r.length(), 2);
        assert_eq!(r.length_bytes(), 4);
        assert!(r.is_external());
        assert_eq!(r.reloc_type(), 2);
    }

    #[test]
    fn test_scattered_relocation_le() {
        // Set bit 31 for LE scattered: r_address=0xABC, r_type=1, r_length=2, r_pcrel=0
        let i1: u32 = 0x8000_0000 | 0xABC | (1 << 24) | (2 << 28);
        let r = RelocationInfo::new(i1, 0xDEAD, false);
        assert!(r.is_scattered());
        assert_eq!(r.address(), 0xABC);
        assert_eq!(r.value(), 0xDEAD);
        assert_eq!(r.reloc_type(), 1);
        assert_eq!(r.length(), 2);
    }

    #[test]
    fn test_scattered_relocation_be() {
        // Big-endian scattered: bit 0 set
        let i1: u32 = 0x0000_0001 | (0x50 << 8) | (2 << 2) | (1 << 1);
        let r = RelocationInfo::new(i1, 0xBEEF, true);
        assert!(r.is_scattered());
        assert_eq!(r.address(), 0x50);
        assert_eq!(r.value(), 0xBEEF);
        assert!(r.is_pcrel());
        assert_eq!(r.length(), 2);
    }

    #[test]
    fn test_to_values() {
        let r = RelocationInfo::new(0x100, 0x00000002, false);
        let v = r.to_values();
        assert_eq!(v[0], 0); // not scattered
        assert_eq!(v[1], 0x100); // address
        assert_eq!(v[2], 2); // value
    }

    #[test]
    fn test_length_bytes() {
        for len in 0..=3u32 {
            let r = RelocationInfo::new(0, len << 25, false);
            assert_eq!(r.length_bytes(), 1u32 << len);
        }
    }

    #[test]
    fn test_display() {
        let r = RelocationInfo::new(0x100, 0, false);
        let s = format!("{}", r);
        assert!(s.contains("Address:"));
        assert!(s.contains("Scattered:"));
    }
}
