//! Mach-O constants ported from Ghidra's `ghidra.app.util.bin.format.macho.MachConstants`.

/// PowerPC 32-bit magic number (big-endian).
pub const MH_MAGIC: u32 = 0xFEEDFACE;

/// PowerPC 64-bit magic number (big-endian).
pub const MH_MAGIC_64: u32 = 0xFEEDFACF;

/// Intel x86 32-bit magic number (little-endian swapped).
pub const MH_CIGAM: u32 = 0xCEFAEDFE;

/// Intel x86 64-bit magic number (little-endian swapped).
pub const MH_CIGAM_64: u32 = 0xCFFAEDFE;

/// Length of name fields in Mach-O structures (section name, segment name).
pub const NAME_LENGTH: usize = 16;

/// Ghidra data-type category path for Mach-O types.
pub const DATA_TYPE_CATEGORY: &str = "/MachO";

/// Returns `true` if the given value is a valid Mach-O magic number.
pub fn is_magic(magic: u32) -> bool {
    matches!(magic, MH_MAGIC | MH_MAGIC_64 | MH_CIGAM | MH_CIGAM_64)
}

/// Returns `true` if the magic indicates a little-endian (swapped) file.
pub fn is_little_endian(magic: u32) -> bool {
    magic == MH_CIGAM || magic == MH_CIGAM_64
}

/// Returns `true` if the magic indicates a 64-bit Mach-O.
pub fn is_64bit(magic: u32) -> bool {
    magic == MH_MAGIC_64 || magic == MH_CIGAM_64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_values() {
        assert_eq!(MH_MAGIC, 0xFEEDFACE);
        assert_eq!(MH_MAGIC_64, 0xFEEDFACF);
        assert_eq!(MH_CIGAM, 0xCEFAEDFE);
        assert_eq!(MH_CIGAM_64, 0xCFFAEDFE);
    }

    #[test]
    fn test_is_magic() {
        assert!(is_magic(MH_MAGIC));
        assert!(is_magic(MH_MAGIC_64));
        assert!(is_magic(MH_CIGAM));
        assert!(is_magic(MH_CIGAM_64));
        assert!(!is_magic(0x00000000));
        assert!(!is_magic(0xDEADBEEF));
    }

    #[test]
    fn test_is_little_endian() {
        assert!(!is_little_endian(MH_MAGIC));
        assert!(!is_little_endian(MH_MAGIC_64));
        assert!(is_little_endian(MH_CIGAM));
        assert!(is_little_endian(MH_CIGAM_64));
    }

    #[test]
    fn test_is_64bit() {
        assert!(!is_64bit(MH_MAGIC));
        assert!(is_64bit(MH_MAGIC_64));
        assert!(!is_64bit(MH_CIGAM));
        assert!(is_64bit(MH_CIGAM_64));
    }

    #[test]
    fn test_name_length() {
        assert_eq!(NAME_LENGTH, 16);
    }
}
