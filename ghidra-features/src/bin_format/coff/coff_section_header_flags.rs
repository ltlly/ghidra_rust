//! COFF section header flags ported from Ghidra's
//! `ghidra.app.util.bin.format.coff.CoffSectionHeaderFlags`.

/// Regular segment.
pub const STYP_REG: u32 = 0x0000;
/// Dummy section.
pub const STYP_DSECT: u32 = 0x0001;
/// No-load segment.
pub const STYP_NOLOAD: u32 = 0x0002;
/// Group segment.
pub const STYP_GROUP: u32 = 0x0004;
/// Pad segment.
pub const STYP_PAD: u32 = 0x0008;
/// Copy segment.
pub const STYP_COPY: u32 = 0x0010;
/// The section contains only executable code.
pub const STYP_TEXT: u32 = 0x0020;
/// The section contains only initialized data.
pub const STYP_DATA: u32 = 0x0040;
/// The section defines uninitialized data.
pub const STYP_BSS: u32 = 0x0080;
/// Exception section.
pub const STYP_EXCEPT: u32 = 0x0100;
/// Comment section.
pub const STYP_INFO: u32 = 0x0200;
/// Overlay section (defines a piece of another named section which has no bytes).
pub const STYP_OVER: u32 = 0x0400;
/// Library section.
pub const STYP_LIB: u32 = 0x0800;
/// Loader section.
pub const STYP_LOADER: u32 = 0x1000;
/// Debug section.
pub const STYP_DEBUG: u32 = 0x2000;
/// Type check section.
pub const STYP_TYPECHK: u32 = 0x4000;
/// RLD and line number overflow sec hdr section.
pub const STYP_OVRFLO: u32 = 0x8000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flags_do_not_overlap() {
        let flags = [
            STYP_REG, STYP_DSECT, STYP_NOLOAD, STYP_GROUP, STYP_PAD, STYP_COPY, STYP_TEXT,
            STYP_DATA, STYP_BSS, STYP_EXCEPT, STYP_INFO, STYP_OVER, STYP_LIB, STYP_LOADER,
            STYP_DEBUG, STYP_TYPECHK, STYP_OVRFLO,
        ];
        // Verify no two non-zero flags share bits (except STYP_REG which is 0)
        for i in 0..flags.len() {
            for j in (i + 1)..flags.len() {
                if flags[i] != 0 && flags[j] != 0 {
                    assert_eq!(
                        flags[i] & flags[j],
                        0,
                        "Flags 0x{:04x} and 0x{:04x} overlap",
                        flags[i],
                        flags[j]
                    );
                }
            }
        }
    }

    #[test]
    fn test_flag_values() {
        assert_eq!(STYP_TEXT, 0x0020);
        assert_eq!(STYP_DATA, 0x0040);
        assert_eq!(STYP_BSS, 0x0080);
        assert_eq!(STYP_OVRFLO, 0x8000);
    }
}
