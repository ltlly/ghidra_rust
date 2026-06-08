//! COFF section header reserved flags ported from Ghidra's
//! `ghidra.app.util.bin.format.coff.CoffSectionHeaderReserved`.

/// Assuming the underlying processor is word aligned,
/// then this value indicates that a section is byte aligned.
pub const EXPLICITLY_BYTE_ALIGNED: i16 = 0x08;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_explicitly_byte_aligned() {
        assert_eq!(EXPLICITLY_BYTE_ALIGNED, 0x08);
    }
}
