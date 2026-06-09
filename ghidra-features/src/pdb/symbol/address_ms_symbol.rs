//! AddressMsSymbol -- trait for symbols that carry a segment:offset address.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AddressMsSymbol`.

/// Trait for PDB symbols that reference a real address via segment and offset.
///
/// Many `S_*` symbol records contain a `(segment, offset)` pair that locates
/// the symbol's data or code within the binary image. This trait exposes those
/// fields through a uniform interface.
///
/// # Implementors
///
/// - Data symbols (`S_GDATA32`, `S_LDATA32`, etc.)
/// - Procedure symbols (`S_GPROC32`, `S_LPROC32`, etc.)
/// - Public symbols (`S_PUB32`)
/// - Label symbols (`S_LABEL32`)
/// - Thread storage symbols (`S_GTHREAD32`, `S_LTHREAD32`)
/// - Thunk symbols (`S_THUNK32`)
/// - Block symbols (`S_BLOCK32`)
/// - COFF group symbols (`S_COFFGROUP`)
/// - Section symbols (`S_SECTION`)
/// - VfTable symbols (`S_VFTABLE32`)
pub trait AddressMsSymbol {
    /// Return the offset within the segment.
    fn offset(&self) -> u64;

    /// Return the segment index (1-based PE section number).
    fn segment(&self) -> u16;

    /// Compute the flat address as `(segment << 32) | offset`.
    ///
    /// This is a convenience for simple comparisons; for proper address
    /// resolution the segment table must be consulted.
    fn flat_address(&self) -> u64 {
        ((self.segment() as u64) << 32) | (self.offset() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::name_ms_symbol::NameMsSymbol;

    #[derive(Debug)]
    struct TestAddrSym {
        pub off: u64,
        pub seg: u16,
        pub n: String,
    }

    impl AddressMsSymbol for TestAddrSym {
        fn offset(&self) -> u64 {
            self.off
        }
        fn segment(&self) -> u16 {
            self.seg
        }
    }

    impl NameMsSymbol for TestAddrSym {
        fn name(&self) -> &str {
            &self.n
        }
    }

    #[test]
    fn test_address_ms_symbol() {
        let sym = TestAddrSym {
            off: 0x1000,
            seg: 1,
            n: "main".to_string(),
        };
        assert_eq!(sym.offset(), 0x1000);
        assert_eq!(sym.segment(), 1);
    }

    #[test]
    fn test_flat_address() {
        let sym = TestAddrSym {
            off: 0x1234,
            seg: 2,
            n: "foo".to_string(),
        };
        assert_eq!(sym.flat_address(), (2u64 << 32) | 0x1234);
    }

    #[test]
    fn test_name_ms_symbol() {
        let sym = TestAddrSym {
            off: 0,
            seg: 0,
            n: "test_var".to_string(),
        };
        assert_eq!(sym.name(), "test_var");
    }
}
