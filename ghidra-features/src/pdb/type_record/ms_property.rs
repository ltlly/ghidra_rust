//! MsProperty -- property attributes for PDB composite types.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.type.MsProperty`.
//!
//! The low 12 bits are standard property flags (packed, nested, forward ref,
//! etc.). Bits 11-12 encode an HFA classification, bit 13 is the intrinsic
//! flag, and bits 14-15 encode a Mocom classification.

use std::fmt;

/// HFA (Homogeneous Floating-point Aggregate) classification.
///
/// ARM ABI uses HFA classification to determine how aggregates
/// containing only floating-point members are passed in registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Hfa {
    /// Not an HFA type.
    NONE = 0,
    /// HFA containing `float` members.
    FLOAT = 1,
    /// HFA containing `double` members.
    DOUBLE = 2,
    /// Reserved HFA classification.
    RESV = 3,
}

impl Hfa {
    /// The label string used in PDB emit output.
    pub fn label(&self) -> &'static str {
        match self {
            Hfa::NONE => "",
            Hfa::FLOAT => "hfaFloat",
            Hfa::DOUBLE => "hfaDouble",
            Hfa::RESV => "hfa(3)",
        }
    }

    /// Parse an HFA value from a 2-bit integer.
    pub fn from_value(val: u8) -> Self {
        match val {
            0 => Hfa::NONE,
            1 => Hfa::FLOAT,
            2 => Hfa::DOUBLE,
            3 => Hfa::RESV,
            _ => Hfa::NONE,
        }
    }
}

impl fmt::Display for Hfa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// MOCOM (Managed/COM) classification.
///
/// Indicates the managed or COM interop characteristics of a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Mocom {
    /// No managed/COM classification.
    NONE = 0,
    /// Managed reference type.
    REF = 1,
    /// Managed value type.
    VALUE = 2,
    /// Managed interface type.
    INTERFACE = 3,
}

impl Mocom {
    /// The label string used in PDB emit output.
    pub fn label(&self) -> &'static str {
        match self {
            Mocom::NONE => "",
            Mocom::REF => "ref",
            Mocom::VALUE => "value",
            Mocom::INTERFACE => "interface",
        }
    }

    /// Parse a Mocom value from a 2-bit integer.
    pub fn from_value(val: u8) -> Self {
        match val {
            0 => Mocom::NONE,
            1 => Mocom::REF,
            2 => Mocom::VALUE,
            3 => Mocom::INTERFACE,
            _ => Mocom::NONE,
        }
    }
}

impl fmt::Display for Mocom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

bitflags::bitflags! {
    /// Property attributes for PDB composite and other complex types.
    ///
    /// `MsProperty` is a 16-bit bitfield parsed from the PDB type record.
    /// Each flag describes a characteristic of the type (packed, nested,
    /// forward reference, etc.).
    ///
    /// # Bit Layout
    ///
    /// | Bits  | Field                |
    /// |-------|----------------------|
    /// | 0     | Packed               |
    /// | 1     | Ctor/dtor present    |
    /// | 2     | Overloaded operators |
    /// | 3     | Nested               |
    /// | 4     | Contains nested      |
    /// | 5     | Overloaded assign    |
    /// | 6     | Casting methods      |
    /// | 7     | Forward reference    |
    /// | 8     | Scoped               |
    /// | 9     | Has unique name      |
    /// | 10    | Sealed               |
    /// | 11-12 | Hfa (use `hfa()` accessor) |
    /// | 13    | Intrinsic            |
    /// | 14-15 | Mocom (use `mocom()` accessor) |
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct MsProperty: u16 {
        const PACKED          = 0x0001;
        const CTOR            = 0x0002;
        const OVERLOADED_OPS  = 0x0004;
        const NESTED          = 0x0008;
        const CONTAINS_NESTED = 0x0010;
        const OVLD_ASSIGN     = 0x0020;
        const CASTING_OPS     = 0x0040;
        const FORWARD_REF     = 0x0080;
        const SCOPED          = 0x0100;
        const HAS_UNIQUE_NAME = 0x0200;
        const SEALED          = 0x0400;
        // bits 11-12 are HFA (accessed via hfa() method)
        const INTRINSIC       = 0x2000;
        // bits 14-15 are Mocom (accessed via mocom() method)
    }
}

impl MsProperty {
    /// Extract the HFA classification from the property bits.
    ///
    /// Bits 11-12 encode the HFA value.
    pub fn hfa(&self) -> Hfa {
        Hfa::from_value(((self.bits() >> 11) & 0x03) as u8)
    }

    /// Extract the Mocom classification from the property bits.
    ///
    /// Bits 14-15 encode the Mocom value.
    pub fn mocom(&self) -> Mocom {
        Mocom::from_value(((self.bits() >> 14) & 0x03) as u8)
    }

    /// Parse an `MsProperty` from a raw 16-bit value.
    ///
    /// Uses `from_bits_retain` so that the HFA (bits 11-12) and Mocom
    /// (bits 14-15) fields are preserved in the raw value even though
    /// they are not individual bitflags.
    pub fn from_u16(val: u16) -> Self {
        MsProperty::from_bits_retain(val)
    }
}

impl fmt::Display for MsProperty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (flag, name) in [
            (Self::PACKED, "packed"),
            (Self::CTOR, "ctor"),
            (Self::OVERLOADED_OPS, "ovlops"),
            (Self::NESTED, "isnested"),
            (Self::CONTAINS_NESTED, "cnested"),
            (Self::OVLD_ASSIGN, "opassign"),
            (Self::CASTING_OPS, "opcast"),
            (Self::FORWARD_REF, "fwdref"),
            (Self::SCOPED, "scoped"),
            (Self::HAS_UNIQUE_NAME, "hasuniquename"),
            (Self::SEALED, "sealed"),
            (Self::INTRINSIC, "intrinsic"),
        ] {
            if self.contains(flag) {
                if !first {
                    write!(f, " ")?;
                }
                write!(f, "{}", name)?;
                first = false;
            }
        }
        let hfa = self.hfa();
        if hfa != Hfa::NONE {
            if !first {
                write!(f, " ")?;
            }
            write!(f, "{}", hfa)?;
            first = false;
        }
        let mocom = self.mocom();
        if mocom != Mocom::NONE {
            if !first {
                write!(f, " ")?;
            }
            write!(f, "{}", mocom)?;
            first = false;
        }
        if first {
            write!(f, "none")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_none() {
        let prop = MsProperty::empty();
        assert!(!prop.contains(MsProperty::PACKED));
        assert!(!prop.contains(MsProperty::FORWARD_REF));
        assert_eq!(prop.hfa(), Hfa::NONE);
        assert_eq!(prop.mocom(), Mocom::NONE);
    }

    #[test]
    fn test_packed() {
        let prop = MsProperty::from_u16(0x0001);
        assert!(prop.contains(MsProperty::PACKED));
        assert!(!prop.contains(MsProperty::CTOR));
    }

    #[test]
    fn test_forward_ref() {
        let prop = MsProperty::from_u16(0x0080);
        assert!(prop.contains(MsProperty::FORWARD_REF));
    }

    #[test]
    fn test_hfa() {
        let prop = MsProperty::from_u16(0x0800); // bits 11-12 = 01 -> FLOAT
        assert_eq!(prop.hfa(), Hfa::FLOAT);

        let prop2 = MsProperty::from_u16(0x1000); // bits 11-12 = 10 -> DOUBLE
        assert_eq!(prop2.hfa(), Hfa::DOUBLE);
    }

    #[test]
    fn test_mocom() {
        let prop = MsProperty::from_u16(0x4000); // bits 14-15 = 01 -> REF
        assert_eq!(prop.mocom(), Mocom::REF);

        let prop2 = MsProperty::from_u16(0x8000); // bits 14-15 = 10 -> VALUE
        assert_eq!(prop2.mocom(), Mocom::VALUE);
    }

    #[test]
    fn test_intrinsic() {
        let prop = MsProperty::from_u16(0x2000); // bit 13
        assert!(prop.contains(MsProperty::INTRINSIC));
    }

    #[test]
    fn test_multiple_flags() {
        // Packed + nested + forward_ref
        let prop = MsProperty::from_u16(0x0089);
        assert!(prop.contains(MsProperty::PACKED));
        assert!(prop.contains(MsProperty::NESTED));
        assert!(prop.contains(MsProperty::FORWARD_REF));
        assert!(!prop.contains(MsProperty::SEALED));
    }

    #[test]
    fn test_display() {
        let prop = MsProperty::from_u16(0x0081); // packed + fwdref
        let s = format!("{}", prop);
        assert!(s.contains("packed"));
        assert!(s.contains("fwdref"));
    }

    #[test]
    fn test_display_none() {
        let prop = MsProperty::empty();
        assert_eq!(format!("{}", prop), "none");
    }

    #[test]
    fn test_display_hfa_in_output() {
        let prop = MsProperty::from_u16(0x0800); // hfa = FLOAT
        let s = format!("{}", prop);
        assert!(s.contains("hfaFloat"));
    }

    #[test]
    fn test_hfa_display() {
        assert_eq!(format!("{}", Hfa::FLOAT), "hfaFloat");
        assert_eq!(format!("{}", Hfa::NONE), "");
    }

    #[test]
    fn test_mocom_display() {
        assert_eq!(format!("{}", Mocom::REF), "ref");
        assert_eq!(format!("{}", Mocom::NONE), "");
    }
}
