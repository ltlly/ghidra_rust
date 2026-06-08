//! PEF packed data opcodes ported from Ghidra's `PackedDataOpcodes.java`.
//!
//! Opcodes for unpacking packed PEF section data.

/// Packed data contents opcodes.
///
/// See Apple's IOPEFInternals.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PackedDataOpcodes {
    /// Zero fill "count" bytes.
    Zero = 0,
    /// Block copy "count" bytes.
    Block = 1,
    /// Repeat "count" bytes "count2"+1 times.
    Repeat = 2,
    /// Interleaved repeated and unique data.
    RepeatBlock = 3,
    /// Interleaved zero and unique data.
    RepeatZero = 4,
    /// Reserved.
    Reserved5 = 5,
    /// Reserved.
    Reserved6 = 6,
    /// Reserved.
    Reserved7 = 7,
}

impl PackedDataOpcodes {
    /// Returns the numeric value of this opcode.
    pub fn value(self) -> u8 {
        self as u8
    }

    /// Look up a `PackedDataOpcodes` by its numeric value.
    ///
    /// Returns `None` for unrecognized values.
    pub fn from_value(value: u8) -> Option<Self> {
        match value {
            0 => Some(PackedDataOpcodes::Zero),
            1 => Some(PackedDataOpcodes::Block),
            2 => Some(PackedDataOpcodes::Repeat),
            3 => Some(PackedDataOpcodes::RepeatBlock),
            4 => Some(PackedDataOpcodes::RepeatZero),
            5 => Some(PackedDataOpcodes::Reserved5),
            6 => Some(PackedDataOpcodes::Reserved6),
            7 => Some(PackedDataOpcodes::Reserved7),
            _ => None,
        }
    }

    /// Returns a human-readable name for this opcode.
    pub fn name(self) -> &'static str {
        match self {
            PackedDataOpcodes::Zero => "kPEFPkDataZero",
            PackedDataOpcodes::Block => "kPEFPkDataBlock",
            PackedDataOpcodes::Repeat => "kPEFPkDataRepeat",
            PackedDataOpcodes::RepeatBlock => "kPEFPkDataRepeatBlock",
            PackedDataOpcodes::RepeatZero => "kPEFPkDataRepeatZero",
            PackedDataOpcodes::Reserved5 => "kPEFPkDataReserved5",
            PackedDataOpcodes::Reserved6 => "kPEFPkDataReserved6",
            PackedDataOpcodes::Reserved7 => "kPEFPkDataReserved7",
        }
    }
}

impl std::fmt::Display for PackedDataOpcodes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_from_value() {
        assert_eq!(PackedDataOpcodes::from_value(0), Some(PackedDataOpcodes::Zero));
        assert_eq!(PackedDataOpcodes::from_value(1), Some(PackedDataOpcodes::Block));
        assert_eq!(PackedDataOpcodes::from_value(2), Some(PackedDataOpcodes::Repeat));
        assert_eq!(
            PackedDataOpcodes::from_value(3),
            Some(PackedDataOpcodes::RepeatBlock)
        );
        assert_eq!(
            PackedDataOpcodes::from_value(4),
            Some(PackedDataOpcodes::RepeatZero)
        );
        assert_eq!(PackedDataOpcodes::from_value(8), None);
    }

    #[test]
    fn test_opcode_value_roundtrip() {
        for v in 0..=7u8 {
            let opcode = PackedDataOpcodes::from_value(v).unwrap();
            assert_eq!(opcode.value(), v);
        }
    }

    #[test]
    fn test_opcode_name() {
        assert_eq!(PackedDataOpcodes::Zero.name(), "kPEFPkDataZero");
        assert_eq!(PackedDataOpcodes::Block.name(), "kPEFPkDataBlock");
        assert_eq!(PackedDataOpcodes::Repeat.name(), "kPEFPkDataRepeat");
    }

    #[test]
    fn test_opcode_display() {
        assert_eq!(format!("{}", PackedDataOpcodes::Zero), "kPEFPkDataZero");
    }
}
