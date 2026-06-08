//! PEF section kind values ported from Ghidra's `SectionKind.java`.
//!
//! Values for the `sectionKind` field in PEF section headers.

/// Section kind values for instantiated sections.
///
/// See Apple's PEFBinaryFormat.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SectionKind {
    /// Code, presumed pure and position independent.
    Code = 0,
    /// Unpacked writeable data.
    UnpackedData = 1,
    /// Packed writeable data.
    PackedData = 2,
    /// Read-only data.
    Constant = 3,
    /// Loader tables.
    Loader = 4,
    /// Reserved for future use.
    Debug = 5,
    /// Intermixed code and writeable data.
    ExecutableData = 6,
    /// Reserved for future use.
    Exception = 7,
    /// Reserved for future use.
    Traceback = 8,
}

impl SectionKind {
    /// Returns the numeric value of this section kind.
    pub fn value(self) -> u8 {
        self as u8
    }

    /// Returns true if this section kind is instantiated (contains code or data
    /// required for execution).
    pub fn is_instantiated(self) -> bool {
        matches!(
            self,
            SectionKind::Code
                | SectionKind::UnpackedData
                | SectionKind::PackedData
                | SectionKind::Constant
                | SectionKind::ExecutableData
        )
    }

    /// Look up a `SectionKind` by its numeric value.
    ///
    /// Returns `None` for unrecognized values.
    pub fn from_value(value: u8) -> Option<Self> {
        match value {
            0 => Some(SectionKind::Code),
            1 => Some(SectionKind::UnpackedData),
            2 => Some(SectionKind::PackedData),
            3 => Some(SectionKind::Constant),
            4 => Some(SectionKind::Loader),
            5 => Some(SectionKind::Debug),
            6 => Some(SectionKind::ExecutableData),
            7 => Some(SectionKind::Exception),
            8 => Some(SectionKind::Traceback),
            _ => None,
        }
    }

    /// Returns a human-readable name for this section kind.
    pub fn name(self) -> &'static str {
        match self {
            SectionKind::Code => "Code",
            SectionKind::UnpackedData => "UnpackedData",
            SectionKind::PackedData => "PackedData",
            SectionKind::Constant => "Constant",
            SectionKind::Loader => "Loader",
            SectionKind::Debug => "Debug",
            SectionKind::ExecutableData => "ExecutableData",
            SectionKind::Exception => "Exception",
            SectionKind::Traceback => "Traceback",
        }
    }
}

impl std::fmt::Display for SectionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_kind_from_value() {
        assert_eq!(SectionKind::from_value(0), Some(SectionKind::Code));
        assert_eq!(SectionKind::from_value(1), Some(SectionKind::UnpackedData));
        assert_eq!(SectionKind::from_value(2), Some(SectionKind::PackedData));
        assert_eq!(SectionKind::from_value(3), Some(SectionKind::Constant));
        assert_eq!(SectionKind::from_value(4), Some(SectionKind::Loader));
        assert_eq!(SectionKind::from_value(5), Some(SectionKind::Debug));
        assert_eq!(SectionKind::from_value(6), Some(SectionKind::ExecutableData));
        assert_eq!(SectionKind::from_value(7), Some(SectionKind::Exception));
        assert_eq!(SectionKind::from_value(8), Some(SectionKind::Traceback));
        assert_eq!(SectionKind::from_value(9), None);
        assert_eq!(SectionKind::from_value(0xff), None);
    }

    #[test]
    fn test_section_kind_value_roundtrip() {
        for v in 0..=8u8 {
            let kind = SectionKind::from_value(v).unwrap();
            assert_eq!(kind.value(), v);
        }
    }

    #[test]
    fn test_section_kind_is_instantiated() {
        assert!(SectionKind::Code.is_instantiated());
        assert!(SectionKind::UnpackedData.is_instantiated());
        assert!(SectionKind::PackedData.is_instantiated());
        assert!(SectionKind::Constant.is_instantiated());
        assert!(SectionKind::ExecutableData.is_instantiated());
        assert!(!SectionKind::Loader.is_instantiated());
        assert!(!SectionKind::Debug.is_instantiated());
        assert!(!SectionKind::Exception.is_instantiated());
        assert!(!SectionKind::Traceback.is_instantiated());
    }

    #[test]
    fn test_section_kind_name() {
        assert_eq!(SectionKind::Code.name(), "Code");
        assert_eq!(SectionKind::Loader.name(), "Loader");
    }

    #[test]
    fn test_section_kind_display() {
        assert_eq!(format!("{}", SectionKind::Code), "Code");
        assert_eq!(format!("{}", SectionKind::PackedData), "PackedData");
    }
}
