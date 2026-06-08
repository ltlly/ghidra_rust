//! PEF section share kind values ported from Ghidra's `SectionShareKind.java`.
//!
//! Values for the `shareKind` field in PEF section headers.

/// Sharing level for writeable sections.
///
/// See Apple's PEFBinaryFormat.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SectionShareKind {
    /// The section is shared within a process, but a fresh copy is created for
    /// different processes.
    ProcessShare = 1,
    /// The section is shared between all processes in the system.
    GlobalShare = 4,
    /// The section is shared between all processes, but is protected.
    /// Protected sections are read/write in privileged mode and read-only in
    /// user mode.
    ProtectedShare = 5,
}

impl SectionShareKind {
    /// Returns the numeric value of this share kind.
    pub fn value(self) -> u8 {
        self as u8
    }

    /// Look up a `SectionShareKind` by its numeric value.
    ///
    /// Returns `None` for unrecognized values.
    pub fn from_value(value: u8) -> Option<Self> {
        match value {
            1 => Some(SectionShareKind::ProcessShare),
            4 => Some(SectionShareKind::GlobalShare),
            5 => Some(SectionShareKind::ProtectedShare),
            _ => None,
        }
    }

    /// Returns a human-readable name for this share kind.
    pub fn name(self) -> &'static str {
        match self {
            SectionShareKind::ProcessShare => "ProcessShare",
            SectionShareKind::GlobalShare => "GlobalShare",
            SectionShareKind::ProtectedShare => "ProtectedShare",
        }
    }
}

impl std::fmt::Display for SectionShareKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_kind_from_value() {
        assert_eq!(
            SectionShareKind::from_value(1),
            Some(SectionShareKind::ProcessShare)
        );
        assert_eq!(
            SectionShareKind::from_value(4),
            Some(SectionShareKind::GlobalShare)
        );
        assert_eq!(
            SectionShareKind::from_value(5),
            Some(SectionShareKind::ProtectedShare)
        );
        assert_eq!(SectionShareKind::from_value(0), None);
        assert_eq!(SectionShareKind::from_value(2), None);
        assert_eq!(SectionShareKind::from_value(3), None);
        assert_eq!(SectionShareKind::from_value(255), None);
    }

    #[test]
    fn test_share_kind_value_roundtrip() {
        for &val in &[1u8, 4, 5] {
            let kind = SectionShareKind::from_value(val).unwrap();
            assert_eq!(kind.value(), val);
        }
    }

    #[test]
    fn test_share_kind_name() {
        assert_eq!(SectionShareKind::ProcessShare.name(), "ProcessShare");
        assert_eq!(SectionShareKind::GlobalShare.name(), "GlobalShare");
        assert_eq!(SectionShareKind::ProtectedShare.name(), "ProtectedShare");
    }

    #[test]
    fn test_share_kind_display() {
        assert_eq!(format!("{}", SectionShareKind::ProcessShare), "ProcessShare");
    }
}
