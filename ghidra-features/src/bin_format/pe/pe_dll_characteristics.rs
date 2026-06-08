//! PE DLL characteristics flags ported from Ghidra's
//! `ghidra.app.util.bin.format.pe.DllCharacteristics`.
//!
//! Provides [`DllCharacteristic`] which represents the DLL characteristics
//! field in the PE optional header. Each variant maps to a specific bit flag
//! with an associated description.

use std::fmt;

// ---------------------------------------------------------------------------
// DLL Characteristics flags
// ---------------------------------------------------------------------------

/// DLL characteristic flags found in the PE optional header.
///
/// These flags describe security and runtime features of the PE image.
/// Multiple characteristics can be combined using bitwise OR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DllCharacteristic {
    /// Image can handle a high entropy 64-bit virtual address space.
    HighEntropyVa = 0x0020,

    /// DLL can be relocated at load time.
    DynamicBase = 0x0040,

    /// Code Integrity checks are enforced.
    ForceIntegrity = 0x0080,

    /// Image is NX compatible.
    NxCompat = 0x0100,

    /// Isolation aware, but do not isolate the image.
    NoIsolation = 0x0200,

    /// Does not use structured exception (SE) handling. No SE handler may be
    /// called in this image.
    NoSeh = 0x0400,

    /// Do not bind the image.
    NoBind = 0x0800,

    /// Image must execute in an AppContainer.
    AppContainer = 0x1000,

    /// A WDM driver.
    WdmDriver = 0x2000,

    /// Image supports Control Flow Guard.
    GuardCf = 0x4000,

    /// Terminal Server aware.
    TerminalServerAware = 0x8000,
}

impl DllCharacteristic {
    /// Returns the bitmask value for this characteristic.
    pub fn mask(self) -> u16 {
        self as u16
    }

    /// Returns the alias name (e.g., "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE").
    pub fn alias(self) -> &'static str {
        match self {
            Self::HighEntropyVa => "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA",
            Self::DynamicBase => "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
            Self::ForceIntegrity => "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY",
            Self::NxCompat => "IMAGE_DLLCHARACTERISTICS_NX_COMPAT",
            Self::NoIsolation => "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION",
            Self::NoSeh => "IMAGE_DLLCHARACTERISTICS_NO_SEH",
            Self::NoBind => "IMAGE_DLLCHARACTERISTICS_NO_BIND",
            Self::AppContainer => "IMAGE_DLLCHARACTERISTICS_APPCONTAINER",
            Self::WdmDriver => "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER",
            Self::GuardCf => "IMAGE_DLLCHARACTERISTICS_GUARD_CF",
            Self::TerminalServerAware => "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE",
        }
    }

    /// Returns a human-readable description of this characteristic.
    pub fn description(self) -> &'static str {
        match self {
            Self::HighEntropyVa => {
                "Image can handle a high entropy 64-bit virtual address space."
            }
            Self::DynamicBase => "DLL can be relocated at load time.",
            Self::ForceIntegrity => "Code Integrity checks are enforced.",
            Self::NxCompat => "Image is NX compatible.",
            Self::NoIsolation => "Isolation aware, but do not isolate the image.",
            Self::NoSeh => {
                "Does not use structured exception (SE) handling. \
                 No SE handler may be called in this image."
            }
            Self::NoBind => "Do not bind the image.",
            Self::AppContainer => "Image must execute in an AppContainer.",
            Self::WdmDriver => "A WDM driver.",
            Self::GuardCf => "Image supports Control Flow Guard.",
            Self::TerminalServerAware => "Terminal Server aware.",
        }
    }

    /// Returns all possible DLL characteristic values.
    pub fn all() -> &'static [DllCharacteristic] {
        &[
            Self::HighEntropyVa,
            Self::DynamicBase,
            Self::ForceIntegrity,
            Self::NxCompat,
            Self::NoIsolation,
            Self::NoSeh,
            Self::NoBind,
            Self::AppContainer,
            Self::WdmDriver,
            Self::GuardCf,
            Self::TerminalServerAware,
        ]
    }

    /// Resolves a raw `value` into the set of [`DllCharacteristic`] flags
    /// that are set.
    ///
    /// This is a port of `DllCharacteristics.resolveCharacteristics()` from Ghidra.
    pub fn resolve(value: u16) -> Vec<DllCharacteristic> {
        Self::all()
            .iter()
            .copied()
            .filter(|ch| (ch.mask() & value) == ch.mask())
            .collect()
    }

    /// Tries to parse a raw `value` into a single [`DllCharacteristic`].
    ///
    /// Returns `None` if the value does not match any known characteristic.
    pub fn from_u16(value: u16) -> Option<DllCharacteristic> {
        match value {
            0x0020 => Some(Self::HighEntropyVa),
            0x0040 => Some(Self::DynamicBase),
            0x0080 => Some(Self::ForceIntegrity),
            0x0100 => Some(Self::NxCompat),
            0x0200 => Some(Self::NoIsolation),
            0x0400 => Some(Self::NoSeh),
            0x0800 => Some(Self::NoBind),
            0x1000 => Some(Self::AppContainer),
            0x2000 => Some(Self::WdmDriver),
            0x4000 => Some(Self::GuardCf),
            0x8000 => Some(Self::TerminalServerAware),
            _ => None,
        }
    }
}

impl fmt::Display for DllCharacteristic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.alias())
    }
}

// ---------------------------------------------------------------------------
// Composite helper: DllCharacteristics (bitfield)
// ---------------------------------------------------------------------------

/// A bitfield representing the combined DLL characteristics of a PE image.
///
/// Provides methods for testing, setting, and iterating individual flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DllCharacteristics {
    /// The raw bitfield value.
    pub value: u16,
}

impl DllCharacteristics {
    /// Creates a new `DllCharacteristics` from a raw value.
    pub fn new(value: u16) -> Self {
        Self { value }
    }

    /// Returns `true` if the given characteristic flag is set.
    pub fn has(&self, ch: DllCharacteristic) -> bool {
        (self.value & ch.mask()) == ch.mask()
    }

    /// Sets the given characteristic flag.
    pub fn set(&mut self, ch: DllCharacteristic) {
        self.value |= ch.mask();
    }

    /// Clears the given characteristic flag.
    pub fn clear(&mut self, ch: DllCharacteristic) {
        self.value &= !ch.mask();
    }

    /// Returns all characteristics that are currently set.
    pub fn resolve(&self) -> Vec<DllCharacteristic> {
        DllCharacteristic::resolve(self.value)
    }

    /// Returns `true` if ASLR (Dynamic Base) is enabled.
    pub fn has_aslr(&self) -> bool {
        self.has(DllCharacteristic::DynamicBase)
    }

    /// Returns `true` if DEP/NX compatibility is enabled.
    pub fn has_dep(&self) -> bool {
        self.has(DllCharacteristic::NxCompat)
    }

    /// Returns `true` if Control Flow Guard is enabled.
    pub fn has_cfg(&self) -> bool {
        self.has(DllCharacteristic::GuardCf)
    }

    /// Returns `true` if high entropy VA is enabled.
    pub fn has_high_entropy_va(&self) -> bool {
        self.has(DllCharacteristic::HighEntropyVa)
    }

    /// Returns `true` if SEH is disabled (NoSEH flag set).
    pub fn is_seh_disabled(&self) -> bool {
        self.has(DllCharacteristic::NoSeh)
    }

    /// Returns `true` if the image must run in an AppContainer.
    pub fn is_app_container(&self) -> bool {
        self.has(DllCharacteristic::AppContainer)
    }
}

impl fmt::Display for DllCharacteristics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let flags = self.resolve();
        if flags.is_empty() {
            return write!(f, "(none)");
        }
        for (i, ch) in flags.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", ch.alias())?;
        }
        Ok(())
    }
}

impl From<u16> for DllCharacteristics {
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dll_characteristic_mask() {
        assert_eq!(DllCharacteristic::HighEntropyVa.mask(), 0x0020);
        assert_eq!(DllCharacteristic::DynamicBase.mask(), 0x0040);
        assert_eq!(DllCharacteristic::GuardCf.mask(), 0x4000);
        assert_eq!(DllCharacteristic::TerminalServerAware.mask(), 0x8000);
    }

    #[test]
    fn test_dll_characteristic_alias() {
        assert_eq!(
            DllCharacteristic::DynamicBase.alias(),
            "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"
        );
        assert_eq!(
            DllCharacteristic::GuardCf.alias(),
            "IMAGE_DLLCHARACTERISTICS_GUARD_CF"
        );
    }

    #[test]
    fn test_dll_characteristic_description() {
        assert_eq!(
            DllCharacteristic::DynamicBase.description(),
            "DLL can be relocated at load time."
        );
        assert_eq!(
            DllCharacteristic::NxCompat.description(),
            "Image is NX compatible."
        );
    }

    #[test]
    fn test_resolve_empty() {
        let resolved = DllCharacteristic::resolve(0);
        assert!(resolved.is_empty());
    }

    #[test]
    fn test_resolve_single() {
        let resolved = DllCharacteristic::resolve(0x0040);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0], DllCharacteristic::DynamicBase);
    }

    #[test]
    fn test_resolve_multiple() {
        // ASLR + DEP + CFG
        let value = 0x0040 | 0x0100 | 0x4000;
        let resolved = DllCharacteristic::resolve(value);
        assert_eq!(resolved.len(), 3);
        assert!(resolved.contains(&DllCharacteristic::DynamicBase));
        assert!(resolved.contains(&DllCharacteristic::NxCompat));
        assert!(resolved.contains(&DllCharacteristic::GuardCf));
    }

    #[test]
    fn test_resolve_all() {
        let mut value: u16 = 0;
        for ch in DllCharacteristic::all() {
            value |= ch.mask();
        }
        let resolved = DllCharacteristic::resolve(value);
        assert_eq!(resolved.len(), DllCharacteristic::all().len());
    }

    #[test]
    fn test_from_u16() {
        assert_eq!(
            DllCharacteristic::from_u16(0x0040),
            Some(DllCharacteristic::DynamicBase)
        );
        assert_eq!(DllCharacteristic::from_u16(0x0001), None);
        assert_eq!(DllCharacteristic::from_u16(0x0000), None);
    }

    #[test]
    fn test_dll_characteristics_bitfield() {
        let mut dc = DllCharacteristics::new(0x0040 | 0x0100);
        assert!(dc.has(DllCharacteristic::DynamicBase));
        assert!(dc.has(DllCharacteristic::NxCompat));
        assert!(!dc.has(DllCharacteristic::GuardCf));

        dc.set(DllCharacteristic::GuardCf);
        assert!(dc.has(DllCharacteristic::GuardCf));
        assert_eq!(dc.value, 0x0040 | 0x0100 | 0x4000);

        dc.clear(DllCharacteristic::NxCompat);
        assert!(!dc.has(DllCharacteristic::NxCompat));
        assert_eq!(dc.value, 0x0040 | 0x4000);
    }

    #[test]
    fn test_dll_characteristics_convenience() {
        let dc = DllCharacteristics::new(0x0040 | 0x0100 | 0x4000);
        assert!(dc.has_aslr());
        assert!(dc.has_dep());
        assert!(dc.has_cfg());
        assert!(!dc.has_high_entropy_va());
        assert!(!dc.is_seh_disabled());
    }

    #[test]
    fn test_dll_characteristics_display() {
        let dc = DllCharacteristics::new(0x0040 | 0x0100);
        let s = format!("{}", dc);
        assert!(s.contains("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"));
        assert!(s.contains("IMAGE_DLLCHARACTERISTICS_NX_COMPAT"));
    }

    #[test]
    fn test_dll_characteristics_display_empty() {
        let dc = DllCharacteristics::new(0);
        assert_eq!(format!("{}", dc), "(none)");
    }

    #[test]
    fn test_dll_characteristics_from_u16() {
        let dc = DllCharacteristics::from(0x0040u16);
        assert_eq!(dc.value, 0x0040);
    }

    #[test]
    fn test_dll_characteristic_display() {
        assert_eq!(
            format!("{}", DllCharacteristic::DynamicBase),
            "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"
        );
    }

    #[test]
    fn test_all_variants_present() {
        // Ensure all() returns exactly 11 variants
        assert_eq!(DllCharacteristic::all().len(), 11);
    }
}
