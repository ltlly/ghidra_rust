//! PE section characteristics flags ported from Ghidra's
//! `ghidra.app.util.bin.format.pe.SectionFlags` and
//! `ghidra.app.util.bin.format.pe.PeSubsystem`.
//!
//! Provides:
//! - [`SectionFlag`] -- individual section characteristic flag
//! - [`SectionCharacteristics`] -- bitfield helper for section flags
//! - [`PeSubsystem`] -- PE subsystem type enumeration

use std::fmt;

// ---------------------------------------------------------------------------
// SectionFlag enum
// ---------------------------------------------------------------------------

/// Section characteristic flags found in the PE section header.
///
/// These flags describe the content and attributes of each section
/// in a PE image. Multiple flags can be combined using bitwise OR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum SectionFlag {
    /// The section should not be padded to the next boundary.
    TypeNoPad = 0x0000_0008,

    /// Reserved for future use.
    Reserved0001 = 0x0000_0010,

    /// The section contains executable code.
    CntCode = 0x0000_0020,

    /// The section contains initialized data.
    CntInitializedData = 0x0000_0040,

    /// The section contains uninitialized data.
    CntUninitializedData = 0x0000_0080,

    /// Reserved for future use.
    LnkOther = 0x0000_0100,

    /// The section contains comments or other information.
    /// This is valid for object files only.
    LnkInfo = 0x0000_0200,

    /// Reserved for future use.
    Reserved0040 = 0x0000_0400,

    /// The section will not become part of the image.
    /// This is valid only for object files.
    LnkRemove = 0x0000_0800,

    /// The section contains COMDAT data.
    /// This is valid only for object files.
    LnkComdat = 0x0000_1000,

    /// The section contains data referenced through the global pointer (GP).
    GpRel = 0x0000_8000,

    /// Reserved for future use (PURGEABLE / 16-bit).
    MemPurgeable = 0x0002_0000,

    /// Reserved for future use (LOCKED).
    MemLocked = 0x0004_0000,

    /// Reserved for future use (PRELOAD).
    MemPreload = 0x0008_0000,

    /// Align data on a 1-byte boundary. Valid only for object files.
    Align1Bytes = 0x0010_0000,

    /// Align data on a 2-byte boundary. Valid only for object files.
    Align2Bytes = 0x0020_0000,

    /// Align data on a 4-byte boundary. Valid only for object files.
    Align4Bytes = 0x0030_0000,

    /// Align data on an 8-byte boundary. Valid only for object files.
    Align8Bytes = 0x0040_0000,

    /// Align data on a 16-byte boundary. Valid only for object files.
    Align16Bytes = 0x0050_0000,

    /// Align data on a 32-byte boundary. Valid only for object files.
    Align32Bytes = 0x0060_0000,

    /// Align data on a 64-byte boundary. Valid only for object files.
    Align64Bytes = 0x0070_0000,

    /// Align data on a 128-byte boundary. Valid only for object files.
    Align128Bytes = 0x0080_0000,

    /// Align data on a 256-byte boundary. Valid only for object files.
    Align256Bytes = 0x0090_0000,

    /// Align data on a 512-byte boundary. Valid only for object files.
    Align512Bytes = 0x00A0_0000,

    /// Align data on a 1024-byte boundary. Valid only for object files.
    Align1024Bytes = 0x00B0_0000,

    /// Align data on a 2048-byte boundary. Valid only for object files.
    Align2048Bytes = 0x00C0_0000,

    /// Align data on a 4096-byte boundary. Valid only for object files.
    Align4096Bytes = 0x00D0_0000,

    /// Align data on an 8192-byte boundary. Valid only for object files.
    Align8192Bytes = 0x00E0_0000,

    /// The section contains extended relocations.
    LnkNrelocOvfl = 0x0100_0000,

    /// The section can be discarded as needed.
    MemDiscardable = 0x0200_0000,

    /// The section cannot be cached.
    MemNotCached = 0x0400_0000,

    /// The section is not pageable.
    MemNotPaged = 0x0800_0000,

    /// The section can be shared in memory.
    MemShared = 0x1000_0000,

    /// The section can be executed as code.
    MemExecute = 0x2000_0000,

    /// The section can be read.
    MemRead = 0x4000_0000,

    /// The section can be written to.
    MemWrite = 0x8000_0000,
}

impl SectionFlag {
    /// Returns the bitmask value for this flag.
    pub fn mask(self) -> u32 {
        self as u32
    }

    /// Returns the alias name (e.g., "IMAGE_SCN_CNT_CODE").
    pub fn alias(self) -> &'static str {
        match self {
            Self::TypeNoPad => "IMAGE_SCN_TYPE_NO_PAD",
            Self::Reserved0001 => "IMAGE_SCN_RESERVED_0001",
            Self::CntCode => "IMAGE_SCN_CNT_CODE",
            Self::CntInitializedData => "IMAGE_SCN_CNT_INITIALIZED_DATA",
            Self::CntUninitializedData => "IMAGE_SCN_CNT_UNINITIALIZED_DATA",
            Self::LnkOther => "IMAGE_SCN_LNK_OTHER",
            Self::LnkInfo => "IMAGE_SCN_LNK_INFO",
            Self::Reserved0040 => "IMAGE_SCN_RESERVED_0040",
            Self::LnkRemove => "IMAGE_SCN_LNK_REMOVE",
            Self::LnkComdat => "IMAGE_SCN_LNK_COMDAT",
            Self::GpRel => "IMAGE_SCN_GPREL",
            Self::MemPurgeable => "IMAGE_SCN_MEM_PURGEABLE",
            Self::MemLocked => "IMAGE_SCN_MEM_LOCKED",
            Self::MemPreload => "IMAGE_SCN_MEM_PRELOAD",
            Self::Align1Bytes => "IMAGE_SCN_ALIGN_1BYTES",
            Self::Align2Bytes => "IMAGE_SCN_ALIGN_2BYTES",
            Self::Align4Bytes => "IMAGE_SCN_ALIGN_4BYTES",
            Self::Align8Bytes => "IMAGE_SCN_ALIGN_8BYTES",
            Self::Align16Bytes => "IMAGE_SCN_ALIGN_16BYTES",
            Self::Align32Bytes => "IMAGE_SCN_ALIGN_32BYTES",
            Self::Align64Bytes => "IMAGE_SCN_ALIGN_64BYTES",
            Self::Align128Bytes => "IMAGE_SCN_ALIGN_128BYTES",
            Self::Align256Bytes => "IMAGE_SCN_ALIGN_256BYTES",
            Self::Align512Bytes => "IMAGE_SCN_ALIGN_512BYTES",
            Self::Align1024Bytes => "IMAGE_SCN_ALIGN_1024BYTES",
            Self::Align2048Bytes => "IMAGE_SCN_ALIGN_2048BYTES",
            Self::Align4096Bytes => "IMAGE_SCN_ALIGN_4096BYTES",
            Self::Align8192Bytes => "IMAGE_SCN_ALIGN_8192BYTES",
            Self::LnkNrelocOvfl => "IMAGE_SCN_LNK_NRELOC_OVFL",
            Self::MemDiscardable => "IMAGE_SCN_MEM_DISCARDABLE",
            Self::MemNotCached => "IMAGE_SCN_MEM_NOT_CACHED",
            Self::MemNotPaged => "IMAGE_SCN_MEM_NOT_PAGED",
            Self::MemShared => "IMAGE_SCN_MEM_SHARED",
            Self::MemExecute => "IMAGE_SCN_MEM_EXECUTE",
            Self::MemRead => "IMAGE_SCN_MEM_READ",
            Self::MemWrite => "IMAGE_SCN_MEM_WRITE",
        }
    }

    /// Returns a human-readable description of this flag.
    pub fn description(self) -> &'static str {
        match self {
            Self::TypeNoPad => "The section should not be padded to the next boundary.",
            Self::Reserved0001 => "Reserved for future use.",
            Self::CntCode => "The section contains executable code.",
            Self::CntInitializedData => "The section contains initialized data.",
            Self::CntUninitializedData => "The section contains uninitialized data.",
            Self::LnkOther => "Reserved for future use.",
            Self::LnkInfo => {
                "The section contains comments or other information. \
                 This is valid for object files only."
            }
            Self::Reserved0040 => "Reserved for future use.",
            Self::LnkRemove => {
                "The section will not become part of the image. \
                 This is valid only for object files."
            }
            Self::LnkComdat => {
                "The section contains COMDAT data. \
                 This is valid only for object files."
            }
            Self::GpRel => {
                "The section contains data referenced through the global pointer (GP)."
            }
            Self::MemPurgeable => "Reserved for future use (PURGEABLE / 16-bit).",
            Self::MemLocked => "Reserved for future use.",
            Self::MemPreload => "Reserved for future use.",
            Self::Align1Bytes => {
                "Align data on a 1-byte boundary. Valid only for object files."
            }
            Self::Align2Bytes => {
                "Align data on a 2-byte boundary. Valid only for object files."
            }
            Self::Align4Bytes => {
                "Align data on a 4-byte boundary. Valid only for object files."
            }
            Self::Align8Bytes => {
                "Align data on an 8-byte boundary. Valid only for object files."
            }
            Self::Align16Bytes => {
                "Align data on a 16-byte boundary. Valid only for object files."
            }
            Self::Align32Bytes => {
                "Align data on a 32-byte boundary. Valid only for object files."
            }
            Self::Align64Bytes => {
                "Align data on a 64-byte boundary. Valid only for object files."
            }
            Self::Align128Bytes => {
                "Align data on a 128-byte boundary. Valid only for object files."
            }
            Self::Align256Bytes => {
                "Align data on a 256-byte boundary. Valid only for object files."
            }
            Self::Align512Bytes => {
                "Align data on a 512-byte boundary. Valid only for object files."
            }
            Self::Align1024Bytes => {
                "Align data on a 1024-byte boundary. Valid only for object files."
            }
            Self::Align2048Bytes => {
                "Align data on a 2048-byte boundary. Valid only for object files."
            }
            Self::Align4096Bytes => {
                "Align data on a 4096-byte boundary. Valid only for object files."
            }
            Self::Align8192Bytes => {
                "Align data on an 8192-byte boundary. Valid only for object files."
            }
            Self::LnkNrelocOvfl => "The section contains extended relocations.",
            Self::MemDiscardable => "The section can be discarded as needed.",
            Self::MemNotCached => "The section cannot be cached.",
            Self::MemNotPaged => "The section is not pageable.",
            Self::MemShared => "The section can be shared in memory.",
            Self::MemExecute => "The section can be executed as code.",
            Self::MemRead => "The section can be read.",
            Self::MemWrite => "The section can be written to.",
        }
    }

    /// Returns all possible section flag values.
    pub fn all() -> &'static [SectionFlag] {
        &[
            Self::TypeNoPad,
            Self::Reserved0001,
            Self::CntCode,
            Self::CntInitializedData,
            Self::CntUninitializedData,
            Self::LnkOther,
            Self::LnkInfo,
            Self::Reserved0040,
            Self::LnkRemove,
            Self::LnkComdat,
            Self::GpRel,
            Self::MemPurgeable,
            Self::MemLocked,
            Self::MemPreload,
            Self::Align1Bytes,
            Self::Align2Bytes,
            Self::Align4Bytes,
            Self::Align8Bytes,
            Self::Align16Bytes,
            Self::Align32Bytes,
            Self::Align64Bytes,
            Self::Align128Bytes,
            Self::Align256Bytes,
            Self::Align512Bytes,
            Self::Align1024Bytes,
            Self::Align2048Bytes,
            Self::Align4096Bytes,
            Self::Align8192Bytes,
            Self::LnkNrelocOvfl,
            Self::MemDiscardable,
            Self::MemNotCached,
            Self::MemNotPaged,
            Self::MemShared,
            Self::MemExecute,
            Self::MemRead,
            Self::MemWrite,
        ]
    }

    /// Resolves a raw `value` into the set of [`SectionFlag`] flags that are set.
    ///
    /// This is a port of `SectionFlags.resolveFlags()` from Ghidra.
    pub fn resolve(value: u32) -> Vec<SectionFlag> {
        Self::all()
            .iter()
            .copied()
            .filter(|f| (f.mask() & value) == f.mask())
            .collect()
    }

    /// Tries to parse a raw value into a single [`SectionFlag`].
    pub fn from_u32(value: u32) -> Option<SectionFlag> {
        match value {
            0x0000_0008 => Some(Self::TypeNoPad),
            0x0000_0010 => Some(Self::Reserved0001),
            0x0000_0020 => Some(Self::CntCode),
            0x0000_0040 => Some(Self::CntInitializedData),
            0x0000_0080 => Some(Self::CntUninitializedData),
            0x0000_0100 => Some(Self::LnkOther),
            0x0000_0200 => Some(Self::LnkInfo),
            0x0000_0400 => Some(Self::Reserved0040),
            0x0000_0800 => Some(Self::LnkRemove),
            0x0000_1000 => Some(Self::LnkComdat),
            0x0000_8000 => Some(Self::GpRel),
            0x0002_0000 => Some(Self::MemPurgeable),
            0x0004_0000 => Some(Self::MemLocked),
            0x0008_0000 => Some(Self::MemPreload),
            0x0010_0000 => Some(Self::Align1Bytes),
            0x0020_0000 => Some(Self::Align2Bytes),
            0x0030_0000 => Some(Self::Align4Bytes),
            0x0040_0000 => Some(Self::Align8Bytes),
            0x0050_0000 => Some(Self::Align16Bytes),
            0x0060_0000 => Some(Self::Align32Bytes),
            0x0070_0000 => Some(Self::Align64Bytes),
            0x0080_0000 => Some(Self::Align128Bytes),
            0x0090_0000 => Some(Self::Align256Bytes),
            0x00A0_0000 => Some(Self::Align512Bytes),
            0x00B0_0000 => Some(Self::Align1024Bytes),
            0x00C0_0000 => Some(Self::Align2048Bytes),
            0x00D0_0000 => Some(Self::Align4096Bytes),
            0x00E0_0000 => Some(Self::Align8192Bytes),
            0x0100_0000 => Some(Self::LnkNrelocOvfl),
            0x0200_0000 => Some(Self::MemDiscardable),
            0x0400_0000 => Some(Self::MemNotCached),
            0x0800_0000 => Some(Self::MemNotPaged),
            0x1000_0000 => Some(Self::MemShared),
            0x2000_0000 => Some(Self::MemExecute),
            0x4000_0000 => Some(Self::MemRead),
            0x8000_0000 => Some(Self::MemWrite),
            _ => None,
        }
    }

    /// Returns the section alignment in bytes, or `None` if this is not an
    /// alignment flag.
    pub fn alignment_bytes(self) -> Option<u32> {
        match self {
            Self::Align1Bytes => Some(1),
            Self::Align2Bytes => Some(2),
            Self::Align4Bytes => Some(4),
            Self::Align8Bytes => Some(8),
            Self::Align16Bytes => Some(16),
            Self::Align32Bytes => Some(32),
            Self::Align64Bytes => Some(64),
            Self::Align128Bytes => Some(128),
            Self::Align256Bytes => Some(256),
            Self::Align512Bytes => Some(512),
            Self::Align1024Bytes => Some(1024),
            Self::Align2048Bytes => Some(2048),
            Self::Align4096Bytes => Some(4096),
            Self::Align8192Bytes => Some(8192),
            _ => None,
        }
    }
}

impl fmt::Display for SectionFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.alias())
    }
}

// ---------------------------------------------------------------------------
// SectionCharacteristics bitfield
// ---------------------------------------------------------------------------

/// A bitfield representing the combined section characteristics of a PE section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionCharacteristics {
    /// The raw bitfield value.
    pub value: u32,
}

impl SectionCharacteristics {
    /// Creates a new `SectionCharacteristics` from a raw value.
    pub fn new(value: u32) -> Self {
        Self { value }
    }

    /// Returns `true` if the given flag is set.
    pub fn has(&self, flag: SectionFlag) -> bool {
        (self.value & flag.mask()) == flag.mask()
    }

    /// Sets the given flag.
    pub fn set(&mut self, flag: SectionFlag) {
        self.value |= flag.mask();
    }

    /// Clears the given flag.
    pub fn clear(&mut self, flag: SectionFlag) {
        self.value &= !flag.mask();
    }

    /// Returns all flags that are currently set.
    pub fn resolve(&self) -> Vec<SectionFlag> {
        SectionFlag::resolve(self.value)
    }

    /// Returns `true` if the section contains executable code.
    pub fn is_code(&self) -> bool {
        self.has(SectionFlag::CntCode)
    }

    /// Returns `true` if the section contains initialized data.
    pub fn is_initialized_data(&self) -> bool {
        self.has(SectionFlag::CntInitializedData)
    }

    /// Returns `true` if the section contains uninitialized data (BSS).
    pub fn is_uninitialized_data(&self) -> bool {
        self.has(SectionFlag::CntUninitializedData)
    }

    /// Returns `true` if the section is readable.
    pub fn is_readable(&self) -> bool {
        self.has(SectionFlag::MemRead)
    }

    /// Returns `true` if the section is writable.
    pub fn is_writable(&self) -> bool {
        self.has(SectionFlag::MemWrite)
    }

    /// Returns `true` if the section is executable.
    pub fn is_executable(&self) -> bool {
        self.has(SectionFlag::MemExecute)
    }

    /// Returns `true` if the section is discardable.
    pub fn is_discardable(&self) -> bool {
        self.has(SectionFlag::MemDiscardable)
    }

    /// Returns `true` if the section is shareable.
    pub fn is_shareable(&self) -> bool {
        self.has(SectionFlag::MemShared)
    }

    /// Returns `true` if the section is not pageable.
    pub fn is_not_paged(&self) -> bool {
        self.has(SectionFlag::MemNotPaged)
    }

    /// Extracts the section alignment in bytes from the alignment flags.
    ///
    /// Returns 0 if no alignment flag is set.
    pub fn alignment(&self) -> u32 {
        // Iterate in reverse to match the largest/most specific alignment first,
        // since alignment flags are a multi-bit field (e.g., Align4Bytes includes
        // the bits for Align1Bytes and Align2Bytes).
        for flag in SectionFlag::all().iter().rev() {
            if let Some(align) = flag.alignment_bytes() {
                if self.has(*flag) {
                    return align;
                }
            }
        }
        0
    }
}

impl fmt::Display for SectionCharacteristics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let flags = self.resolve();
        if flags.is_empty() {
            return write!(f, "(none)");
        }
        for (i, flag) in flags.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", flag.alias())?;
        }
        Ok(())
    }
}

impl From<u32> for SectionCharacteristics {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

// ---------------------------------------------------------------------------
// PeSubsystem enum (from PeSubsystem.java)
// ---------------------------------------------------------------------------

/// PE subsystem types from the optional header.
///
/// This is a port of `ghidra.app.util.bin.format.pe.PeSubsystem`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum PeSubsystem {
    /// An unknown subsystem.
    Unknown = 0,

    /// Device drivers and native Windows processes.
    Native = 1,

    /// The Windows graphical user interface (GUI) subsystem.
    WindowsGui = 2,

    /// The Windows character subsystem.
    WindowsCui = 3,

    /// The OS/2 character subsystem.
    Os2Cui = 5,

    /// The Posix character subsystem.
    PosixCui = 7,

    /// Native Win9x driver.
    NativeWindows = 8,

    /// Windows CE.
    WindowsCeGui = 9,

    /// An Extensible Firmware Interface (EFI) application.
    EfiApplication = 10,

    /// An EFI driver with boot services.
    EfiBootServiceDriver = 11,

    /// An EFI driver with run-time services.
    EfiRuntimeDriver = 12,

    /// An EFI ROM image.
    EfiRom = 13,

    /// XBOX Image.
    Xbox = 14,

    /// Windows boot application.
    WindowsBootApplication = 16,
}

impl PeSubsystem {
    /// Returns the alias name (e.g., "IMAGE_SUBSYSTEM_WINDOWS_GUI").
    pub fn alias(self) -> &'static str {
        match self {
            Self::Unknown => "IMAGE_SUBSYSTEM_UNKNOWN",
            Self::Native => "IMAGE_SUBSYSTEM_NATIVE",
            Self::WindowsGui => "IMAGE_SUBSYSTEM_WINDOWS_GUI",
            Self::WindowsCui => "IMAGE_SUBSYSTEM_WINDOWS_CUI",
            Self::Os2Cui => "IMAGE_SUBSYSTEM_OS2_CUI",
            Self::PosixCui => "IMAGE_SUBSYSTEM_POSIX_CUI",
            Self::NativeWindows => "IMAGE_SUBSYSTEM_NATIVE_WINDOWS",
            Self::WindowsCeGui => "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
            Self::EfiApplication => "IMAGE_SUBSYSTEM_EFI_APPLICATION",
            Self::EfiBootServiceDriver => "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
            Self::EfiRuntimeDriver => "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
            Self::EfiRom => "IMAGE_SUBSYSTEM_EFI_ROM",
            Self::Xbox => "IMAGE_SUBSYSTEM_XBOX",
            Self::WindowsBootApplication => "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION",
        }
    }

    /// Returns a human-readable description of this subsystem.
    pub fn description(self) -> &'static str {
        match self {
            Self::Unknown => "An unknown subsystem",
            Self::Native => "Device drivers and native Windows processes",
            Self::WindowsGui => "The Windows graphical user interface (GUI) subsystem",
            Self::WindowsCui => "The Windows character subsystem",
            Self::Os2Cui => "The OS/2 character subsystem",
            Self::PosixCui => "The Posix character subsystem",
            Self::NativeWindows => "Native Win9x driver",
            Self::WindowsCeGui => "Windows CE",
            Self::EfiApplication => "An Extensible Firmware Interface (EFI) application",
            Self::EfiBootServiceDriver => {
                "An Extensible Firmware Interface (EFI) driver with boot services"
            }
            Self::EfiRuntimeDriver => {
                "An Extensible Firmware Interface (EFI) driver with run-time services"
            }
            Self::EfiRom => "An Extensible Firmware Interface (EFI) ROM image",
            Self::Xbox => "XBOX Image",
            Self::WindowsBootApplication => "Windows boot application.",
        }
    }

    /// Parses a raw subsystem ID into a [`PeSubsystem`].
    ///
    /// This is a port of `PeSubsystem.parse()` from Ghidra.
    ///
    /// # Errors
    /// Returns an error if the ID does not match any known subsystem.
    pub fn parse(id: u16) -> Result<PeSubsystem, String> {
        match id {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::Native),
            2 => Ok(Self::WindowsGui),
            3 => Ok(Self::WindowsCui),
            5 => Ok(Self::Os2Cui),
            7 => Ok(Self::PosixCui),
            8 => Ok(Self::NativeWindows),
            9 => Ok(Self::WindowsCeGui),
            10 => Ok(Self::EfiApplication),
            11 => Ok(Self::EfiBootServiceDriver),
            12 => Ok(Self::EfiRuntimeDriver),
            13 => Ok(Self::EfiRom),
            14 => Ok(Self::Xbox),
            16 => Ok(Self::WindowsBootApplication),
            _ => Err(format!("Can't resolve '{}' to known PeSubsystem", id)),
        }
    }

    /// Returns the numeric value of this subsystem.
    pub fn value(self) -> u16 {
        self as u16
    }

    /// Returns `true` if this subsystem is an EFI subsystem.
    pub fn is_efi(self) -> bool {
        matches!(
            self,
            Self::EfiApplication | Self::EfiBootServiceDriver | Self::EfiRuntimeDriver | Self::EfiRom
        )
    }

    /// Returns `true` if this is a Windows GUI subsystem.
    pub fn is_gui(self) -> bool {
        matches!(self, Self::WindowsGui | Self::WindowsCeGui)
    }

    /// Returns `true` if this is a character-mode (console) subsystem.
    pub fn is_console(self) -> bool {
        matches!(
            self,
            Self::WindowsCui | Self::Os2Cui | Self::PosixCui
        )
    }
}

impl fmt::Display for PeSubsystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.alias())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_flag_mask() {
        assert_eq!(SectionFlag::CntCode.mask(), 0x0000_0020);
        assert_eq!(SectionFlag::MemRead.mask(), 0x4000_0000);
        assert_eq!(SectionFlag::MemWrite.mask(), 0x8000_0000);
        assert_eq!(SectionFlag::MemExecute.mask(), 0x2000_0000);
    }

    #[test]
    fn test_section_flag_alias() {
        assert_eq!(SectionFlag::CntCode.alias(), "IMAGE_SCN_CNT_CODE");
        assert_eq!(
            SectionFlag::CntInitializedData.alias(),
            "IMAGE_SCN_CNT_INITIALIZED_DATA"
        );
        assert_eq!(SectionFlag::MemRead.alias(), "IMAGE_SCN_MEM_READ");
    }

    #[test]
    fn test_section_flag_description() {
        assert_eq!(
            SectionFlag::CntCode.description(),
            "The section contains executable code."
        );
        assert_eq!(
            SectionFlag::MemDiscardable.description(),
            "The section can be discarded as needed."
        );
    }

    #[test]
    fn test_resolve_empty() {
        let resolved = SectionFlag::resolve(0);
        assert!(resolved.is_empty());
    }

    #[test]
    fn test_resolve_rwx() {
        // Read + Write + Execute
        let value = 0x2000_0000 | 0x4000_0000 | 0x8000_0000;
        let resolved = SectionFlag::resolve(value);
        assert_eq!(resolved.len(), 3);
        assert!(resolved.contains(&SectionFlag::MemExecute));
        assert!(resolved.contains(&SectionFlag::MemRead));
        assert!(resolved.contains(&SectionFlag::MemWrite));
    }

    #[test]
    fn test_resolve_code_section() {
        // Typical .text section flags
        let value = 0x0000_0020 | 0x2000_0000 | 0x4000_0000 | 0x0000_0040;
        let resolved = SectionFlag::resolve(value);
        assert!(resolved.contains(&SectionFlag::CntCode));
        assert!(resolved.contains(&SectionFlag::CntInitializedData));
        assert!(resolved.contains(&SectionFlag::MemExecute));
        assert!(resolved.contains(&SectionFlag::MemRead));
    }

    #[test]
    fn test_alignment_bytes() {
        assert_eq!(SectionFlag::Align1Bytes.alignment_bytes(), Some(1));
        assert_eq!(SectionFlag::Align4Bytes.alignment_bytes(), Some(4));
        assert_eq!(SectionFlag::Align4096Bytes.alignment_bytes(), Some(4096));
        assert_eq!(SectionFlag::Align8192Bytes.alignment_bytes(), Some(8192));
        assert_eq!(SectionFlag::CntCode.alignment_bytes(), None);
    }

    #[test]
    fn test_section_characteristics_bitfield() {
        let mut sc = SectionCharacteristics::new(0x0000_0020 | 0x4000_0000);
        assert!(sc.is_code());
        assert!(sc.is_readable());
        assert!(!sc.is_writable());
        assert!(!sc.is_executable());

        sc.set(SectionFlag::MemWrite);
        assert!(sc.is_writable());
        assert_eq!(sc.value, 0x0000_0020 | 0x4000_0000 | 0x8000_0000);

        sc.clear(SectionFlag::CntCode);
        assert!(!sc.is_code());
    }

    #[test]
    fn test_section_characteristics_convenience() {
        // .text section: code + init data + execute + read
        let sc = SectionCharacteristics::new(
            0x0000_0020 | 0x0000_0040 | 0x2000_0000 | 0x4000_0000,
        );
        assert!(sc.is_code());
        assert!(sc.is_initialized_data());
        assert!(!sc.is_uninitialized_data());
        assert!(sc.is_readable());
        assert!(!sc.is_writable());
        assert!(sc.is_executable());
    }

    #[test]
    fn test_section_characteristics_alignment() {
        // 4-byte alignment
        let sc = SectionCharacteristics::new(0x0030_0000);
        assert_eq!(sc.alignment(), 4);

        // No alignment
        let sc = SectionCharacteristics::new(0x0000_0020);
        assert_eq!(sc.alignment(), 0);
    }

    #[test]
    fn test_section_characteristics_display() {
        let sc = SectionCharacteristics::new(0x0000_0020 | 0x4000_0000);
        let s = format!("{}", sc);
        assert!(s.contains("IMAGE_SCN_CNT_CODE"));
        assert!(s.contains("IMAGE_SCN_MEM_READ"));
    }

    #[test]
    fn test_section_characteristics_display_empty() {
        let sc = SectionCharacteristics::new(0);
        assert_eq!(format!("{}", sc), "(none)");
    }

    #[test]
    fn test_pe_subsystem_parse() {
        assert_eq!(PeSubsystem::parse(0).unwrap(), PeSubsystem::Unknown);
        assert_eq!(PeSubsystem::parse(2).unwrap(), PeSubsystem::WindowsGui);
        assert_eq!(PeSubsystem::parse(3).unwrap(), PeSubsystem::WindowsCui);
        assert_eq!(PeSubsystem::parse(10).unwrap(), PeSubsystem::EfiApplication);
        assert!(PeSubsystem::parse(99).is_err());
    }

    #[test]
    fn test_pe_subsystem_alias() {
        assert_eq!(
            PeSubsystem::WindowsGui.alias(),
            "IMAGE_SUBSYSTEM_WINDOWS_GUI"
        );
        assert_eq!(
            PeSubsystem::EfiApplication.alias(),
            "IMAGE_SUBSYSTEM_EFI_APPLICATION"
        );
    }

    #[test]
    fn test_pe_subsystem_description() {
        assert_eq!(
            PeSubsystem::WindowsGui.description(),
            "The Windows graphical user interface (GUI) subsystem"
        );
        assert_eq!(
            PeSubsystem::Xbox.description(),
            "XBOX Image"
        );
    }

    #[test]
    fn test_pe_subsystem_value() {
        assert_eq!(PeSubsystem::Unknown.value(), 0);
        assert_eq!(PeSubsystem::WindowsGui.value(), 2);
        assert_eq!(PeSubsystem::WindowsCui.value(), 3);
        assert_eq!(PeSubsystem::EfiApplication.value(), 10);
        assert_eq!(PeSubsystem::WindowsBootApplication.value(), 16);
    }

    #[test]
    fn test_pe_subsystem_is_efi() {
        assert!(PeSubsystem::EfiApplication.is_efi());
        assert!(PeSubsystem::EfiBootServiceDriver.is_efi());
        assert!(PeSubsystem::EfiRuntimeDriver.is_efi());
        assert!(PeSubsystem::EfiRom.is_efi());
        assert!(!PeSubsystem::WindowsGui.is_efi());
        assert!(!PeSubsystem::Unknown.is_efi());
    }

    #[test]
    fn test_pe_subsystem_is_gui() {
        assert!(PeSubsystem::WindowsGui.is_gui());
        assert!(PeSubsystem::WindowsCeGui.is_gui());
        assert!(!PeSubsystem::WindowsCui.is_gui());
        assert!(!PeSubsystem::Unknown.is_gui());
    }

    #[test]
    fn test_pe_subsystem_is_console() {
        assert!(PeSubsystem::WindowsCui.is_console());
        assert!(PeSubsystem::Os2Cui.is_console());
        assert!(PeSubsystem::PosixCui.is_console());
        assert!(!PeSubsystem::WindowsGui.is_console());
        assert!(!PeSubsystem::Unknown.is_console());
    }

    #[test]
    fn test_pe_subsystem_display() {
        assert_eq!(format!("{}", PeSubsystem::WindowsGui), "IMAGE_SUBSYSTEM_WINDOWS_GUI");
        assert_eq!(format!("{}", PeSubsystem::Unknown), "IMAGE_SUBSYSTEM_UNKNOWN");
    }

    #[test]
    fn test_section_flag_display() {
        assert_eq!(format!("{}", SectionFlag::CntCode), "IMAGE_SCN_CNT_CODE");
        assert_eq!(format!("{}", SectionFlag::MemRead), "IMAGE_SCN_MEM_READ");
    }

    #[test]
    fn test_section_flag_from_u32() {
        assert_eq!(SectionFlag::from_u32(0x0000_0020), Some(SectionFlag::CntCode));
        assert_eq!(SectionFlag::from_u32(0x0000_0000), None);
        assert_eq!(SectionFlag::from_u32(0xFFFF_FFFF), None);
    }
}
