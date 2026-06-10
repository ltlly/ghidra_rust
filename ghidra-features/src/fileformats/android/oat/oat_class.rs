//! Android OAT class metadata.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.oat.OatClass`
//! class.
//!
//! An `OatClass` describes the compiled state of a class within an OAT
//! file.  It contains the class status, the type of compiled code, and
//! an array of `OatMethod` entries for each method in the class.

use super::oat_method::OatMethod;

// ═══════════════════════════════════════════════════════════════════════════════════
// OatClassStatus enum
// ═══════════════════════════════════════════════════════════════════════════════════

/// The compilation status of a class in the OAT file.
///
/// Ported from Ghidra's `OatClassStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum OatClassStatus {
    /// Class has not been loaded yet.
    NotReady = 0,
    /// Class has been loaded but not resolved.
    Retired = 1,
    /// Class has been resolved.
    ErrorResolved = 2,
    /// Class has been resolved with an error.
    ErrorNotResolved = 3,
    /// Class is in the process of being loaded.
    Loaded = 4,
    /// Class has been resolved successfully.
    Resolvable = 5,
    /// Class is fully resolved and ready to use.
    Resolved = 6,
    /// Class has been verified.
    Verifying = 7,
    /// Class verification failed.
    RetryVerificationAtRuntime = 8,
    /// Class has been verified.
    VerifyingAtRuntime = 9,
    /// Class has been verified successfully.
    Verified = 10,
    /// Class is being initialized.
    SuperclassValidated = 11,
    /// Class is being initialized.
    Initializing = 12,
    /// Class has been initialized.
    Initialized = 13,
    /// Class initialization failed.
    InitializationError = 14,
}

impl OatClassStatus {
    /// Parse a class status from its u16 value.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::NotReady),
            1 => Some(Self::Retired),
            2 => Some(Self::ErrorResolved),
            3 => Some(Self::ErrorNotResolved),
            4 => Some(Self::Loaded),
            5 => Some(Self::Resolvable),
            6 => Some(Self::Resolved),
            7 => Some(Self::Verifying),
            8 => Some(Self::RetryVerificationAtRuntime),
            9 => Some(Self::VerifyingAtRuntime),
            10 => Some(Self::Verified),
            11 => Some(Self::SuperclassValidated),
            12 => Some(Self::Initializing),
            13 => Some(Self::Initialized),
            14 => Some(Self::InitializationError),
            _ => None,
        }
    }

    /// Returns a human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::NotReady => "NOT_READY",
            Self::Retired => "RETIRED",
            Self::ErrorResolved => "ERROR_RESOLVED",
            Self::ErrorNotResolved => "ERROR_NOT_RESOLVED",
            Self::Loaded => "LOADED",
            Self::Resolvable => "RESOLVABLE",
            Self::Resolved => "RESOLVED",
            Self::Verifying => "VERIFYING",
            Self::RetryVerificationAtRuntime => "RETRY_VERIFICATION_AT_RUNTIME",
            Self::VerifyingAtRuntime => "VERIFYING_AT_RUNTIME",
            Self::Verified => "VERIFIED",
            Self::SuperclassValidated => "SUPERCLASS_VALIDATED",
            Self::Initializing => "INITIALIZING",
            Self::Initialized => "INITIALIZED",
            Self::InitializationError => "INITIALIZATION_ERROR",
        }
    }

    /// Returns true if the class is in a successfully loaded state.
    pub fn is_loaded(&self) -> bool {
        matches!(
            self,
            Self::Loaded
                | Self::Resolvable
                | Self::Resolved
                | Self::Verifying
                | Self::VerifyingAtRuntime
                | Self::Verified
                | Self::SuperclassValidated
                | Self::Initializing
                | Self::Initialized
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// OatClassType enum
// ═══════════════════════════════════════════════════════════════════════════════════

/// The type of compiled code for an OAT class.
///
/// Ported from Ghidra's `OatClassType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum OatClassType {
    /// All methods are compiled.
    AllCompiled = 0,
    /// Some methods are compiled, some are not.
    SomeCompiled = 1,
    /// No methods are compiled (interpreter only).
    NoneCompiled = 2,
    /// Class is not in the OAT file.
    Max = 3,
}

impl OatClassType {
    /// Parse a class type from its u16 value.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::AllCompiled),
            1 => Some(Self::SomeCompiled),
            2 => Some(Self::NoneCompiled),
            3 => Some(Self::Max),
            _ => None,
        }
    }

    /// Returns a human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::AllCompiled => "ALL_COMPILED",
            Self::SomeCompiled => "SOME_COMPILED",
            Self::NoneCompiled => "NONE_COMPILED",
            Self::Max => "MAX",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// OatClass
// ═══════════════════════════════════════════════════════════════════════════════════

/// A single OAT class entry.
///
/// This structure describes the compiled state of a class and contains
/// the array of `OatMethod` entries for its methods.
///
/// On-disk layout (all little-endian):
///   status(2) + type(2) + method_offsets(count * 4)
///
/// For `SomeCompiled` classes, each method offset is a relative offset
/// from the start of the class to the method's OAT data.  For
/// `AllCompiled` or `NoneCompiled`, the method offsets array may be
/// empty or use a different encoding.
#[derive(Debug, Clone)]
pub struct OatClass {
    /// File offset of this class entry within the OAT file.
    pub file_offset: u64,
    /// The compilation status of this class.
    pub status: OatClassStatus,
    /// The type of compiled code.
    pub class_type: OatClassType,
    /// Number of methods in the class (derived from the DEX class def).
    pub method_count: u32,
    /// Method offset table.  Each entry is a relative offset from
    /// the start of the OAT class to the corresponding method's
    /// compiled code.  A value of 0 means the method is not compiled.
    pub method_offsets: Vec<u32>,
    /// Parsed method entries (populated after calling `parse_methods`).
    pub methods: Vec<OatMethod>,
}

impl OatClass {
    /// Header size: status(2) + type(2) = 4 bytes.
    const HEADER_SIZE: usize = 4;

    /// Parse an OAT class entry.
    ///
    /// `data`: the full OAT file bytes.
    /// `offset`: byte offset of this class entry.
    /// `method_count`: number of methods in this class (from the DEX class def).
    pub fn parse(data: &[u8], offset: usize, method_count: u32) -> Result<Self, String> {
        if offset + Self::HEADER_SIZE > data.len() {
            return Err("Data too short for OAT class header".to_string());
        }

        let status_raw = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap());
        let type_raw = u16::from_le_bytes(data[offset + 2..offset + 4].try_into().unwrap());

        let status = OatClassStatus::from_u16(status_raw)
            .ok_or_else(|| format!("Unknown OAT class status: {}", status_raw))?;
        let class_type = OatClassType::from_u16(type_raw)
            .ok_or_else(|| format!("Unknown OAT class type: {}", type_raw))?;

        // Read method offsets table.
        let offsets_start = offset + Self::HEADER_SIZE;
        let offsets_size = method_count as usize * 4;

        if offsets_start + offsets_size > data.len() {
            return Err("Data too short for OAT class method offsets".to_string());
        }

        let mut method_offsets = Vec::with_capacity(method_count as usize);
        for i in 0..method_count as usize {
            let off = offsets_start + i * 4;
            let value = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
            method_offsets.push(value);
        }

        Ok(OatClass {
            file_offset: offset as u64,
            status,
            class_type,
            method_count,
            method_offsets,
            methods: Vec::new(),
        })
    }

    /// Returns the total on-disk size of this class entry.
    pub fn size(&self) -> usize {
        Self::HEADER_SIZE + self.method_count as usize * 4
    }

    /// Returns true if the class is fully compiled.
    pub fn is_all_compiled(&self) -> bool {
        self.class_type == OatClassType::AllCompiled
    }

    /// Returns true if no methods are compiled.
    pub fn is_none_compiled(&self) -> bool {
        self.class_type == OatClassType::NoneCompiled
    }

    /// Returns true if some (but not all) methods are compiled.
    pub fn is_some_compiled(&self) -> bool {
        self.class_type == OatClassType::SomeCompiled
    }

    /// Returns true if the class has been verified.
    pub fn is_verified(&self) -> bool {
        matches!(
            self.status,
            OatClassStatus::Verified
                | OatClassStatus::SuperclassValidated
                | OatClassStatus::Initializing
                | OatClassStatus::Initialized
        )
    }

    /// Returns true if the class has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.status == OatClassStatus::Initialized
    }

    /// Returns true if the method at the given index is compiled.
    pub fn is_method_compiled(&self, index: usize) -> bool {
        if index >= self.method_offsets.len() {
            return false;
        }
        self.method_offsets[index] != 0
    }

    /// Parse the OAT methods for this class.
    ///
    /// For each compiled method (non-zero offset in `method_offsets`),
    /// this reads the `OatMethod` data from the OAT file.
    ///
    /// `data`: the full OAT file bytes.
    /// `oat_version`: the OAT version string.
    /// `pointer_size`: 4 or 8.
    pub fn parse_methods(
        &mut self,
        data: &[u8],
        oat_version: &str,
        pointer_size: u32,
    ) -> Result<(), String> {
        let mut methods = Vec::with_capacity(self.method_count as usize);

        for (i, &method_offset) in self.method_offsets.iter().enumerate() {
            if method_offset == 0 {
                // Method is not compiled; push a placeholder.
                methods.push(OatMethod {
                    oat_version: oat_version.to_string(),
                    code_offset: 0,
                    oat_code_offset: 0,
                    gc_map_offset: 0,
                    frame_size: 0,
                    core_spill_mask: 0,
                    fp_spill_mask: 0,
                    method_index: i as u32,
                    mapping_table_offset: 0,
                    vmap_table_offset: 0,
                    quick_code: 0,
                });
            } else {
                let abs_offset = self.file_offset as usize + method_offset as usize;
                let method = OatMethod::parse(&data[abs_offset..], oat_version, pointer_size)?;
                methods.push(method);
            }
        }

        self.methods = methods;
        Ok(())
    }

    /// Parse an OAT class and its methods in one step.
    pub fn parse_with_methods(
        data: &[u8],
        offset: usize,
        method_count: u32,
        oat_version: &str,
        pointer_size: u32,
    ) -> Result<Self, String> {
        let mut class = Self::parse(data, offset, method_count)?;
        class.parse_methods(data, oat_version, pointer_size)?;
        Ok(class)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oat_class_status_from_u16() {
        assert_eq!(OatClassStatus::from_u16(0), Some(OatClassStatus::NotReady));
        assert_eq!(OatClassStatus::from_u16(10), Some(OatClassStatus::Verified));
        assert_eq!(OatClassStatus::from_u16(13), Some(OatClassStatus::Initialized));
        assert_eq!(OatClassStatus::from_u16(99), None);
    }

    #[test]
    fn test_oat_class_status_name() {
        assert_eq!(OatClassStatus::NotReady.name(), "NOT_READY");
        assert_eq!(OatClassStatus::Verified.name(), "VERIFIED");
        assert_eq!(OatClassStatus::Initialized.name(), "INITIALIZED");
    }

    #[test]
    fn test_oat_class_status_is_loaded() {
        assert!(!OatClassStatus::NotReady.is_loaded());
        assert!(OatClassStatus::Loaded.is_loaded());
        assert!(OatClassStatus::Verified.is_loaded());
        assert!(OatClassStatus::Initialized.is_loaded());
        assert!(!OatClassStatus::ErrorResolved.is_loaded());
    }

    #[test]
    fn test_oat_class_type_from_u16() {
        assert_eq!(OatClassType::from_u16(0), Some(OatClassType::AllCompiled));
        assert_eq!(OatClassType::from_u16(1), Some(OatClassType::SomeCompiled));
        assert_eq!(OatClassType::from_u16(2), Some(OatClassType::NoneCompiled));
        assert_eq!(OatClassType::from_u16(99), None);
    }

    #[test]
    fn test_oat_class_type_name() {
        assert_eq!(OatClassType::AllCompiled.name(), "ALL_COMPILED");
        assert_eq!(OatClassType::SomeCompiled.name(), "SOME_COMPILED");
    }

    #[test]
    fn test_parse_oat_class() {
        // Header: status(2)=Verified(10) + type(2)=SomeCompiled(1)
        // + method_offsets: [0x10, 0x00, 0x20]
        let mut data = vec![0u8; 64];
        let offset = 8;
        data[offset] = 10; // status = Verified
        data[offset + 2] = 1; // type = SomeCompiled
        // method_offsets at offset+4
        data[offset + 4..offset + 8].copy_from_slice(&0x10u32.to_le_bytes()); // method 0
        data[offset + 8..offset + 12].copy_from_slice(&0u32.to_le_bytes()); // method 1 (not compiled)
        data[offset + 12..offset + 16].copy_from_slice(&0x20u32.to_le_bytes()); // method 2

        let class = OatClass::parse(&data, offset, 3).unwrap();
        assert_eq!(class.status, OatClassStatus::Verified);
        assert_eq!(class.class_type, OatClassType::SomeCompiled);
        assert_eq!(class.method_count, 3);
        assert_eq!(class.method_offsets, vec![0x10, 0, 0x20]);
        assert!(class.is_some_compiled());
        assert!(class.is_verified());
        assert!(!class.is_initialized());
        assert!(class.is_method_compiled(0));
        assert!(!class.is_method_compiled(1));
        assert!(class.is_method_compiled(2));
        assert_eq!(class.size(), 4 + 3 * 4); // 16
    }

    #[test]
    fn test_parse_oat_class_all_compiled() {
        let mut data = vec![0u8; 32];
        data[0] = 13; // Initialized
        data[2] = 0; // AllCompiled

        let class = OatClass::parse(&data, 0, 2).unwrap();
        assert!(class.is_all_compiled());
        assert!(class.is_initialized());
    }

    #[test]
    fn test_parse_oat_class_none_compiled() {
        let mut data = vec![0u8; 32];
        data[0] = 4; // Loaded
        data[2] = 2; // NoneCompiled

        let class = OatClass::parse(&data, 0, 2).unwrap();
        assert!(class.is_none_compiled());
        assert!(!class.is_verified());
    }

    #[test]
    fn test_parse_oat_class_truncated() {
        let data = vec![0u8; 2];
        assert!(OatClass::parse(&data, 0, 1).is_err());
    }

    #[test]
    fn test_parse_oat_class_offsets_truncated() {
        let mut data = vec![0u8; 6];
        data[0] = 10; // Verified
        data[2] = 1; // SomeCompiled
        // Need 2 method offsets (8 bytes) but only 2 bytes left
        assert!(OatClass::parse(&data, 0, 2).is_err());
    }

    #[test]
    fn test_parse_oat_class_unknown_status() {
        let mut data = vec![0u8; 16];
        data[0] = 99; // Unknown status
        assert!(OatClass::parse(&data, 0, 1).is_err());
    }

    #[test]
    fn test_parse_oat_class_unknown_type() {
        let mut data = vec![0u8; 16];
        data[0] = 10; // Verified
        data[2] = 99; // Unknown type
        assert!(OatClass::parse(&data, 0, 1).is_err());
    }
}
