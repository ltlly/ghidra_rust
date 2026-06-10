//! Android OAT file header parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.oat.OatHeader`
//! and per-version `OatHeader_*.java` classes.
//!
//! OAT files are Android's ahead-of-time compiled DEX files.  The header
//! layout varies across Android releases; this module covers versions
//! 064 (Lollipop) through 095 (Android 13).
//!
//! References:
//! - <https://android.googlesource.com/platform/art/+/refs/heads/master/runtime/oat.h>
//! - <https://android.googlesource.com/platform/art/+/refs/heads/master/runtime/oat/oat_file.h>

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// OAT magic: `"oat\n"`.
pub const OAT_MAGIC: &[u8; 4] = b"oat\n";

/// Length of the version string (4 bytes, ASCII).
pub const VERSION_LENGTH: usize = 4;

// OAT version strings.
/// Lollipop (Android 5.0).
pub const OAT_VERSION_064: &str = "064";
/// Lollipop MR1 (Android 5.1).
pub const OAT_VERSION_065: &str = "065";
/// Marshmallow (Android 6.0).
pub const OAT_VERSION_079: &str = "079";
/// Nougat (Android 7.0).
pub const OAT_VERSION_088: &str = "088";
/// Nougat MR1 (Android 7.1).
pub const OAT_VERSION_124: &str = "124";
/// Oreo (Android 8.0).
pub const OAT_VERSION_131: &str = "131";
/// Oreo MR1 / Pie (Android 8.1 / 9).
pub const OAT_VERSION_138: &str = "138";
/// Q (Android 10).
pub const OAT_VERSION_170: &str = "170";
/// R (Android 11).
pub const OAT_VERSION_183: &str = "183";
/// S (Android 12).
pub const OAT_VERSION_195: &str = "195";
/// Android 12L.
pub const OAT_VERSION_199: &str = "199";
/// Android 13.
pub const OAT_VERSION_206: &str = "206";

/// All supported OAT version strings.
pub const SUPPORTED_VERSIONS: &[&str] = &[
    OAT_VERSION_064,
    OAT_VERSION_065,
    OAT_VERSION_079,
    OAT_VERSION_088,
    OAT_VERSION_124,
    OAT_VERSION_131,
    OAT_VERSION_138,
    OAT_VERSION_170,
    OAT_VERSION_183,
    OAT_VERSION_195,
    OAT_VERSION_199,
    OAT_VERSION_206,
];

// OAT file types.
/// Standard executable OAT.
pub const OAT_EXECUTABLE: &str = "exec";
/// Relocatable OAT (Android 8+).
pub const OAT_RELOCATABLE: &str = "reloc";

// Instruction set types.
pub const OAT_ISA_NONE: u32 = 0;
pub const OAT_ISA_ARM: u32 = 1;
pub const OAT_ISA_ARM_64: u32 = 2;
pub const OAT_ISA_THUMB2: u32 = 3;
pub const OAT_ISA_X86: u32 = 4;
pub const OAT_ISA_X86_64: u32 = 5;
pub const OAT_ISA_MIPS: u32 = 6;
pub const OAT_ISA_MIPS_64: u32 = 7;

// ═══════════════════════════════════════════════════════════════════════════════════
// InstructionSet enum
// ═══════════════════════════════════════════════════════════════════════════════════

/// The instruction set used by the OAT file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum InstructionSet {
    None = OAT_ISA_NONE,
    Arm = OAT_ISA_ARM,
    Arm64 = OAT_ISA_ARM_64,
    Thumb2 = OAT_ISA_THUMB2,
    X86 = OAT_ISA_X86,
    X86_64 = OAT_ISA_X86_64,
    Mips = OAT_ISA_MIPS,
    Mips64 = OAT_ISA_MIPS_64,
}

impl InstructionSet {
    /// Parse an instruction set from its numeric value.
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            OAT_ISA_NONE => Some(Self::None),
            OAT_ISA_ARM => Some(Self::Arm),
            OAT_ISA_ARM_64 => Some(Self::Arm64),
            OAT_ISA_THUMB2 => Some(Self::Thumb2),
            OAT_ISA_X86 => Some(Self::X86),
            OAT_ISA_X86_64 => Some(Self::X86_64),
            OAT_ISA_MIPS => Some(Self::Mips),
            OAT_ISA_MIPS_64 => Some(Self::Mips64),
            _ => None,
        }
    }

    /// Returns a human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Arm => "ARM",
            Self::Arm64 => "ARM64",
            Self::Thumb2 => "THUMB2",
            Self::X86 => "X86",
            Self::X86_64 => "X86_64",
            Self::Mips => "MIPS",
            Self::Mips64 => "MIPS64",
        }
    }

    /// Returns the pointer size (4 for 32-bit ISAs, 8 for 64-bit ISAs).
    pub fn pointer_size(&self) -> u32 {
        match self {
            Self::Arm | Self::Thumb2 | Self::X86 | Self::Mips => 4,
            Self::Arm64 | Self::X86_64 | Self::Mips64 => 8,
            Self::None => 4,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// OatHeaderVersion enum
// ═══════════════════════════════════════════════════════════════════════════════════

/// Discriminated OAT header, covering all supported versions.
///
/// The Java source uses an abstract `OatHeader` base class with per-version
/// subclasses.  In Rust we use an enum whose variants carry the
/// version-specific fields.
#[derive(Debug, Clone)]
pub enum OatHeaderVersion {
    /// Lollipop (version 064).
    V064(OatHeaderV064),
    /// Lollipop MR1 (version 065).
    V065(OatHeaderV065),
    /// Marshmallow (version 079).
    V079(OatHeaderV079),
    /// Nougat (version 088).
    V088(OatHeaderV088),
    /// Nougat MR1 (version 124).
    V124(OatHeaderV124),
    /// Oreo (version 131).
    V131(OatHeaderV131),
    /// Oreo MR1 / Pie (version 138).
    V138(OatHeaderV138),
    /// Q (version 170).
    V170(OatHeaderV170),
    /// R (version 183).
    V183(OatHeaderV183),
    /// S (version 195).
    V195(OatHeaderV195),
    /// Android 12L (version 199).
    V199(OatHeaderV199),
    /// Android 13 (version 206).
    V206(OatHeaderV206),
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Per-version header structs
// ═══════════════════════════════════════════════════════════════════════════════════

/// Lollipop OAT header (version 064).
#[derive(Debug, Clone)]
pub struct OatHeaderV064 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub checksum: u32,
    pub instruction_set: InstructionSet,
    pub instruction_set_features_bitmap: u32,
    pub dex_file_count: u32,
    pub oat_dex_files_offset: u32,
    pub executable_offset: u32,
    pub jni_dlsym_lookup_trampoline_offset: u32,
    pub jni_dlsym_lookup_critical_trampoline_offset: u32,
    pub quick_generic_jni_trampoline_offset: u32,
    pub quick_imt_conflict_trampoline_offset: u32,
    pub quick_resolution_trampoline_offset: u32,
    pub quick_to_interpreter_bridge_offset: u32,
    pub nterp_trampoline_offset: u32,
    // Key-value store follows the fixed header.
    pub key_value_store: Vec<(String, String)>,
}

/// Lollipop MR1 OAT header (version 065).
#[derive(Debug, Clone)]
pub struct OatHeaderV065 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub checksum: u32,
    pub instruction_set: InstructionSet,
    pub instruction_set_features_bitmap: u32,
    pub dex_file_count: u32,
    pub oat_dex_files_offset: u32,
    pub executable_offset: u32,
    pub jni_dlsym_lookup_trampoline_offset: u32,
    pub jni_dlsym_lookup_critical_trampoline_offset: u32,
    pub quick_generic_jni_trampoline_offset: u32,
    pub quick_imt_conflict_trampoline_offset: u32,
    pub quick_resolution_trampoline_offset: u32,
    pub quick_to_interpreter_bridge_offset: u32,
    pub nterp_trampoline_offset: u32,
    pub key_value_store: Vec<(String, String)>,
}

/// Marshmallow OAT header (version 079).
#[derive(Debug, Clone)]
pub struct OatHeaderV079 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub checksum: u32,
    pub instruction_set: InstructionSet,
    pub instruction_set_features_bitmap: u32,
    pub dex_file_count: u32,
    pub oat_dex_files_offset: u32,
    pub executable_offset: u32,
    pub jni_dlsym_lookup_trampoline_offset: u32,
    pub jni_dlsym_lookup_critical_trampoline_offset: u32,
    pub quick_generic_jni_trampoline_offset: u32,
    pub quick_imt_conflict_trampoline_offset: u32,
    pub quick_resolution_trampoline_offset: u32,
    pub quick_to_interpreter_bridge_offset: u32,
    pub nterp_trampoline_offset: u32,
    pub key_value_store: Vec<(String, String)>,
}

/// Nougat OAT header (version 088).
#[derive(Debug, Clone)]
pub struct OatHeaderV088 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub checksum: u32,
    pub instruction_set: InstructionSet,
    pub instruction_set_features_bitmap: u32,
    pub dex_file_count: u32,
    pub oat_dex_files_offset: u32,
    pub executable_offset: u32,
    pub jni_dlsym_lookup_trampoline_offset: u32,
    pub jni_dlsym_lookup_critical_trampoline_offset: u32,
    pub quick_generic_jni_trampoline_offset: u32,
    pub quick_imt_conflict_trampoline_offset: u32,
    pub quick_resolution_trampoline_offset: u32,
    pub quick_to_interpreter_bridge_offset: u32,
    pub nterp_trampoline_offset: u32,
    pub key_value_store: Vec<(String, String)>,
}

/// Nougat MR1 OAT header (version 124).
#[derive(Debug, Clone)]
pub struct OatHeaderV124 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub checksum: u32,
    pub instruction_set: InstructionSet,
    pub instruction_set_features_bitmap: u32,
    pub dex_file_count: u32,
    pub oat_dex_files_offset: u32,
    pub executable_offset: u32,
    pub jni_dlsym_lookup_trampoline_offset: u32,
    pub jni_dlsym_lookup_critical_trampoline_offset: u32,
    pub quick_generic_jni_trampoline_offset: u32,
    pub quick_imt_conflict_trampoline_offset: u32,
    pub quick_resolution_trampoline_offset: u32,
    pub quick_to_interpreter_bridge_offset: u32,
    pub nterp_trampoline_offset: u32,
    pub key_value_store: Vec<(String, String)>,
}

/// Oreo OAT header (version 131).
#[derive(Debug, Clone)]
pub struct OatHeaderV131 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub checksum: u32,
    pub instruction_set: InstructionSet,
    pub instruction_set_features_bitmap: u32,
    pub dex_file_count: u32,
    pub oat_dex_files_offset: u32,
    pub executable_offset: u32,
    pub jni_dlsym_lookup_trampoline_offset: u32,
    pub jni_dlsym_lookup_critical_trampoline_offset: u32,
    pub quick_generic_jni_trampoline_offset: u32,
    pub quick_imt_conflict_trampoline_offset: u32,
    pub quick_resolution_trampoline_offset: u32,
    pub quick_to_interpreter_bridge_offset: u32,
    pub nterp_trampoline_offset: u32,
    pub key_value_store: Vec<(String, String)>,
}

/// Oreo MR1 / Pie OAT header (version 138).
#[derive(Debug, Clone)]
pub struct OatHeaderV138 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub checksum: u32,
    pub instruction_set: InstructionSet,
    pub instruction_set_features_bitmap: u32,
    pub dex_file_count: u32,
    pub oat_dex_files_offset: u32,
    pub executable_offset: u32,
    pub jni_dlsym_lookup_trampoline_offset: u32,
    pub jni_dlsym_lookup_critical_trampoline_offset: u32,
    pub quick_generic_jni_trampoline_offset: u32,
    pub quick_imt_conflict_trampoline_offset: u32,
    pub quick_resolution_trampoline_offset: u32,
    pub quick_to_interpreter_bridge_offset: u32,
    pub nterp_trampoline_offset: u32,
    pub key_value_store: Vec<(String, String)>,
}

/// Q OAT header (version 170).
#[derive(Debug, Clone)]
pub struct OatHeaderV170 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub checksum: u32,
    pub instruction_set: InstructionSet,
    pub instruction_set_features_bitmap: u32,
    pub dex_file_count: u32,
    pub oat_dex_files_offset: u32,
    pub executable_offset: u32,
    pub jni_dlsym_lookup_trampoline_offset: u32,
    pub jni_dlsym_lookup_critical_trampoline_offset: u32,
    pub quick_generic_jni_trampoline_offset: u32,
    pub quick_imt_conflict_trampoline_offset: u32,
    pub quick_resolution_trampoline_offset: u32,
    pub quick_to_interpreter_bridge_offset: u32,
    pub nterp_trampoline_offset: u32,
    pub key_value_store: Vec<(String, String)>,
}

/// R OAT header (version 183).
#[derive(Debug, Clone)]
pub struct OatHeaderV183 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub checksum: u32,
    pub instruction_set: InstructionSet,
    pub instruction_set_features_bitmap: u32,
    pub dex_file_count: u32,
    pub oat_dex_files_offset: u32,
    pub executable_offset: u32,
    pub jni_dlsym_lookup_trampoline_offset: u32,
    pub jni_dlsym_lookup_critical_trampoline_offset: u32,
    pub quick_generic_jni_trampoline_offset: u32,
    pub quick_imt_conflict_trampoline_offset: u32,
    pub quick_resolution_trampoline_offset: u32,
    pub quick_to_interpreter_bridge_offset: u32,
    pub nterp_trampoline_offset: u32,
    pub key_value_store: Vec<(String, String)>,
}

/// S OAT header (version 195).
#[derive(Debug, Clone)]
pub struct OatHeaderV195 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub checksum: u32,
    pub instruction_set: InstructionSet,
    pub instruction_set_features_bitmap: u32,
    pub dex_file_count: u32,
    pub oat_dex_files_offset: u32,
    pub executable_offset: u32,
    pub jni_dlsym_lookup_trampoline_offset: u32,
    pub jni_dlsym_lookup_critical_trampoline_offset: u32,
    pub quick_generic_jni_trampoline_offset: u32,
    pub quick_imt_conflict_trampoline_offset: u32,
    pub quick_resolution_trampoline_offset: u32,
    pub quick_to_interpreter_bridge_offset: u32,
    pub nterp_trampoline_offset: u32,
    pub key_value_store: Vec<(String, String)>,
}

/// Android 12L OAT header (version 199).
#[derive(Debug, Clone)]
pub struct OatHeaderV199 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub checksum: u32,
    pub instruction_set: InstructionSet,
    pub instruction_set_features_bitmap: u32,
    pub dex_file_count: u32,
    pub oat_dex_files_offset: u32,
    pub executable_offset: u32,
    pub jni_dlsym_lookup_trampoline_offset: u32,
    pub jni_dlsym_lookup_critical_trampoline_offset: u32,
    pub quick_generic_jni_trampoline_offset: u32,
    pub quick_imt_conflict_trampoline_offset: u32,
    pub quick_resolution_trampoline_offset: u32,
    pub quick_to_interpreter_bridge_offset: u32,
    pub nterp_trampoline_offset: u32,
    pub key_value_store: Vec<(String, String)>,
}

/// Android 13 OAT header (version 206).
#[derive(Debug, Clone)]
pub struct OatHeaderV206 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub checksum: u32,
    pub instruction_set: InstructionSet,
    pub instruction_set_features_bitmap: u32,
    pub dex_file_count: u32,
    pub oat_dex_files_offset: u32,
    pub executable_offset: u32,
    pub jni_dlsym_lookup_trampoline_offset: u32,
    pub jni_dlsym_lookup_critical_trampoline_offset: u32,
    pub quick_generic_jni_trampoline_offset: u32,
    pub quick_imt_conflict_trampoline_offset: u32,
    pub quick_resolution_trampoline_offset: u32,
    pub quick_to_interpreter_bridge_offset: u32,
    pub nterp_trampoline_offset: u32,
    pub key_value_store: Vec<(String, String)>,
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Parsing helpers
// ═══════════════════════════════════════════════════════════════════════════════════

/// Read a little-endian u32 from `data` at `offset`.
fn read_u32(data: &[u8], offset: usize) -> Result<u32, String> {
    if offset + 4 > data.len() {
        return Err(format!(
            "OAT header: read_u32 at {} beyond data length {}",
            offset,
            data.len()
        ));
    }
    Ok(u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()))
}

/// The fixed header portion (before the key-value store) is 15 x u32 = 60 bytes,
/// starting after magic(4) + version(4) = 8 bytes.
///
/// Total fixed header = 68 bytes.
const FIXED_HEADER_SIZE: usize = 8 + 15 * 4; // 68

/// Parse the key-value store that follows the fixed header.
///
/// The key-value store is a sequence of null-terminated UTF-8 strings.
/// Keys and values alternate.  Parsing stops when an empty string
/// (lone null byte) is encountered, or data is exhausted.
fn parse_key_value_store(data: &[u8], offset: usize) -> Result<Vec<(String, String)>, String> {
    let mut result = Vec::new();
    let mut pos = offset;

    loop {
        if pos >= data.len() {
            break;
        }
        // Read key
        let key = read_null_terminated_string(data, &mut pos)?;
        if key.is_empty() {
            break; // End of key-value store
        }
        // Read value
        if pos >= data.len() {
            return Err("OAT header: key-value store truncated (missing value)".to_string());
        }
        let value = read_null_terminated_string(data, &mut pos)?;
        result.push((key, value));
    }

    Ok(result)
}

/// Read a null-terminated string from `data` starting at `*pos`.
/// Advances `*pos` past the null terminator.
fn read_null_terminated_string(data: &[u8], pos: &mut usize) -> Result<String, String> {
    let start = *pos;
    while *pos < data.len() && data[*pos] != 0 {
        *pos += 1;
    }
    if *pos >= data.len() {
        return Err("OAT header: unterminated string in key-value store".to_string());
    }
    let s = std::str::from_utf8(&data[start..*pos])
        .map_err(|_| "OAT header: non-UTF-8 string in key-value store")?
        .to_string();
    *pos += 1; // skip null terminator
    Ok(s)
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Common parse logic
// ═══════════════════════════════════════════════════════════════════════════════════

/// Common fields parsed from any OAT version header.
struct CommonFields {
    checksum: u32,
    instruction_set: InstructionSet,
    instruction_set_features_bitmap: u32,
    dex_file_count: u32,
    oat_dex_files_offset: u32,
    executable_offset: u32,
    jni_dlsym_lookup_trampoline_offset: u32,
    jni_dlsym_lookup_critical_trampoline_offset: u32,
    quick_generic_jni_trampoline_offset: u32,
    quick_imt_conflict_trampoline_offset: u32,
    quick_resolution_trampoline_offset: u32,
    quick_to_interpreter_bridge_offset: u32,
    nterp_trampoline_offset: u32,
    key_value_store: Vec<(String, String)>,
}

fn parse_common(data: &[u8]) -> Result<CommonFields, String> {
    if data.len() < FIXED_HEADER_SIZE {
        return Err("Data too short for OAT header".to_string());
    }

    let checksum = read_u32(data, 8)?;
    let isa_val = read_u32(data, 12)?;
    let instruction_set =
        InstructionSet::from_u32(isa_val).ok_or_else(|| format!("Unknown ISA: {}", isa_val))?;
    let instruction_set_features_bitmap = read_u32(data, 16)?;
    let dex_file_count = read_u32(data, 20)?;
    let oat_dex_files_offset = read_u32(data, 24)?;
    let executable_offset = read_u32(data, 28)?;
    let jni_dlsym_lookup_trampoline_offset = read_u32(data, 32)?;
    let jni_dlsym_lookup_critical_trampoline_offset = read_u32(data, 36)?;
    let quick_generic_jni_trampoline_offset = read_u32(data, 40)?;
    let quick_imt_conflict_trampoline_offset = read_u32(data, 44)?;
    let quick_resolution_trampoline_offset = read_u32(data, 48)?;
    let quick_to_interpreter_bridge_offset = read_u32(data, 52)?;
    let nterp_trampoline_offset = read_u32(data, 56)?;

    // Key-value store starts at offset 60 (after 8-byte magic+version + 13 u32 fields
    // that come before key_value_store_offset in the struct layout).
    // The key-value store offset is stored at data[60..64] for some versions,
    // but in practice the KV store follows immediately after the fixed fields.
    let kv_offset = read_u32(data, 60)? as usize;
    let key_value_store = if kv_offset > 0 && kv_offset < data.len() {
        parse_key_value_store(data, kv_offset)?
    } else {
        // Fallback: try parsing right after fixed header
        parse_key_value_store(data, FIXED_HEADER_SIZE)?
    };

    Ok(CommonFields {
        checksum,
        instruction_set,
        instruction_set_features_bitmap,
        dex_file_count,
        oat_dex_files_offset,
        executable_offset,
        jni_dlsym_lookup_trampoline_offset,
        jni_dlsym_lookup_critical_trampoline_offset,
        quick_generic_jni_trampoline_offset,
        quick_imt_conflict_trampoline_offset,
        quick_resolution_trampoline_offset,
        quick_to_interpreter_bridge_offset,
        nterp_trampoline_offset,
        key_value_store,
    })
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════════════════════

/// Check if data starts with OAT magic.
pub fn is_oat(data: &[u8]) -> bool {
    data.len() >= 4 && &data[..4] == OAT_MAGIC
}

/// Check if a version string is supported.
pub fn is_supported_version(version: &str) -> bool {
    SUPPORTED_VERSIONS.contains(&version)
}

/// Parse an OAT header from raw bytes.
///
/// Returns the version-specific header variant.  The parser reads the
/// magic and version, then dispatches to the correct layout.
pub fn parse_oat_header(data: &[u8]) -> Result<OatHeaderVersion, String> {
    if data.len() < 8 {
        return Err("Data too short for OAT header (need at least 8 bytes)".to_string());
    }

    let magic: [u8; 4] = data[0..4].try_into().unwrap();
    if magic != *OAT_MAGIC {
        return Err(format!("Invalid OAT magic: {:?}", magic));
    }

    let version: [u8; 4] = data[4..8].try_into().unwrap();
    let version_str = std::str::from_utf8(&version)
        .map_err(|_| "OAT version is not valid UTF-8")?
        .trim_matches('\0');

    let c = parse_common(data)?;

    // All OAT versions share the same fixed layout from 064 through 206.
    // The differences are in the key-value store keys and interpretation.
    macro_rules! make_header {
        ($t:ident, $variant:ident) => {
            Ok(OatHeaderVersion::$variant($t {
                magic,
                version,
                checksum: c.checksum,
                instruction_set: c.instruction_set,
                instruction_set_features_bitmap: c.instruction_set_features_bitmap,
                dex_file_count: c.dex_file_count,
                oat_dex_files_offset: c.oat_dex_files_offset,
                executable_offset: c.executable_offset,
                jni_dlsym_lookup_trampoline_offset: c.jni_dlsym_lookup_trampoline_offset,
                jni_dlsym_lookup_critical_trampoline_offset: c
                    .jni_dlsym_lookup_critical_trampoline_offset,
                quick_generic_jni_trampoline_offset: c.quick_generic_jni_trampoline_offset,
                quick_imt_conflict_trampoline_offset: c.quick_imt_conflict_trampoline_offset,
                quick_resolution_trampoline_offset: c.quick_resolution_trampoline_offset,
                quick_to_interpreter_bridge_offset: c.quick_to_interpreter_bridge_offset,
                nterp_trampoline_offset: c.nterp_trampoline_offset,
                key_value_store: c.key_value_store,
            }))
        };
    }

    match version_str {
        OAT_VERSION_064 => make_header!(OatHeaderV064, V064),
        OAT_VERSION_065 => make_header!(OatHeaderV065, V065),
        OAT_VERSION_079 => make_header!(OatHeaderV079, V079),
        OAT_VERSION_088 => make_header!(OatHeaderV088, V088),
        OAT_VERSION_124 => make_header!(OatHeaderV124, V124),
        OAT_VERSION_131 => make_header!(OatHeaderV131, V131),
        OAT_VERSION_138 => make_header!(OatHeaderV138, V138),
        OAT_VERSION_170 => make_header!(OatHeaderV170, V170),
        OAT_VERSION_183 => make_header!(OatHeaderV183, V183),
        OAT_VERSION_195 => make_header!(OatHeaderV195, V195),
        OAT_VERSION_199 => make_header!(OatHeaderV199, V199),
        OAT_VERSION_206 => make_header!(OatHeaderV206, V206),
        _ => Err(format!("Unsupported OAT version: {:?}", version_str)),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Accessor helpers on OatHeaderVersion
// ═══════════════════════════════════════════════════════════════════════════════════

impl OatHeaderVersion {
    /// Returns the version string (e.g. "131").
    pub fn version_string(&self) -> String {
        let v = match self {
            Self::V064(h) => &h.version,
            Self::V065(h) => &h.version,
            Self::V079(h) => &h.version,
            Self::V088(h) => &h.version,
            Self::V124(h) => &h.version,
            Self::V131(h) => &h.version,
            Self::V138(h) => &h.version,
            Self::V170(h) => &h.version,
            Self::V183(h) => &h.version,
            Self::V195(h) => &h.version,
            Self::V199(h) => &h.version,
            Self::V206(h) => &h.version,
        };
        String::from_utf8_lossy(v).trim_matches('\0').to_string()
    }

    /// Returns the instruction set.
    pub fn instruction_set(&self) -> InstructionSet {
        match self {
            Self::V064(h) => h.instruction_set,
            Self::V065(h) => h.instruction_set,
            Self::V079(h) => h.instruction_set,
            Self::V088(h) => h.instruction_set,
            Self::V124(h) => h.instruction_set,
            Self::V131(h) => h.instruction_set,
            Self::V138(h) => h.instruction_set,
            Self::V170(h) => h.instruction_set,
            Self::V183(h) => h.instruction_set,
            Self::V195(h) => h.instruction_set,
            Self::V199(h) => h.instruction_set,
            Self::V206(h) => h.instruction_set,
        }
    }

    /// Returns the checksum.
    pub fn checksum(&self) -> u32 {
        match self {
            Self::V064(h) => h.checksum,
            Self::V065(h) => h.checksum,
            Self::V079(h) => h.checksum,
            Self::V088(h) => h.checksum,
            Self::V124(h) => h.checksum,
            Self::V131(h) => h.checksum,
            Self::V138(h) => h.checksum,
            Self::V170(h) => h.checksum,
            Self::V183(h) => h.checksum,
            Self::V195(h) => h.checksum,
            Self::V199(h) => h.checksum,
            Self::V206(h) => h.checksum,
        }
    }

    /// Returns the number of DEX files in this OAT.
    pub fn dex_file_count(&self) -> u32 {
        match self {
            Self::V064(h) => h.dex_file_count,
            Self::V065(h) => h.dex_file_count,
            Self::V079(h) => h.dex_file_count,
            Self::V088(h) => h.dex_file_count,
            Self::V124(h) => h.dex_file_count,
            Self::V131(h) => h.dex_file_count,
            Self::V138(h) => h.dex_file_count,
            Self::V170(h) => h.dex_file_count,
            Self::V183(h) => h.dex_file_count,
            Self::V195(h) => h.dex_file_count,
            Self::V199(h) => h.dex_file_count,
            Self::V206(h) => h.dex_file_count,
        }
    }

    /// Returns the offset to the OAT DEX file descriptors.
    pub fn oat_dex_files_offset(&self) -> u32 {
        match self {
            Self::V064(h) => h.oat_dex_files_offset,
            Self::V065(h) => h.oat_dex_files_offset,
            Self::V079(h) => h.oat_dex_files_offset,
            Self::V088(h) => h.oat_dex_files_offset,
            Self::V124(h) => h.oat_dex_files_offset,
            Self::V131(h) => h.oat_dex_files_offset,
            Self::V138(h) => h.oat_dex_files_offset,
            Self::V170(h) => h.oat_dex_files_offset,
            Self::V183(h) => h.oat_dex_files_offset,
            Self::V195(h) => h.oat_dex_files_offset,
            Self::V199(h) => h.oat_dex_files_offset,
            Self::V206(h) => h.oat_dex_files_offset,
        }
    }

    /// Returns the offset to the executable code.
    pub fn executable_offset(&self) -> u32 {
        match self {
            Self::V064(h) => h.executable_offset,
            Self::V065(h) => h.executable_offset,
            Self::V079(h) => h.executable_offset,
            Self::V088(h) => h.executable_offset,
            Self::V124(h) => h.executable_offset,
            Self::V131(h) => h.executable_offset,
            Self::V138(h) => h.executable_offset,
            Self::V170(h) => h.executable_offset,
            Self::V183(h) => h.executable_offset,
            Self::V195(h) => h.executable_offset,
            Self::V199(h) => h.executable_offset,
            Self::V206(h) => h.executable_offset,
        }
    }

    /// Returns the key-value store.
    pub fn key_value_store(&self) -> &[(String, String)] {
        match self {
            Self::V064(h) => &h.key_value_store,
            Self::V065(h) => &h.key_value_store,
            Self::V079(h) => &h.key_value_store,
            Self::V088(h) => &h.key_value_store,
            Self::V124(h) => &h.key_value_store,
            Self::V131(h) => &h.key_value_store,
            Self::V138(h) => &h.key_value_store,
            Self::V170(h) => &h.key_value_store,
            Self::V183(h) => &h.key_value_store,
            Self::V195(h) => &h.key_value_store,
            Self::V199(h) => &h.key_value_store,
            Self::V206(h) => &h.key_value_store,
        }
    }

    /// Look up a key in the key-value store.
    pub fn get_key_value(&self, key: &str) -> Option<&str> {
        self.key_value_store()
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Returns the "dex-file" key from the key-value store, which contains
    /// the original DEX file path.
    pub fn dex_file_location(&self) -> Option<&str> {
        self.get_key_value("dex-file")
    }

    /// Returns the "classpath" key from the key-value store.
    pub fn classpath(&self) -> Option<&str> {
        self.get_key_value("classpath")
    }

    /// Returns the compiler filter (e.g. "speed", "speed-profile", "verify").
    pub fn compiler_filter(&self) -> Option<&str> {
        self.get_key_value("compiler-filter")
    }

    /// Returns the pointer size derived from the instruction set.
    pub fn pointer_size(&self) -> u32 {
        self.instruction_set().pointer_size()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_oat() {
        assert!(is_oat(b"oat\n"));
        assert!(!is_oat(b"nope"));
        assert!(!is_oat(&[0u8; 3]));
    }

    #[test]
    fn test_is_supported_version() {
        assert!(is_supported_version("064"));
        assert!(is_supported_version("131"));
        assert!(is_supported_version("206"));
        assert!(!is_supported_version("999"));
    }

    #[test]
    fn test_instruction_set_from_u32() {
        assert_eq!(InstructionSet::from_u32(0), Some(InstructionSet::None));
        assert_eq!(InstructionSet::from_u32(1), Some(InstructionSet::Arm));
        assert_eq!(InstructionSet::from_u32(5), Some(InstructionSet::X86_64));
        assert_eq!(InstructionSet::from_u32(99), None);
    }

    #[test]
    fn test_instruction_set_pointer_size() {
        assert_eq!(InstructionSet::Arm.pointer_size(), 4);
        assert_eq!(InstructionSet::Arm64.pointer_size(), 8);
        assert_eq!(InstructionSet::X86.pointer_size(), 4);
        assert_eq!(InstructionSet::X86_64.pointer_size(), 8);
    }

    #[test]
    fn test_instruction_set_name() {
        assert_eq!(InstructionSet::Arm.name(), "ARM");
        assert_eq!(InstructionSet::X86_64.name(), "X86_64");
    }

    #[test]
    fn test_parse_header_v131() {
        // Build a minimal v131 header:
        //   magic(4) + version(4) + 13 u32 fixed fields + key_value_store_offset(u32) + KV data
        let mut data = vec![0u8; 256];
        // Magic
        data[0..4].copy_from_slice(b"oat\n");
        // Version
        data[4..8].copy_from_slice(b"131\0");
        // checksum at 8
        data[8..12].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        // instruction_set at 12 = ARM (1)
        data[12..16].copy_from_slice(&1u32.to_le_bytes());
        // instruction_set_features_bitmap at 16
        data[16..20].copy_from_slice(&0u32.to_le_bytes());
        // dex_file_count at 20
        data[20..24].copy_from_slice(&2u32.to_le_bytes());
        // oat_dex_files_offset at 24
        data[24..28].copy_from_slice(&0x100u32.to_le_bytes());
        // executable_offset at 28
        data[28..32].copy_from_slice(&0x200u32.to_le_bytes());
        // Remaining trampoline offsets (32-56): leave as 0
        // nterp_trampoline_offset at 56: leave as 0
        // key_value_store_offset at 60: point to offset 68
        data[60..64].copy_from_slice(&68u32.to_le_bytes());
        // KV store at offset 68: "dex-file\0/tmp/foo.dex\0\0"
        let kv = b"dex-file\0/tmp/foo.dex\0\0";
        data[68..68 + kv.len()].copy_from_slice(kv);

        let header = parse_oat_header(&data).unwrap();
        assert_eq!(header.version_string(), "131");
        assert_eq!(header.instruction_set(), InstructionSet::Arm);
        assert_eq!(header.checksum(), 0xDEADBEEF);
        assert_eq!(header.dex_file_count(), 2);
        assert_eq!(header.oat_dex_files_offset(), 0x100);
        assert_eq!(header.executable_offset(), 0x200);
        assert_eq!(header.pointer_size(), 4);
        assert_eq!(header.dex_file_location(), Some("/tmp/foo.dex"));
    }

    #[test]
    fn test_parse_header_v206() {
        let mut data = vec![0u8; 256];
        data[0..4].copy_from_slice(b"oat\n");
        data[4..8].copy_from_slice(b"206\0");
        data[12..16].copy_from_slice(&2u32.to_le_bytes()); // ARM64
        data[20..24].copy_from_slice(&3u32.to_le_bytes()); // 3 DEX files
        data[60..64].copy_from_slice(&68u32.to_le_bytes());
        let kv = b"dex-file\0/app.apk\0compiler-filter\0speed\0\0";
        data[68..68 + kv.len()].copy_from_slice(kv);

        let header = parse_oat_header(&data).unwrap();
        assert_eq!(header.version_string(), "206");
        assert_eq!(header.instruction_set(), InstructionSet::Arm64);
        assert_eq!(header.dex_file_count(), 3);
        assert_eq!(header.pointer_size(), 8);
        assert_eq!(header.compiler_filter(), Some("speed"));
    }

    #[test]
    fn test_parse_header_invalid_magic() {
        let mut data = vec![0u8; 68];
        data[0..4].copy_from_slice(b"bad\n");
        assert!(parse_oat_header(&data).is_err());
    }

    #[test]
    fn test_parse_header_unsupported_version() {
        let mut data = vec![0u8; 68];
        data[0..4].copy_from_slice(b"oat\n");
        data[4..8].copy_from_slice(b"999\0");
        assert!(parse_oat_header(&data).is_err());
    }

    #[test]
    fn test_parse_header_too_short() {
        assert!(parse_oat_header(&[0u8; 4]).is_err());
    }

    #[test]
    fn test_get_key_value_missing() {
        let mut data = vec![0u8; 256];
        data[0..4].copy_from_slice(b"oat\n");
        data[4..8].copy_from_slice(b"131\0");
        data[12..16].copy_from_slice(&1u32.to_le_bytes()); // ARM
        data[60..64].copy_from_slice(&68u32.to_le_bytes());
        // Empty KV store
        data[68] = 0;

        let header = parse_oat_header(&data).unwrap();
        assert_eq!(header.get_key_value("nonexistent"), None);
        assert_eq!(header.dex_file_location(), None);
    }

    #[test]
    fn test_parse_key_value_store_multiple() {
        let kv_data = b"key1\0val1\0key2\0val2\0\0";
        let result = parse_key_value_store(kv_data, 0).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], ("key1".to_string(), "val1".to_string()));
        assert_eq!(result[1], ("key2".to_string(), "val2".to_string()));
    }

    #[test]
    fn test_parse_key_value_store_empty() {
        let kv_data = b"\0";
        let result = parse_key_value_store(kv_data, 0).unwrap();
        assert!(result.is_empty());
    }
}
