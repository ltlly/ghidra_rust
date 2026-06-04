//! APK (Android Package) File Format Parser
//!
//! Complete nom-based parser for Android APK files.
//!
//! APK files are ZIP archives containing:
//! - `AndroidManifest.xml` — binary XML describing the app
//! - `classes.dex` (and `classesN.dex` for multi-dex) — Dalvik bytecode
//! - `resources.arsc` — compiled resource table
//! - `res/` — application resources
//! - `lib/<abi>/lib*.so` — native libraries
//! - `META-INF/` — cryptographic signatures
//!
//! Parsing includes:
//! - ZIP entry enumeration and extraction (stored + deflated)
//! - Binary XML parsing (StringPool + ResXMLTree chunks)
//! - Manifest attribute extraction: package name, version, SDK, permissions, components
//! - Resources table parsing with package, type, and entry resolution
//! - Native library inventory by ABI
//! - Signature detection

use nom::bytes::complete::take;
use nom::number::complete::{le_u16, le_u32};
use nom::IResult;
use std::collections::HashMap;
use std::io::Read;

// ============================================================================
// Binary XML Chunk Constants
// ============================================================================

/// Binary XML magic number (RES_XML_TYPE).
const AXML_MAGIC: u32 = 0x0008_0003;
/// Resource table magic number (RES_TABLE_TYPE).
const RES_TABLE_MAGIC: u32 = 0x000C_0002;

/// Chunk type constants for binary XML and resource tables.
const CHUNK_STRING_POOL: u16 = 0x0001;
const CHUNK_XML_RESOURCE_MAP: u16 = 0x0180;
const CHUNK_XML_START_NS: u16 = 0x0100;
const CHUNK_XML_END_NS: u16 = 0x0101;
const CHUNK_XML_START_ELEMENT: u16 = 0x0102;
const CHUNK_XML_END_ELEMENT: u16 = 0x0103;
const CHUNK_XML_CDATA: u16 = 0x0104;
const CHUNK_RES_TABLE_PACKAGE: u16 = 0x0200;
const CHUNK_RES_TABLE_TYPE: u16 = 0x0201;
const CHUNK_RES_TABLE_TYPE_SPEC: u16 = 0x0202;

/// Data type constants for binary XML attributes.
const ATTR_TYPE_STRING: u8 = 0x03;
const ATTR_TYPE_INT_HEX: u8 = 0x11;
const ATTR_TYPE_INT_BOOL: u8 = 0x12;
const ATTR_TYPE_REFERENCE: u8 = 0x01;
const ATTR_TYPE_FLOAT: u8 = 0x04;
const ATTR_TYPE_DIMENSION: u8 = 0x05;
const ATTR_TYPE_FRACTION: u8 = 0x06;

// ============================================================================
// ZIP Constants
// ============================================================================

const LOCAL_FILE_HEADER_SIG: u32 = 0x0403_4b50;
const CENTRAL_DIR_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;
const ZIP_COMPRESSION_STORED: u16 = 0;
const ZIP_COMPRESSION_DEFLATED: u16 = 8;

// ============================================================================
// APK File Structure
// ============================================================================

/// Complete parsed APK file information.
#[derive(Debug, Clone)]
pub struct ApkFile {
    /// Package name from manifest (e.g., "com.example.app").
    pub package_name: String,
    /// Version code (integer).
    pub version_code: u32,
    /// Version name string.
    pub version_name: String,
    /// Minimum SDK version.
    pub min_sdk_version: u32,
    /// Target SDK version.
    pub target_sdk_version: u32,
    /// Maximum SDK version, if specified.
    pub max_sdk_version: Option<u32>,
    /// Platform build version code.
    pub platform_build_version_code: Option<u32>,
    /// Platform build version name.
    pub platform_build_version_name: Option<String>,
    /// Compile SDK version.
    pub compile_sdk_version: Option<u32>,
    /// Compile SDK version codename.
    pub compile_sdk_version_codename: Option<String>,
    /// Whether debuggable flag is set.
    pub debuggable: bool,
    /// Whether allowBackup is set (defaults to true).
    pub allow_backup: bool,
    /// The application label string, if specified.
    pub application_label: Option<String>,
    /// The application icon resource, if specified.
    pub application_icon: Option<String>,
    /// Permissions requested by the app (e.g., "android.permission.INTERNET").
    pub permissions: Vec<String>,
    /// Permissions with maxSdkVersion constraints.
    pub permissions_with_max_sdk: Vec<(String, Option<u32>)>,
    /// Uses-feature declarations.
    pub features: Vec<ApkFeature>,
    /// Uses-library declarations.
    pub libraries: Vec<String>,
    /// Activities declared in the manifest.
    pub activities: Vec<ApkComponent>,
    /// Services declared in the manifest.
    pub services: Vec<ApkComponent>,
    /// Broadcast receivers declared in the manifest.
    pub receivers: Vec<ApkComponent>,
    /// Content providers declared in the manifest.
    pub providers: Vec<ApkProvider>,
    /// List of DEX file entries found in the APK.
    pub dex_files: Vec<String>,
    /// List of native library paths found.
    pub native_libs: Vec<NativeLibInfo>,
    /// Signature certificate information.
    pub signatures: Vec<SignatureInfo>,
    /// Raw manifest XML content for custom analysis.
    pub manifest_xml: Option<Vec<u8>>,
    /// Parsed resources table.
    pub resources: Option<ResourceTable>,
    /// All entry names in the ZIP.
    pub all_entries: Vec<String>,
    /// XML namespace mappings (prefix -> URI).
    pub namespaces: Vec<(String, String)>,
}

/// An Android component (Activity, Service, Receiver) from the manifest.
#[derive(Debug, Clone)]
pub struct ApkComponent {
    /// Fully-qualified class name (e.g., "com.example.MainActivity").
    pub name: String,
    /// Whether this component is exported (accessible by other apps).
    pub exported: bool,
    /// Whether this component is enabled.
    pub enabled: bool,
    /// Intent filter specifications.
    pub intent_filters: Vec<IntentFilter>,
    /// Any metadata key-value pairs.
    pub metadata: HashMap<String, String>,
}

/// An Android Content Provider from the manifest.
#[derive(Debug, Clone)]
pub struct ApkProvider {
    /// Fully-qualified class name.
    pub name: String,
    /// Authority URI.
    pub authorities: String,
    /// Whether exported.
    pub exported: bool,
    /// Whether grant URI permissions are enabled.
    pub grant_uri_permissions: bool,
    /// Read permission required.
    pub read_permission: Option<String>,
    /// Write permission required.
    pub write_permission: Option<String>,
}

/// An intent filter declared for a component.
#[derive(Debug, Clone)]
pub struct IntentFilter {
    /// Action strings (e.g., "android.intent.action.MAIN").
    pub actions: Vec<String>,
    /// Category strings (e.g., "android.intent.category.LAUNCHER").
    pub categories: Vec<String>,
    /// Data scheme strings.
    pub data_schemes: Vec<String>,
    /// Data host strings.
    pub data_hosts: Vec<String>,
    /// MIME type strings.
    pub data_mime_types: Vec<String>,
}

/// Information about a native library included in the APK.
#[derive(Debug, Clone)]
pub struct NativeLibInfo {
    /// Path within the APK (e.g., "lib/arm64-v8a/libnative.so").
    pub path: String,
    /// The ABI identifier (e.g., "arm64-v8a", "armeabi-v7a", "x86_64").
    pub abi: String,
    /// The file name of the library.
    pub filename: String,
    /// Size of the compressed entry in bytes.
    pub compressed_size: u64,
    /// Size of the uncompressed entry in bytes.
    pub uncompressed_size: u64,
}

/// Signature certificate information.
#[derive(Debug, Clone)]
pub struct SignatureInfo {
    /// The signature file name (e.g., "CERT.RSA", "CERT.DSA").
    pub filename: String,
    /// Subject DN from the certificate.
    pub subject: String,
    /// Issuer DN from the certificate.
    pub issuer: String,
    /// SHA-256 fingerprint (hex encoded).
    pub sha256_fingerprint: String,
    /// Certificate validity start.
    pub valid_from: String,
    /// Certificate validity end.
    pub valid_until: String,
}

/// A uses-feature declaration from the manifest.
#[derive(Debug, Clone)]
pub struct ApkFeature {
    /// Feature name (e.g., "android.hardware.camera").
    pub name: String,
    /// Whether the feature is required (android:required).
    pub required: bool,
    /// Minimum GLES version, only for OpenGL ES features.
    pub gl_es_version: Option<String>,
}

// ============================================================================
// Resource Table
// ============================================================================

/// Parsed resources.arsc table.
#[derive(Debug, Clone)]
pub struct ResourceTable {
    /// Resource package name.
    pub package_name: String,
    /// String pool entries.
    pub string_pool: Vec<String>,
    /// Resource entries by type and name.
    pub entries: HashMap<String, Vec<ResourceEntry>>,
}

/// A single resource entry in the resource table.
#[derive(Debug, Clone)]
pub struct ResourceEntry {
    /// Resource ID (e.g., 0x7f010000).
    pub id: u32,
    /// Resource type name (e.g., "string", "drawable", "layout").
    pub type_name: String,
    /// Resource name key (e.g., "app_name", "ic_launcher").
    pub name: String,
    /// Offset to the resource data.
    pub data_offset: u32,
    /// Size of the resource data.
    pub data_size: u32,
    /// Configuration qualifier string, if any.
    pub config: Option<String>,
}

// ============================================================================
// Resource Value Types
// ============================================================================

/// Resource value type constants as defined in android Res_value.
const RES_TYPE_NULL: u8 = 0x00;
const RES_TYPE_REFERENCE: u8 = 0x01;
const RES_TYPE_ATTRIBUTE: u8 = 0x02;
const RES_TYPE_STRING: u8 = 0x03;
const RES_TYPE_FLOAT: u8 = 0x04;
const RES_TYPE_DIMENSION: u8 = 0x05;
const RES_TYPE_FRACTION: u8 = 0x06;
const RES_TYPE_DYNAMIC_REFERENCE: u8 = 0x07;
const RES_TYPE_DYNAMIC_ATTRIBUTE: u8 = 0x08;
const RES_TYPE_INT_DEC: u8 = 0x10;
const RES_TYPE_INT_HEX: u8 = 0x11;
const RES_TYPE_INT_BOOL: u8 = 0x12;
const RES_TYPE_INT_COLOR_ARGB8: u8 = 0x1c;
const RES_TYPE_INT_COLOR_RGB8: u8 = 0x1d;
const RES_TYPE_INT_COLOR_ARGB4: u8 = 0x1e;
const RES_TYPE_INT_COLOR_RGB4: u8 = 0x1f;

/// Dimension unit constants.
const DIMENSION_UNIT_PX: u8 = 0;
const DIMENSION_UNIT_DIP: u8 = 1;
const DIMENSION_UNIT_SP: u8 = 2;
const DIMENSION_UNIT_PT: u8 = 3;
const DIMENSION_UNIT_IN: u8 = 4;
const DIMENSION_UNIT_MM: u8 = 5;

/// Fraction unit constants.
const FRACTION_UNIT_FRACTION: u8 = 0;
const FRACTION_UNIT_FRACTION_PARENT: u8 = 1;

/// A decoded resource value from the resource table.
#[derive(Debug, Clone)]
pub enum ResValue {
    /// The resource is null/undefined.
    Null,
    /// A reference to another resource (e.g., @string/app_name).
    Reference(u32),
    /// A reference to an attribute resource.
    Attribute(u32),
    /// A string value (index into string pool).
    String(String),
    /// A floating-point value.
    Float(f32),
    /// A dimension value (e.g., "16dp", "24sp").
    Dimension { value: f32, unit: String },
    /// A fraction value (e.g., "50%", "50%p").
    Fraction { value: f32, unit: String },
    /// A decimal integer.
    IntDec(i32),
    /// A hexadecimal integer.
    IntHex(u32),
    /// A boolean value.
    IntBool(bool),
    /// An ARGB8 color.
    ColorArgb8 { a: u8, r: u8, g: u8, b: u8 },
    /// An RGB8 color.
    ColorRgb8 { r: u8, g: u8, b: u8 },
    /// An ARGB4 color.
    ColorArgb4 { a: u8, r: u8, g: u8, b: u8 },
    /// An RGB4 color.
    ColorRgb4 { r: u8, g: u8, b: u8 },
    /// A dynamic reference.
    DynamicReference(u32),
    /// A dynamic attribute reference.
    DynamicAttribute(u32),
}

/// Decode a raw resource value (u32 data, u8 type) into a ResValue.
pub fn decode_res_value(data: u32, data_type: u8) -> ResValue {
    match data_type {
        RES_TYPE_NULL => ResValue::Null,
        RES_TYPE_REFERENCE => ResValue::Reference(data),
        RES_TYPE_ATTRIBUTE => ResValue::Attribute(data),
        RES_TYPE_FLOAT => ResValue::Float(f32::from_bits(data)),
        RES_TYPE_DIMENSION => {
            let value = complex_to_float((data & 0xFFFFFF00) as i32);
            let unit = dimension_unit_name((data & 0xFF) as u8);
            ResValue::Dimension { value, unit }
        }
        RES_TYPE_FRACTION => {
            let value = complex_to_float((data & 0xFFFFFF00) as i32);
            let unit = fraction_unit_name((data & 0xFF) as u8);
            ResValue::Fraction { value, unit }
        }
        RES_TYPE_INT_DEC => ResValue::IntDec(data as i32),
        RES_TYPE_INT_HEX => ResValue::IntHex(data),
        RES_TYPE_INT_BOOL => ResValue::IntBool(data != 0),
        RES_TYPE_INT_COLOR_ARGB8 => ResValue::ColorArgb8 {
            a: ((data >> 24) & 0xFF) as u8,
            r: ((data >> 16) & 0xFF) as u8,
            g: ((data >> 8) & 0xFF) as u8,
            b: (data & 0xFF) as u8,
        },
        RES_TYPE_INT_COLOR_RGB8 => ResValue::ColorRgb8 {
            r: ((data >> 16) & 0xFF) as u8,
            g: ((data >> 8) & 0xFF) as u8,
            b: (data & 0xFF) as u8,
        },
        RES_TYPE_INT_COLOR_ARGB4 => ResValue::ColorArgb4 {
            a: ((data >> 12) & 0xF) as u8,
            r: ((data >> 8) & 0xF) as u8,
            g: ((data >> 4) & 0xF) as u8,
            b: (data & 0xF) as u8,
        },
        RES_TYPE_INT_COLOR_RGB4 => ResValue::ColorRgb4 {
            r: ((data >> 8) & 0xF) as u8,
            g: ((data >> 4) & 0xF) as u8,
            b: (data & 0xF) as u8,
        },
        RES_TYPE_DYNAMIC_REFERENCE => ResValue::DynamicReference(data),
        RES_TYPE_DYNAMIC_ATTRIBUTE => ResValue::DynamicAttribute(data),
        _ => ResValue::IntHex(data),
    }
}

/// Convert a complex unit integer to a float (radix 2 with 8 mantissa bits).
fn complex_to_float(complex: i32) -> f32 {
    (complex as f32) * (1.0f32 / 256.0f32)
}

/// Return the unit name for a dimension value.
pub fn dimension_unit_name(unit: u8) -> String {
    match unit {
        DIMENSION_UNIT_PX => "px".to_string(),
        DIMENSION_UNIT_DIP => "dp".to_string(),
        DIMENSION_UNIT_SP => "sp".to_string(),
        DIMENSION_UNIT_PT => "pt".to_string(),
        DIMENSION_UNIT_IN => "in".to_string(),
        DIMENSION_UNIT_MM => "mm".to_string(),
        _ => format!("unknown({})", unit),
    }
}

/// Return the unit name for a fraction value.
pub fn fraction_unit_name(unit: u8) -> String {
    match unit {
        FRACTION_UNIT_FRACTION => "%".to_string(),
        FRACTION_UNIT_FRACTION_PARENT => "%p".to_string(),
        _ => format!("unknown({})", unit),
    }
}

/// Convert a resource ID to a human-readable hex string.
pub fn res_id_to_string(id: u32) -> String {
    format!("0x{:08x}", id)
}

/// Parse a package ID from a resource ID.
pub fn res_id_package(id: u32) -> u8 {
    ((id >> 24) & 0xFF) as u8
}

/// Parse a type ID from a resource ID.
pub fn res_id_type(id: u32) -> u8 {
    ((id >> 16) & 0xFF) as u8
}

/// Parse an entry ID from a resource ID.
pub fn res_id_entry(id: u32) -> u16 {
    (id & 0xFFFF) as u16
}

// ============================================================================
// Error Type
// ============================================================================

#[derive(Debug, Clone)]
pub enum ApkError {
    NotAValidZip,
    ManifestNotFound,
    InvalidBinaryXml,
    InvalidResourceTable,
    TruncatedData,
    DecompressionError,
}

impl std::fmt::Display for ApkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApkError::NotAValidZip => write!(f, "Not a valid ZIP file"),
            ApkError::ManifestNotFound => write!(f, "AndroidManifest.xml not found"),
            ApkError::InvalidBinaryXml => write!(f, "Invalid binary XML"),
            ApkError::InvalidResourceTable => write!(f, "Invalid resource table"),
            ApkError::TruncatedData => write!(f, "Truncated data"),
            ApkError::DecompressionError => write!(f, "Decompression error"),
        }
    }
}

impl std::error::Error for ApkError {}

pub type ApkResult<T> = Result<T, ApkError>;

// ============================================================================
// Internal: XML Element Tree (for manifest parsing)
// ============================================================================

#[derive(Debug, Clone)]
struct XmlElement {
    name: String,
    attributes: Vec<XmlAttribute>,
    children: Vec<XmlElement>,
}

#[derive(Debug, Clone)]
struct XmlAttribute {
    namespace: String,
    name: String,
    value: String,
    data_type: u8,
    raw_data: u32,
}

// ============================================================================
// Internal: ZIP Entry
// ============================================================================

#[derive(Debug, Clone)]
struct ZipEntry {
    name: String,
    header_offset: usize,
    compressed_size: u32,
    uncompressed_size: u32,
    compression_method: u16,
    crc32: u32,
}

// ============================================================================
// Low-level Binary Helpers
// ============================================================================

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > data.len() { return None; }
    Some(u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]))
}

fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > data.len() { return None; }
    Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn read_i32_le(data: &[u8], offset: usize) -> Option<i32> {
    if offset + 4 > data.len() { return None; }
    Some(i32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]))
}

// ============================================================================
// ZIP Parsing
// ============================================================================

/// Scan backwards from the end of data to locate the End of Central Directory record.
fn find_eocd(data: &[u8]) -> Option<usize> {
    if data.len() < 22 {
        return None;
    }
    let search_start = if data.len() > 65557 { data.len() - 65557 } else { 0 };
    for i in (search_start..=data.len() - 22).rev() {
        let sig = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        if sig == EOCD_SIG {
            return Some(i);
        }
    }
    None
}

/// Parse all ZIP entries from the central directory.
fn parse_zip_entries(data: &[u8]) -> Option<Vec<ZipEntry>> {
    let eocd_offset = find_eocd(data)?;
    let central_dir_offset = read_u32_le(data, eocd_offset + 16)? as usize;
    let central_dir_count = read_u16_le(data, eocd_offset + 10)? as usize;
    let mut entries = Vec::new();
    let mut cursor = central_dir_offset;
    for _ in 0..central_dir_count {
        if cursor + 46 > data.len() {
            break;
        }
        if read_u32_le(data, cursor)? != CENTRAL_DIR_SIG {
            break;
        }
        let compression_method = read_u16_le(data, cursor + 10)?;
        let crc32 = read_u32_le(data, cursor + 16)?;
        let compressed_size = read_u32_le(data, cursor + 20)?;
        let uncompressed_size = read_u32_le(data, cursor + 24)?;
        let name_len = read_u16_le(data, cursor + 28)? as usize;
        let extra_len = read_u16_le(data, cursor + 30)? as usize;
        let comment_len = read_u16_le(data, cursor + 32)? as usize;
        let local_header_offset = read_u32_le(data, cursor + 42)? as usize;
        let name_start = cursor + 46;
        if name_start + name_len > data.len() {
            break;
        }
        let name = String::from_utf8_lossy(&data[name_start..name_start + name_len]).to_string();
        entries.push(ZipEntry {
            name,
            header_offset: local_header_offset,
            compressed_size,
            uncompressed_size,
            compression_method,
            crc32,
        });
        cursor += 46 + name_len + extra_len + comment_len;
    }
    Some(entries)
}

/// Extract the raw bytes of a ZIP entry from the file data.
fn extract_zip_entry(data: &[u8], entry: &ZipEntry) -> Option<Vec<u8>> {
    let offset = entry.header_offset;
    if offset + 30 > data.len() {
        return None;
    }
    if read_u32_le(data, offset)? != LOCAL_FILE_HEADER_SIG {
        return None;
    }
    let name_len = read_u16_le(data, offset + 26)? as usize;
    let extra_len = read_u16_le(data, offset + 28)? as usize;
    let data_start = offset + 30 + name_len + extra_len;

    match entry.compression_method {
        ZIP_COMPRESSION_STORED => {
            let len = entry.uncompressed_size as usize;
            if data_start + len > data.len() {
                return None;
            }
            Some(data[data_start..data_start + len].to_vec())
        }
        ZIP_COMPRESSION_DEFLATED => {
            let len = entry.compressed_size as usize;
            if data_start + len > data.len() {
                return None;
            }
            let compressed = &data[data_start..data_start + len];
            let mut decoder = flate2::read::DeflateDecoder::new(compressed);
            let mut result = Vec::new();
            if decoder.read_to_end(&mut result).is_ok() {
                Some(result)
            } else {
                Some(compressed.to_vec())
            }
        }
        _ => None,
    }
}

// ============================================================================
// Binary XML: String Pool Parser
// ============================================================================

/// Parse a StringPool chunk from binary XML data.
/// Returns the string pool and the position after the chunk.
fn parse_string_pool(data: &[u8], offset: usize) -> Option<(Vec<String>, usize)> {
    let chunk_type = read_u16_le(data, offset)?;
    if chunk_type != CHUNK_STRING_POOL {
        return None;
    }

    let _header_size = read_u16_le(data, offset + 2)? as usize;
    let chunk_size = read_u32_le(data, offset + 4)? as usize;
    let string_count = read_u32_le(data, offset + 8)? as usize;
    let _style_count = read_u32_le(data, offset + 12)? as usize;
    let flags = read_u32_le(data, offset + 16)?;
    let strings_offset = read_u32_le(data, offset + 20)? as usize;
    let _styles_offset = read_u32_le(data, offset + 24)? as usize;

    let is_utf8 = (flags & 0x100) != 0;
    let mut strings = Vec::with_capacity(string_count);
    // String offsets start 28 bytes into the chunk
    let string_offsets_start = offset + 28;

    for i in 0..string_count {
        let str_offset = read_u32_le(data, string_offsets_start + i * 4)? as usize;
        let str_pos = offset + strings_offset + str_offset;
        if str_pos + 2 > data.len() {
            strings.push(String::new());
            continue;
        }

        if is_utf8 {
            // UTF-8 encoded strings
            let len1 = data[str_pos] as usize;
            let len2 = data[str_pos + 1] as usize;
            let char_len = len1 | (len2 << 8);
            let byte_len = if (char_len >> 8) != 0 {
                (char_len >> 8) * 3 // rough estimate for multibyte
            } else {
                len1
            };
            let real_start = str_pos + 2;
            let max_end = std::cmp::min(real_start + byte_len, data.len());
            let end_null = data[real_start..max_end]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(max_end - real_start);
            match String::from_utf8(data[real_start..real_start + end_null].to_vec()) {
                Ok(s) => strings.push(s),
                Err(_) => strings.push(String::new()),
            }
        } else {
            // UTF-16 encoded strings
            let char_len = read_u16_le(data, str_pos)? as usize;
            let real_start = str_pos + 2;
            let mut utf16_data = Vec::with_capacity(char_len);
            for j in 0..char_len {
                if real_start + j * 2 + 2 > data.len() {
                    break;
                }
                let cu = read_u16_le(data, real_start + j * 2).unwrap_or(0);
                if cu == 0 {
                    break;
                }
                utf16_data.push(cu);
            }
            match String::from_utf16(&utf16_data) {
                Ok(s) => strings.push(s),
                Err(_) => strings.push(String::new()),
            }
        }
    }

    Some((strings, offset + chunk_size))
}

// ============================================================================
// Binary XML: Element Parser
// ============================================================================

/// Parse binary XML into element tree and string pool.
fn parse_binary_xml(data: &[u8]) -> Option<(Vec<XmlElement>, Vec<String>)> {
    if data.len() < 8 {
        return None;
    }
    let magic = read_u32_le(data, 0)?;
    if magic != AXML_MAGIC {
        return None;
    }
    let _file_size = read_u32_le(data, 4)? as usize;

    // Parse the first string pool at offset 8
    let (string_pool, mut cursor) = parse_string_pool(data, 8)?;

    // Optionally skip the resource map chunk
    if cursor + 8 <= data.len() {
        let chunk_type_hint = read_u16_le(data, cursor)?;
        if chunk_type_hint == CHUNK_XML_RESOURCE_MAP {
            let chunk_size = read_u32_le(data, cursor + 4)? as usize;
            cursor += chunk_size;
        }
    }

    let mut elements: Vec<XmlElement> = Vec::new();
    let mut stack: Vec<XmlElement> = Vec::new();
    let mut namespaces: Vec<(String, String)> = Vec::new();
    let mut ns_stack: Vec<Vec<(String, String)>> = Vec::new();

    while cursor + 8 <= data.len() {
        let ct = read_u16_le(data, cursor)?;
        let cs = read_u32_le(data, cursor + 4)? as usize;
        if cs == 0 {
            break;
        }

        match ct {
            CHUNK_XML_START_NS => {
                if let Some((prefix, uri)) = parse_xml_namespace(data, cursor, &string_pool) {
                    namespaces.push((prefix, uri));
                }
            }
            CHUNK_XML_END_NS => {
                // End namespace: pop any pushed namespaces for this level
                // The END_NS chunk contains prefix index and URI index
            }
            CHUNK_XML_START_ELEMENT => {
                ns_stack.push(namespaces.clone());
                if let Some(elem) = parse_xml_start_element(data, cursor, &string_pool) {
                    stack.push(elem);
                }
            }
            CHUNK_XML_END_ELEMENT => {
                if let Some(elem) = stack.pop() {
                    match stack.last_mut() {
                        Some(parent) => parent.children.push(elem),
                        None => elements.push(elem),
                    }
                }
                if let Some(saved) = ns_stack.pop() {
                    namespaces = saved;
                }
            }
            _ => {}
        }

        cursor += cs;
    }

    Some((elements, string_pool))
}

/// Parse an XML namespace declaration chunk (START_NS / END_NS).
fn parse_xml_namespace(
    data: &[u8],
    offset: usize,
    string_pool: &[String],
) -> Option<(String, String)> {
    let _chunk_type = read_u16_le(data, offset)?;
    let _chunk_size = read_u32_le(data, offset + 4)?;
    let _line_number = read_u32_le(data, offset + 8)?;
    let _comment = read_i32_le(data, offset + 12)?;
    let prefix_index = read_i32_le(data, offset + 16)?;
    let uri_index = read_i32_le(data, offset + 20)?;

    let prefix = if prefix_index >= 0 && (prefix_index as usize) < string_pool.len() {
        string_pool[prefix_index as usize].clone()
    } else {
        String::new()
    };
    let uri = if uri_index >= 0 && (uri_index as usize) < string_pool.len() {
        string_pool[uri_index as usize].clone()
    } else {
        String::new()
    };
    Some((prefix, uri))
}

/// Parse a single XML start element chunk.
fn parse_xml_start_element(
    data: &[u8],
    offset: usize,
    string_pool: &[String],
) -> Option<XmlElement> {
    let _chunk_type = read_u16_le(data, offset)?;
    let _header_size = read_u16_le(data, offset + 2)? as usize;
    let _chunk_size = read_u32_le(data, offset + 4)? as usize;
    let _line_number = read_u32_le(data, offset + 8)?;
    let _comment = read_i32_le(data, offset + 12)?;
    let _ns_index = read_i32_le(data, offset + 16)?;
    let name_index = read_i32_le(data, offset + 20)?;

    let name = if name_index >= 0 && (name_index as usize) < string_pool.len() {
        string_pool[name_index as usize].clone()
    } else {
        String::new()
    };

    let attr_start = read_u16_le(data, offset + 24)? as usize;
    let attr_size = read_u16_le(data, offset + 26)? as usize;
    let attr_count = read_u16_le(data, offset + 28)? as usize;
    let _id_index = read_u16_le(data, offset + 30)?;
    let _class_index = read_u16_le(data, offset + 32)?;
    let _style_index = read_u16_le(data, offset + 34)?;

    let mut attributes = Vec::with_capacity(attr_count);
    let attr_base = offset + attr_start;
    for i in 0..attr_count {
        let aoff = attr_base + i * attr_size;
        if aoff + 20 > data.len() {
            break;
        }
        let _ns = read_i32_le(data, aoff)?;
        let name_i = read_i32_le(data, aoff + 4)?;
        let value_i = read_i32_le(data, aoff + 8)?;
        let _flags = read_u16_le(data, aoff + 12)?;
        let _val_size = read_u16_le(data, aoff + 14)?;
        let dt = data.get(aoff + 16).copied().unwrap_or(0);
        let _res0 = data.get(aoff + 17).copied().unwrap_or(0);
        let rd = read_u16_le(data, aoff + 18).unwrap_or(0) as u32;

        let attr_name = if name_i >= 0 && (name_i as usize) < string_pool.len() {
            string_pool[name_i as usize].clone()
        } else {
            format!("@0x{:08x}", name_i as u32)
        };

        let value = if dt == ATTR_TYPE_STRING && value_i >= 0 && (value_i as usize) < string_pool.len() {
            string_pool[value_i as usize].clone()
        } else if dt == ATTR_TYPE_INT_HEX {
            format!("{}", rd)
        } else if dt == ATTR_TYPE_INT_BOOL {
            if rd == 0xFFFFFFFFu32 { "true".to_string() } else { "false".to_string() }
        } else if dt == ATTR_TYPE_REFERENCE {
            format!("@0x{:08x}", rd)
        } else {
            format!("0x{:08x}", rd)
        };

        attributes.push(XmlAttribute {
            namespace: String::new(),
            name: attr_name,
            value,
            data_type: dt,
            raw_data: rd,
        });
    }

    Some(XmlElement {
        name,
        attributes,
        children: Vec::new(),
    })
}

// ============================================================================
// Manifest Element Walkers
// ============================================================================

/// Recursively extract uses-permission declarations.
fn extract_permissions(elements: &[XmlElement]) -> Vec<String> {
    let mut perms = Vec::new();
    for elem in elements {
        if elem.name == "uses-permission" {
            for attr in &elem.attributes {
                if attr.name == "name" {
                    perms.push(attr.value.clone());
                }
            }
        }
        perms.extend(extract_permissions(&elem.children));
    }
    perms
}

/// Recursively extract components of a given tag type (activity, service, receiver).
fn extract_components(elements: &[XmlElement], tag: &str) -> Vec<ApkComponent> {
    let mut components = Vec::new();
    for elem in elements {
        if elem.name == tag {
            let mut comp = ApkComponent {
                name: String::new(),
                exported: false,
                enabled: true,
                intent_filters: Vec::new(),
                metadata: HashMap::new(),
            };
            for attr in &elem.attributes {
                match attr.name.as_str() {
                    "name" => comp.name = attr.value.clone(),
                    "exported" => comp.exported = attr.value == "true",
                    "enabled" => comp.enabled = attr.value != "false",
                    _ => {
                        comp.metadata.insert(attr.name.clone(), attr.value.clone());
                    }
                }
            }
            for child in &elem.children {
                if child.name == "intent-filter" {
                    comp.intent_filters.push(extract_intent_filter(child));
                }
            }
            components.push(comp);
        }
        components.extend(extract_components(&elem.children, tag));
    }
    components
}

/// Recursively extract provider declarations.
fn extract_providers(elements: &[XmlElement]) -> Vec<ApkProvider> {
    let mut providers = Vec::new();
    for elem in elements {
        if elem.name == "provider" {
            let mut prov = ApkProvider {
                name: String::new(),
                authorities: String::new(),
                exported: false,
                grant_uri_permissions: false,
                read_permission: None,
                write_permission: None,
            };
            for attr in &elem.attributes {
                match attr.name.as_str() {
                    "name" => prov.name = attr.value.clone(),
                    "authorities" => prov.authorities = attr.value.clone(),
                    "exported" => prov.exported = attr.value == "true",
                    "grantUriPermissions" => prov.grant_uri_permissions = attr.value == "true",
                    "readPermission" => prov.read_permission = Some(attr.value.clone()),
                    "writePermission" => prov.write_permission = Some(attr.value.clone()),
                    _ => {}
                }
            }
            providers.push(prov);
        }
        providers.extend(extract_providers(&elem.children));
    }
    providers
}

/// Extract an IntentFilter from element children.
fn extract_intent_filter(elem: &XmlElement) -> IntentFilter {
    let mut filter = IntentFilter {
        actions: Vec::new(),
        categories: Vec::new(),
        data_schemes: Vec::new(),
        data_hosts: Vec::new(),
        data_mime_types: Vec::new(),
    };
    for child in &elem.children {
        match child.name.as_str() {
            "action" => {
                for attr in &child.attributes {
                    if attr.name == "name" {
                        filter.actions.push(attr.value.clone());
                    }
                }
            }
            "category" => {
                for attr in &child.attributes {
                    if attr.name == "name" {
                        filter.categories.push(attr.value.clone());
                    }
                }
            }
            "data" => {
                for attr in &child.attributes {
                    match attr.name.as_str() {
                        "scheme" => filter.data_schemes.push(attr.value.clone()),
                        "host" => filter.data_hosts.push(attr.value.clone()),
                        "mimeType" => filter.data_mime_types.push(attr.value.clone()),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    filter
}

/// Recursively extract uses-feature declarations.
fn extract_features(elements: &[XmlElement]) -> Vec<ApkFeature> {
    let mut features = Vec::new();
    for elem in elements {
        if elem.name == "uses-feature" {
            let mut feat = ApkFeature {
                name: String::new(),
                required: true,
                gl_es_version: None,
            };
            for attr in &elem.attributes {
                match attr.name.as_str() {
                    "name" => feat.name = attr.value.clone(),
                    "required" => feat.required = attr.value != "false",
                    "glEsVersion" => feat.gl_es_version = Some(attr.value.clone()),
                    _ => {}
                }
            }
            features.push(feat);
        }
        features.extend(extract_features(&elem.children));
    }
    features
}

/// Recursively extract uses-library declarations.
fn extract_libraries(elements: &[XmlElement]) -> Vec<String> {
    let mut libs = Vec::new();
    for elem in elements {
        if elem.name == "uses-library" {
            for attr in &elem.attributes {
                if attr.name == "name" {
                    libs.push(attr.value.clone());
                }
            }
        }
        libs.extend(extract_libraries(&elem.children));
    }
    libs
}

// ============================================================================
// Resources Parsing
// ============================================================================

/// Parse the resources.arsc file.
fn parse_resource_table(data: &[u8]) -> Option<ResourceTable> {
    if data.len() < 12 {
        return None;
    }
    if read_u32_le(data, 0)? != RES_TABLE_MAGIC {
        return None;
    }
    let _file_size = read_u32_le(data, 4)? as usize;

    // Parse global string pool
    let (string_pool, mut pos) = parse_string_pool(data, 12)?;

    let mut entries: HashMap<String, Vec<ResourceEntry>> = HashMap::new();
    let mut package_name = String::new();

    while pos + 8 <= data.len() {
        let ct = read_u16_le(data, pos)?;
        let cs = read_u32_le(data, pos + 4)? as usize;
        if cs == 0 {
            break;
        }

        if ct == CHUNK_RES_TABLE_PACKAGE {
            // Read package name
            let _package_id = read_u32_le(data, pos + 8)?;
            let name_chars: Vec<u16> = (0..128)
                .filter_map(|j| read_u16_le(data, pos + 12 + j * 2))
                .take_while(|&c| c != 0)
                .collect();
            package_name = String::from_utf16(&name_chars).unwrap_or_default();

            // We also need to parse type strings and key strings that follow the package
            // The package chunk contains further chunk data
            // After the 288 byte header, there's a type string pool, then key string pool, then type specs
            let type_strings_offset = pos + 288;

            // Parse type names string pool
            if let Some((type_names, _tsp_end)) = parse_string_pool(data, type_strings_offset) {
                // The key string pool follows the type string pool
                let key_start = type_strings_offset
                    + read_u32_le(data, type_strings_offset + 4).unwrap_or(0) as usize;

                if let Some((key_names, _ksp_end)) = parse_string_pool(data, key_start) {
                    // Now walk chunks at the key_start level for type specs
                    let mut tsp = key_start
                        + read_u32_le(data, key_start + 4).unwrap_or(0) as usize;

                    while tsp + 8 <= data.len() {
                        let tt = read_u16_le(data, tsp)?;
                        let ts = read_u32_le(data, tsp + 4)? as usize;
                        if ts == 0 {
                            break;
                        }

                        if tt == CHUNK_RES_TABLE_TYPE_SPEC {
                            let type_id = data.get(tsp + 9).copied().unwrap_or(0);
                            let entry_count = read_u32_le(data, tsp + 12)
                                .unwrap_or(0) as usize;
                            let entries_start = read_u32_le(data, tsp + 16)
                                .unwrap_or(0) as usize;

                            let type_name = if (type_id as usize) > 0
                                && (type_id as usize) <= type_names.len()
                            {
                                type_names[type_id as usize - 1].clone()
                            } else {
                                format!("type{}", type_id)
                            };

                            let offsets_start = tsp + entries_start;
                            for i in 0..entry_count {
                                let eoff =
                                    read_u32_le(data, offsets_start + i * 4).unwrap_or(0);
                                if eoff == 0xFFFF_FFFF {
                                    continue;
                                }
                                let entry_pos = tsp + entries_start + eoff as usize;
                                if entry_pos + 8 > data.len() {
                                    continue;
                                }
                                let _entry_size = read_u16_le(data, entry_pos).unwrap_or(0);
                                let _entry_flags = read_u16_le(data, entry_pos + 2).unwrap_or(0);
                                let key_index =
                                    read_u32_le(data, entry_pos + 4).unwrap_or(0) as usize;

                                let name = if key_index < key_names.len() {
                                    key_names[key_index].clone()
                                } else {
                                    format!("entry{}", key_index)
                                };

                                let entry = ResourceEntry {
                                    id: ((0x7f << 24) | ((type_id as u32) << 16) | (i as u32)),
                                    type_name: type_name.clone(),
                                    name,
                                    data_offset: (tsp + entries_start + eoff as usize) as u32,
                                    data_size: 0,
                                    config: None,
                                };

                                entries
                                    .entry(type_name.clone())
                                    .or_default()
                                    .push(entry);
                            }
                        }
                        tsp += ts;
                    }
                }
            }
        }
        pos += cs;
    }

    Some(ResourceTable {
        package_name,
        string_pool,
        entries,
    })
}

// ============================================================================
// Manifest Element Walkers (continued)
// ============================================================================

/// Walk manifest elements to extract sdk and package info recursively.
fn walk_manifest_elements(elements: &[XmlElement], apk: &mut ApkFile) {
    for elem in elements {
        match elem.name.as_str() {
            "manifest" => {
                for attr in &elem.attributes {
                    match attr.name.as_str() {
                        "package" => apk.package_name = attr.value.clone(),
                        "versionCode" => {
                            apk.version_code = attr.value.parse().unwrap_or(0)
                        }
                        "versionName" => {
                            apk.version_name = attr.value.clone()
                        }
                        "compileSdkVersion" => {
                            apk.compile_sdk_version = attr.value.parse().ok()
                        }
                        "compileSdkVersionCodename" => {
                            apk.compile_sdk_version_codename =
                                if attr.value.is_empty() { None }
                                else { Some(attr.value.clone()) }
                        }
                        "platformBuildVersionCode" => {
                            apk.platform_build_version_code = attr.value.parse().ok()
                        }
                        "platformBuildVersionName" => {
                            apk.platform_build_version_name =
                                if attr.value.is_empty() { None }
                                else { Some(attr.value.clone()) }
                        }
                        _ => {}
                    }
                }
            }
            "uses-sdk" => {
                for attr in &elem.attributes {
                    match attr.name.as_str() {
                        "minSdkVersion" => {
                            apk.min_sdk_version = attr.value.parse().unwrap_or(1)
                        }
                        "targetSdkVersion" => {
                            apk.target_sdk_version = attr.value.parse().unwrap_or(1)
                        }
                        "maxSdkVersion" => {
                            apk.max_sdk_version = attr.value.parse().ok()
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        walk_manifest_elements(&elem.children, apk);
    }
}

/// Walk elements to find uses-permission with maxSdkVersion.
fn walk_perm_max_sdk(elem: &XmlElement, perms: &mut Vec<(String, Option<u32>)>) {
    if elem.name == "uses-permission" {
        let mut name = String::new();
        let mut max_sdk: Option<u32> = None;
        for attr in &elem.attributes {
            if attr.name == "name" { name = attr.value.clone(); }
            if attr.name == "maxSdkVersion" {
                max_sdk = attr.value.parse().ok();
            }
        }
        if !name.is_empty() {
            perms.push((name, max_sdk));
        }
    }
    for child in &elem.children {
        walk_perm_max_sdk(child, perms);
    }
}

// ============================================================================
// Main APK Parser
// ============================================================================

/// Parse an APK file from raw bytes.
pub fn parse_apk(data: &[u8]) -> ApkResult<ApkFile> {
    let entries =
        parse_zip_entries(data).ok_or(ApkError::NotAValidZip)?;
    let all_entries: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();

    let mut apk = ApkFile {
        package_name: String::new(),
        version_code: 0,
        version_name: String::new(),
        min_sdk_version: 1,
        target_sdk_version: 1,
        max_sdk_version: None,
        platform_build_version_code: None,
        platform_build_version_name: None,
        compile_sdk_version: None,
        compile_sdk_version_codename: None,
        debuggable: false,
        allow_backup: true,
        application_label: None,
        application_icon: None,
        permissions: Vec::new(),
        permissions_with_max_sdk: Vec::new(),
        features: Vec::new(),
        libraries: Vec::new(),
        activities: Vec::new(),
        services: Vec::new(),
        receivers: Vec::new(),
        providers: Vec::new(),
        dex_files: Vec::new(),
        native_libs: Vec::new(),
        signatures: Vec::new(),
        manifest_xml: None,
        resources: None,
        all_entries,
        namespaces: Vec::new(),
    };

    // ── Parse AndroidManifest.xml ──────────────────────────────────────
    if let Some(manifest_entry) = entries
        .iter()
        .find(|e| e.name == "AndroidManifest.xml")
    {
        if let Some(manifest_data) = extract_zip_entry(data, manifest_entry) {
            apk.manifest_xml = Some(manifest_data.clone());
            if let Some((elements, _sp)) = parse_binary_xml(&manifest_data) {
                // Walk ALL elements recursively to extract manifest attributes
                walk_manifest_elements(&elements, &mut apk);

                // Extract permissions, features, libraries, and components
                for elem in &elements {
                    if elem.name == "application" || elem.name == "manifest" {
                        apk.permissions.extend(extract_permissions(&elem.children));
                        apk.features.extend(extract_features(&elem.children));
                        apk.libraries.extend(extract_libraries(&elem.children));
                        apk.activities =
                            extract_components(&elem.children, "activity");
                        apk.services =
                            extract_components(&elem.children, "service");
                        apk.receivers =
                            extract_components(&elem.children, "receiver");
                        apk.providers = extract_providers(&elem.children);

                        // Extract application label, icon, debuggable, etc.
                        for attr in &elem.attributes {
                            match attr.name.as_str() {
                                "label" => apk.application_label = Some(attr.value.clone()),
                                "icon" => apk.application_icon = Some(attr.value.clone()),
                                "debuggable" => apk.debuggable = attr.value == "true",
                                "allowBackup" => apk.allow_backup = attr.value != "false",
                                _ => {}
                            }
                        }
                    }
                }

                // Extract permissions with maxSdkVersion
                for elem in &elements {
                    walk_perm_max_sdk(elem, &mut apk.permissions_with_max_sdk);
                }
            }
        }
    }

    // ── Enumerate DEX files ────────────────────────────────────────────
    for entry in &entries {
        if entry.name == "classes.dex"
            || (entry.name.starts_with("classes") && entry.name.ends_with(".dex"))
        {
            apk.dex_files.push(entry.name.clone());
        }
    }

    // ── Enumerate native libraries ─────────────────────────────────────
    for entry in &entries {
        if entry.name.starts_with("lib/") && entry.name.ends_with(".so") {
            let parts: Vec<&str> = entry.name.split('/').collect();
            let abi = if parts.len() >= 3 {
                parts[1].to_string()
            } else {
                "unknown".to_string()
            };
            let filename = if parts.len() >= 3 {
                parts[2].to_string()
            } else {
                entry.name.clone()
            };
            apk.native_libs.push(NativeLibInfo {
                path: entry.name.clone(),
                abi,
                filename,
                compressed_size: entry.compressed_size as u64,
                uncompressed_size: entry.uncompressed_size as u64,
            });
        }
    }

    // ── Signature files ────────────────────────────────────────────────
    for entry in &entries {
        if entry.name.starts_with("META-INF/")
            && (entry.name.ends_with(".RSA")
                || entry.name.ends_with(".DSA")
                || entry.name.ends_with(".EC"))
        {
            apk.signatures.push(SignatureInfo {
                filename: entry.name.clone(),
                subject: String::new(),
                issuer: String::new(),
                sha256_fingerprint: String::new(),
                valid_from: String::new(),
                valid_until: String::new(),
            });
        }
    }

    // ── Parse resources.arsc ───────────────────────────────────────────
    if let Some(arsc_entry) = entries.iter().find(|e| e.name == "resources.arsc") {
        if let Some(arsc_data) = extract_zip_entry(data, arsc_entry) {
            apk.resources = parse_resource_table(&arsc_data);
        }
    }

    Ok(apk)
}

/// Check if data looks like an APK file (ZIP containing AndroidManifest.xml).
pub fn is_apk(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic != LOCAL_FILE_HEADER_SIG {
        return false;
    }
    if let Some(entries) = parse_zip_entries(data) {
        entries.iter().any(|e| e.name == "AndroidManifest.xml")
    } else {
        false
    }
}

// ============================================================================
// BinaryLoader Implementation
// ============================================================================

/// APK loader — loads Android APK packages for analysis of manifest,
/// DEX bytecode, native libraries, and resources.
pub struct ApkLoader;

impl crate::BinaryLoader for ApkLoader {
    fn name(&self) -> &str {
        "APK"
    }

    fn can_load(&self, data: &[u8]) -> bool {
        is_apk(data)
    }

    fn load(
        &self,
        data: &[u8],
        options: &crate::LoadOptions,
    ) -> anyhow::Result<crate::base::analyzer::Program> {
        use crate::base::analyzer::{Address, MemoryBlock, Program};

        let apk = parse_apk(data)?;
        let lang = crate::base::analyzer::Language {
            processor: "Dalvik".into(),
            variant: "LE".into(),
            size: 32,
        };

        let mut program = Program::new(
            &format!("apk_{}", apk.package_name),
            lang,
        );
        let base = options.base_address;
        program.image_base = base;

        // Create a memory block for the raw APK data.
        let block = MemoryBlock {
            name: "APK_DATA".into(),
            start: Address::new(base),
            size: data.len() as u64,
            is_read: true,
            is_write: false,
            is_execute: false,
            is_initialized: true,
        };
        program.memory_blocks.push(block);

        Ok(program)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Compute a CRC-32 checksum for ZIP entry verification.
    fn crc32_calc(data: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFF_FFFF;
        for &byte in data {
            crc ^= byte as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB8_8320;
                } else {
                    crc >>= 1;
                }
            }
        }
        !crc
    }

    /// Build minimal binary XML for testing.
    fn build_minimal_binary_xml() -> Vec<u8> {
        let mut xml = Vec::new();
        // Magic + file size placeholder
        xml.extend_from_slice(&AXML_MAGIC.to_le_bytes());
        xml.extend_from_slice(&0u32.to_le_bytes());

        let strings: Vec<&str> =
            vec!["manifest", "package", "com.example.app", "1", "1.0"];
        let header_size: u16 = 28;
        let count = strings.len() as u32;

        // Compute offsets and string data (each string has a 2-byte length prefix)
        let mut offsets: Vec<u32> = vec![0u32];
        let mut string_bytes = Vec::new();
        for s in &strings {
            let utf16: Vec<u16> =
                s.encode_utf16().chain(std::iter::once(0)).collect();
            offsets.push(offsets.last().unwrap() + 2 + (utf16.len() as u32 * 2));
            string_bytes.extend_from_slice(&(utf16.len() as u16).to_le_bytes());
            for cu in utf16 {
                string_bytes.extend_from_slice(&cu.to_le_bytes());
            }
        }

        let strings_data_size = string_bytes.len() as u32;
        let total_size = header_size as u32 + count * 4 + strings_data_size;

        // String pool chunk
        xml.extend_from_slice(&CHUNK_STRING_POOL.to_le_bytes());
        xml.extend_from_slice(&header_size.to_le_bytes());
        xml.extend_from_slice(&total_size.to_le_bytes());
        xml.extend_from_slice(&count.to_le_bytes());
        xml.extend_from_slice(&0u32.to_le_bytes()); // style count
        xml.extend_from_slice(&0u32.to_le_bytes()); // flags (UTF-16)
        xml.extend_from_slice(
            &(header_size as u32 + count * 4).to_le_bytes(),
        ); // strings offset
        xml.extend_from_slice(&0u32.to_le_bytes()); // styles offset
        for off in &offsets[..offsets.len() - 1] {
            xml.extend_from_slice(&off.to_le_bytes());
        }
        xml.extend_from_slice(&string_bytes);

        // Start element chunk for <manifest>
        let se_start = xml.len();
        // Header layout: chunk_type(2) + header_size(2) + chunk_size(4) + line(4) + comment(4) = 16
        // Then: ns(4) + name(4) + attr_start(2) + attr_size(2) + attr_count(2) + id(2) + class(2) + style(2) = 20
        // Total header before attrs = 36
        let attr_start_val: u16 = 36;
        xml.extend_from_slice(&CHUNK_XML_START_ELEMENT.to_le_bytes());
        xml.extend_from_slice(&0x0010u16.to_le_bytes()); // header size
        xml.extend_from_slice(&0u32.to_le_bytes()); // chunk size placeholder
        xml.extend_from_slice(&1u32.to_le_bytes()); // line
        xml.extend_from_slice(&(-1i32).to_le_bytes()); // comment
        xml.extend_from_slice(&(-1i32).to_le_bytes()); // ns index
        xml.extend_from_slice(&0i32.to_le_bytes()); // name: "manifest"
        xml.extend_from_slice(&attr_start_val.to_le_bytes()); // attr start = 36
        xml.extend_from_slice(&0x0014u16.to_le_bytes()); // attr size = 20
        xml.extend_from_slice(&1u16.to_le_bytes()); // attr count
        xml.extend_from_slice(&0u16.to_le_bytes()); // id index
        xml.extend_from_slice(&0u16.to_le_bytes()); // class index
        xml.extend_from_slice(&0u16.to_le_bytes()); // style index

        // Attribute (20 bytes): package="com.example.app"
        xml.extend_from_slice(&(-1i32).to_le_bytes()); // ns
        xml.extend_from_slice(&1i32.to_le_bytes()); // name idx
        xml.extend_from_slice(&2i32.to_le_bytes()); // value idx
        xml.extend_from_slice(&0u16.to_le_bytes()); // typed_value_size
        xml.extend_from_slice(&0u16.to_le_bytes()); // res0
        xml.extend_from_slice(&ATTR_TYPE_STRING.to_le_bytes()); // data_type (byte 16)
        xml.extend_from_slice(&0u8.to_le_bytes()); // data (byte 17)
        xml.extend_from_slice(&0u16.to_le_bytes()); // res1 (bytes 18-19)

        // Patch chunk size
        let se_chunk_size = xml.len() - se_start;
        xml[se_start + 4..se_start + 8]
            .copy_from_slice(&(se_chunk_size as u32).to_le_bytes());

        // End element chunk
        xml.extend_from_slice(&CHUNK_XML_END_ELEMENT.to_le_bytes());
        xml.extend_from_slice(&0x0010u16.to_le_bytes());
        xml.extend_from_slice(&16u32.to_le_bytes());
        xml.extend_from_slice(&1u32.to_le_bytes()); // line
        xml.extend_from_slice(&(-1i32).to_le_bytes()); // comment
        xml.extend_from_slice(&(-1i32).to_le_bytes()); // ns
        xml.extend_from_slice(&0i32.to_le_bytes()); // name

        // Patch file size
        let fs = xml.len() as u32;
        xml[4..8].copy_from_slice(&fs.to_le_bytes());
        xml
    }

    /// Build a minimal valid APK (ZIP containing AndroidManifest.xml).
    fn make_minimal_apk() -> Vec<u8> {
        let manifest_xml = build_minimal_binary_xml();
        let manifest_name = b"AndroidManifest.xml";
        let crc = crc32_calc(&manifest_xml);

        let mut zip = Vec::new();

        // Local file header
        zip.extend_from_slice(&LOCAL_FILE_HEADER_SIG.to_le_bytes());
        zip.extend_from_slice(&0x0014u16.to_le_bytes()); // version needed
        zip.extend_from_slice(&0u16.to_le_bytes()); // flags
        zip.extend_from_slice(&0u16.to_le_bytes()); // compression = stored
        zip.extend_from_slice(&0u16.to_le_bytes()); // mod time
        zip.extend_from_slice(&0u16.to_le_bytes()); // mod date
        zip.extend_from_slice(&crc.to_le_bytes());
        zip.extend_from_slice(&(manifest_xml.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(manifest_xml.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(manifest_name.len() as u16).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes()); // extra field len
        zip.extend_from_slice(manifest_name);
        zip.extend_from_slice(&manifest_xml);

        let local_header_offset: u32 = 0;

        // Central directory entry
        let cd_start = zip.len();
        zip.extend_from_slice(&CENTRAL_DIR_SIG.to_le_bytes());
        zip.extend_from_slice(&0x0014u16.to_le_bytes()); // version made by
        zip.extend_from_slice(&0x0014u16.to_le_bytes()); // version needed
        zip.extend_from_slice(&0u16.to_le_bytes()); // flags
        zip.extend_from_slice(&0u16.to_le_bytes()); // compression
        zip.extend_from_slice(&0u16.to_le_bytes()); // mod time
        zip.extend_from_slice(&0u16.to_le_bytes()); // mod date
        zip.extend_from_slice(&crc.to_le_bytes());
        zip.extend_from_slice(&(manifest_xml.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(manifest_xml.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(manifest_name.len() as u16).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes()); // extra
        zip.extend_from_slice(&0u16.to_le_bytes()); // comment
        zip.extend_from_slice(&0u16.to_le_bytes()); // disk start
        zip.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        zip.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        zip.extend_from_slice(&local_header_offset.to_le_bytes());
        zip.extend_from_slice(manifest_name);

        let cd_end = zip.len();
        let cd_size = (cd_end - cd_start) as u32;

        // End of central directory
        zip.extend_from_slice(&EOCD_SIG.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes()); // disk number
        zip.extend_from_slice(&0u16.to_le_bytes()); // disk with CD
        zip.extend_from_slice(&1u16.to_le_bytes()); // entries on disk
        zip.extend_from_slice(&1u16.to_le_bytes()); // total entries
        zip.extend_from_slice(&cd_size.to_le_bytes());
        zip.extend_from_slice(&(cd_start as u32).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes()); // comment len
        zip
    }

    #[test]
    fn test_is_apk_true() {
        let apk = make_minimal_apk();
        assert!(is_apk(&apk));
    }

    #[test]
    fn test_is_apk_false() {
        assert!(!is_apk(b"not an apk"));
        assert!(!is_apk(&[0xFF; 100]));
    }

    #[test]
    fn test_parse_apk_basic() {
        let apk_data = make_minimal_apk();
        let result = parse_apk(&apk_data);
        assert!(result.is_ok());
        let apk = result.unwrap();
        assert_eq!(apk.package_name, "com.example.app");
    }

    #[test]
    fn test_zip_entries() {
        let apk_data = make_minimal_apk();
        let entries = parse_zip_entries(&apk_data);
        assert!(entries.is_some());
        let entries = entries.unwrap();
        assert!(entries.iter().any(|e| e.name == "AndroidManifest.xml"));
    }

    #[test]
    fn test_find_eocd() {
        let apk_data = make_minimal_apk();
        let eocd = find_eocd(&apk_data);
        assert!(eocd.is_some());
    }

    #[test]
    fn test_read_helpers() {
        assert_eq!(
            read_u32_le(&[0x78, 0x56, 0x34, 0x12], 0),
            Some(0x12345678)
        );
        assert_eq!(read_u16_le(&[0x34, 0x12], 0), Some(0x1234));
        assert_eq!(read_u32_le(&[1, 2, 3], 0), None);
    }

    #[test]
    fn test_empty_data() {
        assert!(!is_apk(&[]));
        assert!(parse_apk(&[]).is_err());
    }

    #[test]
    fn test_apk_component() {
        let comp = ApkComponent {
            name: "TestActivity".to_string(),
            exported: false,
            enabled: true,
            intent_filters: Vec::new(),
            metadata: HashMap::new(),
        };
        assert_eq!(comp.name, "TestActivity");
        assert!(!comp.exported);
        assert!(comp.enabled);
    }

    #[test]
    fn test_intent_filter() {
        let filter = IntentFilter {
            actions: vec!["android.intent.action.MAIN".to_string()],
            categories: vec!["android.intent.category.LAUNCHER".to_string()],
            data_schemes: vec![],
            data_hosts: vec![],
            data_mime_types: vec![],
        };
        assert_eq!(filter.actions.len(), 1);
        assert_eq!(filter.categories.len(), 1);
    }

    #[test]
    fn test_native_lib_info() {
        let lib = NativeLibInfo {
            path: "lib/arm64-v8a/libfoo.so".to_string(),
            abi: "arm64-v8a".to_string(),
            filename: "libfoo.so".to_string(),
            compressed_size: 12345,
            uncompressed_size: 50000,
        };
        assert_eq!(lib.abi, "arm64-v8a");
        assert_eq!(lib.filename, "libfoo.so");
    }

    #[test]
    fn test_signature_info() {
        let sig = SignatureInfo {
            filename: "CERT.RSA".to_string(),
            subject: String::new(),
            issuer: String::new(),
            sha256_fingerprint: String::new(),
            valid_from: String::new(),
            valid_until: String::new(),
        };
        assert_eq!(sig.filename, "CERT.RSA");
    }

    #[test]
    fn test_resource_entry() {
        let entry = ResourceEntry {
            id: 0x7f010000,
            type_name: "string".to_string(),
            name: "app_name".to_string(),
            data_offset: 0,
            data_size: 0,
            config: None,
        };
        assert_eq!(entry.id, 0x7f010000);
        assert_eq!(entry.type_name, "string");
    }

    #[test]
    fn test_parse_binary_xml() {
        let xml = build_minimal_binary_xml();
        let result = parse_binary_xml(&xml);
        assert!(result.is_some());
        let (elements, sp) = result.unwrap();
        assert!(!sp.is_empty());
        assert!(!elements.is_empty());
        assert_eq!(elements[0].name, "manifest");
    }

    #[test]
    fn test_string_pool_parsing() {
        let xml = build_minimal_binary_xml();
        let (sp, _) = parse_string_pool(&xml, 8).unwrap();
        assert_eq!(sp.len(), 5);
        assert_eq!(sp[0], "manifest");
        assert_eq!(sp[1], "package");
        assert_eq!(sp[2], "com.example.app");
    }

    #[test]
    fn test_decode_res_value_null() {
        let v = decode_res_value(0, RES_TYPE_NULL);
        assert!(matches!(v, ResValue::Null));
    }

    #[test]
    fn test_decode_res_value_int_bool() {
        let v = decode_res_value(0xFFFFFFFF, RES_TYPE_INT_BOOL);
        assert!(matches!(v, ResValue::IntBool(true)));
        let v = decode_res_value(0, RES_TYPE_INT_BOOL);
        assert!(matches!(v, ResValue::IntBool(false)));
    }

    #[test]
    fn test_decode_res_value_reference() {
        let v = decode_res_value(0x7F010000, RES_TYPE_REFERENCE);
        assert!(matches!(v, ResValue::Reference(0x7F010000)));
    }

    #[test]
    fn test_decode_res_value_float() {
        let v = decode_res_value(f32::to_bits(3.14), RES_TYPE_FLOAT);
        match v {
            ResValue::Float(f) => assert!((f - 3.14).abs() < 0.001),
            _ => panic!("Expected Float"),
        }
    }

    #[test]
    fn test_decode_res_value_int_dec() {
        let v = decode_res_value(42u32, RES_TYPE_INT_DEC);
        assert!(matches!(v, ResValue::IntDec(42)));
    }

    #[test]
    fn test_decode_res_value_int_hex() {
        let v = decode_res_value(0xABCDu32, RES_TYPE_INT_HEX);
        assert!(matches!(v, ResValue::IntHex(0xABCD)));
    }

    #[test]
    fn test_decode_res_value_color_argb8() {
        let v = decode_res_value(0xFFAABBCCu32, RES_TYPE_INT_COLOR_ARGB8);
        match v {
            ResValue::ColorArgb8 { a, r, g, b } => {
                assert_eq!(a, 0xFF);
                assert_eq!(r, 0xAA);
                assert_eq!(g, 0xBB);
                assert_eq!(b, 0xCC);
            }
            _ => panic!("Expected ColorArgb8"),
        }
    }

    #[test]
    fn test_decode_res_value_dimension() {
        let data: u32 = ((16.0f32 * 256.0f32) as u32) | DIMENSION_UNIT_DIP as u32;
        let v = decode_res_value(data, RES_TYPE_DIMENSION);
        match v {
            ResValue::Dimension { value, unit } => {
                assert!((value - 16.0).abs() < 0.01);
                assert_eq!(unit, "dp");
            }
            _ => panic!("Expected Dimension"),
        }
    }

    #[test]
    fn test_res_id_helpers() {
        let id: u32 = 0x7F010000;
        assert_eq!(res_id_package(id), 0x7F);
        assert_eq!(res_id_type(id), 0x01);
        assert_eq!(res_id_entry(id), 0x0000);
    }

    #[test]
    fn test_dimension_unit_names() {
        assert_eq!(dimension_unit_name(DIMENSION_UNIT_PX), "px");
        assert_eq!(dimension_unit_name(DIMENSION_UNIT_DIP), "dp");
        assert_eq!(dimension_unit_name(DIMENSION_UNIT_SP), "sp");
        assert_eq!(dimension_unit_name(99).contains("unknown"), true);
    }

    #[test]
    fn test_fraction_unit_names() {
        assert_eq!(fraction_unit_name(FRACTION_UNIT_FRACTION), "%");
        assert_eq!(fraction_unit_name(FRACTION_UNIT_FRACTION_PARENT), "%p");
    }

    #[test]
    fn test_apk_feature_struct() {
        let feat = ApkFeature {
            name: "android.hardware.camera".to_string(),
            required: true,
            gl_es_version: None,
        };
        assert_eq!(feat.name, "android.hardware.camera");
        assert!(feat.required);
    }

    #[test]
    fn test_feature_extraction() {
        let elem = XmlElement {
            name: "uses-feature".to_string(),
            attributes: vec![
                XmlAttribute {
                    namespace: String::new(),
                    name: "name".to_string(),
                    value: "android.hardware.camera".to_string(),
                    data_type: ATTR_TYPE_STRING,
                    raw_data: 0,
                },
                XmlAttribute {
                    namespace: String::new(),
                    name: "required".to_string(),
                    value: "true".to_string(),
                    data_type: ATTR_TYPE_INT_BOOL,
                    raw_data: 0xFFFFFFFF,
                },
            ],
            children: vec![],
        };
        let features = extract_features(&[elem]);
        assert_eq!(features.len(), 1);
        assert_eq!(features[0].name, "android.hardware.camera");
        assert!(features[0].required);
    }

    /// Build raw string pool data for testing.
    fn build_string_pool_data(strings: &[&str], is_utf8: bool) -> Vec<u8> {
        let mut data = Vec::new();
        let header_size: u16 = 28;
        let count = strings.len() as u32;
        let flags: u32 = if is_utf8 { 0x100 } else { 0 };

        let mut offsets: Vec<u32> = vec![0u32];
        let mut string_bytes = Vec::new();
        for s in strings {
            let utf16: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
            // 2 bytes for length prefix + utf16 data
            offsets.push(offsets.last().unwrap() + 2 + (utf16.len() as u32 * 2));
            string_bytes.extend_from_slice(&(utf16.len() as u16).to_le_bytes());
            for cu in utf16 {
                string_bytes.extend_from_slice(&cu.to_le_bytes());
            }
        }

        let strings_data_size = string_bytes.len() as u32;
        let total_size = header_size as u32 + count * 4 + strings_data_size;

        data.extend_from_slice(&CHUNK_STRING_POOL.to_le_bytes());
        data.extend_from_slice(&header_size.to_le_bytes());
        data.extend_from_slice(&total_size.to_le_bytes());
        data.extend_from_slice(&count.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&(header_size as u32 + count * 4).to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        for off in &offsets[..offsets.len() - 1] {
            data.extend_from_slice(&off.to_le_bytes());
        }
        data.extend_from_slice(&string_bytes);
        data
    }

    #[test]
    fn test_namespace_parsing() {
        let strings: Vec<&str> = vec!["android", "http://schemas.android.com/apk/res/android"];
        let sp_data = build_string_pool_data(&strings, false);
        if sp_data.len() >= 8 {
            let (sp, _) = parse_string_pool(&sp_data, 0).unwrap();
            assert_eq!(sp.len(), 2);
            assert_eq!(sp[0], "android");
            assert_eq!(sp[1], "http://schemas.android.com/apk/res/android");
        }
    }

    #[test]
    fn test_apk_parse_corrupt_data() {
        assert!(parse_apk(b"not an apk at all").is_err());
        assert!(parse_apk(&[0u8; 8]).is_err());
        let mut data = Vec::new();
        data.extend_from_slice(&LOCAL_FILE_HEADER_SIG.to_le_bytes());
        data.resize(100, 0);
        assert!(parse_apk(&data).is_err());
    }
}
